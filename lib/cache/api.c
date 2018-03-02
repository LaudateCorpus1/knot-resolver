/*  Copyright (C) 2014-2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <assert.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include <libknot/errcode.h>
#include <libknot/descriptor.h>
#include <libknot/dname.h>
#include <libknot/rrtype/rrsig.h>

#include "contrib/ucw/lib.h"
#include "contrib/cleanup.h"
#include "lib/cache/api.h"
#include "lib/cache/cdb_lmdb.h"
#include "lib/defines.h"
#include "lib/utils.h"

#include "lib/dnssec/ta.h"
#include "lib/layer/iterate.h"
#include "lib/resolve.h"
#include "lib/rplan.h"

#include "lib/cache/impl.h"

/* TODO:
 *	- Reconsider when RRSIGs are put in and retrieved from the cache.
 *	  Currently it's always done, which _might_ be spurious, depending
 *	  on how kresd will use the returned result.
 *	  There's also the "problem" that kresd ATM does _not_ ask upstream
 *	  with DO bit in some cases.
 */


/** Cache version */
static const uint16_t CACHE_VERSION = 3;
/** Key size */
#define KEY_HSIZE (sizeof(uint8_t) + sizeof(uint16_t))
#define KEY_SIZE (KEY_HSIZE + KNOT_DNAME_MAXLEN)


/** @internal Removes all records from cache. */
static inline int cache_clear(struct kr_cache *cache)
{
	cache->stats.delete += 1;
	return cache_op(cache, clear);
}

/** @internal Set time when clearing cache. */
static void reset_timestamps(struct kr_cache *cache)
{
	cache->last_clear_monotime = kr_now();
	gettimeofday(&cache->last_clear_walltime, NULL);
}

/** @internal Open cache db transaction and check internal data version. */
static int assert_right_version(struct kr_cache *cache)
{
	/* Check cache ABI version */
	uint8_t key_str[] = "\x00\x00V"; /* CACHE_KEY_DEF; zero-term. but we don't care */
	knot_db_val_t key = { .data = key_str, .len = sizeof(key_str) };
	knot_db_val_t val = { NULL, 0 };
	int ret = cache_op(cache, read, &key, &val, 1);
	if (ret == 0 && val.len == sizeof(CACHE_VERSION)
	    && memcmp(val.data, &CACHE_VERSION, sizeof(CACHE_VERSION)) == 0) {
		ret = kr_error(EEXIST);
	} else {
		int oldret = ret;
		/* Version doesn't match. Recreate cache and write version key. */
		ret = cache_op(cache, count);
		if (ret != 0) { /* Non-empty cache, purge it. */
			kr_log_info("[     ][cach] incompatible cache database detected, purging\n");
			if (oldret) {
				kr_log_verbose("bad ret: %d\n", oldret);
			} else if (val.len != sizeof(CACHE_VERSION)) {
				kr_log_verbose("bad length: %d\n", (int)val.len);
			} else {
				uint16_t ver;
				memcpy(&ver, val.data, sizeof(ver));
				kr_log_verbose("bad version: %d\n", (int)ver);
			}
			ret = cache_clear(cache);
		}
		/* Either purged or empty. */
		if (ret == 0) {
			/* Key/Val is invalidated by cache purge, recreate it */
			val.data = /*const-cast*/(void *)&CACHE_VERSION;
			val.len = sizeof(CACHE_VERSION);
			ret = cache_op(cache, write, &key, &val, 1);
		}
	}
	kr_cache_sync(cache);
	return ret;
}

int kr_cache_open(struct kr_cache *cache, const struct kr_cdb_api *api, struct kr_cdb_opts *opts, knot_mm_t *mm)
{
	if (!cache) {
		return kr_error(EINVAL);
	}
	/* Open cache */
	if (!api) {
		api = kr_cdb_lmdb();
	}
	cache->api = api;
	int ret = cache->api->open(&cache->db, opts, mm);
	if (ret != 0) {
		return ret;
	}
	memset(&cache->stats, 0, sizeof(cache->stats));
	cache->ttl_min = KR_CACHE_DEFAULT_TTL_MIN;
	cache->ttl_max = KR_CACHE_DEFAULT_TTL_MAX;
	/* Check cache ABI version */
	reset_timestamps(cache);
	(void) assert_right_version(cache);
	return 0;
}


#define cache_isvalid(cache) ((cache) && (cache)->api && (cache)->db)

void kr_cache_close(struct kr_cache *cache)
{
	if (cache_isvalid(cache)) {
		cache_op(cache, close);
		cache->db = NULL;
	}
}

int kr_cache_sync(struct kr_cache *cache)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}
	if (cache->api->sync) {
		return cache_op(cache, sync);
	}
	return kr_ok();
}

int kr_cache_clear(struct kr_cache *cache)
{
	if (!cache_isvalid(cache)) {
		return kr_error(EINVAL);
	}
	int ret = cache_clear(cache);
	if (ret == 0) {
		reset_timestamps(cache);
		ret = assert_right_version(cache);
	}
	return ret;
}



struct nsec_p {
	struct {
		uint8_t salt_len;
		uint8_t alg;
		uint16_t iters;
	} s;
	uint8_t *salt;
};

/* When going stricter, BEWARE of breaking entry_h_consistent_NSEC() */
struct entry_h * entry_h_consistent(knot_db_val_t data, uint16_t type)
{
	(void) type; /* unused, for now */
	if (!data.data) return NULL;
	/* Length checks. */
	if (data.len < offsetof(struct entry_h, data))
		return NULL;
	const struct entry_h *eh = data.data;
	if (eh->is_packet) {
		uint16_t pkt_len;
		if (data.len < offsetof(struct entry_h, data) + sizeof(pkt_len)) {
			return NULL;
		}
		memcpy(&pkt_len, eh->data, sizeof(pkt_len));
		if (data.len < offsetof(struct entry_h, data) + sizeof(pkt_len)
				+ pkt_len) {
			return NULL;
		}
	}

	bool ok = true;
	ok = ok && (!kr_rank_test_noassert(eh->rank, KR_RANK_BOGUS)
		    || eh->is_packet);
	ok = ok && (eh->is_packet || !eh->has_optout);

	/* doesn't hold, because of temporary NSEC3 packet caching
	if (eh->is_packet)
		ok = ok && !kr_rank_test(eh->rank, KR_RANK_SECURE);
	*/

	//LATER: rank sanity
	return ok ? /*const-cast*/(struct entry_h *)eh : NULL;
}


int32_t get_new_ttl(const struct entry_h *entry, const struct kr_query *qry,
		    const knot_dname_t *owner, uint16_t type)
{
	int32_t diff = qry->timestamp.tv_sec - entry->time;
	if (diff < 0) {
		/* We may have obtained the record *after* the request started. */
		diff = 0;
	}
	int32_t res = entry->ttl - diff;
	if (res < 0 && owner && qry->stale_cb) {
		/* Stale-serving decision.  FIXME: modularize or make configurable, etc. */
		int res_stale = qry->stale_cb(res, owner, type, qry);
		if (res_stale >= 0)
			return res_stale;
	}
	return res;
}
int32_t kr_cache_ttl(const struct kr_cache_p *peek, const struct kr_query *qry,
		     const knot_dname_t *name, uint16_t type)
{
	const struct entry_h *eh = peek->raw_data;
	return get_new_ttl(eh, qry, name, type);
}






/** Check that no label contains a zero character.
 *
 * We refuse to work with those, as LF and our cache keys might become ambiguous.
 * Assuming uncompressed name, as usual.
 * CACHE_KEY_DEF
 */
static bool check_dname_for_lf(const knot_dname_t *n)
{
	return knot_dname_size(n) == strlen((const char *)n) + 1;
}

/** Like key_exact_type() but omits a couple checks not holding for pkt cache. */
knot_db_val_t key_exact_type_maypkt(struct key *k, uint16_t type)
{
	assert(!knot_rrtype_is_metatype(type));
	switch (type) {
	case KNOT_RRTYPE_RRSIG: /* no RRSIG query caching, at least for now */
		assert(false);
		return (knot_db_val_t){ NULL, 0 };
	/* xNAME lumped into NS. */
	case KNOT_RRTYPE_CNAME:
	case KNOT_RRTYPE_DNAME:
		type = KNOT_RRTYPE_NS;
	default:
		break;
	}

	int name_len = k->buf[0];
	k->buf[name_len + 1] = 0; /* make sure different names can never match */
	k->buf[name_len + 2] = 'E'; /* tag for exact name+type matches */
	memcpy(k->buf + name_len + 3, &type, 2);
	k->type = type;
	/* CACHE_KEY_DEF: key == dname_lf + '\0' + 'E' + RRTYPE */
	return (knot_db_val_t){ k->buf + 1, name_len + 4 };
}

/** Like key_exact_type_maypkt but with extra checks if used for RRs only. */
static knot_db_val_t key_exact_type(struct key *k, uint16_t type)
{
	switch (type) {
	/* Sanity check: forbidden types represented in other way(s). */
	case KNOT_RRTYPE_NSEC:
	case KNOT_RRTYPE_NSEC3:
		assert(false);
		return (knot_db_val_t){ NULL, 0 };
	}
	return key_exact_type_maypkt(k, type);
}


// TODO: move all these and cache_peek_real into a separate c-file that only exposes cache_peek_real
/* Forwards for larger chunks of code.  All just for cache_peek. */
static uint8_t get_lowest_rank(const struct kr_request *req, const struct kr_query *qry);
static int found_exact_hit(kr_layer_t *ctx, knot_pkt_t *pkt, knot_db_val_t val,
			   uint8_t lowest_rank);
static knot_db_val_t closest_NS(kr_layer_t *ctx, struct key *k);
static int answer_simple_hit(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl);
static int peek_nosync(kr_layer_t *ctx, knot_pkt_t *pkt);
static int try_wild(struct key *k, struct answer *ans, const knot_dname_t *clencl_name,
		    uint16_t type, uint8_t lowest_rank,
		    const struct kr_query *qry, struct kr_cache *cache);

static int peek_encloser(
	struct key *k, struct answer *ans, const uint8_t *nsec_p, const int sname_labels,
	uint8_t lowest_rank, const struct kr_query *qry, struct kr_cache *cache);

/** function for .produce phase */
int cache_peek(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	/* We first check various exit-conditions and then call the _real function. */

	if (ctx->state & (KR_STATE_FAIL|KR_STATE_DONE) || qry->flags.NO_CACHE
	    || (qry->flags.CACHE_TRIED && !qry->stale_cb)
	    || qry->stype == KNOT_RRTYPE_RRSIG /* LATER: some other behavior for this STYPE? */
	    || qry->sclass != KNOT_CLASS_IN) {
		return ctx->state; /* Already resolved/failed or already tried, etc. */
	}
	/* ATM cache only peeks for qry->sname and that would be useless
	 * to repeat on every iteration, so disable it from now on.
	 * LATER(optim.): assist with more precise QNAME minimization. */
	qry->flags.CACHE_TRIED = true;

	if (qry->stype == KNOT_RRTYPE_NSEC) {
		VERBOSE_MSG(qry, "=> skipping stype NSEC\n");
		return ctx->state;
	}
	if (!check_dname_for_lf(qry->sname)) {
		WITH_VERBOSE(qry) {
			auto_free char *sname_str = kr_dname_text(qry->sname);
			VERBOSE_MSG(qry, "=> skipping zero-containing sname %s\n", sname_str);
		}
		return ctx->state;
	}

	int ret = peek_nosync(ctx, pkt);
	kr_cache_sync(&req->ctx->cache);
	return ret;
}


/** Find equivalent nsec_p in entry_apex, if any. */
static knot_db_val_t search_plist(const knot_db_val_t val_cut, const uint8_t *nsec_p)
{
	const int nsec_p_dlen = nsec_p_rdlen(nsec_p);
	static const knot_db_val_t VAL_EMPTY = { NULL, 0 };
	const struct entry_apex *ea = entry_apex_consistent(val_cut);
	if (!ea) return VAL_EMPTY;
	const uint8_t *data_it = ea->data;
	int data_stride; /*< length of the current item in entry_apex data */
	for (int i = 0; i < ENTRY_APEX_NSECS_CNT; ++i, data_it += data_stride) {
		int ver = ea->nsecs[i];
		/* get data_stride */
		int data_stride_n;
		switch (ver) {
		case 0:
			data_stride = 0;
			continue;
		case 1:
			data_stride_n = 0; /* just the stamp */
			break;
		case 3:
			data_stride_n = nsec_p_rdlen(data_it);
			break;
		default:
			return VAL_EMPTY;
		}
		data_stride = sizeof(uint32_t) + data_stride_n;

		if ((!nsec_p && ver == 1)
		    || (nsec_p && ver == 3 && nsec_p_dlen == data_stride_n
			&& memcmp(nsec_p, data_it, data_stride_n) == 0)
		   ) {
			return (knot_db_val_t){
				.data = (void *)data_it,
				.len = data_stride,
			};
		}
	}
	return VAL_EMPTY;
}

/** See the call site. */
static int get_nsec_plist(const knot_db_val_t val_cut,
			  const uint8_t **nsec_plist, int *nsec_plen, /*< output */
			  const struct kr_query *qry, const knot_dname_t *zname /*< logging*/)
{
	if (true || !val_cut.data) {
	//  ^^^^ XXX VERBOSE_MSG(qry, "=> not even root NS in cache, but let's try NSEC\n");
		nsec_plist[0] = NULL;
		*nsec_plen = 1;
		return kr_ok();
	}

	*nsec_plen = 0;
	const struct entry_apex *ea = entry_apex_consistent(val_cut);
	const uint8_t *data_it = ea->data;
	int data_stride; /*< length of the current item in entry_apex data */
	for (int i = 0; i < ENTRY_APEX_NSECS_CNT; ++i, data_it += data_stride) {
		int ver = ea->nsecs[i];
		/* get data_stride */
		switch (ver) {
		case 0:
			data_stride = 0;
			continue;
		case 1:
			data_stride = sizeof(uint32_t); /* just the stamp */
			break;
		case 3:
			data_stride = sizeof(uint32_t) + nsec_p_rdlen(data_it);
			break;
		default:
			return kr_error(EILSEQ);
		}
		/* OK iff the stamp is in future */
		uint32_t stamp;
		memcpy(&stamp, data_it, sizeof(stamp));
		const int32_t remains = stamp - qry->timestamp.tv_sec; /* using SOA serial arith. */
		if (remains < 0) continue;
		/* append the params */
		nsec_plist[*nsec_plen] = ver == 1 ? NULL : (data_it + sizeof(stamp));
		++*nsec_plen;
	}
	WITH_VERBOSE(qry) {
		auto_free char *zname_str = kr_dname_text(zname);
		if (!*nsec_plen) {
			VERBOSE_MSG(qry, "=> no NSEC* cached for zone: %s\n", zname_str);
		} else {
			VERBOSE_MSG(qry, "=> trying zone: %s (first %s)\n", zname_str,
					(nsec_plist[0] ? "NSEC3" : "NSEC"));
		}
	}
	return kr_ok();
}



/**
 * \note we don't transition to KR_STATE_FAIL even in case of "unexpected errors".
 */
static int peek_nosync(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	struct key k_storage, *k = &k_storage;
	int ret = kr_dname_lf(k->buf, qry->sname, false);
	if (unlikely(ret)) {
		assert(false);
		return ctx->state;
	}

	const uint8_t lowest_rank = get_lowest_rank(req, qry);

	/**** 1. find the name or the closest (available) zone, not considering wildcards
	 **** 1a. exact name+type match (can be negative answer in insecure zones) */
	knot_db_val_t key = key_exact_type_maypkt(k, qry->stype);
	knot_db_val_t val = { NULL, 0 };
	ret = cache_op(cache, read, &key, &val, 1);
	if (!ret) {
		VERBOSE_MSG(qry, "=> read OK\n");
		/* found an entry: test conditions, materialize into pkt, etc. */
		ret = found_exact_hit(ctx, pkt, val, lowest_rank);
	}
	if (ret && ret != -abs(ENOENT)) {
		VERBOSE_MSG(qry, "=> exact hit error: %d %s\n", ret, kr_strerror(ret));
		assert(false);
		return ctx->state;
	} else if (!ret) {
		return KR_STATE_DONE;
	}

	/**** 1b. otherwise, find the longest prefix NS/xNAME (with OK time+rank). [...] */
	k->zname = qry->sname;
	ret = kr_dname_lf(k->buf, k->zname, false); /* LATER(optim.): probably remove */
	if (unlikely(ret)) {
		assert(false);
		return ctx->state;
	}
	const knot_db_val_t val_cut = closest_NS(ctx, k);
	switch (k->type) {
	case KNOT_RRTYPE_NS:
		break;
	case KNOT_RRTYPE_CNAME: {
		const uint32_t new_ttl = get_new_ttl(val_cut.data, qry,
						     qry->sname, KNOT_RRTYPE_CNAME);
		ret = answer_simple_hit(ctx, pkt, KNOT_RRTYPE_CNAME, val_cut.data,
					val_cut.data + val_cut.len, new_ttl);
		/* TODO: ^^ cumbersome code; we also recompute the TTL */
		return ret == kr_ok() ? KR_STATE_DONE : ctx->state;
		}

	case KNOT_RRTYPE_DNAME:
		VERBOSE_MSG(qry, "=> DNAME not supported yet\n"); // LATER
		return ctx->state;
	default:
		assert(false);
		return ctx->state;
	}

#if 0
	if (!eh) { /* fall back to root hints? */
		ret = kr_zonecut_set_sbelt(req->ctx, &qry->zone_cut);
		if (ret) return ctx->state;
		assert(!qry->zone_cut.parent);

		//VERBOSE_MSG(qry, "=> using root hints\n");
		//qry->flags.AWAIT_CUT = false;
		return ctx->state;
	}

	/* Now `eh` points to the closest NS record that we've found,
	 * and that's the only place to start - we may either find
	 * a negative proof or we may query upstream from that point. */
	kr_zonecut_set(&qry->zone_cut, k->zname);
	ret = kr_make_query(qry, pkt); // TODO: probably not yet - qname minimization
	if (ret) return ctx->state;
#endif

	/** Collecting multiple NSEC* + RRSIG records, in preparation for the answer
	 *  + track the progress */
	struct answer ans;
	memset(&ans, 0, sizeof(ans));
	ans.mm = &pkt->mm;
	const int sname_labels = knot_dname_labels(qry->sname, NULL);

	/* Obtain nsec_p*: the list of usable NSEC* parameters;
	 * it's list of pointers to NSEC3PARAM data (NULL for NSEC). */
	const uint8_t * nsec_plist[ENTRY_APEX_NSECS_CNT];
	int nsec_plen = 0;
	ret = get_nsec_plist(val_cut, nsec_plist, &nsec_plen, qry, k->zname);
	if (ret) return ctx->state;
	/* Try the NSEC* parameters in order, until success.
	 * Let's not mix different parameters for NSEC* RRs in a single proof. */
	for (int i = 0; ;) {
		const uint8_t *nsec_p = nsec_plist[i];
		/**** 2. and 3. inside */
		ret = peek_encloser(k, &ans, nsec_p, sname_labels, lowest_rank, qry, cache);
		if (!ret) break;
		if (ret < 0) return ctx->state;
		/* Otherwise we try another nsec_p, if available. */
		if (++i == nsec_plen) {
			return ctx->state;
		}
		/* clear possible partial answers in `ans` (no need to deallocate) */
		ans.rcode = 0;
		memset(&ans.rrsets, 0, sizeof(ans.rrsets));
	}


	/**** 4. add SOA iff needed */
	if (ans.rcode != PKT_NOERROR) {
		/* Assuming k->buf still starts with zone's prefix,
		 * look up the SOA in cache. */
		k->buf[0] = k->zlf_len;
		key = key_exact_type(k, KNOT_RRTYPE_SOA);
		knot_db_val_t val = { NULL, 0 };
		ret = cache_op(cache, read, &key, &val, 1);
		const struct entry_h *eh;
		if (ret || !(eh = entry_h_consistent(val, KNOT_RRTYPE_SOA))) {
			assert(ret); /* only want to catch `eh` failures */
			VERBOSE_MSG(qry, "=> SOA missed\n");
			return ctx->state;
		}
		/* Check if the record is OK. */
		int32_t new_ttl = get_new_ttl(eh, qry, k->zname, KNOT_RRTYPE_SOA);
		if (new_ttl < 0 || eh->rank < lowest_rank || eh->is_packet) {
			VERBOSE_MSG(qry, "=> SOA unfit %s: rank 0%.2o, new TTL %d\n",
					(eh->is_packet ? "packet" : "RR"),
					eh->rank, new_ttl);
			return ctx->state;
		}
		/* Add the SOA into the answer. */
		void *eh_data_bound = val.data + val.len;
		ret = entry2answer(&ans, AR_SOA, eh, eh_data_bound,
				   k->zname, KNOT_RRTYPE_SOA, new_ttl);
		if (ret) return ctx->state;
	}


	/* Find our target RCODE. */
	int real_rcode;
	switch (ans.rcode) {
	case PKT_NODATA:
	case PKT_NOERROR: /* positive wildcarded response */
		real_rcode = KNOT_RCODE_NOERROR;
		break;
	case PKT_NXDOMAIN:
		real_rcode = KNOT_RCODE_NXDOMAIN;
		break;
	default:
		assert(false);
	case 0: /* i.e. nothing was found */
		/* LATER(optim.): zone cut? */
		VERBOSE_MSG(qry, "=> cache miss\n");
		return ctx->state;
	}

	if (pkt_renew(pkt, qry->sname, qry->stype)
	    || knot_pkt_begin(pkt, KNOT_ANSWER)
	   ) {
		assert(false);
		return ctx->state;
	}
	knot_wire_set_rcode(pkt->wire, real_rcode);


	bool expiring = false; // TODO
	VERBOSE_MSG(qry, "=> writing RRsets: ");
	for (int i = 0; i < sizeof(ans.rrsets) / sizeof(ans.rrsets[0]); ++i) {
		if (i == 1) knot_pkt_begin(pkt, KNOT_AUTHORITY);
		if (!ans.rrsets[i].set.rr) continue;
		expiring = expiring || ans.rrsets[i].set.expiring;
		ret = pkt_append(pkt, &ans.rrsets[i], ans.rrsets[i].set.rank);
		if (ret) {
			assert(false);
			return ctx->state;
		}
		kr_log_verbose(kr_rank_test(ans.rrsets[i].set.rank, KR_RANK_SECURE)
				? "+" : "-");
	}
	kr_log_verbose("\n");
	/* Finishing touches. */
	qry->flags.EXPIRING = expiring;
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;

	return KR_STATE_DONE;
}

/**
 * This is where the high-level "business logic" of aggressive cache is.
 * \return 0: success (may need SOA);  >0: try other nsec_p;  <0: exit cache immediately.
 */
static int peek_encloser(
	struct key *k, struct answer *ans, const uint8_t *nsec_p, const int sname_labels,
	uint8_t lowest_rank, const struct kr_query *qry, struct kr_cache *cache)
{
	ans->nsec_v = nsec_p ? 3 : 1;

	/** Start of NSEC* covering the sname;
	 * it's part of key - the one within zone (read only) */
	knot_db_val_t cover_low_kwz = { NULL, 0 };
	knot_dname_t cover_hi_storage[KNOT_DNAME_MAXLEN];
	/** End of NSEC* covering the sname. */
	knot_db_val_t cover_hi_kwz = {
		.data = cover_hi_storage,
		.len = sizeof(cover_hi_storage),
	};

	/**** 2. Find a closest (provable) encloser (of sname). */
	int clencl_labels = -1;
	if (!nsec_p) { /* NSEC */
		int ret = nsec1_encloser(k, ans, sname_labels, &clencl_labels,
					 &cover_low_kwz, &cover_hi_kwz, qry, cache);
		if (ret) return ret;
	} else { //XXX NSEC3
		int ret = nsec3_encloser(k, ans, sname_labels, &clencl_labels,
					 &cover_low_kwz, &cover_hi_kwz, qry, cache);
		if (ret) return ret;
	}

	/* We should have either a match or a cover at this point. */
	if (ans->rcode != PKT_NODATA && ans->rcode != PKT_NXDOMAIN) {
		assert(false);
		return kr_error(EINVAL);
	}
	const bool sname_covered = ans->rcode == PKT_NXDOMAIN;

	/** Name of the closest (provable) encloser. */
	const knot_dname_t *clencl_name = qry->sname;
	for (int l = sname_labels; l > clencl_labels; --l)
		clencl_name = knot_wire_next_label(clencl_name, NULL);

	/**** 3. source of synthesis checks, in case sname was covered.
	 **** 3a. We want to query for NSEC* of source of synthesis (SS) or its
	 * predecessor, providing us with a proof of its existence or non-existence. */
	if (sname_covered && !nsec_p) {
		int ret = nsec1_src_synth(k, ans, clencl_name,
					  cover_low_kwz, cover_hi_kwz, qry, cache);
		if (ret == AR_SOA) return 0;
		assert(ret <= 0);
		if (ret) return ret;

	} else if (sname_covered && nsec_p) {
		//XXX NSEC3
		int ret = nsec3_src_synth(k, ans, clencl_name,
					  cover_low_kwz, cover_hi_kwz, qry, cache);
		if (ret == AR_SOA) return 0;
		assert(ret <= 0);
		if (ret) return ret;

	} /* else (!sname_covered) so no wildcard checks needed,
	   * as we proved that sname exists. */

	/**** 3b. find wildcarded answer, if sname was covered
	 * and we don't have a full proof yet.  (common for NSEC*) */
	if (!sname_covered)
		return kr_ok(); /* decrease indentation */
	/* Construct key for exact qry->stype + source of synthesis. */
	int ret = kr_dname_lf(k->buf, clencl_name, true);
	if (ret) {
		assert(!ret);
		return kr_error(ret);
	}
	const uint16_t types[] = { qry->stype, KNOT_RRTYPE_CNAME };
	for (int i = 0; i < (2 - (qry->stype == KNOT_RRTYPE_CNAME)); ++i) {
		ret = try_wild(k, ans, clencl_name, types[i],
				lowest_rank, qry, cache);
		if (ret == kr_ok()) {
			return kr_ok();
		} else if (ret != -ABS(ENOENT) && ret != -ABS(ESTALE)) {
			assert(false);
			return kr_error(ret);
		}
		/* else continue */
	}
	/* Neither attempt succeeded, but the NSEC* proofs were found,
	 * so skip trying other parameters, as it seems very unlikely
	 * to turn out differently than by the same wildcard search. */
	return -ABS(ENOENT);
}


/** It's simply inside of cycle taken out to decrease indentation.  \return error code. */
static int stash_rrset(const ranked_rr_array_t *arr, int arr_i,
			const struct kr_query *qry, struct kr_cache *cache,
			int *unauth_cnt, map_t *nsec_pmap);
/** Stash a single nsec_p.  \return 0 (errors are ignored). */
static int stash_nsec_p(const char *key_str, void *nsec_p_v, void *request);



int cache_stash(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	const uint16_t pkt_type = knot_pkt_qtype(pkt);
	const bool type_bad = knot_rrtype_is_metatype(pkt_type)
				|| pkt_type == KNOT_RRTYPE_RRSIG;
	/* Note: we cache even in KR_STATE_FAIL.  For example,
	 * BOGUS answer can go to +cd cache even without +cd request. */
	if (!qry || qry->flags.CACHED || type_bad || qry->sclass != KNOT_CLASS_IN) {
		return ctx->state;
	}
	/* Do not cache truncated answers, at least for now.  LATER */
	if (knot_wire_get_tc(pkt->wire)) {
		return ctx->state;
	}
	/* Stash individual records. */
	ranked_rr_array_t *selected[] = kr_request_selected(req);
	int unauth_cnt = 0;
	map_t nsec_pmap = map_make(&req->pool);
	for (int psec = KNOT_ANSWER; psec <= KNOT_ADDITIONAL; ++psec) {
		const ranked_rr_array_t *arr = selected[psec];
		/* uncached entries are located at the end */
		for (ssize_t i = arr->len - 1; i >= 0; --i) {
			ranked_rr_array_entry_t *entry = arr->at[i];
			if (entry->qry_uid != qry->uid) {
				continue;
				/* TODO: probably safe to break but maybe not worth it */
			}
			int ret = stash_rrset(arr, i, qry, cache, &unauth_cnt, &nsec_pmap);
			if (ret) {
				VERBOSE_MSG(qry, "=> stashing RRs errored out\n");
				goto finally;
			}
			/* LATER(optim.): maybe filter out some type-rank combinations
			 * that won't be useful as separate RRsets. */
		}
	}

	map_walk(&nsec_pmap, stash_nsec_p, req);
	/* LATER(optim.): typically we also have corresponding NS record in the list,
	 * so we might save a cache operation. */

	stash_pkt(pkt, qry, req);

finally:
	if (unauth_cnt) {
		VERBOSE_MSG(qry, "=> stashed also %d nonauth RRs\n", unauth_cnt);
	};
	kr_cache_sync(cache);
	return ctx->state; /* we ignore cache-stashing errors */
}

static int stash_rrset(const ranked_rr_array_t *arr, int arr_i,
			const struct kr_query *qry, struct kr_cache *cache,
			int *unauth_cnt, map_t *nsec_pmap)
{
	//FIXME review entry_h
	const ranked_rr_array_entry_t *entry = arr->at[arr_i];
	if (entry->cached) {
		return kr_ok();
	}
	const knot_rrset_t *rr = entry->rr;
	if (!rr) {
		assert(!EINVAL);
		return kr_error(EINVAL);
	}
	if (!check_dname_for_lf(rr->owner)) {
		WITH_VERBOSE(qry) {
			auto_free char *owner_str = kr_dname_text(rr->owner);
			VERBOSE_MSG(qry, "=> skipping zero-containing name %s\n",
					owner_str);
		}
		return kr_ok();
	}

	#if 0
	WITH_VERBOSE {
		VERBOSE_MSG(qry, "=> considering to stash ");
		kr_rrtype_print(rr->type, "", " ");
		kr_dname_print(rr->owner, "", "\n");
	}
	#endif

	switch (rr->type) {
	case KNOT_RRTYPE_RRSIG:
	case KNOT_RRTYPE_NSEC3:
		// for now; LATER NSEC3
		return kr_ok();
	default:
		break;
	}

	/* Try to find corresponding signatures, always.  LATER(optim.): speed. */
	const knot_rrset_t *rr_sigs = NULL;
	for (ssize_t j = arr->len - 1; j >= 0; --j) {
		/* TODO: ATM we assume that some properties are the same
		 * for all RRSIGs in the set (esp. label count). */
		ranked_rr_array_entry_t *e = arr->at[j];
		bool ok = e->qry_uid == qry->uid && !e->cached
			&& e->rr->type == KNOT_RRTYPE_RRSIG
			&& knot_rrsig_type_covered(&e->rr->rrs, 0) == rr->type
			&& knot_dname_is_equal(rr->owner, e->rr->owner);
		if (!ok) continue;
		rr_sigs = e->rr;
		break;
	}

	const int wild_labels = rr_sigs == NULL ? 0 :
	       knot_dname_labels(rr->owner, NULL) - knot_rrsig_labels(&rr_sigs->rrs, 0);
	//kr_log_verbose("wild_labels = %d\n", wild_labels);
	if (wild_labels < 0) {
		return kr_ok();
	}
	const knot_dname_t *encloser = rr->owner;
	for (int i = 0; i < wild_labels; ++i) {
		encloser = knot_wire_next_label(encloser, NULL);
	}
	if (!check_dname_for_lf(encloser)) {
		/* They would break uniqueness. */
		return kr_ok();
	}

	int ret = 0;
	/* Construct the key under which RRs will be stored. */
	struct key k_storage, *k = &k_storage;
	knot_db_val_t key;
	switch (rr->type) {
	case KNOT_RRTYPE_NSEC:
		if (!kr_rank_test(entry->rank, KR_RANK_SECURE)) {
			/* Skip any NSECs that aren't validated. */
			return kr_ok();
		}
		if (!rr_sigs || !rr_sigs->rrs.rr_count || !rr_sigs->rrs.data) {
			assert(!EINVAL);
			return kr_error(EINVAL);
		}
		const knot_dname_t *signer = knot_rrsig_signer_name(&rr_sigs->rrs, 0);
		k->zlf_len = knot_dname_size(signer) - 1;
		key = key_NSEC1(k, encloser, wild_labels);

		if (likely(check_dname_for_lf(signer))) {
			map_set(nsec_pmap, (const char *)signer, NULL);
		}
		break;
	default:
		ret = kr_dname_lf(k->buf, encloser, wild_labels);
		if (ret) {
			assert(!ret);
			return kr_error(ret);
		}
		key = key_exact_type(k, rr->type);
	}

	/* Compute materialized sizes of the new data. */
	const knot_rdataset_t *rds_sigs = rr_sigs ? &rr_sigs->rrs : NULL;
	const int rr_ssize = rdataset_dematerialize_size(&rr->rrs);
	knot_db_val_t val_new_entry = {
		.data = NULL,
		.len = offsetof(struct entry_h, data) + rr_ssize
			+ rdataset_dematerialize_size(rds_sigs),
	};

	/* Prepare raw memory for the new entry. */
	ret = entry_h_splice(&val_new_entry, entry->rank, key, k->type, rr->type,
				rr->owner, qry, cache);
	if (ret) return kr_ok(); /* some aren't really errors */
	assert(val_new_entry.data);

	/* Compute TTL, just in case they weren't equal. */
	uint32_t ttl = -1;
	const knot_rdataset_t *rdatasets[] = { &rr->rrs, rds_sigs, NULL };
	for (int j = 0; rdatasets[j]; ++j) {
		knot_rdata_t *rd = rdatasets[j]->data;
		assert(rdatasets[j]->rr_count);
		for (uint16_t l = 0; l < rdatasets[j]->rr_count; ++l) {
			ttl = MIN(ttl, knot_rdata_ttl(rd));
			rd = kr_rdataset_next(rd);
		}
	} /* TODO: consider expirations of RRSIGs as well, just in case. */

	/* Write the entry itself. */
	struct entry_h *eh = val_new_entry.data;
	memset(eh, 0, offsetof(struct entry_h, data));
	eh->time = qry->timestamp.tv_sec;
	eh->ttl  = MAX(MIN(ttl, cache->ttl_max), cache->ttl_min);
	eh->rank = entry->rank;
	if (rdataset_dematerialize(&rr->rrs, eh->data)
	    || rdataset_dematerialize(rds_sigs, eh->data + rr_ssize)) {
		/* minimize the damage from incomplete write; TODO: better */
		eh->ttl = 0;
		eh->rank = 0;
		assert(false);
	}
	assert(entry_h_consistent(val_new_entry, rr->type));

	{
	#ifndef NDEBUG
		struct answer ans;
		memset(&ans, 0, sizeof(ans));
		ans.mm = &qry->request->pool;
		ret = entry2answer(&ans, AR_ANSWER, eh,
				   val_new_entry.data + val_new_entry.len,
				   rr->owner, rr->type, 0);
		/*
		VERBOSE_MSG(qry, "=> sanity: written %d and read %d\n",
				(int)val_new_entry.len, ret);
		assert(ret == val_new_entry.len);
		*/
	#endif
	}

	WITH_VERBOSE(qry) {
		/* Reduce verbosity. */
		if (!kr_rank_test(entry->rank, KR_RANK_AUTH)) {
			++*unauth_cnt;
			return kr_ok();
		}
		auto_free char *type_str = kr_rrtype_text(rr->type),
			*encl_str = kr_dname_text(encloser);
		VERBOSE_MSG(qry, "=> stashed rank: 0%.2o, %s %s%s "
			"(%d B total, incl. %d RRSIGs)\n",
			entry->rank, type_str, (wild_labels ? "*." : ""), encl_str,
			(int)val_new_entry.len, (rr_sigs ? rr_sigs->rrs.rr_count : 0)
			);
	}
	return kr_ok();
}

static int stash_nsec_p(const char *dname, void *nsec_p_v, void *request)
{
	struct kr_request *req = request;
	const struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;
	uint32_t valid_until = qry->timestamp.tv_sec + cache->ttl_max;
		/* LATER(optim.): be more precise here ^^ and reduce calls. */
	static const int32_t ttl_margin = 3600;
	const uint8_t *nsec_p = (const uint8_t *)nsec_p_v;
	int data_stride = sizeof(valid_until) + nsec_p_rdlen(nsec_p);
	/* Find what's in the cache. */
	struct key k_storage, *k = &k_storage;
	int ret = kr_dname_lf(k->buf, (const knot_dname_t *)dname, false);
	if (ret) return kr_error(ret);
	knot_db_val_t key = key_exact_type(k, KNOT_RRTYPE_NS);
	knot_db_val_t val_orig = { NULL, 0 };
	ret = cache_op(cache, read, &key, &val_orig, 1);
	if (ret && ret != -ABS(ENOENT)) {
		VERBOSE_MSG(qry, "=> EL read failed (ret: %d)\n", ret);
		return kr_ok();
	}
	/* Prepare new entry_list_t so we can just write at el[0]. */
	entry_list_t el;
	int log_refresh_by = 0;
	if (ret == -ABS(ENOENT)) {
		memset(el, 0, sizeof(el));
	} else {
		ret = entry_list_parse(val_orig, el);
		if (ret) {
			VERBOSE_MSG(qry, "=> EL parse failed (ret: %d)\n", ret);
			return kr_error(0);
		}
		/* Find the index to replace. */
		int i_replace = ENTRY_APEX_NSECS_CNT - 1;
		for (int i = 0; i < ENTRY_APEX_NSECS_CNT; ++i) {
			if (el[i].len != data_stride) continue;
			if (nsec_p && memcmp(nsec_p, el[i].data + sizeof(uint32_t),
						data_stride - sizeof(uint32_t)) != 0) {
				continue;
			}
			/* Save a cache operation if TTL extended only a little. */
			uint32_t valid_orig;
			memcpy(&valid_orig, el[i].data, sizeof(valid_orig));
			const int32_t ttl_extended_by = valid_until - valid_orig;
			if (ttl_extended_by < ttl_margin) {
				VERBOSE_MSG(qry, "=> nsec_p stash skipped (extra TTL: %d)\n",
						ttl_extended_by);
				return kr_ok();
			}
			i_replace = i;
			log_refresh_by = ttl_extended_by;
			break;
		}
		/* Shift the other indices: move the first `i` blocks by one position. */
		if (i_replace) {
			memmove(&el[1], &el[0], sizeof(el[0]) * i_replace);
		}
	}
	/* Prepare old data into a buffer.  See entry_h_splice() for why.  LATER(optim.) */
	el[0].len = data_stride;
	el[0].data = NULL;
	knot_db_val_t val;
	val.len = entry_list_serial_size(el),
	val.data = mm_alloc(&req->pool, val.len),
	entry_list_memcpy(val.data, el);
	/* Prepare the new data chunk */
	memcpy(el[0].data, &valid_until, sizeof(valid_until));
	if (nsec_p) {
		memcpy(el[0].data + sizeof(valid_until), nsec_p,
			data_stride - sizeof(valid_until));
	}
	/* Write it all to the cache */
	ret = cache_op(cache, write, &key, &val, 1);
	if (ret || !val.data) {
		VERBOSE_MSG(qry, "=> EL write failed (ret: %d)\n", ret);
		return kr_ok();
	}
	if (log_refresh_by) {
		VERBOSE_MSG(qry, "=> nsec_p stashed (refresh by %d)\n", log_refresh_by);
	} else {
		VERBOSE_MSG(qry, "=> nsec_p stashed (new)\n");
	}
	return kr_ok();
}


static int answer_simple_hit(kr_layer_t *ctx, knot_pkt_t *pkt, uint16_t type,
		const struct entry_h *eh, const void *eh_bound, uint32_t new_ttl)
#define CHECK_RET(ret) do { \
	if ((ret) < 0) { assert(false); return kr_error((ret)); } \
} while (false)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	/* All OK, so start constructing the (pseudo-)packet. */
	int ret = pkt_renew(pkt, qry->sname, qry->stype);
	CHECK_RET(ret);

	/* Materialize the sets for the answer in (pseudo-)packet. */
	struct answer ans;
	memset(&ans, 0, sizeof(ans));
	ans.mm = &pkt->mm;
	ret = entry2answer(&ans, AR_ANSWER, eh, eh_bound,
			   qry->sname, type, new_ttl);
	CHECK_RET(ret);
	/* Put links to the materialized data into the pkt. */
	ret = pkt_append(pkt, &ans.rrsets[AR_ANSWER], eh->rank);
	CHECK_RET(ret);
	/* Finishing touches. */
	qry->flags.EXPIRING = is_expiring(eh->ttl, new_ttl);
	qry->flags.CACHED = true;
	qry->flags.NO_MINIMIZE = true;
	qry->flags.DNSSEC_INSECURE = kr_rank_test(eh->rank, KR_RANK_INSECURE);
	if (qry->flags.DNSSEC_INSECURE) {
		qry->flags.DNSSEC_WANT = false;
	}
	VERBOSE_MSG(qry, "=> satisfied by exact RR or CNAME: rank 0%.2o, new TTL %d\n",
			eh->rank, new_ttl);
	return kr_ok();
}
#undef CHECK_RET


/** TODO: description; see the single call site for now. */
static int found_exact_hit(kr_layer_t *ctx, knot_pkt_t *pkt, knot_db_val_t val,
			   uint8_t lowest_rank)
{
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;

	int ret = entry_h_seek(&val, qry->stype);
	if (ret) return ret;
	VERBOSE_MSG(qry, "=> FEH seek OK \n");
	const struct entry_h *eh = entry_h_consistent(val, qry->stype);
	if (!eh) {
		assert(false);
		return kr_error(ENOENT);
		// LATER: recovery in case of error, perhaps via removing the entry?
		// LATER(optim): pehaps optimize the zone cut search
	}
	VERBOSE_MSG(qry, "=> FEH consistent OK \n");

	int32_t new_ttl = get_new_ttl(eh, qry, qry->sname, qry->stype);
	if (new_ttl < 0 || eh->rank < lowest_rank) {
		/* Positive record with stale TTL or bad rank.
		 * LATER(optim.): It's unlikely that we find a negative one,
		 * so we might theoretically skip all the cache code. */

		VERBOSE_MSG(qry, "=> skipping exact %s: rank 0%.2o (min. 0%.2o), new TTL %d\n",
				eh->is_packet ? "packet" : "RR", eh->rank, lowest_rank, new_ttl);
		return kr_error(ENOENT);
	}

	const void *eh_bound = val.data + val.len;
	if (eh->is_packet) {
		/* Note: we answer here immediately, even if it's (theoretically)
		 * possible that we could generate a higher-security negative proof.
		 * Rank is high-enough so we take it to save time searching. */
		return answer_from_pkt  (ctx, pkt, qry->stype, eh, eh_bound, new_ttl);
	} else {
		return answer_simple_hit(ctx, pkt, qry->stype, eh, eh_bound, new_ttl);
	}
}


/** Try to satisfy via wildcard.  See the single call site. */
static int try_wild(struct key *k, struct answer *ans, const knot_dname_t *clencl_name,
		    const uint16_t type, const uint8_t lowest_rank,
		    const struct kr_query *qry, struct kr_cache *cache)
{
	knot_db_val_t key = key_exact_type(k, type);
	/* Find the record. */
	knot_db_val_t val = { NULL, 0 };
	int ret = cache_op(cache, read, &key, &val, 1);
	if (!ret) {
		ret = entry_h_seek(&val, type);
	}
	if (ret) {
		if (ret != -ABS(ENOENT)) {
			VERBOSE_MSG(qry, "=> wildcard: hit error %d %s\n",
					ret, strerror(abs(ret)));
			assert(false);
		}
		WITH_VERBOSE(qry) {
			auto_free char *clencl_str = kr_dname_text(clencl_name),
				*type_str = kr_rrtype_text(type);
			VERBOSE_MSG(qry, "=> wildcard: not found: *.%s %s\n",
					clencl_str, type_str);
		}
		return ret;
	}
	/* Check if the record is OK. */
	const struct entry_h *eh = entry_h_consistent(val, type);
	if (!eh) {
		assert(false);
		return kr_error(ret);
		// LATER: recovery in case of error, perhaps via removing the entry?
	}
	int32_t new_ttl = get_new_ttl(eh, qry, qry->sname, type);
		/* ^^ here we use the *expanded* wildcard name */
	if (new_ttl < 0 || eh->rank < lowest_rank || eh->is_packet) {
		/* Wildcard record with stale TTL, bad rank or packet.  */
		VERBOSE_MSG(qry, "=> wildcard: skipping %s, rank 0%.2o, new TTL %d\n",
				eh->is_packet ? "packet" : "RR", eh->rank, new_ttl);
		return -ABS(ESTALE);
	}
	/* Add the RR into the answer. */
	const void *eh_bound = val.data + val.len;
	ret = entry2answer(ans, AR_ANSWER, eh, eh_bound, qry->sname, type, new_ttl);
	VERBOSE_MSG(qry, "=> NSEC wildcard: answer expanded, ret = %d, new TTL %d\n",
			ret, (int)new_ttl);
	if (ret) return kr_error(ret);
	ans->rcode = PKT_NOERROR;
	return kr_ok();
}


static int peek_exact_real(struct kr_cache *cache, const knot_dname_t *name, uint16_t type,
			struct kr_cache_p *peek)
{
	struct key k_storage, *k = &k_storage;

	int ret = kr_dname_lf(k->buf, name, false);
	if (ret) return kr_error(ret);

	knot_db_val_t key = key_exact_type(k, type);
	knot_db_val_t val = { NULL, 0 };
	ret = cache_op(cache, read, &key, &val, 1);
	if (!ret) ret = entry_h_seek(&val, type);
	if (ret) return kr_error(ret);

	const struct entry_h *eh = entry_h_consistent(val, type);
	if (!eh || eh->is_packet) {
		// TODO: no packets, but better get rid of whole kr_cache_peek_exact().
		return kr_error(ENOENT);
	}
	*peek = (struct kr_cache_p){
		.time = eh->time,
		.ttl  = eh->ttl,
		.rank = eh->rank,
		.raw_data = val.data,
		.raw_bound = val.data + val.len,
	};
	return kr_ok();
}
int kr_cache_peek_exact(struct kr_cache *cache, const knot_dname_t *name, uint16_t type,
			struct kr_cache_p *peek)
{	/* Just wrap with extra verbose logging. */
	const int ret = peek_exact_real(cache, name, type, peek);
	if (false && VERBOSE_STATUS) { /* too noisy for usual --verbose */
		auto_free char *type_str = kr_rrtype_text(type),
			*name_str = kr_dname_text(name);
		const char *result_str = (ret == kr_ok() ? "hit" :
				(ret == kr_error(ENOENT) ? "miss" : "error"));
		VERBOSE_MSG(NULL, "_peek_exact: %s %s %s (ret: %d)",
				type_str, name_str, result_str, ret);
	}
	return ret;
}

/** Find the longest prefix NS/xNAME (with OK time+rank), starting at k->*.
 * We store xNAME at NS type to lower the number of searches.
 * CNAME is only considered for equal name, of course.
 * We also store NSEC* parameters at NS type; probably the latest two will be kept.
 * Found type is returned via k->type.
 *
 * \param exact_match Whether exact match is considered special.
 * \return raw entry from cache (for NS) or rewound entry (xNAME)
 */
static knot_db_val_t closest_NS(kr_layer_t *ctx, struct key *k)
{
	static const knot_db_val_t VAL_EMPTY = { NULL, 0 };
	struct kr_request *req = ctx->req;
	struct kr_query *qry = req->current_query;
	struct kr_cache *cache = &req->ctx->cache;

	int zlf_len = k->buf[0];

	uint8_t rank_min = KR_RANK_INSECURE | KR_RANK_AUTH;
	// LATER(optim): if stype is NS, we check the same value again
	bool exact_match = true;
	/* Inspect the NS/xNAME entries, shortening by a label on each iteration. */
	do {
		k->buf[0] = zlf_len;
		knot_db_val_t key = key_exact_type(k, KNOT_RRTYPE_NS);
		knot_db_val_t val = VAL_EMPTY;
		int ret = cache_op(cache, read, &key, &val, 1);
		if (ret == -abs(ENOENT)) goto next_label;
		if (ret) {
			assert(!ret);
			return VAL_EMPTY; // TODO: do something with kr_error(ret)?
		}

		/* Check consistency, find any type;
		 * using `goto` for shortening by another label. */
		const struct entry_apex *ea = entry_apex_consistent(val);
		const knot_db_val_t val_orig = val;
		if (unlikely(!ea)) {
			assert(!EILSEQ); // do something about it?
			goto next_label;
		}
		/* More types are possible; try in order.
		 * For non-fatal failures just "continue;" to try the next type. */
		uint16_t type = 0;
		while (type != KNOT_RRTYPE_DNAME) {
			/* Determine the next type to try. */
			switch (type) {
			case 0:
				type = KNOT_RRTYPE_NS;
				if (!ea->has_ns
				    /* On a zone cut we want DS from the parent zone. */
				    || (exact_match && qry->stype == KNOT_RRTYPE_DS)) {
					continue;
				}
				break;
			case KNOT_RRTYPE_NS:
				type = KNOT_RRTYPE_CNAME;
				/* CNAME is interesting only if we
				 * directly hit the name that was asked.
				 * Note that we want it even in the DS case. */
				if (!ea->has_cname || !exact_match)
					continue;
				break;
			case KNOT_RRTYPE_CNAME:
				type = KNOT_RRTYPE_DNAME;
				/* DNAME is interesting only if we did NOT
				 * directly hit the name that was asked. */
				if (!ea->has_dname || exact_match)
					continue;
				break;
			default:
				assert(false);
				return VAL_EMPTY;
			}
			/* Find the entry for the type, check positivity, TTL */
			val = val_orig;
			ret = entry_h_seek(&val, type);
			const struct entry_h *eh;
			if (ret || !(eh = entry_h_consistent(val, type))) {
				VERBOSE_MSG(qry, "=> EH seek ret: %d\n", ret);
				assert(false);
				goto next_label;
			}
			int32_t new_ttl = get_new_ttl(eh, qry, k->zname, type);
			if (new_ttl < 0
			    /* Not interested in negative or bogus. */
			    || eh->is_packet
			    /* For NS any kr_rank is accepted,
			     * as insecure or even nonauth is OK */
			    || (type != KNOT_RRTYPE_NS && eh->rank < rank_min)) {

				WITH_VERBOSE(qry) {
					auto_free char *type_str =
						kr_rrtype_text(type);
					const char *packet_str =
						eh->is_packet ? "packet" : "RR";
					VERBOSE_MSG(qry, "=> skipping unfit %s %s: "
						"rank 0%.2o, new TTL %d\n",
						type_str, packet_str,
						eh->rank, new_ttl);
				}
				continue;
			}
			/* We found our match. */
			k->type = type;
			k->zlf_len = zlf_len;
			return type == KNOT_RRTYPE_NS ? val_orig : val;
		}

	next_label:
		/* remove one more label */
		exact_match = false;
		if (k->zname[0] == 0) {
			/* We miss root NS in cache, but let's at least assume it exists. */
			k->type = KNOT_RRTYPE_NS;
			k->zlf_len = zlf_len;
			assert(zlf_len == 0);
			return VAL_EMPTY;
		}
		zlf_len -= (k->zname[0] + 1);
		k->zname += (k->zname[0] + 1);
		k->buf[zlf_len + 1] = 0;
	} while (true);
}


static uint8_t get_lowest_rank(const struct kr_request *req, const struct kr_query *qry)
{
	/* TODO: move rank handling into the iterator (DNSSEC_* flags)? */
	const bool allow_unverified =
		knot_wire_get_cd(req->answer->wire) || qry->flags.STUB;
		/* in stub mode we don't trust RRs anyway ^^ */
	if (qry->flags.NONAUTH) {
		return KR_RANK_INITIAL;
		/* Note: there's little sense in validation status for non-auth records.
		 * In case of using NONAUTH to get NS IPs, knowing that you ask correct
		 * IP doesn't matter much for security; it matters whether you can
		 * validate the answers from the NS.
		 */
	} else if (!allow_unverified) {
		/* Records not present under any TA don't have their security
		 * verified at all, so we also accept low ranks in that case. */
		const bool ta_covers = kr_ta_covers_qry(req->ctx, qry->sname, qry->stype);
		/* ^ TODO: performance?  TODO: stype - call sites */
		if (ta_covers) {
			return KR_RANK_INSECURE | KR_RANK_AUTH;
		} /* else falltrhough */
	}
	return KR_RANK_INITIAL | KR_RANK_AUTH;
}




