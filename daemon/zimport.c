/*  Copyright (C) 2018 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *  SPDX-License-Identifier: GPL-3.0-or-later
 */

/* Module is intended to import resource records from file into resolver's cache.
 * File supposed to be a standard DNS zone file
 * which contains text representations of resource records.
 * For now only root zone import is supported.
 *
 * Import process consists of two stages.
 * 1) Zone file parsing.
 * 2) Import of parsed entries into the cache.
 *
 * These stages are implemented as two separate functions
 * (zi_zone_import and zi_zone_process) which runs sequentially with the
 * pause between them. This is done because resolver is a single-threaded
 * application, so it can't process user's requests during the whole import
 * process. Separation into two stages allows to reduce the
 * continuous time interval when resolver can't serve user requests.
 * Since root zone isn't large it is imported as single
 * chunk. If it would be considered as necessary, import stage can be
 * split into shorter stages.
 *
 * zi_zone_import() uses libzscanner to parse zone file.
 * Parsed records are stored to internal storage from where they are imported to
 * cache during the second stage.
 *
 * zi_zone_process() imports parsed resource records to cache.
 * It imports rrset by creating request that will never be sent to upstream.
 * After request creation resolver creates pseudo-answer which must contain
 * all necessary data for validation. Then resolver process answer as if he had
 * been received from network.
 */

#include "daemon/zimport.h"

#include <inttypes.h> /* PRIu64 */
#include <limits.h>
#include <stdlib.h>
#include <uv.h>
#include <ucw/mempool.h>
#include <libknot/rrset.h>
#include <libzscanner/scanner.h>

#include <libknot/version.h>
#define ENABLE_ZONEMD (KNOT_VERSION_HEX >= 0x030100)
#if ENABLE_ZONEMD
	#include <libdnssec/digest.h>
#endif

#include "daemon/worker.h"
#include "lib/dnssec/ta.h"
#include "lib/dnssec.h"
#include "lib/generic/map.h"
#include "lib/generic/array.h"
#include "lib/generic/trie.h"
#include "lib/utils.h"

/* Pause between parse and import stages, milliseconds.
 * See comment in zi_zone_import() */
#define ZONE_IMPORT_PAUSE 100

struct zone_import_ctx {
	struct worker_ctx *worker;
	bool started;
	knot_dname_t *origin;
	knot_rrset_t *ta;
	knot_rrset_t *key;
	uint64_t start_timestamp;
	size_t rrset_idx;
	uv_timer_t timer;
	knot_mm_t pool;
	zi_callback cb;
	void *cb_param;

	trie_t *rrsets; /// map: key_get() -> knot_rrset_t*
	uint32_t timestamp_rr; /// stamp of when RR data arrived (seconds since epoch)

	struct kr_svldr_ctx *svldr;
	const knot_dname_t *last_cut; /// internal to zi_rrset_import()

#if ENABLE_ZONEMD
	uint8_t *digest_buf; /// temporary buffer for digest computation (on pool)
	#define DIGEST_BUF_SIZE (64*1024 - 1)
	#define DIGEST_ALG_COUNT 2
	struct {
		bool active; /// whether we want it computed
		dnssec_digest_ctx_t *ctx;
		const uint8_t *expected; /// expected digest (inside zonemd on pool)
	} digests[DIGEST_ALG_COUNT]; /// we use indices 0 and 1 for SHA 384 and 512
#endif
};

typedef struct zone_import_ctx zone_import_ctx_t;


#define KEY_LEN (KNOT_DNAME_MAXLEN + 1 + 2 + 2)
/** Construct key for name, type and signed type (if type == RRSIG).  ZONEMD order!
 *
 * Return negative error code in asserted cases.
 */
static int key_get(char buf[KEY_LEN], const knot_dname_t *name,
		uint16_t type, uint16_t type_maysig, char **key_p)
{
	char *lf_len_p = (char *)knot_dname_lf(name, (uint8_t *)buf);
	if (kr_fails_assert(lf_len_p && key_p))
		return kr_error(EINVAL);
	*key_p = lf_len_p + 1;
	// LF is output as right-aligned on KNOT_DNAME_MAXLEN index.
	if (kr_fails_assert(*key_p + *lf_len_p - KNOT_DNAME_MAXLEN == buf))
		return kr_error(EINVAL);
	buf[KNOT_DNAME_MAXLEN] = 0;
	memcpy(buf + KNOT_DNAME_MAXLEN + 1, &type, sizeof(type));
	if (type == KNOT_RRTYPE_RRSIG)
		memcpy(buf + KNOT_DNAME_MAXLEN + 1 + sizeof(type),
			&type_maysig, sizeof(type_maysig));
	return *lf_len_p + 1 + sizeof(type) * (1 + (type == KNOT_RRTYPE_RRSIG));
}

/** Simple helper to retreive from zone_import_ctx_t::rrsets */
static knot_rrset_t * rrset_get(trie_t *rrsets, const knot_dname_t *name,
				uint16_t type, uint16_t type_maysig)
{
	char key_buf[KEY_LEN], *key;
	const int len = key_get(key_buf, name, type, type_maysig, &key);
	if (len < 0)
		return NULL;
	const trie_val_t *rrsig_p = trie_get_try(rrsets, key, len);
	if (!rrsig_p)
		return NULL;
	kr_assert(*rrsig_p);
	return *rrsig_p;
}

#if ENABLE_ZONEMD
static int digest_rrset(trie_val_t *rr_p, void *z_import_v)
{
	zone_import_ctx_t *z_import = z_import_v;
	const knot_rrset_t *rr = *rr_p;

	// ignore apex ZONEMD or its RRSIG
	const bool is_apex = knot_dname_is_equal(z_import->origin, rr->owner);
	if (is_apex && kr_rrset_type_maysig(rr) == KNOT_RRTYPE_ZONEMD)
		return KNOT_EOK;

	const int len = knot_rrset_to_wire_extra(rr, z_import->digest_buf, DIGEST_BUF_SIZE,
						 0, NULL, KNOT_PF_ORIGTTL);
	if (len < 0)
		return kr_error(len);

	// digest serialized RRSet
	for (int i = 0; i < DIGEST_ALG_COUNT; ++i) {
		if (!z_import->digests[i].active)
			continue;
		dnssec_binary_t bufbin = { len, z_import->digest_buf };
		int ret = dnssec_digest(z_import->digests[i].ctx, &bufbin);
		if (ret != KNOT_EOK)
			return kr_error(ret);
	}
	return KNOT_EOK;
}

/** Verify ZONEMD in the stored zone, and return error code.
 *
 * All conditions are verified *except* for DNSSEC (not even for ZONEMD itself):
   https://www.rfc-editor.org/rfc/rfc8976.html#name-verifying-zone-digest
 */
static int zonemd_verify(zone_import_ctx_t *z_import)
{
	bool zonemd_is_valid = false;
	// Find ZONEMD RR + RRSIG
	knot_rrset_t * const rr_zonemd
		= rrset_get(z_import->rrsets, z_import->origin, KNOT_RRTYPE_ZONEMD, 0);
	if (!rr_zonemd) {
		// no zonemd; let's compute digest and throw an error afterwards
		z_import->digests[KNOT_ZONEMD_ALORITHM_SHA384 - 1].active = true;
		//z_import->digests[KNOT_ZONEMD_ALORITHM_SHA512 - 1].active = true;
		goto do_digest;
	}
	const knot_rrset_t * const rrsig_zonemd
		= rrset_get(z_import->rrsets, z_import->origin,
				KNOT_RRTYPE_RRSIG, KNOT_RRTYPE_ZONEMD);
	// Validate ZONEMD RRSIG
	{
		int ret = rrsig_zonemd
			? kr_svldr_rrset(rr_zonemd, &rrsig_zonemd->rrs, z_import->svldr)
			: kr_error(ENOENT);
		zonemd_is_valid = (ret == kr_ok());
		if (!zonemd_is_valid)
			kr_log_error(PREFILL, "ZONEMD signature failed to validate\n");
	}

	// Get SOA serial
	uint32_t soa_serial = -1;
	{
		const knot_rrset_t *soa = rrset_get(z_import->rrsets, z_import->origin,
							KNOT_RRTYPE_SOA, 0);
		if (!soa) {
			kr_log_error(PREFILL, "SOA record not found\n");
			return kr_error(ENOENT);
		}
		if (soa->rrs.count != 1) {
			kr_log_error(PREFILL, "the SOA RR set is weird\n");
			return kr_error(EINVAL);
		} // length is checked by parser already
		soa_serial = knot_soa_serial(soa->rrs.rdata);
	}
	// Figure out SOA+ZONEMD RR contents.
	bool some_active = false;
	knot_rdata_t *rd = rr_zonemd->rrs.rdata;
	for (int i = 0; i < rr_zonemd->rrs.count; ++i, rd = knot_rdataset_next(rd)) {
		if (rd->len < 6 || knot_zonemd_scheme(rd) != KNOT_ZONEMD_SCHEME_SIMPLE
		    || knot_zonemd_soa_serial(rd) != soa_serial)
			continue;
		const int algo = knot_zonemd_algorithm(rd);
		if (algo != KNOT_ZONEMD_ALORITHM_SHA384 && algo != KNOT_ZONEMD_ALORITHM_SHA512)
			continue;
		if (rd->len != 6 + knot_zonemd_digest_size(rd)) {
			kr_log_error(PREFILL, "ZONEMD record has incorrect digest length\n");
			return kr_error(EINVAL);
		}
		if (z_import->digests[algo - 1].active) {
			kr_log_error(PREFILL, "multiple clashing ZONEMD records found\n");
			return kr_error(EINVAL);
		}
		some_active = true;
		z_import->digests[algo - 1].active = true;
		z_import->digests[algo - 1].expected = knot_zonemd_digest(rd);
	}
	if (!some_active) {
		kr_log_error(PREFILL, "ZONEMD record(s) found but none were usable\n");
		return kr_error(ENOENT);
	}
do_digest:
	// Init memory, etc.
	if (!z_import->digest_buf) {
		z_import->digest_buf = mm_alloc(&z_import->pool, DIGEST_BUF_SIZE);
		if (!z_import->digest_buf)
			return kr_error(ENOMEM);
	}
	for (int i = 0; i < DIGEST_ALG_COUNT; ++i) {
		const int algo = i + 1;
		if (!z_import->digests[i].active)
			continue;
		int ret = dnssec_digest_init(algo, &z_import->digests[i].ctx);
		if (ret != KNOT_EOK) {
			// free previous successful _ctx, if applicable
			dnssec_binary_t digest = { 0 };
			while (--i >= 0) {
				if (z_import->digests[i].active)
					dnssec_digest_finish(z_import->digests[i].ctx,
								&digest);
			}
			return kr_error(ENOMEM);
		}
	}
	// Actually compute the digest(s).
	int ret = trie_apply(z_import->rrsets, digest_rrset, z_import);
	dnssec_binary_t digests[DIGEST_ALG_COUNT] = { 0 };
	for (int i = 0; i < DIGEST_ALG_COUNT; ++i) {
		if (!z_import->digests[i].active)
			continue;
		int ret2 = dnssec_digest_finish(z_import->digests[i].ctx, &digests[i]);
		if (ret == DNSSEC_EOK)
			ret = ret2;
		// we need to keep going to free all the _ctx
	}
	if (ret != DNSSEC_EOK) { // TODO: additional error logging?
		for (int i = 0; i < DIGEST_ALG_COUNT; ++i)
			free(digests[i].data);
		return kr_error(ret);
	}
	// Now only check that one of the hashes match.
	bool has_match = false;
	for (int i = 0; i < DIGEST_ALG_COUNT; ++i) {
		if (!z_import->digests[i].active)
			continue;
		if (!z_import->digests[i].expected) {
			kr_log_error(PREFILL, "no ZONEMD found; computed hash:\n");
		} else if (memcmp(z_import->digests[i].expected, digests[i].data,
					digests[i].size) != 0) {
			kr_log_info(PREFILL, "ZONEMD hash mismatch; computed hash:\n");
		} else {
			kr_log_debug(PREFILL, "ZONEMD hash matches\n");
			has_match = true;
			continue;
		}
		// TODO: better printing
		for (ssize_t j = 0; j < digests[i].size; ++j)
			fprintf(stderr, "%02x", digests[i].data[j]);
		fprintf(stderr, "\n");
	}

	for (int i = 0; i < DIGEST_ALG_COUNT; ++i)
		free(digests[i].data);
	return has_match && zonemd_is_valid ? kr_ok() : kr_error(ENOENT);
}
#endif


/** @internal Allocate zone import context.
 * @return pointer to zone import context or NULL. */
static zone_import_ctx_t *zi_ctx_alloc()
{
	return calloc(1, sizeof(zone_import_ctx_t));
}

/** @internal Free zone import context. */
static void zi_ctx_free(zone_import_ctx_t *z_import)
{
	if (z_import != NULL) {
		free(z_import);
	}
}

/** @internal Reset all fields in the zone import context to their default values.
 * Flushes memory pool, but doesn't reallocate memory pool buffer.
 * Doesn't affect timer handle, pointers to callback and callback parameter.
 * @return 0 if success; -1 if failed. */
static int zi_reset(struct zone_import_ctx *z_import, size_t rrset_sorted_list_size)
{
	mp_flush(z_import->pool.ctx);

	z_import->started = false;
	z_import->start_timestamp = 0;
	z_import->rrset_idx = 0;
	z_import->pool.alloc = (knot_mm_alloc_t) mp_alloc;
	z_import->rrsets = trie_create(&z_import->pool);

#if ENABLE_ZONEMD
	memset(z_import->digests, 0, sizeof(z_import->digests));
#endif
	return kr_ok();
}

/** @internal Close callback for timer handle.
 * @note Actually frees zone import context. */
static void on_timer_close(uv_handle_t *handle)
{
	zone_import_ctx_t *z_import = (zone_import_ctx_t *)handle->data;
	if (z_import != NULL) {
		zi_ctx_free(z_import);
	}
}

zone_import_ctx_t *zi_allocate(struct worker_ctx *worker,
			       zi_callback cb, void *param)
{
	if (worker->loop == NULL) {
		return NULL;
	}
	zone_import_ctx_t *z_import = zi_ctx_alloc();
	if (!z_import) {
		return NULL;
	}
	void *mp = mp_new (8192);
	if (!mp) {
		zi_ctx_free(z_import);
		return NULL;
	}
	z_import->pool.ctx = mp;
	z_import->worker = worker;
	int ret = zi_reset(z_import, 0);
	if (ret < 0) {
		mp_delete(mp);
		zi_ctx_free(z_import);
		return NULL;
	}
	uv_timer_init(z_import->worker->loop, &z_import->timer);
	z_import->timer.data = z_import;
	z_import->cb = cb;
	z_import->cb_param = param;
	return z_import;
}

void zi_free(zone_import_ctx_t *z_import)
{
	z_import->started = false;
	z_import->start_timestamp = 0;
	z_import->rrset_idx = 0;
	mp_delete(z_import->pool.ctx);
	z_import->pool.ctx = NULL;
	z_import->pool.alloc = NULL;
	z_import->worker = NULL;
	z_import->cb = NULL;
	z_import->cb_param = NULL;
	uv_close((uv_handle_t *)&z_import->timer, on_timer_close);
}

/**
 * @internal Import given rrset to cache.
 *
 * @return 0; let's keep importing even if some RRset fails
 */
static int zi_rrset_import(trie_val_t *rr_p, void *z_import_v)
{
	zone_import_ctx_t *z_import = z_import_v;
	knot_rrset_t *rr = *rr_p;

	if (rr->type == KNOT_RRTYPE_RRSIG)
		return 0; // we do RRSIGs at once with their types

	// Determine if this RRset is authoritative.
	// We utilize that iteration happens in canonical order.
	// BUG (rare): `A` exactly on zone cut would be misdetected and fail validation.
	bool is_auth;
	const int kdib = knot_dname_in_bailiwick(rr->owner, z_import->last_cut);
	if (kdib == 0 && (rr->type == KNOT_RRTYPE_DS || rr->type == KNOT_RRTYPE_NSEC
				|| rr->type == KNOT_RRTYPE_NSEC3)) {
		// parent side of the zone cut (well, presumably in case of NSEC*)
		is_auth = true;
	} else if (kdib >= 0) {
		// inside non-auth subtree
		is_auth = false;
	} else if (rr->type == KNOT_RRTYPE_NS
			&& knot_dname_in_bailiwick(rr->owner, z_import->origin) > 0) {
		// entering non-auth subtree
		z_import->last_cut = rr->owner;
		is_auth = false;
	} else {
		// outside non-auth subtree
		is_auth = true;
		z_import->last_cut = NULL; // so that the next _in_bailiwick() is faster
	}

	// Get and validate the corresponding RRSIGs, if authoritative.
	// LATER: improve logging here and below?
	const knot_rrset_t *rrsig = NULL;
	if (is_auth) {
		rrsig = rrset_get(z_import->rrsets, rr->owner, KNOT_RRTYPE_RRSIG, rr->type);
		if (unlikely(!rrsig)) {
			KR_DNAME_GET_STR(owner_str, rr->owner);
			KR_RRTYPE_GET_STR(type_str, rr->type);
			kr_log_error(PREFILL, "no records found for %s RRSIG %s\n",
					owner_str, type_str);
			return 0;
		}
		int ret = kr_svldr_rrset(rr, &rrsig->rrs, z_import->svldr);
		if (unlikely(ret)) {
			kr_log_error(PREFILL, "validation of this RRset failed: %s\n",
					kr_strerror(ret));
			return 0;
		}
	}

	// TODO: re-check TTL+timestamp handling.  (downloaded file might be older)
	const uint8_t rank = is_auth ? KR_RANK_AUTH|KR_RANK_SECURE : KR_RANK_OMIT;
	int ret = kr_cache_insert_rr(&the_worker->engine->resolver.cache, rr, rrsig,
					rank, z_import->timestamp_rr);
	if (ret) {
		kr_log_error(PREFILL, "caching this RRset failed: %s\n",
				kr_strerror(ret));
		return 0;
	}
	return 0; // Success, unlike all other returns.
}

/** @internal Iterate over parsed rrsets and try to import each of them. */
static void zi_zone_process(uv_timer_t* handle)
{
	zone_import_ctx_t *z_import = (zone_import_ctx_t *)handle->data;

	KR_DNAME_GET_STR(zone_name_str, z_import->origin);


	trie_apply(z_import->rrsets, zi_rrset_import, z_import);

	kr_svldr_free_ctx(z_import->svldr);
	z_import->svldr = NULL;


	kr_log_debug(PREFILL, "finished importing `%s`\n", zone_name_str);

	// FIXME: review all below
	z_import->started = false;

	if (z_import->cb != NULL)
		z_import->cb(kr_ok(), z_import->cb_param);
}

/** @internal Store rrset that has been imported to zone import context memory pool.
 * @return -1 if failed; 0 if success. */
static int zi_record_store(zs_scanner_t *s)
{
	if (s->r_data_length > UINT16_MAX) {
		/* Due to knot_rrset_add_rdata(..., const uint16_t size, ...); */
		kr_log_error(PREFILL, "line %"PRIu64": rdata is too long\n",
				s->line_counter);
		return -1;
	}

	if (knot_dname_size(s->r_owner) != strlen((const char *)(s->r_owner)) + 1) {
		kr_log_error(PREFILL, "line %"PRIu64
				": owner name contains zero byte, skip\n",
				s->line_counter);
		return 0;
	}

	zone_import_ctx_t *z_import = (zone_import_ctx_t *)s->process.data;

	knot_rrset_t *new_rr = knot_rrset_new(s->r_owner, s->r_type, s->r_class,
					      s->r_ttl, &z_import->pool);
	if (!new_rr) {
		kr_log_error(PREFILL, "line %"PRIu64": error creating rrset\n",
				s->line_counter);
		return -1;
	}
	int res = knot_rrset_add_rdata(new_rr, s->r_data, s->r_data_length,
				       &z_import->pool);
	if (res != KNOT_EOK) {
		kr_log_error(PREFILL, "line %"PRIu64": error adding rdata to rrset\n",
				s->line_counter);
		return -1;
	}

	/* Records in zone file may not be grouped by name and RR type.
	 * Use map to create search key and
	 * avoid ineffective searches across all the imported records. */
	char key_buf[KEY_LEN], *key;
	const int len = key_get(key_buf, new_rr->owner, new_rr->type,
				kr_rrset_type_maysig(new_rr), &key);
	if (len < 0) {
		kr_log_error(PREFILL, "line %"PRIu64": error constructing rrkey\n",
				s->line_counter);
		return -1;
	}
	trie_val_t *rr_p = trie_get_ins(z_import->rrsets, key, len);
	if (!rr_p)
		return -1; // ENOMEM
	if (*rr_p) {
		knot_rrset_t *rr = *rr_p;
		res = knot_rdataset_merge(&rr->rrs, &new_rr->rrs, &z_import->pool);
	} else {
		*rr_p = new_rr;
	}
	if (res != 0) {
		kr_log_error(PREFILL, "line %"PRIu64": error saving parsed rrset\n",
				s->line_counter);
		return -1;
	}

	return 0;
}

static int zi_state_parsing(zs_scanner_t *s)
{
	bool empty = true;
	while (zs_parse_record(s) == 0) {
		switch (s->state) {
		case ZS_STATE_DATA:
			if (zi_record_store(s) != 0) {
				return -1;
			}
			zone_import_ctx_t *z_import = (zone_import_ctx_t *) s->process.data;
			empty = false;
			if (s->r_type == KNOT_RRTYPE_SOA) {
				z_import->origin = knot_dname_copy(s->r_owner,
                                                                 &z_import->pool);
			}
			break;
		case ZS_STATE_ERROR:
			kr_log_error(PREFILL, "line: %"PRIu64
				     ": parse error; code: %i ('%s')\n",
				     s->line_counter, s->error.code,
				     zs_strerror(s->error.code));
			return -1;
		case ZS_STATE_INCLUDE:
			kr_log_error(PREFILL, "line: %"PRIu64
				     ": INCLUDE is not supported\n",
				     s->line_counter);
			return -1;
		case ZS_STATE_EOF:
		case ZS_STATE_STOP:
			if (empty) {
				kr_log_error(PREFILL, "empty zone file\n");
				return -1;
			}
			if (!((zone_import_ctx_t *) s->process.data)->origin) {
				kr_log_error(PREFILL, "zone file doesn't contain SOA record\n");
				return -1;
			}
			return (s->error.counter == 0) ? 0 : -1;
		default:
			kr_log_error(PREFILL, "line: %"PRIu64
				     ": unexpected parse state: %i\n",
				     s->line_counter, s->state);
			return -1;
		}
	}

	return -1;
}

int zi_zone_import(struct zone_import_ctx *z_import,
		   const char *zone_file, const char *origin,
		   uint16_t rclass, uint32_t ttl)
{
	if (kr_fails_assert(z_import && z_import->worker && zone_file))
		return -1;

   //// Parse the whole zone file into z_import->rrsets.
	zs_scanner_t s_storage, *s = &s_storage;
	/* zs_init(), zs_set_input_file(), zs_set_processing() returns -1 in case of error,
	 * so don't print error code as it meaningless. */
	int res = zs_init(s, origin, rclass, ttl);
	if (res != 0) {
		kr_log_error(PREFILL, "error initializing zone scanner instance, error: %i (%s)\n",
			     s->error.code, zs_strerror(s->error.code));
		return -1;
	}

	res = zs_set_input_file(s, zone_file);
	if (res != 0) {
		kr_log_error(PREFILL, "error opening zone file `%s`, error: %i (%s)\n",
			     zone_file, s->error.code, zs_strerror(s->error.code));
		zs_deinit(s);
		return -1;
	}

	/* Don't set processing and error callbacks as we don't use automatic parsing.
	 * Parsing as well error processing will be performed in zi_state_parsing().
	 * Store pointer to zone import context for further use. */
	if (zs_set_processing(s, NULL, NULL, (void *)z_import) != 0) {
		kr_log_error(PREFILL, "zs_set_processing() failed for zone file `%s`, "
				"error: %i (%s)\n",
				zone_file, s->error.code, zs_strerror(s->error.code));
		zs_deinit(s);
		return -1;
	}

	int ret = zi_reset(z_import, 4096);
	if (ret == 0) {
		z_import->started = true;
		z_import->start_timestamp = kr_now();
		kr_log_debug(PREFILL, "import started for zone file `%s`\n",
			    zone_file);
		ret = zi_state_parsing(s);
	}
	zs_deinit(s);

	if (ret != 0) {
		kr_log_error(PREFILL, "error parsing zone file `%s`\n", zone_file);
		z_import->started = false;
		return ret;
	}

	KR_DNAME_GET_STR(zone_name_str, z_import->origin);
	// TODO: basic sanity checks?  For example, non-zero record count?
	{ // FIXME: get stamp from the file instead, and maybe check against OS time.
		struct timespec now;
		if (clock_gettime(CLOCK_REALTIME, &now)) {
			ret = kr_error(errno);
			kr_log_error(PREFILL, "failed to get current time: %s\n",
					kr_strerror(ret));
			return ret;
		}
		z_import->timestamp_rr = now.tv_sec;
	}

   //// Initialize validator context with the DNSKEY.
	// TODO: for now we assume that the DS comes from pre-configured trust anchors;
	// later we should be able to fetch it from DNS, practically allowing non-root zones.
	const knot_rrset_t * const ds =
		kr_ta_get(&the_worker->engine->resolver.trust_anchors, z_import->origin);
	if (!ds) {
		kr_log_error(PREFILL, "no DS found for `%s`, fail\n", zone_name_str);
		return -1;
	}

	knot_rrset_t * const dnskey = rrset_get(z_import->rrsets, z_import->origin,
						KNOT_RRTYPE_DNSKEY, 0);
	if (!dnskey) {
		kr_log_error(PREFILL, "no DNSKEY found for `%s`, fail\n", zone_name_str);
		return -1;
	}
	knot_rrset_t * const dnskey_sigs = rrset_get(z_import->rrsets, z_import->origin,
						KNOT_RRTYPE_RRSIG, KNOT_RRTYPE_DNSKEY);
	if (!dnskey_sigs) {
		kr_log_error(PREFILL, "no RRSIGs for DNSKEY found for `%s`, fail\n",
				zone_name_str);
		return -1;
	}

	z_import->svldr = kr_svldr_new_ctx(ds, dnskey, &dnskey_sigs->rrs,
						z_import->timestamp_rr);
	if (!z_import->svldr) {
		kr_log_error(PREFILL, "failed to validate DNSKEY for `%s`\n", zone_name_str);
		return -1;
	}

#if ENABLE_ZONEMD
	ret = zonemd_verify(z_import);
	//if (ret) return ret;
#endif

	/* Zone have been parsed already, so start the import. */
	uv_timer_start(&z_import->timer, zi_zone_process, ZONE_IMPORT_PAUSE, 0);

	return 0;
}

bool zi_import_started(struct zone_import_ctx *z_import)
{
	return z_import ? z_import->started : false;
}
