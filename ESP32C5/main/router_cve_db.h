#ifndef ROUTER_CVE_DB_H
#define ROUTER_CVE_DB_H

#include "router_fingerprint.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROUTER_CVE_DB_MAX_BYTES (4U * 1024U * 1024U)
#define ROUTER_CVE_DB_MAX_SOURCES 16U
#define ROUTER_CVE_DB_MAX_MODELS 128U
#define ROUTER_CVE_DB_MAX_ALIASES 256U
#define ROUTER_CVE_DB_MAX_ADVISORIES 256U
#define ROUTER_CVE_DB_MAX_FIRMWARE_RULES 1024U
#define ROUTER_CVE_DB_MAX_STRING_ENTRIES 2048U
#define ROUTER_CVE_DB_MAX_VALIDATION_WORK 4000000U
#define ROUTER_CVE_DB_SNAPSHOT_CHUNK 512U
#define ROUTER_CVE_CVE_MAX 255U
#define ROUTER_CVE_URL_MAX 255U
#define ROUTER_CVE_TEXT_MAX 255U
#define ROUTER_CVE_SOURCE_ID_MAX 64U
#define ROUTER_CVE_SEVERITY_MAX 8U

typedef enum {
    ROUTER_CVE_DB_OK = 0,
    ROUTER_CVE_DB_IO,
    ROUTER_CVE_DB_FORMAT,
    ROUTER_CVE_DB_CRC,
    ROUTER_CVE_DB_HASH,
    ROUTER_CVE_DB_CAPACITY,
    ROUTER_CVE_DB_NOT_FOUND
} router_cve_db_result_t;

typedef enum {
    ROUTER_CVE_NO_MATCH = 0,
    ROUTER_CVE_MODEL_CANDIDATE,
    ROUTER_CVE_EXACT_FIRMWARE
} router_cve_match_t;

typedef struct {
    router_cve_match_t match;
    char cve[ROUTER_CVE_CVE_MAX + 1U];
    char advisory_url[ROUTER_CVE_URL_MAX + 1U];
    char severity[ROUTER_CVE_SEVERITY_MAX + 1U];
    char kev_date[11U];
    char fixed_version[ROUTER_CVE_TEXT_MAX + 1U];
    char source_id[ROUTER_CVE_SOURCE_ID_MAX + 1U];
    bool kev;
    bool eol;
} router_cve_result_t;

typedef struct {
    uint32_t file_size;
    uint64_t created_epoch;
    uint64_t expires_epoch;
    uint64_t serial;
    uint8_t key_id[16U];
    uint8_t payload_sha256[32U];
    uint8_t provenance_sha256[32U];
    uint32_t source_count;
    uint32_t model_count;
    uint32_t alias_count;
    uint32_t advisory_count;
    uint32_t firmware_rule_count;
    uint32_t string_count;
    uint32_t validation_work;
    uint32_t snapshot_read_ops;
    uint32_t string_hash_bytes;
    uint32_t string_sort_comparisons;
    uint32_t string_compare_bytes;
} router_cve_db_metadata_t;

typedef void *(*router_cve_db_allocate_fn)(void *context, size_t size);
typedef void (*router_cve_db_release_fn)(void *context, void *memory,
                                         size_t size);

/* The allocator owns the immutable whole-file snapshot. Allocation failure
 * makes open return ROUTER_CVE_DB_CAPACITY; validated bytes are never reread
 * from mutable storage. NULL selects the bounded default allocator. */
typedef struct {
    router_cve_db_allocate_fn allocate;
    router_cve_db_release_fn release;
    void *context;
} router_cve_db_alloc_t;

typedef enum {
    ROUTER_CVE_IO_OK = 0,
    ROUTER_CVE_IO_MISSING,
    ROUTER_CVE_IO_ERROR
} router_cve_io_result_t;

typedef struct {
    router_cve_io_result_t (*open)(void *context, const char *path,
                                   void **handle);
    bool (*size)(void *context, void *handle, uint32_t *size);
    bool (*read_at)(void *context, void *handle, uint32_t offset,
                    void *buffer, size_t size);
    bool (*close)(void *context, void *handle);
    void *context;
} router_cve_db_io_t;

typedef struct router_cve_db router_cve_db_t;

router_cve_db_t *router_cve_db_open(const char *path,
                                    const router_cve_db_alloc_t *allocator,
                                    router_cve_db_result_t *result);

router_cve_db_t *router_cve_db_open_with_io(
    const char *path, const router_cve_db_alloc_t *allocator,
    const router_cve_db_io_t *io, router_cve_db_result_t *result);

/* Consumes a malloc-compatible immutable whole-file snapshot on every path.
 * The returned DB owns it until router_cve_db_close(). */
router_cve_db_t *router_cve_db_open_owned_snapshot(
    uint8_t *snapshot, uint32_t size, router_cve_db_result_t *result);

/* Same ownership transfer with an explicit snapshot releaser. The releaser
 * is called exactly once on every path; NULL selects the default free-based
 * releaser. Parser auxiliary allocations remain independently owned. */
router_cve_db_t *router_cve_db_open_owned_snapshot_with_release(
    uint8_t *snapshot, uint32_t size,
    router_cve_db_release_fn release, void *release_context,
    router_cve_db_result_t *result);

router_cve_db_result_t router_cve_db_metadata(
    const router_cve_db_t *db, router_cve_db_metadata_t *metadata);

router_cve_db_result_t router_cve_db_lookup(
    router_cve_db_t *db, const router_fingerprint_t *fingerprint,
    router_cve_result_t *results, size_t capacity, size_t *required);

void router_cve_db_close(router_cve_db_t *db);

#ifdef __cplusplus
}
#endif

#endif
