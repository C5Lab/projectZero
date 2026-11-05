#ifndef ROUTER_CVE_VERIFY_H
#define ROUTER_CVE_VERIFY_H

#include "router_cve_db.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROUTER_CVE_SIG_HEADER_BYTES 80U
#define ROUTER_CVE_SIG_MAX_DER_BYTES 72U
#define ROUTER_CVE_SIG_MAX_BYTES (ROUTER_CVE_SIG_HEADER_BYTES + ROUTER_CVE_SIG_MAX_DER_BYTES)
#define ROUTER_CVE_INSTALL_JOURNAL_BYTES 128U
#define ROUTER_CVE_INSTALL_SLOT_COUNT 2U
#define ROUTER_CVE_MAX_TRUSTED_KEYS 4U
#define ROUTER_CVE_MAX_PUBLIC_KEY_BYTES 512U

typedef enum {
    ROUTER_CVE_VERIFY_OK = 0,
    ROUTER_CVE_VERIFY_BAD_FORMAT,
    ROUTER_CVE_VERIFY_BAD_HASH,
    ROUTER_CVE_VERIFY_BAD_SIGNATURE,
    ROUTER_CVE_VERIFY_UNKNOWN_KEY,
    ROUTER_CVE_VERIFY_NOT_YET_VALID,
    ROUTER_CVE_VERIFY_STALE,
    ROUTER_CVE_VERIFY_TIME_UNKNOWN,
    ROUTER_CVE_VERIFY_ROLLBACK,
    ROUTER_CVE_VERIFY_BUSY,
    ROUTER_CVE_VERIFY_IO,
    ROUTER_CVE_VERIFY_CAPACITY,
    ROUTER_CVE_VERIFY_PUBLISH,
    ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN,
    ROUTER_CVE_VERIFY_NOT_FOUND,
    ROUTER_CVE_VERIFY_RECOVERY
} router_cve_verify_result_t;

typedef struct {
    uint8_t key_id[16U];
    const uint8_t *subject_public_key_info;
    size_t subject_public_key_info_size;
} router_cve_trusted_key_t;

typedef bool (*router_cve_ecdsa_verify_fn)(
    void *context, const uint8_t *subject_public_key_info,
    size_t subject_public_key_info_size, const uint8_t digest[32U],
    const uint8_t *strict_der, size_t strict_der_size);

typedef struct {
    const router_cve_trusted_key_t *keys;
    size_t key_count;
    router_cve_ecdsa_verify_fn verify;
    void *context;
} router_cve_crypto_t;

typedef struct {
    bool reliable;
    uint64_t now_epoch;
    bool allow_unknown;
} router_cve_time_policy_t;

/* Apply the catalog validity-window policy shared by verification and
 * production status reporting. Creation times up to 24 hours in the future
 * are tolerated for bounded clock skew; expiry is exclusive. */
router_cve_verify_result_t router_cve_validate_catalog_time(
    uint64_t created_epoch, uint64_t expires_epoch,
    const router_cve_time_policy_t *time_policy);

typedef struct {
    router_cve_db_metadata_t catalog;
    uint8_t catalog_sha256[32U];
    uint8_t signature_sha256[32U];
    bool catalog_time_unknown;
} router_cve_verified_t;

typedef void (*router_cve_owned_release_fn)(void *context, void *data,
                                             size_t size);

/* A single immutable allocation transferred by the caller. Owned APIs move
 * and clear this handle before validation or callbacks and consume it on
 * every result. A NULL release uses free(); otherwise release must accept the
 * exact data/size pair. The caller must retain no aliases after transfer. */
typedef struct {
    uint8_t *data;
    size_t size;
    router_cve_owned_release_fn release;
    void *context;
} router_cve_owned_bytes_t;

router_cve_verify_result_t router_cve_verify_owned(
    router_cve_owned_bytes_t *catalog,
    router_cve_owned_bytes_t *signature,
    const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,
    router_cve_verified_t *verified);

router_cve_verify_result_t router_cve_verify_bytes(
    const uint8_t *catalog, size_t catalog_size,
    const uint8_t *signature, size_t signature_size,
    const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,
    router_cve_verified_t *verified);

typedef enum {
    ROUTER_CVE_OBJECT_SLOT0_CATALOG = 0,
    ROUTER_CVE_OBJECT_SLOT0_SIGNATURE,
    ROUTER_CVE_OBJECT_SLOT1_CATALOG,
    ROUTER_CVE_OBJECT_SLOT1_SIGNATURE,
    ROUTER_CVE_OBJECT_JOURNAL0,
    ROUTER_CVE_OBJECT_JOURNAL1,
    ROUTER_CVE_OBJECT_COUNT
} router_cve_install_object_t;

typedef enum {
    ROUTER_CVE_STORAGE_OK = 0,
    ROUTER_CVE_STORAGE_MISSING,
    ROUTER_CVE_STORAGE_ERROR
} router_cve_storage_result_t;

typedef struct {
    uint8_t slot;
    uint64_t generation;
    uint64_t serial;
    uint8_t catalog_sha256[32U];
    uint8_t signature_sha256[32U];
    uint8_t key_id[16U];
    bool catalog_time_unknown;
} router_cve_commit_record_t;

typedef struct {
    /* enter/leave serialize the complete trusted commit transaction. enter is
     * bounded and returns false rather than waiting forever. */
    bool (*enter)(void *context);
    void (*leave)(void *context);
    router_cve_storage_result_t (*read)(void *context,
        router_cve_install_object_t object, void *buffer, size_t capacity,
        size_t *size);
    bool (*write)(void *context, router_cve_install_object_t object,
                  const void *data, size_t size);
    bool (*write_atomic)(void *context, router_cve_install_object_t object,
                         const void *data, size_t size);
    bool (*sync)(void *context);
    bool (*get_commit)(void *context, router_cve_commit_record_t *commit,
                       bool *present);
    /* Atomic compare-and-advance in trusted NVS. The implementation must
     * reject stale expected records and every non-increasing serial or
     * generation. */
    bool (*advance_commit)(void *context,
                           const router_cve_commit_record_t *expected,
                           bool expected_present,
                           const router_cve_commit_record_t *desired);
    void *context;
} router_cve_install_ops_t;

typedef struct {
    uint8_t *catalog;
    size_t catalog_capacity;
    uint8_t *signature;
    size_t signature_capacity;
} router_cve_install_scratch_t;

typedef struct {
    bool available;
    uint8_t slot;
    uint64_t generation;
    uint64_t serial;
    uint8_t catalog_sha256[32U];
    uint8_t signature_sha256[32U];
    uint8_t key_id[16U];
    uint64_t created_epoch;
    uint64_t expires_epoch;
    bool installed_time_unknown;
    bool catalog_time_unknown;
} router_cve_install_status_t;

router_cve_verify_result_t router_cve_install_recover(
    const router_cve_install_ops_t *ops,
    const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,
    const router_cve_install_scratch_t *scratch,
    router_cve_install_status_t *status);

/* Production recovery/verify path. The input sizes are allocation
 * capacities. The exact trusted commit/journal pair is read into these
 * buffers; both handles are consumed on every result and no second
 * catalog-sized allocation is made. */
router_cve_verify_result_t router_cve_install_recover_owned(
    router_cve_owned_bytes_t *catalog_buffer,
    router_cve_owned_bytes_t *signature_buffer,
    const router_cve_install_ops_t *ops,
    const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,
    router_cve_install_status_t *status);

router_cve_verify_result_t router_cve_install_catalog(
    const uint8_t *catalog, size_t catalog_size,
    const uint8_t *signature, size_t signature_size,
    const router_cve_install_ops_t *ops,
    const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,
    const router_cve_install_scratch_t *scratch,
    router_cve_install_status_t *status);

/* Production install path. Consumes both handles on every result, uses the
 * catalog allocation as the inactive-slot readback buffer, and never
 * allocates a second catalog-sized buffer. */
router_cve_verify_result_t router_cve_install_catalog_owned(
    router_cve_owned_bytes_t *catalog,
    router_cve_owned_bytes_t *signature,
    const router_cve_install_ops_t *ops,
    const router_cve_crypto_t *crypto,
    const router_cve_time_policy_t *time_policy,
    router_cve_install_status_t *status);

/* Production adapter: the SPKI is selected by bounded key ID before this call.
 * Test builds normally inject router_cve_crypto_t.verify instead. */
bool router_cve_mbedtls_p256_verify(
    void *context, const uint8_t *subject_public_key_info,
    size_t subject_public_key_info_size, const uint8_t digest[32U],
    const uint8_t *strict_der, size_t strict_der_size);

#ifdef __cplusplus
}
#endif

#endif
