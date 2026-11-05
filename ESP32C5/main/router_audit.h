#ifndef ROUTER_AUDIT_H
#define ROUTER_AUDIT_H

#include "router_audit_core.h"
#include "router_audit_wire.h"
#include "router_cve_verify.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ROUTER_AUDIT_CVE_RESULT_MAX 16U
#define ROUTER_AUDIT_COMMAND_WORKSPACE_MIN (32U * 1024U)

typedef struct {
    bool available;
    uint64_t serial;
    uint64_t age_seconds;
    bool stale;
    bool time_unknown;
    bool incomplete_stage;
} router_audit_catalog_state_t;

typedef bool (*router_audit_snapshot_fn)(void *context,
    router_network_context_t *network);
typedef router_audit_result_t (*router_audit_collect_fn)(void *context,
    router_audit_mode_t mode, const router_network_context_t *network,
    router_evidence_set_t *evidence);
typedef router_cve_db_result_t (*router_audit_lookup_fn)(void *context,
    const router_fingerprint_t *fingerprint,
    router_cve_result_t *results, size_t capacity, size_t *required,
    router_audit_catalog_state_t *catalog);
typedef router_cve_verify_result_t (*router_audit_db_status_fn)(void *context,
    router_audit_catalog_state_t *catalog);
typedef router_cve_verify_result_t (*router_audit_db_verify_fn)(void *context,
    router_audit_catalog_state_t *catalog);
typedef router_cve_verify_result_t (*router_audit_db_install_fn)(void *context,
    bool allow_time_unknown, router_audit_catalog_state_t *catalog);
typedef bool (*router_audit_write_fn)(void *context, const char *line,
    size_t length);

typedef struct {
    router_audit_snapshot_fn snapshot;
    router_audit_collect_fn collect;
    router_audit_lookup_fn lookup;
    router_audit_db_status_fn db_status;
    router_audit_db_verify_fn db_verify;
    router_audit_db_install_fn db_install;
    router_audit_write_fn write;
    void *context;
    /* Caller-owned, aligned workspace. Production supplies PSRAM; the command
     * wipes it after every operation and never falls back to internal SRAM. */
    void *command_workspace;
    size_t command_workspace_size;
} router_audit_hooks_t;

bool router_audit_init(const router_audit_hooks_t *hooks);
int router_audit_command(int argc, char **argv);
bool router_audit_busy(void);
#if defined(ROUTER_AUDIT_TESTING)
bool router_audit_test_workspace_clear(void);
#endif

/* Release builds may provide a strong definition backed by reviewed public
 * trust anchors. The default weak definition returns an empty registry; test
 * keys are never compiled into production. */
size_t router_audit_provisioned_trusted_keys(
    const router_cve_trusted_key_t **keys);

#ifdef __cplusplus
}
#endif

#endif
