#include "router_audit.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char output[8192];
    size_t used;
    unsigned collect_calls;
    unsigned lookup_calls;
    unsigned verify_calls;
    unsigned install_calls;
    unsigned write_calls;
    unsigned fail_at_write;
    bool fail_write;
    bool recursive_busy_checked;
    bool snapshot_ok;
    router_audit_result_t collect_result;
    uint32_t collect_error_mask;
    uint32_t collect_requests;
    bool probable_identity;
    bool unknown_identity;
    bool conflicting_identity;
    router_cve_db_result_t lookup_result;
    router_cve_match_t lookup_match;
    size_t lookup_required;
    bool catalog_stale;
    bool catalog_time_unknown;
    router_cve_verify_result_t db_status_result;
    bool nested_status_sink_failure;
    bool db_incomplete_stage;
} fixture_t;

static bool snapshot(void *context, router_network_context_t *network)
{
    (void)context;
    *network = (router_network_context_t){
        .sta_connected = true,
        .local_ipv4 = UINT32_C(0xC0000202),
        .netmask_ipv4 = UINT32_C(0xFFFFFF00),
        .gateway_ipv4 = UINT32_C(0xC0000201),
        .bssid_known = true,
        .bssid = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
    };
    return ((fixture_t *)context)->snapshot_ok;
}

static router_audit_result_t collect(void *context, router_audit_mode_t mode,
                                     const router_network_context_t *network,
                                     router_evidence_set_t *evidence)
{
    fixture_t *fixture = context;
    assert(network->gateway_ipv4 == UINT32_C(0xC0000201));
    ++fixture->collect_calls;
    if (!fixture->recursive_busy_checked) {
        fixture->recursive_busy_checked = true;
        char *again[] = {"router_audit", "scan", "passive"};
        assert(router_audit_command(3, again) == 1);
    }
    *evidence = (router_evidence_set_t){0};
    if (fixture->unknown_identity) {
        evidence->items[0].source = ROUTER_EVIDENCE_OUI;
        strcpy(evidence->items[0].vendor, "lab vendor");
        evidence->count = 1U;
        evidence->request_count = fixture->collect_requests;
        return fixture->collect_result;
    }
    if (fixture->probable_identity) {
        evidence->items[0].source = ROUTER_EVIDENCE_HTTP_TITLE;
        strcpy(evidence->items[0].model, "router-one");
        evidence->count = 1U;
        evidence->request_count = fixture->collect_requests;
        return fixture->collect_result;
    }
    evidence->items[0].source = ROUTER_EVIDENCE_OUI;
    strcpy(evidence->items[0].vendor, "lab vendor");
    evidence->items[1].source = ROUTER_EVIDENCE_UPNP_STRUCTURED;
    strcpy(evidence->items[1].vendor, "lab vendor");
    strcpy(evidence->items[1].model, "router-one");
    strcpy(evidence->items[1].firmware, "1.2.3");
    evidence->count = 2U;
    if (fixture->conflicting_identity) {
        evidence->items[2].source = ROUTER_EVIDENCE_UPNP_STRUCTURED;
        strcpy(evidence->items[2].vendor, "lab vendor");
        strcpy(evidence->items[2].model, "router-two");
        strcpy(evidence->items[2].firmware, "9.9.9");
        evidence->count = 3U;
    }
    evidence->error_mask = fixture->collect_error_mask;
    evidence->request_count = fixture->collect_requests;
    evidence->ssdp_responses = mode == ROUTER_AUDIT_STANDARD_OWNED ? 1U : 0U;
    if (fixture->nested_status_sink_failure) {
        router_evidence_set_t before = *evidence;
        fixture->nested_status_sink_failure = false;
        fixture->fail_write = true;
        char *status[] = {"router_audit", "status"};
        assert(router_audit_command(2, status) == 1);
        fixture->fail_write = false;
        assert(memcmp(evidence, &before, sizeof(before)) == 0);
    }
    return fixture->collect_result;
}

static router_cve_db_result_t lookup(
    void *context, const router_fingerprint_t *fingerprint,
    router_cve_result_t *results, size_t capacity, size_t *required,
    router_audit_catalog_state_t *catalog)
{
    fixture_t *fixture = context;
    ++fixture->lookup_calls;
    assert(strcmp(fingerprint->model, "router one") == 0);
    *required = fixture->lookup_required;
    *catalog = (router_audit_catalog_state_t){
        .available = fixture->lookup_result == ROUTER_CVE_DB_OK ||
                     fixture->lookup_result == ROUTER_CVE_DB_NOT_FOUND,
        .serial = 7U, .age_seconds = 12U,
        .stale = fixture->catalog_stale,
        .time_unknown = fixture->catalog_time_unknown,
    };
    if (fixture->lookup_result != ROUTER_CVE_DB_OK)
        return fixture->lookup_result;
    assert(fixture->lookup_required <= capacity);
    memset(results, 0, sizeof(*results));
    if (fixture->lookup_required > 0U) {
        results[0].match = fixture->lookup_match;
        strcpy(results[0].cve, "CVE-2099-0001");
        strcpy(results[0].severity, "high");
        strcpy(results[0].advisory_url, "https://security.example.invalid/a");
    }
    return ROUTER_CVE_DB_OK;
}

static router_cve_verify_result_t db_verify(void *context,
    router_audit_catalog_state_t *catalog)
{
    fixture_t *fixture = context;
    ++fixture->verify_calls;
    *catalog = (router_audit_catalog_state_t){
        .available = true, .serial = 7U,
        .incomplete_stage = fixture->db_incomplete_stage,
    };
    if (fixture->db_incomplete_stage) return ROUTER_CVE_VERIFY_NOT_FOUND;
    return ROUTER_CVE_VERIFY_OK;
}

static router_cve_verify_result_t db_install(void *context, bool allow_unknown,
    router_audit_catalog_state_t *catalog)
{
    fixture_t *fixture = context;
    ++fixture->install_calls;
    *catalog = (router_audit_catalog_state_t){
        .available = true, .serial = 8U, .time_unknown = allow_unknown,
    };
    return ROUTER_CVE_VERIFY_OK;
}

static router_cve_verify_result_t db_status(
    void *context, router_audit_catalog_state_t *catalog)
{
    fixture_t *fixture = context;
    *catalog = (router_audit_catalog_state_t){
        .available = fixture->db_status_result == ROUTER_CVE_VERIFY_OK ||
                     fixture->db_status_result == ROUTER_CVE_VERIFY_STALE ||
                     fixture->db_status_result == ROUTER_CVE_VERIFY_TIME_UNKNOWN ||
                     fixture->db_status_result == ROUTER_CVE_VERIFY_NOT_YET_VALID,
        .serial = 7U,
        .stale = fixture->db_status_result == ROUTER_CVE_VERIFY_STALE,
        .time_unknown = fixture->db_status_result == ROUTER_CVE_VERIFY_TIME_UNKNOWN,
    };
    return fixture->db_status_result;
}

static bool write_line(void *context, const char *line, size_t length)
{
    fixture_t *fixture = context;
    ++fixture->write_calls;
    if (fixture->fail_write ||
        (fixture->fail_at_write != 0U &&
         fixture->write_calls == fixture->fail_at_write) || length == 0U ||
        fixture->used + length >= sizeof(fixture->output)) return false;
    memcpy(fixture->output + fixture->used, line, length);
    fixture->used += length;
    fixture->output[fixture->used] = '\0';
    return true;
}

static void reset_output(fixture_t *fixture)
{
    fixture->used = 0U;
    fixture->write_calls = 0U;
    fixture->output[0] = '\0';
}

int main(void)
{
    _Alignas(max_align_t) static unsigned char command_workspace[
        ROUTER_AUDIT_COMMAND_WORKSPACE_MIN];
    fixture_t fixture = {
        .snapshot_ok = true,
        .collect_requests = 2U,
        .lookup_result = ROUTER_CVE_DB_OK,
        .lookup_match = ROUTER_CVE_EXACT_FIRMWARE,
        .lookup_required = 1U,
        .db_status_result = ROUTER_CVE_VERIFY_OK,
    };
    router_audit_hooks_t hooks = {
        .snapshot = snapshot,
        .collect = collect,
        .lookup = lookup,
        .db_status = db_status,
        .db_verify = db_verify,
        .db_install = db_install,
        .write = write_line,
        .context = &fixture,
        .command_workspace = command_workspace,
        .command_workspace_size = sizeof(command_workspace),
    };
    router_audit_hooks_t missing_workspace = hooks;
    missing_workspace.command_workspace = NULL;
    assert(!router_audit_init(&missing_workspace));
    router_audit_hooks_t short_workspace = hooks;
    short_workspace.command_workspace_size =
        ROUTER_AUDIT_COMMAND_WORKSPACE_MIN - 1U;
    assert(!router_audit_init(&short_workspace));
    assert(router_audit_init(&hooks));

    char *passive[] = {"router_audit", "scan", "passive"};
    assert(router_audit_command(3, passive) == 0);
    assert(fixture.collect_calls == 1U && fixture.lookup_calls == 1U);
    assert(strstr(fixture.output, "CATALOG_SERIAL=7") != NULL);
    assert(strstr(fixture.output, "MODE=passive REQUESTS=0") != NULL);
    assert(strstr(fixture.output, "OUTCOME=exact_firmware_match") != NULL);
    assert(strstr(fixture.output, "OUTCOME=busy") != NULL);
    assert(strstr(fixture.output, "vulnerable") == NULL);
    assert(strstr(fixture.output, "exploitable") == NULL);
    assert(!router_audit_busy());
    assert(router_audit_test_workspace_clear());

    reset_output(&fixture);
    fixture.nested_status_sink_failure = true;
    assert(router_audit_command(3, passive) == 0);
    assert(strstr(fixture.output, "OUTCOME=exact_firmware_match") != NULL);
    assert(strstr(fixture.output, "OUTCOME=output_failed") == NULL);
    assert(router_audit_test_workspace_clear());

    reset_output(&fixture);
    char *standard_missing[] = {"router_audit", "scan", "standard"};
    assert(router_audit_command(3, standard_missing) == 1);
    assert(fixture.collect_calls == 2U);
    char *standard[] = {"router_audit", "scan", "standard", "--owned"};
    assert(router_audit_command(4, standard) == 0);
    assert(strstr(fixture.output, "MODE=standard REQUESTS=2") != NULL);

    reset_output(&fixture);
    fixture.collect_result = ROUTER_AUDIT_RESULT_PARTIAL;
    fixture.collect_error_mask = ROUTER_AUDIT_ERROR_HTTP;
    assert(router_audit_command(3, passive) == 0);
    assert(strstr(fixture.output, "ERRORS=1") != NULL);
    assert(strstr(fixture.output, "OUTCOME=partial") != NULL);
    fixture.collect_result = ROUTER_AUDIT_RESULT_OK;
    fixture.collect_error_mask = 0U;

    reset_output(&fixture);
    fixture.collect_result = ROUTER_AUDIT_RESULT_CANCELLED;
    unsigned lookups_before_cancel = fixture.lookup_calls;
    assert(router_audit_command(3, passive) == 1);
    assert(fixture.lookup_calls == lookups_before_cancel);
    assert(strstr(fixture.output, "OUTCOME=cancelled") != NULL);

    reset_output(&fixture);
    fixture.collect_result = ROUTER_AUDIT_RESULT_INVALID;
    assert(router_audit_command(3, passive) == 1);
    assert(fixture.lookup_calls == lookups_before_cancel);
    assert(strstr(fixture.output, "OUTCOME=invalid") != NULL);
    fixture.collect_result = ROUTER_AUDIT_RESULT_OK;

    reset_output(&fixture);
    fixture.probable_identity = true;
    unsigned lookups_before_probable = fixture.lookup_calls;
    assert(router_audit_command(3, passive) == 0);
    assert(fixture.lookup_calls == lookups_before_probable);
    assert(strstr(fixture.output, "CONFIDENCE=probable") != NULL);
    assert(strstr(fixture.output, "OUTCOME=identity_unknown") != NULL);
    assert(strstr(fixture.output, "[ROUTER_AUDIT/1] CVE") == NULL);
    fixture.probable_identity = false;

    reset_output(&fixture);
    fixture.unknown_identity = true;
    unsigned lookups_before_unknown = fixture.lookup_calls;
    assert(router_audit_command(3, passive) == 0);
    assert(fixture.lookup_calls == lookups_before_unknown);
    assert(strstr(fixture.output, "CONFIDENCE=unknown") != NULL);
    assert(strstr(fixture.output, "OUTCOME=identity_unknown") != NULL);
    fixture.unknown_identity = false;

    reset_output(&fixture);
    fixture.conflicting_identity = true;
    unsigned lookups_before_conflict = fixture.lookup_calls;
    assert(router_audit_command(3, passive) == 0);
    assert(fixture.lookup_calls == lookups_before_conflict);
    assert(strstr(fixture.output, "CONFLICT=1") != NULL);
    assert(strstr(fixture.output, "OUTCOME=identity_unknown") != NULL);
    fixture.conflicting_identity = false;

    reset_output(&fixture);
    fixture.lookup_match = ROUTER_CVE_MODEL_CANDIDATE;
    assert(router_audit_command(3, passive) == 0);
    assert(strstr(fixture.output, "MATCH=candidate_manual_check") != NULL);
    assert(strstr(fixture.output, "OUTCOME=candidate_manual_check") != NULL);
    fixture.lookup_match = ROUTER_CVE_EXACT_FIRMWARE;

    reset_output(&fixture);
    fixture.catalog_stale = true;
    fixture.catalog_time_unknown = true;
    assert(router_audit_command(3, passive) == 0);
    assert(strstr(fixture.output, "STALE=1 TIME_UNKNOWN=1") != NULL);
    fixture.catalog_stale = false;
    fixture.catalog_time_unknown = false;

    reset_output(&fixture);
    fixture.lookup_result = ROUTER_CVE_DB_NOT_FOUND;
    fixture.lookup_required = 0U;
    assert(router_audit_command(3, passive) == 0);
    assert(strstr(fixture.output, "OUTCOME=no_catalog_match") != NULL);
    assert(strstr(fixture.output, "[ROUTER_AUDIT/1] CVE") == NULL);

    reset_output(&fixture);
    fixture.lookup_result = ROUTER_CVE_DB_FORMAT;
    assert(router_audit_command(3, passive) == 0);
    assert(strstr(fixture.output, "OUTCOME=catalog_unavailable") != NULL);

    reset_output(&fixture);
    fixture.lookup_result = ROUTER_CVE_DB_CAPACITY;
    fixture.lookup_required = ROUTER_AUDIT_CVE_RESULT_MAX + 1U;
    assert(router_audit_command(3, passive) == 0);
    assert(strstr(fixture.output, "OUTCOME=capacity_failed") != NULL);
    fixture.lookup_result = ROUTER_CVE_DB_OK;
    fixture.lookup_required = 1U;

    reset_output(&fixture);
    fixture.fail_at_write = 7U; /* END after four evidence, identity and CVE. */
    assert(router_audit_command(3, passive) == 1);
    fixture.fail_at_write = 0U;
    reset_output(&fixture);
    char *status_after_terminal_failure[] = {"router_audit", "status"};
    assert(router_audit_command(2, status_after_terminal_failure) == 0);
    assert(strstr(fixture.output, "OUTCOME=output_failed") != NULL);

    reset_output(&fixture);
    fixture.snapshot_ok = false;
    assert(router_audit_command(3, passive) == 1);
    assert(strstr(fixture.output, "OUTCOME=precondition_failed") != NULL);
    fixture.snapshot_ok = true;

    reset_output(&fixture);
    char *status[] = {"router_audit", "status"};
    assert(router_audit_command(2, status) == 0);
    assert(strstr(fixture.output, "[ROUTER_AUDIT/1] STATUS") != NULL);
    assert(strstr(fixture.output, "DB_OUTCOME=ok") != NULL);
    assert(strstr(fixture.output, "OUTCOME=precondition_failed") != NULL);
    reset_output(&fixture);
    fixture.db_status_result = ROUTER_CVE_VERIFY_RECOVERY;
    assert(router_audit_command(2, status) == 0);
    assert(strstr(fixture.output, "DB_AVAILABLE=0") != NULL);
    assert(strstr(fixture.output, "DB_OUTCOME=recovery_failed") != NULL);
    assert(strstr(fixture.output, "OUTCOME=precondition_failed") != NULL);
    fixture.db_status_result = ROUTER_CVE_VERIFY_OK;

    reset_output(&fixture);
    char *db_status_argv[] = {"router_audit", "db", "status"};
    assert(router_audit_command(3, db_status_argv) == 0);
    assert(strstr(fixture.output, "END MODE=db_status") != NULL);
    assert(strstr(fixture.output, "DB_OUTCOME=ok") != NULL);
    reset_output(&fixture);
    fixture.db_status_result = ROUTER_CVE_VERIFY_STALE;
    assert(router_audit_command(3, db_status_argv) == 0);
    assert(strstr(fixture.output, "DB_AVAILABLE=1") != NULL);
    assert(strstr(fixture.output, "STALE=1") != NULL);
    assert(strstr(fixture.output, "DB_OUTCOME=stale") != NULL);
    reset_output(&fixture);
    fixture.db_status_result = ROUTER_CVE_VERIFY_TIME_UNKNOWN;
    assert(router_audit_command(3, db_status_argv) == 0);
    assert(strstr(fixture.output, "DB_AVAILABLE=1") != NULL);
    assert(strstr(fixture.output, "TIME_UNKNOWN=1") != NULL);
    assert(strstr(fixture.output, "DB_OUTCOME=time_unknown") != NULL);
    reset_output(&fixture);
    fixture.db_status_result = ROUTER_CVE_VERIFY_NOT_YET_VALID;
    assert(router_audit_command(3, db_status_argv) == 0);
    assert(strstr(fixture.output, "DB_AVAILABLE=1") != NULL);
    assert(strstr(fixture.output, "DB_OUTCOME=not_yet_valid") != NULL);
    const struct {
        router_cve_verify_result_t result;
        const char *outcome;
    } db_failures[] = {
        {ROUTER_CVE_VERIFY_NOT_FOUND, "catalog_unavailable"},
        {ROUTER_CVE_VERIFY_RECOVERY, "recovery_failed"},
        {ROUTER_CVE_VERIFY_IO, "io_failed"},
        {ROUTER_CVE_VERIFY_UNKNOWN_KEY, "unknown_key"},
        {ROUTER_CVE_VERIFY_CAPACITY, "capacity_failed"},
    };
    for (size_t index = 0U;
         index < sizeof(db_failures) / sizeof(db_failures[0]); ++index) {
        reset_output(&fixture);
        fixture.db_status_result = db_failures[index].result;
        assert(router_audit_command(3, db_status_argv) == 1);
        assert(strstr(fixture.output, "DB_AVAILABLE=0") != NULL);
        char expected[64];
        int written = snprintf(expected, sizeof(expected), "DB_OUTCOME=%s",
                               db_failures[index].outcome);
        assert(written > 0 && (size_t)written < sizeof(expected));
        assert(strstr(fixture.output, expected) != NULL);
    }
    fixture.db_status_result = ROUTER_CVE_VERIFY_OK;
    char *db_verify_argv[] = {"router_audit", "db", "verify"};
    assert(router_audit_command(3, db_verify_argv) == 0);
    assert(fixture.verify_calls == 1U);
    reset_output(&fixture);
    fixture.db_incomplete_stage = true;
    assert(router_audit_command(3, db_verify_argv) == 1);
    assert(strstr(fixture.output, "OUTCOME=incomplete_stage") != NULL);
    fixture.db_incomplete_stage = false;
    char *db_install_argv[] = {"router_audit", "db", "install",
                               "--allow-time-unknown"};
    assert(router_audit_command(4, db_install_argv) == 0);
    assert(fixture.install_calls == 1U);
    assert(strstr(fixture.output, "TIME_UNKNOWN=1") != NULL);

    char *bad[] = {"router_audit", "db", "install", "--owned"};
    assert(router_audit_command(4, bad) == 1);
    char *trailing[] = {"router_audit", "status", "extra"};
    assert(router_audit_command(3, trailing) == 1);
    char *missing_scan[] = {"router_audit", "scan"};
    char *passive_extra[] = {"router_audit", "scan", "passive", "extra"};
    char *standard_flag[] = {"router_audit", "scan", "standard", "--OWNED"};
    char *db_only[] = {"router_audit", "db"};
    char *verify_flag[] = {"router_audit", "db", "verify", "--allow-time-unknown"};
    char *unknown[] = {"router_audit", "lookup"};
    assert(router_audit_command(2, missing_scan) == 1);
    assert(router_audit_command(4, passive_extra) == 1);
    assert(router_audit_command(4, standard_flag) == 1);
    assert(router_audit_command(2, db_only) == 1);
    assert(router_audit_command(4, verify_flag) == 1);
    assert(router_audit_command(2, unknown) == 1);

    fixture.fail_write = true;
    assert(router_audit_command(2, status) == 1);
    fixture.fail_write = false;
    reset_output(&fixture);
    assert(router_audit_command(2, status) == 0);
    assert(strstr(fixture.output, "OUTCOME=ok") != NULL);
    assert(strstr(fixture.output, "OUTCOME=output_failed") == NULL);
    assert(!router_audit_busy());

    puts("PASS: Router Audit CLI, bounded operations, evidence records");
    return 0;
}
