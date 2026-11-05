#include "router_audit.h"

#include <stdatomic.h>
#include <string.h>

static router_audit_hooks_t command_hooks;
static atomic_bool command_initialized = ATOMIC_VAR_INIT(false);
static atomic_bool command_busy = ATOMIC_VAR_INIT(false);
static atomic_int last_outcome = ATOMIC_VAR_INIT(ROUTER_AUDIT_OUTCOME_CATALOG_UNAVAILABLE);
static atomic_uint_fast64_t invocation_generation = ATOMIC_VAR_INIT(0U);
static atomic_uint_fast64_t telemetry_generation = ATOMIC_VAR_INIT(0U);
static atomic_flag telemetry_lock = ATOMIC_FLAG_INIT;

#define ROUTER_AUDIT_CONTROL_LINE_MAX 384U
#define ROUTER_AUDIT_COMMAND_STATE_MAX ROUTER_AUDIT_COMMAND_WORKSPACE_MIN

typedef struct {
    uint64_t generation;
    bool output_failed;
} router_audit_invocation_t;

typedef struct {
    router_network_context_t network;
    router_evidence_set_t evidence;
    router_fingerprint_t identity;
    router_cve_result_t results[ROUTER_AUDIT_CVE_RESULT_MAX];
    char line[ROUTER_AUDIT_LINE_MAX];
} router_audit_command_state_t;

static router_audit_command_state_t *command_state;
_Static_assert(sizeof(router_audit_command_state_t) <= ROUTER_AUDIT_COMMAND_STATE_MAX,
               "Router Audit command state exceeded its bounded arena");

#if defined(__GNUC__)
__attribute__((weak))
#endif
size_t router_audit_provisioned_trusted_keys(
    const router_cve_trusted_key_t **keys)
{
    if (keys != NULL) *keys = NULL;
    return 0U;
}

static router_audit_invocation_t invocation_begin(void)
{
    return (router_audit_invocation_t){
        .generation = atomic_fetch_add_explicit(
            &invocation_generation, 1U, memory_order_relaxed) + 1U,
    };
}

static void telemetry_publish(router_audit_outcome_t outcome)
{
    while (atomic_flag_test_and_set_explicit(&telemetry_lock,
                                              memory_order_acquire)) {
    }
    (void)atomic_fetch_add_explicit(&telemetry_generation, 1U,
                                    memory_order_relaxed);
    atomic_store_explicit(&last_outcome, outcome, memory_order_release);
    atomic_flag_clear_explicit(&telemetry_lock, memory_order_release);
}

static bool emit_line(router_audit_invocation_t *invocation, const char *line)
{
    if (invocation == NULL || line == NULL || command_hooks.write == NULL)
        return false;
    size_t length = strlen(line);
    if (length == 0U || length >= ROUTER_AUDIT_LINE_MAX ||
        !command_hooks.write(command_hooks.context, line, length)) {
        invocation->output_failed = true;
        return false;
    }
    return true;
}

static uint32_t bit_count(uint32_t value)
{
    uint32_t count = 0U;
    while (value != 0U) {
        count += value & 1U;
        value >>= 1U;
    }
    return count;
}

static router_audit_outcome_t verify_outcome(router_cve_verify_result_t result)
{
    switch (result) {
    case ROUTER_CVE_VERIFY_OK: return ROUTER_AUDIT_OUTCOME_OK;
    case ROUTER_CVE_VERIFY_BAD_FORMAT: return ROUTER_AUDIT_OUTCOME_BAD_FORMAT;
    case ROUTER_CVE_VERIFY_BAD_HASH: return ROUTER_AUDIT_OUTCOME_BAD_HASH;
    case ROUTER_CVE_VERIFY_BAD_SIGNATURE: return ROUTER_AUDIT_OUTCOME_BAD_SIGNATURE;
    case ROUTER_CVE_VERIFY_UNKNOWN_KEY: return ROUTER_AUDIT_OUTCOME_UNKNOWN_KEY;
    case ROUTER_CVE_VERIFY_NOT_YET_VALID: return ROUTER_AUDIT_OUTCOME_NOT_YET_VALID;
    case ROUTER_CVE_VERIFY_STALE: return ROUTER_AUDIT_OUTCOME_STALE;
    case ROUTER_CVE_VERIFY_TIME_UNKNOWN: return ROUTER_AUDIT_OUTCOME_TIME_UNKNOWN;
    case ROUTER_CVE_VERIFY_ROLLBACK: return ROUTER_AUDIT_OUTCOME_ROLLBACK;
    case ROUTER_CVE_VERIFY_BUSY: return ROUTER_AUDIT_OUTCOME_BUSY;
    case ROUTER_CVE_VERIFY_IO: return ROUTER_AUDIT_OUTCOME_IO_FAILED;
    case ROUTER_CVE_VERIFY_CAPACITY: return ROUTER_AUDIT_OUTCOME_CAPACITY_FAILED;
    case ROUTER_CVE_VERIFY_PUBLISH: return ROUTER_AUDIT_OUTCOME_PUBLISH_FAILED;
    case ROUTER_CVE_VERIFY_PUBLISHED_UNCERTAIN:
        return ROUTER_AUDIT_OUTCOME_PUBLISHED_UNCERTAIN;
    case ROUTER_CVE_VERIFY_RECOVERY: return ROUTER_AUDIT_OUTCOME_RECOVERY_FAILED;
    case ROUTER_CVE_VERIFY_NOT_FOUND:
    default: return ROUTER_AUDIT_OUTCOME_CATALOG_UNAVAILABLE;
    }
}

static bool db_status_readable(router_cve_verify_result_t result)
{
    return result == ROUTER_CVE_VERIFY_OK ||
           result == ROUTER_CVE_VERIFY_STALE ||
           result == ROUTER_CVE_VERIFY_TIME_UNKNOWN ||
           result == ROUTER_CVE_VERIFY_NOT_YET_VALID;
}

static bool claim_busy(void)
{
    bool expected = false;
    return atomic_compare_exchange_strong_explicit(
        &command_busy, &expected, true, memory_order_acq_rel, memory_order_acquire);
}

static void release_busy(void)
{
    memset(command_state, 0, sizeof(*command_state));
    atomic_store_explicit(&command_busy, false, memory_order_release);
}

static int emit_busy(router_audit_wire_mode_t mode)
{
    router_audit_invocation_t invocation = invocation_begin();
    char line[ROUTER_AUDIT_CONTROL_LINE_MAX];
    router_audit_terminal_t terminal = {
        .mode = mode,
        .confidence = ROUTER_CONFIDENCE_UNKNOWN,
        .outcome = ROUTER_AUDIT_OUTCOME_BUSY,
    };
    bool emitted = router_audit_wire_terminal(line, sizeof(line), &terminal) &&
                   emit_line(&invocation, line);
    router_audit_outcome_t outcome = emitted ? ROUTER_AUDIT_OUTCOME_BUSY :
                                               ROUTER_AUDIT_OUTCOME_OUTPUT_FAILED;
    telemetry_publish(outcome);
    return 1;
}

bool router_audit_init(const router_audit_hooks_t *hooks)
{
    if (hooks == NULL || hooks->snapshot == NULL || hooks->collect == NULL ||
        hooks->lookup == NULL || hooks->db_status == NULL ||
        hooks->db_verify == NULL || hooks->db_install == NULL ||
        hooks->write == NULL || hooks->command_workspace == NULL ||
        hooks->command_workspace_size < ROUTER_AUDIT_COMMAND_WORKSPACE_MIN ||
        (uintptr_t)hooks->command_workspace %
            _Alignof(router_audit_command_state_t) != 0U) return false;
    command_hooks = *hooks;
    command_state = hooks->command_workspace;
    memset(command_state, 0, sizeof(*command_state));
    atomic_store_explicit(&command_busy, false, memory_order_release);
    atomic_store_explicit(&invocation_generation, 0U, memory_order_release);
    atomic_store_explicit(&telemetry_generation, 0U, memory_order_release);
    atomic_flag_clear_explicit(&telemetry_lock, memory_order_release);
    atomic_store_explicit(&last_outcome, ROUTER_AUDIT_OUTCOME_CATALOG_UNAVAILABLE,
                          memory_order_release);
    atomic_store_explicit(&command_initialized, true, memory_order_release);
    return true;
}

bool router_audit_busy(void)
{
    return atomic_load_explicit(&command_busy, memory_order_acquire);
}

#if defined(ROUTER_AUDIT_TESTING)
bool router_audit_test_workspace_clear(void)
{
    if (router_audit_busy() || command_state == NULL) return false;
    const unsigned char *bytes = (const unsigned char *)command_state;
    for (size_t index = 0U; index < sizeof(*command_state); ++index)
        if (bytes[index] != 0U) return false;
    return true;
}
#endif

static int run_status(void)
{
    router_audit_invocation_t invocation = invocation_begin();
    router_audit_catalog_state_t catalog = {0};
    router_cve_verify_result_t db_result = command_hooks.db_status(
        command_hooks.context, &catalog);
    router_audit_status_record_t record = {
        .busy = router_audit_busy(),
        .available = catalog.available,
        .serial = catalog.serial,
        .stale = catalog.stale,
        .time_unknown = catalog.time_unknown,
        .db_outcome = verify_outcome(db_result),
        .outcome = (router_audit_outcome_t)atomic_load_explicit(
            &last_outcome, memory_order_acquire),
    };
    char line[ROUTER_AUDIT_CONTROL_LINE_MAX];
    bool ok = router_audit_wire_status(line, sizeof(line), &record) &&
              emit_line(&invocation, line);
    return ok ? 0 : 1;
}

static int run_scan(router_audit_mode_t mode)
{
    router_audit_wire_mode_t wire_mode = mode == ROUTER_AUDIT_PASSIVE ?
        ROUTER_AUDIT_WIRE_SCAN_PASSIVE : ROUTER_AUDIT_WIRE_SCAN_STANDARD_OWNED;
    if (!claim_busy()) return emit_busy(wire_mode);
    router_audit_invocation_t invocation = invocation_begin();
    memset(command_state, 0, sizeof(*command_state));
    router_network_context_t *network = &command_state->network;
    router_evidence_set_t *evidence = &command_state->evidence;
    router_fingerprint_t *identity = &command_state->identity;
    router_cve_result_t *results = command_state->results;
    char *line = command_state->line;
    router_audit_terminal_t terminal = {
        .mode = wire_mode,
        .confidence = ROUTER_CONFIDENCE_UNKNOWN,
        .outcome = ROUTER_AUDIT_OUTCOME_PRECONDITION_FAILED,
    };
    bool preconditions_ok = command_hooks.snapshot(command_hooks.context, network);
    router_audit_result_t result = preconditions_ok ? command_hooks.collect(
        command_hooks.context, mode, network, evidence) :
        ROUTER_AUDIT_RESULT_PRECONDITION;
    bool operation_ok = false;
    if (result == ROUTER_AUDIT_RESULT_OK || result == ROUTER_AUDIT_RESULT_PARTIAL) {
        operation_ok = evidence->count <= ROUTER_EVIDENCE_MAX &&
                       router_fingerprint_normalize(evidence->items,
                                                    evidence->count, identity);
        if (!operation_ok) result = ROUTER_AUDIT_RESULT_INVALID;
    }
    terminal.requests = evidence->request_count <= UINT32_MAX ?
        (uint32_t)evidence->request_count : UINT32_MAX;
    terminal.errors = bit_count(evidence->error_mask);
    terminal.evidence = (uint32_t)evidence->count;
    terminal.confidence = operation_ok ? identity->confidence : ROUTER_CONFIDENCE_UNKNOWN;
    bool sink_ok = true;
    if (operation_ok) {
        for (size_t index = 0U; index < evidence->count && sink_ok; ++index) {
            const router_evidence_t *item = &evidence->items[index];
            if (item->vendor[0] != '\0') sink_ok = router_audit_wire_evidence(
                line, ROUTER_AUDIT_LINE_MAX, item, "vendor", item->vendor, false) &&
                emit_line(&invocation, line);
            if (sink_ok && item->model[0] != '\0') sink_ok = router_audit_wire_evidence(
                line, ROUTER_AUDIT_LINE_MAX, item, "model", item->model, false) &&
                emit_line(&invocation, line);
            if (sink_ok && item->firmware[0] != '\0') sink_ok = router_audit_wire_evidence(
                line, ROUTER_AUDIT_LINE_MAX, item, "firmware", item->firmware, false) &&
                emit_line(&invocation, line);
        }
        if (sink_ok) sink_ok = router_audit_wire_identity(
            line, ROUTER_AUDIT_LINE_MAX, identity) && emit_line(&invocation, line);
    }
    router_audit_catalog_state_t catalog = {0};
    size_t required = 0U;
    if (sink_ok && operation_ok &&
        identity->confidence == ROUTER_CONFIDENCE_CONFIRMED &&
        !identity->conflict && !identity->truncated) {
        memset(results, 0, sizeof(command_state->results));
        router_cve_db_result_t lookup = command_hooks.lookup(
            command_hooks.context, identity, results,
            ROUTER_AUDIT_CVE_RESULT_MAX, &required, &catalog);
        if (lookup == ROUTER_CVE_DB_OK && required <= ROUTER_AUDIT_CVE_RESULT_MAX) {
            for (size_t index = 0U; index < required && sink_ok; ++index) {
                if (results[index].match == ROUTER_CVE_EXACT_FIRMWARE)
                    ++terminal.exact;
                else if (results[index].match == ROUTER_CVE_MODEL_CANDIDATE)
                    ++terminal.candidates;
                else {
                    sink_ok = false;
                    break;
                }
                sink_ok = router_audit_wire_cve(
                    line, ROUTER_AUDIT_LINE_MAX, &results[index], catalog.serial,
                    catalog.age_seconds, catalog.stale, catalog.time_unknown) &&
                    emit_line(&invocation, line);
            }
            terminal.outcome = terminal.exact > 0U ?
                ROUTER_AUDIT_OUTCOME_EXACT_FIRMWARE_MATCH :
                terminal.candidates > 0U ? ROUTER_AUDIT_OUTCOME_CANDIDATE_MANUAL_CHECK :
                                           ROUTER_AUDIT_OUTCOME_NO_CATALOG_MATCH;
        } else if (lookup == ROUTER_CVE_DB_NOT_FOUND) {
            terminal.outcome = ROUTER_AUDIT_OUTCOME_NO_CATALOG_MATCH;
        } else {
            terminal.outcome = lookup == ROUTER_CVE_DB_CAPACITY ?
                ROUTER_AUDIT_OUTCOME_CAPACITY_FAILED : ROUTER_AUDIT_OUTCOME_CATALOG_UNAVAILABLE;
        }
    }
    if (result == ROUTER_AUDIT_RESULT_PRECONDITION) {
        terminal.outcome = ROUTER_AUDIT_OUTCOME_PRECONDITION_FAILED;
    } else if (result == ROUTER_AUDIT_RESULT_CANCELLED) {
        terminal.outcome = ROUTER_AUDIT_OUTCOME_CANCELLED;
    } else if (result == ROUTER_AUDIT_RESULT_INVALID) {
        terminal.outcome = ROUTER_AUDIT_OUTCOME_INVALID;
    } else if (result == ROUTER_AUDIT_RESULT_PARTIAL || evidence->error_mask != 0U) {
        terminal.outcome = ROUTER_AUDIT_OUTCOME_PARTIAL;
    } else if (operation_ok &&
               (identity->confidence != ROUTER_CONFIDENCE_CONFIRMED ||
                identity->conflict || identity->truncated)) {
        terminal.outcome = ROUTER_AUDIT_OUTCOME_IDENTITY_UNKNOWN;
    }
    if (!sink_ok || invocation.output_failed)
        terminal.outcome = ROUTER_AUDIT_OUTCOME_OUTPUT_FAILED;
    bool terminal_ok = sink_ok && router_audit_wire_terminal(
        line, ROUTER_AUDIT_LINE_MAX, &terminal) && emit_line(&invocation, line);
    if (!terminal_ok && invocation.output_failed)
        terminal.outcome = ROUTER_AUDIT_OUTCOME_OUTPUT_FAILED;
    telemetry_publish(terminal.outcome);
    int command_result = terminal_ok &&
        (result == ROUTER_AUDIT_RESULT_OK ||
         result == ROUTER_AUDIT_RESULT_PARTIAL) ? 0 : 1;
    release_busy();
    return command_result;
}

static int run_db(router_audit_wire_mode_t mode, bool allow_time_unknown)
{
    if (!claim_busy()) return emit_busy(mode);
    router_audit_invocation_t invocation = invocation_begin();
    memset(command_state, 0, sizeof(*command_state));
    router_audit_catalog_state_t catalog = {0};
    router_cve_verify_result_t result = mode == ROUTER_AUDIT_WIRE_DB_VERIFY ?
        command_hooks.db_verify(command_hooks.context, &catalog) :
        command_hooks.db_install(command_hooks.context, allow_time_unknown, &catalog);
    char line[ROUTER_AUDIT_CONTROL_LINE_MAX];
    router_audit_outcome_t operation_outcome = verify_outcome(result);
    if (catalog.incomplete_stage)
        operation_outcome = ROUTER_AUDIT_OUTCOME_INCOMPLETE_STAGE;
    router_audit_status_record_t status = {
        .busy = true, .available = catalog.available, .serial = catalog.serial,
        .stale = catalog.stale, .time_unknown = catalog.time_unknown,
        .db_outcome = operation_outcome,
        .outcome = operation_outcome,
    };
    bool ok = router_audit_wire_status(line, sizeof(line), &status) &&
              emit_line(&invocation, line);
    router_audit_terminal_t terminal = {
        .mode = mode,
        .confidence = ROUTER_CONFIDENCE_UNKNOWN,
        .outcome = operation_outcome,
    };
    if (invocation.output_failed)
        terminal.outcome = ROUTER_AUDIT_OUTCOME_OUTPUT_FAILED;
    bool terminal_ok = router_audit_wire_terminal(line, sizeof(line), &terminal) &&
                       emit_line(&invocation, line);
    ok = ok && terminal_ok;
    if (!terminal_ok && invocation.output_failed)
        terminal.outcome = ROUTER_AUDIT_OUTCOME_OUTPUT_FAILED;
    telemetry_publish(terminal.outcome);
    int command_result = ok && result == ROUTER_CVE_VERIFY_OK ? 0 : 1;
    release_busy();
    return command_result;
}

static int run_db_status(void)
{
    router_audit_invocation_t invocation = invocation_begin();
    router_audit_catalog_state_t catalog = {0};
    router_cve_verify_result_t result = command_hooks.db_status(
        command_hooks.context, &catalog);
    router_audit_outcome_t outcome = verify_outcome(result);
    router_audit_status_record_t status = {
        .busy = router_audit_busy(),
        .available = catalog.available,
        .serial = catalog.serial,
        .stale = catalog.stale,
        .time_unknown = catalog.time_unknown,
        .db_outcome = outcome,
        .outcome = outcome,
    };
    char line[ROUTER_AUDIT_CONTROL_LINE_MAX];
    bool ok = router_audit_wire_status(line, sizeof(line), &status) &&
              emit_line(&invocation, line);
    router_audit_terminal_t terminal = {
        .mode = ROUTER_AUDIT_WIRE_DB_STATUS,
        .confidence = ROUTER_CONFIDENCE_UNKNOWN,
        .outcome = outcome,
    };
    if (!ok || invocation.output_failed)
        terminal.outcome = ROUTER_AUDIT_OUTCOME_OUTPUT_FAILED;
    bool terminal_ok = router_audit_wire_terminal(line, sizeof(line), &terminal) &&
                       emit_line(&invocation, line);
    ok = ok && terminal_ok;
    if (!terminal_ok && invocation.output_failed)
        terminal.outcome = ROUTER_AUDIT_OUTCOME_OUTPUT_FAILED;
    return ok && db_status_readable(result) ? 0 : 1;
}

int router_audit_command(int argc, char **argv)
{
    if (!atomic_load_explicit(&command_initialized, memory_order_acquire) ||
        argc < 2 || argv == NULL || argv[0] == NULL) return 1;
    if (argc == 2 && strcmp(argv[1], "status") == 0) {
        return run_status();
    }
    if (strcmp(argv[1], "scan") == 0) {
        if (argc == 3 && strcmp(argv[2], "passive") == 0)
            return run_scan(ROUTER_AUDIT_PASSIVE);
        if (argc == 4 && strcmp(argv[2], "standard") == 0 &&
            strcmp(argv[3], "--owned") == 0)
            return run_scan(ROUTER_AUDIT_STANDARD_OWNED);
        return 1;
    }
    if (strcmp(argv[1], "db") != 0) return 1;
    if (argc == 3 && strcmp(argv[2], "status") == 0) {
        return run_db_status();
    }
    if (argc == 3 && strcmp(argv[2], "verify") == 0)
        return run_db(ROUTER_AUDIT_WIRE_DB_VERIFY, false);
    if ((argc == 3 || argc == 4) && strcmp(argv[2], "install") == 0) {
        if (argc == 4 && strcmp(argv[3], "--allow-time-unknown") != 0) return 1;
        return run_db(ROUTER_AUDIT_WIRE_DB_INSTALL, argc == 4);
    }
    return 1;
}
