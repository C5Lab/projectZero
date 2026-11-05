#include "sae_guard.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    sae_guard_runtime_hooks_t runtime;
    sae_guard_output_hooks_t output;
    sae_guard_core_t core;
    sae_guard_status_t last_status;
    wifi_shield_target_t *targets;
    size_t target_count;
    size_t allocation_count;
    uint32_t report_sequence;
    uint32_t runtime_baseline_generation;
    uint64_t next_epoch;
    uint64_t active_epoch;
    uintptr_t active_context_token;
    uint64_t next_cleanup_attempt;
    uint64_t active_cleanup_attempt;
    uint64_t terminal_claimed_attempt;
    uint32_t cleanup_attempt_participants;
    bool initialized;
    bool starting;
    bool runtime_start_committed;
    bool running;
    bool stopping;
    bool cancel_requested;
    bool output_failed;
} sae_guard_state_t;

static sae_guard_state_t guard;
/* Opaque session tokens are never dereferenced. Keeping the sequence outside
 * guard prevents sae_guard_init() in host fixtures from reusing an old token. */
static uintptr_t next_context_token;

static void enter(void)
{
    guard.runtime.enter(guard.runtime.context);
}

static void leave(void)
{
    guard.runtime.leave(guard.runtime.context);
}

static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (bytes != NULL && size-- != 0U) *bytes++ = 0U;
}

static void increment(uint32_t *value)
{
    if (*value != UINT32_MAX) ++*value;
}

static uint32_t saturated_add(uint32_t left, uint32_t right)
{
    return UINT32_MAX - left < right ? UINT32_MAX : left + right;
}

static bool context_live_locked(void)
{
    return guard.targets != NULL || guard.starting || guard.running ||
           guard.stopping;
}

static bool context_matches_locked(const void *context)
{
    return context != NULL && guard.active_context_token != 0U &&
           (uintptr_t)context == guard.active_context_token;
}

static uint64_t join_cleanup_attempt_locked(void)
{
    if (guard.active_cleanup_attempt == 0U) {
        ++guard.next_cleanup_attempt;
        if (guard.next_cleanup_attempt == 0U) ++guard.next_cleanup_attempt;
        guard.active_cleanup_attempt = guard.next_cleanup_attempt;
        guard.cleanup_attempt_participants = 0U;
    }
    increment(&guard.cleanup_attempt_participants);
    return guard.active_cleanup_attempt;
}

static void leave_cleanup_attempt(uint64_t attempt)
{
    if (attempt == 0U) return;
    enter();
    if (guard.active_cleanup_attempt == attempt &&
        guard.cleanup_attempt_participants != 0U) {
        --guard.cleanup_attempt_participants;
        if (guard.cleanup_attempt_participants == 0U)
            guard.active_cleanup_attempt = 0U;
    }
    leave();
}

static void merge_runtime_status_locked(sae_guard_status_t *status)
{
    wifi_security_runtime_status_t runtime = {0};
    guard.runtime.status_snapshot(guard.runtime.context, &runtime);
    if (runtime.module == WIFI_SECURITY_MODULE_SAE_GUARD &&
        runtime.generation != guard.runtime_baseline_generation) {
        status->rx_drops = saturated_add(runtime.dropped_pool,
                                         runtime.dropped_queue);
    }
}

static void status_locked(sae_guard_status_t *status)
{
    if (guard.targets != NULL || guard.starting || guard.running)
        sae_guard_get_status(&guard.core, status);
    else
        *status = guard.last_status;
    if (guard.targets != NULL || guard.starting || guard.running)
        merge_runtime_status_locked(status);
    status->running = guard.running;
    status->stopping = guard.stopping;
}

static void record_output_failure(void)
{
    enter();
    if (guard.targets != NULL || guard.starting || guard.running)
        increment(&guard.core.status.output_failures);
    else
        increment(&guard.last_status.output_failures);
    guard.output_failed = true;
    if (context_live_locked()) guard.stopping = true;
    leave();
}

static bool publish(const char *line, size_t length)
{
    if (line == NULL || length == 0U) {
        record_output_failure();
        return false;
    }
    if (!guard.output.enter(guard.output.context,
                            SAE_GUARD_OUTPUT_TIMEOUT_MS)) {
        record_output_failure();
        return false;
    }
    bool written = guard.output.write(guard.output.context, line, length);
    if (!written) record_output_failure();
    guard.output.complete(guard.output.context, written);
    guard.output.leave(guard.output.context);
    return written;
}

static int publish_armed(uint64_t epoch, const char *line, size_t length)
{
    if (line == NULL || length == 0U) {
        record_output_failure();
        return -1;
    }
    if (!guard.output.enter(guard.output.context,
                            SAE_GUARD_OUTPUT_TIMEOUT_MS)) {
        record_output_failure();
        return -1;
    }
    enter();
    bool valid = guard.active_epoch == epoch && guard.targets != NULL &&
                 guard.target_count != 0U && guard.running && !guard.starting &&
                 !guard.stopping && !guard.cancel_requested;
    leave();
    if (!valid) {
        guard.output.leave(guard.output.context);
        return 0;
    }
    bool written = guard.output.write(guard.output.context, line, length);
    if (!written) record_output_failure();
    guard.output.complete(guard.output.context, written);
    guard.output.leave(guard.output.context);
    return written ? 1 : -1;
}

static const char *result_outcome(wifi_security_session_result_t result,
                                  bool stopping)
{
    switch (result) {
    case WIFI_SECURITY_SESSION_OK: return "ok";
    case WIFI_SECURITY_SESSION_BUSY:
        return stopping ? "timeout" : "busy";
    case WIFI_SECURITY_SESSION_BASELINE_BUSY: return "busy";
    case WIFI_SECURITY_SESSION_CANCELLED:
    case WIFI_SECURITY_SESSION_JOIN_TIMEOUT:
        return "timeout";
    case WIFI_SECURITY_SESSION_CHANNEL_FAILED:
    case WIFI_SECURITY_SESSION_RESTORE_FAILED:
    case WIFI_SECURITY_SESSION_CLEANUP_FAILED:
    case WIFI_SECURITY_SESSION_FILTER_SNAPSHOT_FAILED:
    case WIFI_SECURITY_SESSION_FILTER_APPLY_FAILED:
    case WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED:
        return "restore_failed";
    case WIFI_SECURITY_SESSION_INVALID:
    case WIFI_SECURITY_SESSION_PREPARE_FAILED:
    case WIFI_SECURITY_SESSION_WORKER_FAILED:
    case WIFI_SECURITY_SESSION_CALLBACK_FAILED:
    case WIFI_SECURITY_SESSION_PROMISCUOUS_FAILED:
    case WIFI_SECURITY_SESSION_MARK_FAILED:
    default:
        return "invalid";
    }
}

static bool publish_diagnostic_terminal(const char *outcome)
{
    sae_guard_status_t status;
    char line[SAE_GUARD_LINE_MAX];
    enter();
    status_locked(&status);
    leave();
    int length = sae_guard_format_terminal(line, sizeof(line), &status, outcome);
    return length > 0 && publish(line, (size_t)length);
}

static bool publish_lifecycle_terminal(uint64_t attempt, const char *outcome)
{
    if (attempt == 0U) return publish_diagnostic_terminal(outcome);
    sae_guard_status_t status;
    if (!guard.output.enter(guard.output.context,
                            SAE_GUARD_OUTPUT_TIMEOUT_MS)) {
        record_output_failure();
        return false;
    }
    enter();
    if (guard.terminal_claimed_attempt == attempt) {
        leave();
        guard.output.leave(guard.output.context);
        return true;
    }
    guard.terminal_claimed_attempt = attempt;
    status_locked(&status);
    leave();
    bool written = guard.output.write_terminal(guard.output.context, &status,
                                                outcome);
    if (!written) record_output_failure();
    guard.output.complete(guard.output.context, written);
    guard.output.leave(guard.output.context);
    return written;
}

static bool valid_bssid(const uint8_t bssid[6])
{
    uint8_t any = 0U;
    for (size_t i = 0; i < 6U; ++i) any |= bssid[i];
    return any != 0U && (bssid[0] & 1U) == 0U;
}

static bool parse_index(const char *text, size_t *index)
{
    if (text == NULL || text[0] == '\0' || index == NULL) return false;
    size_t value = 0U;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        size_t digit = (size_t)(*p - '0');
        if (value > (SIZE_MAX - digit) / 10U) return false;
        value = value * 10U + digit;
    }
    if (value == 0U) return false;
    *index = value;
    return true;
}

static void release_snapshot(wifi_shield_target_t *targets,
                             size_t allocation_count)
{
    if (targets == NULL) return;
    secure_zero(targets, allocation_count * sizeof(*targets));
    guard.runtime.scan_release(guard.runtime.context, targets, allocation_count);
}

static bool feature_validate(void *context)
{
    enter();
    bool valid = context_matches_locked(context) && guard.initialized &&
                 guard.active_epoch != 0U &&
                 guard.starting && guard.runtime_start_committed &&
                 !guard.cancel_requested && !guard.stopping &&
                 guard.targets != NULL && guard.target_count != 0U &&
                 guard.target_count <= guard.allocation_count &&
                 context_live_locked();
    leave();
    return valid;
}

static void feature_wipe(void *context)
{
    wifi_shield_target_t *targets;
    size_t allocation_count;
    enter();
    if (!context_matches_locked(context)) {
        leave();
        return;
    }
    targets = guard.targets;
    allocation_count = guard.allocation_count;
    sae_guard_get_status(&guard.core, &guard.last_status);
    merge_runtime_status_locked(&guard.last_status);
    guard.last_status.active_pairs = 0U;
    guard.last_status.active_malformed_bssids = 0U;
    guard.last_status.running = false;
    guard.last_status.stopping = false;
    guard.targets = NULL;
    guard.target_count = 0U;
    guard.allocation_count = 0U;
    guard.starting = false;
    guard.runtime_start_committed = false;
    guard.running = false;
    guard.stopping = false;
    guard.cancel_requested = false;
    guard.active_epoch = 0U;
    guard.active_context_token = 0U;
    guard.output_failed = false;
    sae_guard_reset(&guard.core);
    leave();
    release_snapshot(targets, allocation_count);
}

static void feature_uncertainty(void *telemetry_context,
                                wifi_security_session_result_t result,
                                bool owned)
{
    (void)telemetry_context;
    enter();
    ++guard.report_sequence;
    uint64_t attempt = guard.active_cleanup_attempt;
    bool was_stopping = guard.stopping;
    bool output_failed = guard.output_failed;
    if (owned) guard.stopping = true;
    leave();
    const char *outcome = output_failed ? "output_failed" :
                          result_outcome(result, was_stopping);
    (void)publish_lifecycle_terminal(attempt, outcome);
}

static bool selected_locked(const uint8_t bssid[6])
{
    for (size_t i = 0; i < guard.target_count; ++i) {
        if (memcmp(guard.targets[i].bssid, bssid, 6U) == 0) return true;
    }
    return false;
}

static bool publish_event(const sae_guard_event_t *event)
{
    char line[SAE_GUARD_LINE_MAX];
    int length = sae_guard_format_event(line, sizeof(line), event);
    return length == 0 || (length > 0 && publish(line, (size_t)length));
}

static bool decoded_is_sae_authentication(
    const wifi_security_decoded_t *decoded)
{
    return decoded->kind == WIFI_SEC_FRAME_AUTH &&
           !decoded->protected_frame && decoded->body != NULL &&
           decoded->body_len >= 2U && decoded->body[0] == 3U &&
           decoded->body[1] == 0U;
}

static bool feature_consume(void *context,
                            const wifi_security_frame_slot_t *slot,
                            const wifi_security_decoded_t *decoded)
{
    if (slot == NULL || decoded == NULL) return false;
    enter();
    if (!context_matches_locked(context) || guard.targets == NULL ||
        guard.stopping) {
        leave();
        return true;
    }
    increment(&guard.core.status.received);
    if (!selected_locked(decoded->bssid)) {
        increment(&guard.core.status.filtered);
        leave();
        return true;
    }
    leave();

    if (!decoded_is_sae_authentication(decoded)) {
        enter();
        if (context_matches_locked(context) && guard.targets != NULL &&
            !guard.stopping)
            increment(&guard.core.status.unrelated);
        leave();
        return true;
    }
    uint64_t now_us = guard.runtime.monotonic_us(guard.runtime.context);
    sae_guard_observation_t observation;
    if (!sae_guard_parse(decoded, slot->truncated, now_us, &observation)) {
        enter();
        if (context_matches_locked(context) && guard.targets != NULL &&
            !guard.stopping)
            increment(&guard.core.status.unrelated);
        leave();
        return true;
    }
    observation.channel = slot->channel;
    observation.rssi = slot->rssi;
    sae_guard_event_t event;
    enter();
    if (!context_matches_locked(context) || guard.stopping ||
        guard.targets == NULL) {
        leave();
        return true;
    }
    bool emitted = sae_guard_observe(&guard.core, &observation, &event);
    leave();
    return !emitted || publish_event(&event);
}

static bool uncertain_cleanup(wifi_security_session_result_t result)
{
    return result == WIFI_SECURITY_SESSION_JOIN_TIMEOUT ||
           result == WIFI_SECURITY_SESSION_RESTORE_FAILED ||
           result == WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED ||
           result == WIFI_SECURITY_SESSION_CLEANUP_FAILED;
}

static bool stop_internal(uint32_t timeout_ms, bool publish_success,
                          uint64_t inherited_attempt)
{
    enter();
    if (!context_live_locked()) {
        leave();
        return true;
    }
    bool start_pending = guard.starting;
    bool owns_participant = inherited_attempt == 0U;
    uint64_t attempt = owns_participant ? join_cleanup_attempt_locked() :
                                          inherited_attempt;
    if (start_pending) guard.cancel_requested = true;
    guard.stopping = true;
    uint32_t report_sequence = guard.report_sequence;
    bool pre_runtime_pending = start_pending && !guard.runtime_start_committed;
    leave();

    if (pre_runtime_pending) {
        if (owns_participant) leave_cleanup_attempt(attempt);
        return true;
    }

    bool stopped = guard.runtime.stop(guard.runtime.context, timeout_ms);
    if (stopped) {
        enter();
        bool still_live = guard.targets != NULL;
        void *session_context = (void *)guard.active_context_token;
        start_pending = guard.starting;
        bool cleanup_only = !still_live && !start_pending && guard.stopping;
        if (cleanup_only) {
            guard.runtime_start_committed = false;
            guard.running = false;
            guard.stopping = false;
            guard.cancel_requested = false;
            guard.active_epoch = 0U;
            guard.active_context_token = 0U;
        }
        leave();
        if (still_live && !start_pending) feature_wipe(session_context);
        if (start_pending || !publish_success) {
            if (owns_participant) leave_cleanup_attempt(attempt);
            return true;
        }
        bool published = publish_lifecycle_terminal(attempt, "stopped");
        if (owns_participant) leave_cleanup_attempt(attempt);
        return published;
    }
    enter();
    bool already_reported = guard.report_sequence != report_sequence;
    leave();
    if (!already_reported)
        (void)publish_lifecycle_terminal(attempt, "timeout");
    if (owns_participant) leave_cleanup_attempt(attempt);
    return false;
}

bool sae_guard_init(const sae_guard_runtime_hooks_t *runtime_hooks,
                    const sae_guard_output_hooks_t *output_hooks)
{
    if (runtime_hooks == NULL || output_hooks == NULL ||
        runtime_hooks->enter == NULL || runtime_hooks->leave == NULL ||
        runtime_hooks->scan_snapshot == NULL ||
        runtime_hooks->scan_release == NULL ||
        runtime_hooks->monotonic_us == NULL ||
        runtime_hooks->status_snapshot == NULL ||
        runtime_hooks->start == NULL || runtime_hooks->stop == NULL ||
        output_hooks->enter == NULL || output_hooks->leave == NULL ||
        output_hooks->write == NULL || output_hooks->write_terminal == NULL ||
        output_hooks->complete == NULL || output_hooks->idle == NULL)
        return false;
    if (guard.initialized) {
        enter();
        bool busy = context_live_locked() || guard.active_cleanup_attempt != 0U ||
                    !guard.output.idle(guard.output.context);
        leave();
        if (busy) return false;
    }
    memset(&guard, 0, sizeof(guard));
    guard.runtime = *runtime_hooks;
    guard.output = *output_hooks;
    sae_guard_core_init(&guard.core);
    guard.initialized = true;
    return true;
}

bool sae_guard_busy(void)
{
    if (!guard.initialized) return false;
    enter();
    bool busy = context_live_locked() || guard.active_cleanup_attempt != 0U ||
                !guard.output.idle(guard.output.context);
    leave();
    return busy;
}

void sae_guard_report_output_failure(void)
{
    if (guard.initialized) record_output_failure();
}

int sae_guard_format_terminal_for_output(char *out, size_t capacity,
                                         const sae_guard_status_t *status,
                                         const char *outcome)
{
    if (out == NULL || status == NULL || outcome == NULL) return -1;
    sae_guard_status_t final_status = *status;
    bool output_failed = final_status.output_failures != 0U;
    if (guard.initialized) {
        sae_guard_status_t latest;
        enter();
        status_locked(&latest);
        if (latest.output_failures > final_status.output_failures)
            final_status.output_failures = latest.output_failures;
        output_failed = output_failed || guard.output_failed ||
                        latest.output_failures != 0U;
        leave();
    }
    const char *published_outcome = output_failed ? "output_failed" :
        (final_status.rx_drops != 0U &&
         (strcmp(outcome, "ok") == 0 || strcmp(outcome, "stopped") == 0) ?
         "queue_overflow" : outcome);
    return sae_guard_format_terminal(out, capacity, &final_status,
                                     published_outcome);
}

static int invalid_command(void)
{
    if (guard.initialized) (void)publish_diagnostic_terminal("invalid");
    return 1;
}

static int start_command(int argc, char **argv)
{
    bool filtered = argc >= 3 && argv[2] != NULL &&
                    strcmp(argv[2], "--only") == 0;
    if (!((argc == 2) || (filtered && argc >= 4))) return invalid_command();
    enter();
    if (context_live_locked() || guard.active_cleanup_attempt != 0U ||
        !guard.output.idle(guard.output.context)) {
        leave();
        (void)publish_diagnostic_terminal("busy");
        return 1;
    }
    guard.starting = true;
    guard.stopping = false;
    guard.cancel_requested = false;
    guard.output_failed = false;
    ++guard.next_epoch;
    if (guard.next_epoch == 0U) ++guard.next_epoch;
    guard.active_epoch = guard.next_epoch;
    ++next_context_token;
    if (next_context_token == 0U) ++next_context_token;
    guard.active_context_token = next_context_token;
    uint64_t epoch = guard.active_epoch;
    void *session_context = (void *)guard.active_context_token;
    uint64_t attempt = join_cleanup_attempt_locked();
    sae_guard_core_init(&guard.core);
    memset(&guard.last_status, 0, sizeof(guard.last_status));
    wifi_security_runtime_status_t runtime_status = {0};
    guard.runtime.status_snapshot(guard.runtime.context, &runtime_status);
    guard.runtime_baseline_generation = runtime_status.generation;
    leave();

    wifi_shield_target_t *targets = NULL;
    size_t allocation_count = 0U;
    if (!guard.runtime.scan_snapshot(guard.runtime.context, &targets,
                                     &allocation_count) ||
        targets == NULL || allocation_count == 0U) {
        if (targets != NULL) release_snapshot(targets, allocation_count);
        enter();
        bool cancelled = guard.active_epoch == epoch && guard.cancel_requested;
        if (guard.active_epoch == epoch) {
            guard.starting = false;
            guard.stopping = false;
            guard.cancel_requested = false;
            guard.active_epoch = 0U;
            guard.active_context_token = 0U;
        }
        leave();
        (void)publish_lifecycle_terminal(attempt,
                                         cancelled ? "stopped" : "invalid");
        leave_cleanup_attempt(attempt);
        return 1;
    }

    size_t target_count = allocation_count;
    bool valid = true;
    if (filtered) {
        for (int i = 3; i < argc && valid; ++i) {
            size_t index;
            valid = argv[i] != NULL && parse_index(argv[i], &index) &&
                    index <= allocation_count;
            for (int j = 3; j < i && valid; ++j) {
                size_t previous;
                valid = parse_index(argv[j], &previous) && previous != index;
            }
        }
        target_count = 0U;
        for (size_t scan = 1U; scan <= allocation_count && valid; ++scan) {
            bool wanted = false;
            for (int i = 3; i < argc; ++i) {
                size_t index;
                if (!parse_index(argv[i], &index)) {
                    valid = false;
                    break;
                }
                if (index == scan) wanted = true;
            }
            if (wanted) {
                if (!valid_bssid(targets[scan - 1U].bssid) ||
                    targets[scan - 1U].channel == 0U) {
                    valid = false;
                    break;
                }
                if (target_count != scan - 1U)
                    targets[target_count] = targets[scan - 1U];
                ++target_count;
            }
        }
        if (target_count == 0U) valid = false;
        if (valid && target_count < allocation_count)
            secure_zero(targets + target_count,
                        (allocation_count - target_count) * sizeof(*targets));
    } else {
        for (size_t i = 0; i < target_count; ++i) {
            if (!valid_bssid(targets[i].bssid) || targets[i].channel == 0U) {
                valid = false;
                break;
            }
        }
    }
    if (!valid) {
        release_snapshot(targets, allocation_count);
        enter();
        bool cancelled = guard.active_epoch == epoch && guard.cancel_requested;
        if (guard.active_epoch == epoch) {
            guard.starting = false;
            guard.stopping = false;
            guard.cancel_requested = false;
            guard.active_epoch = 0U;
            guard.active_context_token = 0U;
        }
        leave();
        (void)publish_lifecycle_terminal(attempt,
                                         cancelled ? "stopped" : "invalid");
        leave_cleanup_attempt(attempt);
        return 1;
    }

    enter();
    bool cancelled = guard.active_epoch != epoch || guard.cancel_requested;
    if (cancelled) {
        if (guard.active_epoch == epoch) {
            guard.starting = false;
            guard.stopping = false;
            guard.cancel_requested = false;
            guard.active_epoch = 0U;
            guard.active_context_token = 0U;
        }
        leave();
        release_snapshot(targets, allocation_count);
        (void)publish_lifecycle_terminal(attempt, "stopped");
        leave_cleanup_attempt(attempt);
        return 1;
    }
    guard.targets = targets;
    guard.target_count = target_count;
    guard.allocation_count = allocation_count;
    uint32_t report_sequence = guard.report_sequence;
    leave();

    const wifi_security_session_config_t config = {
        .module = WIFI_SECURITY_MODULE_SAE_GUARD,
        .context = session_context,
        .consume = feature_consume,
        .validate = feature_validate,
        .wipe = feature_wipe,
        .telemetry_context = &guard,
        .uncertainty = feature_uncertainty,
    };
    enter();
    cancelled = guard.active_epoch != epoch || guard.cancel_requested ||
                guard.stopping || guard.targets == NULL;
    if (!cancelled) guard.runtime_start_committed = true;
    leave();
    if (cancelled) {
        feature_wipe(session_context);
        (void)publish_lifecycle_terminal(attempt, "stopped");
        leave_cleanup_attempt(attempt);
        return 1;
    }

    wifi_security_session_result_t result =
        guard.runtime.start(guard.runtime.context, targets, target_count,
                            &config);
    if (result != WIFI_SECURITY_SESSION_OK) {
        enter();
        bool reported = guard.report_sequence != report_sequence;
        bool cancelled_epoch = result == WIFI_SECURITY_SESSION_CANCELLED ||
            (guard.active_epoch == epoch &&
             (guard.cancel_requested || guard.stopping));
        bool retained = uncertain_cleanup(result) && guard.targets != NULL;
        leave();
        if (!retained) {
            enter();
            bool still_live = guard.targets != NULL;
            leave();
            if (still_live) feature_wipe(session_context);
        }
        if (!reported)
            (void)publish_lifecycle_terminal(
                attempt, cancelled_epoch ? "stopped" :
                result_outcome(result, false));
        leave_cleanup_attempt(attempt);
        return 1;
    }

    enter();
    cancelled = guard.active_epoch != epoch || guard.cancel_requested ||
                guard.stopping || guard.targets == NULL;
    size_t armed_targets = guard.target_count;
    uint32_t post_start_report = guard.report_sequence;
    bool context_present = guard.targets != NULL;
    if (!cancelled) {
        guard.starting = false;
        guard.runtime_start_committed = false;
        guard.running = true;
        guard.stopping = false;
    }
    leave();
    if (cancelled) {
        if (context_present) {
            bool stopped = guard.runtime.stop(guard.runtime.context, 5000U);
            enter();
            bool still_live = guard.targets != NULL;
            bool reported = guard.report_sequence != post_start_report;
            leave();
            if (stopped && still_live) feature_wipe(session_context);
            if (stopped && !reported)
                (void)publish_lifecycle_terminal(attempt, "stopped");
        }
        leave_cleanup_attempt(attempt);
        return 1;
    }

    char line[SAE_GUARD_LINE_MAX];
    int length = snprintf(line, sizeof(line),
                          "[SAE_GUARD/1] ARMED TARGETS=%zu\r\n",
                          armed_targets);
    int armed_result = length > 0 && (size_t)length < sizeof(line) ?
        publish_armed(epoch, line, (size_t)length) : -1;
    if (armed_result == 0) {
        leave_cleanup_attempt(attempt);
        return 1;
    }
    if (armed_result < 0) {
        if (stop_internal(5000U, false, attempt))
            (void)publish_lifecycle_terminal(attempt, "output_failed");
        leave_cleanup_attempt(attempt);
        return 1;
    }
    leave_cleanup_attempt(attempt);
    return 0;
}

bool sae_guard_stop(uint32_t timeout_ms)
{
    if (!guard.initialized) return true;
    return stop_internal(timeout_ms, true, 0U);
}

int sae_guard_command(int argc, char **argv)
{
    if (!guard.initialized || argv == NULL || argc < 2 || argv[0] == NULL ||
        argv[1] == NULL || strcmp(argv[0], "sae_guard") != 0)
        return invalid_command();
    if (strcmp(argv[1], "start") == 0) return start_command(argc, argv);
    if (strcmp(argv[1], "status") == 0) {
        if (argc != 2) return invalid_command();
        sae_guard_status_t status;
        char line[SAE_GUARD_LINE_MAX];
        enter();
        status_locked(&status);
        leave();
        int length = sae_guard_format_status(line, sizeof(line), &status);
        return length > 0 && publish(line, (size_t)length) ? 0 : 1;
    }
    if (strcmp(argv[1], "stop") == 0) {
        if (argc != 2) return invalid_command();
        return sae_guard_stop(5000U) ? 0 : 1;
    }
    return invalid_command();
}
