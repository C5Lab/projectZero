#define _POSIX_C_SOURCE 200809L

#include "sae_guard.h"
#include "wifi_shield_channel.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static pthread_mutex_t state_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t runtime_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t runtime_stop_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t output_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_condition = PTHREAD_COND_INITIALIZER;

static const uint8_t scan_fixture[3][6] = {
    {0x02, 0x11, 0x22, 0x33, 0x44, 0x50},
    {0x02, 0x11, 0x22, 0x33, 0x44, 0x51},
    {0x02, 0x11, 0x22, 0x33, 0x44, 0x52},
};
static wifi_shield_target_t scan_targets[3];

static wifi_security_session_config_t active_config;
static wifi_shield_target_t active_targets[3];
static size_t active_target_count;
static wifi_security_runtime_t shared_runtime;
static wifi_security_session_result_t start_result;
static wifi_security_session_result_t stop_reason;
static uint64_t now_us;
static uint32_t runtime_generation;
static unsigned start_calls, stop_calls, release_calls, complete_calls;
static unsigned output_enter_attempts;
static bool borrowed, feature_context_wiped, stop_succeeds;
static bool wipe_before_stop_failure, scan_succeeds, corrupt_scan;
static bool output_enter_succeeds, output_write_succeeds, output_idle;
static bool block_scan, scan_entered, release_scan;
static bool block_start_return, start_committed, release_start_return;
static bool block_stop_cleanup, stop_cleanup_entered, release_stop_cleanup;
static bool stop_cleanup_done;
static bool block_event_write, event_write_entered, release_event_write;
static bool block_armed_write, armed_write_entered, release_armed_write;
static bool fail_next_output, retain_failed_admission_token;
static bool failed_admission_token_retained;
static bool block_failed_write_return, failed_write_entered;
static bool release_failed_write_return;
static bool block_failed_write_leave, failed_write_leave_entered;
static bool release_failed_write_leave;
static bool block_terminal_format, terminal_format_entered;
static bool release_terminal_format;
static _Thread_local bool output_lock_owned;
static _Thread_local bool previous_write_failed;
static char output[32768];
static size_t output_used;

static void lock_enter(void *context)
{
    (void)context;
    assert(pthread_mutex_lock(&state_lock) == 0);
}

static void lock_leave(void *context)
{
    (void)context;
    assert(pthread_mutex_unlock(&state_lock) == 0);
}

static bool scan_snapshot(void *context, wifi_shield_target_t **targets,
                          size_t *count)
{
    (void)context;
    assert(targets != NULL && count != NULL);
    if (!scan_succeeds) return false;
    wifi_shield_target_t *copy = calloc(3U, sizeof(*copy));
    assert(copy != NULL);
    memcpy(copy, scan_targets, sizeof(scan_targets));
    if (corrupt_scan) memset(copy[1].bssid, 0, 6U);
    pthread_mutex_lock(&gate_lock);
    if (block_scan) {
        scan_entered = true;
        pthread_cond_broadcast(&gate_condition);
        while (!release_scan) pthread_cond_wait(&gate_condition, &gate_lock);
    }
    pthread_mutex_unlock(&gate_lock);
    *targets = copy;
    *count = 3U;
    return true;
}

static void scan_release(void *context, wifi_shield_target_t *targets,
                         size_t count)
{
    (void)context;
    assert(targets != NULL && count == 3U);
    const uint8_t *bytes = (const uint8_t *)targets;
    for (size_t i = 0; i < count * sizeof(*targets); ++i)
        assert(bytes[i] == 0U);
    ++release_calls;
    free(targets);
}

static uint64_t monotonic_us(void *context)
{
    (void)context;
    return ++now_us;
}

static void shared_enter(void *context)
{
    (void)context;
    assert(pthread_mutex_lock(&runtime_lock) == 0);
}

static void shared_leave(void *context)
{
    (void)context;
    assert(pthread_mutex_unlock(&runtime_lock) == 0);
}

static void status_snapshot(void *context, wifi_security_runtime_status_t *status)
{
    (void)context;
    assert(status != NULL);
    wifi_security_runtime_get_status(&shared_runtime, status);
}

static bool uncertain_result(wifi_security_session_result_t result)
{
    return result == WIFI_SECURITY_SESSION_JOIN_TIMEOUT ||
           result == WIFI_SECURITY_SESSION_RESTORE_FAILED ||
           result == WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED ||
           result == WIFI_SECURITY_SESSION_CLEANUP_FAILED;
}

static wifi_security_session_result_t runtime_start(
    void *context, const wifi_shield_target_t *targets, size_t target_count,
    const wifi_security_session_config_t *config)
{
    (void)context;
    assert(targets != NULL && target_count != 0U && target_count <= 3U);
    assert(config != NULL);
    ++start_calls;
    memcpy(active_targets, targets, target_count * sizeof(*targets));
    active_target_count = target_count;
    if (target_count < 3U) {
        const uint8_t *tail = (const uint8_t *)(targets + target_count);
        for (size_t i = 0U; i < (3U - target_count) * sizeof(*targets); ++i)
            assert(tail[i] == 0U);
    }
    active_config = *config;
    if (!config->validate(config->context)) return WIFI_SECURITY_SESSION_INVALID;
    if (start_result == WIFI_SECURITY_SESSION_OK) {
        const wifi_security_runtime_config_t runtime_config = {
            .module = WIFI_SECURITY_MODULE_SAE_GUARD,
            .generation = ++runtime_generation,
            .context = config->context,
            .consume = config->consume,
        };
        assert(wifi_security_runtime_start(&shared_runtime, &runtime_config));
        borrowed = true;
        feature_context_wiped = false;
        assert(pthread_mutex_lock(&gate_lock) == 0);
        if (block_start_return) {
            start_committed = true;
            assert(pthread_cond_broadcast(&gate_condition) == 0);
            while (!release_start_return)
                assert(pthread_cond_wait(&gate_condition, &gate_lock) == 0);
        }
        assert(pthread_mutex_unlock(&gate_lock) == 0);
    } else if (uncertain_result(start_result)) {
        borrowed = true;
        config->uncertainty(config->telemetry_context, start_result, true);
    } else if (start_result != WIFI_SECURITY_SESSION_BUSY &&
               start_result != WIFI_SECURITY_SESSION_BASELINE_BUSY) {
        config->wipe(config->context);
        feature_context_wiped = true;
    }
    return start_result;
}

static bool runtime_stop(void *context, uint32_t timeout_ms)
{
    (void)context;
    assert(timeout_ms <= 5000U);
    assert(pthread_mutex_lock(&gate_lock) == 0);
    ++stop_calls;
    assert(pthread_cond_broadcast(&gate_condition) == 0);
    assert(pthread_mutex_unlock(&gate_lock) == 0);
    assert(pthread_mutex_lock(&runtime_stop_lock) == 0);
    if (!borrowed) {
        assert(pthread_mutex_unlock(&runtime_stop_lock) == 0);
        return true;
    }
    assert(pthread_mutex_lock(&gate_lock) == 0);
    if (block_stop_cleanup) {
        stop_cleanup_entered = true;
        assert(pthread_cond_broadcast(&gate_condition) == 0);
        while (!release_stop_cleanup)
            assert(pthread_cond_wait(&gate_condition, &gate_lock) == 0);
    }
    assert(pthread_mutex_unlock(&gate_lock) == 0);
    if (!stop_succeeds) {
        if (wipe_before_stop_failure && !feature_context_wiped) {
            wifi_security_runtime_close_callbacks(&shared_runtime);
            wifi_security_runtime_request_stop(&shared_runtime);
            (void)wifi_security_runtime_drain(&shared_runtime);
            assert(wifi_security_runtime_finish(&shared_runtime));
            active_config.wipe(active_config.context);
            feature_context_wiped = true;
        }
        active_config.uncertainty(active_config.telemetry_context,
                                  stop_reason, true);
        assert(pthread_mutex_unlock(&runtime_stop_lock) == 0);
        return false;
    }
    if (!feature_context_wiped) {
        wifi_security_runtime_close_callbacks(&shared_runtime);
        wifi_security_runtime_request_stop(&shared_runtime);
        (void)wifi_security_runtime_drain(&shared_runtime);
        assert(wifi_security_runtime_finish(&shared_runtime));
        active_config.wipe(active_config.context);
        feature_context_wiped = true;
    }
    borrowed = false;
    assert(pthread_mutex_lock(&gate_lock) == 0);
    stop_cleanup_done = true;
    assert(pthread_cond_broadcast(&gate_condition) == 0);
    assert(pthread_mutex_unlock(&gate_lock) == 0);
    assert(pthread_mutex_unlock(&runtime_stop_lock) == 0);
    return true;
}

static bool output_enter(void *context, uint32_t timeout_ms)
{
    (void)context;
    assert(timeout_ms == SAE_GUARD_OUTPUT_TIMEOUT_MS);
    assert(pthread_mutex_lock(&gate_lock) == 0);
    ++output_enter_attempts;
    assert(pthread_cond_broadcast(&gate_condition) == 0);
    assert(pthread_mutex_unlock(&gate_lock) == 0);
    if (!output_enter_succeeds) return false;
    assert(pthread_mutex_lock(&output_lock) == 0);
    assert(!output_lock_owned);
    output_lock_owned = true;
    return true;
}

static void output_leave(void *context)
{
    (void)context;
    assert(output_lock_owned);
    if (previous_write_failed && block_failed_write_leave) {
        assert(pthread_mutex_lock(&gate_lock) == 0);
        failed_write_leave_entered = true;
        assert(pthread_cond_broadcast(&gate_condition) == 0);
        while (!release_failed_write_leave)
            assert(pthread_cond_wait(&gate_condition, &gate_lock) == 0);
        assert(pthread_mutex_unlock(&gate_lock) == 0);
    }
    previous_write_failed = false;
    output_lock_owned = false;
    assert(pthread_mutex_unlock(&output_lock) == 0);
}

static bool append_output(const char *line, size_t length)
{
    if (!output_write_succeeds) return false;
    assert(line != NULL && length != 0U && output_used + length < sizeof(output));
    memcpy(output + output_used, line, length);
    output_used += length;
    output[output_used] = '\0';
    return true;
}

static bool output_write(void *context, const char *line, size_t length)
{
    (void)context;
    assert(output_lock_owned);
    if (strstr(line, " BSSID=") != NULL && block_event_write) {
        assert(pthread_mutex_lock(&gate_lock) == 0);
        event_write_entered = true;
        assert(pthread_cond_broadcast(&gate_condition) == 0);
        while (!release_event_write)
            assert(pthread_cond_wait(&gate_condition, &gate_lock) == 0);
        assert(pthread_mutex_unlock(&gate_lock) == 0);
    }
    if (strstr(line, " ARMED ") != NULL && block_armed_write) {
        assert(pthread_mutex_lock(&gate_lock) == 0);
        armed_write_entered = true;
        assert(pthread_cond_broadcast(&gate_condition) == 0);
        while (!release_armed_write)
            assert(pthread_cond_wait(&gate_condition, &gate_lock) == 0);
        assert(pthread_mutex_unlock(&gate_lock) == 0);
    }
    if (fail_next_output) {
        fail_next_output = false;
        previous_write_failed = true;
        if (retain_failed_admission_token) {
            assert(output_idle);
            output_idle = false;
            failed_admission_token_retained = true;
        }
        if (block_failed_write_return) {
            assert(pthread_mutex_lock(&gate_lock) == 0);
            failed_write_entered = true;
            assert(pthread_cond_broadcast(&gate_condition) == 0);
            while (!release_failed_write_return)
                assert(pthread_cond_wait(&gate_condition, &gate_lock) == 0);
            assert(pthread_mutex_unlock(&gate_lock) == 0);
        }
        return false;
    }
    return append_output(line, length);
}

static bool output_write_terminal(void *context,
                                  const sae_guard_status_t *status,
                                  const char *outcome)
{
    (void)context;
    assert(output_lock_owned);
    if (block_terminal_format) {
        assert(pthread_mutex_lock(&gate_lock) == 0);
        terminal_format_entered = true;
        assert(pthread_cond_broadcast(&gate_condition) == 0);
        while (!release_terminal_format)
            assert(pthread_cond_wait(&gate_condition, &gate_lock) == 0);
        assert(pthread_mutex_unlock(&gate_lock) == 0);
    }
    char line[SAE_GUARD_LINE_MAX];
    int length = sae_guard_format_terminal_for_output(
        line, sizeof(line), status, outcome);
    return length > 0 && append_output(line, (size_t)length);
}

static void output_complete(void *context, bool accepted)
{
    (void)context;
    assert(output_lock_owned);
    ++complete_calls;
    if (!accepted && failed_admission_token_retained) {
        assert(!output_idle);
        failed_admission_token_retained = false;
        output_idle = true;
    }
}

static bool output_is_idle(void *context)
{
    (void)context;
    return output_idle;
}

static const sae_guard_runtime_hooks_t runtime_hooks = {
    .enter = lock_enter,
    .leave = lock_leave,
    .scan_snapshot = scan_snapshot,
    .scan_release = scan_release,
    .monotonic_us = monotonic_us,
    .status_snapshot = status_snapshot,
    .start = runtime_start,
    .stop = runtime_stop,
};

static const sae_guard_output_hooks_t output_hooks = {
    .enter = output_enter,
    .leave = output_leave,
    .write = output_write,
    .write_terminal = output_write_terminal,
    .complete = output_complete,
    .idle = output_is_idle,
};

static void reset_fixture(void)
{
    if (borrowed) {
        stop_succeeds = true;
        wifi_security_runtime_close_callbacks(&shared_runtime);
        wifi_security_runtime_request_stop(&shared_runtime);
        (void)wifi_security_runtime_drain(&shared_runtime);
        assert(wifi_security_runtime_finish(&shared_runtime));
        if (!feature_context_wiped) active_config.wipe(active_config.context);
        borrowed = false;
    }
    assert(!sae_guard_busy());
    memset(&active_config, 0, sizeof(active_config));
    memset(active_targets, 0, sizeof(active_targets));
    active_target_count = 0U;
    memset(scan_targets, 0, sizeof(scan_targets));
    for (size_t i = 0; i < 3U; ++i) {
        memcpy(scan_targets[i].bssid, scan_fixture[i], 6U);
        scan_targets[i].channel = (uint8_t)(1U + i * 5U);
        snprintf(scan_targets[i].ssid, sizeof(scan_targets[i].ssid),
                 "SAE-SCAN-%u", (unsigned)(i + 1U));
        scan_targets[i].wpa2_psk_ccmp = i != 1U;
    }
    const wifi_security_runtime_hooks_t shared_hooks = {
        .enter = shared_enter, .leave = shared_leave, .notify = NULL,
    };
    assert(wifi_security_runtime_init(&shared_runtime, &shared_hooks, 1U));
    runtime_generation = 0U;
    start_result = WIFI_SECURITY_SESSION_OK;
    stop_reason = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    now_us = 1000U;
    start_calls = stop_calls = release_calls = complete_calls = 0U;
    output_enter_attempts = 0U;
    borrowed = feature_context_wiped = false;
    stop_succeeds = scan_succeeds = true;
    wipe_before_stop_failure = false;
    corrupt_scan = false;
    output_enter_succeeds = output_write_succeeds = output_idle = true;
    block_scan = scan_entered = release_scan = false;
    block_start_return = start_committed = release_start_return = false;
    block_stop_cleanup = stop_cleanup_entered = release_stop_cleanup = false;
    stop_cleanup_done = false;
    block_event_write = event_write_entered = release_event_write = false;
    block_armed_write = armed_write_entered = release_armed_write = false;
    fail_next_output = retain_failed_admission_token = false;
    failed_admission_token_retained = false;
    block_failed_write_return = failed_write_entered = false;
    release_failed_write_return = false;
    block_failed_write_leave = failed_write_leave_entered = false;
    release_failed_write_leave = false;
    block_terminal_format = terminal_format_entered = false;
    release_terminal_format = false;
    output_lock_owned = previous_write_failed = false;
    memset(output, 0, sizeof(output));
    output_used = 0U;
    assert(sae_guard_init(&runtime_hooks, &output_hooks));
}

static int command(size_t argc, const char *const *argv)
{
    return sae_guard_command((int)argc, (char **)argv);
}

static void release_scan_gate(void)
{
    pthread_mutex_lock(&gate_lock);
    release_scan = true;
    pthread_cond_broadcast(&gate_condition);
    pthread_mutex_unlock(&gate_lock);
}

static void wait_for_scan(void)
{
    pthread_mutex_lock(&gate_lock);
    while (!scan_entered) pthread_cond_wait(&gate_condition, &gate_lock);
    pthread_mutex_unlock(&gate_lock);
}

static void wait_for_flag(bool *flag)
{
    assert(pthread_mutex_lock(&gate_lock) == 0);
    while (!*flag)
        assert(pthread_cond_wait(&gate_condition, &gate_lock) == 0);
    assert(pthread_mutex_unlock(&gate_lock) == 0);
}

static void release_flag(bool *flag)
{
    assert(pthread_mutex_lock(&gate_lock) == 0);
    *flag = true;
    assert(pthread_cond_broadcast(&gate_condition) == 0);
    assert(pthread_mutex_unlock(&gate_lock) == 0);
}

static void wait_for_stop_calls(unsigned expected)
{
    assert(pthread_mutex_lock(&gate_lock) == 0);
    while (stop_calls < expected)
        assert(pthread_cond_wait(&gate_condition, &gate_lock) == 0);
    assert(pthread_mutex_unlock(&gate_lock) == 0);
}

static void wait_for_output_attempts(unsigned expected)
{
    assert(pthread_mutex_lock(&gate_lock) == 0);
    while (output_enter_attempts < expected)
        assert(pthread_cond_wait(&gate_condition, &gate_lock) == 0);
    assert(pthread_mutex_unlock(&gate_lock) == 0);
}

static void clear_output(void)
{
    memset(output, 0, sizeof(output));
    output_used = 0U;
}

static size_t occurrences(const char *needle)
{
    size_t count = 0U;
    for (const char *cursor = output;
         (cursor = strstr(cursor, needle)) != NULL;
         cursor += strlen(needle))
        ++count;
    return count;
}

static void assert_one_terminal(const char *outcome)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "TERMINAL OUTCOME=%s", outcome);
    assert(occurrences("TERMINAL OUTCOME=") == 1U);
    assert(strstr(output, needle) != NULL);
}

static void assert_full_output(const char *expected)
{
    if (strcmp(output, expected) != 0) {
        fprintf(stderr, "EXPECTED:\n%sACTUAL:\n%s", expected, output);
        assert(false);
    }
}

typedef struct {
    size_t argc;
    const char *const *argv;
    int result;
} command_thread_t;

typedef struct {
    bool result;
} consume_thread_t;

static wifi_security_decoded_t frame_for(const uint8_t bssid[6], uint8_t *body,
                                         size_t body_len);

static void *run_command(void *context)
{
    command_thread_t *item = context;
    item->result = command(item->argc, item->argv);
    return NULL;
}

static void *run_anti_clogging_consume(void *context)
{
    consume_thread_t *item = context;
    uint8_t anti_clogging[8] = {3, 0, 1, 0, 76, 0, 19, 0};
    wifi_security_decoded_t decoded = frame_for(scan_fixture[0], anti_clogging,
                                                sizeof(anti_clogging));
    wifi_security_frame_slot_t slot = {.channel = 6U, .rssi = -50};
    item->result = active_config.consume(active_config.context, &slot, &decoded);
    return NULL;
}

static void test_cli_validation_filter_and_snapshot_wipe(void)
{
    reset_fixture();
    const char *bad[][6] = {
        {"sae_guard"},
        {"sae_guard", "start", "--only"},
        {"sae_guard", "start", "1"},
        {"sae_guard", "start", "--only", "0"},
        {"sae_guard", "start", "--only", "4"},
        {"sae_guard", "start", "--only", "1", "1"},
        {"sae_guard", "start", "--only", "184467440737095516160"},
        {"sae_guard", "status", "extra"},
        {"sae_guard", "stop", "extra"},
        {"sae_guard", "clear"},
    };
    const size_t sizes[] = {1, 3, 3, 4, 4, 5, 4, 3, 3, 2};
    for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); ++i)
        assert(command(sizes[i], bad[i]) != 0);
    assert(start_calls == 0U);

    reset_fixture();
    const char *selected[] = {"sae_guard", "start", "--only", "2"};
    assert(command(4, selected) == 0);
    assert(start_calls == 1U && sae_guard_busy());
    assert(active_config.module == WIFI_SECURITY_MODULE_SAE_GUARD);
    assert(active_target_count == 1U);
    assert(memcmp(active_targets[0].bssid, scan_fixture[1], 6U) == 0);
    assert(active_targets[0].channel == 6U);
    assert(strcmp(active_targets[0].ssid, "SAE-SCAN-2") == 0);
    assert(!active_targets[0].wpa2_psk_ccmp);
    assert(strstr(output, "[SAE_GUARD/1] ARMED TARGETS=1\r\n") != NULL);

    const char *again[] = {"sae_guard", "start"};
    assert(command(2, again) != 0 && start_calls == 1U);
    const char *stop[] = {"sae_guard", "stop"};
    assert(command(2, stop) == 0);
    assert(!sae_guard_busy() && release_calls == 1U);

    reset_fixture();
    corrupt_scan = true;
    assert(command(2, again) != 0);
    assert(start_calls == 0U && release_calls == 1U && !sae_guard_busy());
}

static void test_exact_idle_lifecycle_transcript(void)
{
    static const char *const status_line =
        "[SAE_GUARD/1] STATUS RECEIVED=0 FILTERED=0 UNRELATED=0"
        " OBSERVATIONS=0 COMMITS=0 CONFIRMS=0 RETRIES=0 MALFORMED=0"
        " ANTI_CLOGGING=0 STATUS_FAILURES=0 CAPACITY_DROPS=0 PAIR_DROPS=0"
        " MALFORMED_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0 ACTIVE=0"
        " RUNNING=1 STOPPING=0 REASONS=0,0,0,0,0,0,0\r\n";
    static const char *const stopped_line =
        "[SAE_GUARD/1] TERMINAL OUTCOME=stopped RECEIVED=0 FILTERED=0"
        " UNRELATED=0 OBSERVATIONS=0 COMMITS=0 CONFIRMS=0 RETRIES=0"
        " MALFORMED=0 ANTI_CLOGGING=0 STATUS_FAILURES=0 CAPACITY_DROPS=0"
        " PAIR_DROPS=0 MALFORMED_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0"
        " ACTIVE=0 RUNNING=0 STOPPING=0 REASONS=0,0,0,0,0,0,0\r\n";
    const char *start[] = {"sae_guard", "start", "--only", "1"};
    const char *status[] = {"sae_guard", "status"};
    const char *stop[] = {"sae_guard", "stop"};

    reset_fixture();
    assert(command(4, start) == 0);
    assert(strcmp(output, "[SAE_GUARD/1] ARMED TARGETS=1\r\n") == 0);
    clear_output();
    assert(command(2, status) == 0);
    assert(strcmp(output, status_line) == 0);
    clear_output();
    assert(command(2, stop) == 0);
    assert(strcmp(output, stopped_line) == 0);
}

static void test_exact_busy_invalid_event_output_failure_and_retry_transcripts(void)
{
    static const char *const zero_busy =
        "[SAE_GUARD/1] TERMINAL OUTCOME=busy RECEIVED=0 FILTERED=0"
        " UNRELATED=0 OBSERVATIONS=0 COMMITS=0 CONFIRMS=0 RETRIES=0"
        " MALFORMED=0 ANTI_CLOGGING=0 STATUS_FAILURES=0 CAPACITY_DROPS=0"
        " PAIR_DROPS=0 MALFORMED_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0"
        " ACTIVE=0 RUNNING=0 STOPPING=0 REASONS=0,0,0,0,0,0,0\r\n";
    static const char *const zero_invalid =
        "[SAE_GUARD/1] TERMINAL OUTCOME=invalid RECEIVED=0 FILTERED=0"
        " UNRELATED=0 OBSERVATIONS=0 COMMITS=0 CONFIRMS=0 RETRIES=0"
        " MALFORMED=0 ANTI_CLOGGING=0 STATUS_FAILURES=0 CAPACITY_DROPS=0"
        " PAIR_DROPS=0 MALFORMED_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0"
        " ACTIVE=0 RUNNING=0 STOPPING=0 REASONS=0,0,0,0,0,0,0\r\n";
    static const char *const event_line =
        "[SAE_GUARD/1] BSSID=02:11:22:33:44:51"
        " STA=02:aa:bb:cc:dd:ee DIR=ap_to_sta CH=11 RSSI=-47"
        " TRANSACTION=1 STATUS=76 GROUP=19 COMMITS=0 CONFIRMS=0"
        " MALFORMED=0 WINDOW_MS=0 REASON=anti_clogging SEVERITY=info"
        " INTERPRETATION=observation TS_US=1001\r\n";
    static const char *const event_status =
        "[SAE_GUARD/1] STATUS RECEIVED=1 FILTERED=0 UNRELATED=0"
        " OBSERVATIONS=1 COMMITS=0 CONFIRMS=0 RETRIES=0 MALFORMED=0"
        " ANTI_CLOGGING=1 STATUS_FAILURES=0 CAPACITY_DROPS=0 PAIR_DROPS=0"
        " MALFORMED_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0 ACTIVE=0"
        " RUNNING=1 STOPPING=0 REASONS=0,0,0,0,1,0,0\r\n";
    static const char *const output_failed =
        "[SAE_GUARD/1] TERMINAL OUTCOME=output_failed RECEIVED=0 FILTERED=0"
        " UNRELATED=0 OBSERVATIONS=0 COMMITS=0 CONFIRMS=0 RETRIES=0"
        " MALFORMED=0 ANTI_CLOGGING=0 STATUS_FAILURES=0 CAPACITY_DROPS=0"
        " PAIR_DROPS=0 MALFORMED_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=1"
        " ACTIVE=0 RUNNING=0 STOPPING=0 REASONS=0,0,0,0,0,0,0\r\n";
    static const char *const timeout =
        "[SAE_GUARD/1] TERMINAL OUTCOME=timeout RECEIVED=0 FILTERED=0"
        " UNRELATED=0 OBSERVATIONS=0 COMMITS=0 CONFIRMS=0 RETRIES=0"
        " MALFORMED=0 ANTI_CLOGGING=0 STATUS_FAILURES=0 CAPACITY_DROPS=0"
        " PAIR_DROPS=0 MALFORMED_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0"
        " ACTIVE=0 RUNNING=1 STOPPING=1 REASONS=0,0,0,0,0,0,0\r\n";
    static const char *const stopped =
        "[SAE_GUARD/1] TERMINAL OUTCOME=stopped RECEIVED=0 FILTERED=0"
        " UNRELATED=0 OBSERVATIONS=0 COMMITS=0 CONFIRMS=0 RETRIES=0"
        " MALFORMED=0 ANTI_CLOGGING=0 STATUS_FAILURES=0 CAPACITY_DROPS=0"
        " PAIR_DROPS=0 MALFORMED_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0"
        " ACTIVE=0 RUNNING=0 STOPPING=0 REASONS=0,0,0,0,0,0,0\r\n";
    const char *start[] = {"sae_guard", "start"};
    const char *selected[] = {"sae_guard", "start", "--only", "2"};
    const char *status[] = {"sae_guard", "status"};
    const char *stop[] = {"sae_guard", "stop"};

    reset_fixture();
    start_result = WIFI_SECURITY_SESSION_BUSY;
    assert(command(2, start) == 1);
    assert_full_output(zero_busy);

    reset_fixture();
    scan_succeeds = false;
    assert(command(2, start) == 1);
    assert_full_output(zero_invalid);

    reset_fixture();
    assert(command(4, selected) == 0);
    clear_output();
    uint8_t anti_clogging[8] = {3, 0, 1, 0, 76, 0, 19, 0};
    wifi_security_decoded_t decoded = frame_for(
        scan_fixture[1], anti_clogging, sizeof(anti_clogging));
    wifi_security_frame_slot_t slot = {.channel = 11U, .rssi = -47};
    assert(active_config.consume(active_config.context, &slot, &decoded));
    assert_full_output(event_line);
    clear_output();
    assert(command(2, status) == 0);
    assert_full_output(event_status);
    assert(command(2, stop) == 0);

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    sae_guard_report_output_failure();
    assert(command(2, stop) == 0);
    assert_full_output(output_failed);

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    stop_succeeds = false;
    stop_reason = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    assert(command(2, stop) == 1);
    assert(sae_guard_busy());
    assert_full_output(timeout);
    clear_output();
    stop_succeeds = true;
    assert(command(2, stop) == 0);
    assert(!sae_guard_busy());
    assert_full_output(stopped);
}

static wifi_security_decoded_t frame_for(const uint8_t bssid[6], uint8_t *body,
                                         size_t body_len)
{
    wifi_security_decoded_t frame = {0};
    frame.kind = WIFI_SEC_FRAME_AUTH;
    frame.body = body;
    frame.body_len = body_len;
    memcpy(frame.bssid, bssid, 6U);
    memcpy(frame.addr2, bssid, 6U);
    memcpy(frame.addr3, bssid, 6U);
    const uint8_t station[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    memcpy(frame.station, station, 6U);
    memcpy(frame.addr1, station, 6U);
    frame.sequence = 7U;
    return frame;
}

static size_t raw_sae_auth(uint8_t *raw, size_t capacity,
                           const uint8_t bssid[6], uint16_t status)
{
    assert(raw != NULL && capacity >= 32U);
    memset(raw, 0xa5, capacity);
    raw[0] = 0xb0U;
    raw[1] = 0x08U;
    const uint8_t station[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    memcpy(raw + 4U, station, 6U);
    memcpy(raw + 10U, bssid, 6U);
    memcpy(raw + 16U, bssid, 6U);
    raw[22] = 0x70U;
    raw[23] = 0x00U;
    raw[24] = 3U;
    raw[25] = 0U;
    raw[26] = 1U;
    raw[27] = 0U;
    raw[28] = (uint8_t)status;
    raw[29] = (uint8_t)(status >> 8);
    raw[30] = 19U;
    raw[31] = 0U;
    return capacity;
}

static bool submit_and_drain_sae(size_t length, uint16_t status)
{
    uint8_t raw[1600];
    assert(length >= 32U && length <= sizeof(raw));
    (void)raw_sae_auth(raw, length, scan_fixture[0], status);
    bool accepted = wifi_security_runtime_submit(
        &shared_runtime, runtime_generation, raw, (uint16_t)length,
        now_us, -41, 6U);
    if (accepted) assert(wifi_security_runtime_drain(&shared_runtime) == 1U);
    return accepted;
}

static void induce_real_pool_and_queue_loss_with_truncation(void)
{
    uint8_t raw[1600];
    (void)raw_sae_auth(raw, sizeof(raw), scan_fixture[0], 76U);
    assert(wifi_security_runtime_submit(&shared_runtime, runtime_generation,
        raw, sizeof(raw), 1U, -40, 6U));
    assert(!wifi_security_runtime_submit(&shared_runtime, runtime_generation,
        raw, sizeof(raw), 2U, -41, 6U));

    uint8_t claimed[WIFI_SECURITY_POOL_SLOTS - 1U];
    for (size_t i = 0; i < sizeof(claimed); ++i) {
        wifi_security_frame_slot_t *slot = NULL;
        assert(wifi_security_runtime_claim(&shared_runtime, &claimed[i], &slot));
        assert(slot != NULL);
    }
    assert(!wifi_security_runtime_submit(&shared_runtime, runtime_generation,
        raw, sizeof(raw), 3U, -42, 6U));
    for (size_t i = 0; i < sizeof(claimed); ++i)
        assert(wifi_security_runtime_release(&shared_runtime, claimed[i]));
    assert(wifi_security_runtime_drain(&shared_runtime) == 1U);
}

static void test_worker_filter_and_sae_only_parse(void)
{
    reset_fixture();
    const char *start[] = {"sae_guard", "start", "--only", "2"};
    assert(command(4, start) == 0);
    wifi_security_frame_slot_t slot = {.channel = 11U, .rssi = -47};

    uint8_t anti_clogging[8] = {3, 0, 1, 0, 76, 0, 19, 0};
    wifi_security_decoded_t selected = frame_for(scan_fixture[1],
                                                 anti_clogging,
                                                 sizeof(anti_clogging));
    wifi_security_decoded_t filtered = frame_for(scan_fixture[0],
                                                 anti_clogging,
                                                 sizeof(anti_clogging));
    assert(active_config.consume(active_config.context, &slot, &filtered));

    uint8_t open_system[6] = {0, 0, 1, 0, 0, 0};
    wifi_security_decoded_t unrelated = frame_for(scan_fixture[1], open_system,
                                                  sizeof(open_system));
    assert(active_config.consume(active_config.context, &slot, &unrelated));
    selected.protected_frame = true;
    assert(active_config.consume(active_config.context, &slot, &selected));
    selected.protected_frame = false;
    selected.kind = WIFI_SEC_FRAME_BEACON;
    assert(active_config.consume(active_config.context, &slot, &selected));
    selected.kind = WIFI_SEC_FRAME_AUTH;
    assert(active_config.consume(active_config.context, &slot, &selected));

    assert(now_us == 1001U);
    assert(strstr(output, "REASON=anti_clogging") != NULL);
    assert(strstr(output, "CH=11 RSSI=-47") != NULL);
    const char *status[] = {"sae_guard", "status"};
    assert(command(2, status) == 0);
    assert(strstr(output, "RECEIVED=5 FILTERED=1 UNRELATED=3 OBSERVATIONS=1") != NULL);
    assert(strstr(output, "ANTI_CLOGGING=1") != NULL);
    const char *stop[] = {"sae_guard", "stop"};
    assert(command(2, stop) == 0);
}

static void test_runtime_conflicts_cleanup_retry_and_loss_precedence(void)
{
    const char *start[] = {"sae_guard", "start"};
    const char *stop[] = {"sae_guard", "stop"};

    reset_fixture();
    start_result = WIFI_SECURITY_SESSION_BUSY;
    assert(command(2, start) != 0);
    assert(strstr(output, "TERMINAL OUTCOME=busy") != NULL);
    assert(!sae_guard_busy() && release_calls == 1U);

    reset_fixture();
    start_result = WIFI_SECURITY_SESSION_BASELINE_BUSY;
    assert(command(2, start) != 0);
    assert(strstr(output, "TERMINAL OUTCOME=busy") != NULL);

    reset_fixture();
    assert(command(2, start) == 0);
    assert(pthread_mutex_lock(&runtime_lock) == 0);
    shared_runtime.status.dropped_pool = UINT32_MAX;
    shared_runtime.status.dropped_queue = 7U;
    assert(pthread_mutex_unlock(&runtime_lock) == 0);
    stop_succeeds = false;
    assert(command(2, stop) != 0 && sae_guard_busy());
    assert(strstr(output, "TERMINAL OUTCOME=timeout") != NULL);
    stop_succeeds = true;
    assert(command(2, stop) == 0 && !sae_guard_busy());
    assert(strstr(output, "TERMINAL OUTCOME=queue_overflow") != NULL);
    assert(strstr(output, "RX_DROPS=4294967295") != NULL);
}

static void test_output_failure_fail_closes_and_prestart_cancel(void)
{
    const char *start[] = {"sae_guard", "start"};
    const char *stop[] = {"sae_guard", "stop"};

    reset_fixture();
    assert(command(2, start) == 0);
    sae_guard_report_output_failure();
    assert(sae_guard_busy());
    assert(command(2, stop) == 0);
    assert(strstr(output, "TERMINAL OUTCOME=output_failed") != NULL);

    reset_fixture();
    block_scan = true;
    command_thread_t starting = {.argc = 2, .argv = start};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, run_command, &starting) == 0);
    wait_for_scan();
    assert(command(2, stop) == 0);
    release_scan_gate();
    assert(pthread_join(thread, NULL) == 0);
    assert(starting.result != 0 && start_calls == 0U && release_calls == 1U);
    assert(!sae_guard_busy());
    assert(strstr(output, "TERMINAL OUTCOME=stopped") != NULL);
}

static void test_pending_output_blocks_restart_and_init_requires_all_hooks(void)
{
    reset_fixture();
    output_idle = false;
    const char *start[] = {"sae_guard", "start"};
    assert(command(2, start) != 0 && start_calls == 0U);
    assert(sae_guard_busy());
    output_idle = true;
    assert(!sae_guard_busy());

    sae_guard_runtime_hooks_t bad_runtime = runtime_hooks;
    bad_runtime.monotonic_us = NULL;
    assert(!sae_guard_init(&bad_runtime, &output_hooks));
    sae_guard_output_hooks_t bad_output = output_hooks;
    bad_output.complete = NULL;
    assert(!sae_guard_init(&runtime_hooks, &bad_output));
}

static void test_concurrent_start_is_busy_and_stale_consumer_is_inert(void)
{
    reset_fixture();
    block_scan = true;
    const char *start[] = {"sae_guard", "start"};
    const char *stop[] = {"sae_guard", "stop"};
    command_thread_t starting = {.argc = 2, .argv = start};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, run_command, &starting) == 0);
    wait_for_scan();
    assert(command(2, start) != 0);
    assert(strstr(output, "TERMINAL OUTCOME=busy") != NULL);
    assert(command(2, stop) == 0);
    release_scan_gate();
    assert(pthread_join(thread, NULL) == 0);
    assert(starting.result != 0 && start_calls == 0U && release_calls == 1U);

    reset_fixture();
    assert(command(2, start) == 0);
    wifi_security_session_config_t stale = active_config;
    assert(command(2, stop) == 0);
    size_t before = output_used;
    uint8_t anti_clogging[8] = {3, 0, 1, 0, 76, 0, 19, 0};
    wifi_security_decoded_t decoded = frame_for(scan_fixture[0], anti_clogging,
                                                sizeof(anti_clogging));
    wifi_security_frame_slot_t slot = {.channel = 1U, .rssi = -20};
    assert(stale.consume(stale.context, &slot, &decoded));
    assert(output_used == before);
}

static void test_start_rollback_outcomes_and_restart_clears_counters(void)
{
    const char *start[] = {"sae_guard", "start"};
    const char *status[] = {"sae_guard", "status"};
    const char *stop[] = {"sae_guard", "stop"};

    reset_fixture();
    scan_succeeds = false;
    assert(command(2, start) != 0);
    assert(start_calls == 0U && release_calls == 0U && !sae_guard_busy());
    assert(strstr(output, "TERMINAL OUTCOME=invalid") != NULL);

    reset_fixture();
    start_result = WIFI_SECURITY_SESSION_WORKER_FAILED;
    assert(command(2, start) != 0);
    assert(start_calls == 1U && release_calls == 1U && !sae_guard_busy());
    assert(strstr(output, "TERMINAL OUTCOME=invalid") != NULL);

    reset_fixture();
    assert(command(2, start) == 0);
    uint8_t anti_clogging[8] = {3, 0, 1, 0, 76, 0, 19, 0};
    wifi_security_decoded_t decoded = frame_for(scan_fixture[0], anti_clogging,
                                                sizeof(anti_clogging));
    wifi_security_frame_slot_t slot = {.channel = 6U, .rssi = -30};
    assert(active_config.consume(active_config.context, &slot, &decoded));
    uint32_t first_generation = runtime_generation;
    assert(command(2, stop) == 0);
    output_used = 0U;
    output[0] = '\0';
    assert(command(2, start) == 0);
    assert(runtime_generation > first_generation);
    assert(command(2, status) == 0);
    assert(strstr(output, "OBSERVATIONS=0 COMMITS=0 CONFIRMS=0") != NULL);
    assert(strstr(output, "ANTI_CLOGGING=0") != NULL);
    assert(command(2, stop) == 0);
}

static void test_concurrent_stops_share_one_cleanup_terminal(void)
{
    const char *start[] = {"sae_guard", "start"};
    const char *stop[] = {"sae_guard", "stop"};
    command_thread_t first = {.argc = 2, .argv = stop};
    command_thread_t second = {.argc = 2, .argv = stop};
    pthread_t first_thread, second_thread;

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    block_stop_cleanup = true;
    assert(pthread_create(&first_thread, NULL, run_command, &first) == 0);
    wait_for_flag(&stop_cleanup_entered);
    assert(pthread_create(&second_thread, NULL, run_command, &second) == 0);
    wait_for_stop_calls(2U);
    release_flag(&release_stop_cleanup);
    assert(pthread_join(first_thread, NULL) == 0);
    assert(pthread_join(second_thread, NULL) == 0);
    assert(first.result == 0 && second.result == 0);
    assert(!sae_guard_busy() && release_calls == 1U);
    assert_one_terminal("stopped");
}

static void test_stop_after_commit_and_consume_burst_ordering(void)
{
    const char *start[] = {"sae_guard", "start"};
    const char *stop[] = {"sae_guard", "stop"};
    command_thread_t starting = {.argc = 2, .argv = start};
    pthread_t start_thread;

    reset_fixture();
    block_start_return = true;
    assert(pthread_create(&start_thread, NULL, run_command, &starting) == 0);
    wait_for_flag(&start_committed);
    assert(command(2, stop) == 0);
    assert(!borrowed && release_calls == 1U);
    release_flag(&release_start_return);
    assert(pthread_join(start_thread, NULL) == 0);
    assert(starting.result != 0 && !sae_guard_busy());
    assert(strstr(output, " ARMED ") == NULL);
    assert_one_terminal("stopped");

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    block_event_write = true;
    consume_thread_t consuming = {0};
    command_thread_t stopping = {.argc = 2, .argv = stop};
    pthread_t consume_thread, stop_thread;
    assert(pthread_create(&consume_thread, NULL, run_anti_clogging_consume,
                          &consuming) == 0);
    wait_for_flag(&event_write_entered);
    assert(pthread_create(&stop_thread, NULL, run_command, &stopping) == 0);
    wait_for_flag(&stop_cleanup_done);
    release_flag(&release_event_write);
    assert(pthread_join(consume_thread, NULL) == 0);
    assert(pthread_join(stop_thread, NULL) == 0);
    assert(consuming.result && stopping.result == 0 && !sae_guard_busy());
    const char *event = strstr(output, "REASON=anti_clogging");
    const char *terminal = strstr(output, "TERMINAL OUTCOME=stopped");
    assert(event != NULL && terminal != NULL && event < terminal);
    assert(occurrences("TERMINAL OUTCOME=") == 1U);
}

static void test_uncertain_cleanup_retries_and_terminal_precedence(void)
{
    const char *start[] = {"sae_guard", "start"};
    const char *stop[] = {"sae_guard", "stop"};
    const wifi_security_session_result_t failures[] = {
        WIFI_SECURITY_SESSION_JOIN_TIMEOUT,
        WIFI_SECURITY_SESSION_RESTORE_FAILED,
        WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED,
        WIFI_SECURITY_SESSION_CLEANUP_FAILED,
    };
    const char *outcomes[] = {
        "timeout", "restore_failed", "restore_failed", "restore_failed",
    };
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); ++i) {
        reset_fixture();
        assert(command(2, start) == 0);
        clear_output();
        stop_succeeds = false;
        stop_reason = failures[i];
        wipe_before_stop_failure = failures[i] ==
                                   WIFI_SECURITY_SESSION_CLEANUP_FAILED;
        assert(command(2, stop) != 0);
        assert(sae_guard_busy());
        assert(release_calls == (wipe_before_stop_failure ? 1U : 0U));
        assert_one_terminal(outcomes[i]);
        clear_output();
        stop_succeeds = true;
        assert(command(2, stop) == 0);
        assert(!sae_guard_busy() && release_calls == 1U);
        assert_one_terminal("stopped");
    }

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    assert(pthread_mutex_lock(&runtime_lock) == 0);
    shared_runtime.status.dropped_queue = 1U;
    assert(pthread_mutex_unlock(&runtime_lock) == 0);
    sae_guard_report_output_failure();
    stop_succeeds = false;
    stop_reason = WIFI_SECURITY_SESSION_RESTORE_FAILED;
    assert(command(2, stop) != 0);
    assert_one_terminal("output_failed");
    assert(strstr(output, "RX_DROPS=1") != NULL);
    clear_output();
    stop_succeeds = true;
    assert(command(2, stop) == 0);
    assert_one_terminal("output_failed");
}

static void test_late_output_failure_and_failed_admission_token(void)
{
    const char *start[] = {"sae_guard", "start"};
    const char *status[] = {"sae_guard", "status"};
    const char *stop[] = {"sae_guard", "stop"};

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    block_terminal_format = true;
    command_thread_t stopping = {.argc = 2, .argv = stop};
    pthread_t stop_thread;
    assert(pthread_create(&stop_thread, NULL, run_command, &stopping) == 0);
    wait_for_flag(&terminal_format_entered);
    sae_guard_report_output_failure();
    release_flag(&release_terminal_format);
    assert(pthread_join(stop_thread, NULL) == 0);
    assert(stopping.result == 0 && !sae_guard_busy());
    assert_one_terminal("output_failed");
    assert(strstr(output, "OUTPUT_FAILURES=1") != NULL);

    clear_output();
    output_idle = false;
    unsigned starts_before = start_calls;
    assert(command(2, start) != 0);
    assert(start_calls == starts_before && sae_guard_busy());
    assert_one_terminal("busy");
    output_idle = true;
    assert(!sae_guard_busy());

    reset_fixture();
    fail_next_output = true;
    retain_failed_admission_token = true;
    block_failed_write_return = true;
    command_thread_t status_call = {.argc = 2, .argv = status};
    command_thread_t start_call = {.argc = 2, .argv = start};
    pthread_t status_thread, start_thread;
    assert(pthread_create(&status_thread, NULL, run_command, &status_call) == 0);
    wait_for_flag(&failed_write_entered);
    assert(failed_admission_token_retained && sae_guard_busy());
    assert(pthread_create(&start_thread, NULL, run_command, &start_call) == 0);
    wait_for_output_attempts(2U);
    assert(start_calls == 0U);
    release_flag(&release_failed_write_return);
    assert(pthread_join(status_thread, NULL) == 0);
    assert(pthread_join(start_thread, NULL) == 0);
    assert(status_call.result != 0 && start_call.result != 0);
    assert(!failed_admission_token_retained && !sae_guard_busy());
    assert(start_calls == 0U);
    assert_one_terminal("busy");
    assert(command(2, status) == 0);
    assert(strstr(output, "OUTPUT_FAILURES=1") != NULL);
}

static void test_armed_failure_racing_stop_has_one_output_failed_terminal(void)
{
    const char *start[] = {"sae_guard", "start"};
    const char *stop[] = {"sae_guard", "stop"};
    command_thread_t starting = {.argc = 2, .argv = start};
    command_thread_t stopping = {.argc = 2, .argv = stop};
    pthread_t start_thread, stop_thread;

    reset_fixture();
    fail_next_output = true;
    block_failed_write_return = true;
    assert(pthread_create(&start_thread, NULL, run_command, &starting) == 0);
    wait_for_flag(&failed_write_entered);
    assert(pthread_create(&stop_thread, NULL, run_command, &stopping) == 0);
    wait_for_flag(&stop_cleanup_done);
    release_flag(&release_failed_write_return);
    assert(pthread_join(start_thread, NULL) == 0);
    assert(pthread_join(stop_thread, NULL) == 0);
    assert(starting.result != 0 && stopping.result == 0 && !sae_guard_busy());
    assert_one_terminal("output_failed");
    assert(strstr(output, " ARMED ") == NULL);
    assert(strstr(output, "TERMINAL OUTCOME=stopped") == NULL);
}

static void test_stale_generation_and_real_runtime_loss_truncation(void)
{
    const char *start[] = {"sae_guard", "start"};
    const char *status[] = {"sae_guard", "status"};
    const char *stop[] = {"sae_guard", "stop"};

    reset_fixture();
    assert(command(2, start) == 0);
    uint32_t old_generation = runtime_generation;
    wifi_security_session_config_t old_config = active_config;
    assert(command(2, stop) == 0);
    clear_output();
    assert(command(2, start) == 0);
    assert(runtime_generation != old_generation);
    assert(!old_config.validate(old_config.context));
    old_config.wipe(old_config.context);
    assert(sae_guard_busy());
    uint8_t old_body[8] = {3, 0, 1, 0, 76, 0, 19, 0};
    wifi_security_decoded_t old_decoded = frame_for(
        scan_fixture[0], old_body, sizeof(old_body));
    wifi_security_frame_slot_t old_slot = {.channel = 1U, .rssi = -20};
    assert(old_config.consume(old_config.context, &old_slot, &old_decoded));
    assert(strstr(output, "REASON=anti_clogging") == NULL);
    uint8_t raw[32];
    (void)raw_sae_auth(raw, sizeof(raw), scan_fixture[0], 76U);
    assert(!wifi_security_runtime_submit(&shared_runtime, old_generation,
        raw, sizeof(raw), 1U, -20, 1U));
    assert(wifi_security_runtime_drain(&shared_runtime) == 0U);
    assert(command(2, status) == 0);
    assert(strstr(output, "RECEIVED=0") != NULL);
    assert(strstr(output, "REASON=anti_clogging") == NULL);
    assert(command(2, stop) == 0);

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    induce_real_pool_and_queue_loss_with_truncation();
    assert(submit_and_drain_sae(1600U, 76U));
    assert(submit_and_drain_sae(1600U, 76U));
    assert(strstr(output, "REASON=malformed") != NULL);
    assert(strstr(output, "INTERPRETATION=malformed_observation") != NULL);
    assert(command(2, status) == 0);
    assert(strstr(output, "MALFORMED=3") != NULL);
    assert(strstr(output, "CAPACITY_DROPS=0 PAIR_DROPS=0 MALFORMED_DROPS=0 RX_DROPS=2") != NULL);
    clear_output();
    assert(command(2, stop) == 0);
    assert_one_terminal("queue_overflow");
    assert(strstr(output, "RX_DROPS=2") != NULL);
}

int main(void)
{
    test_cli_validation_filter_and_snapshot_wipe();
    test_exact_idle_lifecycle_transcript();
    test_exact_busy_invalid_event_output_failure_and_retry_transcripts();
    test_worker_filter_and_sae_only_parse();
    test_runtime_conflicts_cleanup_retry_and_loss_precedence();
    test_output_failure_fail_closes_and_prestart_cancel();
    test_pending_output_blocks_restart_and_init_requires_all_hooks();
    test_concurrent_start_is_busy_and_stale_consumer_is_inert();
    test_start_rollback_outcomes_and_restart_clears_counters();
    test_concurrent_stops_share_one_cleanup_terminal();
    test_stop_after_commit_and_consume_burst_ordering();
    test_uncertain_cleanup_retries_and_terminal_precedence();
    test_late_output_failure_and_failed_admission_token();
    test_armed_failure_racing_stop_has_one_output_failed_terminal();
    test_stale_generation_and_real_runtime_loss_truncation();
    puts("PASS: SAE Guard CLI, filtering, lifecycle, rollback");
    return 0;
}
