#define _POSIX_C_SOURCE 200809L

#include "wps_guard.h"
#include "wifi_shield_channel.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t ap1[6] = {0x02, 1, 2, 3, 4, 5};
static const uint8_t ap2[6] = {0x06, 6, 7, 8, 9, 10};
static const uint8_t ap3[6] = {0x0a, 11, 12, 13, 14, 15};
static const uint8_t sta[6] = {0x0c, 16, 17, 18, 19, 20};

static wifi_shield_target_t scan_targets[3];
static size_t scan_count;
static bool snapshot_fail;
static unsigned snapshot_calls, release_calls, start_calls, stop_calls, now_calls;
static unsigned foundation_start_effects;
static uint64_t now_us;
static wifi_security_session_result_t start_result;
static wifi_security_session_result_t stop_reason;
static bool stop_ok, borrowed;
static bool wipe_before_stop_failure, feature_context_wiped;
static wifi_security_session_config_t saved_config;
static wifi_shield_target_t saved_start_targets[3];
static size_t saved_start_target_count;
static char output[65536];
static size_t output_used;
static unsigned output_calls;
static bool fail_next_output, worker_context;
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t runtime_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
static bool block_snapshot, snapshot_entered, release_snapshot_gate;
static bool block_start_return, start_succeeded, release_start_gate;
static bool block_primary_idle_gap, primary_gap_entered, release_primary_gap;
static bool block_primary_precommit_gap, primary_precommit_entered;
static bool release_primary_precommit_gap;
static bool block_primary_committed_gap, primary_committed_entered;
static bool release_primary_committed_gap;
static bool block_primary_poststate_gap, primary_poststate_entered;
static bool release_primary_poststate_gap;
static bool block_armed_write, armed_write_entered, release_armed_write;
static bool stop_cleanup_done;
static bool block_failed_write_return, failed_write_entered;
static bool release_failed_write_return;
static bool block_failed_write_leave, failed_write_leave_entered;
static bool release_failed_write_leave;
static _Thread_local bool primary_start_thread;
static _Thread_local unsigned thread_leave_count;
static _Thread_local bool output_lock_owned;
static _Thread_local bool previous_write_failed;
static wifi_security_runtime_t shared_runtime;
static uint32_t runtime_generation;
static bool bounded_output_enter;
static uint32_t last_output_enter_timeout_ms;
static bool output_idle;
static bool block_terminal_format, terminal_format_entered;
static bool release_terminal_format;
static bool retain_failed_admission_token, failed_admission_token_retained;
static unsigned output_enter_attempts;

static void fake_enter(void *context)
{
    (void)context;
    assert(pthread_mutex_lock(&state_mutex) == 0);
}

static void fake_leave(void *context)
{
    (void)context;
    assert(pthread_mutex_unlock(&state_mutex) == 0);
    ++thread_leave_count;
    if (primary_start_thread && block_primary_idle_gap && thread_leave_count == 1U) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        primary_gap_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!release_primary_gap)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
    if (primary_start_thread && block_primary_precommit_gap &&
        thread_leave_count == 2U) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        primary_precommit_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!release_primary_precommit_gap)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
    if (primary_start_thread && block_primary_committed_gap &&
        thread_leave_count == 3U) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        primary_committed_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!release_primary_committed_gap)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
    if (primary_start_thread && block_primary_poststate_gap &&
        thread_leave_count == 5U) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        primary_poststate_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!release_primary_poststate_gap)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
}

static bool fake_output_enter(void *context, uint32_t timeout_ms)
{
    (void)context;
    last_output_enter_timeout_ms = timeout_ms;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    ++output_enter_attempts;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    int result;
    if (bounded_output_enter) {
        struct timespec deadline;
        assert(clock_gettime(CLOCK_REALTIME, &deadline) == 0);
        deadline.tv_sec += (time_t)(timeout_ms / 1000U);
        deadline.tv_nsec += (long)(timeout_ms % 1000U) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            ++deadline.tv_sec;
            deadline.tv_nsec -= 1000000000L;
        }
        result = pthread_mutex_timedlock(&output_mutex, &deadline);
        if (result == ETIMEDOUT) return false;
    } else {
        result = pthread_mutex_lock(&output_mutex);
    }
    assert(result == 0);
    assert(!output_lock_owned);
    output_lock_owned = true;
    return true;
}

static void fake_output_leave(void *context)
{
    (void)context;
    assert(output_lock_owned);
    if (previous_write_failed && block_failed_write_leave) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        failed_write_leave_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!release_failed_write_leave)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
    previous_write_failed = false;
    output_lock_owned = false;
    assert(pthread_mutex_unlock(&output_mutex) == 0);
}

static bool fake_snapshot(void *context, wifi_shield_target_t **targets,
                          size_t *count)
{
    (void)context;
    ++snapshot_calls;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (block_snapshot) {
        snapshot_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!release_snapshot_gate)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    if (snapshot_fail || !targets || !count || scan_count == 0) return false;
    wifi_shield_target_t *copy = malloc(scan_count * sizeof(*copy));
    if (!copy) return false;
    memcpy(copy, scan_targets, scan_count * sizeof(*copy));
    *targets = copy;
    *count = scan_count;
    return true;
}

static void fake_release(void *context, wifi_shield_target_t *targets,
                         size_t count)
{
    (void)context;
    const uint8_t *bytes = (const uint8_t *)targets;
    for (size_t i = 0; i < count * sizeof(*targets); ++i) assert(bytes[i] == 0);
    ++release_calls;
    free(targets);
}

static uint64_t fake_now(void *context)
{
    (void)context;
    ++now_calls;
    return now_us;
}

static void runtime_enter(void *context)
{
    (void)context;
    assert(pthread_mutex_lock(&runtime_mutex) == 0);
}

static void runtime_leave(void *context)
{
    (void)context;
    assert(pthread_mutex_unlock(&runtime_mutex) == 0);
}

static void fake_runtime_status(void *context,
                                wifi_security_runtime_status_t *status)
{
    (void)context;
    wifi_security_runtime_get_status(&shared_runtime, status);
}

static bool uncertain_result(wifi_security_session_result_t result)
{
    return result == WIFI_SECURITY_SESSION_JOIN_TIMEOUT ||
           result == WIFI_SECURITY_SESSION_RESTORE_FAILED ||
           result == WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED ||
           result == WIFI_SECURITY_SESSION_CLEANUP_FAILED;
}

static wifi_security_session_result_t fake_start(
    void *context, const wifi_shield_target_t *targets, size_t target_count,
    const wifi_security_session_config_t *config)
{
    (void)context;
    ++start_calls;
    assert(targets != NULL && target_count != 0U && target_count <= 3U);
    assert(config && config->module == WIFI_SECURITY_MODULE_WPS_GUARD);
    assert(config->consume && config->validate && config->wipe && config->uncertainty);
    assert(config->initial_channel == targets[0].channel);
    memcpy(saved_start_targets, targets, target_count * sizeof(*targets));
    saved_start_target_count = target_count;
    if (target_count == 2U) {
        const uint8_t *trailing = (const uint8_t *)&targets[2];
        for (size_t i = 0U; i < sizeof(targets[2]); ++i)
            assert(trailing[i] == 0U);
    }
    saved_config = *config;
    if (!config->validate(config->context))
        return WIFI_SECURITY_SESSION_INVALID;
    ++foundation_start_effects;
    if (start_result == WIFI_SECURITY_SESSION_OK) {
        const wifi_security_runtime_config_t runtime_config = {
            .module = WIFI_SECURITY_MODULE_WPS_GUARD,
            .generation = ++runtime_generation,
            .context = config->context,
            .consume = config->consume
        };
        assert(wifi_security_runtime_start(&shared_runtime, &runtime_config));
        feature_context_wiped = false;
        borrowed = true;
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        if (block_start_return) {
            start_succeeded = true;
            assert(pthread_cond_broadcast(&gate_cond) == 0);
            while (!release_start_gate)
                assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        }
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    } else if (uncertain_result(start_result)) {
        borrowed = true;
        config->uncertainty(config->telemetry_context, start_result, true);
    } else if (start_result != WIFI_SECURITY_SESSION_BUSY &&
               start_result != WIFI_SECURITY_SESSION_BASELINE_BUSY) {
        config->wipe(config->context);
    }
    return start_result;
}

static bool fake_stop(void *context, uint32_t timeout_ms)
{
    (void)context;
    assert(timeout_ms == 5000U || timeout_ms == 77U);
    ++stop_calls;
    if (!borrowed) return true;
    if (!stop_ok) {
        if (wipe_before_stop_failure && !feature_context_wiped) {
            wifi_security_runtime_close_callbacks(&shared_runtime);
            wifi_security_runtime_request_stop(&shared_runtime);
            (void)wifi_security_runtime_drain(&shared_runtime);
            assert(wifi_security_runtime_finish(&shared_runtime));
            saved_config.wipe(saved_config.context);
            feature_context_wiped = true;
        }
        saved_config.uncertainty(saved_config.telemetry_context, stop_reason, true);
        return false;
    }
    if (!feature_context_wiped) {
        wifi_security_runtime_close_callbacks(&shared_runtime);
        wifi_security_runtime_request_stop(&shared_runtime);
        (void)wifi_security_runtime_drain(&shared_runtime);
        assert(wifi_security_runtime_finish(&shared_runtime));
        saved_config.wipe(saved_config.context);
        feature_context_wiped = true;
    }
    borrowed = false;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    stop_cleanup_done = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    return true;
}

static bool fake_write(void *context, const char *line, size_t length)
{
    (void)context;
    assert(output_lock_owned);
    ++output_calls;
    assert(line && length != 0 && length == strlen(line));
    if (strstr(line, " BSSID=") != NULL) assert(worker_context);
    if (strstr(line, " ARMED ") != NULL && block_armed_write) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        armed_write_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!release_armed_write)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
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
            assert(pthread_mutex_lock(&gate_mutex) == 0);
            failed_write_entered = true;
            assert(pthread_cond_broadcast(&gate_cond) == 0);
            while (!release_failed_write_return)
                assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
            assert(pthread_mutex_unlock(&gate_mutex) == 0);
        }
        return false;
    }
    assert(output_used + length < sizeof(output));
    memcpy(output + output_used, line, length);
    output_used += length;
    output[output_used] = '\0';
    return true;
}

static void fake_output_complete(void *context, bool accepted)
{
    (void)context;
    assert(output_lock_owned);
    if (!accepted && failed_admission_token_retained) {
        assert(!output_idle);
        failed_admission_token_retained = false;
        output_idle = true;
    }
}

static bool fake_write_terminal(void *context, const wps_guard_status_t *status,
                                const char *outcome)
{
    (void)context;
    assert(output_lock_owned);
    if (block_terminal_format) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        terminal_format_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!release_terminal_format)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
    char line[WPS_GUARD_LINE_MAX];
    int length = wps_guard_format_terminal_for_output(
        line, sizeof(line), status, outcome);
    return length > 0 && fake_write(NULL, line, (size_t)length);
}

static bool fake_output_idle(void *context)
{
    (void)context;
    return output_idle;
}

static const wps_guard_runtime_hooks_t runtime_hooks = {
    .enter = fake_enter, .leave = fake_leave,
    .scan_snapshot = fake_snapshot, .scan_release = fake_release,
    .monotonic_us = fake_now, .status_snapshot = fake_runtime_status,
    .start = fake_start, .stop = fake_stop
};
static const wps_guard_output_hooks_t output_hooks = {
    .enter = fake_output_enter, .leave = fake_output_leave, .write = fake_write,
    .write_terminal = fake_write_terminal, .complete = fake_output_complete,
    .idle = fake_output_idle
};

static void clear_output(void)
{
    memset(output, 0, sizeof(output));
    output_used = 0;
}

static size_t occurrences(const char *needle)
{
    size_t count = 0;
    for (const char *p = output; (p = strstr(p, needle)) != NULL; p += strlen(needle))
        ++count;
    return count;
}

static void reset_fixture(void)
{
    if (borrowed) {
        stop_ok = true;
        wifi_security_runtime_close_callbacks(&shared_runtime);
        wifi_security_runtime_request_stop(&shared_runtime);
        (void)wifi_security_runtime_drain(&shared_runtime);
        assert(wifi_security_runtime_finish(&shared_runtime));
        if (!feature_context_wiped) saved_config.wipe(saved_config.context);
        borrowed = false;
    }
    const wifi_security_runtime_hooks_t shared_hooks = {
        .enter = runtime_enter, .leave = runtime_leave, .notify = NULL
    };
    assert(wifi_security_runtime_init(&shared_runtime, &shared_hooks, 1U));
    runtime_generation = 0U;
    memset(scan_targets, 0, sizeof(scan_targets));
    memcpy(scan_targets[0].bssid, ap1, 6);
    memcpy(scan_targets[1].bssid, ap2, 6);
    memcpy(scan_targets[2].bssid, ap3, 6);
    scan_targets[0].channel = 1U;
    scan_targets[1].channel = 6U;
    scan_targets[2].channel = 11U;
    memcpy(scan_targets[0].ssid, "SCAN-1", sizeof("SCAN-1"));
    memcpy(scan_targets[1].ssid, "SCAN-2", sizeof("SCAN-2"));
    memcpy(scan_targets[2].ssid, "SCAN-3", sizeof("SCAN-3"));
    scan_targets[0].wpa2_psk_ccmp = true;
    scan_targets[1].wpa2_psk_ccmp = false;
    scan_targets[2].wpa2_psk_ccmp = true;
    scan_count = 3;
    snapshot_fail = false;
    snapshot_calls = release_calls = start_calls = stop_calls = now_calls = 0;
    foundation_start_effects = 0;
    memset(saved_start_targets, 0, sizeof(saved_start_targets));
    saved_start_target_count = 0U;
    now_us = 100;
    start_result = WIFI_SECURITY_SESSION_OK;
    stop_reason = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    stop_ok = true;
    wipe_before_stop_failure = feature_context_wiped = false;
    fail_next_output = worker_context = false;
    block_snapshot = snapshot_entered = release_snapshot_gate = false;
    block_start_return = start_succeeded = release_start_gate = false;
    block_primary_idle_gap = primary_gap_entered = release_primary_gap = false;
    block_primary_precommit_gap = primary_precommit_entered = false;
    release_primary_precommit_gap = false;
    block_primary_committed_gap = primary_committed_entered = false;
    release_primary_committed_gap = false;
    block_primary_poststate_gap = primary_poststate_entered = false;
    release_primary_poststate_gap = false;
    block_armed_write = armed_write_entered = release_armed_write = false;
    stop_cleanup_done = false;
    block_failed_write_return = failed_write_entered = false;
    release_failed_write_return = false;
    block_failed_write_leave = failed_write_leave_entered = false;
    release_failed_write_leave = false;
    previous_write_failed = false;
    bounded_output_enter = false;
    last_output_enter_timeout_ms = 0U;
    output_idle = true;
    block_terminal_format = terminal_format_entered = false;
    release_terminal_format = false;
    retain_failed_admission_token = failed_admission_token_retained = false;
    output_enter_attempts = 0U;
    primary_start_thread = false;
    thread_leave_count = 0U;
    output_calls = 0;
    clear_output();
    assert(wps_guard_init(&runtime_hooks, &output_hooks));
}

static int command(int argc, const char *const values[])
{
    return wps_guard_command(argc, (char **)values);
}

static void expect_invalid(int argc, const char *const values[])
{
    unsigned before = start_calls;
    assert(command(argc, values) != 0);
    assert(start_calls == before);
}

static void test_cli_validation_and_owned_snapshot(void)
{
    reset_fixture();
    const char *missing[] = {"wps_guard"};
    const char *missing_indexes[] = {"wps_guard", "start", "--only"};
    const char *duplicate_only[] = {"wps_guard", "start", "--only", "1", "--only", "2"};
    const char *nonnumeric[] = {"wps_guard", "start", "--only", "1x"};
    const char *zero[] = {"wps_guard", "start", "--only", "0"};
    const char *range[] = {"wps_guard", "start", "--only", "4"};
    const char *duplicate_index[] = {"wps_guard", "start", "--only", "2", "2"};
    const char *status_tail[] = {"wps_guard", "status", "tail"};
    const char *stop_tail[] = {"wps_guard", "stop", "tail"};
    expect_invalid(1, missing);
    expect_invalid(3, missing_indexes);
    expect_invalid(6, duplicate_only);
    expect_invalid(4, nonnumeric);
    expect_invalid(4, zero);
    expect_invalid(4, range);
    expect_invalid(5, duplicate_index);
    expect_invalid(3, status_tail);
    expect_invalid(3, stop_tail);

    unsigned releases = release_calls;
    scan_targets[1].bssid[0] = 1;
    const char *bare[] = {"wps_guard", "start"};
    expect_invalid(2, bare);
    assert(release_calls == releases + 1U);
    memcpy(scan_targets[1].bssid, ap2, 6);
    memset(scan_targets[2].bssid, 0, 6);
    expect_invalid(2, bare);
    assert(release_calls == releases + 2U);
    memcpy(scan_targets[2].bssid, ap3, 6);

    const char *start[] = {"wps_guard", "start", "--only", "3", "1"};
    assert(command(5, start) == 0);
    assert(start_calls == 1 && snapshot_calls >= 3 &&
           release_calls == releases + 2U);
    assert(saved_start_target_count == 2U);
    /* Existing selection semantics preserve scan order, not argv order. */
    assert(memcmp(saved_start_targets[0].bssid, ap1, 6U) == 0 &&
           saved_start_targets[0].channel == 1U);
    assert(strcmp(saved_start_targets[0].ssid, "SCAN-1") == 0 &&
           saved_start_targets[0].wpa2_psk_ccmp);
    assert(memcmp(saved_start_targets[1].bssid, ap3, 6U) == 0 &&
           saved_start_targets[1].channel == 11U);
    assert(strcmp(saved_start_targets[1].ssid, "SCAN-3") == 0 &&
           saved_start_targets[1].wpa2_psk_ccmp);
    assert(saved_config.initial_channel == 1U);
    assert(wps_guard_busy());
    assert(strstr(output, "[WPS_GUARD/1] ARMED TARGETS=2\r\n"));
    size_t armed_offset = (size_t)(strstr(output, " ARMED ") - output);
    assert(armed_offset < output_used); /* fake Start returned before publication */
    unsigned snapshots = snapshot_calls;
    assert(command(5, start) != 0);
    assert(snapshot_calls == snapshots && start_calls == 1);
    assert(wps_guard_stop(77U));
    assert(!wps_guard_busy() && release_calls == releases + 3U);
}

static void test_exact_idle_lifecycle_transcript(void)
{
    static const char *const zeros =
        "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0";
    char expected[2048];
    const char *start[] = {"wps_guard", "start", "--only", "1"};
    const char *status[] = {"wps_guard", "status"};
    const char *stop[] = {"wps_guard", "stop"};

    reset_fixture();
    assert(command(4, start) == 0);
    assert(strcmp(output, "[WPS_GUARD/1] ARMED TARGETS=1\r\n") == 0);

    clear_output();
    assert(command(2, status) == 0);
    int length = snprintf(expected, sizeof(expected),
        "[WPS_GUARD/1] STATUS RECEIVED=0 FILTERED=0 UNRELATED=0"
        " FRAGMENTS=0 RETRANSMISSIONS=0 COMPLETIONS=0 ANOMALIES=0"
        " TIMEOUTS=0 CAPACITY_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0"
        " ACTIVE=0 RUNNING=1 STOPPING=0 REASONS=%s\r\n", zeros);
    assert(length > 0 && (size_t)length < sizeof(expected));
    assert(strcmp(output, expected) == 0);

    clear_output();
    assert(command(2, stop) == 0);
    length = snprintf(expected, sizeof(expected),
        "[WPS_GUARD/1] TERMINAL OUTCOME=stopped RECEIVED=0 FILTERED=0"
        " UNRELATED=0 FRAGMENTS=0 RETRANSMISSIONS=0 COMPLETIONS=0"
        " ANOMALIES=0 TIMEOUTS=0 CAPACITY_DROPS=0 RX_DROPS=0"
        " OUTPUT_FAILURES=0 ACTIVE=0 RUNNING=0 STOPPING=0 REASONS=%s\r\n",
        zeros);
    assert(length > 0 && (size_t)length < sizeof(expected));
    assert(strcmp(output, expected) == 0);

    clear_output();
    const char *invalid[] = {"wps_guard", "start", "--only"};
    assert(command(3, invalid) != 0);
    length = snprintf(expected, sizeof(expected),
        "[WPS_GUARD/1] TERMINAL OUTCOME=invalid RECEIVED=0 FILTERED=0"
        " UNRELATED=0 FRAGMENTS=0 RETRANSMISSIONS=0 COMPLETIONS=0"
        " ANOMALIES=0 TIMEOUTS=0 CAPACITY_DROPS=0 RX_DROPS=0"
        " OUTPUT_FAILURES=0 ACTIVE=0 RUNNING=0 STOPPING=0 REASONS=%s\r\n",
        zeros);
    assert(length > 0 && (size_t)length < sizeof(expected));
    assert(strcmp(output, expected) == 0);
}

static void assert_exact_output(const char *expected)
{
    if (strcmp(output, expected) != 0)
        fprintf(stderr, "EXPECTED:\n%sACTUAL:\n%s", expected, output);
    assert(strcmp(output, expected) == 0);
}

static void exact_zero_terminal(char *expected, size_t capacity,
                                const char *outcome,
                                unsigned output_failures,
                                unsigned running, unsigned stopping)
{
    int length = snprintf(expected, capacity,
        "[WPS_GUARD/1] TERMINAL OUTCOME=%s RECEIVED=0 FILTERED=0"
        " UNRELATED=0 FRAGMENTS=0 RETRANSMISSIONS=0 COMPLETIONS=0"
        " ANOMALIES=0 TIMEOUTS=0 CAPACITY_DROPS=0 RX_DROPS=0"
        " OUTPUT_FAILURES=%u ACTIVE=0 RUNNING=%u STOPPING=%u"
        " REASONS=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0\r\n",
        outcome, output_failures, running, stopping);
    assert(length > 0 && (size_t)length < capacity);
}

static bool deliver(const uint8_t bssid[6], bool recognizable, uint8_t flags,
                    uint16_t total, uint8_t channel, int8_t rssi);

static void test_exact_busy_event_output_failure_and_retained_retry(void)
{
    char expected[2048];
    const char *start[] = {"wps_guard", "start"};
    const char *stop[] = {"wps_guard", "stop"};

    reset_fixture();
    start_result = WIFI_SECURITY_SESSION_BUSY;
    assert(command(2, start) == 1);
    exact_zero_terminal(expected, sizeof(expected), "busy", 0U, 0U, 0U);
    assert_exact_output(expected);

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    assert(deliver(ap1, true, 1U, 0U, 6U, -60));
    assert_exact_output(
        "[WPS_GUARD/1] BSSID=02:01:02:03:04:05"
        " STA=0c:10:11:12:13:14 DIR=ap_to_sta CH=6 RSSI=-60 OPCODE=4"
        " FRAGMENTS=1 DECLARED=0 OBSERVED=4 RETRANSMITS=0"
        " REASON=first_missing_length SEVERITY=alert TRUNCATED=0 TS_US=100\r\n");
    clear_output();
    assert(command(2, stop) == 0);

    reset_fixture();
    fail_next_output = true;
    assert(command(2, start) == 1);
    exact_zero_terminal(expected, sizeof(expected), "output_failed", 1U,
                        0U, 0U);
    assert_exact_output(expected);

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    stop_ok = false;
    stop_reason = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    assert(command(2, stop) == 1);
    exact_zero_terminal(expected, sizeof(expected), "timeout", 0U, 1U, 1U);
    assert_exact_output(expected);
    assert(wps_guard_busy() && release_calls == 0U);
    clear_output();
    stop_ok = true;
    assert(command(2, stop) == 0);
    exact_zero_terminal(expected, sizeof(expected), "stopped", 0U, 0U, 0U);
    assert_exact_output(expected);
    assert(!wps_guard_busy() && release_calls == 1U);
}

static void be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static size_t wsc(uint8_t *p, uint8_t flags, uint16_t total,
                  const uint8_t *payload, size_t length)
{
    static const uint8_t header[] = {
        2, 0, 0, 0, 1, 37, 0, 0, 254, 0, 0x37, 0x2a,
        0, 0, 0, 1, 4, 0
    };
    memcpy(p, header, sizeof(header));
    p[17] = flags;
    size_t offset = sizeof(header);
    if (flags & 2U) { be16(p + offset, total); offset += 2; }
    if (length) memcpy(p + offset, payload, length);
    be16(p + 2, (uint16_t)(offset + length - 4));
    be16(p + 6, (uint16_t)(offset + length - 4));
    return offset + length;
}

static size_t mac_frame(uint8_t *mac, const uint8_t bssid[6], bool recognizable,
                        uint8_t flags, uint16_t total)
{
    memset(mac, 0, 128);
    mac[0] = 0x08; mac[1] = 0x02;
    memcpy(mac + 4, sta, 6); memcpy(mac + 10, bssid, 6); memcpy(mac + 16, bssid, 6);
    const uint8_t snap[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
    memcpy(mac + 24, snap, sizeof(snap));
    const uint8_t payload[] = {1, 2, 3, 4};
    size_t length = wsc(mac + 32, flags, total, payload, sizeof(payload));
    if (!recognizable) mac[32 + 9] ^= 0x80U;
    return 32 + length;
}

static bool deliver(const uint8_t bssid[6], bool recognizable, uint8_t flags,
                    uint16_t total, uint8_t channel, int8_t rssi)
{
    uint8_t mac[128];
    size_t length = mac_frame(mac, bssid, recognizable, flags, total);
    wifi_security_decoded_t decoded;
    assert(wifi_security_decode(mac, length, &decoded));
    wifi_security_frame_slot_t slot = {0};
    slot.channel = channel; slot.rssi = rssi;
    worker_context = true;
    bool result = saved_config.consume(saved_config.context, &slot, &decoded);
    worker_context = false;
    return result;
}

static void test_filter_worker_clock_and_stop_fence(void)
{
    reset_fixture();
    const char *start[] = {"wps_guard", "start", "--only", "1"};
    assert(command(4, start) == 0);
    assert(saved_start_target_count == 1U &&
           saved_start_targets[0].channel == 1U);
    clear_output();
    assert(deliver(ap2, true, 1, 0, 11, -80));
    assert(now_calls == 0);
    assert(deliver(ap1, false, 0, 0, 1, -42));
    assert(now_calls == 1);
    /* The selected target was captured on channel 1. Once the profile owns a
     * received channel-6 slot, legacy filtering remains BSSID-based and the
     * frame reaches the one existing consumer instead of being discarded as
     * if the scan-time channel were a permanent filter. */
    assert(deliver(ap1, true, 3, 10, 6, -51));
    assert(now_calls == 2);
    assert(output_used == 0); /* selected valid first fragment is not an anomaly */

    now_us = 5000102U;
    assert(deliver(ap1, false, 0, 0, 1, -43));
    assert(now_calls == 3); /* expiry and decode share this single sample */
    assert(strstr(output, "REASON=session_timeout"));
    assert(strstr(output, "CH=6 RSSI=-51"));

    const char *status[] = {"wps_guard", "status"};
    assert(command(2, status) == 0);
    assert(strstr(output, "RECEIVED=4 FILTERED=1 UNRELATED=2 FRAGMENTS=1"));

    now_us = 6000000U;
    assert(deliver(ap1, true, 3, 10, 6, -55));
    unsigned before_stop_time = now_calls;
    clear_output();
    const char *stop[] = {"wps_guard", "stop"};
    assert(command(2, stop) == 0);
    assert(strstr(output, "TERMINAL OUTCOME=stopped"));
    assert(!wps_guard_busy());
    size_t stopped_length = output_used;
    assert(saved_config.consume(saved_config.context,
        &(wifi_security_frame_slot_t){0}, &(wifi_security_decoded_t){0}));
    assert(now_calls == before_stop_time && output_used == stopped_length);
    unsigned stopped_calls = output_calls;
    assert(command(2, stop) == 0);
    assert(output_calls == stopped_calls); /* repeated Stop is a silent no-op */
}

typedef struct {
    int argc;
    const char *const *argv;
    int result;
    bool primary;
} command_thread_t;

static void *run_command_thread(void *opaque)
{
    command_thread_t *command = opaque;
    primary_start_thread = command->primary;
    thread_leave_count = 0U;
    command->result = wps_guard_command(command->argc, (char **)command->argv);
    return NULL;
}

static void wait_for(bool *condition)
{
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while (!*condition) assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}

static void release_gate(bool *gate)
{
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    *gate = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}

static void wait_for_output_enter_attempts(unsigned expected)
{
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while (output_enter_attempts < expected)
        assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}

static void assert_one_terminal(const char *outcome);

static void test_concurrent_start_and_stop_boundaries(void)
{
    const char *start[] = {"wps_guard", "start"};
    const char *stop[] = {"wps_guard", "stop"};
    pthread_t thread;
    command_thread_t first = {.argc = 2, .argv = start, .primary = true};

    /* Catch a check-then-set idle claim: pause the primary immediately after
     * its first state-lock release, then let a competing Start claim idle. */
    reset_fixture();
    block_primary_idle_gap = true;
    assert(pthread_create(&thread, NULL, run_command_thread, &first) == 0);
    wait_for(&primary_gap_entered);
    unsigned snapshots = snapshot_calls;
    assert(command(2, start) != 0);
    assert(snapshot_calls == snapshots);
    release_gate(&release_primary_gap);
    assert(pthread_join(thread, NULL) == 0);
    assert(first.result == 0 && start_calls == 1 && snapshot_calls == snapshots + 1U);
    assert(command(2, stop) == 0);

    /* Stop while snapshot acquisition is blocked must latch cancellation.
     * Once the snapshot returns, Start may release it but may not call runtime. */
    reset_fixture();
    first = (command_thread_t){.argc = 2, .argv = start};
    block_snapshot = true;
    assert(pthread_create(&thread, NULL, run_command_thread, &first) == 0);
    wait_for(&snapshot_entered);
    assert(command(2, stop) == 0);
    release_gate(&release_snapshot_gate);
    assert(pthread_join(thread, NULL) == 0);
    assert(first.result != 0 && start_calls == 0 && !wps_guard_busy());
    assert(strstr(output, " ARMED ") == NULL);
    assert(release_calls == 1);
    assert_one_terminal("stopped");

    /* The feature-local runtime-start commit is the linearization point. A
     * Stop ordered after target assignment but before that commit must prevent
     * even the foundation Start hook from being called. */
    reset_fixture();
    first = (command_thread_t){.argc = 2, .argv = start, .primary = true};
    block_primary_precommit_gap = true;
    assert(pthread_create(&thread, NULL, run_command_thread, &first) == 0);
    wait_for(&primary_precommit_entered);
    assert(command(2, stop) == 0);
    assert(start_calls == 0 && stop_calls == 0);
    release_gate(&release_primary_precommit_gap);
    assert(pthread_join(thread, NULL) == 0);
    assert(first.result != 0 && start_calls == 0 && stop_calls == 0);
    assert(!wps_guard_busy() && release_calls == 1);
    assert(strstr(output, " ARMED ") == NULL);
    assert_one_terminal("stopped");

    /* Once the feature-local commit is published, Stop may call an idle
     * foundation Stop before the Start hook is entered. The later validation
     * must reject the cancelled epoch before any lease/radio side effect. */
    reset_fixture();
    first = (command_thread_t){.argc = 2, .argv = start, .primary = true};
    block_primary_committed_gap = true;
    assert(pthread_create(&thread, NULL, run_command_thread, &first) == 0);
    wait_for(&primary_committed_entered);
    assert(command(2, stop) == 0);
    assert(start_calls == 0 && foundation_start_effects == 0 && stop_calls == 1);
    release_gate(&release_primary_committed_gap);
    assert(pthread_join(thread, NULL) == 0);
    assert(first.result != 0 && start_calls == 1 && foundation_start_effects == 0);
    assert(!wps_guard_busy() && release_calls == 1);
    assert(strstr(output, " ARMED ") == NULL);
    assert(strstr(output, "TERMINAL OUTCOME=invalid") == NULL);
    assert_one_terminal("stopped");

    /* Stop wins after the adapter transitions to running but before ARMED is
     * published. A delayed Start must not append stale ARMED or return success. */
    reset_fixture();
    first = (command_thread_t){.argc = 2, .argv = start, .primary = true};
    block_primary_poststate_gap = true;
    assert(pthread_create(&thread, NULL, run_command_thread, &first) == 0);
    wait_for(&primary_poststate_entered);
    assert(command(2, stop) == 0);
    assert(wps_guard_busy() && release_calls == 1);
    assert_one_terminal("stopped");
    release_gate(&release_primary_poststate_gap);
    assert(pthread_join(thread, NULL) == 0);
    assert(first.result != 0 && !wps_guard_busy());
    assert(strstr(output, " ARMED ") == NULL);
    assert_one_terminal("stopped");

    /* Start wins publication by entering the output serialization gate and
     * revalidating first. Concurrent Stop may clean state, but its terminal
     * must follow the already-authorized ARMED record. */
    reset_fixture();
    first = (command_thread_t){.argc = 2, .argv = start};
    command_thread_t stopping = {.argc = 2, .argv = stop};
    pthread_t stop_thread;
    block_armed_write = true;
    assert(pthread_create(&thread, NULL, run_command_thread, &first) == 0);
    wait_for(&armed_write_entered);
    assert(pthread_create(&stop_thread, NULL, run_command_thread, &stopping) == 0);
    wait_for(&stop_cleanup_done);
    release_gate(&release_armed_write);
    assert(pthread_join(thread, NULL) == 0);
    assert(pthread_join(stop_thread, NULL) == 0);
    assert(first.result == 0 && stopping.result == 0 && !wps_guard_busy());
    const char *armed = strstr(output, "[WPS_GUARD/1] ARMED TARGETS=3");
    const char *stopped = strstr(output, "TERMINAL OUTCOME=stopped");
    assert(armed && stopped && armed < stopped);
    assert(occurrences(" ARMED ") == 1 && occurrences("TERMINAL OUTCOME=") == 1);

    /* Foundation may already own and successfully start the context while the
     * adapter has not marked itself running. Stop/wipe must invalidate this
     * epoch so the returning Start cannot revive it or publish ARMED TARGETS=0. */
    reset_fixture();
    first = (command_thread_t){.argc = 2, .argv = start};
    block_start_return = true;
    assert(pthread_create(&thread, NULL, run_command_thread, &first) == 0);
    wait_for(&start_succeeded);
    assert(command(2, stop) == 0);
    assert(!borrowed && release_calls == 1);
    release_gate(&release_start_gate);
    assert(pthread_join(thread, NULL) == 0);
    assert(first.result != 0 && !wps_guard_busy());
    assert(strstr(output, " ARMED ") == NULL);
    assert(strstr(output, "ARMED TARGETS=0") == NULL);
}

static void assert_one_terminal(const char *outcome)
{
    char needle[64];
    snprintf(needle, sizeof(needle), "TERMINAL OUTCOME=%s", outcome);
    assert(occurrences("TERMINAL OUTCOME=") == 1);
    assert(strstr(output, needle));
    assert(strstr(output, "TERMINAL OUTCOME=ok") == NULL);
}

static void test_start_and_stop_failure_rollback(void)
{
    const char *start[] = {"wps_guard", "start"};
    const char *stop[] = {"wps_guard", "stop"};

    reset_fixture();
    snapshot_fail = true;
    assert(command(2, start) != 0);
    assert(start_calls == 0 && release_calls == 0 && !wps_guard_busy());
    assert_one_terminal("invalid");

    reset_fixture();
    start_result = WIFI_SECURITY_SESSION_BUSY;
    assert(command(2, start) != 0);
    assert(start_calls == 1 && release_calls == 1 && !wps_guard_busy());
    assert_one_terminal("busy");

    reset_fixture();
    start_result = WIFI_SECURITY_SESSION_WORKER_FAILED;
    assert(command(2, start) != 0);
    assert(start_calls == 1 && release_calls == 1 && !wps_guard_busy());
    assert_one_terminal("invalid");

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    stop_ok = false; stop_reason = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    assert(command(2, stop) != 0);
    assert(wps_guard_busy() && release_calls == 0);
    assert_one_terminal("timeout");
    clear_output(); stop_ok = true;
    assert(command(2, stop) == 0);
    assert(!wps_guard_busy() && release_calls == 1);
    assert_one_terminal("stopped");

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    stop_ok = false; stop_reason = WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED;
    assert(command(2, stop) != 0);
    assert(wps_guard_busy() && release_calls == 0);
    assert_one_terminal("restore_failed");
    clear_output(); stop_ok = true;
    assert(command(2, stop) == 0);
    assert(release_calls == 1 && !wps_guard_busy());
    assert_one_terminal("stopped");

    reset_fixture();
    fail_next_output = true;
    assert(command(2, start) != 0);
    assert(stop_calls == 1 && release_calls == 1 && !wps_guard_busy());
    assert_one_terminal("output_failed");
    assert(strstr(output, "OUTPUT_FAILURES=1"));

    reset_fixture();
    fail_next_output = true;
    stop_ok = false; stop_reason = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    assert(command(2, start) != 0);
    assert(stop_calls == 1 && release_calls == 0 && wps_guard_busy());
    assert_one_terminal("output_failed");
    clear_output(); stop_ok = true;
    assert(command(2, stop) == 0);
    assert(release_calls == 1 && !wps_guard_busy());
    /* OUTPUT_FAILURES is retained through uncertain cleanup, so the retry's
     * own terminal is independently claimed but remains output_failed. */
    assert_one_terminal("output_failed");
}

static void test_worker_output_failure_fail_closes_until_stop(void)
{
    reset_fixture();
    const char *start[] = {"wps_guard", "start", "--only", "1"};
    const char *stop[] = {"wps_guard", "stop"};
    assert(command(4, start) == 0);
    clear_output();

    assert(deliver(ap1, true, 1, 0, 6, -61));
    assert(strstr(output, "BSSID=02:01:02:03:04:05"));
    assert(strstr(output, "DIR=ap_to_sta"));
    clear_output();

    fail_next_output = true;
    unsigned time_before = now_calls;
    assert(!deliver(ap1, true, 1, 0, 6, -62));
    assert(now_calls == time_before + 1U && wps_guard_busy());
    assert(deliver(ap1, true, 1, 0, 6, -63));
    assert(now_calls == time_before + 1U);
    assert(output_used == 0);

    assert(command(2, stop) == 0);
    assert_one_terminal("output_failed");
    assert(!wps_guard_busy() && release_calls == 1);
}

static void test_async_publisher_failure_fail_closes_until_stop(void)
{
    reset_fixture();
    const char *start[] = {"wps_guard", "start"};
    const char *status[] = {"wps_guard", "status"};
    const char *stop[] = {"wps_guard", "stop"};
    assert(command(2, start) == 0);
    clear_output();

    unsigned time_before = now_calls;
    wps_guard_report_output_failure();
    assert(command(2, status) == 0);
    assert(strstr(output, "OUTPUT_FAILURES=1"));
    assert(strstr(output, "STOPPING=1"));
    clear_output();
    assert(deliver(ap1, true, 1U, 0U, 6U, -65));
    assert(now_calls == time_before && output_used == 0U);

    assert(command(2, stop) == 0);
    assert_one_terminal("output_failed");
    assert(!wps_guard_busy());
}

static void induce_runtime_pool_and_queue_drop(void)
{
    uint8_t frame[24] = {0};
    assert(wifi_security_runtime_submit(&shared_runtime, runtime_generation,
        frame, sizeof(frame), 1U, -40, 6U));
    assert(!wifi_security_runtime_submit(&shared_runtime, runtime_generation,
        frame, sizeof(frame), 2U, -41, 6U));

    uint8_t claimed[WIFI_SECURITY_POOL_SLOTS - 1U];
    for (size_t i = 0; i < sizeof(claimed); ++i) {
        wifi_security_frame_slot_t *slot = NULL;
        assert(wifi_security_runtime_claim(&shared_runtime, &claimed[i], &slot));
        assert(slot != NULL);
    }
    assert(!wifi_security_runtime_submit(&shared_runtime, runtime_generation,
        frame, sizeof(frame), 3U, -42, 6U));
    for (size_t i = 0; i < sizeof(claimed); ++i)
        assert(wifi_security_runtime_release(&shared_runtime, claimed[i]));
    wifi_security_runtime_status_t status;
    wifi_security_runtime_get_status(&shared_runtime, &status);
    assert(status.dropped_pool == 1U && status.dropped_queue == 1U);
}

static void test_runtime_rx_drops_status_terminal_and_retry(void)
{
    const char *start[] = {"wps_guard", "start"};
    const char *status[] = {"wps_guard", "status"};
    const char *stop[] = {"wps_guard", "stop"};

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    induce_runtime_pool_and_queue_drop();
    assert(command(2, status) == 0);
    assert(strstr(output, "CAPACITY_DROPS=0 RX_DROPS=2"));

    clear_output();
    stop_ok = false;
    stop_reason = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    assert(command(2, stop) != 0);
    assert_one_terminal("timeout");
    assert(strstr(output, "RX_DROPS=2"));

    clear_output();
    stop_ok = true;
    assert(command(2, stop) == 0);
    assert_one_terminal("queue_overflow");
    assert(strstr(output, "RX_DROPS=2"));

    clear_output();
    assert(command(2, status) == 0);
    assert(strstr(output, "RX_DROPS=2"));
    assert(strstr(output, "RUNNING=0 STOPPING=0"));

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    assert(pthread_mutex_lock(&runtime_mutex) == 0);
    shared_runtime.status.dropped_pool = UINT32_MAX;
    shared_runtime.status.dropped_queue = 1U;
    assert(pthread_mutex_unlock(&runtime_mutex) == 0);
    assert(command(2, status) == 0);
    assert(strstr(output, "RX_DROPS=4294967295"));
    clear_output();
    assert(command(2, stop) == 0);
    assert_one_terminal("queue_overflow");

    /* A future security module can advance the shared runtime while WPS is
     * still resolving its scan. Its drops must not leak into a rejected WPS
     * Start merely because the shared generation changed. */
    reset_fixture();
    start_result = WIFI_SECURITY_SESSION_BUSY;
    block_snapshot = true;
    command_thread_t starting = {.argc = 2, .argv = start};
    pthread_t start_thread;
    assert(pthread_create(&start_thread, NULL, run_command_thread, &starting) == 0);
    wait_for(&snapshot_entered);
    assert(pthread_mutex_lock(&runtime_mutex) == 0);
    shared_runtime.status.generation = 99U;
    shared_runtime.status.module = WIFI_SECURITY_MODULE_SAE_GUARD;
    shared_runtime.status.dropped_pool = 3U;
    shared_runtime.status.dropped_queue = 4U;
    assert(pthread_mutex_unlock(&runtime_mutex) == 0);
    release_gate(&release_snapshot_gate);
    assert(pthread_join(start_thread, NULL) == 0);
    assert(starting.result != 0 && !wps_guard_busy());
    assert_one_terminal("busy");
    assert(strstr(output, "RX_DROPS=0"));
}

static void test_post_wipe_cleanup_retry_preserves_status_and_clears_busy(void)
{
    const char *start[] = {"wps_guard", "start"};
    const char *stop[] = {"wps_guard", "stop"};

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    fail_next_output = true;
    assert(!deliver(ap1, true, 1U, 0U, 6U, -60));
    induce_runtime_pool_and_queue_drop();
    clear_output();

    wipe_before_stop_failure = true;
    stop_ok = false;
    stop_reason = WIFI_SECURITY_SESSION_CLEANUP_FAILED;
    assert(command(2, stop) != 0);
    assert(wps_guard_busy() && release_calls == 1U);
    assert_one_terminal("output_failed");
    assert(strstr(output, "RECEIVED=1"));
    assert(strstr(output, "FRAGMENTS=1"));
    assert(strstr(output, "RX_DROPS=2"));
    assert(strstr(output, "OUTPUT_FAILURES=1"));

    clear_output();
    stop_ok = true;
    assert(command(2, stop) == 0);
    assert(!wps_guard_busy() && release_calls == 1U);
    assert_one_terminal("output_failed");
    assert(strstr(output, "RECEIVED=1"));
    assert(strstr(output, "FRAGMENTS=1"));
    assert(strstr(output, "RX_DROPS=2"));
    assert(strstr(output, "OUTPUT_FAILURES=1"));
}

static void test_late_output_failure_reformats_terminal_and_blocks_restart(void)
{
    const char *start[] = {"wps_guard", "start"};
    const char *stop[] = {"wps_guard", "stop"};
    command_thread_t stopping = {.argc = 2, .argv = stop};
    pthread_t stop_thread;

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    block_terminal_format = true;
    assert(pthread_create(&stop_thread, NULL, run_command_thread, &stopping) == 0);
    wait_for(&terminal_format_entered);
    wps_guard_report_output_failure();
    release_gate(&release_terminal_format);
    assert(pthread_join(stop_thread, NULL) == 0);
    assert(stopping.result == 0 && !wps_guard_busy());
    assert_one_terminal("output_failed");
    assert(strstr(output, "OUTPUT_FAILURES=1"));

    clear_output();
    output_idle = false;
    unsigned starts_before = start_calls;
    assert(command(2, start) != 0);
    assert(start_calls == starts_before && wps_guard_busy());
    assert_one_terminal("busy");

    clear_output();
    output_idle = true;
    assert(!wps_guard_busy());
    assert(command(2, start) == 0);
    assert(command(2, stop) == 0);
}

static void test_failed_queue_admission_blocks_restart_until_failure_recorded(void)
{
    const char *status[] = {"wps_guard", "status"};
    const char *start[] = {"wps_guard", "start"};
    const char *stop[] = {"wps_guard", "stop"};
    command_thread_t status_call = {.argc = 2, .argv = status};
    command_thread_t start_call = {.argc = 2, .argv = start};
    pthread_t status_thread, start_thread;

    reset_fixture();
    fail_next_output = true;
    retain_failed_admission_token = true;
    block_failed_write_return = true;
    assert(pthread_create(&status_thread, NULL, run_command_thread,
                          &status_call) == 0);
    wait_for(&failed_write_entered);
    assert(failed_admission_token_retained && wps_guard_busy());

    assert(pthread_create(&start_thread, NULL, run_command_thread,
                          &start_call) == 0);
    wait_for_output_enter_attempts(2U);
    assert(start_calls == 0U && snapshot_calls == 0U);

    release_gate(&release_failed_write_return);
    assert(pthread_join(status_thread, NULL) == 0);
    assert(pthread_join(start_thread, NULL) == 0);
    assert(status_call.result != 0 && start_call.result != 0);
    assert(!failed_admission_token_retained && !wps_guard_busy());
    assert(start_calls == 0U && snapshot_calls == 0U);
    assert_one_terminal("busy");
    assert(command(2, status) == 0);
    assert(strstr(output, "OUTPUT_FAILURES=1"));

    clear_output();
    assert(command(2, start) == 0);
    assert(command(2, status) == 0);
    assert(strstr(output, "OUTPUT_FAILURES=0"));
    assert(command(2, stop) == 0);
}

static uint64_t monotonic_ms(void)
{
    struct timespec now;
    assert(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static void run_with_held_output_gate(command_thread_t *command_state,
                                      uint64_t maximum_ms)
{
    pthread_t thread;
    bounded_output_enter = true;
    assert(pthread_mutex_lock(&output_mutex) == 0);
    uint64_t started = monotonic_ms();
    assert(pthread_create(&thread, NULL, run_command_thread, command_state) == 0);
    assert(pthread_join(thread, NULL) == 0);
    uint64_t elapsed = monotonic_ms() - started;
    assert(pthread_mutex_unlock(&output_mutex) == 0);
    bounded_output_enter = false;
    assert(last_output_enter_timeout_ms == WPS_GUARD_OUTPUT_TIMEOUT_MS);
    assert(elapsed <= maximum_ms);
}

static void test_blocked_output_gate_is_bounded_and_fail_closed(void)
{
    const char *start[] = {"wps_guard", "start"};
    const char *status[] = {"wps_guard", "status"};
    const char *stop[] = {"wps_guard", "stop"};

    reset_fixture();
    command_thread_t status_call = {.argc = 2, .argv = status};
    run_with_held_output_gate(&status_call, WPS_GUARD_OUTPUT_TIMEOUT_MS + 1000U);
    assert(status_call.result != 0 && !wps_guard_busy());

    reset_fixture();
    command_thread_t start_call = {.argc = 2, .argv = start};
    run_with_held_output_gate(&start_call,
        2U * WPS_GUARD_OUTPUT_TIMEOUT_MS + 1000U);
    assert(start_call.result != 0 && !wps_guard_busy() && release_calls == 1U);
    clear_output();
    assert(command(2, status) == 0);
    assert(strstr(output, "OUTPUT_FAILURES=2"));

    reset_fixture();
    assert(command(2, start) == 0);
    clear_output();
    command_thread_t stop_call = {.argc = 2, .argv = stop};
    run_with_held_output_gate(&stop_call, WPS_GUARD_OUTPUT_TIMEOUT_MS + 1000U);
    assert(stop_call.result != 0 && !wps_guard_busy() && release_calls == 1U);
    clear_output();
    assert(command(2, status) == 0);
    assert(strstr(output, "OUTPUT_FAILURES=1"));
}

static void assert_single_output_failed_terminal(void)
{
    assert(occurrences("TERMINAL OUTCOME=") == 1);
    assert(strstr(output, "TERMINAL OUTCOME=output_failed"));
    assert(strstr(output, "TERMINAL OUTCOME=stopped") == NULL);
    assert(strstr(output, "TERMINAL OUTCOME=ok") == NULL);
    assert(strstr(output, " ARMED ") == NULL);
}

static void test_armed_write_failure_terminal_claim_races(void)
{
    const char *start[] = {"wps_guard", "start"};
    const char *stop[] = {"wps_guard", "stop"};
    command_thread_t starting = {.argc = 2, .argv = start};
    command_thread_t stopping = {.argc = 2, .argv = stop};
    pthread_t start_thread, stop_thread;

    /* Stop wipes state while the failed ARMED write has not yet returned to
     * production, hence before failure recording. Output ordering must delay
     * its terminal until output_failed is recorded under the same gate. */
    reset_fixture();
    fail_next_output = true;
    block_failed_write_return = true;
    assert(pthread_create(&start_thread, NULL, run_command_thread, &starting) == 0);
    wait_for(&failed_write_entered);
    assert(pthread_create(&stop_thread, NULL, run_command_thread, &stopping) == 0);
    wait_for(&stop_cleanup_done);
    release_gate(&release_failed_write_return);
    assert(pthread_join(start_thread, NULL) == 0);
    assert(pthread_join(stop_thread, NULL) == 0);
    assert(starting.result != 0 && stopping.result == 0 && !wps_guard_busy());
    assert_single_output_failed_terminal();

    /* Failure is now recorded, but Start has not left output serialization or
     * begun rollback. External Stop must win the sole terminal claim. */
    reset_fixture();
    starting = (command_thread_t){.argc = 2, .argv = start};
    stopping = (command_thread_t){.argc = 2, .argv = stop};
    fail_next_output = true;
    block_failed_write_leave = true;
    assert(pthread_create(&start_thread, NULL, run_command_thread, &starting) == 0);
    wait_for(&failed_write_leave_entered);
    assert(pthread_create(&stop_thread, NULL, run_command_thread, &stopping) == 0);
    wait_for(&stop_cleanup_done);
    release_gate(&release_failed_write_leave);
    assert(pthread_join(start_thread, NULL) == 0);
    assert(pthread_join(stop_thread, NULL) == 0);
    assert(starting.result != 0 && stopping.result == 0 && !wps_guard_busy());
    assert_single_output_failed_terminal();
}

int main(void)
{
    test_cli_validation_and_owned_snapshot();
    test_exact_idle_lifecycle_transcript();
    test_exact_busy_event_output_failure_and_retained_retry();
    test_filter_worker_clock_and_stop_fence();
    test_concurrent_start_and_stop_boundaries();
    test_start_and_stop_failure_rollback();
    test_worker_output_failure_fail_closes_until_stop();
    test_async_publisher_failure_fail_closes_until_stop();
    test_runtime_rx_drops_status_terminal_and_retry();
    test_post_wipe_cleanup_retry_preserves_status_and_clears_busy();
    test_late_output_failure_reformats_terminal_and_blocks_restart();
    test_failed_queue_admission_blocks_restart_until_failure_recorded();
    test_blocked_output_gate_is_bounded_and_fail_closed();
    test_armed_write_failure_terminal_claim_races();
    puts("PASS: WPS Guard CLI, filtering, lifecycle, rollback");
    return 0;
}
