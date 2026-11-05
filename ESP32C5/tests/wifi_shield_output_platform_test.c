#include "wifi_shield_output_platform.h"

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    pthread_mutex_t output_mutex;
    pthread_mutex_t gate_mutex;
    pthread_cond_t gate_condition;
    bool writer_admitted;
    bool release_writer;
    atomic_uint lock_attempts;
    atomic_uint lock_calls;
    atomic_uint unlock_calls;
    atomic_uint_fast64_t now_us;
    wifi_shield_output_platform_t output;
} fixture_t;

static fixture_t fixture;

static bool output_lock(void *context, uint32_t timeout_ms)
{
    fixture_t *f = context;
    assert(f == &fixture && timeout_ms != 0U);
    atomic_fetch_add(&f->lock_attempts, 1U);
    assert(pthread_mutex_lock(&f->output_mutex) == 0);
    atomic_fetch_add(&f->lock_calls, 1U);
    return true;
}

static void output_unlock(void *context)
{
    fixture_t *f = context;
    assert(f == &fixture);
    atomic_fetch_add(&f->unlock_calls, 1U);
    assert(pthread_mutex_unlock(&f->output_mutex) == 0);
}

static uint64_t monotonic_us(void *context)
{
    fixture_t *f = context;
    assert(f == &fixture);
    return atomic_fetch_add(&f->now_us, UINT64_C(10000));
}

static void *paused_writer(void *context)
{
    fixture_t *f = context;
    assert(output_lock(f, 100U));
    assert(wifi_shield_output_platform_admitted(&f->output));

    assert(pthread_mutex_lock(&f->gate_mutex) == 0);
    f->writer_admitted = true;
    assert(pthread_cond_broadcast(&f->gate_condition) == 0);
    while (!f->release_writer)
        assert(pthread_cond_wait(&f->gate_condition, &f->gate_mutex) == 0);
    assert(pthread_mutex_unlock(&f->gate_mutex) == 0);

    /* This is the exact post-admission/pre-pending window. Drain must still be
     * blocked on output_mutex until accepted() and the outer writer leave. */
    wifi_shield_output_platform_accepted(&f->output);
    output_unlock(f);
    return NULL;
}

typedef struct {
    bool result;
    uint32_t remaining_ms;
} drain_result_t;

static void *closing_drain(void *context)
{
    drain_result_t *result = context;
    result->result = wifi_shield_output_platform_close(
        &fixture.output, 100U, &result->remaining_ms);
    return NULL;
}

static void reset_fixture(void)
{
    fixture = (fixture_t){0};
    assert(pthread_mutex_init(&fixture.output_mutex, NULL) == 0);
    assert(pthread_mutex_init(&fixture.gate_mutex, NULL) == 0);
    assert(pthread_cond_init(&fixture.gate_condition, NULL) == 0);
    wifi_shield_output_platform_hooks_t hooks = {
        .context = &fixture,
        .lock = output_lock,
        .unlock = output_unlock,
        .monotonic_us = monotonic_us,
    };
    assert(wifi_shield_output_platform_init(&fixture.output, &hooks));
    wifi_shield_output_platform_open(&fixture.output);
}

static void destroy_fixture(void)
{
    assert(pthread_cond_destroy(&fixture.gate_condition) == 0);
    assert(pthread_mutex_destroy(&fixture.gate_mutex) == 0);
    assert(pthread_mutex_destroy(&fixture.output_mutex) == 0);
}

static void test_close_serializes_with_admitted_writer(void)
{
    reset_fixture();
    pthread_t writer;
    pthread_t drain;
    drain_result_t result = {0};
    assert(pthread_create(&writer, NULL, paused_writer, &fixture) == 0);

    assert(pthread_mutex_lock(&fixture.gate_mutex) == 0);
    while (!fixture.writer_admitted)
        assert(pthread_cond_wait(&fixture.gate_condition,
                                 &fixture.gate_mutex) == 0);
    assert(pthread_mutex_unlock(&fixture.gate_mutex) == 0);

    assert(pthread_create(&drain, NULL, closing_drain, &result) == 0);
    while (atomic_load(&fixture.lock_attempts) != 2U)
        assert(sched_yield() == 0);
    assert(!wifi_shield_output_platform_is_closed(&fixture.output));

    assert(pthread_mutex_lock(&fixture.gate_mutex) == 0);
    fixture.release_writer = true;
    assert(pthread_cond_broadcast(&fixture.gate_condition) == 0);
    assert(pthread_mutex_unlock(&fixture.gate_mutex) == 0);

    assert(pthread_join(writer, NULL) == 0);
    assert(pthread_join(drain, NULL) == 0);
    assert(result.result && result.remaining_ms == 90U);
    assert(wifi_shield_output_platform_is_closed(&fixture.output));
    assert(!wifi_shield_output_platform_admitted(&fixture.output));
    assert(wifi_shield_output_platform_pending(&fixture.output) == 1U);
    wifi_shield_output_platform_published(&fixture.output, 10U, 10);
    assert(wifi_shield_output_platform_pending(&fixture.output) == 0U);
    assert(wifi_shield_output_platform_take_failures(&fixture.output) == 0U);
    assert(atomic_load(&fixture.lock_attempts) == 2U);
    assert(atomic_load(&fixture.lock_calls) == 2U);
    assert(atomic_load(&fixture.unlock_calls) == 2U);
    destroy_fixture();
}

static void test_failed_and_partial_uart_are_counted(void)
{
    reset_fixture();
    wifi_shield_output_platform_accepted(&fixture.output);
    wifi_shield_output_platform_published(&fixture.output, 10U, -1);
    wifi_shield_output_platform_accepted(&fixture.output);
    wifi_shield_output_platform_published(&fixture.output, 10U, 4);
    assert(wifi_shield_output_platform_pending(&fixture.output) == 0U);
    assert(wifi_shield_output_platform_take_failures(&fixture.output) == 2U);
    assert(wifi_shield_output_platform_take_failures(&fixture.output) == 0U);
    destroy_fixture();
}

static void test_idle_status_uses_only_the_synchronous_status_path(void)
{
    static const char status[] =
        "[SHIELD/1] STATUS RUNNING=0 MODE=passive\r\n";
    static const char event[] =
        "[SHIELD/1] EVENT SOURCE=wps TYPE=enrollment_activity\r\n";
    assert(wifi_shield_output_platform_should_sync_status(
        status, sizeof(status) - 1U, false, false));
    assert(wifi_shield_output_platform_should_sync_status(
        status, sizeof(status) - 1U, true, false));
    assert(!wifi_shield_output_platform_should_sync_status(
        status, sizeof(status) - 1U, true, true));
    assert(!wifi_shield_output_platform_should_sync_status(
        event, sizeof(event) - 1U, false, false));
    assert(!wifi_shield_output_platform_should_sync_status(
        status, sizeof("[SHIELD/1] STATUS") - 1U, false, false));

    static const char *const v2[] = {
        "[SHIELD/2] CAMPAIGN ID=1\r\n",
        "[SHIELD/2] AP_HEALTH BSSID=02:00:00:00:00:01\r\n",
        "[SHIELD/2] RECOMMENDATION BSSID=02:00:00:00:00:01\r\n",
        "[SHIELD/2] LOG STATE=active\r\n",
        "[SHIELD/2] STORAGE STATE=degraded\r\n",
    };
    for (size_t i = 0U; i < sizeof(v2) / sizeof(v2[0]); ++i) {
        assert(wifi_shield_output_platform_should_sync_status(
            v2[i], strlen(v2[i]), false, false));
        assert(!wifi_shield_output_platform_should_sync_status(
            v2[i], strlen(v2[i]), true, true));
    }
    static const char spoof[] = "[SHIELD/2] EVENT arbitrary\r\n";
    assert(!wifi_shield_output_platform_should_sync_status(
        spoof, sizeof(spoof) - 1U, false, false));
    assert(!wifi_shield_output_platform_should_sync_status(
        v2[0], sizeof("[SHIELD/2] CAMPAIGN") - 1U, false, false));
}

int main(void)
{
    test_close_serializes_with_admitted_writer();
    test_failed_and_partial_uart_are_counted();
    test_idle_status_uses_only_the_synchronous_status_path();
    puts("wifi shield output platform: PASS");
    return 0;
}
