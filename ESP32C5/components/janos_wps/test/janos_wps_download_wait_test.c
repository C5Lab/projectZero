/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_download_wait.h"

#include <assert.h>
#include <stdio.h>

typedef struct {
    janos_wps_download_state_t state;
    uint64_t now_ms;
    unsigned reads;
    unsigned delays;
    unsigned clear_worker_after;
    bool read_ok;
} fixture_t;

static bool read_state(void *context, janos_wps_download_state_t *out)
{
    fixture_t *fixture = context;
    ++fixture->reads;
    if (!fixture->read_ok) return false;
    *out = fixture->state;
    if (fixture->clear_worker_after != 0U &&
        fixture->reads >= fixture->clear_worker_after)
        out->worker_active = false;
    return true;
}

static uint64_t now_ms(void *context)
{
    return ((fixture_t *)context)->now_ms;
}

static void delay_ms(void *context, uint32_t milliseconds)
{
    fixture_t *fixture = context;
    assert(milliseconds == 20U);
    ++fixture->delays;
    fixture->now_ms += milliseconds;
}

static fixture_t fixture(void)
{
    fixture_t value = {
        .state = {
            .service_quarantined = true,
            .service_generation = 7U,
            .lease = {
                .owner = JANOS_RADIO_OWNER_WPS,
                .state = JANOS_RADIO_LEASE_QUARANTINED,
                .generation = 7U,
            },
        },
        .read_ok = true,
    };
    return value;
}

static janos_wps_download_wait_ops_t ops(fixture_t *value)
{
    janos_wps_download_wait_ops_t result = {
        .context = value,
        .read_state = read_state,
        .now_ms = now_ms,
        .delay_ms = delay_ms,
    };
    return result;
}

int main(void)
{
    fixture_t value = fixture();
    janos_wps_download_wait_ops_t hooks = ops(&value);
    assert(janos_wps_download_ready(&value.state));
    assert(janos_wps_download_wait(&hooks, 40U));
    assert(value.reads == 1U && value.delays == 0U);

    value = fixture();
    value.state.worker_active = true;
    value.clear_worker_after = 3U;
    hooks = ops(&value);
    assert(!janos_wps_download_ready(&value.state));
    assert(janos_wps_download_wait(&hooks, 50U));
    assert(value.reads == 3U && value.delays == 2U && value.now_ms == 40U);

    value = fixture();
    value.state.worker_active = true;
    hooks = ops(&value);
    assert(!janos_wps_download_wait(&hooks, 40U));
    assert(value.reads == 3U && value.delays == 2U && value.now_ms == 40U);

    value = fixture();
    value.state.worker_active = true;
    hooks = ops(&value);
    assert(!janos_wps_download_wait(&hooks, 0U));
    assert(value.reads == 1U && value.delays == 0U);

    value = fixture();
    value.state.lease.generation = 8U;
    hooks = ops(&value);
    assert(!janos_wps_download_ready(&value.state));
    assert(!janos_wps_download_wait(&hooks, 40U));
    assert(value.reads == 1U && value.delays == 0U);

    value = fixture();
    value.state.lease.callbacks_open = true;
    hooks = ops(&value);
    assert(!janos_wps_download_ready(&value.state));
    assert(!janos_wps_download_wait(&hooks, 40U));

    value = fixture();
    value.read_ok = false;
    hooks = ops(&value);
    assert(!janos_wps_download_wait(&hooks, 40U));
    assert(value.reads == 1U && value.delays == 0U);
    puts("PASS: JanOS WPS bounded download wait");
    return 0;
}
