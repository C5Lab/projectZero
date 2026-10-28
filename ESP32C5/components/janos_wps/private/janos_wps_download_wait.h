/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janos_radio_lease.h"

typedef struct {
    bool service_quarantined;
    bool worker_active;
    uint32_t service_generation;
    janos_radio_lease_snapshot_t lease;
} janos_wps_download_state_t;

static inline bool janos_wps_download_quarantine_matches(
    const janos_wps_download_state_t *state)
{
    return state && state->service_quarantined &&
           state->service_generation != 0U &&
           state->lease.owner == JANOS_RADIO_OWNER_WPS &&
           state->lease.state == JANOS_RADIO_LEASE_QUARANTINED &&
           state->lease.generation == state->service_generation &&
           !state->lease.callbacks_open;
}

/* Reusable one-shot guard for the reset and terminal-wipe paths. */
static inline bool janos_wps_download_ready(
    const janos_wps_download_state_t *state)
{
    return janos_wps_download_quarantine_matches(state) &&
           !state->worker_active;
}

typedef struct {
    void *context;
    bool (*read_state)(void *context, janos_wps_download_state_t *out);
    uint64_t (*now_ms)(void *context);
    void (*delay_ms)(void *context, uint32_t milliseconds);
} janos_wps_download_wait_ops_t;

/* Returns false immediately for a mismatched lease/service. Only a matching
 * quarantine with a still-active worker is polled until its epilogue ends. */
static inline bool janos_wps_download_wait(
    const janos_wps_download_wait_ops_t *ops, uint32_t timeout_ms)
{
    if (!ops || !ops->read_state || !ops->now_ms || !ops->delay_ms)
        return false;
    uint64_t started = ops->now_ms(ops->context);
    for (;;) {
        janos_wps_download_state_t state = {0};
        if (!ops->read_state(ops->context, &state) ||
            !janos_wps_download_quarantine_matches(&state))
            return false;
        if (janos_wps_download_ready(&state)) return true;
        if (ops->now_ms(ops->context) - started >= timeout_ms) return false;
        ops->delay_ms(ops->context, 20U);
    }
}
