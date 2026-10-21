/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stdatomic.h>

typedef struct {
    atomic_bool active;
    atomic_bool released;
} janos_wps_worker_state_t;

typedef enum {
    JANOS_WPS_STOP_ALREADY_JOINED = 0,
    JANOS_WPS_STOP_WAIT_EPILOGUE,
    JANOS_WPS_STOP_REQUEST_CANCEL,
    JANOS_WPS_STOP_QUARANTINED,
} janos_wps_worker_stop_action_t;

static inline void janos_wps_worker_state_init(janos_wps_worker_state_t *state)
{
    if (state) {
        atomic_init(&state->active, false);
        atomic_init(&state->released, false);
    }
}

static inline bool janos_wps_worker_state_try_start(
    janos_wps_worker_state_t *state)
{
    bool expected = false;
    if (!state || !atomic_compare_exchange_strong_explicit(
        &state->active, &expected, true, memory_order_acq_rel,
        memory_order_acquire)) return false;
    atomic_store_explicit(&state->released, false, memory_order_release);
    return true;
}

static inline void janos_wps_worker_state_release(
    janos_wps_worker_state_t *state)
{
    if (state)
        atomic_store_explicit(&state->released, true, memory_order_release);
}

static inline bool janos_wps_worker_state_released(
    const janos_wps_worker_state_t *state)
{
    return state && atomic_load_explicit(&state->released,
                                          memory_order_acquire);
}

static inline void janos_wps_worker_state_finish(
    janos_wps_worker_state_t *state)
{
    if (state) {
        atomic_store_explicit(&state->released, false, memory_order_relaxed);
        atomic_store_explicit(&state->active, false, memory_order_release);
    }
}

static inline bool janos_wps_worker_state_active(
    const janos_wps_worker_state_t *state)
{
    return state && atomic_load_explicit(&state->active, memory_order_acquire);
}

static inline bool janos_wps_worker_state_joined(
    const janos_wps_worker_state_t *state, bool service_terminal)
{
    return service_terminal && !janos_wps_worker_state_active(state);
}

/* Pure policy seam used by the real runtime stop path and host tests.  An
 * IDLE service is not joined while its runtime terminal-output epilogue is
 * still active, and a late stop never requests cancellation in that window. */
static inline janos_wps_worker_stop_action_t janos_wps_worker_stop_action(
    bool service_idle, bool service_quarantined, bool worker_active)
{
    if (service_idle)
        return worker_active ? JANOS_WPS_STOP_WAIT_EPILOGUE :
                               JANOS_WPS_STOP_ALREADY_JOINED;
    if (service_quarantined)
        return worker_active ? JANOS_WPS_STOP_WAIT_EPILOGUE :
                               JANOS_WPS_STOP_QUARANTINED;
    return JANOS_WPS_STOP_REQUEST_CANCEL;
}
