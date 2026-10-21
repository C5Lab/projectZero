/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>

#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#endif

typedef enum {
    JANOS_RADIO_OWNER_NONE = 0,
    JANOS_RADIO_OWNER_ANALYZER,
    JANOS_RADIO_OWNER_WPS,
    JANOS_RADIO_OWNER_LEGACY,
} janos_radio_owner_t;

typedef enum {
    JANOS_RADIO_LEASE_IDLE = 0,
    JANOS_RADIO_LEASE_PREPARING,
    JANOS_RADIO_LEASE_RUNNING,
    JANOS_RADIO_LEASE_CLEANUP,
    JANOS_RADIO_LEASE_QUARANTINED,
} janos_radio_lease_state_t;

typedef enum {
    JANOS_RADIO_LEASE_OK = 0,
    JANOS_RADIO_LEASE_BUSY,
    JANOS_RADIO_LEASE_QUARANTINED_RESULT,
    JANOS_RADIO_LEASE_EXHAUSTED,
    JANOS_RADIO_LEASE_INVALID,
} janos_radio_lease_result_t;

typedef struct {
    janos_radio_owner_t owner;
    janos_radio_lease_state_t state;
    uint32_t generation;
    bool cancel_requested;
    bool callbacks_open;
    bool generation_exhausted;
} janos_radio_lease_snapshot_t;

typedef struct {
#ifdef ESP_PLATFORM
    portMUX_TYPE mutation_mux;
#else
    atomic_flag mutation_lock;
#endif
    atomic_uint_least32_t owner;
    atomic_uint_least32_t state;
    atomic_uint_least32_t generation;
    atomic_bool cancel_requested;
    atomic_bool callbacks_open;
    atomic_uint_least32_t next_generation;
    atomic_bool generation_exhausted;
} janos_radio_lease_t;

void janos_radio_lease_init(janos_radio_lease_t *lease);
janos_radio_lease_result_t janos_radio_lease_acquire(
    janos_radio_lease_t *lease, janos_radio_owner_t owner,
    uint32_t *generation_out);
/* Release a legacy startup only after its handler publishes state or fails.
 * Unexpected state/owner/generation remains reserved (fail closed). */
bool janos_radio_lease_finish_startup(janos_radio_lease_t *lease,
                                     janos_radio_owner_t owner,
                                     uint32_t generation);
bool janos_radio_lease_mark_running(janos_radio_lease_t *lease,
                                    janos_radio_owner_t owner,
                                    uint32_t generation);
bool janos_radio_lease_request_cancel(janos_radio_lease_t *lease,
                                      janos_radio_owner_t owner,
                                      uint32_t generation);
bool janos_radio_lease_cancel_requested(const janos_radio_lease_t *lease,
                                        janos_radio_owner_t owner,
                                        uint32_t generation);
bool janos_radio_lease_accept_callback(const janos_radio_lease_t *lease,
                                       janos_radio_owner_t owner,
                                       uint32_t generation);
bool janos_radio_lease_begin_cleanup(janos_radio_lease_t *lease,
                                     janos_radio_owner_t owner,
                                     uint32_t generation);
bool janos_radio_lease_finish_cleanup(janos_radio_lease_t *lease,
                                      janos_radio_owner_t owner,
                                      uint32_t generation, bool restored);
janos_radio_lease_snapshot_t janos_radio_lease_snapshot(
    const janos_radio_lease_t *lease);

