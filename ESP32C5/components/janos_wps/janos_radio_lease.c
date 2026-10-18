/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_radio_lease.h"

#include <string.h>

void janos_radio_lease_init(janos_radio_lease_t *lease)
{
    if (!lease) return;
    memset(lease, 0, sizeof(*lease));
#ifdef ESP_PLATFORM
    lease->mutation_mux = (portMUX_TYPE)portMUX_INITIALIZER_UNLOCKED;
#else
    atomic_flag_clear_explicit(&lease->mutation_lock, memory_order_release);
#endif
    atomic_init(&lease->owner, JANOS_RADIO_OWNER_NONE);
    atomic_init(&lease->state, JANOS_RADIO_LEASE_IDLE);
    atomic_init(&lease->generation, 0U);
    atomic_init(&lease->cancel_requested, false);
    atomic_init(&lease->callbacks_open, false);
    atomic_init(&lease->next_generation, 1U);
    atomic_init(&lease->generation_exhausted, false);
}

static void mutation_enter(janos_radio_lease_t *lease)
{
#ifdef ESP_PLATFORM
    portENTER_CRITICAL(&lease->mutation_mux);
#else
    while (atomic_flag_test_and_set_explicit(
               &lease->mutation_lock, memory_order_acquire)) {
    }
#endif
}

static void mutation_leave(janos_radio_lease_t *lease)
{
#ifdef ESP_PLATFORM
    portEXIT_CRITICAL(&lease->mutation_mux);
#else
    atomic_flag_clear_explicit(&lease->mutation_lock, memory_order_release);
#endif
}

static bool matches(const janos_radio_lease_t *lease,
                    janos_radio_owner_t owner, uint32_t generation)
{
    return lease && owner > JANOS_RADIO_OWNER_NONE &&
        owner <= JANOS_RADIO_OWNER_LEGACY && generation != 0U &&
        atomic_load_explicit(&lease->owner, memory_order_acquire) ==
            (uint32_t)owner &&
        atomic_load_explicit(&lease->generation, memory_order_acquire) ==
            generation;
}

janos_radio_lease_result_t janos_radio_lease_acquire(
    janos_radio_lease_t *lease, janos_radio_owner_t owner,
    uint32_t *generation_out)
{
    if (!lease || owner <= JANOS_RADIO_OWNER_NONE ||
        owner > JANOS_RADIO_OWNER_LEGACY) return JANOS_RADIO_LEASE_INVALID;
    mutation_enter(lease);
    janos_radio_lease_result_t result = JANOS_RADIO_LEASE_BUSY;
    const uint32_t state = atomic_load_explicit(&lease->state, memory_order_acquire);
    if (state == JANOS_RADIO_LEASE_QUARANTINED) {
        result = JANOS_RADIO_LEASE_QUARANTINED_RESULT;
        goto done;
    }
    if (state != JANOS_RADIO_LEASE_IDLE) goto done;
    if (atomic_load_explicit(&lease->generation, memory_order_acquire) != 0U ||
        atomic_load_explicit(&lease->callbacks_open, memory_order_acquire) ||
        atomic_load_explicit(&lease->cancel_requested, memory_order_acquire))
        goto done;
    if (atomic_load_explicit(&lease->generation_exhausted,
                             memory_order_acquire) ||
        atomic_load_explicit(&lease->next_generation,
                             memory_order_acquire) == 0U) {
        result = JANOS_RADIO_LEASE_EXHAUSTED;
        goto done;
    }

    uint_least32_t expected_owner = JANOS_RADIO_OWNER_NONE;
    if (!atomic_compare_exchange_strong_explicit(
            &lease->owner, &expected_owner, (uint_least32_t)owner,
            memory_order_acq_rel, memory_order_acquire)) {
        result = atomic_load_explicit(&lease->state, memory_order_acquire) ==
                         JANOS_RADIO_LEASE_QUARANTINED ?
                     JANOS_RADIO_LEASE_QUARANTINED_RESULT :
                     JANOS_RADIO_LEASE_BUSY;
        goto done;
    }

    const uint32_t generation = (uint32_t)atomic_load_explicit(
        &lease->next_generation, memory_order_relaxed);
    if (generation == UINT32_MAX) {
        atomic_store_explicit(&lease->next_generation, 0U,
                              memory_order_relaxed);
        atomic_store_explicit(&lease->generation_exhausted, true,
                              memory_order_release);
    } else {
        atomic_store_explicit(&lease->next_generation, generation + 1U,
                              memory_order_relaxed);
    }
    atomic_store_explicit(&lease->cancel_requested, false, memory_order_release);
    atomic_store_explicit(&lease->callbacks_open, false, memory_order_release);
    atomic_store_explicit(&lease->generation, generation, memory_order_release);
    atomic_store_explicit(&lease->state, JANOS_RADIO_LEASE_PREPARING,
                          memory_order_release);
    if (generation_out) *generation_out = generation;
    result = JANOS_RADIO_LEASE_OK;
done:
    mutation_leave(lease);
    return result;
}

bool janos_radio_lease_finish_startup(janos_radio_lease_t *lease,
                                     janos_radio_owner_t owner,
                                     uint32_t generation)
{
    if (!lease || owner != JANOS_RADIO_OWNER_LEGACY) return false;
    mutation_enter(lease);
    bool valid = matches(lease, owner, generation) &&
        atomic_load_explicit(&lease->state, memory_order_acquire) ==
            JANOS_RADIO_LEASE_PREPARING &&
        !atomic_load_explicit(&lease->callbacks_open, memory_order_acquire);
    if (valid) {
        atomic_store_explicit(&lease->cancel_requested, false, memory_order_release);
        atomic_store_explicit(&lease->state, JANOS_RADIO_LEASE_IDLE, memory_order_release);
        atomic_store_explicit(&lease->generation, 0U, memory_order_release);
        atomic_store_explicit(&lease->owner, JANOS_RADIO_OWNER_NONE, memory_order_release);
    }
    mutation_leave(lease);
    return valid;
}

bool janos_radio_lease_mark_running(janos_radio_lease_t *lease,
                                    janos_radio_owner_t owner,
                                    uint32_t generation)
{
    if (!lease) return false;
    mutation_enter(lease);
    if (!matches(lease, owner, generation)) {
        mutation_leave(lease);
        return false;
    }
    atomic_store_explicit(&lease->callbacks_open, true, memory_order_release);
    uint_least32_t expected_state = JANOS_RADIO_LEASE_PREPARING;
    if (!atomic_compare_exchange_strong_explicit(
            &lease->state, &expected_state, JANOS_RADIO_LEASE_RUNNING,
            memory_order_acq_rel, memory_order_acquire)) {
        if (expected_state != JANOS_RADIO_LEASE_RUNNING) {
            atomic_store_explicit(&lease->callbacks_open, false,
                                  memory_order_release);
        }
        mutation_leave(lease);
        return false;
    }
    mutation_leave(lease);
    return true;
}

bool janos_radio_lease_request_cancel(janos_radio_lease_t *lease,
                                      janos_radio_owner_t owner,
                                      uint32_t generation)
{
    if (!lease) return false;
    mutation_enter(lease);
    if (!matches(lease, owner, generation)) {
        mutation_leave(lease);
        return false;
    }
    const uint32_t state = atomic_load_explicit(&lease->state, memory_order_acquire);
    if (state != JANOS_RADIO_LEASE_PREPARING &&
        state != JANOS_RADIO_LEASE_RUNNING) {
        mutation_leave(lease);
        return false;
    }
    atomic_store_explicit(&lease->cancel_requested, true, memory_order_release);
    atomic_store_explicit(&lease->callbacks_open, false, memory_order_release);
    mutation_leave(lease);
    return true;
}

bool janos_radio_lease_cancel_requested(const janos_radio_lease_t *lease,
                                        janos_radio_owner_t owner,
                                        uint32_t generation)
{
    return matches(lease, owner, generation) &&
        atomic_load_explicit(&lease->cancel_requested, memory_order_acquire);
}

bool janos_radio_lease_accept_callback(const janos_radio_lease_t *lease,
                                       janos_radio_owner_t owner,
                                       uint32_t generation)
{
    return matches(lease, owner, generation) &&
        atomic_load_explicit(&lease->state, memory_order_acquire) ==
            JANOS_RADIO_LEASE_RUNNING &&
        atomic_load_explicit(&lease->callbacks_open, memory_order_acquire);
}

bool janos_radio_lease_begin_cleanup(janos_radio_lease_t *lease,
                                     janos_radio_owner_t owner,
                                     uint32_t generation)
{
    if (!lease) return false;
    mutation_enter(lease);
    if (!matches(lease, owner, generation)) {
        mutation_leave(lease);
        return false;
    }
    atomic_store_explicit(&lease->callbacks_open, false, memory_order_release);
    uint_least32_t expected_state = atomic_load_explicit(
        &lease->state, memory_order_acquire);
    while (expected_state == JANOS_RADIO_LEASE_PREPARING ||
           expected_state == JANOS_RADIO_LEASE_RUNNING) {
        if (atomic_compare_exchange_weak_explicit(
                &lease->state, &expected_state, JANOS_RADIO_LEASE_CLEANUP,
                memory_order_acq_rel, memory_order_acquire)) {
            atomic_store_explicit(&lease->callbacks_open, false,
                                  memory_order_release);
            mutation_leave(lease);
            return true;
        }
    }
    mutation_leave(lease);
    return false;
}

bool janos_radio_lease_finish_cleanup(janos_radio_lease_t *lease,
                                      janos_radio_owner_t owner,
                                      uint32_t generation, bool restored)
{
    if (!lease) return false;
    mutation_enter(lease);
    if (!matches(lease, owner, generation)) {
        mutation_leave(lease);
        return false;
    }
    atomic_store_explicit(&lease->callbacks_open, false, memory_order_release);
    if (!restored) {
        uint_least32_t expected_state = JANOS_RADIO_LEASE_CLEANUP;
        (void)atomic_compare_exchange_strong_explicit(
            &lease->state, &expected_state, JANOS_RADIO_LEASE_QUARANTINED,
            memory_order_acq_rel, memory_order_acquire);
        mutation_leave(lease);
        return false;
    }
    uint_least32_t expected_state = JANOS_RADIO_LEASE_CLEANUP;
    if (!atomic_compare_exchange_strong_explicit(
            &lease->state, &expected_state, JANOS_RADIO_LEASE_IDLE,
            memory_order_acq_rel, memory_order_acquire)) {
        mutation_leave(lease);
        return false;
    }
    atomic_store_explicit(&lease->cancel_requested, false, memory_order_release);
    atomic_store_explicit(&lease->generation, 0U, memory_order_release);
    atomic_store_explicit(&lease->owner, JANOS_RADIO_OWNER_NONE,
                          memory_order_release);
    mutation_leave(lease);
    return true;
}

janos_radio_lease_snapshot_t janos_radio_lease_snapshot(
    const janos_radio_lease_t *lease)
{
    janos_radio_lease_snapshot_t snapshot = {0};
    if (!lease) return snapshot;
    for (unsigned attempt = 0; attempt < 8U; ++attempt) {
        uint_least32_t owner_before = atomic_load_explicit(
            &lease->owner, memory_order_acquire);
        snapshot.state = (janos_radio_lease_state_t)atomic_load_explicit(
            &lease->state, memory_order_acquire);
        snapshot.generation = (uint32_t)atomic_load_explicit(
            &lease->generation, memory_order_acquire);
        snapshot.cancel_requested = atomic_load_explicit(
            &lease->cancel_requested, memory_order_acquire);
        snapshot.callbacks_open = atomic_load_explicit(
            &lease->callbacks_open, memory_order_acquire);
        snapshot.generation_exhausted = atomic_load_explicit(
            &lease->generation_exhausted, memory_order_acquire);
        uint_least32_t owner_after = atomic_load_explicit(
            &lease->owner, memory_order_acquire);

        if (owner_before != owner_after) continue;
        if (owner_before == JANOS_RADIO_OWNER_NONE) {
            if (snapshot.state != JANOS_RADIO_LEASE_IDLE ||
                snapshot.generation != 0U || snapshot.callbacks_open) continue;
        } else if (snapshot.state == JANOS_RADIO_LEASE_IDLE ||
                   snapshot.generation == 0U) {
            continue;
        }
        snapshot.owner = (janos_radio_owner_t)owner_before;
        return snapshot;
    }

    /* A single-core caller must not spin until a preempted publisher runs.
     * Return a conservative busy snapshot for the two short publication
     * windows: claim -> PREPARING, and IDLE -> owner release. */
    snapshot.owner = (janos_radio_owner_t)atomic_load_explicit(
        &lease->owner, memory_order_acquire);
    snapshot.state = (janos_radio_lease_state_t)atomic_load_explicit(
        &lease->state, memory_order_acquire);
    snapshot.generation = (uint32_t)atomic_load_explicit(
        &lease->generation, memory_order_acquire);
    snapshot.cancel_requested = atomic_load_explicit(
        &lease->cancel_requested, memory_order_acquire);
    snapshot.callbacks_open = false;
    snapshot.generation_exhausted = atomic_load_explicit(
        &lease->generation_exhausted, memory_order_acquire);
    if (snapshot.owner == JANOS_RADIO_OWNER_NONE) {
        snapshot.state = JANOS_RADIO_LEASE_IDLE;
        snapshot.generation = 0U;
        snapshot.cancel_requested = false;
    } else if (snapshot.generation == 0U) {
        snapshot.state = JANOS_RADIO_LEASE_PREPARING;
        snapshot.generation = (uint32_t)atomic_load_explicit(
            &lease->next_generation, memory_order_acquire);
        if (snapshot.generation == 0U) snapshot.generation = UINT32_MAX;
    } else if (snapshot.state == JANOS_RADIO_LEASE_IDLE) {
        snapshot.state = JANOS_RADIO_LEASE_CLEANUP;
    }
    return snapshot;
}

