/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_radio_lease.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

int main(void)
{
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    /* Simulate a preempted startup release after clearing its generation.
     * Status must remain conservatively busy rather than expose owner+zero. */
    atomic_store(&lease.owner, JANOS_RADIO_OWNER_LEGACY);
    atomic_store(&lease.state, JANOS_RADIO_LEASE_PREPARING);
    atomic_store(&lease.next_generation, 2U);
    janos_radio_lease_snapshot_t releasing = janos_radio_lease_snapshot(&lease);
    assert(releasing.owner == JANOS_RADIO_OWNER_LEGACY);
    assert(releasing.generation != 0U);
    janos_radio_lease_init(&lease);
    /* Corrupt idle tuples must not be replaced by a newly valid owner. */
    atomic_store(&lease.generation, 41U);
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_LEGACY, NULL) ==
           JANOS_RADIO_LEASE_BUSY);
    janos_radio_lease_init(&lease);
    atomic_store(&lease.callbacks_open, true);
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_WPS, NULL) ==
           JANOS_RADIO_LEASE_BUSY);
    janos_radio_lease_init(&lease);
    janos_radio_lease_snapshot_t snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_NONE);
    assert(snapshot.state == JANOS_RADIO_LEASE_IDLE);
    assert(snapshot.generation == 0U);
    assert(!snapshot.cancel_requested);
    assert(!snapshot.callbacks_open);
    assert(!snapshot.generation_exhausted);

    /* A snapshot must never spin forever if it preempts the owner between
     * atomic claim and publication, or between IDLE publication and release. */
    atomic_store_explicit(&lease.owner, JANOS_RADIO_OWNER_WPS,
                          memory_order_release);
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_WPS);
    assert(snapshot.state == JANOS_RADIO_LEASE_PREPARING);
    assert(snapshot.generation == 1U);
    atomic_store_explicit(&lease.generation, 7U, memory_order_release);
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_WPS);
    assert(snapshot.state == JANOS_RADIO_LEASE_CLEANUP);
    assert(snapshot.generation == 7U);
    janos_radio_lease_init(&lease);

    assert(janos_radio_lease_acquire(NULL, JANOS_RADIO_OWNER_WPS, NULL) ==
           JANOS_RADIO_LEASE_INVALID);
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_NONE, NULL) ==
           JANOS_RADIO_LEASE_INVALID);
    assert(janos_radio_lease_acquire(&lease, (janos_radio_owner_t)99, NULL) ==
           JANOS_RADIO_LEASE_INVALID);
    uint32_t analyzer_generation = 0;
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_ANALYZER,
                                     &analyzer_generation) == JANOS_RADIO_LEASE_OK);
    assert(analyzer_generation == 1);
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_ANALYZER);
    assert(snapshot.state == JANOS_RADIO_LEASE_PREPARING);
    assert(snapshot.generation == analyzer_generation);

    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_WPS, NULL) ==
           JANOS_RADIO_LEASE_BUSY);
    janos_radio_lease_snapshot_t after_loser =
        janos_radio_lease_snapshot(&lease);
    assert(after_loser.owner == snapshot.owner);
    assert(after_loser.state == snapshot.state);
    assert(after_loser.generation == snapshot.generation);
    assert(!janos_radio_lease_accept_callback(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation));
    assert(janos_radio_lease_mark_running(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation));
    assert(!janos_radio_lease_mark_running(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation));
    assert(janos_radio_lease_accept_callback(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation));
    assert(!janos_radio_lease_accept_callback(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation + 1));
    assert(janos_radio_lease_request_cancel(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation));
    assert(!janos_radio_lease_request_cancel(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation + 1U));
    assert(janos_radio_lease_cancel_requested(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation));
    assert(!janos_radio_lease_accept_callback(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation));
    assert(janos_radio_lease_begin_cleanup(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation));
    assert(!janos_radio_lease_begin_cleanup(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation));
    assert(janos_radio_lease_finish_cleanup(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation, true));
    assert(!janos_radio_lease_finish_cleanup(
        &lease, JANOS_RADIO_OWNER_ANALYZER, analyzer_generation, true));
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_NONE);
    assert(snapshot.state == JANOS_RADIO_LEASE_IDLE);
    assert(snapshot.generation == 0U);
    assert(!snapshot.cancel_requested);
    assert(!snapshot.callbacks_open);

    uint32_t wps_generation = 0;
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_WPS,
                                     &wps_generation) == JANOS_RADIO_LEASE_OK);
    assert(wps_generation == 2);
    assert(janos_radio_lease_mark_running(
        &lease, JANOS_RADIO_OWNER_WPS, wps_generation));
    assert(janos_radio_lease_begin_cleanup(
        &lease, JANOS_RADIO_OWNER_WPS, wps_generation));
    assert(!janos_radio_lease_finish_cleanup(
        &lease, JANOS_RADIO_OWNER_WPS, wps_generation, false));
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.state == JANOS_RADIO_LEASE_QUARANTINED);
    assert(snapshot.owner == JANOS_RADIO_OWNER_WPS);
    assert(snapshot.generation == wps_generation);
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_ANALYZER,
                                     NULL) == JANOS_RADIO_LEASE_QUARANTINED_RESULT);

    janos_radio_lease_init(&lease);
    atomic_store_explicit(&lease.next_generation, UINT32_MAX,
                          memory_order_release);
    uint32_t last_generation = 0;
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_WPS,
                                     &last_generation) == JANOS_RADIO_LEASE_OK);
    assert(last_generation == UINT32_MAX);
    assert(janos_radio_lease_begin_cleanup(
        &lease, JANOS_RADIO_OWNER_WPS, last_generation));
    assert(janos_radio_lease_finish_cleanup(
        &lease, JANOS_RADIO_OWNER_WPS, last_generation, true));
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_WPS,
                                     NULL) == JANOS_RADIO_LEASE_EXHAUSTED);

    puts("PASS: JanOS shared radio lease");
    return 0;
}
