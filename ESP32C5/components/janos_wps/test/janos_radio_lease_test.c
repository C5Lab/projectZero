/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_radio_lease.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>

#define SHIELD_OWNER JANOS_RADIO_OWNER_SHIELD

static void shield_owner_lifecycle(void)
{
    _Static_assert(JANOS_RADIO_OWNER_NONE == 0 &&
                   JANOS_RADIO_OWNER_ANALYZER == 1 &&
                   JANOS_RADIO_OWNER_WPS == 2 &&
                   JANOS_RADIO_OWNER_LEGACY == 3 &&
                   JANOS_RADIO_OWNER_DEFENCE == 4 &&
                   JANOS_RADIO_OWNER_SECURITY_MONITOR == 5 &&
                   JANOS_RADIO_OWNER_SHIELD == 6,
                   "Existing owner values are a compatibility contract");
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    uint32_t old_generation = 0U;
    assert(janos_radio_lease_acquire(&lease, SHIELD_OWNER,
                                     &old_generation) == JANOS_RADIO_LEASE_OK);
    assert(old_generation != 0U);
    janos_radio_lease_snapshot_t snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == SHIELD_OWNER);
    assert(snapshot.state == JANOS_RADIO_LEASE_PREPARING);
    assert(janos_radio_lease_mark_running(&lease, SHIELD_OWNER, old_generation));
    assert(janos_radio_lease_accept_callback(&lease, SHIELD_OWNER, old_generation));
    const janos_radio_owner_t contenders[] = {
        JANOS_RADIO_OWNER_ANALYZER, JANOS_RADIO_OWNER_WPS,
        JANOS_RADIO_OWNER_LEGACY, JANOS_RADIO_OWNER_DEFENCE,
        JANOS_RADIO_OWNER_SECURITY_MONITOR, SHIELD_OWNER,
    };
    for (size_t i = 0; i < sizeof(contenders) / sizeof(contenders[0]); ++i)
        assert(janos_radio_lease_acquire(&lease, contenders[i], NULL) ==
               JANOS_RADIO_LEASE_BUSY);
    assert(!janos_radio_lease_finish_startup(&lease, SHIELD_OWNER, old_generation));
    assert(janos_radio_lease_request_cancel(&lease, SHIELD_OWNER, old_generation));
    assert(janos_radio_lease_cancel_requested(&lease, SHIELD_OWNER, old_generation));
    assert(!janos_radio_lease_accept_callback(&lease, SHIELD_OWNER, old_generation));
    assert(janos_radio_lease_begin_cleanup(&lease, SHIELD_OWNER, old_generation));
    assert(!janos_radio_lease_begin_cleanup(&lease, SHIELD_OWNER, old_generation));
    assert(janos_radio_lease_finish_cleanup(&lease, SHIELD_OWNER, old_generation, true));
    assert(!janos_radio_lease_finish_cleanup(&lease, SHIELD_OWNER, old_generation, true));
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_NONE);
    assert(snapshot.state == JANOS_RADIO_LEASE_IDLE);
    assert(snapshot.generation == 0U);

    uint32_t generation = 0U;
    assert(janos_radio_lease_acquire(&lease, SHIELD_OWNER, &generation) ==
           JANOS_RADIO_LEASE_OK);
    assert(generation != old_generation);
    assert(janos_radio_lease_mark_running(&lease, SHIELD_OWNER, generation));
    assert(!janos_radio_lease_request_cancel(&lease, SHIELD_OWNER, old_generation));
    assert(!janos_radio_lease_begin_cleanup(&lease, SHIELD_OWNER, old_generation));
    assert(!janos_radio_lease_finish_cleanup(&lease, SHIELD_OWNER, old_generation, true));
    assert(!janos_radio_lease_cancel_requested(&lease, SHIELD_OWNER, generation));
    assert(janos_radio_lease_accept_callback(&lease, SHIELD_OWNER, generation));
    assert(janos_radio_lease_begin_cleanup(&lease, SHIELD_OWNER, generation));
    assert(!janos_radio_lease_finish_cleanup(&lease, SHIELD_OWNER, generation, false));
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == SHIELD_OWNER);
    assert(snapshot.state == JANOS_RADIO_LEASE_QUARANTINED);
    assert(snapshot.generation == generation);
    assert(!snapshot.callbacks_open);
    for (size_t i = 0; i < sizeof(contenders) / sizeof(contenders[0]); ++i)
        assert(janos_radio_lease_acquire(&lease, contenders[i], NULL) ==
               JANOS_RADIO_LEASE_QUARANTINED_RESULT);
    assert(janos_radio_lease_begin_cleanup(&lease, SHIELD_OWNER, generation));
    assert(janos_radio_lease_finish_cleanup(&lease, SHIELD_OWNER, generation, true));
    assert(!janos_radio_lease_finish_cleanup(&lease, SHIELD_OWNER, generation, true));
    assert(janos_radio_lease_acquire(&lease, (janos_radio_owner_t)(SHIELD_OWNER + 1),
                                     NULL) == JANOS_RADIO_LEASE_INVALID);
}

int main(void)
{
    shield_owner_lifecycle();
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
    assert(janos_radio_lease_begin_cleanup(
        &lease, JANOS_RADIO_OWNER_WPS, wps_generation));
    assert(janos_radio_lease_finish_cleanup(
        &lease, JANOS_RADIO_OWNER_WPS, wps_generation, true));
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_NONE);
    assert(snapshot.state == JANOS_RADIO_LEASE_IDLE);

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

    janos_radio_lease_init(&lease);
    uint32_t defence_generation = 0U;
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_DEFENCE,
                                     &defence_generation) ==
           JANOS_RADIO_LEASE_OK);
    assert(defence_generation != 0U);
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_DEFENCE);
    assert(snapshot.state == JANOS_RADIO_LEASE_PREPARING);
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_WPS, NULL) ==
           JANOS_RADIO_LEASE_BUSY);
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_ANALYZER,
                                     NULL) == JANOS_RADIO_LEASE_BUSY);
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_LEGACY,
                                     NULL) == JANOS_RADIO_LEASE_BUSY);
    assert(janos_radio_lease_mark_running(&lease, JANOS_RADIO_OWNER_DEFENCE,
                                          defence_generation));
    assert(janos_radio_lease_accept_callback(
        &lease, JANOS_RADIO_OWNER_DEFENCE, defence_generation));
    assert(!janos_radio_lease_request_cancel(
        &lease, JANOS_RADIO_OWNER_DEFENCE, defence_generation + 1U));
    assert(!janos_radio_lease_begin_cleanup(
        &lease, JANOS_RADIO_OWNER_DEFENCE, defence_generation + 1U));
    assert(janos_radio_lease_request_cancel(
        &lease, JANOS_RADIO_OWNER_DEFENCE, defence_generation));
    assert(janos_radio_lease_begin_cleanup(
        &lease, JANOS_RADIO_OWNER_DEFENCE, defence_generation));
    assert(janos_radio_lease_finish_cleanup(
        &lease, JANOS_RADIO_OWNER_DEFENCE, defence_generation, true));
    assert(!janos_radio_lease_finish_cleanup(
        &lease, JANOS_RADIO_OWNER_DEFENCE, defence_generation, true));
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_NONE);
    assert(snapshot.state == JANOS_RADIO_LEASE_IDLE);

    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_DEFENCE,
                                     &defence_generation) ==
           JANOS_RADIO_LEASE_OK);
    assert(janos_radio_lease_mark_running(&lease, JANOS_RADIO_OWNER_DEFENCE,
                                          defence_generation));
    assert(janos_radio_lease_begin_cleanup(
        &lease, JANOS_RADIO_OWNER_DEFENCE, defence_generation));
    assert(!janos_radio_lease_finish_cleanup(
        &lease, JANOS_RADIO_OWNER_DEFENCE, defence_generation, false));
    assert(janos_radio_lease_begin_cleanup(
        &lease, JANOS_RADIO_OWNER_DEFENCE, defence_generation));
    assert(janos_radio_lease_finish_cleanup(
        &lease, JANOS_RADIO_OWNER_DEFENCE, defence_generation, true));

    const janos_radio_owner_t security_monitor_owner =
        JANOS_RADIO_OWNER_SECURITY_MONITOR;
    uint32_t security_generation = 0U;
    assert(janos_radio_lease_acquire(&lease, security_monitor_owner,
                                     &security_generation) ==
           JANOS_RADIO_LEASE_OK);
    assert(security_generation != 0U);
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == security_monitor_owner);
    assert(snapshot.state == JANOS_RADIO_LEASE_PREPARING);
    assert(snapshot.generation == security_generation);
    assert(janos_radio_lease_mark_running(
        &lease, security_monitor_owner, security_generation));
    assert(janos_radio_lease_accept_callback(
        &lease, security_monitor_owner, security_generation));
    const janos_radio_owner_t other_owners[] = {
        JANOS_RADIO_OWNER_ANALYZER, JANOS_RADIO_OWNER_WPS,
        JANOS_RADIO_OWNER_LEGACY, JANOS_RADIO_OWNER_DEFENCE,
    };
    for (unsigned i = 0; i < sizeof(other_owners) / sizeof(other_owners[0]); ++i) {
        assert(janos_radio_lease_acquire(&lease, other_owners[i], NULL) ==
               JANOS_RADIO_LEASE_BUSY);
    }
    assert(janos_radio_lease_request_cancel(
        &lease, security_monitor_owner, security_generation));
    assert(janos_radio_lease_cancel_requested(
        &lease, security_monitor_owner, security_generation));
    assert(!janos_radio_lease_accept_callback(
        &lease, security_monitor_owner, security_generation));
    assert(janos_radio_lease_begin_cleanup(
        &lease, security_monitor_owner, security_generation));
    assert(janos_radio_lease_finish_cleanup(
        &lease, security_monitor_owner, security_generation, true));
    assert(!janos_radio_lease_finish_cleanup(
        &lease, security_monitor_owner, security_generation, true));

    uint32_t new_security_generation = 0U;
    assert(janos_radio_lease_acquire(&lease, security_monitor_owner,
                                     &new_security_generation) ==
           JANOS_RADIO_LEASE_OK);
    assert(new_security_generation != security_generation);
    assert(janos_radio_lease_mark_running(
        &lease, security_monitor_owner, new_security_generation));
    assert(!janos_radio_lease_request_cancel(
        &lease, security_monitor_owner, security_generation));
    assert(!janos_radio_lease_begin_cleanup(
        &lease, security_monitor_owner, security_generation));
    assert(!janos_radio_lease_finish_cleanup(
        &lease, security_monitor_owner, security_generation, true));
    assert(!janos_radio_lease_cancel_requested(
        &lease, security_monitor_owner, new_security_generation));
    assert(janos_radio_lease_accept_callback(
        &lease, security_monitor_owner, new_security_generation));
    assert(janos_radio_lease_begin_cleanup(
        &lease, security_monitor_owner, new_security_generation));
    assert(!janos_radio_lease_finish_cleanup(
        &lease, security_monitor_owner, security_generation, true));
    assert(janos_radio_lease_finish_cleanup(
        &lease, security_monitor_owner, new_security_generation, true));
    assert(!janos_radio_lease_finish_cleanup(
        &lease, security_monitor_owner, new_security_generation, true));
    snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_NONE);
    assert(snapshot.state == JANOS_RADIO_LEASE_IDLE);
    assert(snapshot.generation == 0U);
    assert(!snapshot.cancel_requested);
    assert(!snapshot.callbacks_open);
    assert(janos_radio_lease_acquire(&lease, (janos_radio_owner_t)(SHIELD_OWNER + 1), NULL) ==
           JANOS_RADIO_LEASE_INVALID);

    puts("PASS: JanOS shared radio lease");
    return 0;
}
