/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_radio_lease.h"

#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>

enum { ITERATIONS = 10000 };

typedef struct {
    janos_radio_lease_t *lease;
    janos_radio_owner_t owner;
    atomic_bool *start;
    atomic_uint *ready;
    janos_radio_lease_result_t result;
    uint32_t generation;
} contender_t;

typedef struct {
    janos_radio_lease_t *lease;
    atomic_bool *stop;
    atomic_bool *invalid_snapshot;
} observer_t;

typedef struct {
    janos_radio_lease_t *lease;
    janos_radio_owner_t owner;
    uint32_t generation;
    atomic_bool *start;
    atomic_uint *ready;
    bool cleanup;
    bool result;
} transition_t;

typedef struct {
    janos_radio_lease_t *lease;
    janos_radio_owner_t owner;
    uint32_t old_generation;
    uint32_t new_generation;
    atomic_bool *start;
    atomic_uint *ready;
    bool cancel_result;
    bool cleanup_result;
    janos_radio_lease_result_t acquire_result;
} aba_t;

static void *acquire_once(void *opaque)
{
    contender_t *contender = opaque;
    atomic_fetch_add_explicit(contender->ready, 1U, memory_order_release);
    while (!atomic_load_explicit(contender->start, memory_order_acquire)) {
        sched_yield();
    }
    contender->result = janos_radio_lease_acquire(
        contender->lease, contender->owner, &contender->generation);
    return NULL;
}

static void *observe_snapshots(void *opaque)
{
    observer_t *observer = opaque;
    while (!atomic_load_explicit(observer->stop, memory_order_acquire)) {
        janos_radio_lease_snapshot_t snapshot =
            janos_radio_lease_snapshot(observer->lease);
        bool idle = snapshot.owner == JANOS_RADIO_OWNER_NONE &&
            snapshot.state == JANOS_RADIO_LEASE_IDLE &&
            snapshot.generation == 0U && !snapshot.callbacks_open;
        bool owned = snapshot.owner != JANOS_RADIO_OWNER_NONE &&
            snapshot.state != JANOS_RADIO_LEASE_IDLE &&
            snapshot.generation != 0U;
        if (!idle && !owned) {
            atomic_store_explicit(observer->invalid_snapshot, true,
                                  memory_order_release);
            break;
        }
        sched_yield();
    }
    return NULL;
}

static void *transition_once(void *opaque)
{
    transition_t *transition = opaque;
    atomic_fetch_add_explicit(transition->ready, 1U, memory_order_release);
    while (!atomic_load_explicit(transition->start, memory_order_acquire)) {
        sched_yield();
    }
    transition->result = transition->cleanup ?
        janos_radio_lease_begin_cleanup(transition->lease, transition->owner,
                                        transition->generation) :
        janos_radio_lease_mark_running(transition->lease, transition->owner,
                                       transition->generation);
    return NULL;
}

static void *cancel_old_generation(void *opaque)
{
    aba_t *race = opaque;
    atomic_fetch_add_explicit(race->ready, 1U, memory_order_release);
    while (!atomic_load_explicit(race->start, memory_order_acquire)) {
        sched_yield();
    }
    race->cancel_result = janos_radio_lease_request_cancel(
        race->lease, race->owner, race->old_generation);
    return NULL;
}

static void *release_and_reacquire(void *opaque)
{
    aba_t *race = opaque;
    atomic_fetch_add_explicit(race->ready, 1U, memory_order_release);
    while (!atomic_load_explicit(race->start, memory_order_acquire)) {
        sched_yield();
    }
    race->cleanup_result = janos_radio_lease_finish_cleanup(
        race->lease, race->owner, race->old_generation, true);
    if (race->cleanup_result) {
        race->acquire_result = janos_radio_lease_acquire(
            race->lease, race->owner, &race->new_generation);
    }
    return NULL;
}

int main(void)
{
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);

    /* The startup-release publication must remain coherent for lock-free
     * observers, including immediate reuse by another generation. */
    atomic_bool stop_startup_observer = ATOMIC_VAR_INIT(false);
    atomic_bool invalid_startup_snapshot = ATOMIC_VAR_INIT(false);
    observer_t startup_observer = {.lease = &lease,
        .stop = &stop_startup_observer, .invalid_snapshot = &invalid_startup_snapshot};
    pthread_t startup_observer_thread;
    assert(pthread_create(&startup_observer_thread, NULL, observe_snapshots,
                          &startup_observer) == 0);
    for (unsigned i = 0; i < ITERATIONS * 10U; ++i) {
        uint32_t generation = 0;
        assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_LEGACY,
                                         &generation) == JANOS_RADIO_LEASE_OK);
        assert(janos_radio_lease_finish_startup(&lease, JANOS_RADIO_OWNER_LEGACY,
                                                generation));
    }
    atomic_store_explicit(&stop_startup_observer, true, memory_order_release);
    assert(pthread_join(startup_observer_thread, NULL) == 0);
    assert(!atomic_load_explicit(&invalid_startup_snapshot, memory_order_acquire));

    for (unsigned iteration = 0; iteration < ITERATIONS; ++iteration) {
        atomic_bool start = ATOMIC_VAR_INIT(false);
        atomic_bool stop_observer = ATOMIC_VAR_INIT(false);
        atomic_bool invalid_snapshot = ATOMIC_VAR_INIT(false);
        atomic_uint ready = ATOMIC_VAR_INIT(0U);
        contender_t analyzer = {
            .lease = &lease,
            .owner = iteration % 2U ? JANOS_RADIO_OWNER_ANALYZER : JANOS_RADIO_OWNER_LEGACY,
            .start = &start,
            .ready = &ready,
        };
        contender_t wps = {
            .lease = &lease,
            .owner = JANOS_RADIO_OWNER_WPS,
            .start = &start,
            .ready = &ready,
        };
        pthread_t analyzer_thread;
        pthread_t wps_thread;
        pthread_t observer_thread;
        observer_t observer = {
            .lease = &lease,
            .stop = &stop_observer,
            .invalid_snapshot = &invalid_snapshot,
        };
        assert(pthread_create(&observer_thread, NULL, observe_snapshots,
                              &observer) == 0);
        assert(pthread_create(&analyzer_thread, NULL, acquire_once,
                              &analyzer) == 0);
        assert(pthread_create(&wps_thread, NULL, acquire_once, &wps) == 0);
        while (atomic_load_explicit(&ready, memory_order_acquire) != 2U) {
            sched_yield();
        }
        atomic_store_explicit(&start, true, memory_order_release);
        assert(pthread_join(analyzer_thread, NULL) == 0);
        assert(pthread_join(wps_thread, NULL) == 0);

        assert((analyzer.result == JANOS_RADIO_LEASE_OK) ^
               (wps.result == JANOS_RADIO_LEASE_OK));
        assert((analyzer.result == JANOS_RADIO_LEASE_BUSY) ^
               (wps.result == JANOS_RADIO_LEASE_BUSY));

        contender_t *winner = analyzer.result == JANOS_RADIO_LEASE_OK ?
            &analyzer : &wps;
        atomic_store_explicit(&start, false, memory_order_release);
        atomic_store_explicit(&ready, 0U, memory_order_release);
        transition_t running = {
            .lease = &lease,
            .owner = winner->owner,
            .generation = winner->generation,
            .start = &start,
            .ready = &ready,
            .cleanup = false,
        };
        transition_t cleanup = running;
        cleanup.cleanup = true;
        pthread_t running_thread;
        pthread_t cleanup_thread;
        assert(pthread_create(&running_thread, NULL, transition_once,
                              &running) == 0);
        assert(pthread_create(&cleanup_thread, NULL, transition_once,
                              &cleanup) == 0);
        while (atomic_load_explicit(&ready, memory_order_acquire) != 2U) {
            sched_yield();
        }
        atomic_store_explicit(&start, true, memory_order_release);
        assert(pthread_join(running_thread, NULL) == 0);
        assert(pthread_join(cleanup_thread, NULL) == 0);
        assert(cleanup.result);
        janos_radio_lease_snapshot_t cleanup_snapshot =
            janos_radio_lease_snapshot(&lease);
        assert(cleanup_snapshot.state == JANOS_RADIO_LEASE_CLEANUP);
        assert(!cleanup_snapshot.callbacks_open);
        atomic_store_explicit(&start, false, memory_order_release);
        atomic_store_explicit(&ready, 0U, memory_order_release);
        aba_t aba = {
            .lease = &lease,
            .owner = winner->owner,
            .old_generation = winner->generation,
            .start = &start,
            .ready = &ready,
            .acquire_result = JANOS_RADIO_LEASE_INVALID,
        };
        pthread_t stale_cancel_thread;
        pthread_t reacquire_thread;
        assert(pthread_create(&stale_cancel_thread, NULL,
                              cancel_old_generation, &aba) == 0);
        assert(pthread_create(&reacquire_thread, NULL,
                              release_and_reacquire, &aba) == 0);
        while (atomic_load_explicit(&ready, memory_order_acquire) != 2U) {
            sched_yield();
        }
        atomic_store_explicit(&start, true, memory_order_release);
        assert(pthread_join(stale_cancel_thread, NULL) == 0);
        assert(pthread_join(reacquire_thread, NULL) == 0);
        assert(!aba.cancel_result);
        assert(aba.cleanup_result);
        assert(aba.acquire_result == JANOS_RADIO_LEASE_OK);
        assert(aba.new_generation != winner->generation);
        assert(!janos_radio_lease_cancel_requested(
            &lease, winner->owner, aba.new_generation));
        janos_radio_lease_snapshot_t new_snapshot =
            janos_radio_lease_snapshot(&lease);
        assert(new_snapshot.owner == winner->owner);
        assert(new_snapshot.state == JANOS_RADIO_LEASE_PREPARING);
        assert(new_snapshot.generation == aba.new_generation);
        assert(janos_radio_lease_begin_cleanup(
            &lease, winner->owner, aba.new_generation));
        assert(janos_radio_lease_finish_cleanup(
            &lease, winner->owner, aba.new_generation, true));
        atomic_store_explicit(&stop_observer, true, memory_order_release);
        assert(pthread_join(observer_thread, NULL) == 0);
        assert(!atomic_load_explicit(&invalid_snapshot, memory_order_acquire));
    }

    puts("PASS: JanOS shared radio lease concurrency");
    return 0;
}
