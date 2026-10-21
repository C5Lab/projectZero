/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_worker_state.h"

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>

typedef struct {
    janos_wps_worker_state_t *worker;
    atomic_bool service_idle;
    atomic_bool release_epilogue;
    atomic_bool accepted_emitted;
    atomic_bool operation_entered;
} fixture_t;

static void *finish_worker(void *context)
{
    fixture_t *fixture = context;
    /* The service terminalizes before runtime formats/emits its terminal
     * record.  Join must remain false throughout this epilogue window. */
    atomic_store(&fixture->service_idle, true);
    while (!atomic_load(&fixture->release_epilogue)) {}
    janos_wps_worker_state_finish(fixture->worker);
    return NULL;
}

static void *start_gated_worker(void *context)
{
    fixture_t *fixture = context;
    while (!janos_wps_worker_state_released(fixture->worker)) {}
    assert(atomic_load(&fixture->accepted_emitted));
    atomic_store(&fixture->operation_entered, true);
    return NULL;
}

int main(void)
{
    assert(janos_wps_worker_stop_action(true, false, false) ==
           JANOS_WPS_STOP_ALREADY_JOINED);
    assert(janos_wps_worker_stop_action(true, false, true) ==
           JANOS_WPS_STOP_WAIT_EPILOGUE);
    assert(janos_wps_worker_stop_action(false, false, true) ==
           JANOS_WPS_STOP_REQUEST_CANCEL);
    assert(janos_wps_worker_stop_action(false, true, true) ==
           JANOS_WPS_STOP_WAIT_EPILOGUE);
    assert(janos_wps_worker_stop_action(false, true, false) ==
           JANOS_WPS_STOP_QUARANTINED);

    janos_wps_worker_state_t worker;
    janos_wps_worker_state_init(&worker);
    assert(janos_wps_worker_state_joined(&worker, true));
    assert(janos_wps_worker_state_try_start(&worker));
    assert(!janos_wps_worker_state_try_start(&worker));

    fixture_t fixture = {.worker = &worker};
    atomic_init(&fixture.service_idle, false);
    atomic_init(&fixture.release_epilogue, false);
    atomic_init(&fixture.accepted_emitted, false);
    atomic_init(&fixture.operation_entered, false);
    pthread_t gated_thread;
    assert(pthread_create(&gated_thread, NULL, start_gated_worker, &fixture) == 0);
    assert(!atomic_load(&fixture.operation_entered));
    atomic_store(&fixture.accepted_emitted, true);
    janos_wps_worker_state_release(&worker);
    assert(pthread_join(gated_thread, NULL) == 0);
    assert(atomic_load(&fixture.operation_entered));

    pthread_t thread;
    assert(pthread_create(&thread, NULL, finish_worker, &fixture) == 0);
    while (!atomic_load(&fixture.service_idle)) {}
    assert(!janos_wps_worker_state_joined(&worker, true));
    atomic_store(&fixture.release_epilogue, true);
    assert(pthread_join(thread, NULL) == 0);
    assert(janos_wps_worker_state_joined(&worker, true));
    puts("PASS: JanOS WPS runtime worker completion");
    return 0;
}
