/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_service.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>

typedef struct {
    janos_wps_worker_fn worker;
    void *worker_arg;
    janos_wps_operation_t seen_operation;
    char seen_ssid[33];
    unsigned calls;
    bool success_secret;
    const char *storage_result;
    atomic_bool block_execute;
    atomic_bool execute_entered;
    atomic_bool release_execute;
    atomic_bool call_commit_gate;
    atomic_bool commit_gate_done;
    atomic_bool commit_gate_result;
    atomic_bool block_free;
    atomic_bool free_entered;
    atomic_bool release_free;
    janos_wps_service_t *service;
} fake_t;

static void *alloc_fn(void *ctx, size_t size, uint32_t caps)
{ (void)ctx; (void)caps; return calloc(1, size); }
static void free_fn(void *ctx, void *ptr, size_t size,
                    janos_wps_memory_class_t cls)
{
    fake_t *fake = ctx;
    (void)size;
    if (fake && cls == JANOS_WPS_MEMORY_SECRET &&
        atomic_load(&fake->block_free)) {
        atomic_store(&fake->free_entered, true);
        while (!atomic_load(&fake->release_free)) {}
    }
    free(ptr);
}
static uint64_t now_fn(void *ctx) { (void)ctx; return 1000U; }
static bool admit_fn(void *ctx, const char **reason)
{ (void)ctx; (void)reason; return true; }
static bool start_fn(void *ctx, janos_wps_worker_fn worker, void *arg)
{
    fake_t *fake = ctx;
    fake->worker = worker;
    fake->worker_arg = arg;
    return true;
}

static void *run_worker(void *context)
{
    fake_t *fake = context;
    fake->worker(fake->worker_arg);
    return NULL;
}

typedef struct {
    janos_wps_service_t *service;
    atomic_bool entered;
    bool result;
} stop_racer_t;

static void *run_stop(void *context)
{
    stop_racer_t *race = context;
    atomic_store(&race->entered, true);
    race->result = janos_wps_service_stop(race->service);
    return NULL;
}

typedef struct {
    janos_wps_service_t *service;
    janos_wps_memory_t *memory;
    atomic_bool stop;
} vault_racer_t;

static void *race_vault(void *context)
{
    vault_racer_t *race = context;
    while (!atomic_load(&race->stop)) {
        janos_wps_service_status_t status =
            janos_wps_service_status(race->service);
        (void)janos_wps_memory_snapshot(race->memory);
        char pin[9] = {0};
        char key[65] = {0};
        uint32_t operation_id = 0U;
        lab_secret_state_t reveal_state = LAB_SECRET_EMPTY;
        bool revealed = janos_wps_service_reveal_with_state(
            race->service, pin, sizeof(pin), key, sizeof(key), &operation_id,
            &reveal_state);
        assert(revealed || reveal_state == LAB_SECRET_EMPTY ||
               reveal_state == LAB_SECRET_EXPIRED);
        janos_wps_secure_wipe(pin, sizeof(pin));
        janos_wps_secure_wipe(key, sizeof(key));
        janos_wps_service_erase_secret(race->service);
        assert(status.phase <= JANOS_WPS_SERVICE_QUARANTINED);
    }
    return NULL;
}
static bool execute_fn(void *ctx, const janos_wps_request_t *request,
                       janos_wps_outcome_t *outcome)
{
    fake_t *fake = ctx;
    atomic_store(&fake->execute_entered, true);
    if (atomic_load(&fake->block_execute))
        while (!atomic_load(&fake->release_execute)) {}
    if (atomic_load(&fake->call_commit_gate)) {
        atomic_store(&fake->commit_gate_result,
            janos_wps_service_commit_gate(fake->service,
                                           request->operation_id));
        atomic_store(&fake->commit_gate_done, true);
        while (!atomic_load(&fake->release_execute)) {}
    }
    ++fake->calls;
    fake->seen_operation = request->command.operation;
    memcpy(fake->seen_ssid, request->command.ssid, sizeof(fake->seen_ssid));
    memset(outcome, 0, sizeof(*outcome));
    outcome->operation_result = request->command.operation ==
        JANOS_WPS_OP_JWPS_PLAN ? "plan_ready" :
        request->command.operation == JANOS_WPS_OP_PIXIE ?
        "pixie_pin_and_m7_verified" : "selftest_verified";
    outcome->cleanup_ok = true;
    outcome->storage_result = fake->storage_result ? fake->storage_result :
                                                    "not_required";
    if (fake->success_secret) {
        outcome->authenticated_m7 = true;
        memcpy(outcome->pin, "12345670", 9U);
        memcpy(outcome->network_key, "synthetic-key", 14U);
    }
    return true;
}

int main(void)
{
    fake_t fake = {0};
    janos_wps_memory_t memory;
    const janos_wps_memory_ops_t memory_ops = {alloc_fn, free_fn};
    janos_wps_memory_init(&memory, &memory_ops, &fake);
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    const janos_wps_service_ops_t ops = {
        .now_ms = now_fn, .admit = admit_fn, .start_worker = start_fn,
        .execute_operation = execute_fn,
    };
    janos_wps_service_t service;
    janos_wps_service_init(&service, &lease, &memory, &ops, &fake);
    fake.service = &service;

    /* The service is a trust boundary too: callers other than the console
     * parser must not be able to enqueue malformed operation descriptors. */
    janos_wps_command_t malformed = {.operation = JANOS_WPS_OP_JWPS_PLAN};
    assert(!janos_wps_service_start(&service, &malformed, NULL));
    assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
    malformed.operation = JANOS_WPS_OP_JWPS_CAMPAIGN;
    const uint8_t bssid[6] = {0x68,0xff,0x7b,0xcd,0xfc,0x40};
    memcpy(malformed.bssid, bssid, sizeof(bssid));
    malformed.count = 0U;
    assert(!janos_wps_service_start(&service, &malformed, NULL));
    malformed.count = 1U;
    memset(malformed.ssid, 'X', sizeof(malformed.ssid));
    assert(!janos_wps_service_start(&service, &malformed, NULL));

    janos_wps_command_t plan = {.operation = JANOS_WPS_OP_JWPS_PLAN};
    memcpy(plan.bssid, bssid, sizeof(bssid));
    memcpy(plan.ssid, "Pure Rental Apartments", 23U);
    uint32_t id = 0;
    assert(janos_wps_service_start(&service, &plan, &id));
    assert(id == 1U);
    assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
    memset(plan.ssid, 'X', strlen(plan.ssid));
    fake.worker(fake.worker_arg);
    assert(fake.seen_operation == JANOS_WPS_OP_JWPS_PLAN);
    assert(strcmp(fake.seen_ssid, "Pure Rental Apartments") == 0);
    janos_wps_service_status_t status = janos_wps_service_status(&service);
    assert(status.phase == JANOS_WPS_SERVICE_IDLE);
    assert(strcmp(status.operation_result, "plan_ready") == 0);
    assert(strcmp(status.cleanup_result, "not_required") == 0);
    assert(strcmp(status.storage_result, "not_required") == 0);
    assert(janos_wps_memory_snapshot(&memory).secret_bytes == 0U);

    janos_wps_command_t transport = {
        .operation = JANOS_WPS_OP_SELFTEST_TRANSPORT,
    };
    assert(janos_wps_service_start(&service, &transport, &id));
    assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_WPS);
    fake.worker(fake.worker_arg);
    status = janos_wps_service_status(&service);
    assert(status.phase == JANOS_WPS_SERVICE_IDLE);
    assert(strcmp(status.cleanup_result, "restored") == 0);
    assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);

    fake.success_secret = true;
    fake.storage_result = "mount_error";
    janos_wps_command_t pixie = {.operation = JANOS_WPS_OP_PIXIE};
    memcpy(pixie.bssid, bssid, sizeof(bssid));
    assert(janos_wps_service_start(&service, &pixie, &id));
    fake.worker(fake.worker_arg);
    status = janos_wps_service_status(&service);
    assert(status.secret.state == LAB_SECRET_AVAILABLE);
    assert(strcmp(status.operation_result, "pixie_pin_and_m7_verified") == 0);
    assert(strcmp(status.storage_result, "mount_error") == 0);
    char pin[9] = {0}, key[65] = {0};
    uint32_t secret_id = 0U;
    assert(janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                    sizeof(key), &secret_id));
    assert(secret_id == id);
    assert(strcmp(pin, "12345670") == 0);
    assert(strcmp(key, "synthetic-key") == 0);

    fake.success_secret = false;
    fake.storage_result = "not_required";
    janos_wps_command_t db = {.operation = JANOS_WPS_OP_SELFTEST_DB};
    assert(janos_wps_service_start(&service, &db, &id));
    assert(janos_wps_service_stop(&service));
    fake.worker(fake.worker_arg);
    status = janos_wps_service_status(&service);
    assert(strcmp(status.operation_result, "cancelled") == 0);
    assert(status.secret.state == LAB_SECRET_EMPTY);

    /* Repeated mixed offline/radio work must not accumulate tracked request
     * allocations, including authenticated outcomes with independent storage. */
    for (unsigned iteration = 0; iteration < 12U; ++iteration) {
        fake.success_secret = false;
        assert(janos_wps_service_start(&service, &plan, &id));
        fake.worker(fake.worker_arg);
        assert(janos_wps_service_start(&service, &transport, &id));
        fake.worker(fake.worker_arg);
        fake.success_secret = true;
        fake.storage_result = (iteration & 1U) ? "ok" : "mount_error";
        assert(janos_wps_service_start(&service, &pixie, &id));
        fake.worker(fake.worker_arg);
        assert(janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                        sizeof(key), &secret_id));
        janos_wps_memory_snapshot_t snapshot =
            janos_wps_memory_snapshot(&memory);
        assert(snapshot.bulk_bytes == 0U);
        assert(snapshot.secret_bytes == 0U);
    }

    /* Stop before the commit gate wins and cannot poison the next request. */
    atomic_store(&fake.block_execute, true);
    atomic_store(&fake.call_commit_gate, true);
    atomic_store(&fake.execute_entered, false);
    atomic_store(&fake.release_execute, false);
    atomic_store(&fake.commit_gate_done, false);
    assert(janos_wps_service_start(&service, &db, &id));
    pthread_t thread;
    assert(pthread_create(&thread, NULL, run_worker, &fake) == 0);
    while (!atomic_load(&fake.execute_entered)) {}
    assert(janos_wps_service_stop(&service));
    atomic_store(&fake.release_execute, true);
    assert(pthread_join(thread, NULL) == 0);
    assert(atomic_load(&fake.commit_gate_done));
    assert(!atomic_load(&fake.commit_gate_result));
    status = janos_wps_service_status(&service);
    assert(strcmp(status.operation_result, "cancelled") == 0);

    /* Once the commit gate wins, a late stop is rejected and success wins. */
    atomic_store(&fake.block_execute, false);
    atomic_store(&fake.release_execute, false);
    atomic_store(&fake.commit_gate_done, false);
    assert(janos_wps_service_start(&service, &db, &id));
    assert(pthread_create(&thread, NULL, run_worker, &fake) == 0);
    while (!atomic_load(&fake.commit_gate_done)) {}
    assert(atomic_load(&fake.commit_gate_result));
    assert(!janos_wps_service_stop(&service));
    atomic_store(&fake.release_execute, true);
    assert(pthread_join(thread, NULL) == 0);
    status = janos_wps_service_status(&service);
    assert(strcmp(status.operation_result, "selftest_verified") == 0);

    /* Vault erase is vault-only: it linearizes with publish but never cancels
     * the active operation.  An erase before publish permits the later secret. */
    fake.success_secret = true;
    atomic_store(&fake.call_commit_gate, false);
    atomic_store(&fake.block_execute, true);
    atomic_store(&fake.execute_entered, false);
    atomic_store(&fake.release_execute, false);
    assert(janos_wps_service_start(&service, &db, &id));
    assert(pthread_create(&thread, NULL, run_worker, &fake) == 0);
    while (!atomic_load(&fake.execute_entered)) {}
    janos_wps_service_erase_secret(&service);
    assert(!janos_wps_service_cancel_requested(&service));
    atomic_store(&fake.release_execute, true);
    assert(pthread_join(thread, NULL) == 0);
    status = janos_wps_service_status(&service);
    assert(status.secret.state == LAB_SECRET_AVAILABLE);
    assert(janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                    sizeof(key), &secret_id));
    assert(!janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                     sizeof(key), &secret_id));

    /* Status/reveal/erase may race authenticated publication, but all are
     * vault-only operations: they must remain memory-safe and must never
     * cancel or suppress the active operation.  Depending on linearization,
     * the newly published secret may be consumed or erased by the racer. */
    atomic_store(&fake.block_execute, false);
    fake.success_secret = true;
    vault_racer_t vault_race = {.service = &service, .memory = &memory};
    atomic_init(&vault_race.stop, false);
    pthread_t vault_thread;
    assert(pthread_create(&vault_thread, NULL, race_vault, &vault_race) == 0);
    for (unsigned iteration = 0; iteration < 1000U; ++iteration) {
        assert(janos_wps_service_start(&service, &db, &id));
        fake.worker(fake.worker_arg);
        status = janos_wps_service_status(&service);
        assert(status.phase == JANOS_WPS_SERVICE_IDLE);
        assert(strcmp(status.operation_result, "selftest_verified") == 0);
        assert(!janos_wps_service_cancel_requested(&service));
    }
    atomic_store(&vault_race.stop, true);
    assert(pthread_join(vault_thread, NULL) == 0);
    janos_wps_service_erase_secret(&service);

    /* Ten thousand deterministic worker/stop interleavings cover stop-wins
     * and teardown-wins for both offline and radio requests.  The teardown
     * barrier stops inside request destruction while lifecycle_lock is held,
     * proving a concurrent stop cannot dereference the released request. */
    fake.success_secret = false;
    const unsigned calls_before_race = fake.calls;
    unsigned stop_wins = 0U;
    unsigned teardown_wins = 0U;
    for (unsigned iteration = 0; iteration < 10000U; ++iteration) {
        janos_wps_command_t *active = (iteration & 1U) ? &transport : &db;
        atomic_store(&fake.execute_entered, false);
        atomic_store(&fake.release_execute, false);
        atomic_store(&fake.free_entered, false);
        atomic_store(&fake.release_free, false);
        bool stop_must_win = (iteration & 2U) == 0U;
        atomic_store(&fake.block_execute, stop_must_win);
        atomic_store(&fake.block_free, !stop_must_win);
        assert(janos_wps_service_start(&service, active, &id));
        assert(pthread_create(&thread, NULL, run_worker, &fake) == 0);
        if (stop_must_win) {
            while (!atomic_load(&fake.execute_entered)) {}
            assert(janos_wps_service_stop(&service));
            ++stop_wins;
            atomic_store(&fake.release_execute, true);
        } else {
            /* block_free was published before startup; execute_entered
             * confirms the worker observed this iteration. */
            while (!atomic_load(&fake.execute_entered)) {}
            while (!atomic_load(&fake.free_entered)) {}
            stop_racer_t stop_race = {.service = &service, .result = true};
            atomic_init(&stop_race.entered, false);
            pthread_t stop_thread;
            assert(pthread_create(&stop_thread, NULL, run_stop,
                                  &stop_race) == 0);
            while (!atomic_load(&stop_race.entered)) {}
            atomic_store(&fake.release_free, true);
            assert(pthread_join(stop_thread, NULL) == 0);
            assert(!stop_race.result);
            ++teardown_wins;
        }
        assert(pthread_join(thread, NULL) == 0);
        status = janos_wps_service_status(&service);
        assert(status.phase == JANOS_WPS_SERVICE_IDLE);
        assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
        assert(janos_wps_memory_snapshot(&memory).secret_bytes == 0U);
        assert(!janos_wps_service_cancel_requested(&service));
    }
    assert(stop_wins == 5000U);
    assert(teardown_wins == 5000U);
    assert(fake.calls == calls_before_race + 10000U);

    /* The final non-zero operation id remains usable exactly once.  Wrap to
     * zero is a permanent, fail-closed exhaustion state and must not allocate
     * or acquire the radio. */
    service.next_operation_id = UINT32_MAX;
    janos_wps_memory_snapshot_t before_exhaustion =
        janos_wps_memory_snapshot(&memory);
    assert(janos_wps_service_start(&service, &plan, &id));
    assert(id == UINT32_MAX);
    fake.worker(fake.worker_arg);
    assert(service.next_operation_id == 0U);
    assert(!janos_wps_service_start(&service, &plan, &id));
    janos_wps_memory_snapshot_t after_exhaustion =
        janos_wps_memory_snapshot(&memory);
    assert(after_exhaustion.bulk_bytes == before_exhaustion.bulk_bytes);
    assert(after_exhaustion.secret_bytes == before_exhaustion.secret_bytes);
    assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);

    puts("PASS: JanOS generalized WPS service operations");
    return 0;
}
