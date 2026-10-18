/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_service.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SYNTHETIC_TEST_PIN "31415927"
#define SYNTHETIC_TEST_NETWORK_KEY "synthetic-test-key"

typedef struct {
    uint64_t now;
    bool admitted;
    bool worker_ok;
    bool execute_ok;
    bool cleanup_ok;
    bool worker_immediate;
    bool cancel_before_worker;
    bool execute_returns_false;
    bool fail_alloc;
    bool retain_freed_request;
    void *retained_allocation;
    janos_wps_worker_fn worker;
    void *worker_arg;
} fake_t;

static void *alloc_fn(void *ctx, size_t size, uint32_t caps)
{
    (void)caps;
    fake_t *fake = ctx;
    return fake && fake->fail_alloc ? NULL : malloc(size);
}
static void free_fn(void *ctx, void *p, size_t size,
                    janos_wps_memory_class_t memory_class)
{
    fake_t *fake = ctx;
    if (fake && fake->retain_freed_request) {
        assert(memory_class == JANOS_WPS_MEMORY_SECRET);
        assert(fake->retained_allocation == NULL);
        /* Keep the storage valid, but make any post-release read observable. */
        memset(p, 0xa5, size);
        fake->retained_allocation = p;
    } else {
        free(p);
    }
}
static uint64_t now_fn(void *ctx) { return ((fake_t *)ctx)->now; }
static bool admit_fn(void *ctx, const char **reason)
{ (void)reason; return ((fake_t *)ctx)->admitted; }
static bool worker_fn(void *ctx, janos_wps_worker_fn worker, void *arg)
{
    fake_t *fake = ctx;
    fake->worker = worker;
    fake->worker_arg = arg;
    if (!fake->worker_ok) return false;
    if (fake->worker_immediate) {
        if (fake->cancel_before_worker)
            assert(janos_wps_service_stop(arg));
        worker(arg);
    }
    return true;
}
static bool execute_fn(void *ctx, const janos_wps_verify_request_t *request,
                       janos_wps_verify_outcome_t *outcome)
{
    fake_t *fake = ctx;
    assert(strcmp(request->pin, SYNTHETIC_TEST_PIN) == 0);
    memset(outcome, 0, sizeof(*outcome));
    outcome->cleanup_ok = fake->cleanup_ok;
    if (fake->execute_returns_false) return false;
    if (!fake->execute_ok) {
        outcome->operation_result = "timeout";
        return true;
    }
    outcome->authenticated_m7 = true;
    outcome->operation_result = "success";
    memcpy(outcome->pin, SYNTHETIC_TEST_PIN, sizeof(SYNTHETIC_TEST_PIN));
    memcpy(outcome->network_key, SYNTHETIC_TEST_NETWORK_KEY,
           sizeof(SYNTHETIC_TEST_NETWORK_KEY));
    return true;
}

static void test_immediate_worker(bool retain_freed_request)
{
    /* Returning request->operation_id after start_worker() must fail these
     * cases: the callback has already released and wiped that request. */
    static const struct {
        bool execute_ok;
        bool cleanup_ok;
        bool cancel;
        bool execute_returns_false;
        bool null_output;
        janos_wps_service_phase_t phase;
        const char *result;
        lab_secret_state_t secret;
    } cases[] = {
        {true, true, false, false, false, JANOS_WPS_SERVICE_IDLE,
         "success", LAB_SECRET_AVAILABLE},
        {false, true, false, false, false, JANOS_WPS_SERVICE_IDLE,
         "timeout", LAB_SECRET_EMPTY},
        {true, true, false, true, false, JANOS_WPS_SERVICE_IDLE,
         "internal_failure", LAB_SECRET_EMPTY},
        {true, true, true, false, false, JANOS_WPS_SERVICE_IDLE,
         "cancelled", LAB_SECRET_EMPTY},
        {true, false, false, false, false, JANOS_WPS_SERVICE_QUARANTINED,
         "success", LAB_SECRET_EMPTY},
        {true, true, false, false, true, JANOS_WPS_SERVICE_IDLE,
         "success", LAB_SECRET_AVAILABLE},
    };
    const uint8_t bssid[6] = {0x68,0xff,0x7b,0xcd,0xfc,0x40};
    const janos_wps_memory_ops_t memory_ops = {alloc_fn, free_fn};
    const janos_wps_service_ops_t ops = {
        .now_ms = now_fn, .admit = admit_fn, .start_worker = worker_fn,
        .execute_verify = execute_fn,
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        fake_t fake = {.now = 1000, .admitted = true, .worker_ok = true,
                       .execute_ok = cases[i].execute_ok,
                       .cleanup_ok = cases[i].cleanup_ok,
                       .worker_immediate = true,
                       .cancel_before_worker = cases[i].cancel,
                       .execute_returns_false = cases[i].execute_returns_false,
                       .retain_freed_request = retain_freed_request};
        janos_wps_memory_t memory;
        janos_wps_memory_init(&memory, &memory_ops, &fake);
        janos_radio_lease_t lease;
        janos_radio_lease_init(&lease);
        janos_wps_service_t service;
        janos_wps_service_init(&service, &lease, &memory, &ops, &fake);
        uint32_t operation = UINT32_C(0xdeadbeef);
        assert(janos_wps_service_start_verify(
            &service, bssid, SYNTHETIC_TEST_PIN,
            cases[i].null_output ? NULL : &operation));
        if (!cases[i].null_output) assert(operation == 1U);
        else assert(operation == UINT32_C(0xdeadbeef));
        janos_wps_service_status_t status = janos_wps_service_status(&service);
        assert(status.operation_id == 1U);
        assert(status.phase == cases[i].phase);
        assert(strcmp(status.operation_result, cases[i].result) == 0);
        assert(status.secret.state == cases[i].secret);
        assert(strcmp(status.cleanup_result,
                      cases[i].cleanup_ok ? "restored" : "failed") == 0);
        assert(status.lease.state == (cases[i].cleanup_ok ?
               JANOS_RADIO_LEASE_IDLE : JANOS_RADIO_LEASE_QUARANTINED));
        assert(service.request == NULL);
        assert(janos_wps_memory_snapshot(&memory).secret_bytes == 0U);
        if (cases[i].secret == LAB_SECRET_AVAILABLE) {
            char pin[9] = {0}, key[65] = {0};
            uint32_t source_operation = 0U;
            assert(janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                            sizeof(key), &source_operation));
            assert(source_operation == 1U);
        }
        janos_wps_service_erase_secret(&service);
        free(fake.retained_allocation);
    }

    fake_t fake = {.now = 1000, .admitted = true, .worker_ok = false,
                   .worker_immediate = true,
                   .retain_freed_request = retain_freed_request};
    janos_wps_memory_t memory;
    janos_wps_memory_init(&memory, &memory_ops, &fake);
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    janos_wps_service_t service;
    janos_wps_service_init(&service, &lease, &memory, &ops, &fake);
    uint32_t operation = UINT32_C(0xdeadbeef);
    assert(!janos_wps_service_start_verify(
        &service, bssid, SYNTHETIC_TEST_PIN, &operation));
    assert(operation == UINT32_C(0xdeadbeef));
    janos_wps_service_status_t status = janos_wps_service_status(&service);
    assert(status.phase == JANOS_WPS_SERVICE_IDLE);
    assert(status.lease.state == JANOS_RADIO_LEASE_IDLE);
    assert(strcmp(status.operation_result, "worker_start_failed") == 0);
    assert(strcmp(status.cleanup_result, "restored") == 0);
    assert(service.request == NULL);
    assert(janos_wps_memory_snapshot(&memory).secret_bytes == 0U);
    free(fake.retained_allocation);
}

typedef enum {
    REJECT_LEASE_BUSY,
    REJECT_ADMISSION,
    REJECT_ALLOCATION,
    REJECT_WORKER_START,
    ACCEPT_NEW_REQUEST,
} replacement_case_t;

static void test_rejected_start_preserves_existing_secret(
    replacement_case_t replacement_case)
{
    const uint8_t bssid[6] = {0x68,0xff,0x7b,0xcd,0xfc,0x40};
    fake_t fake = {.now = 1000, .admitted = true, .worker_ok = true,
                   .execute_ok = true, .cleanup_ok = true,
                   .worker_immediate = true};
    const janos_wps_memory_ops_t memory_ops = {alloc_fn, free_fn};
    janos_wps_memory_t memory;
    janos_wps_memory_init(&memory, &memory_ops, &fake);
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    const janos_wps_service_ops_t ops = {
        .now_ms = now_fn, .admit = admit_fn, .start_worker = worker_fn,
        .execute_verify = execute_fn,
    };
    janos_wps_service_t service;
    janos_wps_service_init(&service, &lease, &memory, &ops, &fake);

    assert(janos_wps_service_start_verify(
        &service, bssid, SYNTHETIC_TEST_PIN, NULL));
    assert(janos_wps_service_status(&service).secret.state ==
           LAB_SECRET_AVAILABLE);

    fake.worker_immediate = false;
    uint32_t other_generation = 0U;
    if (replacement_case == REJECT_LEASE_BUSY) {
        assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_ANALYZER,
                                        &other_generation) ==
               JANOS_RADIO_LEASE_OK);
    } else if (replacement_case == REJECT_ADMISSION) {
        fake.admitted = false;
    } else if (replacement_case == REJECT_ALLOCATION) {
        fake.fail_alloc = true;
    } else if (replacement_case == REJECT_WORKER_START) {
        fake.worker_ok = false;
    }

    bool started = janos_wps_service_start_verify(
        &service, bssid, SYNTHETIC_TEST_PIN, NULL);
    if (replacement_case == ACCEPT_NEW_REQUEST) {
        assert(started);
        assert(janos_wps_service_status(&service).secret.state ==
               LAB_SECRET_EMPTY);
        assert(janos_wps_service_stop(&service));
        fake.worker(fake.worker_arg);
    } else {
        assert(!started);
        assert(janos_wps_service_status(&service).secret.state ==
               LAB_SECRET_AVAILABLE);
        char pin[9] = {0}, key[65] = {0};
        uint32_t source_operation = 0U;
        assert(janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                        sizeof(key), &source_operation));
        assert(source_operation == 1U);
        assert(strcmp(pin, SYNTHETIC_TEST_PIN) == 0);
        assert(strcmp(key, SYNTHETIC_TEST_NETWORK_KEY) == 0);
    }

    if (replacement_case == REJECT_LEASE_BUSY) {
        assert(janos_radio_lease_begin_cleanup(
            &lease, JANOS_RADIO_OWNER_ANALYZER, other_generation));
        assert(janos_radio_lease_finish_cleanup(
            &lease, JANOS_RADIO_OWNER_ANALYZER, other_generation, true));
    }
    janos_wps_service_erase_secret(&service);
}

int main(int argc, char **argv)
{
    /* The dedicated real-free entry lets sanitizers diagnose the original UAF
     * before the deterministic poison assertion terminates the ordinary test. */
    if (argc == 2 && strcmp(argv[1], "--immediate-real-free") == 0) {
        test_immediate_worker(false);
        puts("PASS: JanOS immediate known-PIN service (real free)");
        return 0;
    }
    test_immediate_worker(true);
    test_immediate_worker(false);
    test_rejected_start_preserves_existing_secret(REJECT_LEASE_BUSY);
    test_rejected_start_preserves_existing_secret(REJECT_ADMISSION);
    test_rejected_start_preserves_existing_secret(REJECT_ALLOCATION);
    test_rejected_start_preserves_existing_secret(REJECT_WORKER_START);
    test_rejected_start_preserves_existing_secret(ACCEPT_NEW_REQUEST);
    fake_t fake = {.now = 1000, .admitted = true, .worker_ok = true,
                   .execute_ok = true, .cleanup_ok = true};
    const janos_wps_memory_ops_t memory_ops = {alloc_fn, free_fn};
    janos_wps_memory_t memory;
    janos_wps_memory_init(&memory, &memory_ops, NULL);
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    const janos_wps_service_ops_t ops = {
        .now_ms = now_fn, .admit = admit_fn, .start_worker = worker_fn,
        .execute_verify = execute_fn,
    };
    janos_wps_service_t service;
    janos_wps_service_init(&service, &lease, &memory, &ops, &fake);
    const uint8_t bssid[6] = {0x68,0xff,0x7b,0xcd,0xfc,0x40};

    uint32_t operation = 0;
    assert(!janos_wps_service_start_verify(&service, bssid, "12345678",
                                            &operation));
    assert(janos_wps_service_start_verify(&service, bssid, SYNTHETIC_TEST_PIN,
                                           &operation));
    assert(operation == 1 && fake.worker != NULL);
    assert(!janos_wps_service_start_verify(
        &service, bssid, SYNTHETIC_TEST_PIN, NULL));
    fake.worker(fake.worker_arg);
    janos_wps_service_status_t status = janos_wps_service_status(&service);
    assert(status.phase == JANOS_WPS_SERVICE_IDLE);
    assert(strcmp(status.operation_result, "success") == 0);
    assert(status.secret.state == LAB_SECRET_AVAILABLE);
    char pin[9] = {0}, key[65] = {0};
    uint32_t source_operation = 0;
    assert(janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                    sizeof(key), &source_operation));
    assert(strcmp(pin, SYNTHETIC_TEST_PIN) == 0 &&
           strcmp(key, SYNTHETIC_TEST_NETWORK_KEY) == 0);
    assert(source_operation == operation);
    assert(!janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                     sizeof(key), NULL));
    lab_secret_state_t unavailable_state = LAB_SECRET_AVAILABLE;
    assert(!janos_wps_service_reveal_with_state(
        &service, pin, sizeof(pin), key, sizeof(key), NULL,
        &unavailable_state));
    assert(unavailable_state == LAB_SECRET_EMPTY);
    char reveal_response[128] = {0};
    assert(janos_wps_secret_unavailable_response(
               LAB_SECRET_EMPTY, reveal_response,
               sizeof(reveal_response)) == 0);
    assert(strcmp(reveal_response,
                  "{\"schema_version\":1,\"record_type\":\"secret_reveal\","
                  "\"result\":\"empty\"}") == 0);

    /* A stale completion after the request was released must be harmless. */
    fake.worker(fake.worker_arg);
    assert(janos_wps_service_status(&service).phase == JANOS_WPS_SERVICE_IDLE);

    assert(janos_wps_service_start_verify(
        &service, bssid, SYNTHETIC_TEST_PIN, NULL));
    fake.worker(fake.worker_arg);
    fake.now += 300001U;
    unavailable_state = LAB_SECRET_AVAILABLE;
    assert(!janos_wps_service_reveal_with_state(
        &service, pin, sizeof(pin), key, sizeof(key), NULL,
        &unavailable_state));
    assert(unavailable_state == LAB_SECRET_EXPIRED);
    memset(reveal_response, 0, sizeof(reveal_response));
    assert(janos_wps_secret_unavailable_response(
               LAB_SECRET_EXPIRED, reveal_response,
               sizeof(reveal_response)) == 0);
    assert(strcmp(reveal_response,
                  "{\"schema_version\":1,\"record_type\":\"secret_reveal\","
                  "\"result\":\"expired\"}") == 0);
    assert(janos_wps_secret_unavailable_response(
               LAB_SECRET_AVAILABLE, reveal_response,
               sizeof(reveal_response)) != 0);

    char stop_response[160] = {0};
    assert(janos_wps_stop_response(
               true, JANOS_WPS_SERVICE_IDLE, stop_response,
               sizeof(stop_response)) == 0);
    assert(strcmp(stop_response,
                  "{\"schema_version\":1,\"record_type\":\"wps_stop\","
                  "\"result\":\"stopped\",\"phase\":\"idle\"}") == 0);
    memset(stop_response, 0, sizeof(stop_response));
    assert(janos_wps_stop_response(
               false, JANOS_WPS_SERVICE_CLEANUP, stop_response,
               sizeof(stop_response)) == 0);
    assert(strcmp(stop_response,
                  "{\"schema_version\":1,\"record_type\":\"wps_stop\","
                  "\"result\":\"stop_pending\",\"phase\":\"cleanup\"}") == 0);
    memset(stop_response, 0, sizeof(stop_response));
    assert(janos_wps_stop_response(
               false, JANOS_WPS_SERVICE_QUARANTINED, stop_response,
               sizeof(stop_response)) != 0);
    assert(strcmp(stop_response,
                  "{\"schema_version\":1,\"record_type\":\"wps_stop\","
                  "\"result\":\"quarantined\",\"phase\":\"quarantined\"}") == 0);

    fake.worker_ok = false;
    assert(!janos_wps_service_start_verify(
        &service, bssid, SYNTHETIC_TEST_PIN, NULL));
    assert(janos_radio_lease_snapshot(&lease).state == JANOS_RADIO_LEASE_IDLE);

    fake.worker_ok = true;
    fake.execute_ok = false;
    assert(janos_wps_service_start_verify(
        &service, bssid, SYNTHETIC_TEST_PIN, NULL));
    assert(janos_wps_service_stop(&service));
    fake.worker(fake.worker_arg);
    status = janos_wps_service_status(&service);
    assert(strcmp(status.operation_result, "cancelled") == 0);
    assert(status.secret.state == LAB_SECRET_EMPTY);

    /* Deterministic lifecycle stress: success, protocol failure and cooperative
     * cancellation all have to return the same lease and allocation baseline. */
    for (unsigned i = 0; i < 1000U; ++i) {
        fake.execute_ok = (i % 3U) != 1U;
        fake.cleanup_ok = true;
        assert(janos_wps_service_start_verify(
            &service, bssid, SYNTHETIC_TEST_PIN, NULL));
        if ((i % 3U) == 2U) assert(janos_wps_service_stop(&service));
        fake.worker(fake.worker_arg);
        status = janos_wps_service_status(&service);
        assert(status.phase == JANOS_WPS_SERVICE_IDLE);
        assert(status.lease.state == JANOS_RADIO_LEASE_IDLE);
        janos_wps_memory_snapshot_t memory_status =
            janos_wps_memory_snapshot(&memory);
        assert(memory_status.bulk_bytes == 0U);
        assert(memory_status.secret_bytes == 0U);
        if (status.secret.state == LAB_SECRET_AVAILABLE) {
            uint32_t revealed_operation = 0U;
            assert(janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                            sizeof(key), &revealed_operation));
            assert(revealed_operation != 0U);
        }
        janos_wps_service_erase_secret(&service);
    }

    fake.execute_ok = true;
    fake.cleanup_ok = false;
    assert(janos_wps_service_start_verify(
        &service, bssid, SYNTHETIC_TEST_PIN, NULL));
    fake.worker(fake.worker_arg);
    status = janos_wps_service_status(&service);
    assert(status.phase == JANOS_WPS_SERVICE_QUARANTINED);
    assert(janos_radio_lease_snapshot(&lease).state ==
           JANOS_RADIO_LEASE_QUARANTINED);

    puts("PASS: JanOS asynchronous known-PIN service");
    return 0;
}
