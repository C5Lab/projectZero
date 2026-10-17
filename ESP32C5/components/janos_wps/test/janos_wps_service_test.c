/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_service.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint64_t now;
    bool admitted;
    bool worker_ok;
    bool execute_ok;
    bool cleanup_ok;
    janos_wps_worker_fn worker;
    void *worker_arg;
} fake_t;

static void *alloc_fn(void *ctx, size_t size, uint32_t caps)
{ (void)ctx; (void)caps; return malloc(size); }
static void free_fn(void *ctx, void *p, size_t size,
                    janos_wps_memory_class_t memory_class)
{ (void)ctx; (void)size; (void)memory_class; free(p); }
static uint64_t now_fn(void *ctx) { return ((fake_t *)ctx)->now; }
static bool admit_fn(void *ctx, const char **reason)
{ (void)reason; return ((fake_t *)ctx)->admitted; }
static bool worker_fn(void *ctx, janos_wps_worker_fn worker, void *arg)
{
    fake_t *fake = ctx;
    fake->worker = worker;
    fake->worker_arg = arg;
    return fake->worker_ok;
}
static bool execute_fn(void *ctx, const janos_wps_verify_request_t *request,
                       janos_wps_verify_outcome_t *outcome)
{
    fake_t *fake = ctx;
    assert(strcmp(request->pin, "60980465") == 0);
    memset(outcome, 0, sizeof(*outcome));
    outcome->cleanup_ok = fake->cleanup_ok;
    if (!fake->execute_ok) {
        outcome->operation_result = "timeout";
        return true;
    }
    outcome->authenticated_m7 = true;
    outcome->operation_result = "success";
    memcpy(outcome->pin, "60980465", 9);
    memcpy(outcome->network_key, "Sara1980", 9);
    return true;
}

int main(void)
{
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
    assert(janos_wps_service_start_verify(&service, bssid, "60980465",
                                           &operation));
    assert(operation == 1 && fake.worker != NULL);
    assert(!janos_wps_service_start_verify(&service, bssid, "60980465", NULL));
    fake.worker(fake.worker_arg);
    janos_wps_service_status_t status = janos_wps_service_status(&service);
    assert(status.phase == JANOS_WPS_SERVICE_IDLE);
    assert(strcmp(status.operation_result, "success") == 0);
    assert(status.secret.state == LAB_SECRET_AVAILABLE);
    char pin[9] = {0}, key[65] = {0};
    uint32_t source_operation = 0;
    assert(janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                    sizeof(key), &source_operation));
    assert(strcmp(pin, "60980465") == 0 && strcmp(key, "Sara1980") == 0);
    assert(source_operation == operation);
    assert(!janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                     sizeof(key), NULL));
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

    assert(janos_wps_service_start_verify(&service, bssid, "60980465", NULL));
    fake.worker(fake.worker_arg);
    fake.now += 300001U;
    status = janos_wps_service_status(&service);
    assert(status.secret.state == LAB_SECRET_EXPIRED);
    assert(!janos_wps_service_reveal(&service, pin, sizeof(pin), key,
                                     sizeof(key), NULL));
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
    assert(!janos_wps_service_start_verify(&service, bssid, "60980465", NULL));
    assert(janos_radio_lease_snapshot(&lease).state == JANOS_RADIO_LEASE_IDLE);

    fake.worker_ok = true;
    fake.execute_ok = false;
    assert(janos_wps_service_start_verify(&service, bssid, "60980465", NULL));
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
        assert(janos_wps_service_start_verify(&service, bssid, "60980465", NULL));
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
    assert(janos_wps_service_start_verify(&service, bssid, "60980465", NULL));
    fake.worker(fake.worker_arg);
    status = janos_wps_service_status(&service);
    assert(status.phase == JANOS_WPS_SERVICE_QUARANTINED);
    assert(janos_radio_lease_snapshot(&lease).state ==
           JANOS_RADIO_LEASE_QUARANTINED);

    puts("PASS: JanOS asynchronous known-PIN service");
    return 0;
}
