/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_service.h"

#include <stdio.h>
#include <string.h>

static uint64_t now_ms(janos_wps_service_t *service)
{
    return service && service->ops && service->ops->now_ms
        ? service->ops->now_ms(service->ops_context) : 0U;
}

int janos_wps_secret_unavailable_response(lab_secret_state_t state,
                                          char *output,
                                          size_t output_capacity)
{
    const char *result = state == LAB_SECRET_EMPTY ? "empty" :
                         state == LAB_SECRET_EXPIRED ? "expired" : NULL;
    if (!result || !output || output_capacity == 0U) return 1;
    int written = snprintf(output, output_capacity,
        "{\"schema_version\":1,\"record_type\":\"secret_reveal\","
        "\"result\":\"%s\"}", result);
    return written >= 0 && (size_t)written < output_capacity ? 0 : 1;
}

int janos_wps_stop_response(bool joined,
                            janos_wps_service_phase_t phase,
                            char *output,
                            size_t output_capacity)
{
    static const char *const phases[] = {
        "idle", "preparing", "running", "cleanup", "quarantined"
    };
    if (!output || output_capacity == 0U ||
        (unsigned)phase >= sizeof(phases) / sizeof(phases[0])) return 1;

    const char *result = "stop_pending";
    int command_result = 0;
    const char *phase_name = phases[phase];
    if (phase == JANOS_WPS_SERVICE_QUARANTINED) {
        result = "quarantined";
        command_result = 1;
    } else if (joined || phase == JANOS_WPS_SERVICE_IDLE) {
        result = "stopped";
        phase_name = "idle";
    }
    int written = snprintf(output, output_capacity,
        "{\"schema_version\":1,\"record_type\":\"wps_stop\","
        "\"result\":\"%s\",\"phase\":\"%s\"}", result, phase_name);
    return written >= 0 && (size_t)written < output_capacity ? command_result : 1;
}

static bool valid_bssid(const uint8_t bssid[6])
{
    uint8_t any = 0U;
    uint8_t all_ff = 0xffU;
    if (!bssid || (bssid[0] & 1U) != 0U) return false;
    for (size_t i = 0; i < 6U; ++i) {
        any |= bssid[i];
        all_ff &= bssid[i];
    }
    return any != 0U && all_ff != 0xffU;
}

static bool valid_pin(const char *pin)
{
    if (!pin || strlen(pin) != 8U) return false;
    unsigned sum = 0U;
    for (size_t i = 0; i < 8U; ++i) {
        if (pin[i] < '0' || pin[i] > '9') return false;
        if (i < 7U)
            sum += (unsigned)(pin[i] - '0') * ((i & 1U) == 0U ? 3U : 1U);
    }
    return (10U - sum % 10U) % 10U == (unsigned)(pin[7] - '0');
}

static void set_result(janos_wps_service_t *service, const char *operation,
                       const char *cleanup)
{
    if (!service) return;
    (void)snprintf(service->operation_result,
                   sizeof(service->operation_result), "%s",
                   operation ? operation : "internal_failure");
    (void)snprintf(service->cleanup_result,
                   sizeof(service->cleanup_result), "%s",
                   cleanup ? cleanup : "not_required");
}

void janos_wps_service_init(janos_wps_service_t *service,
                            janos_radio_lease_t *lease,
                            janos_wps_memory_t *memory,
                            const janos_wps_service_ops_t *ops,
                            void *ops_context)
{
    if (!service) return;
    memset(service, 0, sizeof(*service));
    service->lease = lease;
    service->memory = memory;
    service->ops = ops;
    service->ops_context = ops_context;
    service->next_operation_id = 1U;
    atomic_init(&service->phase, JANOS_WPS_SERVICE_IDLE);
    lab_secret_init(&service->secret, janos_wps_secure_wipe);
    set_result(service, "none", "not_required");
}

bool janos_wps_service_start_verify(janos_wps_service_t *service,
                                    const uint8_t bssid[6], const char *pin,
                                    uint32_t *operation_id_out)
{
    if (!service || !service->lease || !service->memory || !service->ops ||
        !service->ops->start_worker || !service->ops->execute_verify ||
        !valid_bssid(bssid) || !valid_pin(pin) ||
        atomic_load_explicit(&service->phase, memory_order_acquire) !=
            JANOS_WPS_SERVICE_IDLE || service->request != NULL ||
        service->next_operation_id == 0U) return false;
    const char *reason = NULL;
    if (service->ops->admit && !service->ops->admit(service->ops_context, &reason))
        return false;

    uint32_t generation = 0U;
    if (janos_radio_lease_acquire(service->lease, JANOS_RADIO_OWNER_WPS,
                                  &generation) != JANOS_RADIO_LEASE_OK)
        return false;
    janos_wps_verify_request_t *request = janos_wps_alloc_secret(
        service->memory, sizeof(*request));
    if (!request) {
        (void)janos_radio_lease_begin_cleanup(service->lease,
                                               JANOS_RADIO_OWNER_WPS,
                                               generation);
        (void)janos_radio_lease_finish_cleanup(service->lease,
                                                JANOS_RADIO_OWNER_WPS,
                                                generation, true);
        return false;
    }
    memset(request, 0, sizeof(*request));
    memcpy(request->bssid, bssid, 6U);
    memcpy(request->pin, pin, 8U);
    request->operation_id = service->next_operation_id++;
    request->generation = generation;
    service->request = request;
    service->operation_id = request->operation_id;
    service->generation = generation;
    set_result(service, "running", "pending");
    atomic_store_explicit(&service->phase, JANOS_WPS_SERVICE_PREPARING,
                          memory_order_release);
    if (!service->ops->start_worker(service->ops_context,
                                    janos_wps_service_run_pending, service)) {
        atomic_store_explicit(&service->phase, JANOS_WPS_SERVICE_CLEANUP,
                              memory_order_release);
        (void)janos_radio_lease_begin_cleanup(service->lease,
                                               JANOS_RADIO_OWNER_WPS,
                                               generation);
        bool restored = janos_radio_lease_finish_cleanup(
            service->lease, JANOS_RADIO_OWNER_WPS, generation, true);
        janos_wps_free_secret(service->memory, request);
        service->request = NULL;
        set_result(service, "worker_start_failed",
                   restored ? "restored" : "failed");
        atomic_store_explicit(&service->phase,
                              restored ? JANOS_WPS_SERVICE_IDLE :
                                         JANOS_WPS_SERVICE_QUARANTINED,
                              memory_order_release);
        return false;
    }
    if (operation_id_out) *operation_id_out = request->operation_id;
    return true;
}

void janos_wps_service_run_pending(void *argument)
{
    janos_wps_service_t *service = argument;
    if (!service || !service->request) return;
    janos_wps_verify_request_t *request = service->request;
    janos_wps_verify_outcome_t outcome;
    memset(&outcome, 0, sizeof(outcome));
    outcome.operation_result = "internal_failure";
    /* Cancelling before the adapter is entered has nothing to restore. */
    outcome.cleanup_ok = true;

    bool running = janos_radio_lease_mark_running(
        service->lease, JANOS_RADIO_OWNER_WPS, request->generation);
    if (running)
        atomic_store_explicit(&service->phase, JANOS_WPS_SERVICE_RUNNING,
                              memory_order_release);
    bool cancelled = !running || janos_radio_lease_cancel_requested(
        service->lease, JANOS_RADIO_OWNER_WPS, request->generation);
    bool executed = false;
    if (!cancelled)
        executed = service->ops->execute_verify(service->ops_context,
                                                 request, &outcome);
    cancelled = cancelled || janos_radio_lease_cancel_requested(
        service->lease, JANOS_RADIO_OWNER_WPS, request->generation);
    atomic_store_explicit(&service->phase, JANOS_WPS_SERVICE_CLEANUP,
                          memory_order_release);
    bool cleanup_started = janos_radio_lease_begin_cleanup(
        service->lease, JANOS_RADIO_OWNER_WPS, request->generation);
    bool cleanup_ok = cleanup_started && outcome.cleanup_ok;
    bool released = cleanup_started && janos_radio_lease_finish_cleanup(
        service->lease, JANOS_RADIO_OWNER_WPS, request->generation, cleanup_ok);

    if (cancelled) {
        lab_secret_erase(&service->secret);
        set_result(service, "cancelled", released ? "restored" : "failed");
    } else if (executed && outcome.authenticated_m7 && cleanup_ok && released &&
               lab_secret_store(&service->secret, outcome.pin,
                                outcome.network_key, request->operation_id,
                                now_ms(service))) {
        set_result(service, outcome.operation_result ? outcome.operation_result :
                                                   "success",
                   "restored");
    } else {
        lab_secret_erase(&service->secret);
        set_result(service,
                   executed && outcome.operation_result ? outcome.operation_result :
                                                          "internal_failure",
                   released ? "restored" : "failed");
    }
    janos_wps_secure_wipe(&outcome, sizeof(outcome));
    janos_wps_free_secret(service->memory, request);
    service->request = NULL;
    atomic_store_explicit(&service->phase,
                          released ? JANOS_WPS_SERVICE_IDLE :
                                     JANOS_WPS_SERVICE_QUARANTINED,
                          memory_order_release);
}

bool janos_wps_service_stop(janos_wps_service_t *service)
{
    if (!service || !service->request) return false;
    return janos_radio_lease_request_cancel(service->lease,
                                             JANOS_RADIO_OWNER_WPS,
                                             service->generation);
}

janos_wps_service_status_t janos_wps_service_status(
    janos_wps_service_t *service)
{
    janos_wps_service_status_t status = {0};
    if (!service) return status;
    status.phase = (janos_wps_service_phase_t)atomic_load_explicit(
        &service->phase, memory_order_acquire);
    status.operation_id = service->operation_id;
    status.generation = service->generation;
    status.operation_result = service->operation_result;
    status.cleanup_result = service->cleanup_result;
    status.lease = janos_radio_lease_snapshot(service->lease);
    status.secret = lab_secret_status(&service->secret, now_ms(service));
    return status;
}

bool janos_wps_service_reveal(janos_wps_service_t *service,
                              char *pin, size_t pin_capacity,
                              char *network_key, size_t key_capacity,
                              uint32_t *operation_id)
{
    return service && lab_secret_take(&service->secret, now_ms(service), pin,
                                       pin_capacity, network_key, key_capacity,
                                       operation_id);
}

void janos_wps_service_erase_secret(janos_wps_service_t *service)
{
    if (service) lab_secret_erase(&service->secret);
}

