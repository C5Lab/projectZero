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

static void lifecycle_lock(janos_wps_service_t *service)
{
#ifdef ESP_PLATFORM
    (void)xSemaphoreTake(service->lifecycle_lock, portMAX_DELAY);
#else
    while (atomic_flag_test_and_set_explicit(&service->lifecycle_lock,
                                              memory_order_acquire)) {}
#endif
}

static void lifecycle_unlock(janos_wps_service_t *service)
{
#ifdef ESP_PLATFORM
    (void)xSemaphoreGive(service->lifecycle_lock);
#else
    atomic_flag_clear_explicit(&service->lifecycle_lock, memory_order_release);
#endif
}

static void vault_lock(janos_wps_service_t *service)
{
#ifdef ESP_PLATFORM
    (void)xSemaphoreTake(service->vault_lock, portMAX_DELAY);
#else
    while (atomic_flag_test_and_set_explicit(&service->vault_lock,
                                              memory_order_acquire)) {}
#endif
}

static void vault_unlock(janos_wps_service_t *service)
{
#ifdef ESP_PLATFORM
    (void)xSemaphoreGive(service->vault_lock);
#else
    atomic_flag_clear_explicit(&service->vault_lock, memory_order_release);
#endif
}

static bool vault_store(janos_wps_service_t *service, const char *pin,
                        const char *network_key, uint32_t operation_id)
{
    vault_lock(service);
    bool stored = lab_secret_store(&service->secret, pin, network_key,
                                   operation_id, now_ms(service));
    vault_unlock(service);
    return stored;
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

static bool valid_ssid(const char ssid[33])
{
    const char *end = memchr(ssid, '\0', 33U);
    if (!end) return false;
    for (const unsigned char *p = (const unsigned char *)ssid;
         p < (const unsigned char *)end; ++p)
        if (*p < 0x20U || *p == 0x7fU) return false;
    return true;
}

static bool valid_command(const janos_wps_command_t *command)
{
    if (!command) return false;
    switch (command->operation) {
    case JANOS_WPS_OP_VERIFY:
        return valid_bssid(command->bssid) && valid_pin(command->pin);
    case JANOS_WPS_OP_PIXIE:
        return valid_bssid(command->bssid);
    case JANOS_WPS_OP_JWPS_PLAN:
        return valid_bssid(command->bssid) && valid_ssid(command->ssid);
    case JANOS_WPS_OP_JWPS_CAMPAIGN:
        return valid_bssid(command->bssid) && command->count >= 1U &&
               command->count <= 3U && valid_ssid(command->ssid);
    case JANOS_WPS_OP_SELFTEST_DB:
    case JANOS_WPS_OP_SELFTEST_FRAGMENT:
    case JANOS_WPS_OP_SELFTEST_TRANSPORT:
    case JANOS_WPS_OP_SELFTEST_PIXIE:
        return true;
    default:
        return false;
    }
}

static void set_result_locked(janos_wps_service_t *service,
                              const char *operation,
                              const char *cleanup, const char *storage)
{
    if (!service) return;
    (void)snprintf(service->operation_result,
                   sizeof(service->operation_result), "%s",
                   operation ? operation : "internal_failure");
    (void)snprintf(service->cleanup_result,
                   sizeof(service->cleanup_result), "%s",
                   cleanup ? cleanup : "not_required");
    (void)snprintf(service->storage_result,
                   sizeof(service->storage_result), "%s",
                   storage ? storage : "not_required");
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
    atomic_init(&service->cancel_requested, false);
#ifdef ESP_PLATFORM
    service->lifecycle_lock = xSemaphoreCreateMutexStatic(
        &service->lifecycle_lock_storage);
    service->vault_lock = xSemaphoreCreateMutexStatic(
        &service->vault_lock_storage);
#else
    atomic_flag_clear(&service->lifecycle_lock);
    atomic_flag_clear(&service->vault_lock);
#endif
    lab_secret_init(&service->secret, janos_wps_secure_wipe);
    set_result_locked(service, "none", "not_required", "not_required");
}

bool janos_wps_service_start(janos_wps_service_t *service,
                             const janos_wps_command_t *command,
                             uint32_t *operation_id_out)
{
    if (!service || !service->lease || !service->memory || !service->ops ||
        !service->ops->start_worker ||
        (!service->ops->execute_operation && !service->ops->execute_verify) ||
        !valid_command(command)) return false;

    lifecycle_lock(service);
    if (service->active || service->request != NULL ||
        atomic_load_explicit(&service->phase, memory_order_relaxed) !=
            JANOS_WPS_SERVICE_IDLE || service->next_operation_id == 0U) {
        lifecycle_unlock(service);
        return false;
    }
    bool requires_radio = janos_wps_operation_requires_radio(command->operation);
    uint32_t generation = 0U;
    if (requires_radio &&
        janos_radio_lease_acquire(service->lease, JANOS_RADIO_OWNER_WPS,
                                  &generation) != JANOS_RADIO_LEASE_OK) {
        lifecycle_unlock(service);
        return false;
    }
    /* The shared reservation excludes legacy startup throughout baseline
     * admission. No coordinator lock is held during driver/state probes. */
    const char *reason = NULL;
    if (requires_radio && service->ops->admit &&
        !service->ops->admit(service->ops_context, &reason)) {
        if (janos_radio_lease_begin_cleanup(service->lease,
                                           JANOS_RADIO_OWNER_WPS, generation))
            (void)janos_radio_lease_finish_cleanup(service->lease,
                JANOS_RADIO_OWNER_WPS, generation, true);
        lifecycle_unlock(service);
        return false;
    }
    janos_wps_request_t *request = janos_wps_alloc_secret(
        service->memory, sizeof(*request));
    if (!request) {
        if (requires_radio) {
            (void)janos_radio_lease_begin_cleanup(service->lease,
                                                   JANOS_RADIO_OWNER_WPS,
                                                   generation);
            (void)janos_radio_lease_finish_cleanup(service->lease,
                                                    JANOS_RADIO_OWNER_WPS,
                                                    generation, true);
        }
        lifecycle_unlock(service);
        return false;
    }
    memset(request, 0, sizeof(*request));
    request->command = *command;
    memcpy(request->bssid, command->bssid, sizeof(request->bssid));
    memcpy(request->pin, command->pin, sizeof(request->pin));
    request->operation_id = service->next_operation_id++;
    request->generation = generation;
    request->requires_radio = requires_radio;
    const uint32_t accepted_operation_id = request->operation_id;
    service->request = request;
    service->active = true;
    service->active_operation_id = request->operation_id;
    service->active_generation = generation;
    service->active_requires_radio = requires_radio;
    service->commit_closed = false;
    service->operation_id = request->operation_id;
    service->generation = generation;
    set_result_locked(service, "running",
                      requires_radio ? "pending" : "not_required",
                      "not_required");
    atomic_store_explicit(&service->cancel_requested, false,
                          memory_order_release);
    atomic_store_explicit(&service->phase, JANOS_WPS_SERVICE_PREPARING,
                          memory_order_release);
    lifecycle_unlock(service);

    if (!service->ops->start_worker(service->ops_context,
                                    janos_wps_service_run_pending, service)) {
        lifecycle_lock(service);
        if (!service->active || service->active_operation_id !=
                accepted_operation_id || service->request != request) {
            lifecycle_unlock(service);
            return false;
        }
        atomic_store_explicit(&service->phase, JANOS_WPS_SERVICE_CLEANUP,
                              memory_order_release);
        service->commit_closed = true;
        bool restored = true;
        if (requires_radio) {
            (void)janos_radio_lease_begin_cleanup(service->lease,
                                                   JANOS_RADIO_OWNER_WPS,
                                                   generation);
            restored = janos_radio_lease_finish_cleanup(
                service->lease, JANOS_RADIO_OWNER_WPS, generation, true);
        }
        janos_wps_free_secret(service->memory, request);
        service->request = NULL;
        service->active = false;
        service->active_requires_radio = false;
        service->active_generation = 0U;
        service->active_operation_id = 0U;
        atomic_store_explicit(&service->cancel_requested, false,
                              memory_order_release);
        set_result_locked(service, "worker_start_failed",
                          requires_radio ? (restored ? "restored" : "failed") :
                                           "not_required",
                          "not_required");
        atomic_store_explicit(&service->phase,
                              restored ? JANOS_WPS_SERVICE_IDLE :
                                         JANOS_WPS_SERVICE_QUARANTINED,
                              memory_order_release);
        lifecycle_unlock(service);
        return false;
    }
    /* Only an accepted operation replaces an unrevealed prior result.  A
     * refused lease/admission/allocation/worker start must leave the vault
     * untouched.  The production worker is start-gated; the active/request
     * check also keeps the service robust to a host worker which completed
     * synchronously and already published or erased its own outcome. */
    lifecycle_lock(service);
    if (service->active && service->active_operation_id ==
            accepted_operation_id && service->request == request) {
        vault_lock(service);
        lab_secret_erase(&service->secret);
        vault_unlock(service);
    }
    lifecycle_unlock(service);
    if (operation_id_out) *operation_id_out = accepted_operation_id;
    return true;
}

bool janos_wps_service_start_verify(janos_wps_service_t *service,
                                    const uint8_t bssid[6], const char *pin,
                                    uint32_t *operation_id_out)
{
    if (!valid_bssid(bssid) || !valid_pin(pin)) return false;
    janos_wps_command_t command = {.operation = JANOS_WPS_OP_VERIFY};
    memcpy(command.bssid, bssid, sizeof(command.bssid));
    memcpy(command.pin, pin, sizeof(command.pin));
    bool started = janos_wps_service_start(service, &command, operation_id_out);
    janos_wps_secure_wipe(&command, sizeof(command));
    return started;
}

void janos_wps_service_run_pending(void *argument)
{
    janos_wps_service_t *service = argument;
    if (!service) return;
    lifecycle_lock(service);
    if (!service->active || !service->request) {
        lifecycle_unlock(service);
        return;
    }
    janos_wps_request_t *request = service->request;
    const uint32_t operation_id = request->operation_id;
    bool running = !request->requires_radio || janos_radio_lease_mark_running(
        service->lease, JANOS_RADIO_OWNER_WPS, request->generation);
    if (running)
        atomic_store_explicit(&service->phase, JANOS_WPS_SERVICE_RUNNING,
                              memory_order_release);
    bool cancelled = !running || atomic_load_explicit(
        &service->cancel_requested, memory_order_acquire) ||
        (request->requires_radio && janos_radio_lease_cancel_requested(
            service->lease, JANOS_RADIO_OWNER_WPS, request->generation));
    lifecycle_unlock(service);

    janos_wps_outcome_t outcome;
    memset(&outcome, 0, sizeof(outcome));
    outcome.operation_result = "internal_failure";
    outcome.storage_result = "not_required";
    /* Cancelling before the adapter is entered has nothing to restore. */
    outcome.cleanup_ok = true;

    bool executed = false;
    if (!cancelled)
        executed = service->ops->execute_operation ?
            service->ops->execute_operation(service->ops_context, request, &outcome) :
            service->ops->execute_verify(service->ops_context, request, &outcome);
    lifecycle_lock(service);
    if (!service->active || service->active_operation_id != operation_id ||
        service->request != request) {
        lifecycle_unlock(service);
        janos_wps_secure_wipe(&outcome, sizeof(outcome));
        return;
    }
    if (!service->commit_closed) {
        cancelled = cancelled || atomic_load_explicit(
            &service->cancel_requested, memory_order_acquire) ||
            (request->requires_radio && janos_radio_lease_cancel_requested(
                service->lease, JANOS_RADIO_OWNER_WPS, request->generation));
        /* Teardown is the final completion gate for operations which did not
         * publish a success file.  Stops after this point are too late. */
        service->commit_closed = true;
    } else {
        /* A successful persistence commit won before stop; late cancellation
         * cannot turn a published authenticated result into "cancelled". */
        cancelled = false;
    }
    atomic_store_explicit(&service->phase, JANOS_WPS_SERVICE_CLEANUP,
                          memory_order_release);
    lifecycle_unlock(service);

    bool cleanup_started = !request->requires_radio ||
        janos_radio_lease_begin_cleanup(service->lease, JANOS_RADIO_OWNER_WPS,
                                        request->generation);
    bool cleanup_ok = cleanup_started && outcome.cleanup_ok;
    bool released = cleanup_started && (!request->requires_radio ||
        janos_radio_lease_finish_cleanup(service->lease, JANOS_RADIO_OWNER_WPS,
                                         request->generation, cleanup_ok));
    const char *cleanup_result = request->requires_radio ?
        (released ? "restored" : "failed") :
        (outcome.cleanup_ok ? "not_required" : "failed");

    lifecycle_lock(service);
    if (cancelled) {
        vault_lock(service);
        lab_secret_erase(&service->secret);
        vault_unlock(service);
        set_result_locked(service, "cancelled", cleanup_result,
                          outcome.storage_result);
    } else if (executed && outcome.authenticated_m7 && cleanup_ok && released &&
               vault_store(service, outcome.pin, outcome.network_key,
                            operation_id)) {
        set_result_locked(service,
                          outcome.operation_result ? outcome.operation_result :
                                                     "success",
                          cleanup_result, outcome.storage_result);
    } else {
        vault_lock(service);
        lab_secret_erase(&service->secret);
        vault_unlock(service);
        set_result_locked(service,
                          executed && outcome.operation_result ?
                              outcome.operation_result : "internal_failure",
                          cleanup_result, outcome.storage_result);
    }
    janos_wps_secure_wipe(&outcome, sizeof(outcome));
    janos_wps_free_secret(service->memory, request);
    service->request = NULL;
    service->active = false;
    service->active_requires_radio = false;
    service->active_generation = 0U;
    service->active_operation_id = 0U;
    atomic_store_explicit(&service->cancel_requested, false,
                          memory_order_release);
    atomic_store_explicit(&service->phase,
                          released ? JANOS_WPS_SERVICE_IDLE :
                                     JANOS_WPS_SERVICE_QUARANTINED,
                          memory_order_release);
    lifecycle_unlock(service);
}

bool janos_wps_service_stop(janos_wps_service_t *service)
{
    if (!service) return false;
    lifecycle_lock(service);
    janos_wps_service_phase_t phase = (janos_wps_service_phase_t)
        atomic_load_explicit(&service->phase, memory_order_relaxed);
    if (!service->active || service->commit_closed ||
        phase == JANOS_WPS_SERVICE_IDLE ||
        phase == JANOS_WPS_SERVICE_QUARANTINED) {
        lifecycle_unlock(service);
        return false;
    }
    atomic_store_explicit(&service->cancel_requested, true,
                          memory_order_release);
    const bool requires_radio = service->active_requires_radio;
    const uint32_t generation = service->active_generation;
    lifecycle_unlock(service);
    if (requires_radio)
        (void)janos_radio_lease_request_cancel(service->lease,
                                               JANOS_RADIO_OWNER_WPS,
                                               generation);
    return true;
}

bool janos_wps_service_cancel_requested(janos_wps_service_t *service)
{
    return service && atomic_load_explicit(&service->cancel_requested,
                                           memory_order_acquire);
}

bool janos_wps_service_commit_gate(janos_wps_service_t *service,
                                   uint32_t operation_id)
{
    if (!service || operation_id == 0U) return false;
    lifecycle_lock(service);
    bool granted = service->active && !service->commit_closed &&
        service->active_operation_id == operation_id &&
        !atomic_load_explicit(&service->cancel_requested,
                              memory_order_acquire) &&
        (!service->active_requires_radio ||
         !janos_radio_lease_cancel_requested(service->lease,
                                              JANOS_RADIO_OWNER_WPS,
                                              service->active_generation));
    if (granted) service->commit_closed = true;
    lifecycle_unlock(service);
    return granted;
}

janos_wps_service_status_t janos_wps_service_status(
    janos_wps_service_t *service)
{
    janos_wps_service_status_t status = {0};
    if (!service) return status;
    lifecycle_lock(service);
    status.phase = (janos_wps_service_phase_t)atomic_load_explicit(
        &service->phase, memory_order_relaxed);
    status.operation_id = service->operation_id;
    status.generation = service->generation;
    (void)snprintf(status.operation_result, sizeof(status.operation_result),
                   "%s", service->operation_result);
    (void)snprintf(status.cleanup_result, sizeof(status.cleanup_result), "%s",
                   service->cleanup_result);
    (void)snprintf(status.storage_result, sizeof(status.storage_result), "%s",
                   service->storage_result);
    status.lease = janos_radio_lease_snapshot(service->lease);
    vault_lock(service);
    status.secret = lab_secret_status(&service->secret, now_ms(service));
    vault_unlock(service);
    lifecycle_unlock(service);
    return status;
}

bool janos_wps_service_reveal(janos_wps_service_t *service,
                              char *pin, size_t pin_capacity,
                              char *network_key, size_t key_capacity,
                              uint32_t *operation_id)
{
    return janos_wps_service_reveal_with_state(
        service, pin, pin_capacity, network_key, key_capacity, operation_id,
        NULL);
}

bool janos_wps_service_reveal_with_state(janos_wps_service_t *service,
                                         char *pin, size_t pin_capacity,
                                         char *network_key,
                                         size_t key_capacity,
                                         uint32_t *operation_id,
                                         lab_secret_state_t *state_out)
{
    if (!service) return false;
    vault_lock(service);
    const uint64_t now = now_ms(service);
    lab_secret_info_t info = lab_secret_status(&service->secret, now);
    bool available = info.state == LAB_SECRET_AVAILABLE &&
        lab_secret_take(&service->secret, now, pin, pin_capacity, network_key,
                        key_capacity, operation_id);
    if (state_out) *state_out = available ? LAB_SECRET_AVAILABLE : info.state;
    vault_unlock(service);
    return available;
}

void janos_wps_service_erase_secret(janos_wps_service_t *service)
{
    if (service) {
        vault_lock(service);
        lab_secret_erase(&service->secret);
        vault_unlock(service);
    }
}

