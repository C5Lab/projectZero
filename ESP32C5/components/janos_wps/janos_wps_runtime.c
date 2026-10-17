/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_runtime.h"

#include <stdio.h>
#include <string.h>

#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "janos_wps_memory.h"
#include "janos_wps_service.h"
#include "janos_wps_transport.h"
#include "private/workflow/lab_command.h"
#include "private/workflow/lab_platform.h"
#include "private/workflow/lab_radio.h"
#include "private/workflow/lab_secret.h"
#include "private/workflow/lab_workflows.h"

typedef struct {
    janos_radio_lease_t *lease;
    janos_wps_runtime_hooks_t hooks;
    janos_wps_memory_t memory;
    lab_platform_t platform;
    lab_radio_t radio;
    lab_workflows_t workflows;
    janos_wps_transport_context_t transport;
    janos_wps_service_t service;
    uint8_t effective_boot_mac[6];
    janos_wps_worker_fn pending_worker;
    void *pending_argument;
    TaskHandle_t worker_task;
    bool initialized;
} runtime_t;

static runtime_t runtime;

static void emit_line(const char *line)
{
    if (runtime.hooks.tx_activity) runtime.hooks.tx_activity();
    flockfile(stdout);
    fputc('\n', stdout);
    fputs(line, stdout);
    fputc('\n', stdout);
    fflush(stdout);
    funlockfile(stdout);
}

static int platform_sd_mount(void *context)
{
    runtime_t *state = context;
    return state->hooks.mount_sd && state->hooks.mount_sd() == ESP_OK ? 0 : -1;
}

static int platform_sd_unmount(void *context)
{
    (void)context;
    /* JanOS owns the shared mount for the whole application lifetime. */
    return 0;
}

static int platform_factory_mac(void *context, uint8_t output[6])
{
    runtime_t *state = context;
    memcpy(output, state->effective_boot_mac, 6U);
    return 0;
}

static int platform_entropy(void *context, uint8_t *output, size_t length)
{
    (void)context;
    if (!output || length == 0U) return -1;
    esp_fill_random(output, length);
    return 0;
}

static int platform_read_mac(void *context, uint8_t output[6])
{
    (void)context;
    return esp_wifi_get_mac(WIFI_IF_STA, output);
}

static void *platform_psram_alloc(void *context, size_t size)
{
    runtime_t *state = context;
    return janos_wps_alloc_bulk(&state->memory, size);
}

static void platform_psram_free(void *context, void *memory)
{
    runtime_t *state = context;
    janos_wps_free_bulk(&state->memory, memory);
}

static uint64_t platform_now(void *context)
{
    (void)context;
    return (uint64_t)(esp_timer_get_time() / 1000);
}

static void platform_reboot(void *context) { (void)context; }

static bool platform_cancelled(void *context)
{
    runtime_t *state = context;
    janos_wps_service_status_t status = janos_wps_service_status(&state->service);
    return status.generation != 0U && janos_radio_lease_cancel_requested(
        state->lease, JANOS_RADIO_OWNER_WPS, status.generation);
}

static const lab_platform_ops_t platform_ops = {
    .sd_mount = platform_sd_mount,
    .sd_unmount = platform_sd_unmount,
    .factory_mac = platform_factory_mac,
    .entropy = platform_entropy,
    .read_sta_mac = platform_read_mac,
    .psram_alloc = platform_psram_alloc,
    .psram_free = platform_psram_free,
    .monotonic_ms = platform_now,
    .reboot = platform_reboot,
    .poll_cancel = platform_cancelled,
};

static uint64_t service_now(void *context)
{
    return platform_now(context);
}

static bool service_admit(void *context, const char **reason)
{
    runtime_t *state = context;
    const char *busy = state->hooks.busy_reason ? state->hooks.busy_reason() :
                                                  "missing_host_hook";
    if (reason) *reason = busy;
    return busy == NULL;
}

static void runtime_worker(void *argument)
{
    runtime_t *state = argument;
    janos_wps_worker_fn worker = state->pending_worker;
    void *worker_argument = state->pending_argument;
    if (worker) worker(worker_argument);
    janos_wps_service_status_t status = janos_wps_service_status(&state->service);
    janos_wps_memory_snapshot_t memory =
        janos_wps_memory_snapshot(&state->memory);
    char line[512];
    (void)snprintf(line, sizeof(line),
        "{\"schema_version\":1,\"record_type\":\"terminal\","
        "\"run_id\":%u,\"operation_result\":\"%s\","
        "\"cleanup_result\":\"%s\",\"lease_state\":\"%s\","
        "\"bulk_bytes\":%u,\"bulk_peak_bytes\":%u,"
        "\"secret_bytes\":%u,\"secret_peak_bytes\":%u,"
        "\"allocation_failures\":%u}",
        (unsigned)status.operation_id, status.operation_result,
        status.cleanup_result,
        status.lease.state == JANOS_RADIO_LEASE_IDLE ? "released" : "retained",
        (unsigned)memory.bulk_bytes, (unsigned)memory.bulk_peak_bytes,
        (unsigned)memory.secret_bytes, (unsigned)memory.secret_peak_bytes,
        (unsigned)memory.failed_allocations);
    emit_line(line);
    janos_wps_secure_wipe(line, sizeof(line));
    state->pending_worker = NULL;
    state->pending_argument = NULL;
    state->worker_task = NULL;
    vTaskDelete(NULL);
}

static bool service_start_worker(void *context, janos_wps_worker_fn worker,
                                 void *argument)
{
    runtime_t *state = context;
    if (state->worker_task || state->pending_worker) return false;
    state->pending_worker = worker;
    state->pending_argument = argument;
    if (xTaskCreate(runtime_worker, "janos_wps", 14336U, state, 4,
                    &state->worker_task) != pdPASS) {
        state->pending_worker = NULL;
        state->pending_argument = NULL;
        state->worker_task = NULL;
        return false;
    }
    return true;
}

static void workflow_emit(void *context, const char *line)
{
    (void)context;
    if (line) emit_line(line);
}

static bool service_execute(void *context,
                            const janos_wps_verify_request_t *request,
                            janos_wps_verify_outcome_t *outcome)
{
    runtime_t *state = context;
    memset(outcome, 0, sizeof(*outcome));
    outcome->operation_result = "internal_failure";
    if (!state->hooks.prepare_wifi || state->hooks.prepare_wifi() != ESP_OK) {
        outcome->cleanup_ok = true;
        outcome->operation_result = "wifi_prepare_failed";
        return true;
    }
    uint8_t current_mac[6];
    if (esp_wifi_get_mac(WIFI_IF_STA, current_mac) != ESP_OK ||
        memcmp(current_mac, state->effective_boot_mac, 6U) != 0) {
        outcome->cleanup_ok = false;
        outcome->operation_result = "boot_mac_mismatch";
        return true;
    }

    lab_command_t command;
    memset(&command, 0, sizeof(command));
    command.kind = LAB_COMMAND_WPS_VERIFY;
    memcpy(command.bssid, request->bssid, 6U);
    memcpy(command.pin, request->pin, 9U);
    lab_secret_vault_t vault;
    lab_secret_init(&vault, janos_wps_secure_wipe);
    const char *operation = "internal_failure";
    const char *cleanup = "failed";
    bool ran = lab_workflows_execute(&state->workflows, &command,
                                     request->operation_id, &vault,
                                     &operation, &cleanup);
    outcome->cleanup_ok = strcmp(cleanup, "ok") == 0;
    outcome->operation_result = operation;
    if (ran && outcome->cleanup_ok &&
        strcmp(operation, "pin_and_m7_verified") == 0) {
        uint32_t source_operation = 0;
        outcome->authenticated_m7 = lab_secret_take(
            &vault, platform_now(state), outcome->pin, sizeof(outcome->pin),
            outcome->network_key, sizeof(outcome->network_key),
            &source_operation) && source_operation == request->operation_id;
        if (outcome->authenticated_m7) outcome->operation_result = "success";
    }
    lab_secret_erase(&vault);
    janos_wps_secure_wipe(&command, sizeof(command));
    janos_wps_secure_wipe(current_mac, sizeof(current_mac));
    return ran;
}

static const janos_wps_service_ops_t service_ops = {
    .now_ms = service_now,
    .admit = service_admit,
    .start_worker = service_start_worker,
    .execute_verify = service_execute,
};

bool janos_wps_runtime_init(janos_radio_lease_t *lease,
                            const janos_wps_runtime_hooks_t *hooks,
                            const uint8_t effective_boot_mac[6])
{
    if (!lease || !hooks || !hooks->busy_reason || !hooks->prepare_wifi ||
        !hooks->mount_sd || !effective_boot_mac || runtime.initialized)
        return false;
    memset(&runtime, 0, sizeof(runtime));
    runtime.lease = lease;
    runtime.hooks = *hooks;
    memcpy(runtime.effective_boot_mac, effective_boot_mac, 6U);
    janos_wps_memory_init_esp(&runtime.memory);
    lab_platform_init(&runtime.platform, &platform_ops, &runtime, NULL);
    lab_radio_init(&runtime.radio, &runtime.platform, &janos_wps_transport_ops,
                   &runtime.transport, effective_boot_mac);
    if (!lab_workflows_init(&runtime.workflows, &runtime.platform,
                            &runtime.radio)) return false;
    lab_workflows_set_emitter(&runtime.workflows, workflow_emit, &runtime);
    janos_wps_service_init(&runtime.service, lease, &runtime.memory,
                           &service_ops, &runtime);
    runtime.initialized = true;
    return true;
}

static bool parse_bssid(const char *text, uint8_t output[6])
{
    unsigned values[6];
    int consumed = 0;
    if (!text || sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%n",
                        &values[0], &values[1], &values[2], &values[3],
                        &values[4], &values[5], &consumed) != 6 ||
        text[consumed] != '\0') return false;
    for (size_t i = 0; i < 6U; ++i) output[i] = (uint8_t)values[i];
    return true;
}

static const char *phase_name(janos_wps_service_phase_t phase)
{
    static const char *const names[] = {
        "idle", "preparing", "running", "cleanup", "quarantined"
    };
    return (unsigned)phase < sizeof(names) / sizeof(names[0]) ? names[phase] :
                                                               "invalid";
}

int janos_wps_command(int argc, char **argv)
{
    if (!runtime.initialized || argc < 2) return 1;
    if (argc == 2 && strcmp(argv[1], "status") == 0) {
        janos_wps_service_status_t status = janos_wps_service_status(&runtime.service);
        janos_wps_memory_snapshot_t memory =
            janos_wps_memory_snapshot(&runtime.memory);
        printf("{\"schema_version\":1,\"record_type\":\"wps_status\","
               "\"phase\":\"%s\",\"run_id\":%u,\"generation\":%u,"
               "\"operation_result\":\"%s\",\"cleanup_result\":\"%s\","
               "\"bulk_bytes\":%u,\"bulk_peak_bytes\":%u,"
               "\"secret_bytes\":%u,\"secret_peak_bytes\":%u,"
               "\"allocation_failures\":%u}\n",
               phase_name(status.phase), (unsigned)status.operation_id,
               (unsigned)status.generation, status.operation_result,
               status.cleanup_result, (unsigned)memory.bulk_bytes,
               (unsigned)memory.bulk_peak_bytes,
               (unsigned)memory.secret_bytes,
               (unsigned)memory.secret_peak_bytes,
               (unsigned)memory.failed_allocations);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "stop") == 0) {
        bool joined = janos_wps_runtime_stop(5000U);
        janos_wps_service_status_t status =
            janos_wps_service_status(&runtime.service);
        char response[160] = {0};
        int result = janos_wps_stop_response(joined, status.phase,
                                             response, sizeof(response));
        if (response[0] != '\0') printf("%s\n", response);
        janos_wps_secure_wipe(response, sizeof(response));
        return result;
    }
    if (argc == 4 && strcmp(argv[1], "verify") == 0) {
        uint8_t bssid[6];
        if (!parse_bssid(argv[2], bssid)) return 1;
        uint32_t operation = 0;
        bool started = janos_wps_service_start_verify(&runtime.service, bssid,
                                                       argv[3], &operation);
        /* The service owns an internal-RAM copy after start; remove the PIN
         * from the mutable console command buffer on both success and error. */
        janos_wps_secure_wipe(argv[3], strlen(argv[3]));
        janos_wps_secure_wipe(bssid, sizeof(bssid));
        if (!started) return 1;
        printf("{\"schema_version\":1,\"record_type\":\"accepted\","
               "\"run_id\":%u,\"operation\":\"wps_verify\"}\n",
               (unsigned)operation);
        return 0;
    }
    return 1;
}

int janos_wps_secret_command(int argc, char **argv)
{
    if (!runtime.initialized || argc != 2) return 1;
    if (strcmp(argv[1], "status") == 0) {
        janos_wps_service_status_t status = janos_wps_service_status(&runtime.service);
        const char *state = status.secret.state == LAB_SECRET_AVAILABLE ?
            "available" : status.secret.state == LAB_SECRET_EXPIRED ?
            "expired" : "empty";
        printf("{\"schema_version\":1,\"record_type\":\"secret_status\","
               "\"state\":\"%s\",\"run_id\":%u,\"remaining_ms\":%llu}\n",
               state, (unsigned)status.secret.operation_id,
               (unsigned long long)status.secret.remaining_ms);
        return 0;
    }
    if (strcmp(argv[1], "erase") == 0) {
        janos_wps_service_erase_secret(&runtime.service);
        return 0;
    }
    if (strcmp(argv[1], "reveal") == 0) {
        janos_wps_service_status_t status =
            janos_wps_service_status(&runtime.service);
        char pin[9] = {0};
        char key[65] = {0};
        uint32_t operation = 0;
        bool available = janos_wps_service_reveal(
            &runtime.service, pin, sizeof(pin), key, sizeof(key), &operation);
        if (available)
            printf("SENSITIVE operation_id=%u recovered_pin=%s network_key=\"%s\"\n",
                   (unsigned)operation, pin, key);
        int result = 0;
        if (!available) {
            char response[128] = {0};
            result = janos_wps_secret_unavailable_response(
                status.secret.state, response, sizeof(response));
            if (result == 0) printf("%s\n", response);
            janos_wps_secure_wipe(response, sizeof(response));
        }
        janos_wps_secure_wipe(pin, sizeof(pin));
        janos_wps_secure_wipe(key, sizeof(key));
        return available ? 0 : result;
    }
    return 1;
}

bool janos_wps_runtime_stop(uint32_t timeout_ms)
{
    if (!runtime.initialized) return true;
    janos_wps_service_status_t status = janos_wps_service_status(&runtime.service);
    if (status.phase == JANOS_WPS_SERVICE_IDLE) return true;
    if (status.phase == JANOS_WPS_SERVICE_QUARANTINED) return false;
    (void)janos_wps_service_stop(&runtime.service);
    uint64_t deadline = platform_now(&runtime) + timeout_ms;
    do {
        status = janos_wps_service_status(&runtime.service);
        if (status.phase == JANOS_WPS_SERVICE_IDLE) return true;
        if (status.phase == JANOS_WPS_SERVICE_QUARANTINED) return false;
        vTaskDelay(pdMS_TO_TICKS(20));
    } while (platform_now(&runtime) < deadline);
    return false;
}

bool janos_wps_runtime_busy(void)
{
    if (!runtime.initialized) return false;
    janos_wps_service_phase_t phase =
        janos_wps_service_status(&runtime.service).phase;
    return phase != JANOS_WPS_SERVICE_IDLE;
}

