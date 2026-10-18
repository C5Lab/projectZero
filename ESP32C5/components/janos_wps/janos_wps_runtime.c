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
#include "janos_wps_wire.h"
#include "private/janos_wps_worker_state.h"
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
    janos_wps_worker_state_t worker_state;
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
    if (janos_wps_service_cancel_requested(&state->service)) return true;
    janos_wps_service_status_t status = janos_wps_service_status(&state->service);
    return status.generation != 0U && janos_radio_lease_cancel_requested(
        state->lease, JANOS_RADIO_OWNER_WPS, status.generation);
}

static bool platform_commit_gate(void *context, uint32_t operation_id)
{
    runtime_t *state = context;
    return janos_wps_service_commit_gate(&state->service, operation_id);
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
    .commit_gate = platform_commit_gate,
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
    /* xTaskCreate may schedule this task immediately.  Do not let a fast
     * offline operation emit terminal before its accepted record. */
    while (!janos_wps_worker_state_released(&state->worker_state))
        /* CONFIG_FREERTOS_HZ=100 makes pdMS_TO_TICKS(1) zero.  Delay one
         * actual tick so a same/lower-priority caller can release the gate. */
        vTaskDelay(1);
    janos_wps_worker_fn worker = state->pending_worker;
    void *worker_argument = state->pending_argument;
    if (worker) worker(worker_argument);
    janos_wps_service_status_t status = janos_wps_service_status(&state->service);
    janos_wps_memory_snapshot_t memory =
        janos_wps_memory_snapshot(&state->memory);
    char line[512];
    unsigned candidate_count = 0U;
    unsigned attempt_count = 0U;
    unsigned resume_index = 0U;
    if (lab_workflows_campaign_progress(&state->workflows, &candidate_count,
                                        &attempt_count, &resume_index) &&
        janos_wps_format_campaign_progress(
            line, sizeof(line), status.operation_id, candidate_count,
            attempt_count, resume_index)) {
        emit_line(line);
    }
    if (strcmp(status.storage_result, "not_required") != 0 &&
        janos_wps_format_storage(line, sizeof(line), &status)) {
        emit_line(line);
    }
    if (janos_wps_format_terminal(line, sizeof(line), &status, &memory))
        emit_line(line);
    janos_wps_secure_wipe(line, sizeof(line));
    state->pending_worker = NULL;
    state->pending_argument = NULL;
    /* Release publishes completion only after terminal output and all shared
     * epilogue state are finished.  Stop/join and the next command wait here,
     * not merely for the service phase to become IDLE. */
    janos_wps_worker_state_finish(&state->worker_state);
    vTaskDelete(NULL);
}

static bool service_start_worker(void *context, janos_wps_worker_fn worker,
                                 void *argument)
{
    runtime_t *state = context;
    if (!janos_wps_worker_state_try_start(&state->worker_state)) return false;
    state->pending_worker = worker;
    state->pending_argument = argument;
    if (xTaskCreate(runtime_worker, "janos_wps", 14336U, state, 4,
                    NULL) != pdPASS) {
        state->pending_worker = NULL;
        state->pending_argument = NULL;
        janos_wps_worker_state_finish(&state->worker_state);
        return false;
    }
    return true;
}

static void workflow_emit(void *context, const char *line)
{
    (void)context;
    if (line) emit_line(line);
}

static lab_command_kind_t workflow_kind(janos_wps_operation_t operation)
{
    switch (operation) {
    case JANOS_WPS_OP_VERIFY: return LAB_COMMAND_WPS_VERIFY;
    case JANOS_WPS_OP_PIXIE: return LAB_COMMAND_WPS_PIXIE;
    case JANOS_WPS_OP_JWPS_PLAN: return LAB_COMMAND_JWPS_PLAN;
    case JANOS_WPS_OP_JWPS_CAMPAIGN: return LAB_COMMAND_WPS_CAMPAIGN;
    case JANOS_WPS_OP_SELFTEST_DB: return LAB_COMMAND_SELFTEST_DB;
    case JANOS_WPS_OP_SELFTEST_FRAGMENT: return LAB_COMMAND_SELFTEST_FRAGMENT;
    case JANOS_WPS_OP_SELFTEST_TRANSPORT: return LAB_COMMAND_SELFTEST_TRANSPORT;
    case JANOS_WPS_OP_SELFTEST_PIXIE: return LAB_COMMAND_SELFTEST_PIXIE;
    default: return LAB_COMMAND_INVALID;
    }
}

static bool service_execute(void *context,
                            const janos_wps_request_t *request,
                            janos_wps_outcome_t *outcome)
{
    runtime_t *state = context;
    memset(outcome, 0, sizeof(*outcome));
    outcome->operation_result = "internal_failure";
    outcome->storage_result = "not_required";
    if (request->requires_radio &&
        (!state->hooks.prepare_wifi || state->hooks.prepare_wifi() != ESP_OK)) {
        outcome->cleanup_ok = true;
        outcome->operation_result = "wifi_prepare_failed";
        return true;
    }
    uint8_t current_mac[6] = {0};
    if (request->requires_radio &&
        (esp_wifi_get_mac(WIFI_IF_STA, current_mac) != ESP_OK ||
         memcmp(current_mac, state->effective_boot_mac, 6U) != 0)) {
        outcome->cleanup_ok = false;
        outcome->operation_result = "boot_mac_mismatch";
        return true;
    }

    lab_command_t command;
    memset(&command, 0, sizeof(command));
    command.kind = workflow_kind(request->command.operation);
    memcpy(command.bssid, request->command.bssid, sizeof(command.bssid));
    memcpy(command.pin, request->command.pin, sizeof(command.pin));
    memcpy(command.ssid, request->command.ssid, sizeof(command.ssid));
    command.start_index = request->command.start_index;
    command.count = request->command.count;
    command.epoch = request->command.epoch;
    command.epoch_set = request->command.epoch_set;
    lab_secret_vault_t vault;
    lab_secret_init(&vault, janos_wps_secure_wipe);
    const char *operation = "internal_failure";
    const char *cleanup = "failed";
    bool ran = lab_workflows_execute(&state->workflows, &command,
                                     request->operation_id, &vault,
                                     &operation, &cleanup);
    outcome->cleanup_ok = lab_workflows_cleanup_succeeded(cleanup);
    outcome->operation_result = operation;
    outcome->storage_result = lab_workflows_storage_result(&state->workflows);
    if (ran && outcome->cleanup_ok) {
        uint32_t source_operation = 0;
        outcome->authenticated_m7 = lab_secret_take(
            &vault, platform_now(state), outcome->pin, sizeof(outcome->pin),
            outcome->network_key, sizeof(outcome->network_key),
            &source_operation) && source_operation == request->operation_id;
        if (outcome->authenticated_m7 &&
            request->command.operation == JANOS_WPS_OP_VERIFY)
            outcome->operation_result = "success";
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
    .execute_operation = service_execute,
};

typedef struct {
    bool cancellation_accepted;
    bool joined;
    janos_wps_service_phase_t decision_phase;
    janos_wps_service_phase_t final_phase;
} runtime_stop_attempt_t;

static runtime_stop_attempt_t runtime_stop_attempt(uint32_t timeout_ms);

bool janos_wps_runtime_init(janos_radio_lease_t *lease,
                            const janos_wps_runtime_hooks_t *hooks,
                            const uint8_t effective_boot_mac[6])
{
    if (!lease || !hooks || !hooks->busy_reason || !hooks->prepare_wifi ||
        !hooks->mount_sd || !effective_boot_mac || runtime.initialized)
        return false;
    memset(&runtime, 0, sizeof(runtime));
    janos_wps_worker_state_init(&runtime.worker_state);
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

static void wipe_verify_pin_argument(int argc, char **argv)
{
    if (argc >= 4 && argv && argv[0] && argv[1] && argv[3] &&
        strcmp(argv[0], "wps") == 0 && strcmp(argv[1], "verify") == 0)
        janos_wps_secure_wipe(argv[3], strlen(argv[3]));
}

int janos_wps_command(int argc, char **argv)
{
    if (!runtime.initialized || argc < 2) return 1;
    if (argc == 2 && strcmp(argv[1], "status") == 0) {
        janos_wps_service_status_t status = janos_wps_service_status(&runtime.service);
        janos_wps_memory_snapshot_t memory =
            janos_wps_memory_snapshot(&runtime.memory);
        char response[512] = {0};
        bool formatted = janos_wps_format_status(response, sizeof(response),
                                                 &status, &memory);
        if (formatted) printf("%s\n", response);
        janos_wps_secure_wipe(response, sizeof(response));
        return formatted ? 0 : 1;
    }
    if (argc == 2 && strcmp(argv[1], "stop") == 0) {
        runtime_stop_attempt_t attempt = runtime_stop_attempt(5000U);
        /* A worker which already crossed the commit gate owns completion.
         * Waiting for it is still required for safe global teardown, but the
         * CLI must not claim that this late stop caused the completion. */
        bool stopped_by_request = attempt.cancellation_accepted &&
                                  attempt.joined;
        janos_wps_service_phase_t response_phase =
            !attempt.cancellation_accepted &&
            attempt.decision_phase != JANOS_WPS_SERVICE_IDLE &&
            attempt.final_phase != JANOS_WPS_SERVICE_QUARANTINED
                ? attempt.decision_phase : attempt.final_phase;
        char response[160] = {0};
        int result = janos_wps_stop_response(stopped_by_request,
                                             response_phase,
                                             response, sizeof(response));
        if (response[0] != '\0') printf("%s\n", response);
        janos_wps_secure_wipe(response, sizeof(response));
        return result;
    }
    janos_wps_command_t command;
    janos_wps_parse_result_t parse_result =
        janos_wps_command_parse(argc, argv, &command);
    /* The parser has copied a valid PIN into command by this point.  Erase
     * the mutable console token before any busy/start/error return; malformed
     * verify commands with an argv[3] are secret-bearing too. */
    wipe_verify_pin_argument(argc, argv);
    if (parse_result == JANOS_WPS_PARSE_OK &&
        (command.operation == JANOS_WPS_OP_VERIFY ||
         command.operation == JANOS_WPS_OP_PIXIE)) {
        if (janos_wps_worker_state_active(&runtime.worker_state)) {
            janos_wps_command_wipe(&command);
            return 1;
        }
        uint32_t operation = 0;
        bool started = janos_wps_service_start(&runtime.service, &command,
                                                &operation);
        const char *name = janos_wps_operation_name(command.operation);
        janos_wps_command_wipe(&command);
        if (!started) return 1;
        char response[160] = {0};
        bool formatted = janos_wps_format_accepted(response, sizeof(response),
                                                   operation, name);
        if (formatted) {
            printf("%s\n", response);
            (void)fflush(stdout);
        }
        janos_wps_worker_state_release(&runtime.worker_state);
        janos_wps_secure_wipe(response, sizeof(response));
        return formatted ? 0 : 1;
    }
    janos_wps_command_wipe(&command);
    return 1;
}

static int start_parsed_operation(int argc, char **argv,
                                  janos_wps_operation_t first,
                                  janos_wps_operation_t last)
{
    if (!runtime.initialized) return 1;
    janos_wps_command_t command;
    if (janos_wps_command_parse(argc, argv, &command) != JANOS_WPS_PARSE_OK ||
        command.operation < first || command.operation > last) {
        janos_wps_command_wipe(&command);
        return 1;
    }
    janos_wps_operation_t kind = command.operation;
    if (janos_wps_worker_state_active(&runtime.worker_state)) {
        janos_wps_command_wipe(&command);
        return 1;
    }
    uint32_t operation = 0;
    bool started = janos_wps_service_start(&runtime.service, &command, &operation);
    janos_wps_command_wipe(&command);
    if (!started) return 1;
    char response[160] = {0};
    bool formatted = janos_wps_format_accepted(
        response, sizeof(response), operation, janos_wps_operation_name(kind));
    if (formatted) {
        printf("%s\n", response);
        (void)fflush(stdout);
    }
    janos_wps_worker_state_release(&runtime.worker_state);
    janos_wps_secure_wipe(response, sizeof(response));
    return formatted ? 0 : 1;
}

int janos_jwps_command(int argc, char **argv)
{
    return start_parsed_operation(argc, argv, JANOS_WPS_OP_JWPS_PLAN,
                                  JANOS_WPS_OP_JWPS_CAMPAIGN);
}

int janos_wps_selftest_command(int argc, char **argv)
{
    return start_parsed_operation(argc, argv, JANOS_WPS_OP_SELFTEST_DB,
                                  JANOS_WPS_OP_SELFTEST_PIXIE);
}

int janos_wps_secret_command(int argc, char **argv)
{
    if (!runtime.initialized || argc != 2) return 1;
    if (strcmp(argv[1], "status") == 0) {
        janos_wps_service_status_t status = janos_wps_service_status(&runtime.service);
        char response[192] = {0};
        bool formatted = janos_wps_format_secret_status(
            response, sizeof(response), &status);
        if (formatted) printf("%s\n", response);
        janos_wps_secure_wipe(response, sizeof(response));
        return formatted ? 0 : 1;
    }
    if (strcmp(argv[1], "erase") == 0) {
        janos_wps_service_erase_secret(&runtime.service);
        return 0;
    }
    if (strcmp(argv[1], "reveal") == 0) {
        char pin[9] = {0};
        char key[65] = {0};
        uint32_t operation = 0;
        lab_secret_state_t unavailable_state = LAB_SECRET_EMPTY;
        bool available = janos_wps_service_reveal_with_state(
            &runtime.service, pin, sizeof(pin), key, sizeof(key), &operation,
            &unavailable_state);
        if (available) {
            char response[512] = {0};
            bool formatted = janos_wps_format_secret_reveal(
                response, sizeof(response), operation, pin, key);
            if (formatted) printf("%s\n", response);
            janos_wps_secure_wipe(response, sizeof(response));
            if (!formatted) {
                janos_wps_secure_wipe(pin, sizeof(pin));
                janos_wps_secure_wipe(key, sizeof(key));
                return 1;
            }
        }
        int result = 0;
        if (!available) {
            char response[128] = {0};
            result = janos_wps_secret_unavailable_response(
                unavailable_state, response, sizeof(response));
            if (result == 0) printf("%s\n", response);
            janos_wps_secure_wipe(response, sizeof(response));
        }
        janos_wps_secure_wipe(pin, sizeof(pin));
        janos_wps_secure_wipe(key, sizeof(key));
        return available ? 0 : result;
    }
    return 1;
}

static runtime_stop_attempt_t runtime_stop_attempt(uint32_t timeout_ms)
{
    runtime_stop_attempt_t attempt = {
        .cancellation_accepted = true,
        .joined = true,
        .decision_phase = JANOS_WPS_SERVICE_IDLE,
        .final_phase = JANOS_WPS_SERVICE_IDLE,
    };
    if (!runtime.initialized) return attempt;
    janos_wps_service_status_t status = janos_wps_service_status(&runtime.service);
    attempt.decision_phase = status.phase;
    attempt.final_phase = status.phase;
    bool worker_active = janos_wps_worker_state_active(&runtime.worker_state);
    janos_wps_worker_stop_action_t action = janos_wps_worker_stop_action(
        status.phase == JANOS_WPS_SERVICE_IDLE,
        status.phase == JANOS_WPS_SERVICE_QUARANTINED, worker_active);
    if (action == JANOS_WPS_STOP_ALREADY_JOINED) return attempt;
    if (action == JANOS_WPS_STOP_WAIT_EPILOGUE) {
        attempt.decision_phase = JANOS_WPS_SERVICE_CLEANUP;
        attempt.cancellation_accepted = false;
        attempt.joined = false;
    } else if (action == JANOS_WPS_STOP_QUARANTINED) {
        attempt.cancellation_accepted = false;
        attempt.joined = false;
        return attempt;
    } else {
        attempt.cancellation_accepted =
            janos_wps_service_stop(&runtime.service);
        attempt.joined = false;
    }
    uint64_t deadline = platform_now(&runtime) + timeout_ms;
    do {
        status = janos_wps_service_status(&runtime.service);
        attempt.final_phase = status.phase;
        worker_active = janos_wps_worker_state_active(&runtime.worker_state);
        if (status.phase == JANOS_WPS_SERVICE_IDLE && !worker_active) {
            attempt.joined = true;
            return attempt;
        }
        if (status.phase == JANOS_WPS_SERVICE_QUARANTINED && !worker_active)
            return attempt;
        vTaskDelay(pdMS_TO_TICKS(20));
    } while (platform_now(&runtime) < deadline);
    return attempt;
}

bool janos_wps_runtime_stop(uint32_t timeout_ms)
{
    return runtime_stop_attempt(timeout_ms).joined;
}

bool janos_wps_runtime_busy(void)
{
    if (!runtime.initialized) return false;
    janos_wps_service_phase_t phase =
        janos_wps_service_status(&runtime.service).phase;
    return phase != JANOS_WPS_SERVICE_IDLE ||
           janos_wps_worker_state_active(&runtime.worker_state);
}

