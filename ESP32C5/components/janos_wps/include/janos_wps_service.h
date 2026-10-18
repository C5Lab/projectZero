/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#endif

#include "janos_radio_lease.h"
#include "janos_wps_command.h"
#include "janos_wps_memory.h"
#include "../private/workflow/lab_secret.h"

typedef void (*janos_wps_worker_fn)(void *argument);

typedef struct {
    janos_wps_command_t command;
    /* Legacy aliases kept populated for the known-PIN adapter contract. */
    uint8_t bssid[6];
    char pin[9];
    uint32_t operation_id;
    uint32_t generation;
    bool requires_radio;
} janos_wps_request_t;

/* Compatibility alias retained for existing host adapters. */
typedef janos_wps_request_t janos_wps_verify_request_t;

typedef struct {
    const char *operation_result;
    bool cleanup_ok;
    bool authenticated_m7;
    char pin[9];
    char network_key[65];
    const char *storage_result;
} janos_wps_outcome_t;

typedef janos_wps_outcome_t janos_wps_verify_outcome_t;

typedef struct {
    uint64_t (*now_ms)(void *context);
    bool (*admit)(void *context, const char **reason);
    bool (*start_worker)(void *context, janos_wps_worker_fn worker,
                         void *argument);
    bool (*execute_verify)(void *context,
                           const janos_wps_verify_request_t *request,
                           janos_wps_verify_outcome_t *outcome);
    bool (*execute_operation)(void *context,
                              const janos_wps_request_t *request,
                              janos_wps_outcome_t *outcome);
} janos_wps_service_ops_t;

typedef enum {
    JANOS_WPS_SERVICE_IDLE = 0,
    JANOS_WPS_SERVICE_PREPARING,
    JANOS_WPS_SERVICE_RUNNING,
    JANOS_WPS_SERVICE_CLEANUP,
    JANOS_WPS_SERVICE_QUARANTINED,
} janos_wps_service_phase_t;

typedef struct {
    janos_wps_service_phase_t phase;
    uint32_t operation_id;
    uint32_t generation;
    char operation_result[40];
    char cleanup_result[16];
    char storage_result[24];
    janos_radio_lease_snapshot_t lease;
    lab_secret_info_t secret;
} janos_wps_service_status_t;

typedef struct {
    janos_radio_lease_t *lease;
    janos_wps_memory_t *memory;
    const janos_wps_service_ops_t *ops;
    void *ops_context;
    janos_wps_request_t *request;
    lab_secret_vault_t secret;
    atomic_uint_least32_t phase;
    atomic_bool cancel_requested;
    /* Serializes request publication, stop/commit/teardown arbitration and
     * terminal result publication.  Slow protocol and storage work never run
     * while this lock is held. */
#ifdef ESP_PLATFORM
    StaticSemaphore_t lifecycle_lock_storage;
    StaticSemaphore_t vault_lock_storage;
    SemaphoreHandle_t lifecycle_lock;
    SemaphoreHandle_t vault_lock;
#else
    atomic_flag lifecycle_lock;
    atomic_flag vault_lock;
#endif
    bool active;
    bool active_requires_radio;
    bool commit_closed;
    uint32_t active_operation_id;
    uint32_t active_generation;
    uint32_t next_operation_id;
    uint32_t operation_id;
    uint32_t generation;
    char operation_result[40];
    char cleanup_result[16];
    char storage_result[24];
} janos_wps_service_t;

void janos_wps_service_init(janos_wps_service_t *service,
                            janos_radio_lease_t *lease,
                            janos_wps_memory_t *memory,
                            const janos_wps_service_ops_t *ops,
                            void *ops_context);
bool janos_wps_service_start_verify(janos_wps_service_t *service,
                                    const uint8_t bssid[6], const char *pin,
                                    uint32_t *operation_id_out);
bool janos_wps_service_start(janos_wps_service_t *service,
                             const janos_wps_command_t *command,
                             uint32_t *operation_id_out);
void janos_wps_service_run_pending(void *argument);
bool janos_wps_service_stop(janos_wps_service_t *service);
bool janos_wps_service_cancel_requested(janos_wps_service_t *service);
/* Linearization point for irreversible success-file publication.  Once this
 * gate grants, a later stop is too late and the worker owns bounded teardown. */
bool janos_wps_service_commit_gate(janos_wps_service_t *service,
                                   uint32_t operation_id);
janos_wps_service_status_t janos_wps_service_status(
    janos_wps_service_t *service);
bool janos_wps_service_reveal(janos_wps_service_t *service,
                              char *pin, size_t pin_capacity,
                              char *network_key, size_t key_capacity,
                              uint32_t *operation_id);
/* Returns the one-shot secret and, on failure, the vault state observed at
 * the same linearization point.  This avoids status-then-reveal TOCTOU races
 * in callers which must always emit a deterministic empty/expired response. */
bool janos_wps_service_reveal_with_state(janos_wps_service_t *service,
                                         char *pin, size_t pin_capacity,
                                         char *network_key,
                                         size_t key_capacity,
                                         uint32_t *operation_id,
                                         lab_secret_state_t *state_out);
void janos_wps_service_erase_secret(janos_wps_service_t *service);
int janos_wps_secret_unavailable_response(lab_secret_state_t state,
                                          char *output,
                                          size_t output_capacity);
int janos_wps_stop_response(bool joined,
                            janos_wps_service_phase_t phase,
                            char *output,
                            size_t output_capacity);

