/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#include "janos_radio_lease.h"
#include "janos_wps_memory.h"
#include "../private/workflow/lab_secret.h"

typedef void (*janos_wps_worker_fn)(void *argument);

typedef struct {
    uint8_t bssid[6];
    char pin[9];
    uint32_t operation_id;
    uint32_t generation;
} janos_wps_verify_request_t;

typedef struct {
    const char *operation_result;
    bool cleanup_ok;
    bool authenticated_m7;
    char pin[9];
    char network_key[65];
} janos_wps_verify_outcome_t;

typedef struct {
    uint64_t (*now_ms)(void *context);
    bool (*admit)(void *context, const char **reason);
    bool (*start_worker)(void *context, janos_wps_worker_fn worker,
                         void *argument);
    bool (*execute_verify)(void *context,
                           const janos_wps_verify_request_t *request,
                           janos_wps_verify_outcome_t *outcome);
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
    const char *operation_result;
    const char *cleanup_result;
    janos_radio_lease_snapshot_t lease;
    lab_secret_info_t secret;
} janos_wps_service_status_t;

typedef struct {
    janos_radio_lease_t *lease;
    janos_wps_memory_t *memory;
    const janos_wps_service_ops_t *ops;
    void *ops_context;
    janos_wps_verify_request_t *request;
    lab_secret_vault_t secret;
    atomic_uint_least32_t phase;
    uint32_t next_operation_id;
    uint32_t operation_id;
    uint32_t generation;
    char operation_result[40];
    char cleanup_result[16];
} janos_wps_service_t;

void janos_wps_service_init(janos_wps_service_t *service,
                            janos_radio_lease_t *lease,
                            janos_wps_memory_t *memory,
                            const janos_wps_service_ops_t *ops,
                            void *ops_context);
bool janos_wps_service_start_verify(janos_wps_service_t *service,
                                    const uint8_t bssid[6], const char *pin,
                                    uint32_t *operation_id_out);
void janos_wps_service_run_pending(void *argument);
bool janos_wps_service_stop(janos_wps_service_t *service);
janos_wps_service_status_t janos_wps_service_status(
    janos_wps_service_t *service);
bool janos_wps_service_reveal(janos_wps_service_t *service,
                              char *pin, size_t pin_capacity,
                              char *network_key, size_t key_capacity,
                              uint32_t *operation_id);
void janos_wps_service_erase_secret(janos_wps_service_t *service);
int janos_wps_secret_unavailable_response(lab_secret_state_t state,
                                          char *output,
                                          size_t output_capacity);
int janos_wps_stop_response(bool joined,
                            janos_wps_service_phase_t phase,
                            char *output,
                            size_t output_capacity);

