/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_wifi.h"

/* The transport engine is component-private. Public consumers only need the
 * opaque operations type to reference the JanOS adapter instance. */
typedef struct wps_transport_ops wps_transport_ops_t;

typedef struct {
    bool borrowed;
    bool driver_running;
    bool session_mac_set;
    bool restore_verified;
    uint8_t restored_mac[6];
    struct janos_wps_wifi_snapshot *snapshot;
    unsigned restore_phase;
    bool rejected_baseline;
    bool terminal_failure;
} janos_wps_transport_context_t;

/* JanOS owns driver lifecycle/storage. All host changes must use these wrappers.
 * ESP-IDF has no public running/storage getter; only successful operations
 * advance this tracked state. Init establishes the driver's FLASH default. */
esp_err_t janos_wps_wifi_init(const wifi_init_config_t *config);
esp_err_t janos_wps_wifi_deinit(void);
esp_err_t janos_wps_wifi_start(void);
esp_err_t janos_wps_wifi_stop(void);
esp_err_t janos_wps_wifi_set_storage(wifi_storage_t storage);

/* Terminal disposal wipes secrets but deliberately cannot release ownership. */
void janos_wps_transport_reset(janos_wps_transport_context_t *context);

extern const wps_transport_ops_t janos_wps_transport_ops;

