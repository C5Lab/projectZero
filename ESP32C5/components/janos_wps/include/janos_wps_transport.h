/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "wps_transport_core.h"

typedef struct {
    bool borrowed;
    bool driver_running;
    bool session_mac_set;
    bool restore_verified;
    uint8_t restored_mac[6];
} janos_wps_transport_context_t;

extern const wps_transport_ops_t janos_wps_transport_ops;

