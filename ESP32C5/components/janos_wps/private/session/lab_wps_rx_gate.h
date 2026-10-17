/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stdatomic.h>

typedef struct {
    atomic_bool m3_pending;
    atomic_uint coalesced_m3;
} lab_wps_rx_gate_t;

void lab_wps_rx_gate_init(lab_wps_rx_gate_t *gate);
bool lab_wps_rx_gate_admit(lab_wps_rx_gate_t *gate, bool is_m3);
void lab_wps_rx_gate_consumed(lab_wps_rx_gate_t *gate, bool is_m3);
unsigned lab_wps_rx_gate_coalesced_m3(const lab_wps_rx_gate_t *gate);
