/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "lab_wps_rx_gate.h"

void lab_wps_rx_gate_init(lab_wps_rx_gate_t *gate)
{
    if (!gate) return;
    atomic_init(&gate->m3_pending, false);
    atomic_init(&gate->coalesced_m3, 0U);
}

bool lab_wps_rx_gate_admit(lab_wps_rx_gate_t *gate, bool is_m3)
{
    if (!gate || !is_m3) return true;
    if (!atomic_exchange_explicit(&gate->m3_pending, true,
                                  memory_order_acq_rel))
        return true;
    atomic_fetch_add_explicit(&gate->coalesced_m3, 1U,
                              memory_order_relaxed);
    return false;
}

void lab_wps_rx_gate_consumed(lab_wps_rx_gate_t *gate, bool is_m3)
{
    if (gate && is_m3)
        atomic_store_explicit(&gate->m3_pending, false, memory_order_release);
}

unsigned lab_wps_rx_gate_coalesced_m3(const lab_wps_rx_gate_t *gate)
{
    return gate ? atomic_load_explicit(&gate->coalesced_m3,
                                       memory_order_relaxed) : 0U;
}
