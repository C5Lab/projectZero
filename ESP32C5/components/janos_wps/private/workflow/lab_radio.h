/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LAB_RADIO_H
#define LAB_RADIO_H

#include <stdatomic.h>

#include "lab_platform.h"
#include "wps_transport_core.h"

typedef enum {
    LAB_RADIO_IDLE,
    LAB_RADIO_PREPARING,
    LAB_RADIO_RUNNING,
    LAB_RADIO_QUARANTINED,
} lab_radio_phase_t;

typedef struct {
    int workflow_result;
    bool cleanup_ok;
    bool quarantined;
} lab_radio_result_t;

typedef struct {
    lab_platform_t *platform;
    wps_transport_t transport;
    uint8_t effective_boot_mac[STA_MAC_SIZE];
    void *scratch;
    size_t scratch_size;
    uint32_t next_owner_token;
    uint32_t owner_token;
    atomic_uint_least32_t callback_token;
    atomic_bool callbacks_open;
    lab_radio_phase_t phase;
    bool cancel_requested;
} lab_radio_t;

void lab_radio_init(lab_radio_t *radio, lab_platform_t *platform,
                    const wps_transport_ops_t *transport_ops,
                    void *transport_context,
                    const uint8_t effective_boot_mac[STA_MAC_SIZE]);
bool lab_radio_acquire(lab_radio_t *radio,
                       const uint8_t session_mac[STA_MAC_SIZE],
                       size_t scratch_size, uint32_t *owner_token);
bool lab_radio_mark_running(lab_radio_t *radio, uint32_t owner_token);
void lab_radio_cancel(lab_radio_t *radio, uint32_t owner_token);
bool lab_radio_cancel_requested(const lab_radio_t *radio, uint32_t owner_token);
bool lab_radio_accept_callback(const lab_radio_t *radio, uint32_t owner_token);
lab_radio_result_t lab_radio_release(lab_radio_t *radio, int workflow_result);
void lab_radio_quarantine(lab_radio_t *radio);
bool lab_radio_is_quarantined(const lab_radio_t *radio);

#endif
