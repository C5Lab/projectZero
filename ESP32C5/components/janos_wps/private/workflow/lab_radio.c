/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "lab_radio.h"

#include <string.h>

void lab_radio_init(lab_radio_t *radio, lab_platform_t *platform,
                    const wps_transport_ops_t *transport_ops,
                    void *transport_context,
                    const uint8_t effective_boot_mac[STA_MAC_SIZE])
{
    if (!radio) return;
    memset(radio, 0, sizeof(*radio));
    radio->platform = platform;
    if (effective_boot_mac)
        memcpy(radio->effective_boot_mac, effective_boot_mac, STA_MAC_SIZE);
    radio->next_owner_token = 1;
    radio->phase = LAB_RADIO_IDLE;
    atomic_init(&radio->callback_token, 0);
    atomic_init(&radio->callbacks_open, false);
    wps_transport_init(&radio->transport, transport_ops, transport_context);
}

static bool restored_exactly(lab_radio_t *radio)
{
    uint8_t readback[STA_MAC_SIZE] = {0};
    return lab_platform_read_sta_mac(radio->platform, readback) == LAB_PLATFORM_OK &&
           memcmp(readback, radio->effective_boot_mac, STA_MAC_SIZE) == 0;
}

static void release_scratch(lab_radio_t *radio)
{
    if (!radio->scratch) return;
    lab_platform_psram_free(radio->platform, radio->scratch);
    radio->scratch = NULL;
    radio->scratch_size = 0;
}

bool lab_radio_acquire(lab_radio_t *radio,
                       const uint8_t session_mac[STA_MAC_SIZE],
                       size_t scratch_size, uint32_t *owner_token)
{
    if (!radio || !session_mac || !owner_token || radio->phase != LAB_RADIO_IDLE ||
        radio->owner_token != 0 || wps_transport_cleanup_pending(&radio->transport))
        return false;

    uint32_t token = radio->next_owner_token++;
    if (radio->next_owner_token == 0) radio->next_owner_token = 1;
    if (token == 0) token = radio->next_owner_token++;
    radio->owner_token = token;
    radio->phase = LAB_RADIO_PREPARING;
    radio->cancel_requested = false;
    atomic_store_explicit(&radio->callback_token, token, memory_order_release);
    atomic_store_explicit(&radio->callbacks_open, false, memory_order_release);

    if (scratch_size != 0) {
        radio->scratch = lab_platform_psram_alloc(radio->platform, scratch_size);
        if (!radio->scratch) goto failed;
        radio->scratch_size = scratch_size;
    }
    if (!wps_transport_begin(&radio->transport, session_mac,
                             radio->effective_boot_mac))
        goto failed;
    *owner_token = token;
    return true;

failed:
    atomic_store_explicit(&radio->callbacks_open, false, memory_order_release);
    bool cleanup_ok = !wps_transport_cleanup_pending(&radio->transport);
    if (cleanup_ok) cleanup_ok = restored_exactly(radio);
    if (cleanup_ok) {
        release_scratch(radio);
        radio->owner_token = 0;
        atomic_store_explicit(&radio->callback_token, 0, memory_order_release);
        radio->phase = LAB_RADIO_IDLE;
    } else {
        radio->phase = LAB_RADIO_QUARANTINED;
    }
    return false;
}

bool lab_radio_mark_running(lab_radio_t *radio, uint32_t owner_token)
{
    if (!radio || radio->phase != LAB_RADIO_PREPARING ||
        owner_token == 0 || owner_token != radio->owner_token ||
        !wps_transport_active(&radio->transport)) return false;
    radio->phase = LAB_RADIO_RUNNING;
    atomic_store_explicit(&radio->callbacks_open, true, memory_order_release);
    return true;
}

void lab_radio_cancel(lab_radio_t *radio, uint32_t owner_token)
{
    if (!radio || owner_token == 0 || owner_token != radio->owner_token) return;
    radio->cancel_requested = true;
    atomic_store_explicit(&radio->callbacks_open, false, memory_order_release);
}

bool lab_radio_cancel_requested(const lab_radio_t *radio, uint32_t owner_token)
{
    return radio && owner_token != 0 && owner_token == radio->owner_token &&
           radio->cancel_requested;
}

bool lab_radio_accept_callback(const lab_radio_t *radio, uint32_t owner_token)
{
    if (!radio || owner_token == 0 || radio->phase != LAB_RADIO_RUNNING) return false;
    bool open = atomic_load_explicit(&radio->callbacks_open, memory_order_acquire);
    uint32_t active = atomic_load_explicit(&radio->callback_token, memory_order_acquire);
    return open && active == owner_token;
}

lab_radio_result_t lab_radio_release(lab_radio_t *radio, int workflow_result)
{
    lab_radio_result_t result = {
        .workflow_result = workflow_result,
        .cleanup_ok = false,
        .quarantined = true,
    };
    if (!radio || radio->owner_token == 0) return result;

    atomic_store_explicit(&radio->callbacks_open, false, memory_order_release);
    bool cleanup_ok = wps_transport_cancel(&radio->transport);
    if (cleanup_ok) cleanup_ok = !wps_transport_cleanup_pending(&radio->transport);
    if (cleanup_ok) cleanup_ok = restored_exactly(radio);
    if (!cleanup_ok) {
        radio->phase = LAB_RADIO_QUARANTINED;
        return result;
    }

    release_scratch(radio);
    radio->owner_token = 0;
    radio->cancel_requested = false;
    atomic_store_explicit(&radio->callback_token, 0, memory_order_release);
    radio->phase = LAB_RADIO_IDLE;
    result.cleanup_ok = true;
    result.quarantined = false;
    return result;
}

bool lab_radio_is_quarantined(const lab_radio_t *radio)
{
    return radio && radio->phase == LAB_RADIO_QUARANTINED;
}

void lab_radio_quarantine(lab_radio_t *radio)
{
    if (!radio) return;
    atomic_store_explicit(&radio->callbacks_open, false, memory_order_release);
    radio->phase = LAB_RADIO_QUARANTINED;
}
