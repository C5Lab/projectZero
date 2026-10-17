/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "lab_wps_session_esp.h"
#include "lab_wps_rx_gate.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_private/wifi.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "utils/common.h"
#include "esp_wifi_driver.h"
#include "esp_wps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "m3_protocol.h"
#include "pin_crypto.h"
#include "pin_protocol.h"
#include "protocol.h"
#include "session_frames.h"
#include "wsc_fragment.h"

enum { ESP_EVENT_ASSOC = 1, ESP_EVENT_RX, ESP_EVENT_DISCONNECT };
enum {
    ESP_RX_MAX = 1536,
    ESP_REASSEMBLY_MAX = 2048,
    ESP_FRAME_MAX = 2066,
    ESP_TXATTRS_MAX = 900,
    ESP_TXPACKET_MAX = 960,
    ESP_QUEUE_DEPTH = 8,
};

typedef struct {
    unsigned type;
    unsigned reason;
    bool m3;
    size_t length;
    uint8_t bytes[ESP_RX_MAX];
} queued_event_t;

struct lab_wps_esp_session {
    lab_radio_t *radio;
    uint32_t owner_token;
    QueueHandle_t queue;
    StaticQueue_t queue_control;
    uint8_t *queue_storage;
    struct wps_funcs *callbacks;
    bool handler_registered;
    bool capture_pixie;
    lab_wps_cancel_fn cancelled;
    void *cancel_context;
    uint8_t target[6];
    char pin[9];
    size_t pin_len;
    atomic_uint dropped;
    lab_wps_rx_gate_t rx_gate;
    int64_t overall_deadline_us;
    int64_t stage_deadline_us;

    m3_m1_t m1;
    m3_m3_t m3;
    pin_keys_t keys;
    pin_secure_message_t secure;
    uint8_t nr[16], uuid[16], pkr[192];
    uint8_t psk1[16], psk2[16], rs1[16], rs2[16], rh1[32], rh2[32];
    uint8_t ehash1[32], ehash2[32];
    uint8_t *txattrs;
    uint8_t *txpacket;
    uint8_t *current;
    uint8_t *fragment_storage;
    uint8_t plain[512];
    size_t txattrs_len;
    size_t cached_packet_len;
    size_t current_len;
    unsigned stage;
    uint8_t rf_band;
    lab_wps_action_t cached_action;
    uint8_t cached_eap_id;
    bool cached_action_valid;
    wsc_reassembly_t reassembly;
};

static _Atomic(lab_wps_esp_session_t *) active_session;
static atomic_uint callbacks_inflight;

static void callback_leave(void)
{
    atomic_fetch_sub_explicit(&callbacks_inflight, 1U, memory_order_release);
}

static lab_wps_esp_session_t *callback_enter(
    lab_wps_esp_session_t *expected_session)
{
    atomic_fetch_add_explicit(&callbacks_inflight, 1U, memory_order_acquire);
    lab_wps_esp_session_t *session = atomic_load_explicit(
        &active_session, memory_order_acquire);
    if (!session || (expected_session && expected_session != session)) {
        callback_leave();
        return NULL;
    }
    return session;
}

static void callback_drain(void)
{
    while (atomic_load_explicit(&callbacks_inflight, memory_order_acquire) != 0U)
        vTaskDelay(1);
}

static void wipe(void *memory, size_t size) {
    volatile uint8_t *bytes = memory;
    while (size--) *bytes++ = 0;
}

static uint8_t *scratch_take(uint8_t **cursor, size_t *remaining, size_t size)
{
    const size_t alignment = sizeof(void *);
    uintptr_t address = (uintptr_t)*cursor;
    size_t padding = (alignment - (address % alignment)) % alignment;
    if (padding > *remaining || size > *remaining - padding) return NULL;
    *cursor += padding;
    *remaining -= padding;
    uint8_t *result = *cursor;
    *cursor += size;
    *remaining -= size;
    return result;
}

static void put16(uint8_t *output, unsigned value) {
    output[0] = (uint8_t)(value >> 8);
    output[1] = (uint8_t)value;
}

static bool add_attr(uint8_t *output, size_t capacity, size_t *position,
                     unsigned type, const void *value, size_t length) {
    if (!output || !position || !value || *position > capacity ||
        capacity - *position < 4U || length > capacity - *position - 4U)
        return false;
    put16(output + *position, type);
    put16(output + *position + 2U, (unsigned)length);
    memcpy(output + *position + 4U, value, length);
    *position += length + 4U;
    return true;
}

static bool same8(const uint8_t left[8], const uint8_t right[8]) {
    uint8_t difference = 0;
    for (size_t i = 0; i < 8; ++i) difference |= left[i] ^ right[i];
    return difference == 0;
}

static unsigned message_type(const uint8_t *frame, size_t length) {
    if (!frame || length < 18U) return 0;
    size_t position = 18U;
    while (position <= length && length - position >= 4U) {
        unsigned type = ((unsigned)frame[position] << 8) | frame[position + 1U];
        size_t size = ((size_t)frame[position + 2U] << 8) | frame[position + 3U];
        position += 4U;
        if (size > length - position) return 0;
        if (type == 0x1022U && size == 1U) return frame[position];
        position += size;
    }
    return 0;
}

static bool make_encrypted(const uint8_t authkey[32], const uint8_t wrap[16],
                           unsigned nonce_type, const uint8_t nonce[16],
                           uint8_t *output, size_t capacity, size_t *length) {
    uint8_t plain[64] = {0}, kwa[8] = {0}, iv[16] = {0};
    size_t position = 0;
    bool ok = add_attr(plain, sizeof(plain), &position, nonce_type, nonce, 16) &&
              pin_kwa(authkey, plain, position, kwa) &&
              add_attr(plain, sizeof(plain), &position, 0x101eU, kwa, sizeof(kwa)) &&
              pin_random(iv, sizeof(iv)) &&
              pin_encrypt_settings(wrap, iv, plain, position, output, capacity, length);
    wipe(plain, sizeof(plain));
    wipe(kwa, sizeof(kwa));
    wipe(iv, sizeof(iv));
    return ok;
}

static bool callback_allowed(lab_wps_esp_session_t *session) {
    return session && lab_radio_accept_callback(session->radio, session->owner_token);
}

static bool post(lab_wps_esp_session_t *session, queued_event_t *event) {
    if (!callback_allowed(session) || xQueueSend(session->queue, event, 0) != pdTRUE) {
        atomic_fetch_add_explicit(&session->dropped, 1U, memory_order_relaxed);
        return false;
    }
    return true;
}

static int rx_callback(u8 *source, u8 *buffer, u32 length) {
    lab_wps_esp_session_t *session = callback_enter(NULL);
    if (!session) return ESP_OK;
    if (!callback_allowed(session) || !source || !buffer ||
        memcmp(source, session->target, 6) != 0) {
        callback_leave();
        return ESP_OK;
    }
    if (length > ESP_RX_MAX) {
        atomic_fetch_add_explicit(&session->dropped, 1U, memory_order_relaxed);
        callback_leave();
        return ESP_OK;
    }
    const bool is_m3 = message_type(buffer, length) == 7U;
    if (!lab_wps_rx_gate_admit(&session->rx_gate, is_m3)) {
        callback_leave();
        return ESP_OK;
    }
    queued_event_t event = {
        .type = ESP_EVENT_RX,
        .m3 = is_m3,
        .length = length,
    };
    memcpy(event.bytes, buffer, length);
    if (!post(session, &event))
        lab_wps_rx_gate_consumed(&session->rx_gate, is_m3);
    callback_leave();
    return ESP_OK;
}

static int pending_callback(void) {
    lab_wps_esp_session_t *session = callback_enter(NULL);
    if (!session) return ESP_OK;
    queued_event_t event = {.type = ESP_EVENT_ASSOC};
    post(session, &event);
    callback_leave();
    return ESP_OK;
}

static bool ignore_scan(struct wps_scan_ie *scan) { (void)scan; return false; }
static int ignore_start(void) { return ESP_OK; }

static void wifi_event(void *argument, esp_event_base_t base, int32_t id,
                       void *data) {
    (void)base;
    lab_wps_esp_session_t *session = callback_enter(argument);
    if (!session) return;
    if (!callback_allowed(session)) {
        callback_leave();
        return;
    }
    if (id == WIFI_EVENT_STA_CONNECTED) {
        queued_event_t event = {.type = ESP_EVENT_ASSOC};
        post(session, &event);
    } else if (id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *disconnected = data;
        queued_event_t event = {.type = ESP_EVENT_DISCONNECT,
                                .reason = disconnected ? disconnected->reason : 0};
        post(session, &event);
    }
    callback_leave();
}

static bool send_payload(lab_wps_esp_session_t *session,
                         const uint8_t *payload, size_t length) {
    if (!payload || length > 1386U) return false;
    uint8_t *frame = heap_caps_malloc(length + 14U,
                                     MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!frame) return false;
    uint8_t own[6];
    esp_err_t error = esp_wifi_get_mac(WIFI_IF_STA, own);
    if (error == ESP_OK) {
        memcpy(frame, session->target, 6);
        memcpy(frame + 6, own, 6);
        frame[12] = 0x88;
        frame[13] = 0x8e;
        memcpy(frame + 14, payload, length);
        error = esp_wifi_internal_tx(WIFI_IF_STA, frame, length + 14U);
    }
    wipe(frame, length + 14U);
    heap_caps_free(frame);
    return error == ESP_OK;
}

static bool esp_send_action(void *opaque, lab_wps_action_t action, uint8_t eap_id) {
    lab_wps_esp_session_t *session = opaque;
    uint8_t tag[8];
    size_t body = 0, encrypted_len = 0, packet_len = 0;
    uint8_t encrypted[80];
    bool ok = false;
    if (session->cached_action_valid && action == session->cached_action &&
        eap_id == session->cached_eap_id && session->cached_packet_len != 0U) {
        ok = send_payload(session, session->txpacket, session->cached_packet_len);
        if (ok) session->stage_deadline_us = esp_timer_get_time() + 3000000;
        return ok;
    }
    switch (action) {
    case LAB_WPS_ACTION_START: {
        static const uint8_t start[] = {1, 1, 0, 0};
        ok = send_payload(session, start, sizeof(start));
        break;
    }
    case LAB_WPS_ACTION_IDENTITY: {
        uint8_t response[64];
        size_t length = probe_identity(eap_id, response, sizeof(response));
        ok = length != 0U && send_payload(session, response, length);
        wipe(response, sizeof(response));
        break;
    }
    case LAB_WPS_ACTION_M2:
        session->txattrs_len = 0;
        body = m3_build_m2_body(session->txattrs, ESP_TXATTRS_MAX,
                                session->m1.enrollee_nonce, session->nr,
                                session->uuid, session->pkr, session->rf_band,
                                session->m1.wsc2);
        if (body && pin_authenticator(session->keys.authkey, session->m1.attrs,
                                     session->m1.attrs_len, session->txattrs,
                                     body, tag))
            session->txattrs_len = m3_append_authenticator(
                session->txattrs, ESP_TXATTRS_MAX, body, tag);
        if (session->txattrs_len)
            packet_len = m3_wrap_m2(session->txpacket, ESP_TXPACKET_MAX,
                                    session->m1.eap_id, session->txattrs,
                                    session->txattrs_len);
        ok = packet_len && send_payload(session, session->txpacket, packet_len);
        break;
    case LAB_WPS_ACTION_M4:
        session->txattrs_len = 0;
        if (!pin_random(session->rs1, 16) || !pin_random(session->rs2, 16) ||
            !pin_commitment(session->keys.authkey, session->rs1, session->psk1,
                            session->m1.public_key, session->pkr, session->rh1) ||
            !pin_commitment(session->keys.authkey, session->rs2, session->psk2,
                            session->m1.public_key, session->pkr, session->rh2) ||
            !make_encrypted(session->keys.authkey, session->keys.keywrapkey,
                            0x103fU, session->rs1, encrypted,
                            sizeof(encrypted), &encrypted_len)) break;
        body = pin_build_m4_body(session->txattrs, ESP_TXATTRS_MAX,
                                 session->m1.enrollee_nonce, session->rh1,
                                 session->rh2, encrypted, encrypted_len,
                                 session->m1.wsc2);
        if (body && pin_authenticator(session->keys.authkey,
                                     session->current + 18,
                                     session->current_len - 18U,
                                     session->txattrs, body, tag))
            session->txattrs_len = pin_append_authenticator(
                session->txattrs, ESP_TXATTRS_MAX, body, tag);
        if (session->txattrs_len)
            packet_len = m3_wrap_m2(session->txpacket, ESP_TXPACKET_MAX,
                                    eap_id, session->txattrs, session->txattrs_len);
        ok = packet_len && send_payload(session, session->txpacket, packet_len);
        break;
    case LAB_WPS_ACTION_M6:
        session->txattrs_len = 0;
        if (!make_encrypted(session->keys.authkey, session->keys.keywrapkey,
                            0x1040U, session->rs2, encrypted,
                            sizeof(encrypted), &encrypted_len)) break;
        body = pin_build_m6_body(session->txattrs, ESP_TXATTRS_MAX,
                                 session->m1.enrollee_nonce, encrypted,
                                 encrypted_len, session->m1.wsc2);
        if (body && pin_authenticator(session->keys.authkey, session->secure.attrs,
                                     session->secure.attrs_len, session->txattrs,
                                     body, tag))
            session->txattrs_len = pin_append_authenticator(
                session->txattrs, ESP_TXATTRS_MAX, body, tag);
        if (session->txattrs_len)
            packet_len = m3_wrap_m2(session->txpacket, ESP_TXPACKET_MAX,
                                    eap_id, session->txattrs, session->txattrs_len);
        ok = packet_len && send_payload(session, session->txpacket, packet_len);
        break;
    case LAB_WPS_ACTION_NACK:
        packet_len = wps_build_nack(session->txpacket, ESP_TXPACKET_MAX,
                                    eap_id, session->m1.enrollee_nonce,
                                    session->nr, session->m1.wsc2);
        ok = packet_len && send_payload(session, session->txpacket, packet_len);
        break;
    default:
        break;
    }
    wipe(tag, sizeof(tag));
    wipe(encrypted, sizeof(encrypted));
    if (ok) {
        if (packet_len != 0U) {
            session->cached_action = action;
            session->cached_eap_id = eap_id;
            session->cached_packet_len = packet_len;
            session->cached_action_valid = true;
        }
        session->stage_deadline_us = esp_timer_get_time() + 3000000;
    }
    return ok;
}

static bool decode_secure(lab_wps_esp_session_t *session, unsigned type,
                          lab_wps_event_t *event) {
    uint8_t tag[8], commitment[32];
    size_t plain_len = 0;
    pin_inner_t inner;
    unsigned nonce_type = type == 9U ? 0x1016U : 0x1017U;
    bool ok = pin_parse_secure_frame(session->current, session->current_len,
                                     (uint8_t)type, session->current[5],
                                     session->nr, &session->secure) &&
              pin_authenticator(session->keys.authkey, session->txattrs,
                                session->txattrs_len, session->secure.attrs,
                                session->secure.body_len, tag) &&
              same8(tag, session->secure.authenticator) &&
              pin_decrypt_settings(session->keys.keywrapkey,
                                   session->secure.encrypted,
                                   session->secure.encrypted_len, session->plain,
                                   sizeof(session->plain), &plain_len) &&
              pin_parse_inner(session->plain, plain_len, nonce_type, &inner) &&
              pin_kwa(session->keys.authkey, session->plain, inner.body_len, tag) &&
              same8(tag, inner.kwa);
    if (ok) {
        const uint8_t *psk = type == 9U ? session->psk1 : session->psk2;
        const uint8_t *wanted = type == 9U ? session->ehash1 : session->ehash2;
        ok = pin_commitment(session->keys.authkey, inner.snonce, psk,
                            session->m1.public_key, session->pkr, commitment);
        event->authenticated = true;
        event->pin_half_verified = ok && memcmp(commitment, wanted, 32) == 0;
        if (type == 11U && event->pin_half_verified) {
            event->credential_present = inner.credential_present;
            event->network_key = inner.network_key;
            event->network_key_len = inner.network_key_len;
            event->ssid = inner.ssid;
            event->ssid_len = inner.ssid_len;
        }
    }
    wipe(tag, sizeof(tag));
    wipe(commitment, sizeof(commitment));
    return ok;
}

static bool esp_next_event(void *opaque, lab_wps_event_t *event) {
    lab_wps_esp_session_t *session = opaque;
    queued_event_t queued;
    while (esp_timer_get_time() < session->overall_deadline_us) {
        if (lab_radio_cancel_requested(session->radio, session->owner_token) ||
            (session->cancelled && session->cancelled(session->cancel_context))) {
            event->kind = LAB_WPS_EVENT_CANCELLED;
            return true;
        }
        if (atomic_load_explicit(&session->dropped, memory_order_relaxed) != 0U) {
            event->kind = LAB_WPS_EVENT_QUEUE_OVERFLOW;
            return true;
        }
        if (xQueueReceive(session->queue, &queued, pdMS_TO_TICKS(200)) != pdTRUE) {
            if (session->stage_deadline_us &&
                esp_timer_get_time() >= session->stage_deadline_us) {
                event->kind = LAB_WPS_EVENT_TIMEOUT;
                return true;
            }
            continue;
        }
        lab_wps_rx_gate_consumed(&session->rx_gate, queued.m3);
        if (queued.type == ESP_EVENT_ASSOC) {
            event->kind = LAB_WPS_EVENT_ASSOCIATED;
            return true;
        }
        if (queued.type == ESP_EVENT_DISCONNECT) {
            event->kind = LAB_WPS_EVENT_DISCONNECTED;
            return true;
        }
        if (queued.type != ESP_EVENT_RX) continue;

        const uint8_t *frame = queued.bytes;
        size_t length = queued.length;
        if (length >= 18U && frame[8] == 254U && frame[10] == 0x37U &&
            frame[11] == 0x2aU) {
            wsc_fragment_view_t view;
            wsc_fragment_result_t status = wsc_reassembly_accept(
                &session->reassembly, frame, length,
                (uint32_t)(esp_timer_get_time() / 1000), &view);
            if (status == WSC_FRAGMENT_NEED_ACK) {
                uint8_t ack[18];
                size_t ack_len = wsc_build_fragment_ack(view.eap_id, ack, sizeof(ack));
                if (!ack_len || !send_payload(session, ack, ack_len)) {
                    event->kind = LAB_WPS_EVENT_DISCONNECTED;
                    return true;
                }
                continue;
            }
            if (status == WSC_FRAGMENT_COMPLETE) {
                length = wsc_materialize_message(&view, session->current,
                                                 ESP_FRAME_MAX);
                if (!length) {
                    event->kind = LAB_WPS_EVENT_QUEUE_OVERFLOW;
                    return true;
                }
                frame = session->current;
                event->fragmented = true;
            } else if (status == WSC_FRAGMENT_INVALID ||
                       status == WSC_FRAGMENT_OVERSIZE) {
                event->kind = LAB_WPS_EVENT_QUEUE_OVERFLOW;
                return true;
            } else if (status == WSC_FRAGMENT_TIMEOUT) {
                event->kind = LAB_WPS_EVENT_TIMEOUT;
                return true;
            }
        }
        if (frame != session->current) {
            if (length > ESP_FRAME_MAX) {
                event->kind = LAB_WPS_EVENT_QUEUE_OVERFLOW;
                return true;
            }
            memcpy(session->current, frame, length);
        }
        session->current_len = length;
        event->eap_id = length > 5U ? session->current[5] : 0;
        uint8_t ignored_id = 0;
        enum probe_message parsed = probe_parse(session->current, length, &ignored_id);
        unsigned type = message_type(session->current, length);
        if (parsed == PROBE_IDENTITY) event->kind = LAB_WPS_EVENT_IDENTITY;
        else if (parsed == PROBE_FAILURE) event->kind = LAB_WPS_EVENT_EAP_FAILURE;
        else if (parsed == PROBE_M1) {
            event->kind = LAB_WPS_EVENT_M1;
            event->authenticated = m3_parse_m1(session->current, length,
                                               &session->m1) &&
                session->m1.pin_mode &&
                memcmp(session->target, session->m1.enrollee_mac, 6) == 0 &&
                pin_session_keys(session->m1.public_key, session->m1.enrollee_nonce,
                                 session->m1.enrollee_mac, session->nr,
                                 session->uuid, session->pkr, &session->keys);
            if (event->authenticated) {
                memcpy(event->identity.manufacturer,
                       session->m1.manufacturer,
                       sizeof(event->identity.manufacturer));
                memcpy(event->identity.model_name, session->m1.model_name,
                       sizeof(event->identity.model_name));
                memcpy(event->identity.model_number, session->m1.model_number,
                       sizeof(event->identity.model_number));
                memcpy(event->identity.device_name, session->m1.device_name,
                       sizeof(event->identity.device_name));
            }
            if (event->authenticated && session->pin_len != 0U)
                event->authenticated = pin_derive_psks(
                    session->keys.authkey, session->pin, session->pin_len,
                    session->psk1, session->psk2);
        } else if (type == 7U) {
            event->kind = LAB_WPS_EVENT_M3;
            uint8_t tag[8];
            event->authenticated = m3_parse_m3(
                session->current, length, event->eap_id, session->nr, &session->m3) &&
                pin_authenticator(session->keys.authkey, session->txattrs,
                                  session->txattrs_len, session->current + 18,
                                  session->m3.body_len, tag) &&
                same8(tag, session->m3.authenticator);
            if (event->authenticated) {
                memcpy(session->ehash1, session->m3.e_hash1, 32);
                memcpy(session->ehash2, session->m3.e_hash2, 32);
                memcpy(event->bundle.pke, session->m1.public_key, 192);
                memcpy(event->bundle.pkr, session->pkr, 192);
                memcpy(event->bundle.e_hash1, session->m3.e_hash1, 32);
                memcpy(event->bundle.e_hash2, session->m3.e_hash2, 32);
                memcpy(event->bundle.e_nonce, session->m1.enrollee_nonce, 16);
                memcpy(event->bundle.authkey, session->keys.authkey, 32);
            }
            wipe(tag, sizeof(tag));
        } else if (type == 9U || type == 11U) {
            event->kind = type == 9U ? LAB_WPS_EVENT_M5 : LAB_WPS_EVENT_M7;
            decode_secure(session, type, event);
        } else if (type == 14U) {
            event->kind = LAB_WPS_EVENT_NACK;
            event->config_error_present = wps_parse_config_error(
                session->current, length, &event->config_error);
        } else {
            continue;
        }
        return true;
    }
    event->kind = LAB_WPS_EVENT_TIMEOUT;
    return true;
}

bool lab_wps_esp_session_open(lab_wps_esp_session_t **out,
                              lab_wps_session_t *session,
                              lab_radio_t *radio, uint32_t owner_token,
                              const lab_wps_request_t *request,
                              bool capture_pixie,
                              lab_wps_fatal_reason_t *failure_reason) {
    if (failure_reason) *failure_reason = LAB_WPS_FATAL_NONE;
    if (!out || !session || !radio || !request ||
        !lab_radio_accept_callback(radio, owner_token)) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_RADIO_START;
        return false;
    }
    lab_wps_esp_session_t *state = heap_caps_calloc(
        1, sizeof(*state), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    if (!state) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_ADAPTER_MEMORY;
        return false;
    }
    state->radio = radio;
    state->owner_token = owner_token;
    state->capture_pixie = capture_pixie;
    state->cancelled = request->cancelled;
    state->cancel_context = request->cancel_context;
    memcpy(state->target, request->bssid, sizeof(state->target));
    if (request->pin && request->pin_len <= 8U) {
        memcpy(state->pin, request->pin, request->pin_len);
        state->pin_len = request->pin_len;
    }
    uint8_t *scratch = radio->scratch;
    size_t scratch_size = radio->scratch_size;
    state->queue_storage = scratch_take(
        &scratch, &scratch_size, ESP_QUEUE_DEPTH * sizeof(queued_event_t));
    state->txattrs = scratch_take(&scratch, &scratch_size, ESP_TXATTRS_MAX);
    state->txpacket = scratch_take(&scratch, &scratch_size, ESP_TXPACKET_MAX);
    state->current = scratch_take(&scratch, &scratch_size, ESP_FRAME_MAX);
    state->fragment_storage = scratch_take(
        &scratch, &scratch_size, ESP_REASSEMBLY_MAX);
    if (!state->queue_storage || !state->txattrs || !state->txpacket ||
        !state->current || !state->fragment_storage) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_ADAPTER_SCRATCH;
        goto fail;
    }
    atomic_init(&state->dropped, 0);
    lab_wps_rx_gate_init(&state->rx_gate);
    state->queue = xQueueCreateStatic(
        ESP_QUEUE_DEPTH, sizeof(queued_event_t), state->queue_storage,
        &state->queue_control);
    if (!state->queue) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_ADAPTER_QUEUE;
        goto fail;
    }
    wsc_reassembly_init(&state->reassembly, state->fragment_storage,
                        ESP_REASSEMBLY_MAX, 3000U);
    state->callbacks = calloc(1, sizeof(*state->callbacks));
    if (!state->callbacks) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_ADAPTER_MEMORY;
        goto fail;
    }
    state->callbacks->wps_parse_scan_result = ignore_scan;
    state->callbacks->wifi_station_wps_start = ignore_start;
    state->callbacks->wps_sm_rx_eapol = rx_callback;
    state->callbacks->wps_start_pending = pending_callback;
    atomic_store_explicit(&active_session, state, memory_order_release);
    if (esp_wifi_set_wps_cb_internal(state->callbacks) != ESP_OK) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_CALLBACK_INSTALL;
        goto fail;
    }
    /* The private IDF API takes ownership after a successful install. */
    state->callbacks = NULL;
    if (esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event,
                                   state) != ESP_OK) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_EVENT_HANDLER;
        goto fail;
    }
    state->handler_registered = true;
    wifi_scan_config_t scan = {.bssid = state->target, .show_hidden = true};
    if (esp_wifi_scan_start(&scan, true) != ESP_OK) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_SCAN_START;
        goto fail;
    }
    uint16_t count = 1;
    wifi_ap_record_t ap = {0};
    if (esp_wifi_scan_get_ap_records(&count, &ap) != ESP_OK) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_SCAN_RESULTS;
        goto fail;
    }
    if (count == 0U || memcmp(ap.bssid, state->target, 6) != 0) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_TARGET_NOT_FOUND;
        goto fail;
    }
    if (!ap.wps) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_WPS_UNAVAILABLE;
        goto fail;
    }
    wifi_config_t config = {0};
    memcpy(config.sta.ssid, ap.ssid, sizeof(config.sta.ssid));
    memcpy(config.sta.bssid, state->target, 6);
    config.sta.bssid_set = 1;
    config.sta.channel = ap.primary;
    state->rf_band = ap.primary <= 14U ? 1U : 2U;
    if (esp_wifi_set_config(WIFI_IF_STA, &config) != ESP_OK) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_WIFI_CONFIG;
        goto fail;
    }
    if (!pin_crypto_init()) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_CRYPTO_INIT;
        goto fail;
    }
    if (esp_wifi_connect() != ESP_OK) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_WIFI_CONNECT;
        goto fail;
    }
    state->overall_deadline_us = esp_timer_get_time() + 25000000;
    state->stage_deadline_us = esp_timer_get_time() + 3000000;
    const lab_wps_session_ops_t ops = {
        .next_event = esp_next_event,
        .send_action = esp_send_action,
    };
    if (!lab_wps_session_init(session, &ops, state)) {
        if (failure_reason) *failure_reason = LAB_WPS_FATAL_SESSION_INIT;
        goto fail;
    }
    *out = state;
    return true;

fail:
    if (!lab_wps_esp_session_close(state)) lab_radio_quarantine(radio);
    return false;
}

unsigned lab_wps_esp_session_coalesced_m3(
    const lab_wps_esp_session_t *session)
{
    return session ? lab_wps_rx_gate_coalesced_m3(&session->rx_gate) : 0U;
}

bool lab_wps_esp_session_close(lab_wps_esp_session_t *session) {
    if (!session) return true;
    bool ok = true;
    lab_wps_esp_session_t *expected = session;
    atomic_compare_exchange_strong_explicit(&active_session, &expected, NULL,
                                             memory_order_acq_rel,
                                             memory_order_acquire);
    if (esp_wifi_set_wps_cb_internal(NULL) != ESP_OK) ok = false;
    if (session->handler_registered)
        if (esp_event_handler_unregister(
                WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event) != ESP_OK) ok = false;
    callback_drain();
    if (session->queue) vQueueDelete(session->queue);
    wsc_reassembly_reset(&session->reassembly);
    if (session->callbacks) free(session->callbacks);
    if (session->queue_storage)
        wipe(session->queue_storage, ESP_QUEUE_DEPTH * sizeof(queued_event_t));
    if (session->txattrs) wipe(session->txattrs, ESP_TXATTRS_MAX);
    if (session->txpacket) wipe(session->txpacket, ESP_TXPACKET_MAX);
    if (session->current) wipe(session->current, ESP_FRAME_MAX);
    if (session->fragment_storage)
        wipe(session->fragment_storage, ESP_REASSEMBLY_MAX);
    wipe(session, sizeof(*session));
    heap_caps_free(session);
    return ok;
}
