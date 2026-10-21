/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "handshake_ducb_guard.h"

#include <string.h>

void hs_ducb_target_snapshot_init(hs_ducb_target_snapshot_t *snapshot,
                                  const uint8_t bssid[6],
                                  const uint8_t client[6], const char *ssid,
                                  uint8_t channel, uint32_t slot_generation,
                                  uint32_t session_generation)
{
    if (!snapshot) return;
    memset(snapshot, 0, sizeof(*snapshot));
    if (bssid) memcpy(snapshot->bssid, bssid, sizeof(snapshot->bssid));
    if (client) memcpy(snapshot->client, client, sizeof(snapshot->client));
    if (ssid) {
        strncpy(snapshot->ssid, ssid, sizeof(snapshot->ssid) - 1U);
        snapshot->ssid[sizeof(snapshot->ssid) - 1U] = '\0';
    }
    snapshot->channel = channel;
    snapshot->slot_generation = slot_generation;
    snapshot->session_generation = session_generation;
}

bool hs_ducb_target_snapshot_matches(const hs_ducb_target_snapshot_t *snapshot,
                                     const uint8_t bssid[6],
                                     const uint8_t client[6],
                                     uint32_t slot_generation,
                                     uint32_t session_generation)
{
    return snapshot && bssid && client && slot_generation != 0U &&
           session_generation != 0U &&
           snapshot->slot_generation == slot_generation &&
           snapshot->session_generation == session_generation &&
           memcmp(snapshot->bssid, bssid, sizeof(snapshot->bssid)) == 0 &&
           memcmp(snapshot->client, client, sizeof(snapshot->client)) == 0;
}

void hs_capture_snapshot_release(hs_capture_snapshot_t *snapshot,
                                 hs_snapshot_free_fn free_fn)
{
    if (!snapshot) return;
    if (free_fn) {
        if (snapshot->pcap) free_fn(snapshot->pcap);
        if (snapshot->hccapx) free_fn(snapshot->hccapx);
    }
    memset(snapshot, 0, sizeof(*snapshot));
}

bool hs_capture_snapshot_create(hs_capture_snapshot_t *snapshot,
                                const void *pcap, size_t pcap_size,
                                const void *hccapx, size_t hccapx_size,
                                hs_snapshot_alloc_fn alloc_fn,
                                hs_snapshot_free_fn free_fn)
{
    if (!snapshot || !pcap || pcap_size == 0U || !alloc_fn || !free_fn) {
        return false;
    }

    hs_capture_snapshot_t owned = {0};
    owned.pcap = alloc_fn(pcap_size);
    if (!owned.pcap) return false;
    memcpy(owned.pcap, pcap, pcap_size);
    owned.pcap_size = pcap_size;

    if (hccapx && hccapx_size != 0U) {
        owned.hccapx = alloc_fn(hccapx_size);
        if (!owned.hccapx) {
            hs_capture_snapshot_release(&owned, free_fn);
            return false;
        }
        memcpy(owned.hccapx, hccapx, hccapx_size);
        owned.hccapx_size = hccapx_size;
    }

    *snapshot = owned;
    return true;
}

bool hs_ducb_run_burst(void *context, hs_ducb_burst_tx_fn tx_fn,
                       hs_ducb_burst_delay_fn delay_fn,
                       hs_ducb_stop_requested_fn stop_requested_fn)
{
    if (!tx_fn || !delay_fn) return false;
    bool any_tx_succeeded = false;
    for (unsigned ordinal = 0U; ordinal < 8U; ++ordinal) {
        if (stop_requested_fn && stop_requested_fn(context)) return false;
        any_tx_succeeded = tx_fn(context, ordinal, ordinal < 5U) ||
                           any_tx_succeeded;
        delay_fn(context, 10U);
    }
    return any_tx_succeeded &&
           !(stop_requested_fn && stop_requested_fn(context));
}

hs_ducb_stop_action_t hs_ducb_stop_decide(bool task_running,
                                          bool snapshot_owned,
                                          bool writer_active,
                                          uint32_t elapsed_ms,
                                          uint32_t wait_budget_ms)
{
    if (!task_running) return HS_DUCB_STOP_COMPLETE;
    if (elapsed_ms < wait_budget_ms) return HS_DUCB_STOP_WAIT;
    if (snapshot_owned || writer_active) return HS_DUCB_STOP_DEFER;
    return HS_DUCB_STOP_PENDING;
}

unsigned hs_ducb_target_budget(void)
{
    return HS_DUCB_TARGETS_PER_DWELL;
}

bool hs_ducb_reservation_try_set(uint32_t *attempt_generation,
                                 uint32_t *attempt_slot_generation,
                                 uint32_t slot_generation,
                                 uint32_t session_generation)
{
    if (!attempt_generation || !attempt_slot_generation ||
        slot_generation == 0U || session_generation == 0U ||
        (*attempt_generation == session_generation &&
         *attempt_slot_generation == slot_generation)) {
        return false;
    }
    *attempt_generation = session_generation;
    *attempt_slot_generation = slot_generation;
    return true;
}

bool hs_ducb_reservation_release_if_matching(
    uint32_t *attempt_generation, uint32_t *attempt_slot_generation,
    uint32_t slot_generation, uint32_t session_generation)
{
    if (!attempt_generation || !attempt_slot_generation ||
        *attempt_generation != session_generation ||
        *attempt_slot_generation != slot_generation) {
        return false;
    }
    *attempt_generation = 0U;
    *attempt_slot_generation = 0U;
    return true;
}

unsigned hs_ducb_release_pending_targets(
    bool *have_target, const hs_ducb_target_snapshot_t *targets,
    unsigned target_count, hs_ducb_release_target_fn release_fn)
{
    if (!have_target || !targets || !release_fn) return 0U;
    unsigned released = 0U;
    for (unsigned i = 0U; i < target_count; ++i) {
        if (!have_target[i]) continue;
        if (release_fn(&targets[i])) released++;
        have_target[i] = false;
    }
    return released;
}

void hs_ducb_capture_identity_set(hs_ducb_capture_identity_t *identity,
                                  const uint8_t bssid[6],
                                  const uint8_t client[6],
                                  uint32_t slot_generation,
                                  uint32_t session_generation)
{
    if (!identity) return;
    memset(identity, 0, sizeof(*identity));
    if (!bssid || !client || slot_generation == 0U ||
        session_generation == 0U) return;
    memcpy(identity->bssid, bssid, sizeof(identity->bssid));
    memcpy(identity->client, client, sizeof(identity->client));
    identity->slot_generation = slot_generation;
    identity->session_generation = session_generation;
    identity->active = true;
}

void hs_ducb_capture_identity_clear(hs_ducb_capture_identity_t *identity)
{
    if (identity) memset(identity, 0, sizeof(*identity));
}

bool hs_ducb_capture_identity_matches(
    const hs_ducb_capture_identity_t *identity, const uint8_t bssid[6],
    const uint8_t client[6],
    uint32_t slot_generation, uint32_t session_generation)
{
    return hs_ducb_capture_identity_matches_ap(
               identity, bssid, slot_generation, session_generation) &&
           client &&
           memcmp(identity->client, client, sizeof(identity->client)) == 0;
}

bool hs_ducb_capture_identity_matches_ap(
    const hs_ducb_capture_identity_t *identity, const uint8_t bssid[6],
    uint32_t slot_generation, uint32_t session_generation)
{
    return identity && identity->active && bssid && slot_generation != 0U &&
           session_generation != 0U &&
           identity->slot_generation == slot_generation &&
           identity->session_generation == session_generation &&
           memcmp(identity->bssid, bssid, sizeof(identity->bssid)) == 0;
}

bool hs_ducb_hccapx_matches_target(const hs_ducb_target_snapshot_t *target,
                                   const uint8_t mac_ap[6],
                                   const uint8_t mac_sta[6],
                                   const uint8_t *essid, size_t essid_len)
{
    if (!target || !mac_ap || !mac_sta || !essid || essid_len > 32U) {
        return false;
    }
    const size_t target_len = strlen(target->ssid);
    return target_len == essid_len &&
           memcmp(target->bssid, mac_ap, sizeof(target->bssid)) == 0 &&
           memcmp(target->client, mac_sta, sizeof(target->client)) == 0 &&
           memcmp(target->ssid, essid, essid_len) == 0;
}

bool hs_ducb_capture_is_publishable(
    const hs_ducb_target_snapshot_t *target,
    const hs_capture_snapshot_t *capture, size_t expected_hccapx_size,
    const uint8_t mac_ap[6], const uint8_t mac_sta[6],
    const uint8_t *essid, size_t essid_len)
{
    return target && capture && capture->pcap && capture->pcap_size != 0U &&
           capture->hccapx && expected_hccapx_size != 0U &&
           capture->hccapx_size == expected_hccapx_size &&
           capture->session_generation == target->session_generation &&
           hs_ducb_hccapx_matches_target(target, mac_ap, mac_sta, essid,
                                         essid_len);
}

typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} hs_pcap_global_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} hs_pcap_record_header_t;

bool hs_attempt_pcap_init(hs_attempt_pcap_t *pcap, size_t capacity,
                          hs_snapshot_alloc_fn alloc_fn)
{
    if (!pcap || !alloc_fn || capacity < sizeof(hs_pcap_global_header_t)) {
        return false;
    }
    hs_attempt_pcap_t fresh = {0};
    fresh.bytes = alloc_fn(capacity);
    if (!fresh.bytes) return false;
    const hs_pcap_global_header_t header = {
        .magic_number = 0xa1b2c3d4U,
        .version_major = 2U,
        .version_minor = 4U,
        .thiszone = 0,
        .sigfigs = 0U,
        .snaplen = 65535U,
        .network = 105U,
    };
    memcpy(fresh.bytes, &header, sizeof(header));
    fresh.size = sizeof(header);
    fresh.capacity = capacity;
    *pcap = fresh;
    return true;
}

bool hs_attempt_pcap_append(hs_attempt_pcap_t *pcap, const void *frame,
                            size_t frame_size, uint32_t timestamp_us)
{
    if (!pcap || !pcap->bytes || !frame || frame_size == 0U ||
        frame_size > 65535U ||
        frame_size > SIZE_MAX - sizeof(hs_pcap_record_header_t) ||
        pcap->size > pcap->capacity ||
        sizeof(hs_pcap_record_header_t) + frame_size >
            pcap->capacity - pcap->size) {
        return false;
    }
    const hs_pcap_record_header_t record = {
        .ts_sec = timestamp_us / 1000000U,
        .ts_usec = timestamp_us % 1000000U,
        .incl_len = (uint32_t)frame_size,
        .orig_len = (uint32_t)frame_size,
    };
    memcpy(pcap->bytes + pcap->size, &record, sizeof(record));
    pcap->size += sizeof(record);
    memcpy(pcap->bytes + pcap->size, frame, frame_size);
    pcap->size += frame_size;
    return true;
}

bool hs_attempt_pcap_append_if_matching(
    hs_attempt_pcap_t *pcap, const hs_ducb_capture_identity_t *identity,
    const uint8_t bssid[6], const uint8_t client[6],
    uint32_t slot_generation, uint32_t session_generation,
    const void *frame, size_t frame_size, uint32_t timestamp_us)
{
    return hs_ducb_capture_identity_matches(
               identity, bssid, client, slot_generation,
               session_generation) &&
           hs_attempt_pcap_append(pcap, frame, frame_size, timestamp_us);
}

void hs_attempt_pcap_release(hs_attempt_pcap_t *pcap,
                             hs_snapshot_free_fn free_fn)
{
    if (!pcap) return;
    if (pcap->bytes && free_fn) free_fn(pcap->bytes);
    memset(pcap, 0, sizeof(*pcap));
}

bool hs_ducb_has_suffix(const char *text, const char *suffix)
{
    if (!text || !suffix) return false;
    const size_t text_len = strlen(text);
    const size_t suffix_len = strlen(suffix);
    return suffix_len <= text_len &&
           memcmp(text + text_len - suffix_len, suffix, suffix_len) == 0;
}

bool hs_ducb_writer_succeeded(size_t expected, size_t written, int flush_rc,
                              int sync_rc, int close_rc)
{
    return written == expected && flush_rc == 0 && sync_rc == 0 &&
           close_rc == 0;
}
