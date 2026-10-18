/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#ifndef HANDSHAKE_DUCB_GUARD_H
#define HANDSHAKE_DUCB_GUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t bssid[6];
    uint8_t client[6];
    char ssid[33];
    uint8_t channel;
    uint32_t slot_generation;
    uint32_t session_generation;
} hs_ducb_target_snapshot_t;

typedef bool (*hs_ducb_release_target_fn)(
    const hs_ducb_target_snapshot_t *target);

typedef struct {
    uint8_t *pcap;
    size_t pcap_size;
    uint8_t *hccapx;
    size_t hccapx_size;
    uint32_t session_generation;
} hs_capture_snapshot_t;

typedef struct {
    uint8_t bssid[6];
    uint8_t client[6];
    uint32_t slot_generation;
    uint32_t session_generation;
    bool active;
} hs_ducb_capture_identity_t;

typedef struct {
    uint8_t *bytes;
    size_t size;
    size_t capacity;
} hs_attempt_pcap_t;

typedef void *(*hs_snapshot_alloc_fn)(size_t size);
typedef void (*hs_snapshot_free_fn)(void *ptr);

#define HS_DUCB_TARGETS_PER_DWELL 3U

typedef bool (*hs_ducb_burst_tx_fn)(void *context, unsigned ordinal,
                                    bool ap_to_client);
typedef void (*hs_ducb_burst_delay_fn)(void *context, uint32_t delay_ms);
typedef bool (*hs_ducb_stop_requested_fn)(void *context);

typedef enum {
    HS_DUCB_STOP_COMPLETE = 0,
    HS_DUCB_STOP_WAIT,
    HS_DUCB_STOP_DEFER,
    HS_DUCB_STOP_PENDING,
} hs_ducb_stop_action_t;

void hs_ducb_target_snapshot_init(hs_ducb_target_snapshot_t *snapshot,
                                  const uint8_t bssid[6],
                                  const uint8_t client[6], const char *ssid,
                                  uint8_t channel, uint32_t slot_generation,
                                  uint32_t session_generation);
bool hs_ducb_target_snapshot_matches(const hs_ducb_target_snapshot_t *snapshot,
                                     const uint8_t bssid[6],
                                     const uint8_t client[6],
                                     uint32_t slot_generation,
                                     uint32_t session_generation);

bool hs_capture_snapshot_create(hs_capture_snapshot_t *snapshot,
                                const void *pcap, size_t pcap_size,
                                const void *hccapx, size_t hccapx_size,
                                hs_snapshot_alloc_fn alloc_fn,
                                hs_snapshot_free_fn free_fn);
void hs_capture_snapshot_release(hs_capture_snapshot_t *snapshot,
                                 hs_snapshot_free_fn free_fn);

bool hs_ducb_run_burst(void *context, hs_ducb_burst_tx_fn tx_fn,
                       hs_ducb_burst_delay_fn delay_fn,
                       hs_ducb_stop_requested_fn stop_requested_fn);
hs_ducb_stop_action_t hs_ducb_stop_decide(bool task_running,
                                          bool snapshot_owned,
                                          bool writer_active,
                                          uint32_t elapsed_ms,
                                          uint32_t wait_budget_ms);
unsigned hs_ducb_target_budget(void);
bool hs_ducb_reservation_try_set(uint32_t *attempt_generation,
                                 uint32_t *attempt_slot_generation,
                                 uint32_t slot_generation,
                                 uint32_t session_generation);
bool hs_ducb_reservation_release_if_matching(
    uint32_t *attempt_generation, uint32_t *attempt_slot_generation,
    uint32_t slot_generation, uint32_t session_generation);
unsigned hs_ducb_release_pending_targets(
    bool *have_target, const hs_ducb_target_snapshot_t *targets,
    unsigned target_count, hs_ducb_release_target_fn release_fn);
void hs_ducb_capture_identity_set(hs_ducb_capture_identity_t *identity,
                                  const uint8_t bssid[6],
                                  const uint8_t client[6],
                                  uint32_t slot_generation,
                                  uint32_t session_generation);
void hs_ducb_capture_identity_clear(hs_ducb_capture_identity_t *identity);
bool hs_ducb_capture_identity_matches(
    const hs_ducb_capture_identity_t *identity, const uint8_t bssid[6],
    const uint8_t client[6],
    uint32_t slot_generation, uint32_t session_generation);
bool hs_ducb_capture_identity_matches_ap(
    const hs_ducb_capture_identity_t *identity, const uint8_t bssid[6],
    uint32_t slot_generation, uint32_t session_generation);
bool hs_ducb_hccapx_matches_target(const hs_ducb_target_snapshot_t *target,
                                   const uint8_t mac_ap[6],
                                   const uint8_t mac_sta[6],
                                   const uint8_t *essid, size_t essid_len);
bool hs_ducb_capture_is_publishable(
    const hs_ducb_target_snapshot_t *target,
    const hs_capture_snapshot_t *capture, size_t expected_hccapx_size,
    const uint8_t mac_ap[6], const uint8_t mac_sta[6],
    const uint8_t *essid, size_t essid_len);
bool hs_attempt_pcap_init(hs_attempt_pcap_t *pcap, size_t capacity,
                          hs_snapshot_alloc_fn alloc_fn);
bool hs_attempt_pcap_append(hs_attempt_pcap_t *pcap, const void *frame,
                            size_t frame_size, uint32_t timestamp_us);
bool hs_attempt_pcap_append_if_matching(
    hs_attempt_pcap_t *pcap, const hs_ducb_capture_identity_t *identity,
    const uint8_t bssid[6], const uint8_t client[6],
    uint32_t slot_generation, uint32_t session_generation,
    const void *frame, size_t frame_size, uint32_t timestamp_us);
void hs_attempt_pcap_release(hs_attempt_pcap_t *pcap,
                             hs_snapshot_free_fn free_fn);
bool hs_ducb_has_suffix(const char *text, const char *suffix);
bool hs_ducb_writer_succeeded(size_t expected, size_t written, int flush_rc,
                              int sync_rc, int close_rc);

#endif
