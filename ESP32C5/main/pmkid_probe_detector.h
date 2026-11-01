#pragma once

#include <stddef.h>
#include <stdint.h>

#define PMKID_PROBE_SLOTS 32U
#define PMKID_PROBE_WINDOW_US INT64_C(2000000)

typedef enum {
    PMKID_PROBE_NONE = 0,
    PMKID_PROBE_AUTH_SEEN,
    PMKID_PROBE_ASSOC_SEQUENCE,
} pmkid_probe_result_t;

typedef struct {
    uint8_t bssid[6];
    uint8_t sta[6];
    uint8_t channel;
    int64_t auth_us;
    int64_t last_seen_us;
    uint8_t used;
} pmkid_probe_slot_t;

typedef struct {
    pmkid_probe_slot_t slots[PMKID_PROBE_SLOTS];
} pmkid_probe_detector_t;

void pmkid_probe_reset(pmkid_probe_detector_t *detector);

pmkid_probe_result_t pmkid_probe_observe(
    pmkid_probe_detector_t *detector, const uint8_t *frame, size_t length,
    uint8_t rx_channel, int64_t now_us,
    uint8_t bssid_out[6], uint8_t sta_out[6]);
