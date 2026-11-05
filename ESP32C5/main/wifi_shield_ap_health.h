#ifndef WIFI_SHIELD_AP_HEALTH_H
#define WIFI_SHIELD_AP_HEALTH_H

#include "wifi_shield_core.h"
#include "wifi_shield_time.h"

typedef enum { WIFI_SHIELD_AP_UNKNOWN = 0, WIFI_SHIELD_AP_NO,
               WIFI_SHIELD_AP_YES } wifi_shield_ap_fact_t;
typedef enum { WIFI_SHIELD_AP_BAND_2GHZ = 0, WIFI_SHIELD_AP_BAND_5GHZ,
               WIFI_SHIELD_AP_BAND_6GHZ } wifi_shield_ap_band_t;
typedef enum { WIFI_SHIELD_AP_CONFIDENCE_NONE = 0,
    WIFI_SHIELD_AP_CONFIDENCE_OBSERVED, WIFI_SHIELD_AP_CONFIDENCE_LIMITED
} wifi_shield_ap_confidence_t;

#define WIFI_SHIELD_AP_RECOMMENDATION_MAX 10U

typedef enum {
    WIFI_SHIELD_AP_EVIDENCE_NONE = 0,
    WIFI_SHIELD_AP_EVIDENCE_WPS_ADVERTISED,
    WIFI_SHIELD_AP_EVIDENCE_PMF_NOT_REQUIRED,
    WIFI_SHIELD_AP_EVIDENCE_WPA3_NOT_ONLY,
    WIFI_SHIELD_AP_EVIDENCE_TRANSITION_MODE,
    WIFI_SHIELD_AP_EVIDENCE_LEGACY_CIPHER,
    WIFI_SHIELD_AP_EVIDENCE_CHANNEL_CHANGES,
    WIFI_SHIELD_AP_EVIDENCE_CSA_ACTIVITY,
    WIFI_SHIELD_AP_EVIDENCE_OBSERVED_NEIGHBORS,
    WIFI_SHIELD_AP_EVIDENCE_RSSI_OBSERVATIONS,
    WIFI_SHIELD_AP_EVIDENCE_AP_TSF_EPOCH_CHANGE,
    WIFI_SHIELD_AP_EVIDENCE_VALIDATED_CATALOG_MATCH
} wifi_shield_ap_recommendation_evidence_t;

typedef struct {
    uint32_t action; /* Exactly one WIFI_SHIELD_AP_RECOMMEND_* bit. */
    wifi_shield_ap_recommendation_evidence_t evidence;
    wifi_shield_ap_confidence_t confidence;
} wifi_shield_ap_recommendation_detail_t;

enum {
    WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS = 1U << 0,
    WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF = 1U << 1,
    WIFI_SHIELD_AP_RECOMMEND_PREFER_WPA3_ONLY = 1U << 2,
    WIFI_SHIELD_AP_RECOMMEND_REVIEW_TRANSITION_MODE = 1U << 3,
    WIFI_SHIELD_AP_RECOMMEND_REVIEW_LEGACY_CIPHER = 1U << 4,
    WIFI_SHIELD_AP_RECOMMEND_CHANNEL_UNSTABLE = 1U << 5,
    WIFI_SHIELD_AP_RECOMMEND_CHANNEL_CONGESTED = 1U << 6,
    WIFI_SHIELD_AP_RECOMMEND_WEAK_OR_UNSTABLE_SIGNAL = 1U << 7,
    WIFI_SHIELD_AP_RECOMMEND_TSF_EPOCH_CHANGE_OBSERVED = 1U << 8,
    /* Source compatibility for pre-rename V2 callers. The UART/JSON token is
     * the evidence-bounded tsf_epoch_change_observed name. */
    WIFI_SHIELD_AP_RECOMMEND_AP_RESTART_OBSERVED =
        WIFI_SHIELD_AP_RECOMMEND_TSF_EPOCH_CHANGE_OBSERVED,
    WIFI_SHIELD_AP_RECOMMEND_FIRMWARE_REVIEW = 1U << 9
};

typedef struct {
    uint8_t bssid[6];
    uint16_t sequence; /* 12-bit management sequence, not sequence-control. */
    int8_t rssi;
    uint8_t channel;
    wifi_shield_ap_band_t band;
    uint16_t interval_tu;
    bool retry;
    wifi_shield_time_stamp_t time;
} wifi_shield_ap_beacon_t;

typedef struct {
    wifi_shield_ap_fact_t wps, pmf_required, wpa3_supported, wpa3_only;
    wifi_shield_ap_fact_t transition_mode, legacy_cipher;
    /* Caller must provide a separately validated catalog match. This module
     * cannot authenticate a match and never derives one from OUI/SSID. */
    bool validated_catalog_match;
} wifi_shield_ap_posture_t;

typedef struct {
    bool sampled;
    uint32_t rx_drops, event_drops, journal_drops; /* New local contributions. */
} wifi_shield_ap_quality_t;

typedef struct {
    uint32_t beacons, sequence_gaps, interval_pairs;
    int16_t rssi_average, rssi_min, rssi_max;
    uint64_t jitter_average_us, jitter_max_us;
    uint32_t epoch_changes, channel_changes, csa_events;
    uint32_t retry_beacons, retry_events, deauth_events, disassoc_events;
    uint32_t rx_drops, event_drops, journal_drops;
    bool sampled;
    uint32_t same_channel_neighbors, overlapping_channel_neighbors;
    uint32_t recommendations;
    uint8_t recommendation_count;
    wifi_shield_ap_recommendation_detail_t
        recommendation_details[WIFI_SHIELD_AP_RECOMMENDATION_MAX];
    wifi_shield_ap_confidence_t continuity_confidence, timing_confidence;
} wifi_shield_ap_health_snapshot_t;

typedef struct {
    bool used, continuity_limited, timing_limited;
    uint8_t bssid[6];
    wifi_shield_ap_beacon_t last;
    wifi_shield_ap_posture_t posture;
    wifi_shield_ap_health_snapshot_t measurements;
    int64_t rssi_sum;
    uint64_t jitter_sum_us;
} wifi_shield_ap_health_entry_t;

/* Fixed caller-owned PSRAM arena storage; serialize calls in session worker.
 * No eviction or heap. Caller admits selected BSSIDs and any explicitly wanted
 * neighbor evidence. Init resets a session; no pointers to input are retained. */
typedef struct {
    wifi_shield_ap_health_entry_t entries[WIFI_SHIELD_TARGET_MAX];
} wifi_shield_ap_health_core_t;

void wifi_shield_ap_health_init(wifi_shield_ap_health_core_t *core);
bool wifi_shield_ap_health_observe_beacon(wifi_shield_ap_health_core_t *core,
    const wifi_shield_ap_beacon_t *beacon);
bool wifi_shield_ap_health_note_event(wifi_shield_ap_health_core_t *core,
    const uint8_t bssid[6], wifi_shield_event_type_t type, uint32_t count);
/* Replaces the complete posture; UNKNOWN fields withdraw earlier advice. */
bool wifi_shield_ap_health_note_posture(wifi_shield_ap_health_core_t *core,
    const uint8_t bssid[6], const wifi_shield_ap_posture_t *posture);
/* Session-sticky limitations. They never create AP packet-loss claims. */
bool wifi_shield_ap_health_note_quality(wifi_shield_ap_health_core_t *core,
    const uint8_t bssid[6], const wifi_shield_ap_quality_t *quality);
/* Clears output on failure. Output must not overlap core or bssid.
 * Gaps are management sequence gaps, not missing beacons or AP packet loss.
 * Jitter uses exact same-epoch TSF and unchanged advertised interval/channel.
 * It is the residual to the nearest positive interval multiple, independent
 * of sequence delta; other management frames use the same sequence space.
 * Repeated exact TSF in the same epoch does not create a cadence pair or
 * change timing confidence. An initial exact TSF of zero is valid.
 * TSF advice reports a spoofable exact epoch discontinuity only. It is not
 * evidence that the selected AP restarted.
 * Congestion: >=3 distinct fresh (<30 s age), >=2-beacon neighbors at >=-75
 * dBm on same channel or 2.4 GHz channel distance <=4 (excludes channel 14).
 * It is observed occupancy evidence, not utilization or a channel choice.
 * Signal advice: >=2 beacons and rounded mean <=-75 or RSSI range >=15 dB.
 * Instability: >=2 observed channel/band changes. CSA activity is retained as
 * threat evidence but cannot establish that the selected AP changed channel.
 * Measurements are retained even when confidence is limited. */
bool wifi_shield_ap_health_snapshot(const wifi_shield_ap_health_core_t *core,
    const uint8_t bssid[6], wifi_shield_ap_health_snapshot_t *out);
/* Accepts exactly one bit; returns NULL for unknown/combined bits. */
const char *wifi_shield_ap_recommendation_token(uint32_t recommendation);
const char *wifi_shield_ap_recommendation_evidence_token(
    wifi_shield_ap_recommendation_evidence_t evidence);
bool wifi_shield_ap_recommendation_detail_valid(
    const wifi_shield_ap_recommendation_detail_t *detail);
#endif



