#ifndef WIFI_SHIELD_JOURNAL_H
#define WIFI_SHIELD_JOURNAL_H

#include "wifi_shield_ap_health.h"
#include "wifi_shield_campaign.h"

#define WIFI_SHIELD_JOURNAL_LINE_MAX 1024U
#define WIFI_SHIELD_JOURNAL_PATH_MAX 128U
#define WIFI_SHIELD_JOURNAL_AGGREGATE_WINDOW_US UINT64_C(1000000)
#define WIFI_SHIELD_JOURNAL_RECOMMENDATION_MASK UINT32_C(1023)

typedef enum {
    WIFI_SHIELD_JOURNAL_SESSION_START = 0,
    WIFI_SHIELD_JOURNAL_EVENT,
    WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION,
    WIFI_SHIELD_JOURNAL_AP_HEALTH,
    WIFI_SHIELD_JOURNAL_RECOMMENDATION,
    WIFI_SHIELD_JOURNAL_STORAGE_DEGRADED,
    WIFI_SHIELD_JOURNAL_SESSION_TERMINAL,
    /* Provisional radio uncertainty; a later recovery may still append the
     * one actual terminal record. */
    WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN
} wifi_shield_journal_type_t;

typedef enum {
    WIFI_SHIELD_JOURNAL_UNAVAILABLE = 0,
    WIFI_SHIELD_JOURNAL_ACTIVE,
    WIFI_SHIELD_JOURNAL_DEGRADED,
    WIFI_SHIELD_JOURNAL_QUOTA_REACHED,
    WIFI_SHIELD_JOURNAL_FINALIZED,
    WIFI_SHIELD_JOURNAL_INCOMPLETE
} wifi_shield_journal_state_t;

typedef enum {
    WIFI_SHIELD_JOURNAL_STOPPED = 0,
    WIFI_SHIELD_JOURNAL_BUSY,
    WIFI_SHIELD_JOURNAL_INVALID,
    WIFI_SHIELD_JOURNAL_TIMEOUT,
    WIFI_SHIELD_JOURNAL_QUEUE_OVERFLOW,
    WIFI_SHIELD_JOURNAL_RESTORE_FAILED,
    WIFI_SHIELD_JOURNAL_OUTPUT_FAILED,
    WIFI_SHIELD_JOURNAL_NO_MEM
} wifi_shield_journal_outcome_t;

enum {
    WIFI_SHIELD_JOURNAL_TIME_MONOTONIC = 1U << 0,
    WIFI_SHIELD_JOURNAL_TIME_AP_TSF = 1U << 1,
    WIFI_SHIELD_JOURNAL_TIME_GPS = 1U << 2
};
#define WIFI_SHIELD_JOURNAL_TIME_MASK UINT32_C(7)

/* Scalar copy; no file handle or arbitrary JSON. Path includes its NUL and is
 * bounded ASCII. JSON escapes controls/quotes; UART requires token-safe ASCII.
 * The worker owns/acknowledges degraded_notice_pending after successful output;
 * pure const formatters cannot consume or re-arm that one-shot notice. */
typedef struct {
    wifi_shield_journal_state_t state;
    char path[WIFI_SHIELD_JOURNAL_PATH_MAX];
    uint64_t bytes_written;
    uint32_t records_written, failures, dropped;
    uint32_t queue_high_water;
    uint32_t admission_drops;
    uint32_t encoding_failures;
    uint32_t write_failures;
    uint32_t sync_failures;
    uint32_t finalization_failures;
    uint32_t summary_failures;
    uint32_t latest_failures;
    uint32_t time_sources;
    bool degraded_notice_pending;
} wifi_shield_journal_status_t;

/* No raw frames, credentials, keys, protocol blobs, station identities or decoy
 * material. Each type serializes only its own normalized payload. BSSID is
 * observed evidence, never attacker identity. AP time is spoofable/relative.
 * Trusted GPS wall time is an indivisible epoch/source/uncertainty tuple.
 * Untrusted records require both epoch_ms and time_uncertainty_ms to be zero. */
typedef struct {
    wifi_shield_journal_type_t type;
    uint32_t boot_id, session_id;
    uint64_t sequence;
    wifi_shield_time_stamp_t time;
    bool has_bssid;
    uint8_t bssid[6];
    bool gps_time_trusted;
    uint64_t epoch_ms;
    uint32_t time_uncertainty_ms;
    size_t target_count;
    wifi_shield_source_t event_source;
    wifi_shield_event_type_t event_type;
    /* High-rate Deauth/Disassoc/CSA evidence is coalesced before admission.
     * Zero preserves the legacy one-record/one-event encoding for all other
     * producers. Aggregate timestamps are monotonic boot time and include the
     * first and last observation represented by event_count. */
    uint32_t event_count;
    uint64_t event_first_boot_us;
    uint64_t event_last_boot_us;
    wifi_shield_campaign_transition_t campaign;
    wifi_shield_ap_health_snapshot_t ap_health;
    /* Complete replacement-set envelope. A new AP_HEALTH rec_rev opens a
     * replacement set; its following RECOMMENDATION records repeat rev/count
     * and carry deterministic zero-based indexes. A periodic AP_HEALTH with an
     * already-complete unchanged rec_rev is only a reference and has no
     * following details. Count zero explicitly withdraws the previous set.
     * Missing records in a newly opened set remain detectable. */
    uint32_t recommendation_set_revision;
    uint8_t recommendation_set_index;
    uint8_t recommendation_set_count;
    wifi_shield_ap_recommendation_detail_t recommendation;
    wifi_shield_journal_status_t storage;
    wifi_shield_journal_outcome_t outcome;
} wifi_shield_journal_record_t;

/* Returns bytes excluding NUL, including LF. -1 preserves ALL caller bytes.
 * boot_id/session_id/sequence are nonzero. NONE AP time requires zero AP fields;
 * AP health/recommendations/transitions require a validated observed BSSID.
 * Even valid records can exceed the line bound; reject without truncation.
 * Input and output must not overlap. No allocation, global state or I/O. */
int wifi_shield_journal_encode(char *out, size_t capacity,
                                const wifi_shield_journal_record_t *record);
#endif
