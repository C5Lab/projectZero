#ifndef WIFI_SHIELD_CAMPAIGN_H
#define WIFI_SHIELD_CAMPAIGN_H

#include "wifi_shield_core.h"

#define WIFI_SHIELD_CAMPAIGN_CORRELATION_US UINT64_C(30000000)
#define WIFI_SHIELD_CAMPAIGN_IDLE_US UINT64_C(60000000)
#define WIFI_SHIELD_CAMPAIGN_HISTORY_CAPACITY 4U

typedef enum {
    WIFI_SHIELD_THREAT_NONE = 0,
    WIFI_SHIELD_THREAT_WATCH,
    WIFI_SHIELD_THREAT_ATTACK,
    WIFI_SHIELD_THREAT_CRITICAL
} wifi_shield_threat_t;

typedef enum {
    WIFI_SHIELD_CAMPAIGN_CONFIDENCE_FULL = 0,
    WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED
} wifi_shield_campaign_confidence_t;

typedef enum {
    WIFI_SHIELD_CAMPAIGN_REASON_NONE = 0,
    WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ACTIVITY,
    WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ALERT,
    WIFI_SHIELD_CAMPAIGN_REASON_CROSS_VECTOR
} wifi_shield_campaign_reason_t;

typedef struct {
    uint64_t id;
    uint8_t bssid[6];
    uint64_t first_us;
    uint64_t last_us;
    uint32_t sources;
    uint32_t source_events[WIFI_SHIELD_SOURCE_COUNT];
    uint32_t rx_drops;
    uint32_t event_drops;
    uint32_t output_failures;
    uint32_t journal_drops;
    uint32_t completed_campaigns;
    bool sampled;
    wifi_shield_threat_t threat;
    wifi_shield_threat_t session_peak;
    wifi_shield_campaign_confidence_t confidence;
    wifi_shield_campaign_reason_t last_transition_reason;
    bool active;
} wifi_shield_campaign_snapshot_t;

typedef struct {
    uint64_t id;
    uint8_t bssid[6];
    wifi_shield_threat_t from;
    wifi_shield_threat_t to;
    uint32_t sources;
    wifi_shield_campaign_confidence_t confidence;
    wifi_shield_campaign_reason_t reason;
} wifi_shield_campaign_transition_t;

typedef struct {
    uint64_t timestamp_us;
    bool alert;
} wifi_shield_campaign_evidence_t;

typedef struct {
    wifi_shield_campaign_snapshot_t snapshot;
    wifi_shield_campaign_evidence_t
        history[WIFI_SHIELD_SOURCE_COUNT][WIFI_SHIELD_CAMPAIGN_HISTORY_CAPACITY];
    size_t history_count[WIFI_SHIELD_SOURCE_COUNT];
    uint64_t completed_through_us;
    bool has_completed_campaign;
} wifi_shield_campaign_entry_t;

/* Session-worker serialized fixed storage, intended for the Shield PSRAM arena.
 * No heap, pointers, frames, SSIDs, station addresses or transmitter identity.
 * BSSIDs are selected observed addresses, never attacker attribution. */
typedef struct {
    wifi_shield_campaign_entry_t targets[WIFI_SHIELD_TARGET_MAX];
    size_t target_count;
    uint64_t next_id;
} wifi_shield_campaign_core_t;

/* Copies selected BSSIDs only. Invalid input clears core; plan is not retained.
 * Input plan must not overlap core. Init is the session reset boundary. */
bool wifi_shield_campaign_init(wifi_shield_campaign_core_t *core,
                                const wifi_shield_channel_plan_t *plan);
/* Consumes upstream-qualified evidence once, including suppressed repeats.
 * Source/severity range and nonzero count are checked here; protocol type,
 * station and channel qualification belongs to the existing producer/core.
 * Returns true only for a new threat transition (NONE -> WATCH/ATTACK included).
 * Repeats still add saturating counts, sources and monotonically update last_us.
 * First is the campaign opening timestamp and never moves backward. Delayed
 * evidence may escalate even before first_us, but evidence at/before a completed
 * campaign watermark is inert. Each source retains four distinct timestamps
 * with alert flags, correlating inclusively within 30 s. Duplicate timestamps
 * merge alert flags without consuming history. If a fifth timestamp cannot be
 * retained, confidence becomes LIMITED for that campaign. The four newest
 * timestamps survive; incoming evidence still correlates before any eviction.
 * Threat never decreases in a campaign. session_peak and completed_campaigns
 * are session aggregates retained across campaign IDs. An idle gap >=60 s
 * completes the previous campaign exactly once and opens a new ID.
 * A cleared transition is returned on false; NULL output still consumes input. */
bool wifi_shield_campaign_observe(wifi_shield_campaign_core_t *core,
                                   const wifi_shield_event_t *event,
                                   wifi_shield_campaign_transition_t *transition);
/* Loss counters are per selected target/session, persist across campaigns, and
 * conservatively limit confidence until init, including pre-evidence loss.
 * Loss never creates a campaign, erases evidence, or refreshes idle time. */
void wifi_shield_campaign_note_loss(wifi_shield_campaign_core_t *core,
                                     const uint8_t bssid[6], uint32_t rx_drops,
                                     uint32_t event_drops, uint32_t output_failures);
void wifi_shield_campaign_note_journal_loss(
    wifi_shield_campaign_core_t *core, const uint8_t bssid[6],
    uint32_t journal_drops);
void wifi_shield_campaign_note_sampled(
    wifi_shield_campaign_core_t *core, const uint8_t bssid[6], bool sampled);
/* Returns number expired. Retains the last snapshot (active=false). Explicit
 * expiry records now_us as an inclusive completed-campaign watermark, retained
 * across future openings. Timestamps <= it cannot reopen or cross-correlate.
 * Implicit expiry on observe completes through previous last_us + IDLE_US - 1,
 * preserving the exact boundary event as new campaign evidence. Backward times
 * are inert. Each completed campaign increments the saturating session count.
 * Selected target slots are never evicted. */
size_t wifi_shield_campaign_expire(wifi_shield_campaign_core_t *core, uint64_t now_us);
/* Session stop closes every active campaign immediately while preserving its
 * retained evidence. The closure time becomes the inclusive watermark. */
size_t wifi_shield_campaign_close(wifi_shield_campaign_core_t *core,
                                  uint64_t now_us);
/* Copies selected target evidence even before first event or after expiry.
 * Returns false for invalid/unselected input, clearing a non-NULL output. */
bool wifi_shield_campaign_snapshot(const wifi_shield_campaign_core_t *core,
                                    const uint8_t bssid[6],
                                    wifi_shield_campaign_snapshot_t *snapshot);
/* Closed UART/JSON token table; NONE and unknown values have no token. */
const char *wifi_shield_campaign_reason_token(
    wifi_shield_campaign_reason_t reason);
bool wifi_shield_campaign_reason_valid(wifi_shield_threat_t threat,
    wifi_shield_campaign_reason_t reason, uint32_t sources);

#endif
