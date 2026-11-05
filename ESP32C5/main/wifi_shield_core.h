#ifndef WIFI_SHIELD_CORE_H
#define WIFI_SHIELD_CORE_H

#include "wifi_shield_channel.h"
#include "wifi_shield_wps.h"

typedef enum {
    WIFI_SHIELD_SOURCE_DEAUTH = 0,
    WIFI_SHIELD_SOURCE_WPS,
    WIFI_SHIELD_SOURCE_SAE,
    WIFI_SHIELD_SOURCE_TRUST,
    WIFI_SHIELD_SOURCE_PMKID
} wifi_shield_source_t;

typedef enum {
    WIFI_SHIELD_SEVERITY_INFO = 0,
    WIFI_SHIELD_SEVERITY_WARN,
    WIFI_SHIELD_SEVERITY_ALERT
} wifi_shield_severity_t;

typedef enum {
    WIFI_SHIELD_EVENT_DEAUTH = 0,
    WIFI_SHIELD_EVENT_DISASSOC,
    WIFI_SHIELD_EVENT_CSA,
    WIFI_SHIELD_EVENT_WPS_ACTIVITY,
    WIFI_SHIELD_EVENT_WPS_RETRY_BURST,
    WIFI_SHIELD_EVENT_WPS_ANOMALY,
    WIFI_SHIELD_EVENT_SAE_ACTIVITY,
    WIFI_SHIELD_EVENT_SAE_ANOMALY,
    WIFI_SHIELD_EVENT_TRUST_DRIFT,
    WIFI_SHIELD_EVENT_PMKID_SEQUENCE
} wifi_shield_event_type_t;

#define WIFI_SHIELD_SOURCE_COUNT 5U
#define WIFI_SHIELD_RATE_LIMIT_CAPACITY 64U
#define WIFI_SHIELD_RATE_WINDOW_MS 10000U
#define WIFI_SHIELD_DEAUTH_TYPE_COUNT 3U
#define WIFI_SHIELD_COMPACT_EVENT_CAPACITY 24U
#define WIFI_SHIELD_DEAUTH_EVENT_CAPACITY 16U
#define WIFI_SHIELD_COMPACT_BYTES 64U

typedef enum {
    WIFI_SHIELD_COMPACT_DEAUTH = 0,
    WIFI_SHIELD_COMPACT_DISASSOC,
    WIFI_SHIELD_COMPACT_CSA,
    WIFI_SHIELD_COMPACT_AUTH,
    WIFI_SHIELD_COMPACT_ASSOC,
    WIFI_SHIELD_COMPACT_REASSOC
} wifi_shield_compact_kind_t;

typedef struct {
    wifi_shield_compact_kind_t kind;
    uint32_t generation;
    uint8_t bytes[WIFI_SHIELD_COMPACT_BYTES];
    uint8_t length;
    uint8_t bssid[6];
    uint8_t station[6];
    uint8_t channel;
    int8_t rssi;
    int64_t rx_us;
} wifi_shield_compact_event_t;

typedef struct {
    wifi_shield_source_t source;
    wifi_shield_event_type_t type;
    wifi_shield_severity_t severity;
    uint8_t bssid[6];
    uint8_t station[6];
    uint8_t channel;
    uint32_t count;
    uint32_t window_ms;
    wifi_shield_wps_message_t wps_message;
    uint64_t timestamp_us;
} wifi_shield_event_t;

typedef struct {
    bool used;
    wifi_shield_source_t source;
    wifi_shield_event_type_t type;
    uint8_t bssid[6];
    uint8_t station[6];
    uint64_t window_started_us;
    uint32_t count;
    bool threshold_published;
} wifi_shield_rate_limit_t;

typedef struct {
    uint64_t window_started_us[WIFI_SHIELD_DEAUTH_TYPE_COUNT];
    uint8_t used_mask;
} wifi_shield_deauth_rate_limit_t;

/* Serialized by the session worker. Borrows its immutable plan for one session:
 * the plan outlives this core and is wiped only after the worker has joined.
 * No frame/payload pointers, protocol cores, TX hooks or heap ownership. */
typedef struct {
    const wifi_shield_channel_plan_t *plan;
    wifi_shield_rate_limit_t rate_limits[WIFI_SHIELD_RATE_LIMIT_CAPACITY];
    /* One fixed entry per immutable target. This keeps high-priority Deauth,
     * Disassoc and CSA suppression independent from untrusted activity-flow
     * diversity. The enclosing Shield state lives in the PSRAM arena. */
    wifi_shield_deauth_rate_limit_t
        deauth_rate_limits[WIFI_SHIELD_TARGET_MAX];
    uint32_t source_events[WIFI_SHIELD_SOURCE_COUNT];
    uint32_t alerts;
    uint32_t received;
    uint32_t filtered;
    uint32_t wps_fragments;
    uint32_t rx_drops;
    uint32_t event_drops;
    uint32_t output_failures;
    uint8_t current_channel;
    bool running;
    bool stopping;
    bool active_defence;
    bool pmkid_decoy;
    bool multi_vector;
    bool protect_all;
} wifi_shield_core_t;

typedef struct {
    uint32_t source_events[WIFI_SHIELD_SOURCE_COUNT];
    uint32_t alerts;
    /* Internal regression/diagnostic snapshot. The Shield wire formatter does
     * not serialize these fields, preserving the existing STATUS bytes. */
    uint32_t received;
    uint32_t filtered;
    uint32_t wps_fragments;
    uint32_t rx_drops;
    uint32_t event_drops;
    uint32_t output_failures;
    size_t target_count;
    size_t channel_count;
    uint8_t channels[WIFI_SHIELD_TARGET_MAX];
    uint8_t current_channel;
    bool running;
    bool stopping;
    bool active_defence;
    bool pmkid_decoy;
    bool multi_vector;
    bool protect_all;
} wifi_shield_status_t;

/* Init also resets all session state; it never mutates the borrowed plan.
 * Pass a validated channel-plan snapshot, or NULL for an inert core. */
void wifi_shield_core_init(wifi_shield_core_t *core,
                           const wifi_shield_channel_plan_t *plan);
bool wifi_shield_core_selected(const wifi_shield_core_t *core,
                               const uint8_t bssid[6]);
/* Consume bounded metadata synchronously, retaining no event pointer.
 * Source/type/severity must match: activity/PMKID INFO, retry WARN,
 * Deauth/Disassoc/CSA/Trust/protocol anomalies ALERT. Invalid or unselected
 * evidence is inert. WPS/SAE/PMKID require a distinct unicast station; other
 * sources allow aggregate/broadcast station identities.
 * Each nonzero count contributes to saturating source totals even if suppressed.
 * Count is a new contribution, never a cumulative upstream counter. Deauth,
 * Disassoc and CSA publish at most once per selected BSSID/type in a fixed
 * 10-second window. Their dedicated per-target policy cannot be starved by
 * activity-flow identity capacity. For retry evidence, publish once on reaching
 * 8 in a fixed 10-second window. Activity publishes once per
 * BSSID/station/type per 10-second window. The window starts on the first
 * contribution; equality at 10 seconds opens the next window.
 * Timestamps preceding the current window start contribute only to source
 * totals, without changing that window/count. window_ms is upstream display
 * metadata; it cannot override these fixed policy windows. Other event types
 * are already module-qualified and pass.
 * Identities persist until init, with no eviction. New rate-limited identities
 * at capacity increment event_drops, saturating, without replacing old entries.
 * alerts counts published ALERT events, not evidence contributions.
 * This is a stateful decision: call exactly once per evidence contribution. */
bool wifi_shield_core_publishable(wifi_shield_core_t *core,
                                  const wifi_shield_event_t *event);
/* Called exactly once for each worker lane record after the one selected-BSSID
 * decision. wps_fragment is true only for a selected decoded EAP-WSC record. */
void wifi_shield_core_record_input(wifi_shield_core_t *core, bool selected,
                                   bool wps_fragment);
void wifi_shield_core_add_rx_drops(wifi_shield_core_t *core, uint32_t count);
/* Clears status first; NULL core produces a zero snapshot. NULL outputs safe. */
void wifi_shield_core_status(const wifi_shield_core_t *core,
                             wifi_shield_status_t *status);

#endif
