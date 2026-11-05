#ifndef WPS_GUARD_CORE_H
#define WPS_GUARD_CORE_H

#include "wifi_security_frame.h"

#define WPS_GUARD_MAX_SESSIONS 8U
#define WPS_GUARD_MAX_DECLARED 4096U
#define WPS_GUARD_TIMEOUT_MS 5000U

typedef enum {
    WPS_GUARD_DIR_AP_TO_STA = 0,
    WPS_GUARD_DIR_STA_TO_AP
} wps_guard_direction_t;

typedef enum {
    WPS_GUARD_NONE = 0,
    WPS_GUARD_RETRANSMISSION,
    WPS_GUARD_COMPLETE,
    WPS_GUARD_FIRST_MISSING_LENGTH,
    WPS_GUARD_DECLARED_NOT_LARGER_THAN_FIRST,
    WPS_GUARD_DECLARED_OVER_LIMIT,
    WPS_GUARD_REPEATED_LENGTH_FIELD,
    WPS_GUARD_OPCODE_CHANGED,
    WPS_GUARD_EAP_ID_CONFLICT,
    WPS_GUARD_OBSERVED_EXCEEDS_DECLARED,
    WPS_GUARD_FINAL_LENGTH_MISMATCH,
    WPS_GUARD_EMPTY_MORE_FRAGMENT,
    WPS_GUARD_SESSION_TIMEOUT,
    WPS_GUARD_SESSION_CAPACITY,
    WPS_GUARD_FRAME_TRUNCATED,
    WPS_GUARD_INVALID_ENVELOPE,
    WPS_GUARD_REASON_COUNT
} wps_guard_reason_t;

/* Metadata only: never extend these objects with payload storage or views.
 * payload_hash is noncryptographic FNV-1a, useful only for comparing observations.
 * channel/rssi are filled by the worker from its copied slot after decoding. */
typedef struct {
    uint8_t bssid[6], station[6];
    wps_guard_direction_t direction;
    uint8_t eap_id, opcode, flags;
    uint16_t declared_total;
    uint16_t payload_len;
    uint32_t payload_hash;
    uint64_t timestamp_us;
    uint8_t channel;
    int8_t rssi;
    bool length_present, more_fragments, input_truncated;
    wps_guard_reason_t envelope_reason;
} wps_guard_fragment_t;

typedef struct {
    wps_guard_fragment_t fragment;
    wps_guard_reason_t reason;
    uint16_t declared_total;
    uint32_t observed_total;
    uint32_t fragment_count;
    uint32_t retransmission_count;
} wps_guard_event_t;

typedef struct {
    uint32_t fragments, retransmissions, completions, anomalies;
    uint32_t timeouts, capacity_drops;
    uint32_t reason_counts[WPS_GUARD_REASON_COUNT];
    uint32_t active_sessions;
    /* Adapter-owned counters saturate at UINT32_MAX; snapshot with core state.
     * Core itself neither updates nor interprets these additive fields. */
    uint32_t received, filtered, unrelated, rx_drops, output_failures;
    bool running, stopping;
} wps_guard_status_t;

/* Public layout allows fixed caller-owned storage; caller serializes all access.
 * Only the latest fragment fingerprint is kept, with no WSC reassembly. */
typedef struct {
    wps_guard_fragment_t last_fragment;
    uint64_t last_seen_us;
    uint16_t declared_total;
    uint32_t observed_total;
    uint32_t fragment_count;
    uint32_t retransmission_count;
    bool active;
} wps_guard_session_t;

typedef struct {
    wps_guard_session_t sessions[WPS_GUARD_MAX_SESSIONS];
    wps_guard_status_t status;
} wps_guard_core_t;

void wps_guard_core_init(wps_guard_core_t *core);
/* Clears flows and counters, including all metadata. Safe on an idle core. */
void wps_guard_reset(wps_guard_core_t *core);
void wps_guard_get_status(const wps_guard_core_t *core, wps_guard_status_t *status);

/* Borrows the decoded view only during this call. false clears out and means
 * unrelated, protected, ambiguous-identity or too short to identify EAP-WSC.
 * true includes recognizable malformed/truncated EAP-WSC: envelope_reason then
 * identifies uncertainty, payload_len/hash stay zero, and no missing tail is read.
 * Identification requires EAP packet Request/Response, Expanded 254, WFA OUI and
 * vendor type 1. Valid EAPOL versions are 1..3, WSC opcodes 1..6, flags MF/LF only.
 * A complete slice must match both EAPOL and EAP length fields exactly.
 * timestamp_us and expire(now_us) must share a monotonic microsecond clock;
 * the adapter must not mix a raw driver RX timestamp with lifecycle time.
 * No attributes, nonces, keys, PINs or credentials are decoded or retained. */
bool wps_guard_decode_fragment(const wifi_security_decoded_t *frame,
                               bool input_truncated, uint64_t timestamp_us,
                               wps_guard_fragment_t *out);

/* Validates that fragment still matches this exact complete decoded EAP-WSC
 * slice, then borrows only its payload (18-byte header, or 20 with LF).
 * Both outputs are required; any failure clears each non-NULL output.
 * The caller consumes the view synchronously while frame storage is alive;
 * no core/session/event object stores the returned pointer. */
bool wps_guard_payload_view(const wifi_security_decoded_t *frame,
                            const wps_guard_fragment_t *fragment,
                            const uint8_t **payload, size_t *length);

/* Observational reasons are not router-vulnerability or attribution claims.
 * A flow is (BSSID, station, direction). Exact latest-fragment retransmissions
 * refresh observation metadata/time, without accumulating bytes/count. Hashes
 * can collide; only a changed latest EAP-ID hash/length establishes conflict.
 * Complete and terminal-invalid observations clear that flow. Standalone frames
 * need no slot. Expired flows are removed before lookup/capacity checks; callers
 * wanting their events must call expire with an eight-event buffer first.
 * NULL event discards output; invalid NULL arguments return INVALID_ENVELOPE.
 * fragments counts non-NULL observe inputs; reason_counts also counts expiry.
 * anomalies counts FIRST_MISSING_LENGTH..EMPTY_MORE_FRAGMENT and INVALID_ENVELOPE;
 * timeout/capacity/truncated observations are uncertainty, counted by reason.
 * All counters, including per-flow fragment_count, saturate at UINT32_MAX. */
wps_guard_reason_t wps_guard_observe(wps_guard_core_t *core,
                                     const wps_guard_fragment_t *fragment,
                                     wps_guard_event_t *event);

/* Strictly greater than 5,000,000 us since latest observation expires a flow.
 * now earlier than last_seen never underflows. Events preserve latest observation
 * metadata, including its timestamp/channel/rssi. Every expired flow is removed
 * and counted even if output is full/NULL; return is events actually written,
 * never greater than capacity. Query status for total expirations. */
size_t wps_guard_expire(wps_guard_core_t *core, uint64_t now_us,
                        wps_guard_event_t *events, size_t capacity);

#endif
