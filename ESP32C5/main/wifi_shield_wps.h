#ifndef WIFI_SHIELD_WPS_H
#define WIFI_SHIELD_WPS_H

#include "wps_guard_core.h"

typedef enum {
    WIFI_SHIELD_WPS_UNKNOWN = 0,
    WIFI_SHIELD_WPS_M1, WIFI_SHIELD_WPS_M2,
    WIFI_SHIELD_WPS_M3, WIFI_SHIELD_WPS_M4,
    WIFI_SHIELD_WPS_M5, WIFI_SHIELD_WPS_M6,
    WIFI_SHIELD_WPS_M7, WIFI_SHIELD_WPS_M8,
    WIFI_SHIELD_WPS_ACK, WIFI_SHIELD_WPS_NACK,
    WIFI_SHIELD_WPS_DONE
} wifi_shield_wps_message_t;

#define WIFI_SHIELD_WPS_FLOW_CAPACITY 32U

/* Fixed caller-owned metadata, serialized by its owner. At most one partial
 * attribute header and the Message Type classification survive a call.
 * The additional scalars validate fragment totals and fingerprint only the
 * latest observation, following WPS Guard's noncryptographic replay contract. */
typedef struct {
    uint8_t bssid[6], station[6];
    wps_guard_direction_t direction;
    uint8_t tlv_header[4];
    uint16_t value_remaining;
    uint8_t header_used;
    wifi_shield_wps_message_t message;
    uint64_t last_seen_us;
    bool active, malformed;
    uint16_t declared_total, observed_total;
    uint16_t last_declared_total, last_payload_len;
    uint32_t last_payload_hash;
    uint8_t last_eap_id, last_opcode, last_flags;
    bool fragmented, complete, message_seen;
} wifi_shield_wps_cursor_t;

typedef struct {
    wifi_shield_wps_cursor_t flows[WIFI_SHIELD_WPS_FLOW_CAPACITY];
    uint32_t capacity_drops;
} wifi_shield_wps_table_t;

/* Consume a borrowed view synchronously; retain no input pointer or attribute
 * value. Only a complete, well-formed message with exactly one 0x1022 attribute
 * of length one can return a known type. Unknown/malformed/incomplete returns
 * UNKNOWN. Opcode alone is never evidence of Message Type.
 * Key: BSSID + station + direction (EAP IDs do not identify a flow).
 * Completed cursors retain metadata until a new message or expiry, allowing
 * terminal retransmissions without consuming their bytes twice. No eviction:
 * a new identity at capacity increments capacity_drops, saturating at UINT32_MAX.
 * Latest-fragment fingerprints can collide; classification is evidence only.
 * Payload length must match decoded fragment metadata; input must not overlap
 * table storage. Invalid envelope/sequence evidence invalidates that flow. */
wifi_shield_wps_message_t wifi_shield_wps_observe(
    wifi_shield_wps_table_t *table, const wps_guard_fragment_t *fragment,
    const uint8_t *payload, size_t length);

/* Same monotonic microsecond clock and strict >5-second boundary as WPS Guard.
 * Backwards timestamps never reduce last_seen or underflow elapsed time.
 * Every expired cursor is wiped; returns the number removed. */
size_t wifi_shield_wps_expire(wifi_shield_wps_table_t *table, uint64_t now_us);
/* Wipes every cursor, padding byte and counter; NULL is safe. */
void wifi_shield_wps_reset(wifi_shield_wps_table_t *table);

#endif
