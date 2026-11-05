#include "wifi_shield_wps.h"

#include <string.h>

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static bool unicast(const uint8_t address[6])
{
    return (address[0] & 1U) == 0 &&
           (address[0] | address[1] | address[2] |
            address[3] | address[4] | address[5]) != 0;
}

void wifi_shield_wps_reset(wifi_shield_wps_table_t *table)
{
    if (table != NULL) memset(table, 0, sizeof(*table));
}

size_t wifi_shield_wps_expire(wifi_shield_wps_table_t *table, uint64_t now_us)
{
    if (table == NULL) return 0;
    size_t expired = 0;
    const uint64_t timeout_us = (uint64_t)WPS_GUARD_TIMEOUT_MS * 1000U;
    for (size_t i = 0; i < WIFI_SHIELD_WPS_FLOW_CAPACITY; ++i) {
        wifi_shield_wps_cursor_t *c = &table->flows[i];
        if (!c->active || now_us < c->last_seen_us ||
            now_us - c->last_seen_us <= timeout_us) continue;
        memset(c, 0, sizeof(*c));
        ++expired;
    }
    return expired;
}

static wifi_shield_wps_message_t message_type(uint8_t value)
{
    switch (value) {
    case 4: return WIFI_SHIELD_WPS_M1;
    case 5: return WIFI_SHIELD_WPS_M2;
    case 7: return WIFI_SHIELD_WPS_M3;
    case 8: return WIFI_SHIELD_WPS_M4;
    case 9: return WIFI_SHIELD_WPS_M5;
    case 10: return WIFI_SHIELD_WPS_M6;
    case 11: return WIFI_SHIELD_WPS_M7;
    case 12: return WIFI_SHIELD_WPS_M8;
    case 13: return WIFI_SHIELD_WPS_ACK;
    case 14: return WIFI_SHIELD_WPS_NACK;
    case 15: return WIFI_SHIELD_WPS_DONE;
    default: return WIFI_SHIELD_WPS_UNKNOWN;
    }
}

/* No attribute value is copied: unrelated values are skipped, even if their
 * bytes resemble a Message Type TLV. Only a single classification is retained. */
static void consume(wifi_shield_wps_cursor_t *c, const uint8_t *p, size_t length)
{
    size_t offset = 0;
    while (offset < length && !c->malformed) {
        if (c->header_used < 4) {
            c->tlv_header[c->header_used++] = p[offset++];
            if (c->header_used != 4) continue;
            c->value_remaining = read_be16(c->tlv_header + 2);
            if (read_be16(c->tlv_header) == 0x1022 &&
                (c->value_remaining != 1 || c->message_seen)) {
                c->malformed = true;
                break;
            }
        }
        if (c->value_remaining != 0) {
            size_t count = length - offset;
            if (count > c->value_remaining) count = c->value_remaining;
            if (count == 0) continue;
            if (read_be16(c->tlv_header) == 0x1022) {
                c->message = message_type(p[offset]);
                c->message_seen = true;
            }
            offset += count;
            c->value_remaining = (uint16_t)(c->value_remaining - count);
        }
        if (c->value_remaining == 0) {
            c->header_used = 0;
            memset(c->tlv_header, 0, sizeof(c->tlv_header));
        }
    }
}

static bool same_flow(const wifi_shield_wps_cursor_t *c, const wps_guard_fragment_t *f)
{
    return c->active && c->direction == f->direction &&
           memcmp(c->bssid, f->bssid, 6) == 0 && memcmp(c->station, f->station, 6) == 0;
}

static bool valid_fragment(const wps_guard_fragment_t *f, const uint8_t *p, size_t length)
{
    return (p != NULL || length == 0) && length == f->payload_len &&
           !f->input_truncated && f->envelope_reason == WPS_GUARD_NONE &&
           unicast(f->bssid) && unicast(f->station) &&
           memcmp(f->bssid, f->station, 6) != 0 &&
           (f->direction == WPS_GUARD_DIR_AP_TO_STA || f->direction == WPS_GUARD_DIR_STA_TO_AP) &&
           f->opcode >= 1 && f->opcode <= 6 && (f->flags & ~3U) == 0 &&
           f->length_present == ((f->flags & 2U) != 0) &&
           f->more_fragments == ((f->flags & 1U) != 0) &&
           (f->length_present || f->declared_total == 0);
}

static bool replay(const wifi_shield_wps_cursor_t *c, const wps_guard_fragment_t *f)
{
    return c->last_eap_id == f->eap_id && c->last_opcode == f->opcode &&
           c->last_flags == f->flags && c->last_declared_total == f->declared_total &&
           c->last_payload_len == f->payload_len && c->last_payload_hash == f->payload_hash;
}

static wifi_shield_wps_message_t result(const wifi_shield_wps_cursor_t *c)
{
    return c->complete && !c->malformed && c->message_seen ? c->message : WIFI_SHIELD_WPS_UNKNOWN;
}

wifi_shield_wps_message_t wifi_shield_wps_observe(
    wifi_shield_wps_table_t *table, const wps_guard_fragment_t *f,
    const uint8_t *payload, size_t length)
{
    if (table == NULL || f == NULL) return WIFI_SHIELD_WPS_UNKNOWN;
    (void)wifi_shield_wps_expire(table, f->timestamp_us);
    wifi_shield_wps_cursor_t *c = NULL, *available = NULL;
    for (size_t i = 0; i < WIFI_SHIELD_WPS_FLOW_CAPACITY; ++i) {
        if (same_flow(&table->flows[i], f)) c = &table->flows[i];
        else if (!table->flows[i].active && available == NULL) available = &table->flows[i];
    }
    if (!valid_fragment(f, payload, length)) {
        if (c != NULL) memset(c, 0, sizeof(*c));
        return WIFI_SHIELD_WPS_UNKNOWN;
    }
    if (c != NULL && replay(c, f)) {
        if (f->timestamp_us > c->last_seen_us) c->last_seen_us = f->timestamp_us;
        return result(c);
    }
    /* Completed messages do not carry TLV state into the next WSC message. */
    if (c != NULL && c->complete) {
        available = c;
        c = NULL;
    }
    if (c == NULL) {
        if ((f->more_fragments && (!f->length_present || length == 0 ||
                                  f->declared_total <= length)) ||
            (f->length_present && (f->declared_total > WPS_GUARD_MAX_DECLARED ||
                                  (!f->more_fragments && f->declared_total != length)))) {
            if (available != NULL) memset(available, 0, sizeof(*available));
            return WIFI_SHIELD_WPS_UNKNOWN;
        }
        if (available == NULL) {
            if (table->capacity_drops != UINT32_MAX) ++table->capacity_drops;
            return WIFI_SHIELD_WPS_UNKNOWN;
        }
        c = available;
        const uint64_t last_seen = c->last_seen_us;
        memset(c, 0, sizeof(*c));
        memcpy(c->bssid, f->bssid, 6);
        memcpy(c->station, f->station, 6);
        c->direction = f->direction;
        c->active = true;
        c->fragmented = f->more_fragments;
        c->declared_total = f->declared_total;
        c->last_seen_us = last_seen;
    } else if (c->last_eap_id == f->eap_id || c->last_opcode != f->opcode ||
               f->length_present || (f->more_fragments && length == 0)) {
        memset(c, 0, sizeof(*c));
        return WIFI_SHIELD_WPS_UNKNOWN;
    }
    /* Addition is widened before checking, never allowed to wrap uint16_t. */
    const size_t observed = (size_t)c->observed_total + length;
    if ((c->fragmented && (observed > c->declared_total ||
                          (!f->more_fragments && observed != c->declared_total))) ||
        observed > UINT16_MAX) {
        memset(c, 0, sizeof(*c));
        return WIFI_SHIELD_WPS_UNKNOWN;
    }
    consume(c, payload, length);
    c->observed_total = (uint16_t)observed;
    c->last_eap_id = f->eap_id;
    c->last_opcode = f->opcode;
    c->last_flags = f->flags;
    c->last_declared_total = f->declared_total;
    c->last_payload_len = f->payload_len;
    c->last_payload_hash = f->payload_hash;
    if (f->timestamp_us > c->last_seen_us) c->last_seen_us = f->timestamp_us;
    c->complete = !f->more_fragments;
    if (c->complete && (c->header_used != 0 || c->value_remaining != 0)) c->malformed = true;
    if (c->malformed) c->message = WIFI_SHIELD_WPS_UNKNOWN;
    return result(c);
}
