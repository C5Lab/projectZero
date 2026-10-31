#include "csa_detector_core.h"
#include <stdio.h>
#include <string.h>

bool csa_capture_length(size_t sig_len, size_t dump_len, unsigned rx_state, size_t *length)
{
    if (!length || rx_state || sig_len < 28 || sig_len > CSA_FRAME_LIMIT + 4) return false;
    *length = sig_len - 4;
    /* A short C5 dump is not a complete announcement, even when its prefix has a CSA. */
    return dump_len >= *length;
}

void csa_safe_ssid(char out[CSA_SSID_SIZE], const uint8_t *ssid, size_t length)
{
    if (!ssid || !length) { strcpy(out, "<Unknown>"); return; }
    if (length > 32) length = 32;
    for (size_t i = 0; i < length; ++i) {
        uint8_t c = ssid[i];
        out[i] = (c >= 32 && c <= 126 && c != '|') ? (char)c : '?';
    }
    out[length] = 0;
}

bool csa_parse(const uint8_t *f, size_t n, uint8_t ch, int8_t rssi, csa_event_t *out)
{
    if (!f || !out || n < 24 || n > CSA_FRAME_LIMIT || (f[0] & 15) ||
        (f[1] & 0xc7) || (f[22] & 15)) return false; /* DS, encryption, HT-Control, fragments */
    csa_event_t e = {0};
    size_t offset;
    bool found = false;
    switch (f[0]) {
    case 0x80: e.via = CSA_VIA_BEACON; offset = 36; break;
    case 0x50: e.via = CSA_VIA_PROBE; offset = 36; break;
    case 0xd0:
        e.via = CSA_VIA_ACTION;
        if (n < 26) return false;
        if (f[24] == 0 && f[25] == 4) offset = 26;
        else if (f[24] == 4 && f[25] == 4) {
            if (n < 30) return false;
            e.mode = f[26]; e.operating_class = f[27];
            e.target_channel = f[28]; e.count = f[29];
            e.has_class = true; found = true; offset = 30;
        } else return false;
        break;
    default: return false;
    }
    if (offset > n) return false;
    strcpy(e.ssid, "<Unknown>");
    while (offset < n) {
        if (n - offset < 2) return false;
        uint8_t id = f[offset], len = f[offset + 1];
        offset += 2;
        if (len > n - offset) return false;
        const uint8_t *data = f + offset;
        if (id == 0 && e.via != CSA_VIA_ACTION) {
            if (len > 32) return false;
            csa_safe_ssid(e.ssid, data, len);
        } else if (id == 37 || id == 60) {
            bool ext = id == 60;
            if (len != (ext ? 4 : 3)) return false;
            if (found && (e.mode != data[0] || e.target_channel != data[ext ? 2 : 1] ||
                e.count != data[ext ? 3 : 2] || (e.has_class && ext && e.operating_class != data[1]))) return false;
            /* Matching ECSA adds the class when both announcement IEs are present. */
            if (!e.has_class || ext) {
                e.mode = data[0]; e.has_class = ext;
                e.operating_class = ext ? data[1] : 0;
                e.target_channel = data[ext ? 2 : 1];
                e.count = data[ext ? 3 : 2];
                found = true;
            }
        }
        offset += len;
    }
    if (!found) return false;
    e.rx_channel = ch; e.rssi = rssi;
    memcpy(e.bssid, f + 16, 6); memcpy(e.transmitter, f + 10, 6);
    *out = e;
    return true;
}

size_t csa_format_line(const csa_event_t *e, char *line, size_t capacity)
{
    if (!e || !line || !capacity) return 0;
    char cls[4], ssid[CSA_SSID_SIZE];
    if (e->has_class) snprintf(cls, sizeof(cls), "%u", (unsigned)e->operating_class);
    else strcpy(cls, "-");
    size_t ssid_len = 0;
    while (ssid_len < 32 && e->ssid[ssid_len]) ++ssid_len;
    csa_safe_ssid(ssid, (const uint8_t *)e->ssid, ssid_len);
    const char *via = e->via == CSA_VIA_BEACON ? "beacon" : e->via == CSA_VIA_PROBE ? "probe" : "action";
    int n = snprintf(line, capacity,
        "[CSA] RX: %u | TO: %u | BSSID: %02X:%02X:%02X:%02X:%02X:%02X | TX: %02X:%02X:%02X:%02X:%02X:%02X | RSSI: %d | VIA: %s | COUNT: %u | MODE: %u | CLASS: %s | SSID: %s",
        (unsigned)e->rx_channel, (unsigned)e->target_channel,
        e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3], e->bssid[4], e->bssid[5],
        e->transmitter[0], e->transmitter[1], e->transmitter[2], e->transmitter[3], e->transmitter[4], e->transmitter[5],
        (int)e->rssi, via, (unsigned)e->count, (unsigned)e->mode, cls, ssid);
    if (n < 0 || (size_t)n >= capacity) { line[0] = 0; return 0; }
    return (size_t)n;
}

bool csa_rate_allow(csa_rate_limit_t *state, const csa_event_t *e, uint32_t now)
{
    csa_rate_slot_t *slot = &state->slots[0];
    for (size_t i = 0; i < CSA_RATE_SLOTS; ++i) {
        csa_rate_slot_t *s = &state->slots[i];
        if (s->used && !memcmp(s->event.bssid, e->bssid, 6) &&
            !memcmp(s->event.transmitter, e->transmitter, 6) &&
            s->event.rx_channel == e->rx_channel && s->event.target_channel == e->target_channel &&
            s->event.mode == e->mode && s->event.has_class == e->has_class &&
            s->event.operating_class == e->operating_class) {
            if ((uint32_t)(now - s->last_ms) < 2000) return false;
            slot = s; break;
        }
        if (!s->used || (slot->used && (uint32_t)(now - s->last_ms) > (uint32_t)(now - slot->last_ms))) slot = s;
    }
    if (slot->used && (uint32_t)(now - slot->last_ms) < 2000) {
        if (state->capacity_dropped != UINT32_MAX) ++state->capacity_dropped;
        return false;
    }
    slot->used = true; slot->event = *e; slot->last_ms = now;
    return true;
}
