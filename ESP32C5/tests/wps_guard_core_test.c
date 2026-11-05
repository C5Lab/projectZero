#include "wps_guard_core.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static const uint8_t ap[6] = {0x02, 1, 2, 3, 4, 5};
static const uint8_t sta[6] = {0x04, 6, 7, 8, 9, 10};
static bool reasons_seen[WPS_GUARD_REASON_COUNT];

static void be16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)(value >> 8);
    p[1] = (uint8_t)value;
}

static size_t envelope(uint8_t *p, uint8_t flags, uint16_t total,
                       const uint8_t *payload, size_t length)
{
    static const uint8_t header[] = {
        2, 0, 0, 0, /* EAPOL version, EAP packet, EAP length */
        1, 37, 0, 0, /* EAP Request, identifier, length */
        254, 0, 0x37, 0x2a, 0, 0, 0, 1, 4, 0
    };
    memcpy(p, header, sizeof(header));
    p[17] = flags;
    size_t offset = sizeof(header);
    if ((flags & 2U) != 0) {
        be16(p + offset, total);
        offset += 2;
    }
    if (length != 0) memcpy(p + offset, payload, length);
    be16(p + 2, (uint16_t)(offset + length - 4));
    be16(p + 6, (uint16_t)(offset + length - 4));
    return offset + length;
}

static wifi_security_decoded_t view(const uint8_t *bytes, size_t length)
{
    wifi_security_decoded_t frame = {0};
    frame.kind = WIFI_SEC_FRAME_EAPOL;
    frame.from_ds = true;
    frame.eapol = bytes;
    frame.eapol_len = length;
    memcpy(frame.bssid, ap, 6);
    memcpy(frame.station, sta, 6);
    return frame;
}

static wps_guard_fragment_t fragment(uint8_t id, uint16_t length, uint32_t hash,
                                      uint8_t flags, uint16_t total)
{
    wps_guard_fragment_t f = {0};
    memcpy(f.bssid, ap, 6);
    memcpy(f.station, sta, 6);
    f.direction = WPS_GUARD_DIR_AP_TO_STA;
    f.eap_id = id;
    f.opcode = 4;
    f.flags = flags;
    f.declared_total = total;
    f.length_present = (flags & 2U) != 0;
    f.more_fragments = (flags & 1U) != 0;
    f.payload_len = length;
    f.payload_hash = hash;
    f.timestamp_us = 100;
    f.channel = 6;
    f.rssi = -51;
    return f;
}

static void check(wps_guard_core_t *core, const wps_guard_fragment_t *f,
                   wps_guard_reason_t want, wps_guard_event_t *event)
{
    wps_guard_reason_t actual = wps_guard_observe(core, f, event);
    if (actual != want) {
        fprintf(stderr, "reason mismatch: got %u, wanted %u\n",
                (unsigned)actual, (unsigned)want);
    }
    assert(actual == want);
    assert(event->reason == want);
    assert(memcmp(event->fragment.bssid, f->bssid, 6) == 0);
    assert(memcmp(event->fragment.station, f->station, 6) == 0);
    assert(event->fragment.channel == f->channel);
    assert(event->fragment.rssi == f->rssi);
    reasons_seen[actual] = true;
}

static uint32_t active(wps_guard_core_t *core)
{
    wps_guard_status_t status;
    wps_guard_get_status(core, &status);
    return status.active_sessions;
}

static void test_envelope_fields_and_offsets(void)
{
    uint8_t bytes[128];
    const uint8_t abc[] = {'a', 'b', 'c'};
    wps_guard_fragment_t out;
    size_t size = envelope(bytes, 3, 0x1234, abc, 3);
    wifi_security_decoded_t frame = view(bytes, size);
    assert(wps_guard_decode_fragment(&frame, false, 123456, &out));
    assert(out.envelope_reason == WPS_GUARD_NONE);
    assert(out.eap_id == 37 && out.opcode == 4 && out.flags == 3);
    assert(out.length_present && out.more_fragments && !out.input_truncated);
    assert(out.declared_total == 0x1234 && out.payload_len == 3);
    assert(out.payload_hash == UINT32_C(0x1a47e90b)); /* FNV-1a of abc */
    assert(out.timestamp_us == 123456 && out.direction == WPS_GUARD_DIR_AP_TO_STA);
    assert(memcmp(out.bssid, ap, 6) == 0 && memcmp(out.station, sta, 6) == 0);
    assert(out.channel == 0 && out.rssi == 0); /* slot metadata belongs to adapter */

    for (uint8_t version = 1; version <= 3; ++version) {
        for (uint8_t code = 1; code <= 2; ++code) {
            for (uint8_t opcode = 1; opcode <= 6; ++opcode) {
                for (uint8_t flags = 0; flags <= 3; ++flags) {
                    size = envelope(bytes, flags, 0x0102, abc, 3);
                    bytes[0] = version;
                    bytes[4] = code;
                    bytes[16] = opcode;
                    frame = view(bytes, size);
                    frame.from_ds = code == 1;
                    frame.to_ds = code == 2;
                    assert(wps_guard_decode_fragment(&frame, false, 2, &out));
                    assert(out.envelope_reason == WPS_GUARD_NONE);
                    assert(out.opcode == opcode && out.flags == flags);
                    assert(out.payload_len == 3 && out.payload_hash == UINT32_C(0x1a47e90b));
                    assert(out.declared_total == ((flags & 2U) ? 0x0102 : 0));
                    assert(out.direction == (code == 1 ? WPS_GUARD_DIR_AP_TO_STA :
                                                        WPS_GUARD_DIR_STA_TO_AP));
                }
            }
        }
    }
    size = envelope(bytes, 0, 0, NULL, 0);
    frame = view(bytes, size);
    assert(wps_guard_decode_fragment(&frame, false, 2, &out));
    assert(out.payload_len == 0 && out.payload_hash == UINT32_C(2166136261));
    assert(out.envelope_reason == WPS_GUARD_NONE);

    /* The foundation's exact MAC/SNAP slice feeds this parser unmodified. */
    uint8_t mac[128] = {0x08, 0x02};
    memcpy(mac + 4, sta, 6);
    memcpy(mac + 10, ap, 6);
    memcpy(mac + 16, ap, 6);
    const uint8_t snap[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
    memcpy(mac + 24, snap, 8);
    size = envelope(mac + 32, 2, 3, abc, 3);
    assert(wifi_security_decode(mac, size + 32, &frame));
    assert(wps_guard_decode_fragment(&frame, false, 99, &out));
    assert(out.declared_total == 3 && out.payload_len == 3);
}

static void test_unrelated_and_malformed_envelopes(void)
{
    uint8_t bytes[128];
    const uint8_t abc[] = {'a', 'b', 'c'};
    size_t size = envelope(bytes, 3, 10, abc, 3);
    wifi_security_decoded_t frame = view(bytes, size);
    wps_guard_fragment_t out, zero = {0};
    const size_t unrelated_offsets[] = {1, 4, 8, 9, 10, 11, 12, 13, 14, 15};
    for (size_t i = 0; i < sizeof(unrelated_offsets) / sizeof(unrelated_offsets[0]); ++i) {
        size_t off = unrelated_offsets[i];
        uint8_t saved = bytes[off];
        bytes[off] = off == 4 ? 3 : (uint8_t)(saved ^ 0x80U);
        memset(&out, 0xa5, sizeof(out));
        assert(!wps_guard_decode_fragment(&frame, false, 1, &out));
        assert(memcmp(&out, &zero, sizeof(out)) == 0);
        bytes[off] = saved;
    }
    frame.protected_frame = true;
    assert(!wps_guard_decode_fragment(&frame, true, 1, &out));
    frame.protected_frame = false;
    frame.kind = WIFI_SEC_FRAME_DATA;
    assert(!wps_guard_decode_fragment(&frame, true, 1, &out));
    frame.kind = WIFI_SEC_FRAME_EAPOL;
    frame.to_ds = true; /* WDS and unknown identities are not reportable flows. */
    assert(!wps_guard_decode_fragment(&frame, false, 1, &out));
    frame.to_ds = false;
    frame.from_ds = false;
    assert(!wps_guard_decode_fragment(&frame, false, 1, &out));
    frame.from_ds = true;
    memset(frame.station, 0, 6);
    assert(!wps_guard_decode_fragment(&frame, false, 1, &out));
    memcpy(frame.station, sta, 6);
    frame.bssid[0] |= 1;
    assert(!wps_guard_decode_fragment(&frame, false, 1, &out));
    frame = view(bytes, size);

    const size_t malformed_offsets[] = {0, 2, 3, 6, 7, 16, 17};
    for (size_t i = 0; i < sizeof(malformed_offsets) / sizeof(malformed_offsets[0]); ++i) {
        size_t off = malformed_offsets[i];
        uint8_t saved = bytes[off];
        bytes[off] = off == 0 || off == 16 ? 0 : (uint8_t)(saved ^ 0x80U);
        assert(wps_guard_decode_fragment(&frame, false, 1, &out));
        assert(out.envelope_reason == WPS_GUARD_INVALID_ENVELOPE);
        assert(out.payload_len == 0 && out.payload_hash == 0);
        bytes[off] = saved;
    }
    bytes[0] = 4;
    assert(wps_guard_decode_fragment(&frame, false, 1, &out));
    assert(out.envelope_reason == WPS_GUARD_INVALID_ENVELOPE);
    bytes[0] = 2;
    bytes[16] = 7;
    assert(wps_guard_decode_fragment(&frame, false, 1, &out));
    assert(out.envelope_reason == WPS_GUARD_INVALID_ENVELOPE);
    bytes[16] = 4;

    /* Every cut point ends at an allocation boundary under ASan. Identity
     * ends at offset 15, so no absent opcode/flags/length/tail may be touched. */
    for (size_t cut = 0; cut < size; ++cut) {
        uint8_t short_bytes[128];
        memcpy(short_bytes, bytes, cut);
        frame = view(short_bytes + sizeof(short_bytes) - cut, cut);
        if (cut != 0) memmove((uint8_t *)frame.eapol, bytes, cut);
        bool recognized = wps_guard_decode_fragment(&frame, true, 42, &out);
        assert(recognized == (cut >= 16));
        if (recognized) {
            assert(out.envelope_reason == WPS_GUARD_FRAME_TRUNCATED);
            assert(out.input_truncated && out.payload_len == 0 && out.payload_hash == 0);
        }
    }
    frame = view(bytes, 16);
    assert(wps_guard_decode_fragment(&frame, false, 1, &out));
    assert(out.envelope_reason == WPS_GUARD_INVALID_ENVELOPE);
    frame = view(bytes, 19); /* LF is present but its second length byte is absent */
    be16(bytes + 2, 15);
    be16(bytes + 6, 15);
    assert(wps_guard_decode_fragment(&frame, false, 1, &out));
    assert(out.envelope_reason == WPS_GUARD_INVALID_ENVELOPE);
    assert(!wps_guard_decode_fragment(NULL, false, 1, &out));
    assert(!wps_guard_decode_fragment(&frame, false, 1, NULL));
    frame.eapol = NULL;
    assert(!wps_guard_decode_fragment(&frame, true, 1, &out));
}

static void test_real_fragment_sequence_and_retransmission(void)
{
    wps_guard_core_t core;
    wps_guard_event_t event;
    wps_guard_core_init(&core);
    wps_guard_fragment_t f = fragment(10, 4, 111, 3, 10);
    check(&core, &f, WPS_GUARD_NONE, &event);
    assert(active(&core) == 1 && event.observed_total == 4 && event.fragment_count == 1);
    assert(event.retransmission_count == 0 && core.sessions[0].retransmission_count == 0);
    f.timestamp_us = 200;
    check(&core, &f, WPS_GUARD_RETRANSMISSION, &event);
    assert(event.observed_total == 4 && event.fragment_count == 1);
    assert(event.retransmission_count == 1 && core.sessions[0].retransmission_count == 1);
    f = fragment(11, 3, 222, 1, 0);
    f.timestamp_us = 300;
    check(&core, &f, WPS_GUARD_NONE, &event);
    assert(event.declared_total == 10 && event.observed_total == 7 && event.fragment_count == 2);
    assert(event.retransmission_count == 1);
    f.timestamp_us = 400;
    check(&core, &f, WPS_GUARD_RETRANSMISSION, &event);
    assert(event.observed_total == 7 && event.fragment_count == 2);
    assert(event.retransmission_count == 2 && core.sessions[0].retransmission_count == 2);
    f = fragment(12, 3, 333, 0, 0);
    f.timestamp_us = 500;
    check(&core, &f, WPS_GUARD_COMPLETE, &event);
    assert(event.declared_total == 10 && event.observed_total == 10 && event.fragment_count == 3);
    assert(event.retransmission_count == 2);
    assert(active(&core) == 0);
    check(&core, &f, WPS_GUARD_COMPLETE, &event); /* no retained terminal payload */
    assert(event.observed_total == 3 && event.fragment_count == 1);
    assert(event.retransmission_count == 0);
    wps_guard_status_t status;
    wps_guard_get_status(&core, &status);
    assert(status.fragments == 6 && status.retransmissions == 2 && status.completions == 2);
    assert(status.anomalies == 0 && status.timeouts == 0 && status.capacity_drops == 0);
    assert(status.reason_counts[WPS_GUARD_NONE] == 2);
    assert(status.reason_counts[WPS_GUARD_RETRANSMISSION] == 2);
    assert(status.reason_counts[WPS_GUARD_COMPLETE] == 2);

    f = fragment(20, 4, 111, 3, 10);
    check(&core, &f, WPS_GUARD_NONE, &event);
    check(&core, &f, WPS_GUARD_RETRANSMISSION, &event);
    f.payload_hash++;
    check(&core, &f, WPS_GUARD_EAP_ID_CONFLICT, &event);
    assert(event.retransmission_count == 1 && active(&core) == 0);
}

static void test_decode_to_observe_exact_4096_and_truncated_terminal(void)
{
    uint8_t mac[1536] = {0x08, 0x02};
    uint8_t payload[1400];
    for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = (uint8_t)(i * 7U + 19U);
    memcpy(mac + 4, sta, 6);
    memcpy(mac + 10, ap, 6);
    memcpy(mac + 16, ap, 6);
    const uint8_t snap[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
    memcpy(mac + 24, snap, 8);
    const uint8_t flags[] = {3, 1, 0};
    const uint16_t lengths[] = {1400, 1400, 1296};
    const uint32_t observed[] = {1400, 2800, 4096};
    wps_guard_core_t core;
    wps_guard_event_t event;
    wps_guard_core_init(&core);
    for (size_t i = 0; i < 3; ++i) {
        size_t length = envelope(mac + 32, flags[i], 4096, payload, lengths[i]);
        mac[37] = (uint8_t)(254 + i); /* EAP identifier wrap is allowed. */
        wifi_security_decoded_t frame;
        wps_guard_fragment_t f;
        assert(wifi_security_decode(mac, length + 32, &frame));
        assert(wps_guard_decode_fragment(&frame, false, 100 + i, &f));
        f.channel = 13; f.rssi = -69;
        check(&core, &f, i == 2 ? WPS_GUARD_COMPLETE : WPS_GUARD_NONE, &event);
        assert(event.observed_total == observed[i] && event.fragment_count == i + 1);
        assert(event.declared_total == 4096);
    }
    assert(active(&core) == 0);
    size_t length = envelope(mac + 32, 3, 4096, payload, 1400);
    wifi_security_decoded_t frame;
    wps_guard_fragment_t f;
    assert(wifi_security_decode(mac, length + 32, &frame));
    assert(wps_guard_decode_fragment(&frame, false, 200, &f));
    check(&core, &f, WPS_GUARD_NONE, &event);
    /* Foundation can expose a 16-byte method identity while its copied MAC
     * frame is truncated. The absent opcode/flags/length/payload stay unread. */
    assert(wifi_security_decode(mac, 48, &frame));
    assert(wps_guard_decode_fragment(&frame, true, 201, &f));
    check(&core, &f, WPS_GUARD_FRAME_TRUNCATED, &event);
    assert(active(&core) == 0 && event.observed_total == 1400);
}

static void test_first_fragment_and_standalone_boundaries(void)
{
    struct first_case {
        uint8_t flags;
        uint16_t length, declared;
        wps_guard_reason_t want;
    } cases[] = {
        {1, 4, 0, WPS_GUARD_FIRST_MISSING_LENGTH},
        {3, 4, 4, WPS_GUARD_DECLARED_NOT_LARGER_THAN_FIRST},
        {3, 4, 3, WPS_GUARD_DECLARED_NOT_LARGER_THAN_FIRST},
        {3, 4, 4097, WPS_GUARD_DECLARED_OVER_LIMIT},
        {3, 0, 10, WPS_GUARD_EMPTY_MORE_FRAGMENT},
        {0, 0, 0, WPS_GUARD_COMPLETE},
        {2, 4, 4, WPS_GUARD_COMPLETE},
        {2, 4, 5, WPS_GUARD_FINAL_LENGTH_MISMATCH},
        {2, 4, 3, WPS_GUARD_OBSERVED_EXCEEDS_DECLARED},
        {2, 4, 4097, WPS_GUARD_DECLARED_OVER_LIMIT}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        wps_guard_core_t core;
        wps_guard_event_t event;
        wps_guard_core_init(&core);
        core.status.reason_counts[cases[i].want] = UINT32_MAX;
        wps_guard_fragment_t f = fragment(1, cases[i].length, 99, cases[i].flags,
                                          cases[i].declared);
        check(&core, &f, cases[i].want, &event);
        assert(active(&core) == 0);
        assert(core.status.reason_counts[cases[i].want] == UINT32_MAX);
    }
    wps_guard_core_t core;
    wps_guard_event_t event;
    wps_guard_core_init(&core);
    wps_guard_fragment_t f = fragment(1, 4, 1, 3, 4096);
    check(&core, &f, WPS_GUARD_NONE, &event);
    f = fragment(2, 4092, 2, 0, 0);
    check(&core, &f, WPS_GUARD_COMPLETE, &event);
    assert(event.observed_total == 4096 && active(&core) == 0);
}

static void test_terminal_anomalies_clear_flow(void)
{
    const wps_guard_reason_t cases[] = {
        WPS_GUARD_REPEATED_LENGTH_FIELD, WPS_GUARD_OPCODE_CHANGED,
        WPS_GUARD_EAP_ID_CONFLICT, WPS_GUARD_OBSERVED_EXCEEDS_DECLARED,
        WPS_GUARD_FINAL_LENGTH_MISMATCH, WPS_GUARD_EMPTY_MORE_FRAGMENT,
        WPS_GUARD_FRAME_TRUNCATED, WPS_GUARD_INVALID_ENVELOPE
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        wps_guard_core_t core;
        wps_guard_event_t event;
        wps_guard_core_init(&core);
        core.status.reason_counts[cases[i]] = UINT32_MAX;
        wps_guard_fragment_t f = fragment(1, 4, 1, 3, 10);
        check(&core, &f, WPS_GUARD_NONE, &event);
        f = fragment(2, 3, 2, 1, 0);
        switch (cases[i]) {
        case WPS_GUARD_REPEATED_LENGTH_FIELD:
            f.flags = 3; f.length_present = true; f.declared_total = 10; break;
        case WPS_GUARD_OPCODE_CHANGED: f.opcode = 5; break;
        case WPS_GUARD_EAP_ID_CONFLICT: f.eap_id = 1; f.payload_len = 4; break;
        case WPS_GUARD_OBSERVED_EXCEEDS_DECLARED: f.payload_len = 7; break;
        case WPS_GUARD_FINAL_LENGTH_MISMATCH: f.flags = 0; f.more_fragments = false; break;
        case WPS_GUARD_EMPTY_MORE_FRAGMENT: f.payload_len = 0; break;
        case WPS_GUARD_FRAME_TRUNCATED:
            f.input_truncated = true; f.envelope_reason = WPS_GUARD_FRAME_TRUNCATED; break;
        case WPS_GUARD_INVALID_ENVELOPE: f.envelope_reason = WPS_GUARD_INVALID_ENVELOPE; break;
        default: assert(false);
        }
        check(&core, &f, cases[i], &event);
        assert(active(&core) == 0);
        assert(core.status.reason_counts[cases[i]] == UINT32_MAX);
        f = fragment(20, 4, 44, 3, 10);
        check(&core, &f, WPS_GUARD_NONE, &event);
        assert(event.observed_total == 4 && event.fragment_count == 1);
    }
    /* Same EAP ID/length with changed hash also conflicts, even on first replay. */
    wps_guard_core_t core;
    wps_guard_event_t event;
    wps_guard_core_init(&core);
    wps_guard_fragment_t f = fragment(1, 4, 1, 3, 10);
    check(&core, &f, WPS_GUARD_NONE, &event);
    f.payload_hash = 2;
    check(&core, &f, WPS_GUARD_EAP_ID_CONFLICT, &event);
    check(&core, &f, WPS_GUARD_NONE, &event);
    f.payload_len = 3;
    check(&core, &f, WPS_GUARD_EAP_ID_CONFLICT, &event);
}

static void test_flow_keys_and_eight_session_capacity(void)
{
    wps_guard_core_t core;
    wps_guard_event_t event;
    wps_guard_core_init(&core);
    wps_guard_fragment_t first = fragment(1, 4, 1, 3, 10);
    check(&core, &first, WPS_GUARD_NONE, &event);
    wps_guard_fragment_t f = first;
    f.direction = WPS_GUARD_DIR_STA_TO_AP;
    check(&core, &f, WPS_GUARD_NONE, &event);
    f = first; f.bssid[5]++;
    check(&core, &f, WPS_GUARD_NONE, &event);
    f = first; f.station[5]++;
    check(&core, &f, WPS_GUARD_NONE, &event);
    assert(active(&core) == 4);
    for (uint8_t i = 0; i < 4; ++i) {
        f = first; f.station[5] = (uint8_t)(20 + i);
        check(&core, &f, WPS_GUARD_NONE, &event);
    }
    assert(active(&core) == 8);
    f = first; f.station[5] = 99;
    check(&core, &f, WPS_GUARD_SESSION_CAPACITY, &event);
    assert(active(&core) == 8);
    /* Standalone and malformed candidates need no slot even at capacity. */
    f.flags = 0; f.length_present = false; f.more_fragments = false; f.declared_total = 0;
    check(&core, &f, WPS_GUARD_COMPLETE, &event);
    assert(active(&core) == 8);
    f.envelope_reason = WPS_GUARD_FRAME_TRUNCATED;
    f.input_truncated = true;
    check(&core, &f, WPS_GUARD_FRAME_TRUNCATED, &event);
    assert(active(&core) == 8);
    f = first; f.station[5] = 99; f.timestamp_us = 5000101;
    check(&core, &f, WPS_GUARD_NONE, &event);
    assert(active(&core) == 1); /* expired before capacity is evaluated */
    wps_guard_status_t status;
    wps_guard_get_status(&core, &status);
    assert(status.timeouts == 8 && status.capacity_drops == 1);
    assert(status.anomalies == 0);
}

static void test_timeout_boundaries_metadata_and_output_capacity(void)
{
    wps_guard_core_t core;
    wps_guard_event_t event, expired[2];
    wps_guard_core_init(&core);
    wps_guard_fragment_t f = fragment(1, 4, 1, 3, 10);
    check(&core, &f, WPS_GUARD_NONE, &event);
    assert(wps_guard_expire(&core, 99, expired, 2) == 0);
    assert(wps_guard_expire(&core, 5000100, expired, 2) == 0);
    assert(active(&core) == 1);
    assert(wps_guard_expire(&core, 5000101, expired, 2) == 1);
    assert(expired[0].reason == WPS_GUARD_SESSION_TIMEOUT);
    reasons_seen[WPS_GUARD_SESSION_TIMEOUT] = true;
    assert(expired[0].fragment.timestamp_us == 100);
    assert(expired[0].fragment.channel == 6 && expired[0].fragment.rssi == -51);
    assert(expired[0].declared_total == 10 && expired[0].observed_total == 4);
    assert(active(&core) == 0);
    check(&core, &f, WPS_GUARD_NONE, &event);
    f.timestamp_us = 900; f.channel = 11; f.rssi = -73;
    check(&core, &f, WPS_GUARD_RETRANSMISSION, &event);
    assert(wps_guard_expire(&core, 5000900, expired, 2) == 0);
    assert(wps_guard_expire(&core, 5000901, expired, 2) == 1);
    assert(expired[0].fragment.timestamp_us == 900 && expired[0].fragment.channel == 11);
    assert(expired[0].fragment.rssi == -73 && expired[0].observed_total == 4);
    assert(expired[0].retransmission_count == 1);
    f.timestamp_us = 100;
    check(&core, &f, WPS_GUARD_NONE, &event);
    f.station[5]++;
    check(&core, &f, WPS_GUARD_NONE, &event);
    memset(expired, 0xa5, sizeof(expired));
    assert(wps_guard_expire(&core, 5000101, expired, 1) == 1);
    assert(active(&core) == 0 && expired[0].reason == WPS_GUARD_SESSION_TIMEOUT);
    const uint8_t *untouched = (const uint8_t *)&expired[1];
    for (size_t i = 0; i < sizeof(expired[1]); ++i) assert(untouched[i] == 0xa5);
    check(&core, &f, WPS_GUARD_NONE, &event);
    assert(wps_guard_expire(&core, 5000101, NULL, 7) == 0);
    assert(active(&core) == 0);
    wps_guard_status_t status;
    wps_guard_get_status(&core, &status);
    assert(status.timeouts == 5 && status.reason_counts[WPS_GUARD_SESSION_TIMEOUT] == 5);
}

static bool contains(const void *memory, size_t length, const uint8_t *marker, size_t size)
{
    const uint8_t *p = memory;
    if (length < size) return false;
    for (size_t i = 0; i <= length - size; ++i) {
        if (memcmp(p + i, marker, size) == 0) return true;
    }
    return false;
}

static void test_payload_hygiene_after_process_and_reset(void)
{
    uint8_t marker[64], bytes[128];
    for (size_t i = 0; i < sizeof(marker); ++i) marker[i] = (uint8_t)(17 + i * 3);
    size_t size = envelope(bytes, 3, 128, marker, sizeof(marker));
    assert(contains(bytes, size, marker, sizeof(marker)));
    wifi_security_decoded_t frame = view(bytes, size);
    wps_guard_fragment_t f;
    assert(wps_guard_decode_fragment(&frame, false, 100, &f));
    wps_guard_core_t core;
    wps_guard_event_t event;
    wps_guard_core_init(&core);
    check(&core, &f, WPS_GUARD_NONE, &event);
    assert(active(&core) == 1 && event.observed_total == 64);
    assert(!contains(&core, sizeof(core), marker, sizeof(marker)));
    assert(!contains(&event, sizeof(event), marker, sizeof(marker)));
    memset(bytes, 0, sizeof(bytes));
    assert(wps_guard_expire(&core, 5000101, &event, 1) == 1);
    assert(!contains(&core, sizeof(core), marker, sizeof(marker)));
    assert(!contains(&event, sizeof(event), marker, sizeof(marker)));
    wps_guard_reset(&core);
    assert(!contains(&core, sizeof(core), marker, sizeof(marker)));
    assert(!contains(&event, sizeof(event), marker, sizeof(marker)));
    const uint8_t *p = (const uint8_t *)&core;
    for (size_t i = 0; i < sizeof(core); ++i) assert(p[i] == 0);
}

static void test_saturating_counters_and_invalid_api_metadata(void)
{
    wps_guard_core_t core;
    wps_guard_event_t event;
    wps_guard_core_init(&core);
    core.status.fragments = UINT32_MAX - 1;
    core.status.retransmissions = UINT32_MAX - 1;
    core.status.completions = UINT32_MAX - 1;
    core.status.anomalies = UINT32_MAX - 1;
    core.status.timeouts = UINT32_MAX - 1;
    core.status.capacity_drops = UINT32_MAX - 1;
    for (size_t i = 0; i < WPS_GUARD_REASON_COUNT; ++i) core.status.reason_counts[i] = UINT32_MAX - 1;
    for (size_t pass = 0; pass < 3; ++pass) {
        wps_guard_fragment_t f = fragment(1, 4, 1, 3, 10);
        check(&core, &f, WPS_GUARD_NONE, &event);
        core.sessions[0].fragment_count = UINT32_MAX;
        core.sessions[0].retransmission_count = UINT32_MAX - 1;
        check(&core, &f, WPS_GUARD_RETRANSMISSION, &event);
        assert(event.retransmission_count == UINT32_MAX);
        check(&core, &f, WPS_GUARD_RETRANSMISSION, &event);
        assert(event.retransmission_count == UINT32_MAX);
        f = fragment(2, 6, 2, 0, 0);
        check(&core, &f, WPS_GUARD_COMPLETE, &event);
        assert(event.fragment_count == UINT32_MAX);
        assert(event.retransmission_count == UINT32_MAX);
        f = fragment(1, 4, 1, 1, 0);
        check(&core, &f, WPS_GUARD_FIRST_MISSING_LENGTH, &event);
        f = fragment(1, 4, 1, 3, 10);
        for (uint8_t i = 0; i < 8; ++i) {
            f.station[5] = (uint8_t)(40 + i);
            check(&core, &f, WPS_GUARD_NONE, &event);
        }
        f.station[5] = 99;
        check(&core, &f, WPS_GUARD_SESSION_CAPACITY, &event);
        assert(wps_guard_expire(&core, 5000101, NULL, 0) == 0);
    }
    assert(core.status.fragments == UINT32_MAX && core.status.retransmissions == UINT32_MAX);
    assert(core.status.completions == UINT32_MAX && core.status.anomalies == UINT32_MAX);
    assert(core.status.timeouts == UINT32_MAX && core.status.capacity_drops == UINT32_MAX);
    const wps_guard_reason_t counted[] = {WPS_GUARD_NONE, WPS_GUARD_RETRANSMISSION,
        WPS_GUARD_COMPLETE, WPS_GUARD_FIRST_MISSING_LENGTH,
        WPS_GUARD_SESSION_TIMEOUT, WPS_GUARD_SESSION_CAPACITY};
    for (size_t i = 0; i < sizeof(counted) / sizeof(counted[0]); ++i)
        assert(core.status.reason_counts[counted[i]] == UINT32_MAX);

    wps_guard_reset(&core);
    wps_guard_fragment_t f = fragment(1, 4, 1, 3, 10);
    f.flags = 7;
    check(&core, &f, WPS_GUARD_INVALID_ENVELOPE, &event);
    f = fragment(1, 4, 1, 3, 10);
    f.length_present = false;
    check(&core, &f, WPS_GUARD_INVALID_ENVELOPE, &event);
    f = fragment(1, 4, 1, 3, 10);
    f.input_truncated = true;
    check(&core, &f, WPS_GUARD_FRAME_TRUNCATED, &event);
    f = fragment(1, 4, 1, 3, 10);
    f.direction = (wps_guard_direction_t)2;
    check(&core, &f, WPS_GUARD_INVALID_ENVELOPE, &event);
    f = fragment(1, 4, 1, 3, 10);
    f.opcode = 0;
    check(&core, &f, WPS_GUARD_INVALID_ENVELOPE, &event);
    f = fragment(1, 4, 1, 3, 10);
    f.envelope_reason = WPS_GUARD_RETRANSMISSION;
    check(&core, &f, WPS_GUARD_INVALID_ENVELOPE, &event);
    assert(active(&core) == 0);
    assert(wps_guard_observe(NULL, &f, &event) == WPS_GUARD_INVALID_ENVELOPE);
    assert(wps_guard_observe(&core, NULL, &event) == WPS_GUARD_INVALID_ENVELOPE);
    assert(wps_guard_expire(NULL, 0, &event, 1) == 0);
    wps_guard_core_init(NULL);
    wps_guard_reset(NULL);
    wps_guard_get_status(&core, NULL);
    wps_guard_status_t status;
    memset(&status, 0xa5, sizeof(status));
    wps_guard_get_status(NULL, &status);
    const uint8_t *p = (const uint8_t *)&status;
    for (size_t i = 0; i < sizeof(status); ++i) assert(p[i] == 0);
    f = fragment(1, 4, 1, 3, 10);
    assert(wps_guard_observe(&core, &f, NULL) == WPS_GUARD_NONE);
    assert(active(&core) == 1);
}

static void test_short_and_mutated_inputs_are_bounded(void)
{
    uint32_t random = 0x2381a91b;
    uint8_t bytes[96];
    for (size_t iteration = 0; iteration < 20000; ++iteration) {
        size_t length = iteration % (sizeof(bytes) + 1);
        for (size_t i = 0; i < length; ++i) {
            random = random * UINT32_C(1664525) + UINT32_C(1013904223);
            bytes[sizeof(bytes) - length + i] = (uint8_t)(random >> 24);
        }
        uint8_t *input = bytes + sizeof(bytes) - length;
        if (length >= 18 && (iteration & 1U) != 0) {
            envelope(input, 0, 0, NULL, 0);
            be16(input + 2, (uint16_t)(length - 4));
            be16(input + 6, (uint16_t)(length - 4));
            input[17] = (uint8_t)random;
        }
        wifi_security_decoded_t frame = view(input, length);
        wps_guard_fragment_t f;
        if (wps_guard_decode_fragment(&frame, (iteration & 3U) == 0, iteration, &f)) {
            wps_guard_core_t core;
            wps_guard_event_t event;
            wps_guard_core_init(&core);
            (void)wps_guard_observe(&core, &f, &event);
        }
    }
}

static void view_failure(const wifi_security_decoded_t *frame,
                         const wps_guard_fragment_t *fragment)
{
    static const uint8_t sentinel = 1;
    const uint8_t *payload = &sentinel;
    size_t length = 99;
    assert(!wps_guard_payload_view(frame, fragment, &payload, &length));
    assert(payload == NULL && length == 0);
}

static void test_borrowed_payload_view_is_exact_and_fail_closed(void)
{
    uint8_t bytes[80];
    const uint8_t data[] = {0x10, 0x22, 0, 1, 4};
    for (uint8_t flags = 0; flags < 4; ++flags) {
        size_t size = envelope(bytes, flags, 50, data, sizeof(data));
        /* Bytes outside the exact EAPOL slice must not enter the view. */
        memset(bytes + size, 0xa5, sizeof(bytes) - size);
        wifi_security_decoded_t frame = view(bytes, size);
        wps_guard_fragment_t f;
        assert(wps_guard_decode_fragment(&frame, false, 100, &f));
        const uint8_t *payload = NULL;
        size_t length = 0;
        assert(wps_guard_payload_view(&frame, &f, &payload, &length));
        assert(payload == bytes + ((flags & 2U) ? 20 : 18));
        assert(length == sizeof(data) && length == f.payload_len);
        assert(payload + length == frame.eapol + frame.eapol_len);
        assert(memcmp(payload, data, length) == 0);
        /* Metadata state must never capture the borrowed address. */
        wps_guard_core_t core;
        wps_guard_event_t event;
        wps_guard_core_init(&core);
        (void)wps_guard_observe(&core, &f, &event);
        assert(!contains(&core, sizeof(core), (const uint8_t *)&payload, sizeof(payload)));
        assert(!contains(&event, sizeof(event), (const uint8_t *)&payload, sizeof(payload)));

        wps_guard_fragment_t bad = f;
        bad.payload_len++;
        view_failure(&frame, &bad);
        bad = f; bad.payload_hash++;
        view_failure(&frame, &bad);
        bad = f; bad.declared_total++;
        view_failure(&frame, &bad);
        bad = f; bad.eap_id++;
        view_failure(&frame, &bad);
        bad = f; bad.opcode++;
        view_failure(&frame, &bad);
        bad = f; bad.flags ^= 1U;
        view_failure(&frame, &bad);
        bad = f; bad.more_fragments = !bad.more_fragments;
        view_failure(&frame, &bad);
        bad = f; bad.length_present = !bad.length_present;
        view_failure(&frame, &bad);
        bad = f; bad.bssid[5]++;
        view_failure(&frame, &bad);
        bad = f; bad.station[5]++;
        view_failure(&frame, &bad);
        bad = f; bad.direction = WPS_GUARD_DIR_STA_TO_AP;
        view_failure(&frame, &bad);
        bad = f; bad.input_truncated = true;
        view_failure(&frame, &bad);
        bad = f; bad.envelope_reason = WPS_GUARD_INVALID_ENVELOPE;
        view_failure(&frame, &bad);
        frame.eapol_len--;
        view_failure(&frame, &f);
        frame.eapol_len += 2;
        view_failure(&frame, &f);
        frame.eapol_len--;
        bytes[2] ^= 1U;
        view_failure(&frame, &f);
        bytes[2] ^= 1U;
        bytes[6] ^= 1U;
        view_failure(&frame, &f);
        bytes[6] ^= 1U;
        frame.protected_frame = true;
        view_failure(&frame, &f);
        frame.protected_frame = false;
        view_failure(NULL, &f);
        view_failure(&frame, NULL);
        payload = data; length = 1;
        assert(!wps_guard_payload_view(&frame, &f, NULL, &length) && length == 0);
        assert(!wps_guard_payload_view(&frame, &f, &payload, NULL) && payload == NULL);
    }
    size_t size = envelope(bytes, 0, 0, NULL, 0);
    wifi_security_decoded_t frame = view(bytes, size);
    wps_guard_fragment_t f;
    assert(wps_guard_decode_fragment(&frame, false, 0, &f));
    const uint8_t *payload = NULL;
    size_t length = 99;
    assert(wps_guard_payload_view(&frame, &f, &payload, &length));
    assert(payload == bytes + 18 && length == 0);
    for (size_t n = 0; n < size; ++n) {
        frame.eapol_len = n;
        view_failure(&frame, &f);
    }
}

int main(void)
{
    test_envelope_fields_and_offsets();
    test_unrelated_and_malformed_envelopes();
    test_real_fragment_sequence_and_retransmission();
    test_decode_to_observe_exact_4096_and_truncated_terminal();
    test_first_fragment_and_standalone_boundaries();
    test_terminal_anomalies_clear_flow();
    test_flow_keys_and_eight_session_capacity();
    test_timeout_boundaries_metadata_and_output_capacity();
    test_payload_hygiene_after_process_and_reset();
    test_saturating_counters_and_invalid_api_metadata();
    test_short_and_mutated_inputs_are_bounded();
    test_borrowed_payload_view_is_exact_and_fail_closed();
    for (size_t i = 0; i < WPS_GUARD_REASON_COUNT; ++i) assert(reasons_seen[i]);
    puts("PASS: passive WPS Guard envelopes, sequences, hygiene");
    return 0;
}
