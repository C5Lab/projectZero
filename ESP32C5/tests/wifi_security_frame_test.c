#include "wifi_security_frame.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t ap[6] = {2, 16, 32, 48, 64, 80};
static const uint8_t sta[6] = {4, 17, 33, 49, 65, 81};
static const uint8_t dest[6] = {6, 18, 34, 50, 66, 82};
static const uint8_t zero[6] = {0};
static const uint8_t group[6] = {1, 0, 94, 0, 0, 1};

/* ToDS data: seq 0x123, fragment 0; exact RFC1042 EAPOL SNAP, then 4 bytes. */
static const uint8_t data[] = {
    0x08, 0x01, 0, 0,
    2, 16, 32, 48, 64, 80,
    4, 17, 33, 49, 65, 81,
    6, 18, 34, 50, 66, 82,
    0x30, 0x12,
    0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e,
    2, 0, 0, 0
};
static const uint8_t beacon[] = {
    0x80, 0x08, 0, 0,
    255, 255, 255, 255, 255, 255,
    2, 16, 32, 48, 64, 80,
    2, 16, 32, 48, 64, 80,
    0xc0, 0xab,
    0, 0, 0, 0, 0, 0, 0, 0, 0x64, 0, 0x11, 0
};
static const uint8_t auth[] = {
    0xb0, 0, 0, 0,
    2, 16, 32, 48, 64, 80,
    4, 17, 33, 49, 65, 81,
    2, 16, 32, 48, 64, 80,
    0x10, 0,
    3, 0, 1, 0, 0, 0 /* SAE algorithm 3, transaction 1, success. */
};

static void equal_addr(const uint8_t actual[6], const uint8_t expected[6])
{
    assert(memcmp(actual, expected, 6) == 0);
}

static void hidden_body(const wifi_security_decoded_t *out)
{
    assert(out->body == NULL && out->body_len == 0);
    assert(out->eapol == NULL && out->eapol_len == 0);
}

/* Catches wrong management subtype, sequence endian/shift, or peer derivation. */
static void management(void)
{
    wifi_security_decoded_t out;
    uint8_t frame[sizeof(beacon)];
    assert(wifi_security_decode(beacon, sizeof(beacon), &out));
    assert(out.kind == WIFI_SEC_FRAME_BEACON && out.subtype == 8);
    assert(out.retry && !out.protected_frame && !out.to_ds && !out.from_ds && !out.qos);
    assert(out.sequence == 0xabc);
    equal_addr(out.addr1, beacon + 4);
    equal_addr(out.addr2, ap);
    equal_addr(out.addr3, ap);
    equal_addr(out.bssid, ap);
    equal_addr(out.station, zero);
    assert(out.body == beacon + 24 && out.body_len == 12);
    assert(out.eapol == NULL && out.eapol_len == 0);

    memcpy(frame, beacon, sizeof(frame));
    frame[0] = 0x50; /* Probe response to a single station. */
    memcpy(frame + 4, sta, 6);
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    assert(out.kind == WIFI_SEC_FRAME_PROBE_RESPONSE && out.subtype == 5);
    equal_addr(out.station, sta);
    memcpy(frame + 4, group, 6);
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    equal_addr(out.station, zero);

    memcpy(frame + 10, sta, 6); /* A beacon cannot come from another transmitter. */
    assert(!wifi_security_decode(frame, sizeof(frame), &out));
    memcpy(frame, beacon, sizeof(frame));
    for (size_t offset = 4; offset <= 16; offset += 6) {
        memset(frame + offset, 0, 6);
        assert(!wifi_security_decode(frame, sizeof(frame), &out));
        memcpy(frame, beacon, sizeof(frame));
    }
    memcpy(frame + 16, group, 6);
    assert(!wifi_security_decode(frame, sizeof(frame), &out));

    assert(wifi_security_decode(auth, sizeof(auth), &out));
    assert(out.kind == WIFI_SEC_FRAME_AUTH && out.subtype == 11);
    assert(out.sequence == 1 && !out.retry);
    equal_addr(out.bssid, ap);
    equal_addr(out.station, sta);
    assert(out.body == auth + 24 && out.body_len == 6 && out.body[0] == 3);
    memcpy(frame, auth, sizeof(auth));
    memcpy(frame + 4, sta, 6);
    memcpy(frame + 10, ap, 6);
    assert(wifi_security_decode(frame, sizeof(auth), &out));
    equal_addr(out.station, sta);
    frame[0] = 0xc0; /* Other management: deauthentication. */
    assert(wifi_security_decode(frame, 26, &out));
    assert(out.kind == WIFI_SEC_FRAME_MGMT && out.subtype == 12);
    frame[1] = 0x80; /* Management HT control is included in header length. */
    assert(!wifi_security_decode(frame, 27, &out));
    assert(wifi_security_decode(frame, 30, &out));
    assert(out.body == frame + 28 && out.body_len == 2);
    frame[1] = 0x40;
    assert(wifi_security_decode(frame, 26, &out));
    assert(out.protected_frame);
    hidden_body(&out);
}

/* Catches swapped DS roles and guessing a station from multicast/no-DS traffic. */
static void directions_and_payload(void)
{
    uint8_t frame[sizeof(data)];
    wifi_security_decoded_t out;
    assert(wifi_security_decode(data, sizeof(data), &out));
    assert(out.kind == WIFI_SEC_FRAME_EAPOL && out.subtype == 0);
    assert(out.to_ds && !out.from_ds && !out.qos && !out.retry && !out.protected_frame);
    assert(out.sequence == 0x123);
    equal_addr(out.addr1, ap);
    equal_addr(out.addr2, sta);
    equal_addr(out.addr3, dest);
    equal_addr(out.bssid, ap);
    equal_addr(out.station, sta);
    assert(out.body == data + 24 && out.body_len == 12);
    assert(out.eapol == data + 32 && out.eapol_len == 4);
    memcpy(frame, data, sizeof(frame));
    memcpy(frame + 16, group, 6);
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    equal_addr(out.station, sta);
    memcpy(frame + 10, ap, 6); /* Distinctness is not an extra decoding policy. */
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    equal_addr(out.station, ap);

    frame[1] = 0x0a; /* FromDS and retry. */
    memcpy(frame + 4, sta, 6);
    memcpy(frame + 10, ap, 6);
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    assert(out.from_ds && !out.to_ds && out.retry);
    equal_addr(out.bssid, ap);
    equal_addr(out.station, sta);
    memcpy(frame + 4, group, 6);
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    equal_addr(out.bssid, ap);
    equal_addr(out.station, zero);

    frame[1] = 0; /* No DS: preserve bytes, never guess derived identities. */
    memcpy(frame + 16, ap, 6);
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    assert(out.kind == WIFI_SEC_FRAME_EAPOL);
    equal_addr(out.bssid, zero);
    equal_addr(out.station, zero);
    assert(out.body_len == 12);
    frame[24] = 0;
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    assert(out.kind == WIFI_SEC_FRAME_DATA && out.eapol == NULL && out.eapol_len == 0);
    equal_addr(out.bssid, zero);
    equal_addr(out.station, zero);

    memcpy(frame, data, sizeof(frame));
    frame[1] = 0x49; /* ToDS, retry, protected: apparent SNAP must stay hidden. */
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    assert(out.kind == WIFI_SEC_FRAME_DATA && out.protected_frame && out.retry);
    equal_addr(out.bssid, ap);
    equal_addr(out.station, sta);
    hidden_body(&out);
}

/* Wildcard probe requests are valid MGMT, without inferred AP/peer identity. */
static void wildcard_management(void)
{
    uint8_t frame[sizeof(data)];
    wifi_security_decoded_t out;
    memcpy(frame, data, sizeof(frame));
    frame[0] = 0x40;
    frame[1] = 0;
    memset(frame + 4, 255, 6);
    memset(frame + 16, 255, 6);
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    assert(out.kind == WIFI_SEC_FRAME_MGMT && out.subtype == 4);
    equal_addr(out.bssid, zero);
    equal_addr(out.station, zero);
    assert(out.body == frame + 24 && out.body_len == 12);
    assert(out.eapol == NULL && out.eapol_len == 0);
    memcpy(frame + 16, dest, 6); /* Unicast BSSID, but neither endpoint matches. */
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    equal_addr(out.bssid, zero);
    equal_addr(out.station, zero);
    memset(frame + 16, 0, 6); /* Unknown generic-management identity. */
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    equal_addr(out.bssid, zero);
    memset(frame + 10, 0, 6);
    assert(!wifi_security_decode(frame, sizeof(frame), &out));
}

/* Catches fixed 24-byte offsets for QoS/HT and false LLC/EAPOL recognition. */
static void qos_and_llc(void)
{
    uint8_t frame[42] = {0};
    wifi_security_decoded_t out;
    memcpy(frame, data, 24);
    frame[0] = 0x88;
    frame[24] = 5; frame[25] = 0;
    memcpy(frame + 26, data + 24, 12);
    assert(wifi_security_decode(frame, 38, &out));
    assert(out.qos && out.subtype == 8 && out.kind == WIFI_SEC_FRAME_EAPOL);
    assert(out.body == frame + 26 && out.body_len == 12);
    assert(out.eapol == frame + 34 && out.eapol_len == 4);
    frame[1] = 0x41;
    assert(wifi_security_decode(frame, 38, &out));
    assert(out.qos && out.kind == WIFI_SEC_FRAME_DATA && out.protected_frame);
    hidden_body(&out);
    frame[1] = 1;
    assert(!wifi_security_decode(frame, 24, &out));
    assert(!wifi_security_decode(frame, 25, &out));
    frame[1] = 0x81; /* QoS + Order adds the 4-byte HT control. */
    memmove(frame + 30, frame + 26, 12);
    memset(frame + 26, 0, 4);
    assert(!wifi_security_decode(frame, 29, &out));
    assert(wifi_security_decode(frame, 42, &out));
    assert(out.body == frame + 30 && out.eapol == frame + 38 && out.eapol_len == 4);
    frame[24] = 0x85; /* A-MSDU: body has a different encapsulation. */
    assert(wifi_security_decode(frame, 42, &out));
    assert(out.kind == WIFI_SEC_FRAME_DATA && out.eapol == NULL);

    /* Every single SNAP octet matters; no OUI or EtherType shortcuts. */
    for (size_t i = 24; i < 32; ++i) {
        memcpy(frame, data, sizeof(data));
        frame[i] ^= 1;
        assert(wifi_security_decode(frame, sizeof(data), &out));
        assert(out.kind == WIFI_SEC_FRAME_DATA && out.eapol == NULL && out.eapol_len == 0);
    }
    memcpy(frame, data, sizeof(data));
    for (size_t length = 24; length < 32; ++length) {
        assert(wifi_security_decode(frame, length, &out));
        assert(out.kind == WIFI_SEC_FRAME_DATA && out.eapol == NULL);
    }
    assert(wifi_security_decode(frame, 32, &out));
    assert(out.kind == WIFI_SEC_FRAME_EAPOL && out.eapol == frame + 32 && out.eapol_len == 0);
    frame[22] = 0x31; /* Fragment 1 cannot begin a complete LLC MSDU. */
    assert(wifi_security_decode(frame, sizeof(data), &out));
    assert(out.kind == WIFI_SEC_FRAME_DATA && out.eapol == NULL);
    frame[22] = 0x30; frame[1] = 5; /* More fragments. */
    assert(wifi_security_decode(frame, sizeof(data), &out));
    assert(out.kind == WIFI_SEC_FRAME_DATA && out.eapol == NULL);
    frame[1] = 1; frame[0] = 0x48; /* Null data has no LLC MSDU. */
    assert(wifi_security_decode(frame, sizeof(data), &out));
    assert(out.kind == WIFI_SEC_FRAME_DATA && out.eapol == NULL);
}

/* Catches accepting malformed role addresses, DS flags or reserved versions. */
static void rejected_inputs(void)
{
    uint8_t frame[sizeof(data)];
    wifi_security_decoded_t out;
    assert(!wifi_security_decode(NULL, 0, &out));
    assert(!wifi_security_decode(data, sizeof(data), NULL));
    memcpy(frame, data, sizeof(frame));
    frame[1] = 3;
    assert(!wifi_security_decode(frame, sizeof(frame), &out));
    for (size_t offset = 4; offset <= 16; offset += 6) {
        memcpy(frame, data, sizeof(frame));
        memset(frame + offset, 0, 6);
        assert(!wifi_security_decode(frame, sizeof(frame), &out));
    }
    for (size_t offset = 4; offset <= 10; offset += 6) {
        memcpy(frame, data, sizeof(frame));
        memcpy(frame + offset, group, 6);
        assert(!wifi_security_decode(frame, sizeof(frame), &out));
    }
    memcpy(frame, data, sizeof(frame));
    frame[1] = 2;
    memcpy(frame + 10, group, 6);
    assert(!wifi_security_decode(frame, sizeof(frame), &out));
    for (size_t offset = 4; offset <= 16; offset += 6) {
        memcpy(frame, data, sizeof(frame));
        frame[1] = 2;
        memset(frame + offset, 0, 6);
        assert(!wifi_security_decode(frame, sizeof(frame), &out));
    }
    memcpy(frame, auth, sizeof(auth));
    frame[1] = 1;
    assert(!wifi_security_decode(frame, sizeof(auth), &out));
    memcpy(frame, auth, sizeof(auth));
    memcpy(frame + 16, dest, 6); /* Neither endpoint is BSSID. */
    assert(!wifi_security_decode(frame, sizeof(auth), &out));
    memcpy(frame, auth, sizeof(auth));
    memcpy(frame + 10, group, 6);
    assert(!wifi_security_decode(frame, sizeof(auth), &out));
    memcpy(frame, auth, sizeof(auth));
    memcpy(frame + 4, group, 6);
    assert(!wifi_security_decode(frame, sizeof(auth), &out));
    memcpy(frame, data, sizeof(frame));
    frame[0] |= 1;
    assert(!wifi_security_decode(frame, sizeof(frame), &out));
    frame[0] = 0x0c; /* Reserved frame type. */
    assert(!wifi_security_decode(frame, sizeof(frame), &out));
}

/* Catches a blanket 24-byte control minimum or acceptance of truncated controls. */
static void controls(void)
{
    const uint8_t ack[] = {0xd4, 0, 0, 0, 4, 17, 33, 49, 65, 81};
    const uint8_t rts[] = {0xb4, 0, 0, 0, 2, 16, 32, 48, 64, 80,
                         4, 17, 33, 49, 65, 81};
    uint8_t frame[28] = {0};
    wifi_security_decoded_t out;
    assert(wifi_security_decode(ack, sizeof(ack), &out));
    assert(out.kind == WIFI_SEC_FRAME_UNSUPPORTED && out.subtype == 13);
    equal_addr(out.addr1, sta);
    equal_addr(out.addr2, zero);
    equal_addr(out.bssid, zero);
    equal_addr(out.station, zero);
    hidden_body(&out);
    assert(!wifi_security_decode(ack, 9, &out));
    assert(wifi_security_decode(rts, sizeof(rts), &out));
    assert(out.kind == WIFI_SEC_FRAME_UNSUPPORTED && out.subtype == 11);
    equal_addr(out.addr2, sta);
    assert(!wifi_security_decode(rts, 15, &out));
    memcpy(frame, ack, sizeof(ack));
    frame[0] = 0xc4; /* CTS has only a receiver, like ACK. */
    assert(wifi_security_decode(frame, 10, &out));
    assert(out.kind == WIFI_SEC_FRAME_UNSUPPORTED && out.subtype == 12);
    frame[1] = 1;
    assert(!wifi_security_decode(frame, 10, &out));
    frame[1] = 0;
    memset(frame + 4, 0, 6);
    assert(!wifi_security_decode(frame, 10, &out));
    memcpy(frame, rts, sizeof(rts));
    frame[0] = 0x84; /* Block Ack Request needs control and start sequence. */
    assert(!wifi_security_decode(frame, 19, &out));
    assert(wifi_security_decode(frame, 20, &out));
    assert(out.kind == WIFI_SEC_FRAME_UNSUPPORTED);
    frame[0] = 0x94; /* Compressed Block Ack adds an 8-byte bitmap. */
    frame[16] = 4; /* Compressed-bitmap bit in BA Control. */
    assert(!wifi_security_decode(frame, 27, &out));
    assert(wifi_security_decode(frame, 28, &out));
    assert(out.kind == WIFI_SEC_FRAME_UNSUPPORTED);
    memcpy(frame + 10, group, 6);
    assert(!wifi_security_decode(frame, 28, &out));
}

/* Exact allocations let ASan detect reads beyond the declared frame length. */
static void bounds_and_unaligned(void)
{
    wifi_security_decoded_t out;
    for (size_t length = 0; length < 24; ++length) {
        uint8_t *frame = malloc(length ? length : 1);
        assert(frame != NULL);
        memcpy(frame, data, length);
        assert(!wifi_security_decode(frame, length, &out));
        free(frame);
    }
    uint8_t header[24];
    memcpy(header, data, 24);
    assert(wifi_security_decode(header, 24, &out));
    assert(out.kind == WIFI_SEC_FRAME_DATA && out.body == header + 24 && out.body_len == 0);
    uint8_t large[1537] = {0};
    memcpy(large, data, sizeof(data));
    assert(wifi_security_decode(large, 1536, &out));
    assert(out.body_len == 1512 && out.eapol_len == 1504);
    assert(!wifi_security_decode(large, 1537, &out));
    /* A rejected decode must not retain views/identities from the previous one. */
    equal_addr(out.bssid, zero);
    equal_addr(out.station, zero);
    assert(out.kind == WIFI_SEC_FRAME_UNSUPPORTED);
    hidden_body(&out);
    uint8_t odd[sizeof(data) + 1];
    memcpy(odd + 1, data, sizeof(data));
    assert(wifi_security_decode(odd + 1, sizeof(data), &out));
    assert(out.sequence == 0x123 && out.eapol == odd + 33);
}

/* Catches treating ACK RA or no-DS BSSID as a generic nonzero destination. */
static void individual_role_rejections(void)
{
    const uint8_t multicast_ack[] = {0xd4, 0, 0, 0, 1, 0, 94, 0, 0, 1};
    uint8_t frame[sizeof(data)];
    wifi_security_decoded_t out;
    assert(wifi_security_decode(data, sizeof(data), &out));
    const bool ack_rejected = !wifi_security_decode(multicast_ack, sizeof(multicast_ack), &out);
    if (!ack_rejected) {
        fputs("FAIL: multicast ACK receiver accepted\n", stderr);
    }

    memcpy(frame, data, sizeof(frame));
    frame[1] = 0;
    assert(wifi_security_decode(frame, sizeof(frame), &out));
    memcpy(frame + 16, group, 6);
    const bool bssid_rejected = !wifi_security_decode(frame, sizeof(frame), &out);
    if (!bssid_rejected) {
        fputs("FAIL: DS=00 multicast BSSID accepted\n", stderr);
    } else {
        assert(out.kind == WIFI_SEC_FRAME_UNSUPPORTED && out.subtype == 0);
        equal_addr(out.addr1, zero);
        equal_addr(out.addr2, zero);
        equal_addr(out.addr3, zero);
        equal_addr(out.bssid, zero);
        equal_addr(out.station, zero);
        assert(out.sequence == 0 && !out.retry && !out.protected_frame);
        assert(!out.to_ds && !out.from_ds && !out.qos);
        hidden_body(&out);
    }

    /* Group-addressed CF-End remains a valid unsupported control frame. */
    memcpy(frame, data, 16);
    frame[0] = 0xe4;
    frame[1] = 0;
    memset(frame + 4, 255, 6);
    assert(wifi_security_decode(frame, 16, &out));
    assert(out.kind == WIFI_SEC_FRAME_UNSUPPORTED && out.subtype == 14);
    hidden_body(&out);
    frame[0] = 0xf4;
    assert(wifi_security_decode(frame, 16, &out));
    assert(out.kind == WIFI_SEC_FRAME_UNSUPPORTED && out.subtype == 15);
    assert(ack_rejected && bssid_rejected);
}

int main(void)
{
    management();
    directions_and_payload();
    wildcard_management();
    qos_and_llc();
    rejected_inputs();
    controls();
    bounds_and_unaligned();
    individual_role_rejections();
    puts("PASS: bounded Wi-Fi security frame decoder");
    return 0;
}
