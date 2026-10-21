#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pin_protocol.h"

static void be16(uint8_t *p, unsigned v) { p[0] = v >> 8; p[1] = v; }
static size_t tlv(uint8_t *p, unsigned type, const void *v, size_t n) {
    be16(p, type); be16(p + 2, n); memcpy(p + 4, v, n); return n + 4;
}

int main(void) {
    uint8_t ne[16], nr[16], rh1[32], rh2[32], enc[48], auth[8], body[512];
    memset(ne, 1, 16); memset(nr, 2, 16); memset(rh1, 3, 32); memset(rh2, 4, 32);
    memset(enc, 5, sizeof(enc)); memset(auth, 6, sizeof(auth));
    size_t n = pin_build_m4_body(body, sizeof(body), ne, rh1, rh2, enc, sizeof(enc), true);
    assert(n > 0 && pin_append_authenticator(body, sizeof(body), n, auth) == n + 12);

    uint8_t m5[256], version = 0x10, type = 9; size_t p = 0;
    p += tlv(m5 + p, 0x104a, &version, 1); p += tlv(m5 + p, 0x1022, &type, 1);
    p += tlv(m5 + p, 0x1039, nr, 16); p += tlv(m5 + p, 0x1018, enc, sizeof(enc));
    size_t before_auth = p; p += tlv(m5 + p, 0x1005, auth, 8);
    pin_secure_message_t parsed;
    assert(pin_parse_secure_message(m5, p, 9, nr, &parsed));
    assert(parsed.body_len == before_auth && parsed.encrypted_len == sizeof(enc));
    assert(memcmp(parsed.authenticator, auth, 8) == 0);
    assert(!pin_parse_secure_message(m5, p - 1, 9, nr, &parsed));
    m5[p - 1] ^= 1; /* Auth bytes are data, not framing: still structurally valid. */
    assert(pin_parse_secure_message(m5, p, 9, nr, &parsed));
    m5[p - 1] ^= 1;
    p += tlv(m5 + p, 0x1018, enc, sizeof(enc));
    assert(!pin_parse_secure_message(m5, p, 9, nr, &parsed));

    /* The frame-level parser must bind the attributes to the exact EAP/WSC
     * envelope and identifier, not merely find a Message Type TLV. */
    p -= sizeof(enc) + 4;
    uint8_t frame[320] = {0};
    frame[0] = 1; frame[4] = 1; frame[5] = 42;
    frame[8] = 254; frame[10] = 0x37; frame[11] = 0x2a;
    frame[15] = 1; frame[16] = 4;
    be16(frame + 2, p + 14); be16(frame + 6, p + 14);
    memcpy(frame + 18, m5, p);
    assert(pin_parse_secure_frame(frame, p + 18, 9, 42, nr, &parsed));
    assert(parsed.attrs == frame + 18 && parsed.attrs_len == p);
    frame[5] = 43;
    assert(!pin_parse_secure_frame(frame, p + 18, 9, 42, nr, &parsed));
    frame[5] = 42; frame[17] = 1;
    assert(!pin_parse_secure_frame(frame, p + 18, 9, 42, nr, &parsed));
    frame[17] = 0; be16(frame + 2, p + 13);
    assert(!pin_parse_secure_frame(frame, p + 18, 9, 42, nr, &parsed));

    uint8_t m6[256]; n = pin_build_m6_body(m6, sizeof(m6), ne, enc, sizeof(enc), true);
    assert(n > 0 && pin_append_authenticator(m6, sizeof(m6), n, auth) == n + 12);

    uint8_t inner[256], es[16], ssid[] = "lab", key[] = "secret-pass";
    memset(es, 7, sizeof(es)); p = 0;
    p += tlv(inner + p, 0x1017, es, 16);
    p += tlv(inner + p, 0x1045, ssid, sizeof(ssid) - 1);
    const uint8_t auth_type[] = {0, 0x20}, encr_type[] = {0, 8};
    p += tlv(inner + p, 0x1003, auth_type, 2);
    p += tlv(inner + p, 0x100f, encr_type, 2);
    p += tlv(inner + p, 0x1027, key, sizeof(key) - 1);
    size_t kwa_body = p; p += tlv(inner + p, 0x101e, auth, 8);
    pin_inner_t in;
    assert(pin_parse_inner(inner, p, 0x1017, &in));
    assert(in.body_len == kwa_body && in.snonce && in.credential_present);
    assert(in.ssid_len == 3 && memcmp(in.ssid, "lab", 3) == 0);
    assert(in.network_key_len == 11 && memcmp(in.network_key, "secret-pass", 11) == 0);
    assert(in.auth_type == 0x20 && in.encr_type == 8);
    inner[p - 12] = 0x10; inner[p - 11] = 0x27; /* Duplicate Network Key instead of KWA. */
    assert(!pin_parse_inner(inner, p, 0x1017, &in));
    assert(pin_validate_wps_pin("1234", 4));
    assert(pin_validate_wps_pin("12345670", 8));
    assert(!pin_validate_wps_pin("12345671", 8));
    assert(!pin_validate_wps_pin("123456789", 9));
    assert(!pin_validate_wps_pin("1234567x", 8));
    puts("PASS: M4/M6 construction and bounded M5/M7 parser");
}
