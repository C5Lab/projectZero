#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "m3_protocol.h"

static void be16(uint8_t *p, unsigned n) { p[0] = n >> 8; p[1] = n; }
static size_t attr(uint8_t *p, unsigned type, const uint8_t *data, size_t n) {
    be16(p, type); be16(p + 2, n); memcpy(p + 4, data, n); return n + 4;
}
static size_t frame(uint8_t *out, unsigned id, const uint8_t *attrs, size_t n) {
    memset(out, 0, 18); out[0] = 1; out[4] = 1; out[5] = id;
    out[8] = 254; out[10] = 0x37; out[11] = 0x2a; out[15] = 1; out[16] = 4;
    be16(out + 2, n + 14); be16(out + 6, n + 14);
    memcpy(out + 18, attrs, n); return n + 18;
}

int main(void) {
    uint8_t a[512], f[600], nonce[16], mac[6], pke[192], hash1[32], hash2[32], auth[8];
    memset(nonce, 7, sizeof(nonce)); memset(mac, 2, sizeof(mac));
    memset(pke, 3, sizeof(pke)); memset(hash1, 4, sizeof(hash1));
    memset(hash2, 5, sizeof(hash2)); memset(auth, 6, sizeof(auth));
    const uint8_t version = 0x10, m1_type = 4, m3_type = 7;
    const uint8_t pin_mode[] = {0, 0}, button_mode[] = {0, 4};
    size_t n = 0;
    n += attr(a + n, 0x104a, &version, 1);
    n += attr(a + n, 0x1022, &m1_type, 1);
    n += attr(a + n, 0x101a, nonce, 16);
    n += attr(a + n, 0x1020, mac, 6);
    n += attr(a + n, 0x1032, pke, 192);
    size_t password_id_offset = n;
    n += attr(a + n, 0x1012, pin_mode, sizeof(pin_mode));
    n += attr(a + n, 0x1021, (const uint8_t *)"Realtek", 7);
    n += attr(a + n, 0x1023, (const uint8_t *)"RTL8xxx", 7);
    n += attr(a + n, 0x1024, (const uint8_t *)"1.0", 3);
    n += attr(a + n, 0x1011, (const uint8_t *)"Lab Router", 10);
    size_t flen = frame(f, 23, a, n);
    m3_m1_t m1;
    assert(m3_parse_m1(f, flen, &m1));
    assert(m1.eap_id == 23 && m1.attrs_len == n);
    assert(memcmp(m1.enrollee_nonce, nonce, 16) == 0);
    assert(memcmp(m1.public_key, pke, 192) == 0);
    assert(m1.dev_password_id == 0 && m1.pin_mode);
    assert(strcmp(m1.manufacturer, "Realtek") == 0);
    assert(strcmp(m1.model_name, "RTL8xxx") == 0);
    assert(strcmp(m1.model_number, "1.0") == 0);
    assert(strcmp(m1.device_name, "Lab Router") == 0);
    assert(!m1.wsc2);
    assert(!m3_parse_m1(f, flen - 1, &m1));
    n += attr(a + n, 0x1020, mac, 6);
    flen = frame(f, 23, a, n);
    assert(!m3_parse_m1(f, flen, &m1));
    n -= 10;
    memcpy(a + password_id_offset + 4, button_mode, 2);
    flen = frame(f, 23, a, n);
    assert(m3_parse_m1(f, flen, &m1));
    assert(m1.dev_password_id == 4 && !m1.pin_mode);
    memcpy(a + password_id_offset + 4, pin_mode, 2);
    const uint8_t wfa_version2[] = {0, 0x37, 0x2a, 0, 1, 0x20};
    n += attr(a + n, 0x1049, wfa_version2, sizeof(wfa_version2));
    flen = frame(f, 23, a, n);
    assert(m3_parse_m1(f, flen, &m1) && m1.wsc2);

    uint8_t registrar_nonce[16], uuid[16], pkr[192], body[512], reply[600];
    memset(registrar_nonce, 9, 16); memset(uuid, 10, 16); memset(pkr, 11, 192);
    size_t body_len = m3_build_m2_body(body, sizeof(body), nonce, registrar_nonce, uuid, pkr, 1, true);
    assert(body_len > 240);
    assert(body[0] == 0x10 && body[1] == 0x4a && body[4] == 0x10);
    assert(body[5] == 0x10 && body[6] == 0x22 && body[9] == 5);
    assert(body[body_len - 10] == 0x10 && body[body_len - 9] == 0x49);
    assert(memcmp(body + body_len - 6, wfa_version2, 6) == 0);
    assert(m3_build_m2_body(body, 20, nonce, registrar_nonce, uuid, pkr, 1, true) == 0);
    size_t reply_len = m3_wrap_m2(reply, sizeof(reply), 24, body, body_len);
    assert(reply_len == body_len + 18 && reply[0] == 1 && reply[4] == 2);
    assert(reply[5] == 24 && reply[8] == 254 && reply[16] == 4);
    assert(m3_wrap_m2(reply, 10, 24, body, body_len) == 0);

    n = 0;
    n += attr(a + n, 0x104a, &version, 1);
    n += attr(a + n, 0x1022, &m3_type, 1);
    n += attr(a + n, 0x1039, registrar_nonce, 16);
    n += attr(a + n, 0x1014, hash1, 32);
    n += attr(a + n, 0x1015, hash2, 32);
    size_t body_without_auth = n;
    n += attr(a + n, 0x1005, auth, 8);
    flen = frame(f, 24, a, n);
    m3_m3_t m3;
    assert(m3_parse_m3(f, flen, 24, registrar_nonce, &m3));
    assert(m3.body_len == body_without_auth && memcmp(m3.authenticator, auth, 8) == 0);
    assert(memcmp(m3.e_hash1, hash1, 32) == 0 && memcmp(m3.e_hash2, hash2, 32) == 0);
    assert(!m3_parse_m3(f, flen, 25, registrar_nonce, &m3));
    registrar_nonce[0] ^= 1;
    assert(!m3_parse_m3(f, flen, 24, registrar_nonce, &m3));
    registrar_nonce[0] ^= 1;
    f[17] = 1;
    assert(!m3_parse_m3(f, flen, 24, registrar_nonce, &m3));
    f[17] = 0;
    assert(!m3_parse_m3(f, flen - 1, 24, registrar_nonce, &m3));
    n += attr(a + n, 0x1014, hash1, 32);
    flen = frame(f, 24, a, n);
    assert(!m3_parse_m3(f, flen, 24, registrar_nonce, &m3));
    puts("PASS: M1 fields, M2 framing, M3 fields and malformed input");
    return 0;
}
