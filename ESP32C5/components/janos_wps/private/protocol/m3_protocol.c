#include "m3_protocol.h"
#include <string.h>

static unsigned be16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }
static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

static bool copy_identity(char output[M3_IDENTITY_TEXT_MAX + 1],
                          const uint8_t *value, size_t length) {
    if (length > M3_IDENTITY_TEXT_MAX) return false;
    for (size_t index = 0; index < length; ++index)
        output[index] = value[index] >= 0x20 && value[index] <= 0x7e ?
                            (char)value[index] : '?';
    output[length] = 0;
    return true;
}

static bool attrs_from_frame(const uint8_t *f, size_t len, const uint8_t **a,
                             size_t *n, uint8_t *id) {
    if (!f || len < 18 || f[0] < 1 || f[0] > 3 || f[1] != 0 ||
        f[4] != 1 || f[8] != 254 || f[9] != 0 || f[10] != 0x37 ||
        f[11] != 0x2a || f[12] != 0 || f[13] != 0 || f[14] != 0 ||
        f[15] != 1 || f[16] != 4 || f[17] != 0 ||
        be16(f + 2) != len - 4 || be16(f + 6) != len - 4 ||
        len - 18 > M3_MAX_ATTRS) return false;
    *a = f + 18; *n = len - 18; *id = f[5]; return true;
}

static bool parse_attrs(const uint8_t *a, size_t n, uint8_t wanted,
                        const uint8_t expected_nonce[16], m3_m1_t *m1,
                        m3_m3_t *m3) {
    unsigned seen = 0;
    size_t pos = 0;
    while (pos < n) {
        if (n - pos < 4) return false;
        unsigned type = be16(a + pos), size = be16(a + pos + 2), bit = 0;
        size_t start = pos; pos += 4;
        if (size > n - pos) return false;
        const uint8_t *v = a + pos;
        if (type == 0x104a) { bit = 1; if (size != 1 || v[0] != 0x10) return false; }
        if (type == 0x1022) { bit = 2; if (size != 1 || v[0] != wanted) return false; }
        if (type == (wanted == 4 ? 0x101a : 0x1039)) {
            bit = 4; if (size != 16) return false;
            if (m1) memcpy(m1->enrollee_nonce, v, 16);
            if (m3 && memcmp(v, expected_nonce, 16)) return false;
        }
        if (wanted == 4 && type == 0x1020) {
            bit = 8; if (size != 6) return false;
            memcpy(m1->enrollee_mac, v, 6);
        }
        if (wanted == 4 && type == 0x1032) {
            bit = 16; if (size != 192) return false;
            memcpy(m1->public_key, v, 192);
        }
        if (wanted == 4 && type == 0x1012) {
            bit = 32; if (size != 2) return false;
            m1->dev_password_id = (uint16_t)be16(v);
            m1->pin_mode = m1->dev_password_id == 0;
        }
        if (wanted == 4 && type == 0x1021) {
            bit = 64; if (!copy_identity(m1->manufacturer, v, size)) return false;
        }
        if (wanted == 4 && type == 0x1023) {
            bit = 128; if (!copy_identity(m1->model_name, v, size)) return false;
        }
        if (wanted == 4 && type == 0x1024) {
            bit = 256; if (!copy_identity(m1->model_number, v, size)) return false;
        }
        if (wanted == 4 && type == 0x1011) {
            bit = 512; if (!copy_identity(m1->device_name, v, size)) return false;
        }
        if (wanted == 4 && type == 0x1049 && size >= 6 &&
            v[0] == 0 && v[1] == 0x37 && v[2] == 0x2a &&
            v[3] == 0 && v[4] == 1 && v[5] >= 0x20) m1->wsc2 = true;
        if (wanted == 7 && type == 0x1014) {
            bit = 8; if (size != 32) return false;
            memcpy(m3->e_hash1, v, 32);
        }
        if (wanted == 7 && type == 0x1015) {
            bit = 16; if (size != 32) return false;
            memcpy(m3->e_hash2, v, 32);
        }
        if (wanted == 7 && type == 0x1005) {
            bit = 32; if (size != 8 || pos + size != n) return false;
            memcpy(m3->authenticator, v, 8); m3->body_len = start;
        }
        if (bit && (seen & bit)) return false;
        seen |= bit; pos += size;
    }
    return (seen & 63u) == 63u;
}

bool m3_parse_m1(const uint8_t *frame, size_t len, m3_m1_t *out) {
    const uint8_t *a; size_t n; uint8_t id;
    if (!out || !attrs_from_frame(frame, len, &a, &n, &id)) return false;
    memset(out, 0, sizeof(*out));
    if (!parse_attrs(a, n, 4, NULL, out, NULL)) return false;
    memcpy(out->attrs, a, n); out->attrs_len = n; out->eap_id = id;
    return true;
}

bool m3_parse_m3(const uint8_t *frame, size_t len, uint8_t expected_eap_id,
                 const uint8_t registrar_nonce[16], m3_m3_t *out) {
    const uint8_t *a; size_t n; uint8_t id;
    if (!out || !registrar_nonce ||
        !attrs_from_frame(frame, len, &a, &n, &id) || id != expected_eap_id) return false;
    memset(out, 0, sizeof(*out));
    return parse_attrs(a, n, 7, registrar_nonce, NULL, out);
}

static bool add(uint8_t *out, size_t cap, size_t *pos, unsigned type,
                const void *data, size_t size) {
    if (size > 65535 || *pos > cap || size > cap - *pos || cap - *pos - size < 4) return false;
    put16(out + *pos, type); put16(out + *pos + 2, size);
    memcpy(out + *pos + 4, data, size); *pos += size + 4; return true;
}

size_t m3_build_m2_body(uint8_t *out, size_t cap, const uint8_t nonce_e[16],
                        const uint8_t nonce_r[16], const uint8_t uuid_r[16],
                        const uint8_t public_r[192], uint8_t rf_band, bool wsc2) {
    if (!out || !nonce_e || !nonce_r || !uuid_r || !public_r ||
        (rf_band != 1 && rf_band != 2)) return 0;
    static const uint8_t v = 0x10, type = 5, auth_types[] = {0, 0x3f},
        encr_types[] = {0, 0x0f}, conn = 1, config[] = {0, 0x84},
        dev_type[] = {0, 1, 0, 0x50, 0xf2, 4, 0, 1}, zero2[] = {0, 0},
        os_version[] = {0x80, 0, 0, 0};
    size_t p = 0;
#define A(t,d,n) if (!add(out, cap, &p, t, d, n)) return 0
    A(0x104a, &v, 1); A(0x1022, &type, 1);
    A(0x101a, nonce_e, 16); A(0x1039, nonce_r, 16);
    A(0x1048, uuid_r, 16); A(0x1032, public_r, 192);
    A(0x1004, auth_types, 2); A(0x1010, encr_types, 2);
    A(0x100d, &conn, 1); A(0x1008, config, 2);
    A(0x1021, "JanOS", 5); A(0x1023, "C5", 2);
    A(0x1024, "1", 1); A(0x1042, "1", 1);
    A(0x1054, dev_type, 8); A(0x1011, "JanOS C5", 8);
    A(0x103c, &rf_band, 1); A(0x1002, zero2, 2);
    A(0x1009, zero2, 2); A(0x1012, zero2, 2);
    A(0x102d, os_version, 4);
    if (wsc2) {
        static const uint8_t ext[] = {0, 0x37, 0x2a, 0, 1, 0x20};
        A(0x1049, ext, sizeof(ext));
    }
#undef A
    return p;
}

size_t m3_append_authenticator(uint8_t *attrs, size_t cap, size_t body_len,
                               const uint8_t authenticator[8]) {
    if (!attrs || !authenticator || body_len > cap) return 0;
    size_t p = body_len;
    return add(attrs, cap, &p, 0x1005, authenticator, 8) ? p : 0;
}

size_t m3_wrap_m2(uint8_t *out, size_t cap, uint8_t id,
                  const uint8_t *attrs, size_t n) {
    if (!out || !attrs || n > 65521 || n > cap || cap - n < 18) return 0;
    memset(out, 0, 18); out[0] = 1; out[4] = 2; out[5] = id;
    put16(out + 2, n + 14); put16(out + 6, n + 14);
    out[8] = 254; out[10] = 0x37; out[11] = 0x2a;
    out[15] = 1; out[16] = 4;
    memcpy(out + 18, attrs, n); return n + 18;
}
