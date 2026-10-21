#include "pin_protocol.h"
#include <string.h>

static unsigned be16(const uint8_t *p) { return ((unsigned)p[0] << 8) | p[1]; }
static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }

static bool add(uint8_t *out, size_t cap, size_t *pos, unsigned type,
                const void *data, size_t size) {
    if (!out || !pos || !data || size > 65535 || *pos > cap || cap - *pos < 4 ||
        size > cap - *pos - 4) return false;
    put16(out + *pos, type); put16(out + *pos + 2, size);
    memcpy(out + *pos + 4, data, size); *pos += size + 4; return true;
}

static bool version2(uint8_t *out, size_t cap, size_t *pos) {
    static const uint8_t ext[] = {0, 0x37, 0x2a, 0, 1, 0x20};
    return add(out, cap, pos, 0x1049, ext, sizeof(ext));
}

size_t pin_build_m4_body(uint8_t *out, size_t cap, const uint8_t nonce_e[16],
                         const uint8_t r_hash1[32], const uint8_t r_hash2[32],
                         const uint8_t *encrypted, size_t encrypted_len, bool wsc2) {
    if (!out || !nonce_e || !r_hash1 || !r_hash2 || !encrypted || encrypted_len < 32) return 0;
    static const uint8_t version = 0x10, type = 8; size_t p = 0;
    if (!add(out, cap, &p, 0x104a, &version, 1) || !add(out, cap, &p, 0x1022, &type, 1) ||
        !add(out, cap, &p, 0x101a, nonce_e, 16) || !add(out, cap, &p, 0x103d, r_hash1, 32) ||
        !add(out, cap, &p, 0x103e, r_hash2, 32) ||
        !add(out, cap, &p, 0x1018, encrypted, encrypted_len) ||
        (wsc2 && !version2(out, cap, &p))) return 0;
    return p;
}

size_t pin_build_m6_body(uint8_t *out, size_t cap, const uint8_t nonce_e[16],
                         const uint8_t *encrypted, size_t encrypted_len, bool wsc2) {
    if (!out || !nonce_e || !encrypted || encrypted_len < 32) return 0;
    static const uint8_t version = 0x10, type = 10; size_t p = 0;
    if (!add(out, cap, &p, 0x104a, &version, 1) || !add(out, cap, &p, 0x1022, &type, 1) ||
        !add(out, cap, &p, 0x101a, nonce_e, 16) ||
        !add(out, cap, &p, 0x1018, encrypted, encrypted_len) ||
        (wsc2 && !version2(out, cap, &p))) return 0;
    return p;
}

size_t pin_append_authenticator(uint8_t *attrs, size_t cap, size_t body_len,
                                const uint8_t authenticator[8]) {
    if (!attrs || !authenticator || body_len > cap) return 0;
    size_t p = body_len;
    return add(attrs, cap, &p, 0x1005, authenticator, 8) ? p : 0;
}

bool pin_parse_secure_message(const uint8_t *a, size_t n, uint8_t expected_type,
                              const uint8_t registrar_nonce[16],
                              pin_secure_message_t *out) {
    if (!a || !registrar_nonce || !out || n > 4096 ||
        (expected_type != 9 && expected_type != 11)) return false;
    memset(out, 0, sizeof(*out)); unsigned seen = 0; size_t pos = 0;
    while (pos < n) {
        if (n - pos < 4) return false;
        size_t start = pos; unsigned type = be16(a + pos), size = be16(a + pos + 2), bit = 0;
        pos += 4; if (size > n - pos) return false; const uint8_t *v = a + pos;
        if (type == 0x104a) { bit = 1; if (size != 1 || v[0] != 0x10) return false; }
        if (type == 0x1022) { bit = 2; if (size != 1 || v[0] != expected_type) return false; }
        if (type == 0x1039) { bit = 4; if (size != 16 || memcmp(v, registrar_nonce, 16)) return false; }
        if (type == 0x1018) { bit = 8; if (size < 32 || size % 16) return false;
            out->encrypted = v; out->encrypted_len = size; }
        if (type == 0x1049 && size >= 6 && v[0] == 0 && v[1] == 0x37 && v[2] == 0x2a &&
            v[3] == 0 && v[4] == 1 && v[5] >= 0x20) out->wsc2 = true;
        if (type == 0x1005) { bit = 16; if (size != 8 || pos + size != n) return false;
            memcpy(out->authenticator, v, 8); out->body_len = start; }
        if (bit && (seen & bit)) return false;
        seen |= bit; pos += size;
    }
    return seen == 31;
}

bool pin_parse_secure_frame(const uint8_t *f, size_t len,
                            uint8_t expected_type, uint8_t expected_eap_id,
                            const uint8_t registrar_nonce[16],
                            pin_secure_message_t *out) {
    if (!f || !out || len < 18 || len - 18 > 4096 ||
        f[0] < 1 || f[0] > 3 || f[1] != 0 || f[4] != 1 ||
        f[5] != expected_eap_id || f[8] != 254 || f[9] != 0 ||
        f[10] != 0x37 || f[11] != 0x2a || f[12] != 0 || f[13] != 0 ||
        f[14] != 0 || f[15] != 1 || f[16] != 4 || f[17] != 0 ||
        be16(f + 2) != len - 4 || be16(f + 6) != len - 4 ||
        !pin_parse_secure_message(f + 18, len - 18, expected_type,
                                  registrar_nonce, out)) return false;
    out->attrs = f + 18;
    out->attrs_len = len - 18;
    return true;
}

bool pin_parse_inner(const uint8_t *a, size_t n, uint16_t expected_snonce_type,
                     pin_inner_t *out) {
    if (!a || !out || n > 4096 ||
        (expected_snonce_type != 0x1016 && expected_snonce_type != 0x1017)) return false;
    memset(out, 0, sizeof(*out)); unsigned seen = 0; size_t pos = 0;
    while (pos < n) {
        if (n - pos < 4) return false;
        size_t start = pos; unsigned type = be16(a + pos), size = be16(a + pos + 2), bit = 0;
        pos += 4; if (size > n - pos) return false; const uint8_t *v = a + pos;
        if (type == expected_snonce_type) { bit = 1; if (size != 16) return false; out->snonce = v; }
        if (type == 0x1045) { bit = 2; if (!size || size > 32) return false; out->ssid = v; out->ssid_len = size; }
        if (type == 0x1003) { bit = 4; if (size != 2) return false; out->auth_type = (uint16_t)be16(v); }
        if (type == 0x100f) { bit = 8; if (size != 2) return false; out->encr_type = (uint16_t)be16(v); }
        if (type == 0x1027) { bit = 16; if (!size || size > 64) return false;
            out->network_key = v; out->network_key_len = size; }
        if (type == 0x101e) { bit = 32; if (size != 8 || pos + size != n) return false;
            memcpy(out->kwa, v, 8); out->body_len = start; }
        if (bit && (seen & bit)) return false;
        seen |= bit; pos += size;
    }
    if ((seen & (1u | 32u)) != (1u | 32u)) return false;
    unsigned cred = seen & (2u | 4u | 8u | 16u);
    if (cred && cred != (2u | 4u | 8u | 16u)) return false;
    out->credential_present = cred != 0;
    return true;
}

bool pin_validate_wps_pin(const char *pin, size_t len) {
    if (!pin || (len != 4 && len != 8)) return false;
    for (size_t i = 0; i < len; i++)
        if (pin[i] < '0' || pin[i] > '9') return false;
    if (len == 4) return true;
    unsigned sum = 0;
    for (size_t i = 0; i < 7; i++)
        sum += (unsigned)(pin[i] - '0') * (i % 2 == 0 ? 3u : 1u);
    return (10u - sum % 10u) % 10u == (unsigned)(pin[7] - '0');
}
