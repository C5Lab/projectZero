#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { M3_MAX_ATTRS = 1024 };
enum { M3_IDENTITY_TEXT_MAX = 32 };
typedef struct {
    uint8_t eap_id;
    uint8_t enrollee_nonce[16];
    uint8_t enrollee_mac[6];
    uint8_t public_key[192];
    uint16_t dev_password_id;
    bool pin_mode;
    bool wsc2;
    char manufacturer[M3_IDENTITY_TEXT_MAX + 1];
    char model_name[M3_IDENTITY_TEXT_MAX + 1];
    char model_number[M3_IDENTITY_TEXT_MAX + 1];
    char device_name[M3_IDENTITY_TEXT_MAX + 1];
    uint8_t attrs[M3_MAX_ATTRS];
    size_t attrs_len;
} m3_m1_t;
typedef struct {
    uint8_t e_hash1[32];
    uint8_t e_hash2[32];
    uint8_t authenticator[8];
    size_t body_len; /* WSC attributes before the final Authenticator TLV. */
} m3_m3_t;

bool m3_parse_m1(const uint8_t *frame, size_t len, m3_m1_t *out);
bool m3_parse_m3(const uint8_t *frame, size_t len, uint8_t expected_eap_id,
                 const uint8_t registrar_nonce[16], m3_m3_t *out);
size_t m3_build_m2_body(uint8_t *out, size_t cap, const uint8_t nonce_e[16],
                        const uint8_t nonce_r[16], const uint8_t uuid_r[16],
                        const uint8_t public_r[192], uint8_t rf_band, bool wsc2);
size_t m3_append_authenticator(uint8_t *attrs, size_t cap, size_t body_len,
                               const uint8_t authenticator[8]);
size_t m3_wrap_m2(uint8_t *out, size_t cap, uint8_t eap_id,
                  const uint8_t *attrs, size_t attrs_len);
