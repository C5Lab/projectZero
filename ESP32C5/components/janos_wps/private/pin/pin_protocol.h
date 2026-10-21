#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const uint8_t *attrs;
    size_t attrs_len;
    const uint8_t *encrypted;
    size_t encrypted_len;
    uint8_t authenticator[8];
    size_t body_len;
    bool wsc2;
} pin_secure_message_t;

typedef struct {
    const uint8_t *snonce;
    const uint8_t *ssid;
    size_t ssid_len;
    const uint8_t *network_key;
    size_t network_key_len;
    uint16_t auth_type;
    uint16_t encr_type;
    uint8_t kwa[8];
    size_t body_len;
    bool credential_present;
} pin_inner_t;

size_t pin_build_m4_body(uint8_t *out, size_t cap, const uint8_t nonce_e[16],
                         const uint8_t r_hash1[32], const uint8_t r_hash2[32],
                         const uint8_t *encrypted, size_t encrypted_len, bool wsc2);
size_t pin_build_m6_body(uint8_t *out, size_t cap, const uint8_t nonce_e[16],
                         const uint8_t *encrypted, size_t encrypted_len, bool wsc2);
size_t pin_append_authenticator(uint8_t *attrs, size_t cap, size_t body_len,
                                const uint8_t authenticator[8]);
bool pin_parse_secure_message(const uint8_t *attrs, size_t len,
                              uint8_t expected_type,
                              const uint8_t registrar_nonce[16],
                              pin_secure_message_t *out);
bool pin_parse_secure_frame(const uint8_t *frame, size_t len,
                            uint8_t expected_type, uint8_t expected_eap_id,
                            const uint8_t registrar_nonce[16],
                            pin_secure_message_t *out);
bool pin_parse_inner(const uint8_t *plain, size_t len,
                     uint16_t expected_snonce_type, pin_inner_t *out);
bool pin_validate_wps_pin(const char *pin, size_t len);
