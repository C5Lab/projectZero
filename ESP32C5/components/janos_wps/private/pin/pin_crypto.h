#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t authkey[32];
    uint8_t keywrapkey[16];
    uint8_t emsk[32];
} pin_keys_t;

bool pin_crypto_init(void);
bool pin_random(uint8_t *out, size_t len);
bool pin_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
bool pin_derive_keys(const uint8_t shared[192], const uint8_t nonce_e[16],
                     const uint8_t mac_e[6], const uint8_t nonce_r[16],
                     pin_keys_t *keys);
bool pin_derive_psks(const uint8_t authkey[32], const char *pin, size_t pin_len,
                     uint8_t psk1[16], uint8_t psk2[16]);
bool pin_commitment(const uint8_t authkey[32], const uint8_t snonce[16],
                    const uint8_t psk[16], const uint8_t pke[192],
                    const uint8_t pkr[192], uint8_t out[32]);
bool pin_authenticator(const uint8_t authkey[32], const uint8_t *previous,
                       size_t previous_len, const uint8_t *current,
                       size_t current_len, uint8_t out[8]);
bool pin_kwa(const uint8_t authkey[32], const uint8_t *plain, size_t plain_len,
             uint8_t out[8]);
bool pin_encrypt_settings(const uint8_t key[16], const uint8_t iv[16],
                          const uint8_t *plain, size_t plain_len,
                          uint8_t *out, size_t cap, size_t *out_len);
bool pin_decrypt_settings(const uint8_t key[16], const uint8_t *encrypted,
                          size_t encrypted_len, uint8_t *plain, size_t cap,
                          size_t *plain_len);
bool pin_group5_compute(const uint8_t private_value[192],
                        const uint8_t peer_public[192],
                        uint8_t public_value[192], uint8_t shared[192]);
void pin_scrub(void *data, size_t len);
#ifndef WPS_HOST_TEST
bool pin_session_keys(const uint8_t peer_public[192], const uint8_t nonce_e[16],
                      const uint8_t mac_e[6], uint8_t nonce_r[16],
                      uint8_t uuid_r[16], uint8_t public_r[192], pin_keys_t *keys);
#endif
