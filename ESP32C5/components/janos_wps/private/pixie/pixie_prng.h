#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void pixie_glibc_nonce(uint32_t seed, uint8_t out[16]);
uint32_t pixie_glibc_first_word(uint32_t seed);
bool pixie_find_glibc_nonce_seed(const uint8_t nonce[16], uint32_t start,
                                 uint32_t end, uint32_t *seed_out);

void pixie_ralink_forward(uint32_t state, uint8_t *out, size_t len);
bool pixie_ralink_recover(const uint8_t nonce[16], uint8_t e_s1[16],
                          uint8_t e_s2[16]);
