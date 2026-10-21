#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    PIXIE_MODE_NONE = 0,
    PIXIE_MODE_NULL_SECRET = 1u << 0,
    PIXIE_MODE_STATIC_SECRET = 1u << 1,
    PIXIE_MODE_RALINK = 1u << 2,
    PIXIE_MODE_RTL819X = 1u << 3,
    PIXIE_MODE_DEFAULT = PIXIE_MODE_NULL_SECRET | PIXIE_MODE_STATIC_SECRET |
                         PIXIE_MODE_RALINK | PIXIE_MODE_RTL819X,
} pixie_mode_t;

typedef struct {
    uint8_t pke[192];
    uint8_t pkr[192];
    uint8_t e_hash1[32];
    uint8_t e_hash2[32];
    uint8_t e_nonce[16];
    uint8_t authkey[32];
} pixie_bundle_t;

typedef struct {
    uint8_t e_s1[16];
    uint8_t e_s2[16];
} pixie_secret_pair_t;

typedef bool (*pixie_cancel_fn)(void *context);
typedef void (*pixie_yield_fn)(void *context);
typedef void *(*pixie_cache_alloc_fn)(void *context, size_t size);
typedef void (*pixie_cache_free_fn)(void *context, void *memory, size_t size);

typedef struct {
    uint32_t modes;
    const pixie_secret_pair_t *static_secrets;
    size_t static_secret_count;
    bool rtl_window_set;
    uint32_t rtl_window_start;
    uint32_t rtl_window_end;
    uint32_t yield_every;
    pixie_cancel_fn should_cancel;
    pixie_yield_fn yield;
    void *callback_context;
    pixie_cache_alloc_fn cache_alloc;
    pixie_cache_free_fn cache_free;
    void *cache_context;
} pixie_options_t;

typedef struct {
    bool found;
    bool partial;
    bool cancelled;
    pixie_mode_t mode;
    char pin[9];
    char first_half[5];
    uint32_t commitment_checks;
} pixie_result_t;

bool pixie_recover(const pixie_bundle_t *bundle, const pixie_options_t *options,
                   pixie_result_t *result);
