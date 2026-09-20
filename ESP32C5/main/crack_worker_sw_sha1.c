/* Private, self-contained software SHA-1 for the dictionary worker. This avoids
 * the ESP32-C5 hardware/compatibility HMAC path without depending on the mbedtls
 * source layout, which changed with the TF-PSA-Crypto rework in ESP-IDF 6.0. */
#include "crack_worker_sw_sha1.h"
#include <string.h>

typedef struct {
    uint32_t state[5];
    uint32_t count[2]; /* bit length, [0] = high word, [1] = low word */
    uint8_t buffer[64];
} cw_sw_sha1_context;

static void cw_sw_zeroize(void *buffer, size_t length)
{
    volatile uint8_t *p = (volatile uint8_t *)buffer;
    while (length-- > 0) *p++ = 0;
}

#define CW_ROL(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

static void cw_sw_sha1_process(cw_sw_sha1_context *ctx, const uint8_t data[64])
{
    uint32_t w[16];
    uint32_t a, b, c, d, e, t;

    for (unsigned i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    for (unsigned i = 0; i < 80; ++i) {
        if (i >= 16) {
            uint32_t x = w[(i + 13) & 15] ^ w[(i + 8) & 15] ^
                         w[(i + 2) & 15] ^ w[i & 15];
            w[i & 15] = CW_ROL(x, 1);
        }
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999U;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1U;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCU;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6U;
        }
        t = CW_ROL(a, 5) + f + e + k + w[i & 15];
        e = d;
        d = c;
        c = CW_ROL(b, 30);
        b = a;
        a = t;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;

    cw_sw_zeroize(w, sizeof(w));
}

static void cw_sw_sha1_starts(cw_sw_sha1_context *ctx)
{
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xEFCDAB89U;
    ctx->state[2] = 0x98BADCFEU;
    ctx->state[3] = 0x10325476U;
    ctx->state[4] = 0xC3D2E1F0U;
    ctx->count[0] = 0;
    ctx->count[1] = 0;
}

static void cw_sw_sha1_update(cw_sw_sha1_context *ctx, const uint8_t *data,
                              size_t length)
{
    size_t fill = (ctx->count[1] >> 3) & 0x3F;
    uint32_t added = (uint32_t)(length << 3);

    ctx->count[1] += added;
    if (ctx->count[1] < added) ctx->count[0]++;
    ctx->count[0] += (uint32_t)(length >> 29);

    if (fill != 0) {
        size_t left = 64 - fill;
        size_t take = length < left ? length : left;
        memcpy(ctx->buffer + fill, data, take);
        data += take;
        length -= take;
        if (fill + take < 64) return;
        cw_sw_sha1_process(ctx, ctx->buffer);
    }

    while (length >= 64) {
        cw_sw_sha1_process(ctx, data);
        data += 64;
        length -= 64;
    }

    if (length > 0) memcpy(ctx->buffer, data, length);
}

static void cw_sw_sha1_finish(cw_sw_sha1_context *ctx, uint8_t output[20])
{
    uint8_t length_bytes[8];
    for (unsigned i = 0; i < 4; ++i) {
        length_bytes[i] = (uint8_t)(ctx->count[0] >> (24 - i * 8));
        length_bytes[i + 4] = (uint8_t)(ctx->count[1] >> (24 - i * 8));
    }

    static const uint8_t padding[64] = {0x80};
    size_t used = (ctx->count[1] >> 3) & 0x3F;
    size_t pad_len = (used < 56) ? (56 - used) : (120 - used);
    cw_sw_sha1_update(ctx, padding, pad_len);
    cw_sw_sha1_update(ctx, length_bytes, 8);

    for (unsigned i = 0; i < 5; ++i) {
        output[i * 4] = (uint8_t)(ctx->state[i] >> 24);
        output[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        output[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        output[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
    cw_sw_zeroize(length_bytes, sizeof(length_bytes));
}

static void cw_sw_sha1(const uint8_t *input, size_t length, uint8_t output[20])
{
    cw_sw_sha1_context ctx;
    cw_sw_sha1_starts(&ctx);
    cw_sw_sha1_update(&ctx, input, length);
    cw_sw_sha1_finish(&ctx, output);
    cw_sw_zeroize(&ctx, sizeof(ctx));
}

typedef struct {
    cw_sw_sha1_context inner;
    cw_sw_sha1_context outer;
} cw_hmac_seed_t;

static int cw_seed(cw_hmac_seed_t *seed, const uint8_t *key, size_t length)
{
    uint8_t pad[64] = {0};
    if (length > sizeof(pad)) cw_sw_sha1(key, length, pad);
    else if (length > 0) memcpy(pad, key, length);
    for (size_t i = 0; i < sizeof(pad); ++i) pad[i] ^= 0x36U;
    cw_sw_sha1_starts(&seed->inner);
    cw_sw_sha1_update(&seed->inner, pad, sizeof(pad));
    for (size_t i = 0; i < sizeof(pad); ++i) pad[i] ^= 0x36U ^ 0x5cU;
    cw_sw_sha1_starts(&seed->outer);
    cw_sw_sha1_update(&seed->outer, pad, sizeof(pad));
    cw_sw_zeroize(pad, sizeof(pad));
    return 0;
}

static int cw_seed_hmac(const cw_hmac_seed_t *seed, const uint8_t *data,
                        size_t length, uint8_t output[20])
{
    cw_sw_sha1_context context;
    uint8_t digest[20];
    context = seed->inner;
    cw_sw_sha1_update(&context, data, length);
    cw_sw_sha1_finish(&context, digest);
    context = seed->outer;
    cw_sw_sha1_update(&context, digest, sizeof(digest));
    cw_sw_sha1_finish(&context, output);
    cw_sw_zeroize(&context, sizeof(context));
    cw_sw_zeroize(digest, sizeof(digest));
    return 0;
}

int crack_worker_sw_hmac_sha1(const uint8_t *key, size_t key_length,
                              const uint8_t *data, size_t data_length,
                              uint8_t output[20])
{
    if (output == NULL || (key == NULL && key_length > 0) ||
        (data == NULL && data_length > 0)) return -2;
    cw_hmac_seed_t seed = {0};
    int result = cw_seed(&seed, key, key_length);
    if (result == 0) result = cw_seed_hmac(&seed, data, data_length, output);
    cw_sw_zeroize(&seed, sizeof(seed));
    if (result != 0) cw_sw_zeroize(output, 20);
    return result == 0 ? 0 : -2;
}

int crack_worker_sw_derive_pmk(const char *password, const uint8_t *ssid,
                               size_t ssid_length, uint8_t pmk[32],
                               crack_worker_sw_checkpoint_fn checkpoint,
                               void *checkpoint_context)
{
    if (pmk == NULL) return -2;
    memset(pmk, 0, 32);
    if (password == NULL || ssid_length > 32 ||
        (ssid == NULL && ssid_length > 0)) return -2;
    size_t password_length = strnlen(password, 64);
    if (password_length < 8 || password_length > 63) return -2;
    cw_hmac_seed_t seed = {0};
    uint8_t salt[36] = {0}, u[20] = {0}, sum[20] = {0};
    int result = -1;
    if (checkpoint != NULL && !checkpoint(checkpoint_context)) goto done;
    result = -2;
    if (cw_seed(&seed, (const uint8_t *)password, password_length) != 0) goto done;
    if (ssid_length > 0) memcpy(salt, ssid, ssid_length);
    for (unsigned block = 1; block <= 2; ++block) {
        salt[ssid_length + 3U] = (uint8_t)block;
        if (cw_seed_hmac(&seed, salt, ssid_length + 4U, u) != 0) goto done;
        memcpy(sum, u, sizeof(sum));
        for (unsigned iteration = 2; iteration <= 4096; ++iteration) {
            if (cw_seed_hmac(&seed, u, sizeof(u), u) != 0) goto done;
            for (size_t i = 0; i < sizeof(sum); ++i) sum[i] ^= u[i];
            if ((iteration & 31U) == 0U && checkpoint != NULL &&
                !checkpoint(checkpoint_context)) {
                result = -1;
                goto done;
            }
        }
        memcpy(pmk + (block - 1U) * 20U, sum, block == 1U ? 20U : 12U);
    }
    result = 0;
done:
    cw_sw_zeroize(&seed, sizeof(seed));
    cw_sw_zeroize(salt, sizeof(salt));
    cw_sw_zeroize(u, sizeof(u));
    cw_sw_zeroize(sum, sizeof(sum));
    if (result != 0) cw_sw_zeroize(pmk, 32);
    return result;
}
