#include "pin_crypto.h"
#include <stdlib.h>
#include <string.h>

#ifdef WPS_HOST_TEST
/* Test-only declarations for the libcrypto.so.3 ABI; WSL has the runtime but
 * not the development headers. Firmware never sees this branch. */
typedef struct evp_md_st EVP_MD;
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct bignum_st BIGNUM;
typedef struct bignum_ctx BN_CTX;
const EVP_MD *EVP_sha256(void);
const EVP_CIPHER *EVP_aes_128_cbc(void);
int EVP_Digest(const void *, size_t, unsigned char *, unsigned int *, const EVP_MD *, void *);
unsigned char *HMAC(const EVP_MD *, const void *, int, const unsigned char *, size_t,
                    unsigned char *, unsigned int *);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *);
int EVP_CipherInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, void *, const unsigned char *,
                      const unsigned char *, int);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *, int);
int EVP_CipherUpdate(EVP_CIPHER_CTX *, unsigned char *, int *, const unsigned char *, int);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *);
BIGNUM *BN_bin2bn(const unsigned char *, int, BIGNUM *);
BIGNUM *BN_new(void);
BIGNUM *BN_dup(const BIGNUM *);
BIGNUM *BN_copy(BIGNUM *, const BIGNUM *);
void BN_free(BIGNUM *);
void BN_clear_free(BIGNUM *);
BN_CTX *BN_CTX_new(void);
BN_CTX *BN_CTX_secure_new(void);
void BN_CTX_free(BN_CTX *);
int BN_set_word(BIGNUM *, unsigned long);
int BN_add_word(BIGNUM *, unsigned long);
int BN_sub_word(BIGNUM *, unsigned long);
int BN_cmp(const BIGNUM *, const BIGNUM *);
int BN_nnmod(BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
int BN_mod_exp(BIGNUM *, const BIGNUM *, const BIGNUM *, const BIGNUM *, BN_CTX *);
int BN_bn2binpad(const BIGNUM *, unsigned char *, int);
#else
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include "mbedtls/private/bignum.h"
#include "psa/crypto.h"
#endif

static const uint8_t group5[192] = {
    255,255,255,255,255,255,255,255,201,15,218,162,33,104,194,52,
    196,198,98,139,128,220,28,209,41,2,78,8,138,103,204,116,
    2,11,190,166,59,19,155,34,81,74,8,121,142,52,4,221,
    239,149,25,179,205,58,67,27,48,43,10,109,242,95,20,55,
    79,225,53,109,109,81,194,69,228,133,181,118,98,94,126,198,
    244,76,66,233,166,55,237,107,11,255,92,182,244,6,183,237,
    238,56,107,251,90,137,159,165,174,159,36,17,124,75,31,230,
    73,40,102,81,236,228,91,61,194,0,124,184,161,99,191,5,
    152,218,72,54,28,85,211,154,105,22,63,168,253,36,207,95,
    131,101,93,35,220,163,173,150,28,98,243,86,32,133,82,187,
    158,213,41,7,112,150,150,109,103,12,53,78,74,188,152,4,
    241,116,108,8,202,35,115,39,255,255,255,255,255,255,255,255
};

void pin_scrub(void *data, size_t len) {
    volatile uint8_t *p = data;
    while (len--) *p++ = 0;
}

bool pin_crypto_init(void) {
#ifdef WPS_HOST_TEST
    return true;
#else
    return psa_crypto_init() == PSA_SUCCESS;
#endif
}

bool pin_sha256(const uint8_t *data, size_t len, uint8_t out[32]) {
#ifdef WPS_HOST_TEST
    unsigned n = 0;
    return EVP_Digest(data, len, out, &n, EVP_sha256(), NULL) == 1 && n == 32;
#else
    size_t n = 0;
    return psa_hash_compute(PSA_ALG_SHA_256, data, len, out, 32, &n) == PSA_SUCCESS && n == 32;
#endif
}

bool pin_random(uint8_t *out, size_t len) {
    if (!out || !len) return false;
#ifdef WPS_HOST_TEST
    (void)out; (void)len; return false;
#else
    return psa_generate_random(out, len) == PSA_SUCCESS;
#endif
}

static bool hmac256(const uint8_t *key, size_t key_len, const uint8_t *data,
                    size_t len, uint8_t out[32]) {
#ifdef WPS_HOST_TEST
    unsigned n = 0;
    return HMAC(EVP_sha256(), key, (int)key_len, data, len, out, &n) != NULL && n == 32;
#else
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id = 0; size_t n = 0;
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    bool ok = psa_import_key(&attr, key, key_len, &id) == PSA_SUCCESS;
    psa_reset_key_attributes(&attr);
    if (ok) ok = psa_mac_compute(id, PSA_ALG_HMAC(PSA_ALG_SHA_256), data, len,
                                  out, 32, &n) == PSA_SUCCESS && n == 32;
    if (id && psa_destroy_key(id) != PSA_SUCCESS) ok = false;
    return ok;
#endif
}

bool pin_derive_keys(const uint8_t shared[192], const uint8_t nonce_e[16],
                     const uint8_t mac_e[6], const uint8_t nonce_r[16],
                     pin_keys_t *keys) {
    if (!shared || !nonce_e || !mac_e || !nonce_r || !keys) return false;
    static const uint8_t label[] = "Wi-Fi Easy and Secure Key Derivation";
    uint8_t dhkey[32], kdk[32], seed[38], input[4 + sizeof(label) - 1 + 4];
    uint8_t material[96]; bool ok = pin_sha256(shared, 192, dhkey);
    if (ok) {
        memcpy(seed, nonce_e, 16); memcpy(seed + 16, mac_e, 6); memcpy(seed + 22, nonce_r, 16);
        ok = hmac256(dhkey, 32, seed, sizeof(seed), kdk);
    }
    for (unsigned i = 1; ok && i <= 3; i++) {
        input[0] = input[1] = input[2] = 0; input[3] = (uint8_t)i;
        memcpy(input + 4, label, sizeof(label) - 1);
        input[sizeof(input) - 4] = 0; input[sizeof(input) - 3] = 0;
        input[sizeof(input) - 2] = 2; input[sizeof(input) - 1] = 128;
        ok = hmac256(kdk, 32, input, sizeof(input), material + (i - 1) * 32);
    }
    if (ok) memcpy(keys, material, sizeof(*keys)); else pin_scrub(keys, sizeof(*keys));
    pin_scrub(dhkey, sizeof(dhkey)); pin_scrub(kdk, sizeof(kdk));
    pin_scrub(seed, sizeof(seed)); pin_scrub(input, sizeof(input)); pin_scrub(material, sizeof(material));
    return ok;
}

bool pin_derive_psks(const uint8_t authkey[32], const char *pin, size_t pin_len,
                     uint8_t psk1[16], uint8_t psk2[16]) {
    if (!authkey || !pin || !psk1 || !psk2 || (pin_len != 4 && pin_len != 8)) return false;
    for (size_t i = 0; i < pin_len; i++) if (pin[i] < '0' || pin[i] > '9') return false;
    size_t first = (pin_len + 1) / 2; uint8_t digest[32];
    bool ok = hmac256(authkey, 32, (const uint8_t *)pin, first, digest);
    if (ok) memcpy(psk1, digest, 16);
    if (ok) ok = hmac256(authkey, 32, (const uint8_t *)pin + first, pin_len / 2, digest);
    if (ok) memcpy(psk2, digest, 16);
    if (!ok) { pin_scrub(psk1, 16); pin_scrub(psk2, 16); }
    pin_scrub(digest, sizeof(digest)); return ok;
}

bool pin_commitment(const uint8_t authkey[32], const uint8_t snonce[16],
                    const uint8_t psk[16], const uint8_t pke[192],
                    const uint8_t pkr[192], uint8_t out[32]) {
    if (!authkey || !snonce || !psk || !pke || !pkr || !out) return false;
    uint8_t input[416];
    memcpy(input, snonce, 16); memcpy(input + 16, psk, 16);
    memcpy(input + 32, pke, 192); memcpy(input + 224, pkr, 192);
    bool ok = hmac256(authkey, 32, input, sizeof(input), out);
    pin_scrub(input, sizeof(input)); return ok;
}

static bool hmac_parts(const uint8_t key[32], const uint8_t *a, size_t an,
                       const uint8_t *b, size_t bn, uint8_t out[32]) {
    if (an > SIZE_MAX - bn) return false;
    uint8_t *buf = malloc(an + bn ? an + bn : 1); if (!buf) return false;
    memcpy(buf, a, an); memcpy(buf + an, b, bn);
    bool ok = hmac256(key, 32, buf, an + bn, out);
    pin_scrub(buf, an + bn); free(buf); return ok;
}

bool pin_authenticator(const uint8_t authkey[32], const uint8_t *previous,
                       size_t previous_len, const uint8_t *current,
                       size_t current_len, uint8_t out[8]) {
    if (!authkey || !previous || !current || !out || previous_len > 4096 || current_len > 4096) return false;
    uint8_t digest[32]; bool ok = hmac_parts(authkey, previous, previous_len, current, current_len, digest);
    if (ok) memcpy(out, digest, 8);
    pin_scrub(digest, sizeof(digest));
    return ok;
}

bool pin_kwa(const uint8_t authkey[32], const uint8_t *plain, size_t plain_len,
             uint8_t out[8]) {
    if (!authkey || !plain || !out || plain_len > 4096) return false;
    uint8_t digest[32]; bool ok = hmac256(authkey, 32, plain, plain_len, digest);
    if (ok) memcpy(out, digest, 8);
    pin_scrub(digest, sizeof(digest));
    return ok;
}

static bool aes_cbc(bool encrypt, const uint8_t key[16], uint8_t iv[16],
                    uint8_t *data, size_t len) {
#ifdef WPS_HOST_TEST
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); int n = 0, tail = 0;
    bool ok = ctx && EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, encrypt) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 && EVP_CipherUpdate(ctx, data, &n, data, (int)len) == 1 &&
        EVP_CipherFinal_ex(ctx, data + n, &tail) == 1 && (size_t)(n + tail) == len;
    EVP_CIPHER_CTX_free(ctx); return ok;
#else
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t id = 0;
    psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
    uint8_t *tmp = malloc(len);
    size_t written = 0, tail = 0;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, encrypt ? PSA_KEY_USAGE_ENCRYPT : PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_CBC_NO_PADDING);
    bool ok = tmp && psa_import_key(&attr, key, 16, &id) == PSA_SUCCESS;
    psa_reset_key_attributes(&attr);
    if (ok) ok = (encrypt ? psa_cipher_encrypt_setup(&op, id, PSA_ALG_CBC_NO_PADDING)
                           : psa_cipher_decrypt_setup(&op, id, PSA_ALG_CBC_NO_PADDING)) == PSA_SUCCESS;
    if (ok) ok = psa_cipher_set_iv(&op, iv, 16) == PSA_SUCCESS;
    if (ok) ok = psa_cipher_update(&op, data, len, tmp, len, &written) == PSA_SUCCESS;
    if (ok) ok = psa_cipher_finish(&op, tmp + written, len - written, &tail) == PSA_SUCCESS &&
                 written + tail == len;
    if (ok) memcpy(data, tmp, len);
    psa_cipher_abort(&op);
    if (id && psa_destroy_key(id) != PSA_SUCCESS) ok = false;
    if (tmp) { pin_scrub(tmp, len); free(tmp); }
    return ok;
#endif
}

bool pin_encrypt_settings(const uint8_t key[16], const uint8_t iv[16],
                          const uint8_t *plain, size_t plain_len,
                          uint8_t *out, size_t cap, size_t *out_len) {
    if (!key || !iv || !plain || !out || !out_len || plain_len > 4096) return false;
    size_t pad = 16 - plain_len % 16, total = 16 + plain_len + pad;
    if (cap < total) return false;
    memcpy(out, iv, 16); memcpy(out + 16, plain, plain_len); memset(out + 16 + plain_len, (int)pad, pad);
    uint8_t iv_copy[16]; memcpy(iv_copy, iv, 16);
    bool ok = aes_cbc(true, key, iv_copy, out + 16, plain_len + pad);
    pin_scrub(iv_copy, sizeof(iv_copy)); if (ok) *out_len = total; return ok;
}

bool pin_decrypt_settings(const uint8_t key[16], const uint8_t *encrypted,
                          size_t encrypted_len, uint8_t *plain, size_t cap,
                          size_t *plain_len) {
    if (!key || !encrypted || !plain || !plain_len || encrypted_len < 32 ||
        encrypted_len % 16 || cap < encrypted_len - 16) return false;
    size_t n = encrypted_len - 16; memcpy(plain, encrypted + 16, n);
    uint8_t iv[16]; memcpy(iv, encrypted, 16);
    bool ok = aes_cbc(false, key, iv, plain, n); pin_scrub(iv, sizeof(iv));
    if (!ok) return false;
    uint8_t pad = plain[n - 1], bad = (uint8_t)(pad == 0 || pad > 16);
    for (size_t i = 0; i < 16; i++) if (i < pad) bad |= (uint8_t)(plain[n - 1 - i] ^ pad);
    if (bad) { pin_scrub(plain, n); return false; }
    *plain_len = n - pad; return true;
}

bool pin_group5_compute(const uint8_t private_value[192],
                        const uint8_t peer_public[192],
                        uint8_t public_value[192], uint8_t shared[192]) {
    if (!private_value || !peer_public || !public_value || !shared) return false;
    bool ok = false;
    memset(public_value, 0, 192); memset(shared, 0, 192);
#ifdef WPS_HOST_TEST
    BN_CTX *ctx = BN_CTX_secure_new();
    BIGNUM *p = BN_bin2bn(group5, sizeof(group5), NULL);
    BIGNUM *g = BN_new(), *x = BN_bin2bn(private_value, 192, NULL);
    BIGNUM *peer = BN_bin2bn(peer_public, 192, NULL), *result = BN_new();
    BIGNUM *pub = BN_new(), *bound = p ? BN_dup(p) : NULL, *two = BN_new();
    if (ctx && p && g && x && peer && result && pub && bound && two &&
        BN_set_word(g, 2) && BN_set_word(two, 2) && BN_sub_word(bound, 2) &&
        BN_cmp(peer, two) >= 0 && BN_cmp(peer, bound) <= 0 &&
        BN_copy(bound, p) && BN_sub_word(bound, 3) &&
        BN_nnmod(x, x, bound, ctx) && BN_add_word(x, 2) &&
        BN_mod_exp(pub, g, x, p, ctx) && BN_mod_exp(result, peer, x, p, ctx) &&
        BN_bn2binpad(pub, public_value, 192) == 192 &&
        BN_bn2binpad(result, shared, 192) == 192) ok = true;
    BN_free(two); BN_free(bound); BN_free(pub); BN_clear_free(result);
    BN_free(peer); BN_clear_free(x); BN_free(g); BN_free(p); BN_CTX_free(ctx);
#else
    mbedtls_mpi p, g, x, pub, peer, result, rr, bound;
    mbedtls_mpi_init(&p); mbedtls_mpi_init(&g); mbedtls_mpi_init(&x);
    mbedtls_mpi_init(&pub); mbedtls_mpi_init(&peer); mbedtls_mpi_init(&result);
    mbedtls_mpi_init(&rr); mbedtls_mpi_init(&bound);
    if (!mbedtls_mpi_read_binary(&p, group5, sizeof(group5)) &&
        !mbedtls_mpi_read_binary(&x, private_value, 192) &&
        !mbedtls_mpi_read_binary(&peer, peer_public, 192) &&
        !mbedtls_mpi_sub_int(&bound, &p, 2) &&
        mbedtls_mpi_cmp_int(&peer, 2) >= 0 &&
        mbedtls_mpi_cmp_mpi(&peer, &bound) <= 0 &&
        !mbedtls_mpi_sub_int(&bound, &p, 3) &&
        !mbedtls_mpi_mod_mpi(&x, &x, &bound) &&
        !mbedtls_mpi_add_int(&x, &x, 2) &&
        !mbedtls_mpi_lset(&g, 2) &&
        !mbedtls_mpi_exp_mod(&pub, &g, &x, &p, &rr) &&
        !mbedtls_mpi_write_binary(&pub, public_value, 192) &&
        !mbedtls_mpi_exp_mod(&result, &peer, &x, &p, &rr) &&
        !mbedtls_mpi_write_binary(&result, shared, 192)) ok = true;
    mbedtls_mpi_free(&bound); mbedtls_mpi_free(&rr); mbedtls_mpi_free(&result);
    mbedtls_mpi_free(&peer); mbedtls_mpi_free(&pub); mbedtls_mpi_free(&x);
    mbedtls_mpi_free(&g); mbedtls_mpi_free(&p);
#endif
    if (!ok) { pin_scrub(public_value, 192); pin_scrub(shared, 192); }
    return ok;
}

#ifndef WPS_HOST_TEST
bool pin_session_keys(const uint8_t peer_public[192], const uint8_t nonce_e[16],
                      const uint8_t mac_e[6], uint8_t nonce_r[16],
                      uint8_t uuid_r[16], uint8_t public_r[192], pin_keys_t *keys) {
    if (!peer_public || !nonce_e || !mac_e || !nonce_r || !uuid_r || !public_r || !keys) return false;
    uint8_t private_value[192], shared[192];
    bool ok = pin_random(private_value, sizeof(private_value)) &&
              pin_random(nonce_r, 16) && pin_random(uuid_r, 16) &&
              pin_group5_compute(private_value, peer_public, public_r, shared) &&
              pin_derive_keys(shared, nonce_e, mac_e, nonce_r, keys);
    if (!ok) { pin_scrub(public_r, 192); pin_scrub(keys, sizeof(*keys)); }
    pin_scrub(private_value, sizeof(private_value)); pin_scrub(shared, sizeof(shared));
    return ok;
}
#endif
