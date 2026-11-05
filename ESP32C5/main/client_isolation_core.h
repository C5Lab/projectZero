#ifndef CLIENT_ISOLATION_CORE_H
#define CLIENT_ISOLATION_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define JISO_MAGIC UINT32_C(0x4A49534F)
#define JISO_VERSION 1U
#define JISO_TOKEN_BYTES 16U
#define JISO_NONCE_BYTES 16U
#define JISO_TAG_BYTES 16U
#define JISO_SHA256_BYTES 32U
#define JISO_AUTHENTICATED_BYTES 36U
#define JISO_PACKET_BYTES 52U

typedef enum {
    JISO_CHALLENGE = 1,
    JISO_REPLY = 2,
} jiso_type_t;

typedef struct {
    jiso_type_t type;
    uint64_t run_id;
    uint32_t sequence;
    uint8_t nonce[JISO_NONCE_BYTES];
} jiso_message_t;

typedef bool (*jiso_hmac_sha256_fn)(
    void *context,
    const uint8_t token[JISO_TOKEN_BYTES],
    const uint8_t *data,
    size_t data_length,
    uint8_t digest[JISO_SHA256_BYTES]);

typedef struct {
    jiso_hmac_sha256_fn hmac_sha256;
    void *context;
} jiso_crypto_t;

bool jiso_encode(uint8_t out[JISO_PACKET_BYTES],
                 const jiso_message_t *message,
                 const uint8_t token[JISO_TOKEN_BYTES],
                 const jiso_crypto_t *crypto);

bool jiso_decode(const uint8_t *packet,
                 size_t length,
                 const uint8_t token[JISO_TOKEN_BYTES],
                 const jiso_crypto_t *crypto,
                 jiso_message_t *message);

bool jiso_reply_matches(const jiso_message_t *challenge,
                        const jiso_message_t *reply);

/* The optional work counter is diagnostic only and always receives length. */
bool jiso_constant_time_equal(const uint8_t *left,
                              const uint8_t *right,
                              size_t length,
                              size_t *compared_bytes);

#ifdef __cplusplus
}
#endif

#endif
