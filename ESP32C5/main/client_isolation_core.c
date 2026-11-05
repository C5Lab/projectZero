#include "client_isolation_core.h"

#include <string.h>

enum {
    JISO_MAGIC_OFFSET = 0,
    JISO_VERSION_OFFSET = 4,
    JISO_TYPE_OFFSET = 5,
    JISO_RESERVED_OFFSET = 6,
    JISO_RUN_ID_OFFSET = 8,
    JISO_SEQUENCE_OFFSET = 16,
    JISO_NONCE_OFFSET = 20,
    JISO_TAG_OFFSET = 36,
};

static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (size > 0U) {
        *bytes++ = 0U;
        --size;
    }
}

static bool bytes_are_not_all_zero(const uint8_t *bytes, size_t length)
{
    uint8_t aggregate = 0U;
    if (bytes == NULL || length == 0U) return false;
    for (size_t index = 0U; index < length; ++index) aggregate |= bytes[index];
    return aggregate != 0U;
}

static bool type_valid(jiso_type_t type)
{
    return type == JISO_CHALLENGE || type == JISO_REPLY;
}

static void write_u32_be(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)(value >> 24U);
    out[1] = (uint8_t)(value >> 16U);
    out[2] = (uint8_t)(value >> 8U);
    out[3] = (uint8_t)value;
}

static void write_u64_be(uint8_t *out, uint64_t value)
{
    for (size_t index = 0U; index < 8U; ++index) {
        out[index] = (uint8_t)(value >> (56U - (index * 8U)));
    }
}

static uint32_t read_u32_be(const uint8_t *in)
{
    return ((uint32_t)in[0] << 24U) |
           ((uint32_t)in[1] << 16U) |
           ((uint32_t)in[2] << 8U) |
           (uint32_t)in[3];
}

static uint64_t read_u64_be(const uint8_t *in)
{
    uint64_t value = 0U;
    for (size_t index = 0U; index < 8U; ++index) {
        value = (value << 8U) | (uint64_t)in[index];
    }
    return value;
}

bool jiso_constant_time_equal(const uint8_t *left,
                              const uint8_t *right,
                              size_t length,
                              size_t *compared_bytes)
{
    uint8_t difference = 0U;
    if (compared_bytes != NULL) *compared_bytes = 0U;
    if (left == NULL || right == NULL || length == 0U) return false;

    for (size_t index = 0U; index < length; ++index) {
        difference |= (uint8_t)(left[index] ^ right[index]);
        if (compared_bytes != NULL) *compared_bytes = index + 1U;
    }
    return difference == 0U;
}

bool jiso_encode(uint8_t out[JISO_PACKET_BYTES],
                 const jiso_message_t *message,
                 const uint8_t token[JISO_TOKEN_BYTES],
                 const jiso_crypto_t *crypto)
{
    uint8_t packet[JISO_PACKET_BYTES] = {0};
    uint8_t digest[JISO_SHA256_BYTES] = {0};
    bool success = false;

    if (out == NULL || message == NULL || token == NULL || crypto == NULL ||
        crypto->hmac_sha256 == NULL || !type_valid(message->type) ||
        !bytes_are_not_all_zero(token, JISO_TOKEN_BYTES) ||
        !bytes_are_not_all_zero(message->nonce, JISO_NONCE_BYTES)) {
        goto done;
    }

    write_u32_be(packet + JISO_MAGIC_OFFSET, JISO_MAGIC);
    packet[JISO_VERSION_OFFSET] = JISO_VERSION;
    packet[JISO_TYPE_OFFSET] = (uint8_t)message->type;
    write_u64_be(packet + JISO_RUN_ID_OFFSET, message->run_id);
    write_u32_be(packet + JISO_SEQUENCE_OFFSET, message->sequence);
    memcpy(packet + JISO_NONCE_OFFSET, message->nonce, JISO_NONCE_BYTES);

    if (!crypto->hmac_sha256(crypto->context, token, packet,
                             JISO_AUTHENTICATED_BYTES, digest)) {
        goto done;
    }
    memcpy(packet + JISO_TAG_OFFSET, digest, JISO_TAG_BYTES);
    memcpy(out, packet, sizeof(packet));
    success = true;

done:
    secure_zero(digest, sizeof(digest));
    secure_zero(packet, sizeof(packet));
    return success;
}

bool jiso_decode(const uint8_t *packet,
                 size_t length,
                 const uint8_t token[JISO_TOKEN_BYTES],
                 const jiso_crypto_t *crypto,
                 jiso_message_t *message)
{
    uint8_t digest[JISO_SHA256_BYTES] = {0};
    jiso_message_t decoded = {0};
    bool success = false;

    if (packet == NULL || token == NULL || crypto == NULL || message == NULL ||
        crypto->hmac_sha256 == NULL || length != JISO_PACKET_BYTES ||
        !bytes_are_not_all_zero(token, JISO_TOKEN_BYTES)) {
        goto done;
    }
    if (read_u32_be(packet + JISO_MAGIC_OFFSET) != JISO_MAGIC ||
        packet[JISO_VERSION_OFFSET] != JISO_VERSION ||
        !type_valid((jiso_type_t)packet[JISO_TYPE_OFFSET]) ||
        packet[JISO_RESERVED_OFFSET] != 0U ||
        packet[JISO_RESERVED_OFFSET + 1U] != 0U ||
        !bytes_are_not_all_zero(packet + JISO_NONCE_OFFSET, JISO_NONCE_BYTES)) {
        goto done;
    }
    if (!crypto->hmac_sha256(crypto->context, token, packet,
                             JISO_AUTHENTICATED_BYTES, digest) ||
        !jiso_constant_time_equal(packet + JISO_TAG_OFFSET, digest,
                                  JISO_TAG_BYTES, NULL)) {
        goto done;
    }

    decoded.type = (jiso_type_t)packet[JISO_TYPE_OFFSET];
    decoded.run_id = read_u64_be(packet + JISO_RUN_ID_OFFSET);
    decoded.sequence = read_u32_be(packet + JISO_SEQUENCE_OFFSET);
    memcpy(decoded.nonce, packet + JISO_NONCE_OFFSET, JISO_NONCE_BYTES);
    *message = decoded;
    success = true;

done:
    secure_zero(digest, sizeof(digest));
    secure_zero(&decoded, sizeof(decoded));
    return success;
}

bool jiso_reply_matches(const jiso_message_t *challenge,
                        const jiso_message_t *reply)
{
    if (challenge == NULL || reply == NULL ||
        challenge->type != JISO_CHALLENGE || reply->type != JISO_REPLY ||
        challenge->run_id != reply->run_id ||
        challenge->sequence != reply->sequence ||
        !bytes_are_not_all_zero(challenge->nonce, JISO_NONCE_BYTES)) {
        return false;
    }
    return jiso_constant_time_equal(challenge->nonce, reply->nonce,
                                    JISO_NONCE_BYTES, NULL);
}
