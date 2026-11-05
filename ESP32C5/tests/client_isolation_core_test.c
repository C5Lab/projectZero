#include "client_isolation_core.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    size_t calls;
    bool saw_exact_known_answer_input;
} kat_context_t;

static const uint8_t kat_token[JISO_TOKEN_BYTES] = {
    0x00U, 0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U,
    0x88U, 0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU,
};

static const uint8_t kat_prefix[JISO_AUTHENTICATED_BYTES] = {
    0x4AU, 0x49U, 0x53U, 0x4FU, 0x01U, 0x01U, 0x00U, 0x00U,
    0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U,
    0x11U, 0x22U, 0x33U, 0x44U,
    0x10U, 0x11U, 0x12U, 0x13U, 0x14U, 0x15U, 0x16U, 0x17U,
    0x18U, 0x19U, 0x1AU, 0x1BU, 0x1CU, 0x1DU, 0x1EU, 0x1FU,
};

/* Calculated independently with Python hmac.new(..., hashlib.sha256). */
static const uint8_t kat_digest[JISO_SHA256_BYTES] = {
    0xE4U, 0x37U, 0x82U, 0x04U, 0xC5U, 0x2FU, 0x13U, 0xE6U,
    0x76U, 0x69U, 0xBBU, 0x84U, 0x4FU, 0x59U, 0x81U, 0xA7U,
    0xC5U, 0xF2U, 0x8BU, 0x65U, 0x29U, 0x20U, 0x9EU, 0x87U,
    0x7EU, 0x65U, 0x23U, 0xA6U, 0x5DU, 0xD6U, 0x8EU, 0xF5U,
};

static bool kat_hmac(void *context, const uint8_t token[JISO_TOKEN_BYTES],
                     const uint8_t *data, size_t data_length,
                     uint8_t digest[JISO_SHA256_BYTES])
{
    kat_context_t *kat = context;
    assert(kat != NULL);
    kat->calls++;
    kat->saw_exact_known_answer_input =
        data_length == sizeof(kat_prefix) &&
        memcmp(token, kat_token, sizeof(kat_token)) == 0 &&
        memcmp(data, kat_prefix, sizeof(kat_prefix)) == 0;
    if (!kat->saw_exact_known_answer_input) return false;
    memcpy(digest, kat_digest, sizeof(kat_digest));
    return true;
}

static bool fake_hmac(void *context, const uint8_t token[JISO_TOKEN_BYTES],
                      const uint8_t *data, size_t data_length,
                      uint8_t digest[JISO_SHA256_BYTES])
{
    (void)context;
    if (token == NULL || data == NULL || digest == NULL ||
        data_length != JISO_AUTHENTICATED_BYTES) return false;
    for (size_t index = 0U; index < JISO_SHA256_BYTES; ++index) {
        digest[index] = (uint8_t)(0xA5U ^ token[index % JISO_TOKEN_BYTES] ^
                                  data[index % data_length] ^
                                  data[(index + 11U) % data_length] ^
                                  data[(index + 23U) % data_length]);
    }
    return true;
}

static bool failing_hmac(void *context, const uint8_t token[JISO_TOKEN_BYTES],
                         const uint8_t *data, size_t data_length,
                         uint8_t digest[JISO_SHA256_BYTES])
{
    (void)context;
    (void)token;
    (void)data;
    (void)data_length;
    (void)digest;
    return false;
}

static jiso_message_t make_message(jiso_type_t type)
{
    jiso_message_t message = {
        .type = type,
        .run_id = UINT64_C(0x0102030405060708),
        .sequence = UINT32_C(0x11223344),
    };
    for (size_t index = 0U; index < sizeof(message.nonce); ++index) {
        message.nonce[index] = (uint8_t)(0x10U + index);
    }
    return message;
}

static void test_known_answer_and_offsets(void)
{
    kat_context_t kat = {0};
    const jiso_crypto_t crypto = {.hmac_sha256 = kat_hmac, .context = &kat};
    jiso_message_t message = make_message(JISO_CHALLENGE);
    uint8_t packet[JISO_PACKET_BYTES];
    uint8_t expected[JISO_PACKET_BYTES];
    memcpy(expected, kat_prefix, sizeof(kat_prefix));
    memcpy(expected + JISO_AUTHENTICATED_BYTES, kat_digest, JISO_TAG_BYTES);

    assert(jiso_encode(packet, &message, kat_token, &crypto));
    assert(kat.calls == 1U);
    assert(kat.saw_exact_known_answer_input);
    assert(memcmp(packet, expected, sizeof(expected)) == 0);
    assert(packet[0] == 0x4AU && packet[1] == 0x49U &&
           packet[2] == 0x53U && packet[3] == 0x4FU);
    assert(packet[4] == JISO_VERSION && packet[5] == JISO_CHALLENGE);
    assert(packet[6] == 0U && packet[7] == 0U);

    jiso_message_t decoded = {0};
    assert(jiso_decode(packet, sizeof(packet), kat_token, &crypto, &decoded));
    assert(kat.calls == 2U);
    assert(decoded.type == message.type);
    assert(decoded.run_id == message.run_id);
    assert(decoded.sequence == message.sequence);
    assert(memcmp(decoded.nonce, message.nonce, sizeof(message.nonce)) == 0);
}

static void test_types_and_correlation(void)
{
    const jiso_crypto_t crypto = {.hmac_sha256 = fake_hmac, .context = NULL};
    jiso_message_t challenge = make_message(JISO_CHALLENGE);
    jiso_message_t reply = make_message(JISO_REPLY);
    uint8_t packet[JISO_PACKET_BYTES];
    jiso_message_t decoded = {0};

    assert(jiso_encode(packet, &reply, kat_token, &crypto));
    assert(packet[5] == JISO_REPLY);
    assert(jiso_decode(packet, sizeof(packet), kat_token, &crypto, &decoded));
    assert(decoded.type == JISO_REPLY);
    assert(jiso_reply_matches(&challenge, &decoded));

    reply.type = JISO_CHALLENGE;
    assert(!jiso_reply_matches(&challenge, &reply));
    reply.type = JISO_REPLY;
    challenge.type = JISO_REPLY;
    assert(!jiso_reply_matches(&challenge, &reply));
    challenge.type = JISO_CHALLENGE;
    reply.run_id++;
    assert(!jiso_reply_matches(&challenge, &reply));
    reply = make_message(JISO_REPLY);
    reply.sequence++;
    assert(!jiso_reply_matches(&challenge, &reply));
    reply = make_message(JISO_REPLY);
    reply.nonce[15] ^= 0x01U;
    assert(!jiso_reply_matches(&challenge, &reply));
    reply = make_message(JISO_REPLY);
    memset(challenge.nonce, 0, sizeof(challenge.nonce));
    memset(reply.nonce, 0, sizeof(reply.nonce));
    assert(!jiso_reply_matches(&challenge, &reply));
}

static void assert_decode_rejected(const uint8_t *packet, size_t length,
                                   const uint8_t token[JISO_TOKEN_BYTES],
                                   const jiso_crypto_t *crypto)
{
    jiso_message_t output;
    memset(&output, 0xA5, sizeof(output));
    const jiso_message_t before = output;
    assert(!jiso_decode(packet, length, token, crypto, &output));
    assert(memcmp(&output, &before, sizeof(output)) == 0);
}

static void test_fail_closed_validation(void)
{
    const jiso_crypto_t crypto = {.hmac_sha256 = fake_hmac, .context = NULL};
    const jiso_crypto_t failed_crypto = {
        .hmac_sha256 = failing_hmac, .context = NULL};
    jiso_message_t message = make_message(JISO_CHALLENGE);
    uint8_t packet[JISO_PACKET_BYTES + 1U] = {0};
    uint8_t original[JISO_PACKET_BYTES];
    uint8_t wrong_token[JISO_TOKEN_BYTES];
    uint8_t zero_token[JISO_TOKEN_BYTES] = {0};

    assert(jiso_encode(packet, &message, kat_token, &crypto));
    memcpy(original, packet, sizeof(original));
    memcpy(wrong_token, kat_token, sizeof(wrong_token));
    wrong_token[0] ^= 0x80U;

    assert_decode_rejected(packet, JISO_PACKET_BYTES - 1U, kat_token, &crypto);
    assert_decode_rejected(packet, JISO_PACKET_BYTES + 1U, kat_token, &crypto);
    assert_decode_rejected(packet, JISO_PACKET_BYTES, wrong_token, &crypto);
    assert_decode_rejected(packet, JISO_PACKET_BYTES, zero_token, &crypto);
    assert_decode_rejected(packet, JISO_PACKET_BYTES, kat_token, &failed_crypto);

    const size_t offsets[] = {0U, 4U, 5U, 6U, 7U, 8U, 16U, 20U, 35U, 36U, 51U};
    for (size_t index = 0U; index < sizeof(offsets) / sizeof(offsets[0]); ++index) {
        memcpy(packet, original, sizeof(original));
        packet[offsets[index]] ^= 0x5AU;
        assert_decode_rejected(packet, JISO_PACKET_BYTES, kat_token, &crypto);
    }

    memcpy(packet, original, sizeof(original));
    packet[5] = 0U;
    assert_decode_rejected(packet, JISO_PACKET_BYTES, kat_token, &crypto);
    memcpy(packet, original, sizeof(original));
    packet[5] = 3U;
    assert_decode_rejected(packet, JISO_PACKET_BYTES, kat_token, &crypto);

    memcpy(packet, original, sizeof(original));
    memset(packet + 20U, 0, JISO_NONCE_BYTES);
    assert_decode_rejected(packet, JISO_PACKET_BYTES, kat_token, &crypto);

    uint8_t output[JISO_PACKET_BYTES];
    memset(output, 0xA5, sizeof(output));
    assert(!jiso_encode(NULL, &message, kat_token, &crypto));
    assert(!jiso_encode(output, NULL, kat_token, &crypto));
    assert(!jiso_encode(output, &message, NULL, &crypto));
    assert(!jiso_encode(output, &message, kat_token, NULL));
    assert(!jiso_encode(output, &message, kat_token, &failed_crypto));
    assert(!jiso_encode(output, &message, zero_token, &crypto));
    message.type = (jiso_type_t)0;
    assert(!jiso_encode(output, &message, kat_token, &crypto));
    message.type = (jiso_type_t)3;
    assert(!jiso_encode(output, &message, kat_token, &crypto));
    message = make_message(JISO_CHALLENGE);
    memset(message.nonce, 0, sizeof(message.nonce));
    assert(!jiso_encode(output, &message, kat_token, &crypto));

    assert_decode_rejected(NULL, JISO_PACKET_BYTES, kat_token, &crypto);
    assert_decode_rejected(original, JISO_PACKET_BYTES, NULL, &crypto);
    assert_decode_rejected(original, JISO_PACKET_BYTES, kat_token, NULL);
    assert(!jiso_decode(original, JISO_PACKET_BYTES, kat_token, &crypto, NULL));
}

static void test_constant_time_comparison_work_count(void)
{
    uint8_t left[JISO_TAG_BYTES] = {0};
    uint8_t right[JISO_TAG_BYTES] = {0};
    size_t compared = 99U;

    right[0] = 1U;
    assert(!jiso_constant_time_equal(left, right, sizeof(left), &compared));
    assert(compared == JISO_TAG_BYTES);
    right[0] = 0U;
    assert(jiso_constant_time_equal(left, right, sizeof(left), &compared));
    assert(compared == JISO_TAG_BYTES);
    assert(!jiso_constant_time_equal(NULL, right, sizeof(left), &compared));
    assert(compared == 0U);
    assert(!jiso_constant_time_equal(left, right, 0U, &compared));
    assert(compared == 0U);
}

int main(void)
{
    test_known_answer_and_offsets();
    test_types_and_correlation();
    test_fail_closed_validation();
    test_constant_time_comparison_work_count();
    puts("PASS: JISO/1 byte contract, fail-closed validation, correlation");
    return 0;
}
