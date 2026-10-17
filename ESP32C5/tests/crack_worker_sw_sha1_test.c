#include "crack_worker_sw_sha1.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void assert_bytes(const uint8_t *actual, const uint8_t *expected,
                         size_t length)
{
    assert(memcmp(actual, expected, length) == 0);
}

static void assert_zero(const uint8_t *buffer, size_t length)
{
    for (size_t i = 0; i < length; ++i) assert(buffer[i] == 0U);
}

static void test_rfc2202_hmac_sha1_vectors(void)
{
    static const uint8_t expected_1[20] = {
        0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
        0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
    };
    static const uint8_t expected_2[20] = {
        0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74,
        0x16, 0xd5, 0xf1, 0x84, 0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
    };
    uint8_t output[20];
    uint8_t repeated_key[20];
    memset(repeated_key, 0x0b, sizeof(repeated_key));
    assert(crack_worker_sw_hmac_sha1(repeated_key, sizeof(repeated_key),
        (const uint8_t *)"Hi There", 8U, output) == 0);
    assert_bytes(output, expected_1, sizeof(output));

    assert(crack_worker_sw_hmac_sha1((const uint8_t *)"Jefe", 4U,
        (const uint8_t *)"what do ya want for nothing?", 28U, output) == 0);
    assert_bytes(output, expected_2, sizeof(output));
}

static void test_ieee_wpa_pmk_known_answer(void)
{
    static const uint8_t expected[32] = {
        0xf4, 0x2c, 0x6f, 0xc5, 0x2d, 0xf0, 0xeb, 0xef,
        0x9e, 0xbb, 0x4b, 0x90, 0xb3, 0x8a, 0x5f, 0x90,
        0x2e, 0x83, 0xfe, 0x1b, 0x13, 0x5a, 0x70, 0xe2,
        0x3a, 0xed, 0x76, 0x2e, 0x97, 0x10, 0xa1, 0x2e,
    };
    uint8_t pmk[32];
    assert(crack_worker_sw_derive_pmk("password", (const uint8_t *)"IEEE",
                                      4U, pmk, NULL, NULL) == 0);
    assert_bytes(pmk, expected, sizeof(pmk));
}

static bool cancel_immediately(void *context)
{
    unsigned *calls = context;
    ++*calls;
    return false;
}

static void test_invalid_inputs_and_cancel_wipe_output(void)
{
    uint8_t output[32];
    memset(output, 0xa5, sizeof(output));
    assert(crack_worker_sw_derive_pmk("short", (const uint8_t *)"ssid", 4U,
                                      output, NULL, NULL) == -2);
    assert_zero(output, sizeof(output));

    memset(output, 0xa5, sizeof(output));
    static const uint8_t oversized_ssid[33] = {0};
    assert(crack_worker_sw_derive_pmk("password", oversized_ssid,
                                      sizeof(oversized_ssid), output,
                                      NULL, NULL) == -2);
    assert_zero(output, sizeof(output));

    unsigned calls = 0;
    memset(output, 0xa5, sizeof(output));
    assert(crack_worker_sw_derive_pmk("password", (const uint8_t *)"ssid", 4U,
                                      output, cancel_immediately, &calls) == -1);
    assert(calls == 1U);
    assert_zero(output, sizeof(output));

    uint8_t hmac[20] = {0};
    assert(crack_worker_sw_hmac_sha1(NULL, 1U, NULL, 0U, hmac) == -2);
    assert(crack_worker_sw_hmac_sha1(NULL, 0U, NULL, 1U, hmac) == -2);
    assert(crack_worker_sw_hmac_sha1(NULL, 0U, NULL, 0U, NULL) == -2);
}

int main(void)
{
    test_rfc2202_hmac_sha1_vectors();
    test_ieee_wpa_pmk_known_answer();
    test_invalid_inputs_and_cancel_wipe_output();
    return 0;
}
