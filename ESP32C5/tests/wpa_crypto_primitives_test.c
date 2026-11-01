#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "wpa_crypto_primitives.h"

static void assert_bytes(const uint8_t *actual, const uint8_t *expected,
                         size_t length)
{
    if (memcmp(actual, expected, length) != 0) {
        fprintf(stderr, "actual=");
        for (size_t i = 0; i < length; ++i) fprintf(stderr, "%02x", actual[i]);
        fprintf(stderr, "\nexpected=");
        for (size_t i = 0; i < length; ++i) fprintf(stderr, "%02x", expected[i]);
        fputc('\n', stderr);
        assert(memcmp(actual, expected, length) == 0);
    }
}
static void assert_zero(const uint8_t *buffer, size_t length)
{
    for (size_t i = 0; i < length; ++i) assert(buffer[i] == 0U);
}

int main(void)
{
    static const uint8_t expected_ptk[64] = {
        0x79, 0xc3, 0x15, 0x81, 0x7d, 0xa2, 0xce, 0x91,
        0x7e, 0x32, 0x64, 0xee, 0xac, 0x39, 0xf9, 0x08,
        0xed, 0xaf, 0xe7, 0x82, 0x05, 0xab, 0x10, 0xe5,
        0xfa, 0x4d, 0x85, 0x50, 0x52, 0x35, 0xf6, 0x96,
        0xad, 0x89, 0x09, 0x20, 0x24, 0xc3, 0x45, 0x24,
        0xf0, 0x7b, 0x21, 0xe1, 0xf7, 0xba, 0xf3, 0xb4,
        0x76, 0xe2, 0xb3, 0xf0, 0x64, 0xf8, 0x10, 0xeb,
        0x14, 0x07, 0x08, 0xbe, 0x96, 0x8d, 0x02, 0xf3,
    };
    static const uint8_t expected_mic[16] = {
        0xeb, 0xcd, 0x0a, 0x21, 0x23, 0xff, 0xf5, 0x8d,
        0xab, 0xcd, 0x0f, 0x59, 0xdf, 0x20, 0xf2, 0x3b,
    };
    static const uint8_t expected_pmkid[16] = {
        0x51, 0x71, 0xfd, 0x0e, 0x71, 0x83, 0xf4, 0xf1,
        0x41, 0x4a, 0x93, 0xf3, 0x56, 0x07, 0x25, 0xe4,
    };

    uint8_t pmk[32], aa[6], spa[6], anonce[32], snonce[32], eapol[99];
    for (size_t i = 0; i < sizeof(pmk); ++i) pmk[i] = (uint8_t)i;
    const uint8_t aa_literal[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t spa_literal[6] = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
    memcpy(aa, aa_literal, sizeof(aa));
    memcpy(spa, spa_literal, sizeof(spa));
    for (size_t i = 0; i < sizeof(anonce); ++i) {
        anonce[i] = (uint8_t)i;
        snonce[i] = (uint8_t)(i + 32U);
    }
    for (size_t i = 0; i < sizeof(eapol); ++i) eapol[i] = (uint8_t)i;

    uint8_t ptk[64];
    assert(janos_wpa_ptk_sha1(pmk, aa, spa, anonce, snonce, ptk));
    assert_bytes(ptk, expected_ptk, sizeof(ptk));

    uint8_t reversed[64];
    assert(janos_wpa_ptk_sha1(pmk, spa, aa, snonce, anonce, reversed));
    assert_bytes(reversed, expected_ptk, sizeof(reversed));

    uint8_t changed[64];
    pmk[0] ^= 1U;
    assert(janos_wpa_ptk_sha1(pmk, aa, spa, anonce, snonce, changed));
    assert(memcmp(changed, expected_ptk, sizeof(changed)) != 0);
    pmk[0] ^= 1U;

    uint8_t mic[16];
    assert(janos_wpa_eapol_mic_v2(ptk, eapol, sizeof(eapol), mic));
    assert_bytes(mic, expected_mic, sizeof(mic));

    uint8_t pmkid[16];
    assert(janos_wpa_pmkid(pmk, aa, spa, pmkid));
    assert_bytes(pmkid, expected_pmkid, sizeof(pmkid));

    memset(ptk, 0xa5, sizeof(ptk));
    assert(!janos_wpa_ptk_sha1(NULL, aa, spa, anonce, snonce, ptk));
    assert_zero(ptk, sizeof(ptk));
    memset(mic, 0xa5, sizeof(mic));
    assert(!janos_wpa_eapol_mic_v2(expected_ptk, NULL, sizeof(eapol), mic));
    assert_zero(mic, sizeof(mic));
    memset(mic, 0xa5, sizeof(mic));
    assert(!janos_wpa_eapol_mic_v2(expected_ptk, eapol, 0U, mic));
    assert_zero(mic, sizeof(mic));
    memset(mic, 0xa5, sizeof(mic));
    assert(!janos_wpa_eapol_mic_v2(expected_ptk, eapol,
                                    JANOS_WPA_EAPOL_MAX + 1U, mic));
    assert_zero(mic, sizeof(mic));
    memset(pmkid, 0xa5, sizeof(pmkid));
    assert(!janos_wpa_pmkid(pmk, NULL, spa, pmkid));
    assert_zero(pmkid, sizeof(pmkid));

    uint8_t secret[37];
    memset(secret, 0xa5, sizeof(secret));
    janos_wpa_zeroize(secret, sizeof(secret));
    assert_zero(secret, sizeof(secret));
    janos_wpa_zeroize(NULL, sizeof(secret));
    janos_wpa_zeroize(secret, 0U);

    puts("WPA crypto primitives: PASS");
    return 0;
}
