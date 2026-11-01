#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "crack_worker_sw_sha1.h"
#include "wpa_decoy.h"

#define DOT11_HEADER_LEN 24U
#define LLC_LEN 8U
#define EAPOL_OFFSET (DOT11_HEADER_LEN + LLC_LEN)
#define EAPOL_MIC_OFFSET 81U

static const uint8_t LLC_EAPOL[LLC_LEN] = {
    0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
};

static void assert_zero(const uint8_t *buffer, size_t length)
{
    for (size_t i = 0; i < length; ++i) assert(buffer[i] == 0U);
}
static bool contains_bytes(const uint8_t *buffer, size_t length,
                           const uint8_t *needle, size_t needle_length)
{
    if (needle_length == 0U || needle_length > length) return false;
    for (size_t i = 0; i + needle_length <= length; ++i) {
        if (memcmp(buffer + i, needle, needle_length) == 0) return true;
    }
    return false;
}

static uint16_t be16(const uint8_t *value)
{
    return (uint16_t)(((uint16_t)value[0] << 8) | value[1]);
}

static bool m2_mic_valid(const uint8_t *frame, size_t length)
{
    static const uint8_t kck[16] = {
        0x22, 0x28, 0xae, 0xd0, 0xbf, 0x46, 0xe1, 0x0b,
        0x9a, 0xdf, 0xf8, 0xab, 0x60, 0xd1, 0x9d, 0x1d,
    };
    if (!frame || length != 131U) return false;
    uint8_t eapol[99];
    memcpy(eapol, frame + EAPOL_OFFSET, sizeof(eapol));
    uint8_t received[16];
    memcpy(received, eapol + EAPOL_MIC_OFFSET, sizeof(received));
    memset(eapol + EAPOL_MIC_OFFSET, 0, sizeof(received));
    uint8_t digest[20];
    assert(crack_worker_sw_hmac_sha1(kck, sizeof(kck), eapol,
                                     sizeof(eapol), digest) == 0);
    return memcmp(received, digest, sizeof(received)) == 0;
}

static wpa_decoy_material_t fixture(void)
{
    wpa_decoy_material_t material = {0};
    const uint8_t bssid[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t sta[6] = {0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb};
    memcpy(material.bssid, bssid, sizeof(bssid));
    memcpy(material.sta, sta, sizeof(sta));
    for (size_t i = 0; i < sizeof(material.pmk); ++i) {
        material.pmk[i] = (uint8_t)(i + 128U);
        material.anonce[i] = (uint8_t)i;
        material.snonce[i] = (uint8_t)(i + 32U);
    }
    material.replay_counter = UINT64_C(0x0102030405060708);
    return material;
}

static void assert_common_data_header(const uint8_t *frame)
{
    assert(frame[2] == 0U && frame[3] == 0U);
    assert(memcmp(frame + DOT11_HEADER_LEN, LLC_EAPOL, LLC_LEN) == 0);
    assert(frame[EAPOL_OFFSET] == 2U);
    assert(frame[EAPOL_OFFSET + 1U] == 3U);
}

int main(void)
{
    wpa_decoy_material_t material = fixture();
    wpa_decoy_pair_t pair;
    memset(&pair, 0xa5, sizeof(pair));
    assert(wpa_decoy_build_pair(&material, &pair));
    assert(pair.m1_len == 131U && pair.m2_len == 131U);

    assert(pair.m1[0] == 0x08U && pair.m1[1] == 0x02U);
    assert(memcmp(pair.m1 + 4U, material.sta, 6U) == 0);
    assert(memcmp(pair.m1 + 10U, material.bssid, 6U) == 0);
    assert(memcmp(pair.m1 + 16U, material.bssid, 6U) == 0);
    assert(pair.m2[0] == 0x08U && pair.m2[1] == 0x01U);
    assert(memcmp(pair.m2 + 4U, material.bssid, 6U) == 0);
    assert(memcmp(pair.m2 + 10U, material.sta, 6U) == 0);
    assert(memcmp(pair.m2 + 16U, material.bssid, 6U) == 0);
    assert_common_data_header(pair.m1);
    assert_common_data_header(pair.m2);

    const uint8_t *m1_eapol = pair.m1 + EAPOL_OFFSET;
    const uint8_t *m2_eapol = pair.m2 + EAPOL_OFFSET;
    assert(be16(m1_eapol + 2U) == 95U && be16(m2_eapol + 2U) == 95U);
    assert(m1_eapol[4] == 2U && m2_eapol[4] == 2U);
    assert(be16(m1_eapol + 5U) == 0x008aU);
    assert(be16(m2_eapol + 5U) == 0x010aU);
    assert(be16(m1_eapol + 7U) == 16U && be16(m2_eapol + 7U) == 16U);
    const uint8_t replay[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    assert(memcmp(m1_eapol + 9U, replay, sizeof(replay)) == 0);
    assert(memcmp(m2_eapol + 9U, replay, sizeof(replay)) == 0);
    assert(memcmp(m1_eapol + 17U, material.anonce, 32U) == 0);
    assert(memcmp(m2_eapol + 17U, material.snonce, 32U) == 0);
    assert_zero(m1_eapol + EAPOL_MIC_OFFSET, 16U);
    static const uint8_t expected_m2_mic[16] = {
        0x0b, 0x27, 0x39, 0x42, 0xdb, 0xeb, 0x2f, 0x8a,
        0x80, 0x3e, 0x46, 0xfc, 0xbd, 0x39, 0x48, 0xc0,
    };
    assert(memcmp(m2_eapol + EAPOL_MIC_OFFSET, expected_m2_mic,
                  sizeof(expected_m2_mic)) == 0);
    assert(be16(m1_eapol + 97U) == 0U && be16(m2_eapol + 97U) == 0U);
    assert(m2_mic_valid(pair.m2, pair.m2_len));
    pair.m2[EAPOL_OFFSET + 17U] ^= 1U;
    assert(!m2_mic_valid(pair.m2, pair.m2_len));
    pair.m2[EAPOL_OFFSET + 17U] ^= 1U;

    assert(!contains_bytes(pair.m1, pair.m1_len, material.pmk,
                           sizeof(material.pmk)));
    assert(!contains_bytes(pair.m2, pair.m2_len, material.pmk,
                           sizeof(material.pmk)));

    uint8_t pmkid_m1[WPA_DECOY_FRAME_MAX];
    size_t pmkid_m1_len = 0U;
    memset(pmkid_m1, 0xa5, sizeof(pmkid_m1));
    assert(wpa_decoy_build_pmkid_m1(&material, pmkid_m1, &pmkid_m1_len));
    assert(pmkid_m1_len == 153U);
    assert_common_data_header(pmkid_m1);
    const uint8_t *pmkid_eapol = pmkid_m1 + EAPOL_OFFSET;
    assert(be16(pmkid_eapol + 2U) == 117U);
    assert(be16(pmkid_eapol + 5U) == 0x008aU);
    assert(memcmp(pmkid_eapol + 17U, material.anonce, 32U) == 0);
    assert_zero(pmkid_eapol + EAPOL_MIC_OFFSET, 16U);
    assert(be16(pmkid_eapol + 97U) == 22U);
    static const uint8_t expected_kde[22] = {
        0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04,
        0x51, 0x2f, 0x1c, 0x43, 0xf0, 0x44, 0x8f, 0x04,
        0x17, 0x7f, 0xca, 0x02, 0xbc, 0x88, 0xd4, 0x9e,
    };
    assert(memcmp(pmkid_eapol + 99U, expected_kde,
                  sizeof(expected_kde)) == 0);
    assert(!contains_bytes(pmkid_m1, pmkid_m1_len, material.pmk,
                           sizeof(material.pmk)));

    wpa_decoy_pair_t rejected;
    memset(&rejected, 0xa5, sizeof(rejected));
    material.bssid[0] |= 1U;
    assert(!wpa_decoy_build_pair(&material, &rejected));
    assert_zero((const uint8_t *)&rejected, sizeof(rejected));
    material = fixture();
    material.sta[0] |= 1U;
    assert(!wpa_decoy_build_pair(&material, &rejected));
    material = fixture();
    memcpy(material.sta, material.bssid, 6U);
    assert(!wpa_decoy_build_pair(&material, &rejected));
    material = fixture();
    memset(material.anonce, 0, sizeof(material.anonce));
    assert(!wpa_decoy_build_pair(&material, &rejected));
    material = fixture();
    memset(material.snonce, 0, sizeof(material.snonce));
    assert(!wpa_decoy_build_pair(&material, &rejected));
    material = fixture();
    assert(!wpa_decoy_build_pair(NULL, &rejected));
    assert(!wpa_decoy_build_pair(&material, NULL));
    pmkid_m1_len = 99U;
    assert(!wpa_decoy_build_pmkid_m1(NULL, pmkid_m1, &pmkid_m1_len));
    assert(pmkid_m1_len == 0U);
    assert_zero(pmkid_m1, sizeof(pmkid_m1));

    puts("WPA decoy frames: PASS");
    return 0;
}
