#include "wpa_decoy.h"

#include "wpa_crypto_primitives.h"

#include <string.h>

#define DOT11_HEADER_LEN 24U
#define LLC_LEN 8U
#define EAPOL_FIXED_LEN 99U
#define EAPOL_MIC_OFFSET 81U
#define EAPOL_KEY_DATA_LENGTH_OFFSET 97U
#define EAPOL_KEY_DATA_OFFSET 99U

static const uint8_t LLC_EAPOL[LLC_LEN] = {
    0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
};

static bool any_nonzero(const uint8_t *value, size_t length)
{
    uint8_t combined = 0U;
    for (size_t i = 0; i < length; ++i) combined |= value[i];
    return combined != 0U;
}
static bool unicast_address(const uint8_t address[6])
{
    return address && (address[0] & 1U) == 0U && any_nonzero(address, 6U);
}

static bool material_valid(const wpa_decoy_material_t *material)
{
    return material && unicast_address(material->bssid) &&
           unicast_address(material->sta) &&
           memcmp(material->bssid, material->sta, 6U) != 0 &&
           any_nonzero(material->anonce, sizeof(material->anonce)) &&
           any_nonzero(material->snonce, sizeof(material->snonce));
}

static void write_be16(uint8_t *output, uint16_t value)
{
    output[0] = (uint8_t)(value >> 8);
    output[1] = (uint8_t)value;
}

static void write_be64(uint8_t *output, uint64_t value)
{
    for (size_t i = 0; i < 8U; ++i) {
        output[7U - i] = (uint8_t)value;
        value >>= 8;
    }
}

static void build_dot11_header(uint8_t *frame,
                               const wpa_decoy_material_t *material,
                               bool from_ap)
{
    frame[0] = 0x08U;
    frame[1] = from_ap ? 0x02U : 0x01U;
    if (from_ap) {
        memcpy(frame + 4U, material->sta, 6U);
        memcpy(frame + 10U, material->bssid, 6U);
    } else {
        memcpy(frame + 4U, material->bssid, 6U);
        memcpy(frame + 10U, material->sta, 6U);
    }
    memcpy(frame + 16U, material->bssid, 6U);
    memcpy(frame + DOT11_HEADER_LEN, LLC_EAPOL, sizeof(LLC_EAPOL));
}

static bool build_eapol_key(uint8_t frame[WPA_DECOY_FRAME_MAX],
                            size_t *frame_len,
                            const wpa_decoy_material_t *material,
                            bool m2, const uint8_t *key_data,
                            size_t key_data_len)
{
    const size_t eapol_len = EAPOL_FIXED_LEN + key_data_len;
    const size_t total_len = DOT11_HEADER_LEN + LLC_LEN + eapol_len;
    if (!frame || !frame_len || !material ||
        (key_data_len > 0U && !key_data) ||
        eapol_len - 4U > UINT16_MAX || total_len > WPA_DECOY_FRAME_MAX) {
        return false;
    }

    memset(frame, 0, WPA_DECOY_FRAME_MAX);
    build_dot11_header(frame, material, !m2);
    uint8_t *eapol = frame + DOT11_HEADER_LEN + LLC_LEN;
    eapol[0] = 2U;
    eapol[1] = 3U;
    write_be16(eapol + 2U, (uint16_t)(eapol_len - 4U));
    eapol[4] = 2U;
    write_be16(eapol + 5U, m2 ? 0x010aU : 0x008aU);
    write_be16(eapol + 7U, 16U);
    write_be64(eapol + 9U, material->replay_counter);
    memcpy(eapol + 17U, m2 ? material->snonce : material->anonce, 32U);
    write_be16(eapol + EAPOL_KEY_DATA_LENGTH_OFFSET,
               (uint16_t)key_data_len);
    if (key_data_len > 0U) {
        memcpy(eapol + EAPOL_KEY_DATA_OFFSET, key_data, key_data_len);
    }

    if (m2) {
        uint8_t ptk[64] = {0};
        uint8_t mic[16] = {0};
        bool ok = janos_wpa_ptk_sha1(
            material->pmk, material->bssid, material->sta,
            material->anonce, material->snonce, ptk) &&
            janos_wpa_eapol_mic_v2(ptk, eapol, eapol_len, mic);
        if (ok) memcpy(eapol + EAPOL_MIC_OFFSET, mic, sizeof(mic));
        janos_wpa_zeroize(mic, sizeof(mic));
        janos_wpa_zeroize(ptk, sizeof(ptk));
        if (!ok) {
            memset(frame, 0, WPA_DECOY_FRAME_MAX);
            return false;
        }
    }

    *frame_len = total_len;
    return true;
}

bool wpa_decoy_build_pair(const wpa_decoy_material_t *material,
                          wpa_decoy_pair_t *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !material_valid(material)) return false;
    if (!build_eapol_key(out->m1, &out->m1_len, material, false, NULL, 0U) ||
        !build_eapol_key(out->m2, &out->m2_len, material, true, NULL, 0U)) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    return true;
}

bool wpa_decoy_build_pmkid_m1(const wpa_decoy_material_t *material,
                              uint8_t out[WPA_DECOY_FRAME_MAX],
                              size_t *out_len)
{
    if (out) memset(out, 0, WPA_DECOY_FRAME_MAX);
    if (out_len) *out_len = 0U;
    if (!out || !out_len || !material_valid(material)) return false;

    uint8_t key_data[22] = {0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04};
    bool ok = janos_wpa_pmkid(material->pmk, material->bssid, material->sta,
                              key_data + 6U) &&
              build_eapol_key(out, out_len, material, false,
                              key_data, sizeof(key_data));
    janos_wpa_zeroize(key_data, sizeof(key_data));
    if (!ok) {
        memset(out, 0, WPA_DECOY_FRAME_MAX);
        *out_len = 0U;
    }
    return ok;
}
