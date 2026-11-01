#include "wpa_crypto_primitives.h"

#include "crack_worker_sw_sha1.h"

#include <string.h>

void janos_wpa_zeroize(void *buffer, size_t length)
{
    volatile uint8_t *bytes = (volatile uint8_t *)buffer;
    if (!bytes) return;
    while (length > 0U) {
        *bytes++ = 0U;
        --length;
    }
}
bool janos_wpa_ptk_sha1(const uint8_t pmk[32], const uint8_t aa[6],
                        const uint8_t spa[6], const uint8_t anonce[32],
                        const uint8_t snonce[32], uint8_t ptk[64])
{
    if (ptk) memset(ptk, 0, 64U);
    if (!pmk || !aa || !spa || !anonce || !snonce || !ptk) return false;

    static const uint8_t label[] = "Pairwise key expansion";
    const uint8_t *mac_min = aa;
    const uint8_t *mac_max = spa;
    const uint8_t *nonce_min = anonce;
    const uint8_t *nonce_max = snonce;
    if (memcmp(mac_min, mac_max, 6U) > 0) {
        mac_min = spa;
        mac_max = aa;
    }
    if (memcmp(nonce_min, nonce_max, 32U) > 0) {
        nonce_min = snonce;
        nonce_max = anonce;
    }

    uint8_t data[100] = {0};
    size_t offset = 0U;
    memcpy(data + offset, label, sizeof(label) - 1U);
    offset += sizeof(label) - 1U;
    data[offset++] = 0U;
    memcpy(data + offset, mac_min, 6U); offset += 6U;
    memcpy(data + offset, mac_max, 6U); offset += 6U;
    memcpy(data + offset, nonce_min, 32U); offset += 32U;
    memcpy(data + offset, nonce_max, 32U); offset += 32U;

    uint8_t digest[20] = {0};
    size_t written = 0U;
    bool ok = true;
    for (uint8_t counter = 0U; counter < 4U; ++counter) {
        data[offset] = counter;
        if (crack_worker_sw_hmac_sha1(pmk, 32U, data, offset + 1U,
                                      digest) != 0) {
            ok = false;
            break;
        }
        size_t remaining = 64U - written;
        size_t take = remaining < sizeof(digest) ? remaining : sizeof(digest);
        memcpy(ptk + written, digest, take);
        written += take;
    }
    janos_wpa_zeroize(digest, sizeof(digest));
    janos_wpa_zeroize(data, sizeof(data));
    if (!ok || written != 64U) {
        janos_wpa_zeroize(ptk, 64U);
        return false;
    }
    return true;
}

bool janos_wpa_eapol_mic_v2(const uint8_t kck[16], const uint8_t *eapol,
                            size_t eapol_len, uint8_t mic[16])
{
    if (mic) memset(mic, 0, 16U);
    if (!kck || !eapol || !mic || eapol_len == 0U ||
        eapol_len > JANOS_WPA_EAPOL_MAX) return false;

    uint8_t digest[20] = {0};
    bool ok = crack_worker_sw_hmac_sha1(kck, 16U, eapol, eapol_len,
                                        digest) == 0;
    if (ok) memcpy(mic, digest, 16U);
    janos_wpa_zeroize(digest, sizeof(digest));
    return ok;
}

bool janos_wpa_pmkid(const uint8_t pmk[32], const uint8_t aa[6],
                     const uint8_t spa[6], uint8_t pmkid[16])
{
    if (pmkid) memset(pmkid, 0, 16U);
    if (!pmk || !aa || !spa || !pmkid) return false;

    static const uint8_t name[] = "PMK Name";
    uint8_t data[(sizeof(name) - 1U) + 6U + 6U];
    size_t offset = 0U;
    memcpy(data + offset, name, sizeof(name) - 1U);
    offset += sizeof(name) - 1U;
    memcpy(data + offset, aa, 6U); offset += 6U;
    memcpy(data + offset, spa, 6U); offset += 6U;

    uint8_t digest[20] = {0};
    bool ok = crack_worker_sw_hmac_sha1(pmk, 32U, data, offset, digest) == 0;
    if (ok) memcpy(pmkid, digest, 16U);
    janos_wpa_zeroize(digest, sizeof(digest));
    janos_wpa_zeroize(data, sizeof(data));
    return ok;
}
