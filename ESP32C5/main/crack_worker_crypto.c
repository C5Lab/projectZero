#include "crack_worker_crypto.h"
#include "crack_worker_sw_sha1.h"

#include <string.h>

/* ESP-IDF 6.0 (TF-PSA-Crypto) hides the legacy one-shot HMAC prototype
 * (mbedtls_md_hmac) behind this switch; the symbol is still compiled and
 * linked from the mbedtls "extras" library. */
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include "mbedtls/md.h"
#include "mbedtls/platform_util.h"

static bool compute_kck(const uint8_t pmk[32], const crack_worker_hccapx_t *record,
                        uint8_t kck[16])
{
    static const char label[] = "Pairwise key expansion";
    const uint8_t *mac_min = record->mac_ap;
    const uint8_t *mac_max = record->mac_sta;
    const uint8_t *nonce_min = record->nonce_ap;
    const uint8_t *nonce_max = record->nonce_sta;
    if (memcmp(mac_min, mac_max, 6) > 0) {
        mac_min = record->mac_sta;
        mac_max = record->mac_ap;
    }
    if (memcmp(nonce_min, nonce_max, 32) > 0) {
        nonce_min = record->nonce_sta;
        nonce_max = record->nonce_ap;
    }

    uint8_t data[100];
    size_t offset = 0;
    memcpy(data + offset, label, 22); offset += 22;
    data[offset++] = 0;
    memcpy(data + offset, mac_min, 6); offset += 6;
    memcpy(data + offset, mac_max, 6); offset += 6;
    memcpy(data + offset, nonce_min, 32); offset += 32;
    memcpy(data + offset, nonce_max, 32); offset += 32;
    data[offset++] = 0;

    uint8_t digest[20];
    bool ok = crack_worker_sw_hmac_sha1(pmk, 32, data, offset, digest) == 0;
    if (ok) memcpy(kck, digest, 16);
    mbedtls_platform_zeroize(digest, sizeof(digest));
    mbedtls_platform_zeroize(data, sizeof(data));
    return ok;
}

static int test_pmk(const uint8_t pmk[32], const crack_worker_hccapx_t *record)
{
    uint8_t kck[16] = {0};
    uint8_t mic[20] = {0};
    uint8_t eapol[256];
    int result = -2;
    if (!crack_worker_hccapx_valid(record) || !compute_kck(pmk, record, kck)) goto done;
    memcpy(eapol, record->eapol, record->eapol_len);
    memset(eapol + 81, 0, 16);
    int error;
    if (record->keyver == 1) {
        const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_MD5);
        error = md == NULL ? -1 : mbedtls_md_hmac(md, kck, sizeof(kck), eapol,
                                                  record->eapol_len, mic);
    } else {
        error = crack_worker_sw_hmac_sha1(kck, sizeof(kck), eapol,
                                          record->eapol_len, mic);
    }
    if (error == 0) result = memcmp(mic, record->keymic, 16) == 0;
done:
    mbedtls_platform_zeroize(kck, sizeof(kck));
    mbedtls_platform_zeroize(mic, sizeof(mic));
    mbedtls_platform_zeroize(eapol, sizeof(eapol));
    return result;
}

int crack_worker_verify_candidate(const char *password,
                                  const crack_worker_hccapx_t *records,
                                  size_t record_count,
                                  crack_worker_checkpoint_fn checkpoint,
                                  void *checkpoint_context)
{
    if (password == NULL || records == NULL || record_count == 0 || record_count > 16) {
        return -2;
    }
    uint8_t pmks[16][32] = {{0}};
    int result = -1;
    for (size_t i = 0; i < record_count; ++i) {
        if (!crack_worker_hccapx_valid(&records[i])) {
            result = -2;
            break;
        }
        size_t same = i;
        for (size_t j = 0; j < i; ++j) {
            if (records[j].essid_len == records[i].essid_len &&
                memcmp(records[j].essid, records[i].essid, records[i].essid_len) == 0) {
                same = j;
                break;
            }
        }
        if (same < i) memcpy(pmks[i], pmks[same], sizeof(pmks[i]));
        else {
            int derive = crack_worker_sw_derive_pmk(
                password, records[i].essid, records[i].essid_len, pmks[i],
                checkpoint, checkpoint_context);
            if (derive != 0) {
                result = derive == -1 ? -3 : -2;
                break;
            }
        }
        int match = test_pmk(pmks[i], &records[i]);
        if (match < 0) {
            result = -2;
            break;
        }
        if (match > 0) {
            result = (int)i;
            break;
        }
    }
    mbedtls_platform_zeroize(pmks, sizeof(pmks));
    return result;
}
