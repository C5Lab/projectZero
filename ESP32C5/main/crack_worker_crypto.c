#include "crack_worker_crypto.h"
#include "crack_worker_sw_sha1.h"
#include "wpa_crypto_primitives.h"

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
    uint8_t ptk[64] = {0};
    bool ok = janos_wpa_ptk_sha1(pmk, record->mac_ap, record->mac_sta,
                                 record->nonce_ap, record->nonce_sta, ptk);
    if (ok) memcpy(kck, ptk, 16U);
    janos_wpa_zeroize(ptk, sizeof(ptk));
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
        error = janos_wpa_eapol_mic_v2(kck, eapol, record->eapol_len, mic) ?
                    0 : -1;
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
