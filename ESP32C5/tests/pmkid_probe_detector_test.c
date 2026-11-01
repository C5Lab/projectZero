#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "pmkid_probe_detector.h"

static const uint8_t AP_A[6] = {0x02, 0, 0, 0, 0, 1};
static const uint8_t AP_B[6] = {0x02, 0, 0, 0, 0, 2};
static const uint8_t STA_A[6] = {0x06, 0, 0, 0, 0, 1};
static const uint8_t STA_B[6] = {0x06, 0, 0, 0, 0, 2};

static size_t auth_request(uint8_t frame[64], const uint8_t bssid[6],
                           const uint8_t sta[6])
{
    memset(frame, 0, 64U);
    frame[0] = 0xb0U;
    memcpy(frame + 4U, bssid, 6U);
    memcpy(frame + 10U, sta, 6U);
    memcpy(frame + 16U, bssid, 6U);
    frame[24] = 0U; frame[25] = 0U; /* Open System. */
    frame[26] = 1U; frame[27] = 0U; /* Request sequence. */
    frame[28] = 0U; frame[29] = 0U;
    return 30U;
}
static size_t assoc_request(uint8_t frame[64], const uint8_t bssid[6],
                            const uint8_t sta[6], bool reassoc)
{
    memset(frame, 0, 64U);
    frame[0] = reassoc ? 0x20U : 0x00U;
    memcpy(frame + 4U, bssid, 6U);
    memcpy(frame + 10U, sta, 6U);
    memcpy(frame + 16U, bssid, 6U);
    frame[24] = 0x31U;
    frame[26] = 10U;
    if (reassoc) memcpy(frame + 28U, bssid, 6U);
    return reassoc ? 34U : 28U;
}

static void assert_zero_mac(const uint8_t value[6])
{
    static const uint8_t zero[6] = {0};
    assert(memcmp(value, zero, sizeof(zero)) == 0);
}

static pmkid_probe_result_t observe(pmkid_probe_detector_t *detector,
                                    const uint8_t *frame, size_t length,
                                    uint8_t channel, int64_t now_us,
                                    const uint8_t *expected_bssid,
                                    const uint8_t *expected_sta)
{
    uint8_t bssid[6];
    uint8_t sta[6];
    memset(bssid, 0xa5, sizeof(bssid));
    memset(sta, 0xa5, sizeof(sta));
    pmkid_probe_result_t result = pmkid_probe_observe(
        detector, frame, length, channel, now_us, bssid, sta);
    if (result == PMKID_PROBE_ASSOC_SEQUENCE) {
        assert(expected_bssid && expected_sta);
        assert(memcmp(bssid, expected_bssid, 6U) == 0);
        assert(memcmp(sta, expected_sta, 6U) == 0);
    } else {
        assert_zero_mac(bssid);
        assert_zero_mac(sta);
    }
    return result;
}

static void test_auth_assoc_and_reassoc_sequences(void)
{
    pmkid_probe_detector_t detector;
    pmkid_probe_reset(&detector);
    uint8_t frame[64];
    size_t length = auth_request(frame, AP_A, STA_A);
    assert(observe(&detector, frame, length, 6U, 1000U, NULL, NULL) ==
           PMKID_PROBE_AUTH_SEEN);
    length = assoc_request(frame, AP_A, STA_A, false);
    assert(observe(&detector, frame, length, 6U,
                   1000U + PMKID_PROBE_WINDOW_US, AP_A, STA_A) ==
           PMKID_PROBE_ASSOC_SEQUENCE);
    /* A consumed association cannot be replayed without a new auth. */
    assert(observe(&detector, frame, length, 6U,
                   1001U + PMKID_PROBE_WINDOW_US, NULL, NULL) ==
           PMKID_PROBE_NONE);

    length = auth_request(frame, AP_A, STA_A);
    assert(observe(&detector, frame, length, 6U, 5000000U, NULL, NULL) ==
           PMKID_PROBE_AUTH_SEEN);
    length = assoc_request(frame, AP_A, STA_A, true);
    assert(observe(&detector, frame, length, 6U, 5000100U, AP_A, STA_A) ==
           PMKID_PROBE_ASSOC_SEQUENCE);
}

static void test_mismatch_timeout_response_and_malformed_frames(void)
{
    pmkid_probe_detector_t detector;
    pmkid_probe_reset(&detector);
    uint8_t frame[64];
    size_t length = assoc_request(frame, AP_A, STA_A, false);
    assert(observe(&detector, frame, length, 6U, 1U, NULL, NULL) ==
           PMKID_PROBE_NONE);

    length = auth_request(frame, AP_A, STA_A);
    assert(observe(&detector, frame, length, 6U, 100U, NULL, NULL) ==
           PMKID_PROBE_AUTH_SEEN);
    length = assoc_request(frame, AP_A, STA_B, false);
    assert(observe(&detector, frame, length, 6U, 101U, NULL, NULL) ==
           PMKID_PROBE_NONE);
    length = assoc_request(frame, AP_B, STA_A, false);
    assert(observe(&detector, frame, length, 6U, 102U, NULL, NULL) ==
           PMKID_PROBE_NONE);
    length = assoc_request(frame, AP_A, STA_A, false);
    assert(observe(&detector, frame, length, 11U, 103U, NULL, NULL) ==
           PMKID_PROBE_NONE);
    assert(observe(&detector, frame, length, 6U,
                   100U + PMKID_PROBE_WINDOW_US + 1, NULL, NULL) ==
           PMKID_PROBE_NONE);

    length = auth_request(frame, AP_A, STA_A);
    frame[26] = 2U; /* Authentication Response. */
    assert(observe(&detector, frame, length, 6U, 3000000U, NULL, NULL) ==
           PMKID_PROBE_NONE);
    frame[26] = 1U;
    frame[24] = 1U; /* Shared Key algorithm. */
    assert(observe(&detector, frame, length, 6U, 3000001U, NULL, NULL) ==
           PMKID_PROBE_NONE);
    frame[24] = 0U;
    frame[1] = 0x40U; /* Protected management frame. */
    assert(observe(&detector, frame, length, 6U, 3000002U, NULL, NULL) ==
           PMKID_PROBE_NONE);
    frame[1] = 0U;
    assert(observe(&detector, frame, 29U, 6U, 3000003U, NULL, NULL) ==
           PMKID_PROBE_NONE);
    frame[10] |= 1U;
    assert(observe(&detector, frame, length, 6U, 3000004U, NULL, NULL) ==
           PMKID_PROBE_NONE);
    assert(observe(&detector, NULL, length, 6U, 3000005U, NULL, NULL) ==
           PMKID_PROBE_NONE);
    assert(observe(&detector, frame, length, 0U, 3000006U, NULL, NULL) ==
           PMKID_PROBE_NONE);
    assert(observe(&detector, frame, length, 6U, -1, NULL, NULL) ==
           PMKID_PROBE_NONE);
}

static void test_retry_refresh_and_table_eviction_are_bounded(void)
{
    pmkid_probe_detector_t detector;
    pmkid_probe_reset(&detector);
    uint8_t frame[64];
    for (unsigned i = 0; i < PMKID_PROBE_SLOTS + 4U; ++i) {
        uint8_t sta[6] = {0x06, 0, 0, 0, 0, (uint8_t)(i + 1U)};
        size_t length = auth_request(frame, AP_A, sta);
        assert(observe(&detector, frame, length, 6U, (int64_t)i,
                       NULL, NULL) == PMKID_PROBE_AUTH_SEEN);
    }
    uint8_t latest_sta[6] = {
        0x06, 0, 0, 0, 0, (uint8_t)(PMKID_PROBE_SLOTS + 4U)
    };
    size_t length = assoc_request(frame, AP_A, latest_sta, false);
    assert(observe(&detector, frame, length, 6U, 100U,
                   AP_A, latest_sta) == PMKID_PROBE_ASSOC_SEQUENCE);

    pmkid_probe_reset(&detector);
    length = auth_request(frame, AP_A, STA_A);
    assert(observe(&detector, frame, length, 6U, 1000U, NULL, NULL) ==
           PMKID_PROBE_AUTH_SEEN);
    assert(observe(&detector, frame, length, 6U, 2000U, NULL, NULL) ==
           PMKID_PROBE_AUTH_SEEN);
    length = assoc_request(frame, AP_A, STA_A, false);
    assert(observe(&detector, frame, length, 6U,
                   2000U + PMKID_PROBE_WINDOW_US, AP_A, STA_A) ==
           PMKID_PROBE_ASSOC_SEQUENCE);
    pmkid_probe_reset(&detector);
    assert(observe(&detector, frame, length, 6U, 2100U, NULL, NULL) ==
           PMKID_PROBE_NONE);
}

int main(void)
{
    test_auth_assoc_and_reassoc_sequences();
    test_mismatch_timeout_response_and_malformed_frames();
    test_retry_refresh_and_table_eviction_are_bounded();
    puts("PMKID probe detector: PASS");
    return 0;
}
