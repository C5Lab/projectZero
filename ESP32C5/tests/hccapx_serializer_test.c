#include "hccapx_serializer.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t AP[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
static const uint8_t STA[6] = {0x02, 0x10, 0x20, 0x30, 0x40, 0x50};

static data_frame_t *make_key_frame(bool from_ap, uint8_t nonce_seed,
                                    uint8_t mic_seed)
{
    const size_t key_length = sizeof(eapol_key_packet_t);
    const size_t body_length = 8U + sizeof(eapol_packet_header_t) + key_length;
    data_frame_t *frame = calloc(1, sizeof(*frame) + body_length);
    assert(frame != NULL);
    memcpy(frame->mac_header.addr1, from_ap ? STA : AP, 6U);
    memcpy(frame->mac_header.addr2, from_ap ? AP : STA, 6U);
    memcpy(frame->mac_header.addr3, AP, 6U);

    static const uint8_t llc_snap[6] = {0xaa, 0xaa, 0x03, 0, 0, 0};
    memcpy(frame->body, llc_snap, sizeof(llc_snap));
    frame->body[6] = 0x88;
    frame->body[7] = 0x8e;
    eapol_packet_t *eapol = (eapol_packet_t *)(frame->body + 8U);
    eapol->header.version = 2U;
    eapol->header.packet_type = EAPOL_KEY;
    eapol->header.packet_body_length = htons((uint16_t)key_length);
    eapol_key_packet_t *key = (eapol_key_packet_t *)eapol->packet_body;
    key->descriptor_type = 2U;
    key->key_data_length = 0U;
    for (size_t i = 0; i < sizeof(key->key_nonce); ++i)
        key->key_nonce[i] = nonce_seed == 0U ? 0U : (uint8_t)(nonce_seed + i);
    for (size_t i = 0; i < sizeof(key->key_mic); ++i)
        key->key_mic[i] = mic_seed == 0U ? 0U : (uint8_t)(mic_seed + i);
    return frame;
}

static void test_m1_m2_produces_literal_hccapx_contract(void)
{
    static const uint8_t ssid[] = {'L', 'a', 'b'};
    hccapx_serializer_init(ssid, sizeof(ssid));
    assert(hccapx_serializer_get() == NULL);

    data_frame_t *m1 = make_key_frame(true, 0x20U, 0U);
    data_frame_t *m2 = make_key_frame(false, 0x70U, 0xa0U);
    hccapx_serializer_add_frame(m1);
    assert(hccapx_serializer_get() == NULL);
    hccapx_serializer_add_frame(m2);

    const hccapx_t *result = hccapx_serializer_get();
    assert(result != NULL);
    assert(result->signature == UINT32_C(0x58504348));
    assert(result->version == 4U);
    assert(result->message_pair == 0U);
    assert(result->essid_len == sizeof(ssid));
    assert(memcmp(result->essid, ssid, sizeof(ssid)) == 0);
    assert(result->keyver == 2U);
    assert(memcmp(result->mac_ap, AP, sizeof(AP)) == 0);
    assert(memcmp(result->mac_sta, STA, sizeof(STA)) == 0);
    for (size_t i = 0; i < 32U; ++i) {
        assert(result->nonce_ap[i] == (uint8_t)(0x20U + i));
        assert(result->nonce_sta[i] == (uint8_t)(0x70U + i));
    }
    for (size_t i = 0; i < 16U; ++i) {
        assert(result->keymic[i] == (uint8_t)(0xa0U + i));
        assert(result->eapol[81U + i] == 0U);
    }
    assert(result->eapol_len ==
           sizeof(eapol_packet_header_t) + sizeof(eapol_key_packet_t));
    free(m1);
    free(m2);
}

static void test_init_isolates_sessions_and_clears_old_identity(void)
{
    static const uint8_t replacement[] = {'N', 'e', 'w'};
    hccapx_serializer_init(replacement, sizeof(replacement));
    assert(hccapx_serializer_get() == NULL);

    data_frame_t *m2_only = make_key_frame(false, 0x55U, 0x90U);
    hccapx_serializer_add_frame(m2_only);
    assert(hccapx_serializer_get() == NULL);
    free(m2_only);
}

static void test_m3_m4_capture_keeps_the_m3_anonce(void)
{
    static const uint8_t ssid[] = {'M', '3'};
    hccapx_serializer_init(ssid, sizeof(ssid));
    data_frame_t *m3 = make_key_frame(true, 0x30U, 0xb0U);
    data_frame_t *m4 = make_key_frame(false, 0U, 0xc0U);
    hccapx_serializer_add_frame(m3);
    hccapx_serializer_add_frame(m4);

    const hccapx_t *result = hccapx_serializer_get();
    assert(result != NULL);
    assert(result->message_pair == 4U);
    for (size_t i = 0; i < 32U; ++i)
        assert(result->nonce_ap[i] == (uint8_t)(0x30U + i));
    free(m3);
    free(m4);
}

int main(void)
{
    test_m1_m2_produces_literal_hccapx_contract();
    test_init_isolates_sessions_and_clears_old_identity();
    test_m3_m4_capture_keeps_the_m3_anonce();
    return 0;
}
