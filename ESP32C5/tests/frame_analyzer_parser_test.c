#include "frame_analyzer_parser.h"

#include <arpa/inet.h>
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static data_frame_t *make_data_frame(size_t body_length)
{
    data_frame_t *frame = calloc(1, sizeof(*frame) + body_length);
    assert(frame != NULL);
    return frame;
}

static void put_eapol_body(uint8_t *body, size_t qos_prefix,
                           uint8_t packet_type)
{
    static const uint8_t llc_snap[6] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00};
    memcpy(body + qos_prefix, llc_snap, sizeof(llc_snap));
    body[qos_prefix + 6] = 0x88;
    body[qos_prefix + 7] = 0x8e;
    eapol_packet_t *eapol = (eapol_packet_t *)(body + qos_prefix + 8);
    eapol->header.version = 2;
    eapol->header.packet_type = packet_type;
    eapol->header.packet_body_length = htons(0);
}

static void test_bssid_match_uses_addr3(void)
{
    const size_t bytes = offsetof(wifi_promiscuous_pkt_t, payload) +
                         sizeof(data_frame_mac_header_t);
    wifi_promiscuous_pkt_t *packet = calloc(1, bytes);
    assert(packet != NULL);
    data_frame_mac_header_t *header =
        (data_frame_mac_header_t *)packet->payload;
    static const uint8_t wanted[6] = {0x02, 1, 2, 3, 4, 5};
    memcpy(header->addr3, wanted, sizeof(wanted));
    assert(is_frame_bssid_matching(packet, (uint8_t *)wanted));
    header->addr3[5] ^= 1U;
    assert(!is_frame_bssid_matching(packet, (uint8_t *)wanted));
    free(packet);
}

static void test_eapol_detection_and_rejections(void)
{
    data_frame_t *frame = make_data_frame(8U + sizeof(eapol_packet_header_t));
    put_eapol_body(frame->body, 0U, EAPOL_KEY);
    eapol_packet_t *eapol = parse_eapol_packet(frame);
    assert(eapol != NULL);
    assert(eapol->header.version == 2U);
    assert(parse_eapol_key_packet(eapol) ==
           (eapol_key_packet_t *)eapol->packet_body);

    eapol->header.packet_type = EAPOL_START;
    assert(parse_eapol_key_packet(eapol) == NULL);
    frame->body[6] = 0x08;
    frame->body[7] = 0x00;
    assert(parse_eapol_packet(frame) == NULL);
    frame->mac_header.frame_control.protected_frame = 1U;
    assert(parse_eapol_packet(frame) == NULL);
    free(frame);
}

static void test_qos_prefix_is_skipped(void)
{
    data_frame_t *frame = make_data_frame(2U + 8U +
                                          sizeof(eapol_packet_header_t));
    frame->mac_header.frame_control.subtype = 8U;
    frame->body[0] = 0x34;
    frame->body[1] = 0x12;
    put_eapol_body(frame->body, 2U, EAPOL_KEY);
    assert(parse_eapol_packet(frame) ==
           (eapol_packet_t *)(frame->body + 10U));
    free(frame);
}

static void test_pmkid_kde_and_encrypted_rejection(void)
{
    static const uint8_t expected[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    const size_t kde_length = 22U;
    eapol_key_packet_t *key = calloc(1, sizeof(*key) + kde_length);
    assert(key != NULL);
    key->key_data_length = htons((uint16_t)kde_length);
    key->key_data[0] = KEY_DATA_TYPE;
    key->key_data[1] = 20U;
    key->key_data[2] = 0x00;
    key->key_data[3] = 0x0f;
    key->key_data[4] = 0xac;
    key->key_data[5] = KEY_DATA_DATA_TYPE_PMKID_KDE;
    memcpy(key->key_data + 6U, expected, sizeof(expected));

    pmkid_item_t *item = parse_pmkid(key);
    assert(item != NULL);
    assert(item->next == NULL);
    assert(memcmp(item->pmkid, expected, sizeof(expected)) == 0);
    free(item);

    key->key_information.encrypted_key_data = 1U;
    assert(parse_pmkid(key) == NULL);
    key->key_information.encrypted_key_data = 0U;
    key->key_data_length = 0U;
    assert(parse_pmkid(key) == NULL);
    free(key);
}

static void write_pmkid_kde(uint8_t *destination, const uint8_t pmkid[16])
{
    destination[0] = KEY_DATA_TYPE;
    destination[1] = 20U;
    destination[2] = 0x00;
    destination[3] = 0x0f;
    destination[4] = 0xac;
    destination[5] = KEY_DATA_DATA_TYPE_PMKID_KDE;
    memcpy(destination + 6U, pmkid, 16U);
}

static void test_multiple_adjacent_pmkids_are_all_returned(void)
{
    static const uint8_t first[16] = {
        0x10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    };
    static const uint8_t second[16] = {
        0x20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    };
    const size_t key_data_length = 44U;
    eapol_key_packet_t *key = calloc(1, sizeof(*key) + key_data_length);
    assert(key != NULL);
    key->key_data_length = htons((uint16_t)key_data_length);
    write_pmkid_kde(key->key_data, first);
    write_pmkid_kde(key->key_data + 22U, second);

    pmkid_item_t *head = parse_pmkid(key);
    assert(head != NULL);
    assert(memcmp(head->pmkid, second, sizeof(second)) == 0);
    assert(head->next != NULL);
    assert(memcmp(head->next->pmkid, first, sizeof(first)) == 0);
    assert(head->next->next == NULL);
    free(head->next);
    free(head);
    free(key);
}

static void test_truncated_key_data_is_rejected_without_overread(void)
{
    eapol_key_packet_t *key = calloc(1, sizeof(*key) + 2U);
    assert(key != NULL);
    key->key_data_length = htons(2U);
    key->key_data[0] = KEY_DATA_TYPE;
    key->key_data[1] = 20U;
    assert(parse_pmkid(key) == NULL);

    key->key_data_length = htons(1U);
    assert(parse_pmkid(key) == NULL);
    free(key);
}

int main(void)
{
    test_bssid_match_uses_addr3();
    test_eapol_detection_and_rejections();
    test_qos_prefix_is_skipped();
    test_pmkid_kde_and_encrypted_rejection();
    test_multiple_adjacent_pmkids_are_all_returned();
    test_truncated_key_data_is_rejected_without_overread();
    return 0;
}
