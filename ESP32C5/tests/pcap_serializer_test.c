#include "pcap_serializer.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static void test_empty_capture_header(void)
{
    uint8_t *bytes = pcap_serializer_init();
    assert(bytes != NULL);
    assert(pcap_serializer_get_buffer() == bytes);
    assert(pcap_serializer_get_size() == 24U);

    const pcap_global_header_t *header = (const pcap_global_header_t *)bytes;
    assert(header->magic_number == UINT32_C(0xa1b2c3d4));
    assert(header->version_major == 2U);
    assert(header->version_minor == 4U);
    assert(header->thiszone == 0);
    assert(header->sigfigs == 0U);
    assert(header->snaplen == 65535U);
    assert(header->network == 105U);
}

static void test_timestamp_and_payload_are_serialized(void)
{
    static const uint8_t frame[] = {0xde, 0xad, 0xbe};
    pcap_serializer_append_frame(frame, sizeof(frame), 1500001U);
    assert(pcap_serializer_get_size() == 24U + 16U + sizeof(frame));

    const uint8_t *bytes = pcap_serializer_get_buffer();
    const pcap_record_header_t *record =
        (const pcap_record_header_t *)(bytes + 24U);
    assert(record->ts_sec == 1U);
    assert(record->ts_usec == 500001U);
    assert(record->incl_len == sizeof(frame));
    assert(record->orig_len == sizeof(frame));
    assert(memcmp(bytes + 24U + 16U, frame, sizeof(frame)) == 0);

    unsigned before = pcap_serializer_get_size();
    pcap_serializer_append_frame(frame, 0U, 999U);
    assert(pcap_serializer_get_size() == before);
}

static void test_snaplen_truncates_saved_bytes_but_preserves_original_length(void)
{
    const unsigned original_size = 65536U;
    uint8_t *frame = malloc(original_size);
    assert(frame != NULL);
    for (unsigned i = 0; i < original_size; ++i) frame[i] = (uint8_t)i;

    pcap_serializer_append_frame(frame, original_size, 2000003U);
    const uint8_t *bytes = pcap_serializer_get_buffer();
    const unsigned record_offset = 24U + 16U + 3U;
    const pcap_record_header_t *record =
        (const pcap_record_header_t *)(bytes + record_offset);
    assert(record->ts_sec == 2U);
    assert(record->ts_usec == 3U);
    assert(record->incl_len == 65535U);
    assert(record->orig_len == original_size);
    assert(pcap_serializer_get_size() == record_offset + 16U + 65535U);
    assert(memcmp(bytes + record_offset + 16U, frame, 65535U) == 0);
    free(frame);
}

static void test_deinit_and_reinit_reset_the_capture(void)
{
    pcap_serializer_deinit();
    assert(pcap_serializer_get_buffer() == NULL);
    assert(pcap_serializer_get_size() == 0U);

    test_empty_capture_header();
    assert(pcap_serializer_get_size() == 24U);
    pcap_serializer_deinit();
}

int main(void)
{
    test_empty_capture_header();
    test_timestamp_and_payload_are_serialized();
    test_snaplen_truncates_saved_bytes_but_preserves_original_length();
    test_deinit_and_reinit_reset_the_capture();
    return 0;
}
