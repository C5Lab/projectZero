#include "pcap_serializer.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static bool fail_next_realloc = false;
static bool fail_next_malloc = false;

void *__real_malloc(size_t size);
void *__real_realloc(void *buffer, size_t size);

void *__wrap_malloc(size_t size)
{
    if (fail_next_malloc) {
        fail_next_malloc = false;
        return NULL;
    }
    return __real_malloc(size);
}

void *__wrap_realloc(void *buffer, size_t size)
{
    if (fail_next_realloc) {
        fail_next_realloc = false;
        return NULL;
    }
    return __real_realloc(buffer, size);
}

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

static void test_checked_append_requires_initialized_serializer(void)
{
    static const uint8_t frame[] = {0x01};

    pcap_serializer_deinit();
    assert(pcap_serializer_append_frame_checked(frame, sizeof(frame), 1U) ==
           PCAP_SERIALIZER_APPEND_NOT_INITIALIZED);
}

static void test_bounded_capture_rejects_overflow_without_mutating_data(void)
{
    static const uint8_t first_frame[] = {0xde, 0xad, 0xbe, 0xef};
    static const uint8_t overflowing_frame[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };

    uint8_t *bytes = pcap_serializer_init_bounded(32U, 64U, false);
    assert(bytes != NULL);
    assert(pcap_serializer_get_capacity() == 32U);
    assert(pcap_serializer_get_limit() == 64U);

    assert(pcap_serializer_append_frame_checked(first_frame,
                                                sizeof(first_frame), 2U) ==
           PCAP_SERIALIZER_APPEND_OK);
    assert(pcap_serializer_get_size() == 44U);
    assert(pcap_serializer_get_capacity() >= pcap_serializer_get_size());
    assert(pcap_serializer_get_capacity() <= 64U);

    uint8_t snapshot[64];
    const unsigned size_before = pcap_serializer_get_size();
    const unsigned capacity_before = pcap_serializer_get_capacity();
    memcpy(snapshot, pcap_serializer_get_buffer(), size_before);

    assert(pcap_serializer_append_frame_checked(overflowing_frame,
                                                sizeof(overflowing_frame), 3U) ==
           PCAP_SERIALIZER_APPEND_LIMIT);
    assert(pcap_serializer_get_size() == size_before);
    assert(pcap_serializer_get_capacity() == capacity_before);
    assert(memcmp(snapshot, pcap_serializer_get_buffer(), size_before) == 0);
}

static void test_bounded_exact_fit_and_initial_capacity_edges(void)
{
    static const uint8_t frame[] = {0x01, 0x02, 0x03, 0x04};
    const size_t exact = sizeof(pcap_global_header_t) +
                         sizeof(pcap_record_header_t) + sizeof(frame);

    pcap_serializer_deinit();
    assert(pcap_serializer_init_bounded(1U,
               sizeof(pcap_global_header_t) - 1U, false) == NULL);
    assert(pcap_serializer_get_buffer() == NULL);

    assert(pcap_serializer_init_bounded(exact + 100U, exact, false) != NULL);
    assert(pcap_serializer_get_capacity() == exact);
    assert(pcap_serializer_get_limit() == exact);
    assert(pcap_serializer_append_frame_checked(frame, sizeof(frame),
                                                UINT_MAX) ==
           PCAP_SERIALIZER_APPEND_OK);
    assert(pcap_serializer_get_size() == exact);

    uint8_t snapshot[sizeof(pcap_global_header_t) +
                     sizeof(pcap_record_header_t) + sizeof(frame)];
    memcpy(snapshot, pcap_serializer_get_buffer(), exact);
    assert(pcap_serializer_append_frame_checked(frame, 1U, 0U) ==
           PCAP_SERIALIZER_APPEND_LIMIT);
    assert(pcap_serializer_get_size() == exact);
    assert(memcmp(snapshot, pcap_serializer_get_buffer(), exact) == 0);
}

static void test_checked_append_rejects_invalid_buffer_without_mutation(void)
{
    const unsigned size_before = pcap_serializer_get_size();
    const unsigned capacity_before = pcap_serializer_get_capacity();

    assert(pcap_serializer_append_frame_checked(NULL, 1U, 4U) ==
           PCAP_SERIALIZER_APPEND_INVALID);
    assert(pcap_serializer_get_size() == size_before);
    assert(pcap_serializer_get_capacity() == capacity_before);
}

static void test_allocation_failure_does_not_mutate_existing_capture(void)
{
    static const uint8_t frame[] = {0x10, 0x20, 0x30, 0x40};
    uint8_t snapshot[32];

    assert(pcap_serializer_init_bounded(32U, 128U, false) != NULL);
    const unsigned size_before = pcap_serializer_get_size();
    const size_t capacity_before = pcap_serializer_get_capacity();
    memcpy(snapshot, pcap_serializer_get_buffer(), size_before);

    fail_next_realloc = true;
    assert(pcap_serializer_append_frame_checked(frame, sizeof(frame), 5U) ==
           PCAP_SERIALIZER_APPEND_ALLOC_FAILED);
    assert(pcap_serializer_get_size() == size_before);
    assert(pcap_serializer_get_capacity() == capacity_before);
    assert(memcmp(snapshot, pcap_serializer_get_buffer(), size_before) == 0);
}

static void test_failed_reinit_preserves_existing_capture(void)
{
    static const uint8_t frame[] = {0xaa, 0xbb};

    assert(pcap_serializer_init_bounded(64U, 128U, false) != NULL);
    assert(pcap_serializer_append_frame_checked(frame, sizeof(frame), 6U) ==
           PCAP_SERIALIZER_APPEND_OK);
    uint8_t snapshot[64];
    uint8_t *const pointer_before = pcap_serializer_get_buffer();
    const unsigned size_before = pcap_serializer_get_size();
    const size_t capacity_before = pcap_serializer_get_capacity();
    const size_t limit_before = pcap_serializer_get_limit();
    memcpy(snapshot, pointer_before, size_before);

    fail_next_malloc = true;
    assert(pcap_serializer_init_bounded(32U, 64U, false) == NULL);
    assert(pcap_serializer_get_buffer() == pointer_before);
    assert(pcap_serializer_get_size() == size_before);
    assert(pcap_serializer_get_capacity() == capacity_before);
    assert(pcap_serializer_get_limit() == limit_before);
    assert(memcmp(snapshot, pcap_serializer_get_buffer(), size_before) == 0);
}

static void test_maximum_unsigned_frame_size_is_rejected_before_copy(void)
{
    static const uint8_t one_byte_buffer[] = {0x7f};
    uint8_t snapshot[32];

    assert(pcap_serializer_init_bounded(32U, 128U, false) != NULL);
    const unsigned size_before = pcap_serializer_get_size();
    memcpy(snapshot, pcap_serializer_get_buffer(), size_before);

    assert(pcap_serializer_append_frame_checked(one_byte_buffer, UINT_MAX, 7U) ==
           PCAP_SERIALIZER_APPEND_LIMIT);
    assert(pcap_serializer_get_size() == size_before);
    assert(memcmp(snapshot, pcap_serializer_get_buffer(), size_before) == 0);
}

static void test_repeated_bounded_rotations_stay_below_limit(void)
{
    uint8_t frame[31];
    memset(frame, 0xa5, sizeof(frame));

    for (unsigned rotation = 0; rotation < 128U; ++rotation) {
        uint8_t *bytes = pcap_serializer_init_bounded(32U, 256U, false);
        assert(bytes != NULL);
        assert(pcap_serializer_get_size() == 24U);
        assert(((const pcap_global_header_t *)bytes)->magic_number ==
               UINT32_C(0xa1b2c3d4));

        while (pcap_serializer_append_frame_checked(frame, sizeof(frame),
                                                    rotation) ==
               PCAP_SERIALIZER_APPEND_OK) {
            assert(pcap_serializer_get_size() <= 256U);
            assert(pcap_serializer_get_capacity() <= 256U);
        }
        assert(pcap_serializer_get_size() <= 256U);
        assert(pcap_serializer_get_capacity() <= 256U);
    }

    pcap_serializer_deinit();
}

int main(void)
{
    test_empty_capture_header();
    test_timestamp_and_payload_are_serialized();
    test_snaplen_truncates_saved_bytes_but_preserves_original_length();
    test_deinit_and_reinit_reset_the_capture();
    test_checked_append_requires_initialized_serializer();
    test_bounded_capture_rejects_overflow_without_mutating_data();
    test_bounded_exact_fit_and_initial_capacity_edges();
    test_checked_append_rejects_invalid_buffer_without_mutation();
    test_allocation_failure_does_not_mutate_existing_capture();
    test_failed_reinit_preserves_existing_capture();
    test_maximum_unsigned_frame_size_is_rejected_before_copy();
    test_repeated_bounded_rotations_stay_below_limit();
    return 0;
}
