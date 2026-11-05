#include "wifi_shield_storage_bundle.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    CAP_SPIRAM = 0x10U,
    CAP_8BIT = 0x02U,
    ALIGNMENT = 16U,
    EVENT_CAPACITY = 24U,
    EVENT_SIZE = 7U,
    OUTPUT_RECORDS = 8U,
    OUTPUT_RECORD_SIZE = 13U,
    STACK_BYTES = 4096U,
    STATE_BYTES = 101U,
    JOURNAL_PLATFORM_BYTES = 73U,
};

static void *state_storage;
static void *event_ring;
static void *output_queue;
static void *publisher_stack;
static void *journal_queue;
static void *journal_stack;
static void *journal_platform;
static void *allocations[7];
static size_t allocation_sizes[7];
static unsigned allocation_calls;
static unsigned release_calls;
static unsigned fail_at;
static unsigned queue_fail;
static unsigned queue_calls;

static wifi_shield_storage_destinations_t destinations(void)
{
    wifi_shield_storage_destinations_t result = {
        .state = &state_storage,
        .event_ring = &event_ring,
        .output_queue = &output_queue,
        .publisher_stack = &publisher_stack,
        .journal_queue = &journal_queue,
        .journal_stack = &journal_stack,
        .journal_platform = &journal_platform,
    };
    return result;
}

static wifi_shield_storage_layout_t layout(void)
{
    wifi_shield_storage_layout_t result = {
        .state_bytes = STATE_BYTES,
        .event_capacity = EVENT_CAPACITY,
        .event_size = EVENT_SIZE,
        .output_records = OUTPUT_RECORDS,
        .output_record_size = OUTPUT_RECORD_SIZE,
        .publisher_stack_bytes = STACK_BYTES,
        .journal_records = 3U,
        .journal_record_size = 19U,
        .journal_stack_bytes = 8192U,
        .journal_platform_bytes = JOURNAL_PLATFORM_BYTES,
        .alignment = ALIGNMENT,
        .spiram_capability = CAP_SPIRAM,
        .byte_capability = CAP_8BIT,
    };
    return result;
}

static void *tracked_allocate(size_t alignment, size_t count, size_t size,
                              uint32_t capabilities)
{
    assert(alignment == ALIGNMENT && count == 1U);
    assert(capabilities == (CAP_SPIRAM | CAP_8BIT));
    static const size_t expected[] = {
        STATE_BYTES,
        EVENT_CAPACITY * EVENT_SIZE,
        OUTPUT_RECORDS * OUTPUT_RECORD_SIZE,
        STACK_BYTES,
        3U * 19U,
        8192U,
        JOURNAL_PLATFORM_BYTES,
    };
    assert(allocation_calls < 7U && size == expected[allocation_calls]);
    ++allocation_calls;
    if (allocation_calls == fail_at) {
        /* Dirty prior allocations so rollback must actively wipe them. */
        for (unsigned i = 0; i + 1U < allocation_calls; ++i)
            memset(allocations[i], 0xa5, allocation_sizes[i]);
        return NULL;
    }
    size_t rounded = (size + alignment - 1U) & ~(alignment - 1U);
    void *memory = aligned_alloc(alignment, rounded);
    assert(memory != NULL);
    memset(memory, 0, rounded);
    allocations[allocation_calls - 1U] = memory;
    allocation_sizes[allocation_calls - 1U] = size;
    return memory;
}

static void tracked_release(void *memory)
{
    unsigned index = 0U;
    while (index < 7U && allocations[index] != memory) ++index;
    assert(index < 7U);
    for (size_t byte = 0U; byte < allocation_sizes[index]; ++byte)
        assert(((const uint8_t *)memory)[byte] == 0U);
    allocations[index] = NULL;
    ++release_calls;
    free(memory);
}

static bool tracked_queue_create(void *context, wifi_shield_storage_queue_role_t role, void *buffer,
                                 size_t records, size_t record_size)
{
    assert(context == &queue_calls);
    assert((unsigned)role == queue_calls);
    if (role == WIFI_SHIELD_STORAGE_QUEUE_OUTPUT) {
        assert(buffer == output_queue);
        assert(records == OUTPUT_RECORDS && record_size == OUTPUT_RECORD_SIZE);
    } else {
        assert(buffer == journal_queue);
        assert(records == 3U && record_size == 19U);
    }
    ++queue_calls;
    if (queue_calls == queue_fail) {
        for (unsigned i = 0; i < 7U; ++i)
            memset(allocations[i], 0xa5, allocation_sizes[i]);
        return false;
    }
    return true;
}

static void reset(void)
{
    state_storage = event_ring = output_queue = publisher_stack = journal_queue =
        journal_stack = journal_platform = NULL;
    memset(allocations, 0, sizeof(allocations));
    memset(allocation_sizes, 0, sizeof(allocation_sizes));
    allocation_calls = release_calls = fail_at = queue_calls = 0U;
    queue_fail = false;
}

static void assert_destinations_null(void)
{
    assert(state_storage == NULL && event_ring == NULL &&
           output_queue == NULL && publisher_stack == NULL &&
           journal_queue == NULL && journal_stack == NULL &&
           journal_platform == NULL);
}

int main(void)
{
    wifi_shield_storage_layout_t configured = layout();
    for (unsigned failure = 1U; failure <= 7U; ++failure) {
        reset();
        fail_at = failure;
        wifi_shield_storage_destinations_t storage = destinations();
        assert(!wifi_shield_storage_bundle_acquire(
            &storage, &configured, tracked_allocate, tracked_release,
            tracked_queue_create, &queue_calls));
        assert(allocation_calls == failure);
        assert(release_calls == failure - 1U && queue_calls == 0U);
        assert_destinations_null();
    }

    wifi_shield_storage_destinations_t storage;
    for (unsigned role_failure = 1U; role_failure <= 2U; ++role_failure) {
        reset();
        storage = destinations();
        queue_fail = role_failure;
        assert(!wifi_shield_storage_bundle_acquire(
            &storage, &configured, tracked_allocate, tracked_release,
            tracked_queue_create, &queue_calls));
        assert(allocation_calls == 7U && queue_calls == role_failure &&
               release_calls == 7U);
        assert_destinations_null();
    }

    reset();
    storage = destinations();
    assert(wifi_shield_storage_bundle_acquire(
        &storage, &configured, tracked_allocate, tracked_release,
        tracked_queue_create, &queue_calls));
    assert(allocation_calls == 7U && queue_calls == 2U && release_calls == 0U);
    memset(state_storage, 0xa5, STATE_BYTES);
    memset(event_ring, 0xa5, EVENT_CAPACITY * EVENT_SIZE);
    memset(output_queue, 0xa5, OUTPUT_RECORDS * OUTPUT_RECORD_SIZE);
    memset(publisher_stack, 0xa5, STACK_BYTES);
    memset(journal_queue, 0xa5, 3U * 19U);
    memset(journal_stack, 0xa5, 8192U);
    memset(journal_platform, 0xa5, JOURNAL_PLATFORM_BYTES);
    wifi_shield_storage_bundle_release(&storage, &configured, tracked_release);
    assert(release_calls == 7U);
    assert_destinations_null();

    puts("wifi shield storage bundle: PASS");
    return 0;
}
