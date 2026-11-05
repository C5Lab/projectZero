#include "janos_psram_storage.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { EXPECTED_CAPS = 0x12U };

static unsigned allocation_calls;
static unsigned release_calls;
static unsigned fail_at_call;
static void *last_allocations[3];

static void *tracked_aligned_calloc(size_t alignment, size_t count, size_t size,
                                    uint32_t caps)
{
    assert(caps == EXPECTED_CAPS);
    assert(alignment == 16U);
    ++allocation_calls;
    if (allocation_calls == fail_at_call) return NULL;
    size_t bytes = count * size;
    size_t rounded = (bytes + alignment - 1U) & ~(alignment - 1U);
    void *memory = aligned_alloc(alignment, rounded);
    assert(memory != NULL);
    memset(memory, 0, rounded);
    last_allocations[allocation_calls - 1U] = memory;
    return memory;
}

static void tracked_free(void *memory)
{
    assert(memory != NULL);
    size_t request_index = 0U;
    while (request_index < 3U && last_allocations[request_index] != memory)
        ++request_index;
    assert(request_index < 3U);
    static const size_t sizes[] = {17U, 33U, 65U};
    for (size_t index = 0U; index < sizes[request_index]; ++index)
        assert(((const uint8_t *)memory)[index] == 0U);
    last_allocations[request_index] = NULL;
    ++release_calls;
    free(memory);
}

static void reset_counters(void)
{
    allocation_calls = 0U;
    release_calls = 0U;
    fail_at_call = 0U;
    memset(last_allocations, 0, sizeof(last_allocations));
}

int main(void)
{
    void *first = NULL;
    void *second = NULL;
    void *third = NULL;
    janos_psram_request_t requests[] = {
        {.destination = &first, .size = 17U, .alignment = 16U},
        {.destination = &second, .size = 33U, .alignment = 16U},
        {.destination = &third, .size = 65U, .alignment = 16U},
    };

    reset_counters();
    assert(janos_psram_allocate_all(requests, 3U, tracked_aligned_calloc,
                                    tracked_free, EXPECTED_CAPS));
    assert(allocation_calls == 3U && release_calls == 0U);
    assert(first != NULL && second != NULL && third != NULL);
    for (size_t index = 0U; index < requests[0].size; ++index)
        assert(((const uint8_t *)first)[index] == 0U);
    for (size_t index = 0U; index < requests[1].size; ++index)
        assert(((const uint8_t *)second)[index] == 0U);
    for (size_t index = 0U; index < requests[2].size; ++index)
        assert(((const uint8_t *)third)[index] == 0U);
    memset(first, 0xa5, requests[0].size);
    memset(second, 0xa5, requests[1].size);
    memset(third, 0xa5, requests[2].size);
    janos_psram_release_all(requests, 3U, tracked_free);
    assert(first == NULL && second == NULL && third == NULL);
    assert(release_calls == 3U);

    reset_counters();
    fail_at_call = 2U;
    assert(!janos_psram_allocate_all(requests, 3U, tracked_aligned_calloc,
                                     tracked_free, EXPECTED_CAPS));
    assert(allocation_calls == 2U && release_calls == 1U);
    assert(first == NULL && second == NULL && third == NULL);

    reset_counters();
    first = (void *)(uintptr_t)1U;
    assert(!janos_psram_allocate_all(requests, 3U, tracked_aligned_calloc,
                                     tracked_free, EXPECTED_CAPS));
    assert(allocation_calls == 0U && release_calls == 0U);
    first = NULL;

    reset_counters();
    requests[1].size = 0U;
    assert(!janos_psram_allocate_all(requests, 3U, tracked_aligned_calloc,
                                     tracked_free, EXPECTED_CAPS));
    assert(allocation_calls == 0U && release_calls == 0U);

    requests[1].size = 33U;
    requests[1].alignment = 3U;
    assert(!janos_psram_allocate_all(requests, 3U, tracked_aligned_calloc,
                                     tracked_free, EXPECTED_CAPS));
    assert(allocation_calls == 0U && release_calls == 0U);

    puts("PASS: transactional PSRAM storage");
    return 0;
}
