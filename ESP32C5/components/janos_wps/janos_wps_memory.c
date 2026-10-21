/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_memory.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef ESP_PLATFORM
#include "esp_heap_caps.h"
#endif

#define JANOS_WPS_ALLOCATION_MAGIC UINT32_C(0x5750534d)

typedef union {
    max_align_t alignment;
    struct {
        uint32_t magic;
        uint32_t memory_class;
        size_t payload_size;
        size_t allocation_size;
    } value;
} allocation_header_t;

void janos_wps_secure_wipe(void *memory, size_t size)
{
    volatile uint8_t *bytes = (volatile uint8_t *)memory;
    if (!bytes) return;
    while (size-- != 0U) *bytes++ = 0U;
}

void janos_wps_memory_init(janos_wps_memory_t *memory,
                           const janos_wps_memory_ops_t *ops,
                           void *ops_context)
{
    if (!memory) return;
    memset(memory, 0, sizeof(*memory));
    memory->ops = ops;
    memory->ops_context = ops_context;
    atomic_init(&memory->counters.bulk_bytes, 0U);
    atomic_init(&memory->counters.bulk_peak_bytes, 0U);
    atomic_init(&memory->counters.secret_bytes, 0U);
    atomic_init(&memory->counters.secret_peak_bytes, 0U);
    atomic_init(&memory->counters.failed_allocations, 0U);
}

#ifdef ESP_PLATFORM
static void *esp_allocate(void *context, size_t size, uint32_t caps)
{
    (void)context;
    uint32_t heap_caps = MALLOC_CAP_8BIT;
    if ((caps & JANOS_WPS_CAP_SPIRAM) != 0U) heap_caps |= MALLOC_CAP_SPIRAM;
    if ((caps & JANOS_WPS_CAP_INTERNAL) != 0U) heap_caps |= MALLOC_CAP_INTERNAL;
    return heap_caps_malloc(size, heap_caps);
}

static void esp_release(void *context, void *memory, size_t size,
                        janos_wps_memory_class_t memory_class)
{
    (void)context;
    (void)size;
    (void)memory_class;
    heap_caps_free(memory);
}

static const janos_wps_memory_ops_t esp_ops = {esp_allocate, esp_release};
#endif

void janos_wps_memory_init_esp(janos_wps_memory_t *memory)
{
#ifdef ESP_PLATFORM
    janos_wps_memory_init(memory, &esp_ops, NULL);
#else
    janos_wps_memory_init(memory, NULL, NULL);
#endif
}

static void *allocate(janos_wps_memory_t *memory, size_t size,
                      janos_wps_memory_class_t memory_class, uint32_t caps)
{
    if (!memory || !memory->ops || !memory->ops->alloc ||
        !memory->ops->free || size == 0U ||
        size > SIZE_MAX - sizeof(allocation_header_t)) {
        return NULL;
    }
    const size_t total = sizeof(allocation_header_t) + size;
    allocation_header_t *header = memory->ops->alloc(
        memory->ops_context, total, caps);
    if (!header) {
        (void)atomic_fetch_add_explicit(&memory->counters.failed_allocations,
                                        1U, memory_order_relaxed);
        return NULL;
    }
    header->value.magic = JANOS_WPS_ALLOCATION_MAGIC;
    header->value.memory_class = (uint32_t)memory_class;
    header->value.payload_size = size;
    header->value.allocation_size = total;
    atomic_size_t *current_counter = memory_class == JANOS_WPS_MEMORY_BULK
        ? &memory->counters.bulk_bytes : &memory->counters.secret_bytes;
    atomic_size_t *peak_counter = memory_class == JANOS_WPS_MEMORY_BULK
        ? &memory->counters.bulk_peak_bytes : &memory->counters.secret_peak_bytes;
    size_t current = atomic_fetch_add_explicit(current_counter, size,
                                                memory_order_relaxed) + size;
    size_t peak = atomic_load_explicit(peak_counter, memory_order_relaxed);
    while (peak < current && !atomic_compare_exchange_weak_explicit(
               peak_counter, &peak, current, memory_order_relaxed,
               memory_order_relaxed)) {}
    return header + 1;
}

static void release(janos_wps_memory_t *memory, void *pointer,
                    janos_wps_memory_class_t expected_class)
{
    if (!memory || !pointer || !memory->ops || !memory->ops->free) return;
    allocation_header_t *header = ((allocation_header_t *)pointer) - 1;
    if (header->value.magic != JANOS_WPS_ALLOCATION_MAGIC ||
        header->value.memory_class != (uint32_t)expected_class) return;
    const size_t payload_size = header->value.payload_size;
    const size_t allocation_size = header->value.allocation_size;
    header->value.magic = 0U;
    if (expected_class == JANOS_WPS_MEMORY_SECRET) {
        (void)atomic_fetch_sub_explicit(&memory->counters.secret_bytes,
                                        payload_size, memory_order_relaxed);
        janos_wps_secure_wipe(header, allocation_size);
    } else {
        (void)atomic_fetch_sub_explicit(&memory->counters.bulk_bytes,
                                        payload_size, memory_order_relaxed);
    }
    memory->ops->free(memory->ops_context, header, allocation_size,
                      expected_class);
}

void *janos_wps_alloc_bulk(janos_wps_memory_t *memory, size_t size)
{
    return allocate(memory, size, JANOS_WPS_MEMORY_BULK,
                    JANOS_WPS_CAP_SPIRAM | JANOS_WPS_CAP_8BIT);
}

void janos_wps_free_bulk(janos_wps_memory_t *memory, void *pointer)
{
    release(memory, pointer, JANOS_WPS_MEMORY_BULK);
}

void *janos_wps_alloc_secret(janos_wps_memory_t *memory, size_t size)
{
    return allocate(memory, size, JANOS_WPS_MEMORY_SECRET,
                    JANOS_WPS_CAP_INTERNAL | JANOS_WPS_CAP_8BIT);
}

void janos_wps_free_secret(janos_wps_memory_t *memory, void *pointer)
{
    release(memory, pointer, JANOS_WPS_MEMORY_SECRET);
}

janos_wps_memory_snapshot_t janos_wps_memory_snapshot(
    const janos_wps_memory_t *memory)
{
    if (!memory) return (janos_wps_memory_snapshot_t){0};
    return (janos_wps_memory_snapshot_t){
        .bulk_bytes = atomic_load_explicit(&memory->counters.bulk_bytes,
                                           memory_order_relaxed),
        .bulk_peak_bytes = atomic_load_explicit(
            &memory->counters.bulk_peak_bytes, memory_order_relaxed),
        .secret_bytes = atomic_load_explicit(&memory->counters.secret_bytes,
                                             memory_order_relaxed),
        .secret_peak_bytes = atomic_load_explicit(
            &memory->counters.secret_peak_bytes, memory_order_relaxed),
        .failed_allocations = atomic_load_explicit(
            &memory->counters.failed_allocations, memory_order_relaxed),
    };
}

