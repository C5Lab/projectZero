/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_memory.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t last_caps;
    unsigned allocs;
    unsigned frees;
    bool fail;
    bool secret_wiped;
} fake_heap_t;

static void *fake_alloc(void *opaque, size_t size, uint32_t caps)
{
    fake_heap_t *heap = opaque;
    heap->last_caps = caps;
    heap->allocs++;
    return heap->fail ? NULL : malloc(size);
}

static void fake_free(void *opaque, void *memory, size_t size,
                      janos_wps_memory_class_t memory_class)
{
    fake_heap_t *heap = opaque;
    const uint8_t *bytes = memory;
    heap->frees++;
    if (memory_class == JANOS_WPS_MEMORY_SECRET) {
        heap->secret_wiped = true;
        for (size_t i = 0; i < size; ++i) {
            if (bytes[i] != 0U) heap->secret_wiped = false;
        }
    }
    free(memory);
}

int main(void)
{
    fake_heap_t heap = {0};
    janos_wps_memory_t memory;
    const janos_wps_memory_ops_t ops = {fake_alloc, fake_free};
    janos_wps_memory_init(&memory, &ops, &heap);

    assert(janos_wps_alloc_bulk(&memory, 0) == NULL);
    assert(janos_wps_alloc_secret(&memory, SIZE_MAX) == NULL);

    void *bulk = janos_wps_alloc_bulk(&memory, 128);
    assert(bulk != NULL);
    assert(heap.last_caps == (JANOS_WPS_CAP_SPIRAM | JANOS_WPS_CAP_8BIT));

    uint8_t *secret = janos_wps_alloc_secret(&memory, 32);
    assert(secret != NULL);
    assert(heap.last_caps == (JANOS_WPS_CAP_INTERNAL | JANOS_WPS_CAP_8BIT));
    memset(secret, 0xa5, 32);

    janos_wps_memory_snapshot_t snapshot = janos_wps_memory_snapshot(&memory);
    assert(snapshot.bulk_bytes == 128 && snapshot.bulk_peak_bytes == 128);
    assert(snapshot.secret_bytes == 32 && snapshot.secret_peak_bytes == 32);
    assert(snapshot.failed_allocations == 0);

    janos_wps_free_secret(&memory, secret);
    assert(heap.secret_wiped);
    janos_wps_free_bulk(&memory, bulk);
    snapshot = janos_wps_memory_snapshot(&memory);
    assert(snapshot.bulk_bytes == 0 && snapshot.secret_bytes == 0);

    heap.fail = true;
    assert(janos_wps_alloc_bulk(&memory, 64) == NULL);
    snapshot = janos_wps_memory_snapshot(&memory);
    assert(snapshot.failed_allocations == 1);
    assert(heap.allocs == 3 && heap.frees == 2);

    puts("PASS: JanOS WPS memory policy");
    return 0;
}
