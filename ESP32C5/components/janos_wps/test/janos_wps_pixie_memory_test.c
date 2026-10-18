/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_memory.h"
#include "pixie.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint32_t seen_caps;
    size_t seen_payload;
    unsigned allocs;
    unsigned frees;
    bool fail;
    bool scrubbed;
} probe_t;

static void *probe_alloc(void *context, size_t size, uint32_t caps)
{
    probe_t *probe = context;
    ++probe->allocs;
    probe->seen_caps = caps;
    probe->seen_payload = size;
    return probe->fail ? NULL : malloc(size);
}

static void probe_free(void *context, void *memory, size_t size,
                       janos_wps_memory_class_t memory_class)
{
    probe_t *probe = context;
    assert(memory_class == JANOS_WPS_MEMORY_BULK);
    assert(size >= 160000U);
    const uint8_t *payload = (const uint8_t *)memory + size - 160000U;
    probe->scrubbed = true;
    for (size_t index = 0; index < 160000U; ++index)
        if (payload[index] != 0U) probe->scrubbed = false;
    ++probe->frees;
    free(memory);
}

static void *pixie_alloc(void *context, size_t size)
{
    assert(size == 160000U);
    return janos_wps_alloc_bulk(context, size);
}

static void pixie_free(void *context, void *memory, size_t size)
{
    assert(size == 160000U);
    janos_wps_free_bulk(context, memory);
}

static bool cancel_now(void *context)
{
    (void)context;
    return true;
}

int main(void)
{
    probe_t probe = {0};
    const janos_wps_memory_ops_t memory_ops = {probe_alloc, probe_free};
    janos_wps_memory_t memory;
    janos_wps_memory_init(&memory, &memory_ops, &probe);

    pixie_bundle_t bundle = {0};
    memset(bundle.authkey, 0x11, sizeof(bundle.authkey));
    memset(bundle.pke, 0x22, sizeof(bundle.pke));
    memset(bundle.pkr, 0x33, sizeof(bundle.pkr));
    static const uint8_t hash1[32] = {
        0xb3,0x1d,0xec,0x12,0x52,0x90,0xad,0x93,0x3c,0x08,0x43,0x3e,0xe5,0x44,0x8b,0x6b,
        0x7e,0x9c,0x80,0xbc,0x15,0x74,0x57,0x66,0x7b,0xbc,0xb6,0xf3,0xb3,0x83,0xb8,0xdf};
    static const uint8_t hash2[32] = {
        0x00,0x29,0x88,0x84,0x38,0x66,0x48,0x99,0xe3,0x47,0x00,0x60,0xc5,0x35,0x62,0xe9,
        0x32,0x43,0xdd,0xdd,0xd4,0x11,0x3b,0xca,0x02,0x7f,0x5e,0xb9,0x7c,0xbf,0xbf,0xfe};
    memcpy(bundle.e_hash1, hash1, sizeof(hash1));
    memcpy(bundle.e_hash2, hash2, sizeof(hash2));

    pixie_options_t options = {
        .modes = PIXIE_MODE_NULL_SECRET,
        .cache_alloc = pixie_alloc,
        .cache_free = pixie_free,
        .cache_context = &memory,
    };
    pixie_result_t result;
    assert(pixie_recover(&bundle, &options, &result));
    assert(result.found);
    assert(probe.allocs == 1U && probe.frees == 1U && probe.scrubbed);
    assert(probe.seen_caps == (JANOS_WPS_CAP_SPIRAM | JANOS_WPS_CAP_8BIT));
    janos_wps_memory_snapshot_t snapshot = janos_wps_memory_snapshot(&memory);
    assert(snapshot.bulk_bytes == 0U);
    assert(snapshot.bulk_peak_bytes == 160000U);
    assert(snapshot.failed_allocations == 0U);

    probe.scrubbed = false;
    options.should_cancel = cancel_now;
    assert(pixie_recover(&bundle, &options, &result));
    assert(result.cancelled && !result.found);
    assert(probe.allocs == 2U && probe.frees == 2U && probe.scrubbed);
    snapshot = janos_wps_memory_snapshot(&memory);
    assert(snapshot.bulk_bytes == 0U);

    probe.fail = true;
    options.should_cancel = NULL;
    assert(!pixie_recover(&bundle, &options, &result));
    snapshot = janos_wps_memory_snapshot(&memory);
    assert(snapshot.bulk_bytes == 0U);
    assert(snapshot.failed_allocations == 1U);
    assert(probe.frees == 2U);
    puts("PASS: JanOS tracked Pixie cache");
    return 0;
}
