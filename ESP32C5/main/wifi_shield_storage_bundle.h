#ifndef WIFI_SHIELD_STORAGE_BUNDLE_H
#define WIFI_SHIELD_STORAGE_BUNDLE_H

#include "janos_psram_storage.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    void *state;
    void *event_ring;
    void *output_queue;
    void *publisher_stack;
    void *journal_queue;
    void *journal_stack;
    void *journal_platform;
} wifi_shield_storage_destinations_t;

typedef struct {
    size_t state_bytes;
    size_t event_capacity;
    size_t event_size;
    size_t output_records;
    size_t output_record_size;
    size_t publisher_stack_bytes;
    size_t journal_records;
    size_t journal_record_size;
    size_t journal_stack_bytes;
    size_t journal_platform_bytes;
    size_t alignment;
    uint32_t spiram_capability;
    uint32_t byte_capability;
} wifi_shield_storage_layout_t;

typedef enum {
    WIFI_SHIELD_STORAGE_QUEUE_OUTPUT = 0,
    WIFI_SHIELD_STORAGE_QUEUE_JOURNAL
} wifi_shield_storage_queue_role_t;

typedef bool (*wifi_shield_storage_queue_create_fn)(
    void *context, wifi_shield_storage_queue_role_t role,
    void *buffer, size_t records, size_t record_size);

bool wifi_shield_storage_bundle_acquire(
    const wifi_shield_storage_destinations_t *destinations,
    const wifi_shield_storage_layout_t *layout,
    janos_psram_aligned_calloc_fn allocate,
    janos_psram_free_fn release,
    wifi_shield_storage_queue_create_fn queue_create,
    void *queue_context);

void wifi_shield_storage_bundle_release(
    const wifi_shield_storage_destinations_t *destinations,
    const wifi_shield_storage_layout_t *layout,
    janos_psram_free_fn release);

#endif
