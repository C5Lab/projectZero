#include "wifi_shield_storage_bundle.h"

#include <stdint.h>
#include <string.h>

static bool valid_layout(const wifi_shield_storage_layout_t *layout)
{
    return layout != NULL && layout->state_bytes != 0U &&
        layout->event_capacity != 0U && layout->event_size != 0U &&
        layout->event_capacity <= SIZE_MAX / layout->event_size &&
        layout->output_records != 0U && layout->output_record_size != 0U &&
        layout->output_records <= SIZE_MAX / layout->output_record_size &&
        layout->publisher_stack_bytes != 0U && layout->alignment != 0U &&
        layout->journal_records != 0U && layout->journal_record_size != 0U &&
        layout->journal_records <= SIZE_MAX / layout->journal_record_size &&
        layout->journal_stack_bytes != 0U &&
        layout->journal_platform_bytes != 0U &&
        layout->spiram_capability != 0U && layout->byte_capability != 0U;
}

static bool make_requests(
    const wifi_shield_storage_destinations_t *destinations,
    const wifi_shield_storage_layout_t *layout,
    janos_psram_request_t requests[7])
{
    if (destinations == NULL || !valid_layout(layout) ||
        destinations->state == NULL || destinations->event_ring == NULL ||
        destinations->output_queue == NULL ||
        destinations->publisher_stack == NULL ||
        destinations->journal_queue == NULL || destinations->journal_stack == NULL) return false;
    if (destinations->journal_platform == NULL) return false;
    requests[0] = (janos_psram_request_t){
        .destination = destinations->state,
        .size = layout->state_bytes,
        .alignment = layout->alignment,
    };
    requests[1] = (janos_psram_request_t){
        .destination = destinations->event_ring,
        .size = layout->event_capacity * layout->event_size,
        .alignment = layout->alignment,
    };
    requests[2] = (janos_psram_request_t){
        .destination = destinations->output_queue,
        .size = layout->output_records * layout->output_record_size,
        .alignment = layout->alignment,
    };
    requests[3] = (janos_psram_request_t){
        .destination = destinations->publisher_stack,
        .size = layout->publisher_stack_bytes,
        .alignment = layout->alignment,
    };
    requests[4] = (janos_psram_request_t){
        .destination = destinations->journal_queue,
        .size = layout->journal_records * layout->journal_record_size,
        .alignment = layout->alignment,
    };
    requests[5] = (janos_psram_request_t){
        .destination = destinations->journal_stack,
        .size = layout->journal_stack_bytes,
        .alignment = layout->alignment,
    };
    requests[6] = (janos_psram_request_t){
        .destination = destinations->journal_platform,
        .size = layout->journal_platform_bytes,
        .alignment = layout->alignment,
    };
    return true;
}

bool wifi_shield_storage_bundle_acquire(
    const wifi_shield_storage_destinations_t *destinations,
    const wifi_shield_storage_layout_t *layout,
    janos_psram_aligned_calloc_fn allocate,
    janos_psram_free_fn release,
    wifi_shield_storage_queue_create_fn queue_create,
    void *queue_context)
{
    janos_psram_request_t requests[7];
    if (allocate == NULL || release == NULL || queue_create == NULL ||
        !make_requests(destinations, layout, requests)) return false;
    if (!janos_psram_allocate_all(
            requests, 7U, allocate, release,
            layout->spiram_capability | layout->byte_capability)) return false;
    void *queue_buffer = NULL;
    memcpy(&queue_buffer, destinations->output_queue, sizeof(queue_buffer));
    if (queue_create(queue_context, WIFI_SHIELD_STORAGE_QUEUE_OUTPUT, queue_buffer,
                     layout->output_records, layout->output_record_size)) {
        memcpy(&queue_buffer, destinations->journal_queue, sizeof(queue_buffer));
        if (queue_create(queue_context, WIFI_SHIELD_STORAGE_QUEUE_JOURNAL,
                         queue_buffer, layout->journal_records,
                         layout->journal_record_size)) return true;
    }
    janos_psram_release_all(requests, 7U, release);
    return false;
}

void wifi_shield_storage_bundle_release(
    const wifi_shield_storage_destinations_t *destinations,
    const wifi_shield_storage_layout_t *layout,
    janos_psram_free_fn release)
{
    janos_psram_request_t requests[7];
    if (release == NULL || !make_requests(destinations, layout, requests))
        return;
    janos_psram_release_all(requests, 7U, release);
}
