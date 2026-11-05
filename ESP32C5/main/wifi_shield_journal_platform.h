#ifndef WIFI_SHIELD_JOURNAL_PLATFORM_H
#define WIFI_SHIELD_JOURNAL_PLATFORM_H

#include "wifi_shield_journal_store.h"
#include "wifi_shield_summary.h"

/* Queue hooks copy one fixed record with zero wait. lock/unlock are short,
 * nonblocking critical sections, never filesystem or task waits. task_start
 * must use only the supplied stack; false guarantees no task was created.
 * task_join true guarantees the task was deleted and cannot touch any memory.
 * task_wait is writer-only and bounded; wake may be a no-op with bounded polling.
 * GPS is sampled at submission and must return true only for a trusted wall
 * epoch plus its conservative uncertainty in milliseconds. */
typedef struct {
    void *context;
    void (*lock)(void *context);
    void (*unlock)(void *context);
    bool (*queue_send)(void *context, const wifi_shield_journal_record_t *record);
    bool (*queue_receive)(void *context, wifi_shield_journal_record_t *record);
    bool (*task_start)(void *context, void (*entry)(void *), void *argument,
                       void *stack, size_t stack_bytes);
    void (*task_wake)(void *context);
    void (*task_wait)(void *context);
    bool (*task_join)(void *context, uint32_t timeout_ms);
    bool (*gps_epoch_ms)(void *context, uint64_t *epoch_ms,
                         uint32_t *uncertainty_ms);
} wifi_shield_journal_platform_hooks_t;

/* Zero initialize before first use. Lifecycle start/finish calls are serialized
 * by the session owner. submit/status/ack/drain may run alongside the writer.
 * Reusing the same boot/session identity is rejected even after finish.
 * Queue storage and stack belong to the transactional PSRAM bundle. Retain
 * them, this object and hook contexts until finish returns true. No allocation.
 * Store and its handles are private to writer_poll/entry. */
typedef struct {
    wifi_shield_journal_platform_hooks_t hooks;
    wifi_shield_journal_store_hooks_t store_hooks;
    wifi_shield_journal_store_t store;
    wifi_shield_journal_status_t snapshot;
    wifi_shield_summary_t summary;
    char summary_text[WIFI_SHIELD_SUMMARY_TEXT_MAX];
    uint64_t quota_bytes, next_sequence;
    uint32_t boot_id, session_id, pending, dropped;
    uint32_t admission_drops, encoding_failures, queue_high_water, time_sources;
    uint32_t summary_failures, latest_failures;
    bool initialized, task_live, admission, stop, clean;
    bool writer_started, writer_finished, notice_acknowledged;
    bool summary_enabled;
} wifi_shield_journal_platform_t;

bool wifi_shield_journal_platform_start(wifi_shield_journal_platform_t *platform,
    const wifi_shield_journal_platform_hooks_t *hooks,
    const wifi_shield_journal_store_hooks_t *store_hooks,
    const wifi_shield_summary_metadata_t *summary_metadata,
    uint32_t boot_id, uint32_t session_id, uint64_t quota_bytes,
    void *queue_buffer, size_t queue_records, void *writer_stack,
    size_t writer_stack_bytes);
bool wifi_shield_journal_platform_submit(wifi_shield_journal_platform_t *platform,
    const wifi_shield_journal_record_t *record);
wifi_shield_journal_status_t wifi_shield_journal_platform_status(
    wifi_shield_journal_platform_t *platform);
void wifi_shield_journal_platform_acknowledge_degraded(
    wifi_shield_journal_platform_t *platform);
/* Poll only: true means every accepted record has been processed or accounted.
 * This is not a join and does not authorize releasing the bundle. */
bool wifi_shield_journal_platform_drain(wifi_shield_journal_platform_t *platform);
/* Closes admission, drains, finishes store, and joins. SD errors do not change
 * this result: false means task ownership remains and PSRAM MUST be retained.
 * Retry finish after a join timeout; the original clean request is retained. */
bool wifi_shield_journal_platform_finish(wifi_shield_journal_platform_t *platform,
    bool clean, uint32_t timeout_ms);
/* Writer context only; processes at most one queued record. False means store
 * cleanup completed. Exposed for deterministic scheduler tests and adapters. */
bool wifi_shield_journal_platform_writer_poll(wifi_shield_journal_platform_t *platform);
#endif
