#include "wifi_shield_journal_platform.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void increment(uint32_t *n) { if (*n != UINT32_MAX) ++*n; }
static void add_saturating(uint32_t *n, uint32_t value)
{
    *n = value > UINT32_MAX - *n ? UINT32_MAX : *n + value;
}
static uint32_t observation_count(const wifi_shield_journal_record_t *record)
{
    return record->type == WIFI_SHIELD_JOURNAL_EVENT &&
           record->event_count != 0U ? record->event_count : 1U;
}
static void lock(wifi_shield_journal_platform_t *p) { p->hooks.lock(p->hooks.context); }
static void unlock(wifi_shield_journal_platform_t *p) { p->hooks.unlock(p->hooks.context); }
static void publish(wifi_shield_journal_platform_t *p)
{
    wifi_shield_journal_status_t s = wifi_shield_journal_store_status(&p->store);
    lock(p);
    if (p->notice_acknowledged) s.degraded_notice_pending = false;
    p->snapshot = s;
    if (s.state != WIFI_SHIELD_JOURNAL_ACTIVE) p->admission = false;
    unlock(p);
}

static void sidecar_failure(wifi_shield_journal_platform_t *p, bool latest)
{
    lock(p);
    increment(latest ? &p->latest_failures : &p->summary_failures);
    unlock(p);
}

static bool write_sidecar(wifi_shield_journal_platform_t *p,
    const char *part_path, const char *final_path, const char *bytes,
    size_t length, bool replace)
{
    void *handle = replace ?
        p->store_hooks.open_replace(p->store_hooks.context, part_path) :
        p->store_hooks.open_exclusive(p->store_hooks.context, part_path);
    if (handle == NULL) return false;
    bool ok = p->store_hooks.write(p->store_hooks.context, handle, bytes,
                                  length) == length;
    if (ok) ok = p->store_hooks.flush(p->store_hooks.context, handle);
    if (ok) ok = p->store_hooks.fsync_file(p->store_hooks.context, handle);
    bool closed = p->store_hooks.close(p->store_hooks.context, handle);
    if (!closed) ok = false;
    if (ok) ok = p->store_hooks.sync_sd(p->store_hooks.context);
    if (ok) ok = replace ?
        p->store_hooks.rename_replace(p->store_hooks.context, part_path,
                                      final_path) :
        p->store_hooks.rename_no_replace(p->store_hooks.context, part_path,
                                         final_path);
    if (ok) ok = p->store_hooks.sync_sd(p->store_hooks.context);
    return ok;
}

static void publish_summary_sidecars(wifi_shield_journal_platform_t *p)
{
    if (!p->summary_enabled || p->store_hooks.open_replace == NULL ||
        p->store_hooks.rename_replace == NULL) {
        if (p->summary_enabled) sidecar_failure(p, false);
        return;
    }
    wifi_shield_journal_status_t status = wifi_shield_journal_platform_status(p);
    if (status.state != WIFI_SHIELD_JOURNAL_FINALIZED) return;
    char summary_path[WIFI_SHIELD_JOURNAL_PATH_MAX];
    char summary_part[WIFI_SHIELD_JOURNAL_PATH_MAX];
    int path_length = snprintf(summary_path, sizeof(summary_path),
        "/sdcard/lab/shield/shield-b%08" PRIx32 "-s%" PRIu32
        "-summary.txt", p->boot_id, p->session_id);
    int part_length = path_length > 0 ? snprintf(summary_part,
        sizeof(summary_part), "%s.part", summary_path) : -1;
    int summary_length = path_length > 0 && part_length > 0 ?
        wifi_shield_summary_format(p->summary_text,
            sizeof(p->summary_text), &p->summary, &status,
            p->store.final_path) : -1;
    if (path_length <= 0 || (size_t)path_length >= sizeof(summary_path) ||
        part_length <= 0 || (size_t)part_length >= sizeof(summary_part) ||
        summary_length <= 0 || !write_sidecar(p, summary_part, summary_path,
            p->summary_text, (size_t)summary_length, false)) {
        sidecar_failure(p, false);
        memset(p->summary_text, 0, sizeof(p->summary_text));
        return;
    }
    const char latest_part[] = "/sdcard/lab/shield/00-LATEST.txt.part";
    const char latest_path[] = "/sdcard/lab/shield/00-LATEST.txt";
    int latest_length = snprintf(p->summary_text, sizeof(p->summary_text),
        "JanOS Wi-Fi Shield - Latest Session\n"
        "Session: b%08" PRIx32 "-s%" PRIu32 "\n"
        "Summary: %s\nJSONL: %s\n",
        p->boot_id, p->session_id, summary_path, p->store.final_path);
    if (latest_length <= 0 ||
        (size_t)latest_length >= sizeof(p->summary_text) ||
        !write_sidecar(p, latest_part, latest_path, p->summary_text,
                       (size_t)latest_length, true))
        sidecar_failure(p, true);
    memset(p->summary_text, 0, sizeof(p->summary_text));
}

bool wifi_shield_journal_platform_writer_poll(wifi_shield_journal_platform_t *p)
{
    if (!p || !p->initialized || p->writer_finished) return false;
    if (!p->writer_started) {
        p->writer_started = true;
        (void)wifi_shield_journal_store_start(&p->store, &p->store_hooks,
            p->boot_id, p->session_id, p->quota_bytes);
        publish(p);
    }
    wifi_shield_journal_record_t record;
    if (p->hooks.queue_receive(p->hooks.context, &record)) {
        char line[WIFI_SHIELD_JOURNAL_LINE_MAX];
        int length = wifi_shield_journal_encode(line, sizeof(line), &record);
        if (length > 0) {
            bool stored = wifi_shield_journal_store_append(
                &p->store, record.type, line, (size_t)length);
            if (stored && p->summary_enabled)
                wifi_shield_summary_observe(&p->summary, &record);
            else if (!stored) {
                uint32_t represented = observation_count(&record);
                if (represented > 1U) {
                    lock(p);
                    add_saturating(&p->dropped, represented - 1U);
                    unlock(p);
                }
            }
        } else {
            lock(p);
            increment(&p->encoding_failures);
            add_saturating(&p->dropped, observation_count(&record));
            unlock(p);
        }
        memset(&record, 0, sizeof(record));
        memset(line, 0, sizeof(line));
        publish(p);
        lock(p);
        if (p->pending) --p->pending;
        unlock(p);
    }
    lock(p);
    bool finish = p->stop && p->pending == 0U;
    bool clean = p->clean;
    unlock(p);
    if (!finish) return true;
    wifi_shield_journal_store_finish(&p->store, clean);
    publish(p);
    if (clean) publish_summary_sidecars(p);
    p->writer_finished = true;
    return false;
}

static void writer_entry(void *argument)
{
    wifi_shield_journal_platform_t *p = argument;
    while (wifi_shield_journal_platform_writer_poll(p))
        p->hooks.task_wait(p->hooks.context);
}

bool wifi_shield_journal_platform_start(wifi_shield_journal_platform_t *p,
    const wifi_shield_journal_platform_hooks_t *h,
    const wifi_shield_journal_store_hooks_t *s,
    const wifi_shield_summary_metadata_t *summary_metadata,
    uint32_t boot_id, uint32_t session_id, uint64_t quota_bytes,
    void *queue_buffer, size_t queue_records, void *writer_stack, size_t stack_bytes)
{
    if (!p || p->task_live || !h || !s || !h->lock || !h->unlock ||
        !h->queue_send || !h->queue_receive || !h->task_start || !h->task_wake ||
        !h->task_wait || !h->task_join || !boot_id || !session_id || !quota_bytes ||
        !queue_buffer || !queue_records || !writer_stack || !stack_bytes) return false;
    if (p->initialized && p->boot_id == boot_id && p->session_id == session_id)
        return false; /* One attempt for each accepted session identity. */
    memset(p, 0, sizeof(*p));
    p->hooks = *h;
    p->store_hooks = *s;
    p->boot_id = boot_id;
    p->session_id = session_id;
    p->quota_bytes = quota_bytes;
    p->next_sequence = 1U;
    p->time_sources = WIFI_SHIELD_JOURNAL_TIME_MONOTONIC;
    if (summary_metadata != NULL) {
        if (!wifi_shield_summary_init(&p->summary, summary_metadata,
                                      boot_id, session_id)) return false;
        p->summary_enabled = true;
    }
    p->initialized = p->admission = p->task_live = true;
    if (h->task_start(h->context, writer_entry, p, writer_stack, stack_bytes)) return true;
    p->task_live = p->admission = false;
    p->snapshot.failures = 1U;
    p->snapshot.write_failures = 1U;
    p->snapshot.time_sources = WIFI_SHIELD_JOURNAL_TIME_MONOTONIC;
    return false;
}

bool wifi_shield_journal_platform_submit(wifi_shield_journal_platform_t *p,
    const wifi_shield_journal_record_t *record)
{
    if (!p || !p->initialized || !record) return false;
    wifi_shield_journal_record_t copy = *record;
    uint64_t epoch = 0;
    uint32_t uncertainty = 0U;
    copy.gps_time_trusted = p->hooks.gps_epoch_ms &&
        p->hooks.gps_epoch_ms(p->hooks.context, &epoch, &uncertainty) &&
        epoch != 0U;
    copy.epoch_ms = copy.gps_time_trusted ? epoch : 0U;
    copy.time_uncertainty_ms = copy.gps_time_trusted ? uncertainty : 0U;
    lock(p);
    bool accepted = false;
    if (p->admission && p->next_sequence != 0U && p->pending != UINT32_MAX) {
        copy.boot_id = p->boot_id;
        copy.session_id = p->session_id;
        copy.sequence = p->next_sequence;
        accepted = p->hooks.queue_send(p->hooks.context, &copy);
        if (accepted) {
            ++p->next_sequence;
            ++p->pending;
            if (p->pending > p->queue_high_water)
                p->queue_high_water = p->pending;
            if (copy.time.quality != WIFI_SHIELD_TIME_NONE)
                p->time_sources |= WIFI_SHIELD_JOURNAL_TIME_AP_TSF;
            if (copy.gps_time_trusted)
                p->time_sources |= WIFI_SHIELD_JOURNAL_TIME_GPS;
        }
    }
    if (!accepted) {
        uint32_t represented = observation_count(&copy);
        add_saturating(&p->dropped, represented);
        add_saturating(&p->admission_drops, represented);
    }
    unlock(p);
    memset(&copy, 0, sizeof(copy));
    if (accepted) p->hooks.task_wake(p->hooks.context);
    return accepted;
}

wifi_shield_journal_status_t wifi_shield_journal_platform_status(wifi_shield_journal_platform_t *p)
{
    wifi_shield_journal_status_t s = {0};
    if (!p || !p->initialized) return s;
    lock(p);
    s = p->snapshot;
    s.dropped = p->dropped > UINT32_MAX - s.dropped ? UINT32_MAX : s.dropped + p->dropped;
    s.failures = p->encoding_failures > UINT32_MAX - s.failures ?
        UINT32_MAX : s.failures + p->encoding_failures;
    s.admission_drops = p->admission_drops >
        UINT32_MAX - s.admission_drops ? UINT32_MAX :
        s.admission_drops + p->admission_drops;
    s.encoding_failures = p->encoding_failures >
        UINT32_MAX - s.encoding_failures ? UINT32_MAX :
        s.encoding_failures + p->encoding_failures;
    s.summary_failures = p->summary_failures;
    s.latest_failures = p->latest_failures;
    uint32_t sidecar_failures = p->summary_failures >
        UINT32_MAX - p->latest_failures ? UINT32_MAX :
        p->summary_failures + p->latest_failures;
    s.failures = sidecar_failures > UINT32_MAX - s.failures ? UINT32_MAX :
        s.failures + sidecar_failures;
    s.queue_high_water = p->queue_high_water;
    s.time_sources |= p->time_sources;
    unlock(p);
    return s;
}
void wifi_shield_journal_platform_acknowledge_degraded(wifi_shield_journal_platform_t *p)
{
    if (!p || !p->initialized) return;
    lock(p);
    if (p->snapshot.degraded_notice_pending) {
        p->notice_acknowledged = true;
        p->snapshot.degraded_notice_pending = false;
    }
    unlock(p);
}
bool wifi_shield_journal_platform_drain(wifi_shield_journal_platform_t *p)
{
    if (!p || !p->initialized) return true;
    lock(p);
    bool drained = p->pending == 0U;
    unlock(p);
    return drained;
}
bool wifi_shield_journal_platform_finish(wifi_shield_journal_platform_t *p,
    bool clean, uint32_t timeout_ms)
{
    if (!p || !p->initialized || !p->task_live) return true;
    lock(p);
    p->admission = false;
    if (!p->stop) p->clean = clean;
    p->stop = true;
    unlock(p);
    p->hooks.task_wake(p->hooks.context);
    if (!p->hooks.task_join(p->hooks.context, timeout_ms)) return false;
    p->task_live = false;
    return true;
}
