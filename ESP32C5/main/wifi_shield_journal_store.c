#include "wifi_shield_journal_store.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static void increment(uint32_t *counter)
{
    if (*counter != UINT32_MAX) ++*counter;
}

static void add_bytes(uint64_t *counter, size_t amount)
{
    uint64_t n = (uint64_t)amount;
    *counter = n > UINT64_MAX - *counter ? UINT64_MAX : *counter + n;
}

static void failure(wifi_shield_journal_store_t *s,
                    wifi_shield_journal_state_t state,
                    uint32_t *domain)
{
    increment(&s->status.failures);
    if (domain != NULL) increment(domain);
    if (s->status.state != WIFI_SHIELD_JOURNAL_DEGRADED &&
        state == WIFI_SHIELD_JOURNAL_DEGRADED)
        s->status.degraded_notice_pending = true;
    s->status.state = state;
}

static bool hooks_valid(const wifi_shield_journal_store_hooks_t *h)
{
    return h && h->mount && h->mkdir && h->open_exclusive && h->write &&
        h->flush && h->fsync_file && h->close && h->sync_sd && h->rename_no_replace;
}

static bool checkpoint(wifi_shield_journal_store_t *store)
{
    bool durable = store->hooks.flush(store->hooks.context, store->handle);
    if (durable)
        durable = store->hooks.fsync_file(store->hooks.context,
                                          store->handle);
    if (durable) durable = store->hooks.sync_sd(store->hooks.context);
    if (durable) store->records_since_checkpoint = 0U;
    return durable;
}

bool wifi_shield_journal_store_start(wifi_shield_journal_store_t *store,
    const wifi_shield_journal_store_hooks_t *hooks, uint32_t boot_id,
    uint32_t session_id, uint64_t quota_bytes)
{
    if (!store || store->attempted || store->finished) return false;
    store->attempted = true;
    store->status.state = WIFI_SHIELD_JOURNAL_UNAVAILABLE;
    store->status.time_sources = WIFI_SHIELD_JOURNAL_TIME_MONOTONIC;
    if (!hooks_valid(hooks) || !boot_id || !session_id || !quota_bytes) {
        failure(store, WIFI_SHIELD_JOURNAL_UNAVAILABLE,
                &store->status.write_failures);
        return false;
    }
    store->hooks = *hooks;
    store->quota_bytes = quota_bytes;
    int n = snprintf(store->final_path, sizeof(store->final_path),
        "/sdcard/lab/shield/shield-b%08" PRIx32 "-s%" PRIu32 ".jsonl",
        boot_id, session_id);
    if (n < 0 || (size_t)n >= sizeof(store->final_path)) {
        failure(store, WIFI_SHIELD_JOURNAL_UNAVAILABLE,
                &store->status.write_failures);
        return false;
    }
    n = snprintf(store->status.path, sizeof(store->status.path), "%s.part", store->final_path);
    if (n < 0 || (size_t)n >= sizeof(store->status.path)) {
        store->status.path[0] = '\0';
        failure(store, WIFI_SHIELD_JOURNAL_UNAVAILABLE,
                &store->status.write_failures);
        return false;
    }
    if (!hooks->mount(hooks->context)) {
        failure(store, WIFI_SHIELD_JOURNAL_UNAVAILABLE,
                &store->status.write_failures);
        return false;
    }
    if (!hooks->mkdir(hooks->context, "/sdcard/lab/shield")) {
        failure(store, WIFI_SHIELD_JOURNAL_DEGRADED,
                &store->status.write_failures);
        return false;
    }
    store->handle = hooks->open_exclusive(hooks->context, store->status.path);
    if (!store->handle) {
        failure(store, WIFI_SHIELD_JOURNAL_DEGRADED,
                &store->status.write_failures);
        return false;
    }
    store->status.state = WIFI_SHIELD_JOURNAL_ACTIVE;
    return true;
}

bool wifi_shield_journal_store_append(wifi_shield_journal_store_t *store,
    wifi_shield_journal_type_t type, const char *line, size_t length)
{
    if (!store) return false;
    if (!store->attempted || store->finished ||
        store->status.state != WIFI_SHIELD_JOURNAL_ACTIVE) {
        increment(&store->status.dropped);
        increment(&store->status.admission_drops);
        return false;
    }
    /* The encoder owns JSON/schema validation; retain strict record framing and
     * lifecycle checks here so malformed input cannot create a clean journal. */
    bool valid = line && length > 1 && length < WIFI_SHIELD_JOURNAL_LINE_MAX &&
        type >= WIFI_SHIELD_JOURNAL_SESSION_START &&
        type <= WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN &&
        !store->terminal_written &&
        (store->start_written ? type != WIFI_SHIELD_JOURNAL_SESSION_START :
                               type == WIFI_SHIELD_JOURNAL_SESSION_START);
    if (valid)
        valid = line[length - 1] == '\n' && !memchr(line, '\0', length) &&
            !memchr(line, '\n', length - 1) && !memchr(line, '\r', length);
    if (!valid) {
        increment(&store->status.dropped);
        increment(&store->status.admission_drops);
        failure(store, WIFI_SHIELD_JOURNAL_DEGRADED,
                &store->status.write_failures);
        return false;
    }
    if (store->status.bytes_written > store->quota_bytes ||
        (uint64_t)length > store->quota_bytes - store->status.bytes_written) {
        increment(&store->status.dropped);
        increment(&store->status.admission_drops);
        store->status.state = WIFI_SHIELD_JOURNAL_QUOTA_REACHED;
        return false;
    }
    size_t written = store->hooks.write(store->hooks.context, store->handle, line, length);
    /* A broken hook cannot manufacture an impossible byte count. */
    if (written <= length) add_bytes(&store->status.bytes_written, written);
    if (written != length) {
        increment(&store->status.dropped);
        failure(store, WIFI_SHIELD_JOURNAL_DEGRADED,
                &store->status.write_failures);
        return false;
    }
    increment(&store->status.records_written);
    increment(&store->records_since_checkpoint);
    if (type == WIFI_SHIELD_JOURNAL_SESSION_START) store->start_written = true;
    if (type == WIFI_SHIELD_JOURNAL_SESSION_TERMINAL) store->terminal_written = true;
    if (type == WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN ||
        type == WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION ||
        store->records_since_checkpoint >=
            WIFI_SHIELD_JOURNAL_CHECKPOINT_RECORDS) {
        /* Stop may return with radio ownership quarantined and retry later. Make
         * that provisional outcome durable now, but keep the .part handle open
         * so the same session can append its eventual recovery terminal.
         * Threat transitions and bounded batches use the same checkpoint. */
        if (!checkpoint(store)) {
            increment(&store->status.dropped);
            failure(store, WIFI_SHIELD_JOURNAL_DEGRADED,
                    &store->status.sync_failures);
            return false;
        }
    }
    return true;
}

void wifi_shield_journal_store_finish(wifi_shield_journal_store_t *store, bool clean)
{
    if (!store || store->finished) return;
    store->finished = true;
    if (!store->handle) return;
    bool complete = clean && store->start_written && store->terminal_written &&
        store->status.state == WIFI_SHIELD_JOURNAL_ACTIVE;
    wifi_shield_journal_store_hooks_t *h = &store->hooks;
    bool flushed = h->flush(h->context, store->handle);
    if (!flushed) failure(store, WIFI_SHIELD_JOURNAL_DEGRADED,
                          &store->status.finalization_failures);
    if (flushed && !h->fsync_file(h->context, store->handle))
        failure(store, WIFI_SHIELD_JOURNAL_DEGRADED,
                &store->status.finalization_failures);
    if (!h->close(h->context, store->handle))
        failure(store, WIFI_SHIELD_JOURNAL_DEGRADED,
                &store->status.finalization_failures);
    store->handle = NULL;
    if (!h->sync_sd(h->context))
        failure(store, WIFI_SHIELD_JOURNAL_DEGRADED,
                &store->status.finalization_failures);
    if (store->status.state == WIFI_SHIELD_JOURNAL_DEGRADED) return;
    if (!complete) {
        if (store->status.state == WIFI_SHIELD_JOURNAL_ACTIVE)
            store->status.state = WIFI_SHIELD_JOURNAL_INCOMPLETE;
        return;
    }
    if (!h->rename_no_replace(h->context, store->status.path, store->final_path)) {
        failure(store, WIFI_SHIELD_JOURNAL_DEGRADED,
                &store->status.finalization_failures);
        return;
    }
    memcpy(store->status.path, store->final_path, strlen(store->final_path) + 1);
    if (!h->sync_sd(h->context)) {
        failure(store, WIFI_SHIELD_JOURNAL_DEGRADED,
                &store->status.finalization_failures);
        return;
    }
    store->status.state = WIFI_SHIELD_JOURNAL_FINALIZED;
}

wifi_shield_journal_status_t wifi_shield_journal_store_status(
    const wifi_shield_journal_store_t *store)
{
    if (store) return store->status;
    wifi_shield_journal_status_t status = {0};
    return status;
}
