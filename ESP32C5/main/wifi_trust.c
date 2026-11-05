#include "wifi_trust.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    wifi_trust_profile_t baseline[WIFI_TRUST_MAX_PROFILES];
    wifi_trust_table_t observed;
    wifi_shield_target_t targets[WIFI_TRUST_MAX_PROFILES];
    wifi_trust_event_t event_batch[WIFI_TRUST_REASON_COUNT];
    wifi_trust_profile_t previous_snapshot;
    wifi_trust_profile_t current_snapshot;
} wifi_trust_arena_t;

_Static_assert(sizeof(wifi_trust_arena_t) <= WIFI_TRUST_ARENA_MAX_BYTES,
               "Wi-Fi Trust arena exceeds the PSRAM budget");

typedef enum {
    END_NONE = 0,
    END_NATURAL,
    END_CANCELLED,
    END_ERROR,
} end_claim_t;

typedef struct {
    wifi_trust_runtime_hooks_t runtime;
    wifi_trust_storage_hooks_t storage;
    wifi_trust_output_hooks_t output;
    wifi_trust_arena_t *arena;
    wifi_trust_status_t status;
    wifi_trust_status_t last_status;
    wifi_trust_store_meta_t meta;
    size_t baseline_count;
    size_t target_count;
    uint32_t runtime_baseline_generation;
    uint32_t seconds;
    uint64_t next_epoch;
    uint64_t active_epoch;
    uintptr_t context_token;
    end_claim_t end_claim;
    bool initialized;
    bool starting;
    bool runtime_start_inflight;
    bool runtime_start_committed;
    bool running;
    bool stopping;
    bool filtered;
    bool deadline_armed;
    bool wiped;
    bool pending_publish;
    bool cleanup_in_progress;
    bool output_failed;
} wifi_trust_state_t;

static wifi_trust_state_t trust;
static uintptr_t next_context_token;

static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (bytes != NULL && size-- != 0U) *bytes++ = 0U;
}

static void increment(uint32_t *value)
{
    if (*value != UINT32_MAX) ++*value;
}

static uint32_t saturated_add(uint32_t left, uint32_t right)
{
    return UINT32_MAX - left < right ? UINT32_MAX : left + right;
}

static void enter(void)
{
    trust.runtime.enter(trust.runtime.context);
}

static void leave(void)
{
    trust.runtime.leave(trust.runtime.context);
}

static bool live_locked(void)
{
    return trust.arena != NULL || trust.starting || trust.running ||
           trust.stopping || trust.pending_publish;
}

static bool context_matches_locked(const void *context)
{
    return context != NULL && trust.context_token != 0U &&
           (uintptr_t)context == trust.context_token;
}

static void merge_runtime_status_locked(wifi_trust_status_t *status)
{
    wifi_security_runtime_status_t runtime = {0};
    trust.runtime.status_snapshot(trust.runtime.context, &runtime);
    if (runtime.module == WIFI_SECURITY_MODULE_TRUST_MONITOR &&
        runtime.generation != trust.runtime_baseline_generation) {
        status->rx_drops = saturated_add(runtime.dropped_pool,
                                         runtime.dropped_queue);
    }
}

static void status_locked(wifi_trust_status_t *status)
{
    if (live_locked()) {
        *status = trust.status;
        merge_runtime_status_locked(status);
    } else {
        *status = trust.last_status;
    }
    status->running = trust.running ? 1U : 0U;
    status->stopping = trust.stopping ? 1U : 0U;
    if (!live_locked()) {
        status->mode = WIFI_TRUST_MODE_IDLE;
        status->running = 0U;
        status->stopping = 0U;
    }
}

static void record_output_failure(void)
{
    enter();
    if (live_locked()) increment(&trust.status.output_failures);
    else increment(&trust.last_status.output_failures);
    trust.output_failed = true;
    if (live_locked()) trust.stopping = true;
    leave();
}

static bool publish(const char *line, size_t length)
{
    if (line == NULL || length == 0U ||
        !trust.output.enter(trust.output.context,
                            WIFI_TRUST_OUTPUT_TIMEOUT_MS)) {
        record_output_failure();
        return false;
    }
    bool written = trust.output.write(trust.output.context, line, length);
    if (!written) record_output_failure();
    trust.output.complete(trust.output.context, written);
    trust.output.leave(trust.output.context);
    return written;
}

static bool publish_terminal_status(const wifi_trust_status_t *status,
                                    const char *outcome)
{
    if (status == NULL || outcome == NULL ||
        !trust.output.enter(trust.output.context,
                            WIFI_TRUST_OUTPUT_TIMEOUT_MS)) {
        record_output_failure();
        return false;
    }
    bool written = trust.output.write_terminal(trust.output.context, status,
                                                outcome);
    if (!written) record_output_failure();
    trust.output.complete(trust.output.context, written);
    trust.output.leave(trust.output.context);
    return written;
}

static bool publish_current_terminal(const char *outcome)
{
    wifi_trust_status_t status;
    enter();
    status_locked(&status);
    leave();
    return publish_terminal_status(&status, outcome);
}

static bool valid_bssid(const uint8_t bssid[6])
{
    uint8_t any = 0U;
    for (size_t i = 0; i < 6U; ++i) any |= bssid[i];
    return any != 0U && (bssid[0] & 1U) == 0U;
}

static bool parse_positive(const char *text, size_t *value)
{
    if (text == NULL || value == NULL || text[0] == '\0') return false;
    size_t parsed = 0U;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        size_t digit = (size_t)(*p - '0');
        if (parsed > (SIZE_MAX - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    if (parsed == 0U) return false;
    *value = parsed;
    return true;
}

static void release_arena(wifi_trust_arena_t *arena)
{
    if (arena == NULL) return;
    secure_zero(arena, sizeof(*arena));
    trust.storage.arena_release(trust.storage.context, arena, sizeof(*arena));
}

static bool acquire_arena(wifi_trust_arena_t **arena)
{
    void *memory = NULL;
    if (arena == NULL ||
        !trust.storage.arena_acquire(trust.storage.context,
                                     sizeof(wifi_trust_arena_t), &memory) ||
        memory == NULL)
        return false;
    secure_zero(memory, sizeof(wifi_trust_arena_t));
    *arena = memory;
    return true;
}

static const wifi_trust_profile_t *find_baseline_locked(
    const uint8_t bssid[6])
{
    for (size_t i = 0; i < trust.baseline_count; ++i)
        if (memcmp(trust.arena->baseline[i].bssid, bssid, 6U) == 0)
            return &trust.arena->baseline[i];
    return NULL;
}

static wifi_trust_builder_t *find_builder_locked(const uint8_t bssid[6])
{
    for (size_t i = 0; i < WIFI_TRUST_MAX_PROFILES; ++i)
        if (trust.arena->observed.entries[i].used &&
            memcmp(trust.arena->observed.entries[i].bssid, bssid, 6U) == 0)
            return &trust.arena->observed.entries[i];
    return NULL;
}

static bool selected_locked(const uint8_t bssid[6])
{
    if (!trust.filtered) return true;
    for (size_t i = 0; i < trust.target_count; ++i)
        if (memcmp(trust.arena->targets[i].bssid, bssid, 6U) == 0)
            return true;
    return false;
}

static bool selected_channel_locked(uint8_t channel)
{
    if (!trust.filtered) return channel == trust.status.channel;
    for (size_t i = 0; i < trust.target_count; ++i)
        if (trust.arena->targets[i].channel == channel) return true;
    return false;
}

static bool selected_target_channel_locked(const uint8_t bssid[6],
                                           uint8_t channel)
{
    if (!trust.filtered)
        return channel == trust.status.channel;
    for (size_t i = 0; i < trust.target_count; ++i)
        if (trust.arena->targets[i].channel == channel &&
            memcmp(trust.arena->targets[i].bssid, bssid, 6U) == 0)
            return true;
    return false;
}

static bool semantic_change(const wifi_trust_profile_t *before,
                            const wifi_trust_profile_t *after)
{
    return wifi_trust_diff(before, after, NULL, 0U) != 0U ||
           wifi_trust_diff(after, before, NULL, 0U) != 0U;
}

static void count_event_locked(const wifi_trust_event_t *event)
{
    if (event->reason == WIFI_TRUST_PMF_DOWNGRADE) {
        increment(&trust.status.events_alert);
    } else if (event->reason == WIFI_TRUST_NEW_BSSID ||
               event->reason == WIFI_TRUST_COUNTRY_CHANGED ||
               event->reason == WIFI_TRUST_CHANNEL_CHANGED) {
        increment(&trust.status.events_info);
    } else {
        increment(&trust.status.events_warn);
    }
}

static bool publish_event_batch(size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        char line[WIFI_TRUST_LINE_MAX];
        int length = wifi_trust_format_event(
            line, sizeof(line), &trust.arena->event_batch[i]);
        if (length <= 0 || !publish(line, (size_t)length)) return false;
    }
    return true;
}

static bool feature_consume(void *context,
                            const wifi_security_frame_slot_t *slot,
                            const wifi_security_decoded_t *decoded)
{
    if (slot == NULL || decoded == NULL) return false;
    enter();
    if (!context_matches_locked(context) || trust.arena == NULL ||
        trust.stopping || trust.wiped) {
        leave();
        return true;
    }
    bool filtered_session = trust.filtered;
    leave();
    uint8_t resident_channel = 0U;
    bool resident_known = !filtered_session ||
        trust.runtime.current_channel(trust.runtime.context,
                                      &resident_channel);
    enter();
    if (!context_matches_locked(context) || trust.arena == NULL ||
        trust.stopping || trust.wiped) {
        leave();
        return true;
    }
    increment(&trust.status.received);
    bool selected = trust.filtered ?
        resident_known && selected_channel_locked(resident_channel) &&
            slot->channel == resident_channel &&
            selected_target_channel_locked(decoded->bssid, resident_channel) :
        slot->channel == trust.status.channel && selected_locked(decoded->bssid);
    if (trust.filtered && selected_channel_locked(resident_channel))
        trust.status.channel = resident_channel;
    if (!selected) {
        increment(&trust.status.filtered);
        leave();
        return true;
    }
    leave();

    sx_observation_t observation;
    if (!sx_parse(slot->bytes, slot->captured_len, &observation) ||
        (observation.source != SX_BEACON &&
         observation.source != SX_PROBE_RESP)) {
        enter();
        if (context_matches_locked(context) && trust.arena != NULL &&
            !trust.stopping) increment(&trust.status.unrelated);
        leave();
        return true;
    }

    uint64_t now = trust.runtime.monotonic_us(trust.runtime.context);
    enter();
    if (!context_matches_locked(context) || trust.arena == NULL ||
        trust.stopping || trust.wiped) {
        leave();
        return true;
    }
    wifi_trust_builder_t *previous_builder = find_builder_locked(observation.bssid);
    bool had_previous = previous_builder != NULL &&
        wifi_trust_builder_snapshot(previous_builder,
                                    &trust.arena->previous_snapshot);
    wifi_trust_builder_t *builder = NULL;
    wifi_trust_field_mask_t new_conflicts = 0U;
    wifi_trust_ingest_result_t result = wifi_trust_table_observe(
        &trust.arena->observed, &observation, slot->channel, now,
        &builder, &new_conflicts);
    trust.status.profiles = (uint32_t)trust.arena->observed.active;
    trust.status.capacity_drops = trust.arena->observed.capacity_drops;

    if (result == WIFI_TRUST_INGEST_UNRELATED) {
        increment(&trust.status.unrelated);
        leave();
        return true;
    }
    if (result == WIFI_TRUST_INGEST_CAPACITY) {
        leave();
        return true;
    }
    if (result == WIFI_TRUST_INGEST_MALFORMED) {
        increment(&trust.status.invalid);
        size_t count = trust.status.mode == WIFI_TRUST_MODE_MONITOR ?
            wifi_trust_malformed_events(
                &observation, slot->channel, now,
                trust.arena->event_batch, WIFI_TRUST_REASON_COUNT) : 0U;
        for (size_t i = 0; i < count; ++i)
            count_event_locked(&trust.arena->event_batch[i]);
        leave();
        return count == 0U || publish_event_batch(count);
    }

    increment(&trust.status.accepted);
    size_t publish_count = 0U;
    if (result == WIFI_TRUST_INGEST_CONFLICT) {
        trust.status.conflicts = saturated_add(
            trust.status.conflicts, (uint32_t)(new_conflicts != 0U));
        if (trust.status.mode == WIFI_TRUST_MODE_MONITOR &&
            new_conflicts != 0U && builder != NULL) {
            size_t all = wifi_trust_builder_conflict_events(
                builder, trust.arena->event_batch, WIFI_TRUST_REASON_COUNT);
            size_t kept = 0U;
            for (size_t i = 0; i < all; ++i) {
                wifi_trust_field_mask_t bit = WIFI_TRUST_FIELD_MASK(
                    trust.arena->event_batch[i].field);
                if ((new_conflicts & bit) != 0U)
                    trust.arena->event_batch[kept++] =
                        trust.arena->event_batch[i];
            }
            publish_count = kept;
        }
    } else if (trust.status.mode == WIFI_TRUST_MODE_MONITOR &&
               builder != NULL &&
               wifi_trust_builder_snapshot(builder,
                                           &trust.arena->current_snapshot) &&
               (!had_previous || semantic_change(
                   &trust.arena->previous_snapshot,
                   &trust.arena->current_snapshot))) {
        const wifi_trust_profile_t *baseline = find_baseline_locked(
            trust.arena->current_snapshot.bssid);
        publish_count = wifi_trust_diff(
            baseline, &trust.arena->current_snapshot,
            trust.arena->event_batch, WIFI_TRUST_REASON_COUNT);
    }
    if (publish_count > WIFI_TRUST_REASON_COUNT) {
        increment(&trust.status.capacity_drops);
        leave();
        return false;
    }
    for (size_t i = 0; i < publish_count; ++i)
        count_event_locked(&trust.arena->event_batch[i]);
    leave();
    return publish_count == 0U || publish_event_batch(publish_count);
}

static bool feature_validate(void *context)
{
    uint8_t channel = 0U;
    if (!trust.runtime.current_channel(trust.runtime.context, &channel))
        return false;
    enter();
    bool valid = context_matches_locked(context) && trust.initialized &&
                 trust.arena != NULL && trust.active_epoch != 0U &&
                 trust.starting && trust.runtime_start_inflight &&
                 !trust.stopping && trust.end_claim == END_NONE &&
                 selected_channel_locked(channel);
    if (valid && trust.filtered) trust.status.channel = channel;
    leave();
    return valid;
}

static void finalize_capture_locked(void)
{
    trust.baseline_count = 0U;
    for (size_t i = 0; i < WIFI_TRUST_MAX_PROFILES; ++i) {
        wifi_trust_builder_t *builder = &trust.arena->observed.entries[i];
        if (!builder->used || builder->conflict_mask != 0U) continue;
        wifi_trust_profile_t snapshot;
        if (!wifi_trust_builder_snapshot(builder, &snapshot)) continue;
        if (trust.baseline_count == WIFI_TRUST_MAX_PROFILES) {
            increment(&trust.status.capacity_drops);
            break;
        }
        trust.arena->baseline[trust.baseline_count++] = snapshot;
    }
    trust.status.profiles = (uint32_t)trust.baseline_count;
    trust.pending_publish = trust.status.rx_drops == 0U &&
                            trust.status.capacity_drops == 0U &&
                            trust.status.output_failures == 0U &&
                            !trust.output_failed;
}

static void feature_wipe(void *context)
{
    enter();
    if (!context_matches_locked(context) || trust.arena == NULL || trust.wiped) {
        leave();
        return;
    }
    merge_runtime_status_locked(&trust.status);
    if (trust.status.mode == WIFI_TRUST_MODE_CAPTURE &&
        trust.end_claim == END_NATURAL)
        finalize_capture_locked();
    secure_zero(&trust.arena->observed, sizeof(trust.arena->observed));
    secure_zero(trust.arena->targets, sizeof(trust.arena->targets));
    secure_zero(trust.arena->event_batch, sizeof(trust.arena->event_batch));
    secure_zero(&trust.arena->previous_snapshot,
                sizeof(trust.arena->previous_snapshot));
    secure_zero(&trust.arena->current_snapshot,
                sizeof(trust.arena->current_snapshot));
    trust.target_count = 0U;
    trust.filtered = false;
    trust.starting = false;
    trust.runtime_start_committed = false;
    trust.running = false;
    trust.stopping = true;
    trust.wiped = true;
    leave();
}

static void feature_uncertainty(void *telemetry_context,
                                wifi_security_session_result_t result,
                                bool owned)
{
    (void)telemetry_context;
    (void)result;
    if (owned) {
        enter();
        trust.stopping = true;
        leave();
    }
}

static const char *session_outcome(wifi_security_session_result_t result)
{
    switch (result) {
    case WIFI_SECURITY_SESSION_BUSY:
    case WIFI_SECURITY_SESSION_BASELINE_BUSY:
        return "busy";
    case WIFI_SECURITY_SESSION_CANCELLED:
    case WIFI_SECURITY_SESSION_JOIN_TIMEOUT:
        return "timeout";
    case WIFI_SECURITY_SESSION_CHANNEL_FAILED:
    case WIFI_SECURITY_SESSION_RESTORE_FAILED:
    case WIFI_SECURITY_SESSION_CLEANUP_FAILED:
    case WIFI_SECURITY_SESSION_FILTER_SNAPSHOT_FAILED:
    case WIFI_SECURITY_SESSION_FILTER_APPLY_FAILED:
    case WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED:
        return "restore_failed";
    default:
        return "invalid";
    }
}

static bool uncertain_cleanup(wifi_security_session_result_t result)
{
    return result == WIFI_SECURITY_SESSION_JOIN_TIMEOUT ||
           result == WIFI_SECURITY_SESSION_RESTORE_FAILED ||
           result == WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED ||
           result == WIFI_SECURITY_SESSION_CLEANUP_FAILED;
}

static bool store_uncertain(wifi_trust_store_result_t result)
{
    return result == WIFI_TRUST_STORE_OK_BACKUP_PENDING ||
           result == WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN;
}

static const char *publish_pending_snapshot(bool *retain)
{
    *retain = false;
    wifi_trust_store_result_t result = wifi_trust_store_publish(
        trust.arena->baseline, trust.baseline_count, &trust.meta,
        &trust.storage.store);
    enter();
    trust.status.store = result;
    trust.status.baseline_loaded =
        (result == WIFI_TRUST_STORE_OK || store_uncertain(result)) ? 1U : 0U;
    trust.status.baseline_count = trust.status.baseline_loaded ?
        (uint32_t)trust.baseline_count : 0U;
    if (trust.status.baseline_loaded) {
        trust.status.boot_known = 1U;
        memcpy(trust.status.boot_id, trust.meta.boot_id,
               sizeof(trust.status.boot_id));
        trust.status.created_unix_known =
            trust.meta.created_unix_known ? 1U : 0U;
        trust.status.created_unix = trust.meta.created_unix;
    }
    if (result != WIFI_TRUST_STORE_OK) increment(&trust.status.storage_failures);
    if (result == WIFI_TRUST_STORE_RECOVERED_RETRY) {
        *retain = true;
        trust.pending_publish = true;
    } else {
        trust.pending_publish = false;
    }
    leave();
    if (result == WIFI_TRUST_STORE_OK) return "ok";
    if (store_uncertain(result)) return "storage_uncertain";
    return "storage_failed";
}

static void finish_state(wifi_trust_status_t *terminal,
                         wifi_trust_arena_t **arena)
{
    enter();
    status_locked(terminal);
    *arena = trust.arena;
    trust.arena = NULL;
    trust.last_status = *terminal;
    trust.last_status.mode = WIFI_TRUST_MODE_IDLE;
    trust.last_status.running = 0U;
    trust.last_status.stopping = 0U;
    trust.starting = false;
    trust.runtime_start_inflight = false;
    trust.runtime_start_committed = false;
    trust.running = false;
    trust.stopping = false;
    trust.filtered = false;
    trust.deadline_armed = false;
    trust.wiped = false;
    trust.pending_publish = false;
    trust.cleanup_in_progress = false;
    trust.active_epoch = 0U;
    trust.context_token = 0U;
    trust.end_claim = END_NONE;
    trust.target_count = 0U;
    trust.baseline_count = 0U;
    leave();
}

static bool stop_internal(uint32_t timeout_ms, bool natural, uint64_t epoch,
                          const char *forced_outcome)
{
    bool cancel_deadline = false;
    uint8_t resident_channel = 0U;
    bool resident_known = trust.runtime.current_channel(
        trust.runtime.context, &resident_channel);
    enter();
    if (!live_locked()) {
        leave();
        return true;
    }
    if (trust.filtered && resident_known &&
        selected_channel_locked(resident_channel))
        trust.status.channel = resident_channel;
    if (natural) {
        if (epoch == 0U || epoch != trust.active_epoch ||
            trust.end_claim != END_NONE) {
            leave();
            return true;
        }
        trust.end_claim = END_NATURAL;
    } else if (trust.end_claim == END_NONE) {
        trust.end_claim = END_CANCELLED;
        cancel_deadline = trust.deadline_armed;
    }
    trust.stopping = true;
    uint64_t active_epoch = trust.active_epoch;
    bool pre_runtime = trust.starting && !trust.runtime_start_committed &&
                       !trust.running;
    bool start_inflight = trust.runtime_start_inflight;
    bool has_arena = trust.arena != NULL;
    void *session_context = (void *)trust.context_token;
    leave();

    if (cancel_deadline)
        trust.runtime.deadline_cancel(trust.runtime.context, active_epoch);
    if (start_inflight) return false;
    if (pre_runtime) return true;

    enter();
    if (trust.cleanup_in_progress) {
        leave();
        return true;
    }
    trust.cleanup_in_progress = true;
    leave();

    bool stopped = trust.runtime.stop(trust.runtime.context, timeout_ms);
    if (!stopped) {
        (void)publish_current_terminal(forced_outcome != NULL ?
                                       forced_outcome : "timeout");
        enter();
        trust.cleanup_in_progress = false;
        leave();
        return false;
    }
    enter();
    bool needs_wipe = has_arena && trust.arena != NULL && !trust.wiped;
    leave();
    if (needs_wipe) feature_wipe(session_context);

    enter();
    bool retain = false;
    bool publish_pending = trust.pending_publish;
    end_claim_t claim = trust.end_claim;
    wifi_trust_mode_t mode = trust.status.mode;
    leave();
    const char *outcome = forced_outcome;
    if (publish_pending) outcome = publish_pending_snapshot(&retain);
    if (retain) {
        (void)publish_current_terminal(outcome);
        enter();
        trust.cleanup_in_progress = false;
        leave();
        return false;
    }
    if (outcome == NULL)
        outcome = claim == END_CANCELLED || mode == WIFI_TRUST_MODE_MONITOR ?
                  "stopped" : "ok";

    wifi_trust_status_t terminal;
    wifi_trust_arena_t *arena;
    finish_state(&terminal, &arena);
    bool published = publish_terminal_status(&terminal, outcome);
    release_arena(arena);
    return published;
}

static void deadline_expired(void *context, uint64_t epoch)
{
    (void)context;
    (void)stop_internal(5000U, true, epoch, NULL);
}

static bool prepare_selection(int argc, char **argv, int first_index)
{
    size_t scan_entries_count = 0U;
    if (!trust.runtime.scan_snapshot(
            trust.runtime.context, trust.arena->targets,
            WIFI_TRUST_MAX_PROFILES, &scan_entries_count) ||
        scan_entries_count == 0U ||
        scan_entries_count > WIFI_TRUST_MAX_PROFILES)
        return false;
    for (int i = first_index; i < argc; ++i) {
        size_t index;
        if (!parse_positive(argv[i], &index) || index > scan_entries_count)
            return false;
        for (int j = first_index; j < i; ++j) {
            size_t previous;
            if (!parse_positive(argv[j], &previous) || previous == index)
                return false;
        }
        const wifi_shield_target_t *entry =
            &trust.arena->targets[index - 1U];
        if (!valid_bssid(entry->bssid) || entry->channel == 0U ||
            entry->channel > 233U)
            return false;
        for (int j = first_index; j < i; ++j) {
            size_t previous;
            if (!parse_positive(argv[j], &previous) ||
                memcmp(trust.arena->targets[previous - 1U].bssid,
                       entry->bssid, 6U) == 0)
                return false;
        }
    }
    size_t selected = 0U;
    for (size_t scan = 1U; scan <= scan_entries_count; ++scan) {
        bool wanted = false;
        for (int i = first_index; i < argc; ++i) {
            size_t index;
            if (!parse_positive(argv[i], &index)) return false;
            if (index == scan) wanted = true;
        }
        if (wanted) {
            if (selected != scan - 1U)
                trust.arena->targets[selected] =
                    trust.arena->targets[scan - 1U];
            ++selected;
        }
    }
    if (selected == 0U) return false;
    if (selected < WIFI_TRUST_MAX_PROFILES)
        secure_zero(trust.arena->targets + selected,
                    (WIFI_TRUST_MAX_PROFILES - selected) *
                    sizeof(trust.arena->targets[0]));
    enter();
    trust.target_count = selected;
    trust.filtered = true;
    leave();
    return true;
}

static bool initialize_start_state(wifi_trust_mode_t mode, uint32_t seconds,
                                   uint64_t *epoch, void **session_context)
{
    enter();
    if (live_locked() || !trust.output.idle(trust.output.context)) {
        leave();
        return false;
    }
    trust.starting = true;
    trust.runtime_start_inflight = false;
    trust.runtime_start_committed = false;
    trust.stopping = false;
    trust.running = false;
    trust.output_failed = false;
    trust.end_claim = END_NONE;
    trust.seconds = seconds;
    ++trust.next_epoch;
    if (trust.next_epoch == 0U) ++trust.next_epoch;
    trust.active_epoch = trust.next_epoch;
    ++next_context_token;
    if (next_context_token == 0U) ++next_context_token;
    trust.context_token = next_context_token;
    memset(&trust.status, 0, sizeof(trust.status));
    trust.status.mode = mode;
    trust.status.store = WIFI_TRUST_STORE_OK;
    trust.status.recovery = WIFI_TRUST_RECOVERY_NONE;
    wifi_security_runtime_status_t runtime = {0};
    trust.runtime.status_snapshot(trust.runtime.context, &runtime);
    trust.runtime_baseline_generation = runtime.generation;
    *epoch = trust.active_epoch;
    *session_context = (void *)trust.context_token;
    leave();
    return true;
}

static void abandon_start(uint64_t epoch, const char *outcome)
{
    wifi_trust_arena_t *arena = NULL;
    wifi_trust_status_t terminal;
    enter();
    if (trust.active_epoch == epoch) {
        status_locked(&terminal);
        arena = trust.arena;
        trust.arena = NULL;
        trust.last_status = terminal;
        trust.last_status.mode = WIFI_TRUST_MODE_IDLE;
        trust.last_status.running = 0U;
        trust.last_status.stopping = 0U;
        trust.starting = false;
        trust.runtime_start_inflight = false;
        trust.runtime_start_committed = false;
        trust.running = false;
        trust.stopping = false;
        trust.filtered = false;
        trust.active_epoch = 0U;
        trust.context_token = 0U;
        trust.end_claim = END_NONE;
        trust.target_count = 0U;
        trust.baseline_count = 0U;
    } else {
        memset(&terminal, 0, sizeof(terminal));
        terminal.mode = WIFI_TRUST_MODE_IDLE;
        terminal.store = WIFI_TRUST_STORE_OK;
        terminal.recovery = WIFI_TRUST_RECOVERY_NONE;
    }
    leave();
    (void)publish_terminal_status(&terminal, outcome);
    release_arena(arena);
}

static int start_command(wifi_trust_mode_t mode, uint32_t seconds,
                         bool filtered, int argc, char **argv,
                         int first_index)
{
    uint64_t epoch;
    void *session_context;
    if (!initialize_start_state(mode, seconds, &epoch, &session_context)) {
        (void)publish_current_terminal("busy");
        return 1;
    }
    wifi_trust_arena_t *arena = NULL;
    if (!acquire_arena(&arena)) {
        abandon_start(epoch, "invalid");
        return 1;
    }
    enter();
    if (trust.active_epoch != epoch || trust.end_claim != END_NONE) {
        leave();
        release_arena(arena);
        abandon_start(epoch, "stopped");
        return 1;
    }
    trust.arena = arena;
    leave();

    uint8_t channel;
    if (!trust.runtime.current_channel(trust.runtime.context, &channel)) {
        abandon_start(epoch, "invalid");
        return 1;
    }
    enter();
    trust.status.channel = channel;
    leave();

    if (mode == WIFI_TRUST_MODE_MONITOR) {
        size_t count = 0U;
        wifi_trust_store_meta_t meta;
        wifi_trust_recovery_action_t recovery = WIFI_TRUST_RECOVERY_NONE;
        wifi_trust_store_result_t result = wifi_trust_store_load(
            WIFI_TRUST_STORE_PATH, arena->baseline,
            WIFI_TRUST_MAX_PROFILES, &count, &meta, &recovery,
            &trust.storage.store);
        enter();
        trust.status.store = result;
        trust.status.recovery = recovery;
        if (result == WIFI_TRUST_STORE_OK) {
            trust.baseline_count = count;
            trust.meta = meta;
            trust.status.baseline_loaded = 1U;
            trust.status.baseline_count = (uint32_t)count;
            trust.status.boot_known = 1U;
            memcpy(trust.status.boot_id, meta.boot_id,
                   sizeof(trust.status.boot_id));
            trust.status.created_unix_known =
                meta.created_unix_known ? 1U : 0U;
            trust.status.created_unix = meta.created_unix;
        }
        leave();
        if (result != WIFI_TRUST_STORE_OK) {
            abandon_start(epoch, "storage_failed");
            return 1;
        }
    } else if (!trust.storage.meta_snapshot(trust.storage.context,
                                            &trust.meta)) {
        abandon_start(epoch, "storage_failed");
        return 1;
    }

    if (filtered && !prepare_selection(argc, argv, first_index)) {
        abandon_start(epoch, "invalid");
        return 1;
    }

    const wifi_security_session_config_t config = {
        .module = WIFI_SECURITY_MODULE_TRUST_MONITOR,
        .context = session_context,
        .consume = feature_consume,
        .validate = feature_validate,
        .wipe = feature_wipe,
        .telemetry_context = &trust,
        .uncertainty = feature_uncertainty,
    };
    enter();
    bool cancelled = trust.active_epoch != epoch ||
                     trust.end_claim != END_NONE || trust.stopping ||
                     trust.arena == NULL;
    if (!cancelled) trust.runtime_start_inflight = true;
    leave();
    if (cancelled) {
        abandon_start(epoch, "stopped");
        return 1;
    }

    const wifi_shield_target_t *targets = filtered ? arena->targets : NULL;
    size_t target_count = filtered ? trust.target_count : 0U;
    wifi_security_session_result_t result = trust.runtime.start(
        trust.runtime.context, targets, target_count, &config);
    enter();
    if (trust.active_epoch == epoch) {
        trust.runtime_start_inflight = false;
        if (result == WIFI_SECURITY_SESSION_OK || uncertain_cleanup(result))
            trust.runtime_start_committed = true;
    }
    bool cancelled_after_start = trust.active_epoch == epoch &&
        trust.end_claim != END_NONE;
    leave();
    if (result != WIFI_SECURITY_SESSION_OK) {
        enter();
        bool retained = uncertain_cleanup(result) && trust.arena != NULL;
        if (retained) trust.stopping = true;
        leave();
        if (!retained)
            abandon_start(epoch, cancelled_after_start ? "stopped" :
                          session_outcome(result));
        else (void)publish_current_terminal(session_outcome(result));
        return 1;
    }

    enter();
    cancelled = trust.active_epoch != epoch || trust.end_claim != END_NONE ||
                trust.stopping || trust.arena == NULL;
    if (!cancelled) {
        trust.starting = false;
        trust.runtime_start_committed = false;
        trust.running = true;
    }
    leave();
    if (cancelled) {
        (void)stop_internal(5000U, false, 0U, "stopped");
        return 1;
    }

    if (mode == WIFI_TRUST_MODE_CAPTURE) {
        bool armed = trust.runtime.deadline_arm(
            trust.runtime.context, epoch, seconds,
            deadline_expired, &trust);
        if (!armed) {
            enter();
            if (trust.active_epoch == epoch && trust.end_claim == END_NONE)
                trust.end_claim = END_ERROR;
            leave();
            (void)stop_internal(5000U, false, 0U, "invalid");
            return 1;
        }
        enter();
        bool accepted = trust.active_epoch == epoch &&
                        trust.end_claim == END_NONE && trust.running &&
                        trust.arena != NULL;
        if (accepted) trust.deadline_armed = true;
        leave();
        if (!accepted) {
            trust.runtime.deadline_cancel(trust.runtime.context, epoch);
            return 1;
        }
    }
    return 0;
}

static int invalid_command(void)
{
    if (trust.initialized) (void)publish_current_terminal("invalid");
    return 1;
}

static int capture_command(int argc, char **argv)
{
    uint32_t seconds = 15U;
    bool filtered = false;
    int at = 3;
    if (at < argc && strcmp(argv[at], "--seconds") == 0) {
        size_t parsed;
        if (at + 1 >= argc || !parse_positive(argv[at + 1], &parsed) ||
            parsed < 5U || parsed > 120U)
            return invalid_command();
        seconds = (uint32_t)parsed;
        at += 2;
    }
    if (at < argc && strcmp(argv[at], "--only") == 0) {
        filtered = true;
        ++at;
        if (at >= argc) return invalid_command();
    }
    if ((!filtered && at != argc) || (filtered && at >= argc))
        return invalid_command();
    if (filtered) {
        for (int i = at; i < argc; ++i) {
            size_t ignored;
            if (!parse_positive(argv[i], &ignored)) return invalid_command();
        }
    }
    return start_command(WIFI_TRUST_MODE_CAPTURE, seconds, filtered,
                         argc, argv, at);
}

static int monitor_command(int argc, char **argv)
{
    bool filtered = argc >= 3 && strcmp(argv[2], "--only") == 0;
    if (!((argc == 2) || (filtered && argc >= 4))) return invalid_command();
    if (filtered) {
        for (int i = 3; i < argc; ++i) {
            size_t ignored;
            if (!parse_positive(argv[i], &ignored)) return invalid_command();
        }
    }
    return start_command(WIFI_TRUST_MODE_MONITOR, 0U, filtered,
                         argc, argv, filtered ? 3 : argc);
}

static bool claim_sync_command(uint64_t *epoch)
{
    enter();
    if (live_locked() || !trust.output.idle(trust.output.context)) {
        leave();
        return false;
    }
    trust.starting = true;
    ++trust.next_epoch;
    if (trust.next_epoch == 0U) ++trust.next_epoch;
    trust.active_epoch = trust.next_epoch;
    memset(&trust.status, 0, sizeof(trust.status));
    trust.status.store = WIFI_TRUST_STORE_OK;
    trust.status.recovery = WIFI_TRUST_RECOVERY_NONE;
    *epoch = trust.active_epoch;
    leave();
    return true;
}

static void finish_sync_command(uint64_t epoch, wifi_trust_arena_t *arena,
                                const wifi_trust_status_t *status)
{
    enter();
    if (trust.active_epoch == epoch) {
        trust.last_status = *status;
        trust.last_status.mode = WIFI_TRUST_MODE_IDLE;
        trust.last_status.running = 0U;
        trust.last_status.stopping = 0U;
        trust.starting = false;
        trust.stopping = false;
        trust.cleanup_in_progress = false;
        trust.active_epoch = 0U;
        trust.end_claim = END_NONE;
    }
    leave();
    release_arena(arena);
}

static int list_command(void)
{
    uint64_t epoch;
    if (!claim_sync_command(&epoch)) {
        (void)publish_current_terminal("busy");
        return 1;
    }
    wifi_trust_arena_t *arena = NULL;
    if (!acquire_arena(&arena)) {
        wifi_trust_status_t status = trust.status;
        finish_sync_command(epoch, NULL, &status);
        (void)publish_terminal_status(&status, "invalid");
        return 1;
    }
    size_t count = 0U;
    wifi_trust_store_meta_t meta;
    wifi_trust_recovery_action_t recovery = WIFI_TRUST_RECOVERY_NONE;
    wifi_trust_store_result_t result = wifi_trust_store_load(
        WIFI_TRUST_STORE_PATH, arena->baseline, WIFI_TRUST_MAX_PROFILES,
        &count, &meta, &recovery, &trust.storage.store);
    wifi_trust_status_t status = {0};
    status.store = result;
    status.recovery = recovery;
    bool ok = result == WIFI_TRUST_STORE_OK;
    if (ok) {
        status.baseline_loaded = 1U;
        status.baseline_count = (uint32_t)count;
        status.boot_known = 1U;
        memcpy(status.boot_id, meta.boot_id, sizeof(status.boot_id));
        status.created_unix_known = meta.created_unix_known ? 1U : 0U;
        status.created_unix = meta.created_unix;
        for (size_t i = 0; i < count && ok; ++i) {
            char line[WIFI_TRUST_LINE_MAX];
            int length = wifi_trust_format_baseline(
                line, sizeof(line), &arena->baseline[i], &meta);
            ok = length > 0 && publish(line, (size_t)length);
        }
    } else {
        increment(&status.storage_failures);
    }
    finish_sync_command(epoch, arena, &status);
    bool terminal = publish_terminal_status(
        &status, ok ? "ok" : (result == WIFI_TRUST_STORE_OK_BACKUP_PENDING ||
                              result == WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN ?
                              "storage_uncertain" : "storage_failed"));
    return ok && terminal ? 0 : 1;
}

static int clear_command(void)
{
    uint64_t epoch;
    if (!claim_sync_command(&epoch)) {
        (void)publish_current_terminal("busy");
        return 1;
    }
    wifi_trust_arena_t *arena = NULL;
    if (!acquire_arena(&arena)) {
        wifi_trust_status_t status = trust.status;
        finish_sync_command(epoch, NULL, &status);
        (void)publish_terminal_status(&status, "invalid");
        return 1;
    }
    wifi_trust_store_result_t result = wifi_trust_store_clear(
        &trust.storage.store);
    wifi_trust_status_t status = {0};
    status.store = result;
    status.recovery = WIFI_TRUST_RECOVERY_NONE;
    bool ok = result == WIFI_TRUST_STORE_OK;
    if (!ok) increment(&status.storage_failures);
    finish_sync_command(epoch, arena, &status);
    bool terminal = publish_terminal_status(
        &status, ok ? "ok" : (store_uncertain(result) ?
                               "storage_uncertain" : "storage_failed"));
    return ok && terminal ? 0 : 1;
}

static bool store_ops_valid(const wifi_trust_store_ops_t *ops)
{
    return ops != NULL && ops->enter != NULL && ops->leave != NULL &&
           ops->open != NULL && ops->read != NULL && ops->write != NULL &&
           ops->flush != NULL && ops->sync != NULL && ops->close != NULL &&
           ops->path_state != NULL && ops->rename_path != NULL &&
           ops->remove_path != NULL && ops->sync_volume != NULL &&
           ops->publish_staged != NULL && ops->recover_staged != NULL;
}

bool wifi_trust_init(const wifi_trust_runtime_hooks_t *runtime_hooks,
                     const wifi_trust_storage_hooks_t *storage_hooks,
                     const wifi_trust_output_hooks_t *output_hooks)
{
    if (runtime_hooks == NULL || storage_hooks == NULL || output_hooks == NULL ||
        runtime_hooks->enter == NULL || runtime_hooks->leave == NULL ||
        runtime_hooks->current_channel == NULL ||
        runtime_hooks->scan_snapshot == NULL ||
        runtime_hooks->monotonic_us == NULL ||
        runtime_hooks->status_snapshot == NULL ||
        runtime_hooks->start == NULL || runtime_hooks->stop == NULL ||
        runtime_hooks->deadline_arm == NULL ||
        runtime_hooks->deadline_cancel == NULL ||
        storage_hooks->arena_acquire == NULL ||
        storage_hooks->arena_release == NULL ||
        storage_hooks->meta_snapshot == NULL ||
        !store_ops_valid(&storage_hooks->store) ||
        output_hooks->enter == NULL || output_hooks->leave == NULL ||
        output_hooks->write == NULL || output_hooks->write_terminal == NULL ||
        output_hooks->complete == NULL || output_hooks->idle == NULL)
        return false;
    if (trust.initialized) {
        enter();
        bool busy = live_locked() || !trust.output.idle(trust.output.context);
        leave();
        if (busy) return false;
    }
    memset(&trust, 0, sizeof(trust));
    trust.runtime = *runtime_hooks;
    trust.storage = *storage_hooks;
    trust.output = *output_hooks;
    trust.last_status.store = WIFI_TRUST_STORE_OK;
    trust.last_status.recovery = WIFI_TRUST_RECOVERY_NONE;
    trust.initialized = true;
    return true;
}

bool wifi_trust_busy(void)
{
    if (!trust.initialized) return false;
    enter();
    bool busy = live_locked() || !trust.output.idle(trust.output.context);
    leave();
    return busy;
}

bool wifi_trust_stop(uint32_t timeout_ms)
{
    if (!trust.initialized) return true;
    return stop_internal(timeout_ms, false, 0U, NULL);
}

void wifi_trust_report_output_failure(void)
{
    if (trust.initialized) record_output_failure();
}

int wifi_trust_format_terminal_for_output(char *out, size_t capacity,
                                          const wifi_trust_status_t *status,
                                          const char *outcome)
{
    if (out == NULL || status == NULL || outcome == NULL) return -1;
    wifi_trust_status_t final_status = *status;
    bool output_failed = final_status.output_failures != 0U;
    if (trust.initialized) {
        enter();
        wifi_trust_status_t latest;
        status_locked(&latest);
        if (latest.output_failures > final_status.output_failures)
            final_status.output_failures = latest.output_failures;
        output_failed = output_failed || trust.output_failed ||
                        latest.output_failures != 0U;
        leave();
    }
    const char *published = outcome;
    if (output_failed) {
        published = "output_failed";
    } else if (strcmp(outcome, "restore_failed") != 0 &&
               strcmp(outcome, "timeout") != 0) {
        bool storage_chain = strcmp(outcome, "ok") == 0 ||
                             strcmp(outcome, "stopped") == 0 ||
                             strcmp(outcome, "storage_uncertain") == 0 ||
                             strcmp(outcome, "storage_failed") == 0;
        if (storage_chain && store_uncertain(final_status.store)) {
            published = "storage_uncertain";
        } else if (storage_chain &&
                   (final_status.store == WIFI_TRUST_STORE_RECOVERED_RETRY ||
                    final_status.store == WIFI_TRUST_STORE_NOT_FOUND ||
                    final_status.store == WIFI_TRUST_STORE_IO ||
                    final_status.store == WIFI_TRUST_STORE_FORMAT ||
                    final_status.store == WIFI_TRUST_STORE_CAPACITY ||
                    final_status.store == WIFI_TRUST_STORE_PUBLISH ||
                    final_status.store == WIFI_TRUST_STORE_RECOVERY)) {
            published = "storage_failed";
        } else if ((final_status.rx_drops != 0U ||
                    final_status.capacity_drops != 0U) &&
                   (strcmp(outcome, "ok") == 0 ||
                    strcmp(outcome, "stopped") == 0)) {
            published = "queue_overflow";
        }
    }
    return wifi_trust_format_terminal(out, capacity, &final_status, published);
}

int wifi_trust_command(int argc, char **argv)
{
    if (!trust.initialized || argv == NULL || argc < 2 || argv[0] == NULL ||
        argv[1] == NULL || strcmp(argv[0], "wifi_trust") != 0)
        return invalid_command();
    if (strcmp(argv[1], "baseline") == 0) {
        if (argc < 3 || argv[2] == NULL) return invalid_command();
        if (strcmp(argv[2], "capture") == 0)
            return capture_command(argc, argv);
        if (strcmp(argv[2], "list") == 0 && argc == 3)
            return list_command();
        if (strcmp(argv[2], "clear") == 0 && argc == 3)
            return clear_command();
        return invalid_command();
    }
    if (strcmp(argv[1], "monitor") == 0)
        return monitor_command(argc, argv);
    if (strcmp(argv[1], "status") == 0) {
        if (argc != 2) return invalid_command();
        wifi_trust_status_t status;
        char line[WIFI_TRUST_LINE_MAX];
        uint8_t resident_channel = 0U;
        bool resident_known = trust.runtime.current_channel(
            trust.runtime.context, &resident_channel);
        enter();
        if (live_locked() && trust.filtered && resident_known &&
            selected_channel_locked(resident_channel))
            trust.status.channel = resident_channel;
        status_locked(&status);
        leave();
        int length = wifi_trust_format_status(line, sizeof(line), &status);
        return length > 0 && publish(line, (size_t)length) ? 0 : 1;
    }
    if (strcmp(argv[1], "stop") == 0) {
        if (argc != 2) return invalid_command();
        return wifi_trust_stop(5000U) ? 0 : 1;
    }
    return invalid_command();
}
