#include "wifi_security_runtime.h"

#include <string.h>

enum { SLOT_FREE, SLOT_CLAIMED, SLOT_QUEUED, SLOT_WORKER };

static void enter(wifi_security_runtime_t *r)
{
    if (r->hooks.enter != NULL) r->hooks.enter(r->hooks.context);
}

static void leave(wifi_security_runtime_t *r)
{
    if (r->hooks.leave != NULL) r->hooks.leave(r->hooks.context);
}

static void increment(uint32_t *counter)
{
    if (*counter != UINT32_MAX) ++*counter;
}

/* Volatile stores keep the payload wipe observable even before lifetime ends. */
static void wipe(void *memory, size_t size)
{
    volatile unsigned char *p = memory;
    while (size-- != 0) *p++ = 0;
}

static bool claim_locked(wifi_security_runtime_t *r, uint8_t *index)
{
    for (uint8_t i = 0; i < WIFI_SECURITY_POOL_SLOTS; ++i) {
        if (r->slot_state[i] == SLOT_FREE) {
            r->slot_state[i] = SLOT_CLAIMED;
            *index = i;
            return true;
        }
    }
    increment(&r->status.dropped_pool);
    return false;
}

static void release_locked(wifi_security_runtime_t *r, uint8_t index)
{
    wipe(&r->slots[index], sizeof(r->slots[index]));
    r->slot_state[index] = SLOT_FREE;
}

bool wifi_security_runtime_init(wifi_security_runtime_t *r,
                                const wifi_security_runtime_hooks_t *hooks,
                                uint8_t capacity)
{
    if (r == NULL || hooks == NULL || capacity == 0 ||
        capacity > WIFI_SECURITY_POOL_SLOTS ||
        ((hooks->enter == NULL) != (hooks->leave == NULL))) return false;
    wifi_security_runtime_hooks_t saved = *hooks;
    memset(r, 0, sizeof(*r));
    r->hooks = saved;
    r->queue_capacity = capacity;
    return true;
}

bool wifi_security_runtime_start(wifi_security_runtime_t *r,
                                 const wifi_security_runtime_config_t *config)
{
    if (r == NULL || config == NULL || config->generation == 0 ||
        config->module < WIFI_SECURITY_MODULE_WPS_GUARD ||
        config->module > WIFI_SECURITY_MODULE_DEAUTH_V2) return false;
    enter(r);
    bool result = false;
    if (r->status.running) {
        result = r->callbacks_open && !r->status.stopping &&
                 r->config.generation == config->generation &&
                 r->config.module == config->module &&
                 r->config.context == config->context &&
                 r->config.consume == config->consume;
    } else if (config->generation > r->last_generation) {
        r->config = *config;
        r->last_generation = config->generation;
        memset(&r->status, 0, sizeof(r->status));
        r->status.module = config->module;
        r->status.generation = config->generation;
        r->status.running = true;
        r->callbacks_open = true;
        result = true;
    }
    leave(r);
    return result;
}

void wifi_security_runtime_close_callbacks(wifi_security_runtime_t *r)
{
    if (r == NULL) return;
    enter(r);
    r->callbacks_open = false;
    leave(r);
}

void wifi_security_runtime_request_stop(wifi_security_runtime_t *r)
{
    if (r == NULL) return;
    enter(r);
    r->callbacks_open = false;
    if (r->status.running) r->status.stopping = true;
    leave(r);
}

bool wifi_security_runtime_finish(wifi_security_runtime_t *r)
{
    if (r == NULL) return false;
    enter(r);
    bool result = !r->draining && r->queue_count == 0 && r->compact_count == 0 &&
                  (!r->status.running || r->status.stopping);
    for (unsigned i = 0; i < WIFI_SECURITY_POOL_SLOTS; ++i)
        if (r->slot_state[i] != SLOT_FREE) result = false;
    if (result) {
        wipe(r->slots, sizeof(r->slots));
        if (r->compact_events != NULL)
            wipe(r->compact_events, WIFI_SHIELD_COMPACT_EVENT_CAPACITY * sizeof(*r->compact_events));
        r->compact_events = NULL;
        r->compact_consume = NULL;
        r->compact_context = NULL;
        r->compact_head = r->compact_deauth_count = 0;
        memset(&r->config, 0, sizeof(r->config));
        memset(r->queue, 0, sizeof(r->queue));
        r->queue_head = 0;
        r->callbacks_open = false;
        r->status.running = false;
        r->status.stopping = false;
    }
    leave(r);
    return result;
}

bool wifi_security_runtime_claim(wifi_security_runtime_t *r, uint8_t *index,
                                 wifi_security_frame_slot_t **slot)
{
    if (r == NULL || index == NULL || slot == NULL) return false;
    enter(r);
    bool result = r->status.running && claim_locked(r, index);
    if (result) *slot = &r->slots[*index];
    leave(r);
    return result;
}

bool wifi_security_runtime_release(wifi_security_runtime_t *r, uint8_t index)
{
    if (r == NULL || index >= WIFI_SECURITY_POOL_SLOTS) return false;
    enter(r);
    bool result = r->slot_state[index] == SLOT_CLAIMED;
    if (result) release_locked(r, index);
    leave(r);
    return result;
}

bool wifi_security_runtime_submit(wifi_security_runtime_t *r,
                                  uint32_t generation, const uint8_t *bytes,
                                  uint16_t length, uint64_t timestamp_us,
                                  int8_t rssi, uint8_t channel)
{
    if (r == NULL || bytes == NULL || length == 0) return false;
    enter(r);
    increment(&r->status.received);
    if (generation == 0 || generation != r->last_generation) {
        increment(&r->status.stale_generation);
        leave(r);
        return false;
    }
    if (!r->status.running || !r->callbacks_open || r->status.stopping) {
        leave(r);
        return false;
    }
    uint8_t index;
    if (!claim_locked(r, &index)) {
        if (r->config.module == WIFI_SECURITY_MODULE_SHIELD) increment(&r->status.rx_drops);
        leave(r);
        return false;
    }
    wifi_security_frame_slot_t *slot = &r->slots[index];
    slot->generation = generation;
    slot->timestamp_us = timestamp_us;
    slot->original_len = length;
    slot->captured_len = length > WIFI_SECURITY_FRAME_COPY_MAX ?
                         WIFI_SECURITY_FRAME_COPY_MAX : length;
    slot->rssi = rssi;
    slot->channel = channel;
    slot->truncated = length > slot->captured_len;
    memcpy(slot->bytes, bytes, slot->captured_len);
    if (slot->truncated) increment(&r->status.truncated);
    if (r->queue_count == r->queue_capacity) {
        increment(&r->status.dropped_queue);
        if (r->config.module == WIFI_SECURITY_MODULE_SHIELD) increment(&r->status.rx_drops);
        release_locked(r, index);
        leave(r);
        return false;
    }
    bool notify = r->queue_count == 0 && r->compact_count == 0;
    unsigned tail = (r->queue_head + r->queue_count) % WIFI_SECURITY_POOL_SLOTS;
    r->queue[tail] = index;
    ++r->queue_count;
    r->slot_state[index] = SLOT_QUEUED;
    increment(&r->status.queued);
    leave(r);
    if (notify && r->hooks.notify != NULL) r->hooks.notify(r->hooks.context);
    return true;
}

bool wifi_security_runtime_bind_compact(wifi_security_runtime_t *r,
    wifi_shield_compact_event_t *storage,
    wifi_security_compact_consume_fn consume, void *context)
{
    if (r == NULL) return false;
    enter(r);
    bool idle = !r->status.running && !r->draining && r->compact_count == 0;
    if (idle) {
        r->compact_events = storage;
        r->compact_consume = consume;
        r->compact_context = context;
        r->compact_head = r->compact_deauth_count = 0;
        if (storage != NULL)
            memset(storage, 0, WIFI_SHIELD_COMPACT_EVENT_CAPACITY * sizeof(*storage));
    }
    leave(r);
    return idle;
}

bool wifi_security_runtime_detach_compact(wifi_security_runtime_t *r)
{
    return wifi_security_runtime_bind_compact(r, NULL, NULL, NULL);
}

static bool compact_deauth(wifi_shield_compact_kind_t kind)
{
    return kind == WIFI_SHIELD_COMPACT_DEAUTH || kind == WIFI_SHIELD_COMPACT_DISASSOC;
}

bool wifi_security_runtime_submit_compact(wifi_security_runtime_t *r,
    const wifi_shield_compact_event_t *event)
{
    if (r == NULL || event == NULL || event->length == 0 ||
        event->length > WIFI_SHIELD_COMPACT_BYTES ||
        event->kind < WIFI_SHIELD_COMPACT_DEAUTH ||
        event->kind > WIFI_SHIELD_COMPACT_REASSOC) return false;
    enter(r);
    increment(&r->status.received);
    if (event->generation == 0 || event->generation != r->last_generation) {
        increment(&r->status.stale_generation);
        leave(r);
        return false;
    }
    if (!r->status.running || !r->callbacks_open || r->status.stopping ||
        r->config.module != WIFI_SECURITY_MODULE_SHIELD) {
        leave(r);
        return false;
    }
    bool deauth = compact_deauth(event->kind);
    if (r->compact_events == NULL || r->compact_count == WIFI_SHIELD_COMPACT_EVENT_CAPACITY ||
        (deauth && r->compact_deauth_count == WIFI_SHIELD_DEAUTH_EVENT_CAPACITY)) {
        increment(&r->status.dropped_queue);
        increment(&r->status.rx_drops);
        leave(r);
        return false;
    }
    bool notify = r->queue_count == 0 && r->compact_count == 0;
    unsigned tail = (r->compact_head + r->compact_count) % WIFI_SHIELD_COMPACT_EVENT_CAPACITY;
    r->compact_events[tail] = *event;
    ++r->compact_count;
    if (deauth) ++r->compact_deauth_count;
    increment(&r->status.queued);
    leave(r);
    if (notify && r->hooks.notify != NULL) r->hooks.notify(r->hooks.context);
    return true;
}

size_t wifi_security_runtime_drain_bounded(wifi_security_runtime_t *r,
                                           size_t max_records)
{
    if (r == NULL || max_records == 0U) return 0;
    enter(r);
    if (r->draining) {
        leave(r);
        return 0;
    }
    r->draining = true;
    size_t released = 0;
    bool prefer_compact = true;
    while (released < max_records &&
           (r->queue_count != 0 || r->compact_count != 0)) {
        if (r->compact_count != 0 && (prefer_compact || r->queue_count == 0)) {
            wifi_shield_compact_event_t event = r->compact_events[r->compact_head];
            wipe(&r->compact_events[r->compact_head], sizeof(event));
            r->compact_head = (r->compact_head + 1U) % WIFI_SHIELD_COMPACT_EVENT_CAPACITY;
            --r->compact_count;
            if (compact_deauth(event.kind)) --r->compact_deauth_count;
            wifi_security_compact_consume_fn consume = r->compact_consume;
            void *context = r->compact_context;
            leave(r);
            bool processed = consume != NULL && consume(context, &event);
            wipe(&event, sizeof(event));
            enter(r);
            if (processed) increment(&r->status.processed);
            ++released;
            prefer_compact = false;
            continue;
        }
        uint8_t index = r->queue[r->queue_head];
        r->queue[r->queue_head] = 0;
        r->queue_head = (r->queue_head + 1U) % WIFI_SECURITY_POOL_SLOTS;
        --r->queue_count;
        r->slot_state[index] = SLOT_WORKER;
        wifi_security_runtime_config_t config = r->config;
        const wifi_security_frame_slot_t *slot = &r->slots[index];
        leave(r);

        wifi_security_decoded_t decoded;
        bool valid = wifi_security_decode(slot->bytes, slot->captured_len, &decoded);
        bool processed = valid && config.consume != NULL &&
                         config.consume(config.context, slot, &decoded);

        enter(r);
        if (!valid) increment(&r->status.decode_rejected);
        if (processed) increment(&r->status.processed);
        release_locked(r, index);
        ++released;
        prefer_compact = true;
    }
    r->draining = false;
    leave(r);
    return released;
}

size_t wifi_security_runtime_drain(wifi_security_runtime_t *r)
{
    return wifi_security_runtime_drain_bounded(r, SIZE_MAX);
}

void wifi_security_runtime_get_status(wifi_security_runtime_t *r,
                                      wifi_security_runtime_status_t *status)
{
    if (r == NULL || status == NULL) return;
    enter(r);
    *status = r->status;
    leave(r);
}

bool wifi_security_session_init(wifi_security_session_t *s,
                                wifi_security_runtime_t *runtime,
                                const wifi_security_platform_hooks_t *h)
{
    if (s == NULL || runtime == NULL || h == NULL ||
        h->lease_acquire == NULL || h->baseline_idle == NULL || h->lease_mark_running == NULL ||
        h->lease_cancelled == NULL || h->generation_open == NULL || h->lease_cancel == NULL ||
        h->lease_begin_cleanup == NULL || h->lease_finish_cleanup == NULL ||
        h->channel_read == NULL || h->channel_tune == NULL ||
        h->channel_restore == NULL ||
        h->filter_read == NULL || h->filter_apply == NULL || h->filter_restore == NULL ||
        h->prepare == NULL || h->worker_create == NULL ||
        h->callback_register == NULL || h->callback_unregister == NULL ||
        h->promiscuous == NULL || h->worker_stop == NULL ||
        h->worker_join == NULL || h->monotonic_us == NULL || h->uncertainty == NULL) return false;
    memset(s, 0, sizeof(*s));
    s->runtime = runtime;
    s->hooks = *h;
    return true;
}

static wifi_security_session_result_t uncertain(
    wifi_security_session_t *s, wifi_security_session_result_t result)
{
    wifi_security_platform_hooks_t *h = &s->hooks;
    if (!s->cleanup_begun)
        s->cleanup_begun = h->lease_begin_cleanup(h->context, s->generation);
    if (s->cleanup_begun) {
        (void)h->lease_finish_cleanup(h->context, s->generation, false);
        s->cleanup_begun = false; /* Quarantined; retry begins cleanup anew. */
    }
    h->uncertainty(h->context, &s->config, result);
    return result;
}

wifi_security_session_result_t wifi_security_session_quiesce(
    wifi_security_session_t *s, uint32_t timeout_ms)
{
    if (s == NULL) return WIFI_SECURITY_SESSION_INVALID;
    if (!s->active) return WIFI_SECURITY_SESSION_OK;
    wifi_security_platform_hooks_t *h = &s->hooks;
    void *ctx = h->context;
    if (s->quiesced) {
        /* The legacy monolithic Stop historically repeated cancellation on a
         * cleanup retry. Shield's outer lifecycle does not re-enter this phase. */
        h->lease_cancel(ctx, s->generation);
        return WIFI_SECURITY_SESSION_OK;
    }
    /* A rejected host baseline owns only a PREPARING reservation. It must not
     * touch legacy callbacks/filter/channel/workers or wipe the feature context. */
    if (!s->baseline_ready) {
        s->quiesced = true;
        return WIFI_SECURITY_SESSION_OK;
    }
    uint64_t started = h->monotonic_us(ctx);
    wifi_security_runtime_close_callbacks(s->runtime);
    bool quiet = true;
    if (s->callback_registered) {
        if (h->callback_unregister(ctx)) s->callback_registered = false;
        else quiet = false;
    }
    if (s->promiscuous_enabled) {
        if (h->promiscuous(ctx, false)) s->promiscuous_enabled = false;
        else quiet = false;
    }
    wifi_security_runtime_request_stop(s->runtime);
    h->lease_cancel(ctx, s->generation);
    if (s->worker_created) {
        h->worker_stop(ctx);
        uint64_t elapsed_ms = (h->monotonic_us(ctx) - started) / 1000U;
        uint32_t remaining = elapsed_ms < timeout_ms ?
                             timeout_ms - (uint32_t)elapsed_ms : 0U;
        if (!h->worker_join(ctx, remaining))
            return uncertain(s, WIFI_SECURITY_SESSION_JOIN_TIMEOUT);
        s->worker_created = false;
    }
    if (!quiet) return uncertain(s, WIFI_SECURITY_SESSION_CLEANUP_FAILED);
    s->quiesced = true;
    return WIFI_SECURITY_SESSION_OK;
}

wifi_security_session_result_t wifi_security_session_finish_cleanup(
    wifi_security_session_t *s)
{
    if (s == NULL) return WIFI_SECURITY_SESSION_INVALID;
    if (!s->active) return WIFI_SECURITY_SESSION_OK;
    if (!s->quiesced) return WIFI_SECURITY_SESSION_CLEANUP_FAILED;
    wifi_security_platform_hooks_t *h = &s->hooks;
    void *ctx = h->context;
    if (!s->baseline_ready) goto release_lease;
    if (s->filter_restore_pending) {
        if (!h->filter_restore(ctx, s->saved_filter))
            return uncertain(s, WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED);
        s->filter_restore_pending = false;
    }
    if (s->channel_saved) {
        if (!h->channel_restore(ctx, s->saved_primary, s->saved_secondary))
            return uncertain(s, WIFI_SECURITY_SESSION_RESTORE_FAILED);
        s->channel_saved = false;
    }
    if (!wifi_security_runtime_finish(s->runtime))
        return uncertain(s, WIFI_SECURITY_SESSION_CLEANUP_FAILED);
release_lease:
    if (!s->cleanup_begun)
        s->cleanup_begun = h->lease_begin_cleanup(ctx, s->generation);
    if (!s->cleanup_begun ||
        !h->lease_finish_cleanup(ctx, s->generation, true))
        return uncertain(s, WIFI_SECURITY_SESSION_CLEANUP_FAILED);
    /* The feature context remains borrowed while this exact generation can
     * still own or mutate the radio.  Feature wipe is infallible, so perform
     * it only after verified lease release and exactly once. */
    if (s->baseline_ready && !s->context_wiped) {
        s->config.wipe(s->config.context);
        s->context_wiped = true;
    }
    memset(&s->config, 0, sizeof(s->config));
    s->generation = 0;
    s->active = false;
    s->baseline_ready = false;
    s->saved_filter = 0;
    s->cleanup_begun = false;
    s->quiesced = false;
    return WIFI_SECURITY_SESSION_OK;
}

wifi_security_session_result_t wifi_security_session_stop(
    wifi_security_session_t *s, uint32_t timeout_ms)
{
    wifi_security_session_result_t result =
        wifi_security_session_quiesce(s, timeout_ms);
    return result == WIFI_SECURITY_SESSION_OK ?
        wifi_security_session_finish_cleanup(s) : result;
}

static wifi_security_session_result_t session_start_after_baseline(
    wifi_security_session_t *s, const wifi_security_session_config_t *config,
    uint32_t rollback_timeout_ms)
{
    wifi_security_platform_hooks_t *h = &s->hooks;
    void *ctx = h->context;
    wifi_security_session_result_t error = WIFI_SECURITY_SESSION_CANCELLED;
    if (h->lease_cancelled(ctx, s->generation)) goto rollback;
    error = WIFI_SECURITY_SESSION_CHANNEL_FAILED;
    if (!h->channel_read(ctx, &s->saved_primary, &s->saved_secondary)) goto rollback;
    s->channel_saved = true;
    if (h->lease_cancelled(ctx, s->generation)) goto cancelled;
    error = WIFI_SECURITY_SESSION_FILTER_SNAPSHOT_FAILED;
    if (!h->filter_read(ctx, &s->saved_filter)) goto rollback;
    if (h->lease_cancelled(ctx, s->generation)) goto cancelled;
    error = WIFI_SECURITY_SESSION_PREPARE_FAILED;
    if (!h->prepare(ctx)) goto rollback;
    if (h->lease_cancelled(ctx, s->generation)) goto cancelled;
    error = WIFI_SECURITY_SESSION_WORKER_FAILED;
    if (!h->worker_create(ctx, s->runtime)) goto rollback;
    s->worker_created = true;
    if (h->lease_cancelled(ctx, s->generation)) goto cancelled;
    error = WIFI_SECURITY_SESSION_CALLBACK_FAILED;
    if (!h->callback_register(ctx, s->generation)) goto rollback;
    s->callback_registered = true;
    if (h->lease_cancelled(ctx, s->generation)) goto cancelled;
    error = WIFI_SECURITY_SESSION_FILTER_APPLY_FAILED;
    s->filter_restore_pending = true; /* Failed apply may have partially mutated. */
    wifi_security_receive_policy_t receive_policy = config->receive_policy;
    if (receive_policy == WIFI_SECURITY_RECEIVE_DEFAULT)
        receive_policy = WIFI_SECURITY_RECEIVE_MGMT |
                         WIFI_SECURITY_RECEIVE_DATA;
    if ((receive_policy & ~(WIFI_SECURITY_RECEIVE_MGMT |
                            WIFI_SECURITY_RECEIVE_DATA)) != 0U ||
        receive_policy == WIFI_SECURITY_RECEIVE_DEFAULT ||
        !h->filter_apply(ctx, receive_policy))
        goto rollback;
    if (h->lease_cancelled(ctx, s->generation)) goto cancelled;
    if (config->initial_channel != 0U) {
        error = WIFI_SECURITY_SESSION_CHANNEL_FAILED;
        if (!h->channel_tune(ctx, config->initial_channel)) goto rollback;
        if (h->lease_cancelled(ctx, s->generation)) goto cancelled;
    }
    error = WIFI_SECURITY_SESSION_PROMISCUOUS_FAILED;
    if (!h->promiscuous(ctx, true)) goto rollback;
    s->promiscuous_enabled = true;
    if (h->lease_cancelled(ctx, s->generation)) goto cancelled;
    error = WIFI_SECURITY_SESSION_MARK_FAILED;
    if (!h->lease_mark_running(ctx, s->generation)) goto rollback;
    if (h->lease_cancelled(ctx, s->generation)) goto cancelled;
    wifi_security_runtime_config_t core = {
        config->module, s->generation, config->context, config->consume
    };
    if (h->generation_open(ctx, s->runtime, &core)) return WIFI_SECURITY_SESSION_OK;
    error = WIFI_SECURITY_SESSION_INVALID;
    goto rollback;

cancelled:
    error = WIFI_SECURITY_SESSION_CANCELLED;
rollback:
    if (h->lease_cancelled(ctx, s->generation)) error = WIFI_SECURITY_SESSION_CANCELLED;
    {
        wifi_security_session_result_t cleanup = wifi_security_session_stop(s, rollback_timeout_ms);
        return cleanup == WIFI_SECURITY_SESSION_OK ? error : cleanup;
    }
}

static bool session_config_valid(const wifi_security_session_config_t *config)
{
    return config != NULL && config->validate != NULL && config->wipe != NULL &&
        config->uncertainty != NULL &&
        config->module >= WIFI_SECURITY_MODULE_WPS_GUARD &&
        config->module <= WIFI_SECURITY_MODULE_DEAUTH_V2;
}

wifi_security_session_result_t wifi_security_session_start_reserved(
    wifi_security_session_t *s, const wifi_security_session_config_t *config,
    uint32_t generation, uint32_t rollback_timeout_ms)
{
    if (s == NULL || !session_config_valid(config) || generation == 0U)
        return WIFI_SECURITY_SESSION_INVALID;
    if (s->active) return WIFI_SECURITY_SESSION_BUSY;
    if (!config->validate(config->context)) return WIFI_SECURITY_SESSION_INVALID;
    s->generation = generation;
    s->active = true;
    s->context_wiped = false;
    s->quiesced = false;
    s->baseline_ready = true;
    s->config = *config;
    return session_start_after_baseline(s, config, rollback_timeout_ms);
}

wifi_security_session_result_t wifi_security_session_start(
    wifi_security_session_t *s, const wifi_security_session_config_t *config,
    uint32_t rollback_timeout_ms)
{
    if (s == NULL || !session_config_valid(config))
        return WIFI_SECURITY_SESSION_INVALID;
    if (s->active) return WIFI_SECURITY_SESSION_BUSY;
    if (!config->validate(config->context)) return WIFI_SECURITY_SESSION_INVALID;
    wifi_security_platform_hooks_t *h = &s->hooks;
    void *ctx = h->context;
    if (!h->lease_acquire(ctx, &s->generation)) return WIFI_SECURITY_SESSION_BUSY;
    s->active = true;
    s->context_wiped = false;
    s->quiesced = false;
    s->config = *config;
    if (h->lease_cancelled(ctx, s->generation))
        return wifi_security_session_stop(s, rollback_timeout_ms) ==
            WIFI_SECURITY_SESSION_OK ? WIFI_SECURITY_SESSION_CANCELLED :
            WIFI_SECURITY_SESSION_CLEANUP_FAILED;
    if (!h->baseline_idle(ctx)) {
        wifi_security_session_result_t cleanup =
            wifi_security_session_stop(s, rollback_timeout_ms);
        return cleanup == WIFI_SECURITY_SESSION_OK ?
            WIFI_SECURITY_SESSION_BASELINE_BUSY : cleanup;
    }
    s->baseline_ready = true;
    return session_start_after_baseline(s, config, rollback_timeout_ms);
}
