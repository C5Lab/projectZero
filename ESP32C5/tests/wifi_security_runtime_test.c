#include "wifi_security_runtime.h"
#include "janos_radio_lease.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    wifi_security_runtime_t runtime;
    unsigned lock_depth, notifications, calls;
    bool in_callback, fail_consume, reenter;
    uint64_t order[32];
} fixture_t;

static void enter(void *context)
{
    fixture_t *f = context;
    assert(f->lock_depth == 0);
    f->lock_depth++;
}

static void leave(void *context)
{
    fixture_t *f = context;
    assert(f->lock_depth == 1);
    f->lock_depth--;
}

static void notify(void *context)
{
    fixture_t *f = context;
    assert(f->lock_depth == 0);
    f->notifications++;
}

static bool consume(void *context, const wifi_security_frame_slot_t *slot,
                    const wifi_security_decoded_t *decoded)
{
    fixture_t *f = context;
    assert(!f->in_callback && f->lock_depth == 0);
    assert(slot->generation == f->runtime.config.generation);
    assert(slot->captured_len <= 1536);
    assert(decoded->body == slot->bytes + 24);
    assert(decoded->body_len == (size_t)slot->captured_len - 24);
    assert(slot->rssi == -42 && slot->channel == 6);
    if (slot->truncated) {
        assert(slot->captured_len == 1536 && slot->original_len == 1600);
        assert(decoded->body_len == 1512);
        assert(decoded->body[1511] == 0xa5);
    }
    f->order[f->calls++] = slot->timestamp_us;
    if (f->reenter) {
        assert(wifi_security_runtime_drain(&f->runtime) == 0);
        wifi_security_runtime_request_stop(&f->runtime);
        assert(!wifi_security_runtime_finish(&f->runtime));
    }
    return !f->fail_consume;
}

static wifi_security_runtime_config_t config(fixture_t *f, uint32_t generation)
{
    wifi_security_runtime_config_t c = {
        WIFI_SECURITY_MODULE_WPS_GUARD, generation, f, consume
    };
    return c;
}

static void setup(fixture_t *f, uint8_t capacity)
{
    memset(f, 0, sizeof(*f));
    wifi_security_runtime_hooks_t h = {f, enter, leave, notify};
    assert(wifi_security_runtime_init(&f->runtime, &h, capacity));
    wifi_security_runtime_config_t c = config(f, 1);
    assert(wifi_security_runtime_start(&f->runtime, &c));
}

static void frame(uint8_t *bytes, size_t size)
{
    memset(bytes, 0xa5, size);
    bytes[0] = 0x08; /* Unprotected no-DS data, 24-byte header. */
    bytes[1] = 0;
    bytes[4] = bytes[10] = bytes[16] = 2;
}

static bool submit(fixture_t *f, uint32_t gen, uint64_t id, uint16_t length)
{
    uint8_t bytes[1600];
    frame(bytes, sizeof(bytes));
    f->in_callback = true;
    bool result = wifi_security_runtime_submit(&f->runtime, gen, bytes, length,
                                               id, -42, 6);
    f->in_callback = false;
    memset(bytes, 0, sizeof(bytes)); /* Queued bytes must own their storage. */
    return result;
}

static wifi_security_runtime_status_t status(fixture_t *f)
{
    wifi_security_runtime_status_t out;
    wifi_security_runtime_get_status(&f->runtime, &out);
    return out;
}

static void zero_slot(const wifi_security_frame_slot_t *slot)
{
    const unsigned char *bytes = (const unsigned char *)slot;
    for (size_t i = 0; i < sizeof(*slot); ++i) assert(bytes[i] == 0);
}

static void empty_pool(fixture_t *f)
{
    uint8_t indexes[8];
    for (unsigned i = 0; i < 8; ++i) {
        wifi_security_frame_slot_t *slot;
        assert(wifi_security_runtime_claim(&f->runtime, &indexes[i], &slot));
        zero_slot(slot);
    }
    for (unsigned i = 0; i < 8; ++i)
        assert(wifi_security_runtime_release(&f->runtime, indexes[i]));
}

/* Catches pool overcommit, double free, and incomplete metadata/payload wipes. */
static void pool_lifecycle(void)
{
    fixture_t f;
    setup(&f, 8);
    uint8_t indexes[8], extra;
    wifi_security_frame_slot_t *slots[8], *slot;
    for (unsigned i = 0; i < 8; ++i) {
        assert(wifi_security_runtime_claim(&f.runtime, &indexes[i], &slots[i]));
        zero_slot(slots[i]);
        memset(slots[i], 0x5a, sizeof(*slots[i]));
        for (unsigned j = 0; j < i; ++j) assert(indexes[j] != indexes[i]);
    }
    assert(!wifi_security_runtime_claim(&f.runtime, &extra, &slot));
    assert(status(&f).dropped_pool == 1);
    const unsigned order[] = {5, 1, 7, 0, 3, 6, 2, 4};
    for (unsigned i = 0; i < 8; ++i) {
        uint8_t index = indexes[order[i]];
        assert(wifi_security_runtime_release(&f.runtime, index));
        zero_slot(slots[order[i]]);
        assert(!wifi_security_runtime_release(&f.runtime, index));
    }
    assert(!wifi_security_runtime_release(&f.runtime, 8));
    empty_pool(&f);
}

/* Catches premature decoding, reordering, leaked slots and uncopied tail views. */
static void worker_order_and_failures(void)
{
    fixture_t f;
    setup(&f, 8);
    for (unsigned i = 0; i < 8; ++i) assert(submit(&f, 1, i, i == 7 ? 1600 : 32));
    assert(!submit(&f, 1, 99, 32));
    assert(f.calls == 0 && f.notifications == 1);
    assert(status(&f).decode_rejected == 0 && status(&f).processed == 0);
    assert(!wifi_security_runtime_release(&f.runtime, 0)); /* Queue owns it. */
    assert(wifi_security_runtime_drain(&f.runtime) == 8);
    for (unsigned i = 0; i < 8; ++i) assert(f.order[i] == i);
    assert(status(&f).processed == 8 && status(&f).truncated == 1);
    assert(wifi_security_runtime_drain(&f.runtime) == 0);
    empty_pool(&f);
    assert(submit(&f, 1, 8, 1)); /* Decoder rejects short frame on worker only. */
    assert(status(&f).decode_rejected == 0);
    assert(wifi_security_runtime_drain(&f.runtime) == 1);
    assert(status(&f).decode_rejected == 1 && f.calls == 8);
    empty_pool(&f);
    f.fail_consume = true;
    assert(submit(&f, 1, 9, 32));
    assert(wifi_security_runtime_drain(&f.runtime) == 1);
    assert(status(&f).processed == 8 && f.calls == 9);
    empty_pool(&f);
    /* Wrap the ring head repeatedly, preserving FIFO across partial occupancy. */
    for (unsigned i = 10; i < 25; ++i) {
        assert(submit(&f, 1, i, 32));
        assert(wifi_security_runtime_drain(&f.runtime) == 1);
        assert(f.order[f.calls - 1] == i);
    }
    empty_pool(&f);
}

/* Catches a sustained producer starving the session scheduler/Stop poll. */
static void bounded_worker_drain(void)
{
    fixture_t f;
    setup(&f, 8);
    for (unsigned i = 0; i < 5; ++i) assert(submit(&f, 1, i, 32));
    assert(wifi_security_runtime_drain_bounded(&f.runtime, 2U) == 2U);
    assert(f.calls == 2U && f.order[0] == 0U && f.order[1] == 1U);
    assert(status(&f).processed == 2U);
    assert(wifi_security_runtime_drain_bounded(&f.runtime, 0U) == 0U);
    assert(f.calls == 2U);
    assert(wifi_security_runtime_drain_bounded(&f.runtime, 2U) == 2U);
    assert(wifi_security_runtime_drain_bounded(&f.runtime, 2U) == 1U);
    assert(f.calls == 5U && f.order[4] == 4U);
    assert(wifi_security_runtime_drain_bounded(&f.runtime, 2U) == 0U);
    empty_pool(&f);
}

/* Catches overwritten queue entries and leaked overflow reservations. */
static void queue_overflow(void)
{
    fixture_t f;
    setup(&f, 2);
    assert(submit(&f, 1, 11, 32));
    assert(submit(&f, 1, 12, 32));
    assert(!submit(&f, 1, 13, 1600));
    wifi_security_runtime_status_t s = status(&f);
    assert(s.received == 3 && s.queued == 2 && s.dropped_queue == 1);
    assert(s.dropped_pool == 0 && s.truncated == 1);
    assert(wifi_security_runtime_drain(&f.runtime) == 2);
    assert(f.calls == 2 && f.order[0] == 11 && f.order[1] == 12);
    empty_pool(&f);
}

/* Catches reopening a closed generation, stale delivery and unsafe finish. */
static void lifecycle(void)
{
    fixture_t f;
    setup(&f, 8);
    wifi_security_runtime_config_t c = config(&f, 1);
    assert(wifi_security_runtime_start(&f.runtime, &c));
    assert(status(&f).generation == 1U);
    assert(status(&f).module == WIFI_SECURITY_MODULE_WPS_GUARD);
    assert(!wifi_security_runtime_finish(&f.runtime));
    assert(!submit(&f, 0, 1, 32));
    assert(submit(&f, 1, 2, 32));
    wifi_security_runtime_close_callbacks(&f.runtime);
    wifi_security_runtime_close_callbacks(&f.runtime);
    assert(!submit(&f, 1, 3, 32));
    assert(!wifi_security_runtime_start(&f.runtime, &c));
    wifi_security_runtime_request_stop(&f.runtime);
    wifi_security_runtime_request_stop(&f.runtime);
    assert(status(&f).running && status(&f).stopping);
    assert(!wifi_security_runtime_finish(&f.runtime));
    assert(wifi_security_runtime_drain(&f.runtime) == 1);
    assert(f.calls == 1 && f.order[0] == 2);
    assert(wifi_security_runtime_finish(&f.runtime));
    assert(wifi_security_runtime_finish(&f.runtime));
    assert(!status(&f).running && !status(&f).stopping);
    assert(status(&f).generation == 1U);
    assert(!submit(&f, 1, 4, 32));
    assert(!wifi_security_runtime_start(&f.runtime, &c));
    c.generation = 0;
    assert(!wifi_security_runtime_start(&f.runtime, &c));
    c.generation = 2;
    assert(wifi_security_runtime_start(&f.runtime, &c));
    assert(status(&f).generation == 2U);
    assert(status(&f).module == WIFI_SECURITY_MODULE_WPS_GUARD);
    assert(!submit(&f, 1, 5, 32));
    assert(status(&f).stale_generation == 1);
    assert(submit(&f, 2, 6, 32));
    f.reenter = true;
    assert(wifi_security_runtime_drain(&f.runtime) == 1);
    assert(wifi_security_runtime_finish(&f.runtime));
    c.generation = 3;
    c.consume = NULL;
    assert(wifi_security_runtime_start(&f.runtime, &c));
    assert(status(&f).generation == 3U);
    assert(submit(&f, 3, 7, 32));
    assert(wifi_security_runtime_drain(&f.runtime) == 1);
    assert(status(&f).processed == 0 && f.calls == 2);
    empty_pool(&f);
    wifi_security_runtime_request_stop(&f.runtime);
    assert(wifi_security_runtime_finish(&f.runtime));
}

/* Each counter executes its real increment twice, from MAX-1 through MAX. */
static void saturation(void)
{
    fixture_t f;
    setup(&f, 1);
    f.runtime.status.received = f.runtime.status.queued = UINT32_MAX - 1;
    f.runtime.status.processed = f.runtime.status.truncated = UINT32_MAX - 1;
    f.runtime.status.dropped_pool = f.runtime.status.dropped_queue = UINT32_MAX - 1;
    f.runtime.status.stale_generation = f.runtime.status.decode_rejected = UINT32_MAX - 1;
    for (unsigned i = 0; i < 2; ++i) {
        assert(!submit(&f, 0, 0, 32));
        assert(submit(&f, 1, i, 1600));
        assert(!submit(&f, 1, 99, 32));
        assert(wifi_security_runtime_drain(&f.runtime) == 1);
        assert(submit(&f, 1, 0, 1));
        assert(wifi_security_runtime_drain(&f.runtime) == 1);
        uint8_t ids[8], id;
        wifi_security_frame_slot_t *slot;
        for (unsigned j = 0; j < 8; ++j)
            assert(wifi_security_runtime_claim(&f.runtime, &ids[j], &slot));
        assert(!wifi_security_runtime_claim(&f.runtime, &id, &slot));
        for (unsigned j = 0; j < 8; ++j)
            assert(wifi_security_runtime_release(&f.runtime, ids[j]));
    }
    wifi_security_runtime_status_t s = status(&f);
    assert(s.received == UINT32_MAX && s.queued == UINT32_MAX);
    assert(s.processed == UINT32_MAX && s.truncated == UINT32_MAX);
    assert(s.dropped_pool == UINT32_MAX && s.dropped_queue == UINT32_MAX);
    assert(s.stale_generation == UINT32_MAX && s.decode_rejected == UINT32_MAX);
    empty_pool(&f);
}

static void invalid_init_and_inputs(void)
{
    fixture_t f;
    memset(&f, 0, sizeof(f));
    wifi_security_runtime_hooks_t h = {&f, enter, leave, NULL};
    assert(!wifi_security_runtime_init(NULL, &h, 8));
    assert(!wifi_security_runtime_init(&f.runtime, &h, 0));
    assert(!wifi_security_runtime_init(&f.runtime, &h, 9));
    h.leave = NULL;
    assert(!wifi_security_runtime_init(&f.runtime, &h, 8));
    h.enter = NULL; /* Explicit single-thread mode. */
    assert(wifi_security_runtime_init(&f.runtime, &h, 8));
    wifi_security_runtime_config_t c = config(&f, 0);
    assert(!wifi_security_runtime_start(&f.runtime, &c));
    c.generation = 1;
    c.module = WIFI_SECURITY_MODULE_NONE;
    assert(!wifi_security_runtime_start(&f.runtime, &c));
    c.module = WIFI_SECURITY_MODULE_TRUST_MONITOR;
    assert(wifi_security_runtime_start(&f.runtime, &c));
    assert(!wifi_security_runtime_submit(&f.runtime, 1, NULL, 32, 0, -42, 6));
    assert(!submit(&f, 1, 0, 0));
    assert(wifi_security_runtime_drain(&f.runtime) == 0);
    wifi_security_runtime_request_stop(&f.runtime);
    assert(wifi_security_runtime_finish(&f.runtime));
    wifi_security_runtime_close_callbacks(&f.runtime);
    wifi_security_runtime_request_stop(&f.runtime);
    assert(wifi_security_runtime_finish(&f.runtime));
}

/* Real runtime + real lease; only the hardware/task boundary is replaced.
 * Removing/reordering any lifecycle operation breaks the literal traces below. */
typedef struct {
    fixture_t core;
    wifi_security_session_t session;
    janos_radio_lease_t lease;
    char trace[256];
    size_t used;
    char fail, cancel_at;
    bool opening, worker, callback, promiscuous, stop_signal;
    unsigned wipes, reports;
    wifi_security_receive_policy_t applied_policy;
    uint8_t secret[16];
    uint64_t now;
    uint32_t filter_mask;
    uint8_t tuned_channel;
} platform_t;

static void event(platform_t *p, char id)
{
    assert(p->core.lock_depth == 0);
    p->trace[p->used++] = id;
    p->trace[p->used] = 0;
    assert(p->used < sizeof(p->trace));
    if (p->opening) {
        /* Even mark-running cannot admit a frame before the final core open. */
        assert(!submit(&p->core, p->session.generation, 99, 32));
        assert(p->core.calls == 0);
    }
    if (p->cancel_at == id) {
        janos_radio_lease_snapshot_t s = janos_radio_lease_snapshot(&p->lease);
        assert(janos_radio_lease_request_cancel(&p->lease, s.owner, s.generation));
    }
}

static bool validate_module(void *context)
{
    platform_t *p = context;
    event(p, 'V');
    return p->fail != 'V';
}

static bool acquire_lease(void *context, uint32_t *generation)
{
    platform_t *p = context;
    event(p, 'A');
    bool ok = janos_radio_lease_acquire(&p->lease,
        JANOS_RADIO_OWNER_SECURITY_MONITOR, generation) == JANOS_RADIO_LEASE_OK;
    if (ok && p->cancel_at == 'a')
        assert(janos_radio_lease_request_cancel(&p->lease,
            JANOS_RADIO_OWNER_SECURITY_MONITOR, *generation));
    return ok;
}

static bool mark_lease(void *context, uint32_t generation)
{
    platform_t *p = context;
    bool marked = p->fail != 'M' && janos_radio_lease_mark_running(&p->lease,
        JANOS_RADIO_OWNER_SECURITY_MONITOR, generation);
    /* Also try submit/cancel after the lease really becomes RUNNING. */
    event(p, 'M');
    return marked;
}

static bool is_cancelled(void *context, uint32_t generation)
{
    platform_t *p = context;
    return janos_radio_lease_cancel_requested(&p->lease,
        JANOS_RADIO_OWNER_SECURITY_MONITOR, generation);
}

static bool open_generation(void *context, wifi_security_runtime_t *runtime,
                            const wifi_security_runtime_config_t *config)
{
    /* The deterministic fake has no interleaving inside this handoff. The real
     * adapter's cancellation/open arbitration is exercised by the Python C fixture. */
    if (is_cancelled(context, config->generation)) return false;
    return wifi_security_runtime_start(runtime, config);
}

static void cancel_lease(void *context, uint32_t generation)
{
    platform_t *p = context;
    event(p, 'c');
    (void)janos_radio_lease_request_cancel(&p->lease,
        JANOS_RADIO_OWNER_SECURITY_MONITOR, generation);
}

static bool begin_cleanup(void *context, uint32_t generation)
{
    platform_t *p = context;
    event(p, 'B');
    return janos_radio_lease_begin_cleanup(&p->lease,
        JANOS_RADIO_OWNER_SECURITY_MONITOR, generation);
}

static bool finish_cleanup(void *context, uint32_t generation, bool restored)
{
    platform_t *p = context;
    event(p, restored ? 'L' : 'Q');
    if (restored && p->fail == 'L') return false;
    return janos_radio_lease_finish_cleanup(&p->lease,
        JANOS_RADIO_OWNER_SECURITY_MONITOR, generation, restored);
}

static bool baseline_idle(void *context)
{
    platform_t *p = context;
    event(p, 'H');
    assert(janos_radio_lease_snapshot(&p->lease).owner == JANOS_RADIO_OWNER_SECURITY_MONITOR);
    return p->fail != 'H';
}

static bool read_filter(void *context, uint32_t *mask)
{
    platform_t *p = context;
    event(p, 'F');
    *mask = p->filter_mask;
    return p->fail != 'F';
}

static bool apply_filter(void *context,
                         wifi_security_receive_policy_t policy)
{
    platform_t *p = context;
    event(p, 'I');
    p->applied_policy = policy;
    p->filter_mask = 5; /* Also mutate on failure: rollback must restore it. */
    return p->fail != 'I';
}

static bool restore_filter(void *context, uint32_t mask)
{
    platform_t *p = context;
    event(p, 'f');
    assert(!p->worker && !p->callback && !p->promiscuous && mask == 1);
    if (p->fail == 'f') return false;
    p->filter_mask = mask;
    return true;
}

static bool snapshot_channel(void *context, uint8_t *primary, uint8_t *secondary)
{
    platform_t *p = context;
    event(p, 'S');
    *primary = 44; *secondary = 2;
    return p->fail != 'S';
}

static bool restore_channel(void *context, uint8_t primary, uint8_t secondary)
{
    platform_t *p = context;
    event(p, 'R');
    assert(primary == 44 && secondary == 2 && !p->worker);
    return p->fail != 'R';
}

static bool tune_channel(void *context, uint8_t primary)
{
    platform_t *p = context;
    event(p, 'N');
    assert(primary != 0U && p->callback && !p->promiscuous);
    if (p->fail == 'N') return false;
    p->tuned_channel = primary;
    return true;
}

static bool prepare_resources(void *context)
{
    platform_t *p = context;
    event(p, 'P');
    return p->fail != 'P';
}

static bool create_worker(void *context, wifi_security_runtime_t *runtime)
{
    platform_t *p = context;
    event(p, 'T');
    assert(runtime == &p->core.runtime && !p->worker);
    if (p->fail == 'T') return false;
    p->worker = true;
    return true;
}

static bool register_callback(void *context, uint32_t generation)
{
    platform_t *p = context;
    event(p, 'C');
    assert(generation != 0 && p->worker);
    if (p->fail == 'C') return false;
    p->callback = true;
    return true;
}

static bool unregister_callback(void *context)
{
    platform_t *p = context;
    event(p, 'U');
    assert(!submit(&p->core, p->session.generation, 99, 32));
    if (!p->stop_signal) assert(!status(&p->core).stopping); /* close precedes stop signal */
    if (p->fail == 'U') return false;
    p->callback = false;
    return true;
}

static bool promiscuous(void *context, bool enabled)
{
    platform_t *p = context;
    event(p, enabled ? 'E' : 'D');
    if (p->fail == (enabled ? 'E' : 'D')) return false;
    p->promiscuous = enabled;
    return true;
}

static void stop_worker(void *context)
{
    platform_t *p = context;
    event(p, 'X');
    assert(!p->core.runtime.callbacks_open);
    if (status(&p->core).running) assert(status(&p->core).stopping);
    p->stop_signal = true;
}

static bool join_worker(void *context, uint32_t timeout_ms)
{
    platform_t *p = context;
    event(p, 'J');
    assert(timeout_ms <= 5000 && p->stop_signal);
    if (p->fail == 'J') return false;
    (void)wifi_security_runtime_drain(&p->core.runtime);
    p->worker = false;
    return true;
}

static void wipe_module(void *context)
{
    platform_t *p = context;
    event(p, 'W');
    assert(!p->worker && !p->core.runtime.status.running);
    for (unsigned i = 0; i < 8; ++i) zero_slot(&p->core.runtime.slots[i]);
    memset(p->secret, 0, sizeof(p->secret));
    p->wipes++;
}

static uint64_t monotonic_us(void *context)
{
    platform_t *p = context;
    p->now += 1000;
    return p->now;
}

static void feature_uncertainty(void *context, wifi_security_session_result_t result, bool owned)
{
    platform_t *p = context;
    assert(result != WIFI_SECURITY_SESSION_OK && owned);
    event(p, '!');
    p->reports++;
}

static void uncertainty(void *context, const wifi_security_session_config_t *config,
                        wifi_security_session_result_t result)
{
    platform_t *p = context;
    config->uncertainty(config->telemetry_context, result,
        janos_radio_lease_snapshot(&p->lease).owner == JANOS_RADIO_OWNER_SECURITY_MONITOR);
}

static wifi_security_session_config_t session_config(platform_t *p)
{
    wifi_security_session_config_t c = {
        .module = WIFI_SECURITY_MODULE_WPS_GUARD,
        .context = p, .consume = NULL,
        .validate = validate_module, .wipe = wipe_module,
        .uncertainty = feature_uncertainty, .telemetry_context = p
    };
    return c;
}

static void platform_setup(platform_t *p)
{
    memset(p, 0, sizeof(*p));
    memset(p->secret, 0x5a, sizeof(p->secret));
    p->filter_mask = 1;
    wifi_security_runtime_hooks_t h = {&p->core, enter, leave, notify};
    assert(wifi_security_runtime_init(&p->core.runtime, &h, WIFI_SECURITY_POOL_SLOTS));
    janos_radio_lease_init(&p->lease);
    wifi_security_platform_hooks_t hooks = {
        .context = p, .lease_acquire = acquire_lease, .lease_mark_running = mark_lease,
        .lease_cancelled = is_cancelled, .lease_cancel = cancel_lease,
        .generation_open = open_generation, .baseline_idle = baseline_idle,
        .filter_read = read_filter, .filter_apply = apply_filter, .filter_restore = restore_filter,
        .lease_begin_cleanup = begin_cleanup, .lease_finish_cleanup = finish_cleanup,
        .channel_read = snapshot_channel, .channel_tune = tune_channel,
        .channel_restore = restore_channel,
        .prepare = prepare_resources, .worker_create = create_worker,
        .callback_register = register_callback, .callback_unregister = unregister_callback,
        .promiscuous = promiscuous, .worker_stop = stop_worker, .worker_join = join_worker,
        .monotonic_us = monotonic_us, .uncertainty = uncertainty
    };
    assert(wifi_security_session_init(&p->session, &p->core.runtime, &hooks));
    p->opening = true;
}

static void expect_trace(platform_t *p, const char *expected);

static void platform_initial_tune_and_split_stop(void)
{
    platform_t p;
    platform_setup(&p);
    wifi_security_session_config_t c = session_config(&p);
    c.module = WIFI_SECURITY_MODULE_DEAUTH_V2;
    c.receive_policy = WIFI_SECURITY_RECEIVE_MGMT;
    c.initial_channel = 6U;
    assert(wifi_security_session_start(&p.session, &c, 5000) ==
           WIFI_SECURITY_SESSION_OK);
    p.opening = false;
    expect_trace(&p, "VAHSFPTCINEM");
    assert(p.applied_policy == WIFI_SECURITY_RECEIVE_MGMT);
    assert(p.tuned_channel == 6U);
    assert(wifi_security_session_quiesce(&p.session, 5000) ==
           WIFI_SECURITY_SESSION_OK);
    expect_trace(&p, "UDcXJ");
    assert(p.session.active && !p.worker && !p.callback && !p.promiscuous);
    assert(janos_radio_lease_snapshot(&p.lease).owner ==
           JANOS_RADIO_OWNER_SECURITY_MONITOR);
    assert(wifi_security_session_finish_cleanup(&p.session) ==
           WIFI_SECURITY_SESSION_OK);
    expect_trace(&p, "fRBLW");
    assert(!p.session.active && p.wipes == 1U);

    platform_setup(&p);
    p.fail = 'N';
    c = session_config(&p);
    c.initial_channel = 11U;
    assert(wifi_security_session_start(&p.session, &c, 5000) ==
           WIFI_SECURITY_SESSION_CHANNEL_FAILED);
    expect_trace(&p, "VAHSFPTCINUcXJfRBLW");
    assert(!p.session.active && p.wipes == 1U);
}

static void platform_adopts_existing_preparing_reservation(void)
{
    platform_t p;
    platform_setup(&p);
    uint32_t generation = 0U;
    assert(acquire_lease(&p, &generation));
    assert(baseline_idle(&p));
    expect_trace(&p, "AH");
    wifi_security_session_config_t c = session_config(&p);
    c.initial_channel = 11U;
    assert(wifi_security_session_start_reserved(&p.session, &c, generation,
                                                 5000U) ==
           WIFI_SECURITY_SESSION_OK);
    p.opening = false;
    expect_trace(&p, "VSFPTCINEM");
    assert(p.session.generation == generation && p.tuned_channel == 11U);
    assert(wifi_security_session_stop(&p.session, 5000U) ==
           WIFI_SECURITY_SESSION_OK);
    expect_trace(&p, "UDcXJfRBLW");
}

static void expect_trace(platform_t *p, const char *expected)
{
    if (strcmp(p->trace, expected) != 0) fprintf(stderr, "trace %s expected %s\n", p->trace, expected);
    assert(strcmp(p->trace, expected) == 0);
    p->used = 0; p->trace[0] = 0;
}

static void platform_lifecycle(void)
{
    platform_t p;
    platform_setup(&p);
    wifi_security_session_config_t c = session_config(&p);
    assert(wifi_security_session_start(&p.session, &c, 5000) == WIFI_SECURITY_SESSION_OK);
    p.opening = false;
    expect_trace(&p, "VAHSFPTCIEM");
    assert(janos_radio_lease_snapshot(&p.lease).state == JANOS_RADIO_LEASE_RUNNING);
    assert(submit(&p.core, p.session.generation, 7, 32));
    assert(wifi_security_session_stop(&p.session, 5000) == WIFI_SECURITY_SESSION_OK);
    expect_trace(&p, "UDcXJfRBLW");
    assert(!p.session.active && p.wipes == 1 && !p.worker);
    assert(janos_radio_lease_snapshot(&p.lease).owner == JANOS_RADIO_OWNER_NONE);
    assert(wifi_security_session_stop(&p.session, 5000) == WIFI_SECURITY_SESSION_OK);
    expect_trace(&p, "");
    assert(p.wipes == 1 && p.reports == 0);
}

static void platform_start_failures(void)
{
    const struct { char fail; wifi_security_session_result_t result; const char *trace; } cases[] = {
        {'V', WIFI_SECURITY_SESSION_INVALID, "V"},
        {'H', WIFI_SECURITY_SESSION_BASELINE_BUSY, "VAHBL"},
        {'F', WIFI_SECURITY_SESSION_FILTER_SNAPSHOT_FAILED, "VAHSFcRBLW"},
        {'I', WIFI_SECURITY_SESSION_FILTER_APPLY_FAILED, "VAHSFPTCIUcXJfRBLW"},
        {'S', WIFI_SECURITY_SESSION_CHANNEL_FAILED, "VAHScBLW"},
        {'P', WIFI_SECURITY_SESSION_PREPARE_FAILED, "VAHSFPcRBLW"},
        {'T', WIFI_SECURITY_SESSION_WORKER_FAILED, "VAHSFPTcRBLW"},
        {'C', WIFI_SECURITY_SESSION_CALLBACK_FAILED, "VAHSFPTCcXJRBLW"},
        {'E', WIFI_SECURITY_SESSION_PROMISCUOUS_FAILED, "VAHSFPTCIEUcXJfRBLW"},
        {'M', WIFI_SECURITY_SESSION_MARK_FAILED, "VAHSFPTCIEMUDcXJfRBLW"}
    };
    for (unsigned i = 0; i < sizeof(cases)/sizeof(cases[0]); ++i) {
        platform_t p;
        platform_setup(&p);
        p.fail = cases[i].fail;
        wifi_security_session_config_t c = session_config(&p);
        assert(wifi_security_session_start(&p.session, &c, 5000) == cases[i].result);
        expect_trace(&p, cases[i].trace);
        assert(!p.session.active && !p.worker && !p.callback && !p.promiscuous);
        assert(p.filter_mask == 1);
        if (p.fail == 'H') assert(p.wipes == 0 && p.secret[0] == 0x5a);
        assert(janos_radio_lease_snapshot(&p.lease).owner == JANOS_RADIO_OWNER_NONE);
    }
    platform_t p;
    platform_setup(&p);
    uint32_t occupied;
    assert(janos_radio_lease_acquire(&p.lease, JANOS_RADIO_OWNER_LEGACY, &occupied) == JANOS_RADIO_LEASE_OK);
    wifi_security_session_config_t c = session_config(&p);
    c.uncertainty = NULL;
    assert(wifi_security_session_start(&p.session, &c, 5000) == WIFI_SECURITY_SESSION_INVALID);
    expect_trace(&p, "");
    c = session_config(&p);
    assert(wifi_security_session_start(&p.session, &c, 5000) == WIFI_SECURITY_SESSION_BUSY);
    expect_trace(&p, "VA");
    assert(janos_radio_lease_snapshot(&p.lease).owner == JANOS_RADIO_OWNER_LEGACY);
    assert(p.wipes == 0);
}

static void platform_cancel_and_retry(void)
{
    /* Cancel at every completed startup side effect, including mark-running. */
    const char boundaries[] = "aHSFPTCIEM";
    const char *traces[] = {
        "VABL", "VAHcBLW", "VAHScRBLW", "VAHSFcRBLW", "VAHSFPcRBLW",
        "VAHSFPTcXJRBLW", "VAHSFPTCUcXJRBLW", "VAHSFPTCIUcXJfRBLW",
        "VAHSFPTCIEUDcXJfRBLW", "VAHSFPTCIEMUDcXJfRBLW"
    };
    for (size_t i = 0; i < sizeof(boundaries) - 1; ++i) {
        platform_t p;
        platform_setup(&p);
        p.cancel_at = boundaries[i];
        wifi_security_session_config_t c = session_config(&p);
        assert(wifi_security_session_start(&p.session, &c, 5000) == WIFI_SECURITY_SESSION_CANCELLED);
        expect_trace(&p, traces[i]);
        assert(!p.session.active && !p.worker && !p.callback && !p.promiscuous);
        assert(p.filter_mask == 1);
        assert(janos_radio_lease_snapshot(&p.lease).owner == JANOS_RADIO_OWNER_NONE);
        assert(p.core.calls == 0 && p.wipes == (boundaries[i] == 'a' ? 0U : 1U));
    }
    const char failures[] = "JfR";
    for (size_t i = 0; i < sizeof(failures) - 1; ++i) {
        platform_t p;
        platform_setup(&p);
        wifi_security_session_config_t c = session_config(&p);
        assert(wifi_security_session_start(&p.session, &c, 5000) == WIFI_SECURITY_SESSION_OK);
        p.opening = false;
        p.used = 0; p.trace[0] = 0;
        assert(submit(&p.core, p.session.generation, 1, 32));
        p.fail = failures[i];
        wifi_security_session_result_t want = p.fail == 'J' ?
            WIFI_SECURITY_SESSION_JOIN_TIMEOUT : p.fail == 'f' ?
            WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED : WIFI_SECURITY_SESSION_RESTORE_FAILED;
        assert(wifi_security_session_stop(&p.session, 5000) == want);
        expect_trace(&p, p.fail == 'J' ? "UDcXJBQ!" : p.fail == 'f' ? "UDcXJfBQ!" : "UDcXJfRBQ!");
        assert(p.session.active && p.wipes == 0 && p.secret[0] == 0x5a);
        assert(status(&p.core).stopping && p.core.runtime.config.context == &p);
        assert(!submit(&p.core, p.session.generation, 2, 32));
        assert(janos_radio_lease_snapshot(&p.lease).state == JANOS_RADIO_LEASE_QUARANTINED);
        assert(janos_radio_lease_snapshot(&p.lease).owner == JANOS_RADIO_OWNER_SECURITY_MONITOR);
        p.fail = 0;
        assert(wifi_security_session_stop(&p.session, 5000) == WIFI_SECURITY_SESSION_OK);
        expect_trace(&p, failures[i] == 'J' ? "cXJfRBLW" : failures[i] == 'f' ? "cfRBLW" : "cRBLW");
        assert(!p.session.active && p.wipes == 1 && p.secret[0] == 0 && p.reports == 1);
        assert(janos_radio_lease_snapshot(&p.lease).owner == JANOS_RADIO_OWNER_NONE);
    }
}

/* An unregister/disable error must not wipe context or release ownership even
 * when the worker joins; retry only the platform operations still outstanding. */
static void platform_quiescence_retry(void)
{
    const char failures[] = "UD";
    for (size_t i = 0; i < sizeof(failures) - 1; ++i) {
        platform_t p;
        platform_setup(&p);
        wifi_security_session_config_t c = session_config(&p);
        assert(wifi_security_session_start(&p.session, &c, 5000) == WIFI_SECURITY_SESSION_OK);
        p.opening = false;
        p.used = 0; p.trace[0] = 0;
        p.fail = failures[i];
        assert(wifi_security_session_stop(&p.session, 5000) == WIFI_SECURITY_SESSION_CLEANUP_FAILED);
        expect_trace(&p, "UDcXJBQ!");
        assert(p.session.active && !p.worker && p.wipes == 0 && p.secret[0] == 0x5a);
        assert(janos_radio_lease_snapshot(&p.lease).state == JANOS_RADIO_LEASE_QUARANTINED);
        p.fail = 0;
        assert(wifi_security_session_stop(&p.session, 5000) == WIFI_SECURITY_SESSION_OK);
        expect_trace(&p, failures[i] == 'U' ? "UcfRBLW" : "DcfRBLW");
        assert(!p.session.active && p.wipes == 1 && p.secret[0] == 0);
    }
}

/* Feature context and secrets stay live until the exact lease generation is
 * verifiably released.  A failed release is retryable and never double-wipes. */
static void platform_lease_release_retry_preserves_context(void)
{
    platform_t p;
    platform_setup(&p);
    wifi_security_session_config_t c = session_config(&p);
    assert(wifi_security_session_start(&p.session, &c, 5000) ==
           WIFI_SECURITY_SESSION_OK);
    p.opening = false;
    p.used = 0; p.trace[0] = 0;
    p.fail = 'L';
    assert(wifi_security_session_stop(&p.session, 5000) ==
           WIFI_SECURITY_SESSION_CLEANUP_FAILED);
    expect_trace(&p, "UDcXJfRBLQ!");
    assert(p.session.active && p.wipes == 0U && p.secret[0] == 0x5a);
    assert(janos_radio_lease_snapshot(&p.lease).state ==
           JANOS_RADIO_LEASE_QUARANTINED);
    assert(janos_radio_lease_snapshot(&p.lease).owner ==
           JANOS_RADIO_OWNER_SECURITY_MONITOR);

    p.fail = 0;
    assert(wifi_security_session_stop(&p.session, 5000) ==
           WIFI_SECURITY_SESSION_OK);
    expect_trace(&p, "cBLW");
    assert(!p.session.active && p.wipes == 1U && p.secret[0] == 0U);
    assert(janos_radio_lease_snapshot(&p.lease).owner ==
           JANOS_RADIO_OWNER_NONE);
    assert(wifi_security_session_stop(&p.session, 5000) ==
           WIFI_SECURITY_SESSION_OK);
    assert(p.wipes == 1U);
}

/* New identity must neither renumber legacy modules nor reuse generations. */
static void shield_identity(void)
{
    fixture_t f;
    setup(&f, 8);
    assert(WIFI_SECURITY_MODULE_WPS_GUARD == 1);
    assert(WIFI_SECURITY_MODULE_SAE_GUARD == 2);
    assert(WIFI_SECURITY_MODULE_TRUST_MONITOR == 3);
    const wifi_security_module_t modules[] = {
        WIFI_SECURITY_MODULE_SAE_GUARD, WIFI_SECURITY_MODULE_TRUST_MONITOR,
        WIFI_SECURITY_MODULE_SHIELD, WIFI_SECURITY_MODULE_WPS_GUARD
    };
    for (unsigned i = 0; i < 4; ++i) {
        wifi_security_runtime_request_stop(&f.runtime);
        assert(wifi_security_runtime_finish(&f.runtime));
        wifi_security_runtime_config_t c = config(&f, i + 2);
        c.module = modules[i];
        assert(wifi_security_runtime_start(&f.runtime, &c));
        assert(!submit(&f, i + 1, 99, 32));
        assert(submit(&f, i + 2, i, 32));
        f.reenter = true; /* Consumer requests stop during drain. */
        assert(wifi_security_runtime_drain(&f.runtime) == 1);
        wifi_security_runtime_status_t s = status(&f);
        assert(s.module == modules[i] && s.generation == i + 2);
        assert(s.received == 2 && s.queued == 1 && s.processed == 1);
        assert(s.stale_generation == 1 && s.stopping);
        uint8_t index;
        wifi_security_frame_slot_t *slot;
        assert(wifi_security_runtime_claim(&f.runtime, &index, &slot));
        assert(!wifi_security_runtime_finish(&f.runtime));
        assert(wifi_security_runtime_release(&f.runtime, index));
        assert(wifi_security_runtime_finish(&f.runtime));
        assert(!wifi_security_runtime_start(&f.runtime, &c));
    }
}

int main(void)
{
    shield_identity();
    pool_lifecycle();
    worker_order_and_failures();
    bounded_worker_drain();
    queue_overflow();
    lifecycle();
    saturation();
    invalid_init_and_inputs();
    platform_lifecycle();
    platform_initial_tune_and_split_stop();
    platform_adopts_existing_preparing_reservation();
    platform_start_failures();
    platform_cancel_and_retry();
    platform_quiescence_retry();
    platform_lease_release_retry_preserves_context();
    puts("PASS: fixed Wi-Fi security runtime");
    return 0;
}
