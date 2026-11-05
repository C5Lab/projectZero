#ifndef WIFI_SECURITY_RUNTIME_H
#define WIFI_SECURITY_RUNTIME_H

#include "wifi_security_frame.h"
#include "wifi_shield_core.h"

#define WIFI_SECURITY_POOL_SLOTS 8U

typedef enum {
    WIFI_SECURITY_MODULE_NONE = 0,
    WIFI_SECURITY_MODULE_WPS_GUARD,
    WIFI_SECURITY_MODULE_SAE_GUARD,
    WIFI_SECURITY_MODULE_TRUST_MONITOR,
    WIFI_SECURITY_MODULE_SHIELD,
    WIFI_SECURITY_MODULE_DEAUTH_V2
} wifi_security_module_t;

typedef enum {
    WIFI_SECURITY_RECEIVE_DEFAULT = 0,
    WIFI_SECURITY_RECEIVE_MGMT = 1U << 0,
    WIFI_SECURITY_RECEIVE_DATA = 1U << 1
} wifi_security_receive_policy_t;

/* Callback-borrowed view. bytes is valid only for the callback invocation;
 * features must copy or fully classify it before returning. signal_length
 * includes the driver FCS, while captured_length is the complete MAC dump
 * after FCS removal. */
typedef struct {
    const uint8_t *bytes;
    uint16_t captured_length;
    uint16_t signal_length;
    uint16_t dump_length;
    uint32_t rx_state;
    uint64_t timestamp_us;
    int8_t rssi;
    uint8_t channel;
    wifi_security_receive_policy_t packet_class;
} wifi_security_rx_view_t;

typedef bool (*wifi_security_borrowed_receive_fn)(
    void *context, uint32_t generation,
    const wifi_security_rx_view_t *observation);
typedef void (*wifi_security_worker_poll_fn)(void *context);

typedef struct {
    uint32_t generation;
    /* Adapter-provided receive timestamp. Shield supplies its lifecycle
     * monotonic clock so response latency never crosses clock domains. */
    uint64_t timestamp_us;
    uint16_t captured_len;
    uint16_t original_len;
    int8_t rssi;
    uint8_t channel;
    bool truncated;
    uint8_t bytes[WIFI_SECURITY_FRAME_COPY_MAX];
} wifi_security_frame_slot_t;

typedef bool (*wifi_security_consume_fn)(
    void *context, const wifi_security_frame_slot_t *slot,
    const wifi_security_decoded_t *decoded);

typedef bool (*wifi_security_compact_consume_fn)(
    void *context, const wifi_shield_compact_event_t *event);

typedef struct {
    wifi_security_module_t module;
    uint32_t generation;
    void *context;
    wifi_security_consume_fn consume;
} wifi_security_runtime_config_t;

typedef struct {
    wifi_security_module_t module;
    uint32_t generation;
    uint32_t received, queued, processed, truncated, dropped_pool;
    uint32_t dropped_queue, stale_generation, decode_rejected;
    /* Shield RX_DROPS: saturating admission losses across both bounded lanes. */
    uint32_t rx_drops;
    bool running, stopping;
} wifi_security_runtime_status_t;

/* enter/leave must be paired, bounded, callback-safe mutual exclusion with
 * acquire/release ordering. NULL/NULL is only for externally serialized use.
 * notify is optional, nonblocking, and called outside the lock on an empty to
 * nonempty transition across both lanes. It must only wake a worker, never call drain inline.
 * Hooks and their context live until all calls (including callbacks) have joined.
 */
typedef struct {
    void *context;
    void (*enter)(void *context);
    void (*leave)(void *context);
    void (*notify)(void *context);
} wifi_security_runtime_hooks_t;

/* Public layout permits fixed caller-owned storage. Fields are private to this
 * component; do not access/mutate them concurrently or copy a live runtime.
 */
typedef struct {
    wifi_security_runtime_hooks_t hooks;
    wifi_security_runtime_config_t config;
    wifi_security_runtime_status_t status;
    wifi_security_frame_slot_t slots[WIFI_SECURITY_POOL_SLOTS];
    uint8_t slot_state[WIFI_SECURITY_POOL_SLOTS];
    uint8_t queue[WIFI_SECURITY_POOL_SLOTS];
    uint8_t queue_capacity, queue_head, queue_count;
    uint32_t last_generation;
    bool callbacks_open, draining;
    /* Borrowed fixed 24-entry storage, never an inline array or heap owner. */
    wifi_shield_compact_event_t *compact_events;
    wifi_security_compact_consume_fn compact_consume;
    void *compact_context;
    uint8_t compact_head, compact_count, compact_deauth_count;
} wifi_security_runtime_t;

/* Idle-only binding. storage holds at least WIFI_SHIELD_COMPACT_EVENT_CAPACITY
 * entries, exclusively borrowed through successful finish and platform callback
 * join. NULL detaches. Finish wipes and detaches; each session binds afresh.
 * The worker invokes consume outside the lock, with an ephemeral event view.
 * No allocation: the platform may supply PSRAM in its later lifecycle adapter. */
bool wifi_security_runtime_bind_compact(wifi_security_runtime_t *runtime,
    wifi_shield_compact_event_t *storage,
    wifi_security_compact_consume_fn consume, void *context);
bool wifi_security_runtime_detach_compact(wifi_security_runtime_t *runtime);

/* Shield-only callback admission, same generation/close fence as full frames.
 * At most 16 Deauth/Disassoc entries; the remaining eight admit control/Defence.
 * Copies metadata and <=64 raw bytes, never parses. Shares one worker wakeup
 * with the full lane. Counters received/queued/processed include both lanes;
 * compact capacity/unbound losses increment dropped_queue and rx_drops.
 * request_stop and platform worker_stop use no queue entry. */
bool wifi_security_runtime_submit_compact(wifi_security_runtime_t *runtime,
    const wifi_shield_compact_event_t *event);

/* Init once before publication, never on a live runtime. Capacity is 1..8;
 * production adapters should use WIFI_SECURITY_POOL_SLOTS. No heap is used.
 * All following calls require successful init and use the injected lock.
 */
bool wifi_security_runtime_init(wifi_security_runtime_t *runtime,
                                const wifi_security_runtime_hooks_t *hooks,
                                uint8_t queue_capacity);

/* Starts a session with counters reset. Generation must be nonzero and strictly
 * greater than every previous session of this runtime (no wrap/reuse). Exhaustion
 * requires a new runtime after every producer retaining an old token has joined.
 * Repeating the identical active/open config succeeds without resetting state;
 * a closed/stopping session cannot be reopened. Context is borrowed until finish.
 * A NULL consumer is allowed; drain releases those frames without dispatch.
 */
bool wifi_security_runtime_start(wifi_security_runtime_t *runtime,
                                 const wifi_security_runtime_config_t *config);

/* Close only disables acceptance. Stop also sets stopping. Both are idempotent;
 * stop on idle is a no-op. Neither discards already queued frames. Finish succeeds
 * only for idle or stopped, fully drained runtimes with no outstanding pool claim.
 * It wipes config and slot storage, preserves final counters and generation guard,
 * and is idempotent. The platform must join callbacks before destroying contexts
 * or runtime memory: close/finish are not a platform callback-unregistration fence.
 */
void wifi_security_runtime_close_callbacks(wifi_security_runtime_t *runtime);
void wifi_security_runtime_request_stop(wifi_security_runtime_t *runtime);
bool wifi_security_runtime_finish(wifi_security_runtime_t *runtime);

/* Callback path: borrowed bytes need only remain valid for this call. Copies at
 * most 1536 bytes, queues the slot index, optionally notifies; never decodes or
 * dispatches. FIFO follows successful enqueue order under the lock. NULL/empty
 * inputs are rejected. Original length is the adapter-supplied MAC-frame length.
 */
bool wifi_security_runtime_submit(wifi_security_runtime_t *runtime,
                                  uint32_t generation, const uint8_t *bytes,
                                  uint16_t length, uint64_t timestamp_us,
                                  int8_t rssi, uint8_t channel);

/* One worker alternates ready lanes until empty; concurrent/reentrant drain returns zero. Returns
 * records released, including decode/consumer failures. Decode and consume execute
 * outside the lock; all views borrow the slot ONLY until consume returns. Consumer
 * may query status or request stop; it must not retain views or mutate/init runtime.
 * Every dequeued slot is zeroized before reuse, including failure/missing-consumer.
 */
size_t wifi_security_runtime_drain(wifi_security_runtime_t *runtime);
/* Same alternating-lane semantics, but releases at most max_records. A zero
 * limit is a no-op. This is the worker scheduler boundary: callers can poll
 * Stop/channel work even while producers keep either lane nonempty. */
size_t wifi_security_runtime_drain_bounded(wifi_security_runtime_t *runtime,
                                           size_t max_records);

/* module/generation identify the latest successfully opened runtime session and
 * are preserved after finish. received counts nonempty submit attempts (including
 * stale/closed); queued counts
 * accepted frames; processed counts successful consumer returns; truncated counts
 * bounded copies even if enqueue fails. stale_generation counts token mismatch or
 * zero, including when closed. Closed valid-token submissions have no drop counter.
 * decode_rejected counts decoder failures only; missing/false consumers leave
 * processed unchanged. All counters saturate at UINT32_MAX.
 */
void wifi_security_runtime_get_status(wifi_security_runtime_t *runtime,
                                      wifi_security_runtime_status_t *status);

/* Internal-component pool interfaces, not feature APIs. They take the same lock;
 * callers must NOT hold it. A claim reserves a zeroed slot until exactly one
 * release, and prevents finish. Caller owns its bytes exclusively during that
 * interval; returned pointers/indices must not be used after release. Only claimed
 * slots can be released here, never queued/worker slots. Exhaustion increments
 * dropped_pool. These calls do not enqueue or increment received/queued.
 */
bool wifi_security_runtime_claim(wifi_security_runtime_t *runtime, uint8_t *index,
                                 wifi_security_frame_slot_t **slot);
bool wifi_security_runtime_release(wifi_security_runtime_t *runtime, uint8_t index);

typedef enum {
    WIFI_SECURITY_SESSION_OK = 0,
    WIFI_SECURITY_SESSION_INVALID,
    WIFI_SECURITY_SESSION_BUSY,
    WIFI_SECURITY_SESSION_CHANNEL_FAILED,
    WIFI_SECURITY_SESSION_PREPARE_FAILED,
    WIFI_SECURITY_SESSION_WORKER_FAILED,
    WIFI_SECURITY_SESSION_CALLBACK_FAILED,
    WIFI_SECURITY_SESSION_PROMISCUOUS_FAILED,
    WIFI_SECURITY_SESSION_MARK_FAILED,
    WIFI_SECURITY_SESSION_CANCELLED,
    WIFI_SECURITY_SESSION_JOIN_TIMEOUT,
    WIFI_SECURITY_SESSION_RESTORE_FAILED,
    WIFI_SECURITY_SESSION_CLEANUP_FAILED,
    WIFI_SECURITY_SESSION_BASELINE_BUSY,
    WIFI_SECURITY_SESSION_FILTER_SNAPSHOT_FAILED,
    WIFI_SECURITY_SESSION_FILTER_APPLY_FAILED,
    WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED
} wifi_security_session_result_t;

/* Feature-owned context remains borrowed until successful cleanup. validate is
 * called before acquiring the radio; wipe runs once, after worker join/restore.
 * Generation is supplied by the radio lease, never by the feature. */
typedef struct {
    wifi_security_module_t module;
    /* Zero preserves the legacy current-channel behavior. A nonzero channel is
     * tuned after callback/filter setup and before promiscuous RX opens. */
    uint8_t initial_channel;
    /* Zero preserves the historical MGMT|DATA platform filter. Profiles may
     * request an explicit subset. borrowed_receive and worker_poll are paired:
     * the callback borrows driver bytes and the shared worker drains feature
     * state; neither may retain the observation pointer. */
    wifi_security_receive_policy_t receive_policy;
    wifi_security_borrowed_receive_fn borrowed_receive;
    wifi_security_worker_poll_fn worker_poll;
    void *context;
    wifi_security_consume_fn consume;
    bool (*validate)(void *context);
    void (*wipe)(void *context);
    /* Required feature-owned reporting; foundation emits no wire prefix. Called
     * outside locks owned by the reporting Start/Stop caller. This separate
     * context must survive module wipe and ALL concurrent Start/Stop returns;
     * the callback must be concurrency-safe. owned is a security-lease snapshot. */
    void *telemetry_context;
    void (*uncertainty)(void *telemetry_context, wifi_security_session_result_t result,
                        bool owned);
} wifi_security_session_config_t;

/* Platform-only API. All hooks are required. Lifecycle calls
 * are serialized by their caller, never made from a callback or consumer. Lease
 * cancellation must be latched independently of lease ownership, checked after
 * every startup side effect, and arbitrated atomically by generation_open. That
 * hook commits cancellation versus opening, calls core start only if it wins,
 * and returns false on cancellation/failure. A Stop ordered after the commit may
 * wait for the lifecycle owner; it cannot retroactively cancel a committed open.
 * Hooks run outside the core lock. Failed startup hooks must leave
 * no acquired resource; successful unregister must prevent new callbacks. Static
 * adapter state must outlive late callback/notification returns. worker_join must
 * join all consumer activity and drain the queue before reporting success.
 * prepare reserves fixed resources; no heap allocation is required by the core.
 * channel secondary is an opaque platform value. Time is monotonic microseconds.
 * finish_cleanup(false) quarantines ownership; false is its expected return.
 * baseline_idle probes legacy host activity after acquire, before any radio
 * mutation/snapshot. filter_apply installs the normalized per-profile receive
 * policy (DEFAULT becomes MGMT|DATA); even its
 * failure may partially mutate hardware, so restore is then always required.
 * uncertainty schedules feature reporting outside caller-owned lifecycle locks.
 */
typedef struct {
    void *context;
    bool (*lease_acquire)(void *context, uint32_t *generation);
    bool (*baseline_idle)(void *context);
    bool (*lease_mark_running)(void *context, uint32_t generation);
    bool (*lease_cancelled)(void *context, uint32_t generation);
    bool (*generation_open)(void *context, wifi_security_runtime_t *runtime,
                            const wifi_security_runtime_config_t *config);
    void (*lease_cancel)(void *context, uint32_t generation);
    bool (*lease_begin_cleanup)(void *context, uint32_t generation);
    bool (*lease_finish_cleanup)(void *context, uint32_t generation, bool restored);
    bool (*channel_read)(void *context, uint8_t *primary, uint8_t *secondary);
    bool (*channel_tune)(void *context, uint8_t primary);
    bool (*channel_restore)(void *context, uint8_t primary, uint8_t secondary);
    bool (*filter_read)(void *context, uint32_t *saved_mask);
    bool (*filter_apply)(void *context,
                         wifi_security_receive_policy_t policy);
    bool (*filter_restore)(void *context, uint32_t saved_mask);
    bool (*prepare)(void *context);
    bool (*worker_create)(void *context, wifi_security_runtime_t *runtime);
    bool (*callback_register)(void *context, uint32_t generation);
    bool (*callback_unregister)(void *context);
    bool (*promiscuous)(void *context, bool enabled);
    void (*worker_stop)(void *context);
    bool (*worker_join)(void *context, uint32_t timeout_ms);
    uint64_t (*monotonic_us)(void *context);
    void (*uncertainty)(void *context, const wifi_security_session_config_t *config,
                        wifi_security_session_result_t result);
} wifi_security_platform_hooks_t;

/* Private fields exposed only for fixed storage; lifecycle caller owns access. */
typedef struct {
    wifi_security_runtime_t *runtime;
    wifi_security_platform_hooks_t hooks;
    wifi_security_session_config_t config;
    uint32_t generation;
    uint32_t saved_filter;
    uint8_t saved_primary, saved_secondary;
    bool active, channel_saved, worker_created, callback_registered;
    bool promiscuous_enabled, context_wiped, cleanup_begun;
    bool baseline_ready, filter_restore_pending, quiesced;
} wifi_security_session_t;

bool wifi_security_session_init(wifi_security_session_t *session,
                                wifi_security_runtime_t *runtime,
                                const wifi_security_platform_hooks_t *hooks);
/* Start is rejected while any session/cleanup owns the radio. On rollback a
 * cleanup failure takes precedence over the original start error. The core is
 * opened only after mark-running; a cancelled startup never opens it. */
wifi_security_session_result_t wifi_security_session_start(
    wifi_security_session_t *session, const wifi_security_session_config_t *config,
    uint32_t rollback_timeout_ms);
/* Continues a PREPARING lease already acquired and baseline-checked by the
 * platform. generation remains the same across the owned scan and monitoring. */
wifi_security_session_result_t wifi_security_session_start_reserved(
    wifi_security_session_t *session, const wifi_security_session_config_t *config,
    uint32_t generation, uint32_t rollback_timeout_ms);
/* Split cleanup for Shield: quiesce closes every producer but retains snapshots
 * and lease ownership so an external publisher can drain before restoration. */
wifi_security_session_result_t wifi_security_session_quiesce(
    wifi_security_session_t *session, uint32_t timeout_ms);
wifi_security_session_result_t wifi_security_session_finish_cleanup(
    wifi_security_session_t *session);
/* Idle is a silent no-op. Failure retains ownership and retry state; join/restore
 * failure also retains module context. This legacy wrapper performs both split
 * phases without an intervening publisher drain. Only OK permits reset. */
wifi_security_session_result_t wifi_security_session_stop(
    wifi_security_session_t *session, uint32_t timeout_ms);

/* ESP-IDF adapter entry points; feature parsers supply consumers in later plans.
 * Driver must already be initialized so its channel can be snapshotted. Adapter
 * mutex serializes starts/stops; Start waits, contended Stop latches startup
 * cancellation without mutating the lease and waits within its timeout. The
 * atomic open commit decides whether cancellation wins. Timeout reports the
 * actual ownership snapshot. Never invoke from a consumer/callback. No CLI. */
#ifdef ESP_PLATFORM
wifi_security_session_result_t wifi_security_runtime_platform_start(
    const wifi_security_session_config_t *config);
bool wifi_security_runtime_stop(uint32_t timeout_ms);
#endif

#endif
