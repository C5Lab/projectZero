#include "wifi_shield.h"
#include "sae_guard.h"
#include "wps_guard.h"
#include "wpa_decoy.h"

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

_Static_assert(WIFI_SHIELD_PRESENTATION_INFO == 0,
               "presentation indicator ABI changed");
_Static_assert(WIFI_SHIELD_PRESENTATION_WARN == 1,
               "presentation indicator ABI changed");
_Static_assert(WIFI_SHIELD_PRESENTATION_ALERT == 2,
               "presentation indicator ABI changed");
_Static_assert(WIFI_SHIELD_PRESENTATION_DECOY_TX == 3,
               "presentation indicator ABI changed");
_Static_assert(WIFI_SHIELD_PRESENTATION_INDICATOR_COUNT == 4,
               "presentation indicator ABI changed");
_Static_assert(sizeof(((wifi_shield_oled_lines_t *)0)->line[0]) == 22U,
               "OLED storage must include 21 visible columns plus NUL");
_Static_assert(sizeof(wifi_shield_presentation_snapshot_t) <= 64U,
               "presentation snapshot must remain scalar and bounded");

#define STORAGE_BYTES (512U * 1024U)
#define ORDER_MAX 64U

enum {
    EV_STORAGE = 1, EV_RESERVE, EV_SCAN, EV_TRUST, EV_TUNE, EV_START, EV_ARMED,
    EV_ABORT,
    EV_QUIESCE, EV_DRAIN, EV_FINISH, EV_WIPE, EV_RELEASE, EV_TERMINAL,
    EV_DEFENCE_ARMED, EV_DEFENCE_TRIGGER, EV_DEFENCE_TX, EV_DEFENCE_STOPPED
};

typedef struct {
    uint8_t static_storage[STORAGE_BYTES];
    uint8_t *storage;
    size_t storage_size;
    wifi_shield_target_t scan[4];
    size_t scan_count;
    size_t snapshot_indices[WIFI_SHIELD_TARGET_MAX];
    size_t snapshot_count;
    wifi_security_session_config_t config;
    wifi_security_session_config_t profile_config;
    wifi_security_runtime_status_t runtime_status;
    wifi_trust_profile_t trust_profile;
    wifi_security_session_result_t start_result;
    wifi_security_session_result_t profile_start_result;
    bool storage_fail, trust_ok, trust_fill, reserve_ok, reserve_retained;
    bool abort_ok;
    bool tune_ok, quiesce_ok, defence_random_ok;
    bool finish_failure_reports_uncertainty;
    bool profile_stop_ok, profile_retune_ok;
    int defence_tx_fail_call;
    bool drain_ok, finish_ok, output_idle, fail_write, fail_terminal_write;
    bool journal_start_ok, journal_drain_ok, journal_finish_ok;
    bool journal_zero_after_release;
    bool journal_submit_fail, journal_submit_fail_until_drain;
    int journal_fail_recommendation_index_once;
    bool journal_fail_terminal_until_drain;
    bool journal_fail_uncertain_until_drain;
    bool journal_activate_on_drain;
    bool block_journal_drain, journal_drain_entered, release_journal_drain;
    bool reenter_journal_drain;
    bool block_journal_finish, journal_finish_entered;
    bool release_journal_finish, reenter_journal_finish;
    bool force_output_idle;
    bool reenter_terminal, reenter_abort, reenter_release;
    bool block_retune, retune_entered, release_retune;
    bool block_profile_retune, profile_retune_entered;
    bool release_profile_retune;
    bool block_profile_start, profile_start_entered, release_profile_start;
    bool block_profile_gate_start, profile_gate_start_entered;
    bool release_profile_gate_start;
    bool block_wps_profile_gate_start, wps_profile_gate_start_entered;
    bool release_wps_profile_gate_start;
    bool block_sae_profile_gate_start, sae_profile_gate_start_entered;
    bool release_sae_profile_gate_start;
    bool fail_sae_profile_gate_start;
    bool block_trust_profile_gate_start, trust_profile_gate_start_entered;
    bool release_trust_profile_gate_start;
    bool fail_trust_profile_gate_start;
    bool block_profile_gate_stop, profile_gate_stop_entered;
    bool release_profile_gate_stop;
    bool block_profile_arm_clock, profile_arm_clock_entered;
    bool release_profile_arm_clock;
    bool block_radio_enter, radio_entered, release_radio_enter;
    bool block_stop_before_radio, stop_before_radio;
    bool release_stop_before_radio;
    bool block_lock_before_radio, lock_before_radio, release_lock_before_radio;
    bool block_release_before_radio, release_before_radio;
    bool release_release_before_radio;
    bool block_tune, tune_entered, release_tune;
    bool block_quiesce, quiesce_entered, release_quiesce;
    bool block_finish_wipe, finish_wipe_entered, release_finish_wipe;
    bool block_defence_tx, defence_tx_entered, release_defence_tx;
    bool block_state_enter, state_entered, release_state_enter;
    bool arm_state_before_lock_on_runtime_status;
    bool block_state_before_lock, state_before_lock_entered;
    bool release_state_before_lock;
    bool block_terminal_copy, terminal_copy_entered, release_terminal_copy;
    bool block_armed_leave, armed_leave_entered, release_armed_leave;
    bool armed_leave_pending;
    bool block_failed_leave, failed_leave_entered, release_failed_leave;
    bool failed_leave_pending;
    bool block_output_enter_once, output_enter_blocked;
    bool release_output_enter, fail_blocked_output_enter;
    bool release_attempted;
    bool acquired, released, lease_released, reserved;
    unsigned acquire_calls, release_calls, scan_all_calls, scan_snapshot_calls;
    unsigned trust_calls, reserve_calls, abort_calls, tune_calls, start_calls;
    unsigned profile_start_calls, profile_stop_calls, profile_retune_calls;
    unsigned profile_consume_calls;
    unsigned profile_gate_enter_attempts, profile_gate_enter_calls;
    unsigned profile_gate_leave_calls;
    unsigned quiesce_calls;
    unsigned retune_calls, runtime_status_calls;
    unsigned radio_enter_attempts, radio_enter_calls, radio_leave_calls;
    unsigned state_depth, state_enter_calls, state_leave_calls;
    unsigned state_enter_attempts;
    unsigned drain_calls, finish_calls;
    unsigned journal_start_calls, journal_submit_calls, journal_status_calls;
    unsigned journal_ack_calls, journal_drain_calls, journal_finish_calls;
    unsigned journal_drain_finish_calls;
    size_t journal_drain_record_count;
    unsigned journal_finish_radio_calls, journal_finish_quiesce_calls;
    uint32_t async_failures;
    unsigned write_calls, terminal_calls, complete_calls;
    unsigned defence_random_calls, defence_tx_calls;
    size_t defence_tx_lengths[2];
    uint8_t defence_tx_frames[2][WPA_DECOY_FRAME_MAX];
    unsigned output_depth, reenter_acquire_delta;
    unsigned cleanup_reenter_calls, cleanup_reenter_acquire_delta;
    int reenter_result;
    int journal_reenter_stop_result, journal_reenter_start_result;
    int journal_drain_reenter_stop_result;
    unsigned journal_reenter_acquire_delta;
    uint8_t tuned_channel;
    uint8_t retuned_channel;
    uint8_t profile_channel;
    uint8_t profile_retune_history[8];
    uint64_t now_us;
    char last_line[512U];
    char all_lines[32768U];
    size_t all_lines_used;
    char terminal_outcome[32];
    wifi_shield_status_t terminal_status;
    wifi_shield_journal_status_t journal_status;
    wifi_shield_summary_metadata_t summary_metadata;
    wifi_shield_journal_record_t journal_records[512];
    size_t journal_record_count;
    uint64_t journal_next_sequence;
    bool journal_start_before_armed;
    int order[ORDER_MAX];
    size_t order_count;
} fixture_t;

static fixture_t f;
_Alignas(max_align_t) static uint8_t retained_storage[1024U];
_Alignas(max_align_t) static uint8_t other_retained_storage[1024U];
#define wifi_shield_init(runtime, output) \
    wifi_shield_init((runtime), (output), retained_storage, \
                     wifi_shield_retained_size())
static pthread_mutex_t radio_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t profile_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t guard_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t guard_output_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t order_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
typedef enum {
    ASYNC_ACTOR_NONE = 0,
    ASYNC_ACTOR_LOCK,
    ASYNC_ACTOR_RELEASE,
    ASYNC_ACTOR_STOP,
    ASYNC_ACTOR_PROFILE_START
} async_actor_t;
static _Thread_local async_actor_t async_actor;
static _Thread_local wifi_security_module_t async_profile_module;
static _Thread_local bool output_owned;
static bool heap_watch;
static unsigned heap_calls;
static unsigned tx_calls;
static unsigned guard_release_calls;
static unsigned guard_complete_calls;
static char guard_output[WPS_GUARD_LINE_MAX * 2U];
static size_t guard_output_used;

int esp_wifi_80211_tx(int interface_id, const void *buffer, int length,
                      bool encrypt)
{
    (void)interface_id;
    (void)buffer;
    (void)length;
    (void)encrypt;
    ++tx_calls;
    return 0;
}

void *__real_malloc(size_t size);
void *__real_calloc(size_t count, size_t size);
void *__real_realloc(void *memory, size_t size);
void __real_free(void *memory);

void *__wrap_malloc(size_t size)
{
    if (heap_watch) ++heap_calls;
    return __real_malloc(size);
}

void *__wrap_calloc(size_t count, size_t size)
{
    if (heap_watch) ++heap_calls;
    return __real_calloc(count, size);
}

void *__wrap_realloc(void *memory, size_t size)
{
    if (heap_watch) ++heap_calls;
    return __real_realloc(memory, size);
}

void __wrap_free(void *memory)
{
    if (heap_watch) ++heap_calls;
    __real_free(memory);
}

static void order(int event)
{
    assert(pthread_mutex_lock(&order_mutex) == 0);
    assert(f.order_count < ORDER_MAX);
    f.order[f.order_count++] = event;
    assert(pthread_mutex_unlock(&order_mutex) == 0);
}

static void cleanup_reenter(bool *armed)
{
    if (!*armed) return;
    *armed = false;
    unsigned before = f.acquire_calls;
    char *start[] = {"wifi_shield", "start"};
    assert(wifi_shield_command(2, start) == 1);
    ++f.cleanup_reenter_calls;
    f.cleanup_reenter_acquire_delta += f.acquire_calls - before;
}

static void make_target(size_t slot, uint8_t tail, uint8_t channel)
{
    memset(&f.scan[slot], 0, sizeof(f.scan[slot]));
    f.scan[slot].bssid[0] = 0x02U;
    f.scan[slot].bssid[5] = tail;
    f.scan[slot].channel = channel;
    f.scan[slot].wpa2_psk_ccmp = true;
    (void)snprintf(f.scan[slot].ssid, sizeof(f.scan[slot].ssid), "ap-%u",
                   (unsigned)tail);
}

static bool defence_random(void *context, uint8_t *out, size_t length)
{
    assert(context == &f && out != NULL && length != 0U);
    ++f.defence_random_calls;
    memset(out, 0x5a, length);
    return f.defence_random_ok;
}

static int defence_tx(void *context, const uint8_t *frame, size_t length,
                      bool en_sys_seq)
{
    assert(context == &f && frame != NULL && length != 0U && en_sys_seq);
    ++f.defence_tx_calls;
    ++tx_calls;
    if (f.defence_tx_calls <= 2U) {
        assert(length <= WPA_DECOY_FRAME_MAX);
        f.defence_tx_lengths[f.defence_tx_calls - 1U] = length;
        memcpy(f.defence_tx_frames[f.defence_tx_calls - 1U], frame, length);
    }
    order(EV_DEFENCE_TX);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_defence_tx) {
        f.defence_tx_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_defence_tx)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    return f.defence_tx_fail_call != 0 &&
           f.defence_tx_calls == (unsigned)f.defence_tx_fail_call ? -1 : 0;
}

static bool storage_acquire(void *context, size_t bytes, void **storage)
{
    assert(context == &f && storage != NULL);
    order(EV_STORAGE);
    ++f.acquire_calls;
    *storage = NULL;
    if (f.storage_fail || bytes == 0U || bytes > sizeof(f.static_storage))
        return false;
#ifdef JANOS_TEST_FREE_AFTER_RELEASE
    f.storage = __real_malloc(bytes);
    if (f.storage == NULL) return false;
#else
    f.storage = f.static_storage;
#endif
    memset(f.storage, 0, bytes);
    f.storage_size = bytes;
    f.acquired = true;
    f.released = false;
    *storage = f.storage;
    return true;
}

static void storage_release(void *context, void **storage, size_t bytes)
{
    assert(context == &f && storage != NULL && *storage == f.storage);
    assert(bytes == f.storage_size);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    f.release_attempted = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    order(EV_RELEASE);
    ++f.release_calls;
    cleanup_reenter(&f.reenter_release);
    for (size_t i = 0; i < bytes; ++i) assert(f.storage[i] == 0U);
#ifdef JANOS_TEST_FREE_AFTER_RELEASE
    __real_free(f.storage);
    f.storage = NULL;
#else
    memset(f.storage, 0xA5, bytes);
#endif
    if (f.journal_zero_after_release)
        memset(&f.journal_status, 0, sizeof(f.journal_status));
    *storage = NULL;
    f.acquired = false;
    f.released = true;
}

static bool scan_all(void *context, wifi_shield_target_t *targets,
                     size_t capacity, size_t *count)
{
    assert(context == &f && targets != NULL && count != NULL);
    order(EV_SCAN);
    ++f.scan_all_calls;
    if (capacity < f.scan_count) return false;
    memcpy(targets, f.scan, f.scan_count * sizeof(*targets));
    *count = f.scan_count;
    return f.scan_count != 0U;
}

static bool scan_snapshot(void *context, const size_t *indices,
                          size_t index_count, wifi_shield_target_t *targets,
                          size_t capacity, size_t *count)
{
    assert(context == &f && indices != NULL && targets != NULL && count != NULL);
    order(EV_SCAN);
    ++f.scan_snapshot_calls;
    if (index_count == 0U || index_count > capacity) return false;
    f.snapshot_count = index_count;
    for (size_t i = 0; i < index_count; ++i) {
        f.snapshot_indices[i] = indices[i];
        if (indices[i] == 0U || indices[i] > f.scan_count) return false;
        targets[i] = f.scan[indices[i] - 1U];
    }
    *count = index_count;
    return true;
}

static bool trust_snapshot(void *context, wifi_trust_profile_t *profiles,
                           size_t capacity, size_t *count)
{
    assert(context == &f && profiles != NULL && count != NULL);
    assert(capacity == WIFI_TRUST_MAX_PROFILES);
    order(EV_TRUST);
    ++f.trust_calls;
    if (f.trust_fill) {
        profiles[0] = f.trust_profile;
        *count = 1U;
    } else {
        *count = 0U;
    }
    return f.trust_ok;
}

static bool reserve_scan(void *context)
{
    assert(context == &f);
    order(EV_RESERVE);
    ++f.reserve_calls;
    if (!f.reserve_ok) {
        f.reserved = f.reserve_retained;
        return false;
    }
    f.reserved = true;
    return true;
}

static bool profile_reserve_scan(void *context, wifi_security_module_t module)
{
    assert(context == &f && module == WIFI_SECURITY_MODULE_DEAUTH_V2);
    ++f.reserve_calls;
    if (!f.reserve_ok) {
        f.reserved = f.reserve_retained;
        return false;
    }
    f.reserved = true;
    return true;
}

static bool profile_abort_prepare(void *context,
                                  wifi_security_module_t module,
                                  uint32_t timeout_ms)
{
    assert(context == &f && module == WIFI_SECURITY_MODULE_DEAUTH_V2 &&
           timeout_ms != 0U);
    ++f.abort_calls;
    if (!f.abort_ok) return false;
    f.reserved = false;
    return true;
}

static bool abort_prepare(void *context, uint32_t timeout_ms)
{
    assert(context == &f && timeout_ms != 0U);
    order(EV_ABORT);
    ++f.abort_calls;
    cleanup_reenter(&f.reenter_abort);
    if (!f.reserved) return true;
    if (!f.abort_ok) return false;
    f.reserved = false;
    f.lease_released = true;
    return true;
}

static wifi_security_session_result_t start_radio(
    void *context, const wifi_security_session_config_t *config)
{
    assert(context == &f && config != NULL);
    assert(config->module == WIFI_SECURITY_MODULE_SHIELD);
    assert(config->validate != NULL && config->wipe != NULL);
    assert(config->validate(config->context));
    order(EV_START);
    ++f.start_calls;
    f.reserved = false; /* The radio session adopts the same reservation. */
    f.config = *config;
    return f.start_result;
}

static wifi_security_session_result_t profile_start_radio(
    void *context, const wifi_security_session_config_t *config)
{
    assert(context == &f && config != NULL);
    assert(config->module == WIFI_SECURITY_MODULE_WPS_GUARD ||
           config->module == WIFI_SECURITY_MODULE_SAE_GUARD ||
           config->module == WIFI_SECURITY_MODULE_TRUST_MONITOR ||
           config->module == WIFI_SECURITY_MODULE_DEAUTH_V2);
    assert(config->initial_channel != 0U ||
           config->module == WIFI_SECURITY_MODULE_TRUST_MONITOR);
    assert(config->consume != NULL && config->validate != NULL &&
           config->wipe != NULL && config->uncertainty != NULL);
    ++f.profile_start_calls;
    f.reserved = false;
    f.profile_config = *config;
    f.profile_channel = config->initial_channel != 0U ?
        config->initial_channel : 6U;
    if (f.profile_start_result == WIFI_SECURITY_SESSION_OK) {
        f.runtime_status.module = config->module;
        ++f.runtime_status.generation;
        if (f.runtime_status.generation == 0U) ++f.runtime_status.generation;
        f.runtime_status.running = true;
        f.runtime_status.stopping = false;
    }
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_profile_start) {
        f.profile_start_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_profile_start)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    return f.profile_start_result;
}

static bool profile_stop_radio(void *context, uint32_t timeout_ms)
{
    assert(context == &f && timeout_ms != 0U);
    ++f.profile_stop_calls;
    if (!f.profile_stop_ok) return false;
    f.runtime_status.running = false;
    f.runtime_status.stopping = false;
    if (f.profile_config.wipe != NULL)
        f.profile_config.wipe(f.profile_config.context);
    return true;
}

static bool profile_retune(void *context, wifi_security_module_t module,
                           uint32_t generation, uint8_t channel)
{
    assert(context == &f && module == f.runtime_status.module &&
            (module == WIFI_SECURITY_MODULE_WPS_GUARD ||
             module == WIFI_SECURITY_MODULE_SAE_GUARD ||
            module == WIFI_SECURITY_MODULE_TRUST_MONITOR ||
            module == WIFI_SECURITY_MODULE_DEAUTH_V2) &&
           generation == f.runtime_status.generation && channel != 0U);
    assert(f.profile_retune_calls <
           sizeof(f.profile_retune_history) / sizeof(f.profile_retune_history[0]));
    f.profile_retune_history[f.profile_retune_calls++] = channel;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_profile_retune) {
        f.profile_retune_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_profile_retune)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    if (!f.profile_retune_ok) return false;
    f.profile_channel = channel;
    return true;
}

static bool tune(void *context, uint8_t channel)
{
    assert(context == &f && channel != 0U);
    /* Task 8 contract: stage only. This fake intentionally has no radio side
     * effect; start_radio consumes the recorded channel in production. */
    order(EV_TUNE);
    ++f.tune_calls;
    f.tuned_channel = channel;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_tune) {
        f.tune_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_tune)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    return f.tune_ok;
}

static bool retune(void *context, uint8_t channel)
{
    assert(context == &f && channel != 0U && f.state_depth == 0U);
    ++f.retune_calls;
    f.retuned_channel = channel;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_retune) {
        f.retune_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_retune)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    return f.tune_ok;
}

static bool radio_enter(void *context, uint32_t timeout_ms)
{
    assert(context == &f && timeout_ms != 0U && f.state_depth == 0U);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    ++f.radio_enter_attempts;
    if (async_actor == ASYNC_ACTOR_LOCK && f.block_lock_before_radio) {
        f.lock_before_radio = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_lock_before_radio)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    if (async_actor == ASYNC_ACTOR_RELEASE &&
        f.block_release_before_radio) {
        f.release_before_radio = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_release_before_radio)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    if (async_actor == ASYNC_ACTOR_STOP && f.block_stop_before_radio) {
        f.stop_before_radio = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_stop_before_radio)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    assert(pthread_mutex_lock(&radio_mutex) == 0);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    ++f.radio_enter_calls;
    if (f.block_radio_enter) {
        f.radio_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_radio_enter)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    return true;
}

static void radio_leave(void *context)
{
    assert(context == &f && f.state_depth == 0U);
    ++f.radio_leave_calls;
    assert(pthread_mutex_unlock(&radio_mutex) == 0);
}

static bool profile_gate_enter(void *context, uint32_t timeout_ms)
{
    assert(context == &f && timeout_ms != 0U && f.state_depth == 0U);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    ++f.profile_gate_enter_attempts;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    if (async_actor == ASYNC_ACTOR_PROFILE_START &&
        f.block_profile_gate_start) {
        f.profile_gate_start_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_profile_gate_start)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    if (async_actor == ASYNC_ACTOR_PROFILE_START &&
        async_profile_module == WIFI_SECURITY_MODULE_WPS_GUARD &&
        f.block_wps_profile_gate_start) {
        f.wps_profile_gate_start_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_wps_profile_gate_start)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    if (async_actor == ASYNC_ACTOR_PROFILE_START &&
        async_profile_module == WIFI_SECURITY_MODULE_SAE_GUARD &&
        f.block_sae_profile_gate_start) {
        f.sae_profile_gate_start_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_sae_profile_gate_start)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    if (async_actor == ASYNC_ACTOR_PROFILE_START &&
        async_profile_module == WIFI_SECURITY_MODULE_TRUST_MONITOR &&
        f.block_trust_profile_gate_start) {
        f.trust_profile_gate_start_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_trust_profile_gate_start)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    if (async_actor == ASYNC_ACTOR_STOP && f.block_profile_gate_stop) {
        f.profile_gate_stop_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_profile_gate_stop)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    bool fail_start_gate = async_actor == ASYNC_ACTOR_PROFILE_START &&
        ((async_profile_module == WIFI_SECURITY_MODULE_SAE_GUARD &&
          f.fail_sae_profile_gate_start) ||
         (async_profile_module == WIFI_SECURITY_MODULE_TRUST_MONITOR &&
          f.fail_trust_profile_gate_start));
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    if (fail_start_gate) return false;
    assert(pthread_mutex_lock(&profile_mutex) == 0);
    ++f.profile_gate_enter_calls;
    return true;
}

static void profile_gate_leave(void *context)
{
    assert(context == &f && f.state_depth == 0U);
    ++f.profile_gate_leave_calls;
    assert(pthread_mutex_unlock(&profile_mutex) == 0);
}

static void state_enter(void *context)
{
    assert(context == &f);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    ++f.state_enter_attempts;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    if (f.block_state_before_lock) {
        f.block_state_before_lock = false;
        f.state_before_lock_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_state_before_lock)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    assert(pthread_mutex_lock(&state_mutex) == 0);
    assert(f.state_depth == 0U && !output_owned);
    ++f.state_depth;
    ++f.state_enter_calls;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_state_enter) {
        f.state_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_state_enter)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}

static void state_leave(void *context)
{
    assert(context == &f && f.state_depth == 1U);
    --f.state_depth;
    ++f.state_leave_calls;
    assert(pthread_mutex_unlock(&state_mutex) == 0);
}

static void runtime_status_snapshot(
    void *context, wifi_security_runtime_status_t *status)
{
    assert(context == &f && status != NULL && f.state_depth == 0U);
    ++f.runtime_status_calls;
    *status = f.runtime_status;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.arm_state_before_lock_on_runtime_status) {
        f.arm_state_before_lock_on_runtime_status = false;
        f.block_state_before_lock = true;
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}

static bool quiesce_radio(void *context, uint32_t timeout_ms)
{
    assert(context == &f && timeout_ms != 0U);
    order(EV_QUIESCE);
    ++f.quiesce_calls;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_quiesce) {
        f.quiesce_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_quiesce)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    return f.quiesce_ok;
}

static bool finish_radio_cleanup(void *context, uint32_t timeout_ms)
{
    assert(context == &f && timeout_ms != 0U);
    order(EV_FINISH);
    ++f.finish_calls;
    if (!f.finish_ok) {
        if (f.finish_failure_reports_uncertainty && f.config.uncertainty != NULL)
            f.config.uncertainty(f.config.context,
                                 WIFI_SECURITY_SESSION_RESTORE_FAILED, true);
        return false;
    }
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_finish_wipe) {
        f.finish_wipe_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_finish_wipe)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    if (f.config.wipe != NULL) f.config.wipe(f.config.context);
    order(EV_WIPE);
    f.lease_released = true;
    return true;
}

static uint64_t monotonic_us(void *context)
{
    assert(context == &f);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_profile_arm_clock) {
        f.profile_arm_clock_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_profile_arm_clock)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    return f.now_us;
}

static bool output_enter(void *context, uint32_t timeout_ms)
{
    assert(context == &f && timeout_ms != 0U);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    bool blocked = f.block_output_enter_once;
    if (blocked) {
        f.block_output_enter_once = false;
        f.output_enter_blocked = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_output_enter)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    bool failed = blocked && f.fail_blocked_output_enter;
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    if (failed) return false;
    assert(pthread_mutex_lock(&output_mutex) == 0);
    output_owned = true;
    ++f.output_depth;
    return true;
}

static void output_leave(void *context)
{
    assert(context == &f);
    assert(f.output_depth != 0U);
    bool block = false;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_armed_leave && f.armed_leave_pending) {
        f.armed_leave_pending = false;
        f.armed_leave_entered = true;
        block = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
    }
    if (f.block_failed_leave && f.failed_leave_pending) {
        f.failed_leave_pending = false;
        f.failed_leave_entered = true;
        block = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    --f.output_depth;
    output_owned = false;
    assert(pthread_mutex_unlock(&output_mutex) == 0);
    if (block) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        while (!f.release_armed_leave && !f.release_failed_leave)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
}

static bool output_write(void *context, const char *line, size_t length)
{
    assert(context == &f && line != NULL && length != 0U);
    ++f.write_calls;
    size_t copied = length < sizeof(f.last_line) - 1U ? length : sizeof(f.last_line) - 1U;
    memcpy(f.last_line, line, copied);
    f.last_line[copied] = '\0';
    if (f.all_lines_used + length < sizeof(f.all_lines)) {
        memcpy(f.all_lines + f.all_lines_used, line, length);
        f.all_lines_used += length;
        f.all_lines[f.all_lines_used] = '\0';
    }
    if (strstr(f.last_line, " ARMED ") != NULL) {
        order(EV_ARMED);
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        f.armed_leave_pending = true;
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
    if (strstr(f.last_line, "[DETECTOR_DEFENCE] armed ") != NULL)
        order(EV_DEFENCE_ARMED);
    if (strstr(f.last_line, "[DETECTOR_DEFENCE] trigger=") != NULL)
        order(EV_DEFENCE_TRIGGER);
    if (strstr(f.last_line, "[DETECTOR_DEFENCE] stopped ") != NULL)
        order(EV_DEFENCE_STOPPED);
    bool written = !f.fail_write;
    if (!written) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        f.failed_leave_pending = true;
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
    return written;
}

static bool all_poisoned(void)
{
#ifdef JANOS_TEST_FREE_AFTER_RELEASE
    return f.storage == NULL;
#else
    for (size_t i = 0; i < f.storage_size; ++i)
        if (f.storage[i] != 0xA5U) return false;
    return true;
#endif
}

static bool output_terminal(void *context, const wifi_shield_status_t *status,
                            const char *outcome)
{
    assert(context == &f && status != NULL && outcome != NULL);
    order(EV_TERMINAL);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    ++f.terminal_calls;
    if (f.block_terminal_copy) {
        f.terminal_copy_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_terminal_copy)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    f.terminal_status = *status;
    (void)snprintf(f.terminal_outcome, sizeof(f.terminal_outcome), "%s", outcome);
    if (strcmp(outcome, "stopped") == 0 || strcmp(outcome, "output_failed") == 0) {
        assert(f.lease_released && f.released && all_poisoned());
    }
    if (f.reenter_terminal) {
        f.reenter_terminal = false;
        unsigned before = f.acquire_calls;
        char *start[] = {"wifi_shield", "start"};
        f.reenter_result = wifi_shield_command(2, start);
        f.reenter_acquire_delta = f.acquire_calls - before;
    }
    return !f.fail_terminal_write;
}

static void output_complete(void *context, bool accepted)
{
    assert(context == &f);
    (void)accepted;
    ++f.complete_calls;
}

static bool output_idle(void *context)
{
    assert(context == &f);
    return f.output_idle &&
        (f.force_output_idle || f.output_depth == 0U);
}

static bool output_drain(void *context, uint32_t timeout_ms)
{
    assert(context == &f && timeout_ms != 0U);
    order(EV_DRAIN);
    ++f.drain_calls;
    return f.drain_ok;
}

static uint32_t output_take_failures(void *context)
{
    assert(context == &f);
    uint32_t failures = f.async_failures;
    f.async_failures = 0U;
    return failures;
}

static uint32_t journal_boot_id(void *context)
{
    assert(context == &f);
    return UINT32_C(0x1234abcd);
}

static bool journal_start(void *context, uint32_t boot_id,
                           uint32_t session_id, uint64_t quota_bytes,
                           const wifi_shield_summary_metadata_t *metadata)
{
    assert(context == &f && boot_id == UINT32_C(0x1234abcd));
    assert(session_id != 0U && quota_bytes != 0U && metadata != NULL);
    f.summary_metadata = *metadata;
    ++f.journal_start_calls;
    f.journal_next_sequence = 1U;
    memset(&f.journal_status, 0, sizeof(f.journal_status));
    f.journal_status.time_sources = WIFI_SHIELD_JOURNAL_TIME_MONOTONIC;
    if (!f.journal_start_ok) {
        f.journal_status.failures = 1U;
        return false;
    }
    f.journal_status.state = WIFI_SHIELD_JOURNAL_ACTIVE;
    snprintf(f.journal_status.path, sizeof(f.journal_status.path),
             "/sdcard/lab/shield/shield-b1234abcd-s%u.jsonl.part",
             (unsigned)session_id);
    return true;
}

static bool journal_submit(void *context,
                           const wifi_shield_journal_record_t *record)
{
    assert(context == &f && record != NULL);
    ++f.journal_submit_calls;
    bool fail_recommendation_once =
        record->type == WIFI_SHIELD_JOURNAL_RECOMMENDATION &&
        f.journal_fail_recommendation_index_once >= 0 &&
        record->recommendation_set_index ==
            (uint8_t)f.journal_fail_recommendation_index_once;
    if (f.journal_submit_fail || f.journal_submit_fail_until_drain ||
        fail_recommendation_once ||
        (f.journal_fail_terminal_until_drain &&
         record->type == WIFI_SHIELD_JOURNAL_SESSION_TERMINAL) ||
        (f.journal_fail_uncertain_until_drain &&
         record->type == WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN) ||
        f.journal_status.state != WIFI_SHIELD_JOURNAL_ACTIVE ||
        f.journal_record_count >=
            sizeof(f.journal_records) / sizeof(f.journal_records[0])) {
        if (fail_recommendation_once)
            f.journal_fail_recommendation_index_once = -1;
        if (f.journal_status.dropped != UINT32_MAX)
            ++f.journal_status.dropped;
        return false;
    }
    wifi_shield_journal_record_t copy = *record;
    copy.boot_id = UINT32_C(0x1234abcd);
    copy.sequence = f.journal_next_sequence++;
    f.journal_records[f.journal_record_count++] = copy;
    if (copy.type == WIFI_SHIELD_JOURNAL_SESSION_START)
        f.journal_start_before_armed = f.write_calls == 0U;
    if (f.journal_status.records_written != UINT32_MAX)
        ++f.journal_status.records_written;
    return true;
}

static wifi_shield_journal_status_t journal_status_snapshot(void *context)
{
    assert(context == &f);
    ++f.journal_status_calls;
    return f.journal_status;
}

static void journal_acknowledge(void *context)
{
    assert(context == &f);
    ++f.journal_ack_calls;
    f.journal_status.degraded_notice_pending = false;
}

static bool journal_drain(void *context, uint32_t timeout_ms)
{
    assert(context == &f && timeout_ms != 0U);
    ++f.journal_drain_calls;
    f.journal_drain_finish_calls = f.finish_calls;
    f.journal_drain_record_count = f.journal_record_count;
    if (f.reenter_journal_drain) {
        f.reenter_journal_drain = false;
        f.journal_drain_reenter_stop_result = wifi_shield_stop(timeout_ms);
    }
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_journal_drain && !f.journal_drain_entered) {
        f.journal_drain_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_journal_drain)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    if (f.journal_drain_ok) {
        f.journal_submit_fail_until_drain = false;
        f.journal_fail_terminal_until_drain = false;
        f.journal_fail_uncertain_until_drain = false;
        if (f.journal_activate_on_drain)
            f.journal_status.state = WIFI_SHIELD_JOURNAL_ACTIVE;
    }
    return f.journal_drain_ok;
}

static bool journal_finish(void *context, bool clean, uint32_t timeout_ms)
{
    assert(context == &f && timeout_ms != 0U);
    ++f.journal_finish_calls;
    f.journal_finish_radio_calls = f.finish_calls;
    f.journal_finish_quiesce_calls = f.quiesce_calls;
    if (f.reenter_journal_finish) {
        f.reenter_journal_finish = false;
        unsigned acquisitions = f.acquire_calls;
        f.journal_reenter_stop_result = wifi_shield_stop(timeout_ms);
        char *start[] = {"wifi_shield", "start"};
        f.journal_reenter_start_result = wifi_shield_command(2, start);
        f.journal_reenter_acquire_delta = f.acquire_calls - acquisitions;
    }
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    if (f.block_journal_finish && !f.journal_finish_entered) {
        f.journal_finish_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!f.release_journal_finish)
            assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    if (!f.journal_finish_ok) return false;
    if (f.journal_status.state == WIFI_SHIELD_JOURNAL_ACTIVE)
        f.journal_status.state = clean ? WIFI_SHIELD_JOURNAL_FINALIZED :
                                         WIFI_SHIELD_JOURNAL_INCOMPLETE;
    return true;
}

static wifi_shield_runtime_hooks_t runtime_hooks(void)
{
    wifi_shield_runtime_hooks_t hooks = {
        .context = &f,
        .storage_acquire = storage_acquire,
        .storage_release = storage_release,
        .scan_all = scan_all,
        .scan_snapshot = scan_snapshot,
        .trust_snapshot = trust_snapshot,
        .reserve_scan = reserve_scan,
        .abort_prepare = abort_prepare,
        .start_radio = start_radio,
        .tune = tune,
        .retune = retune,
        .radio_enter = radio_enter,
        .radio_leave = radio_leave,
        .state_enter = state_enter,
        .state_leave = state_leave,
        .runtime_status = runtime_status_snapshot,
        .quiesce_radio = quiesce_radio,
        .finish_radio_cleanup = finish_radio_cleanup,
        .monotonic_us = monotonic_us,
        .defence_random = defence_random,
        .defence_tx = defence_tx,
        .profile_start_radio = profile_start_radio,
        .profile_stop_radio = profile_stop_radio,
        .profile_retune = profile_retune,
        .profile_gate_enter = profile_gate_enter,
        .profile_gate_leave = profile_gate_leave,
        .profile_reserve_scan = profile_reserve_scan,
        .profile_abort_prepare = profile_abort_prepare,
        .journal_boot_id = journal_boot_id,
        .journal_start = journal_start,
        .journal_submit = journal_submit,
        .journal_status = journal_status_snapshot,
        .journal_acknowledge_degraded = journal_acknowledge,
        .journal_drain = journal_drain,
        .journal_finish = journal_finish
    };
    return hooks;
}

static wifi_shield_output_hooks_t output_hooks(void)
{
    wifi_shield_output_hooks_t hooks = {
        .context = &f,
        .enter = output_enter,
        .leave = output_leave,
        .write = output_write,
        .write_terminal = output_terminal,
        .complete = output_complete,
        .idle = output_idle,
        .drain = output_drain,
        .take_failures = output_take_failures
    };
    return hooks;
}

static void reset_fixture(size_t targets)
{
    assert(!wifi_shield_busy());
    assert(wifi_shield_retained_size() != 0U &&
           wifi_shield_retained_size() <= sizeof(retained_storage));
    memset(&f, 0, sizeof(f));
    f.journal_fail_recommendation_index_once = -1;
    tx_calls = 0U;
    f.scan_count = targets;
    for (size_t i = 0; i < targets; ++i)
        make_target(i, (uint8_t)(i + 1U), (uint8_t)(1U + i * 5U));
    f.start_result = WIFI_SECURITY_SESSION_OK;
    f.profile_start_result = WIFI_SECURITY_SESSION_OK;
    f.trust_ok = true;
    f.reserve_ok = true;
    f.abort_ok = true;
    f.tune_ok = true;
    f.profile_stop_ok = true;
    f.profile_retune_ok = true;
    f.defence_random_ok = true;
    f.quiesce_ok = true;
    f.drain_ok = true;
    f.finish_ok = true;
    f.journal_start_ok = true;
    f.journal_drain_ok = true;
    f.journal_finish_ok = true;
    f.output_idle = true;
    f.now_us = UINT64_C(1000000);
    f.runtime_status.generation = 7U;
    wifi_shield_runtime_hooks_t runtime = runtime_hooks();
    wifi_shield_output_hooks_t output = output_hooks();
    assert(wifi_shield_init(&runtime, &output));
    assert(!(wifi_shield_init)(&runtime, &output, other_retained_storage,
                               wifi_shield_retained_size()));
}

static void guard_state_enter(void *context)
{
    assert(context == &f);
    assert(pthread_mutex_lock(&guard_state_mutex) == 0);
}

static void guard_state_leave(void *context)
{
    assert(context == &f);
    assert(pthread_mutex_unlock(&guard_state_mutex) == 0);
}

static bool guard_scan_snapshot(void *context, wifi_shield_target_t **targets,
                                size_t *count)
{
    assert(context == &f && targets != NULL && count != NULL);
    if (f.scan_count == 0U) return false;
    wifi_shield_target_t *copy = malloc(f.scan_count * sizeof(*copy));
    assert(copy != NULL);
    memcpy(copy, f.scan, f.scan_count * sizeof(*copy));
    *targets = copy;
    *count = f.scan_count;
    return true;
}

static void guard_scan_release(void *context, wifi_shield_target_t *targets,
                               size_t count)
{
    assert(context == &f && targets != NULL && count != 0U);
    assert(!f.runtime_status.running && !f.runtime_status.stopping);
    const uint8_t *bytes = (const uint8_t *)targets;
    for (size_t i = 0U; i < count * sizeof(*targets); ++i)
        assert(bytes[i] == 0U);
    ++guard_release_calls;
    free(targets);
}

static uint64_t guard_monotonic_us(void *context)
{
    assert(context == &f);
    return f.now_us;
}

static void guard_runtime_status(void *context,
                                 wifi_security_runtime_status_t *status)
{
    assert(context == &f && status != NULL);
    *status = f.runtime_status;
}

static wifi_security_session_result_t guard_runtime_start(
    void *context, const wifi_shield_target_t *targets, size_t target_count,
    const wifi_security_session_config_t *config)
{
    assert(context == &f);
    return wifi_shield_start_wps_profile(targets, target_count, config);
}

static bool guard_runtime_stop(void *context, uint32_t timeout_ms)
{
    assert(context == &f);
    return wifi_shield_stop_wps_profile(timeout_ms);
}

static bool guard_output_enter(void *context, uint32_t timeout_ms)
{
    assert(context == &f && timeout_ms != 0U);
    return pthread_mutex_lock(&guard_output_mutex) == 0;
}

static void guard_output_leave(void *context)
{
    assert(context == &f);
    assert(pthread_mutex_unlock(&guard_output_mutex) == 0);
}

static bool guard_output_append(const char *line, size_t length)
{
    assert(line != NULL && length != 0U);
    if (length > sizeof(guard_output) - guard_output_used - 1U)
        return false;
    memcpy(guard_output + guard_output_used, line, length);
    guard_output_used += length;
    guard_output[guard_output_used] = '\0';
    return true;
}

static bool guard_output_write(void *context, const char *line, size_t length)
{
    assert(context == &f);
    return guard_output_append(line, length);
}

static bool guard_output_terminal(void *context,
                                  const wps_guard_status_t *status,
                                  const char *outcome)
{
    assert(context == &f && status != NULL && outcome != NULL);
    char line[WPS_GUARD_LINE_MAX];
    int length = wps_guard_format_terminal_for_output(
        line, sizeof(line), status, outcome);
    return length > 0 && guard_output_append(line, (size_t)length);
}

static void guard_output_complete(void *context, bool accepted)
{
    assert(context == &f && accepted);
    ++guard_complete_calls;
}

static bool guard_output_idle(void *context)
{
    assert(context == &f);
    return true;
}

static bool init_integrated_guard(void)
{
    const wps_guard_runtime_hooks_t runtime = {
        .context = &f,
        .enter = guard_state_enter,
        .leave = guard_state_leave,
        .scan_snapshot = guard_scan_snapshot,
        .scan_release = guard_scan_release,
        .monotonic_us = guard_monotonic_us,
        .status_snapshot = guard_runtime_status,
        .start = guard_runtime_start,
        .stop = guard_runtime_stop,
    };
    const wps_guard_output_hooks_t output = {
        .context = &f,
        .enter = guard_output_enter,
        .leave = guard_output_leave,
        .write = guard_output_write,
        .write_terminal = guard_output_terminal,
        .complete = guard_output_complete,
        .idle = guard_output_idle,
    };
    return wps_guard_init(&runtime, &output);
}

static wifi_security_session_result_t integrated_sae_runtime_start(
    void *context, const wifi_shield_target_t *targets, size_t target_count,
    const wifi_security_session_config_t *config)
{
    assert(context == &f);
    return wifi_shield_start_sae_profile(targets, target_count, config);
}

static bool integrated_sae_runtime_stop(void *context, uint32_t timeout_ms)
{
    assert(context == &f);
    return wifi_shield_stop_sae_profile(timeout_ms);
}

static bool integrated_sae_output_terminal(
    void *context, const sae_guard_status_t *status, const char *outcome)
{
    assert(context == &f && status != NULL && outcome != NULL);
    char line[SAE_GUARD_LINE_MAX];
    int length = sae_guard_format_terminal_for_output(
        line, sizeof(line), status, outcome);
    return length > 0 && guard_output_append(line, (size_t)length);
}

static bool init_integrated_sae_guard(void)
{
    const sae_guard_runtime_hooks_t runtime = {
        .context = &f,
        .enter = guard_state_enter,
        .leave = guard_state_leave,
        .scan_snapshot = guard_scan_snapshot,
        .scan_release = guard_scan_release,
        .monotonic_us = guard_monotonic_us,
        .status_snapshot = guard_runtime_status,
        .start = integrated_sae_runtime_start,
        .stop = integrated_sae_runtime_stop,
    };
    const sae_guard_output_hooks_t output = {
        .context = &f,
        .enter = guard_output_enter,
        .leave = guard_output_leave,
        .write = guard_output_write,
        .write_terminal = integrated_sae_output_terminal,
        .complete = guard_output_complete,
        .idle = guard_output_idle,
    };
    return sae_guard_init(&runtime, &output);
}

static void wait_flag(bool *flag)
{
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while (!*flag) assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}

static void wait_radio_attempts(unsigned count)
{
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while (f.radio_enter_attempts < count)
        assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}

static void wait_profile_gate_attempts(unsigned count)
{
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while (f.profile_gate_enter_attempts < count)
        assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}

static void release_gate(bool *flag)
{
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    *flag = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}

typedef struct {
    bool result;
    int command_result;
    wifi_shield_presentation_snapshot_t snapshot;
    wifi_shield_compact_event_t compact;
} async_result_t;

static void *poll_thread(void *argument)
{
    (void)argument;
    wifi_shield_worker_poll();
    return NULL;
}

static void *lock_thread(void *argument)
{
    async_result_t *result = argument;
    async_actor = ASYNC_ACTOR_LOCK;
    result->result = wifi_shield_channel_lock_running(
        f.config.context, f.scan[0].bssid, f.scan[0].channel);
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *release_thread(void *argument)
{
    async_result_t *result = argument;
    async_actor = ASYNC_ACTOR_RELEASE;
    result->result = wifi_shield_channel_release_running(f.config.context);
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *stop_thread(void *argument)
{
    async_result_t *result = argument;
    async_actor = ASYNC_ACTOR_STOP;
    result->result = wifi_shield_stop(100U);
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *profile_stop_thread(void *argument)
{
    async_result_t *result = argument;
    async_actor = ASYNC_ACTOR_STOP;
    result->result = wifi_shield_stop_wps_profile(100U);
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *sae_profile_stop_thread(void *argument)
{
    async_result_t *result = argument;
    async_actor = ASYNC_ACTOR_STOP;
    result->result = wifi_shield_stop_sae_profile(100U);
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *trust_profile_stop_thread(void *argument)
{
    async_result_t *result = argument;
    async_actor = ASYNC_ACTOR_STOP;
    result->result = wifi_shield_stop_trust_profile(100U);
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

typedef struct {
    wifi_shield_target_t target;
    wifi_security_session_config_t config;
    wifi_security_session_result_t result;
} profile_start_thread_t;

static void *profile_start_thread(void *argument)
{
    profile_start_thread_t *start = argument;
    async_actor = ASYNC_ACTOR_PROFILE_START;
    async_profile_module = WIFI_SECURITY_MODULE_WPS_GUARD;
    start->result = wifi_shield_start_wps_profile(
        &start->target, 1U, &start->config);
    async_profile_module = WIFI_SECURITY_MODULE_NONE;
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *sae_profile_start_thread(void *argument)
{
    profile_start_thread_t *start = argument;
    async_actor = ASYNC_ACTOR_PROFILE_START;
    async_profile_module = WIFI_SECURITY_MODULE_SAE_GUARD;
    start->result = wifi_shield_start_sae_profile(
        &start->target, 1U, &start->config);
    async_profile_module = WIFI_SECURITY_MODULE_NONE;
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *trust_profile_start_thread(void *argument)
{
    profile_start_thread_t *start = argument;
    async_actor = ASYNC_ACTOR_PROFILE_START;
    async_profile_module = WIFI_SECURITY_MODULE_TRUST_MONITOR;
    start->result = wifi_shield_start_trust_profile(
        &start->target, 1U, &start->config);
    async_profile_module = WIFI_SECURITY_MODULE_NONE;
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *guard_start_thread(void *argument)
{
    async_result_t *result = argument;
    async_actor = ASYNC_ACTOR_PROFILE_START;
    char *start[] = {"wps_guard", "start"};
    result->command_result = wps_guard_command(2, start);
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *guard_stop_thread(void *argument)
{
    async_result_t *result = argument;
    async_actor = ASYNC_ACTOR_STOP;
    char *stop[] = {"wps_guard", "stop"};
    result->command_result = wps_guard_command(2, stop);
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *sae_guard_start_thread(void *argument)
{
    async_result_t *result = argument;
    async_actor = ASYNC_ACTOR_PROFILE_START;
    char *start[] = {"sae_guard", "start"};
    result->command_result = sae_guard_command(2, start);
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *sae_guard_stop_thread(void *argument)
{
    async_result_t *result = argument;
    async_actor = ASYNC_ACTOR_STOP;
    char *stop[] = {"sae_guard", "stop"};
    result->command_result = sae_guard_command(2, stop);
    async_actor = ASYNC_ACTOR_NONE;
    return NULL;
}

static void *start_thread(void *argument)
{
    async_result_t *result = argument;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    result->command_result = wifi_shield_command(4, start);
    return NULL;
}

static void *active_start_thread(void *argument)
{
    async_result_t *result = argument;
    char *start[] = {"wifi_shield", "start", "--only", "1",
                     "--defence", "decoy-4way"};
    result->command_result = wifi_shield_command(6, start);
    return NULL;
}

static void *status_thread(void *argument)
{
    async_result_t *result = argument;
    char *status[] = {"wifi_shield", "status"};
    result->command_result = wifi_shield_command(2, status);
    return NULL;
}

static void *invalid_command_thread(void *argument)
{
    async_result_t *result = argument;
    char *invalid[] = {"wifi_shield", "invalid"};
    result->command_result = wifi_shield_command(2, invalid);
    return NULL;
}

static void *presentation_get_thread(void *argument)
{
    async_result_t *result = argument;
    wifi_shield_presentation_get(&result->snapshot);
    return NULL;
}

static void *compact_thread(void *argument)
{
    async_result_t *result = argument;
    result->result = wifi_shield_consume_compact(
        f.config.context, &result->compact);
    return NULL;
}

static int command(int argc, char **argv)
{
    heap_watch = true;
    int result = wifi_shield_command(argc, argv);
    heap_watch = false;
    return result;
}

static void scenario_incomplete_hooks_and_header_contract(void)
{
    memset(&f, 0, sizeof(f));
    f.output_idle = true;
    wifi_shield_runtime_hooks_t runtime = runtime_hooks();
    wifi_shield_output_hooks_t output = output_hooks();
    size_t retained_bytes = wifi_shield_retained_size();
    assert(retained_bytes != 0U && retained_bytes <= sizeof(retained_storage));
    assert(!(wifi_shield_init)(&runtime, &output, NULL, retained_bytes));
    assert(!(wifi_shield_init)(&runtime, &output, retained_storage,
                               retained_bytes - 1U));
    assert(!(wifi_shield_init)(&runtime, &output, retained_storage + 1U,
                               retained_bytes));
    runtime.trust_snapshot = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.defence_random = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.defence_tx = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.retune = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.radio_enter = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.radio_leave = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.state_enter = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.state_leave = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.runtime_status = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.reserve_scan = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.abort_prepare = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.quiesce_radio = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.finish_radio_cleanup = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.profile_start_radio = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.profile_stop_radio = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.profile_retune = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.profile_gate_enter = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.profile_gate_leave = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.journal_drain = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.journal_finish = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    output.drain = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    output = output_hooks();
    output.take_failures = NULL;
    assert(!wifi_shield_init(&runtime, &output));
    runtime = runtime_hooks();
    runtime.journal_boot_id = NULL;
    runtime.journal_start = NULL;
    runtime.journal_submit = NULL;
    runtime.journal_status = NULL;
    runtime.journal_acknowledge_degraded = NULL;
    runtime.journal_drain = NULL;
    runtime.journal_finish = NULL;
    output = output_hooks();
    assert(wifi_shield_init(&runtime, &output));
    char *log_status[] = {"wifi_shield", "log", "status"};
    assert(command(3, log_status) == 0);
    assert(strcmp(f.last_line,
        "[SHIELD/2] LOG STATE=unavailable PATH=- BYTES=0 RECORDS=0 "
        "QUEUE_HIGH=0 DROPS=0 FAILURES=0 ADMISSION_DROPS=0 "
        "ENCODING_FAILURES=0 WRITE_FAILURES=0 SYNC_FAILURES=0 "
        "FINALIZATION_FAILURES=0 TIME=monotonic\r\n") == 0);
    assert(wifi_shield_state_size() > sizeof(wifi_shield_channel_plan_t) +
           sizeof(wifi_shield_core_t) + sizeof(wifi_shield_wps_table_t));
    assert(strcmp(WIFI_SHIELD_HELP_TEXT,
        "Wi-Fi Shield: start [--only indexes...] [--protect-all | --defence decoy-4way [--pmkid-decoy [--multi-vector]]] | status | report | log status | stop") == 0);
}

static void scenario_parse_failure_before_mutation(void)
{
    reset_fixture(1U);
    char *argv[] = {"wifi_shield", "start", "--bad"};
    assert(command(3, argv) == 1);
    assert(f.acquire_calls == 0U && f.scan_all_calls == 0U && f.start_calls == 0U);
    assert(!wifi_shield_busy());
}

static void scenario_bare_scan_single_channel_and_stop_order(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    assert(f.scan_all_calls == 1U && f.scan_snapshot_calls == 0U);
    assert(f.reserve_calls == 1U && f.abort_calls == 0U && !f.reserved);
    size_t reserved = 0U, scanned = 0U;
    while (reserved < f.order_count && f.order[reserved] != EV_RESERVE) ++reserved;
    while (scanned < f.order_count && f.order[scanned] != EV_SCAN) ++scanned;
    assert(reserved < scanned);
    assert(f.tune_calls == 1U && f.tuned_channel == 1U && f.start_calls == 1U);
    size_t staged = 0U, started = 0U;
    while (staged < f.order_count && f.order[staged] != EV_TUNE) ++staged;
    while (started < f.order_count && f.order[started] != EV_START) ++started;
    assert(staged < started);
    assert(strstr(f.all_lines, "[SHIELD/1] ARMED MODE=passive TARGETS=1 CHANNELS=1 COVERAGE=continuous") != NULL);
    assert(wifi_shield_busy());
    assert(wifi_shield_stop(123U));
    assert(!wifi_shield_busy() && f.release_calls == 1U && f.terminal_calls == 1U);
    assert(strcmp(f.terminal_outcome, "stopped") == 0);
    size_t stop = 0U;
    while (stop < f.order_count && f.order[stop] != EV_QUIESCE) ++stop;
    assert(stop + 5U < f.order_count);
    assert(f.order[stop + 1U] == EV_DRAIN);
    assert(f.order[stop + 2U] == EV_FINISH);
    assert(f.order[stop + 3U] == EV_WIPE);
    assert(f.order[stop + 4U] == EV_RELEASE);
    assert(f.order[stop + 5U] == EV_TERMINAL);
}

static void scenario_start_publishes_selected_target_identity(void)
{
    reset_fixture(1U);
    static const uint8_t bssid[6] = {0xb0U, 0xbeU, 0x76U, 0x70U, 0x0eU, 0x90U};
    memcpy(f.scan[0].bssid, bssid, sizeof(bssid));
    f.scan[0].channel = 4U;
    (void)snprintf(f.scan[0].ssid, sizeof(f.scan[0].ssid), "TP-Link_0E90");
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    char *armed = strstr(f.all_lines,
        "[SHIELD/1] ARMED MODE=passive TARGETS=1 CHANNELS=4 COVERAGE=continuous\r\n");
    char *target = strstr(f.all_lines,
        "[SHIELD/1] TARGET N=1/1 SSID=\"TP-Link_0E90\" "
        "BSSID=b0:be:76:70:0e:90 CH=4\r\n");
    assert(armed != NULL && target != NULL && armed < target);
    assert(strstr(target + 1, "[SHIELD/1] TARGET ") == NULL);
    assert(wifi_shield_stop(100U));
}

static void scenario_start_escapes_target_ssids_and_lists_each_target(void)
{
    reset_fixture(2U);
    static const char unsafe[] = {'L', 'a', 'b', '"', '\\', '\r', '\n', '\0'};
    memcpy(f.scan[0].ssid, unsafe, sizeof(unsafe));
    f.scan[1].ssid[0] = '\0';
    char *start[] = {"wifi_shield", "start", "--only", "1", "2"};
    assert(command(5, start) == 0);
    char *first = strstr(f.all_lines,
        "[SHIELD/1] TARGET N=1/2 SSID=\"Lab\\\"\\\\\\x0d\\x0a\" "
        "BSSID=02:00:00:00:00:01 CH=1\r\n");
    char *second = strstr(f.all_lines,
        "[SHIELD/1] TARGET N=2/2 SSID=\"<hidden>\" "
        "BSSID=02:00:00:00:00:02 CH=6\r\n");
    assert(first != NULL && second != NULL && first < second);
    assert(strstr(second + 1, "[SHIELD/1] TARGET ") == NULL);
    assert(wifi_shield_stop(100U));
}

static void scenario_only_snapshot_and_multi_channel(void)
{
    reset_fixture(3U);
    char *start[] = {"wifi_shield", "start", "--only", "3", "1"};
    assert(command(5, start) == 0);
    assert(f.scan_all_calls == 0U && f.scan_snapshot_calls == 1U);
    assert(f.reserve_calls == 0U && f.abort_calls == 0U);
    assert(f.snapshot_count == 2U && f.snapshot_indices[0] == 3U &&
           f.snapshot_indices[1] == 1U);
    assert(f.tuned_channel == 11U);
    assert(strstr(f.all_lines, "TARGETS=2 CHANNELS=11,1 COVERAGE=sampled") != NULL);
    assert(wifi_shield_stop(100U));
}

static void scenario_duplicate_and_invalid_indices(void)
{
    reset_fixture(2U);
    char *duplicate[] = {"wifi_shield", "start", "--only", "1", "1"};
    assert(command(5, duplicate) == 1);
    assert(f.acquire_calls == 0U && f.scan_snapshot_calls == 0U);
    char *zero[] = {"wifi_shield", "start", "--only", "0"};
    assert(command(4, zero) == 1);
    assert(f.acquire_calls == 0U);
    char *missing[] = {"wifi_shield", "start", "--only", "9"};
    assert(command(4, missing) == 1);
    assert(f.acquire_calls == 1U && f.release_calls == 1U && !wifi_shield_busy());
}

static void scenario_no_memory(void)
{
    reset_fixture(1U);
    f.storage_fail = true;
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 1);
    assert(f.start_calls == 0U && f.terminal_calls == 1U);
    assert(strcmp(f.terminal_outcome, "no_mem") == 0 && !wifi_shield_busy());

    reset_fixture(1U);
    f.storage_fail = true;
    char *protect_all[] = {
        "wifi_shield", "start", "--only", "1", "--protect-all"
    };
    assert(command(5, protect_all) == 1);
    assert(strcmp(f.terminal_outcome, "no_mem") == 0);
    assert(f.terminal_status.active_defence);
    assert(f.terminal_status.pmkid_decoy);
    assert(f.terminal_status.multi_vector);
    assert(f.terminal_status.protect_all);
}

static void scenario_reserve_failure_retries_retained_abort(void)
{
    reset_fixture(1U);
    f.reserve_ok = false;
    f.reserve_retained = true;
    f.abort_ok = false;
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 1);
    assert(f.reserve_calls == 1U && f.abort_calls == 1U);
    assert(f.reserved && wifi_shield_busy());
    assert(f.release_calls == 0U && f.terminal_calls == 0U);

    f.abort_ok = true;
    assert(wifi_shield_stop(100U));
    assert(!f.reserved && f.abort_calls == 2U);
    assert(f.release_calls == 1U && !wifi_shield_busy());
    assert(strcmp(f.terminal_outcome, "stopped") == 0);
}

static void scenario_partial_snapshot_failure_wipes_before_release(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 0U;
    f.trust_fill = true;
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 1);
    assert(f.scan_all_calls == 1U && f.trust_calls == 1U);
    assert(f.release_calls == 1U && !wifi_shield_busy());
    assert(strcmp(f.terminal_outcome, "invalid") == 0);
}

static void scenario_protect_all_prestart_failure_keeps_requested_mode(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "9", "--protect-all"};
    assert(command(5, start) == 1);
    assert(f.scan_snapshot_calls == 1U && f.release_calls == 1U);
    assert(strcmp(f.terminal_outcome, "invalid") == 0);
    assert(f.terminal_status.active_defence);
    assert(f.terminal_status.pmkid_decoy);
    assert(f.terminal_status.multi_vector);
    assert(f.terminal_status.protect_all);
}

static void scenario_prestart_cleanup_blocks_reentrant_terminal(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 0U;
    f.reenter_abort = true;
    f.reenter_release = true;
    unsigned terminals = f.terminal_calls;
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 1);
    assert(f.cleanup_reenter_calls == 2U);
    assert(f.cleanup_reenter_acquire_delta == 0U);
    assert(f.terminal_calls == terminals + 1U);
    assert(strcmp(f.terminal_outcome, "invalid") == 0);
    assert(!wifi_shield_busy());
}

static void scenario_absent_trust_disables_comparison(void)
{
    reset_fixture(1U);
    f.trust_fill = true;
    f.trust_ok = false;
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    assert(f.trust_calls == 1U && wifi_shield_busy());
    assert(wifi_shield_stop(100U));
}

static void start_result_scenario(wifi_security_session_result_t result,
                                  const char *outcome)
{
    reset_fixture(1U);
    f.start_result = result;
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 1);
    assert(f.start_calls == 1U && f.release_calls == 1U);
    assert(strcmp(f.terminal_outcome, outcome) == 0 && !wifi_shield_busy());
}

static void scenario_connected_busy_worker(void)
{
    start_result_scenario(WIFI_SECURITY_SESSION_BASELINE_BUSY, "busy");
    start_result_scenario(WIFI_SECURITY_SESSION_BUSY, "busy");
    start_result_scenario(WIFI_SECURITY_SESSION_WORKER_FAILED, "invalid");
}

static void scenario_uncertain_adopted_start_uses_full_retry_cleanup(void)
{
    reset_fixture(1U);
    f.start_result = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 1);
    assert(wifi_shield_busy() && f.release_calls == 0U);
    assert(wifi_shield_stop(100U));
    assert(f.abort_calls == 1U);
    assert(f.quiesce_calls == 1U && f.drain_calls == 1U &&
           f.finish_calls == 1U && f.release_calls == 1U);
    assert(!wifi_shield_busy());
}

static void scenario_tune_failure(void)
{
    reset_fixture(1U);
    f.tune_ok = false;
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 1);
    assert(f.tune_calls == 1U && f.start_calls == 0U &&
           f.abort_calls == 1U && f.release_calls == 1U);
    assert(strcmp(f.terminal_outcome, "restore_failed") == 0);
    assert(f.journal_start_calls == 1U && f.journal_finish_calls == 1U);
    assert(f.journal_record_count >= 2U);
    assert(f.journal_records[f.journal_record_count - 1U].type ==
           WIFI_SHIELD_JOURNAL_SESSION_TERMINAL);
}

static void scenario_prestart_journal_join_retry_is_bounded(void)
{
    reset_fixture(1U);
    f.tune_ok = false;
    f.journal_finish_ok = false;
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 1);
    assert(wifi_shield_busy() && f.release_calls == 0U &&
           f.start_calls == 0U && f.journal_finish_calls == 1U);
    unsigned radio_enters = f.radio_enter_calls;
    f.journal_finish_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.radio_enter_calls == radio_enters && f.quiesce_calls == 0U &&
           f.finish_calls == 0U && f.journal_finish_calls == 2U &&
           f.release_calls == 1U);
    assert(strcmp(f.terminal_outcome, "restore_failed") == 0);
}

static void scenario_prepare_abort_quarantines_and_retries(void)
{
    reset_fixture(0U);
    f.abort_ok = false;
    char *start[] = {"wifi_shield", "start"};
    unsigned terminals = f.terminal_calls;
    assert(command(2, start) == 1);
    assert(f.reserve_calls == 1U && f.abort_calls == 1U && f.reserved);
    assert(wifi_shield_busy() && f.release_calls == 0U &&
           f.terminal_calls == terminals);
    f.abort_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.abort_calls == 2U && !f.reserved && f.release_calls == 1U);
    assert(!wifi_shield_busy() && f.terminal_calls == terminals + 1U);
}

static void scenario_duplicate_start_and_read_only_status(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    unsigned acquisitions = f.acquire_calls;
    assert(command(2, start) == 1);
    assert(f.acquire_calls == acquisitions && wifi_shield_busy());
    assert(strcmp(f.terminal_outcome, "busy") == 0);
    char *status[] = {"wifi_shield", "status"};
    unsigned stops = f.quiesce_calls;
    assert(command(2, status) == 0);
    assert(f.quiesce_calls == stops && wifi_shield_busy());
    assert(strstr(f.last_line, "[SHIELD/1] STATUS RUNNING=1") != NULL);
    assert(wifi_shield_stop(100U));
}

static void scenario_armed_output_failure_cleans(void)
{
    reset_fixture(1U);
    f.fail_write = true;
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 1);
    assert(f.quiesce_calls == 1U && f.drain_calls == 1U &&
           f.finish_calls == 1U && f.release_calls == 1U &&
           !wifi_shield_busy());
    assert(f.terminal_calls == 1U);
    assert(strcmp(f.terminal_outcome, "output_failed") == 0);
}

static void scenario_quarantine_retries_without_success(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    f.quiesce_ok = false;
    unsigned terminals = f.terminal_calls;
    assert(!wifi_shield_stop(100U));
    assert(f.quiesce_calls == 1U && f.drain_calls == 0U &&
           f.finish_calls == 0U && wifi_shield_busy() && !f.released &&
           f.terminal_calls == terminals);
    f.quiesce_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.quiesce_calls == 2U && f.drain_calls == 1U &&
           f.finish_calls == 1U);
    assert(!wifi_shield_busy() && f.terminal_calls == terminals + 1U);
    assert(strcmp(f.terminal_outcome, "stopped") == 0);
}

static void scenario_output_publisher_quarantine(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    f.drain_ok = false;
    unsigned terminals = f.terminal_calls;
    assert(!wifi_shield_stop(100U));
    assert(f.quiesce_calls == 1U && f.drain_calls == 1U &&
           f.finish_calls == 0U && wifi_shield_busy() && !f.released &&
           f.terminal_calls == terminals);
    f.drain_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.quiesce_calls == 1U && f.drain_calls == 2U &&
           f.finish_calls == 1U);
    assert(!wifi_shield_busy() && f.release_calls == 1U);
    assert(f.terminal_calls == terminals + 1U);
}

static void scenario_async_output_failure_is_terminal_not_quarantine(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    f.async_failures = 2U;
    assert(wifi_shield_stop(100U));
    assert(f.drain_calls == 1U && f.finish_calls == 1U);
    assert(strcmp(f.terminal_outcome, "output_failed") == 0);
    assert(f.terminal_status.output_failures == 2U);
    assert(!wifi_shield_busy());
}

static void scenario_concurrent_output_failure_precedes_stop_terminal(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);

    f.fail_write = true;
    f.block_failed_leave = true;
    async_result_t status_result = {.command_result = -1};
    pthread_t status_worker;
    assert(pthread_create(&status_worker, NULL, status_thread,
                          &status_result) == 0);
    wait_flag(&f.failed_leave_entered);

    f.fail_write = false;
    async_result_t stop_result = {0};
    pthread_t stopper;
    assert(pthread_create(&stopper, NULL, stop_thread, &stop_result) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(!stop_result.result);
    assert(f.terminal_calls == 0U && wifi_shield_busy());

    release_gate(&f.release_failed_leave);
    assert(pthread_join(status_worker, NULL) == 0);
    assert(status_result.command_result == 1);
    assert(wifi_shield_stop(100U));
    assert(f.terminal_calls == 1U);
    assert(strcmp(f.terminal_outcome, "output_failed") == 0);
    assert(f.terminal_status.output_failures == 1U);
    assert(f.release_calls == 1U && !wifi_shield_busy());
}

static void scenario_output_enter_timeout_blocks_success_terminal(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);

    f.block_output_enter_once = true;
    f.fail_blocked_output_enter = true;
    async_result_t status_result = {.command_result = -1};
    pthread_t status_worker;
    assert(pthread_create(&status_worker, NULL, status_thread,
                          &status_result) == 0);
    wait_flag(&f.output_enter_blocked);

    assert(!wifi_shield_stop(100U));
    assert(f.terminal_calls == 0U && wifi_shield_busy());

    release_gate(&f.release_output_enter);
    assert(pthread_join(status_worker, NULL) == 0);
    assert(status_result.command_result == 1);
    assert(wifi_shield_stop(100U));
    assert(f.terminal_calls == 1U);
    assert(strcmp(f.terminal_outcome, "output_failed") == 0);
    assert(f.terminal_status.output_failures == 1U);
    assert(f.release_calls == 1U && !wifi_shield_busy());
}

static void scenario_finish_cleanup_retry_only(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    f.finish_ok = false;
    unsigned terminals = f.terminal_calls;
    assert(!wifi_shield_stop(100U));
    assert(f.quiesce_calls == 1U && f.drain_calls == 1U &&
           f.finish_calls == 1U && !f.released &&
           f.terminal_calls == terminals);
    assert(f.journal_finish_calls == 0U);
    assert(f.journal_record_count >= 2U);
    assert(f.journal_records[f.journal_record_count - 1U].type ==
           WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN);
    assert(f.journal_drain_calls == 1U &&
           f.journal_drain_finish_calls == 1U &&
           f.journal_drain_record_count == f.journal_record_count);
    f.journal_fail_terminal_until_drain = true;
    f.finish_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.quiesce_calls == 1U && f.drain_calls == 1U &&
           f.finish_calls == 2U && f.released);
    assert(f.journal_finish_calls == 1U);
    assert(f.journal_drain_calls == 2U);
    assert(f.journal_records[f.journal_record_count - 1U].type ==
           WIFI_SHIELD_JOURNAL_SESSION_TERMINAL);
    assert(f.journal_status.state == WIFI_SHIELD_JOURNAL_FINALIZED);
}

static void scenario_uncertain_checkpoint_timeout_retries_before_radio(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    f.finish_ok = false;
    f.journal_drain_ok = false;
    assert(!wifi_shield_stop(100U));
    assert(f.finish_calls == 1U && f.journal_drain_calls == 1U &&
           f.release_calls == 0U && wifi_shield_busy());
    size_t records = f.journal_record_count;
    unsigned radio_enters = f.radio_enter_calls;

    /* A pending checkpoint retry is storage-only until drain succeeds. */
    assert(!wifi_shield_stop(100U));
    assert(f.journal_drain_calls == 2U && f.finish_calls == 1U &&
           f.radio_enter_calls == radio_enters &&
           f.journal_record_count == records && f.release_calls == 0U);

    f.journal_drain_ok = true;
    assert(!wifi_shield_stop(100U));
    assert(f.journal_drain_calls == 3U && f.finish_calls == 2U &&
           f.journal_record_count == records && f.release_calls == 0U);

    f.finish_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.journal_drain_calls == 3U && f.finish_calls == 3U &&
           f.release_calls == 1U && !wifi_shield_busy());
}

static void scenario_uncertain_queue_full_drains_retries_then_recovers(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    f.finish_ok = false;
    f.journal_fail_uncertain_until_drain = true;

    assert(!wifi_shield_stop(100U));
    /* First drain creates queue capacity; the second makes the retried
     * uncertainty record durable before the Stop returns. */
    assert(f.journal_drain_calls == 2U && f.journal_record_count >= 2U);
    assert(f.journal_records[f.journal_record_count - 1U].type ==
           WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN);
    size_t uncertain_index = f.journal_record_count - 1U;

    f.finish_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.journal_records[uncertain_index].type ==
           WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN);
    assert(f.journal_records[f.journal_record_count - 1U].type ==
           WIFI_SHIELD_JOURNAL_SESSION_TERMINAL);
    assert(f.journal_status.state == WIFI_SHIELD_JOURNAL_FINALIZED &&
           f.release_calls == 1U && !wifi_shield_busy());
}

static void scenario_initial_uncertainty_callback_keeps_stop_exclusive(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    f.finish_ok = false;
    f.finish_failure_reports_uncertainty = true;
    f.block_journal_drain = true;

    async_result_t first = {0};
    pthread_t finisher;
    assert(pthread_create(&finisher, NULL, stop_thread, &first) == 0);
    wait_flag(&f.journal_drain_entered);
    unsigned drains = f.journal_drain_calls;
    unsigned radio_enters = f.radio_enter_calls;
    unsigned finishes = f.finish_calls;
    assert(!wifi_shield_stop(100U));
    assert(f.journal_drain_calls == drains &&
           f.radio_enter_calls == radio_enters &&
           f.finish_calls == finishes && f.release_calls == 0U);

    release_gate(&f.release_journal_drain);
    assert(pthread_join(finisher, NULL) == 0 && !first.result);
    assert(f.finish_calls == 1U && f.release_calls == 0U &&
           wifi_shield_busy());
    f.finish_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.finish_calls == 2U && f.release_calls == 1U &&
           !wifi_shield_busy());
}

static void enter_quarantined_uncertainty_pending(void)
{
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    f.finish_ok = false;
    f.journal_drain_ok = false;
    assert(!wifi_shield_stop(100U));
    assert(f.journal_drain_calls == 1U && f.finish_calls == 1U &&
           f.release_calls == 0U && wifi_shield_busy());
    f.journal_drain_ok = true;
}

static void scenario_quarantined_uncertainty_retry_is_exclusive(void)
{
    reset_fixture(1U);
    enter_quarantined_uncertainty_pending();
    f.block_journal_drain = true;
    async_result_t first = {0};
    pthread_t finisher;
    assert(pthread_create(&finisher, NULL, stop_thread, &first) == 0);
    wait_flag(&f.journal_drain_entered);
    unsigned drains = f.journal_drain_calls;
    unsigned radio_enters = f.radio_enter_calls;
    assert(!wifi_shield_stop(100U));
    assert(f.journal_drain_calls == drains &&
           f.radio_enter_calls == radio_enters && f.release_calls == 0U);
    release_gate(&f.release_journal_drain);
    assert(pthread_join(finisher, NULL) == 0 && !first.result);
    assert(f.journal_drain_calls == drains && f.finish_calls == 2U &&
           f.release_calls == 0U && wifi_shield_busy());
    f.finish_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.release_calls == 1U && !wifi_shield_busy());

    reset_fixture(1U);
    enter_quarantined_uncertainty_pending();
    f.reenter_journal_drain = true;
    assert(!wifi_shield_stop(100U));
    assert(f.journal_drain_reenter_stop_result == 0 &&
           f.journal_drain_calls == 2U && f.finish_calls == 2U &&
           f.release_calls == 0U && wifi_shield_busy());
    f.finish_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.release_calls == 1U && !wifi_shield_busy());
}

static void scenario_terminal_blocks_reentrant_start(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    f.reenter_terminal = true;
    assert(wifi_shield_stop(100U));
    assert(f.reenter_result == 1 && f.reenter_acquire_delta == 0U);
    assert(f.terminal_calls == 1U && !wifi_shield_busy());
}

static void scenario_late_generation_is_inert(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start"};
    assert(command(2, start) == 0);
    wifi_security_session_config_t old = f.config;
    assert(!old.consume(old.context, NULL, NULL));
    assert(wifi_shield_stop(100U));
    assert(!old.validate(old.context));
    assert(!old.consume(old.context, NULL, NULL));

    f.lease_released = false;
    assert(command(2, start) == 0);
    unsigned releases = f.release_calls;
    old.wipe(old.context);
    assert(wifi_shield_busy() && f.release_calls == releases);
    assert(!f.config.consume(f.config.context, NULL, NULL));
    assert(wifi_shield_stop(100U));
}

static void be16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8U);
    bytes[1] = (uint8_t)value;
}

static size_t make_wps_frame(uint8_t frame[128], const uint8_t bssid[6],
                             bool protected_frame)
{
    static const uint8_t station[6] = {0x04, 6, 7, 8, 9, 10};
    static const uint8_t snap[] = {0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e};
    static const uint8_t wsc_header[] = {
        2, 0, 0, 0, 1, 37, 0, 0, 254, 0, 0x37, 0x2a,
        0, 0, 0, 1, 4, 0
    };
    static const uint8_t message_type[] = {0x10, 0x22, 0, 1, 0x04};
    memset(frame, 0, 128U);
    frame[0] = 0x08U;
    frame[1] = protected_frame ? 0x42U : 0x02U;
    memcpy(frame + 4U, station, 6U);
    memcpy(frame + 10U, bssid, 6U);
    memcpy(frame + 16U, bssid, 6U);
    memcpy(frame + 24U, snap, sizeof(snap));
    memcpy(frame + 32U, wsc_header, sizeof(wsc_header));
    memcpy(frame + 32U + sizeof(wsc_header), message_type,
           sizeof(message_type));
    size_t eapol_length = sizeof(wsc_header) + sizeof(message_type);
    be16(frame + 34U, (uint16_t)(eapol_length - 4U));
    be16(frame + 38U, (uint16_t)(eapol_length - 4U));
    return 32U + eapol_length;
}

static size_t make_eapol_key_frame(uint8_t frame[256],
                                   const uint8_t bssid[6],
                                   const uint8_t station[6],
                                   uint16_t key_info)
{
    static const uint8_t snap[] = {
        0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e
    };
    memset(frame, 0, 256U);
    frame[0] = 0x08U;
    frame[1] = 0x01U; /* To DS: station to AP. */
    memcpy(frame + 4U, bssid, 6U);
    memcpy(frame + 10U, station, 6U);
    memcpy(frame + 16U, bssid, 6U);
    memcpy(frame + 24U, snap, sizeof(snap));
    uint8_t *eapol = frame + 32U;
    eapol[0] = 2U;
    eapol[1] = 3U; /* EAPOL-Key. */
    be16(eapol + 2U, 95U);
    eapol[4] = 2U; /* RSN Key descriptor. */
    be16(eapol + 5U, key_info);
    return 131U;
}

static bool deliver_full_rssi(uint8_t frame[128], size_t length,
                              uint8_t channel, bool truncated, int8_t rssi)
{
    wifi_security_decoded_t decoded;
    assert(wifi_security_decode(frame, length, &decoded));
    wifi_security_frame_slot_t slot = {0};
    memcpy(slot.bytes, frame, length);
    slot.captured_len = (uint16_t)length;
    slot.original_len = (uint16_t)(length + (truncated ? 10U : 0U));
    slot.channel = channel;
    slot.rssi = rssi;
    slot.truncated = truncated;
    return f.config.consume(f.config.context, &slot, &decoded);
}

static bool deliver_full(uint8_t frame[128], size_t length, uint8_t channel,
                         bool truncated)
{
    return deliver_full_rssi(frame, length, channel, truncated, -42);
}

static size_t make_beacon(uint8_t frame[128], const uint8_t bssid[6],
                          const char *ssid)
{
    size_t length = strlen(ssid);
    assert(length <= 32U);
    memset(frame, 0, 128U);
    frame[0] = 0x80U;
    memset(frame + 4U, 0xff, 6U);
    memcpy(frame + 10U, bssid, 6U);
    memcpy(frame + 16U, bssid, 6U);
    frame[32] = 100U; /* 100 TU beacon interval. */
    frame[33] = 0U;
    frame[36] = 0U;
    frame[37] = (uint8_t)length;
    memcpy(frame + 38U, ssid, length);
    return 38U + length;
}

static size_t append_transition_posture(uint8_t frame[128], size_t length)
{
    static const uint8_t rsn[] = {
        1U, 0U,                         /* version */
        0x00U, 0x0fU, 0xacU, 0x02U,   /* group TKIP */
        1U, 0U,
        0x00U, 0x0fU, 0xacU, 0x04U,   /* pairwise CCMP */
        2U, 0U,
        0x00U, 0x0fU, 0xacU, 0x02U,   /* PSK */
        0x00U, 0x0fU, 0xacU, 0x08U,   /* SAE */
        0U, 0U,                         /* PMF not required */
    };
    static const uint8_t wps[] = {
        0x00U, 0x50U, 0xf2U, 0x04U,
        0x10U, 0x44U, 0x00U, 0x01U, 0x02U,
    };
    assert(length + 4U + sizeof(rsn) + sizeof(wps) <= 128U);
    frame[34] |= 0x10U;
    frame[length++] = 48U;
    frame[length++] = (uint8_t)sizeof(rsn);
    memcpy(frame + length, rsn, sizeof(rsn));
    length += sizeof(rsn);
    frame[length++] = 221U;
    frame[length++] = (uint8_t)sizeof(wps);
    memcpy(frame + length, wps, sizeof(wps));
    return length + sizeof(wps);
}

static size_t append_safe_posture(uint8_t frame[128], size_t length)
{
    static const uint8_t rsn[] = {
        1U, 0U,
        0x00U, 0x0fU, 0xacU, 0x04U,   /* group CCMP */
        1U, 0U,
        0x00U, 0x0fU, 0xacU, 0x04U,   /* pairwise CCMP */
        1U, 0U,
        0x00U, 0x0fU, 0xacU, 0x08U,   /* SAE only */
        0x40U, 0U,                      /* PMF required */
    };
    assert(length + 2U + sizeof(rsn) <= 128U);
    frame[34] |= 0x10U;
    frame[length++] = 48U;
    frame[length++] = (uint8_t)sizeof(rsn);
    memcpy(frame + length, rsn, sizeof(rsn));
    return length + sizeof(rsn);
}

static size_t record_count(wifi_shield_journal_type_t type)
{
    size_t count = 0U;
    for (size_t i = 0U; i < f.journal_record_count; ++i)
        if (f.journal_records[i].type == type) ++count;
    return count;
}

static size_t text_count(const char *text, const char *needle)
{
    size_t count = 0U;
    size_t length = strlen(needle);
    for (const char *p = text; (p = strstr(p, needle)) != NULL; p += length)
        ++count;
    return count;
}

static void le16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8U);
}

static size_t make_sae_auth(uint8_t frame[128], const uint8_t bssid[6],
                            bool protected_frame, uint16_t sequence)
{
    static const uint8_t station[6] = {0x04, 6, 7, 8, 9, 10};
    memset(frame, 0, 128U);
    frame[0] = 0xb0U;
    frame[1] = protected_frame ? 0x40U : 0U;
    memcpy(frame + 4U, station, 6U);
    memcpy(frame + 10U, bssid, 6U);
    memcpy(frame + 16U, bssid, 6U);
    le16(frame + 22U, (uint16_t)(sequence << 4U));
    if (protected_frame) return 24U;
    le16(frame + 24U, 3U);
    le16(frame + 26U, 1U);
    le16(frame + 28U, 1U);
    return 30U;
}

static void scenario_wps_channel_four_filtering_and_silence(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 4U;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    uint8_t frame[128];
    size_t length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, 4U, false));
    assert(strstr(f.all_lines, "[SHIELD/1] EVENT SOURCE=wps TYPE=enrollment_activity") != NULL);
    assert(strstr(f.all_lines, "[WPS_GUARD/1]") == NULL);
    uint8_t other[6] = {0x02, 9, 8, 7, 6, 5};
    length = make_wps_frame(frame, other, false);
    assert(deliver_full(frame, length, 4U, false));
    length = make_wps_frame(frame, f.scan[0].bssid, true);
    assert(deliver_full(frame, length, 4U, false));
    assert(wifi_shield_stop(100U));
    assert(f.terminal_status.received == 3U);
    assert(f.terminal_status.filtered == 1U);
    assert(f.terminal_status.wps_fragments == 1U);
    assert(f.terminal_status.source_events[WIFI_SHIELD_SOURCE_WPS] >= 1U);
}

static void scenario_trust_readonly_baseline_aggregates_drift(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    uint8_t frame[128];
    size_t length = make_beacon(frame, f.scan[0].bssid, "known");
    sx_observation_t observation;
    assert(sx_parse(frame, length, &observation));
    assert(wifi_trust_profile_from_observation(
        &observation, 6U, f.now_us, &f.trust_profile));
    f.trust_fill = true;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    length = make_beacon(frame, f.scan[0].bssid, "changed");
    ++f.now_us;
    assert(deliver_full(frame, length, 6U, false));
    assert(strstr(f.all_lines, "SOURCE=trust TYPE=security_drift") != NULL);
    assert(strstr(f.all_lines, "[WIFI_TRUST/1]") == NULL);
    assert(wifi_shield_stop(100U));
    assert(f.terminal_status.source_events[WIFI_SHIELD_SOURCE_TRUST] != 0U);

    reset_fixture(1U);
    f.trust_fill = true;
    memset(&f.trust_profile, 0x6b, sizeof(f.trust_profile));
    assert(command(4, start) == 0);
    length = make_beacon(frame, f.scan[0].bssid, "changed");
    assert(deliver_full(frame, length, f.scan[0].channel, false));
    assert(strstr(f.all_lines, "SOURCE=trust") == NULL);
    assert(wifi_shield_stop(100U));
    assert(f.terminal_status.source_events[WIFI_SHIELD_SOURCE_TRUST] == 0U);
}

static void scenario_sae_selected_filter_protected_and_truncated(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    uint8_t frame[128];
    size_t length = make_sae_auth(frame, f.scan[0].bssid, false, 1U);
    assert(deliver_full(frame, length, f.scan[0].channel, false));
    assert(strstr(f.all_lines,
                  "SOURCE=sae TYPE=authentication_activity") != NULL);

    uint8_t other[6] = {0x02, 9, 8, 7, 6, 5};
    length = make_sae_auth(frame, other, false, 2U);
    assert(deliver_full(frame, length, f.scan[0].channel, false));
    length = make_sae_auth(frame, f.scan[0].bssid, true, 3U);
    assert(deliver_full(frame, length, f.scan[0].channel, false));
    for (uint16_t sequence = 4U; sequence < 7U; ++sequence) {
        length = make_sae_auth(frame, f.scan[0].bssid, false, sequence);
        assert(deliver_full(frame, length, f.scan[0].channel, true));
    }
    assert(strstr(f.all_lines, "SOURCE=sae TYPE=protocol_anomaly") != NULL);
    assert(strstr(f.all_lines, "[SAE_GUARD/1]") == NULL);
    assert(wifi_shield_stop(100U));
    assert(f.terminal_status.received == 6U);
    assert(f.terminal_status.filtered == 1U);
    assert(f.terminal_status.source_events[WIFI_SHIELD_SOURCE_SAE] >= 2U);
}

static void compact_header(wifi_shield_compact_event_t *event,
                           wifi_shield_compact_kind_t kind,
                           const uint8_t bssid[6], uint8_t channel,
                           size_t length)
{
    static const uint8_t station[6] = {0x04, 6, 7, 8, 9, 10};
    memset(event, 0, sizeof(*event));
    event->kind = kind;
    event->generation = f.runtime_status.generation;
    event->length = (uint8_t)length;
    event->channel = channel;
    event->rssi = -44;
    memcpy(event->bssid, bssid, 6U);
    memcpy(event->station, station, 6U);
    memcpy(event->bytes + 4U, bssid, 6U);
    memcpy(event->bytes + 10U, station, 6U);
    memcpy(event->bytes + 16U, bssid, 6U);
}

static bool compact_produced_output(wifi_shield_compact_event_t *event)
{
    unsigned before = f.write_calls;
    assert(wifi_shield_consume_compact(f.config.context, event));
    return f.write_calls != before;
}

static void compact_csa(wifi_shield_compact_event_t *event,
                        const uint8_t metadata_bssid[6],
                        const uint8_t raw_bssid[6])
{
    compact_header(event, WIFI_SHIELD_COMPACT_CSA,
                   metadata_bssid, 6U, 47U);
    event->bytes[0] = 0x80U;
    memcpy(event->bytes + 10U, "\x02\x11\x22\x33\x44\x55", 6U);
    memcpy(event->bytes + 16U, raw_bssid, 6U);
    memcpy(event->bytes + 36U, "\x00\x04Test\x25\x03\x01\x24\x03", 11U);
}

static void scenario_compact_mixed_deauth_csa_and_pmkid(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    wifi_shield_compact_event_t event;
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(strstr(f.all_lines, "SOURCE=deauth TYPE=deauth") != NULL);
    assert(strstr(f.all_lines, "WINDOW_MS=10000") != NULL);
    unsigned deauth_output_calls = f.write_calls;
    for (size_t i = 0U; i < 32U; ++i) {
        ++f.now_us;
        assert(wifi_shield_consume_compact(f.config.context, &event));
    }
    assert(f.write_calls == deauth_output_calls);

    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U; event.bytes[26] = 1U;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    ++f.now_us;
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(strstr(f.all_lines, "SOURCE=pmkid TYPE=sequence") == NULL);
    f.now_us += 30000U;
    wifi_shield_worker_poll();
    assert(strstr(f.all_lines, "SOURCE=pmkid TYPE=sequence") != NULL);

    compact_header(&event, WIFI_SHIELD_COMPACT_CSA,
                   f.scan[0].bssid, 6U, 47U);
    event.bytes[0] = 0x80U;
    memcpy(event.bytes + 10U, "\x02\x11\x22\x33\x44\x55", 6U);
    memcpy(event.bytes + 16U, f.scan[0].bssid, 6U);
    memcpy(event.bytes + 36U, "\x00\x04Test\x25\x03\x01\x24\x03", 11U);
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(strstr(f.all_lines,
                  "[SHIELD/2] EVENT SOURCE=deauth TYPE=csa_announcement") != NULL);
    assert(strstr(f.all_lines, "[DEAUTH_V2]") == NULL);
    assert(wifi_shield_stop(100U));
}

static void scenario_compact_validates_raw_identity_before_module_state(void)
{
    static const uint8_t broadcast[6] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    static const uint8_t zero[6] = {0};
    static const uint8_t multicast[6] = {0x03, 1, 2, 3, 4, 5};
    static const uint8_t unselected[6] = {
        0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee
    };
    static const uint8_t unrelated[6] = {
        0x02, 0x91, 0x92, 0x93, 0x94, 0x95
    };
    reset_fixture(2U);
    f.scan[0].channel = 6U;
    f.scan[1].channel = 6U;
    char *start[] = {"wifi_shield", "start", "--only", "1", "2"};
    assert(command(5, start) == 0);

    wifi_shield_compact_event_t event;
    unsigned unexpected = 0U;
    unsigned expected_outputs = 0U;

    /* Deauth: malformed, DS-bearing, impossible direction and untrusted raw
     * identities are inert even when producer metadata claims a target. */
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 25U);
    event.bytes[0] = 0xc0U;
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    event.bytes[1] = 0x01U;
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    memcpy(event.bytes + 4U, unrelated, 6U);
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    memcpy(event.bytes + 16U, unselected, 6U);
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    memcpy(event.bytes + 16U, zero, 6U);
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    memcpy(event.bytes + 16U, multicast, 6U);
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    memcpy(event.bytes + 16U, f.scan[1].bssid, 6U);
    unexpected += compact_produced_output(&event);

    /* Protected AP-to-broadcast robust management is valid evidence. The
     * aggregate Deauth source intentionally permits a broadcast station. */
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    event.bytes[1] = 0x40U;
    memcpy(event.bytes + 4U, broadcast, 6U);
    memcpy(event.bytes + 10U, f.scan[0].bssid, 6U);
    memcpy(event.station, broadcast, 6U);
    expected_outputs += compact_produced_output(&event);

    /* Disassoc has the same raw validation; protected STA-to-AP is accepted. */
    compact_header(&event, WIFI_SHIELD_COMPACT_DISASSOC,
                   f.scan[0].bssid, 6U, 25U);
    event.bytes[0] = 0xa0U;
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_DISASSOC,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xa0U;
    event.bytes[1] = 0x02U;
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_DISASSOC,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xa0U;
    memcpy(event.bytes + 16U, unselected, 6U);
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_DISASSOC,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xa0U;
    event.bytes[1] = 0x40U;
    expected_outputs += compact_produced_output(&event);

    /* CSA validates the raw management header/BSSID before detector output. */
    compact_csa(&event, f.scan[0].bssid, f.scan[0].bssid);
    event.length = 46U;
    unexpected += compact_produced_output(&event);

    compact_csa(&event, f.scan[0].bssid, f.scan[0].bssid);
    event.bytes[1] = 0x01U;
    unexpected += compact_produced_output(&event);

    compact_csa(&event, f.scan[0].bssid, unselected);
    unexpected += compact_produced_output(&event);

    compact_csa(&event, f.scan[0].bssid, f.scan[1].bssid);
    unexpected += compact_produced_output(&event);

    compact_csa(&event, f.scan[0].bssid, f.scan[0].bssid);
    expected_outputs += compact_produced_output(&event);

    /* Protected/DS/invalid/unselected PMKID candidates remain inert. Most
     * importantly, inconsistent metadata cannot seed the detector for a later
     * otherwise-valid association on another selected target. */
    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[1] = 0x40U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    unexpected += compact_produced_output(&event);
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[1] = 0x01U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    unexpected += compact_produced_output(&event);
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    memcpy(event.bytes + 16U, zero, 6U);
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    memcpy(event.bytes + 16U, multicast, 6U);
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    memcpy(event.bytes + 4U, unselected, 6U);
    memcpy(event.bytes + 16U, unselected, 6U);
    unexpected += compact_produced_output(&event);
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    memcpy(event.bytes + 4U, unselected, 6U);
    memcpy(event.bytes + 16U, unselected, 6U);
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    memcpy(event.bytes + 4U, f.scan[1].bssid, 6U);
    memcpy(event.bytes + 16U, f.scan[1].bssid, 6U);
    unexpected += compact_produced_output(&event);
    ++f.now_us;
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[1].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    unexpected += compact_produced_output(&event);
    ++f.now_us;
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    unexpected += compact_produced_output(&event);

    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 29U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    unexpected += compact_produced_output(&event);
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    unexpected += compact_produced_output(&event);

    f.now_us += 30000U;
    unsigned before_grace_output = f.write_calls;
    wifi_shield_worker_poll();
    expected_outputs += f.write_calls != before_grace_output;

    assert(wifi_shield_stop(100U));
    assert(unexpected == 0U);
    assert(expected_outputs == 4U);
    assert(f.terminal_status.received == 31U);
    assert(f.terminal_status.filtered == 9U);
    assert(f.terminal_status.source_events[WIFI_SHIELD_SOURCE_DEAUTH] == 3U);
    assert(f.terminal_status.source_events[WIFI_SHIELD_SOURCE_PMKID] == 1U);
    assert(f.terminal_status.alerts == 2U);
}

static size_t line_occurrences(const char *haystack, const char *needle)
{
    size_t count = 0U;
    size_t length = strlen(needle);
    for (const char *at = haystack; at != NULL && *at != '\0';) {
        at = strstr(at, needle);
        if (at == NULL) break;
        ++count;
        at += length;
    }
    return count;
}

static void scenario_defence_passive_and_active_exact_bridge(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    char *passive[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, passive) == 0);
    wifi_shield_compact_event_t event;
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 11U, 26U);
    event.bytes[0] = 0xc0U;
    event.rx_us = (int64_t)f.now_us - 321;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_random_calls == 0U && f.defence_tx_calls == 0U);
    assert(strstr(f.all_lines, "[DETECTOR_DEFENCE]") == NULL);
    assert(wifi_shield_stop(100U));

    reset_fixture(1U);
    f.scan[0].channel = 6U;
    char *active[] = {"wifi_shield", "start", "--only", "1",
                      "--defence", "decoy-4way"};
    assert(command(6, active) == 0);
    assert(strstr(f.all_lines, "[SHIELD/1] ARMED MODE=active ") != NULL);
    size_t shield_armed = 0U, defence_armed = 0U;
    while (shield_armed < f.order_count &&
           f.order[shield_armed] != EV_ARMED) ++shield_armed;
    while (defence_armed < f.order_count &&
           f.order[defence_armed] != EV_DEFENCE_ARMED) ++defence_armed;
    assert(shield_armed < defence_armed && defence_armed < f.order_count);

    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 11U, 26U);
    event.bytes[0] = 0xc0U;
    event.rx_us = (int64_t)f.now_us - 321;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.retuned_channel == 6U);
    assert(f.defence_tx_calls == 2U && tx_calls == 2U);
    assert(strstr(f.all_lines, "latency_us=321 error=none") != NULL);
    size_t trigger = 0U, tx = 0U;
    while (trigger < f.order_count &&
           f.order[trigger] != EV_DEFENCE_TRIGGER) ++trigger;
    while (tx < f.order_count && f.order[tx] != EV_DEFENCE_TX) ++tx;
    assert(defence_armed < trigger && trigger < tx && tx < f.order_count);

    wpa_decoy_material_t material;
    memset(&material, 0x5a, sizeof(material));
    memcpy(material.bssid, f.scan[0].bssid, 6U);
    material.sta[0] = (uint8_t)((material.sta[0] | 0x02U) & 0xfeU);
    wpa_decoy_pair_t expected;
    assert(wpa_decoy_build_pair(&material, &expected));
    assert(f.defence_tx_lengths[0] == expected.m1_len);
    assert(f.defence_tx_lengths[1] == expected.m2_len);
    assert(memcmp(f.defence_tx_frames[0], expected.m1, expected.m1_len) == 0);
    assert(memcmp(f.defence_tx_frames[1], expected.m2, expected.m2_len) == 0);

    wifi_shield_presentation_snapshot_t snapshot;
    wifi_shield_presentation_get(&snapshot);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_DECOY_TX] == 1U);
    ++f.now_us;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    wifi_shield_presentation_get(&snapshot);
    assert(f.defence_tx_calls == 2U);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_DECOY_TX] == 1U);
    f.now_us += UINT64_C(20000001);
    wifi_shield_worker_poll();
    assert(strstr(f.all_lines, "[DETECTOR_DEFENCE] released_bssid=") != NULL);
    assert(wifi_shield_stop(100U));
    assert(line_occurrences(f.all_lines,
           "[DETECTOR_DEFENCE] stopped ") == 1U);
    assert(wifi_shield_stop(100U));
    assert(line_occurrences(f.all_lines,
           "[DETECTOR_DEFENCE] stopped ") == 1U);
}

static void scenario_defence_preadmission_is_passive(void)
{
    reset_fixture(1U);
    f.block_armed_leave = true;
    async_result_t started = {0};
    pthread_t thread;
    assert(pthread_create(&thread, NULL, active_start_thread, &started) == 0);
    wait_flag(&f.armed_leave_entered);

    wifi_shield_compact_event_t event;
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, f.scan[0].channel, 26U);
    event.bytes[0] = 0xc0U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);

    release_gate(&f.release_armed_leave);
    assert(pthread_join(thread, NULL) == 0);
    assert(started.command_result == 0);
    ++f.now_us;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 2U);
    assert(wifi_shield_stop(100U));
}

static void scenario_defence_allowlist_and_pmkid_opt_in(void)
{
    reset_fixture(2U);
    f.scan[0].channel = 6U;
    f.scan[1].channel = 6U;
    f.scan[0].wpa2_psk_ccmp = false;
    char *active[] = {"wifi_shield", "start", "--only", "1",
                      "--defence", "decoy-4way"};
    assert(command(6, active) == 0);
    wifi_shield_compact_event_t event;
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    event.bytes[1] = 0x40U;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[1].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    uint8_t multicast[6] = {0x03, 1, 2, 3, 4, 5};
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    memcpy(event.bytes + 16U, multicast, 6U);
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    assert(wifi_shield_stop(100U));

    reset_fixture(1U);
    f.scan[0].channel = 6U;
    uint8_t frame[128];
    size_t length = make_beacon(frame, f.scan[0].bssid, "known");
    sx_observation_t trust_observation;
    assert(sx_parse(frame, length, &trust_observation));
    assert(wifi_trust_profile_from_observation(
        &trust_observation, 6U, f.now_us, &f.trust_profile));
    f.trust_fill = true;
    assert(command(6, active) == 0);
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    event.bytes[1] = 0x40U;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 25U);
    event.bytes[0] = 0xc0U;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    uint8_t broadcast[6];
    memset(broadcast, 0xff, sizeof(broadcast));
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    memcpy(event.bytes + 4U, broadcast, 6U);
    memcpy(event.bytes + 10U, f.scan[0].bssid, 6U);
    memcpy(event.station, broadcast, 6U);
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    event.generation = f.runtime_status.generation + 1U;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, 6U, false));
    length = make_sae_auth(frame, f.scan[0].bssid, false, 1U);
    assert(deliver_full(frame, length, 6U, false));
    length = make_beacon(frame, f.scan[0].bssid, "changed");
    assert(deliver_full(frame, length, 6U, false));
    assert(f.defence_tx_calls == 0U);
    assert(strstr(f.all_lines, "SOURCE=trust TYPE=security_drift") != NULL);
    wifi_shield_presentation_snapshot_t no_hint;
    wifi_shield_presentation_get(&no_hint);
    assert(no_hint.indicator_counts[WIFI_SHIELD_PRESENTATION_DECOY_TX] == 0U);
    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    ++f.now_us;
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    assert(wifi_shield_stop(100U));

    reset_fixture(1U);
    f.scan[0].channel = 6U;
    char *pmkid[] = {"wifi_shield", "start", "--only", "1", "--defence",
                     "decoy-4way", "--pmkid-decoy"};
    assert(command(7, pmkid) == 0);
    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    ++f.now_us;
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    f.now_us += 30000U;
    wifi_shield_worker_poll();
    assert(f.defence_tx_calls == 1U);
    assert(wifi_shield_stop(100U));
}

static void scenario_defence_multi_vector_reaches_runtime(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    char *multi[] = {"wifi_shield", "start", "--only", "1", "--defence",
                     "decoy-4way", "--pmkid-decoy", "--multi-vector"};
    assert(command(8, multi) == 0);
    assert(strstr(f.all_lines, "pmkid=decoy policy=multi_vector") != NULL);

    wifi_shield_compact_event_t event;
    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    ++f.now_us;
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    f.now_us += 30000U;
    wifi_shield_worker_poll();
    assert(f.defence_tx_calls == 1U);

    ++f.now_us;
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 3U);
    ++f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 3U);

    wifi_shield_presentation_snapshot_t snapshot;
    wifi_shield_presentation_get(&snapshot);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_DECOY_TX] == 2U);
    assert(wifi_shield_stop(100U));
}

static void scenario_pmkid_grace_suppresses_completed_association(void)
{
    static const uint8_t station[6] = {0x04, 6, 7, 8, 9, 10};
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    char *protect[] = {
        "wifi_shield", "start", "--only", "1", "--protect-all"
    };
    assert(command(5, protect) == 0);

    wifi_shield_compact_event_t event;
    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    ++f.now_us;
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));

    /* The Auth/Assoc sequence is only a candidate. It cannot transmit or
     * publish PMKID evidence until the association-completion grace expires. */
    assert(f.defence_tx_calls == 0U);
    assert(strstr(f.all_lines, "SOURCE=pmkid TYPE=sequence") == NULL);

    f.now_us += 12975U; /* Physical PCAP: first M1 to M2 was 12.975 ms. */
    uint8_t frame[256];
    size_t length = make_eapol_key_frame(
        frame, f.scan[0].bssid, station, 0x010aU);
    assert(deliver_full(frame, length, 6U, false));
    assert(strstr(f.all_lines, "reason=association_complete") != NULL);

    f.now_us += UINT64_C(1000000);
    wifi_shield_worker_poll();
    assert(f.defence_tx_calls == 0U);
    assert(strstr(f.all_lines, "SOURCE=pmkid TYPE=sequence") == NULL);
    assert(wifi_shield_stop(100U));
    assert(f.terminal_status.source_events[WIFI_SHIELD_SOURCE_PMKID] == 0U);
}

static void scenario_protect_all_runs_autonomous_combined_policy(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 6U;

    uint8_t frame[128];
    size_t length = make_beacon(frame, f.scan[0].bssid, "known");
    sx_observation_t trust_observation;
    assert(sx_parse(frame, length, &trust_observation));
    assert(wifi_trust_profile_from_observation(
        &trust_observation, 6U, f.now_us, &f.trust_profile));
    f.trust_fill = true;

    char *protect[] = {
        "wifi_shield", "start", "--only", "1", "--protect-all"
    };
    assert(command(5, protect) == 0);
    assert(strstr(f.all_lines,
        "[SHIELD/1] ARMED MODE=protect-all TARGETS=1 CHANNELS=6 "
        "COVERAGE=continuous ACTIVE=deauth,pmkid "
        "PASSIVE=wps,sae,trust") != NULL);
    assert(strstr(f.all_lines, "pmkid=decoy policy=multi_vector") != NULL);

    length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, 6U, false));
    assert(strstr(f.all_lines,
                  "SOURCE=wps TYPE=enrollment_activity") != NULL);
    length = make_sae_auth(frame, f.scan[0].bssid, false, 1U);
    assert(deliver_full(frame, length, 6U, false));
    assert(strstr(f.all_lines,
                  "SOURCE=sae TYPE=authentication_activity") != NULL);
    length = make_beacon(frame, f.scan[0].bssid, "changed");
    ++f.now_us;
    assert(deliver_full(frame, length, 6U, false));
    assert(strstr(f.all_lines,
                  "SOURCE=trust TYPE=security_drift") != NULL);

    wifi_shield_compact_event_t event;
    compact_header(&event, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    event.bytes[0] = 0xb0U;
    event.bytes[24] = 0U;
    event.bytes[26] = 1U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    ++f.now_us;
    compact_header(&event, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    event.bytes[0] = 0x00U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    f.now_us += 30000U;
    wifi_shield_worker_poll();
    assert(f.defence_tx_calls == 1U);

    ++f.now_us;
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    event.bytes[0] = 0xc0U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 3U);

    char *status[] = {"wifi_shield", "status"};
    assert(command(2, status) == 0);
    assert(strstr(f.all_lines,
        "[SHIELD/1] STATUS RUNNING=1 MODE=protect-all "
        "ACTIVE=deauth,pmkid PASSIVE=wps,sae,trust") != NULL);
    assert(wifi_shield_stop(100U));
    assert(strcmp(f.terminal_outcome, "stopped") == 0);
    assert(f.terminal_status.active_defence && f.terminal_status.pmkid_decoy);
    assert(f.terminal_status.multi_vector && f.terminal_status.protect_all);
}

static void scenario_v2_campaign_time_report_and_degraded_notice(void)
{
    static const uint8_t station[6] = {0x04, 6, 7, 8, 9, 10};
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    assert(f.journal_start_calls == 1U && f.journal_record_count == 1U);
    assert(f.journal_records[0].type == WIFI_SHIELD_JOURNAL_SESSION_START);
    assert(f.journal_start_before_armed);

    uint8_t frame[256];
    size_t length = make_beacon(frame, f.scan[0].bssid, "health");
    frame[24] = 0xe8U; frame[25] = 0x03U; /* TSF 1000 us. */
    assert(deliver_full(frame, length, 6U, false));
    assert(record_count(WIFI_SHIELD_JOURNAL_AP_HEALTH) == 1U);

    /* Three observed same-channel neighbors need two fresh beacons each.
     * They affect occupancy only and never become campaign evidence. */
    for (uint8_t neighbor = 0U; neighbor < 3U; ++neighbor) {
        uint8_t bssid[6] = {0x02U, 0xaaU, 0xbbU, 0xccU, 0xddU,
                            (uint8_t)(0x20U + neighbor)};
        for (unsigned sample = 0U; sample < 2U; ++sample) {
            ++f.now_us;
            length = make_beacon(frame, bssid, "neighbor");
            frame[24] = (uint8_t)(10U + sample);
            assert(deliver_full(frame, length, 6U, false));
        }
    }
    for (size_t i = 0U; i < f.journal_record_count; ++i)
        if (f.journal_records[i].type ==
            WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION)
            assert(memcmp(f.journal_records[i].bssid,
                          f.scan[0].bssid, 6U) == 0);
    ++f.now_us;
    length = make_beacon(frame, f.scan[0].bssid, "health");
    frame[24] = 0xd0U; frame[25] = 0x07U; /* TSF 2000 us. */
    assert(deliver_full(frame, length, 6U, false));
    bool congested_recommendation = false;
    for (size_t i = 0U; i < f.journal_record_count; ++i)
        if (f.journal_records[i].type == WIFI_SHIELD_JOURNAL_RECOMMENDATION &&
            f.journal_records[i].recommendation.action ==
             WIFI_SHIELD_AP_RECOMMEND_CHANNEL_CONGESTED)
            congested_recommendation = true;
    assert(congested_recommendation);

    ++f.now_us;
    length = make_beacon(frame, f.scan[0].bssid, "health");
    frame[0] = 0x50U; /* Probe Response: timing anchor, not beacon cadence. */
    frame[24] = 0x88U; frame[25] = 0x13U; /* TSF 5000 us. */
    assert(deliver_full(frame, length, 6U, false));
    assert(record_count(WIFI_SHIELD_JOURNAL_AP_HEALTH) == 2U);

    ++f.now_us;
    length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, 6U, false));
    bool estimated_wps = false;
    for (size_t i = 0U; i < f.journal_record_count; ++i) {
        const wifi_shield_journal_record_t *r = &f.journal_records[i];
        if (r->type == WIFI_SHIELD_JOURNAL_EVENT &&
            r->event_source == WIFI_SHIELD_SOURCE_WPS &&
            r->time.quality == WIFI_SHIELD_TIME_ESTIMATED)
            estimated_wps = true;
    }
    assert(estimated_wps);

    wifi_shield_compact_event_t compact;
    compact_header(&compact, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    compact.bytes[0] = 0xc0U;
    assert(wifi_shield_consume_compact(f.config.context, &compact));
    bool critical = false;
    for (size_t i = 0U; i < f.journal_record_count; ++i)
        if (f.journal_records[i].type ==
                WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION &&
            f.journal_records[i].campaign.to == WIFI_SHIELD_THREAT_CRITICAL &&
            f.journal_records[i].campaign.reason ==
                WIFI_SHIELD_CAMPAIGN_REASON_CROSS_VECTOR)
            critical = true;
    assert(critical);

    size_t pmkid_before = 0U;
    for (size_t i = 0U; i < f.journal_record_count; ++i)
        pmkid_before += f.journal_records[i].type == WIFI_SHIELD_JOURNAL_EVENT &&
            f.journal_records[i].event_source == WIFI_SHIELD_SOURCE_PMKID;
    compact_header(&compact, WIFI_SHIELD_COMPACT_AUTH,
                   f.scan[0].bssid, 6U, 30U);
    compact.bytes[0] = 0xb0U; compact.bytes[24] = 0U; compact.bytes[26] = 1U;
    assert(wifi_shield_consume_compact(f.config.context, &compact));
    ++f.now_us;
    compact_header(&compact, WIFI_SHIELD_COMPACT_ASSOC,
                   f.scan[0].bssid, 6U, 28U);
    compact.bytes[0] = 0x00U;
    assert(wifi_shield_consume_compact(f.config.context, &compact));
    f.now_us += 1000U;
    length = make_eapol_key_frame(frame, f.scan[0].bssid, station, 0x010aU);
    assert(deliver_full(frame, length, 6U, false));
    size_t pmkid_after = 0U;
    for (size_t i = 0U; i < f.journal_record_count; ++i)
        pmkid_after += f.journal_records[i].type == WIFI_SHIELD_JOURNAL_EVENT &&
            f.journal_records[i].event_source == WIFI_SHIELD_SOURCE_PMKID;
    assert(pmkid_after == pmkid_before);

    unsigned tune_before = f.tune_calls, start_before = f.start_calls;
    unsigned finish_before = f.finish_calls;
    unsigned submit_before = f.journal_submit_calls;
    char *report[] = {"wifi_shield", "report"};
    char *log_status[] = {"wifi_shield", "log", "status"};
    assert(command(2, report) == 0);
    assert(command(3, log_status) == 0);
    assert(strstr(f.all_lines, "[SHIELD/2] CAMPAIGN") != NULL);
    assert(strstr(f.all_lines, "THREAT=critical") != NULL);
    assert(strstr(f.all_lines, "REASON=cross_vector") != NULL);
    assert(strstr(f.all_lines, "[SHIELD/2] AP_HEALTH") != NULL);
    assert(strstr(f.all_lines, "channel_congested") != NULL);
    assert(strstr(f.all_lines, "[SHIELD/2] LOG STATE=active") != NULL);
    assert(f.tune_calls == tune_before && f.start_calls == start_before &&
           f.finish_calls == finish_before &&
           f.journal_submit_calls == submit_before);

    f.journal_submit_fail = true; /* Queue-full admission is fail-open. */
    unsigned output_before = f.write_calls;
    length = make_sae_auth(frame, f.scan[0].bssid, false, 9U);
    assert(deliver_full(frame, length, 6U, false));
    assert(f.write_calls > output_before);
    assert(strstr(f.all_lines,
                  "SOURCE=sae TYPE=authentication_activity") != NULL);
    assert(f.journal_status.dropped != 0U);
    f.journal_submit_fail = false;

    f.journal_status.state = WIFI_SHIELD_JOURNAL_DEGRADED;
    f.journal_status.failures = 1U;
    f.journal_status.degraded_notice_pending = true;
    wifi_shield_worker_poll();
    wifi_shield_worker_poll();
    assert(f.journal_ack_calls == 1U);
    assert(text_count(f.all_lines, "[SHIELD/2] STORAGE ") == 1U);
    assert(wifi_shield_stop(100U));
}

static void scenario_v2_suppressed_evidence_still_updates_campaign_and_health(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    wifi_shield_compact_event_t compact;
    compact_header(&compact, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 6U, 26U);
    compact.bytes[0] = 0xc0U;
    compact.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &compact));
    f.now_us += UINT64_C(9000000);
    compact.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &compact));
    assert(text_count(f.all_lines,
        "[SHIELD/1] ALERT SOURCE=deauth TYPE=deauth") == 1U);

    f.now_us += UINT64_C(26000000);
    uint8_t frame[128];
    size_t length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, 6U, false));
    char *report[] = {"wifi_shield", "report"};
    assert(command(2, report) == 0);
    assert(strstr(f.all_lines, "THREAT=critical") != NULL);

    length = make_beacon(frame, f.scan[0].bssid, "health");
    frame[24] = 1U;
    assert(deliver_full(frame, length, 6U, false));
    bool health_counted_both = false;
    size_t deauth_journal_events = 0U;
    for (size_t i = 0U; i < f.journal_record_count; ++i) {
        const wifi_shield_journal_record_t *record = &f.journal_records[i];
        if (record->type == WIFI_SHIELD_JOURNAL_AP_HEALTH &&
            record->ap_health.deauth_events == 2U)
            health_counted_both = true;
        if (record->type == WIFI_SHIELD_JOURNAL_EVENT &&
            record->event_source == WIFI_SHIELD_SOURCE_DEAUTH)
            ++deauth_journal_events;
    }
    /* AP-health and campaign logic still consume both observations. The first
     * one-second journal bucket is durable; the second remains pending until
     * the Stop flush below. */
    assert(health_counted_both && deauth_journal_events == 1U);
    assert(wifi_shield_stop(100U));
}

static void scenario_v2_deauth_journal_aggregates_without_losing_counts(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 4U;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    assert(f.summary_metadata.target_count == 1U &&
           f.summary_metadata.primary_target_valid &&
           f.summary_metadata.primary_channel == 4U &&
           strcmp(f.summary_metadata.primary_ssid, "ap-1") == 0 &&
           !f.summary_metadata.active_defence &&
           !f.summary_metadata.protect_all);

    wifi_shield_compact_event_t compact;
    compact_header(&compact, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 4U, 26U);
    compact.bytes[0] = 0xc0U;
    const uint64_t first_us = f.now_us;
    for (uint32_t i = 0U; i < 304U; ++i) {
        f.now_us = first_us + (UINT64_C(5580000) * i) / 303U;
        compact.rx_us = (int64_t)f.now_us;
        assert(wifi_shield_consume_compact(f.config.context, &compact));
        wifi_shield_worker_poll();
    }
    assert(wifi_shield_stop(100U));
    assert(f.terminal_status.source_events[WIFI_SHIELD_SOURCE_DEAUTH] == 304U);

    size_t aggregate_records = 0U;
    uint32_t aggregate_total = 0U;
    for (size_t i = 0U; i < f.journal_record_count; ++i) {
        const wifi_shield_journal_record_t *record = &f.journal_records[i];
        if (record->type != WIFI_SHIELD_JOURNAL_EVENT ||
            record->event_source != WIFI_SHIELD_SOURCE_DEAUTH ||
            record->event_type != WIFI_SHIELD_EVENT_DEAUTH)
            continue;
        char encoded[WIFI_SHIELD_JOURNAL_LINE_MAX];
        int length = wifi_shield_journal_encode(encoded, sizeof(encoded),
                                                record);
        assert(length > 0);
        const char *count = strstr(encoded, "\"count\":");
        unsigned value = 0U;
        assert(count != NULL && sscanf(count, "\"count\":%u", &value) == 1);
        assert(value != 0U && value <= 304U);
        aggregate_total += value;
        ++aggregate_records;
    }
    assert(aggregate_records >= 5U && aggregate_records <= 7U);
    assert(aggregate_total == 304U);
}

static void scenario_v2_rejected_aggregate_does_not_merge_next_window(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 4U;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    wifi_shield_compact_event_t compact;
    compact_header(&compact, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, 4U, 26U);
    compact.bytes[0] = 0xc0U;
    const uint64_t first_us = f.now_us;
    compact.rx_us = (int64_t)first_us;
    assert(wifi_shield_consume_compact(f.config.context, &compact));
    f.journal_submit_fail = true;
    f.now_us = first_us + UINT64_C(1200000);
    compact.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &compact));
    f.journal_submit_fail = false;
    f.now_us = first_us + UINT64_C(2400000);
    compact.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &compact));
    wifi_shield_worker_poll();
    assert(wifi_shield_stop(100U));
    assert(f.terminal_status.source_events[WIFI_SHIELD_SOURCE_DEAUTH] == 3U);
    size_t aggregates=0U;
    uint32_t accepted=0U;
    for(size_t i=0U; i<f.journal_record_count; ++i) {
        const wifi_shield_journal_record_t *r=&f.journal_records[i];
        if(r->type!=WIFI_SHIELD_JOURNAL_EVENT ||
           r->event_type!=WIFI_SHIELD_EVENT_DEAUTH) continue;
        assert(r->event_last_boot_us >= r->event_first_boot_us);
        assert(r->event_last_boot_us-r->event_first_boot_us < UINT64_C(1000000));
        accepted += r->event_count;
        ++aggregates;
    }
    assert(aggregates==2U && accepted==2U && f.journal_status.dropped==1U);
}

static void scenario_v2_quality_losses_and_sampled_coverage_survive_stop(void)
{
    reset_fixture(2U);
    char *start[] = {"wifi_shield", "start", "--only", "1", "2"};
    assert(command(5, start) == 0);

    uint8_t frame[128];
    size_t length;
    for (unsigned i = 0U; i <= WIFI_SHIELD_RATE_LIMIT_CAPACITY; ++i) {
        length = make_wps_frame(frame, f.scan[0].bssid, false);
        frame[4] = 0x06U;
        frame[5] = (uint8_t)i;
        assert(deliver_full(frame, length, f.scan[0].channel, false));
    }
    f.runtime_status.rx_drops = 3U;
    wifi_shield_worker_poll();
    f.journal_status.dropped = 4U;
    wifi_shield_worker_poll();

    f.all_lines_used = 0U;
    f.all_lines[0] = '\0';
    char *report[] = {"wifi_shield", "report"};
    assert(command(2, report) == 0);
    assert(strstr(f.all_lines,
        "ACTIVE=1 THREAT=watch SESSION_PEAK=watch COMPLETED=0 "
        "REASON=isolated_activity SOURCES=2") != NULL);
    assert(strstr(f.all_lines,
        "CONFIDENCE=limited SAMPLED=1 RX_DROPS=3 EVENT_DROPS=1 "
        "OUTPUT_FAILURES=0 JOURNAL_DROPS=4") != NULL);
    assert(strstr(f.all_lines,
        "TIMING=none SAMPLED=1 RX_DROPS=3 EVENT_DROPS=1 "
        "JOURNAL_DROPS=4") != NULL);

    f.async_failures = 2U;
    assert(wifi_shield_stop(100U));
    f.all_lines_used = 0U;
    f.all_lines[0] = '\0';
    assert(command(2, report) == 0);
    assert(strstr(f.all_lines, "ACTIVE=0 THREAT=watch") != NULL);
    assert(strstr(f.all_lines,
        "SAMPLED=1 RX_DROPS=3 EVENT_DROPS=1 OUTPUT_FAILURES=2 "
        "JOURNAL_DROPS=4") != NULL);
}

static void scenario_v2_worker_expires_idle_campaign(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    uint8_t frame[128];
    size_t length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, f.scan[0].channel, false));
    f.now_us += WIFI_SHIELD_CAMPAIGN_IDLE_US;
    wifi_shield_worker_poll();
    f.all_lines_used = 0U;
    f.all_lines[0] = '\0';
    char *report[] = {"wifi_shield", "report"};
    assert(command(2, report) == 0);
    assert(strstr(f.all_lines, "ACTIVE=0 THREAT=watch") != NULL);
    assert(wifi_shield_stop(100U));
}

/* The single retained post-Stop representative is selected by session peak,
 * not by a later, quieter current campaign. */
static void scenario_v2_retained_report_preserves_highest_session_peak(void)
{
    reset_fixture(2U);
    char *start[] = {"wifi_shield", "start", "--only", "1", "2"};
    assert(command(5, start) == 0);

    uint8_t frame[128];
    size_t length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, f.scan[0].channel, false));
    wifi_shield_compact_event_t compact;
    compact_header(&compact, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, f.scan[0].channel, 26U);
    compact.bytes[0] = 0xc0U;
    compact.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &compact));

    f.now_us += WIFI_SHIELD_CAMPAIGN_IDLE_US;
    wifi_shield_worker_poll();
    ++f.now_us;
    length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, f.scan[0].channel, false));

    compact_header(&compact, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[1].bssid, f.scan[1].channel, 26U);
    compact.bytes[0] = 0xc0U;
    compact.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &compact));
    assert(wifi_shield_stop(100U));

    f.all_lines_used = 0U;
    f.all_lines[0] = '\0';
    char *report[] = {"wifi_shield", "report"};
    assert(command(2, report) == 0);
    assert(strstr(f.all_lines,
        "BSSID=02:00:00:00:00:01 ACTIVE=0 THREAT=watch "
        "SESSION_PEAK=critical COMPLETED=2") != NULL);
    assert(strstr(f.all_lines, "BSSID=02:00:00:00:00:02") == NULL);
}

static void scenario_v2_selected_tsf_anchor_survives_neighbor_flood(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    uint8_t frame[128];
    for (unsigned i = 0U; i < WIFI_SHIELD_TIME_MAX_TARGETS; ++i) {
        uint8_t neighbor[6] = {0x02U, 0xa1U, 0xb2U, 0xc3U,
                               (uint8_t)(i >> 8U), (uint8_t)i};
        size_t length = make_beacon(frame, neighbor, "neighbor");
        frame[24] = (uint8_t)i;
        ++f.now_us;
        assert(deliver_full(frame, length, 6U, false));
    }
    size_t length = make_beacon(frame, f.scan[0].bssid, "selected");
    frame[24] = 0x34U;
    frame[25] = 0x12U;
    ++f.now_us;
    assert(deliver_full(frame, length, 6U, false));

    bool selected_exact_health = false;
    for (size_t i = 0U; i < f.journal_record_count; ++i) {
        const wifi_shield_journal_record_t *record = &f.journal_records[i];
        if (record->type == WIFI_SHIELD_JOURNAL_AP_HEALTH &&
            record->has_bssid &&
            memcmp(record->bssid, f.scan[0].bssid, 6U) == 0 &&
            record->ap_health.beacons == 1U &&
            record->time.quality == WIFI_SHIELD_TIME_EXACT)
            selected_exact_health = true;
        if (record->type == WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION)
            assert(memcmp(record->bssid, f.scan[0].bssid, 6U) == 0);
    }
    assert(selected_exact_health);
    assert(wifi_shield_stop(100U));
}

static void scenario_v2_advertised_posture_without_trust_baseline(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    assert(!f.trust_fill);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);

    uint8_t frame[128];
    size_t length = make_beacon(frame, f.scan[0].bssid, "posture");
    length = append_transition_posture(frame, length);
    frame[0] = 0x50U; /* Probe Response is validated posture, not cadence. */
    assert(deliver_full(frame, length, 6U, false));
    const uint32_t expected = WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS |
        WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF |
        WIFI_SHIELD_AP_RECOMMEND_PREFER_WPA3_ONLY |
        WIFI_SHIELD_AP_RECOMMEND_REVIEW_TRANSITION_MODE |
        WIFI_SHIELD_AP_RECOMMEND_REVIEW_LEGACY_CIPHER;
    f.all_lines_used = 0U;
    f.all_lines[0] = '\0';
    char *report[] = {"wifi_shield", "report"};
    assert(command(2, report) == 0);
    assert(strstr(f.all_lines, "BEACONS=0") != NULL);
    assert(strstr(f.all_lines, "RECOMMENDATIONS=5") != NULL);
    assert(strstr(f.all_lines,
        "ACTION=disable_wps EVIDENCE=wps_advertised CONFIDENCE=observed") != NULL);
    assert(strstr(f.all_lines,
        "ACTION=require_pmf EVIDENCE=pmf_not_required CONFIDENCE=observed") != NULL);
    assert(strstr(f.all_lines,
        "ACTION=review_transition_mode EVIDENCE=transition_mode CONFIDENCE=observed") != NULL);

    frame[0] = 0x80U;
    ++f.now_us;
    assert(deliver_full(frame, length, 6U, false));
    bool health = false;
    uint32_t recommendation_mask = 0U;
    uint32_t first_revision = 0U;
    uint8_t next_index = 0U;
    for (size_t i = 0U; i < f.journal_record_count; ++i) {
        const wifi_shield_journal_record_t *record = &f.journal_records[i];
        if (record->type == WIFI_SHIELD_JOURNAL_AP_HEALTH &&
            record->ap_health.beacons == 1U &&
            record->ap_health.recommendations == expected &&
            record->recommendation_set_revision == 1U &&
            record->recommendation_set_count == 5U) {
            health = true;
            first_revision = record->recommendation_set_revision;
        }
        if (record->type == WIFI_SHIELD_JOURNAL_RECOMMENDATION &&
            record->recommendation_set_revision == first_revision &&
            record->recommendation_set_count == 5U &&
            record->recommendation_set_index == next_index &&
            wifi_shield_ap_recommendation_detail_valid(
                &record->recommendation)) {
            recommendation_mask |= record->recommendation.action;
            ++next_index;
        }
    }
    assert(health && next_index == 5U && recommendation_mask == expected);

    f.all_lines_used = 0U;
    f.all_lines[0] = '\0';
    assert(command(2, report) == 0);
    assert(strstr(f.all_lines, "RECOMMENDATIONS=5") != NULL);

    /* A later validated safe advertisement journals the withdrawal and resets
     * change tracking; a subsequent risky posture must be journaled again. */
    size_t safe_length = make_beacon(frame, f.scan[0].bssid, "posture");
    safe_length = append_safe_posture(frame, safe_length);
    ++f.now_us;
    assert(deliver_full(frame, safe_length, 6U, false));
    f.all_lines_used = 0U;
    f.all_lines[0] = '\0';
    assert(command(2, report) == 0);
    assert(strstr(f.all_lines, "RECOMMENDATIONS=0") != NULL);
    bool withdrawal_health = false;
    for (size_t i = 0U; i < f.journal_record_count; ++i)
        if (f.journal_records[i].type == WIFI_SHIELD_JOURNAL_AP_HEALTH &&
            f.journal_records[i].ap_health.recommendations == 0U &&
            f.journal_records[i].ap_health.beacons >= 2U &&
            f.journal_records[i].recommendation_set_revision == 2U &&
            f.journal_records[i].recommendation_set_count == 0U)
            withdrawal_health = true;
    assert(withdrawal_health);

    length = make_beacon(frame, f.scan[0].bssid, "posture");
    length = append_transition_posture(frame, length);
    ++f.now_us;
    assert(deliver_full(frame, length, 6U, false));
    size_t risky_recommendations = 0U, renewed_recommendations = 0U;
    for (size_t i = 0U; i < f.journal_record_count; ++i) {
        bool disable_wps =
            f.journal_records[i].type == WIFI_SHIELD_JOURNAL_RECOMMENDATION &&
            f.journal_records[i].recommendation.action ==
                WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS;
        risky_recommendations += disable_wps;
        renewed_recommendations += disable_wps &&
            f.journal_records[i].recommendation_set_revision == 3U;
    }
    assert(risky_recommendations == 2U && renewed_recommendations == 1U);

    /* A duplicate RSN IE is an incomplete/invalid advertisement and cannot
     * withdraw the last validated posture. */
    frame[length++] = 48U;
    frame[length++] = 2U;
    frame[length++] = 1U;
    frame[length++] = 0U;
    ++f.now_us;
    assert(deliver_full(frame, length, 6U, false));
    f.all_lines_used = 0U;
    f.all_lines[0] = '\0';
    assert(command(2, report) == 0);
    assert(strstr(f.all_lines, "RECOMMENDATIONS=5") != NULL);
    assert(wifi_shield_stop(100U));
}

static void scenario_v2_recommendation_same_mask_confidence_revision(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);

    uint8_t frame[128];
    size_t length = make_beacon(frame, f.scan[0].bssid, "weak");
    frame[22] = 0x10U;
    frame[24] = 1U;
    assert(deliver_full_rssi(frame, length, 6U, false, -80));
    ++f.now_us;
    frame[22] = 0x20U;
    frame[24] = 2U;
    assert(deliver_full_rssi(frame, length, 6U, false, -80));

    bool observed = false;
    for (size_t i = 0U; i < f.journal_record_count; ++i) {
        const wifi_shield_journal_record_t *record = &f.journal_records[i];
        if (record->type == WIFI_SHIELD_JOURNAL_RECOMMENDATION &&
            record->recommendation.action ==
                WIFI_SHIELD_AP_RECOMMEND_WEAK_OR_UNSTABLE_SIGNAL &&
            record->recommendation.confidence ==
                WIFI_SHIELD_AP_CONFIDENCE_OBSERVED &&
            record->recommendation_set_revision == 1U &&
            record->recommendation_set_index == 0U &&
            record->recommendation_set_count == 1U)
            observed = true;
    }
    assert(observed);

    f.runtime_status.rx_drops = 1U;
    wifi_shield_worker_poll();
    ++f.now_us;
    frame[22] = 0x30U;
    frame[24] = 3U;
    assert(deliver_full_rssi(frame, length, 6U, false, -80));

    bool replacement_marker = false, limited = false;
    for (size_t i = 0U; i < f.journal_record_count; ++i) {
        const wifi_shield_journal_record_t *record = &f.journal_records[i];
        if (record->type == WIFI_SHIELD_JOURNAL_AP_HEALTH &&
            record->recommendation_set_revision == 2U &&
            record->recommendation_set_count == 1U)
            replacement_marker = true;
        if (record->type == WIFI_SHIELD_JOURNAL_RECOMMENDATION &&
            record->recommendation.action ==
                WIFI_SHIELD_AP_RECOMMEND_WEAK_OR_UNSTABLE_SIGNAL &&
            record->recommendation.confidence ==
                WIFI_SHIELD_AP_CONFIDENCE_LIMITED &&
            record->recommendation_set_revision == 2U &&
            record->recommendation_set_index == 0U &&
            record->recommendation_set_count == 1U)
            limited = true;
    }
    assert(replacement_marker && limited);
    assert(wifi_shield_stop(100U));
}

/* Catches a partially admitted replacement set being treated as complete.
 * The next beacon must supersede it with a fresh, complete revision. */
static void scenario_v2_incomplete_recommendation_set_is_retried(void)
{
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);

    uint8_t frame[128];
    size_t length = make_beacon(frame, f.scan[0].bssid, "retry");
    length = append_transition_posture(frame, length);
    f.journal_fail_recommendation_index_once = 1;
    assert(deliver_full(frame, length, 6U, false));

    size_t first_revision_records = 0U;
    bool first_revision_missing_index = true;
    for (size_t i = 0U; i < f.journal_record_count; ++i) {
        const wifi_shield_journal_record_t *record = &f.journal_records[i];
        if (record->type == WIFI_SHIELD_JOURNAL_RECOMMENDATION &&
            record->recommendation_set_revision == 1U) {
            ++first_revision_records;
            if (record->recommendation_set_index == 1U)
                first_revision_missing_index = false;
        }
    }
    assert(first_revision_records == 4U && first_revision_missing_index);

    ++f.now_us;
    frame[22] = (uint8_t)(frame[22] + 0x10U);
    assert(deliver_full(frame, length, 6U, false));

    bool replacement_marker = false;
    uint8_t next_index = 0U;
    for (size_t i = 0U; i < f.journal_record_count; ++i) {
        const wifi_shield_journal_record_t *record = &f.journal_records[i];
        if (record->type == WIFI_SHIELD_JOURNAL_AP_HEALTH &&
            record->recommendation_set_revision == 2U &&
            record->recommendation_set_count == 5U)
            replacement_marker = true;
        if (record->type == WIFI_SHIELD_JOURNAL_RECOMMENDATION &&
            record->recommendation_set_revision == 2U &&
            record->recommendation_set_count == 5U &&
            record->recommendation_set_index == next_index)
            ++next_index;
    }
    assert(replacement_marker && next_index == 5U);
    assert(wifi_shield_stop(100U));
}

static void scenario_v2_unavailable_storage_is_fail_open(void)
{
    reset_fixture(1U);
    f.journal_start_ok = false;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    assert(f.journal_start_calls == 1U &&
           f.journal_status.state == WIFI_SHIELD_JOURNAL_UNAVAILABLE);
    uint8_t frame[128];
    size_t length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, f.scan[0].channel, false));
    assert(strstr(f.all_lines,
                  "[SHIELD/1] EVENT SOURCE=wps TYPE=enrollment_activity") != NULL);
    assert(wifi_shield_stop(100U));
    assert(f.quiesce_calls == 1U && f.finish_calls == 1U &&
           f.release_calls == 1U);
}

static void scenario_v2_writer_join_retry_is_radio_inert(void)
{
    reset_fixture(1U);
    f.journal_zero_after_release = true;
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    char *log_status[] = {"wifi_shield", "log", "status"};
    unsigned live_status_calls = f.journal_status_calls;
    assert(command(3, log_status) == 0);
    assert(strstr(f.last_line, "[SHIELD/2] LOG STATE=active") != NULL);
    assert(f.journal_status_calls == live_status_calls + 1U);
    f.journal_finish_ok = false;
    assert(!wifi_shield_stop(100U));
    assert(f.quiesce_calls == 1U && f.finish_calls == 1U &&
           f.journal_finish_calls == 1U && f.release_calls == 0U);
    unsigned radio_enters = f.radio_enter_calls;
    assert(!wifi_shield_stop(100U));
    assert(f.journal_finish_calls == 2U && f.release_calls == 0U &&
           f.radio_enter_calls == radio_enters && wifi_shield_busy());
    /* Storage-pending still owns the live journal platform. Output admission
     * remains closed during Stop, so the retained snapshot must not replace
     * that live owner until finalization and release complete. */
    live_status_calls = f.journal_status_calls;
    assert(command(3, log_status) == 1);
    assert(f.journal_status_calls == live_status_calls + 1U);
    f.journal_finish_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.quiesce_calls == 1U && f.finish_calls == 1U &&
           f.radio_enter_calls == radio_enters &&
           f.journal_finish_calls == 3U && f.release_calls == 1U);
    assert(f.journal_finish_radio_calls == 1U &&
           f.journal_finish_quiesce_calls == 1U);
    char *report[] = {"wifi_shield", "report"};
    assert(command(2, report) == 0);
    assert(strstr(f.all_lines, "[SHIELD/2] AP_HEALTH") != NULL);
    unsigned submits = f.journal_submit_calls;
    unsigned finishes = f.journal_finish_calls;
    unsigned tunes = f.tune_calls;
    unsigned released_status_calls = f.journal_status_calls;
    assert(command(3, log_status) == 0);
    assert(strstr(f.last_line, "[SHIELD/2] LOG STATE=finalized") != NULL);
    assert(f.journal_status_calls == released_status_calls);
    assert(f.journal_submit_calls == submits &&
           f.journal_finish_calls == finishes && f.tune_calls == tunes);
}

static void enter_storage_pending(void)
{
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    f.journal_finish_ok = false;
    assert(!wifi_shield_stop(100U));
    assert(wifi_shield_busy() && f.release_calls == 0U);
    f.journal_finish_ok = true;
}

static void scenario_storage_pending_finalizer_reentrancy_is_exclusive(void)
{
    reset_fixture(1U);
    enter_storage_pending();
    f.reenter_journal_finish = true;
    assert(wifi_shield_stop(100U));
    assert(f.journal_reenter_stop_result == 0);
    assert(f.journal_reenter_start_result == 1);
    assert(f.journal_reenter_acquire_delta == 0U);
    assert(f.release_calls == 1U && !wifi_shield_busy());
}

static void scenario_storage_pending_finalizer_concurrency_is_exclusive(void)
{
    reset_fixture(1U);
    enter_storage_pending();
    f.block_journal_finish = true;
    async_result_t first = {0};
    pthread_t finisher;
    assert(pthread_create(&finisher, NULL, stop_thread, &first) == 0);
    wait_flag(&f.journal_finish_entered);
    unsigned finish_calls = f.journal_finish_calls;
    assert(!wifi_shield_stop(100U));
    assert(f.journal_finish_calls == finish_calls && f.release_calls == 0U);
    release_gate(&f.release_journal_finish);
    assert(pthread_join(finisher, NULL) == 0 && first.result);
    assert(f.release_calls == 1U && !wifi_shield_busy());
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    assert(wifi_shield_stop(100U));
}

static void scenario_terminal_queue_full_drains_and_retries(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    f.journal_fail_terminal_until_drain = true;
    assert(wifi_shield_stop(100U));
    assert(f.journal_drain_calls == 1U && f.journal_finish_calls == 1U);
    assert(f.journal_records[f.journal_record_count - 1U].type ==
           WIFI_SHIELD_JOURNAL_SESSION_TERMINAL);
    assert(f.journal_status.state == WIFI_SHIELD_JOURNAL_FINALIZED);
    assert(f.release_calls == 1U && !wifi_shield_busy());
}

static void scenario_terminal_queue_full_timeout_retains_storage(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    f.journal_submit_fail_until_drain = true;
    f.journal_drain_ok = false;
    assert(!wifi_shield_stop(100U));
    assert(f.journal_drain_calls == 1U && f.journal_finish_calls == 0U &&
           f.release_calls == 0U && wifi_shield_busy());
    unsigned radio_enters = f.radio_enter_calls;
    unsigned radio_finish = f.finish_calls;
    f.journal_drain_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.radio_enter_calls == radio_enters && f.finish_calls == radio_finish);
    assert(f.journal_drain_calls == 2U && f.journal_finish_calls == 1U);
    assert(f.journal_records[f.journal_record_count - 1U].type ==
           WIFI_SHIELD_JOURNAL_SESSION_TERMINAL);
    assert(f.journal_status.state == WIFI_SHIELD_JOURNAL_FINALIZED &&
           f.release_calls == 1U && !wifi_shield_busy());
}

static void scenario_terminal_queue_full_before_writer_status_drains_first(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    f.journal_status.state = WIFI_SHIELD_JOURNAL_UNAVAILABLE;
    f.journal_submit_fail_until_drain = true;
    f.journal_activate_on_drain = true;
    assert(wifi_shield_stop(100U));
    assert(f.journal_drain_calls == 1U && f.journal_finish_calls == 1U);
    assert(f.journal_records[f.journal_record_count - 1U].type ==
           WIFI_SHIELD_JOURNAL_SESSION_TERMINAL);
    assert(f.journal_status.state == WIFI_SHIELD_JOURNAL_FINALIZED &&
           f.release_calls == 1U && !wifi_shield_busy());
}

static void scenario_failed_start_terminal_pressure_retains_storage(void)
{
    char *start[] = {"wifi_shield", "start"};
    reset_fixture(1U);
    f.start_result = WIFI_SECURITY_SESSION_WORKER_FAILED;
    f.journal_fail_terminal_until_drain = true;
    f.journal_drain_ok = false;
    assert(command(2, start) == 1);
    assert(wifi_shield_busy() && f.release_calls == 0U &&
           f.journal_drain_calls == 1U && f.journal_finish_calls == 0U);
    unsigned radio_finish = f.finish_calls;
    f.journal_drain_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.finish_calls == radio_finish && f.release_calls == 1U);
    assert(f.journal_records[f.journal_record_count - 1U].type ==
           WIFI_SHIELD_JOURNAL_SESSION_TERMINAL);

    reset_fixture(1U);
    f.tune_ok = false;
    f.journal_fail_terminal_until_drain = true;
    f.journal_drain_ok = false;
    assert(command(2, start) == 1);
    assert(wifi_shield_busy() && f.release_calls == 0U &&
           f.journal_drain_calls == 1U && f.journal_finish_calls == 0U);
    unsigned radio_enters = f.radio_enter_calls;
    f.journal_drain_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.radio_enter_calls == radio_enters && f.quiesce_calls == 0U &&
           f.finish_calls == 0U && f.release_calls == 1U);
    assert(f.journal_records[f.journal_record_count - 1U].type ==
           WIFI_SHIELD_JOURNAL_SESSION_TERMINAL);
}

static void scenario_terminal_output_failure_updates_retained_campaign(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    uint8_t frame[128];
    size_t length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, f.scan[0].channel, false));
    f.fail_terminal_write = true;
    assert(!wifi_shield_stop(100U));
    assert(!wifi_shield_busy());
    f.fail_terminal_write = false;
    f.all_lines_used = 0U;
    f.all_lines[0] = '\0';
    char *report[] = {"wifi_shield", "report"};
    assert(command(2, report) == 0);
    assert(strstr(f.all_lines, "ACTIVE=0 THREAT=watch") != NULL);
    assert(strstr(f.all_lines,
                  "CONFIDENCE=limited SAMPLED=0 RX_DROPS=0 EVENT_DROPS=0 "
                  "OUTPUT_FAILURES=1 JOURNAL_DROPS=0") != NULL);
}

static void start_active_fixture(void);

static void scenario_defence_disassoc_uses_pair_builder_and_csa_is_observe_only(void)
{
    wifi_shield_compact_event_t event;
    wifi_shield_presentation_snapshot_t presentation;
    reset_fixture(1U);
    f.scan[0].channel = 6U;
    start_active_fixture();
    compact_header(&event, WIFI_SHIELD_COMPACT_DISASSOC,
                   f.scan[0].bssid, 11U, 26U);
    event.bytes[0] = 0xa0U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 2U && f.retuned_channel == 6U);
    assert(strstr(f.all_lines, "trigger=disassoc") != NULL);
    assert(wifi_shield_stop(100U));

    reset_fixture(1U);
    f.scan[0].channel = 6U;
    start_active_fixture();
    compact_csa(&event, f.scan[0].bssid, f.scan[0].bssid);
    event.channel = 11U;
    event.rx_us = (int64_t)f.now_us;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    assert(strstr(f.all_lines, "trigger=csa") == NULL);
    assert(strstr(f.all_lines,
                  "[SHIELD/2] EVENT SOURCE=deauth TYPE=csa_announcement") != NULL);
    wifi_shield_presentation_get(&presentation);
    assert(presentation.indicator_counts[WIFI_SHIELD_PRESENTATION_INFO] == 1U);
    assert(!presentation.latest_alert_valid);
    assert(wifi_shield_stop(100U));

    reset_fixture(1U);
    f.scan[0].channel = 6U;
    start_active_fixture();
    uint8_t frame[128];
    size_t length = make_beacon(frame, f.scan[0].bssid, "plain");
    frame[length++] = 0xddU;
    frame[length++] = 20U;
    memset(frame + length, 0x5a, 20U);
    length += 20U;
    frame[length++] = 0x25U;
    frame[length++] = 3U;
    frame[length++] = 1U;
    frame[length++] = 36U;
    frame[length++] = 3U;
    assert(length > WIFI_SHIELD_COMPACT_BYTES);
    assert(deliver_full(frame, length, 11U, false));
    assert(f.defence_tx_calls == 0U);
    assert(strstr(f.all_lines, "trigger=csa") == NULL);
    assert(strstr(f.all_lines,
                  "[SHIELD/2] EVENT SOURCE=deauth TYPE=csa_announcement") != NULL);
    wifi_shield_presentation_get(&presentation);
    assert(presentation.indicator_counts[WIFI_SHIELD_PRESENTATION_INFO] == 1U);
    assert(!presentation.latest_alert_valid);
    assert(wifi_shield_stop(100U));
}

static void start_active_fixture(void)
{
    char *active[] = {"wifi_shield", "start", "--only", "1",
                      "--defence", "decoy-4way"};
    assert(command(6, active) == 0);
}

static void active_deauth(wifi_shield_compact_event_t *event)
{
    compact_header(event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, f.scan[0].channel, 26U);
    event->bytes[0] = 0xc0U;
    event->rx_us = (int64_t)f.now_us;
}

static void scenario_defence_failures_and_rejected_hint(void)
{
    wifi_shield_compact_event_t event;

    reset_fixture(1U);
    start_active_fixture();
    f.defence_random_ok = false;
    active_deauth(&event);
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    assert(strstr(f.all_lines, "result=error frames=0 latency_us=0 error=random") != NULL);
    assert(wifi_shield_stop(100U));

    reset_fixture(1U);
    start_active_fixture();
    f.tune_ok = false;
    active_deauth(&event);
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 0U);
    assert(strstr(f.all_lines, "result=error frames=0 latency_us=0 error=tune") != NULL);
    assert(wifi_shield_stop(100U));

    reset_fixture(1U);
    start_active_fixture();
    f.defence_tx_fail_call = 1;
    active_deauth(&event);
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 1U);
    assert(strstr(f.all_lines, "result=error frames=0 latency_us=0 error=m1_tx") != NULL);
    assert(wifi_shield_stop(100U));

    reset_fixture(1U);
    start_active_fixture();
    f.defence_tx_fail_call = 2;
    active_deauth(&event);
    assert(wifi_shield_consume_compact(f.config.context, &event));
    assert(f.defence_tx_calls == 2U);
    assert(strstr(f.all_lines, "result=error frames=1 latency_us=0 error=m2_tx") != NULL);
    assert(wifi_shield_stop(100U));

    reset_fixture(1U);
    start_active_fixture();
    f.fail_write = true;
    active_deauth(&event);
    assert(!wifi_shield_consume_compact(f.config.context, &event));
    wifi_shield_presentation_snapshot_t snapshot;
    wifi_shield_presentation_get(&snapshot);
    assert(f.defence_tx_calls == 2U);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_DECOY_TX] == 0U);
    f.fail_write = false;
    assert(wifi_shield_stop(100U));
}

static void scenario_defence_stop_join_retry_and_single_finish(void)
{
    reset_fixture(1U);
    start_active_fixture();
    f.block_defence_tx = true;
    async_result_t consume = {0};
    active_deauth(&consume.compact);
    pthread_t consumer;
    assert(pthread_create(&consumer, NULL, compact_thread, &consume) == 0);
    wait_flag(&f.defence_tx_entered);

    async_result_t stopped = {0};
    pthread_t stopper;
    assert(pthread_create(&stopper, NULL, stop_thread, &stopped) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(!stopped.result);
    release_gate(&f.release_defence_tx);
    assert(pthread_join(consumer, NULL) == 0);
    assert(consume.result);
    assert(wifi_shield_stop(100U));
    assert(line_occurrences(f.all_lines,
           "[DETECTOR_DEFENCE] stopped ") == 1U);

    reset_fixture(1U);
    start_active_fixture();
    f.drain_ok = false;
    unsigned terminals = f.terminal_calls;
    assert(!wifi_shield_stop(100U));
    assert(line_occurrences(f.all_lines,
           "[DETECTOR_DEFENCE] stopped ") == 1U);
    assert(f.drain_calls == 1U && f.finish_calls == 0U &&
           f.release_calls == 0U && f.terminal_calls == terminals);
    f.drain_ok = true;
    assert(wifi_shield_stop(100U));
    assert(line_occurrences(f.all_lines,
           "[DETECTOR_DEFENCE] stopped ") == 1U);
    assert(f.drain_calls == 2U && f.finish_calls == 1U &&
           f.release_calls == 1U && f.terminal_calls == terminals + 1U);

    reset_fixture(1U);
    start_active_fixture();
    f.finish_ok = false;
    assert(!wifi_shield_stop(100U));
    assert(line_occurrences(f.all_lines,
           "[DETECTOR_DEFENCE] stopped ") == 1U);
    size_t quiesce_order = 0U, stopped_order = 0U;
    size_t drain_order = 0U, finish_order = 0U;
    while (quiesce_order < f.order_count &&
           f.order[quiesce_order] != EV_QUIESCE) ++quiesce_order;
    while (stopped_order < f.order_count &&
           f.order[stopped_order] != EV_DEFENCE_STOPPED) ++stopped_order;
    while (drain_order < f.order_count &&
           f.order[drain_order] != EV_DRAIN) ++drain_order;
    while (finish_order < f.order_count &&
           f.order[finish_order] != EV_FINISH) ++finish_order;
    assert(quiesce_order < stopped_order && stopped_order < drain_order &&
           drain_order < finish_order);
    f.finish_ok = true;
    assert(wifi_shield_stop(100U));
    assert(line_occurrences(f.all_lines,
           "[DETECTOR_DEFENCE] stopped ") == 1U);
}

static void scenario_scheduler_hop_lock_release_and_drop_merge(void)
{
    reset_fixture(2U);
    char *start[] = {"wifi_shield", "start", "--only", "1", "2"};
    assert(command(5, start) == 0);
    f.runtime_status.rx_drops = 3U;
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.retune_calls == 1U && f.retuned_channel == 6U);
    char *status[] = {"wifi_shield", "status"};
    assert(command(2, status) == 0);
    assert(strstr(f.last_line, "CURRENT_CH=6") != NULL);
    assert(strstr(f.last_line, "RX_DROPS=3") != NULL);
    assert(wifi_shield_channel_lock_running(
        f.config.context, f.scan[0].bssid, 1U));
    assert(f.retuned_channel == 1U);
    unsigned locked_retunes = f.retune_calls;
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US * 4U;
    wifi_shield_worker_poll();
    assert(f.retune_calls == locked_retunes);
    assert(wifi_shield_channel_release_running(f.config.context));
    wifi_shield_worker_poll();
    assert(f.retune_calls == locked_retunes + 1U);
    assert(f.state_depth == 0U && f.state_enter_calls == f.state_leave_calls);
    assert(wifi_shield_stop(100U));
}

static void scenario_stop_merges_final_runtime_drops(void)
{
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    f.runtime_status.rx_drops = 10U;
    wifi_shield_worker_poll();
    f.runtime_status.rx_drops = 13U;
    assert(wifi_shield_stop(100U));
    assert(f.terminal_status.rx_drops == 13U);

    reset_fixture(1U);
    assert(command(4, start) == 0);
    f.runtime_status.rx_drops = UINT32_MAX - 1U;
    wifi_shield_worker_poll();
    f.runtime_status.rx_drops = 5U; /* Runtime counter reset after poll. */
    f.finish_ok = false;
    assert(!wifi_shield_stop(100U));
    f.finish_ok = true;
    assert(wifi_shield_stop(100U));
    assert(f.terminal_status.rx_drops == UINT32_MAX);
}

static void scenario_radio_fence_serializes_retune_lock_and_stop(void)
{
    pthread_t poll, competing;
    async_result_t result = {0};
    char *start[] = {"wifi_shield", "start", "--only", "1", "2"};

    reset_fixture(2U);
    assert(command(5, start) == 0);
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    f.block_retune = true;
    assert(pthread_create(&poll, NULL, poll_thread, NULL) == 0);
    wait_flag(&f.retune_entered);
    assert(pthread_create(&competing, NULL, lock_thread, &result) == 0);
    wait_radio_attempts(2U);
    release_gate(&f.release_retune);
    assert(pthread_join(poll, NULL) == 0);
    assert(pthread_join(competing, NULL) == 0);
    assert(result.result && f.retuned_channel == f.scan[0].channel);
    char *status[] = {"wifi_shield", "status"};
    assert(command(2, status) == 0);
    assert(strstr(f.last_line, "CURRENT_CH=1") != NULL);
    assert(wifi_shield_stop(100U));

    reset_fixture(2U);
    assert(command(5, start) == 0);
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    f.block_retune = true;
    result.result = false;
    assert(pthread_create(&poll, NULL, poll_thread, NULL) == 0);
    wait_flag(&f.retune_entered);
    assert(pthread_create(&competing, NULL, stop_thread, &result) == 0);
    wait_radio_attempts(2U);
    assert(f.quiesce_calls == 0U && f.release_calls == 0U);
    release_gate(&f.release_retune);
    assert(pthread_join(poll, NULL) == 0);
    assert(pthread_join(competing, NULL) == 0);
    assert(result.result && f.quiesce_calls == 1U && f.release_calls == 1U);

    reset_fixture(2U);
    assert(command(5, start) == 0);
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    f.block_radio_enter = true;
    result.result = false;
    assert(pthread_create(&competing, NULL, stop_thread, &result) == 0);
    wait_flag(&f.radio_entered);
    assert(pthread_create(&poll, NULL, poll_thread, NULL) == 0);
    wait_radio_attempts(2U);
    release_gate(&f.release_radio_enter);
    assert(pthread_join(competing, NULL) == 0);
    assert(pthread_join(poll, NULL) == 0);
    assert(result.result && f.retune_calls == 0U);
    assert(f.radio_enter_calls == f.radio_leave_calls);
}

static void scenario_state_lifetime_fences_start_status_and_release(void)
{
    pthread_t worker, status_worker;
    async_result_t worker_result = {.command_result = -1};
    async_result_t status_result = {.command_result = -1};

    /* The startup candidate remains private while tune is a blocking external
     * hook. STATUS must see the prior terminal snapshot, never partial PSRAM. */
    reset_fixture(1U);
    f.block_tune = true;
    assert(pthread_create(&worker, NULL, start_thread, &worker_result) == 0);
    wait_flag(&f.tune_entered);
    char *status[] = {"wifi_shield", "status"};
    assert(wifi_shield_command(2, status) == 0);
    assert(strstr(f.last_line, "CURRENT_CH=0") != NULL);
    release_gate(&f.release_tune);
    assert(pthread_join(worker, NULL) == 0);
    assert(worker_result.command_result == 0);
    assert(wifi_shield_stop(100U));

    /* A status reader holding the state mutex must delay feature wipe, pointer
     * detach and storage release. The wipe attempt is observable first. */
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    f.block_finish_wipe = true;
    worker_result.result = false;
    assert(pthread_create(&worker, NULL, stop_thread, &worker_result) == 0);
    wait_flag(&f.finish_wipe_entered);
    f.block_state_enter = true;
    assert(pthread_create(&status_worker, NULL, status_thread,
                          &status_result) == 0);
    wait_flag(&f.state_entered);
    unsigned attempts_before_wipe;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    attempts_before_wipe = f.state_enter_attempts;
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    release_gate(&f.release_finish_wipe);

    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while (!f.release_attempted &&
           f.state_enter_attempts == attempts_before_wipe)
        assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    assert(!f.release_attempted);
    assert(f.state_enter_attempts > attempts_before_wipe);
    f.release_state_enter = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);

    assert(pthread_join(status_worker, NULL) == 0);
    assert(pthread_join(worker, NULL) == 0);
    assert(status_result.command_result == 1 && worker_result.result);
    assert(f.release_attempted && f.release_calls == 1U);
}

static void scenario_start_final_commit_linearizes_stop(void)
{
    reset_fixture(1U);
    f.arm_state_before_lock_on_runtime_status = true;

    async_result_t start_result = {.command_result = -1};
    pthread_t starter;
    assert(pthread_create(&starter, NULL, start_thread, &start_result) == 0);
    wait_flag(&f.state_before_lock_entered);

    async_result_t stop_result = {0};
    pthread_t stopper;
    assert(pthread_create(&stopper, NULL, stop_thread, &stop_result) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(!stop_result.result);

    release_gate(&f.release_state_before_lock);
    assert(pthread_join(starter, NULL) == 0);
    assert(start_result.command_result == 1);
    assert(strstr(f.all_lines, "[SHIELD/1] ARMED ") == NULL);
    assert(f.terminal_calls == 1U);
    assert(strcmp(f.terminal_outcome, "stopped") == 0);
    assert(f.quiesce_calls == 1U && f.finish_calls == 1U &&
           f.release_calls == 1U && !wifi_shield_busy());
}

static void scenario_late_channel_lock_release_revalidate_after_stop(void)
{
    pthread_t operation, stopper;
    async_result_t operation_result = {0};
    async_result_t stop_result = {0};
    char *start[] = {"wifi_shield", "start", "--only", "1", "2"};

    reset_fixture(2U);
    assert(command(5, start) == 0);
    f.block_lock_before_radio = true;
    f.block_quiesce = true;
    assert(pthread_create(&operation, NULL, lock_thread,
                          &operation_result) == 0);
    wait_flag(&f.lock_before_radio);
    assert(pthread_create(&stopper, NULL, stop_thread, &stop_result) == 0);
    wait_flag(&f.quiesce_entered);
    unsigned retunes_before = f.retune_calls;
    release_gate(&f.release_lock_before_radio);
    assert(pthread_join(operation, NULL) == 0);
    assert(!operation_result.result);
    assert(f.retune_calls == retunes_before);
    release_gate(&f.release_quiesce);
    assert(pthread_join(stopper, NULL) == 0);
    assert(stop_result.result);
    assert(f.radio_enter_calls == f.radio_leave_calls);

    reset_fixture(2U);
    assert(command(5, start) == 0);
    assert(wifi_shield_channel_lock_running(
        f.config.context, f.scan[0].bssid, f.scan[0].channel));
    f.block_release_before_radio = true;
    f.block_quiesce = true;
    operation_result.result = true;
    stop_result.result = false;
    assert(pthread_create(&operation, NULL, release_thread,
                          &operation_result) == 0);
    wait_flag(&f.release_before_radio);
    assert(pthread_create(&stopper, NULL, stop_thread, &stop_result) == 0);
    wait_flag(&f.quiesce_entered);
    release_gate(&f.release_release_before_radio);
    assert(pthread_join(operation, NULL) == 0);
    assert(!operation_result.result);
    release_gate(&f.release_quiesce);
    assert(pthread_join(stopper, NULL) == 0);
    assert(stop_result.result);
    assert(f.radio_enter_calls == f.radio_leave_calls);
}

static void scenario_terminal_writer_waits_for_status_reader(void)
{
    pthread_t starter, reader;
    async_result_t start_result = {.command_result = -1};
    async_result_t status_result = {.command_result = -1};

    reset_fixture(1U);
    f.tune_ok = false;
    f.block_tune = true;
    assert(pthread_create(&starter, NULL, start_thread, &start_result) == 0);
    wait_flag(&f.tune_entered);

    f.block_state_enter = true;
    assert(pthread_create(&reader, NULL, status_thread, &status_result) == 0);
    wait_flag(&f.state_entered);
    unsigned attempts_before;
    unsigned terminals_before;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    attempts_before = f.state_enter_attempts;
    terminals_before = f.terminal_calls;
    assert(pthread_mutex_unlock(&gate_mutex) == 0);

    release_gate(&f.release_tune);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while (f.state_enter_attempts == attempts_before &&
           f.terminal_calls == terminals_before)
        assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    assert(f.terminal_calls == terminals_before);
    assert(f.state_enter_attempts > attempts_before);
    f.release_state_enter = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);

    assert(pthread_join(reader, NULL) == 0);
    assert(pthread_join(starter, NULL) == 0);
    assert(status_result.command_result == 0);
    assert(start_result.command_result == 1);
    assert(f.terminal_calls == terminals_before + 1U);
}

static void scenario_terminal_publisher_uses_local_snapshot(void)
{
    pthread_t publisher, starter;
    async_result_t publish_result = {.command_result = -1};
    async_result_t start_result = {.command_result = -1};
    char *start[] = {"wifi_shield", "start", "--only", "1"};

    reset_fixture(1U);
    assert(command(4, start) == 0);
    f.runtime_status.rx_drops = 7U;
    wifi_shield_worker_poll();
    assert(wifi_shield_stop(100U));
    assert(f.terminal_status.rx_drops == 7U);

    f.block_terminal_copy = true;
    f.force_output_idle = true;
    assert(pthread_create(&publisher, NULL, invalid_command_thread,
                          &publish_result) == 0);
    wait_flag(&f.terminal_copy_entered);
    assert(wifi_shield_busy());
    unsigned acquisitions = f.acquire_calls;
    assert(command(4, start) == 1);
    assert(f.acquire_calls == acquisitions);

    release_gate(&f.release_terminal_copy);
    assert(pthread_join(publisher, NULL) == 0);
    assert(publish_result.command_result == 1);
    assert(f.terminal_status.rx_drops == 7U);

    assert(pthread_create(&starter, NULL, start_thread, &start_result) == 0);
    assert(pthread_join(starter, NULL) == 0);
    assert(start_result.command_result == 0);
    f.force_output_idle = false;
    assert(wifi_shield_stop(100U));
}

static void assert_oled_widths(const wifi_shield_oled_lines_t *lines)
{
    assert(lines != NULL);
    for (size_t i = 0U; i < 4U; ++i)
        assert(strlen(lines->line[i]) <= 21U);
}

static void scenario_presentation_mapping_and_bounded_oled(void)
{
    static const struct {
        wifi_shield_event_type_t event;
        wifi_shield_presentation_indicator_t indicator;
    } cases[] = {
        {WIFI_SHIELD_EVENT_DEAUTH, WIFI_SHIELD_PRESENTATION_ALERT},
        {WIFI_SHIELD_EVENT_DISASSOC, WIFI_SHIELD_PRESENTATION_ALERT},
        {WIFI_SHIELD_EVENT_CSA, WIFI_SHIELD_PRESENTATION_INFO},
        {WIFI_SHIELD_EVENT_WPS_ACTIVITY, WIFI_SHIELD_PRESENTATION_INFO},
        {WIFI_SHIELD_EVENT_WPS_RETRY_BURST, WIFI_SHIELD_PRESENTATION_WARN},
        {WIFI_SHIELD_EVENT_WPS_ANOMALY, WIFI_SHIELD_PRESENTATION_ALERT},
        {WIFI_SHIELD_EVENT_SAE_ACTIVITY, WIFI_SHIELD_PRESENTATION_INFO},
        {WIFI_SHIELD_EVENT_SAE_ANOMALY, WIFI_SHIELD_PRESENTATION_ALERT},
        {WIFI_SHIELD_EVENT_TRUST_DRIFT, WIFI_SHIELD_PRESENTATION_ALERT},
        {WIFI_SHIELD_EVENT_PMKID_SEQUENCE, WIFI_SHIELD_PRESENTATION_INFO},
    };
    for (size_t i = 0U; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        wifi_shield_presentation_indicator_t indicator =
            WIFI_SHIELD_PRESENTATION_DECOY_TX;
        assert(wifi_shield_presentation_indicator(cases[i].event,
                                                   &indicator));
        assert(indicator == cases[i].indicator);
        assert(indicator != WIFI_SHIELD_PRESENTATION_DECOY_TX);
    }
    wifi_shield_presentation_indicator_t indicator =
        WIFI_SHIELD_PRESENTATION_DECOY_TX;
    assert(!wifi_shield_presentation_indicator(
        (wifi_shield_event_type_t)99, &indicator));
    assert(!wifi_shield_presentation_indicator(
        WIFI_SHIELD_EVENT_DEAUTH, NULL));

    wifi_shield_presentation_snapshot_t snapshot = {
        .target_count = 2U,
        .current_channel = 4U,
        .source_events = {12U, 3U, 0U, 1U},
        .latest_alert_type = WIFI_SHIELD_EVENT_WPS_RETRY_BURST,
        .latest_alert_valid = true,
    };
    wifi_shield_oled_lines_t lines;
    assert(wifi_shield_presentation_format_oled(&snapshot, &lines));
    assert(strcmp(lines.line[0], "> WiFi Shield") == 0);
    assert(strcmp(lines.line[1], "Targets: 2  Ch: 4") == 0);
    assert(strcmp(lines.line[2], "D:12 W:3 S:0 T:1") == 0);
    assert(strcmp(lines.line[3], "Alert: WPS retry") == 0);
    assert_oled_widths(&lines);

    snapshot.target_count = UINT8_MAX;
    snapshot.current_channel = UINT8_MAX;
    snapshot.source_events[0] = 99U;
    snapshot.source_events[1] = 100U;
    snapshot.source_events[2] = UINT32_MAX;
    snapshot.source_events[3] = 7U;
    snapshot.latest_alert_type = WIFI_SHIELD_EVENT_CSA;
    assert(wifi_shield_presentation_format_oled(&snapshot, &lines));
    assert(strcmp(lines.line[1], "Targets: 255  Ch: 255") == 0);
    assert(strcmp(lines.line[2], "D:99W:99+S:99+T:7") == 0);
    assert(strcmp(lines.line[3], "Alert: none") == 0);
    assert_oled_widths(&lines);

    static const struct {
        wifi_shield_event_type_t event;
        const char *line;
    } labels[] = {
        {WIFI_SHIELD_EVENT_WPS_RETRY_BURST, "Alert: WPS retry"},
        {WIFI_SHIELD_EVENT_WPS_ANOMALY, "Alert: WPS anomaly"},
        {WIFI_SHIELD_EVENT_SAE_ANOMALY, "Alert: SAE anomaly"},
        {WIFI_SHIELD_EVENT_DEAUTH, "Alert: Deauth"},
        {WIFI_SHIELD_EVENT_DISASSOC, "Alert: Disassoc"},
        {WIFI_SHIELD_EVENT_CSA, "Alert: none"},
        {WIFI_SHIELD_EVENT_TRUST_DRIFT, "Alert: Trust drift"},
    };
    snapshot.target_count = 0U;
    snapshot.current_channel = 0U;
    memset(snapshot.source_events, 0, sizeof(snapshot.source_events));
    for (size_t i = 0U; i < sizeof(labels) / sizeof(labels[0]); ++i) {
        snapshot.latest_alert_type = labels[i].event;
        assert(wifi_shield_presentation_format_oled(&snapshot, &lines));
        assert(strcmp(lines.line[3], labels[i].line) == 0);
        assert_oled_widths(&lines);
    }
    snapshot.latest_alert_valid = false;
    assert(wifi_shield_presentation_format_oled(&snapshot, &lines));
    assert(strcmp(lines.line[3], "Alert: none") == 0);
    snapshot.latest_alert_valid = true;
    snapshot.latest_alert_type = (wifi_shield_event_type_t)99;
    assert(wifi_shield_presentation_format_oled(&snapshot, &lines));
    assert(strcmp(lines.line[3], "Alert: none") == 0);
    assert(!wifi_shield_presentation_format_oled(NULL, &lines));
    assert(!wifi_shield_presentation_format_oled(&snapshot, NULL));
}

static void scenario_first_event_after_armed_accept_is_not_suppressed(void)
{
    pthread_t starter;
    async_result_t start_result = {.command_result = -1};
    reset_fixture(1U);
    f.block_armed_leave = true;
    assert(pthread_create(&starter, NULL, start_thread, &start_result) == 0);
    wait_flag(&f.armed_leave_entered);
    assert(strstr(f.all_lines, "[SHIELD/1] ARMED ") != NULL);

    uint8_t frame[128];
    size_t length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, f.scan[0].channel, false));
    char *armed = strstr(f.all_lines, "[SHIELD/1] ARMED ");
    char *event = strstr(f.all_lines, "[SHIELD/1] EVENT ");
    assert(armed != NULL && event != NULL && armed < event);
    wifi_shield_presentation_snapshot_t snapshot;
    wifi_shield_presentation_get(&snapshot);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_INFO] == 1U);

    release_gate(&f.release_armed_leave);
    assert(pthread_join(starter, NULL) == 0);
    assert(start_result.command_result == 0);
    wifi_shield_presentation_get(&snapshot);
    assert(snapshot.armed && snapshot.running && !snapshot.stopping);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_INFO] == 1U);
    assert(wifi_shield_stop(100U));
}

static void scenario_presentation_acceptance_lifecycle_and_reset(void)
{
    wifi_shield_presentation_snapshot_t initial;
    wifi_shield_presentation_snapshot_t snapshot;
    reset_fixture(1U);
    wifi_shield_presentation_get(&initial);
    assert(!initial.armed && !initial.running && !initial.stopping);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);
    wifi_shield_presentation_get(&snapshot);
    assert(snapshot.session_id != 0U && snapshot.revision != 0U);
    assert(snapshot.armed && snapshot.running && !snapshot.stopping);
    assert(snapshot.target_count == 1U);
    assert(snapshot.current_channel == f.scan[0].channel);
    for (size_t i = 0U; i < WIFI_SHIELD_PRESENTATION_INDICATOR_COUNT; ++i)
        assert(snapshot.indicator_counts[i] == 0U);

    uint8_t frame[128];
    size_t length = make_wps_frame(frame, f.scan[0].bssid, false);
    assert(deliver_full(frame, length, f.scan[0].channel, false));
    wifi_shield_presentation_get(&snapshot);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_INFO] == 1U);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_WARN] == 0U);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_ALERT] == 0U);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_DECOY_TX] == 0U);
    assert(snapshot.source_events[WIFI_SHIELD_SOURCE_WPS] == 1U);
    assert(!snapshot.latest_alert_valid);

    wifi_shield_compact_event_t event;
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, f.scan[0].channel, 26U);
    event.bytes[0] = 0xc0U;
    assert(wifi_shield_consume_compact(f.config.context, &event));
    wifi_shield_presentation_get(&snapshot);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_ALERT] == 1U);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_DECOY_TX] == 0U);
    assert(snapshot.source_events[WIFI_SHIELD_SOURCE_DEAUTH] == 1U);
    assert(snapshot.latest_alert_valid);
    assert(snapshot.latest_alert_type == WIFI_SHIELD_EVENT_DEAUTH);

    uint32_t indicators[WIFI_SHIELD_PRESENTATION_INDICATOR_COUNT];
    memcpy(indicators, snapshot.indicator_counts, sizeof(indicators));
    uint32_t revision = snapshot.revision;
    f.runtime_status.rx_drops = 9U;
    wifi_shield_worker_poll();
    char *status[] = {"wifi_shield", "status"};
    assert(command(2, status) == 0);
    wifi_shield_presentation_get(&snapshot);
    assert(memcmp(indicators, snapshot.indicator_counts,
                  sizeof(indicators)) == 0);
    assert(snapshot.revision >= revision);

    f.finish_ok = false;
    assert(!wifi_shield_stop(100U));
    wifi_shield_presentation_get(&snapshot);
    assert(snapshot.armed && !snapshot.running && snapshot.stopping);
    f.finish_ok = true;
    assert(wifi_shield_stop(100U));
    wifi_shield_presentation_get(&snapshot);
    assert(!snapshot.armed && !snapshot.running && !snapshot.stopping);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_INFO] == 1U);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_ALERT] == 1U);
    uint32_t completed_session = snapshot.session_id;

    f.lease_released = false;
    assert(command(4, start) == 0);
    wifi_shield_presentation_get(&snapshot);
    assert(snapshot.session_id != completed_session);
    assert(snapshot.armed && snapshot.running && !snapshot.stopping);
    for (size_t i = 0U; i < WIFI_SHIELD_PRESENTATION_INDICATOR_COUNT; ++i)
        assert(snapshot.indicator_counts[i] == 0U);
    assert(!snapshot.latest_alert_valid);
    assert(wifi_shield_stop(100U));

    reset_fixture(1U);
    assert(command(4, start) == 0);
    f.fail_write = true;
    compact_header(&event, WIFI_SHIELD_COMPACT_DEAUTH,
                   f.scan[0].bssid, f.scan[0].channel, 26U);
    event.bytes[0] = 0xc0U;
    assert(!wifi_shield_consume_compact(f.config.context, &event));
    wifi_shield_presentation_get(&snapshot);
    assert(snapshot.source_events[WIFI_SHIELD_SOURCE_DEAUTH] == 1U);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_ALERT] == 0U);
    assert(snapshot.indicator_counts[WIFI_SHIELD_PRESENTATION_DECOY_TX] == 0U);
    f.fail_write = false;
    assert(wifi_shield_stop(100U));
}

static void scenario_presentation_snapshot_is_mutexed_and_owned(void)
{
    pthread_t reader, stopper;
    async_result_t read_result = {0};
    async_result_t stop_result = {0};
    reset_fixture(1U);
    char *start[] = {"wifi_shield", "start", "--only", "1"};
    assert(command(4, start) == 0);

    f.block_finish_wipe = true;
    assert(pthread_create(&stopper, NULL, stop_thread, &stop_result) == 0);
    wait_flag(&f.finish_wipe_entered);
    f.block_state_enter = true;
    assert(pthread_create(&reader, NULL, presentation_get_thread,
                          &read_result) == 0);
    wait_flag(&f.state_entered);
    unsigned attempts_before;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    attempts_before = f.state_enter_attempts;
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    release_gate(&f.release_finish_wipe);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while (f.state_enter_attempts == attempts_before)
        assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    assert(!f.release_attempted);
    f.release_state_enter = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);

    assert(pthread_join(reader, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(read_result.snapshot.armed && !read_result.snapshot.running &&
           read_result.snapshot.stopping);
    assert(stop_result.result && f.release_attempted);
    wifi_shield_presentation_snapshot_t final_snapshot;
    wifi_shield_presentation_get(&final_snapshot);
    assert(!final_snapshot.armed && !final_snapshot.running &&
           !final_snapshot.stopping);
    assert(final_snapshot.session_id == read_result.snapshot.session_id);
}

static void scenario_idempotent_stop(void)
{
    reset_fixture(1U);
    assert(wifi_shield_stop(100U));
    assert(f.quiesce_calls == 0U && f.drain_calls == 0U &&
           f.finish_calls == 0U && f.terminal_calls == 0U);
    assert(wifi_shield_stop(100U));
    assert(f.quiesce_calls == 0U);
}

static bool profile_consume(void *context,
                            const wifi_security_frame_slot_t *slot,
                            const wifi_security_decoded_t *decoded)
{
    assert(context == &f && slot != NULL && decoded != NULL);
    assert(slot->channel == f.profile_channel);
    (void)decoded;
    ++f.profile_consume_calls;
    return true;
}

static bool profile_validate(void *context)
{
    return context == &f;
}

static void profile_wipe(void *context)
{
    assert(context == &f);
}

static void profile_uncertainty(void *context,
                                wifi_security_session_result_t result,
                                bool owned)
{
    assert(context == &f);
    (void)result;
    (void)owned;
}

static wifi_security_session_config_t wps_profile_config(void)
{
    wifi_security_session_config_t config = {
        .module = WIFI_SECURITY_MODULE_WPS_GUARD,
        .context = &f,
        .consume = profile_consume,
        .validate = profile_validate,
        .wipe = profile_wipe,
        .telemetry_context = &f,
        .uncertainty = profile_uncertainty,
    };
    return config;
}

static wifi_security_session_config_t sae_profile_config(void)
{
    wifi_security_session_config_t config = wps_profile_config();
    config.module = WIFI_SECURITY_MODULE_SAE_GUARD;
    return config;
}

static wifi_security_session_config_t trust_profile_config(void)
{
    wifi_security_session_config_t config = wps_profile_config();
    config.module = WIFI_SECURITY_MODULE_TRUST_MONITOR;
    return config;
}

static bool deauth_borrowed_receive(
    void *context, uint32_t generation,
    const wifi_security_rx_view_t *observation)
{
    (void)context;
    (void)generation;
    (void)observation;
    return true;
}

static void deauth_worker_poll(void *context)
{
    (void)context;
}

static wifi_security_session_config_t deauth_profile_config(void)
{
    wifi_security_session_config_t config = wps_profile_config();
    config.module = WIFI_SECURITY_MODULE_DEAUTH_V2;
    config.receive_policy = WIFI_SECURITY_RECEIVE_MGMT;
    config.borrowed_receive = deauth_borrowed_receive;
    config.worker_poll = deauth_worker_poll;
    return config;
}

static bool profile_deliver_on_channel(uint8_t frame_channel)
{
    if (frame_channel != f.profile_channel ||
        f.profile_config.consume == NULL)
        return false;
    wifi_security_frame_slot_t slot = {.channel = frame_channel};
    wifi_security_decoded_t decoded = {0};
    return f.profile_config.consume(
        f.profile_config.context, &slot, &decoded);
}

static void scenario_deauth_profile_explicit_channel_plan(void)
{
    reset_fixture(0U);
    wifi_shield_target_t target = {0};
    target.bssid[0] = 0x02U;
    target.bssid[5] = 0xd2U;
    target.channel = 6U;
    const uint8_t channels[] = {1U, 6U, 11U};
    wifi_security_session_config_t config = deauth_profile_config();

    assert(wifi_shield_start_deauth_profile(
               &target, 1U, channels, 3U, &config, NULL) ==
           WIFI_SECURITY_SESSION_OK);
    assert(f.profile_start_calls == 1U && f.profile_channel == 1U &&
           f.runtime_status.module == WIFI_SECURITY_MODULE_DEAUTH_V2);
    assert(f.profile_config.receive_policy == WIFI_SECURITY_RECEIVE_MGMT);
    assert(f.profile_config.borrowed_receive == deauth_borrowed_receive);
    assert(f.profile_config.worker_poll == deauth_worker_poll);
    uint32_t deauth_generation = 0U;
    assert(wifi_shield_deauth_profile_generation(&deauth_generation));
    assert(deauth_generation == f.runtime_status.generation);
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 0U && f.profile_channel == 1U);
    assert(wifi_shield_deauth_profile_retune(6U));
    assert(f.profile_retune_calls == 1U && f.profile_channel == 6U);
    assert(wifi_shield_deauth_profile_retune(11U));
    assert(f.profile_retune_calls == 2U && f.profile_channel == 11U);
    assert(!wifi_shield_deauth_profile_retune(36U));
    wifi_shield_deauth_radio_token_t token = {0};
    assert(!wifi_shield_deauth_profile_radio_enter(36U, &token));
    assert(wifi_shield_deauth_profile_radio_enter(6U, &token));
    assert(token.held && token.runtime_generation == deauth_generation &&
           token.channel == 6U);
    assert(f.profile_retune_calls == 3U && f.profile_channel == 6U);
    assert(wifi_shield_deauth_profile_radio_leave(&token));
    assert(!token.held);
    assert(wifi_shield_stop_deauth_profile(100U));
    assert(!wifi_shield_deauth_profile_generation(&deauth_generation));
    assert(f.profile_stop_calls == 1U && !wifi_shield_busy());
}

static void scenario_deauth_profile_same_and_cross_module_aba(void)
{
    wifi_shield_target_t target = {0};
    target.bssid[0] = 0x02U;
    target.bssid[5] = 0xe2U;
    target.channel = 6U;
    const uint8_t channels[] = {1U, 6U, 11U};
    wifi_security_session_config_t deauth = deauth_profile_config();

    reset_fixture(0U);
    assert(wifi_shield_start_deauth_profile(
               &target, 1U, channels, 3U, &deauth, NULL) ==
           WIFI_SECURITY_SESSION_OK);
    uint32_t first_generation = 0U;
    assert(wifi_shield_deauth_profile_generation(&first_generation));
    assert(wifi_shield_stop_wps_profile(100U));
    assert(wifi_shield_stop_sae_profile(100U));
    assert(wifi_shield_stop_trust_profile(100U));
    assert(f.runtime_status.running && f.profile_stop_calls == 0U);
    wifi_security_session_config_t wps = wps_profile_config();
    wifi_security_session_config_t sae = sae_profile_config();
    wifi_security_session_config_t trust = trust_profile_config();
    assert(wifi_shield_start_wps_profile(&target, 1U, &wps) ==
           WIFI_SECURITY_SESSION_BUSY);
    assert(wifi_shield_start_sae_profile(&target, 1U, &sae) ==
           WIFI_SECURITY_SESSION_BUSY);
    assert(wifi_shield_start_trust_profile(&target, 1U, &trust) ==
           WIFI_SECURITY_SESSION_BUSY);
    assert(wifi_shield_stop_deauth_profile(100U));

    assert(wifi_shield_start_deauth_profile(
               &target, 1U, channels, 3U, &deauth, NULL) ==
           WIFI_SECURITY_SESSION_OK);
    uint32_t second_generation = 0U;
    assert(wifi_shield_deauth_profile_generation(&second_generation));
    assert(second_generation != first_generation);
    wifi_shield_deauth_radio_token_t token = {0};
    assert(wifi_shield_deauth_profile_radio_enter(6U, &token));
    uint32_t active_generation = f.runtime_status.generation;
    ++f.runtime_status.generation;
    assert(!wifi_shield_deauth_profile_radio_leave(&token));
    f.runtime_status.generation = active_generation;
    assert(wifi_shield_stop_deauth_profile(100U));

    const wifi_security_session_config_t modules[] = {wps, sae, trust};
    for (size_t i = 0U; i < sizeof(modules) / sizeof(modules[0]); ++i) {
        wifi_security_session_result_t started;
        if (modules[i].module == WIFI_SECURITY_MODULE_WPS_GUARD)
            started = wifi_shield_start_wps_profile(&target, 1U, &modules[i]);
        else if (modules[i].module == WIFI_SECURITY_MODULE_SAE_GUARD)
            started = wifi_shield_start_sae_profile(&target, 1U, &modules[i]);
        else
            started = wifi_shield_start_trust_profile(&target, 1U, &modules[i]);
        assert(started == WIFI_SECURITY_SESSION_OK);
        assert(wifi_shield_start_deauth_profile(
                   &target, 1U, channels, 3U, &deauth, NULL) ==
               WIFI_SECURITY_SESSION_BUSY);
        assert(wifi_shield_stop_deauth_profile(100U));
        assert(f.runtime_status.running &&
               f.runtime_status.module == modules[i].module);
        bool stopped = modules[i].module == WIFI_SECURITY_MODULE_WPS_GUARD
            ? wifi_shield_stop_wps_profile(100U)
            : modules[i].module == WIFI_SECURITY_MODULE_SAE_GUARD
                  ? wifi_shield_stop_sae_profile(100U)
                  : wifi_shield_stop_trust_profile(100U);
        assert(stopped);
    }
}

static void scenario_deauth_bare_scan_reservation_is_adopted(void)
{
    wifi_shield_target_t target = {0};
    target.bssid[0] = 0x02U;
    target.bssid[5] = 0xf2U;
    target.channel = 6U;
    const uint8_t channels[] = {1U, 6U, 11U};
    wifi_security_session_config_t deauth = deauth_profile_config();

    reset_fixture(0U);
    wifi_shield_deauth_scan_token_t token = {0};
    assert(wifi_shield_reserve_deauth_scan(&token));
    assert(token.held && token.packed_lifecycle != 0U);
    assert(f.reserved && f.reserve_calls == 1U && wifi_shield_busy());
    assert(wifi_shield_start_deauth_profile(
               &target, 1U, channels, 3U, &deauth, &token) ==
           WIFI_SECURITY_SESSION_OK);
    assert(!token.held);
    assert(!f.reserved && f.profile_start_calls == 1U);
    assert(wifi_shield_stop_deauth_profile(100U));

    reset_fixture(0U);
    wifi_shield_deauth_scan_token_t first = {0};
    assert(wifi_shield_reserve_deauth_scan(&first));
    wifi_shield_deauth_scan_token_t stale = first;
    assert(wifi_shield_abort_deauth_scan(&first, 100U));
    assert(!first.held);
    wifi_shield_deauth_scan_token_t second = {0};
    assert(wifi_shield_reserve_deauth_scan(&second));
    assert(second.held && second.packed_lifecycle != stale.packed_lifecycle);
    assert(wifi_shield_start_deauth_profile(
               &target, 1U, channels, 3U, &deauth, &stale) ==
           WIFI_SECURITY_SESSION_CANCELLED);
    assert(second.held && f.reserved && f.profile_start_calls == 0U);
    assert(wifi_shield_abort_deauth_scan(&stale, 100U));
    assert(second.held && f.reserved && f.abort_calls == 1U);
    assert(wifi_shield_start_deauth_profile(
               &target, 1U, channels, 3U, &deauth, &second) ==
           WIFI_SECURITY_SESSION_OK);
    assert(!second.held && f.profile_start_calls == 1U);
    assert(wifi_shield_stop_deauth_profile(100U));
    assert(f.reserve_calls == 2U && f.abort_calls == 1U &&
           !f.reserved && !wifi_shield_busy());

    reset_fixture(0U);
    f.reserve_ok = false;
    f.reserve_retained = true;
    f.abort_ok = false;
    wifi_shield_deauth_scan_token_t retained = {0};
    assert(!wifi_shield_reserve_deauth_scan(&retained));
    assert(retained.held && retained.packed_lifecycle != 0U);
    assert(f.reserved && f.reserve_calls == 1U && f.abort_calls == 1U);
    assert(wifi_shield_busy());
    assert(!wifi_shield_abort_deauth_scan(&retained, 100U));
    assert(retained.held && f.reserved && f.abort_calls == 2U);
    f.abort_ok = true;
    assert(wifi_shield_abort_deauth_scan(&retained, 100U));
    assert(!retained.held && !f.reserved && f.abort_calls == 3U);
    assert(!wifi_shield_busy());
}

static void scenario_wps_profile_initial_tune_hop_retry_and_silence(void)
{
    reset_fixture(0U);
    wifi_shield_target_t targets[3] = {0};
    for (size_t i = 0U; i < 3U; ++i) {
        targets[i].bssid[0] = 0x02U;
        targets[i].bssid[5] = (uint8_t)(0x20U + i);
    }
    targets[0].channel = 1U;
    targets[1].channel = 6U;
    targets[2].channel = 11U;
    wifi_security_session_config_t config = wps_profile_config();
    unsigned writes = f.write_calls, terminals = f.terminal_calls;
    wifi_shield_presentation_snapshot_t presentation_before;
    wifi_shield_presentation_snapshot_t presentation_after;
    wifi_shield_presentation_get(&presentation_before);

    assert(wifi_shield_start_wps_profile(targets, 3U, &config) ==
           WIFI_SECURITY_SESSION_OK);
    assert(f.profile_start_calls == 1U &&
           f.profile_config.initial_channel == 1U && f.profile_channel == 1U);
    assert(!profile_deliver_on_channel(6U));
    assert(f.profile_consume_calls == 0U);
    assert(profile_deliver_on_channel(1U));
    assert(f.profile_consume_calls == 1U);
    assert(f.write_calls == writes && f.terminal_calls == terminals &&
           tx_calls == 0U);

    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US - 1U;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 0U);
    ++f.now_us;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 1U &&
           f.profile_retune_history[0] == 6U && f.profile_channel == 6U);
    assert(profile_deliver_on_channel(6U));
    assert(f.profile_consume_calls == 2U && f.profile_start_calls == 1U);
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 2U &&
           f.profile_retune_history[1] == 11U && f.profile_channel == 11U);
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 3U &&
           f.profile_retune_history[2] == 1U && f.profile_channel == 1U);

    f.profile_retune_ok = false;
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 4U &&
           f.profile_retune_history[3] == 6U && f.profile_channel == 1U);
    f.profile_retune_ok = true;
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 5U &&
           f.profile_retune_history[4] == 6U && f.profile_channel == 6U);

    ++f.runtime_status.generation;
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 5U);
    assert(wifi_shield_stop_wps_profile(100U));
    assert(f.profile_stop_calls == 1U);
    wifi_shield_presentation_get(&presentation_after);
    assert(memcmp(&presentation_before, &presentation_after,
                  sizeof(presentation_before)) == 0);
    assert(f.write_calls == writes && f.terminal_calls == terminals &&
           tx_calls == 0U);

    reset_fixture(0U);
    targets[1].channel = targets[0].channel;
    targets[2].channel = targets[0].channel;
    config = wps_profile_config();
    assert(wifi_shield_start_wps_profile(targets, 3U, &config) ==
           WIFI_SECURITY_SESSION_OK);
    f.now_us += 4U * WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 0U);
    assert(wifi_shield_stop_wps_profile(100U));
}

static void scenario_sae_profile_reuses_scheduler_and_stays_silent(void)
{
    reset_fixture(0U);
    wifi_shield_target_t targets[3] = {0};
    for (size_t i = 0U; i < 3U; ++i) {
        targets[i].bssid[0] = 0x02U;
        targets[i].bssid[5] = (uint8_t)(0x30U + i);
    }
    targets[0].channel = 1U;
    targets[1].channel = 6U;
    targets[2].channel = 11U;
    wifi_security_session_config_t config = sae_profile_config();
    unsigned writes = f.write_calls;
    unsigned terminals = f.terminal_calls;
    wifi_shield_presentation_snapshot_t before;
    wifi_shield_presentation_snapshot_t after;
    wifi_shield_presentation_get(&before);

    assert(wifi_shield_start_sae_profile(targets, 3U, &config) ==
           WIFI_SECURITY_SESSION_OK);
    assert(f.profile_start_calls == 1U);
    assert(f.profile_config.module == WIFI_SECURITY_MODULE_SAE_GUARD);
    assert(f.profile_config.initial_channel == 1U && f.profile_channel == 1U);
    assert(!profile_deliver_on_channel(6U));
    assert(profile_deliver_on_channel(1U));
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US - 1U;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 0U);
    ++f.now_us;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 1U &&
           f.profile_retune_history[0] == 6U && f.profile_channel == 6U);
    assert(profile_deliver_on_channel(6U));
    f.profile_retune_ok = false;
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 2U &&
           f.profile_retune_history[1] == 11U && f.profile_channel == 6U);
    f.profile_retune_ok = true;
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 3U &&
           f.profile_retune_history[2] == 11U && f.profile_channel == 11U);
    ++f.runtime_status.generation;
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 3U);
    assert(wifi_shield_stop_sae_profile(100U));
    assert(f.profile_stop_calls == 1U);
    wifi_shield_presentation_get(&after);
    assert(memcmp(&before, &after, sizeof(before)) == 0);
    assert(f.write_calls == writes && f.terminal_calls == terminals &&
           tx_calls == 0U);

    reset_fixture(0U);
    targets[1].channel = targets[0].channel;
    targets[2].channel = targets[0].channel;
    config = sae_profile_config();
    assert(wifi_shield_start_sae_profile(targets, 3U, &config) ==
           WIFI_SECURITY_SESSION_OK);
    f.now_us += 4U * WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 0U);
    assert(wifi_shield_stop_sae_profile(100U));
}

static void scenario_trust_profile_bare_and_selected_scheduler(void)
{
    reset_fixture(0U);
    wifi_shield_presentation_snapshot_t before, after;
    wifi_shield_presentation_get(&before);
    unsigned writes = f.write_calls, terminals = f.terminal_calls;
    wifi_security_session_config_t config = trust_profile_config();
    assert(wifi_shield_start_trust_profile(NULL, 0U, &config) ==
           WIFI_SECURITY_SESSION_OK);
    assert(f.profile_start_calls == 1U);
    assert(f.profile_config.module == WIFI_SECURITY_MODULE_TRUST_MONITOR);
    assert(f.profile_config.initial_channel == 0U);
    f.now_us += 4U * WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 0U);
    assert(wifi_shield_stop_trust_profile(100U));
    wifi_shield_presentation_get(&after);
    assert(memcmp(&before, &after, sizeof(before)) == 0);
    assert(f.write_calls == writes && f.terminal_calls == terminals &&
           tx_calls == 0U);

    reset_fixture(0U);
    wifi_shield_presentation_get(&before);
    writes = f.write_calls;
    terminals = f.terminal_calls;
    wifi_shield_target_t targets[2] = {0};
    targets[0].bssid[0] = targets[1].bssid[0] = 0x02U;
    targets[0].bssid[5] = 0xc1U;
    targets[1].bssid[5] = 0xc2U;
    targets[0].channel = 1U;
    targets[1].channel = 11U;
    config = trust_profile_config();
    assert(wifi_shield_start_trust_profile(targets, 2U, &config) ==
           WIFI_SECURITY_SESSION_OK);
    assert(f.profile_config.initial_channel == 1U);
    f.profile_retune_ok = false;
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 1U &&
           f.profile_retune_history[0] == 11U && f.profile_channel == 1U);
    f.profile_retune_ok = true;
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 2U &&
           f.profile_retune_history[1] == 11U && f.profile_channel == 11U);
    ++f.runtime_status.generation;
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 2U);
    assert(wifi_shield_stop_trust_profile(100U));
    wifi_shield_presentation_get(&after);
    assert(memcmp(&before, &after, sizeof(before)) == 0);
    assert(f.write_calls == writes && f.terminal_calls == terminals &&
           tx_calls == 0U);
}

static void scenario_trust_profile_lifecycle_and_retained_cleanup(void)
{
    profile_start_thread_t start = {0};
    start.target.bssid[0] = 0x02U;
    start.target.bssid[5] = 0xe1U;
    start.target.channel = 6U;
    pthread_t starter, stopper, stopper_two;
    async_result_t stopped = {0};
    async_result_t stopped_two = {0};

    /* Two Stops during raw Start join the same attempt and perform one raw
     * cleanup after Start returns. */
    reset_fixture(0U);
    start.config = trust_profile_config();
    f.block_profile_start = true;
    assert(pthread_create(&starter, NULL, trust_profile_start_thread,
                          &start) == 0);
    wait_flag(&f.profile_start_entered);
    assert(pthread_create(&stopper, NULL, trust_profile_stop_thread,
                          &stopped) == 0);
    assert(pthread_create(&stopper_two, NULL, trust_profile_stop_thread,
                          &stopped_two) == 0);
    wait_profile_gate_attempts(3U);
    release_gate(&f.release_profile_start);
    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(pthread_join(stopper_two, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_CANCELLED);
    assert(stopped.result && stopped_two.result &&
           f.profile_stop_calls == 1U && !wifi_shield_busy());

    /* An uncertain raw Start remains quarantined. The blocked Stop does not
     * pretend cleanup happened; an explicit retry owns the one raw cleanup. */
    reset_fixture(0U);
    start.config = trust_profile_config();
    start.result = WIFI_SECURITY_SESSION_INVALID;
    f.profile_start_result = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    f.block_profile_start = true;
    assert(pthread_create(&starter, NULL, trust_profile_start_thread,
                          &start) == 0);
    wait_flag(&f.profile_start_entered);
    stopped = (async_result_t){0};
    assert(pthread_create(&stopper, NULL, trust_profile_stop_thread,
                          &stopped) == 0);
    wait_profile_gate_attempts(2U);
    release_gate(&f.release_profile_start);
    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_JOIN_TIMEOUT &&
           !stopped.result && f.profile_stop_calls == 0U &&
           wifi_shield_busy());
    f.profile_start_result = WIFI_SECURITY_SESSION_OK;
    assert(wifi_shield_stop_trust_profile(100U));
    assert(f.profile_stop_calls == 1U && !wifi_shield_busy());

    /* Stop after raw OK/status but before RUNNING commit preserves the Stop
     * latch and still joins to one verified cleanup. */
    reset_fixture(0U);
    start.config = trust_profile_config();
    start.result = WIFI_SECURITY_SESSION_INVALID;
    f.block_profile_arm_clock = true;
    assert(pthread_create(&starter, NULL, trust_profile_start_thread,
                          &start) == 0);
    wait_flag(&f.profile_arm_clock_entered);
    stopped = (async_result_t){0};
    stopped_two = (async_result_t){0};
    assert(pthread_create(&stopper, NULL, trust_profile_stop_thread,
                          &stopped) == 0);
    assert(pthread_create(&stopper_two, NULL, trust_profile_stop_thread,
                          &stopped_two) == 0);
    wait_profile_gate_attempts(3U);
    release_gate(&f.release_profile_arm_clock);
    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(pthread_join(stopper_two, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_CANCELLED &&
           stopped.result && stopped_two.result &&
           f.profile_stop_calls == 1U && !wifi_shield_busy());
}

static void scenario_sae_profile_lifecycle_gate_and_retained_cleanup(void)
{
    profile_start_thread_t start = {0};
    start.target.bssid[0] = 0x02U;
    start.target.bssid[5] = 0x81U;
    start.target.channel = 6U;
    pthread_t starter, stopper, stopper_two;
    async_result_t stopped = {0};
    async_result_t stopped_two = {0};

    reset_fixture(0U);
    start.config = sae_profile_config();
    f.block_profile_gate_start = true;
    assert(pthread_create(&starter, NULL, sae_profile_start_thread,
                          &start) == 0);
    wait_flag(&f.profile_gate_start_entered);
    assert(pthread_create(&stopper, NULL, sae_profile_stop_thread,
                          &stopped) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(stopped.result && f.profile_start_calls == 0U);
    release_gate(&f.release_profile_gate_start);
    assert(pthread_join(starter, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_CANCELLED);
    assert(f.profile_stop_calls == 0U && !wifi_shield_busy());

    reset_fixture(0U);
    start.config = sae_profile_config();
    start.result = WIFI_SECURITY_SESSION_INVALID;
    f.block_profile_start = true;
    assert(pthread_create(&starter, NULL, sae_profile_start_thread,
                          &start) == 0);
    wait_flag(&f.profile_start_entered);
    memset(&stopped, 0, sizeof(stopped));
    memset(&stopped_two, 0, sizeof(stopped_two));
    assert(pthread_create(&stopper, NULL, sae_profile_stop_thread,
                          &stopped) == 0);
    assert(pthread_create(&stopper_two, NULL, sae_profile_stop_thread,
                          &stopped_two) == 0);
    wait_profile_gate_attempts(3U);
    release_gate(&f.release_profile_start);
    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(pthread_join(stopper_two, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_CANCELLED);
    assert(stopped.result && stopped_two.result);
    assert(f.profile_stop_calls == 1U && !f.runtime_status.running &&
           !wifi_shield_busy());

    reset_fixture(0U);
    start.config = sae_profile_config();
    f.profile_start_result = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    f.block_profile_start = true;
    assert(pthread_create(&starter, NULL, sae_profile_start_thread,
                          &start) == 0);
    wait_flag(&f.profile_start_entered);
    memset(&stopped, 0, sizeof(stopped));
    assert(pthread_create(&stopper, NULL, sae_profile_stop_thread,
                          &stopped) == 0);
    wait_profile_gate_attempts(2U);
    release_gate(&f.release_profile_start);
    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_JOIN_TIMEOUT);
    assert(!stopped.result && f.profile_stop_calls == 0U &&
           wifi_shield_busy());
    f.profile_start_result = WIFI_SECURITY_SESSION_OK;
    assert(wifi_shield_stop_sae_profile(100U));
    assert(f.profile_stop_calls == 1U && !wifi_shield_busy());

    reset_fixture(0U);
    start.config = sae_profile_config();
    f.block_profile_arm_clock = true;
    assert(pthread_create(&starter, NULL, sae_profile_start_thread,
                          &start) == 0);
    wait_flag(&f.profile_arm_clock_entered);
    memset(&stopped, 0, sizeof(stopped));
    memset(&stopped_two, 0, sizeof(stopped_two));
    assert(pthread_create(&stopper, NULL, sae_profile_stop_thread,
                          &stopped) == 0);
    assert(pthread_create(&stopper_two, NULL, sae_profile_stop_thread,
                          &stopped_two) == 0);
    wait_profile_gate_attempts(3U);
    release_gate(&f.release_profile_arm_clock);
    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(pthread_join(stopper_two, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_CANCELLED);
    assert(stopped.result && stopped_two.result);
    assert(f.profile_stop_calls == 1U && !f.runtime_status.running &&
           !wifi_shield_busy());
}

static void scenario_wps_profile_start_failure_and_retained_cleanup(void)
{
    wifi_shield_target_t target = {0};
    target.bssid[0] = 0x02U;
    target.bssid[5] = 0x44U;
    target.channel = 6U;

    reset_fixture(0U);
    wifi_security_session_config_t config = wps_profile_config();
    f.profile_start_result = WIFI_SECURITY_SESSION_BUSY;
    assert(wifi_shield_start_wps_profile(&target, 1U, &config) ==
           WIFI_SECURITY_SESSION_BUSY);
    assert(f.profile_start_calls == 1U && f.profile_stop_calls == 0U);
    f.profile_start_result = WIFI_SECURITY_SESSION_OK;
    assert(wifi_shield_start_wps_profile(&target, 1U, &config) ==
           WIFI_SECURITY_SESSION_OK);
    assert(wifi_shield_stop_wps_profile(100U));

    reset_fixture(0U);
    config = wps_profile_config();
    f.profile_start_result = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    assert(wifi_shield_start_wps_profile(&target, 1U, &config) ==
           WIFI_SECURITY_SESSION_JOIN_TIMEOUT);
    f.now_us += 4U * WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 0U);
    f.profile_stop_ok = false;
    assert(!wifi_shield_stop_wps_profile(100U));
    f.now_us += 4U * WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 0U);
    f.profile_stop_ok = true;
    assert(wifi_shield_stop_wps_profile(100U));
    assert(f.profile_stop_calls == 2U);
}

static void scenario_wps_profile_stop_fence_and_no_late_retune(void)
{
    wifi_shield_target_t targets[2] = {0};
    targets[0].bssid[0] = targets[1].bssid[0] = 0x02U;
    targets[0].bssid[5] = 0x51U;
    targets[1].bssid[5] = 0x52U;
    targets[0].channel = 1U;
    targets[1].channel = 6U;

    reset_fixture(0U);
    wifi_security_session_config_t config = wps_profile_config();
    assert(wifi_shield_start_wps_profile(targets, 2U, &config) ==
           WIFI_SECURITY_SESSION_OK);
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    f.block_stop_before_radio = true;
    async_result_t stopped = {0};
    pthread_t stopper;
    assert(pthread_create(&stopper, NULL, profile_stop_thread, &stopped) == 0);
    wait_flag(&f.stop_before_radio);
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 0U && f.profile_stop_calls == 0U);
    release_gate(&f.release_stop_before_radio);
    assert(pthread_join(stopper, NULL) == 0);
    assert(stopped.result && f.profile_stop_calls == 1U);

    reset_fixture(0U);
    config = wps_profile_config();
    assert(wifi_shield_start_wps_profile(targets, 2U, &config) ==
           WIFI_SECURITY_SESSION_OK);
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    f.block_profile_retune = true;
    pthread_t poller;
    assert(pthread_create(&poller, NULL, poll_thread, NULL) == 0);
    wait_flag(&f.profile_retune_entered);
    memset(&stopped, 0, sizeof(stopped));
    assert(pthread_create(&stopper, NULL, profile_stop_thread, &stopped) == 0);
    wait_radio_attempts(2U);
    assert(f.profile_stop_calls == 0U);
    release_gate(&f.release_profile_retune);
    assert(pthread_join(poller, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(stopped.result && f.profile_stop_calls == 1U &&
           f.profile_retune_calls == 1U);
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 1U);
}

static void scenario_wps_profile_controller_ownership_boundaries(void)
{
    wifi_shield_target_t target = {0};
    target.bssid[0] = 0x02U;
    target.bssid[5] = 0x61U;
    target.channel = 6U;

    reset_fixture(1U);
    char *shield_start[] = {"wifi_shield", "start"};
    assert(command(2, shield_start) == 0);
    wifi_security_session_config_t config = wps_profile_config();
    assert(wifi_shield_start_wps_profile(&target, 1U, &config) ==
           WIFI_SECURITY_SESSION_BUSY);
    assert(f.profile_start_calls == 0U);
    assert(wifi_shield_stop(100U));

    reset_fixture(0U);
    config = wps_profile_config();
    assert(wifi_shield_start_wps_profile(&target, 1U, &config) ==
           WIFI_SECURITY_SESSION_OK);
    unsigned profile_stops = f.profile_stop_calls;
    wifi_shield_runtime_hooks_t runtime = runtime_hooks();
    wifi_shield_output_hooks_t output = output_hooks();
    assert(!wifi_shield_init(&runtime, &output));
    assert(command(2, shield_start) == 1);
    char *shield_status[] = {"wifi_shield", "status"};
    char *shield_stop[] = {"wifi_shield", "stop"};
    assert(command(2, shield_status) == 0);
    assert(command(2, shield_stop) == 0);
    assert(f.profile_stop_calls == profile_stops && wifi_shield_busy() &&
           f.runtime_status.running);
    assert(wifi_shield_stop_wps_profile(100U));
}

static void scenario_wps_profile_preparing_stop_resolution(void)
{
    profile_start_thread_t start = {0};
    start.target.bssid[0] = 0x02U;
    start.target.bssid[5] = 0x71U;
    start.target.channel = 6U;
    pthread_t starter, stopper, stopper_two;
    async_result_t stopped = {0};

    /* Stop wins before Start owns the lifecycle gate: raw Start must never
     * run, and the bounded Stop returns verified success. */
    reset_fixture(0U);
    start.config = wps_profile_config();
    f.block_profile_gate_start = true;
    assert(pthread_create(&starter, NULL, profile_start_thread, &start) == 0);
    wait_flag(&f.profile_gate_start_entered);
    assert(pthread_create(&stopper, NULL, profile_stop_thread, &stopped) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(stopped.result && f.profile_start_calls == 0U);
    release_gate(&f.release_profile_gate_start);
    assert(pthread_join(starter, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_CANCELLED &&
           f.profile_stop_calls == 0U && !wifi_shield_busy());

    /* Raw Start is in flight. Two Stop callers latch once, wait on the same
     * gate and both observe the single verified cancellation cleanup. */
    reset_fixture(0U);
    start.config = wps_profile_config();
    f.block_profile_start = true;
    assert(pthread_create(&starter, NULL, profile_start_thread, &start) == 0);
    wait_flag(&f.profile_start_entered);
    memset(&stopped, 0, sizeof(stopped));
    async_result_t stopped_two = {0};
    assert(pthread_create(&stopper, NULL, profile_stop_thread, &stopped) == 0);
    assert(pthread_create(&stopper_two, NULL, profile_stop_thread,
                          &stopped_two) == 0);
    wait_profile_gate_attempts(3U);
    release_gate(&f.release_profile_start);
    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(pthread_join(stopper_two, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_CANCELLED);
    assert(stopped.result && stopped_two.result &&
           f.profile_stop_calls == 1U && !f.runtime_status.running &&
           !wifi_shield_busy());

    reset_fixture(0U);
    start.config = wps_profile_config();
    start.result = WIFI_SECURITY_SESSION_INVALID;
    f.block_profile_start = true;
    f.profile_stop_ok = false;
    assert(pthread_create(&starter, NULL, profile_start_thread, &start) == 0);
    wait_flag(&f.profile_start_entered);
    memset(&stopped, 0, sizeof(stopped));
    assert(pthread_create(&stopper, NULL, profile_stop_thread, &stopped) == 0);
    wait_profile_gate_attempts(2U);
    release_gate(&f.release_profile_start);
    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_CLEANUP_FAILED);
    assert(!stopped.result && f.profile_stop_calls == 1U &&
           wifi_shield_busy());
    f.profile_stop_ok = true;
    assert(wifi_shield_stop_wps_profile(100U));
    assert(f.profile_stop_calls == 2U && !wifi_shield_busy());

    reset_fixture(0U);
    start.config = wps_profile_config();
    f.profile_start_result = WIFI_SECURITY_SESSION_BUSY;
    f.block_profile_start = true;
    assert(pthread_create(&starter, NULL, profile_start_thread, &start) == 0);
    wait_flag(&f.profile_start_entered);
    memset(&stopped, 0, sizeof(stopped));
    assert(pthread_create(&stopper, NULL, profile_stop_thread, &stopped) == 0);
    wait_profile_gate_attempts(2U);
    release_gate(&f.release_profile_start);
    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_BUSY &&
           stopped.result && f.profile_stop_calls == 0U &&
           !wifi_shield_busy());

    reset_fixture(0U);
    start.config = wps_profile_config();
    f.profile_start_result = WIFI_SECURITY_SESSION_JOIN_TIMEOUT;
    f.block_profile_start = true;
    assert(pthread_create(&starter, NULL, profile_start_thread, &start) == 0);
    wait_flag(&f.profile_start_entered);
    memset(&stopped, 0, sizeof(stopped));
    assert(pthread_create(&stopper, NULL, profile_stop_thread, &stopped) == 0);
    wait_profile_gate_attempts(2U);
    release_gate(&f.release_profile_start);
    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_JOIN_TIMEOUT &&
           !stopped.result && f.profile_stop_calls == 0U &&
           wifi_shield_busy());
    assert(wifi_shield_stop_wps_profile(100U));
    assert(f.profile_stop_calls == 1U && !wifi_shield_busy());

    /* Stop lands after raw OK/status but before the RUNNING commit. CAS must
     * preserve the latch, one Start owner cleans up, and both Stops succeed. */
    reset_fixture(0U);
    start.config = wps_profile_config();
    f.block_profile_arm_clock = true;
    assert(pthread_create(&starter, NULL, profile_start_thread, &start) == 0);
    wait_flag(&f.profile_arm_clock_entered);
    memset(&stopped, 0, sizeof(stopped));
    stopped_two = (async_result_t){0};
    assert(pthread_create(&stopper, NULL, profile_stop_thread, &stopped) == 0);
    assert(pthread_create(&stopper_two, NULL, profile_stop_thread,
                          &stopped_two) == 0);
    wait_profile_gate_attempts(3U);
    release_gate(&f.release_profile_arm_clock);
    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(pthread_join(stopper_two, NULL) == 0);
    assert(start.result == WIFI_SECURITY_SESSION_CANCELLED &&
           stopped.result && stopped_two.result &&
           f.profile_stop_calls == 1U && !f.runtime_status.running &&
           !wifi_shield_busy());
    f.now_us += WIFI_SHIELD_CHANNEL_DWELL_US;
    wifi_shield_worker_poll();
    assert(f.profile_retune_calls == 0U);
}

static void scenario_cross_module_preparing_reservation_has_no_aba(void)
{
    profile_start_thread_t stale = {0};
    profile_start_thread_t next = {0};
    stale.target.bssid[0] = 0x02U;
    stale.target.bssid[5] = 0xa1U;
    stale.target.channel = 6U;
    next.target.bssid[0] = 0x02U;
    next.target.bssid[5] = 0xb2U;
    next.target.channel = 11U;
    pthread_t stale_thread, next_thread;

    /* A completed SAE Stop invalidates exactly the old reservation. A stale
     * SAE Start must not adopt a newer WPS PREPARING reservation. */
    reset_fixture(0U);
    stale.config = sae_profile_config();
    next.config = wps_profile_config();
    f.block_sae_profile_gate_start = true;
    assert(pthread_create(&stale_thread, NULL, sae_profile_start_thread,
                          &stale) == 0);
    wait_flag(&f.sae_profile_gate_start_entered);
    assert(wifi_shield_stop_sae_profile(100U));
    assert(!wifi_shield_busy() && f.profile_start_calls == 0U);

    f.block_wps_profile_gate_start = true;
    assert(pthread_create(&next_thread, NULL, profile_start_thread, &next) == 0);
    wait_flag(&f.wps_profile_gate_start_entered);
    release_gate(&f.release_sae_profile_gate_start);
    assert(pthread_join(stale_thread, NULL) == 0);
    assert(stale.result == WIFI_SECURITY_SESSION_CANCELLED);
    assert(f.profile_start_calls == 0U && !f.runtime_status.running);

    release_gate(&f.release_wps_profile_gate_start);
    assert(pthread_join(next_thread, NULL) == 0);
    assert(next.result == WIFI_SECURITY_SESSION_OK);
    assert(f.profile_start_calls == 1U && f.runtime_status.running &&
           f.runtime_status.module == WIFI_SECURITY_MODULE_WPS_GUARD);
    assert(wifi_shield_stop_wps_profile(100U));

    /* The inverse ordering must be equally safe: stale WPS cannot adopt a
     * newer SAE reservation or clear it during stale cleanup. */
    reset_fixture(0U);
    stale.config = wps_profile_config();
    stale.result = WIFI_SECURITY_SESSION_INVALID;
    next.config = sae_profile_config();
    next.result = WIFI_SECURITY_SESSION_INVALID;
    f.block_wps_profile_gate_start = true;
    assert(pthread_create(&stale_thread, NULL, profile_start_thread,
                          &stale) == 0);
    wait_flag(&f.wps_profile_gate_start_entered);
    assert(wifi_shield_stop_wps_profile(100U));
    assert(!wifi_shield_busy() && f.profile_start_calls == 0U);

    f.block_sae_profile_gate_start = true;
    assert(pthread_create(&next_thread, NULL, sae_profile_start_thread,
                          &next) == 0);
    wait_flag(&f.sae_profile_gate_start_entered);
    release_gate(&f.release_wps_profile_gate_start);
    assert(pthread_join(stale_thread, NULL) == 0);
    assert(stale.result == WIFI_SECURITY_SESSION_CANCELLED);
    assert(f.profile_start_calls == 0U && !f.runtime_status.running);

    release_gate(&f.release_sae_profile_gate_start);
    assert(pthread_join(next_thread, NULL) == 0);
    assert(next.result == WIFI_SECURITY_SESSION_OK);
    assert(f.profile_start_calls == 1U && f.runtime_status.running &&
           f.runtime_status.module == WIFI_SECURITY_MODULE_SAE_GUARD);
    assert(wifi_shield_stop_sae_profile(100U));

    /* A stale gate failure belongs to its old epoch. It is cancellation even
     * when a newer opposite-module PREPARING reservation is already visible. */
    reset_fixture(0U);
    stale.config = sae_profile_config();
    stale.result = WIFI_SECURITY_SESSION_INVALID;
    next.config = wps_profile_config();
    next.result = WIFI_SECURITY_SESSION_INVALID;
    f.block_sae_profile_gate_start = true;
    assert(pthread_create(&stale_thread, NULL, sae_profile_start_thread,
                          &stale) == 0);
    wait_flag(&f.sae_profile_gate_start_entered);
    assert(wifi_shield_stop_sae_profile(100U));
    f.block_wps_profile_gate_start = true;
    assert(pthread_create(&next_thread, NULL, profile_start_thread,
                          &next) == 0);
    wait_flag(&f.wps_profile_gate_start_entered);
    f.fail_sae_profile_gate_start = true;
    release_gate(&f.release_sae_profile_gate_start);
    assert(pthread_join(stale_thread, NULL) == 0);
    assert(stale.result == WIFI_SECURITY_SESSION_CANCELLED &&
           f.profile_start_calls == 0U);
    release_gate(&f.release_wps_profile_gate_start);
    assert(pthread_join(next_thread, NULL) == 0);
    assert(next.result == WIFI_SECURITY_SESSION_OK &&
           f.runtime_status.module == WIFI_SECURITY_MODULE_WPS_GUARD);
    assert(wifi_shield_stop_wps_profile(100U));

    /* A Stop that latched the old SAE epoch may complete after a newer WPS
     * session starts, but it must neither stop nor quarantine that session. */
    reset_fixture(0U);
    stale.config = sae_profile_config();
    stale.result = WIFI_SECURITY_SESSION_INVALID;
    f.block_profile_start = true;
    assert(pthread_create(&stale_thread, NULL, sae_profile_start_thread,
                          &stale) == 0);
    wait_flag(&f.profile_start_entered);
    f.block_profile_gate_stop = true;
    async_result_t stale_stop = {0};
    assert(pthread_create(&next_thread, NULL, sae_profile_stop_thread,
                          &stale_stop) == 0);
    wait_flag(&f.profile_gate_stop_entered);
    f.profile_start_result = WIFI_SECURITY_SESSION_BUSY;
    release_gate(&f.release_profile_start);
    assert(pthread_join(stale_thread, NULL) == 0);
    assert(stale.result == WIFI_SECURITY_SESSION_BUSY &&
           !wifi_shield_busy());

    f.profile_start_result = WIFI_SECURITY_SESSION_OK;
    next.config = wps_profile_config();
    assert(wifi_shield_start_wps_profile(&next.target, 1U, &next.config) ==
           WIFI_SECURITY_SESSION_OK);
    assert(f.runtime_status.running &&
           f.runtime_status.module == WIFI_SECURITY_MODULE_WPS_GUARD);
    release_gate(&f.release_profile_gate_stop);
    assert(pthread_join(next_thread, NULL) == 0);
    assert(stale_stop.result && f.profile_stop_calls == 0U &&
           f.runtime_status.running &&
           f.runtime_status.module == WIFI_SECURITY_MODULE_WPS_GUARD);
    assert(wifi_shield_stop_wps_profile(100U));
    assert(f.profile_stop_calls == 1U);
}

static void scenario_trust_cross_module_lifecycle_has_no_aba(void)
{
    profile_start_thread_t stale = {0};
    profile_start_thread_t next = {0};
    stale.target.bssid[0] = 0x02U;
    stale.target.bssid[5] = 0xc1U;
    stale.target.channel = 6U;
    next.target.bssid[0] = 0x02U;
    next.target.bssid[5] = 0xd2U;
    next.target.channel = 11U;
    pthread_t stale_thread, next_thread;

    /* Trust -> WPS: a stale Trust Start may not adopt or clear the newer
     * WPS PREPARING reservation. */
    reset_fixture(0U);
    stale.config = trust_profile_config();
    next.config = wps_profile_config();
    f.block_trust_profile_gate_start = true;
    assert(pthread_create(&stale_thread, NULL, trust_profile_start_thread,
                          &stale) == 0);
    wait_flag(&f.trust_profile_gate_start_entered);
    assert(wifi_shield_stop_trust_profile(100U));
    f.block_wps_profile_gate_start = true;
    assert(pthread_create(&next_thread, NULL, profile_start_thread,
                          &next) == 0);
    wait_flag(&f.wps_profile_gate_start_entered);
    release_gate(&f.release_trust_profile_gate_start);
    assert(pthread_join(stale_thread, NULL) == 0);
    assert(stale.result == WIFI_SECURITY_SESSION_CANCELLED &&
           f.profile_start_calls == 0U);
    release_gate(&f.release_wps_profile_gate_start);
    assert(pthread_join(next_thread, NULL) == 0);
    assert(next.result == WIFI_SECURITY_SESSION_OK &&
           f.runtime_status.module == WIFI_SECURITY_MODULE_WPS_GUARD);
    assert(wifi_shield_stop_wps_profile(100U));

    /* WPS -> Trust: the reverse ordering retains the Trust epoch. */
    reset_fixture(0U);
    stale.config = wps_profile_config();
    stale.result = WIFI_SECURITY_SESSION_INVALID;
    next.config = trust_profile_config();
    next.result = WIFI_SECURITY_SESSION_INVALID;
    f.block_wps_profile_gate_start = true;
    assert(pthread_create(&stale_thread, NULL, profile_start_thread,
                          &stale) == 0);
    wait_flag(&f.wps_profile_gate_start_entered);
    assert(wifi_shield_stop_wps_profile(100U));
    f.block_trust_profile_gate_start = true;
    assert(pthread_create(&next_thread, NULL, trust_profile_start_thread,
                          &next) == 0);
    wait_flag(&f.trust_profile_gate_start_entered);
    release_gate(&f.release_wps_profile_gate_start);
    assert(pthread_join(stale_thread, NULL) == 0);
    assert(stale.result == WIFI_SECURITY_SESSION_CANCELLED &&
           f.profile_start_calls == 0U);
    release_gate(&f.release_trust_profile_gate_start);
    assert(pthread_join(next_thread, NULL) == 0);
    assert(next.result == WIFI_SECURITY_SESSION_OK &&
           f.runtime_status.module == WIFI_SECURITY_MODULE_TRUST_MONITOR);
    assert(wifi_shield_stop_trust_profile(100U));

    /* Trust -> SAE plus a stale Trust gate failure. The failure is bound to
     * the cancelled Trust attempt and cannot erase the newer SAE epoch. */
    reset_fixture(0U);
    stale.config = trust_profile_config();
    stale.result = WIFI_SECURITY_SESSION_INVALID;
    next.config = sae_profile_config();
    next.result = WIFI_SECURITY_SESSION_INVALID;
    f.block_trust_profile_gate_start = true;
    assert(pthread_create(&stale_thread, NULL, trust_profile_start_thread,
                          &stale) == 0);
    wait_flag(&f.trust_profile_gate_start_entered);
    assert(wifi_shield_stop_trust_profile(100U));
    f.block_sae_profile_gate_start = true;
    assert(pthread_create(&next_thread, NULL, sae_profile_start_thread,
                          &next) == 0);
    wait_flag(&f.sae_profile_gate_start_entered);
    f.fail_trust_profile_gate_start = true;
    release_gate(&f.release_trust_profile_gate_start);
    assert(pthread_join(stale_thread, NULL) == 0);
    assert(stale.result == WIFI_SECURITY_SESSION_CANCELLED &&
           f.profile_start_calls == 0U);
    release_gate(&f.release_sae_profile_gate_start);
    assert(pthread_join(next_thread, NULL) == 0);
    assert(next.result == WIFI_SECURITY_SESSION_OK &&
           f.runtime_status.module == WIFI_SECURITY_MODULE_SAE_GUARD);
    assert(wifi_shield_stop_sae_profile(100U));

    /* SAE -> Trust proves the other reverse pair. */
    reset_fixture(0U);
    stale.config = sae_profile_config();
    stale.result = WIFI_SECURITY_SESSION_INVALID;
    next.config = trust_profile_config();
    next.result = WIFI_SECURITY_SESSION_INVALID;
    f.block_sae_profile_gate_start = true;
    assert(pthread_create(&stale_thread, NULL, sae_profile_start_thread,
                          &stale) == 0);
    wait_flag(&f.sae_profile_gate_start_entered);
    assert(wifi_shield_stop_sae_profile(100U));
    f.block_trust_profile_gate_start = true;
    assert(pthread_create(&next_thread, NULL, trust_profile_start_thread,
                          &next) == 0);
    wait_flag(&f.trust_profile_gate_start_entered);
    release_gate(&f.release_sae_profile_gate_start);
    assert(pthread_join(stale_thread, NULL) == 0);
    assert(stale.result == WIFI_SECURITY_SESSION_CANCELLED &&
           f.profile_start_calls == 0U);
    release_gate(&f.release_trust_profile_gate_start);
    assert(pthread_join(next_thread, NULL) == 0);
    assert(next.result == WIFI_SECURITY_SESSION_OK &&
           f.runtime_status.module == WIFI_SECURITY_MODULE_TRUST_MONITOR);
    assert(wifi_shield_stop_trust_profile(100U));

    /* A Trust Stop latched to an old epoch remains inert after WPS starts. */
    reset_fixture(0U);
    stale.config = trust_profile_config();
    stale.result = WIFI_SECURITY_SESSION_INVALID;
    f.block_profile_start = true;
    assert(pthread_create(&stale_thread, NULL, trust_profile_start_thread,
                          &stale) == 0);
    wait_flag(&f.profile_start_entered);
    f.block_profile_gate_stop = true;
    async_result_t stale_stop = {0};
    assert(pthread_create(&next_thread, NULL, trust_profile_stop_thread,
                          &stale_stop) == 0);
    wait_flag(&f.profile_gate_stop_entered);
    f.profile_start_result = WIFI_SECURITY_SESSION_BUSY;
    release_gate(&f.release_profile_start);
    assert(pthread_join(stale_thread, NULL) == 0);
    assert(stale.result == WIFI_SECURITY_SESSION_BUSY &&
           !wifi_shield_busy());
    f.profile_start_result = WIFI_SECURITY_SESSION_OK;
    next.config = wps_profile_config();
    assert(wifi_shield_start_wps_profile(&next.target, 1U, &next.config) ==
           WIFI_SECURITY_SESSION_OK);
    release_gate(&f.release_profile_gate_stop);
    assert(pthread_join(next_thread, NULL) == 0);
    assert(stale_stop.result && f.profile_stop_calls == 0U &&
           f.runtime_status.running &&
           f.runtime_status.module == WIFI_SECURITY_MODULE_WPS_GUARD);
    assert(wifi_shield_stop_wps_profile(100U));
}

static void scenario_guard_stop_waits_for_profile_start_cleanup(void)
{
    static const char expected[] =
        "[WPS_GUARD/1] TERMINAL OUTCOME=stopped RECEIVED=0 FILTERED=0"
        " UNRELATED=0 FRAGMENTS=0 RETRANSMISSIONS=0 COMPLETIONS=0"
        " ANOMALIES=0 TIMEOUTS=0 CAPACITY_DROPS=0 RX_DROPS=0"
        " OUTPUT_FAILURES=0 ACTIVE=0 RUNNING=0 STOPPING=0"
        " REASONS=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0\r\n";
    reset_fixture(2U);
    guard_release_calls = 0U;
    guard_complete_calls = 0U;
    guard_output_used = 0U;
    memset(guard_output, 0, sizeof(guard_output));
    assert(init_integrated_guard());

    f.block_profile_start = true;
    async_result_t started = {.command_result = -1};
    async_result_t stopped = {.command_result = -1};
    pthread_t starter, stopper;
    assert(pthread_create(&starter, NULL, guard_start_thread, &started) == 0);
    wait_flag(&f.profile_start_entered);
    assert(f.runtime_status.running && guard_release_calls == 0U);

    assert(pthread_create(&stopper, NULL, guard_stop_thread, &stopped) == 0);
    wait_profile_gate_attempts(2U);
    assert(guard_release_calls == 0U && f.profile_stop_calls == 0U);
    release_gate(&f.release_profile_start);

    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(started.command_result == 1 && stopped.command_result == 0);
    assert(f.profile_start_calls == 1U && f.profile_stop_calls == 1U);
    assert(!f.runtime_status.running && !f.runtime_status.stopping);
    assert(guard_release_calls == 1U && guard_complete_calls == 1U);
    assert(!wps_guard_busy() && !wifi_shield_busy());
    assert(guard_output_used == sizeof(expected) - 1U);
    assert(memcmp(guard_output, expected, sizeof(expected)) == 0);
}

static void scenario_sae_guard_stop_waits_for_profile_start_cleanup(void)
{
    static const char expected[] =
        "[SAE_GUARD/1] TERMINAL OUTCOME=stopped RECEIVED=0 FILTERED=0"
        " UNRELATED=0 OBSERVATIONS=0 COMMITS=0 CONFIRMS=0 RETRIES=0"
        " MALFORMED=0 ANTI_CLOGGING=0 STATUS_FAILURES=0 CAPACITY_DROPS=0"
        " PAIR_DROPS=0 MALFORMED_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0"
        " ACTIVE=0 RUNNING=0 STOPPING=0 REASONS=0,0,0,0,0,0,0\r\n";
    reset_fixture(2U);
    guard_release_calls = 0U;
    guard_complete_calls = 0U;
    guard_output_used = 0U;
    memset(guard_output, 0, sizeof(guard_output));
    assert(init_integrated_sae_guard());

    f.block_profile_start = true;
    async_result_t started = {.command_result = -1};
    async_result_t stopped = {.command_result = -1};
    pthread_t starter, stopper;
    assert(pthread_create(&starter, NULL, sae_guard_start_thread,
                          &started) == 0);
    wait_flag(&f.profile_start_entered);
    assert(f.runtime_status.running && guard_release_calls == 0U);

    assert(pthread_create(&stopper, NULL, sae_guard_stop_thread,
                          &stopped) == 0);
    wait_profile_gate_attempts(2U);
    assert(guard_release_calls == 0U && f.profile_stop_calls == 0U);
    release_gate(&f.release_profile_start);

    assert(pthread_join(starter, NULL) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(started.command_result == 1 && stopped.command_result == 0);
    assert(f.profile_start_calls == 1U && f.profile_stop_calls == 1U);
    assert(!f.runtime_status.running && !f.runtime_status.stopping);
    assert(guard_release_calls == 1U && guard_complete_calls == 1U);
    assert(!sae_guard_busy() && !wifi_shield_busy());
    assert(strstr(guard_output, " ARMED ") == NULL);
    assert(strstr(guard_output, "OUTCOME=timeout") == NULL);
    assert(guard_output_used == sizeof(expected) - 1U);
    assert(memcmp(guard_output, expected, sizeof(expected)) == 0);
}

int main(void)
{
    scenario_incomplete_hooks_and_header_contract();
    scenario_parse_failure_before_mutation();
    scenario_bare_scan_single_channel_and_stop_order();
    scenario_start_publishes_selected_target_identity();
    scenario_start_escapes_target_ssids_and_lists_each_target();
    scenario_only_snapshot_and_multi_channel();
    scenario_duplicate_and_invalid_indices();
    scenario_no_memory();
    scenario_reserve_failure_retries_retained_abort();
    scenario_partial_snapshot_failure_wipes_before_release();
    scenario_protect_all_prestart_failure_keeps_requested_mode();
    scenario_prestart_cleanup_blocks_reentrant_terminal();
    scenario_absent_trust_disables_comparison();
    scenario_connected_busy_worker();
    scenario_uncertain_adopted_start_uses_full_retry_cleanup();
    scenario_tune_failure();
    scenario_prestart_journal_join_retry_is_bounded();
    scenario_prepare_abort_quarantines_and_retries();
    scenario_duplicate_start_and_read_only_status();
    scenario_armed_output_failure_cleans();
    scenario_quarantine_retries_without_success();
    scenario_output_publisher_quarantine();
    scenario_async_output_failure_is_terminal_not_quarantine();
    scenario_start_final_commit_linearizes_stop();
    scenario_concurrent_output_failure_precedes_stop_terminal();
    scenario_output_enter_timeout_blocks_success_terminal();
    scenario_finish_cleanup_retry_only();
    scenario_uncertain_checkpoint_timeout_retries_before_radio();
    scenario_uncertain_queue_full_drains_retries_then_recovers();
    scenario_initial_uncertainty_callback_keeps_stop_exclusive();
    scenario_quarantined_uncertainty_retry_is_exclusive();
    scenario_terminal_blocks_reentrant_start();
    scenario_late_generation_is_inert();
    scenario_idempotent_stop();
    scenario_wps_profile_initial_tune_hop_retry_and_silence();
    scenario_wps_profile_start_failure_and_retained_cleanup();
    scenario_wps_profile_stop_fence_and_no_late_retune();
    scenario_wps_profile_controller_ownership_boundaries();
    scenario_wps_profile_preparing_stop_resolution();
    scenario_cross_module_preparing_reservation_has_no_aba();
    scenario_trust_cross_module_lifecycle_has_no_aba();
    scenario_sae_profile_reuses_scheduler_and_stays_silent();
    scenario_trust_profile_bare_and_selected_scheduler();
    scenario_trust_profile_lifecycle_and_retained_cleanup();
    scenario_deauth_profile_explicit_channel_plan();
    scenario_deauth_profile_same_and_cross_module_aba();
    scenario_deauth_bare_scan_reservation_is_adopted();
    scenario_sae_profile_lifecycle_gate_and_retained_cleanup();
    scenario_wps_channel_four_filtering_and_silence();
    scenario_trust_readonly_baseline_aggregates_drift();
    scenario_sae_selected_filter_protected_and_truncated();
    scenario_compact_mixed_deauth_csa_and_pmkid();
    scenario_compact_validates_raw_identity_before_module_state();
    scenario_defence_passive_and_active_exact_bridge();
    scenario_defence_preadmission_is_passive();
    scenario_defence_allowlist_and_pmkid_opt_in();
    scenario_defence_multi_vector_reaches_runtime();
    scenario_pmkid_grace_suppresses_completed_association();
    scenario_protect_all_runs_autonomous_combined_policy();
    scenario_v2_campaign_time_report_and_degraded_notice();
    scenario_v2_suppressed_evidence_still_updates_campaign_and_health();
    scenario_v2_deauth_journal_aggregates_without_losing_counts();
    scenario_v2_rejected_aggregate_does_not_merge_next_window();
    scenario_v2_quality_losses_and_sampled_coverage_survive_stop();
    scenario_v2_worker_expires_idle_campaign();
    scenario_v2_retained_report_preserves_highest_session_peak();
    scenario_v2_selected_tsf_anchor_survives_neighbor_flood();
    scenario_v2_advertised_posture_without_trust_baseline();
    scenario_v2_recommendation_same_mask_confidence_revision();
    scenario_v2_incomplete_recommendation_set_is_retried();
    scenario_v2_unavailable_storage_is_fail_open();
    scenario_v2_writer_join_retry_is_radio_inert();
    scenario_storage_pending_finalizer_reentrancy_is_exclusive();
    scenario_storage_pending_finalizer_concurrency_is_exclusive();
    scenario_terminal_queue_full_drains_and_retries();
    scenario_terminal_queue_full_timeout_retains_storage();
    scenario_terminal_queue_full_before_writer_status_drains_first();
    scenario_failed_start_terminal_pressure_retains_storage();
    scenario_terminal_output_failure_updates_retained_campaign();
    scenario_defence_disassoc_uses_pair_builder_and_csa_is_observe_only();
    scenario_defence_failures_and_rejected_hint();
    scenario_defence_stop_join_retry_and_single_finish();
    scenario_scheduler_hop_lock_release_and_drop_merge();
    scenario_stop_merges_final_runtime_drops();
    scenario_radio_fence_serializes_retune_lock_and_stop();
    scenario_state_lifetime_fences_start_status_and_release();
    scenario_late_channel_lock_release_revalidate_after_stop();
    scenario_terminal_writer_waits_for_status_reader();
    scenario_terminal_publisher_uses_local_snapshot();
    scenario_presentation_mapping_and_bounded_oled();
    scenario_first_event_after_armed_accept_is_not_suppressed();
    scenario_presentation_acceptance_lifecycle_and_reset();
    scenario_presentation_snapshot_is_mutexed_and_owned();
    scenario_guard_stop_waits_for_profile_start_cleanup();
    scenario_sae_guard_stop_waits_for_profile_start_cleanup();
    assert(heap_calls == 0U);
    assert(tx_calls == 0U);
    puts("wifi shield lifecycle: PASS (91 scenarios; heap=0; tx=0; poison=clean)");
    return 0;
}
