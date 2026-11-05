#define _POSIX_C_SOURCE 200809L

#include "wifi_trust.h"
#include "wifi_shield.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEM_FILE_CAP WIFI_TRUST_FILE_MAX

typedef struct {
    bool exists;
    size_t length;
    uint8_t bytes[MEM_FILE_CAP];
} mem_file_t;

typedef struct {
    mem_file_t *file;
    size_t offset;
} mem_handle_t;

static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t runtime_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t output_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t store_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t store_gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t store_gate_condition = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t start_gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t start_gate_condition = PTHREAD_COND_INITIALIZER;
static wifi_security_runtime_t shared_runtime;
static wifi_security_session_config_t active_config;
static bool runtime_borrowed, runtime_wiped;
static uint32_t runtime_generation;
static unsigned start_calls, start_effects, stop_calls, snapshot_calls;
static const wifi_shield_target_t *start_targets;
static size_t start_target_count;
static unsigned deadline_arm_calls, deadline_cancel_calls;
static wifi_security_session_result_t start_result;
static bool wipe_before_start_failure;
static bool stop_fail_before_wipe, stop_fail_after_wipe_once;
static bool reenter_stop, reentrant_stop_result;
static bool arm_fail, stop_during_arm, stop_during_arm_result;
static bool change_channel_on_start;
static uint8_t current_channel_value;
static unsigned current_channel_calls;
static bool block_runtime_start_entry, runtime_start_entry_entered;
static bool release_runtime_start_entry, runtime_start_saw_released_arena;
static bool block_runtime_start_after_wipe, runtime_start_after_wipe_entered;
static bool release_runtime_start_after_wipe;
static wifi_trust_deadline_fn deadline_callback;
static void *deadline_context;
static uint64_t deadline_epoch;
static uint32_t deadline_seconds;

static wifi_shield_target_t scan_entries[WIFI_TRUST_MAX_PROFILES];
static size_t scan_count;
static bool scan_fail;

static void *arena_pointer;
static size_t arena_size;
static unsigned arena_acquires, arena_releases;
static bool arena_release_was_zero, arena_zero_seen_before_hooks;
static bool arena_fail;

static mem_file_t target_file, stage_file, backup_file;
static unsigned store_enter_calls;
static bool store_enter_fail, store_sync_fail;
static bool block_store_enter, release_store_enter;
static unsigned store_enter_waiters, store_publish_calls;
static fs_recovery_result_t forced_recovery;
static fs_publish_result_t forced_publish;

static char output[131072];
static size_t output_used;
static bool output_enter_fail, output_write_fail, output_idle_value;
static unsigned output_complete_calls;

static const uint8_t ap1[6] = {0x02, 1, 2, 3, 4, 5};
static const uint8_t ap2[6] = {0x06, 6, 7, 8, 9, 10};

static void state_enter(void *context)
{
    (void)context;
    assert(pthread_mutex_lock(&state_mutex) == 0);
}

static void state_leave(void *context)
{
    (void)context;
    assert(pthread_mutex_unlock(&state_mutex) == 0);
}

static void shared_enter(void *context)
{
    (void)context;
    assert(pthread_mutex_lock(&runtime_mutex) == 0);
}

static void shared_leave(void *context)
{
    (void)context;
    assert(pthread_mutex_unlock(&runtime_mutex) == 0);
}

static bool bytes_zero(const void *memory, size_t length)
{
    const uint8_t *bytes = memory;
    for (size_t i = 0; i < length; ++i)
        if (bytes[i] != 0U) return false;
    return true;
}

static bool current_channel(void *context, uint8_t *channel)
{
    (void)context;
    ++current_channel_calls;
    if (arena_pointer != NULL && arena_size != 0U && snapshot_calls == 0U)
        arena_zero_seen_before_hooks = bytes_zero(arena_pointer, arena_size);
    if (channel == NULL || current_channel_value == 0U ||
        current_channel_value > 233U) return false;
    *channel = current_channel_value;
    return true;
}

static bool scan_snapshot(void *context, wifi_shield_target_t *entries,
                          size_t capacity, size_t *count)
{
    (void)context;
    ++snapshot_calls;
    if (scan_fail || entries == NULL || count == NULL || scan_count > capacity)
        return false;
    memcpy(entries, scan_entries, scan_count * sizeof(*entries));
    *count = scan_count;
    return true;
}

static uint64_t monotonic_us(void *context)
{
    (void)context;
    static uint64_t now = 1000U;
    return ++now;
}

static void status_snapshot(void *context,
                            wifi_security_runtime_status_t *status)
{
    (void)context;
    wifi_security_runtime_get_status(&shared_runtime, status);
}

static wifi_security_session_result_t runtime_start(
    void *context, const wifi_shield_target_t *targets, size_t target_count,
    const wifi_security_session_config_t *config)
{
    (void)context;
    ++start_calls;
    assert(pthread_mutex_lock(&start_gate_mutex) == 0);
    if (block_runtime_start_entry) {
        runtime_start_entry_entered = true;
        assert(pthread_cond_broadcast(&start_gate_condition) == 0);
        while (!release_runtime_start_entry)
            assert(pthread_cond_wait(&start_gate_condition,
                                     &start_gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&start_gate_mutex) == 0);
    if (arena_pointer == NULL) {
        runtime_start_saw_released_arena = true;
        return WIFI_SECURITY_SESSION_INVALID;
    }
    if (config == NULL) return WIFI_SECURITY_SESSION_INVALID;
    start_targets = targets;
    start_target_count = target_count;
    active_config = *config;
    if (targets != NULL && target_count != 0U)
        current_channel_value = targets[0].channel;
    if (change_channel_on_start) ++current_channel_value;
    if (!config->validate(config->context))
        return WIFI_SECURITY_SESSION_INVALID;
    ++start_effects;
    if (start_result != WIFI_SECURITY_SESSION_OK) {
        if (wipe_before_start_failure && config->wipe != NULL)
            config->wipe(config->context);
        assert(pthread_mutex_lock(&start_gate_mutex) == 0);
        if (block_runtime_start_after_wipe) {
            runtime_start_after_wipe_entered = true;
            assert(pthread_cond_broadcast(&start_gate_condition) == 0);
            while (!release_runtime_start_after_wipe)
                assert(pthread_cond_wait(&start_gate_condition,
                                         &start_gate_mutex) == 0);
        }
        assert(pthread_mutex_unlock(&start_gate_mutex) == 0);
        return start_result;
    }
    wifi_security_runtime_config_t runtime_config = {
        .module = config->module,
        .generation = ++runtime_generation,
        .context = config->context,
        .consume = config->consume,
    };
    if (!wifi_security_runtime_start(&shared_runtime, &runtime_config))
        return WIFI_SECURITY_SESSION_BUSY;
    runtime_borrowed = true;
    runtime_wiped = false;
    return WIFI_SECURITY_SESSION_OK;
}

static bool finish_runtime(bool wipe)
{
    if (runtime_borrowed) {
        wifi_security_runtime_close_callbacks(&shared_runtime);
        wifi_security_runtime_request_stop(&shared_runtime);
        (void)wifi_security_runtime_drain(&shared_runtime);
        assert(wifi_security_runtime_finish(&shared_runtime));
        runtime_borrowed = false;
    }
    if (wipe && !runtime_wiped && active_config.wipe != NULL) {
        active_config.wipe(active_config.context);
        runtime_wiped = true;
    }
    return true;
}

static bool runtime_stop(void *context, uint32_t timeout_ms)
{
    (void)context;
    assert(timeout_ms != 0U);
    ++stop_calls;
    if (reenter_stop && stop_calls == 1U)
        reentrant_stop_result = wifi_trust_stop(timeout_ms);
    if (stop_fail_before_wipe) return false;
    (void)finish_runtime(true);
    if (stop_fail_after_wipe_once) {
        stop_fail_after_wipe_once = false;
        return false;
    }
    return true;
}

static bool deadline_arm(void *context, uint64_t epoch, uint32_t seconds,
                         wifi_trust_deadline_fn callback,
                         void *callback_context)
{
    (void)context;
    ++deadline_arm_calls;
    if (arm_fail) return false;
    deadline_epoch = epoch;
    deadline_seconds = seconds;
    deadline_callback = callback;
    deadline_context = callback_context;
    if (stop_during_arm)
        stop_during_arm_result = wifi_trust_stop(5000U);
    return true;
}

static void deadline_cancel(void *context, uint64_t epoch)
{
    (void)context;
    assert(epoch != 0U);
    ++deadline_cancel_calls;
}

static bool arena_acquire(void *context, size_t size, void **arena)
{
    (void)context;
    ++arena_acquires;
    if (arena_fail || arena == NULL || size == 0U || size > WIFI_TRUST_ARENA_MAX_BYTES)
        return false;
    void *memory = malloc(size);
    assert(memory != NULL);
    memset(memory, 0xA5, size);
    arena_pointer = memory;
    arena_size = size;
    *arena = memory;
    return true;
}

static void arena_release(void *context, void *arena, size_t size)
{
    (void)context;
    assert(arena == arena_pointer);
    assert(size == arena_size);
    arena_release_was_zero = bytes_zero(arena, size);
    ++arena_releases;
    free(arena);
    arena_pointer = NULL;
    arena_size = 0U;
}

static bool meta_snapshot(void *context, wifi_trust_store_meta_t *meta)
{
    (void)context;
    if (meta == NULL) return false;
    *meta = (wifi_trust_store_meta_t){
        .boot_id = {1, 2, 3, 4, 5, 6, 7, 8},
        .created_monotonic_us = 777U,
    };
    return true;
}

static mem_file_t *file_for_path(const char *path)
{
    if (strcmp(path, WIFI_TRUST_STORE_PATH) == 0) return &target_file;
    if (strcmp(path, WIFI_TRUST_STAGE_PATH) == 0) return &stage_file;
    if (strcmp(path, WIFI_TRUST_BACKUP_PATH) == 0) return &backup_file;
    return NULL;
}

static bool store_enter(void *context)
{
    (void)context;
    ++store_enter_calls;
    if (store_enter_fail) return false;
    assert(pthread_mutex_lock(&store_gate_mutex) == 0);
    if (block_store_enter) {
        ++store_enter_waiters;
        assert(pthread_cond_broadcast(&store_gate_condition) == 0);
        while (!release_store_enter)
            assert(pthread_cond_wait(&store_gate_condition,
                                     &store_gate_mutex) == 0);
    }
    assert(pthread_mutex_unlock(&store_gate_mutex) == 0);
    return pthread_mutex_lock(&store_mutex) == 0;
}

static void store_leave(void *context)
{
    (void)context;
    assert(pthread_mutex_unlock(&store_mutex) == 0);
}

static wifi_trust_io_result_t store_open(void *context, const char *path,
                                         bool truncate, void **handle)
{
    (void)context;
    mem_file_t *file = file_for_path(path);
    if (file == NULL || handle == NULL) return WIFI_TRUST_IO_ERROR;
    if (!truncate && !file->exists) return WIFI_TRUST_IO_MISSING;
    mem_handle_t *opened = malloc(sizeof(*opened));
    if (opened == NULL) return WIFI_TRUST_IO_ERROR;
    if (truncate) {
        file->exists = true;
        file->length = 0U;
        memset(file->bytes, 0, sizeof(file->bytes));
    }
    opened->file = file;
    opened->offset = 0U;
    *handle = opened;
    return WIFI_TRUST_IO_OK;
}

static wifi_trust_io_result_t store_read(void *opaque, uint8_t *out,
                                         size_t capacity, size_t *actual)
{
    mem_handle_t *handle = opaque;
    if (handle == NULL || out == NULL || actual == NULL)
        return WIFI_TRUST_IO_ERROR;
    size_t remaining = handle->file->length - handle->offset;
    size_t copied = remaining < capacity ? remaining : capacity;
    if (copied != 0U)
        memcpy(out, handle->file->bytes + handle->offset, copied);
    handle->offset += copied;
    *actual = copied;
    return copied == 0U ? WIFI_TRUST_IO_EOF : WIFI_TRUST_IO_OK;
}

static wifi_trust_io_result_t store_write(void *opaque, const uint8_t *data,
                                          size_t length, size_t *actual)
{
    mem_handle_t *handle = opaque;
    if (handle == NULL || (length != 0U && data == NULL) || actual == NULL ||
        length > MEM_FILE_CAP - handle->offset)
        return WIFI_TRUST_IO_ERROR;
    memcpy(handle->file->bytes + handle->offset, data, length);
    handle->offset += length;
    if (handle->offset > handle->file->length)
        handle->file->length = handle->offset;
    *actual = length;
    return WIFI_TRUST_IO_OK;
}

static wifi_trust_io_result_t store_ok_handle(void *handle)
{
    return handle == NULL ? WIFI_TRUST_IO_ERROR : WIFI_TRUST_IO_OK;
}

static wifi_trust_io_result_t store_close(void *opaque)
{
    if (opaque == NULL) return WIFI_TRUST_IO_ERROR;
    free(opaque);
    return WIFI_TRUST_IO_OK;
}

static wifi_trust_path_state_t store_path_state(void *context,
                                                const char *path)
{
    (void)context;
    mem_file_t *file = file_for_path(path);
    if (file == NULL) return WIFI_TRUST_PATH_ERROR;
    return file->exists ? WIFI_TRUST_PATH_FILE : WIFI_TRUST_PATH_MISSING;
}

static bool store_rename(void *context, const char *from, const char *to)
{
    (void)context;
    mem_file_t *source = file_for_path(from), *destination = file_for_path(to);
    if (source == NULL || destination == NULL || !source->exists || destination->exists)
        return false;
    *destination = *source;
    memset(source, 0, sizeof(*source));
    return true;
}

static bool store_remove(void *context, const char *path)
{
    (void)context;
    mem_file_t *file = file_for_path(path);
    if (file == NULL) return false;
    memset(file, 0, sizeof(*file));
    return true;
}

static bool store_sync_volume(void *context)
{
    (void)context;
    return !store_sync_fail;
}

static fs_publish_result_t store_publish(
    void *context, const char *stage, const char *target,
    const char *backup, bool replace)
{
    (void)context;
    (void)replace;
    ++store_publish_calls;
    if (forced_publish != FS_PUBLISH_OK) return forced_publish;
    mem_file_t *source = file_for_path(stage), *destination = file_for_path(target);
    mem_file_t *old = file_for_path(backup);
    if (source == NULL || destination == NULL || old == NULL || !source->exists)
        return FS_PUBLISH_IO_ERROR;
    memset(old, 0, sizeof(*old));
    if (destination->exists) *old = *destination;
    *destination = *source;
    memset(source, 0, sizeof(*source));
    memset(old, 0, sizeof(*old));
    return FS_PUBLISH_OK;
}

static fs_recovery_result_t store_recover(
    void *context, const char *stage, const char *target, const char *backup)
{
    (void)context;
    (void)stage;
    (void)target;
    (void)backup;
    fs_recovery_result_t result = forced_recovery;
    forced_recovery = FS_RECOVERY_NONE;
    return result;
}

static bool output_enter(void *context, uint32_t timeout_ms)
{
    (void)context;
    assert(timeout_ms == WIFI_TRUST_OUTPUT_TIMEOUT_MS);
    if (output_enter_fail) return false;
    return pthread_mutex_lock(&output_mutex) == 0;
}

static void output_leave(void *context)
{
    (void)context;
    assert(pthread_mutex_unlock(&output_mutex) == 0);
}

static bool append_output(const char *line, size_t length)
{
    if (output_write_fail || line == NULL || length == 0U ||
        length > sizeof(output) - output_used - 1U) return false;
    memcpy(output + output_used, line, length);
    output_used += length;
    output[output_used] = '\0';
    return true;
}

static bool output_write(void *context, const char *line, size_t length)
{
    (void)context;
    return append_output(line, length);
}

static bool output_terminal(void *context, const wifi_trust_status_t *status,
                            const char *outcome)
{
    (void)context;
    char line[WIFI_TRUST_LINE_MAX];
    int length = wifi_trust_format_terminal_for_output(
        line, sizeof(line), status, outcome);
    return length > 0 && append_output(line, (size_t)length);
}

static void output_complete(void *context, bool accepted)
{
    (void)context;
    (void)accepted;
    ++output_complete_calls;
}

static bool output_idle(void *context)
{
    (void)context;
    return output_idle_value;
}

static const wifi_trust_runtime_hooks_t runtime_hooks = {
    .enter = state_enter,
    .leave = state_leave,
    .current_channel = current_channel,
    .scan_snapshot = scan_snapshot,
    .monotonic_us = monotonic_us,
    .status_snapshot = status_snapshot,
    .start = runtime_start,
    .stop = runtime_stop,
    .deadline_arm = deadline_arm,
    .deadline_cancel = deadline_cancel,
};

static const wifi_trust_store_ops_t store_ops = {
    .enter = store_enter,
    .leave = store_leave,
    .open = store_open,
    .read = store_read,
    .write = store_write,
    .flush = store_ok_handle,
    .sync = store_ok_handle,
    .close = store_close,
    .path_state = store_path_state,
    .rename_path = store_rename,
    .remove_path = store_remove,
    .sync_volume = store_sync_volume,
    .publish_staged = store_publish,
    .recover_staged = store_recover,
};

static const wifi_trust_storage_hooks_t storage_hooks = {
    .arena_acquire = arena_acquire,
    .arena_release = arena_release,
    .meta_snapshot = meta_snapshot,
    .store = {
        .enter = store_enter,
        .leave = store_leave,
        .open = store_open,
        .read = store_read,
        .write = store_write,
        .flush = store_ok_handle,
        .sync = store_ok_handle,
        .close = store_close,
        .path_state = store_path_state,
        .rename_path = store_rename,
        .remove_path = store_remove,
        .sync_volume = store_sync_volume,
        .publish_staged = store_publish,
        .recover_staged = store_recover,
    },
};

static const wifi_trust_output_hooks_t output_hooks = {
    .enter = output_enter,
    .leave = output_leave,
    .write = output_write,
    .write_terminal = output_terminal,
    .complete = output_complete,
    .idle = output_idle,
};

static void clear_output(void)
{
    memset(output, 0, sizeof(output));
    output_used = 0U;
}

static void reset_fixture(bool clear_files)
{
    if (runtime_borrowed) (void)finish_runtime(true);
    if (wifi_trust_busy()) assert(wifi_trust_stop(5000U));
    const wifi_security_runtime_hooks_t hooks = {
        .enter = shared_enter, .leave = shared_leave, .notify = NULL,
    };
    assert(wifi_security_runtime_init(&shared_runtime, &hooks, 1U));
    memset(&active_config, 0, sizeof(active_config));
    runtime_borrowed = runtime_wiped = false;
    runtime_generation = 0U;
    start_calls = start_effects = stop_calls = snapshot_calls = 0U;
    start_targets = NULL;
    start_target_count = 0U;
    deadline_arm_calls = deadline_cancel_calls = 0U;
    start_result = WIFI_SECURITY_SESSION_OK;
    wipe_before_start_failure = false;
    stop_fail_before_wipe = stop_fail_after_wipe_once = false;
    reenter_stop = reentrant_stop_result = false;
    arm_fail = stop_during_arm = stop_during_arm_result = false;
    change_channel_on_start = false;
    current_channel_value = 6U;
    current_channel_calls = 0U;
    block_runtime_start_entry = runtime_start_entry_entered = false;
    release_runtime_start_entry = runtime_start_saw_released_arena = false;
    block_runtime_start_after_wipe = runtime_start_after_wipe_entered = false;
    release_runtime_start_after_wipe = false;
    deadline_callback = NULL;
    deadline_context = NULL;
    deadline_epoch = 0U;
    deadline_seconds = 0U;
    memset(scan_entries, 0, sizeof(scan_entries));
    scan_count = 0U;
    scan_fail = false;
    assert(arena_pointer == NULL);
    arena_acquires = arena_releases = 0U;
    arena_release_was_zero = arena_zero_seen_before_hooks = false;
    arena_fail = false;
    store_enter_calls = 0U;
    store_enter_fail = store_sync_fail = false;
    block_store_enter = release_store_enter = false;
    store_enter_waiters = store_publish_calls = 0U;
    forced_recovery = FS_RECOVERY_NONE;
    forced_publish = FS_PUBLISH_OK;
    output_enter_fail = output_write_fail = false;
    output_idle_value = true;
    output_complete_calls = 0U;
    clear_output();
    if (clear_files) {
        memset(&target_file, 0, sizeof(target_file));
        memset(&stage_file, 0, sizeof(stage_file));
        memset(&backup_file, 0, sizeof(backup_file));
    }
    assert(wifi_trust_init(&runtime_hooks, &storage_hooks, &output_hooks));
}

static int command(size_t argc, const char *const *argv)
{
    return wifi_trust_command((int)argc, (char **)argv);
}

static size_t make_beacon(uint8_t *frame, size_t capacity,
                          const uint8_t bssid[6], const char *ssid)
{
    size_t ssid_length = strlen(ssid);
    assert(ssid_length <= 32U && capacity >= 38U + ssid_length);
    memset(frame, 0, capacity);
    frame[0] = 0x80;
    memset(frame + 4, 0xff, 6U);
    memcpy(frame + 10, bssid, 6U);
    memcpy(frame + 16, bssid, 6U);
    frame[36] = 0U;
    frame[37] = (uint8_t)ssid_length;
    memcpy(frame + 38, ssid, ssid_length);
    return 38U + ssid_length;
}

static bool submit_beacon(const uint8_t bssid[6], const char *ssid,
                          uint8_t channel, bool drain)
{
    uint8_t frame[96];
    size_t length = make_beacon(frame, sizeof(frame), bssid, ssid);
    bool queued = wifi_security_runtime_submit(
        &shared_runtime, runtime_generation, frame, (uint16_t)length,
        monotonic_us(NULL), -40, channel);
    if (drain) (void)wifi_security_runtime_drain(&shared_runtime);
    return queued;
}

static wifi_trust_profile_t profile_from_beacon(const uint8_t bssid[6],
                                                const char *ssid)
{
    uint8_t frame[96];
    sx_observation_t observation;
    size_t length = make_beacon(frame, sizeof(frame), bssid, ssid);
    assert(sx_parse(frame, length, &observation));
    wifi_trust_profile_t profile;
    assert(wifi_trust_profile_from_observation(
        &observation, current_channel_value, 1234U, &profile));
    return profile;
}

static void seed_baseline(const wifi_trust_profile_t *profiles, size_t count)
{
    wifi_trust_store_meta_t meta;
    assert(meta_snapshot(NULL, &meta));
    assert(wifi_trust_store_publish(profiles, count, &meta, &store_ops) ==
           WIFI_TRUST_STORE_OK);
}

static size_t load_baseline(wifi_trust_profile_t *profiles, size_t capacity)
{
    size_t count = 0U;
    wifi_trust_store_meta_t meta;
    wifi_trust_recovery_action_t recovery;
    assert(wifi_trust_store_load(WIFI_TRUST_STORE_PATH, profiles, capacity,
                                 &count, &meta, &recovery, &store_ops) ==
           WIFI_TRUST_STORE_OK);
    return count;
}

static void fire_deadline(void)
{
    assert(deadline_callback != NULL && deadline_epoch != 0U);
    deadline_callback(deadline_context, deadline_epoch);
}

static size_t count_text(const char *haystack, const char *needle)
{
    size_t count = 0U, length = strlen(needle);
    for (const char *at = haystack; (at = strstr(at, needle)) != NULL;
         at += length) ++count;
    return count;
}

static void assert_exact_output(const char *expected)
{
    assert(expected != NULL);
    assert(output_used == strlen(expected));
    assert(memcmp(output, expected, output_used + 1U) == 0);
}

static void assert_exact_terminal_precedence_case(
    const wifi_trust_status_t *status, const char *requested,
    const char *published, const char *store)
{
    char actual[WIFI_TRUST_LINE_MAX];
    char expected[WIFI_TRUST_LINE_MAX];
    int actual_length = wifi_trust_format_terminal_for_output(
        actual, sizeof(actual), status, requested);
    int expected_length = snprintf(
        expected, sizeof(expected),
        "[WIFI_TRUST/1] TERMINAL OUTCOME=%s MODE=capture"
        " SCOPE=current_channel CHANNEL=6 BASELINE_LOADED=0 BASELINE_COUNT=0"
        " BOOT=unknown CREATED_UNIX=unknown STORE=%s RECOVERY=none RECEIVED=0"
        " FILTERED=0 UNRELATED=0 ACCEPTED=0 INVALID=0 PROFILES=0 CONFLICTS=0"
        " EVENTS_INFO=0 EVENTS_WARN=0 EVENTS_ALERT=0 CAPACITY_DROPS=0"
        " RX_DROPS=%u OUTPUT_FAILURES=%u STORAGE_FAILURES=0"
        " RUNNING=0 STOPPING=0\r\n",
        published, store, (unsigned)status->rx_drops,
        (unsigned)status->output_failures);
    assert(actual_length == expected_length && actual_length > 0);
    assert(memcmp(actual, expected, (size_t)actual_length + 1U) == 0);
}

static void test_exact_terminal_precedence_buffers(void)
{
    reset_fixture(true);
    wifi_trust_status_t status = {
        .mode = WIFI_TRUST_MODE_CAPTURE,
        .channel = 6U,
        .store = WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN,
        .recovery = WIFI_TRUST_RECOVERY_NONE,
        .rx_drops = 1U,
        .output_failures = 1U,
    };
    assert_exact_terminal_precedence_case(
        &status, "restore_failed", "output_failed", "published_uncertain");
    status.output_failures = 0U;
    assert_exact_terminal_precedence_case(
        &status, "restore_failed", "restore_failed", "published_uncertain");
    assert_exact_terminal_precedence_case(
        &status, "timeout", "timeout", "published_uncertain");
    assert_exact_terminal_precedence_case(
        &status, "stopped", "storage_uncertain", "published_uncertain");
    status.store = WIFI_TRUST_STORE_NOT_FOUND;
    assert_exact_terminal_precedence_case(
        &status, "stopped", "storage_failed", "not_found");
    status.store = WIFI_TRUST_STORE_OK;
    assert_exact_terminal_precedence_case(
        &status, "stopped", "queue_overflow", "ok");
    status.rx_drops = 0U;
    assert_exact_terminal_precedence_case(
        &status, "stopped", "stopped", "ok");
    assert_exact_terminal_precedence_case(&status, "ok", "ok", "ok");
}

static void test_exact_legacy_status_start_stop_buffers(void)
{
    static const char idle_status[] =
        "[WIFI_TRUST/1] STATUS MODE=idle SCOPE=current_channel CHANNEL=unknown"
        " BASELINE_LOADED=0 BASELINE_COUNT=0 BOOT=unknown CREATED_UNIX=unknown"
        " STORE=ok RECOVERY=none RECEIVED=0 FILTERED=0 UNRELATED=0 ACCEPTED=0"
        " INVALID=0 PROFILES=0 CONFLICTS=0 EVENTS_INFO=0 EVENTS_WARN=0"
        " EVENTS_ALERT=0 CAPACITY_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0"
        " STORAGE_FAILURES=0 RUNNING=0 STOPPING=0\r\n";
    static const char running_status[] =
        "[WIFI_TRUST/1] STATUS MODE=capture SCOPE=current_channel CHANNEL=6"
        " BASELINE_LOADED=0 BASELINE_COUNT=0 BOOT=unknown CREATED_UNIX=unknown"
        " STORE=ok RECOVERY=none RECEIVED=0 FILTERED=0 UNRELATED=0 ACCEPTED=0"
        " INVALID=0 PROFILES=0 CONFLICTS=0 EVENTS_INFO=0 EVENTS_WARN=0"
        " EVENTS_ALERT=0 CAPACITY_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0"
        " STORAGE_FAILURES=0 RUNNING=1 STOPPING=0\r\n";
    static const char stopped_terminal[] =
        "[WIFI_TRUST/1] TERMINAL OUTCOME=stopped MODE=capture"
        " SCOPE=current_channel CHANNEL=6 BASELINE_LOADED=0 BASELINE_COUNT=0"
        " BOOT=unknown CREATED_UNIX=unknown STORE=ok RECOVERY=none RECEIVED=0"
        " FILTERED=0 UNRELATED=0 ACCEPTED=0 INVALID=0 PROFILES=0 CONFLICTS=0"
        " EVENTS_INFO=0 EVENTS_WARN=0 EVENTS_ALERT=0 CAPACITY_DROPS=0"
        " RX_DROPS=0 OUTPUT_FAILURES=0 STORAGE_FAILURES=0 RUNNING=0 STOPPING=1\r\n";

    reset_fixture(true);
    const char *status[] = {"wifi_trust", "status"};
    assert(command(2U, status) == 0);
    assert_exact_output(idle_status);

    clear_output();
    const char *capture[] = {"wifi_trust", "baseline", "capture"};
    assert(command(3U, capture) == 0);
    assert_exact_output("");

    assert(command(2U, status) == 0);
    assert_exact_output(running_status);

    clear_output();
    assert(wifi_trust_stop(5000U));
    assert_exact_output(stopped_terminal);
}

static void test_exact_cli_and_allocation_failure(void)
{
    reset_fixture(true);
    wifi_trust_storage_hooks_t bad_storage = storage_hooks;
    bad_storage.store.sync_volume = NULL;
    assert(!wifi_trust_init(&runtime_hooks, &bad_storage, &output_hooks));
    static const char *const invalid[][8] = {
        {"wifi_trust"},
        {"wifi_trust", "baseline"},
        {"wifi_trust", "baseline", "capture", "--seconds"},
        {"wifi_trust", "baseline", "capture", "--seconds", "4"},
        {"wifi_trust", "baseline", "capture", "--seconds", "121"},
        {"wifi_trust", "baseline", "capture", "--only"},
        {"wifi_trust", "baseline", "capture", "--only", "1", "--seconds", "5"},
        {"wifi_trust", "monitor", "--seconds", "5"},
        {"wifi_trust", "monitor", "--only"},
        {"wifi_trust", "status", "extra"},
        {"wifi_trust", "stop", "extra"},
    };
    static const size_t lengths[] = {1, 2, 4, 5, 5, 4, 7, 4, 3, 3, 3};
    for (size_t i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i)
        assert(command(lengths[i], invalid[i]) == 1);

    arena_fail = true;
    const char *capture[] = {"wifi_trust", "baseline", "capture"};
    assert(command(3U, capture) == 1);
    assert(arena_acquires == 1U);
    assert(snapshot_calls == 0U && start_calls == 0U && store_enter_calls == 0U);
}

static void test_capture_natural_and_cancel(void)
{
    reset_fixture(true);
    const char *capture[] = {"wifi_trust", "baseline", "capture"};
    assert(command(3U, capture) == 0);
    assert(snapshot_calls == 0U);
    assert(start_targets == NULL && start_target_count == 0U);
    assert(deadline_arm_calls == 1U && deadline_seconds == 15U);
    assert(arena_zero_seen_before_hooks);
    assert(submit_beacon(ap1, "known", 6U, true));
    fire_deadline();
    assert(!wifi_trust_busy());
    wifi_trust_profile_t loaded[WIFI_TRUST_MAX_PROFILES];
    assert(load_baseline(loaded, WIFI_TRUST_MAX_PROFILES) == 1U);
    assert(memcmp(loaded[0].bssid, ap1, 6U) == 0);
    assert(arena_releases == 1U && arena_release_was_zero);
    assert(deadline_cancel_calls == 0U);
    assert(strstr(output, "OUTCOME=ok") != NULL);

    reset_fixture(false);
    assert(command(3U, capture) == 0);
    assert(submit_beacon(ap2, "replacement", 6U, true));
    assert(wifi_trust_stop(5000U));
    assert(deadline_cancel_calls == 1U);
    assert(load_baseline(loaded, WIFI_TRUST_MAX_PROFILES) == 1U);
    assert(memcmp(loaded[0].bssid, ap1, 6U) == 0);
    assert(strstr(output, "OUTCOME=stopped") != NULL);
}

static void test_selected_validation_and_channel_filter(void)
{
    reset_fixture(true);
    scan_count = 2U;
    memcpy(scan_entries[0].bssid, ap1, 6U);
    scan_entries[0].channel = 6U;
    memcpy(scan_entries[0].ssid, "whole-one", sizeof("whole-one"));
    scan_entries[0].wpa2_psk_ccmp = true;
    memcpy(scan_entries[1].bssid, ap2, 6U);
    scan_entries[1].channel = 11U;
    memcpy(scan_entries[1].ssid, "whole-two", sizeof("whole-two"));
    const char *selected[] = {
        "wifi_trust", "baseline", "capture", "--seconds", "5",
        "--only", "1"
    };
    assert(command(7U, selected) == 0);
    assert(snapshot_calls == 1U && deadline_seconds == 5U);
    assert(start_targets != NULL && start_target_count == 1U);
    assert(memcmp(start_targets[0].bssid, ap1, 6U) == 0 &&
           start_targets[0].channel == 6U &&
           strcmp(start_targets[0].ssid, "whole-one") == 0 &&
           start_targets[0].wpa2_psk_ccmp);
    assert(submit_beacon(ap2, "wrong", 6U, true));
    assert(submit_beacon(ap1, "wrong-channel", 11U, true));
    assert(submit_beacon(ap1, "right", 6U, true));
    wifi_security_session_config_t expired = active_config;
    fire_deadline();
    wifi_trust_profile_t loaded[WIFI_TRUST_MAX_PROFILES];
    assert(load_baseline(loaded, WIFI_TRUST_MAX_PROFILES) == 1U);
    assert(loaded[0].ssid_len == 5U && memcmp(loaded[0].ssid, "right", 5U) == 0);
    wifi_security_frame_slot_t stale_slot = {.channel = 6U};
    wifi_security_decoded_t stale_decoded = {0};
    unsigned calls_before_stale = current_channel_calls;
    assert(expired.consume(expired.context, &stale_slot, &stale_decoded));
    assert(current_channel_calls == calls_before_stale);

    reset_fixture(true);
    scan_count = 1U;
    memcpy(scan_entries[0].bssid, ap1, 6U);
    scan_entries[0].channel = 11U;
    assert(command(7U, selected) == 0);
    assert(start_calls == 1U && start_effects == 1U);
    assert(start_target_count == 1U && start_targets[0].channel == 11U);
    assert(current_channel_value == 11U);
    assert(wifi_trust_stop(5000U));

    reset_fixture(true);
    scan_count = 1U;
    memcpy(scan_entries[0].bssid, ap1, 6U);
    scan_entries[0].channel = 6U;
    change_channel_on_start = true;
    assert(command(7U, selected) == 1);
    assert(start_calls == 1U && start_effects == 0U);

    reset_fixture(true);
    scan_count = 2U;
    memcpy(scan_entries[0].bssid, ap1, 6U);
    scan_entries[0].channel = 6U;
    memcpy(scan_entries[1].bssid, ap2, 6U);
    scan_entries[1].channel = 11U;
    const char *reverse[] = {
        "wifi_trust", "baseline", "capture", "--only", "2", "1"
    };
    assert(command(6U, reverse) == 0);
    assert(start_target_count == 2U);
    assert(memcmp(start_targets[0].bssid, ap1, 6U) == 0 &&
           start_targets[0].channel == 6U);
    assert(memcmp(start_targets[1].bssid, ap2, 6U) == 0 &&
           start_targets[1].channel == 11U);
    assert(submit_beacon(ap1, "one", 6U, true));
    current_channel_value = 11U;
    assert(submit_beacon(ap2, "two", 11U, true));
    clear_output();
    const char *status[] = {"wifi_trust", "status"};
    assert(command(2U, status) == 0);
    assert(strstr(output, " SCOPE=current_channel CHANNEL=11 ") != NULL);
    fire_deadline();
    wifi_trust_profile_t both[WIFI_TRUST_MAX_PROFILES];
    assert(load_baseline(both, WIFI_TRUST_MAX_PROFILES) == 2U);
}

static void test_deadline_fail_stale_and_post_wipe_retry(void)
{
    reset_fixture(true);
    const char *capture[] = {"wifi_trust", "baseline", "capture"};
    arm_fail = true;
    assert(command(3U, capture) == 1);
    assert(start_effects == 1U && stop_calls == 1U);
    assert(!target_file.exists && arena_releases == 1U);

    reset_fixture(true);
    assert(command(3U, capture) == 0);
    wifi_trust_deadline_fn old_callback = deadline_callback;
    void *old_context = deadline_context;
    uint64_t old_epoch = deadline_epoch;
    assert(wifi_trust_stop(5000U));
    assert(command(3U, capture) == 0);
    old_callback(old_context, old_epoch);
    assert(wifi_trust_busy());
    assert(wifi_trust_stop(5000U));

    reset_fixture(true);
    assert(command(3U, capture) == 0);
    assert(submit_beacon(ap1, "retry", 6U, true));
    stop_fail_after_wipe_once = true;
    fire_deadline();
    assert(wifi_trust_busy());
    assert(!target_file.exists && arena_releases == 0U);
    assert(wifi_trust_stop(5000U));
    assert(target_file.exists && arena_releases == 1U);
    assert(count_text(output, "[WIFI_TRUST/1] TERMINAL") == 2U);
}

static void test_uncertain_start_retains_context_for_stop_retry(void)
{
    static const char invalid_after_rollback[] =
        "[WIFI_TRUST/1] TERMINAL OUTCOME=invalid MODE=capture"
        " SCOPE=current_channel CHANNEL=6 BASELINE_LOADED=0 BASELINE_COUNT=0"
        " BOOT=unknown CREATED_UNIX=unknown STORE=ok RECOVERY=none RECEIVED=0"
        " FILTERED=0 UNRELATED=0 ACCEPTED=0 INVALID=0 PROFILES=0 CONFLICTS=0"
        " EVENTS_INFO=0 EVENTS_WARN=0 EVENTS_ALERT=0 CAPACITY_DROPS=0"
        " RX_DROPS=0 OUTPUT_FAILURES=0 STORAGE_FAILURES=0"
        " RUNNING=0 STOPPING=1\r\n";
    reset_fixture(true);
    start_result = WIFI_SECURITY_SESSION_WORKER_FAILED;
    wipe_before_start_failure = true;
    const char *capture[] = {"wifi_trust", "baseline", "capture"};
    assert(command(3U, capture) == 1);
    assert(!wifi_trust_busy() && arena_releases == 1U);
    assert_exact_output(invalid_after_rollback);

    reset_fixture(true);
    start_result = WIFI_SECURITY_SESSION_RESTORE_FAILED;
    assert(command(3U, capture) == 1);
    assert(wifi_trust_busy());
    assert(arena_releases == 0U);
    assert(strstr(output, "OUTCOME=restore_failed") != NULL);
    start_result = WIFI_SECURITY_SESSION_OK;
    assert(wifi_trust_stop(5000U));
    assert(!wifi_trust_busy());
    assert(arena_releases == 1U && arena_release_was_zero);
}

static void test_capture_loss_and_recovered_retry(void)
{
    reset_fixture(true);
    const char *capture[] = {"wifi_trust", "baseline", "capture"};
    assert(command(3U, capture) == 0);
    assert(submit_beacon(ap1, "one", 6U, false));
    assert(!submit_beacon(ap2, "two", 6U, false));
    (void)wifi_security_runtime_drain(&shared_runtime);
    fire_deadline();
    assert(!target_file.exists);
    assert(strstr(output, "OUTCOME=queue_overflow") != NULL);

    reset_fixture(true);
    assert(command(3U, capture) == 0);
    assert(submit_beacon(ap1, "recover", 6U, true));
    forced_recovery = FS_RECOVERY_CLEARED_STAGE;
    fire_deadline();
    assert(wifi_trust_busy());
    assert(arena_releases == 0U);
    assert(wifi_trust_stop(5000U));
    assert(target_file.exists && arena_releases == 1U);
}

static void *deadline_thread(void *context)
{
    (void)context;
    fire_deadline();
    return NULL;
}

static void *stop_thread(void *context)
{
    bool *result = context;
    *result = wifi_trust_stop(5000U);
    return NULL;
}

typedef struct {
    size_t argc;
    const char *const *argv;
    int result;
} command_thread_context_t;

static void *command_thread(void *context)
{
    command_thread_context_t *command_context = context;
    command_context->result = command(command_context->argc,
                                      command_context->argv);
    return NULL;
}

static void wait_runtime_start_entry(void)
{
    assert(pthread_mutex_lock(&start_gate_mutex) == 0);
    while (!runtime_start_entry_entered)
        assert(pthread_cond_wait(&start_gate_condition,
                                 &start_gate_mutex) == 0);
    assert(pthread_mutex_unlock(&start_gate_mutex) == 0);
}

static void release_runtime_start(void)
{
    assert(pthread_mutex_lock(&start_gate_mutex) == 0);
    release_runtime_start_entry = true;
    assert(pthread_cond_broadcast(&start_gate_condition) == 0);
    assert(pthread_mutex_unlock(&start_gate_mutex) == 0);
}

static void wait_runtime_start_after_wipe(void)
{
    assert(pthread_mutex_lock(&start_gate_mutex) == 0);
    while (!runtime_start_after_wipe_entered)
        assert(pthread_cond_wait(&start_gate_condition,
                                 &start_gate_mutex) == 0);
    assert(pthread_mutex_unlock(&start_gate_mutex) == 0);
}

static void release_runtime_start_after_wipe_gate(void)
{
    assert(pthread_mutex_lock(&start_gate_mutex) == 0);
    release_runtime_start_after_wipe = true;
    assert(pthread_cond_broadcast(&start_gate_condition) == 0);
    assert(pthread_mutex_unlock(&start_gate_mutex) == 0);
}

static void test_stop_in_pre_reservation_handoff_retains_arena(void)
{
    static const char expected[] =
        "[WIFI_TRUST/1] TERMINAL OUTCOME=stopped MODE=capture"
        " SCOPE=current_channel CHANNEL=6 BASELINE_LOADED=0 BASELINE_COUNT=0"
        " BOOT=unknown CREATED_UNIX=unknown STORE=ok RECOVERY=none RECEIVED=0"
        " FILTERED=0 UNRELATED=0 ACCEPTED=0 INVALID=0 PROFILES=0 CONFLICTS=0"
        " EVENTS_INFO=0 EVENTS_WARN=0 EVENTS_ALERT=0 CAPACITY_DROPS=0"
        " RX_DROPS=0 OUTPUT_FAILURES=0 STORAGE_FAILURES=0"
        " RUNNING=0 STOPPING=1\r\n";
    reset_fixture(true);
    block_runtime_start_entry = true;
    const char *capture[] = {"wifi_trust", "baseline", "capture"};
    command_thread_context_t start_context = {
        .argc = 3U, .argv = capture, .result = -1,
    };
    pthread_t starter, stopper;
    bool stop_result = false;
    assert(pthread_create(&starter, NULL, command_thread,
                          &start_context) == 0);
    wait_runtime_start_entry();
    assert(pthread_create(&stopper, NULL, stop_thread, &stop_result) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(!stop_result);
    assert(arena_pointer != NULL && arena_releases == 0U);
    assert(count_text(output, "[WIFI_TRUST/1] TERMINAL") == 0U);
    release_runtime_start();
    assert(pthread_join(starter, NULL) == 0);
    assert(start_context.result == 1);
    assert(!runtime_start_saw_released_arena);
    assert(start_effects == 0U && stop_calls == 0U);
    assert(arena_releases == 1U && arena_release_was_zero);
    assert(!wifi_trust_busy());
    assert(count_text(output, "[WIFI_TRUST/1] TERMINAL") == 1U);
    assert_exact_output(expected);
}

static void test_stop_during_start_rollback_wipe_waits_for_caller(void)
{
    static const char expected[] =
        "[WIFI_TRUST/1] TERMINAL OUTCOME=stopped MODE=capture"
        " SCOPE=current_channel CHANNEL=6 BASELINE_LOADED=0 BASELINE_COUNT=0"
        " BOOT=unknown CREATED_UNIX=unknown STORE=ok RECOVERY=none RECEIVED=0"
        " FILTERED=0 UNRELATED=0 ACCEPTED=0 INVALID=0 PROFILES=0 CONFLICTS=0"
        " EVENTS_INFO=0 EVENTS_WARN=0 EVENTS_ALERT=0 CAPACITY_DROPS=0"
        " RX_DROPS=0 OUTPUT_FAILURES=0 STORAGE_FAILURES=0"
        " RUNNING=0 STOPPING=1\r\n";
    reset_fixture(true);
    start_result = WIFI_SECURITY_SESSION_WORKER_FAILED;
    wipe_before_start_failure = true;
    block_runtime_start_after_wipe = true;
    const char *capture[] = {"wifi_trust", "baseline", "capture"};
    command_thread_context_t start_context = {
        .argc = 3U, .argv = capture, .result = -1,
    };
    pthread_t starter, stopper;
    bool stop_result = false;
    assert(pthread_create(&starter, NULL, command_thread,
                          &start_context) == 0);
    wait_runtime_start_after_wipe();
    assert(pthread_create(&stopper, NULL, stop_thread, &stop_result) == 0);
    assert(pthread_join(stopper, NULL) == 0);
    assert(!stop_result);
    assert(stop_calls == 0U && arena_pointer != NULL && arena_releases == 0U);
    assert(count_text(output, "[WIFI_TRUST/1] TERMINAL") == 0U);
    release_runtime_start_after_wipe_gate();
    assert(pthread_join(starter, NULL) == 0);
    assert(start_context.result == 1 && start_effects == 1U);
    assert(stop_calls == 0U && arena_releases == 1U &&
           arena_release_was_zero && !wifi_trust_busy());
    assert(count_text(output, "[WIFI_TRUST/1] TERMINAL") == 1U);
    assert_exact_output(expected);
}

static void test_cleanup_arm_and_sync_command_races(void)
{
    const char *capture[] = {"wifi_trust", "baseline", "capture"};

    reset_fixture(true);
    assert(command(3U, capture) == 0);
    stop_fail_before_wipe = true;
    reenter_stop = true;
    assert(!wifi_trust_stop(5000U));
    assert(reentrant_stop_result);
    assert(stop_calls == 1U);
    assert(count_text(output, "[WIFI_TRUST/1] TERMINAL") == 1U);
    assert(wifi_trust_busy());
    stop_fail_before_wipe = false;
    reenter_stop = false;
    assert(wifi_trust_stop(5000U));
    assert(!wifi_trust_busy());

    reset_fixture(true);
    stop_during_arm = true;
    assert(command(3U, capture) == 1);
    assert(stop_during_arm_result);
    assert(deadline_arm_calls == 1U && deadline_cancel_calls == 1U);
    assert(!wifi_trust_busy() && arena_releases == 1U);

    reset_fixture(true);
    wifi_trust_profile_t profile = profile_from_beacon(ap1, "listed");
    seed_baseline(&profile, 1U);
    block_store_enter = true;
    const char *list[] = {"wifi_trust", "baseline", "list"};
    command_thread_context_t list_context = {
        .argc = 3U, .argv = list, .result = -1,
    };
    pthread_t list_worker;
    assert(pthread_create(&list_worker, NULL, command_thread,
                          &list_context) == 0);
    assert(pthread_mutex_lock(&store_gate_mutex) == 0);
    while (store_enter_waiters < 1U)
        assert(pthread_cond_wait(&store_gate_condition,
                                 &store_gate_mutex) == 0);
    assert(pthread_mutex_unlock(&store_gate_mutex) == 0);
    assert(wifi_trust_stop(5000U));
    assert(pthread_mutex_lock(&store_gate_mutex) == 0);
    release_store_enter = true;
    assert(pthread_cond_broadcast(&store_gate_condition) == 0);
    assert(pthread_mutex_unlock(&store_gate_mutex) == 0);
    assert(pthread_join(list_worker, NULL) == 0);
    assert(list_context.result == 0);
    assert(!wifi_trust_busy());
}

static void test_natural_stop_race_publishes_once(void)
{
    static const char expected[] =
        "[WIFI_TRUST/1] TERMINAL OUTCOME=ok MODE=capture"
        " SCOPE=current_channel CHANNEL=6 BASELINE_LOADED=1 BASELINE_COUNT=1"
        " BOOT=0102030405060708 CREATED_UNIX=unknown STORE=ok RECOVERY=none"
        " RECEIVED=1 FILTERED=0 UNRELATED=0 ACCEPTED=1 INVALID=0 PROFILES=1"
        " CONFLICTS=0 EVENTS_INFO=0 EVENTS_WARN=0 EVENTS_ALERT=0"
        " CAPACITY_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0 STORAGE_FAILURES=0"
        " RUNNING=0 STOPPING=1\r\n";
    reset_fixture(true);
    const char *capture[] = {"wifi_trust", "baseline", "capture"};
    assert(command(3U, capture) == 0);
    assert(submit_beacon(ap1, "race", 6U, true));
    block_store_enter = true;
    pthread_t natural, explicit_stop;
    bool stop_result = false;
    assert(pthread_create(&natural, NULL, deadline_thread, NULL) == 0);
    assert(pthread_mutex_lock(&store_gate_mutex) == 0);
    while (store_enter_waiters < 1U)
        assert(pthread_cond_wait(&store_gate_condition,
                                 &store_gate_mutex) == 0);
    assert(pthread_mutex_unlock(&store_gate_mutex) == 0);
    assert(stop_calls == 1U && runtime_wiped && store_publish_calls == 0U);
    assert(!target_file.exists);
    assert(pthread_create(&explicit_stop, NULL, stop_thread, &stop_result) == 0);
    assert(pthread_join(explicit_stop, NULL) == 0);
    assert(stop_result);
    assert(pthread_mutex_lock(&store_gate_mutex) == 0);
    assert(store_enter_waiters == 1U);
    release_store_enter = true;
    assert(pthread_cond_broadcast(&store_gate_condition) == 0);
    assert(pthread_mutex_unlock(&store_gate_mutex) == 0);
    assert(pthread_join(natural, NULL) == 0);
    assert(store_publish_calls == 1U);
    assert(arena_releases == 1U && arena_release_was_zero);
    assert(count_text(output, "[WIFI_TRUST/1] TERMINAL") == 1U);
    assert_exact_output(expected);
}

static void test_monitor_load_before_lease_and_deduplication(void)
{
    reset_fixture(true);
    const char *monitor[] = {"wifi_trust", "monitor"};
    assert(command(2U, monitor) == 1);
    assert(store_enter_calls != 0U && start_calls == 0U);

    reset_fixture(true);
    wifi_trust_profile_t profile = profile_from_beacon(ap1, "base");
    seed_baseline(&profile, 1U);
    store_enter_calls = 0U;
    assert(command(2U, monitor) == 0);
    assert(store_enter_calls != 0U && start_effects == 1U);
    clear_output();
    assert(submit_beacon(ap1, "base", 6U, true));
    assert(submit_beacon(ap1, "base", 6U, true));
    assert(count_text(output, " EVENT ") == 0U);
    assert(submit_beacon(ap1, "changed", 6U, true));
    assert(submit_beacon(ap1, "changed", 6U, true));
    assert(count_text(output, "REASON=ssid_changed") == 1U);
    assert(wifi_trust_stop(5000U));
    wifi_trust_profile_t loaded[WIFI_TRUST_MAX_PROFILES];
    assert(load_baseline(loaded, WIFI_TRUST_MAX_PROFILES) == 1U);
    assert(loaded[0].ssid_len == 4U && memcmp(loaded[0].ssid, "base", 4U) == 0);
}

static void test_list_clear_busy_and_terminal_precedence(void)
{
    reset_fixture(true);
    wifi_trust_profile_t profiles[2] = {
        profile_from_beacon(ap2, "two"),
        profile_from_beacon(ap1, "one"),
    };
    seed_baseline(profiles, 2U);
    clear_output();
    const char *list[] = {"wifi_trust", "baseline", "list"};
    assert(command(3U, list) == 0);
    assert(count_text(output, " BASELINE ") == 2U);
    assert(strstr(output, "02:01:02:03:04:05") <
           strstr(output, "06:06:07:08:09:0a"));

    const char *capture[] = {"wifi_trust", "baseline", "capture"};
    assert(command(3U, capture) == 0);
    assert(command(3U, list) == 1);
    assert(wifi_trust_stop(5000U));

    const char *clear[] = {"wifi_trust", "baseline", "clear"};
    assert(command(3U, clear) == 0);
    assert(!target_file.exists);

    wifi_trust_status_t status = {
        .mode = WIFI_TRUST_MODE_CAPTURE,
        .channel = 6U,
        .store = WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN,
        .recovery = WIFI_TRUST_RECOVERY_NONE,
    };
    char line[WIFI_TRUST_LINE_MAX];
    int length = wifi_trust_format_terminal_for_output(
        line, sizeof(line), &status, "stopped");
    assert(length > 0 && strstr(line, "OUTCOME=storage_uncertain") != NULL);
    status.rx_drops = 1U;
    status.store = WIFI_TRUST_STORE_OK;
    length = wifi_trust_format_terminal_for_output(
        line, sizeof(line), &status, "ok");
    assert(length > 0 && strstr(line, "OUTCOME=queue_overflow") != NULL);
    status.output_failures = 1U;
    length = wifi_trust_format_terminal_for_output(
        line, sizeof(line), &status, "restore_failed");
    assert(length > 0 && strstr(line, "OUTCOME=output_failed") != NULL);
    status.output_failures = 0U;
    status.store = WIFI_TRUST_STORE_NOT_FOUND;
    length = wifi_trust_format_terminal_for_output(
        line, sizeof(line), &status, "busy");
    assert(length > 0 && strstr(line, "OUTCOME=busy") != NULL);
}

int main(void)
{
    test_exact_legacy_status_start_stop_buffers();
    test_exact_terminal_precedence_buffers();
    test_exact_cli_and_allocation_failure();
    test_capture_natural_and_cancel();
    test_selected_validation_and_channel_filter();
    test_deadline_fail_stale_and_post_wipe_retry();
    test_uncertain_start_retains_context_for_stop_retry();
    test_capture_loss_and_recovered_retry();
    test_natural_stop_race_publishes_once();
    test_stop_in_pre_reservation_handoff_retains_arena();
    test_stop_during_start_rollback_wipe_waits_for_caller();
    test_cleanup_arm_and_sync_command_races();
    test_monitor_load_before_lease_and_deduplication();
    test_list_clear_busy_and_terminal_precedence();
    puts("PASS: Wi-Fi Trust CLI, runtime, storage, deadline, monitor");
    return 0;
}
