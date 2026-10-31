/* Host test for the real module_loader.c with only firmware boundaries stubbed.
 * Run: cc -std=c11 -D_XOPEN_SOURCE=700 -Wall -Wextra -Werror -pthread
 *         -fsanitize=address,undefined -Itests/stubs
 *         tests/test_module_loader.c module_loader.c -o /tmp/c5_module_loader_test
 *      /tmp/c5_module_loader_test
 */
#include "../module_loader.h"

#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct FuriMutex {
    pthread_mutex_t raw;
};

static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_condition = PTHREAD_COND_INITIALIZER;
static pthread_t unload_thread_id;
static bool watch_unload_attempt;
static bool unload_attempted;
static bool block_draw;
static bool draw_entered;
static bool allow_draw_exit;

FuriMutex* furi_mutex_alloc(FuriMutexType type) {
    FuriMutex* mutex = calloc(1, sizeof(*mutex));
    assert(mutex);
    pthread_mutexattr_t attr;
    assert(pthread_mutexattr_init(&attr) == 0);
    if(type == FuriMutexTypeRecursive) {
        assert(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0);
    }
    assert(pthread_mutex_init(&mutex->raw, &attr) == 0);
    assert(pthread_mutexattr_destroy(&attr) == 0);
    return mutex;
}

void furi_mutex_free(FuriMutex* mutex) {
    assert(pthread_mutex_destroy(&mutex->raw) == 0);
    free(mutex);
}

int furi_mutex_acquire(FuriMutex* mutex, uint32_t timeout) {
    assert(timeout == FuriWaitForever);
    if(watch_unload_attempt && pthread_equal(pthread_self(), unload_thread_id)) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        unload_attempted = true;
        assert(pthread_cond_broadcast(&gate_condition) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
    return pthread_mutex_lock(&mutex->raw);
}

int furi_mutex_release(FuriMutex* mutex) {
    return pthread_mutex_unlock(&mutex->raw);
}

struct ElfApiInterface {
    int unused;
};
static const ElfApiInterface firmware_api_stub = {0};
const ElfApiInterface* const firmware_api_interface = &firmware_api_stub;

struct PluginManager {
    bool loaded;
    bool entered;
};

typedef struct {
    char lines[4][C5_MODULE_LINE_CAPACITY];
    size_t line_count;
    uint8_t raw[64];
    size_t raw_length;
    size_t raw_calls;
    size_t draw_count;
    size_t input_count;
    size_t tick_count;
    bool left;
    uint8_t launch[32];
    size_t launch_length;
} TestState;

static TestState state;
static PluginManager* current_manager;
static const C5ModuleV3* chosen_api;
static PluginManagerError chosen_error;
static bool fail_enter;
static atomic_size_t manager_frees;
static size_t enter_calls;
static uint8_t sent_batch[64];
static size_t sent_batch_length;
static size_t sent_batch_calls;
static size_t text_result_calls;
static bool text_result_accepted;
static char text_result_value[64];
static C5HostApiV3 test_host(void);
static char teardown_events[4];
static size_t teardown_event_count;
static C5ModuleRuntime* leave_lock_runtime;
static int leave_lock_probe_result;

static void* probe_leave_lock(void* context) {
    C5ModuleRuntime* runtime = context;
    leave_lock_probe_result = pthread_mutex_trylock(&runtime->lock->raw);
    if(leave_lock_probe_result == 0) {
        assert(pthread_mutex_unlock(&runtime->lock->raw) == 0);
    }
    return NULL;
}

static void* test_enter(const C5HostApiV3* host, const void* params, size_t params_size) {
    assert(host && host->version == C5_MODULE_API_VERSION);
    enter_calls++;
    if(fail_enter) return NULL;
    assert(current_manager);
    current_manager->entered = true;
    memset(&state, 0, sizeof(state));
    assert(params_size <= sizeof(state.launch));
    assert((params == NULL) == (params_size == 0));
    if(params_size) memcpy(state.launch, params, params_size);
    state.launch_length = params_size;
    return &state;
}

static void test_leave(void* value, const C5HostApiV3* host) {
    assert(value == &state && host);
    assert(!state.left);
    if(leave_lock_runtime) {
        pthread_t probe;
        assert(pthread_create(&probe, NULL, probe_leave_lock, leave_lock_runtime) == 0);
        assert(pthread_join(probe, NULL) == 0);
    }
    state.left = true;
    teardown_events[teardown_event_count++] = 'L';
}

static void test_on_line(void* value, const C5HostApiV3* host, const char* line) {
    assert(value == &state && host && !state.left);
    assert(state.line_count < 4);
    strcpy(state.lines[state.line_count++], line);
}

static void test_on_bytes(
    void* value,
    const C5HostApiV3* host,
    const uint8_t* bytes,
    size_t length) {
    TestState* current = value;
    assert(current == &state && host && bytes && !current->left);
    assert(current->raw_length + length <= sizeof(current->raw));
    memcpy(current->raw + current->raw_length, bytes, length);
    current->raw_length += length;
    current->raw_calls++;
}

static C5InputResult test_on_input(
    void* value,
    const C5HostApiV3* host,
    const InputEvent* event) {
    assert(value == &state && host && event && !state.left);
    state.input_count++;
    return C5InputConsumed;
}

static C5InputResult test_batch_input(
    void* value,
    const C5HostApiV3* host,
    const InputEvent* event) {
    assert(value == &state && host && event);
    static const char batch[] = "select_html 2\nstart_evil_twin\n";
    assert(host->send_raw_lines(host->ctx, batch, sizeof(batch) - 1));
    return C5InputConsumed;
}

static bool capture_raw_batch(void* context, const char* batch, size_t length) {
    assert(context == &state && batch && length <= sizeof(sent_batch));
    memcpy(sent_batch, batch, length);
    sent_batch_length = length;
    sent_batch_calls++;
    return true;
}

static bool queue_text_request(void* context, const C5TextInputRequest* request) {
    return c5_module_runtime_request_text_input(context, request);
}

static C5InputResult test_text_input_request(
    void* value,
    const C5HostApiV3* host,
    const InputEvent* event) {
    assert(value == &state && host && event);
    C5TextInputRequest request = {
        .header = "Portal SSID",
        .initial = "Lab",
        .capacity = 33,
        .minimum_length = 1,
    };
    assert(host->request_text_input(host->ctx, &request));
    memset(&request, 0xa5, sizeof(request));
    return C5InputConsumed;
}

static void test_text_input_result(
    void* value,
    const C5HostApiV3* host,
    bool accepted,
    const char* text) {
    assert(value == &state && host && text && !state.left);
    text_result_calls++;
    text_result_accepted = accepted;
    snprintf(text_result_value, sizeof(text_result_value), "%s", text);
}

static void test_draw(void* value, const C5HostApiV3* host, Canvas* canvas) {
    assert(value == &state && host && canvas && !state.left);
    state.draw_count++;
    if(block_draw) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        draw_entered = true;
        assert(pthread_cond_broadcast(&gate_condition) == 0);
        while(!allow_draw_exit) {
            assert(pthread_cond_wait(&gate_condition, &gate_mutex) == 0);
        }
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
}

static void test_tick(void* value, const C5HostApiV3* host, uint32_t now_ticks) {
    assert(value == &state && host && now_ticks == 42 && !state.left);
    state.tick_count++;
}

static const C5ModuleV3 valid_api = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = test_enter,
    .leave = test_leave,
    .on_line = test_on_line,
    .on_input = test_on_input,
    .draw = test_draw,
    .tick = test_tick,
};

static const C5ModuleV3 raw_api = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = test_enter,
    .leave = test_leave,
    .on_line = test_on_line,
    .on_bytes = test_on_bytes,
    .on_input = test_on_input,
    .draw = test_draw,
};

static const C5ModuleV3 batch_api = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = test_enter,
    .leave = test_leave,
    .on_line = test_on_line,
    .on_input = test_batch_input,
    .draw = test_draw,
};

static const C5ModuleV3 text_api = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = test_enter,
    .leave = test_leave,
    .on_line = test_on_line,
    .on_input = test_text_input_request,
    .on_text_input = test_text_input_result,
    .draw = test_draw,
};

PluginManager* plugin_manager_alloc(
    const char* application_id,
    uint32_t api_version,
    const ElfApiInterface* api_interface) {
    assert(strcmp(application_id, C5_MODULE_APP_ID) == 0);
    assert(api_version == C5_MODULE_API_VERSION && api_interface == firmware_api_interface);
    PluginManager* manager = calloc(1, sizeof(*manager));
    assert(manager);
    current_manager = manager;
    return manager;
}

void plugin_manager_free(PluginManager* manager) {
    assert(manager);
    assert(!manager->entered || state.left);
    atomic_fetch_add(&manager_frees, 1);
    teardown_events[teardown_event_count++] = 'F';
    if(manager == current_manager) current_manager = NULL;
    free(manager);
}

PluginManagerError plugin_manager_load_single(PluginManager* manager, const char* path) {
    assert(manager && path && strcmp(path, "gps.fal") == 0);
    if(chosen_error == PluginManagerErrorNone) manager->loaded = true;
    return chosen_error;
}

const void* plugin_manager_get_ep(PluginManager* manager, uint32_t index) {
    assert(manager && manager->loaded && index == 0);
    return chosen_api;
}

static void reset_fixture(void) {
    memset(&state, 0, sizeof(state));
    current_manager = NULL;
    chosen_api = &valid_api;
    chosen_error = PluginManagerErrorNone;
    fail_enter = false;
    atomic_store(&manager_frees, 0);
    enter_calls = 0;
    sent_batch_length = 0;
    sent_batch_calls = 0;
    text_result_calls = 0;
    text_result_accepted = false;
    text_result_value[0] = '\0';
    teardown_event_count = 0;
    memset(teardown_events, 0, sizeof(teardown_events));
    watch_unload_attempt = false;
    unload_attempted = false;
    block_draw = false;
    draw_entered = false;
    allow_draw_exit = false;
}

static void test_atomic_raw_batch_callback_keeps_command_order(void) {
    reset_fixture();
    chosen_api = &batch_api;
    C5ModuleRuntime runtime;
    C5HostApiV3 host = test_host();
    host.ctx = &state;
    host.send_raw_lines = capture_raw_batch;
    assert(c5_module_runtime_init(&runtime, &host));
    assert(c5_module_runtime_load(&runtime, "gps.fal", NULL, 0) == C5ModuleLoadOk);

    InputEvent event = {.type = InputTypeShort, .key = InputKeyOk};
    assert(c5_module_runtime_input(&runtime, &event) == C5InputConsumed);
    static const char expected[] = "select_html 2\nstart_evil_twin\n";
    assert(sent_batch_calls == 1 && sent_batch_length == sizeof(expected) - 1);
    assert(memcmp(sent_batch, expected, sizeof(expected) - 1) == 0);
    c5_module_runtime_deinit(&runtime);
}

static void test_text_input_request_is_deferred_and_canceled_on_unload(void) {
    reset_fixture();
    chosen_api = &text_api;
    C5ModuleRuntime runtime;
    C5HostApiV3 host = test_host();
    host.ctx = &runtime;
    host.request_text_input = queue_text_request;
    assert(c5_module_runtime_init(&runtime, &host));
    assert(c5_module_runtime_load(&runtime, "gps.fal", NULL, 0) == C5ModuleLoadOk);

    InputEvent event = {.type = InputTypeShort, .key = InputKeyOk};
    assert(c5_module_runtime_input(&runtime, &event) == C5InputConsumed);
    assert(text_result_calls == 0);
    C5TextInputRequest request;
    uint32_t token = 0;
    assert(c5_module_runtime_take_text_input(&runtime, &request, &token));
    assert(strcmp(request.header, "Portal SSID") == 0);
    assert(strcmp(request.initial, "Lab") == 0);
    assert(request.capacity == 33 && request.minimum_length == 1);
    assert(!c5_module_runtime_take_text_input(&runtime, &request, &token));
    assert(c5_module_runtime_complete_text_input(&runtime, token, true, "New SSID", 8));
    assert(text_result_calls == 1 && text_result_accepted);
    assert(strcmp(text_result_value, "New SSID") == 0);

    assert(c5_module_runtime_input(&runtime, &event) == C5InputConsumed);
    assert(c5_module_runtime_take_text_input(&runtime, &request, &token));
    assert(!c5_module_runtime_complete_text_input(&runtime, token, true, "", 0));
    assert(text_result_calls == 2 && !text_result_accepted);

    assert(c5_module_runtime_input(&runtime, &event) == C5InputConsumed);
    assert(c5_module_runtime_take_text_input(&runtime, &request, &token));
    const char hidden_nul[] = {'A', '\0', 'B'};
    assert(!c5_module_runtime_complete_text_input(&runtime, token, true, hidden_nul, sizeof(hidden_nul)));
    assert(text_result_calls == 3 && !text_result_accepted);

    assert(c5_module_runtime_input(&runtime, &event) == C5InputConsumed);
    assert(c5_module_runtime_take_text_input(&runtime, &request, &token));
    char full_capacity[33];
    memset(full_capacity, 'A', sizeof(full_capacity));
    assert(!c5_module_runtime_complete_text_input(
        &runtime, token, true, full_capacity, sizeof(full_capacity)));
    assert(text_result_calls == 4 && !text_result_accepted);

    assert(c5_module_runtime_input(&runtime, &event) == C5InputConsumed);
    assert(c5_module_runtime_take_text_input(&runtime, &request, &token));
    char* unread_cancel = malloc(1);
    assert(unread_cancel);
    unread_cancel[0] = 'X';
    assert(c5_module_runtime_complete_text_input(&runtime, token, false, unread_cancel, 0));
    free(unread_cancel);
    assert(text_result_calls == 5 && !text_result_accepted);

    assert(c5_module_runtime_input(&runtime, &event) == C5InputConsumed);
    assert(c5_module_runtime_take_text_input(&runtime, &request, &token));
    assert(c5_module_runtime_complete_text_input(&runtime, token, false, NULL, 0));
    assert(text_result_calls == 6 && !text_result_accepted);

    assert(c5_module_runtime_input(&runtime, &event) == C5InputConsumed);
    assert(c5_module_runtime_take_text_input(&runtime, &request, &token));
    c5_module_runtime_unload(&runtime);
    assert(!c5_module_runtime_complete_text_input(&runtime, token, true, "stale", 5));
    assert(text_result_calls == 6);
    c5_module_runtime_deinit(&runtime);
}

static C5HostApiV3 test_host(void) {
    C5HostApiV3 host = {.version = C5_MODULE_API_VERSION, .size = sizeof(C5HostApiV3)};
    return host;
}

static void test_crlf_split_across_chunks_and_overflow_resync(void) {
    reset_fixture();
    C5ModuleRuntime runtime;
    C5HostApiV3 host = test_host();
    assert(c5_module_runtime_init(&runtime, &host));
    assert(c5_module_runtime_load(&runtime, "gps.fal", NULL, 0) == C5ModuleLoadOk);

    c5_module_runtime_feed(&runtime, (const uint8_t*)"one\r", 4);
    assert(state.line_count == 0);
    c5_module_runtime_feed(&runtime, (const uint8_t*)"\ntwo\n", 5);
    assert(state.line_count == 2);
    assert(strcmp(state.lines[0], "one") == 0);
    assert(strcmp(state.lines[1], "two") == 0);

    char oversized[C5_MODULE_LINE_CAPACITY + 1];
    memset(oversized, 'X', sizeof(oversized));
    oversized[sizeof(oversized) - 1] = '\n';
    c5_module_runtime_feed(&runtime, (const uint8_t*)oversized, sizeof(oversized));
    assert(state.line_count == 2);
    c5_module_runtime_feed(&runtime, (const uint8_t*)"ok\n", 3);
    assert(state.line_count == 3 && strcmp(state.lines[2], "ok") == 0);
    c5_module_runtime_deinit(&runtime);
}

static void test_bad_abi_and_loader_error_release_manager_without_enter(void) {
    reset_fixture();
    C5ModuleRuntime runtime;
    C5HostApiV3 host = test_host();
    assert(c5_module_runtime_init(&runtime, &host));

    C5ModuleV3 bad_api = valid_api;
    bad_api.version++;
    chosen_api = &bad_api;
    assert(c5_module_runtime_load(&runtime, "gps.fal", NULL, 0) == C5ModuleLoadBadApi);
    assert(enter_calls == 0 && atomic_load(&manager_frees) == 1 &&
           !c5_module_runtime_active(&runtime));

    chosen_api = &valid_api;
    chosen_error = PluginManagerErrorLoaderError;
    assert(c5_module_runtime_load(&runtime, "gps.fal", NULL, 0) == C5ModuleLoadManagerError);
    assert(enter_calls == 0 && atomic_load(&manager_frees) == 2 &&
           !c5_module_runtime_active(&runtime));
    c5_module_runtime_deinit(&runtime);
}

static void test_raw_input_preserves_prompt_and_blank_lines(void) {
    reset_fixture();
    chosen_api = &raw_api;
    C5ModuleRuntime runtime;
    C5HostApiV3 host = test_host();
    assert(c5_module_runtime_init(&runtime, &host));
    assert(c5_module_runtime_load(&runtime, "gps.fal", NULL, 0) == C5ModuleLoadOk);

    static const uint8_t first[] = {'l', 'i', 's', 't', '_', 's', 'd', '\r'};
    static const uint8_t second[] = {'\n', '>', '\n', '\n'};
    c5_module_runtime_feed(&runtime, first, sizeof(first));
    c5_module_runtime_feed(&runtime, second, sizeof(second));
    assert(state.raw_calls == 2);
    assert(state.raw_length == sizeof(first) + sizeof(second));
    assert(memcmp(state.raw, first, sizeof(first)) == 0);
    assert(memcmp(state.raw + sizeof(first), second, sizeof(second)) == 0);
    assert(state.line_count == 0);

    c5_module_runtime_unload(&runtime);
    c5_module_runtime_feed(&runtime, second, sizeof(second));
    assert(state.raw_calls == 2);
    c5_module_runtime_deinit(&runtime);
}

static void test_unload_detaches_callbacks_before_freeing_plugin(void) {
    reset_fixture();
    C5ModuleRuntime runtime;
    C5HostApiV3 host = test_host();
    assert(c5_module_runtime_init(&runtime, &host));
    assert(c5_module_runtime_load(&runtime, "gps.fal", NULL, 0) == C5ModuleLoadOk);
    Canvas canvas = {0};
    InputEvent event = {.type = InputTypeShort, .key = InputKeyOk};
    assert(c5_module_runtime_draw(&runtime, &canvas));
    assert(c5_module_runtime_input(&runtime, &event) == C5InputConsumed);
    c5_module_runtime_tick(&runtime, 42);
    assert(state.draw_count == 1 && state.input_count == 1 && state.tick_count == 1);

    static const uint8_t secret_reply[] = "saved password";
    c5_module_runtime_feed(&runtime, secret_reply, sizeof(secret_reply) - 1);
    assert(runtime.line[0] == 's');
    memcpy(runtime.text_input.initial, "private", sizeof("private"));

    c5_module_runtime_unload(&runtime);
    for(size_t i = 0; i < sizeof(runtime.line); i++) assert(runtime.line[i] == 0);
    for(size_t i = 0; i < sizeof(runtime.text_input); i++)
        assert(((const uint8_t*)&runtime.text_input)[i] == 0);
    assert(teardown_event_count == 2 && teardown_events[0] == 'L' && teardown_events[1] == 'F');
    assert(!c5_module_runtime_active(&runtime));
    c5_module_runtime_feed(&runtime, (const uint8_t*)"late\n", 5);
    assert(!c5_module_runtime_draw(&runtime, &canvas));
    assert(c5_module_runtime_input(&runtime, &event) == C5InputIgnored);
    c5_module_runtime_tick(&runtime, 42);
    assert(state.line_count == 0 && state.draw_count == 1 && state.input_count == 1 &&
           state.tick_count == 1);
    c5_module_runtime_deinit(&runtime);
    assert(atomic_load(&manager_frees) == 1);
}

static void* draw_thread_main(void* context) {
    C5ModuleRuntime* runtime = context;
    Canvas canvas = {0};
    assert(c5_module_runtime_draw(runtime, &canvas));
    return NULL;
}

static void* unload_thread_main(void* context) {
    C5ModuleRuntime* runtime = context;
    unload_thread_id = pthread_self();
    c5_module_runtime_unload(runtime);
    return NULL;
}

static void test_unload_waits_for_running_draw(void) {
    reset_fixture();
    C5ModuleRuntime runtime;
    C5HostApiV3 host = test_host();
    assert(c5_module_runtime_init(&runtime, &host));
    assert(c5_module_runtime_load(&runtime, "gps.fal", NULL, 0) == C5ModuleLoadOk);
    block_draw = true;
    pthread_t draw_thread;
    assert(pthread_create(&draw_thread, NULL, draw_thread_main, &runtime) == 0);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while(!draw_entered) assert(pthread_cond_wait(&gate_condition, &gate_mutex) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);

    watch_unload_attempt = true;
    pthread_t unload_thread;
    assert(pthread_create(&unload_thread, NULL, unload_thread_main, &runtime) == 0);
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while(!unload_attempted) assert(pthread_cond_wait(&gate_condition, &gate_mutex) == 0);
    assert(atomic_load(&manager_frees) == 0 && !state.left);
    allow_draw_exit = true;
    assert(pthread_cond_broadcast(&gate_condition) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);

    assert(pthread_join(draw_thread, NULL) == 0);
    assert(pthread_join(unload_thread, NULL) == 0);
    watch_unload_attempt = false;
    assert(atomic_load(&manager_frees) == 1 && state.left);
    assert(teardown_event_count == 2 && teardown_events[0] == 'L' && teardown_events[1] == 'F');
    c5_module_runtime_deinit(&runtime);
}

static void test_load_accepts_launch_snapshot(void) {
    reset_fixture();
    C5ModuleRuntime runtime;
    C5HostApiV3 host = test_host();
    assert(c5_module_runtime_init(&runtime, &host));
    static const uint8_t launch[] = {0xC5, 0x05, 0x41};
    assert(c5_module_runtime_load(&runtime, "gps.fal", launch, sizeof(launch)) ==
           C5ModuleLoadOk);
    assert(state.launch_length == sizeof(launch));
    assert(memcmp(state.launch, launch, sizeof(launch)) == 0);
    c5_module_runtime_deinit(&runtime);
}

static void test_leave_runs_after_detach_without_runtime_lock(void) {
    reset_fixture();
    C5ModuleRuntime runtime;
    C5HostApiV3 host = test_host();
    assert(c5_module_runtime_init(&runtime, &host));
    assert(c5_module_runtime_load(&runtime, "gps.fal", NULL, 0) == C5ModuleLoadOk);
    leave_lock_runtime = &runtime;
    leave_lock_probe_result = -1;
    c5_module_runtime_unload(&runtime);
    assert(leave_lock_probe_result == 0);
    leave_lock_runtime = NULL;
    c5_module_runtime_deinit(&runtime);
}

int main(void) {
    test_crlf_split_across_chunks_and_overflow_resync();
    test_raw_input_preserves_prompt_and_blank_lines();
    test_atomic_raw_batch_callback_keeps_command_order();
    test_text_input_request_is_deferred_and_canceled_on_unload();
    test_bad_abi_and_loader_error_release_manager_without_enter();
    test_unload_detaches_callbacks_before_freeing_plugin();
    test_unload_waits_for_running_draw();
    test_load_accepts_launch_snapshot();
    test_leave_runs_after_detach_without_runtime_lock();
    puts("Module loader tests passed");
    return 0;
}
