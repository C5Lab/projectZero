/* Execute the real console dispatcher and WPS service across startup barriers. */
#define _GNU_SOURCE
#include "janos_console_admission.h"
#include "janos_wps_service.h"
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    int (*func)(int, char **);
    int (*func_w_context)(void *, int, char **);
    void *context;
    const char *command;
} janos_console_cmd_context_t;
static pthread_mutex_t command_mutex;
static pthread_mutex_t *janos_command_mutex = &command_mutex;
static unsigned janos_commands_inflight;
static janos_radio_lease_t janos_radio_lease;
#define portMAX_DELAY 0
static void xSemaphoreTakeRecursive(pthread_mutex_t *mutex, int timeout)
{ (void)timeout; assert(pthread_mutex_lock(mutex) == 0); }
static void xSemaphoreGiveRecursive(pthread_mutex_t *mutex)
{ assert(pthread_mutex_unlock(mutex) == 0); }
static void uart_baud_note_activity(void) {}
static bool wifi_analyzer_busy(void) { return false; }
static void linenoiseHistoryFree(void) {}
/* Scan lifecycle itself is exercised by janos_analyzer_admission_test.c. */
static uint32_t wifi_analyzer_startup_begin(void) { abort(); }
static bool wifi_analyzer_startup_end(uint32_t generation)
{ (void)generation; abort(); }
static int wifi_analyzer_command_with_startup(int argc, char **argv,
                                              const uint32_t *generation)
{ (void)argc; (void)argv; (void)generation; abort(); }

/* DISPATCHER */

static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
static bool gate_entered, gate_open, block_admit, block_handler;
static atomic_uint handlers_called;
static atomic_bool legacy_published;
static bool publish_handler;
static bool admitted = true;
static janos_wps_worker_fn pending_worker;
static void *pending_arg;
static janos_wps_service_t service;

static void barrier(void)
{
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    gate_entered = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    while (!gate_open) assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}
static void await_barrier(void)
{
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    while (!gate_entered) assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}
static void open_barrier(void)
{
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    gate_open = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
}
static void *allocate(void *ctx, size_t size, uint32_t caps)
{ (void)ctx; (void)caps; return malloc(size); }
static void release(void *ctx, void *ptr, size_t size, janos_wps_memory_class_t kind)
{ (void)ctx; (void)size; (void)kind; free(ptr); }
static bool admit(void *ctx, const char **reason)
{
    (void)ctx; (void)reason;
    if (block_admit) barrier();
    return admitted && !atomic_load(&legacy_published);
}
/* ANALYZER_ACQUIRE */
static bool start_worker(void *ctx, janos_wps_worker_fn fn, void *arg)
{ (void)ctx; pending_worker = fn; pending_arg = arg; return true; }
static bool execute(void *ctx, const janos_wps_verify_request_t *request,
                    janos_wps_verify_outcome_t *outcome)
{ (void)ctx; (void)request; outcome->cleanup_ok = true; return false; }
static int handler(int argc, char **argv)
{
    (void)argc; (void)argv;
    atomic_fetch_add(&handlers_called, 1U);
    if (block_handler) barrier();
    if (publish_handler) {
        atomic_store(&legacy_published, true);
        return 0;
    }
    return 1; /* Startup failed without publishing a background task. */
}
static int safe_handler(int argc, char **argv)
{ (void)argc; (void)argv; return 0; }
static int dispatch(const char *command, const char *subcommand,
                    int (*fn)(int, char **))
{
    janos_console_cmd_context_t context = {.func = fn, .command = command};
    char *argv[] = {(char *)command, (char *)subcommand};
    return janos_console_cmd_dispatch(&context, subcommand ? 2 : 1, argv);
}
static void check_safe_dispatch(void)
{
    const char *safe[][2] = {{"wps", "status"}, {"wps", "stop"},
        {"wifi_analyzer", "status"}, {"wifi_analyzer", "stop"},
        {"secret", "status"}, {"help", NULL}, {"stop", NULL},
        {"show_scan_results", NULL}, {"reboot", NULL}};
    for (size_t i = 0; i < sizeof(safe) / sizeof(safe[0]); ++i)
        assert(dispatch(safe[i][0], safe[i][1], safe_handler) == 0);
}
static void *legacy_start(void *argument)
{
    const char *command = argument;
    dispatch(command, !strcmp(command, "wifi_analyzer") ? "clear" : NULL, handler);
    return NULL;
}
static bool wps_start(void)
{
    const uint8_t bssid[6] = {2, 0, 0, 0, 0, 1};
    return janos_wps_service_start_verify(&service, bssid, "00000000", NULL);
}
static void *wps_thread(void *argument)
{ (void)argument; assert(wps_start()); return NULL; }

int main(int argc, char **argv)
{
    assert(argc == 2);
    pthread_mutexattr_t attr;
    assert(pthread_mutexattr_init(&attr) == 0);
    assert(pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) == 0);
    assert(pthread_mutex_init(&command_mutex, &attr) == 0);
    assert(pthread_mutexattr_destroy(&attr) == 0);
    janos_radio_lease_init(&janos_radio_lease);
    janos_wps_memory_t memory;
    const janos_wps_memory_ops_t memory_ops = {allocate, release};
    const janos_wps_service_ops_t ops = {
        .admit = admit, .start_worker = start_worker, .execute_verify = execute};
    janos_wps_memory_init(&memory, &memory_ops, NULL);
    janos_wps_service_init(&service, &janos_radio_lease, &memory, &ops, NULL);
    pthread_t thread;
    if (!strcmp(argv[1], "wps-owned")) {
        assert(wps_start());
        assert(dispatch("start_portal", NULL, handler) != 0);
        assert(atomic_load(&handlers_called) == 0U);
        check_safe_dispatch();
    } else if (!strcmp(argv[1], "published")) {
        publish_handler = true;
        assert(dispatch("start_portal", NULL, handler) == 0);
        assert(janos_radio_lease_snapshot(&janos_radio_lease).owner ==
               JANOS_RADIO_OWNER_NONE);
        assert(!wps_start()); /* Host busy state protects the published task. */
        atomic_store(&legacy_published, false);
        assert(wps_start());
    } else if (!strcmp(argv[1], "wps-first")) {
        block_admit = true;
        assert(pthread_create(&thread, NULL, wps_thread, NULL) == 0);
        await_barrier(); /* WPS baseline inspection must already own the radio. */
        assert(dispatch("start_portal", NULL, handler) != 0);
        assert(atomic_load(&handlers_called) == 0U);
        check_safe_dispatch();
        open_barrier();
        assert(pthread_join(thread, NULL) == 0);
    } else if (!strcmp(argv[1], "admit-failure")) {
        admitted = false;
        assert(!wps_start());
        assert(janos_radio_lease_snapshot(&janos_radio_lease).owner ==
               JANOS_RADIO_OWNER_NONE);
        assert(dispatch("start_portal", NULL, handler) == 1);
        assert(atomic_load(&handlers_called) == 1U);
    } else {
        block_handler = true;
        const char *command = !strcmp(argv[1], "single-channel") ?
            "test_radio_channel" : !strcmp(argv[1], "batch-channel") ?
            "test_radio_channels" : !strcmp(argv[1], "analyzer-clear") ?
            "wifi_analyzer" : "start_portal";
        assert(pthread_create(&thread, NULL, legacy_start, (void *)command) == 0);
        await_barrier(); /* No legacy active flag/task has been published yet. */
        uint32_t sentinel = 1234U;
        assert(!analyzer_host_lease_acquire(&sentinel));
        assert(sentinel == 1234U);
        assert(!wps_start());
        check_safe_dispatch();
        open_barrier();
        assert(pthread_join(thread, NULL) == 0);
        assert(janos_radio_lease_snapshot(&janos_radio_lease).owner ==
               JANOS_RADIO_OWNER_NONE);
        assert(wps_start()); /* Failed legacy startup released its token. */
    }
    if (pending_worker) pending_worker(pending_arg);
    assert(janos_radio_lease_snapshot(&janos_radio_lease).owner ==
           JANOS_RADIO_OWNER_NONE);
    assert(janos_wps_memory_snapshot(&memory).secret_bytes == 0U);
    assert(pthread_mutex_destroy(&command_mutex) == 0);
    printf("PASS: console radio transaction %s\n", argv[1]);
    return 0;
}
