/* Real analyzer command/reserve/release; only driver/RTOS and UART are faked. */
#include "janos_console_admission.h"
#include "janos_wps_command.h"
#include "wifi_analyzer_core.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef void *TaskHandle_t;
typedef int wifi_mode_t;
typedef int wifi_ap_record_t;
enum { WFA_IDLE, WFA_PREPARING, WFA_QUARANTINED, WIFI_MODE_STA, ESP_OK = 0 };
#define WFA_STACK_BYTES 1024
#define pdPASS 1
#define portENTER_CRITICAL(lock) assert(pthread_mutex_lock(lock) == 0)
#define portEXIT_CRITICAL(lock) assert(pthread_mutex_unlock(lock) == 0)
static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;
static int s_state;
static bool s_startup_pending;
static bool s_initialized = true, s_cancel, s_armed, s_done, s_saved_radio;
static uint16_t s_capacity, s_last_count;
static uint32_t s_last_success, s_scan, s_lease_generation;
static size_t s_psram_bytes;
static uint64_t s_started_ms;
static const char *s_last_error;
static void *s_working, *s_committed, *s_worker;
static wfa_options_t s_options;
static janos_radio_lease_t lease;
static const char *host_reason;
static unsigned baseline_calls, prepare_calls;
static bool buffers_ok = true;
static char emitted[512];
static pthread_mutex_t gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_cond = PTHREAD_COND_INITIALIZER;
static bool block_acquire, gate_entered, gate_open;
static bool block_dispatch_boundary;
static _Thread_local bool in_scan_thread;
static bool resume_on_delay, scan_finished;
static atomic_uint fake_clock;
static unsigned radio_teardowns;
static bool acquire(uint32_t *generation)
{
    bool ok = janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_ANALYZER,
                                       generation) == JANOS_RADIO_LEASE_OK;
    if (ok && block_acquire) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        gate_entered = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!gate_open) assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
    return ok;
}
static bool release_lease(uint32_t generation, bool restored)
{
    return janos_radio_lease_begin_cleanup(&lease, JANOS_RADIO_OWNER_ANALYZER,
                                           generation) &&
        janos_radio_lease_finish_cleanup(&lease, JANOS_RADIO_OWNER_ANALYZER,
                                          generation, restored);
}
static bool mark_running(uint32_t generation)
{ return janos_radio_lease_mark_running(&lease, JANOS_RADIO_OWNER_ANALYZER, generation); }
static bool cancel_lease(uint32_t generation)
{ return janos_radio_lease_request_cancel(&lease, JANOS_RADIO_OWNER_ANALYZER, generation); }
static const char *busy_reason(void)
{
    ++baseline_calls;
    assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_ANALYZER);
    if (block_acquire || block_dispatch_boundary) {
        assert(s_cancel);
        assert(janos_radio_lease_cancel_requested(&lease,
            JANOS_RADIO_OWNER_ANALYZER, s_lease_generation));
    }
    janos_console_admission_token_t contender;
    assert(janos_console_admission_begin(&lease, "start_portal", NULL, 0,
                                         false, &contender) != JANOS_CONSOLE_ADMIT);
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_WPS, NULL) ==
           JANOS_RADIO_LEASE_BUSY);
    return host_reason;
}
static int prepare(void) { ++prepare_calls; return ESP_OK; }
static const struct {
    const char *(*busy_reason)(void);
    bool (*lease_acquire)(uint32_t *);
    bool (*lease_release)(uint32_t, bool);
    bool (*lease_mark_running)(uint32_t);
    bool (*lease_cancel)(uint32_t);
    int (*prepare_wifi)(void);
} s_hooks = {busy_reason, acquire, release_lease, mark_running, cancel_lease, prepare};
static bool emit_line(const char *line, int length)
{
    assert(length > 0 && (size_t)length < sizeof(emitted));
    memcpy(emitted, line, (size_t)length);
    emitted[length] = '\0';
    return true;
}
static void show_status(void) {}
static void heap_caps_free(void *ptr) { free(ptr); }
static bool allocate_buffers(uint16_t limit) { (void)limit; return buffers_ok; }
static int esp_wifi_get_mode(int *mode) { *mode = WIFI_MODE_STA; return ESP_OK; }
static int esp_wifi_sta_get_ap_info(wifi_ap_record_t *ap) { (void)ap; return 1; }
static int esp_wifi_get_promiscuous(bool *enabled) { *enabled = false; return ESP_OK; }
static const char *configure_scan(void) { return NULL; }
static bool restore_radio(void) { return true; }
static void set_error(const char *error) { s_last_error = error; }
static uint64_t now_ms(void) { return atomic_fetch_add(&fake_clock, 1000U); }
#define pdMS_TO_TICKS(ticks) (ticks)
static void vTaskDelay(unsigned ticks)
{
    assert(ticks == 20U);
    if (resume_on_delay) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        gate_open = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        while (!scan_finished) assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
    sched_yield();
}
static void analyzer_worker(void *arg) { (void)arg; }
static int xTaskCreate(void (*fn)(void *), const char *name, int stack,
                       void *arg, int priority, TaskHandle_t *worker)
{
    (void)fn; (void)name; (void)stack; (void)arg; (void)priority;
    *worker = (void *)1; return pdPASS;
}
static void xTaskNotifyGive(TaskHandle_t worker) { assert(worker == (void *)1); }
/* ANALYZER_FUNCTIONS */
static bool janos_wps_runtime_stop(unsigned timeout) { (void)timeout; return true; }
/* GLOBAL_STOP_PREFIX */

typedef struct {
    int (*func)(int, char **);
    int (*func_w_context)(void *, int, char **);
    void *context;
    const char *command;
} janos_console_cmd_context_t;
static pthread_mutex_t command_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t *janos_command_mutex = &command_mutex;
static unsigned janos_commands_inflight;
#define janos_radio_lease lease
#define portMAX_DELAY 0
static void xSemaphoreTakeRecursive(pthread_mutex_t *mutex, int timeout)
{ (void)timeout; assert(pthread_mutex_lock(mutex) == 0); }
static void xSemaphoreGiveRecursive(pthread_mutex_t *mutex)
{
    assert(pthread_mutex_unlock(mutex) == 0);
    if (block_dispatch_boundary && in_scan_thread) {
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        if (!gate_entered) {
            gate_entered = true;
            assert(pthread_cond_broadcast(&gate_cond) == 0);
            while (!gate_open) assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        }
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
    }
}
static void uart_baud_note_activity(void) {}
static void linenoiseHistoryFree(void) {}
static int capture_puts(const char *line)
{ snprintf(emitted, sizeof(emitted), "%s\n", line); return 0; }
#define puts capture_puts
/* DISPATCHER */
#undef puts

static void *start_scan(void *argument)
{
    (void)argument;
    char *args[] = {"wifi_analyzer", "scan"};
    janos_console_cmd_context_t context = {
        .func = wifi_analyzer_command, .command = "wifi_analyzer"};
    in_scan_thread = true;
    int result = block_dispatch_boundary ?
        janos_console_cmd_dispatch(&context, 2, args) : wifi_analyzer_command(2, args);
    assert(result == 1); /* no_psram rollback */
    in_scan_thread = false;
    assert(pthread_mutex_lock(&gate_mutex) == 0);
    scan_finished = true;
    assert(pthread_cond_broadcast(&gate_cond) == 0);
    assert(pthread_mutex_unlock(&gate_mutex) == 0);
    return NULL;
}
int main(int argc, char **argv)
{
    (void)s_startup_pending;
    janos_radio_lease_init(&lease);
    char *args[] = {"wifi_analyzer", "scan"};
    if (argc == 2 && !strcmp(argv[1], "announcement")) {
        janos_console_cmd_context_t context = {
            .func = wifi_analyzer_command, .command = "wifi_analyzer"};
        char *invalid[] = {"wifi_analyzer", "scan", "--invalid"};
        assert(janos_console_cmd_dispatch(&context, 3, invalid) == 1);
        assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
        assert(!wifi_analyzer_busy());
        s_scan = UINT32_MAX;
        assert(janos_console_cmd_dispatch(&context, 2, args) == 1);
        assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
        assert(!wifi_analyzer_busy());
        s_scan = 0U;
        s_initialized = false;
        assert(janos_console_cmd_dispatch(&context, 2, args) == 1);
        assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
        assert(!wifi_analyzer_busy());
        s_initialized = true;
        uint32_t old = wifi_analyzer_startup_begin();
        assert(old != 0U && wifi_analyzer_busy());
        assert(wifi_analyzer_command(2, args) == 1); /* Cannot steal another announcement. */
        assert(janos_radio_lease_snapshot(&lease).generation == old);
        assert(wifi_analyzer_startup_end(old));
        uint32_t current = wifi_analyzer_startup_begin();
        assert(current != 0U && current != old);
        assert(wifi_analyzer_startup_end(old));
        assert(janos_radio_lease_snapshot(&lease).generation == current);
        assert(wifi_analyzer_busy());
        buffers_ok = false;
        assert(wifi_analyzer_command_with_startup(2, args, &current) == 1);
        assert(wifi_analyzer_startup_end(current));
        assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
        assert(!wifi_analyzer_busy() && janos_commands_inflight == 0U);
        printf("PASS: analyzer announcements rollback, consume and reject stale cleanup\n");
        return 0;
    }
    if (argc == 2 && (!strcmp(argv[1], "pending-stop") ||
                     !strcmp(argv[1], "pending-stop-release") ||
                     !strcmp(argv[1], "dispatch-boundary") ||
                     !strcmp(argv[1], "dispatch-boundary-release"))) {
        block_dispatch_boundary = !strcmp(argv[1], "dispatch-boundary") ||
            !strcmp(argv[1], "dispatch-boundary-release");
        block_acquire = !block_dispatch_boundary;
        resume_on_delay = !strcmp(argv[1], "pending-stop-release") ||
            !strcmp(argv[1], "dispatch-boundary-release");
        buffers_ok = false;
        pthread_t thread;
        assert(pthread_create(&thread, NULL, start_scan, NULL) == 0);
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        while (!gate_entered) assert(pthread_cond_wait(&gate_cond, &gate_mutex) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
        if (!block_dispatch_boundary)
            assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_ANALYZER);
        janos_console_cmd_context_t stop_context = {.func = cmd_stop, .command = "stop"};
        char *stop_args[] = {"stop"};
        assert(janos_console_cmd_dispatch(&stop_context, 1, stop_args) ==
               (resume_on_delay ? 0 : 1));
        assert(radio_teardowns == (resume_on_delay ? 1U : 0U));
        assert(pthread_mutex_lock(&gate_mutex) == 0);
        gate_open = true;
        assert(pthread_cond_broadcast(&gate_cond) == 0);
        assert(pthread_mutex_unlock(&gate_mutex) == 0);
        assert(pthread_join(thread, NULL) == 0);
        assert(cmd_stop(0, NULL) == 0);
        assert(radio_teardowns == (resume_on_delay ? 2U : 1U));
        printf("PASS: analyzer pending startup blocks global stop teardown\n");
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "clear-busy")) {
        assert(wifi_analyzer_command(2, args) == 0);
        janos_console_cmd_context_t context = {
            .func = wifi_analyzer_command, .command = "wifi_analyzer"};
        char *clear[] = {"wifi_analyzer", "clear"};
        assert(janos_console_cmd_dispatch(&context, 2, clear) == 1);
        assert(strcmp(emitted, "[WFACTL1] {\"v\":1,\"type\":\"error\","
            "\"command\":\"clear\",\"code\":\"busy\",\"reason\":\"wifi_analyzer\"}\n") == 0);
        assert(janos_radio_lease_snapshot(&lease).state == JANOS_RADIO_LEASE_RUNNING);
        release(false);
        s_working = malloc(16U);
        s_committed = malloc(16U);
        assert(s_working && s_committed);
        assert(janos_console_cmd_dispatch(&context, 2, clear) == 0);
        assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
        assert(!s_working && !s_committed);
        assert(strcmp(emitted, "[WFACTL1] {\"v\":1,\"type\":\"cleared\",\"state\":\"idle\"}\n") == 0);
        printf("PASS: analyzer clear busy wire compatibility\n");
        return 0;
    }
    host_reason = "portal";
    assert(wifi_analyzer_command(2, args) == 1);
    assert(baseline_calls == 1U && prepare_calls == 0U);
    assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
    assert(strcmp(emitted, "[WFACTL1] {\"v\":1,\"type\":\"error\","
        "\"command\":\"scan\",\"code\":\"busy\",\"reason\":\"portal\"}\n") == 0);
    host_reason = NULL;
    buffers_ok = false;
    assert(wifi_analyzer_command(2, args) == 1);
    assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
    janos_console_admission_token_t legacy;
    assert(janos_console_admission_begin(&lease, "start_portal", NULL, 0,
                                         false, &legacy) == JANOS_CONSOLE_ADMIT);
    unsigned calls = baseline_calls;
    assert(wifi_analyzer_command(2, args) == 1);
    assert(baseline_calls == calls && prepare_calls == 0U);
    assert(janos_console_admission_end(&lease, legacy));
    buffers_ok = true;
    assert(wifi_analyzer_command(2, args) == 0);
    assert(janos_radio_lease_snapshot(&lease).state == JANOS_RADIO_LEASE_RUNNING);
    assert(prepare_calls == 1U);
    release(false);
    assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
    printf("PASS: analyzer reserve before baseline, busy wire and rollback\n");
}
