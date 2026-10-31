/* From FLIPPER in WSL:
 * cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Itests/stubs \
 *   tests/test_wardrive_module.c modules/wardrive/wardrive_module.c \
 *   -o /tmp/c5_wardrive_module_test && /tmp/c5_wardrive_module_test
 * Transcript strings below come from ESP32C5/main/main.c's JanOS emitters.
 */
#include "../module_api.h"
#include "../modules/wardrive/wardrive_module.h"
#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_wardrive_plugin_ep(void);

typedef struct {
    char tx[1024];
    size_t tx_length;
    unsigned sends;
    unsigned redraws;
} TestHost;

static bool send_raw_lines(void* context, const char* bytes, size_t length) {
    TestHost* test = context;
    assert(bytes && length && bytes[length - 1] == '\n');
    assert(length <= C5_MODULE_RAW_TX_MAX && !memchr(bytes, '\0', length));
    assert(test->tx_length + length < sizeof(test->tx));
    memcpy(test->tx + test->tx_length, bytes, length);
    test->tx_length += length;
    test->tx[test->tx_length] = '\0';
    test->sends++;
    return true;
}

static void redraw(void* context) { ((TestHost*)context)->redraws++; }
void canvas_set_color(Canvas* canvas, Color color) { (void)canvas; (void)color; }
void canvas_set_font(Canvas* canvas, Font font) { (void)canvas; (void)font; }
void canvas_draw_str(Canvas* canvas, int x, int y, const char* value) {
    (void)x;
    (void)y;
    if(canvas->line_count < 16) {
        snprintf(canvas->lines[canvas->line_count++], sizeof(canvas->lines[0]), "%s", value);
    }
}

static C5HostApiV3 make_host(TestHost* test) {
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = test,
        .send_raw_lines = send_raw_lines,
        .request_redraw = redraw,
    };
    return host;
}

static const C5ModuleV3* module(void) {
    const FlipperAppPluginDescriptor* descriptor = lab_c5_wardrive_plugin_ep();
    assert(descriptor && descriptor->ep_api_version == C5_MODULE_API_VERSION);
    assert(strcmp(descriptor->appid, C5_MODULE_APP_ID) == 0);
    const C5ModuleV3* value = descriptor->entry_point;
    assert(value && value->version == C5_MODULE_API_VERSION && value->size == sizeof(*value));
    assert(value->enter && value->leave && value->on_bytes && value->on_input && value->draw && value->tick);
    return value;
}

static C5WardriveLaunchContext launch(C5WardriveMode mode) {
    C5WardriveLaunchContext context = {
        .version = C5_WARDRIVE_LAUNCH_VERSION,
        .size = sizeof(C5WardriveLaunchContext),
        .mode = mode,
        .ticks_per_second = 1000,
    };
    return context;
}

static void* enter(const C5ModuleV3* value, const C5HostApiV3* host, C5WardriveMode mode) {
    C5WardriveLaunchContext context = launch(mode);
    void* state = value->enter(host, &context, sizeof(context));
    assert(state);
    return state;
}

static void feed(const C5ModuleV3* value, void* state, const C5HostApiV3* host, const char* data) {
    size_t length = strlen(data);
    size_t split = length / 3;
    value->on_bytes(state, host, (const uint8_t*)data, split);
    value->on_bytes(state, host, (const uint8_t*)data + split, length - split);
}

static bool drawn(const C5ModuleV3* value, void* state, const C5HostApiV3* host,
                  const char* expected) {
    Canvas canvas = {0};
    value->draw(state, host, &canvas);
    for(size_t i = 0; i < canvas.line_count; i++) {
        if(strstr(canvas.lines[i], expected)) return true;
    }
    return false;
}

static void test_launch_selects_exact_command_and_rejects_bad_context(void) {
    const C5ModuleV3* value = module();
    const char* commands[] = {
        "start_wardrive\n",
        "start_wardrive_promisc\n",
        "start_wardrive_promisc_trace\n",
    };
    for(unsigned mode = 0; mode < 3; mode++) {
        TestHost test = {0};
        C5HostApiV3 host = make_host(&test);
        C5WardriveLaunchContext context = launch((C5WardriveMode)mode);
        context.version++;
        assert(value->enter(&host, &context, sizeof(context)) == NULL);
        context.version--;
        context.ticks_per_second = 0;
        assert(value->enter(&host, &context, sizeof(context)) == NULL);
        context.ticks_per_second = 1000;
        assert(value->enter(&host, &context, sizeof(context) - 1) == NULL);
        void* state = value->enter(&host, &context, sizeof(context));
        assert(state && test.sends == 0);
        value->tick(state, &host, 10);
        value->tick(state, &host, 11);
        assert(strcmp(test.tx, commands[mode]) == 0 && test.sends == 1);
        value->leave(state, &host);
    }
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5WardriveLaunchContext context = launch((C5WardriveMode)3);
    assert(value->enter(&host, &context, sizeof(context)) == NULL);
}

static void test_legacy_start_ack_requires_fix_and_actual_start(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, C5WardriveModeLegacy);
    value->tick(state, &host, 10);
    assert(drawn(value, state, &host, "Starting"));
    assert(drawn(value, state, &host, "SD: --"));
    feed(value, state, &host,
         "SD card initialized on pins MISO:1 MOSI:2 CLK:3 CS:4\n"
         "Wardrive task started. Use 'stop' to stop.\n"
         "Waiting for GPS fix...\n");
    assert(drawn(value, state, &host, "Waiting GPS"));
    assert(drawn(value, state, &host, "SD: ready"));
    assert(!drawn(value, state, &host, "Active"));
    feed(value, state, &host, "I (204) projectZero: GPS fix obtained: Lat=52.2297000 Lon=21.0122000\n");
    assert(!drawn(value, state, &host, "Active"));
    feed(value, state, &host,
         "Password: projectZero: Wardrive started. Use 'stop' command to stop.\n");
    assert(!drawn(value, state, &host, "Active"));
    feed(value, state, &host, "I (205) projectZero: Wardrive started. Use 'stop' command to stop.\n");
    assert(drawn(value, state, &host, "Active"));
    assert(drawn(value, state, &host, "52.2297"));
    feed(value, state, &host, "I (206) projectZero: GPS fix lost! Pausing wardrive...\n");
    assert(drawn(value, state, &host, "GPS lost"));
    assert(!drawn(value, state, &host, "52.2297"));
    feed(value, state, &host,
         "I (207) projectZero: GPS fix recovered: Lat=52.2301000 Lon=21.0133000. Resuming wardrive.\n");
    assert(drawn(value, state, &host, "Active"));
    assert(drawn(value, state, &host, "52.2301"));
    value->leave(state, &host);
}

static void test_promisc_csv_quotes_and_periodic_counts_do_not_double_count(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, C5WardriveModePromiscTrace);
    value->tick(state, &host, 10);
    feed(value, state, &host,
         "I (300) projectZero: Wardrive promisc task started. Use 'stop' to stop.\n"
         "I (301) projectZero: Waiting for GPS fix (no timeout - use 'stop' to cancel)...\n");
    assert(drawn(value, state, &host, "Waiting GPS"));
    assert(!drawn(value, state, &host, "Active"));
    feed(value, state, &host,
         "I (302) projectZero: GPS fix obtained: Lat=52.2297000 Lon=21.0122000\n"
         "I (303) projectZero: Wardrive trace enabled: /sdcard/lab/wardrives/w1_track.inprogress.kml\n"
         "I (304) projectZero: Promiscuous wardrive started. Bands: wifi24,ble, WiFi channels: 11\n");
    assert(drawn(value, state, &host, "Active"));
    feed(value, state, &host,
         "AA:BB:CC:DD:EE:01,\"Lab, \"\"Guest\"\"\",[WPA2],2026-10-30 12:00:00,6,-55,52.2297000,21.0122000,100.00,3.00,WIFI\n");
    assert(drawn(value, state, &host, "Lab, \"Guest\""));
    assert(drawn(value, state, &host, "WiFi: --"));
    const char* stats = "I (305) projectZero: Wardrive promisc: 3 unique networks, 2 BT devices, 0 relogs, D-UCB best ch: 6 (4 visits), GPS: valid, sats: 7, dist: 67.3m\n";
    feed(value, state, &host, stats);
    feed(value, state, &host, stats);
    feed(value, state, &host,
         "I (306) projectZero: Flushed 3 networks + 2 BT devices to /sdcard/lab/wardrives/w1.log\n");
    assert(drawn(value, state, &host, "WiFi: 3 BT: 2"));
    feed(value, state, &host,
         "I (307) projectZero: Wardrive promisc: 4 unique networks, 2 BT devices, 1 relogs, D-UCB best ch: 6 (5 visits), GPS: valid, sats: 7, dist: 68.0m\n");
    assert(drawn(value, state, &host, "WiFi: 4 BT: 2"));
    value->leave(state, &host);
}

static void test_legacy_logged_report_is_last_batch_not_added_to_csv_rows(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, C5WardriveModeLegacy);
    value->tick(state, &host, 10);
    feed(value, state, &host,
         "AA:BB:CC:DD:EE:01,\"Cafe, North\",[WPA2],2026-10-30 12:00:00,6,2437,-55,52.2297000,21.0122000,100.00,3.00,,,WIFI\n"
         "AA:BB:CC:DD:EE:02,Other,[OPEN],2026-10-30 12:00:00,6,2437,-70,52.2297000,21.0122000,100.00,3.00,,,WIFI\n"
         "I (400) projectZero: Logged 2 networks to /sdcard/lab/wardrives/w1.log\n");
    assert(drawn(value, state, &host, "WiFi: 2"));
    assert(drawn(value, state, &host, "SSID: Other"));
    feed(value, state, &host, "I (400) projectZero: Logged 2 networks to /sdcard/lab/wardrives/w1.log\n");
    assert(drawn(value, state, &host, "WiFi: 2"));
    feed(value, state, &host, "I (500) projectZero: Logged 1 networks to /sdcard/lab/wardrives/w1.log\n");
    assert(drawn(value, state, &host, "WiFi: 1"));
    value->leave(state, &host);
}

static void test_missing_gps_or_sd_never_claims_active(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, C5WardriveModeLegacy);
    value->tick(state, &host, 1);
    feed(value, state, &host,
         "I (100) projectZero: Failed to initialize SD card: ESP_FAIL\n");
    assert(drawn(value, state, &host, "SD: failed"));
    assert(!drawn(value, state, &host, "Active"));
    value->leave(state, &host);

    test = (TestHost){0};
    host = make_host(&test);
    state = enter(value, &host, C5WardriveModeLegacy);
    value->tick(state, &host, 1);
    feed(value, state, &host,
         "I (101) projectZero: Wardrive task started. Use 'stop' to stop.\n"
         "I (102) projectZero: Warning: No GPS fix obtained, not continuing without GPS data - please ensure clear view of the sky and try again.\n"
         "I (103) projectZero: Wardrive started. Use 'stop' command to stop.\n");
    assert(!drawn(value, state, &host, "Active"));
    assert(drawn(value, state, &host, "No GPS fix"));
    value->leave(state, &host);

    test = (TestHost){0};
    host = make_host(&test);
    state = enter(value, &host, C5WardriveModeLegacy);
    value->tick(state, &host, 1);
    /* A dropped task-start line must not hide the explicit GPS failure. */
    feed(value, state, &host,
         "I (102) projectZero: Warning: No GPS fix obtained, not continuing without GPS data - please ensure clear view of the sky and try again.\n");
    assert(drawn(value, state, &host, "No GPS fix"));
    assert(!drawn(value, state, &host, "Active"));
    value->leave(state, &host);
}

static void test_back_waits_for_explicit_stop_ack_and_timeout_can_retry(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, C5WardriveModePromisc);
    value->tick(state, &host, 1000);
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(value->on_input(state, &host, &back) == C5InputConsumed);
    assert(strcmp(test.tx, "start_wardrive_promisc\nstop\n") == 0);
    assert(drawn(value, state, &host, "Stopping"));
    feed(value, state, &host, "I (2000) projectZero: All operations stopped.\n");
    assert(!drawn(value, state, &host, "Stopped"));
    value->tick(state, &host, 7000);
    assert(drawn(value, state, &host, "Stop unconfirmed"));
    assert(value->on_input(state, &host, &back) == C5InputConsumed);
    assert(strcmp(test.tx, "start_wardrive_promisc\nstop\nstop\n") == 0);
    feed(value, state, &host, "[WARDRIVE] STOPPED running=1\n");
    assert(drawn(value, state, &host, "Stopped"));
    assert(value->on_input(state, &host, &back) == C5InputSwitchModule);
    value->leave(state, &host);
    assert(test.sends == 3);
}

static void test_back_before_start_exits_without_uart_and_reentry_resets_state(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    void* state = enter(value, &host, C5WardriveModeLegacy);
    assert(value->on_input(state, &host, &back) == C5InputSwitchModule);
    value->leave(state, &host);
    assert(test.sends == 0);
    state = enter(value, &host, C5WardriveModePromisc);
    assert(drawn(value, state, &host, "WiFi: --"));
    value->tick(state, &host, 1);
    feed(value, state, &host,
         "I (200) projectZero: Wardrive promisc: 9 unique networks, 2 BT devices, 0 relogs, D-UCB best ch: 6 (4 visits), GPS: no fix, sats: 0, dist: 0.0m\n");
    assert(drawn(value, state, &host, "WiFi: 9 BT: 2"));
    value->leave(state, &host);
    state = enter(value, &host, C5WardriveModePromiscTrace);
    assert(drawn(value, state, &host, "WiFi: --"));
    value->leave(state, &host);
}

static void test_overlong_uart_line_cannot_forge_start(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, C5WardriveModeLegacy);
    value->tick(state, &host, 1);
    char long_line[400];
    memset(long_line, 'X', sizeof(long_line));
    memcpy(long_line + 310, "Wardrive started. Use 'stop' command to stop.", 45);
    long_line[399] = '\0';
    feed(value, state, &host, long_line);
    feed(value, state, &host, "\nI (3) projectZero: Wardrive task started. Use 'stop' to stop.\n");
    assert(!drawn(value, state, &host, "Active"));
    value->leave(state, &host);
}

int main(void) {
    test_launch_selects_exact_command_and_rejects_bad_context();
    test_legacy_start_ack_requires_fix_and_actual_start();
    test_promisc_csv_quotes_and_periodic_counts_do_not_double_count();
    test_legacy_logged_report_is_last_batch_not_added_to_csv_rows();
    test_missing_gps_or_sd_never_claims_active();
    test_back_waits_for_explicit_stop_ack_and_timeout_can_retry();
    test_back_before_start_exits_without_uart_and_reentry_resets_state();
    test_overlong_uart_line_cannot_forge_start();
    puts("Wardrive module tests passed");
    return 0;
}
