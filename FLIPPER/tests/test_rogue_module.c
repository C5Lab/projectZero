#include "../module_api.h"
#include "../modules/rogue/rogue_module.h"

#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_rogue_plugin_ep(void);

typedef struct {
    char commands[16][192];
    size_t command_count;
    C5TextInputRequest request;
    size_t input_requests;
    char status[64];
    size_t redraws;
    size_t unsafe_command_calls;
    size_t tx_failures_remaining;
} TestHost;

static void test_unsafe_send(void* ctx, const char* command) {
    (void)command;
    ((TestHost*)ctx)->unsafe_command_calls++;
}

static bool test_send(void* ctx, const char* batch, size_t length) {
    TestHost* host = ctx;
    assert(host && batch && length > 0 && length < sizeof(host->commands[0]));
    if(host->tx_failures_remaining) {
        host->tx_failures_remaining--;
        return false;
    }
    assert(batch[length - 1] == '\n' && host->command_count < 16);
    memcpy(host->commands[host->command_count], batch, length);
    host->commands[host->command_count++][length] = '\0';
    return true;
}

static bool test_request_input(void* ctx, const C5TextInputRequest* request) {
    TestHost* host = ctx;
    host->request = *request;
    host->input_requests++;
    return true;
}

static void test_redraw(void* ctx) {
    ((TestHost*)ctx)->redraws++;
}

static void test_status(void* ctx, const char* message, uint32_t duration, bool fullscreen) {
    (void)duration;
    (void)fullscreen;
    snprintf(((TestHost*)ctx)->status, sizeof(((TestHost*)ctx)->status), "%s", message);
}

void canvas_set_color(Canvas* canvas, Color color) { (void)canvas; (void)color; }
void canvas_set_font(Canvas* canvas, Font font) { (void)canvas; (void)font; }
void canvas_draw_str(Canvas* canvas, int x, int y, const char* value) {
    (void)x; (void)y;
    assert(canvas->line_count < 16);
    snprintf(canvas->lines[canvas->line_count++], sizeof(canvas->lines[0]), "%s", value);
}
void canvas_draw_box(Canvas* canvas, int x, int y, int width, int height) {
    (void)canvas; (void)x; (void)y; (void)width; (void)height;
}
void canvas_draw_str_aligned(
    Canvas* canvas, int x, int y, Align horizontal, Align vertical, const char* value) {
    (void)x; (void)y; (void)horizontal; (void)vertical;
    canvas_draw_str(canvas, x, y, value);
}

static bool canvas_has(const Canvas* canvas, const char* value) {
    for(size_t i = 0; i < canvas->line_count; i++) {
        if(strstr(canvas->lines[i], value)) return true;
    }
    return false;
}

static C5HostApiV3 test_api(TestHost* test) {
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = test,
        .send_command = test_unsafe_send,
        .send_raw_lines = test_send,
        .request_text_input = test_request_input,
        .request_redraw = test_redraw,
        .show_status = test_status,
    };
    return host;
}

static C5RogueLaunchContext test_launch(void) {
    C5RogueLaunchContext launch = {
        .version = C5_ROGUE_LAUNCH_VERSION,
        .size = sizeof(C5RogueLaunchContext),
        .selected_number = 7,
        .ssid = "Lab Guest",
        .bssid = "12:34:56:78:9A:BC",
        .ticks_per_second = 1000,
    };
    return launch;
}

static void test_feed(const C5ModuleV3* module, void* state, const C5HostApiV3* host,
                      const char* text) {
    module->on_bytes(state, host, (const uint8_t*)text, strlen(text));
}

static C5InputResult test_press(const C5ModuleV3* module, void* state,
                                const C5HostApiV3* host, InputKey key) {
    InputEvent event = {.type = InputTypeShort, .key = key};
    return module->on_input(state, host, &event);
}

static C5InputResult test_long_ok(const C5ModuleV3* module, void* state,
                                  const C5HostApiV3* host) {
    InputEvent event = {.type = InputTypeLong, .key = InputKeyOk};
    return module->on_input(state, host, &event);
}

static void test_launch_starts_password_lookup(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    assert(test.command_count == 1);
    assert(strcmp(test.commands[0], "show_pass evil\n") == 0);
    module->leave(state, &host);
}

static void test_manual_password_html_and_start_sequence(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    assert(module->on_text_input);

    test_feed(module, state, &host, "/sdcard/lab/eviltwin.txt not found on SD card.\n>");
    assert(test.input_requests == 1);
    assert(test.request.capacity == 64 && test.request.minimum_length == 8);
    assert(test.command_count == 1);

    module->on_text_input(state, &host, true, "password123");
    assert(test.command_count == 2 && strcmp(test.commands[1], "list_sd\n") == 0);
    test_feed(module, state, &host,
              "HTML files found on SD card:\n1 Login.html\n3 Other.html\n>");
    assert(test_press(module, state, &host, InputKeyDown) == C5InputConsumed);
    assert(test_press(module, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.command_count == 3 && strcmp(test.commands[2], "select_html 3\n") == 0);

    test_feed(module, state, &host, "Loaded HTML file: Other.html (123 bytes)\n>");
    assert(test.command_count == 4 && strcmp(test.commands[3], "select_networks 7\n") == 0);
    test_feed(module, state, &host,
              "Selected Networks:\nLab Guest, 12:34:56:78:9a:bc, Ch6, WPA2\n>");
    assert(test.command_count == 5);
    assert(strcmp(test.commands[4], "start_rogueap \"Lab Guest\" \"password123\"\n") == 0);
    test_feed(module, state, &host, "Password: Rogue AP started successfully!\n");
    Canvas premature = {0};
    module->draw(state, &host, &premature);
    assert(!canvas_has(&premature, "Clients: 0"));
    test_feed(module, state, &host,
              "Rogue AP started successfully!\nAP Name: Lab Guest (WPA2 protected)\n"
              "Password: password123\nCustom HTML loaded (123 bytes)\n>");
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Clients: 0") && canvas_has(&canvas, "Captured: 0"));
    assert(!canvas_has(&canvas, "password123"));
    test_feed(module, state, &host,
              "AP: Client connected - MAC: AA:BB:CC:DD:EE:FF\n"
              "Portal: Client count = 1\nPassword: visitorpass\n");
    memset(&canvas, 0, sizeof(canvas));
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Clients: 1") && canvas_has(&canvas, "Captured: 1"));
    assert(!canvas_has(&canvas, "visitorpass"));
    test_feed(module, state, &host,
              "AP: Client disconnected - MAC: AA:BB:CC:DD:EE:FF, AID: 1\n");
    memset(&canvas, 0, sizeof(canvas));
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Clients: 0"));
    assert(test_press(module, state, &host, InputKeyLeft) == C5InputConsumed);
    assert(test_long_ok(module, state, &host) == C5InputConsumed);
    assert(test.command_count == 5);
    assert(test_press(module, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 6 && strcmp(test.commands[5], "stop\n") == 0);
    assert(test_press(module, state, &host, InputKeyBack) == C5InputConsumed);
    test_feed(module, state, &host, "Password: All operations stopped.\n");
    assert(test_press(module, state, &host, InputKeyBack) == C5InputConsumed);
    test_feed(module, state, &host, "All operations stopped. extra\n");
    assert(test_press(module, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 6);
    test_feed(module, state, &host, "All operations stopped.\n>");
    assert(test_press(module, state, &host, InputKeyBack) == C5InputSwitchModule);
    module->leave(state, &host);
    assert(test.command_count == 6);
    assert(test.unsafe_command_calls == 0);
}

static void test_saved_password_skips_input(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    test_feed(module, state, &host, "\"Other\", \"unrelated123\"\n");
    test_feed(module, state, &host, "\"Lab Gu");
    test_feed(module, state, &host, "est\", \"correct123\"\n>");
    assert(test.input_requests == 0);
    assert(test.command_count == 2 && strcmp(test.commands[1], "list_sd\n") == 0);
    module->leave(state, &host);
}

static void test_conflicting_saved_passwords_require_manual_input(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    test_feed(module, state, &host,
              "\"Lab Guest\", \"firstpass\"\n"
              "\"Lab Guest\", \"otherpass\"\n"
              "\"Lab Guest\", \"firstpass\"\n>");
    assert(test.input_requests == 1);
    assert(test.command_count == 1);
    assert(strstr(test.request.header, "Saved passwords differ"));
    assert(test.request.initial[0] == '\0');
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Saved passwords differ"));
    module->on_text_input(state, &host, true, "manualpass");
    assert(test.command_count == 2 && strcmp(test.commands[1], "list_sd\n") == 0);
    module->leave(state, &host);
}

static void test_duplicate_identical_passwords_still_use_saved_value(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    test_feed(module, state, &host,
              "\"Lab Guest\", \"samepass\"\n"
              "\"Lab Guest\", \"samepass\"\n>");
    assert(test.input_requests == 0);
    assert(test.command_count == 2 && strcmp(test.commands[1], "list_sd\n") == 0);
    module->leave(state, &host);
}

static void test_overlong_password_reply_cannot_fake_prompt(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    char overlong[220];
    memset(overlong, 'A', 210);
    overlong[210] = '>';
    overlong[211] = '\0';
    test_feed(module, state, &host, overlong);
    assert(test.input_requests == 0 && test.command_count == 1);
    test_feed(module, state, &host, "\n>");
    assert(test.input_requests == 1);
    module->leave(state, &host);
}

static void test_invalid_launch_never_transmits(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    launch.selected_number = 0;
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch = test_launch();
    memset(launch.ssid, 'A', sizeof(launch.ssid));
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch = test_launch();
    strcpy(launch.ssid, "Bad\nSSID");
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch = test_launch();
    strcpy(launch.ssid, "Bad\"SSID");
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch = test_launch();
    strcpy(launch.bssid, "invalid");
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch = test_launch();
    launch.ticks_per_second = 0;
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    assert(test.command_count == 0 && test.unsafe_command_calls == 0);
}

static void test_password_validation_blocks_unsafe_start(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    test_feed(module, state, &host, ">");
    assert(test.input_requests == 1);
    module->on_text_input(state, &host, true, "short");
    module->on_text_input(state, &host, true, "bad\"password");
    module->on_text_input(state, &host, true, "bad\npassword");
    char too_long[65];
    memset(too_long, 'P', 64);
    too_long[64] = '\0';
    module->on_text_input(state, &host, true, too_long);
    char unterminated[64];
    memset(unterminated, 'P', sizeof(unterminated));
    module->on_text_input(state, &host, true, unterminated);
    assert(test.command_count == 1);
    module->on_text_input(state, &host, true, "good password");
    assert(test.command_count == 2 && strcmp(test.commands[1], "list_sd\n") == 0);
    module->leave(state, &host);
}

static void test_changed_scan_target_never_starts_ap(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    test_feed(module, state, &host, ">");
    module->on_text_input(state, &host, true, "password123");
    test_feed(module, state, &host, "HTML files found on SD card:\n1 Login.html\n>");
    test_press(module, state, &host, InputKeyOk);
    test_feed(module, state, &host, "Loaded HTML file: Login.html (30 bytes)\n>");
    test_feed(module, state, &host,
              "Selected Networks:\nLab Guest, 00:00:00:00:00:01, Ch6, WPA2\n>");
    assert(test.command_count == 4);
    assert(strstr(test.status, "Target changed"));
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Target changed"));
    assert(test_press(module, state, &host, InputKeyBack) == C5InputSwitchModule);
    module->leave(state, &host);
    assert(test.command_count == 4);
}

static void test_lookup_timeout_can_exit_without_start(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state && module->tick);
    module->tick(state, &host, 100);
    module->tick(state, &host, 5101);
    assert(strstr(test.status, "timed out"));
    assert(test.input_requests == 0 && test.command_count == 1);
    assert(test_press(module, state, &host, InputKeyBack) == C5InputSwitchModule);
    module->leave(state, &host);
}

static void test_full_length_ssid_and_password_are_preserved(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    memset(launch.ssid, 'S', 32);
    launch.ssid[32] = '\0';
    char password[64];
    memset(password, 'P', 63);
    password[63] = '\0';
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    char saved[128];
    snprintf(saved, sizeof(saved), "\"%s\", \"%s\"\n>", launch.ssid, password);
    test_feed(module, state, &host, saved);
    assert(test.input_requests == 0 && test.command_count == 2);
    test_feed(module, state, &host, "HTML files found on SD card:\n1 Login.html\n>");
    test_press(module, state, &host, InputKeyOk);
    test_feed(module, state, &host, "Loaded HTML file: Login.html (30 bytes)\n>");
    test_feed(module, state, &host,
              "Selected Networks:\nSSID, 12:34:56:78:9A:BC, Ch6, WPA2\n>");
    assert(test.command_count == 5);
    const char* command = test.commands[4];
    assert(strlen(command) == 115);
    assert(strncmp(command, "start_rogueap \"", 15) == 0);
    assert(memcmp(command + 15, launch.ssid, 32) == 0);
    assert(command[47] == '"' && command[48] == ' ' && command[49] == '"');
    assert(memcmp(command + 50, password, 63) == 0);
    assert(command[113] == '"' && command[114] == '\n');
    module->leave(state, &host);
    assert(test.command_count == 6 && strcmp(test.commands[5], "stop\n") == 0);
}

static void test_start_failure_and_failed_stop_remain_recoverable(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    test_feed(module, state, &host, ">");
    module->on_text_input(state, &host, true, "password123");
    test_feed(module, state, &host, "HTML files found on SD card:\n1 Login.html\n>");
    test_press(module, state, &host, InputKeyOk);
    test_feed(module, state, &host, "Loaded HTML file: Login.html (30 bytes)\n>");
    test_feed(module, state, &host,
              "Selected Networks:\nLab Guest, 12:34:56:78:9a:bc, Ch6, WPA2\n>");
    test_feed(module, state, &host,
              "Failed to start HTTP server: ESP_ERR_NO_MEM\n>");
    assert(strstr(test.status, "start failed"));
    assert(test.command_count == 5);
    test.tx_failures_remaining = 1;
    assert(test_press(module, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 5);
    assert(test_press(module, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 6 && strcmp(test.commands[5], "stop\n") == 0);
    test_feed(module, state, &host, "All operations stopped.\n>");
    assert(test_press(module, state, &host, InputKeyBack) == C5InputSwitchModule);
    module->leave(state, &host);
    assert(test.command_count == 6);
}

static void test_stop_timeout_is_visible_and_back_retries(void) {
    const C5ModuleV3* module = lab_c5_rogue_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = test_api(&test);
    C5RogueLaunchContext launch = test_launch();
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    test_feed(module, state, &host, ">");
    module->on_text_input(state, &host, true, "password123");
    test_feed(module, state, &host, "HTML files found on SD card:\n1 Login.html\n>");
    test_press(module, state, &host, InputKeyOk);
    test_feed(module, state, &host, "Loaded HTML file: Login.html (30 bytes)\n>");
    test_feed(module, state, &host,
              "Selected Networks:\nLab Guest, 12:34:56:78:9a:bc, Ch6, WPA2\n>");
    test_feed(module, state, &host, "Rogue AP started successfully!\n>");
    test_feed(module, state, &host, "All operations stopped.\n");
    assert(test_press(module, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 6);
    module->tick(state, &host, 100);
    module->tick(state, &host, 5101);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "No stop ACK"));
    assert(test_press(module, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 7 && strcmp(test.commands[6], "stop\n") == 0);
    test_feed(module, state, &host, "All operations stopped.\n>");
    assert(test_press(module, state, &host, InputKeyBack) == C5InputSwitchModule);
    module->leave(state, &host);
    assert(test.command_count == 7);
}

int main(void) {
    test_launch_starts_password_lookup();
    test_manual_password_html_and_start_sequence();
    test_saved_password_skips_input();
    test_conflicting_saved_passwords_require_manual_input();
    test_duplicate_identical_passwords_still_use_saved_value();
    test_overlong_password_reply_cannot_fake_prompt();
    test_invalid_launch_never_transmits();
    test_password_validation_blocks_unsafe_start();
    test_changed_scan_target_never_starts_ap();
    test_lookup_timeout_can_exit_without_start();
    test_full_length_ssid_and_password_are_preserved();
    test_start_failure_and_failed_stop_remain_recoverable();
    test_stop_timeout_is_visible_and_back_retries();
    puts("rogue module tests passed");
    return 0;
}
