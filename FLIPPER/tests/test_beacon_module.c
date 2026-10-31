/* From FLIPPER in WSL:
 * cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Itests/stubs \
 *   tests/test_beacon_module.c modules/beacon/beacon_module.c \
 *   -o /tmp/c5_beacon_module_test && /tmp/c5_beacon_module_test
 */
#include "../module_api.h"
#include "../modules/beacon/beacon_module.h"

#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_beacon_plugin_ep(void);

typedef struct {
    char commands[24][96];
    size_t command_count;
    C5TextInputRequest request;
    size_t input_requests;
    size_t redraws;
    size_t unsafe_sends;
    size_t fail_next_send;
    char status[80];
} TestHost;

static bool send_raw(void* context, const char* bytes, size_t length) {
    TestHost* test = context;
    assert(bytes && length && length < sizeof(test->commands[0]));
    assert(bytes[length - 1] == '\n' && !memchr(bytes, '\0', length));
    assert(test->command_count < 24);
    if(test->fail_next_send) {
        test->fail_next_send--;
        return false;
    }
    memcpy(test->commands[test->command_count], bytes, length);
    test->commands[test->command_count++][length] = '\0';
    return true;
}

static void unsafe_send(void* context, const char* command) {
    (void)command;
    ((TestHost*)context)->unsafe_sends++;
}

static bool request_input(void* context, const C5TextInputRequest* request) {
    TestHost* test = context;
    test->request = *request;
    test->input_requests++;
    return true;
}

static void redraw(void* context) { ((TestHost*)context)->redraws++; }

static void status(void* context, const char* message, uint32_t duration, bool fullscreen) {
    (void)duration;
    (void)fullscreen;
    snprintf(((TestHost*)context)->status, sizeof(((TestHost*)context)->status), "%s", message);
}

void canvas_set_color(Canvas* canvas, Color color) { (void)canvas; (void)color; }
void canvas_set_font(Canvas* canvas, Font font) { (void)canvas; (void)font; }
void canvas_draw_str(Canvas* canvas, int x, int y, const char* value) {
    (void)x;
    (void)y;
    assert(canvas->line_count < 16);
    snprintf(canvas->lines[canvas->line_count++], sizeof(canvas->lines[0]), "%s", value);
}
void canvas_draw_str_aligned(Canvas* canvas, int x, int y, Align h, Align v, const char* value) {
    (void)h;
    (void)v;
    canvas_draw_str(canvas, x, y, value);
}
void canvas_draw_box(Canvas* canvas, int x, int y, int width, int height) {
    (void)canvas; (void)x; (void)y; (void)width; (void)height;
}

static const C5ModuleV3* module(void) {
    const FlipperAppPluginDescriptor* descriptor = lab_c5_beacon_plugin_ep();
    assert(descriptor && strcmp(descriptor->appid, C5_MODULE_APP_ID) == 0);
    assert(descriptor->ep_api_version == C5_MODULE_API_VERSION);
    const C5ModuleV3* value = descriptor->entry_point;
    assert(value && value->version == C5_MODULE_API_VERSION && value->size == sizeof(*value));
    return value;
}

static C5HostApiV3 host_api(TestHost* test) {
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = test,
        .send_command = unsafe_send,
        .send_raw_lines = send_raw,
        .request_text_input = request_input,
        .request_redraw = redraw,
        .show_status = status,
    };
    return host;
}

static C5BeaconLaunchContext launch(void) {
    C5BeaconLaunchContext context = {
        .version = C5_BEACON_LAUNCH_VERSION,
        .size = sizeof(C5BeaconLaunchContext),
        .ticks_per_second = 1000,
    };
    return context;
}

static void* enter(const C5ModuleV3* value, const C5HostApiV3* host) {
    C5BeaconLaunchContext context = launch();
    return value->enter(host, &context, sizeof(context));
}

static void feed(const C5ModuleV3* value, void* state, const C5HostApiV3* host, const char* data) {
    for(size_t i = 0; data[i]; i++) {
        value->on_bytes(state, host, (const uint8_t*)&data[i], 1);
    }
}

static C5InputResult press(const C5ModuleV3* value, void* state,
                           const C5HostApiV3* host, InputKey key) {
    InputEvent event = {.type = InputTypeShort, .key = key};
    return value->on_input(state, host, &event);
}

static bool drawn(const C5ModuleV3* value, void* state,
                  const C5HostApiV3* host, const char* fragment) {
    Canvas canvas = {0};
    value->draw(state, host, &canvas);
    for(size_t i = 0; i < canvas.line_count; i++) {
        if(strstr(canvas.lines[i], fragment)) return true;
    }
    return false;
}

static void test_launch_and_empty_list(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    C5BeaconLaunchContext context = launch();
    assert(!value->enter(&host, NULL, 0));
    assert(!value->enter(&host, &context, sizeof(context) - 1));
    context.ticks_per_second = 0;
    assert(!value->enter(&host, &context, sizeof(context)));
    context = launch();
    C5HostApiV3 wrong_host = host;
    wrong_host.version++;
    assert(!value->enter(&wrong_host, &context, sizeof(context)));
    void* state = enter(value, &host);
    assert(state && test.command_count == 1 && strcmp(test.commands[0], "list_ssids\n") == 0);
    feed(value, state, &host, "ssids.txt is empty.\r\n> ");
    assert(drawn(value, state, &host, "0/64"));
    assert(drawn(value, state, &host, "No SSIDs"));
    assert(drawn(value, state, &host, "32 on air"));
    assert(press(value, state, &host, InputKeyRight) == C5InputConsumed);
    assert(test.command_count == 1);
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
    assert(test.command_count == 1 && test.unsafe_sends == 0);
}

static void test_janos_prefixed_list_start_and_stop(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host);
    assert(state);
    feed(value, state, &host, "I (42) projectZero: 1 Home\n> ");
    assert(drawn(value, state, &host, "1/64"));
    assert(press(value, state, &host, InputKeyRight) == C5InputConsumed);
    assert(strcmp(test.commands[1], "start_beacon_spam_ssids\n") == 0);
    feed(value, state, &host, "I (43) projectZero: Beacon spam started. Use 'stop' to end.\n>");
    assert(drawn(value, state, &host, "Active (ACK)"));
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(strcmp(test.commands[2], "stop\n") == 0);
    feed(value, state, &host, "I (44) projectZero: All operations stopped.\n>");
    assert(drawn(value, state, &host, "Stopped (ACK)"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_indexed_remove_requires_ack_and_refresh(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host);
    assert(state);
    feed(value, state, &host, "1 Home\n2 Lab, \"Guest\"\n>");
    assert(drawn(value, state, &host, "2/64"));
    assert(press(value, state, &host, InputKeyDown) == C5InputConsumed);
    assert(drawn(value, state, &host, "Lab, \"Guest\""));
    assert(press(value, state, &host, InputKeyLeft) == C5InputConsumed);
    assert(drawn(value, state, &host, "Remove"));
    assert(test.command_count == 1);
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 1);
    assert(press(value, state, &host, InputKeyLeft) == C5InputConsumed);
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.command_count == 2 && strcmp(test.commands[1], "remove_ssid 2\n") == 0);
    assert(drawn(value, state, &host, "Removing"));
    feed(value, state, &host, "SSID removed. 1 SSIDs remaining.\n>");
    assert(test.command_count == 3 && strcmp(test.commands[2], "list_ssids\n") == 0);
    feed(value, state, &host, "1 Home\n>");
    assert(drawn(value, state, &host, "1/64"));
    value->leave(state, &host);
}

static void test_add_rejects_injection_and_refreshes_only_after_ack(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host);
    assert(state);
    feed(value, state, &host, "ssids.txt not found on SD card.\n>");
    assert(drawn(value, state, &host, "0/64"));
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.input_requests == 1 && test.request.capacity == 33);
    const char* bad[] = {"", "Bad\nSSID", "Bad\rSSID", "Bad\"SSID", "Bad\\SSID",
                         "123456789012345678901234567890123"};
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        value->on_text_input(state, &host, true, bad[i]);
        assert(test.command_count == 1);
    }
    value->on_text_input(state, &host, true, "Lab, Room");
    assert(test.command_count == 2 && strcmp(test.commands[1], "add_ssid \"Lab, Room\"\n") == 0);
    assert(drawn(value, state, &host, "Adding"));
    feed(value, state, &host, "Added SSID: Lab, Room\n>");
    assert(test.command_count == 3 && strcmp(test.commands[2], "list_ssids\n") == 0);
    feed(value, state, &host, "1 Lab, Room\n>");
    assert(drawn(value, state, &host, "1/64"));
    assert(test.unsafe_sends == 0);
    value->leave(state, &host);
}

static void bad_list(const char* transcript) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host);
    assert(state);
    feed(value, state, &host, transcript);
    assert(drawn(value, state, &host, "List invalid"));
    assert(press(value, state, &host, InputKeyRight) == C5InputConsumed);
    assert(test.command_count == 1);
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_malformed_list_cannot_start(void) {
    bad_list("1 Home\n3 Gap\n>");
    bad_list("1 Home\n1 Duplicate\n>");
    bad_list("1\n>");
    bad_list("1 123456789012345678901234567890123\n>");
    bad_list("1 Home\n2 Bad\rName\n>");
    bad_list("1 Home\n2 A\001B\n>");
    bad_list("Failed to initialize SD card: ESP_FAIL\n>");
    char too_long[280];
    memset(too_long, 'X', sizeof(too_long));
    too_long[0] = '1';
    too_long[1] = ' ';
    too_long[sizeof(too_long) - 3] = '\n';
    too_long[sizeof(too_long) - 2] = '>';
    too_long[sizeof(too_long) - 1] = '\0';
    bad_list(too_long);
}

static void test_full_list_disables_add_and_notices_transmit_limit(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host);
    assert(state);
    for(unsigned i = 1; i <= 64; i++) {
        char row[32];
        snprintf(row, sizeof(row), "%u SSID%u\n", i, i);
        feed(value, state, &host, row);
    }
    feed(value, state, &host, ">");
    assert(drawn(value, state, &host, "64/64"));
    assert(drawn(value, state, &host, "32 on air"));
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.input_requests == 0 && test.command_count == 1);
    assert(press(value, state, &host, InputKeyRight) == C5InputConsumed);
    assert(test.command_count == 2 && strcmp(test.commands[1], "start_beacon_spam_ssids\n") == 0);
    value->leave(state, &host);
    assert(test.command_count == 3 && strcmp(test.commands[2], "stop\n") == 0);
}

static void test_start_needs_exact_ack_and_failed_start_is_not_active(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host);
    assert(state);
    feed(value, state, &host, "1 Home\n>");
    assert(press(value, state, &host, InputKeyRight) == C5InputConsumed);
    assert(drawn(value, state, &host, "Starting"));
    assert(!drawn(value, state, &host, "Active"));
    feed(value, state, &host, "Beacon spam started eventually\n");
    assert(!drawn(value, state, &host, "Active"));
    feed(value, state, &host, "Failed to initialize SD card: ESP_FAIL\n>");
    assert(!drawn(value, state, &host, "Active"));
    assert(drawn(value, state, &host, "Start not confirmed"));
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 3 && strcmp(test.commands[2], "stop\n") == 0);
    feed(value, state, &host, "All operations stopped.\n>");
    assert(drawn(value, state, &host, "Stopped"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
    assert(test.command_count == 3);
}

static void test_start_timeout_and_stop_timeout_keep_uncertainty_visible(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host);
    assert(state);
    feed(value, state, &host, "1 Home\n>");
    assert(press(value, state, &host, InputKeyRight) == C5InputConsumed);
    value->tick(state, &host, 100);
    value->tick(state, &host, 15101);
    assert(drawn(value, state, &host, "Start not confirmed"));
    assert(!drawn(value, state, &host, "Active"));
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    value->tick(state, &host, 20000);
    value->tick(state, &host, 25001);
    assert(drawn(value, state, &host, "No stop ACK"));
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 4 && strcmp(test.commands[3], "stop\n") == 0);
    feed(value, state, &host, "All operations stopped.\n>");
    assert(drawn(value, state, &host, "Stopped"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
    assert(test.command_count == 4);
}

static void test_confirmed_active_stops_only_after_ack(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host);
    assert(state);
    feed(value, state, &host, "1 Home\n>");
    press(value, state, &host, InputKeyRight);
    feed(value, state, &host, "Beacon spam started. Use 'stop' to end.\n>");
    assert(drawn(value, state, &host, "Active"));
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(drawn(value, state, &host, "Stopping"));
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 3 && strcmp(test.commands[2], "stop\n") == 0);
    feed(value, state, &host, "> ");
    assert(drawn(value, state, &host, "No stop ACK"));
    feed(value, state, &host, "All operations stopped.\n>");
    assert(drawn(value, state, &host, "Stopped"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
    assert(test.command_count == 3);
}

static void test_unconfirmed_edit_does_not_change_list_or_trap_back(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host);
    assert(state);
    feed(value, state, &host, "1 Home\n>");
    press(value, state, &host, InputKeyOk);
    value->on_text_input(state, &host, true, "Second");
    assert(test.command_count == 2);
    feed(value, state, &host, "Failed to open ssids.txt for writing\n>");
    assert(drawn(value, state, &host, "Edit not confirmed"));
    assert(!drawn(value, state, &host, "2/64"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
    assert(test.command_count == 2);
}

static void test_failed_start_send_never_marks_possible_active(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host);
    assert(state);
    feed(value, state, &host, "1 Home\n>");
    test.fail_next_send = 1;
    press(value, state, &host, InputKeyRight);
    assert(drawn(value, state, &host, "Start command failed"));
    assert(!drawn(value, state, &host, "Active"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
    assert(test.command_count == 1);
}

static void test_stop_tx_failure_stays_uncertain_and_can_retry(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host);
    assert(state);
    feed(value, state, &host, "1 Home\n>");
    press(value, state, &host, InputKeyRight);
    feed(value, state, &host, "Beacon spam started. Use 'stop' to end.\n>");
    test.fail_next_send = 1;
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(drawn(value, state, &host, "Stop TX failed"));
    assert(test.command_count == 2);
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 3 && strcmp(test.commands[2], "stop\n") == 0);
    feed(value, state, &host, "All operations stopped.\n>");
    assert(drawn(value, state, &host, "Stopped"));
    value->leave(state, &host);
    assert(test.command_count == 3);
}

int main(void) {
    test_launch_and_empty_list();
    test_janos_prefixed_list_start_and_stop();
    test_indexed_remove_requires_ack_and_refresh();
    test_add_rejects_injection_and_refreshes_only_after_ack();
    test_malformed_list_cannot_start();
    test_full_list_disables_add_and_notices_transmit_limit();
    test_start_needs_exact_ack_and_failed_start_is_not_active();
    test_start_timeout_and_stop_timeout_keep_uncertainty_visible();
    test_confirmed_active_stops_only_after_ack();
    test_unconfirmed_edit_does_not_change_list_or_trap_back();
    test_failed_start_send_never_marks_possible_active();
    test_stop_tx_failure_stays_uncertain_and_can_retry();
    puts("beacon module host tests passed");
    return 0;
}
