/* From FLIPPER in WSL:
 * cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Itests/stubs \
 *   tests/test_arp_module.c modules/arp/arp_module.c \
 *   -o /tmp/c5_arp_module_test && /tmp/c5_arp_module_test
 */
#include "../module_api.h"
#include "../modules/arp/arp_module.h"
#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_arp_plugin_ep(void);

typedef struct {
    char tx[4096];
    size_t tx_length;
    unsigned sends;
    unsigned redraws;
    unsigned input_requests;
    C5TextInputRequest input;
    char status[64];
} TestHost;

static bool send_raw_lines(void* context, const char* bytes, size_t length) {
    TestHost* host = context;
    assert(bytes && length && bytes[length - 1] == '\n');
    assert(length <= C5_MODULE_RAW_TX_MAX && !memchr(bytes, '\0', length));
    assert(length + host->tx_length < sizeof(host->tx));
    memcpy(host->tx + host->tx_length, bytes, length);
    host->tx_length += length;
    host->tx[host->tx_length] = '\0';
    host->sends++;
    return true;
}

static bool request_text_input(void* context, const C5TextInputRequest* request) {
    TestHost* host = context;
    assert(request);
    host->input = *request;
    host->input_requests++;
    return true;
}

static void request_redraw(void* context) { ((TestHost*)context)->redraws++; }
static void show_status(void* context, const char* message, uint32_t duration, bool fullscreen) {
    (void)duration;
    (void)fullscreen;
    snprintf(((TestHost*)context)->status, sizeof(((TestHost*)context)->status), "%s", message);
}

void canvas_set_color(Canvas* canvas, Color color) { (void)canvas; (void)color; }
void canvas_set_font(Canvas* canvas, Font font) { (void)canvas; (void)font; }
void canvas_draw_str(Canvas* canvas, int x, int y, const char* text) {
    (void)x;
    (void)y;
    if(canvas->line_count < 16) {
        snprintf(canvas->lines[canvas->line_count++], sizeof(canvas->lines[0]), "%s", text);
    }
}
void canvas_draw_str_aligned(Canvas* canvas, int x, int y, Align h, Align v, const char* text) {
    (void)h;
    (void)v;
    canvas_draw_str(canvas, x, y, text);
}
void canvas_draw_box(Canvas* canvas, int x, int y, int width, int height) {
    (void)canvas; (void)x; (void)y; (void)width; (void)height;
}
void canvas_draw_rbox(Canvas* canvas, int x, int y, int width, int height, int radius) {
    (void)canvas; (void)x; (void)y; (void)width; (void)height; (void)radius;
}
void canvas_draw_rframe(Canvas* canvas, int x, int y, int width, int height, int radius) {
    (void)canvas; (void)x; (void)y; (void)width; (void)height; (void)radius;
}

static const C5ModuleV3* module(void) {
    const FlipperAppPluginDescriptor* descriptor = lab_c5_arp_plugin_ep();
    assert(descriptor && descriptor->ep_api_version == C5_MODULE_API_VERSION);
    const C5ModuleV3* value = descriptor->entry_point;
    assert(value && value->version == C5_MODULE_API_VERSION && value->size == sizeof(*value));
    return value;
}

static C5HostApiV3 make_host(TestHost* state) {
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = state,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = request_redraw,
        .show_status = show_status,
    };
    return host;
}

static void feed(const C5ModuleV3* value, void* state, const C5HostApiV3* host, const char* data) {
    for(size_t i = 0; data[i]; i++) {
        value->on_bytes(state, host, (const uint8_t*)&data[i], 1);
    }
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

static void test_selected_target_uses_saved_secret_only_after_preflight(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .selected_number = 7,
        .ssid = "Lab Net",
        .saved_only = false,
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    assert(test.sends == 0);
    value->tick(state, &host, 1);
    assert(strcmp(test.tx, "select_networks 7\n") == 0);
    feed(value, state, &host, "Selected Networks:\nLab Net, 11:22:33:44:55:66, Ch6, WPA2\n>");
    assert(strcmp(test.tx, "select_networks 7\nshow_pass evil\n") == 0);
    feed(value, state, &host, "\"Lab\", \"wrong pass\"\n\"Lab Net\", \"valid pass\"\n>");
    assert(strcmp(test.tx,
                  "select_networks 7\nshow_pass evil\nwifi_connect \"Lab Net\" \"valid pass\"\n") == 0);
    assert(test.input_requests == 0);
    value->leave(state, &host);
}

static void test_saved_list_uses_chosen_record_without_web_handoff(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .selected_number = 0,
        .ssid = "",
        .saved_only = true,
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    assert(strcmp(test.tx, "show_pass evil\n") == 0);
    feed(value, state, &host, "\"Cafe\", \"first pass\"\n\"Lab Net\", \"second pass\"\n>");
    assert(drawn(value, state, &host, "Cafe"));
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    assert(value->on_input(state, &host, &down) == C5InputConsumed);
    assert(value->on_input(state, &host, &ok) == C5InputConsumed);
    assert(strcmp(test.tx, "show_pass evil\nwifi_connect \"Lab Net\" \"second pass\"\n") == 0);
    value->leave(state, &host);
}

static void test_selected_target_without_saved_record_requests_manual_password(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .selected_number = 3,
        .ssid = "Guest Net",
        .saved_only = false,
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    feed(value, state, &host, "Selected Networks:\n>");
    feed(value, state, &host, "\"Other\", \"irrelevant\"\n>");
    assert(test.input_requests == 1 && test.input.capacity == 64);
    assert(strcmp(test.tx, "select_networks 3\nshow_pass evil\n") == 0);
    value->on_text_input(state, &host, true, "manual pass");
    assert(strcmp(test.tx,
                  "select_networks 3\nshow_pass evil\nwifi_connect \"Guest Net\" \"manual pass\"\n") == 0);
    value->leave(state, &host);
}

static void test_host_rows_start_and_stop_require_firmware_ack(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .selected_number = 2,
        .ssid = "Lab",
        .saved_only = false,
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    feed(value, state, &host, "Selected Networks:\n>");
    feed(value, state, &host, "\"Lab\", \"valid pass\"\n>");
    feed(value, state, &host, "SUCCESS: Connected to 'Lab'\n");
    assert(strstr(test.tx, "list_hosts\n") == NULL);
    feed(value, state, &host, "DHCP IP: 192.168.1.9, Netmask: 255.255.255.0, GW: 192.168.1.1\n>");
    assert(strstr(test.tx, "list_hosts\n") != NULL);
    feed(value, state, &host,
         "=== Discovered Hosts ===\n"
         "  192.168.1.2  ->  AA:BB:CC:DD:EE:02  [ARP]\n"
         "  192.168.1.3  ->  (MAC unknown)  [ICMP]\n"
         "  999.168.1.4  ->  AA:BB:CC:DD:EE:04  [ARP]\n"
         "  192.168.1.2  ->  AA:BB:CC:DD:EE:02  [ARP]\n"
         "========================\nFound 4 hosts (2 via ARP, 2 via ICMP)\n>");
    assert(drawn(value, state, &host, "192.168.1.2"));
    assert(drawn(value, state, &host, "AA:BB:CC:DD:EE:02"));
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    assert(value->on_input(state, &host, &down) == C5InputIgnored);
    assert(value->on_input(state, &host, &ok) == C5InputConsumed);
    assert(strstr(test.tx, "arp_ban AA:BB:CC:DD:EE:02 192.168.1.2\n") != NULL);
    assert(!drawn(value, state, &host, "Active"));
    feed(value, state, &host, "Password: ARP ban started. Use 'stop' to stop.\n");
    assert(!drawn(value, state, &host, "Active"));
    feed(value, state, &host, "ARP ban started. Use 'stop' to stop.\n>");
    assert(drawn(value, state, &host, "Active"));
    assert(value->on_input(state, &host, &back) == C5InputConsumed);
    assert(strstr(test.tx, "stop\n") != NULL);
    assert(!drawn(value, state, &host, "Active"));
    feed(value, state, &host, "All operations stopped.\n>");
    assert(drawn(value, state, &host, "Stopped"));
    assert(value->on_input(state, &host, &back) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_saved_only_never_connects_without_usable_record(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .saved_only = true,
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    feed(value, state, &host, "\"Bad\", \"short\"\n\"Quote\", \"some\"\"pass\"\n>");
    assert(strcmp(test.tx, "show_pass evil\n") == 0);
    assert(drawn(value, state, &host, "No usable"));
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(value->on_input(state, &host, &back) == C5InputSwitchModule);
    value->leave(state, &host);
    assert(strcmp(test.tx, "show_pass evil\n") == 0);
}

static void test_manual_blank_password_uses_open_path_and_never_sends_saved_flag(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .selected_number = 1,
        .ssid = "Guest",
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    feed(value, state, &host, "Selected Networks:\n>");
    feed(value, state, &host, ">");
    assert(test.input_requests == 1);
    value->on_text_input(state, &host, true, "");
    assert(strcmp(test.tx, "select_networks 1\nshow_pass evil\nwifi_connect \"Guest\"\n") == 0);
    value->leave(state, &host);
}

static void test_rejects_truncated_or_unsafe_launch_ssid(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .selected_number = 1,
        .ssid = "12345678901234567890123456789012",
    };
    assert(value->enter(&host, &launch, sizeof(launch)) == NULL);
    snprintf(launch.ssid, sizeof(launch.ssid), "%s", "A\"B");
    assert(value->enter(&host, &launch, sizeof(launch)) == NULL);
    snprintf(launch.ssid, sizeof(launch.ssid), "%s", "Lab\nInjected");
    assert(value->enter(&host, &launch, sizeof(launch)) == NULL);
    launch.selected_number = 0;
    snprintf(launch.ssid, sizeof(launch.ssid), "%s", "Lab");
    assert(value->enter(&host, &launch, sizeof(launch)) == NULL);
}

static void test_missing_stop_ack_never_claims_stopped(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .selected_number = 1,
        .ssid = "Lab",
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(value->on_input(state, &host, &back) == C5InputConsumed);
    assert(drawn(value, state, &host, "Stopping"));
    InputEvent held_back = {.type = InputTypeRepeat, .key = InputKeyBack};
    assert(value->on_input(state, &host, &held_back) == C5InputIgnored);
    assert(strcmp(test.tx, "select_networks 1\nstop\n") == 0);
    assert(value->on_input(state, &host, &back) == C5InputConsumed);
    assert(strcmp(test.tx, "select_networks 1\nstop\nstop\n") == 0);
    assert(drawn(value, state, &host, "Stopping"));
    feed(value, state, &host, "Password: All operations stopped.\n");
    assert(drawn(value, state, &host, "Stopping"));
    feed(value, state, &host, "All operations stopped.\n>");
    assert(drawn(value, state, &host, "Stopped"));
    value->leave(state, &host);
}

static void test_malformed_or_unsupported_saved_rows_cannot_start_wifi(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .saved_only = true,
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    feed(value, state, &host,
         "\"Unclosed, \"valid pass\"\n"
         "\"Quote\"\"SSID\", \"valid pass\"\n"
         "\"Lab\", \"1234567890123456789012345678901234567890123456789012345678901234\"\n"
         "\"Backslash\", \"pass\\word\"\n>");
    assert(strcmp(test.tx, "show_pass evil\n") == 0);
    assert(drawn(value, state, &host, "No usable"));
    value->leave(state, &host);
}

static void test_overlong_uart_line_cannot_fake_a_prompt(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .selected_number = 4,
        .ssid = "Lab",
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    feed(value, state, &host, "Selected Networks:\n>");
    char long_line[280];
    memset(long_line, 'X', sizeof(long_line));
    long_line[250] = '>';
    long_line[251] = '\0';
    feed(value, state, &host, long_line);
    assert(strcmp(test.tx, "select_networks 4\nshow_pass evil\n") == 0);
    assert(test.input_requests == 0);
    feed(value, state, &host, "\n>");
    assert(test.input_requests == 1);
    value->leave(state, &host);
}

static void test_manual_password_rejects_cli_control_bytes(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .selected_number = 1,
        .ssid = "Lab",
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    feed(value, state, &host, "Selected Networks:\n>");
    feed(value, state, &host, ">");
    value->on_text_input(state, &host, true, "pass\nword");
    assert(strcmp(test.tx, "select_networks 1\nshow_pass evil\n") == 0);
    assert(drawn(value, state, &host, "Unsupported password"));
    value->leave(state, &host);
}

static void test_back_after_selection_sends_stop_before_exit(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .selected_number = 1,
        .ssid = "Lab",
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    feed(value, state, &host, "Selected Networks:\n>");
    feed(value, state, &host, ">");
    assert(test.input_requests == 1);
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(value->on_input(state, &host, &back) == C5InputConsumed);
    assert(strcmp(test.tx, "select_networks 1\nshow_pass evil\nstop\n") == 0);
    feed(value, state, &host, "All operations stopped.\n>");
    assert(value->on_input(state, &host, &back) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_saved_row_preserves_comma_and_spaces_inside_ssid(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .saved_only = true,
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    feed(value, state, &host, "\" Lab,Cafe \" , \"pass word\"\n>");
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    assert(value->on_input(state, &host, &ok) == C5InputConsumed);
    assert(strcmp(test.tx,
                  "show_pass evil\nwifi_connect \" Lab,Cafe \" \"pass word\"\n") == 0);
    assert(!drawn(value, state, &host, "pass word"));
    value->leave(state, &host);
}

static void test_failed_arp_start_never_appears_active(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5ArpLaunchContext launch = {
        .version = C5_ARP_LAUNCH_VERSION,
        .size = sizeof(C5ArpLaunchContext),
        .selected_number = 1,
        .ssid = "Lab",
    };
    void* state = value->enter(&host, &launch, sizeof(launch));
    assert(state);
    value->tick(state, &host, 1);
    feed(value, state, &host, "Selected Networks:\n>");
    feed(value, state, &host, "\"Lab\", \"valid pass\"\n>");
    feed(value, state, &host, "SUCCESS: Connected to 'Lab'\n>");
    feed(value, state, &host,
         "=== Discovered Hosts ===\n"
         "I (123) janos:   192.168.0.8  ->  AA:BB:CC:DD:EE:08  [ARP]\n"
         "========================\nFound 1 hosts (1 via ARP, 0 via ICMP)\n>");
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    assert(value->on_input(state, &host, &ok) == C5InputConsumed);
    feed(value, state, &host, "Could not find gateway MAC. Make sure you're connected to the network.\n>");
    assert(!drawn(value, state, &host, "Active"));
    assert(drawn(value, state, &host, "ARP start failed"));
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(value->on_input(state, &host, &back) == C5InputConsumed);
    assert(strstr(test.tx, "stop\n") != NULL);
    value->leave(state, &host);
}

int main(void) {
    test_selected_target_uses_saved_secret_only_after_preflight();
    test_saved_list_uses_chosen_record_without_web_handoff();
    test_selected_target_without_saved_record_requests_manual_password();
    test_host_rows_start_and_stop_require_firmware_ack();
    test_saved_only_never_connects_without_usable_record();
    test_manual_blank_password_uses_open_path_and_never_sends_saved_flag();
    test_rejects_truncated_or_unsafe_launch_ssid();
    test_missing_stop_ack_never_claims_stopped();
    test_malformed_or_unsupported_saved_rows_cannot_start_wifi();
    test_overlong_uart_line_cannot_fake_a_prompt();
    test_manual_password_rejects_cli_control_bytes();
    test_back_after_selection_sends_stop_before_exit();
    test_saved_row_preserves_comma_and_spaces_inside_ssid();
    test_failed_arp_start_never_appears_active();
    puts("ARP module tests passed");
    return 0;
}
