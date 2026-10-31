/* From FLIPPER in WSL:
 * cc -std=c11 -Wall -Wextra -Werror -Wdouble-promotion -fsanitize=address,undefined \
 *   -Itests/stubs tests/test_mitm_pcap_module.c modules/mitm_pcap/mitm_pcap_module.c \
 *   -o /tmp/c5_mitm_pcap_test && /tmp/c5_mitm_pcap_test
 * Fixtures follow the JanOS strings in ESP32C5/main/main.c.
 */
#include "../module_api.h"
#include "../modules/mitm_pcap/mitm_pcap_module.h"
#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_mitm_pcap_plugin_ep(void);

typedef struct {
    char commands[16][192];
    size_t command_count;
    unsigned unsafe_sends;
    unsigned redraws;
    unsigned input_requests;
    C5TextInputRequest input;
    char status[80];
} TestHost;

static void unsafe_send(void* ctx, const char* command) {
    (void)command;
    ((TestHost*)ctx)->unsafe_sends++;
}
static bool send_raw(void* ctx, const char* bytes, size_t length) {
    TestHost* test = ctx;
    assert(length && length < sizeof(test->commands[0]));
    assert(bytes[length - 1] == '\n' && !memchr(bytes, '\0', length));
    assert(test->command_count < 16);
    memcpy(test->commands[test->command_count], bytes, length);
    test->commands[test->command_count++][length] = '\0';
    return true;
}
static bool request_input(void* ctx, const C5TextInputRequest* input) {
    TestHost* test = ctx;
    test->input = *input;
    test->input_requests++;
    return true;
}
static void redraw(void* ctx) { ((TestHost*)ctx)->redraws++; }
static void status(void* ctx, const char* message, uint32_t duration, bool fullscreen) {
    (void)duration;
    (void)fullscreen;
    snprintf(((TestHost*)ctx)->status, sizeof(((TestHost*)ctx)->status), "%s", message);
}
void canvas_set_color(Canvas* canvas, Color color) { (void)canvas; (void)color; }
void canvas_set_font(Canvas* canvas, Font font) { (void)canvas; (void)font; }
void canvas_draw_str(Canvas* canvas, int x, int y, const char* value) {
    (void)x;
    (void)y;
    assert(canvas->line_count < 16);
    snprintf(canvas->lines[canvas->line_count++], sizeof(canvas->lines[0]), "%s", value);
}

static C5HostApiV3 make_host(TestHost* test) {
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
static C5MitmPcapLaunchContext launch(void) {
    C5MitmPcapLaunchContext context = {
        .version = C5_MITM_PCAP_LAUNCH_VERSION,
        .size = sizeof(C5MitmPcapLaunchContext),
        .selected_number = 7,
        .ssid = "Lab Net",
        .bssid = "12:34:56:78:9A:BC",
        .ticks_per_second = 1000,
    };
    return context;
}
static const C5ModuleV3* module(void) {
    const FlipperAppPluginDescriptor* descriptor = lab_c5_mitm_pcap_plugin_ep();
    assert(descriptor && descriptor->ep_api_version == C5_MODULE_API_VERSION);
    assert(strcmp(descriptor->appid, C5_MODULE_APP_ID) == 0);
    const C5ModuleV3* value = descriptor->entry_point;
    assert(value && value->version == C5_MODULE_API_VERSION && value->size == sizeof(*value));
    assert(value->enter && value->leave && value->on_bytes && value->on_input &&
           value->on_text_input && value->draw && value->tick);
    return value;
}
static void feed(const C5ModuleV3* value, void* state, const C5HostApiV3* host, const char* text) {
    size_t length = strlen(text);
    size_t split = length / 2;
    value->on_bytes(state, host, (const uint8_t*)text, split);
    value->on_bytes(state, host, (const uint8_t*)text + split, length - split);
}
static C5InputResult back(const C5ModuleV3* value, void* state, const C5HostApiV3* host) {
    InputEvent event = {.type = InputTypeShort, .key = InputKeyBack};
    return value->on_input(state, host, &event);
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
static void* enter(const C5ModuleV3* value, const C5HostApiV3* host) {
    C5MitmPcapLaunchContext context = launch();
    void* state = value->enter(host, &context, sizeof(context));
    assert(state);
    return state;
}
static void selected(const C5ModuleV3* value, void* state, const C5HostApiV3* host) {
    value->tick(state, host, 1);
    feed(value, state, host,
         "Selected Networks:\nLab Net, 12:34:56:78:9a:bc, Ch6, WPA2\n>");
}
static void connected(const C5ModuleV3* value, void* state, const C5HostApiV3* host) {
    feed(value, state, host,
         "SUCCESS: Connected to 'Lab Net'\n"
         "DHCP IP: 192.168.1.9, Netmask: 255.255.255.0, GW: 192.168.1.1\n>");
}
static void starting_pcap(const C5ModuleV3* value, void* state, const C5HostApiV3* host) {
    selected(value, state, host);
    feed(value, state, host, "\"Lab Net\", \"valid pass\"\n>");
    connected(value, state, host);
}

static void test_launch_validation_and_selected_target_match(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5MitmPcapLaunchContext context = launch();
    context.selected_number = 0;
    assert(!value->enter(&host, &context, sizeof(context)));
    context = launch(); context.bssid[0] = 'Z';
    assert(!value->enter(&host, &context, sizeof(context)));
    context = launch(); context.ssid[0] = '"';
    assert(!value->enter(&host, &context, sizeof(context)));
    context = launch(); context.ticks_per_second = 0;
    assert(!value->enter(&host, &context, sizeof(context)));
    context = launch(); context.version++;
    assert(!value->enter(&host, &context, sizeof(context)));
    context = launch();
    assert(!value->enter(&host, &context, sizeof(context) - 1));
    void* state = value->enter(&host, &context, sizeof(context));
    assert(state && test.command_count == 0);
    value->tick(state, &host, 1);
    value->tick(state, &host, 2);
    assert(test.command_count == 1 && strcmp(test.commands[0], "select_networks 7\n") == 0);
    feed(value, state, &host,
         "Selected Networks:\nOther Net, 12:34:56:78:9A:BC, Ch6, WPA2\n>");
    assert(test.command_count == 1);
    assert(drawn(value, state, &host, "Target changed"));
    value->leave(state, &host);
}

static void test_saved_password_waits_for_exact_wifi_success_and_ip(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host);
    selected(value, state, &host);
    assert(test.command_count == 2 && strcmp(test.commands[1], "show_pass evil\n") == 0);
    feed(value, state, &host,
         "\"Other\", \"do not use\"\n\"Lab Net\", \"valid pass\"\n>");
    assert(test.command_count == 3);
    assert(strcmp(test.commands[2], "wifi_connect \"Lab Net\" \"valid pass\"\n") == 0);
    assert(test.unsafe_sends == 0 && test.input_requests == 0);
    assert(!drawn(value, state, &host, "valid pass"));
    feed(value, state, &host, "I (100) projectZero: SUCCESS: Connected to 'Other'\n>");
    assert(test.command_count == 3);
    assert(drawn(value, state, &host, "WiFi failed"));
    value->leave(state, &host);

    test = (TestHost){0}; host = make_host(&test);
    state = enter(value, &host);
    selected(value, state, &host);
    feed(value, state, &host, "\"Lab Net\", \"valid pass\"\n>");
    feed(value, state, &host, "I (100) projectZero: SUCCESS: Connected to 'Lab Net'\n");
    assert(test.command_count == 3);
    feed(value, state, &host,
         "I (101) projectZero: DHCP IP: 192.168.1.9, Netmask: 255.255.255.0, GW: 192.168.1.1\n>");
    assert(test.command_count == 4 && strcmp(test.commands[3], "start_pcap net\n") == 0);
    value->leave(state, &host);
}

static void test_missing_saved_password_prompts_and_blank_uses_open_path(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host);
    selected(value, state, &host);
    feed(value, state, &host, "\"Other\", \"wrong pass\"\n>");
    assert(test.input_requests == 1 && test.input.minimum_length == 0);
    assert(test.command_count == 2);
    value->on_text_input(state, &host, false, "");
    assert(test.command_count == 2 && drawn(value, state, &host, "Password cancelled"));
    value->leave(state, &host);

    test = (TestHost){0}; host = make_host(&test);
    state = enter(value, &host);
    selected(value, state, &host);
    feed(value, state, &host, ">");
    assert(test.input_requests == 1);
    value->on_text_input(state, &host, true, "");
    assert(test.command_count == 3);
    assert(strcmp(test.commands[2], "wifi_connect \"Lab Net\"\n") == 0);
    value->leave(state, &host);
}

static void test_wrong_password_never_starts_capture(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host);
    selected(value, state, &host);
    feed(value, state, &host, ">");
    value->on_text_input(state, &host, true, "wrongpass");
    feed(value, state, &host,
         "I (500) projectZero: FAILED: Connection to 'Lab Net' failed (reason=15). Check SSID/password and signal.\n>");
    assert(test.command_count == 3);
    assert(drawn(value, state, &host, "WiFi failed"));
    assert(!drawn(value, state, &host, "PCAP active"));
    value->leave(state, &host);
}

static void test_capture_ack_file_and_zero_spoof_hosts_are_separate(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host);
    starting_pcap(value, state, &host);
    assert(test.command_count == 4);
    feed(value, state, &host,
         "I (200) projectZero: PCAP net: Found 0 hosts to spoof\n"
         "Password: PCAP net capture started -> /sdcard/lab/pcaps/sniff_4.pcap\n"
         "Password: projectZero: PCAP net capture started -> /sdcard/lab/pcaps/sniff_4.pcap\n");
    assert(!drawn(value, state, &host, "PCAP active"));
    feed(value, state, &host,
         "PCAP net capture started -> /sdcard/lab/pcaps/sniff_4.pcap\n");
    assert(drawn(value, state, &host, "PCAP active"));
    assert(drawn(value, state, &host, "sniff_4.pcap"));
    assert(drawn(value, state, &host, "Spoof: 0 hosts"));
    assert(!drawn(value, state, &host, "Spoof active"));
    value->leave(state, &host);
}

static void test_spoof_start_is_reported_separately_from_capture(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host);
    starting_pcap(value, state, &host);
    feed(value, state, &host,
         "I (210) projectZero: PCAP net: Found 2 hosts to spoof\n"
         "I (211) projectZero: PCAP net capture started -> /sdcard/lab/pcaps/sniff_5.pcap\n");
    assert(drawn(value, state, &host, "PCAP active"));
    assert(drawn(value, state, &host, "Spoof: 2 targets"));
    assert(!drawn(value, state, &host, "Spoof started"));
    feed(value, state, &host,
         "I (212) projectZero: PCAP net: ARP spoof MITM started (IP forwarding enabled)\n");
    assert(drawn(value, state, &host, "Spoof: reported 2"));
    value->leave(state, &host);
}

static void test_stop_requires_matching_final_and_shows_frames_drops(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host);
    starting_pcap(value, state, &host);
    feed(value, state, &host,
         "I (201) projectZero: PCAP net capture started -> /sdcard/lab/pcaps/sniff_4.pcap\n");
    assert(back(value, state, &host) == C5InputConsumed);
    assert(test.command_count == 5 && strcmp(test.commands[4], "stop\n") == 0);
    assert(drawn(value, state, &host, "Stopping"));
    feed(value, state, &host, "I (205) projectZero: All operations stopped.\n");
    assert(drawn(value, state, &host, "PCAP unknown"));
    assert(!drawn(value, state, &host, "Stopped"));
    feed(value, state, &host,
         "[PCAP_FINAL] file=/sdcard/lab/pcaps/other.pcap frames=42 drops=3 drop_alloc=0 drop_queue=1 drop_write=2 rate_queue_drops=0 throttle_events=0 pause_events=0 filter_drops=0\n");
    assert(!drawn(value, state, &host, "Stopped"));
    feed(value, state, &host,
         "[PCAP_FINAL] file=/sdcard/lab/pcaps/sniff_4.pcap frames=42 drops=3 drop_alloc=0 drop_queue=1 drop_write=2 rate_queue_drops=0 throttle_events=0 pause_events=0 filter_drops=0\n");
    assert(drawn(value, state, &host, "Stopped"));
    assert(drawn(value, state, &host, "Frames: 42 Drops: 3"));
    assert(back(value, state, &host) == C5InputSwitchModule);
    value->leave(state, &host);
    assert(test.command_count == 5);
}

static void test_sd_failure_and_start_timeout_never_claim_active(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host);
    starting_pcap(value, state, &host);
    feed(value, state, &host, "I (300) projectZero: Failed to initialize SD card: ESP_FAIL\n>");
    assert(drawn(value, state, &host, "SD unavailable"));
    assert(!drawn(value, state, &host, "PCAP active"));
    assert(back(value, state, &host) == C5InputConsumed);
    assert(strcmp(test.commands[test.command_count - 1], "stop\n") == 0);
    feed(value, state, &host, "All operations stopped.\n>");
    assert(drawn(value, state, &host, "Stopped"));
    assert(drawn(value, state, &host, "No PCAP started"));
    assert(back(value, state, &host) == C5InputSwitchModule);
    value->leave(state, &host);

    test = (TestHost){0}; host = make_host(&test);
    state = enter(value, &host);
    starting_pcap(value, state, &host);
    value->tick(state, &host, 16000);
    assert(drawn(value, state, &host, "Start unconfirmed"));
    assert(!drawn(value, state, &host, "PCAP active"));
    value->leave(state, &host);
}

static void test_stop_ack_without_final_allows_exit_with_unknown_capture_result(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host);
    starting_pcap(value, state, &host);
    feed(value, state, &host,
         "PCAP net capture started -> /sdcard/lab/pcaps/sniff_4.pcap\n");
    assert(back(value, state, &host) == C5InputConsumed);
    feed(value, state, &host, "All operations stopped.\n>");
    assert(drawn(value, state, &host, "PCAP unknown"));
    assert(!drawn(value, state, &host, "Frames:"));
    assert(back(value, state, &host) == C5InputSwitchModule);
    assert(test.command_count == 5);
    value->leave(state, &host);
}

int main(void) {
    test_launch_validation_and_selected_target_match();
    test_saved_password_waits_for_exact_wifi_success_and_ip();
    test_missing_saved_password_prompts_and_blank_uses_open_path();
    test_wrong_password_never_starts_capture();
    test_capture_ack_file_and_zero_spoof_hosts_are_separate();
    test_spoof_start_is_reported_separately_from_capture();
    test_stop_requires_matching_final_and_shows_frames_drops();
    test_sd_failure_and_start_timeout_never_claim_active();
    test_stop_ack_without_final_allows_exit_with_unknown_capture_result();
    puts("MITM PCAP module tests passed");
    return 0;
}
