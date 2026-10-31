/* From FLIPPER in WSL:
 * cc -std=c11 -Wall -Wextra -Werror -Wdouble-promotion -fsanitize=address,undefined \
 *   -Itests/stubs tests/test_wpasec_module.c modules/wpasec/wpasec_module.c \
 *   -o /tmp/c5_wpasec_test && /tmp/c5_wpasec_test
 * Fixtures use bare strings printed by ESP32C5/main/main.c (MY_LOG_INFO is printf).
 */
#include "../module_api.h"
#include "../modules/wpasec/wpasec_module.h"
#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_wpasec_plugin_ep(void);

typedef struct {
    char commands[8][80];
    size_t command_count;
    unsigned unsafe_sends;
    unsigned redraws;
    bool fail_upload;
    char status[80];
} TestHost;

static void unsafe_send(void* ctx, const char* command) {
    (void)command;
    ((TestHost*)ctx)->unsafe_sends++;
}
static bool send_raw(void* ctx, const char* bytes, size_t length) {
    TestHost* test = ctx;
    if(test->fail_upload && length >= 13 &&
       memcmp(bytes, "wpasec_upload", 13) == 0) return false;
    assert(length && length < sizeof(test->commands[0]));
    assert(bytes[length - 1] == '\n' && !memchr(bytes, '\0', length));
    assert(test->command_count < 8);
    memcpy(test->commands[test->command_count], bytes, length);
    test->commands[test->command_count++][length] = '\0';
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
        .request_redraw = redraw,
        .show_status = status,
    };
    return host;
}
static C5WpasecLaunchContext launch(bool tls_verified) {
    C5WpasecLaunchContext context = {
        .version = C5_WPASEC_LAUNCH_VERSION,
        .size = sizeof(C5WpasecLaunchContext),
        .ticks_per_second = 1000,
        .tls_verified = tls_verified,
    };
    return context;
}
static const C5ModuleV3* module(void) {
    const FlipperAppPluginDescriptor* descriptor = lab_c5_wpasec_plugin_ep();
    assert(descriptor && descriptor->ep_api_version == C5_MODULE_API_VERSION);
    assert(strcmp(descriptor->appid, C5_MODULE_APP_ID) == 0);
    const C5ModuleV3* value = descriptor->entry_point;
    assert(value && value->version == C5_MODULE_API_VERSION && value->size == sizeof(*value));
    assert(value->enter && value->leave && value->on_bytes && value->on_input &&
           value->draw && value->tick);
    return value;
}
static void* enter(const C5ModuleV3* value, const C5HostApiV3* host, bool tls_verified) {
    C5WpasecLaunchContext context = launch(tls_verified);
    void* state = value->enter(host, &context, sizeof(context));
    assert(state);
    return state;
}
static void feed(const C5ModuleV3* value, void* state, const C5HostApiV3* host, const char* text) {
    size_t length = strlen(text);
    size_t cut = length / 3;
    value->on_bytes(state, host, (const uint8_t*)text, cut);
    value->on_bytes(state, host, (const uint8_t*)text + cut, length - cut);
}
static C5InputResult press(const C5ModuleV3* value, void* state,
                           const C5HostApiV3* host, InputKey key) {
    InputEvent event = {.type = InputTypeShort, .key = key};
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
static void key_set(const C5ModuleV3* value, void* state, const C5HostApiV3* host) {
    value->tick(state, host, 1);
    feed(value, state, host, "WPA-SEC key: abcd****\n>");
}
static void upload_started(const C5ModuleV3* value, void* state, const C5HostApiV3* host) {
    key_set(value, state, host);
    assert(press(value, state, host, InputKeyOk) == C5InputConsumed);
}

static void test_launch_validation_and_key_check_only_on_first_tick(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    C5WpasecLaunchContext context = launch(false);
    context.version++;
    assert(!value->enter(&host, &context, sizeof(context)));
    context = launch(false); context.ticks_per_second = 0;
    assert(!value->enter(&host, &context, sizeof(context)));
    context = launch(false);
    assert(!value->enter(&host, &context, sizeof(context) - 1));
    void* state = value->enter(&host, &context, sizeof(context));
    assert(state && test.command_count == 0);
    value->tick(state, &host, 1);
    value->tick(state, &host, 2);
    assert(test.command_count == 1 && strcmp(test.commands[0], "wpasec_key read\n") == 0);
    assert(test.unsafe_sends == 0);
    value->leave(state, &host);
}

static void test_missing_key_differs_from_missing_reply(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, true);
    value->tick(state, &host, 1);
    feed(value, state, &host,
         "WPA-SEC key: not set\n"
         "Get your key at: https://wpa-sec.stanev.org/?get_key\n>");
    assert(drawn(value, state, &host, "Key not set"));
    assert(drawn(value, state, &host, "wpasec_key set"));
    assert(test.command_count == 1);
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);

    test = (TestHost){0}; host = make_host(&test);
    state = enter(value, &host, true);
    value->tick(state, &host, 1);
    feed(value, state, &host, ">");
    assert(drawn(value, state, &host, "Key status unknown"));
    assert(!drawn(value, state, &host, "Key not set"));
    value->leave(state, &host);

    test = (TestHost){0}; host = make_host(&test);
    state = enter(value, &host, true);
    value->tick(state, &host, 1);
    value->tick(state, &host, 6000);
    assert(drawn(value, state, &host, "Key status unknown"));
    value->leave(state, &host);
}

static void test_tls_gate_blocks_upload_even_with_key_and_ok(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, false);
    key_set(value, state, &host);
    assert(drawn(value, state, &host, "TLS not verified"));
    assert(drawn(value, state, &host, "Upload blocked"));
    assert(!drawn(value, state, &host, "abcd"));
    assert(!strstr(test.status, "abcd"));
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.command_count == 1 && test.unsafe_sends == 0);
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_upload_scope_requires_explicit_confirmation(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, true);
    key_set(value, state, &host);
    assert(drawn(value, state, &host, "ALL handshake .pcap"));
    assert(drawn(value, state, &host, "/sdcard/lab/handshakes"));
    assert(drawn(value, state, &host, "WiFi via JanOS console"));
    assert(test.command_count == 1);
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    assert(test.command_count == 1);
    value->leave(state, &host);

    test = (TestHost){0}; host = make_host(&test);
    state = enter(value, &host, true);
    upload_started(value, state, &host);
    assert(test.command_count == 2 && strcmp(test.commands[1], "wpasec_upload\n") == 0);
    assert(test.unsafe_sends == 0);
    value->leave(state, &host);
}

static void test_no_wifi_and_empty_directory_are_distinct_results(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, true);
    upload_started(value, state, &host);
    feed(value, state, &host,
         "Not connected to any AP. Use 'wifi_connect' first.\n>");
    assert(drawn(value, state, &host, "Connect WiFi in JanOS"));
    assert(!drawn(value, state, &host, "Uploaded:"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);

    test = (TestHost){0}; host = make_host(&test);
    state = enter(value, &host, true);
    upload_started(value, state, &host);
    feed(value, state, &host,
         "No .pcap files found in /sdcard/lab/handshakes/\n>");
    assert(drawn(value, state, &host, "No handshake .pcap"));
    assert(!drawn(value, state, &host, "Result unconfirmed"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_back_during_sync_upload_does_not_claim_cancel_and_done_is_final(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, true);
    upload_started(value, state, &host);
    feed(value, state, &host,
         "Uploading 3 handshake(s) to wpa-sec.stanev.org...\n"
         "[1/3] a.pcap (4242 bytes) -> OK\n");
    assert(drawn(value, state, &host, "Uploading 1/3"));
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(drawn(value, state, &host, "Back cannot cancel"));
    assert(test.command_count == 2);
    feed(value, state, &host,
         "[2/3] b.pcap (1234 bytes) -> already submitted\n"
         "[3/3] c.pcap (1200 bytes) -> FAILED\n"
         "Done: 1 uploaded, 1 duplicate, 1 failed\n>");
    assert(drawn(value, state, &host, "Uploaded: 1 Dup: 1"));
    assert(drawn(value, state, &host, "Failed: 1"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_malformed_done_and_silence_remain_uncertain_until_real_done(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, true);
    upload_started(value, state, &host);
    feed(value, state, &host, "Uploading 2 handshake(s) to wpa-sec.stanev.org...\n");
    feed(value, state, &host, "Done: -1 uploaded, 0 duplicate, 0 failed\n");
    assert(!drawn(value, state, &host, "Uploaded:"));
    value->tick(state, &host, 121000);
    assert(drawn(value, state, &host, "Result unconfirmed"));
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 2);
    feed(value, state, &host, "Done: 2 uploaded, 0 duplicate, 0 failed\n");
    assert(drawn(value, state, &host, "Uploaded: 2 Dup: 0"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_prompt_without_summary_allows_exit_without_claiming_success(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, true);
    upload_started(value, state, &host);
    feed(value, state, &host, "Uploading 1 handshake(s) to wpa-sec.stanev.org...\n> ");
    assert(drawn(value, state, &host, "Result unconfirmed"));
    assert(!drawn(value, state, &host, "Upload finished"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_upload_tx_failure_allows_exit_without_claiming_remote_work(void) {
    const C5ModuleV3* value = module();
    TestHost test = {.fail_upload = true};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, true);
    upload_started(value, state, &host);
    assert(drawn(value, state, &host, "Upload TX failed"));
    assert(!drawn(value, state, &host, "Monster may continue"));
    assert(test.command_count == 1);
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_key_can_disappear_after_read_and_upload_reports_it(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = make_host(&test);
    void* state = enter(value, &host, true);
    upload_started(value, state, &host);
    feed(value, state, &host,
         "No WPA-SEC API key set. Use 'wpasec_key set <key>' first.\n>");
    assert(drawn(value, state, &host, "Key not set"));
    assert(test.command_count == 2);
    value->leave(state, &host);
}

int main(void) {
    test_launch_validation_and_key_check_only_on_first_tick();
    test_missing_key_differs_from_missing_reply();
    test_tls_gate_blocks_upload_even_with_key_and_ok();
    test_upload_scope_requires_explicit_confirmation();
    test_no_wifi_and_empty_directory_are_distinct_results();
    test_back_during_sync_upload_does_not_claim_cancel_and_done_is_final();
    test_malformed_done_and_silence_remain_uncertain_until_real_done();
    test_prompt_without_summary_allows_exit_without_claiming_success();
    test_upload_tx_failure_allows_exit_without_claiming_remote_work();
    test_key_can_disappear_after_read_and_upload_reports_it();
    puts("WPA-sec module tests passed");
    return 0;
}
