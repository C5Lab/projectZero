/* From FLIPPER in WSL:
 * cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Itests/stubs \
 *   tests/test_wardrive_upload_module.c modules/wardrive_upload/wardrive_upload_module.c \
 *   -o /tmp/c5_wardrive_upload_test && /tmp/c5_wardrive_upload_test
 */
#include "../module_api.h"
#include "../modules/wardrive_upload/wardrive_upload_module.h"

#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_wardrive_upload_plugin_ep(void);

typedef struct {
    char commands[24][192];
    size_t command_count;
    C5TextInputRequest request;
    size_t input_requests;
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
    assert(request);
    test->request = *request;
    test->input_requests++;
    return true;
}

static void redraw(void* context) { (void)context; }
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
    const FlipperAppPluginDescriptor* descriptor = lab_c5_wardrive_upload_plugin_ep();
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

static C5WardriveUploadLaunchContext launch(C5WardriveUploadProvider provider, bool tls_verified) {
    C5WardriveUploadLaunchContext context = {
        .version = C5_WARDRIVE_UPLOAD_LAUNCH_VERSION,
        .size = sizeof(C5WardriveUploadLaunchContext),
        .provider = provider,
        .ticks_per_second = 1000,
        .tls_verified = tls_verified,
    };
    return context;
}

static void* enter(const C5ModuleV3* value, const C5HostApiV3* host,
                   C5WardriveUploadProvider provider, bool tls_verified) {
    C5WardriveUploadLaunchContext context = launch(provider, tls_verified);
    return value->enter(host, &context, sizeof(context));
}

static void feed(const C5ModuleV3* value, void* state, const C5HostApiV3* host, const char* text) {
    for(size_t i = 0; text[i]; i++) {
        value->on_bytes(state, host, (const uint8_t*)&text[i], 1);
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

static void list_one(const C5ModuleV3* value, void* state, const C5HostApiV3* host,
                     const char* name) {
    char response[320];
    int written = snprintf(response, sizeof(response),
                           "Files in /sdcard/lab/wardrives:\n1 %s\n"
                           "Found 1 file(s) in /sdcard/lab/wardrives\n>", name);
    assert(written > 0 && (size_t)written < sizeof(response));
    feed(value, state, host, response);
}

static void key_present(const C5ModuleV3* value, void* state,
                        const C5HostApiV3* host, C5WardriveUploadProvider provider) {
    feed(value, state, host, provider == C5WardriveUploadWigle ?
                             "WiGLE key: name****:toke****\n>" :
                             "WDGWars key: abcd****\n>");
}

static void test_launch_validation_and_empty_listing(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    C5WardriveUploadLaunchContext context = launch(C5WardriveUploadWigle, false);
    assert(!value->enter(&host, NULL, 0));
    assert(!value->enter(&host, &context, sizeof(context) - 1));
    context.provider = (C5WardriveUploadProvider)7;
    assert(!value->enter(&host, &context, sizeof(context)));
    context = launch(C5WardriveUploadWigle, false);
    context.ticks_per_second = 0;
    assert(!value->enter(&host, &context, sizeof(context)));
    void* state = enter(value, &host, C5WardriveUploadWigle, false);
    assert(state && test.command_count == 1);
    assert(strcmp(test.commands[0], "list_dir lab/wardrives\n") == 0);
    feed(value, state, &host,
         "Files in /sdcard/lab/wardrives:\r\n"
         "No files found in /sdcard/lab/wardrives\r\n> ");
    assert(drawn(value, state, &host, "No Wardrive files"));
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.command_count == 1);
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_listing_is_paged_without_twenty_file_ceiling(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWdgwars, true);
    assert(state);
    for(unsigned pass = 0; pass < 2; pass++) {
        feed(value, state, &host, "I (101) projectZero: Files in /sdcard/lab/wardrives:\n");
        for(unsigned i = 1; i <= 25; i++) {
            char row[40];
            snprintf(row, sizeof(row), "%u ward_%02u.log\n", i, i);
            feed(value, state, &host, row);
        }
        feed(value, state, &host, "I (102) projectZero: Found 25 file(s) in /sdcard/lab/wardrives\n>");
        assert(drawn(value, state, &host, pass == 0 ? "1/3" : "2/3"));
        assert(drawn(value, state, &host, pass == 0 ? "ward_01.log" : "ward_13.log"));
        if(pass == 0) {
            assert(press(value, state, &host, InputKeyRight) == C5InputConsumed);
            assert(test.command_count == 2);
            assert(strcmp(test.commands[1], "list_dir lab/wardrives\n") == 0);
        }
    }
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.command_count == 3 && strcmp(test.commands[2], "wdgwars_key read\n") == 0);
    value->leave(state, &host);
}

static void test_filename_filters_and_incomplete_snapshot(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWigle, true);
    assert(state);
    feed(value, state, &host,
         "I (101) projectZero: Files in /sdcard/lab/wardrives:\n"
         "1 capture.csv\n2 notes.gz\n3 upload_state.csv\n"
         "4 old.fixed.log\n5 bad\"name.log\n6 spaced file.log\n"
         "I (102) projectZero: Found 6 file(s) in /sdcard/lab/wardrives\n>");
    assert(drawn(value, state, &host, "1/1"));
    assert(drawn(value, state, &host, "omitted 1"));
    assert(drawn(value, state, &host, "capture.csv"));
    assert(press(value, state, &host, InputKeyDown) == C5InputConsumed);
    assert(drawn(value, state, &host, "spaced file.log"));
    value->leave(state, &host);

    TestHost bad = {0};
    C5HostApiV3 bad_host = host_api(&bad);
    state = enter(value, &bad_host, C5WardriveUploadWigle, true);
    assert(state);
    feed(value, state, &bad_host,
         "I (101) projectZero: Files in /sdcard/lab/wardrives:\n1 first.log\n"
         "I (102) projectZero: Found 2 file(s) in /sdcard/lab/wardrives\n>");
    assert(drawn(value, state, &bad_host, "List incomplete"));
    assert(press(value, state, &bad_host, InputKeyOk) == C5InputConsumed);
    assert(bad.command_count == 2 &&
           strcmp(bad.commands[1], "list_dir lab/wardrives\n") == 0);
    value->leave(state, &bad_host);
}

static void test_tls_gate_blocks_upload_after_key_check(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWigle, false);
    assert(state);
    list_one(value, state, &host, "capture.csv");
    press(value, state, &host, InputKeyOk);
    assert(strcmp(test.commands[1], "wigle_key read\n") == 0);
    key_present(value, state, &host, C5WardriveUploadWigle);
    assert(drawn(value, state, &host, "TLS unverified"));
    assert(test.input_requests == 0);
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.command_count == 2);
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(drawn(value, state, &host, "capture.csv"));
    value->leave(state, &host);
}

static void test_missing_nvs_key_is_distinct_from_missing_reply(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWdgwars, true);
    assert(state);
    list_one(value, state, &host, "capture.gz");
    press(value, state, &host, InputKeyOk);
    feed(value, state, &host, "I (103) projectZero: WDGWars key: not set\n>");
    assert(drawn(value, state, &host, "NVS key missing"));
    assert(drawn(value, state, &host, "Set key in JanOS"));
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.command_count == 3 && strcmp(test.commands[2], "wdgwars_key read\n") == 0);
    assert(test.input_requests == 0);
    value->on_text_input(state, &host, true, "Home");
    assert(test.command_count == 3);
    key_present(value, state, &host, C5WardriveUploadWdgwars);
    assert(test.input_requests == 1 && test.request.capacity == 33);
    value->leave(state, &host);

    TestHost absent = {0};
    C5HostApiV3 absent_host = host_api(&absent);
    state = enter(value, &absent_host, C5WardriveUploadWdgwars, true);
    assert(state);
    list_one(value, state, &absent_host, "capture.gz");
    press(value, state, &absent_host, InputKeyOk);
    feed(value, state, &absent_host, ">");
    assert(drawn(value, state, &absent_host, "Key reply missing"));
    assert(absent.input_requests == 0);
    value->leave(state, &absent_host);
}

static void test_saved_wifi_and_upload_needs_final_summary_and_prompt(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWigle, true);
    assert(state);
    list_one(value, state, &host, "spaced file.log");
    press(value, state, &host, InputKeyOk);
    key_present(value, state, &host, C5WardriveUploadWigle);
    assert(test.input_requests == 1 && test.request.capacity == 33);
    const char* bad[] = {"", "Bad\nSSID", "Bad\rSSID", "Bad\"SSID", "Bad\\SSID",
                         "123456789012345678901234567890123"};
    for(size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        value->on_text_input(state, &host, true, bad[i]);
        assert(test.command_count == 2);
    }
    value->on_text_input(state, &host, true, "Lab, WiFi");
    assert(drawn(value, state, &host, "OK:saved"));
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.command_count == 3);
    assert(strcmp(test.commands[2], "wifi_connect \"Lab, WiFi\" --saved\n") == 0);
    feed(value, state, &host, "SUCCESS: Connected to 'Lab, WiFi'\n>");
    assert(drawn(value, state, &host, "Confirm upload"));
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.command_count == 4);
    assert(strcmp(test.commands[3], "wigle_upload \"spaced file.log\"\n") == 0);
    feed(value, state, &host, "[1/1] spaced file.log (123 bytes) -> OK\n");
    assert(drawn(value, state, &host, "File: OK"));
    assert(!drawn(value, state, &host, "Session done"));
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 4);
    feed(value, state, &host, "Done: 1 uploaded, 0 skipped, 0 failed\n");
    assert(!drawn(value, state, &host, "Session done"));
    feed(value, state, &host, ">");
    assert(drawn(value, state, &host, "Session done"));
    assert(drawn(value, state, &host, "1 up, 0 skip, 0 fail"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
    assert(test.command_count == 4 && test.unsafe_sends == 0);
}

static void test_manual_password_is_quoted_and_never_uses_unsafe_send(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWigle, true);
    assert(state);
    list_one(value, state, &host, "capture.csv");
    press(value, state, &host, InputKeyOk);
    key_present(value, state, &host, C5WardriveUploadWigle);
    value->on_text_input(state, &host, true, "Home Net");
    assert(press(value, state, &host, InputKeyRight) == C5InputConsumed);
    assert(test.input_requests == 2 && test.request.capacity == 64);
    value->on_text_input(state, &host, true, "bad\npass");
    assert(test.command_count == 2);
    value->on_text_input(state, &host, true, "bad\"pass");
    assert(test.command_count == 2);
    value->on_text_input(state, &host, true, "secret123");
    assert(test.command_count == 3);
    assert(strcmp(test.commands[2], "wifi_connect \"Home Net\" \"secret123\"\n") == 0);
    assert(test.unsafe_sends == 0);
    value->leave(state, &host);
}

static void test_wdgwars_rate_limit_is_final_only_after_done_and_prompt(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWdgwars, true);
    assert(state);
    list_one(value, state, &host, "capture.gz");
    press(value, state, &host, InputKeyOk);
    key_present(value, state, &host, C5WardriveUploadWdgwars);
    value->on_text_input(state, &host, true, "Home");
    press(value, state, &host, InputKeyOk);
    feed(value, state, &host, "SUCCESS: Connected to 'Home'\n>");
    press(value, state, &host, InputKeyOk);
    assert(strcmp(test.commands[3], "wdgwars_upload \"capture.gz\"\n") == 0);
    feed(value, state, &host, "I (105) projectZero: [1/1] capture.gz (42 bytes) -> RATE LIMITED\n");
    assert(drawn(value, state, &host, "File: rate limited"));
    feed(value, state, &host, "I (106) projectZero: Done: 0 uploaded, 0 skipped, 0 failed, 1 rate_limited\n>");
    assert(drawn(value, state, &host, "Session done"));
    assert(drawn(value, state, &host, "1 rate limited"));
    value->leave(state, &host);
}

static void test_upload_timeout_and_missing_summary_do_not_claim_completion(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWigle, true);
    assert(state);
    list_one(value, state, &host, "capture.csv");
    press(value, state, &host, InputKeyOk);
    key_present(value, state, &host, C5WardriveUploadWigle);
    value->on_text_input(state, &host, true, "Home");
    press(value, state, &host, InputKeyOk);
    feed(value, state, &host, "I (104) projectZero: SUCCESS: Connected to 'Home'\n>");
    press(value, state, &host, InputKeyOk);
    value->tick(state, &host, 100);
    value->tick(state, &host, 180101);
    assert(drawn(value, state, &host, "May still be running"));
    assert(press(value, state, &host, InputKeyBack) == C5InputConsumed);
    assert(test.command_count == 4);
    feed(value, state, &host, "[1/1] capture.csv (20 bytes) -> OK\n>");
    assert(drawn(value, state, &host, "No final summary"));
    assert(!drawn(value, state, &host, "Session done"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
}

static void test_empty_key_line_is_not_a_confirmed_key(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWigle, true);
    assert(state);
    list_one(value, state, &host, "capture.csv");
    press(value, state, &host, InputKeyOk);
    feed(value, state, &host, "WiGLE key: \n>");
    assert(drawn(value, state, &host, "Key reply missing"));
    assert(test.input_requests == 0);
    value->leave(state, &host);
}

static void test_summary_without_file_marker_keeps_file_result_unconfirmed(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWigle, true);
    assert(state);
    list_one(value, state, &host, "capture.csv");
    press(value, state, &host, InputKeyOk);
    key_present(value, state, &host, C5WardriveUploadWigle);
    value->on_text_input(state, &host, true, "Home");
    press(value, state, &host, InputKeyOk);
    feed(value, state, &host, "SUCCESS: Connected to 'Home'\n>");
    press(value, state, &host, InputKeyOk);
    feed(value, state, &host, "Done: 1 uploaded, 0 skipped, 0 failed\n>");
    assert(drawn(value, state, &host, "Session done"));
    assert(drawn(value, state, &host, "File: unconfirmed"));
    assert(drawn(value, state, &host, "1 up, 0 skip, 0 fail"));
    value->leave(state, &host);
}

static void test_masked_key_with_literal_star_is_still_present(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWigle, true);
    assert(state);
    list_one(value, state, &host, "capture.csv");
    press(value, state, &host, InputKeyOk);
    feed(value, state, &host, "WiGLE key: a*b****:xy*z****\n>");
    assert(test.input_requests == 1);
    assert(!drawn(value, state, &host, "Key reply missing"));
    value->leave(state, &host);
}

static void test_long_filename_is_explicitly_omitted(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWigle, true);
    assert(state);
    char name[133];
    memset(name, 'A', 128);
    memcpy(name + 128, ".log", 5);
    list_one(value, state, &host, name);
    assert(drawn(value, state, &host, "No Wardrive files"));
    assert(drawn(value, state, &host, "omitted 1"));
    assert(press(value, state, &host, InputKeyOk) == C5InputConsumed);
    assert(test.command_count == 1);
    value->leave(state, &host);
}

static void test_credentials_lost_after_check_reports_janos_error(void) {
    const C5ModuleV3* value = module();
    TestHost test = {0};
    C5HostApiV3 host = host_api(&test);
    void* state = enter(value, &host, C5WardriveUploadWigle, true);
    assert(state);
    list_one(value, state, &host, "capture.csv");
    press(value, state, &host, InputKeyOk);
    key_present(value, state, &host, C5WardriveUploadWigle);
    value->on_text_input(state, &host, true, "Home");
    press(value, state, &host, InputKeyOk);
    feed(value, state, &host, "SUCCESS: Connected to 'Home'\n>");
    press(value, state, &host, InputKeyOk);
    feed(value, state, &host,
         "NO WIGLE CREDENTIALS\n"
         "Use 'wigle_key set <api_name> <api_token>' or /sdcard/lab/wigle.txt\n>");
    assert(drawn(value, state, &host, "WiGLE credentials missing"));
    assert(!drawn(value, state, &host, "Session done"));
    assert(press(value, state, &host, InputKeyBack) == C5InputSwitchModule);
    value->leave(state, &host);
}

int main(void) {
    test_launch_validation_and_empty_listing();
    test_listing_is_paged_without_twenty_file_ceiling();
    test_filename_filters_and_incomplete_snapshot();
    test_tls_gate_blocks_upload_after_key_check();
    test_missing_nvs_key_is_distinct_from_missing_reply();
    test_saved_wifi_and_upload_needs_final_summary_and_prompt();
    test_manual_password_is_quoted_and_never_uses_unsafe_send();
    test_wdgwars_rate_limit_is_final_only_after_done_and_prompt();
    test_upload_timeout_and_missing_summary_do_not_claim_completion();
    test_empty_key_line_is_not_a_confirmed_key();
    test_summary_without_file_marker_keeps_file_result_unconfirmed();
    test_masked_key_with_literal_star_is_still_present();
    test_long_filename_is_explicitly_omitted();
    test_credentials_lost_after_check_reports_janos_error();
    puts("wardrive upload module host tests passed");
    return 0;
}
