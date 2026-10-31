/* Host-only contract for the dormant Web FAL. The monolithic UI remains active
 * until the cutover is verified separately on hardware. */
#include "../module_api.h"
#include "../modules/web/web_module.h"
#include "../qrcodegen.h"
#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_web_plugin_ep(void);

typedef struct {
    char raw_tx[512];
    size_t raw_tx_length;
    unsigned raw_tx_calls;
    unsigned raw_tx_failures_remaining;
    C5TextInputRequest request;
    unsigned request_calls;
    unsigned redraws;
    char status[64];
    int32_t saved_karma_duration;
    C5WebSessionPrefs saved_prefs;
    unsigned save_calls;
} TestHost;

static size_t test_free_heap = 1024 * 1024;
static size_t test_max_block = 1024 * 1024;

size_t memmgr_get_free_heap(void) {
    return test_free_heap;
}

size_t memmgr_heap_get_max_free_block(void) {
    return test_max_block;
}

static bool send_raw_lines(void* ctx, const char* batch, size_t length) {
    TestHost* test = ctx;
    assert(test && batch && length < sizeof(test->raw_tx));
    if(test->raw_tx_failures_remaining) {
        test->raw_tx_failures_remaining--;
        return false;
    }
    memcpy(test->raw_tx, batch, length);
    test->raw_tx[length] = '\0';
    test->raw_tx_length = length;
    test->raw_tx_calls++;
    return true;
}

static bool request_text_input(void* ctx, const C5TextInputRequest* request) {
    TestHost* test = ctx;
    assert(test && request);
    test->request = *request;
    test->request_calls++;
    return true;
}

static void redraw(void* ctx) {
    ((TestHost*)ctx)->redraws++;
}

static void show_status(void* ctx, const char* message, uint32_t duration, bool fullscreen) {
    snprintf(((TestHost*)ctx)->status, sizeof(((TestHost*)ctx)->status), "%s", message);
    (void)duration;
    (void)fullscreen;
}

static void save_setting(void* ctx, C5Setting setting, int32_t value) {
    assert(setting == C5SettingKarmaDurationSec);
    ((TestHost*)ctx)->saved_karma_duration = value;
}

static void save_session(void* ctx, const void* data, size_t size) {
    TestHost* test = ctx;
    assert(size == sizeof(test->saved_prefs));
    memcpy(&test->saved_prefs, data, size);
    test->save_calls++;
}

static void test_web_allocations_respect_heap_preflight(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
        .save_session = save_session,
    };
    test_free_heap = 256;
    test_max_block = 256;
    assert(module->enter(&host, NULL, 0) == NULL);
    test_free_heap = 1024 * 1024;
    test_max_block = 1024 * 1024;
    void* state = module->enter(&host, NULL, 0);
    assert(state);
    test_free_heap = 700;
    test_max_block = 400;
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 0);
    assert(strcmp(test.status, "OOM: SSID list") == 0);
    module->leave(state, &host);
    assert(test.raw_tx_calls == 0);
    test_free_heap = 1024 * 1024;
    test_max_block = 1024 * 1024;
}

void canvas_set_color(Canvas* canvas, Color color) {
    (void)canvas;
    (void)color;
}

void canvas_set_font(Canvas* canvas, Font font) {
    (void)canvas;
    (void)font;
}

void canvas_draw_str(Canvas* canvas, int x, int y, const char* value) {
    (void)x;
    (void)y;
    assert(canvas->line_count < 16);
    snprintf(canvas->lines[canvas->line_count++], sizeof(canvas->lines[0]), "%s", value);
}

void canvas_draw_box(Canvas* canvas, int x, int y, int width, int height) {
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    canvas->box_count++;
}

void canvas_draw_rbox(Canvas* canvas, int x, int y, int width, int height, int radius) {
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    (void)radius;
    canvas->rbox_count++;
}

void canvas_draw_rframe(Canvas* canvas, int x, int y, int width, int height, int radius) {
    (void)x;
    (void)y;
    (void)width;
    (void)height;
    (void)radius;
    canvas->rframe_count++;
}

void canvas_draw_str_aligned(
    Canvas* canvas,
    int x,
    int y,
    Align horizontal,
    Align vertical,
    const char* value) {
    (void)horizontal;
    (void)vertical;
    canvas_draw_str(canvas, x, y, value);
}

static bool canvas_has(const Canvas* canvas, const char* value) {
    for(size_t i = 0; i < canvas->line_count; i++) {
        if(strcmp(canvas->lines[i], value) == 0) return true;
    }
    return false;
}

static void test_portal_listing_prompt_and_async_manual_ssid(void) {
    const FlipperAppPluginDescriptor* descriptor = lab_c5_web_plugin_ep();
    assert(descriptor && strcmp(descriptor->appid, C5_MODULE_APP_ID) == 0);
    assert(descriptor->ep_api_version == C5_MODULE_API_VERSION);
    const C5ModuleV3* module = descriptor->entry_point;
    assert(module && module->version == C5_MODULE_API_VERSION);
    assert(module->size == sizeof(*module) && module->on_bytes && module->on_text_input);
    assert(module->enter(NULL, NULL, 0) == NULL);

    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
        .save_session = save_session,
    };
    void* state = module->enter(&host, NULL, 0);
    assert(state);

    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Portal"));

    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    assert(module->on_input(state, &host, &ok) == C5InputConsumed);
    assert(test.raw_tx_calls == 1 && strcmp(test.raw_tx, "list_ssid\n") == 0);

    const uint8_t first[] = "ssid.txt not found\n";
    const uint8_t second[] = ">";
    module->on_bytes(state, &host, first, sizeof(first) - 1);
    module->on_bytes(state, &host, second, sizeof(second) - 1);
    assert(test.request_calls == 1);
    assert(strcmp(test.request.header, "Portal SSID") == 0);
    assert(test.request.capacity == 33 && test.request.minimum_length == 1);

    module->on_text_input(state, &host, true, "  Lab  ");
    assert(test.raw_tx_calls == 1);
    assert(module->on_input(state, &host, &ok) == C5InputConsumed);
    assert(test.raw_tx_calls == 2 && strcmp(test.raw_tx, "list_sd\n") == 0);

    const uint8_t html[] = "HTML files\r\n1 landing.html\r\n\r\n>";
    module->on_bytes(state, &host, html, sizeof(html) - 1);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "landing.html"));
    assert(canvas.rbox_count == 1 && canvas.rframe_count == 1);
    assert(module->on_input(state, &host, &ok) == C5InputConsumed);
    assert(test.raw_tx_calls == 3 && strcmp(test.raw_tx, "select_html 1\n") == 0);
    assert(module->on_input(state, &host, &ok) == C5InputSwitchTerminal);
    assert(test.raw_tx_calls == 4 &&
           strcmp(test.raw_tx, "select_html 1\nstart_portal \"Lab\"\n") == 0);
    const uint8_t status[] = "Portal: Client count = 2\nPassword: caught\n";
    module->on_bytes(state, &host, status, sizeof(status) - 1);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Portal On"));
    assert(canvas_has(&canvas, "Clients: 2"));
    InputEvent long_ok = {.type = InputTypeLong, .key = InputKeyOk};
    assert(module->on_input(state, &host, &long_ok) == C5InputToggleConsole);
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(module->on_input(state, &host, &back) == C5InputSwitchModule);
    assert(test.raw_tx_calls == 5 && strcmp(test.raw_tx, "stop\n") == 0);

    module->leave(state, &host);
    assert(test.save_calls == 1);
    assert(strcmp(test.saved_prefs.portal_ssid, "Lab") == 0);
    assert(test.saved_prefs.selected_html_id == 1);
    assert(strcmp(test.saved_prefs.selected_html_name, "landing.html") == 0);
    C5WebLaunchContext reload = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModePortal,
        .prefs = test.saved_prefs,
    };
    state = module->enter(&host, &reload, sizeof(reload));
    assert(state);
    InputEvent up = {.type = InputTypeShort, .key = InputKeyUp};
    module->on_input(state, &host, &up);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "landing.html"));
    module->on_input(state, &host, &up);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Lab"));
    module->leave(state, &host);
}

static void test_evil_twin_launch_snapshot_and_three_command_start(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
        .save_session = save_session,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModeEvilTwin,
        .selected_count = 1,
        .first_selected_ssid = "TargetNetworkNameLongerThan22",
        .select_networks = "select_networks 7",
        .prefs = {
            .selected_html_id = 1,
            .selected_html_name = "old_evil.html",
            .evil_html_id = 1,
            .evil_html_name = "old_evil.html",
        },
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Evil Twin"));
    assert(canvas_has(&canvas, "old_evil.html"));

    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    module->on_input(state, &host, &down);
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 1 && strcmp(test.raw_tx, "list_sd\n") == 0);
    const uint8_t html[] = "HTML files\n2 evil.html\n>";
    module->on_bytes(state, &host, html, sizeof(html) - 1);
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 2 && strcmp(test.raw_tx, "select_html 2\n") == 0);
    assert(module->on_input(state, &host, &ok) == C5InputSwitchTerminal);
    assert(test.raw_tx_calls == 3);
    assert(strcmp(test.raw_tx,
                  "select_html 2\nselect_networks 7\nstart_evil_twin\n") == 0);
    module->tick(state, &host, 0);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    char initial_title[96];
    snprintf(initial_title, sizeof(initial_title), "%s", canvas.lines[1]);
    module->tick(state, &host, 200);
    module->tick(state, &host, 400);
    module->tick(state, &host, 600);
    module->tick(state, &host, 800);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(strcmp(initial_title, canvas.lines[1]) != 0);
    module->leave(state, &host);
    assert(test.raw_tx_calls == 4 && strcmp(test.raw_tx, "stop\n") == 0);
    assert(test.save_calls == 1);
    assert(test.saved_prefs.selected_html_id == 2);
    assert(strcmp(test.saved_prefs.selected_html_name, "evil.html") == 0);
    assert(test.saved_prefs.evil_html_id == 2);
    assert(strcmp(test.saved_prefs.evil_html_name, "evil.html") == 0);

    launch.prefs = test.saved_prefs;
    state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "evil.html"));
    module->leave(state, &host);

    launch.version = 0;
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
}

static void test_web_launch_snapshot_rejects_bad_prefs(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModePortal,
    };
    assert(module->enter(&host, &launch, sizeof(launch) - 1) == NULL);
    memset(launch.prefs.portal_ssid, 'X', sizeof(launch.prefs.portal_ssid));
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch.prefs.portal_ssid[0] = '\0';
    memset(launch.prefs.selected_html_name, 'Y', sizeof(launch.prefs.selected_html_name));
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch.prefs.selected_html_name[0] = '\0';
    memset(launch.prefs.evil_html_name, 'W', sizeof(launch.prefs.evil_html_name));
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch.prefs.evil_html_name[0] = '\0';
    memset(launch.prefs.selected_probe_name, 'Z', sizeof(launch.prefs.selected_probe_name));
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch.prefs.selected_probe_name[0] = '\0';
    launch.prefs.portal_menu_index = 4;
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch.prefs.portal_menu_index = 0;
    launch.prefs.evil_menu_index = 5;
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch.prefs.evil_menu_index = 0;
    launch.prefs.karma_menu_index = 5;
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch.prefs.karma_menu_index = 0;
    launch.prefs.selected_html_id = 1;
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch.prefs.selected_html_id = 0;
    launch.prefs.evil_html_id = 1;
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch.prefs.evil_html_id = 0;
    launch.prefs.selected_probe_id = 1;
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    launch.prefs.selected_probe_id = 0;
    assert(test.raw_tx_calls == 0);
}

static void test_portal_passwords_select_and_raw_list(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
    };
    void* state = module->enter(&host, NULL, 0);
    assert(state);
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    for(int i = 0; i < 3; i++) module->on_input(state, &host, &down);
    module->on_input(state, &host, &ok);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Show Passwords"));
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 1 && strcmp(test.raw_tx, "show_pass portal\n") == 0);
    const uint8_t result[] = "Portal passwords\nLab: secret\n>";
    module->on_bytes(state, &host, result, sizeof(result) - 1);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Lab: secret"));
    module->on_input(state, &host, &back);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Portal"));
    module->leave(state, &host);
}

static void test_evil_twin_wifi_qr_is_owned_until_back(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModeEvilTwin,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    for(int i = 0; i < 3; i++) module->on_input(state, &host, &down);
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 1 && strcmp(test.raw_tx, "show_pass evil\n") == 0);
    const uint8_t reply[] = "\"Lab\" \"secret\"\n>";
    module->on_bytes(state, &host, reply, sizeof(reply) - 1);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "1 Lab"));
    module->on_input(state, &host, &ok);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "SSID") && canvas_has(&canvas, "PASS"));
    assert(canvas_has(&canvas, "secret") && canvas.box_count > 1);
    module->on_input(state, &host, &back);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "1 Lab"));
    module->leave(state, &host);
}

static void test_karma_collect_probe_html_and_start(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModeKarma,
        .karma_duration_sec = 15,
        .ticks_per_second = 1000,
        .probe_refresh_delay_ticks = 500,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Karma"));
    assert(canvas_has(&canvas, "15s"));
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    module->tick(state, &host, 0);
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 1 && strcmp(test.raw_tx, "start_sniffer\n") == 0);
    module->tick(state, &host, 14999);
    assert(test.raw_tx_calls == 1);
    module->tick(state, &host, 15000);
    assert(test.raw_tx_calls == 2 && strcmp(test.raw_tx, "stop\n") == 0);
    module->tick(state, &host, 15500);
    assert(test.raw_tx_calls == 3 && strcmp(test.raw_tx, "list_probes\n") == 0);
    const uint8_t probes[] = "1 Home\n2 Guest\n>";
    module->on_bytes(state, &host, probes, sizeof(probes) - 1);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Home"));
    module->on_input(state, &host, &ok);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Home"));
    module->on_input(state, &host, &down);
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 4 && strcmp(test.raw_tx, "list_sd\n") == 0);
    const uint8_t html[] = "HTML files\n2 portal.html\n>";
    module->on_bytes(state, &host, html, sizeof(html) - 1);
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 5 && strcmp(test.raw_tx, "select_html 2\n") == 0);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "portal.html"));
    assert(module->on_input(state, &host, &ok) == C5InputSwitchTerminal);
    assert(test.raw_tx_calls == 6 &&
           strcmp(test.raw_tx, "select_html 2\nstart_karma 1\n") == 0);
    module->leave(state, &host);
    assert(test.raw_tx_calls == 7 && strcmp(test.raw_tx, "stop\n") == 0);
}

static void test_karma_collect_unload_stops_once(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModeKarma,
        .karma_duration_sec = 15,
        .ticks_per_second = 1000,
        .probe_refresh_delay_ticks = 500,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 1 && strcmp(test.raw_tx, "start_sniffer\n") == 0);
    module->leave(state, &host);
    assert(test.raw_tx_calls == 2 && strcmp(test.raw_tx, "stop\n") == 0);
}

static void test_karma_duration_controls_and_save(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
        .set_setting = save_setting,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModeKarma,
        .karma_duration_sec = 15,
        .ticks_per_second = 1000,
        .probe_refresh_delay_ticks = 500,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    InputEvent up = {.type = InputTypeShort, .key = InputKeyUp};
    InputEvent left = {.type = InputTypeShort, .key = InputKeyLeft};
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    module->on_input(state, &host, &down);
    module->on_input(state, &host, &ok);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Duration: 15s"));
    module->on_input(state, &host, &up);
    assert(test.saved_karma_duration == 20);
    module->on_input(state, &host, &left);
    assert(test.saved_karma_duration == 19);
    module->on_input(state, &host, &ok);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Karma"));
    module->on_input(state, &host, &ok);
    module->on_input(state, &host, &back);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Karma"));
    module->leave(state, &host);
}

static void test_karma_does_not_replace_an_active_listing(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModeKarma,
        .ticks_per_second = 1000,
        .probe_refresh_delay_ticks = 500,
        .prefs = {.karma_menu_index = 2},
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};

    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 1 && strcmp(test.raw_tx, "list_probes\n") == 0);
    module->on_input(state, &host, &ok);
    module->on_input(state, &host, &down);
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 1);
    const uint8_t probes[] = "1 Home\n>";
    module->on_bytes(state, &host, probes, sizeof(probes) - 1);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Home"));
    module->leave(state, &host);
}

static void test_karma_auto_refresh_waits_for_html_listing_and_popup(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModeKarma,
        .karma_duration_sec = 15,
        .ticks_per_second = 1000,
        .probe_refresh_delay_ticks = 500,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};

    module->tick(state, &host, 0);
    module->on_input(state, &host, &ok);
    module->tick(state, &host, 15000);
    assert(test.raw_tx_calls == 2 && strcmp(test.raw_tx, "stop\n") == 0);
    for(int i = 0; i < 3; i++) module->on_input(state, &host, &down);
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 3 && strcmp(test.raw_tx, "list_sd\n") == 0);

    module->tick(state, &host, 15500);
    assert(test.raw_tx_calls == 3);
    const uint8_t html[] = "HTML files found on SD card:\n1 portal.html\n>";
    module->on_bytes(state, &host, html, sizeof(html) - 1);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "portal.html"));
    module->tick(state, &host, 16000);
    assert(test.raw_tx_calls == 3);
    module->on_input(state, &host, &back);
    module->tick(state, &host, 16500);
    assert(test.raw_tx_calls == 4 && strcmp(test.raw_tx, "list_probes\n") == 0);
    module->leave(state, &host);
}

static void test_list_reply_does_not_take_over_another_screen(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
    };
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    InputEvent up = {.type = InputTypeShort, .key = InputKeyUp};

    C5WebLaunchContext karma = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModeKarma,
        .ticks_per_second = 1000,
        .probe_refresh_delay_ticks = 500,
        .prefs = {.karma_menu_index = 2},
    };
    void* state = module->enter(&host, &karma, sizeof(karma));
    assert(state);
    module->on_input(state, &host, &ok);
    module->on_input(state, &host, &up);
    module->on_input(state, &host, &ok);
    const uint8_t probes[] = "1 Home\n>";
    module->on_bytes(state, &host, probes, sizeof(probes) - 1);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Karma Duration"));
    module->leave(state, &host);

    karma.prefs.karma_menu_index = 3;
    state = module->enter(&host, &karma, sizeof(karma));
    assert(state);
    module->on_input(state, &host, &ok);
    module->on_input(state, &host, &up);
    module->on_input(state, &host, &up);
    module->on_input(state, &host, &ok);
    const uint8_t html[] = "HTML files found on SD card:\n1 portal.html\n>";
    module->on_bytes(state, &host, html, sizeof(html) - 1);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Karma Duration"));
    module->leave(state, &host);

    C5WebLaunchContext portal = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModePortal,
    };
    state = module->enter(&host, &portal, sizeof(portal));
    assert(state);
    module->on_input(state, &host, &ok);
    for(int i = 0; i < 3; i++) module->on_input(state, &host, &down);
    module->on_input(state, &host, &ok);
    const uint8_t ssids[] = "SSID presets from ssid.txt:\n1 Home\n>";
    module->on_bytes(state, &host, ssids, sizeof(ssids) - 1);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Show Passwords"));
    module->leave(state, &host);
}

static void test_evil_twin_preserves_all_64_selected_targets(void) {
    static const char selected[] =
        "select_networks 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 "
        "21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 "
        "41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 "
        "61 62 63 64";
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModeEvilTwin,
        .selected_count = 64,
        .first_selected_ssid = "Target",
        .prefs = {
            .evil_html_id = 1,
            .evil_html_name = "portal.html",
            .evil_menu_index = 2,
        },
    };
    size_t length = strlen(selected);
    if(length >= sizeof(launch.select_networks)) length = sizeof(launch.select_networks) - 1;
    memcpy(launch.select_networks, selected, length);
    launch.select_networks[length] = '\0';
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    assert(module->on_input(state, &host, &ok) == C5InputSwitchTerminal);
    char expected[512];
    snprintf(expected, sizeof(expected), "select_html 1\n%s\nstart_evil_twin\n", selected);
    assert(strcmp(test.raw_tx, expected) == 0);
    module->leave(state, &host);
}

static void test_qr_preflight_requires_room_for_both_buffers(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModeEvilTwin,
        .prefs = {.evil_menu_index = 3},
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    module->on_input(state, &host, &ok);
    const uint8_t reply[] = "\"Lab\" \"secret\"\n>";
    module->on_bytes(state, &host, reply, sizeof(reply) - 1);
    size_t qr_bytes = qrcodegen_BUFFER_LEN_FOR_VERSION(10);
    test_free_heap = qr_bytes * 2 + 1024;
    test_max_block = qr_bytes + 128;
    module->on_input(state, &host, &ok);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "QR OOM"));
    assert(canvas.box_count == 1);
    test_free_heap = 1024 * 1024;
    test_max_block = 1024 * 1024;
    module->leave(state, &host);
}

static void test_failed_terminal_stop_keeps_running_for_retry(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModePortal,
        .prefs = {
            .portal_ssid = "Lab",
            .selected_html_id = 1,
            .selected_html_name = "portal.html",
            .portal_menu_index = 2,
        },
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(module->on_input(state, &host, &ok) == C5InputSwitchTerminal);
    test.raw_tx_failures_remaining = 1;
    assert(module->on_input(state, &host, &back) == C5InputConsumed);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "Portal On"));
    assert(module->on_input(state, &host, &back) == C5InputSwitchModule);
    assert(test.raw_tx_calls == 2 && strcmp(test.raw_tx, "stop\n") == 0);
    module->leave(state, &host);
    assert(test.raw_tx_calls == 2);
}

static void test_failed_timed_stop_retries_before_probe_refresh(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModeKarma,
        .karma_duration_sec = 15,
        .ticks_per_second = 1000,
        .probe_refresh_delay_ticks = 500,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    module->tick(state, &host, 0);
    module->on_input(state, &host, &ok);
    assert(test.raw_tx_calls == 1 && strcmp(test.raw_tx, "start_sniffer\n") == 0);
    test.raw_tx_failures_remaining = 1;
    module->tick(state, &host, 15000);
    assert(test.raw_tx_calls == 1);
    module->tick(state, &host, 15499);
    assert(test.raw_tx_calls == 1);
    module->tick(state, &host, 15500);
    assert(test.raw_tx_calls == 2 && strcmp(test.raw_tx, "stop\n") == 0);
    module->tick(state, &host, 16000);
    assert(test.raw_tx_calls == 3 && strcmp(test.raw_tx, "list_probes\n") == 0);
    module->leave(state, &host);
}

static void test_html_selection_is_shared_across_web_modes(void) {
    const C5ModuleV3* module = lab_c5_web_plugin_ep()->entry_point;
    TestHost test = {0};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &test,
        .send_raw_lines = send_raw_lines,
        .request_text_input = request_text_input,
        .request_redraw = redraw,
        .show_status = show_status,
        .save_session = save_session,
    };
    C5WebLaunchContext launch = {
        .version = C5_WEB_LAUNCH_VERSION,
        .size = sizeof(C5WebLaunchContext),
        .mode = C5WebModePortal,
        .prefs = {.portal_menu_index = 1},
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    module->on_input(state, &host, &ok);
    const uint8_t html[] = "HTML files found on SD card:\n2 shared.html\n>";
    module->on_bytes(state, &host, html, sizeof(html) - 1);
    module->on_input(state, &host, &ok);
    module->leave(state, &host);
    assert(test.save_calls == 1);
    assert(test.saved_prefs.selected_html_id == 2);
    assert(test.saved_prefs.evil_html_id == 2);
    assert(strcmp(test.saved_prefs.evil_html_name, "shared.html") == 0);

    launch.mode = C5WebModeEvilTwin;
    launch.prefs = test.saved_prefs;
    state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(canvas_has(&canvas, "shared.html"));
    module->leave(state, &host);
}

int main(void) {
    test_portal_listing_prompt_and_async_manual_ssid();
    test_evil_twin_launch_snapshot_and_three_command_start();
    test_web_launch_snapshot_rejects_bad_prefs();
    test_portal_passwords_select_and_raw_list();
    test_evil_twin_wifi_qr_is_owned_until_back();
    test_karma_collect_probe_html_and_start();
    test_karma_collect_unload_stops_once();
    test_karma_duration_controls_and_save();
    test_karma_does_not_replace_an_active_listing();
    test_karma_auto_refresh_waits_for_html_listing_and_popup();
    test_list_reply_does_not_take_over_another_screen();
    test_evil_twin_preserves_all_64_selected_targets();
    test_qr_preflight_requires_room_for_both_buffers();
    test_failed_terminal_stop_keeps_running_for_retry();
    test_failed_timed_stop_retries_before_probe_refresh();
    test_html_selection_is_shared_across_web_modes();
    test_web_allocations_respect_heap_preflight();
    puts("Web module tests passed");
    return 0;
}
