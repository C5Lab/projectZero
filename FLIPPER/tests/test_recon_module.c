/* From FLIPPER in WSL:
 * cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Itests/stubs \
 *   tests/test_recon_module.c modules/recon/recon_module.c \
 *   modules/recon/recon_scan.c modules/recon/recon_sniffer_probe.c \
 *   modules/recon/recon_sniffer_clients.c \
 *   -o /tmp/c5_recon_module_test && /tmp/c5_recon_module_test
 */
#include "../module_api.h"
#include "../modules/recon/recon_module.h"
#include "../modules/recon/recon_targets.h"
#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_recon_plugin_ep(void);

typedef struct {
    char tx[1024];
    size_t tx_length;
    unsigned sends;
    unsigned redraws;
    unsigned saves;
    uint16_t selected_number;
    size_t selected_count;
    uint16_t selected_numbers[C5_RECON_SAFE_SELECTED_NETWORKS];
    char status[64];
} TestHost;

static bool send_raw_lines(void* ctx, const char* lines, size_t length) {
    TestHost* test = ctx;
    assert(lines && length && length + test->tx_length < sizeof(test->tx));
    memcpy(test->tx + test->tx_length, lines, length);
    test->tx_length += length;
    test->tx[test->tx_length] = '\0';
    test->sends++;
    return true;
}

static void redraw(void* ctx) { ((TestHost*)ctx)->redraws++; }
static void show_status(void* ctx, const char* message, uint32_t duration, bool fullscreen) {
    (void)duration; (void)fullscreen;
    snprintf(((TestHost*)ctx)->status, sizeof(((TestHost*)ctx)->status), "%s", message);
}

static void save_session(void* ctx, const void* payload, size_t size) {
    TestHost* test = ctx;
    const C5ReconTargetSession* session = payload;
    assert(size == sizeof(*session));
    assert(session->version == C5_RECON_TARGET_SESSION_VERSION);
    assert(session->size == sizeof(*session));
    test->saves++;
    test->selected_count = session->selected_count;
    if(session->selected_count) {
        assert(session->selected_numbers && session->results);
        test->selected_number = session->selected_numbers[0];
        assert(session->result_count > 0);
        if(session->selected_count <= C5_RECON_SAFE_SELECTED_NETWORKS) {
            memcpy(test->selected_numbers, session->selected_numbers,
                   session->selected_count * sizeof(uint16_t));
        }
    }
}

static void capture(Canvas* canvas, const char* line) {
    assert(canvas->line_count < 16);
    snprintf(canvas->lines[canvas->line_count++], sizeof(canvas->lines[0]), "%s", line);
}
void canvas_set_color(Canvas* canvas, Color color) { (void)canvas; (void)color; }
void canvas_set_font(Canvas* canvas, Font font) { (void)canvas; (void)font; }
void canvas_draw_str(Canvas* canvas, int x, int y, const char* line) {
    (void)x; (void)y; capture(canvas, line);
}
void canvas_draw_str_aligned(Canvas* canvas, int x, int y, Align h, Align v, const char* line) {
    (void)x; (void)y; (void)h; (void)v; capture(canvas, line);
}
void canvas_draw_box(Canvas* canvas, int x, int y, int w, int h) {
    (void)canvas; (void)x; (void)y; (void)w; (void)h;
}
void canvas_draw_rbox(Canvas* canvas, int x, int y, int w, int h, int r) {
    (void)canvas; (void)x; (void)y; (void)w; (void)h; (void)r;
}
void canvas_draw_rframe(Canvas* canvas, int x, int y, int w, int h, int r) {
    (void)canvas; (void)x; (void)y; (void)w; (void)h; (void)r;
}

static bool has_line(const Canvas* canvas, const char* line) {
    for(size_t i = 0; i < canvas->line_count; i++) {
        if(strcmp(canvas->lines[i], line) == 0) return true;
    }
    return false;
}

static const C5ModuleV3* recon_module(void) {
    const FlipperAppPluginDescriptor* descriptor = lab_c5_recon_plugin_ep();
    assert(descriptor && descriptor->ep_api_version == C5_MODULE_API_VERSION);
    const C5ModuleV3* module = descriptor->entry_point;
    assert(module && module->version == C5_MODULE_API_VERSION && module->size == sizeof(*module));
    return module;
}

static C5HostApiV3 test_api(TestHost* context) {
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = context,
        .send_raw_lines = send_raw_lines,
        .request_redraw = redraw,
        .show_status = show_status,
        .save_session = save_session,
    };
    return host;
}

static void feed(const C5ModuleV3* module, void* state, const C5HostApiV3* host, const char* data) {
    module->on_bytes(state, host, (const uint8_t*)data, strlen(data));
}

static void test_scanner(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeScanner,
        .min_power_dbm = -110,
        .field_mask = C5ReconFieldAll,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state && context.sends == 0);
    module->tick(state, &host, 1);
    assert(strcmp(context.tx, "scan_networks\n") == 0);
    const char* summary =
        "WiFi scan completed. Found 1 networks\n"
        "\"1\",\"Home\",\"Acme\",\"AA:BB:CC:DD:EE:01\",\"6\",\"WPA2\",\"-55\",\"2.4GHz\"\n"
        "Scan results printed.\n";
    for(size_t i = 0; summary[i]; i++) module->on_bytes(state, &host, (const uint8_t*)&summary[i], 1);
    InputEvent right = {.type = InputTypeShort, .key = InputKeyRight};
    assert(module->on_input(state, &host, &right) == C5InputConsumed);
    assert(strcmp(context.tx, "scan_networks\nshow_scan_results\n") == 0);
    const char* row = "\"1\",\"Home\",\"Acme\",\"AA:BB:CC:DD:EE:01\",\"6\",\"WPA2\",\"-55\",\"2.4GHz\"\nScan results printed.\n";
    for(size_t i = 0; row[i]; i++) module->on_bytes(state, &host, (const uint8_t*)&row[i], 1);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(has_line(&canvas, "1 Home (Acme)"));
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    assert(module->on_input(state, &host, &ok) == C5InputConsumed);
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(has_line(&canvas, "Right: actions (1)"));
    assert(module->on_input(state, &host, &right) == C5InputOpenAttacks);
    module->leave(state, &host);
    assert(context.saves == 1 && context.selected_count == 1 && context.selected_number == 1);
}

static void test_sniffer_start_results_and_stop(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    const uint16_t selected[] = {7, 9};
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeSnifferStart,
        .selected_count = 2,
        .selected_numbers = selected,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state && context.sends == 0);
    module->tick(state, &host, 1);
    assert(strcmp(context.tx, "select_networks 7 9\nstart_sniffer\n") == 0 && context.sends == 1);
    feed(module, state, &host, "Starting sniffer in FAST mode\nSniffer packet count: 243\n");
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(has_line(&canvas, "Packets: 243"));
    InputEvent right = {.type = InputTypeShort, .key = InputKeyRight};
    assert(module->on_input(state, &host, &right) == C5InputConsumed);
    assert(strcmp(context.tx, "select_networks 7 9\nstart_sniffer\nstop\nshow_sniffer_results\n") == 0);
    feed(module, state, &host, "Cafe, CH6: 1\nAA:BB:CC:DD:EE:FF\n>\n");
    canvas = (Canvas){0};
    module->draw(state, &host, &canvas);
    assert(has_line(&canvas, "Cafe"));
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    assert(module->on_input(state, &host, &ok) == C5InputConsumed);
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(module->on_input(state, &host, &back) == C5InputSwitchModule);
    assert(strstr(context.tx, "unselect_stations\nclear_sniffer_results\n"));
    size_t stopped_length = context.tx_length;
    module->leave(state, &host);
    assert(context.tx_length == stopped_length); /* Back already cleaned up. */
    assert(context.saves == 0);
}

static void test_scan_results_back_without_selection_exits(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeScanner,
        .min_power_dbm = -110,
        .field_mask = C5ReconFieldAll,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    module->tick(state, &host, 1);
    feed(module, state, &host,
         "\"1\",\"Home\",\"\",\"AA:BB:CC:DD:EE:01\",\"6\",\"WPA2\",\"-55\",\"2.4GHz\"\n"
         "Scan results printed.\n");
    InputEvent right = {.type = InputTypeShort, .key = InputKeyRight};
    assert(module->on_input(state, &host, &right) == C5InputConsumed);
    feed(module, state, &host,
         "\"1\",\"Home\",\"\",\"AA:BB:CC:DD:EE:01\",\"6\",\"WPA2\",\"-55\",\"2.4GHz\"\n"
         "Scan results printed.\n");
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(module->on_input(state, &host, &back) == C5InputSwitchModule);
    module->leave(state, &host);
    assert(context.saves == 1 && context.selected_count == 0);
}

static void test_scan_selection_limit_is_six(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeScanner,
        .min_power_dbm = -110,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    module->tick(state, &host, 1);
    feed(module, state, &host,
         "\"1\",\"One\",\"\",\"AA:BB:CC:DD:EE:01\",\"1\",\"WPA2\",\"-40\",\"2.4\"\n"
         "Scan results printed.\n");
    InputEvent right = {.type = InputTypeShort, .key = InputKeyRight};
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    InputEvent up = {.type = InputTypeShort, .key = InputKeyUp};
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    assert(module->on_input(state, &host, &right) == C5InputConsumed);
    char row[128];
    for(unsigned i = 1; i <= 7; i++) {
        snprintf(row, sizeof(row),
                 "\"%u\",\"Net%u\",\"\",\"AA:BB:CC:DD:EE:%02X\",\"1\",\"WPA2\",\"-40\",\"2.4\"\n",
                 i, i, i);
        feed(module, state, &host, row);
    }
    feed(module, state, &host, "Scan results printed.\n");
    for(unsigned i = 0; i < C5_RECON_SAFE_SELECTED_NETWORKS; i++) {
        assert(module->on_input(state, &host, &ok) == C5InputConsumed);
        assert(module->on_input(state, &host, &down) == C5InputConsumed);
    }
    assert(module->on_input(state, &host, &ok) == C5InputConsumed);
    assert(strcmp(context.status, "Select at most 6 networks") == 0);
    assert(module->on_input(state, &host, &up) == C5InputConsumed);
    assert(module->on_input(state, &host, &ok) == C5InputConsumed); /* Deselect sixth. */
    assert(module->on_input(state, &host, &down) == C5InputConsumed);
    assert(module->on_input(state, &host, &ok) == C5InputConsumed); /* Select seventh. */
    assert(module->on_input(state, &host, &right) == C5InputOpenAttacks);
    module->leave(state, &host);
    assert(context.selected_count == C5_RECON_SAFE_SELECTED_NETWORKS);
    assert(context.selected_numbers[0] == 1 && context.selected_numbers[5] == 7);
}

static void test_scan_still_running_finishes_command_state(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeScanner,
        .min_power_dbm = -110,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    module->tick(state, &host, 1);
    feed(module, state, &host, "Scan still in progress... Please wait.\n");
    assert(strcmp(context.status, "Scan still running") == 0);
    module->leave(state, &host);
    assert(strcmp(context.tx, "scan_networks\n") == 0);
}

static void test_scan_error_does_not_open_results_or_stop_again(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeScanner,
        .min_power_dbm = -110,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    module->tick(state, &host, 1);
    feed(module, state, &host,
         "\"1\",\"One\",\"\",\"AA:BB:CC:DD:EE:01\",\"1\",\"WPA2\",\"-40\",\"2.4\"\n"
         "Scan failed with status: 1\n");
    assert(strcmp(context.status, "Scan failed") == 0);
    InputEvent right = {.type = InputTypeShort, .key = InputKeyRight};
    assert(module->on_input(state, &host, &right) == C5InputConsumed);
    module->leave(state, &host);
    assert(strcmp(context.tx, "scan_networks\n") == 0);
}

static void test_probe_results_and_back(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeProbeResults,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    module->tick(state, &host, 1);
    assert(strcmp(context.tx, "show_probes\n") == 0);
    feed(module, state, &host, "Probe requests: 1\nCafe (AA:BB:CC:DD:EE:01)\n>\n");
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(has_line(&canvas, "Cafe"));
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(module->on_input(state, &host, &back) == C5InputSwitchModule);
    assert(strcmp(context.tx, "show_probes\nstop\nunselect_stations\nclear_sniffer_results\n") == 0);
    module->leave(state, &host);
    assert(context.saves == 0);
}

static void test_forced_leave_stops_active_sniffer(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    const uint16_t selected[] = {1, 2, 3, 4, 5, 6, 7};
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeSnifferResume,
        .selected_count = 7,
        .selected_numbers = selected,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    module->tick(state, &host, 1);
    assert(strcmp(context.tx, "start_sniffer_noscan\n") == 0);
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(has_line(&canvas, "All networks"));
    module->leave(state, &host);
    assert(strcmp(context.tx,
                  "start_sniffer_noscan\nstop\nunselect_stations\nclear_sniffer_results\n") == 0);
}

static void test_probe_left_owns_sniffer_cleanup(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeProbeResults,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    module->tick(state, &host, 1);
    InputEvent left = {.type = InputTypeShort, .key = InputKeyLeft};
    assert(module->on_input(state, &host, &left) == C5InputConsumed);
    assert(strcmp(context.tx, "show_probes\nshow_sniffer_results\n") == 0);
    feed(module, state, &host, "Cafe, CH6: 1\nAA:BB:CC:DD:EE:FF\n>\n");
    Canvas canvas = {0};
    module->draw(state, &host, &canvas);
    assert(has_line(&canvas, "Cafe"));
    module->leave(state, &host);
    assert(strcmp(context.tx,
                  "show_probes\nshow_sniffer_results\nstop\nunselect_stations\nclear_sniffer_results\n") == 0);
}

static void test_selected_station_survives_attacks_handoff(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    const uint16_t selected_network = 7;
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeSnifferResults,
        .selected_count = 1,
        .selected_numbers = &selected_network,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    module->tick(state, &host, 1);
    feed(module, state, &host, "Cafe, CH6: 1\nAA:BB:CC:DD:EE:FF\n>\n");
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent right = {.type = InputTypeShort, .key = InputKeyRight};
    assert(module->on_input(state, &host, &ok) == C5InputConsumed);
    assert(module->on_input(state, &host, &right) == C5InputOpenAttacks);
    size_t handoff_length = context.tx_length;
    module->leave(state, &host);
    assert(context.tx_length == handoff_length);
    assert(strcmp(context.tx,
                  "show_sniffer_results\nselect_stations AA:BB:CC:DD:EE:FF\n") == 0);
}

static void test_legacy_oversized_selection_cannot_open_attacks(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    const uint16_t selected[] = {1, 2, 3, 4, 5, 6, 7};
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeSnifferResults,
        .selected_count = 7,
        .selected_numbers = selected,
    };
    void* state = module->enter(&host, &launch, sizeof(launch));
    assert(state);
    module->tick(state, &host, 1);
    feed(module, state, &host, "Cafe, CH6: 1\nAA:BB:CC:DD:EE:FF\n>\n");
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent right = {.type = InputTypeShort, .key = InputKeyRight};
    assert(module->on_input(state, &host, &ok) == C5InputConsumed);
    assert(module->on_input(state, &host, &right) == C5InputConsumed);
    assert(strcmp(context.status, "Rescan: max 6 networks") == 0);
    assert(strcmp(context.tx, "show_sniffer_results\n") == 0);
    module->leave(state, &host);
}

static void test_bad_launch_does_not_transmit(void) {
    const C5ModuleV3* module = recon_module();
    TestHost context = {0};
    C5HostApiV3 host = test_api(&context);
    C5ReconLaunchContext launch = {
        .version = C5_RECON_LAUNCH_VERSION + 1,
        .size = sizeof(C5ReconLaunchContext),
        .mode = C5ReconModeScanner,
    };
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    assert(context.sends == 0);
    const uint16_t too_many[] = {1, 2, 3, 4, 5, 6, 7};
    launch.version = C5_RECON_LAUNCH_VERSION;
    launch.mode = C5ReconModeSnifferStart;
    launch.selected_count = 7;
    launch.selected_numbers = too_many;
    assert(module->enter(&host, &launch, sizeof(launch)) == NULL);
    assert(context.sends == 0);
}

int main(void) {
    test_scanner();
    test_scan_results_back_without_selection_exits();
    test_scan_selection_limit_is_six();
    test_scan_still_running_finishes_command_state();
    test_scan_error_does_not_open_results_or_stop_again();
    test_sniffer_start_results_and_stop();
    test_probe_results_and_back();
    test_forced_leave_stops_active_sniffer();
    test_probe_left_owns_sniffer_cleanup();
    test_selected_station_survives_attacks_handoff();
    test_legacy_oversized_selection_cannot_open_attacks();
    test_bad_launch_does_not_transmit();
    puts("recon module tests passed");
    return 0;
}
