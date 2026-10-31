/* From FLIPPER in WSL:
 * cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Itests/stubs \
 *   tests/test_recon_sniffer_clients.c modules/recon/recon_module.c \
 *   modules/recon/recon_scan.c modules/recon/recon_sniffer_probe.c \
 *   modules/recon/recon_sniffer_clients.c -o /tmp/c5_recon_clients_test && \
 *   /tmp/c5_recon_clients_test
 */
#include "../module_api.h"
#include "../modules/recon/recon_module.h"
#include "../modules/recon/recon_sniffer_clients.h"
#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_recon_plugin_ep(void);

static const char snapshot[] =
    "{\"schema_version\":1,\"record_type\":\"sniffer_clients_begin\",\"aps\":2,\"clients\":2}\n"
    "{\"schema_version\":1,\"record_type\":\"sniffer_ap\",\"bssid\":\"02:00:00:00:00:01\",\"channel\":6,\"ssid_hex\":\"43616665\",\"ssid_source\":\"beacon\"}\n"
    "{\"schema_version\":1,\"record_type\":\"sniffer_client\",\"bssid\":\"02:00:00:00:00:01\",\"station\":\"02:00:00:00:01:01\"}\n"
    "{\"schema_version\":1,\"record_type\":\"sniffer_ap\",\"bssid\":\"02:00:00:00:00:02\",\"channel\":11,\"ssid_hex\":\"43616665\",\"ssid_source\":\"scan\"}\n"
    "{\"schema_version\":1,\"record_type\":\"sniffer_client\",\"bssid\":\"02:00:00:00:00:02\",\"station\":\"02:00:00:00:02:02\"}\n"
    "{\"schema_version\":1,\"record_type\":\"sniffer_clients_end\",\"aps\":2,\"clients\":2}\n";

static void model_feed(C5ReconClients* clients, const char* data, uint32_t tick) {
    c5_recon_clients_feed(clients, (const uint8_t*)data, strlen(data), tick);
}

static void test_complete_snapshot_keeps_duplicate_ssids_by_bssid(void) {
    C5ReconClients clients;
    c5_recon_clients_init(&clients);
    c5_recon_clients_begin(&clients, 10);
    for(size_t i = 0; i < strlen(snapshot); i++)
        c5_recon_clients_feed(&clients, (const uint8_t*)snapshot + i, 1, 20);
    assert(clients.phase == C5ReconClientsReady);
    assert(clients.ap_count == 2 && clients.client_count == 2);
    assert(strcmp(clients.aps[0].ssid, "Cafe") == 0);
    assert(strcmp(clients.aps[1].ssid, "Cafe") == 0);
    assert(strcmp(clients.aps[0].bssid, "02:00:00:00:00:01") == 0);
    assert(strcmp(clients.aps[1].bssid, "02:00:00:00:00:02") == 0);
    char command[80] = "unchanged";
    assert(c5_recon_clients_command(&clients, 1, command, sizeof(command)));
    assert(strcmp(command, "start_deauth_station 02:00:00:00:00:02 02:00:00:00:02:02") == 0);
    c5_recon_clients_free(&clients);
}

static void test_incomplete_and_bad_snapshots_never_make_command(void) {
    C5ReconClients clients;
    char command[80] = "unchanged";
    c5_recon_clients_init(&clients);
    c5_recon_clients_begin(&clients, 0);
    model_feed(&clients,
               "{\"schema_version\":1,\"record_type\":\"sniffer_clients_begin\",\"aps\":1,\"clients\":1}\n",
               1);
    assert(!c5_recon_clients_command(&clients, 0, command, sizeof(command)));
    assert(c5_recon_clients_tick(&clients, 5002) == C5ReconClientsListTimeout);
    assert(clients.phase == C5ReconClientsError && strcmp(command, "unchanged") == 0);
    c5_recon_clients_begin(&clients, 0);
    model_feed(&clients,
               "{\"schema_version\":1,\"record_type\":\"sniffer_clients_end\",\"aps\":0,\"clients\":0}\n",
               1);
    assert(clients.phase == C5ReconClientsError);
    c5_recon_clients_begin(&clients, 0);
    model_feed(&clients,
               "{\"schema_version\":2,\"record_type\":\"sniffer_clients_begin\",\"aps\":0,\"clients\":0}\n",
               1);
    assert(clients.phase == C5ReconClientsUnsupported);
    assert(!c5_recon_clients_command(&clients, 0, command, sizeof(command)));
    assert(strcmp(command, "unchanged") == 0);
    c5_recon_clients_free(&clients);
}

static void test_invalid_identity_and_rx_loss_fail_closed(void) {
    C5ReconClients clients;
    char command[80] = "unchanged";
    c5_recon_clients_init(&clients);
    c5_recon_clients_begin(&clients, 0);
    model_feed(&clients,
               "{\"schema_version\":1,\"record_type\":\"sniffer_clients_begin\",\"aps\":1,\"clients\":1}\n"
               "{\"schema_version\":1,\"record_type\":\"sniffer_ap\",\"bssid\":\"GG:00:00:00:00:01\",\"channel\":6,\"ssid_hex\":\"\",\"ssid_source\":\"none\"}\n",
               1);
    assert(clients.phase == C5ReconClientsError);
    assert(!c5_recon_clients_command(&clients, 0, command, sizeof(command)));
    c5_recon_clients_begin(&clients, 0);
    model_feed(&clients,
               "{\"schema_version\":1,\"record_type\":\"sniffer_clients_begin\",\"aps\":1,\"clients\":1}\n"
               "{\"schema_version\":1,\"record_type\":\"sniffer_ap\",\"bssid\":\"02:00:00:00:00:01\",\"channel\":6,\"ssid_hex\":\"\",\"ssid_source\":\"none\"}\n"
               "{\"schema_version\":1,\"record_type\":\"sniffer_client\",\"bssid\":\"02:00:00:00:00:01\",\"station\":\"FF:FF:FF:FF:FF:FF\"}\n",
               1);
    assert(clients.phase == C5ReconClientsError);
    c5_recon_clients_begin(&clients, 0);
    char long_line[300];
    memset(long_line, 'X', sizeof(long_line));
    long_line[0] = '{';
    long_line[sizeof(long_line) - 1] = '\n';
    c5_recon_clients_feed(&clients, (const uint8_t*)long_line, sizeof(long_line), 1);
    assert(clients.phase == C5ReconClientsError);
    assert(!c5_recon_clients_command(&clients, 0, command, sizeof(command)));
    c5_recon_clients_free(&clients);
}

static void test_old_janos_and_radio_refusal_are_explicit(void) {
    C5ReconClients clients;
    c5_recon_clients_init(&clients);
    c5_recon_clients_begin(&clients, 0);
    model_feed(&clients, "Unknown command: show_sniffer_clients\n>\n", 1);
    assert(clients.phase == C5ReconClientsUnsupported);
    c5_recon_clients_begin(&clients, 0);
    model_feed(&clients,
               "[WFACTL1] {\"v\":1,\"type\":\"error\",\"code\":\"busy\",\"command\":\"console\"}\n",
               1);
    assert(clients.phase == C5ReconClientsError);
    assert(strstr(clients.error, "busy"));
    c5_recon_clients_begin(&clients, 0);
    model_feed(&clients,
               "[WFACTL1] {\"v\":4294967297,\"type\":\"error\",\"code\":\"busy\",\"command\":\"console\"}\n",
               1);
    assert(clients.phase == C5ReconClientsLoading);
    c5_recon_clients_free(&clients);
}

static void test_start_requires_matching_ack_and_times_out(void) {
    C5ReconClients clients;
    c5_recon_clients_init(&clients);
    c5_recon_clients_begin(&clients, 0);
    model_feed(&clients, snapshot, 1);
    c5_recon_clients_start_sent(&clients, 1, 2);
    assert(clients.phase == C5ReconClientsStarting);
    model_feed(&clients,
               "{\"schema_version\":1,\"record_type\":\"station_deauth\",\"status\":\"started\",\"bssid\":\"02:00:00:00:00:01\",\"station\":\"02:00:00:00:01:01\"}\n",
               3);
    assert(clients.phase == C5ReconClientsStarting);
    assert(c5_recon_clients_tick(&clients, 15002) == C5ReconClientsStartTimeout);
    assert(clients.phase == C5ReconClientsReloadRequired);
    c5_recon_clients_begin(&clients, 0);
    model_feed(&clients, snapshot, 1);
    c5_recon_clients_start_sent(&clients, 1, 2);
    model_feed(&clients,
               "{\"schema_version\":1,\"record_type\":\"station_deauth\",\"status\":\"started\",\"bssid\":\"02:00:00:00:00:02\",\"station\":\"02:00:00:00:02:02\"}\n",
               3);
    assert(clients.phase == C5ReconClientsActive);
    c5_recon_clients_free(&clients);
}

typedef struct {
    char tx[1024];
    size_t tx_length;
    unsigned sends;
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
static void redraw(void* ctx) { (void)ctx; }
static void status(void* ctx, const char* message, uint32_t duration, bool fullscreen) {
    (void)ctx; (void)message; (void)duration; (void)fullscreen;
}
void canvas_set_color(Canvas* canvas, Color color) { (void)canvas; (void)color; }
void canvas_set_font(Canvas* canvas, Font font) { (void)canvas; (void)font; }
void canvas_draw_str(Canvas* canvas, int x, int y, const char* line) {
    (void)x; (void)y;
    assert(canvas->line_count < 16);
    snprintf(canvas->lines[canvas->line_count++], sizeof(canvas->lines[0]), "%s", line);
}
void canvas_draw_str_aligned(Canvas* canvas, int x, int y, Align h, Align v, const char* line) {
    (void)h; (void)v; canvas_draw_str(canvas, x, y, line);
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
    for(size_t i = 0; i < canvas->line_count; i++)
        if(strcmp(canvas->lines[i], line) == 0) return true;
    return false;
}

static const C5ModuleV3* module(void) {
    const FlipperAppPluginDescriptor* descriptor = lab_c5_recon_plugin_ep();
    assert(descriptor && descriptor->ep_api_version == C5_MODULE_API_VERSION);
    return descriptor->entry_point;
}

static C5HostApiV3 host_api(TestHost* ctx) {
    C5HostApiV3 host = {.version = C5_MODULE_API_VERSION,
                        .size = sizeof(C5HostApiV3),
                        .ctx = ctx,
                        .send_raw_lines = send_raw_lines,
                        .request_redraw = redraw,
                        .show_status = status};
    return host;
}

static void test_ui_selects_second_bssid_and_back_stops(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    C5ReconLaunchContext launch = {.version = C5_RECON_LAUNCH_VERSION,
                                   .size = sizeof(C5ReconLaunchContext),
                                   .mode = C5ReconModeSnifferResults};
    const C5ModuleV3* recon = module();
    void* state = recon->enter(&host, &launch, sizeof(launch));
    assert(state);
    recon->tick(state, &host, 1);
    assert(strcmp(ctx.tx, "show_sniffer_results\n") == 0);
    InputEvent long_right = {.type = InputTypeLong, .key = InputKeyRight};
    assert(recon->on_input(state, &host, &long_right) == C5InputConsumed);
    assert(strcmp(ctx.tx, "show_sniffer_results\nshow_sniffer_clients\n") == 0);
    recon->on_bytes(state, &host, (const uint8_t*)snapshot, strlen(snapshot));
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent right = {.type = InputTypeShort, .key = InputKeyRight};
    recon->on_input(state, &host, &down);
    Canvas canvas = {0};
    recon->draw(state, &host, &canvas);
    assert(has_line(&canvas, "02:00:00:00:00:02"));
    recon->on_input(state, &host, &ok);
    assert(recon->on_input(state, &host, &right) == C5InputConsumed);
    assert(strstr(ctx.tx, "start_deauth_station 02:00:00:00:00:02 02:00:00:00:02:02\n"));
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(recon->on_input(state, &host, &back) == C5InputSwitchModule);
    assert(strstr(ctx.tx, "stop\nunselect_stations\nclear_sniffer_results\n"));
    size_t length = ctx.tx_length;
    recon->leave(state, &host);
    assert(ctx.tx_length == length);
}

static void test_ui_incomplete_snapshot_cannot_send_deauth(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    C5ReconLaunchContext launch = {.version = C5_RECON_LAUNCH_VERSION,
                                   .size = sizeof(C5ReconLaunchContext),
                                   .mode = C5ReconModeSnifferResults};
    const C5ModuleV3* recon = module();
    void* state = recon->enter(&host, &launch, sizeof(launch));
    assert(state);
    recon->tick(state, &host, 1);
    InputEvent long_right = {.type = InputTypeLong, .key = InputKeyRight};
    recon->on_input(state, &host, &long_right);
    const char* partial = "{\"schema_version\":1,\"record_type\":\"sniffer_clients_begin\",\"aps\":1,\"clients\":1}\n";
    recon->on_bytes(state, &host, (const uint8_t*)partial, strlen(partial));
    recon->tick(state, &host, 6000);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent right = {.type = InputTypeShort, .key = InputKeyRight};
    recon->on_input(state, &host, &ok);
    recon->on_input(state, &host, &right);
    assert(!strstr(ctx.tx, "start_deauth_station"));
    recon->leave(state, &host);
}

static void test_ui_early_client_view_does_not_send_stale_legacy_query(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    C5ReconLaunchContext launch = {.version = C5_RECON_LAUNCH_VERSION,
                                   .size = sizeof(C5ReconLaunchContext),
                                   .mode = C5ReconModeSnifferResults};
    const C5ModuleV3* recon = module();
    void* state = recon->enter(&host, &launch, sizeof(launch));
    assert(state);
    InputEvent long_right = {.type = InputTypeLong, .key = InputKeyRight};
    recon->on_input(state, &host, &long_right);
    recon->tick(state, &host, 1);
    assert(strcmp(ctx.tx, "show_sniffer_clients\n") == 0);
    recon->leave(state, &host);
}

static void test_ui_stop_request_keeps_uncertain_station_out_of_legacy(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    C5ReconLaunchContext launch = {.version = C5_RECON_LAUNCH_VERSION,
                                   .size = sizeof(C5ReconLaunchContext),
                                   .mode = C5ReconModeSnifferResults};
    const C5ModuleV3* recon = module();
    void* state = recon->enter(&host, &launch, sizeof(launch));
    assert(state);
    recon->tick(state, &host, 1);
    InputEvent long_right = {.type = InputTypeLong, .key = InputKeyRight};
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent right = {.type = InputTypeShort, .key = InputKeyRight};
    InputEvent left = {.type = InputTypeShort, .key = InputKeyLeft};
    recon->on_input(state, &host, &long_right);
    recon->on_bytes(state, &host, (const uint8_t*)snapshot, strlen(snapshot));
    recon->on_input(state, &host, &ok);
    recon->on_input(state, &host, &right);
    const char* started =
        "{\"schema_version\":1,\"record_type\":\"station_deauth\",\"status\":\"started\",\"bssid\":\"02:00:00:00:00:01\",\"station\":\"02:00:00:00:01:01\"}\n";
    recon->on_bytes(state, &host, (const uint8_t*)started, strlen(started));
    recon->on_input(state, &host, &left);
    size_t after_stop = ctx.tx_length;
    assert(after_stop >= 5 && strcmp(ctx.tx + after_stop - 5, "stop\n") == 0);
    recon->on_input(state, &host, &left);
    assert(ctx.tx_length == after_stop);
    assert(!strstr(ctx.tx, "stop\nshow_sniffer_results\n"));
    recon->leave(state, &host);
}

static void test_ui_old_janos_returns_to_legacy_results(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    C5ReconLaunchContext launch = {.version = C5_RECON_LAUNCH_VERSION,
                                   .size = sizeof(C5ReconLaunchContext),
                                   .mode = C5ReconModeSnifferResults};
    const C5ModuleV3* recon = module();
    void* state = recon->enter(&host, &launch, sizeof(launch));
    assert(state);
    recon->tick(state, &host, 1);
    InputEvent long_right = {.type = InputTypeLong, .key = InputKeyRight};
    InputEvent left = {.type = InputTypeShort, .key = InputKeyLeft};
    recon->on_input(state, &host, &long_right);
    const char* unknown = "Unknown command: show_sniffer_clients\n>\n";
    recon->on_bytes(state, &host, (const uint8_t*)unknown, strlen(unknown));
    Canvas canvas = {0};
    recon->draw(state, &host, &canvas);
    assert(has_line(&canvas, "Update JanOS for clients"));
    recon->on_input(state, &host, &left);
    assert(strcmp(ctx.tx,
                  "show_sniffer_results\nshow_sniffer_clients\nshow_sniffer_results\n") == 0);
    const char* legacy = "Cafe, CH6: 1\n02:00:00:00:01:01\n>\n";
    recon->on_bytes(state, &host, (const uint8_t*)legacy, strlen(legacy));
    canvas = (Canvas){0};
    recon->draw(state, &host, &canvas);
    assert(has_line(&canvas, "Cafe"));
    recon->leave(state, &host);
}

int main(void) {
    test_complete_snapshot_keeps_duplicate_ssids_by_bssid();
    test_incomplete_and_bad_snapshots_never_make_command();
    test_invalid_identity_and_rx_loss_fail_closed();
    test_old_janos_and_radio_refusal_are_explicit();
    test_start_requires_matching_ack_and_times_out();
    test_ui_selects_second_bssid_and_back_stops();
    test_ui_incomplete_snapshot_cannot_send_deauth();
    test_ui_early_client_view_does_not_send_stale_legacy_query();
    test_ui_stop_request_keeps_uncertain_station_out_of_legacy();
    test_ui_old_janos_returns_to_legacy_results();
    puts("recon clients tests passed");
    return 0;
}
