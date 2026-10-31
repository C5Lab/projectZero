/* From FLIPPER in WSL:
 * cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Itests/stubs \
 *   tests/test_nmap_module.c modules/nmap/nmap_module.c \
 *   -o /tmp/c5_nmap_module_test && /tmp/c5_nmap_module_test
 */
#include "../module_api.h"
#include "../modules/nmap/nmap_module.h"
#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_nmap_plugin_ep(void);

typedef struct {
    char tx[16][96];
    size_t tx_count;
    unsigned redraws;
    bool fail_send;
} TestHost;

static bool send_raw(void* context, const char* bytes, size_t length) {
    TestHost* host = context;
    assert(bytes && length && bytes[length - 1] == '\n' && !memchr(bytes, '\0', length));
    assert(length < sizeof(host->tx[0]) && host->tx_count < 16);
    if(host->fail_send) return false;
    memcpy(host->tx[host->tx_count], bytes, length);
    host->tx[host->tx_count++][length] = '\0';
    return true;
}

static void redraw(void* context) { ((TestHost*)context)->redraws++; }
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

static bool has_line(const Canvas* canvas, const char* expected) {
    for(size_t i = 0; i < canvas->line_count; i++)
        if(strcmp(canvas->lines[i], expected) == 0) return true;
    return false;
}

static const C5ModuleV3* module(void) {
    const FlipperAppPluginDescriptor* descriptor = lab_c5_nmap_plugin_ep();
    assert(descriptor && descriptor->ep_api_version == C5_MODULE_API_VERSION);
    const C5ModuleV3* result = descriptor->entry_point;
    assert(result && result->version == C5_MODULE_API_VERSION && result->size == sizeof(*result));
    return result;
}

static C5HostApiV3 host_api(TestHost* context) {
    C5HostApiV3 host = {.version = C5_MODULE_API_VERSION,
                        .size = sizeof(C5HostApiV3),
                        .ctx = context,
                        .send_raw_lines = send_raw,
                        .request_redraw = redraw};
    return host;
}

static void* launch(const C5ModuleV3* nmap, const C5HostApiV3* host) {
    C5NmapLaunchContext context = {.version = C5_NMAP_LAUNCH_VERSION,
                                   .size = sizeof(C5NmapLaunchContext),
                                   .ticks_per_second = 1000};
    return nmap->enter(host, &context, sizeof(context));
}

static void feed(const C5ModuleV3* nmap, void* state, const C5HostApiV3* host,
                 const char* text) {
    nmap->on_bytes(state, host, (const uint8_t*)text, strlen(text));
}

static Canvas draw(const C5ModuleV3* nmap, void* state, const C5HostApiV3* host) {
    Canvas canvas = {0};
    nmap->draw(state, host, &canvas);
    return canvas;
}

static const char hosts_two[] =
    "I (123) projectZero: === Discovered Hosts ===\r\n"
    "I (124) projectZero:   192.168.1.10  ->  AA:BB:CC:DD:EE:10  [ARP]\r\n"
    "I (125) projectZero:   192.168.1.20  ->  (MAC unknown)  [ICMP]\r\n"
    "I (126) projectZero: ========================\r\n"
    "I (127) projectZero: Found 2 hosts (1 via ARP, 1 via ICMP)\r\n";

static void test_launch_and_single_host_medium(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    const C5ModuleV3* nmap = module();
    void* state = launch(nmap, &host);
    assert(state && ctx.tx_count == 1 && strcmp(ctx.tx[0], "list_hosts\n") == 0);
    for(size_t i = 0; i < strlen(hosts_two); i++)
        nmap->on_bytes(state, &host, (const uint8_t*)hosts_two + i, 1);
    Canvas canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "All hosts (2)"));
    InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    nmap->on_input(state, &host, &down);
    nmap->on_input(state, &host, &down);
    canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "192.168.1.20"));
    nmap->on_input(state, &host, &ok);
    nmap->on_input(state, &host, &down);
    canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "Medium (50 ports)"));
    nmap->on_input(state, &host, &ok);
    assert(ctx.tx_count == 2);
    assert(strcmp(ctx.tx[1], "start_nmap medium 192.168.1.20\n") == 0);
    nmap->leave(state, &host);
}

static void test_all_hosts_quick_and_heavy_commands(void) {
    const char* expected[] = {"start_nmap quick\n", "start_nmap heavy\n"};
    for(unsigned pass = 0; pass < 2; pass++) {
        TestHost ctx = {0};
        C5HostApiV3 host = host_api(&ctx);
        const C5ModuleV3* nmap = module();
        void* state = launch(nmap, &host);
        assert(state);
        feed(nmap, state, &host, hosts_two);
        InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
        InputEvent down = {.type = InputTypeShort, .key = InputKeyDown};
        nmap->on_input(state, &host, &ok); /* All hosts. */
        if(pass == 1) {
            nmap->on_input(state, &host, &down);
            nmap->on_input(state, &host, &down);
        }
        nmap->on_input(state, &host, &ok);
        assert(ctx.tx_count == 2 && strcmp(ctx.tx[1], expected[pass]) == 0);
        nmap->leave(state, &host);
    }
}

static void test_results_and_back_only_after_summary(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    const C5ModuleV3* nmap = module();
    void* state = launch(nmap, &host);
    feed(nmap, state, &host, hosts_two);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    nmap->on_input(state, &host, &ok);
    nmap->on_input(state, &host, &ok);
    assert(strcmp(ctx.tx[1], "start_nmap quick\n") == 0);
    feed(nmap, state, &host,
         "I (128) projectZero: Scan level: quick (20 ports)\n"
         "I (129) projectZero: Scanning 2 host(s), 20 ports each (quick)...\n"
         "I (130) projectZero: === NMAP Scan Results ===\n"
         "I (131) projectZero: Host: 192.168.1.10  (AA:BB:CC:DD:EE:10)\n"
         "I (132) projectZero:   Scanning 192.168.1.10 ports 21-143 [1/20] ...\n"
         "I (133) projectZero:      22/tcp  open  SSH\n");
    assert(nmap->on_input(state, &host, &back) == C5InputConsumed);
    assert(ctx.tx_count == 2); /* A queued stop would run after synchronous scan. */
    Canvas canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "Scan in progress"));
    feed(nmap, state, &host,
         "I (134) projectZero: Host: 192.168.1.20  (MAC unknown)\n"
         "I (135) projectZero:     80/tcp  open  HTTP\n"
         "I (136) projectZero: =========================\n"
         "I (137) projectZero: Scanned 2 hosts, found 2 open ports\n> ");
    canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "2 hosts, 2 open ports"));
    assert(has_line(&canvas, "80/tcp open HTTP"));
    assert(has_line(&canvas, "Recent lines Up/Down"));
    assert(nmap->on_input(state, &host, &back) == C5InputSwitchModule);
    nmap->leave(state, &host);
    assert(ctx.tx_count == 2);
}

static void test_not_connected_is_not_empty_and_can_retry(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    const C5ModuleV3* nmap = module();
    void* state = launch(nmap, &host);
    feed(nmap, state, &host,
         "I (124) projectZero: Not connected to any AP. Use 'wifi_connect' first.\n");
    Canvas canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "Use wifi_connect"));
    assert(has_line(&canvas, "via JanOS CLI"));
    InputEvent long_ok = {.type = InputTypeLong, .key = InputKeyOk};
    assert(nmap->on_input(state, &host, &long_ok) == C5InputConsumed);
    assert(ctx.tx_count == 1);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    nmap->on_input(state, &host, &ok);
    assert(ctx.tx_count == 2 && strcmp(ctx.tx[1], "list_hosts\n") == 0);
    feed(nmap, state, &host,
         "=== Discovered Hosts ===\n========================\n"
         "Found 0 hosts (0 via ARP, 0 via ICMP)\n");
    canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "All hosts (0)"));
    nmap->leave(state, &host);
}

static void test_bad_host_snapshot_and_rx_loss_block_scan(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    const C5ModuleV3* nmap = module();
    void* state = launch(nmap, &host);
    feed(nmap, state, &host,
         "=== Discovered Hosts ===\n"
         "  192.168.1.7;stop  ->  AA:BB:CC:DD:EE:07  [ARP]\n"
         "========================\n"
         "Found 1 hosts (1 via ARP, 0 via ICMP)\n");
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    Canvas canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "Host list incomplete"));
    nmap->on_input(state, &host, &ok);
    assert(ctx.tx_count == 2 && strcmp(ctx.tx[1], "list_hosts\n") == 0);
    nmap->leave(state, &host);

    ctx = (TestHost){0};
    host = host_api(&ctx);
    state = launch(nmap, &host);
    char overlong[240];
    memset(overlong, 'X', sizeof(overlong));
    overlong[sizeof(overlong) - 1] = '\n';
    nmap->on_bytes(state, &host, (const uint8_t*)overlong, sizeof(overlong));
    feed(nmap, state, &host, hosts_two);
    canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "Host list incomplete"));
    nmap->on_input(state, &host, &ok);
    assert(ctx.tx_count == 2 && strcmp(ctx.tx[1], "list_hosts\n") == 0);
    nmap->leave(state, &host);
}

static void test_timeout_does_not_claim_scan_stopped(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    const C5ModuleV3* nmap = module();
    void* state = launch(nmap, &host);
    nmap->tick(state, &host, 1);
    feed(nmap, state, &host, hosts_two);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    nmap->on_input(state, &host, &ok);
    nmap->on_input(state, &host, &ok);
    nmap->tick(state, &host, 301000);
    Canvas canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "JanOS may still scan"));
    assert(nmap->on_input(state, &host, &back) == C5InputConsumed);
    assert(ctx.tx_count == 2);
    feed(nmap, state, &host, "Scanned 0 hosts, found 0 open ports\n");
    canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "0 hosts, 0 open ports"));
    nmap->leave(state, &host);
}

static void test_malformed_result_cannot_be_reported_complete(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    const C5ModuleV3* nmap = module();
    void* state = launch(nmap, &host);
    feed(nmap, state, &host, hosts_two);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    nmap->on_input(state, &host, &ok);
    nmap->on_input(state, &host, &ok);
    feed(nmap, state, &host,
         "=== NMAP Scan Results ===\n"
         "Host: 192.168.1.10  (BAD)\n"
         "    80/tcp  open  HTTP\n"
         "Scanned 1 hosts, found 1 open ports\n");
    Canvas canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "Result incomplete"));
    nmap->leave(state, &host);
}

static void test_summary_without_result_marker_is_incomplete(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    const C5ModuleV3* nmap = module();
    void* state = launch(nmap, &host);
    feed(nmap, state, &host, hosts_two);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    nmap->on_input(state, &host, &ok);
    nmap->on_input(state, &host, &ok);
    feed(nmap, state, &host, "Scanned 0 hosts, found 0 open ports\n");
    Canvas canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "Result incomplete"));
    nmap->leave(state, &host);
}

static void test_disconnect_before_scan_reports_wifi_error(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    const C5ModuleV3* nmap = module();
    void* state = launch(nmap, &host);
    feed(nmap, state, &host, hosts_two);
    InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
    nmap->on_input(state, &host, &ok);
    nmap->on_input(state, &host, &ok);
    feed(nmap, state, &host,
         "I (222) projectZero: Not connected to any AP. Use 'wifi_connect' first.\n");
    Canvas canvas = draw(nmap, state, &host);
    assert(has_line(&canvas, "Use wifi_connect"));
    assert(has_line(&canvas, "via JanOS CLI"));
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(nmap->on_input(state, &host, &back) == C5InputSwitchModule);
    nmap->leave(state, &host);
}

static void test_lwip_netif_failure_ends_listing_and_scan(void) {
    const C5ModuleV3* nmap = module();
    const char* error = "I (302) projectZero: Failed to get LwIP netif\r\n> ";
    for(unsigned pass = 0; pass < 2; pass++) {
        TestHost ctx = {0};
        C5HostApiV3 host = host_api(&ctx);
        void* state = launch(nmap, &host);
        assert(state);
        if(pass) {
            feed(nmap, state, &host, hosts_two);
            InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
            nmap->on_input(state, &host, &ok);
            nmap->on_input(state, &host, &ok);
            assert(ctx.tx_count == 2);
        }
        for(size_t i = 0; i < strlen(error); i++)
            nmap->on_bytes(state, &host, (const uint8_t*)error + i, 1);
        Canvas canvas = draw(nmap, state, &host);
        assert(has_line(&canvas, "Use wifi_connect"));
        InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
        assert(nmap->on_input(state, &host, &back) == C5InputSwitchModule);
        assert(ctx.tx_count == (pass ? 2u : 1u));
        nmap->leave(state, &host);
    }
}

static void test_prompt_ends_incomplete_replies_without_newline(void) {
    const C5ModuleV3* nmap = module();
    const char* early[] = {
        "I (310) projectZero: === Discovered Hosts ===\r\n"
        "I (311) projectZero:   192.168.1.10  ->  AA:BB:CC:DD:EE:10  [ARP]\r\n> ",
        "I (312) projectZero: Scan level: quick (20 ports)\r\n"
        "I (313) projectZero: === NMAP Scan Results ===\r\n> ",
    };
    for(unsigned pass = 0; pass < 2; pass++) {
        TestHost ctx = {0};
        C5HostApiV3 host = host_api(&ctx);
        void* state = launch(nmap, &host);
        assert(state);
        if(pass) {
            feed(nmap, state, &host, hosts_two);
            InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
            nmap->on_input(state, &host, &ok);
            nmap->on_input(state, &host, &ok);
        }
        for(size_t i = 0; i < strlen(early[pass]); i++)
            nmap->on_bytes(state, &host, (const uint8_t*)early[pass] + i, 1);
        Canvas canvas = draw(nmap, state, &host);
        assert(has_line(&canvas, pass ? "Result incomplete" : "Host list incomplete"));
        InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
        assert(nmap->on_input(state, &host, &back) == C5InputSwitchModule);
        assert(ctx.tx_count == (pass ? 2u : 1u));
        nmap->leave(state, &host);
    }
}

static void test_other_immediate_janos_failures_are_terminal(void) {
    const C5ModuleV3* nmap = module();
    const struct {
        bool scan;
        const char* reply;
        const char* message;
    } cases[] = {
        {false, "I (320) projectZero: Out of memory for host list\r\n> ",
         "JanOS host list OOM"},
        {true, "I (321) projectZero: Out of memory for host list\r\n> ",
         "JanOS scan failed"},
        {true, "I (322) projectZero: Usage: start_nmap [quick|medium|heavy] [IP]\r\n> ",
         "JanOS scan failed"},
    };
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        TestHost ctx = {0};
        C5HostApiV3 host = host_api(&ctx);
        void* state = launch(nmap, &host);
        assert(state);
        if(cases[i].scan) {
            feed(nmap, state, &host, hosts_two);
            InputEvent ok = {.type = InputTypeShort, .key = InputKeyOk};
            nmap->on_input(state, &host, &ok);
            nmap->on_input(state, &host, &ok);
        }
        feed(nmap, state, &host, cases[i].reply);
        Canvas canvas = draw(nmap, state, &host);
        assert(has_line(&canvas, cases[i].message));
        InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
        assert(nmap->on_input(state, &host, &back) == C5InputSwitchModule);
        assert(ctx.tx_count == (cases[i].scan ? 2u : 1u));
        nmap->leave(state, &host);
    }
}

static void test_bad_launch_sends_nothing(void) {
    TestHost ctx = {0};
    C5HostApiV3 host = host_api(&ctx);
    const C5ModuleV3* nmap = module();
    C5NmapLaunchContext context = {.version = C5_NMAP_LAUNCH_VERSION + 1,
                                   .size = sizeof(C5NmapLaunchContext),
                                   .ticks_per_second = 1000};
    assert(!nmap->enter(&host, &context, sizeof(context)));
    context.version = C5_NMAP_LAUNCH_VERSION;
    context.ticks_per_second = 0;
    assert(!nmap->enter(&host, &context, sizeof(context)));
    assert(ctx.tx_count == 0);
}

int main(void) {
    test_launch_and_single_host_medium();
    test_all_hosts_quick_and_heavy_commands();
    test_results_and_back_only_after_summary();
    test_not_connected_is_not_empty_and_can_retry();
    test_bad_host_snapshot_and_rx_loss_block_scan();
    test_timeout_does_not_claim_scan_stopped();
    test_malformed_result_cannot_be_reported_complete();
    test_summary_without_result_marker_is_incomplete();
    test_disconnect_before_scan_reports_wifi_error();
    test_lwip_netif_failure_ends_listing_and_scan();
    test_prompt_ends_incomplete_replies_without_newline();
    test_other_immediate_janos_failures_are_terminal();
    test_bad_launch_sends_nothing();
    puts("nmap module tests passed");
    return 0;
}
