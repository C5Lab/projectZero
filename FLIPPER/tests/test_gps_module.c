#include "../module_api.h"
#include <flipper_application/flipper_application.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

const FlipperAppPluginDescriptor* lab_c5_gps_plugin_ep(void);

typedef struct {
    int32_t settings[4];
    char command[64];
    unsigned sends;
    unsigned redraws;
} TestHost;

static void send_command(void* ctx, const char* command) {
    TestHost* host = ctx;
    snprintf(host->command, sizeof(host->command), "%s", command);
    host->sends++;
}

static void redraw(void* ctx) {
    ((TestHost*)ctx)->redraws++;
}

static void show_status(void* ctx, const char* message, uint32_t duration, bool fullscreen) {
    (void)ctx;
    (void)message;
    (void)duration;
    (void)fullscreen;
}

static int32_t get_setting(void* ctx, C5Setting setting) {
    assert(setting >= GPS_TIME_24H && setting <= GPS_ZDA_TZ);
    return ((TestHost*)ctx)->settings[setting];
}

static void set_setting(void* ctx, C5Setting setting, int32_t value) {
    assert(setting >= GPS_TIME_24H && setting <= GPS_ZDA_TZ);
    ((TestHost*)ctx)->settings[setting] = value;
}

static void capture(Canvas* canvas, const char* text) {
    assert(canvas->line_count < 16);
    snprintf(canvas->lines[canvas->line_count++], sizeof(canvas->lines[0]), "%s", text);
}

void canvas_set_color(Canvas* canvas, Color color) {
    (void)canvas;
    (void)color;
}

void canvas_set_font(Canvas* canvas, Font font) {
    (void)canvas;
    (void)font;
}

void canvas_draw_str(Canvas* canvas, int x, int y, const char* text) {
    (void)x;
    (void)y;
    capture(canvas, text);
}

void canvas_draw_str_aligned(
    Canvas* canvas,
    int x,
    int y,
    Align horizontal,
    Align vertical,
    const char* text) {
    (void)x;
    (void)y;
    (void)horizontal;
    (void)vertical;
    capture(canvas, text);
}

static bool has_line(const Canvas* canvas, const char* wanted) {
    for(size_t i = 0; i < canvas->line_count; i++) {
        if(strcmp(canvas->lines[i], wanted) == 0) return true;
    }
    return false;
}

static Canvas draw(const C5ModuleV3* module, void* state, const C5HostApiV3* host) {
    Canvas canvas = {0};
    module->draw(state, host, &canvas);
    return canvas;
}

int main(void) {
    const FlipperAppPluginDescriptor* descriptor = lab_c5_gps_plugin_ep();
    assert(strcmp(descriptor->appid, C5_MODULE_APP_ID) == 0);
    assert(descriptor->ep_api_version == C5_MODULE_API_VERSION);
    const C5ModuleV3* module = descriptor->entry_point;
    assert(module->version == C5_MODULE_API_VERSION && module->size == sizeof(*module));
    assert(module->enter(NULL, NULL, 0) == NULL);

    TestHost context = {.settings = {[GPS_TIME_24H] = 1}};
    C5HostApiV3 host = {
        .version = C5_MODULE_API_VERSION,
        .size = sizeof(C5HostApiV3),
        .ctx = &context,
        .send_command = send_command,
        .request_redraw = redraw,
        .show_status = show_status,
        .get_setting = get_setting,
        .set_setting = set_setting,
    };
    void* state = module->enter(&host, NULL, 0);
    assert(state);
    assert(context.sends == 0 && context.redraws == 0);

    module->on_line(
        state, &host, "[GPS RAW] $GPGGA,123519,4807.038,N,01131.000,E,1,08,,,,,,*47");
    Canvas canvas = draw(module, state, &host);
    assert(has_line(&canvas, "Lat: 48.11730"));
    assert(has_line(&canvas, "Lon: 11.51667"));
    assert(has_line(&canvas, "Time: 12:35:19 UTC+0"));
    assert(has_line(&canvas, "Sats: 8"));

    module->on_line(state, &host, "[GPS RAW] $GPRMC,123520,V,,,,,,,281026,,*00");
    canvas = draw(module, state, &host);
    assert(has_line(&canvas, "Waiting for GPS fix"));

    context.settings[GPS_ZDA_TZ] = 1;
    module->on_line(state, &host, "[GPS RAW] $GPZDA,120000,28,10,2026,02,00*00");
    assert(context.settings[GPS_UTC_OFFSET_MIN] == 120);
    canvas = draw(module, state, &host);
    assert(has_line(&canvas, "Time: 14:00:00 UTC+2"));

    InputEvent short_ok = {.type = InputTypeShort, .key = InputKeyOk};
    assert(module->on_input(state, &host, &short_ok) == C5InputConsumed);
    assert(context.settings[GPS_TIME_24H] == 0);
    canvas = draw(module, state, &host);
    assert(has_line(&canvas, "Time: 02:00:00 PM UTC+2"));
    InputEvent long_ok = {.type = InputTypeLong, .key = InputKeyOk};
    assert(module->on_input(state, &host, &long_ok) == C5InputSwitchTerminal);
    InputEvent back = {.type = InputTypeShort, .key = InputKeyBack};
    assert(module->on_input(state, &host, &back) == C5InputIgnored);

    module->leave(state, &host);
    puts("GPS module tests passed");
    return 0;
}
