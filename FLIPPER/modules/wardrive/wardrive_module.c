#include "wardrive_module.h"
#include "../../module_api.h"
#include <flipper_application/flipper_application.h>
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WD_LINE_CAPACITY 256u
#define WD_START_TIMEOUT_SECONDS 10u
#define WD_STOP_TIMEOUT_SECONDS 5u

typedef enum {
    WdPending, WdStarting, WdWaitingGps, WdWaitingRadio, WdActive,
    WdGpsLost, WdStartUnconfirmed, WdError, WdStopping,
    WdStopUnconfirmed, WdStopped,
} WdPhase;
typedef enum { WdSdUnknown, WdSdReady, WdSdFailed } WdSdState;
typedef enum { WdTraceUnknown, WdTraceReady, WdTraceFailed } WdTraceState;

typedef struct {
    C5WardriveMode mode;
    uint32_t ticks_per_second;
    uint32_t last_tick;
    uint32_t command_tick;
    uint32_t stop_tick;
    WdPhase phase;
    WdSdState sd;
    WdTraceState trace;
    bool command_sent;
    bool start_ack;
    bool radio_started;
    bool gps_fix;
    bool gps_failed;
    bool has_coords;
    bool wifi_seen;
    bool bt_seen;
    uint32_t wifi_count;
    uint32_t bt_count;
    char coords[36];
    char last_ssid[33];
    char line[WD_LINE_CAPACITY];
    size_t line_length;
    bool discard_line;
} WdState;

static void wd_redraw(const C5HostApiV3* host) {
    if(host && host->request_redraw) host->request_redraw(host->ctx);
}

static bool wd_send(const C5HostApiV3* host, const char* command) {
    if(!host || !host->send_raw_lines || !command) return false;
    size_t length = strlen(command);
    return length && length <= C5_MODULE_RAW_TX_MAX &&
           host->send_raw_lines(host->ctx, command, length);
}

static const char* wd_start_command(C5WardriveMode mode) {
    switch(mode) {
    case C5WardriveModeLegacy: return "start_wardrive\n";
    case C5WardriveModePromisc: return "start_wardrive_promisc\n";
    case C5WardriveModePromiscTrace: return "start_wardrive_promisc_trace\n";
    }
    return NULL;
}

static bool wd_starts(const char* text, const char* prefix) {
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

static bool wd_parse_number(
    const char** cursor, const char* prefix, const char* suffix, uint32_t* result) {
    const char* p = *cursor;
    if(!wd_starts(p, prefix)) return false;
    p += strlen(prefix);
    if(!isdigit((unsigned char)*p)) return false;
    char* end = NULL;
    unsigned long value = strtoul(p, &end, 10);
    if(end == p || value > UINT32_MAX || !wd_starts(end, suffix)) return false;
    *result = (uint32_t)value;
    *cursor = end + strlen(suffix);
    return true;
}

static bool wd_parse_coords(const char* message, char* out, size_t capacity) {
    const char* lat_text = strstr(message, "Lat=");
    const char* lon_text = strstr(message, "Lon=");
    if(!lat_text || !lon_text || lat_text >= lon_text) return false;
    char* lat_end = NULL;
    char* lon_end = NULL;
    float lat = strtof(lat_text + 4, &lat_end);
    float lon = strtof(lon_text + 4, &lon_end);
    if(lat_end == lat_text + 4 || lon_end == lon_text + 4 || lat_end > lon_text ||
       !isfinite(lat) || !isfinite(lon) || lat < -90.0f || lat > 90.0f ||
       lon < -180.0f || lon > 180.0f ||
       (*lon_end != '\0' && *lon_end != '.' && *lon_end != ' ')) return false;
    int written = snprintf(out, capacity, "%.4f, %.4f", (double)lat, (double)lon);
    return written > 0 && (size_t)written < capacity;
}

/* Consume a complete RFC 4180 field; JanOS quotes commas and doubles quotes. */
static bool wd_csv_field(const char** cursor, char* out, size_t capacity, bool* last) {
    const char* p = *cursor;
    size_t used = 0;
    if(*p == '"') {
        p++;
        for(;;) {
            if(!*p) return false;
            if(*p == '"') {
                if(p[1] != '"') { p++; break; }
                p++;
            }
            if(used + 1 >= capacity) return false;
            out[used++] = *p++;
        }
        if(*p && *p != ',') return false;
    } else {
        while(*p && *p != ',') {
            if(*p == '"' || (unsigned char)*p < 0x20 || used + 1 >= capacity) return false;
            out[used++] = *p++;
        }
    }
    out[used] = '\0';
    *last = *p == '\0';
    *cursor = *last ? p : p + 1;
    return true;
}

static bool wd_valid_mac(const char* mac) {
    if(strlen(mac) != 17) return false;
    for(size_t i = 0; i < 17; i++) {
        if(i % 3 == 2) {
            if(mac[i] != ':') return false;
        } else if(!isxdigit((unsigned char)mac[i])) return false;
    }
    return true;
}

static bool wd_parse_wifi_row(const char* row, char* ssid, size_t capacity) {
    const char* cursor = row;
    char field[80];
    char parsed_ssid[33] = {0};
    size_t count = 0;
    bool last = false;
    do {
        if(count >= 14 || !wd_csv_field(&cursor, field, sizeof(field), &last)) return false;
        if(count == 0 && !wd_valid_mac(field)) return false;
        if(count == 1) {
            size_t length = strlen(field);
            if(length > 32) return false;
            memcpy(parsed_ssid, field, length + 1);
        }
        if(last && strcmp(field, "WIFI") != 0) return false;
        count++;
    } while(!last);
    if(count != 11 && count != 14) return false;
    snprintf(ssid, capacity, "%s", parsed_ssid[0] ? parsed_ssid : "(hidden)");
    return true;
}

static void wd_apply_start_state(WdState* state) {
    if(state->phase == WdError || state->phase == WdStopping ||
       state->phase == WdStopUnconfirmed || state->phase == WdStopped) return;
    if(state->radio_started && state->gps_fix) state->phase = WdActive;
    else if(state->radio_started) state->phase = WdGpsLost;
    else if(state->gps_fix) state->phase = WdWaitingRadio;
    else if(state->start_ack) state->phase = WdWaitingGps;
}

static const char* wd_log_message(const char* line) {
    if((line[0] != 'I' && line[0] != 'W' && line[0] != 'E') ||
       line[1] != ' ' || line[2] != '(') return line;
    const char* cursor = line + 3;
    if(!isdigit((unsigned char)*cursor)) return line;
    while(isdigit((unsigned char)*cursor)) cursor++;
    const char prefix[] = ") projectZero: ";
    return strncmp(cursor, prefix, sizeof(prefix) - 1) == 0 ?
               cursor + sizeof(prefix) - 1 : line;
}

static bool wd_on_line(WdState* state, const char* line) {
    if(state->phase == WdStopping || state->phase == WdStopUnconfirmed) {
        if(strcmp(line, "[WARDRIVE] STOPPED running=1") == 0 ||
           strcmp(line, "[WARDRIVE] STOPPED running=0") == 0) {
            state->phase = WdStopped;
            return true;
        }
        return false;
    }
    if(state->phase == WdStopped || state->phase == WdPending) return false;
    const char* message = wd_log_message(line);
    if(wd_starts(message, "Failed to initialize SD card:")) {
        state->sd = WdSdFailed;
        state->phase = WdError;
        return true;
    }
    if(wd_starts(message, "SD card initialized on pins ")) {
        state->sd = WdSdReady;
        return true;
    }
    if(wd_starts(message, "Failed to initialize GPS UART:") ||
       wd_starts(message, "Failed to create wardrive") ||
       wd_starts(message, "Wardrive already running.") ||
       wd_starts(message, "Wardrive promisc already running.") ||
       wd_starts(message, "Cannot start wardrive")) {
        state->phase = WdError;
        return true;
    }
    if(wd_starts(message, "Warning: No GPS fix obtained,")) {
        state->gps_fix = false;
        state->gps_failed = true;
        state->has_coords = false;
        state->phase = WdError;
        return true;
    }
    if(state->phase == WdError) return false;

    if(state->mode == C5WardriveModeLegacy) {
        if(strcmp(message, "Wardrive task started. Use 'stop' to stop.") == 0 ||
           strcmp(message, "Wardrive task started.") == 0) {
            state->start_ack = true;
            wd_apply_start_state(state);
            return true;
        }
        if(strcmp(message, "Wardrive started. Use 'stop' command to stop.") == 0) {
            state->radio_started = true;
            wd_apply_start_state(state);
            return true;
        }
        const char* count_cursor = message;
        uint32_t count;
        if(wd_parse_number(&count_cursor, "Logged ", " networks to ", &count) &&
           *count_cursor) {
            state->wifi_count = count;
            state->wifi_seen = true;
            return true;
        }
    } else {
        if(strcmp(message, "Wardrive promisc task started. Use 'stop' to stop.") == 0 ||
           strcmp(message, "Wardrive promisc task started.") == 0) {
            state->start_ack = true;
            wd_apply_start_state(state);
            return true;
        }
        if(wd_starts(message, "Promiscuous wardrive started. Bands: ")) {
            state->radio_started = true;
            wd_apply_start_state(state);
            return true;
        }
        if(state->mode == C5WardriveModePromiscTrace) {
            if(wd_starts(message, "Wardrive trace enabled: ")) {
                state->trace = WdTraceReady;
                return true;
            }
            if(wd_starts(message, "Failed to start wardrive trace (file/queue): ")) {
                state->trace = WdTraceFailed;
                return true;
            }
        }
        const char* count_cursor = message;
        uint32_t wifi, bt;
        if(wd_parse_number(&count_cursor, "Wardrive promisc: ", " unique networks, ", &wifi) &&
           wd_parse_number(&count_cursor, "", " BT devices", &bt) &&
           (*count_cursor == ',' || *count_cursor == '\0')) {
            state->wifi_count = wifi;
            state->bt_count = bt;
            state->wifi_seen = true;
            state->bt_seen = true;
            if(strstr(count_cursor, "GPS: no fix")) {
                state->gps_fix = false;
                state->has_coords = false;
                wd_apply_start_state(state);
            }
            return true;
        }
    }

    if(wd_starts(message, "GPS fix obtained: ") ||
       wd_starts(message, "GPS fix recovered: ")) {
        if(!wd_parse_coords(message, state->coords, sizeof(state->coords))) return false;
        state->gps_fix = true;
        state->has_coords = true;
        wd_apply_start_state(state);
        return true;
    }
    if(wd_starts(message, "GPS fix lost")) {
        state->gps_fix = false;
        state->has_coords = false;
        wd_apply_start_state(state);
        return true;
    }
    if(wd_starts(message, "Waiting for GPS fix") && state->start_ack) {
        wd_apply_start_state(state);
        return true;
    }
    char ssid[33];
    if(wd_parse_wifi_row(message, ssid, sizeof(ssid))) {
        memcpy(state->last_ssid, ssid, sizeof(state->last_ssid));
        return true;
    }
    return false;
}

static void* wd_enter(const C5HostApiV3* host, const void* params, size_t params_size) {
    if(!host || host->version != C5_MODULE_API_VERSION ||
       host->size < sizeof(C5HostApiV3) || !host->send_raw_lines ||
       !host->request_redraw || !params || params_size != sizeof(C5WardriveLaunchContext))
        return NULL;
    const C5WardriveLaunchContext* launch = params;
    if(launch->version != C5_WARDRIVE_LAUNCH_VERSION ||
       launch->size != sizeof(C5WardriveLaunchContext) ||
       launch->mode > C5WardriveModePromiscTrace ||
       launch->ticks_per_second == 0 || launch->ticks_per_second > 1000000u) return NULL;
    WdState* state = calloc(1, sizeof(*state));
    if(!state) return NULL;
    state->mode = launch->mode;
    state->ticks_per_second = launch->ticks_per_second;
    state->phase = WdPending;
    return state;
}
static void wd_leave(void* opaque, const C5HostApiV3* host) {
    WdState* state = opaque;
    if(!state) return;
    if(state->command_sent && state->phase != WdStopped) wd_send(host, "stop\n");
    free(state);
}
static void wd_bytes(void* opaque, const C5HostApiV3* host, const uint8_t* bytes, size_t length) {
    WdState* state = opaque;
    if(!state || !bytes) return;
    for(size_t i = 0; i < length; i++) {
        char ch = (char)bytes[i];
        if(ch == '\r') continue;
        if(ch == '\n') {
            if(!state->discard_line && state->line_length) {
                state->line[state->line_length] = '\0';
                if(wd_on_line(state, state->line)) wd_redraw(host);
            }
            state->line_length = 0;
            state->discard_line = false;
        } else if(ch == '\0') {
            state->line_length = 0;
            state->discard_line = true;
        } else if(!state->discard_line) {
            if(state->line_length + 1 < sizeof(state->line)) {
                state->line[state->line_length++] = ch;
            } else {
                state->line_length = 0;
                state->discard_line = true;
            }
        }
    }
}
static C5InputResult wd_input(void* opaque, const C5HostApiV3* host, const InputEvent* event) {
    WdState* state = opaque;
    if(!state || !host || !event || event->type != InputTypeShort ||
       event->key != InputKeyBack) return C5InputIgnored;
    if(state->phase == WdPending || state->phase == WdStopped || !state->command_sent)
        return C5InputSwitchModule;
    if(state->phase == WdStopping) return C5InputConsumed;
    if(!wd_send(host, "stop\n")) state->phase = WdStopUnconfirmed;
    else {
        state->phase = WdStopping;
        state->stop_tick = state->last_tick;
    }
    wd_redraw(host);
    return C5InputConsumed;
}
static void wd_draw(void* opaque, const C5HostApiV3* host, Canvas* canvas) {
    (void)host;
    WdState* state = opaque;
    if(!state || !canvas) return;
    const char* title = state->mode == C5WardriveModeLegacy ? "Wardrive" :
                        state->mode == C5WardriveModePromisc ? "Wardrive Pro" : "Wardrive Trace";
    const char* status = "Starting...";
    switch(state->phase) {
    case WdPending:
    case WdStarting: status = "Starting..."; break;
    case WdWaitingGps: status = "Waiting GPS"; break;
    case WdWaitingRadio: status = "Waiting radio"; break;
    case WdActive: status = "Active"; break;
    case WdGpsLost: status = "GPS lost - paused"; break;
    case WdStartUnconfirmed: status = "Start unconfirmed"; break;
    case WdError: status = state->sd == WdSdFailed ? "SD failed" :
                           state->gps_failed ? "No GPS fix" : "Start failed"; break;
    case WdStopping: status = "Stopping..."; break;
    case WdStopUnconfirmed: status = "Stop unconfirmed"; break;
    case WdStopped: status = "Stopped"; break;
    }
    char line[52];
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 11, title);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 21, status);
    if(state->mode == C5WardriveModeLegacy) {
        if(state->wifi_seen) snprintf(line, sizeof(line), "WiFi: %lu", (unsigned long)state->wifi_count);
        else snprintf(line, sizeof(line), "WiFi: --");
    } else if(state->wifi_seen && state->bt_seen) {
        snprintf(line, sizeof(line), "WiFi: %lu BT: %lu",
                 (unsigned long)state->wifi_count, (unsigned long)state->bt_count);
    } else if(state->wifi_seen) {
        snprintf(line, sizeof(line), "WiFi: %lu BT: --", (unsigned long)state->wifi_count);
    } else if(state->bt_seen) {
        snprintf(line, sizeof(line), "WiFi: -- BT: %lu", (unsigned long)state->bt_count);
    } else {
        snprintf(line, sizeof(line), "WiFi: -- BT: --");
    }
    canvas_draw_str(canvas, 2, 31, line);
    if(state->gps_fix && state->has_coords)
        snprintf(line, sizeof(line), "GPS: %s", state->coords);
    else snprintf(line, sizeof(line), "GPS: %s", state->phase == WdGpsLost ? "lost" : "--");
    canvas_draw_str(canvas, 2, 41, line);
    snprintf(line, sizeof(line), "SSID: %.25s", state->last_ssid[0] ? state->last_ssid : "--");
    canvas_draw_str(canvas, 2, 51, line);
    const char* sd = state->sd == WdSdReady ? "ready" :
                     state->sd == WdSdFailed ? "failed" : "--";
    if(state->mode == C5WardriveModePromiscTrace && state->trace == WdTraceFailed)
        snprintf(line, sizeof(line), "SD: %s Tr: failed", sd);
    else if(state->mode == C5WardriveModePromiscTrace && state->trace == WdTraceReady)
        snprintf(line, sizeof(line), "SD: %s Tr: ready", sd);
    else snprintf(line, sizeof(line), "SD: %s", sd);
    canvas_draw_str(canvas, 2, 61, line);
}
static void wd_tick(void* opaque, const C5HostApiV3* host, uint32_t now_ticks) {
    WdState* state = opaque;
    if(!state || !host) return;
    state->last_tick = now_ticks;
    if(state->phase == WdPending) {
        const char* command = wd_start_command(state->mode);
        if(command && wd_send(host, command)) {
            state->command_sent = true;
            state->command_tick = now_ticks;
            state->phase = WdStarting;
        } else state->phase = WdError;
        wd_redraw(host);
    } else if(state->phase == WdStarting && !state->start_ack && !state->radio_started &&
              now_ticks - state->command_tick >=
                  state->ticks_per_second * WD_START_TIMEOUT_SECONDS) {
        state->phase = WdStartUnconfirmed;
        wd_redraw(host);
    } else if(state->phase == WdStopping &&
              now_ticks - state->stop_tick >=
                  state->ticks_per_second * WD_STOP_TIMEOUT_SECONDS) {
        state->phase = WdStopUnconfirmed;
        wd_redraw(host);
    }
}
static const C5ModuleV3 c5_wardrive_module = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = wd_enter,
    .leave = wd_leave,
    .on_bytes = wd_bytes,
    .on_input = wd_input,
    .draw = wd_draw,
    .tick = wd_tick,
};
static const FlipperAppPluginDescriptor c5_wardrive_descriptor = {
    .appid = C5_MODULE_APP_ID,
    .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_wardrive_module,
};
const FlipperAppPluginDescriptor* lab_c5_wardrive_plugin_ep(void) {
    return &c5_wardrive_descriptor;
}
