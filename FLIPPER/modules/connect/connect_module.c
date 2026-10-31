#include "connect_module.h"
#include "../../module_api.h"

#include <flipper_application/flipper_application.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONNECT_LINE_CAP 192u
#define CONNECT_COMMAND_CAP 96u
#define CONNECT_WAIT_TIMEOUT_SECONDS 30u

typedef enum {ConnectPending, ConnectWaiting, ConnectHidden, ConnectTxFailed} ConnectPhase;
typedef enum {ConnectAuthUnknown, ConnectAuthSaved, ConnectAuthMissing} ConnectAuth;
typedef enum {
    ConnectResultUnknown, ConnectResultSuccess, ConnectResultFailed,
    ConnectResultTimeout, ConnectResultGateway, ConnectResultInitFailed,
    ConnectResultStaMissing, ConnectResultSsidMismatch,
} ConnectResult;
typedef enum {ConnectIpUnknown, ConnectIpReady, ConnectIpMissing} ConnectIp;

typedef struct {
    ConnectPhase phase;
    ConnectAuth auth;
    ConnectResult result;
    ConnectIp ip_state;
    bool prompt_seen;
    bool reply_line_seen;
    bool local_timeout;
    bool already_connected;
    bool discard_line;
    bool prompt_space;
    size_t line_length;
    uint32_t ticks_per_second;
    uint32_t command_tick;
    char ssid[33];
    char ip[16];
    char reason[20];
    char line[CONNECT_LINE_CAP];
} ConnectState;

static void connect_redraw(const C5HostApiV3* host) {
    if(host && host->request_redraw) host->request_redraw(host->ctx);
}

static bool connect_starts(const char* text, const char* prefix) {
    return strncmp(text, prefix, strlen(prefix)) == 0;
}

/* JanOS MY_LOG_INFO is bare; accept a standard ESP-IDF prefix too. */
static const char* connect_message(const char* line) {
    if((line[0] != 'I' && line[0] != 'W' && line[0] != 'E') ||
       line[1] != ' ' || line[2] != '(') return line;
    const char* at = line + 3;
    if(!isdigit((unsigned char)*at)) return line;
    while(isdigit((unsigned char)*at)) at++;
    static const char tail[] = ") projectZero: ";
    return strlen(at) >= sizeof(tail) - 1 &&
           strncmp(at, tail, sizeof(tail) - 1) == 0 ? at + sizeof(tail) - 1 : line;
}

/* A result must name the selected SSID and consume its complete record. */
static bool connect_quoted_ssid(
    const char* line, const char* prefix, const char* suffix, const char* ssid) {
    if(!connect_starts(line, prefix)) return false;
    const char* at = line + strlen(prefix);
    size_t length = strlen(ssid);
    return strlen(at) >= length + 1 && strncmp(at, ssid, length) == 0 && at[length] == '\'' &&
           strcmp(at + length + 1, suffix) == 0;
}

static bool connect_ipv4(const char* text, size_t length, bool allow_zero) {
    if(!length || length > 15) return false;
    size_t pos = 0;
    bool nonzero = false;
    for(unsigned octet = 0; octet < 4; octet++) {
        if(pos == length || !isdigit((unsigned char)text[pos])) return false;
        unsigned value = 0, digits = 0;
        do {
            if(++digits > 3) return false;
            value = value * 10u + (unsigned)(text[pos++] - '0');
        } while(pos < length && isdigit((unsigned char)text[pos]));
        if(value > 255 || (digits > 1 && text[pos - digits] == '0')) return false;
        if(value) nonzero = true;
        if(octet < 3) {
            if(pos == length || text[pos++] != '.') return false;
        }
    }
    return pos == length && (nonzero || allow_zero);
}

static bool connect_ip_line(const char* line, char out[16]) {
    const char* at = NULL;
    if(connect_starts(line, "DHCP IP: ")) at = line + sizeof("DHCP IP: ") - 1;
    else if(connect_starts(line, "Static IP: ")) at = line + sizeof("Static IP: ") - 1;
    else return false;
    const char* mask = strstr(at, ", Netmask: ");
    if(!mask || !connect_ipv4(at, (size_t)(mask - at), false)) return false;
    const char* gw = strstr(mask + sizeof(", Netmask: ") - 1, ", GW: ");
    if(!gw || !connect_ipv4(mask + sizeof(", Netmask: ") - 1,
                            (size_t)(gw - (mask + sizeof(", Netmask: ") - 1)), false))
        return false;
    const char* gw_ip = gw + sizeof(", GW: ") - 1;
    if(!connect_ipv4(gw_ip, strlen(gw_ip), true)) return false;
    size_t length = (size_t)(mask - at);
    memcpy(out, at, length);
    out[length] = '\0';
    return true;
}

static bool connect_reason(const char* line, const char* ssid, char out[20]) {
    static const char prefix[] = "FAILED: Connection to '";
    if(!connect_starts(line, prefix)) return false;
    const char* at = line + sizeof(prefix) - 1;
    size_t length = strlen(ssid);
    static const char reason_prefix[] = "' failed (reason=";
    if(strlen(at) < length + sizeof(reason_prefix) - 1 ||
       strncmp(at, ssid, length) != 0 ||
       strncmp(at + length, reason_prefix, sizeof(reason_prefix) - 1) != 0)
        return false;
    at += length + sizeof(reason_prefix) - 1;
    unsigned reason = 0, digits = 0;
    while(isdigit((unsigned char)*at)) {
        if(++digits > 4) return false;
        reason = reason * 10u + (unsigned)(*at++ - '0');
    }
    if(!digits || !connect_starts(at, ").")) return false;
    snprintf(out, 20, "Reason %u", reason);
    return true;
}

static bool connect_saved_source(const char* line, const char* ssid) {
    static const char prefix[] = "wifi_connect: using saved password from ";
    if(!connect_starts(line, prefix)) return false;
    const char* for_ssid = strstr(line + sizeof(prefix) - 1, " for '");
    if(!for_ssid) return false;
    return connect_quoted_ssid(for_ssid, " for '", "", ssid);
}

static bool connect_valid_ssid(const char ssid[33]) {
    const char* end = memchr(ssid, '\0', 33);
    if(!end) return false;
    size_t length = (size_t)(end - ssid);
    if(length < 1 || length > 31) return false;
    for(size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)ssid[i];
        if(byte < 0x20 || byte == 0x7f) return false;
    }
    return true;
}

static bool connect_send(ConnectState* state, const C5HostApiV3* host) {
    char command[CONNECT_COMMAND_CAP];
    static const char prefix[] = "wifi_connect \"";
    size_t used = sizeof(prefix) - 1;
    memcpy(command, prefix, used);
    for(const char* at = state->ssid; *at; at++) {
        if(*at == '"' || *at == '\\') command[used++] = '\\';
        command[used++] = *at;
    }
    static const char suffix[] = "\" --saved\n";
    if(used + sizeof(suffix) - 1 > sizeof(command) ||
       used + sizeof(suffix) - 1 > C5_MODULE_RAW_TX_MAX) return false;
    memcpy(command + used, suffix, sizeof(suffix) - 1);
    used += sizeof(suffix) - 1;
    return host->send_raw_lines(host->ctx, command, used);
}

static void connect_on_line(ConnectState* state, const char* raw) {
    if(state->phase != ConnectWaiting || state->prompt_seen) return;
    const char* line = connect_message(raw);
    if(connect_saved_source(line, state->ssid) ||
       strcmp(line, "wifi_connect: password source=saved") == 0) {
        if(state->auth != ConnectAuthMissing) state->auth = ConnectAuthSaved;
        return;
    }
    if(connect_quoted_ssid(line, "wifi_connect: no saved password found for '", "",
                           state->ssid) ||
       strcmp(line, "wifi_connect: saved password requested but missing, trying open network") == 0) {
        state->auth = ConnectAuthMissing;
        return;
    }
    if(connect_quoted_ssid(line, "Wi-Fi: already connected to SSID='", "", state->ssid)) {
        state->already_connected = true;
        return;
    }
    if(connect_starts(line, "Capture Gateway is active.")) {
        state->result = ConnectResultGateway;
        return;
    }
    if(strcmp(line, "Failed to reinitialize WiFi") == 0 ||
       connect_starts(line, "Failed to set static IP:")) {
        state->result = ConnectResultInitFailed;
        return;
    }
    if(strcmp(line, "STA interface not found") == 0) {
        state->result = ConnectResultStaMissing;
        return;
    }
    if(state->result != ConnectResultUnknown && state->result != ConnectResultSuccess)
        return;
    if(connect_starts(line, "SUCCESS: Connected to '")) {
        state->result = connect_quoted_ssid(line, "SUCCESS: Connected to '", "", state->ssid) ?
                            ConnectResultSuccess : ConnectResultSsidMismatch;
        return;
    }
    if(connect_starts(line, "FAILED: Connection to '")) {
        state->result = connect_reason(line, state->ssid, state->reason) ?
                            ConnectResultFailed : ConnectResultSsidMismatch;
        return;
    }
    if(connect_starts(line, "TIMEOUT: Connection to '")) {
        state->result = connect_quoted_ssid(
                            line, "TIMEOUT: Connection to '", " timed out", state->ssid) ?
                            ConnectResultTimeout : ConnectResultSsidMismatch;
        return;
    }
    if(state->result == ConnectResultSuccess) {
        if(connect_ip_line(line, state->ip)) state->ip_state = ConnectIpReady;
        else if(strcmp(line, "No IP assigned yet. Wait for DHCP.") == 0)
            state->ip_state = ConnectIpMissing;
    }
}

static void* connect_enter(const C5HostApiV3* host, const void* params, size_t params_size) {
    if(!host || host->version != C5_MODULE_API_VERSION ||
       host->size < sizeof(C5HostApiV3) || !host->send_raw_lines ||
       !host->request_redraw || !params || params_size != sizeof(C5ConnectLaunchContext))
        return NULL;
    const C5ConnectLaunchContext* launch = params;
    if(launch->version != C5_CONNECT_LAUNCH_VERSION ||
       launch->size != sizeof(*launch) || !launch->ticks_per_second ||
       launch->ticks_per_second > 1000000u || !connect_valid_ssid(launch->ssid))
        return NULL;
    ConnectState* state = calloc(1, sizeof(*state));
    if(!state) return NULL;
    memcpy(state->ssid, launch->ssid, sizeof(state->ssid));
    state->ticks_per_second = launch->ticks_per_second;
    state->phase = strcmp(state->ssid, "Hidden") == 0 ? ConnectHidden : ConnectPending;
    return state;
}
static void connect_leave(void* opaque, const C5HostApiV3* host) {
    (void)host;
    free(opaque);
}
static void connect_bytes(
    void* opaque, const C5HostApiV3* host, const uint8_t* bytes, size_t length) {
    ConnectState* state = opaque;
    if(!state || !host || !bytes || state->phase != ConnectWaiting || state->prompt_seen)
        return;
    for(size_t i = 0; i < length; i++) {
        char byte = (char)bytes[i];
        if(state->prompt_space) {
            state->prompt_space = false;
            if(byte == ' ') continue;
        }
        if(byte == '\r') continue;
        if(byte == '\n') {
            if(!state->discard_line && state->line_length) {
                state->line[state->line_length] = '\0';
                state->reply_line_seen = true;
                connect_on_line(state, state->line);
            }
            state->line_length = 0;
            state->discard_line = false;
            continue;
        }
        if(byte == '>' && !state->line_length && !state->discard_line) {
            if(state->reply_line_seen) state->prompt_seen = true;
            state->prompt_space = true;
            connect_redraw(host);
            continue;
        }
        if(state->discard_line) continue;
        if(byte == '\0' || state->line_length + 1 >= sizeof(state->line)) {
            state->line_length = 0;
            state->discard_line = true;
            continue;
        }
        state->line[state->line_length++] = byte;
    }
    connect_redraw(host);
}
static C5InputResult connect_input(
    void* opaque, const C5HostApiV3* host, const InputEvent* event) {
    (void)host;
    ConnectState* state = opaque;
    if(!state || !event || event->type != InputTypeShort || event->key != InputKeyBack)
        return C5InputIgnored;
    if(state->phase == ConnectWaiting && !state->prompt_seen && !state->local_timeout)
        return C5InputConsumed;
    return C5InputSwitchModule;
}
static void connect_draw(void* opaque, const C5HostApiV3* host, Canvas* canvas) {
    (void)host;
    ConnectState* state = opaque;
    if(!state || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_draw_box(canvas, 0, 0, 128, 64);
    canvas_set_color(canvas, ColorWhite);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 10, "WiFi Connect");
    char selected[27];
    snprintf(selected, sizeof(selected), "SSID: %.20s", state->ssid);
    canvas_draw_str(canvas, 2, 21, selected);
    const char* status = "Ready";
    const char* source = "";
    const char* detail = "";
    if(state->phase == ConnectHidden) status = "Hidden SSID unavailable";
    else if(state->phase == ConnectTxFailed) status = "Send failed";
    else if(state->phase == ConnectWaiting) {
        if(state->local_timeout && !state->prompt_seen) {
            status = "Result unconfirmed";
            detail = "JanOS may be busy";
        } else switch(state->result) {
        case ConnectResultUnknown:
            status = state->prompt_seen ? "Result unconfirmed" : "Connecting...";
            break;
        case ConnectResultSuccess:
            status = state->ip_state == ConnectIpReady ? "Connected + IP" : "WiFi joined";
            detail = state->ip_state == ConnectIpReady ? state->ip :
                     state->ip_state == ConnectIpMissing ? "No IP yet" :
                     state->prompt_seen ? "IP unconfirmed" : "Waiting for IP";
            break;
        case ConnectResultFailed: status = "Connect failed"; detail = state->reason; break;
        case ConnectResultTimeout: status = "Connection timeout"; break;
        case ConnectResultGateway: status = "Gateway active"; detail = "Stop it in JanOS"; break;
        case ConnectResultInitFailed: status = "WiFi init failed"; break;
        case ConnectResultStaMissing: status = "STA unavailable"; break;
        case ConnectResultSsidMismatch: status = "SSID mismatch"; break;
        }
        if(state->already_connected && state->result == ConnectResultSuccess)
            source = "Already connected";
        else if(state->auth == ConnectAuthSaved)
            source = state->result == ConnectResultSuccess ? "Saved key used" : "Saved key found";
        else if(state->auth == ConnectAuthMissing)
            source = state->result == ConnectResultSuccess ? "Open network" : "No saved key";
        else source = "Auth unconfirmed";
    }
    canvas_draw_str(canvas, 2, 33, status);
    if(*source) canvas_draw_str(canvas, 2, 44, source);
    if(*detail) canvas_draw_str(canvas, 2, 55, detail);
    canvas_draw_str(canvas, 2, 63,
        state->phase == ConnectWaiting && !state->prompt_seen && !state->local_timeout ?
            "Back: wait" : "Back: exit");
}
static void connect_tick(void* opaque, const C5HostApiV3* host, uint32_t now_ticks) {
    ConnectState* state = opaque;
    if(!state || !host) return;
    if(state->phase == ConnectPending) {
        state->command_tick = now_ticks;
        state->phase = ConnectWaiting;
        if(!connect_send(state, host)) state->phase = ConnectTxFailed;
        connect_redraw(host);
    } else if(state->phase == ConnectWaiting && !state->prompt_seen && !state->local_timeout &&
              (uint32_t)(now_ticks - state->command_tick) >=
                  state->ticks_per_second * CONNECT_WAIT_TIMEOUT_SECONDS) {
        state->local_timeout = true;
        connect_redraw(host);
    }
}
static const C5ModuleV3 c5_connect_module = {
    .version = C5_MODULE_API_VERSION, .size = sizeof(C5ModuleV3),
    .enter = connect_enter, .leave = connect_leave, .on_bytes = connect_bytes,
    .on_input = connect_input, .draw = connect_draw, .tick = connect_tick,
};
static const FlipperAppPluginDescriptor c5_connect_descriptor = {
    .appid = C5_MODULE_APP_ID, .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_connect_module,
};
const FlipperAppPluginDescriptor* lab_c5_connect_plugin_ep(void) {
    return &c5_connect_descriptor;
}
