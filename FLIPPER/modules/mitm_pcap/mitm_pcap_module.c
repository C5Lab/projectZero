#include "mitm_pcap_module.h"
#include "../../module_api.h"
#include <flipper_application/flipper_application.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MITM_LINE_CAPACITY 320u
#define MITM_COMMAND_CAPACITY 160u
#define MITM_PCAP_DIR "/sdcard/lab/pcaps/"

typedef enum {
    MitmPending, MitmSelecting, MitmLookingUp, MitmPasswordInput,
    MitmConnecting, MitmStartingPcap, MitmActive, MitmStartUnconfirmed,
    MitmStopping, MitmStopUnconfirmed, MitmStopped, MitmError,
} MitmStage;

typedef struct {
    C5MitmPcapLaunchContext launch;
    MitmStage stage;
    uint32_t last_tick;
    uint32_t stage_tick;
    bool command_sent;
    bool pcap_attempted;
    bool pcap_start_failed;
    bool stop_ack_seen;
    bool selection_header;
    bool target_seen;
    bool saved_found;
    bool saved_ambiguous;
    bool connect_success;
    bool ip_seen;
    bool connect_failure;
    bool hosts_seen;
    bool spoof_started;
    bool final_seen;
    uint32_t hosts;
    uint32_t frames;
    uint32_t drops;
    char password[64];
    char path[128];
    char error[48];
    char line[MITM_LINE_CAPACITY];
    size_t line_length;
    bool discard_line;
    bool prompt_space;
} MitmState;

static void mitm_scrub(void* pointer, size_t length) {
    volatile unsigned char* bytes = pointer;
    while(length--) *bytes++ = 0;
}

static void mitm_redraw(const C5HostApiV3* host) {
    if(host && host->request_redraw) host->request_redraw(host->ctx);
}

static void mitm_stage(MitmState* state, MitmStage stage) {
    state->stage = stage;
    state->stage_tick = state->last_tick;
}

/* The host's ordinary command path can log its argument. Use only raw TX. */
static bool mitm_send(const C5HostApiV3* host, const char* command) {
    if(!host || !host->send_raw_lines || !command) return false;
    size_t length = strlen(command);
    if(!length || length + 1 > MITM_COMMAND_CAPACITY ||
       length + 1 > C5_MODULE_RAW_TX_MAX) return false;
    char batch[MITM_COMMAND_CAPACITY];
    memcpy(batch, command, length);
    batch[length++] = '\n';
    bool sent = host->send_raw_lines(host->ctx, batch, length);
    mitm_scrub(batch, sizeof(batch));
    return sent;
}

static bool mitm_arg_valid(const char* text, size_t capacity, bool allow_empty) {
    if(!text) return false;
    size_t length = 0;
    while(length < capacity && text[length]) {
        unsigned char ch = (unsigned char)text[length++];
        if(ch < 0x20 || ch == 0x7f || ch == '"' || ch == '\\') return false;
    }
    return length < capacity && (allow_empty || length > 0);
}

static bool mitm_password_valid(const char* password) {
    if(!mitm_arg_valid(password, 64, true)) return false;
    size_t length = strlen(password);
    return length == 0 || (length >= 8 && length <= 63);
}

static bool mitm_bssid_valid(const char* text) {
    if(strlen(text) != 17) return false;
    for(size_t i = 0; i < 17; i++) {
        if(i % 3 == 2) {
            if(text[i] != ':') return false;
        } else if(!isxdigit((unsigned char)text[i])) return false;
    }
    return true;
}

static bool mitm_equal_nocase(char a, char b) {
    return tolower((unsigned char)a) == tolower((unsigned char)b);
}

static bool mitm_selected_row(const MitmState* state, const char* line) {
    size_t ssid_length = strlen(state->launch.ssid);
    if(strncmp(line, state->launch.ssid, ssid_length) != 0 ||
       strncmp(line + ssid_length, ", ", 2) != 0) return false;
    const char* bssid = line + ssid_length + 2;
    for(size_t i = 0; i < 17; i++) {
        if(!bssid[i] || !mitm_equal_nocase(bssid[i], state->launch.bssid[i])) return false;
    }
    return strncmp(bssid + 17, ", Ch", 4) == 0;
}

static bool mitm_csv_field(const char** cursor, char* output, size_t capacity, bool comma) {
    const char* p = *cursor;
    while(*p == ' ' || *p == '\t') p++;
    if(*p++ != '"') return false;
    size_t used = 0;
    bool closed = false;
    while(*p) {
        if(*p == '"') {
            if(p[1] == '"') {
                if(used + 1 >= capacity) return false;
                output[used++] = '"';
                p += 2;
            } else {
                p++;
                closed = true;
                break;
            }
        } else {
            if(used + 1 >= capacity) return false;
            output[used++] = *p++;
        }
    }
    if(!closed) return false;
    output[used] = '\0';
    while(*p == ' ' || *p == '\t') p++;
    if(comma) {
        if(*p++ != ',') return false;
    } else if(*p != '\0') return false;
    *cursor = p;
    return true;
}

static bool mitm_saved_row(const char* line, char ssid[33], char password[64]) {
    const char* cursor = line;
    return mitm_csv_field(&cursor, ssid, 33, true) &&
           mitm_csv_field(&cursor, password, 64, false) &&
           mitm_arg_valid(ssid, 33, false) && strlen(ssid) <= 31 &&
           mitm_password_valid(password) && password[0] != '\0';
}

static void mitm_error(MitmState* state, const C5HostApiV3* host, const char* message) {
    mitm_stage(state, MitmError);
    snprintf(state->error, sizeof(state->error), "%s", message);
    mitm_scrub(state->password, sizeof(state->password));
    mitm_redraw(host);
}

static bool mitm_connect(MitmState* state, const C5HostApiV3* host) {
    char command[MITM_COMMAND_CAPACITY] = {0};
    int written = state->password[0] ?
        snprintf(command, sizeof(command), "wifi_connect \"%s\" \"%s\"",
                 state->launch.ssid, state->password) :
        snprintf(command, sizeof(command), "wifi_connect \"%s\"", state->launch.ssid);
    bool sent = written > 0 && (size_t)written < sizeof(command) && mitm_send(host, command);
    mitm_scrub(command, sizeof(command));
    mitm_scrub(state->password, sizeof(state->password));
    if(!sent) return false;
    state->command_sent = true;
    state->connect_success = false;
    state->ip_seen = false;
    state->connect_failure = false;
    mitm_stage(state, MitmConnecting);
    mitm_redraw(host);
    return true;
}

static bool mitm_pcap_path(const char* path) {
    const size_t prefix = sizeof(MITM_PCAP_DIR) - 1;
    if(strncmp(path, MITM_PCAP_DIR, prefix) != 0) return false;
    const char* name = path + prefix;
    size_t length = strlen(name);
    if(length < 6 || length > 95 || name[0] == '.' ||
       strcmp(name + length - 5, ".pcap") != 0 || strstr(name, "..")) return false;
    for(size_t i = 0; i < length; i++) {
        unsigned char ch = (unsigned char)name[i];
        if(!isalnum(ch) && ch != '_' && ch != '-' && ch != '.') return false;
    }
    return true;
}

static bool mitm_parse_uint(const char** cursor, const char* prefix, uint32_t* out) {
    const char* p = *cursor;
    size_t prefix_length = strlen(prefix);
    if(strncmp(p, prefix, prefix_length) != 0) return false;
    p += prefix_length;
    if(!isdigit((unsigned char)*p)) return false;
    char* end = NULL;
    unsigned long value = strtoul(p, &end, 10);
    if(end == p || value > UINT32_MAX) return false;
    *out = (uint32_t)value;
    *cursor = end;
    return true;
}

static bool mitm_parse_final(const char* line, const char* known_path,
                             char output_path[128], uint32_t* frames, uint32_t* drops) {
    const char* prefix = "[PCAP_FINAL] file=";
    if(strncmp(line, prefix, strlen(prefix)) != 0) return false;
    const char* path = line + strlen(prefix);
    const char* path_end = strchr(path, ' ');
    if(!path_end || (size_t)(path_end - path) >= 128) return false;
    char parsed_path[128];
    memcpy(parsed_path, path, (size_t)(path_end - path));
    parsed_path[path_end - path] = '\0';
    if(!mitm_pcap_path(parsed_path) ||
       (known_path[0] && strcmp(known_path, parsed_path) != 0)) return false;
    const char* cursor = path_end;
    uint32_t parsed_frames, parsed_drops;
    if(!mitm_parse_uint(&cursor, " frames=", &parsed_frames) ||
       !mitm_parse_uint(&cursor, " drops=", &parsed_drops) ||
       (*cursor != ' ' && *cursor != '\0')) return false;
    memcpy(output_path, parsed_path, strlen(parsed_path) + 1);
    *frames = parsed_frames;
    *drops = parsed_drops;
    return true;
}

static bool mitm_connect_ack(const MitmState* state, const char* message) {
    const char* prefix = "SUCCESS: Connected to '";
    if(strncmp(message, prefix, strlen(prefix)) != 0) return false;
    message += strlen(prefix);
    size_t length = strlen(state->launch.ssid);
    return strncmp(message, state->launch.ssid, length) == 0 &&
           message[length] == '\'' && message[length + 1] == '\0';
}

static const char* mitm_log_message(const char* line) {
    if((line[0] != 'I' && line[0] != 'W' && line[0] != 'E') ||
       line[1] != ' ' || line[2] != '(') return line;
    const char* cursor = line + 3;
    if(!isdigit((unsigned char)*cursor)) return line;
    while(isdigit((unsigned char)*cursor)) cursor++;
    const char prefix[] = ") projectZero: ";
    return strncmp(cursor, prefix, sizeof(prefix) - 1) == 0 ?
               cursor + sizeof(prefix) - 1 : line;
}

static void mitm_on_line(MitmState* state, const C5HostApiV3* host, const char* line) {
    const char* message = mitm_log_message(line);
    switch(state->stage) {
    case MitmSelecting:
        if(strcmp(message, "Selected Networks:") == 0) state->selection_header = true;
        else if(state->selection_header && mitm_selected_row(state, message)) state->target_seen = true;
        break;
    case MitmLookingUp: {
        char ssid[33] = {0};
        char candidate[64] = {0};
        if(mitm_saved_row(message, ssid, candidate) &&
           strcmp(ssid, state->launch.ssid) == 0 && !state->saved_ambiguous) {
            if(!state->saved_found) {
                memcpy(state->password, candidate, sizeof(candidate));
                state->saved_found = true;
            } else if(strcmp(state->password, candidate) != 0) {
                mitm_scrub(state->password, sizeof(state->password));
                state->saved_found = false;
                state->saved_ambiguous = true;
            }
        }
        mitm_scrub(ssid, sizeof(ssid));
        mitm_scrub(candidate, sizeof(candidate));
        break;
    }
    case MitmConnecting:
        if(mitm_connect_ack(state, message)) state->connect_success = true;
        if((strncmp(message, "DHCP IP: ", 9) == 0 ||
            strncmp(message, "Static IP: ", 11) == 0) &&
           strstr(message, ", Netmask: ") && strstr(message, ", GW: "))
            state->ip_seen = true;
        if(strncmp(message, "FAILED: Connection to '", 23) == 0 ||
           strncmp(message, "TIMEOUT: Connection to '", 24) == 0 ||
           strcmp(message, "No IP assigned yet. Wait for DHCP.") == 0 ||
           strcmp(message, "Failed to reinitialize WiFi") == 0 ||
           strcmp(message, "STA interface not found") == 0)
            state->connect_failure = true;
        break;
    case MitmStartingPcap:
    case MitmActive:
    case MitmStartUnconfirmed: {
        const char* cursor = message;
        uint32_t hosts;
        if(mitm_parse_uint(&cursor, "PCAP net: Found ", &hosts) &&
           strcmp(cursor, " hosts to spoof") == 0 && hosts <= 254) {
            state->hosts = hosts;
            state->hosts_seen = true;
        } else if(strcmp(message, "PCAP net: ARP spoof MITM started (IP forwarding enabled)") == 0) {
            state->spoof_started = true;
        } else if(strncmp(message, "PCAP net capture started -> ", 28) == 0) {
            const char* path = message + 28;
            if(mitm_pcap_path(path) && strlen(path) < sizeof(state->path)) {
                snprintf(state->path, sizeof(state->path), "%s", path);
                mitm_stage(state, MitmActive);
            }
        } else if(strncmp(message, "Failed to initialize SD card:", 29) == 0) {
            if(!state->path[0]) state->pcap_start_failed = true;
            mitm_error(state, host, "SD unavailable");
        } else if(strncmp(message, "Not connected to WiFi.", 22) == 0) {
            if(!state->path[0]) state->pcap_start_failed = true;
            mitm_error(state, host, "WiFi disconnected");
        } else if(strncmp(message, "PCAP capture already active.", 28) == 0 ||
                  strncmp(message, "Capture Gateway is active;", 26) == 0 ||
                  strncmp(message, "Failed to create ", 17) == 0 ||
                  strncmp(message, "Failed to open ", 15) == 0 ||
                  strncmp(message, "Failed to allocate/configure PCAP", 33) == 0 ||
                  strncmp(message, "Failed to write PCAP header", 27) == 0 ||
                  strncmp(message, "Failed to get ", 14) == 0) {
            if(!state->path[0]) state->pcap_start_failed = true;
            mitm_error(state, host, "PCAP start failed");
        }
        break;
    }
    case MitmStopping:
    case MitmStopUnconfirmed:
        if(state->pcap_attempted && !state->pcap_start_failed) {
            uint32_t frames, drops;
            if(mitm_parse_final(message, state->path, state->path, &frames, &drops)) {
                state->frames = frames;
                state->drops = drops;
                state->final_seen = true;
                mitm_stage(state, MitmStopped);
            }
        }
        if(strcmp(message, "All operations stopped.") == 0) {
            state->stop_ack_seen = true;
            if(!state->pcap_attempted || state->pcap_start_failed)
                mitm_stage(state, MitmStopped);
            else if(!state->final_seen) mitm_stage(state, MitmStopUnconfirmed);
        }
        break;
    default: break;
    }
    mitm_redraw(host);
}

static void mitm_on_prompt(MitmState* state, const C5HostApiV3* host) {
    if(state->stage == MitmSelecting) {
        if(!state->selection_header || !state->target_seen ||
           !mitm_send(host, "show_pass evil")) {
            mitm_error(state, host, "Target changed");
        } else {
            mitm_stage(state, MitmLookingUp);
        }
    } else if(state->stage == MitmLookingUp) {
        if(state->saved_found && !state->saved_ambiguous) {
            if(!mitm_connect(state, host)) mitm_error(state, host, "WiFi command failed");
        } else {
            C5TextInputRequest request = {
                .header = "WiFi password (blank=open)",
                .capacity = C5_TEXT_INPUT_VALUE_CAPACITY,
                .minimum_length = 0,
            };
            mitm_stage(state, MitmPasswordInput);
            if(!host->request_text_input(host->ctx, &request))
                mitm_error(state, host, "Password input unavailable");
        }
    } else if(state->stage == MitmConnecting) {
        if(!state->connect_failure && state->connect_success && state->ip_seen &&
           mitm_send(host, "start_pcap net")) {
            state->pcap_attempted = true;
            state->pcap_start_failed = false;
            state->stop_ack_seen = false;
            mitm_stage(state, MitmStartingPcap);
        } else {
            mitm_error(state, host, "WiFi failed");
        }
    } else if(state->stage == MitmStartingPcap) {
        mitm_error(state, host, "PCAP start failed");
    }
    mitm_redraw(host);
}

static void* mitm_enter(const C5HostApiV3* h, const void* p, size_t n) {
    if(!h || h->version != C5_MODULE_API_VERSION || h->size < sizeof(C5HostApiV3) ||
       !h->send_raw_lines || !h->request_text_input || !h->request_redraw ||
       !p || n != sizeof(C5MitmPcapLaunchContext)) return NULL;
    const C5MitmPcapLaunchContext* launch = p;
    if(launch->version != C5_MITM_PCAP_LAUNCH_VERSION ||
       launch->size != sizeof(*launch) ||
       launch->selected_number == 0 || launch->selected_number > 64 ||
       !memchr(launch->ssid, '\0', sizeof(launch->ssid)) ||
       !memchr(launch->bssid, '\0', sizeof(launch->bssid)) ||
       !mitm_arg_valid(launch->ssid, sizeof(launch->ssid), false) ||
       strlen(launch->ssid) > 31 || !mitm_bssid_valid(launch->bssid) ||
       !launch->ticks_per_second || launch->ticks_per_second > 1000000u) return NULL;
    MitmState* state = calloc(1, sizeof(*state));
    if(!state) return NULL;
    state->launch = *launch;
    state->stage = MitmPending;
    return state;
}
static void mitm_leave(void* opaque, const C5HostApiV3* host) {
    MitmState* state = opaque;
    if(!state) return;
    if(state->command_sent && state->stage != MitmStopped) mitm_send(host, "stop");
    mitm_scrub(state, sizeof(*state));
    free(state);
}
static void mitm_bytes(void* opaque, const C5HostApiV3* host, const uint8_t* bytes, size_t length) {
    MitmState* state = opaque;
    if(!state || !host || !bytes) return;
    for(size_t i = 0; i < length; i++) {
        char ch = (char)bytes[i];
        if(ch == '\r') continue;
        if(state->prompt_space) {
            state->prompt_space = false;
            if(ch == ' ') continue;
        }
        if(ch == '\0') {
            mitm_scrub(state->line, sizeof(state->line));
            state->line_length = 0;
            state->discard_line = true;
        } else if(ch == '>' && state->line_length == 0 && !state->discard_line) {
            mitm_on_prompt(state, host);
            state->prompt_space = true;
        } else if(ch == '\n') {
            if(!state->discard_line && state->line_length) {
                state->line[state->line_length] = '\0';
                mitm_on_line(state, host, state->line);
            }
            mitm_scrub(state->line, sizeof(state->line));
            state->line_length = 0;
            state->discard_line = false;
        } else if(!state->discard_line) {
            if(state->line_length + 1 < sizeof(state->line))
                state->line[state->line_length++] = ch;
            else {
                mitm_scrub(state->line, sizeof(state->line));
                state->line_length = 0;
                state->discard_line = true;
            }
        }
    }
}
static C5InputResult mitm_input(void* s, const C5HostApiV3* h, const InputEvent* e) {
    MitmState* state = s;
    if(!state || !h || !e || e->type != InputTypeShort || e->key != InputKeyBack)
        return C5InputIgnored;
    if(state->stage == MitmPending || state->stage == MitmStopped || !state->command_sent)
        return C5InputSwitchModule;
    if(state->stage == MitmStopUnconfirmed && state->stop_ack_seen)
        return C5InputSwitchModule;
    if(state->stage == MitmStopping) return C5InputConsumed;
    if(mitm_send(h, "stop")) mitm_stage(state, MitmStopping);
    else mitm_stage(state, MitmStopUnconfirmed);
    mitm_redraw(h);
    return C5InputConsumed;
}
static void mitm_text(void* s, const C5HostApiV3* h, bool accepted, const char* text) {
    MitmState* state = s;
    if(!state || !h || state->stage != MitmPasswordInput) return;
    if(!accepted || !text) {
        mitm_error(state, h, "Password cancelled");
    } else if(!mitm_password_valid(text)) {
        mitm_error(state, h, "Invalid password");
    } else {
        snprintf(state->password, sizeof(state->password), "%s", text);
        if(!mitm_connect(state, h)) mitm_error(state, h, "WiFi command failed");
    }
}
static void mitm_draw(void* s, const C5HostApiV3* h, Canvas* c) {
    (void)h;
    MitmState* state = s;
    if(!state || !c) return;
    const char* status = "Selecting target";
    switch(state->stage) {
    case MitmPending:
    case MitmSelecting: status = "Selecting target"; break;
    case MitmLookingUp: status = "Checking password"; break;
    case MitmPasswordInput: status = "Enter WiFi password"; break;
    case MitmConnecting: status = "Connecting WiFi"; break;
    case MitmStartingPcap: status = "Starting PCAP"; break;
    case MitmActive: status = "PCAP active"; break;
    case MitmStartUnconfirmed: status = "Start unconfirmed"; break;
    case MitmStopping: status = "Stopping PCAP"; break;
    case MitmStopUnconfirmed:
        status = state->stop_ack_seen ? "Stop ACK; PCAP unknown" : "Stop unconfirmed";
        break;
    case MitmStopped: status = "Stopped"; break;
    case MitmError: status = state->error; break;
    }
    char line[64];
    canvas_set_color(c, ColorBlack);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "MITM PCAP");
    canvas_set_font(c, FontSecondary);
    canvas_draw_str(c, 2, 21, status);
    snprintf(line, sizeof(line), "SSID: %.20s", state->launch.ssid);
    canvas_draw_str(c, 2, 31, line);
    const char* basename = strrchr(state->path, '/');
    basename = basename ? basename + 1 : "--";
    snprintf(line, sizeof(line), "File: %.20s", basename);
    canvas_draw_str(c, 2, 41, line);
    if(state->hosts_seen && state->hosts == 0) snprintf(line, sizeof(line), "Spoof: 0 hosts");
    else if(state->hosts_seen && state->spoof_started)
        snprintf(line, sizeof(line), "Spoof: reported %lu", (unsigned long)state->hosts);
    else if(state->hosts_seen)
        snprintf(line, sizeof(line), "Spoof: %lu targets", (unsigned long)state->hosts);
    else snprintf(line, sizeof(line), "Spoof: unknown");
    canvas_draw_str(c, 2, 51, line);
    if(state->final_seen)
        snprintf(line, sizeof(line), "Frames: %lu Drops: %lu",
                 (unsigned long)state->frames, (unsigned long)state->drops);
    else if(state->stage == MitmStopped) snprintf(line, sizeof(line), "No PCAP started");
    else if(state->stage == MitmStopUnconfirmed && state->stop_ack_seen)
        snprintf(line, sizeof(line), "Back: exit");
    else snprintf(line, sizeof(line), "Back: stop");
    canvas_draw_str(c, 2, 61, line);
}
static void mitm_tick(void* s, const C5HostApiV3* h, uint32_t t) {
    MitmState* state = s;
    if(!state || !h) return;
    state->last_tick = t;
    if(state->stage == MitmPending) {
        char command[40];
        int written = snprintf(command, sizeof(command), "select_networks %u",
                               (unsigned)state->launch.selected_number);
        if(written <= 0 || (size_t)written >= sizeof(command) || !mitm_send(h, command))
            mitm_error(state, h, "Target command failed");
        else {
            state->command_sent = true;
            mitm_stage(state, MitmSelecting);
        }
        return;
    }
    uint32_t seconds = 0;
    switch(state->stage) {
    case MitmSelecting:
    case MitmLookingUp: seconds = 5; break;
    case MitmConnecting: seconds = 22; break;
    case MitmStartingPcap: seconds = 15; break;
    case MitmStopping: seconds = 30; break;
    default: break;
    }
    if(seconds && (uint32_t)(t - state->stage_tick) >=
                      state->launch.ticks_per_second * seconds) {
        if(state->stage == MitmStopping) mitm_stage(state, MitmStopUnconfirmed);
        else if(state->stage == MitmStartingPcap) mitm_stage(state, MitmStartUnconfirmed);
        else mitm_error(state, h, "Reply timed out");
        mitm_redraw(h);
    }
}
static const C5ModuleV3 c5_mitm_module = {
    .version = C5_MODULE_API_VERSION, .size = sizeof(C5ModuleV3),
    .enter = mitm_enter, .leave = mitm_leave, .on_bytes = mitm_bytes,
    .on_input = mitm_input, .on_text_input = mitm_text,
    .draw = mitm_draw, .tick = mitm_tick,
};
static const FlipperAppPluginDescriptor c5_mitm_descriptor = {
    .appid = C5_MODULE_APP_ID, .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_mitm_module,
};
const FlipperAppPluginDescriptor* lab_c5_mitm_pcap_plugin_ep(void) {
    return &c5_mitm_descriptor;
}
