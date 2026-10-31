#include "arp_module.h"
#include "../../module_api.h"

#include <flipper_application/flipper_application.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define C5_ARP_LINE_CAPACITY 224u
#define C5_ARP_COMMAND_CAPACITY 160u
#define C5_ARP_SAVED_MAX 32u
#define C5_ARP_HOST_MAX 32u

typedef enum {
    ArpPhaseSelectPending,
    ArpPhaseSelectWait,
    ArpPhaseSavedPending,
    ArpPhasePreflightWait,
    ArpPhaseSavedList,
    ArpPhasePasswordInput,
    ArpPhaseConnecting,
    ArpPhaseDiscovering,
    ArpPhaseHostList,
    ArpPhaseStarting,
    ArpPhaseActive,
    ArpPhaseStopping,
    ArpPhaseStopped,
    ArpPhaseError,
} ArpPhase;

typedef struct {
    char ssid[33];
    char password[65];
} ArpSavedEntry;

typedef struct {
    uint8_t ip[4];
    uint8_t mac[6];
} ArpHostEntry;

typedef struct {
    uint16_t selected_number;
    bool saved_only;
    ArpPhase phase;
    char ssid[33];
    bool selected_seen;
    bool found_saved;
    bool connect_success;
    bool connect_error;
    bool host_header_seen;
    bool host_done;
    bool in_host_section;
    bool stop_required;
    bool stop_acknowledged;
    bool prompt_space;
    char password[65];
    ArpSavedEntry* saved;
    size_t saved_count;
    size_t selected_saved;
    ArpHostEntry* hosts;
    size_t host_count;
    size_t selected_host;
    char line[C5_ARP_LINE_CAPACITY];
    size_t line_length;
    bool discard_line;
    char error[48];
} ArpState;

static void arp_zero(void* data, size_t size) {
    volatile unsigned char* bytes = data;
    while(size--) *bytes++ = 0;
}

static bool arp_cli_arg_valid(const char* value, size_t maximum, bool allow_empty) {
    if(!value) return false;
    size_t length = strlen(value);
    if(length > maximum || (!allow_empty && !length)) return false;
    for(size_t i = 0; i < length; i++) {
        unsigned char ch = (unsigned char)value[i];
        if(ch < 0x20 || ch == 0x7f || ch == '"' || ch == '\\') return false;
    }
    return true;
}

static bool arp_send(const C5HostApiV3* host, const char* command) {
    if(!host || !host->send_raw_lines || !command) return false;
    size_t length = strlen(command);
    if(!length || length + 1 > C5_ARP_COMMAND_CAPACITY ||
       length + 1 > C5_MODULE_RAW_TX_MAX) return false;
    char batch[C5_ARP_COMMAND_CAPACITY];
    memcpy(batch, command, length);
    batch[length++] = '\n';
    bool sent = host->send_raw_lines(host->ctx, batch, length);
    arp_zero(batch, sizeof(batch));
    return sent;
}

static bool arp_send_connect(ArpState* state, const C5HostApiV3* host) {
    char command[C5_ARP_COMMAND_CAPACITY];
    bool valid = arp_cli_arg_valid(state->ssid, 31, false) &&
                 arp_cli_arg_valid(state->password, 63, true);
    int written = valid ?
        (state->password[0] ?
            snprintf(command, sizeof(command), "wifi_connect \"%s\" \"%s\"",
                     state->ssid, state->password) :
            snprintf(command, sizeof(command), "wifi_connect \"%s\"", state->ssid)) : -1;
    if(written < 0 || (size_t)written >= sizeof(command)) {
        arp_zero(command, sizeof(command));
        arp_zero(state->password, sizeof(state->password));
        return false;
    }
    state->phase = ArpPhaseConnecting;
    bool sent = arp_send(host, command);
    state->stop_required = state->stop_required || sent;
    arp_zero(command, sizeof(command));
    arp_zero(state->password, sizeof(state->password));
    return sent;
}

static void arp_error(ArpState* state, const C5HostApiV3* host, const char* message) {
    state->phase = ArpPhaseError;
    snprintf(state->error, sizeof(state->error), "%s", message);
    if(host && host->request_redraw) host->request_redraw(host->ctx);
}

static bool arp_request_password(ArpState* state, const C5HostApiV3* host) {
    if(!host->request_text_input) return false;
    C5TextInputRequest request = {
        .header = "WiFi password",
        .capacity = C5_TEXT_INPUT_VALUE_CAPACITY,
        .minimum_length = 0,
    };
    state->phase = ArpPhasePasswordInput;
    return host->request_text_input(host->ctx, &request);
}

static void arp_release_saved(ArpState* state) {
    if(!state->saved) return;
    arp_zero(state->saved, C5_ARP_SAVED_MAX * sizeof(*state->saved));
    free(state->saved);
    state->saved = NULL;
    state->saved_count = 0;
}

static void arp_release_hosts(ArpState* state) {
    free(state->hosts);
    state->hosts = NULL;
    state->host_count = 0;
    state->selected_host = 0;
}

/* JanOS eviltwin.txt uses two CSV quoted fields with doubled quotes. */
static bool arp_csv_field(const char** cursor, char* output, size_t capacity, bool comma) {
    const char* p = *cursor;
    while(*p == ' ' || *p == '\t') p++;
    if(*p++ != '"') return false;
    size_t length = 0;
    bool closed = false;
    while(*p) {
        if(*p == '"') {
            if(p[1] == '"') {
                if(length + 1 >= capacity) return false;
                output[length++] = '"';
                p += 2;
            } else {
                p++;
                closed = true;
                break;
            }
        } else {
            if(length + 1 >= capacity) return false;
            output[length++] = *p++;
        }
    }
    if(!closed) return false;
    output[length] = '\0';
    while(*p == ' ' || *p == '\t') p++;
    if(comma) {
        if(*p++ != ',') return false;
    } else if(*p != '\0') {
        return false;
    }
    *cursor = p;
    return true;
}

static bool arp_parse_saved_row(const char* line, char ssid[33], char password[65]) {
    const char* cursor = line;
    return arp_csv_field(&cursor, ssid, 33, true) &&
           arp_csv_field(&cursor, password, 65, false) &&
           arp_cli_arg_valid(ssid, 31, false) &&
           arp_cli_arg_valid(password, 63, false) && strlen(password) >= 8;
}

static bool arp_parse_ip(const char* text, uint8_t output[4]) {
    const char* cursor = text;
    for(size_t part = 0; part < 4; part++) {
        if(*cursor < '0' || *cursor > '9') return false;
        unsigned number = 0;
        size_t digits = 0;
        while(*cursor >= '0' && *cursor <= '9' && digits < 3) {
            number = number * 10 + (unsigned)(*cursor++ - '0');
            digits++;
        }
        if(number > 255 || (*cursor >= '0' && *cursor <= '9')) return false;
        output[part] = (uint8_t)number;
        if(part < 3) {
            if(*cursor++ != '.') return false;
        } else if(*cursor) {
            return false;
        }
    }
    return output[0] != 0 && output[0] < 224 &&
           !(output[0] == 255 && output[1] == 255 && output[2] == 255 && output[3] == 255);
}

static int arp_hex(char ch) {
    if(ch >= '0' && ch <= '9') return ch - '0';
    if(ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if(ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static bool arp_parse_mac(const char* text, uint8_t output[6]) {
    for(size_t part = 0; part < 6; part++) {
        int high = arp_hex(text[part * 3]);
        int low = arp_hex(text[part * 3 + 1]);
        if(high < 0 || low < 0 || (part < 5 && text[part * 3 + 2] != ':')) return false;
        output[part] = (uint8_t)((high << 4) | low);
    }
    return text[17] == '\0' && !(output[0] & 1u);
}

static bool arp_parse_host_row(const char* line, ArpHostEntry* result) {
    const char* arrow = strstr(line, "->");
    if(!arrow) return false;
    const char* ip_end = arrow;
    while(ip_end > line && (ip_end[-1] == ' ' || ip_end[-1] == '\t')) ip_end--;
    const char* ip_start = ip_end;
    while(ip_start > line && ip_start[-1] != ' ' && ip_start[-1] != '\t') ip_start--;
    size_t ip_length = (size_t)(ip_end - ip_start);
    if(!ip_length || ip_length >= 16) return false;
    char ip[16];
    memcpy(ip, ip_start, ip_length);
    ip[ip_length] = '\0';
    if(!arp_parse_ip(ip, result->ip)) return false;
    const char* mac_start = arrow + 2;
    while(*mac_start == ' ' || *mac_start == '\t') mac_start++;
    if(strlen(mac_start) < 17) return false;
    char mac[18];
    memcpy(mac, mac_start, 17);
    mac[17] = '\0';
    if(mac_start[17] != '\0' && mac_start[17] != ' ' && mac_start[17] != '\t') return false;
    return arp_parse_mac(mac, result->mac);
}

static void arp_format_mac(const ArpHostEntry* entry, char* text, size_t capacity) {
    snprintf(text, capacity, "%02X:%02X:%02X:%02X:%02X:%02X",
             entry->mac[0], entry->mac[1], entry->mac[2],
             entry->mac[3], entry->mac[4], entry->mac[5]);
}

static bool arp_begin_hosts(ArpState* state, const C5HostApiV3* host) {
    arp_release_hosts(state);
    state->hosts = calloc(C5_ARP_HOST_MAX, sizeof(*state->hosts));
    if(!state->hosts) return false;
    state->host_header_seen = false;
    state->host_done = false;
    state->in_host_section = false;
    if(!arp_send(host, "list_hosts")) {
        arp_release_hosts(state);
        return false;
    }
    state->phase = ArpPhaseDiscovering;
    return true;
}

static bool arp_begin_ban(ArpState* state, const C5HostApiV3* host) {
    if(!state->hosts || state->selected_host >= state->host_count) return false;
    const ArpHostEntry* entry = &state->hosts[state->selected_host];
    char command[64];
    int written = snprintf(command, sizeof(command),
                           "arp_ban %02X:%02X:%02X:%02X:%02X:%02X %u.%u.%u.%u",
                           entry->mac[0], entry->mac[1], entry->mac[2],
                           entry->mac[3], entry->mac[4], entry->mac[5],
                           entry->ip[0], entry->ip[1], entry->ip[2], entry->ip[3]);
    if(written < 0 || (size_t)written >= sizeof(command) || !arp_send(host, command)) return false;
    state->phase = ArpPhaseStarting;
    state->stop_required = true;
    return true;
}

static void arp_on_line(ArpState* state, const C5HostApiV3* host, const char* line) {
    if(state->phase == ArpPhaseSelectWait) {
        if(strstr(line, "Selected Networks:")) state->selected_seen = true;
    } else if(state->phase == ArpPhasePreflightWait) {
        char ssid[33] = {0};
        char password[65] = {0};
        if(arp_parse_saved_row(line, ssid, password)) {
            if(state->saved_only) {
                if(state->saved_count < C5_ARP_SAVED_MAX) {
                    ArpSavedEntry* entry = &state->saved[state->saved_count++];
                    memcpy(entry->ssid, ssid, sizeof(ssid));
                    memcpy(entry->password, password, sizeof(password));
                }
            } else if(strcmp(ssid, state->ssid) == 0) {
                memcpy(state->password, password, sizeof(password));
                state->found_saved = true;
            }
        }
        arp_zero(password, sizeof(password));
    } else if(state->phase == ArpPhaseConnecting) {
        const char* success = strstr(line, "SUCCESS: Connected to '");
        if(success) {
            success += strlen("SUCCESS: Connected to '");
            size_t length = strlen(state->ssid);
            if(strncmp(success, state->ssid, length) == 0 && success[length] == '\'') {
                state->connect_success = true;
            }
        }
        if(strstr(line, "FAILED: Connection to '") ||
           strstr(line, "TIMEOUT: Connection to '") ||
           strstr(line, "No IP assigned yet")) state->connect_error = true;
    } else if(state->phase == ArpPhaseDiscovering) {
        if(strstr(line, "=== Discovered Hosts ===")) {
            state->host_header_seen = true;
            state->in_host_section = true;
        } else if(state->in_host_section && strstr(line, "========================")) {
            state->in_host_section = false;
        } else if(state->in_host_section && state->hosts && state->host_count < C5_ARP_HOST_MAX) {
            ArpHostEntry entry;
            if(arp_parse_host_row(line, &entry)) {
                bool duplicate = false;
                for(size_t i = 0; i < state->host_count; i++) {
                    if(memcmp(state->hosts[i].ip, entry.ip, sizeof(entry.ip)) == 0) {
                        duplicate = true;
                        break;
                    }
                }
                if(!duplicate) state->hosts[state->host_count++] = entry;
            }
        }
        if(strstr(line, "Found ") && strstr(line, " hosts (")) state->host_done = true;
    } else if(state->phase == ArpPhaseStarting) {
        if(strcmp(line, "ARP ban started. Use 'stop' to stop.") == 0) {
            state->phase = ArpPhaseActive;
        } else if(strstr(line, "Invalid MAC format") ||
                  strstr(line, "Not connected to any AP") ||
                  strstr(line, "Could not find gateway MAC") ||
                  strstr(line, "Failed to create ARP ban task") ||
                  strstr(line, "ARP ban already running")) {
            arp_error(state, host, "ARP start failed");
        }
    } else if(state->phase == ArpPhaseStopping) {
        if(strcmp(line, "All operations stopped.") == 0) {
            state->stop_acknowledged = true;
            state->stop_required = false;
            state->phase = ArpPhaseStopped;
            arp_release_hosts(state);
        }
    }
    if(host && host->request_redraw) host->request_redraw(host->ctx);
}

static void arp_on_prompt(ArpState* state, const C5HostApiV3* host) {
    if(state->phase == ArpPhaseSelectWait) {
        if(!state->selected_seen || !arp_send(host, "show_pass evil")) {
            arp_error(state, host, "Network selection failed");
        } else {
            state->phase = ArpPhasePreflightWait;
        }
    } else if(state->phase == ArpPhasePreflightWait) {
        if(state->saved_only) {
            if(state->saved_count) state->phase = ArpPhaseSavedList;
            else arp_error(state, host, "No usable saved WiFi");
        } else if(state->found_saved) {
            if(!arp_send_connect(state, host)) arp_error(state, host, "WiFi command failed");
        } else if(!arp_request_password(state, host)) {
            arp_error(state, host, "Password input unavailable");
        }
    } else if(state->phase == ArpPhaseConnecting) {
        if(state->connect_success && !state->connect_error) {
            if(!arp_begin_hosts(state, host)) arp_error(state, host, "Host scan unavailable");
        } else {
            arp_error(state, host, "WiFi connection failed");
        }
    } else if(state->phase == ArpPhaseDiscovering) {
        if(state->host_header_seen && state->host_done) state->phase = ArpPhaseHostList;
        else arp_error(state, host, "Host scan failed");
    } else if(state->phase == ArpPhaseStarting) {
        arp_error(state, host, "ARP start failed");
    }
    if(host && host->request_redraw) host->request_redraw(host->ctx);
}

static void* arp_enter(const C5HostApiV3* host, const void* params, size_t params_size) {
    if(!host || host->version != C5_MODULE_API_VERSION ||
       host->size < sizeof(*host) || !host->send_raw_lines ||
       !params || params_size != sizeof(C5ArpLaunchContext)) return NULL;
    const C5ArpLaunchContext* launch = params;
    if(launch->version != C5_ARP_LAUNCH_VERSION ||
       launch->size != sizeof(*launch) ||
       !memchr(launch->ssid, '\0', sizeof(launch->ssid)) ||
       (launch->saved_only ? (launch->selected_number != 0 || launch->ssid[0] != '\0') :
                             (launch->selected_number == 0 || launch->selected_number > 64 ||
                              !arp_cli_arg_valid(launch->ssid, 31, false)))) return NULL;
    ArpState* state = calloc(1, sizeof(*state));
    if(!state) return NULL;
    state->selected_number = launch->selected_number;
    state->saved_only = launch->saved_only;
    memcpy(state->ssid, launch->ssid, sizeof(state->ssid));
    state->phase = launch->saved_only ? ArpPhaseSavedPending : ArpPhaseSelectPending;
    if(launch->saved_only) {
        state->saved = calloc(C5_ARP_SAVED_MAX, sizeof(*state->saved));
        if(!state->saved) {
            free(state);
            return NULL;
        }
    }
    return state;
}

static void arp_leave(void* opaque, const C5HostApiV3* host) {
    ArpState* state = opaque;
    if(!state) return;
    if(state->stop_required && !state->stop_acknowledged) arp_send(host, "stop");
    arp_release_saved(state);
    arp_release_hosts(state);
    arp_zero(state, sizeof(*state));
    free(state);
}

static void arp_on_bytes(void* opaque, const C5HostApiV3* host, const uint8_t* bytes, size_t length) {
    ArpState* state = opaque;
    if(!state || !bytes) return;
    for(size_t i = 0; i < length; i++) {
        char ch = (char)bytes[i];
        if(ch == '\r') continue;
        if(state->prompt_space) {
            state->prompt_space = false;
            if(ch == ' ') continue;
        }
        if(ch == '\0') {
            arp_zero(state->line, sizeof(state->line));
            state->line_length = 0;
            state->discard_line = true;
            continue;
        }
        if(ch == '>' && state->line_length == 0 && !state->discard_line) {
            arp_on_prompt(state, host);
            state->prompt_space = true;
            continue;
        }
        if(ch == '\n') {
            if(!state->discard_line && state->line_length) {
                state->line[state->line_length] = '\0';
                arp_on_line(state, host, state->line);
            }
            arp_zero(state->line, sizeof(state->line));
            state->line_length = 0;
            state->discard_line = false;
        } else if(!state->discard_line) {
            if(state->line_length + 1 < sizeof(state->line)) {
                state->line[state->line_length++] = ch;
            } else {
                arp_zero(state->line, sizeof(state->line));
                state->line_length = 0;
                state->discard_line = true;
            }
        }
    }
}

static C5InputResult arp_on_input(void* opaque, const C5HostApiV3* host, const InputEvent* event) {
    ArpState* state = opaque;
    if(!state || !host || !event) return C5InputIgnored;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return C5InputIgnored;
    if(event->key == InputKeyBack || event->key == InputKeyLeft) {
        if(event->type != InputTypeShort) return C5InputIgnored;
        if(state->phase == ArpPhaseStopped || state->phase == ArpPhaseSavedList ||
           state->phase == ArpPhaseSavedPending || state->phase == ArpPhaseSelectPending ||
           (state->phase == ArpPhasePasswordInput && !state->stop_required))
            return C5InputSwitchModule;
        if(state->phase == ArpPhaseError && !state->stop_required) return C5InputSwitchModule;
        if(!arp_send(host, "stop")) {
            arp_error(state, host, "Stop command failed");
            return C5InputConsumed;
        }
        state->phase = ArpPhaseStopping;
        state->stop_required = true;
        state->stop_acknowledged = false;
        if(host->request_redraw) host->request_redraw(host->ctx);
        return C5InputConsumed;
    }
    if(state->phase == ArpPhaseSavedList) {
        if(event->key == InputKeyUp && state->selected_saved) {
            state->selected_saved--;
        } else if(event->key == InputKeyDown &&
                  state->selected_saved + 1 < state->saved_count) {
            state->selected_saved++;
        } else if(event->type == InputTypeShort && event->key == InputKeyOk &&
                  state->selected_saved < state->saved_count) {
            const ArpSavedEntry* entry = &state->saved[state->selected_saved];
            memcpy(state->ssid, entry->ssid, sizeof(state->ssid));
            memcpy(state->password, entry->password, sizeof(state->password));
            arp_release_saved(state);
            if(!arp_send_connect(state, host)) arp_error(state, host, "WiFi command failed");
        } else {
            return C5InputIgnored;
        }
    } else if(state->phase == ArpPhaseHostList) {
        if(event->key == InputKeyUp && state->selected_host) {
            state->selected_host--;
        } else if(event->key == InputKeyDown &&
                  state->selected_host + 1 < state->host_count) {
            state->selected_host++;
        } else if(event->type == InputTypeShort && event->key == InputKeyOk &&
                  state->selected_host < state->host_count) {
            if(!arp_begin_ban(state, host)) arp_error(state, host, "ARP command failed");
        } else {
            return C5InputIgnored;
        }
    } else {
        return C5InputIgnored;
    }
    if(host->request_redraw) host->request_redraw(host->ctx);
    return C5InputConsumed;
}

static void arp_draw(void* opaque, const C5HostApiV3* host, Canvas* canvas) {
    ArpState* state = opaque;
    (void)host;
    if(!state || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 12, state->phase == ArpPhaseSavedList ? "ARP Saved" : "ARP Poisoning");
    canvas_set_font(canvas, FontSecondary);
    switch(state->phase) {
    case ArpPhaseSelectPending:
    case ArpPhaseSelectWait: canvas_draw_str(canvas, 2, 32, "Selecting network..."); break;
    case ArpPhaseSavedPending:
    case ArpPhasePreflightWait: canvas_draw_str(canvas, 2, 32, "Reading saved WiFi..."); break;
    case ArpPhaseSavedList: {
        size_t start = state->selected_saved >= 4 ? state->selected_saved - 3 : 0;
        for(size_t i = start; i < state->saved_count && i < start + 4; i++) {
            char label[42];
            size_t written = 0;
            label[written++] = i == state->selected_saved ? '>' : ' ';
            label[written++] = ' ';
            const char* ssid = state->saved[i].ssid;
            for(size_t j = 0; ssid[j] && written + 1 < sizeof(label); j++) {
                unsigned char ch = (unsigned char)ssid[j];
                label[written++] = ch >= 0x20 && ch < 0x7f ? (char)ch : '?';
            }
            label[written] = '\0';
            canvas_draw_str(canvas, 2, 24 + (int)(i - start) * 10, label);
        }
        break;
    }
    case ArpPhasePasswordInput: canvas_draw_str(canvas, 2, 32, "Enter WiFi password"); break;
    case ArpPhaseConnecting: canvas_draw_str(canvas, 2, 32, "Connecting to WiFi..."); break;
    case ArpPhaseDiscovering: canvas_draw_str(canvas, 2, 32, "Discovering hosts..."); break;
    case ArpPhaseHostList:
        if(!state->host_count) canvas_draw_str(canvas, 2, 32, "No ARP hosts found");
        else {
            size_t start = state->selected_host >= 3 ? state->selected_host - 2 : 0;
            for(size_t i = start; i < state->host_count && i < start + 3; i++) {
                char label[48];
                int written = snprintf(label, sizeof(label), "%c %u.%u.%u.%u",
                                       i == state->selected_host ? '>' : ' ',
                                       state->hosts[i].ip[0], state->hosts[i].ip[1],
                                       state->hosts[i].ip[2], state->hosts[i].ip[3]);
                if(written > 0) canvas_draw_str(canvas, 2, 24 + (int)(i - start) * 10, label);
            }
            char selected[48];
            arp_format_mac(&state->hosts[state->selected_host], selected, sizeof(selected));
            canvas_draw_str(canvas, 2, 61, selected);
        }
        break;
    case ArpPhaseStarting: canvas_draw_str(canvas, 2, 32, "Starting ARP..."); break;
    case ArpPhaseActive: canvas_draw_str(canvas, 2, 32, "ARP Active");
        canvas_draw_str(canvas, 2, 51, "Back: stop"); break;
    case ArpPhaseStopping: canvas_draw_str(canvas, 2, 32, "Stopping...");
        canvas_draw_str(canvas, 2, 51, "Back: retry stop"); break;
    case ArpPhaseStopped: canvas_draw_str(canvas, 2, 32, "Stopped");
        canvas_draw_str(canvas, 2, 51, "Back: exit"); break;
    case ArpPhaseError: canvas_draw_str(canvas, 2, 32, state->error);
        canvas_draw_str(canvas, 2, 51, "Back: stop/exit"); break;
    }
}

static void arp_on_text_input(void* opaque, const C5HostApiV3* host,
                              bool accepted, const char* text) {
    ArpState* state = opaque;
    if(!state || state->phase != ArpPhasePasswordInput) return;
    if(!accepted || !text) {
        arp_error(state, host, "Password cancelled");
        return;
    }
    size_t length = strlen(text);
    if(length > 63 || (length > 0 && length < 8) ||
       !arp_cli_arg_valid(text, 63, true)) {
        arp_error(state, host, "Unsupported password");
        return;
    }
    memcpy(state->password, text, length + 1);
    if(!arp_send_connect(state, host)) arp_error(state, host, "WiFi command failed");
    if(host->request_redraw) host->request_redraw(host->ctx);
}

static void arp_tick(void* opaque, const C5HostApiV3* host, uint32_t now_ticks) {
    (void)now_ticks;
    ArpState* state = opaque;
    if(!state) return;
    if(state->phase == ArpPhaseSavedPending) {
        if(arp_send(host, "show_pass evil")) state->phase = ArpPhasePreflightWait;
        else arp_error(state, host, "Saved list unavailable");
    } else if(state->phase == ArpPhaseSelectPending) {
        char command[32];
        int written = snprintf(command, sizeof(command), "select_networks %u",
                               (unsigned)state->selected_number);
        if(written < 0 || (size_t)written >= sizeof(command) || !arp_send(host, command)) {
            arp_error(state, host, "Network selection failed");
        } else {
            state->phase = ArpPhaseSelectWait;
            state->stop_required = true;
        }
    }
}

static const C5ModuleV3 c5_arp_module = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = arp_enter,
    .leave = arp_leave,
    .on_bytes = arp_on_bytes,
    .on_input = arp_on_input,
    .on_text_input = arp_on_text_input,
    .draw = arp_draw,
    .tick = arp_tick,
};

static const FlipperAppPluginDescriptor c5_arp_descriptor = {
    .appid = C5_MODULE_APP_ID,
    .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_arp_module,
};

const FlipperAppPluginDescriptor* lab_c5_arp_plugin_ep(void) {
    return &c5_arp_descriptor;
}
