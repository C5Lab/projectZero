#include "nmap_module.h"
#include "../../module_api.h"

#include <flipper_application/flipper_application.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NMAP_HOST_CAP 32u
#define NMAP_HISTORY_CAP 48u
#define NMAP_LINE_CAP 192u

typedef enum {
    NmapListing,
    NmapNoWifi,
    NmapListError,
    NmapHosts,
    NmapLevels,
    NmapScanning,
    NmapResults,
    NmapIncomplete,
} NmapPhase;

typedef struct {
    char ip[16];
} NmapHost;

typedef struct {
    char text[40];
} NmapHistoryLine;

typedef struct {
    NmapPhase phase;
    NmapHost* hosts;
    NmapHistoryLine* history;
    size_t host_count;
    size_t host_seen;
    size_t host_total;
    size_t host_cursor; /* Zero means all hosts; 1..host_count means one IP. */
    size_t history_start;
    size_t history_count;
    size_t history_scroll;
    uint32_t ticks_per_second;
    uint32_t last_tick;
    uint32_t phase_tick;
    bool has_tick;
    bool phase_tick_set;
    bool list_section;
    bool list_marker;
    bool list_invalid;
    bool list_overdue;
    bool scan_overdue;
    bool scan_marker;
    bool output_bad;
    bool scan_interrupted;
    bool discard_line;
    uint8_t level;
    unsigned scanned_hosts;
    unsigned open_ports;
    unsigned result_hosts_seen;
    unsigned result_ports_seen;
    char target_ip[16];
    char progress_ip[16];
    char error[48];
    char line[NMAP_LINE_CAP];
    size_t line_length;
} NmapState;

static void nmap_redraw(const C5HostApiV3* host) {
    if(host && host->request_redraw) host->request_redraw(host->ctx);
}

static void nmap_phase(NmapState* state, NmapPhase phase) {
    state->phase = phase;
    state->phase_tick = state->last_tick;
    state->phase_tick_set = state->has_tick;
}

static void nmap_error(NmapState* state, NmapPhase phase, const char* error) {
    snprintf(state->error, sizeof(state->error), "%s", error);
    nmap_phase(state, phase);
}

static bool nmap_send(const C5HostApiV3* host, const char* command) {
    if(!host || !host->send_raw_lines || !command) return false;
    size_t length = strlen(command);
    if(!length || length + 1 > C5_MODULE_RAW_TX_MAX || length + 1 > 80) return false;
    char line[80];
    memcpy(line, command, length);
    line[length++] = '\n';
    return host->send_raw_lines(host->ctx, line, length);
}

static bool nmap_ipv4(const char* text) {
    if(!text || !*text) return false;
    const char* at = text;
    for(unsigned octet = 0; octet < 4; octet++) {
        if(!isdigit((unsigned char)*at)) return false;
        const char* start = at;
        unsigned number = 0;
        unsigned digits = 0;
        do {
            if(++digits > 3) return false;
            number = number * 10u + (unsigned)(*at++ - '0');
        } while(isdigit((unsigned char)*at));
        if(number > 255 || (digits > 1 && start[0] == '0')) return false;
        if(octet < 3) {
            if(*at++ != '.') return false;
        } else if(*at != '\0') {
            return false;
        }
    }
    return true;
}

static bool nmap_mac(const char* text) {
    if(!text || strlen(text) != 17) return false;
    for(size_t i = 0; i < 17; i++) {
        if(i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
            if(text[i] != ':') return false;
        } else if(!isxdigit((unsigned char)text[i])) {
            return false;
        }
    }
    return true;
}

static bool nmap_host_row(const char* line, char ip[16]) {
    while(*line == ' ') line++;
    size_t used = 0;
    while(line[used] && line[used] != ' ') {
        if(used + 1 >= 16) return false;
        ip[used] = line[used];
        used++;
    }
    ip[used] = '\0';
    if(!nmap_ipv4(ip)) return false;
    line += used;
    while(*line == ' ') line++;
    if(line[0] != '-' || line[1] != '>') return false;
    line += 2;
    while(*line == ' ') line++;
    if(strncmp(line, "(MAC unknown)", 13) == 0) {
        line += 13;
        while(*line == ' ') line++;
        return strcmp(line, "[ICMP]") == 0;
    }
    char mac[18];
    used = 0;
    while(line[used] && line[used] != ' ') {
        if(used + 1 >= sizeof(mac)) return false;
        mac[used] = line[used];
        used++;
    }
    mac[used] = '\0';
    if(!nmap_mac(mac)) return false;
    line += used;
    while(*line == ' ') line++;
    return strcmp(line, "[ARP]") == 0;
}

static bool nmap_host_summary(const char* line, unsigned* total) {
    unsigned arp = 0, icmp = 0, found = 0;
    int consumed = 0;
    if(sscanf(line, "Found %u hosts (%u via ARP, %u via ICMP)%n",
              &found, &arp, &icmp, &consumed) != 3 || line[consumed] != '\0' ||
       found > 254u || arp > found || icmp > found || arp + icmp != found)
        return false;
    *total = found;
    return true;
}

static void nmap_history_add(NmapState* state, const char* text) {
    if(!state->history) return;
    size_t index = (state->history_start + state->history_count) % NMAP_HISTORY_CAP;
    if(state->history_count == NMAP_HISTORY_CAP) {
        index = state->history_start;
        state->history_start = (state->history_start + 1) % NMAP_HISTORY_CAP;
    } else {
        state->history_count++;
    }
    snprintf(state->history[index].text, sizeof(state->history[index].text), "%s", text);
}

static bool nmap_wifi_error(const char* line) {
    return strstr(line, "Not connected to any AP") ||
           strstr(line, "STA interface not found") ||
           strstr(line, "No IP address assigned yet") ||
           strstr(line, "Failed to get IP info") ||
           strstr(line, "Failed to get LwIP netif");
}

static void nmap_list_line(NmapState* state, const char* line) {
    if(nmap_wifi_error(line)) {
        nmap_error(state, NmapNoWifi, "Connect JanOS Wi-Fi first");
        return;
    }
    if(strstr(line, "Out of memory for host list")) {
        nmap_error(state, NmapListError, "JanOS host list OOM");
        return;
    }
    if(strcmp(line, "=== Discovered Hosts ===") == 0) {
        if(state->list_marker) state->list_invalid = true;
        state->list_marker = true;
        state->list_section = true;
        return;
    }
    if(state->list_section && strcmp(line, "========================") == 0) {
        state->list_section = false;
        return;
    }
    if(strncmp(line, "Found ", 6) == 0) {
        unsigned found = 0;
        if(!nmap_host_summary(line, &found) || !state->list_marker ||
           state->list_invalid || state->host_seen != found) {
            nmap_error(state, NmapListError, "Host list incomplete");
            return;
        }
        state->host_total = found;
        state->host_cursor = 0;
        nmap_phase(state, NmapHosts);
        return;
    }
    if(!state->list_section) return;
    char ip[16];
    if(!nmap_host_row(line, ip) || state->host_seen >= 254u) {
        state->list_invalid = true;
        return;
    }
    for(size_t i = 0; i < state->host_count; i++)
        if(strcmp(state->hosts[i].ip, ip) == 0) {
            state->list_invalid = true;
            return;
        }
    state->host_seen++;
    if(state->host_count < NMAP_HOST_CAP) {
        memcpy(state->hosts[state->host_count].ip, ip, sizeof(ip));
        state->host_count++;
    }
}

static bool nmap_scan_summary(const char* line, unsigned* hosts, unsigned* ports) {
    int consumed = 0;
    if(sscanf(line, "Scanned %u hosts, found %u open ports%n", hosts, ports, &consumed) != 2 ||
       line[consumed] != '\0' || *hosts > 254u || *ports > 25400u)
        return false;
    return true;
}

static bool nmap_port_row(const char* line, unsigned* port, char service[16]) {
    while(*line == ' ') line++;
    if(!isdigit((unsigned char)*line)) return false;
    unsigned value = 0;
    do {
        value = value * 10u + (unsigned)(*line++ - '0');
        if(value > 65535u) return false;
    } while(isdigit((unsigned char)*line));
    if(value == 0 || strncmp(line, "/tcp", 4) != 0) return false;
    line += 4;
    if(*line++ != ' ') return false;
    while(*line == ' ') line++;
    if(strncmp(line, "open", 4) != 0 || line[4] != ' ') return false;
    line += 5;
    while(*line == ' ') line++;
    size_t used = 0;
    while(line[used] && line[used] != ' ') {
        char ch = line[used];
        if(!isalnum((unsigned char)ch) && ch != '-' && ch != '_') return false;
        if(used + 1 >= 16) return false;
        service[used] = ch;
        used++;
    }
    service[used] = '\0';
    if(!used) return false;
    line += used;
    while(*line == ' ') line++;
    if(*line) return false;
    *port = value;
    return true;
}

static bool nmap_scan_host_row(const char* line, char ip[16]) {
    const char* at = line + 6; /* Caller checked "Host: ". */
    size_t used = 0;
    while(at[used] && at[used] != ' ') {
        if(used + 1 >= 16) return false;
        ip[used] = at[used];
        used++;
    }
    ip[used] = '\0';
    if(!nmap_ipv4(ip)) return false;
    at += used;
    while(*at == ' ') at++;
    if(*at++ != '(') return false;
    if(strncmp(at, "MAC unknown)", 12) == 0) {
        at += 12;
    } else {
        char mac[18];
        if(strlen(at) < 18) return false;
        memcpy(mac, at, 17);
        mac[17] = '\0';
        if(!nmap_mac(mac) || at[17] != ')') return false;
        at += 18;
    }
    while(*at == ' ') at++;
    return *at == '\0';
}

static void nmap_scan_line(NmapState* state, const char* line) {
    if(nmap_wifi_error(line)) {
        nmap_error(state, NmapNoWifi, "Connect JanOS Wi-Fi first");
        return;
    }
    if(strstr(line, "Out of memory for host list") ||
       strncmp(line, "Usage: start_nmap", 17) == 0) {
        nmap_error(state, NmapListError, "JanOS scan failed");
        return;
    }
    if(strcmp(line, "=== NMAP Scan Results ===") == 0) {
        if(state->scan_marker) state->output_bad = true;
        state->scan_marker = true;
        return;
    }
    if(strstr(line, "(scan stopped by user)")) {
        state->scan_interrupted = true;
        return;
    }
    unsigned hosts = 0, ports = 0;
    if(strncmp(line, "Scanned ", 8) == 0) {
        if(!nmap_scan_summary(line, &hosts, &ports)) {
            state->output_bad = true;
            return;
        }
        state->scanned_hosts = hosts;
        state->open_ports = ports;
        if(!state->scan_marker || state->result_hosts_seen != hosts ||
           state->result_ports_seen != ports)
            state->output_bad = true;
        nmap_phase(state, state->output_bad || state->scan_interrupted ?
                              NmapIncomplete : NmapResults);
        return;
    }
    if(strncmp(line, "Host: ", 6) == 0) {
        if(!state->scan_marker) state->output_bad = true;
        char ip[16];
        if(!nmap_scan_host_row(line, ip)) {
            state->output_bad = true;
            return;
        }
        snprintf(state->progress_ip, sizeof(state->progress_ip), "%s", ip);
        char history[40];
        snprintf(history, sizeof(history), "Host %s", ip);
        nmap_history_add(state, history);
        state->result_hosts_seen++;
        return;
    }
    const char* at = line;
    while(*at == ' ') at++;
    if(isdigit((unsigned char)*at) && strstr(at, "/tcp")) {
        unsigned port = 0;
        char service[16];
        if(!state->progress_ip[0] || !nmap_port_row(at, &port, service)) {
            state->output_bad = true;
            return;
        }
        char history[40];
        snprintf(history, sizeof(history), "%u/tcp open %s", port, service);
        nmap_history_add(state, history);
        state->result_ports_seen++;
        return;
    }
    if(strcmp(at, "(no open ports)") == 0) {
        if(!state->progress_ip[0]) state->output_bad = true;
        else nmap_history_add(state, "(no open ports)");
    }
}

static void nmap_reply_prompt(NmapState* state) {
    if(state->phase == NmapListing) {
        nmap_error(state, NmapListError, "Host list incomplete");
    } else if(state->phase == NmapScanning) {
        state->scanned_hosts = state->result_hosts_seen;
        state->open_ports = state->result_ports_seen;
        nmap_phase(state, NmapIncomplete);
    }
    state->line_length = 0;
}

static void nmap_process_line(NmapState* state) {
    state->line[state->line_length] = '\0';
    const char* line = state->line;
    if(strcmp(line, ">") == 0) {
        nmap_reply_prompt(state);
        return;
    }
    /* Accept both JanOS's bare MY_LOG_INFO printf and ESP-IDF log-prefixed
     * transcripts without searching arbitrary text for protocol markers. */
    if(strncmp(line, "I (", 3) == 0) {
        const char* at = line + 3;
        while(isdigit((unsigned char)*at)) at++;
        static const char prefix_tail[] = ") projectZero: ";
        if(at > line + 3 && strncmp(at, prefix_tail, sizeof(prefix_tail) - 1) == 0)
            line = at + sizeof(prefix_tail) - 1;
    }
    if(state->phase == NmapListing) nmap_list_line(state, line);
    else if(state->phase == NmapScanning) nmap_scan_line(state, line);
    state->line_length = 0;
}

static void nmap_on_bytes(
    void* opaque, const C5HostApiV3* host, const uint8_t* bytes, size_t length) {
    NmapState* state = opaque;
    if(!state || !bytes) return;
    for(size_t i = 0; i < length; i++) {
        uint8_t byte = bytes[i];
        if(byte == '\r') continue;
        if(byte == '\n') {
            if(!state->discard_line && state->line_length) nmap_process_line(state);
            state->line_length = 0;
            state->discard_line = false;
            continue;
        }
        if(state->phase != NmapListing && state->phase != NmapScanning) continue;
        if(state->discard_line) continue;
        if(byte == 0 || state->line_length + 1 >= sizeof(state->line)) {
            state->line_length = 0;
            state->discard_line = true;
            if(state->phase == NmapListing) state->list_invalid = true;
            else state->output_bad = true;
            continue;
        }
        state->line[state->line_length++] = (char)byte;
        if(state->line_length == 2 && state->line[0] == '>' && state->line[1] == ' ')
            nmap_reply_prompt(state);
    }
    nmap_redraw(host);
}

static void nmap_begin_listing(NmapState* state, const C5HostApiV3* host) {
    free(state->history);
    state->history = NULL;
    free(state->hosts);
    state->hosts = calloc(NMAP_HOST_CAP, sizeof(*state->hosts));
    state->host_count = state->host_seen = state->host_total = 0;
    state->host_cursor = 0;
    state->history_start = state->history_count = state->history_scroll = 0;
    state->list_section = state->list_marker = state->list_invalid = false;
    state->list_overdue = state->scan_overdue = state->output_bad = false;
    state->discard_line = false;
    state->line_length = 0;
    state->error[0] = '\0';
    if(!state->hosts) {
        nmap_error(state, NmapListError, "Flipper out of memory");
    } else if(!nmap_send(host, "list_hosts")) {
        nmap_error(state, NmapListError, "List TX failed");
    } else {
        nmap_phase(state, NmapListing);
    }
    nmap_redraw(host);
}

static void* nmap_enter(const C5HostApiV3* host, const void* params, size_t params_size) {
    if(!host || host->version != C5_MODULE_API_VERSION ||
       host->size < sizeof(C5HostApiV3) || !host->send_raw_lines ||
       !params || params_size != sizeof(C5NmapLaunchContext)) return NULL;
    const C5NmapLaunchContext* context = params;
    if(context->version != C5_NMAP_LAUNCH_VERSION ||
       context->size != sizeof(C5NmapLaunchContext) ||
       context->ticks_per_second == 0 || context->ticks_per_second > 1000000u) return NULL;
    NmapState* state = calloc(1, sizeof(*state));
    if(!state) return NULL;
    state->ticks_per_second = context->ticks_per_second;
    nmap_begin_listing(state, host);
    return state;
}

static void nmap_leave(void* opaque, const C5HostApiV3* host) {
    (void)host;
    NmapState* state = opaque;
    if(!state) return;
    /* start_nmap is synchronous in JanOS's REPL. Sending stop here could
     * queue it after the scan and would not prove cancellation. */
    free(state->hosts);
    free(state->history);
    free(state);
}

static void nmap_start_scan(NmapState* state, const C5HostApiV3* host) {
    static const char* const levels[] = {"quick", "medium", "heavy"};
    char command[64];
    if(state->host_cursor && state->host_cursor <= state->host_count)
        snprintf(state->target_ip, sizeof(state->target_ip), "%s",
                 state->hosts[state->host_cursor - 1].ip);
    else state->target_ip[0] = '\0';
    int written = snprintf(command, sizeof(command), "start_nmap %s%s%s",
                           levels[state->level], state->target_ip[0] ? " " : "",
                           state->target_ip);
    if(written <= 0 || (size_t)written >= sizeof(command)) {
        nmap_error(state, NmapListError, "Invalid scan command");
        return;
    }
    free(state->hosts);
    state->hosts = NULL;
    state->history = calloc(NMAP_HISTORY_CAP, sizeof(*state->history));
    if(!state->history) {
        nmap_error(state, NmapListError, "Flipper out of memory");
        return;
    }
    state->history_start = state->history_count = state->history_scroll = 0;
    state->scanned_hosts = state->open_ports = 0;
    state->result_hosts_seen = state->result_ports_seen = 0;
    state->progress_ip[0] = '\0';
    state->output_bad = state->scan_interrupted = state->scan_overdue = false;
    state->scan_marker = false;
    state->line_length = 0;
    state->discard_line = false;
    if(!nmap_send(host, command)) {
        nmap_error(state, NmapListError, "Scan TX failed");
        return;
    }
    nmap_phase(state, NmapScanning);
}

static C5InputResult nmap_on_input(
    void* opaque, const C5HostApiV3* host, const InputEvent* event) {
    NmapState* state = opaque;
    if(!state || !event) return C5InputIgnored;
    if(event->type != InputTypeShort &&
       !(event->type == InputTypeRepeat &&
         (event->key == InputKeyUp || event->key == InputKeyDown))) return C5InputConsumed;
    if(event->key == InputKeyBack) {
        if(state->phase == NmapLevels) nmap_phase(state, NmapHosts);
        else if(state->phase == NmapListing || state->phase == NmapScanning)
            return C5InputConsumed;
        else return C5InputSwitchModule;
    } else if(state->phase == NmapNoWifi || state->phase == NmapListError) {
        if(event->key == InputKeyOk) nmap_begin_listing(state, host);
    } else if(state->phase == NmapHosts) {
        if(event->key == InputKeyUp && state->host_cursor) state->host_cursor--;
        else if(event->key == InputKeyDown && state->host_cursor < state->host_count)
            state->host_cursor++;
        else if(event->key == InputKeyOk) {
            state->level = 0;
            nmap_phase(state, NmapLevels);
        }
    } else if(state->phase == NmapLevels) {
        if(event->key == InputKeyUp && state->level) state->level--;
        else if(event->key == InputKeyDown && state->level < 2) state->level++;
        else if(event->key == InputKeyOk) nmap_start_scan(state, host);
    } else if(state->phase == NmapResults || state->phase == NmapIncomplete) {
        size_t visible = state->history_count < 2 ? state->history_count : 2;
        size_t max_scroll = state->history_count - visible;
        if(event->key == InputKeyUp && state->history_scroll < max_scroll)
            state->history_scroll++;
        else if(event->key == InputKeyDown && state->history_scroll)
            state->history_scroll--;
    }
    nmap_redraw(host);
    return C5InputConsumed;
}

static void nmap_draw(void* opaque, const C5HostApiV3* host, Canvas* canvas) {
    (void)host;
    const NmapState* state = opaque;
    if(!state || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "Nmap");
    char line[48];
    if(state->phase == NmapListing) {
        canvas_draw_str(canvas, 2, 30, "Discovering hosts...");
        canvas_draw_str(canvas, 2, 44, state->list_overdue ?
                        "JanOS may still list" : "Waiting for JanOS");
        canvas_draw_str(canvas, 2, 62, "Back waits for result");
    } else if(state->phase == NmapNoWifi) {
        canvas_draw_str(canvas, 2, 30, "JanOS Wi-Fi not ready");
        canvas_draw_str(canvas, 2, 42, "Use wifi_connect");
        canvas_draw_str(canvas, 2, 52, "via JanOS CLI");
        canvas_draw_str(canvas, 2, 62, "OK: retry Back: exit");
    } else if(state->phase == NmapListError) {
        canvas_draw_str(canvas, 2, 30, state->error);
        canvas_draw_str(canvas, 2, 62, "OK: retry Back: exit");
    } else if(state->phase == NmapHosts) {
        snprintf(line, sizeof(line), "All hosts (%u)", (unsigned)state->host_total);
        canvas_draw_str(canvas, 2, 26, line);
        if(state->host_cursor) {
            canvas_draw_str(canvas, 2, 40, state->hosts[state->host_cursor - 1].ip);
            snprintf(line, sizeof(line), "Host %u/%u", (unsigned)state->host_cursor,
                     (unsigned)state->host_count);
            canvas_draw_str(canvas, 2, 51, line);
        } else {
            canvas_draw_str(canvas, 2, 40, "Select all at scan time");
            if(state->host_total > state->host_count) {
                snprintf(line, sizeof(line), "First %u shown", (unsigned)state->host_count);
                canvas_draw_str(canvas, 2, 51, line);
            }
        }
        canvas_draw_str(canvas, 2, 62, "Up/Down  OK: level");
    } else if(state->phase == NmapLevels) {
        static const char* const names[] = {
            "Quick (20 ports)", "Medium (50 ports)", "Heavy (100 ports)"};
        canvas_draw_str(canvas, 2, 27, state->host_cursor ?
                        state->hosts[state->host_cursor - 1].ip : "All discovered hosts");
        canvas_draw_str(canvas, 2, 41, names[state->level]);
        canvas_draw_str(canvas, 2, 62, "Up/Down  OK: scan");
    } else if(state->phase == NmapScanning) {
        canvas_draw_str(canvas, 2, 27, "Scan in progress");
        if(state->progress_ip[0]) canvas_draw_str(canvas, 2, 40, state->progress_ip);
        else canvas_draw_str(canvas, 2, 40, "Waiting for JanOS");
        canvas_draw_str(canvas, 2, 51, state->scan_overdue ?
                        "JanOS may still scan" : "Cannot cancel via UART");
        canvas_draw_str(canvas, 2, 62, "Back waits for summary");
    } else {
        canvas_draw_str(canvas, 2, 24, state->phase == NmapIncomplete ?
                        "Result incomplete" : "Nmap results");
        snprintf(line, sizeof(line), "%u hosts, %u open ports",
                 state->scanned_hosts, state->open_ports);
        canvas_draw_str(canvas, 2, 34, line);
        size_t visible = state->history_count < 2 ? state->history_count : 2;
        size_t first = state->history_count - visible - state->history_scroll;
        for(size_t i = 0; i < visible; i++) {
            size_t at = (state->history_start + first + i) % NMAP_HISTORY_CAP;
            canvas_draw_str(canvas, 2, 45 + (int)i * 10, state->history[at].text);
        }
        if(!visible) canvas_draw_str(canvas, 2, 48, "No open ports shown");
        canvas_draw_str(canvas, 2, 63, state->history_count == NMAP_HISTORY_CAP ?
                        "Last 48 lines Up/Down" : "Recent lines Up/Down");
    }
}

static void nmap_tick(void* opaque, const C5HostApiV3* host, uint32_t now_ticks) {
    NmapState* state = opaque;
    if(!state) return;
    state->last_tick = now_ticks;
    state->has_tick = true;
    if(!state->phase_tick_set) {
        state->phase_tick = now_ticks;
        state->phase_tick_set = true;
        return;
    }
    if(state->phase == NmapListing && !state->list_overdue &&
       (uint32_t)(now_ticks - state->phase_tick) >= state->ticks_per_second * 30u) {
        state->list_overdue = true;
        nmap_redraw(host);
    }
    if(state->phase == NmapScanning && !state->scan_overdue &&
       (uint32_t)(now_ticks - state->phase_tick) >= state->ticks_per_second * 300u) {
        state->scan_overdue = true;
        nmap_redraw(host);
    }
}

static const C5ModuleV3 c5_nmap_module = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = nmap_enter,
    .leave = nmap_leave,
    .on_bytes = nmap_on_bytes,
    .on_input = nmap_on_input,
    .draw = nmap_draw,
    .tick = nmap_tick,
};

static const FlipperAppPluginDescriptor c5_nmap_descriptor = {
    .appid = C5_MODULE_APP_ID,
    .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_nmap_module,
};

const FlipperAppPluginDescriptor* lab_c5_nmap_plugin_ep(void) {
    return &c5_nmap_descriptor;
}
