#include "wpasec_module.h"
#include "../../module_api.h"
#include <flipper_application/flipper_application.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WP_LINE_CAPACITY 256u
#define WP_KEY_TIMEOUT_SECONDS 5u
#define WP_UPLOAD_SILENCE_SECONDS 120u

typedef enum {
    WpPending, WpReadingKey, WpKeyMissing, WpKeyUnknown, WpTlsBlocked,
    WpConfirmScope, WpUploading, WpResultUnconfirmed, WpTxError, WpDone,
    WpNoWifi, WpNoFiles, WpSdError, WpDirectoryError,
} WpStage;

typedef struct {
    uint32_t ticks_per_second;
    uint32_t last_tick;
    uint32_t stage_tick;
    uint32_t activity_tick;
    WpStage stage;
    bool tls_verified;
    bool prompt_space;
    bool discard_line;
    bool total_seen;
    bool upload_prompt_seen;
    uint32_t total;
    uint32_t processed;
    uint32_t uploaded;
    uint32_t duplicate;
    uint32_t failed;
    char line[WP_LINE_CAPACITY];
    size_t line_length;
} WpState;

static void wp_scrub(void* pointer, size_t length) {
    volatile unsigned char* bytes = pointer;
    while(length--) *bytes++ = 0;
}

static void wp_redraw(const C5HostApiV3* host) {
    if(host && host->request_redraw) host->request_redraw(host->ctx);
}

static void wp_stage(WpState* state, WpStage stage) {
    state->stage = stage;
    state->stage_tick = state->last_tick;
}

static bool wp_send(const C5HostApiV3* host, const char* command) {
    if(!host || !host->send_raw_lines || !command) return false;
    size_t length = strlen(command);
    if(length == 0 || length + 1 > C5_MODULE_RAW_TX_MAX) return false;
    char batch[32];
    if(length + 1 > sizeof(batch)) return false;
    memcpy(batch, command, length);
    batch[length++] = '\n';
    bool sent = host->send_raw_lines(host->ctx, batch, length);
    wp_scrub(batch, sizeof(batch));
    return sent;
}

static const char* wp_log_message(const char* line) {
    if((line[0] != 'I' && line[0] != 'W' && line[0] != 'E') ||
       line[1] != ' ' || line[2] != '(') return line;
    const char* cursor = line + 3;
    if(!isdigit((unsigned char)*cursor)) return line;
    while(isdigit((unsigned char)*cursor)) cursor++;
    const char prefix[] = ") projectZero: ";
    return strncmp(cursor, prefix, sizeof(prefix) - 1) == 0 ?
               cursor + sizeof(prefix) - 1 : line;
}

static bool wp_key_masked(const char* message) {
    const char prefix[] = "WPA-SEC key: ";
    if(strncmp(message, prefix, sizeof(prefix) - 1) != 0) return false;
    const char* mask = message + sizeof(prefix) - 1;
    size_t length = strlen(mask);
    if(length < 5 || length > 8 || strcmp(mask + length - 4, "****") != 0) return false;
    for(size_t i = 0; i + 4 < length; i++) {
        if(!isgraph((unsigned char)mask[i])) return false;
    }
    return true;
}

static bool wp_number(const char** cursor, const char* prefix, uint32_t* value) {
    const char* p = *cursor;
    size_t length = strlen(prefix);
    if(strncmp(p, prefix, length) != 0) return false;
    p += length;
    if(!isdigit((unsigned char)*p)) return false;
    char* end = NULL;
    unsigned long parsed = strtoul(p, &end, 10);
    if(end == p || parsed > UINT32_MAX) return false;
    *value = (uint32_t)parsed;
    *cursor = end;
    return true;
}

static bool wp_done(const char* message, uint32_t* uploaded,
                    uint32_t* duplicate, uint32_t* failed) {
    const char* cursor = message;
    uint32_t up, dup, fail;
    if(!wp_number(&cursor, "Done: ", &up) ||
       !wp_number(&cursor, " uploaded, ", &dup) ||
       !wp_number(&cursor, " duplicate, ", &fail) ||
       strcmp(cursor, " failed") != 0) return false;
    *uploaded = up;
    *duplicate = dup;
    *failed = fail;
    return true;
}

static bool wp_total(const char* message, uint32_t* total) {
    const char* cursor = message;
    return wp_number(&cursor, "Uploading ", total) &&
           strcmp(cursor, " handshake(s) to wpa-sec.stanev.org...") == 0;
}

static bool wp_progress(const char* message, uint32_t* processed, uint32_t* total) {
    const char* cursor = message;
    uint32_t done, count;
    if(!wp_number(&cursor, "[", &done) ||
       !wp_number(&cursor, "/", &count) ||
       strncmp(cursor, "] ", 2) != 0 || !strstr(cursor + 2, " -> ") ||
       done == 0 || count == 0 || done > count) return false;
    *processed = done;
    *total = count;
    return true;
}

static void wp_on_line(WpState* state, const C5HostApiV3* host, const char* line) {
    const char* message = wp_log_message(line);
    if(state->stage == WpReadingKey) {
        if(strcmp(message, "WPA-SEC key: not set") == 0) {
            wp_stage(state, WpKeyMissing);
        } else if(wp_key_masked(message)) {
            wp_stage(state, state->tls_verified ? WpConfirmScope : WpTlsBlocked);
        }
    } else if(state->stage == WpUploading || state->stage == WpResultUnconfirmed) {
        uint32_t up, dup, fail;
        if(wp_done(message, &up, &dup, &fail)) {
            state->uploaded = up;
            state->duplicate = dup;
            state->failed = fail;
            wp_stage(state, WpDone);
        } else if(strcmp(message, "Not connected to any AP. Use 'wifi_connect' first.") == 0) {
            wp_stage(state, WpNoWifi);
        } else if(strcmp(message,
                         "No WPA-SEC API key set. Use 'wpasec_key set <key>' first.") == 0) {
            wp_stage(state, WpKeyMissing);
        } else if(strncmp(message, "Failed to initialize SD card:", 29) == 0) {
            wp_stage(state, WpSdError);
        } else if(strcmp(message, "Failed to open /sdcard/lab/handshakes directory") == 0) {
            wp_stage(state, WpDirectoryError);
        } else if(strcmp(message, "No .pcap files found in /sdcard/lab/handshakes/") == 0) {
            wp_stage(state, WpNoFiles);
        } else {
            uint32_t total, progress;
            if(wp_total(message, &total)) {
                state->total = total;
                state->total_seen = true;
                state->activity_tick = state->last_tick;
                wp_stage(state, WpUploading);
            } else if(wp_progress(message, &progress, &total)) {
                if(!state->total_seen || total == state->total) {
                    state->total = total;
                    state->total_seen = true;
                    if(progress > state->processed) state->processed = progress;
                    state->activity_tick = state->last_tick;
                    wp_stage(state, WpUploading);
                }
            }
        }
    }
    wp_redraw(host);
}

static void wp_on_prompt(WpState* state, const C5HostApiV3* host) {
    if(state->stage == WpReadingKey) wp_stage(state, WpKeyUnknown);
    else if(state->stage == WpUploading || state->stage == WpResultUnconfirmed) {
        state->upload_prompt_seen = true;
        wp_stage(state, WpResultUnconfirmed);
    }
    wp_redraw(host);
}

static void* wp_enter(const C5HostApiV3* h, const void* p, size_t n) {
    if(!h || h->version != C5_MODULE_API_VERSION || h->size < sizeof(C5HostApiV3) ||
       !h->send_raw_lines || !h->request_redraw ||
       !p || n != sizeof(C5WpasecLaunchContext)) return NULL;
    const C5WpasecLaunchContext* launch = p;
    if(launch->version != C5_WPASEC_LAUNCH_VERSION || launch->size != sizeof(*launch) ||
       !launch->ticks_per_second || launch->ticks_per_second > 1000000u) return NULL;
    WpState* state = calloc(1, sizeof(*state));
    if(!state) return NULL;
    state->ticks_per_second = launch->ticks_per_second;
    state->tls_verified = launch->tls_verified;
    state->stage = WpPending;
    return state;
}
static void wp_leave(void* s, const C5HostApiV3* h) {
    (void)h;
    if(!s) return;
    wp_scrub(s, sizeof(WpState));
    free(s);
}
static void wp_bytes(void* s, const C5HostApiV3* h, const uint8_t* b, size_t n) {
    WpState* state = s;
    if(!state || !h || !b) return;
    for(size_t i = 0; i < n; i++) {
        char ch = (char)b[i];
        if(ch == '\r') continue;
        if(state->prompt_space) {
            state->prompt_space = false;
            if(ch == ' ') continue;
        }
        if(ch == '\0') {
            wp_scrub(state->line, sizeof(state->line));
            state->line_length = 0;
            state->discard_line = true;
        } else if(ch == '>' && state->line_length == 0 && !state->discard_line) {
            wp_on_prompt(state, h);
            state->prompt_space = true;
        } else if(ch == '\n') {
            if(!state->discard_line && state->line_length) {
                state->line[state->line_length] = '\0';
                wp_on_line(state, h, state->line);
            }
            wp_scrub(state->line, sizeof(state->line));
            state->line_length = 0;
            state->discard_line = false;
        } else if(!state->discard_line) {
            if(state->line_length + 1 < sizeof(state->line))
                state->line[state->line_length++] = ch;
            else {
                wp_scrub(state->line, sizeof(state->line));
                state->line_length = 0;
                state->discard_line = true;
            }
        }
    }
}
static C5InputResult wp_input(void* s, const C5HostApiV3* h, const InputEvent* e) {
    WpState* state = s;
    if(!state || !h || !e || e->type != InputTypeShort) return C5InputIgnored;
    if(e->key == InputKeyBack) {
        if(state->stage == WpUploading ||
           (state->stage == WpResultUnconfirmed && !state->upload_prompt_seen))
            return C5InputConsumed;
        return C5InputSwitchModule;
    }
    if(e->key == InputKeyOk) {
        if(state->stage == WpConfirmScope) {
            if(!state->tls_verified) {
                wp_stage(state, WpTlsBlocked);
            } else if(wp_send(h, "wpasec_upload")) {
                state->upload_prompt_seen = false;
                state->activity_tick = state->last_tick;
                wp_stage(state, WpUploading);
            } else {
                wp_stage(state, WpTxError);
            }
            wp_redraw(h);
        }
        return C5InputConsumed;
    }
    return C5InputIgnored;
}
static void wp_draw(void* s, const C5HostApiV3* h, Canvas* c) {
    (void)h;
    WpState* state = s;
    if(!state || !c) return;
    canvas_set_color(c, ColorBlack);
    canvas_set_font(c, FontPrimary);
    canvas_draw_str(c, 2, 11, "WPA-sec");
    canvas_set_font(c, FontSecondary);
    switch(state->stage) {
    case WpPending:
    case WpReadingKey:
        canvas_draw_str(c, 2, 27, "Checking JanOS key...");
        break;
    case WpKeyMissing:
        canvas_draw_str(c, 2, 21, "Key not set");
        canvas_draw_str(c, 2, 34, "In JanOS console:");
        canvas_draw_str(c, 2, 47, "wpasec_key set <key>");
        canvas_draw_str(c, 2, 61, "Back: exit");
        break;
    case WpKeyUnknown:
        canvas_draw_str(c, 2, 25, "Key status unknown");
        canvas_draw_str(c, 2, 43, "Retry from menu");
        canvas_draw_str(c, 2, 61, "Back: exit");
        break;
    case WpTlsBlocked:
        canvas_draw_str(c, 2, 24, "TLS not verified");
        canvas_draw_str(c, 2, 38, "Upload blocked");
        canvas_draw_str(c, 2, 52, "Firmware gate required");
        canvas_draw_str(c, 2, 62, "Back: exit");
        break;
    case WpConfirmScope:
        canvas_draw_str(c, 2, 21, "ALL handshake .pcap");
        canvas_draw_str(c, 2, 31, "/sdcard/lab/handshakes");
        canvas_draw_str(c, 2, 41, "WiFi via JanOS console");
        canvas_draw_str(c, 2, 51, "Upload to wpa-sec");
        canvas_draw_str(c, 2, 61, "OK: send Back: cancel");
        break;
    case WpUploading: {
        char line[48];
        if(state->total_seen)
            snprintf(line, sizeof(line), "Uploading %lu/%lu",
                     (unsigned long)state->processed, (unsigned long)state->total);
        else snprintf(line, sizeof(line), "Waiting for JanOS");
        canvas_draw_str(c, 2, 25, line);
        canvas_draw_str(c, 2, 42, "Back cannot cancel");
        canvas_draw_str(c, 2, 57, "Monster may be busy");
        break;
    }
    case WpResultUnconfirmed:
        canvas_draw_str(c, 2, 23, "Result unconfirmed");
        canvas_draw_str(c, 2, 38, state->upload_prompt_seen ?
                        "JanOS returned to CLI" : "Monster may continue");
        canvas_draw_str(c, 2, 53, state->upload_prompt_seen ?
                        "Back: exit" : "Back cannot cancel");
        break;
    case WpTxError:
        canvas_draw_str(c, 2, 27, "Upload TX failed");
        canvas_draw_str(c, 2, 61, "Back: exit");
        break;
    case WpDone: {
        char line[48];
        canvas_draw_str(c, 2, 21, "Upload finished");
        snprintf(line, sizeof(line), "Uploaded: %lu Dup: %lu",
                 (unsigned long)state->uploaded, (unsigned long)state->duplicate);
        canvas_draw_str(c, 2, 34, line);
        snprintf(line, sizeof(line), "Failed: %lu", (unsigned long)state->failed);
        canvas_draw_str(c, 2, 47, line);
        canvas_draw_str(c, 2, 61, "Back: exit");
        break;
    }
    case WpNoWifi:
        canvas_draw_str(c, 2, 25, "Connect WiFi in JanOS");
        canvas_draw_str(c, 2, 41, "Use wifi_connect");
        canvas_draw_str(c, 2, 61, "Back: exit");
        break;
    case WpNoFiles:
        canvas_draw_str(c, 2, 24, "No handshake .pcap");
        canvas_draw_str(c, 2, 39, "/sdcard/lab/handshakes");
        canvas_draw_str(c, 2, 61, "Back: exit");
        break;
    case WpSdError:
        canvas_draw_str(c, 2, 28, "SD unavailable");
        canvas_draw_str(c, 2, 61, "Back: exit");
        break;
    case WpDirectoryError:
        canvas_draw_str(c, 2, 28, "Handshake dir missing");
        canvas_draw_str(c, 2, 61, "Back: exit");
        break;
    }
}
static void wp_tick(void* s, const C5HostApiV3* h, uint32_t t) {
    WpState* state = s;
    if(!state || !h) return;
    state->last_tick = t;
    if(state->stage == WpPending) {
        if(wp_send(h, "wpasec_key read")) wp_stage(state, WpReadingKey);
        else wp_stage(state, WpKeyUnknown);
        wp_redraw(h);
    } else if(state->stage == WpReadingKey &&
              (uint32_t)(t - state->stage_tick) >=
                  state->ticks_per_second * WP_KEY_TIMEOUT_SECONDS) {
        wp_stage(state, WpKeyUnknown);
        wp_redraw(h);
    } else if(state->stage == WpUploading &&
              (uint32_t)(t - state->activity_tick) >=
                  state->ticks_per_second * WP_UPLOAD_SILENCE_SECONDS) {
        wp_stage(state, WpResultUnconfirmed);
        wp_redraw(h);
    }
}
static const C5ModuleV3 c5_wp_module = {
    .version = C5_MODULE_API_VERSION, .size = sizeof(C5ModuleV3),
    .enter = wp_enter, .leave = wp_leave, .on_bytes = wp_bytes,
    .on_input = wp_input, .draw = wp_draw, .tick = wp_tick,
};
static const FlipperAppPluginDescriptor c5_wp_descriptor = {
    .appid = C5_MODULE_APP_ID, .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_wp_module,
};
const FlipperAppPluginDescriptor* lab_c5_wpasec_plugin_ep(void) {
    return &c5_wp_descriptor;
}
