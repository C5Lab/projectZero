#include "wardrive_upload_module.h"
#include "../../module_api.h"

#include <flipper_application/flipper_application.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WU_PAGE_SIZE 12u
#define WU_NAME_CAPACITY 128u
#define WU_LINE_CAPACITY 320u
#define WU_COMMAND_CAPACITY 192u

typedef enum {
    WuListing,
    WuFiles,
    WuKeyCheck,
    WuKeyMissing,
    WuTlsBlocked,
    WuSsidInput,
    WuWifiChoice,
    WuPasswordInput,
    WuConnecting,
    WuConnectUncertain,
    WuWifiError,
    WuConfirm,
    WuUploading,
    WuUploadUncertain,
    WuDone,
    WuError,
} WuPhase;

typedef enum {
    WuFileUnknown,
    WuFileOk,
    WuFileSkipped,
    WuFileFailed,
    WuFileRateLimited,
} WuFileResult;

typedef enum {
    WuKeyUnknown,
    WuKeyPresent,
    WuKeyNvsMissing,
} WuKeyResult;

typedef struct {
    C5WardriveUploadProvider provider;
    WuPhase phase;
    WuFileResult file_result;
    WuKeyResult key_result;
    bool tls_verified;
    bool header_seen;
    bool no_files_seen;
    bool list_invalid;
    bool summary_seen;
    bool wifi_success;
    bool wifi_error;
    bool discard_line;
    bool pending_cr;
    bool prompt_space;
    bool phase_tick_set;
    uint32_t ticks_per_second;
    uint32_t phase_tick;
    uint32_t page_offset;
    uint32_t candidate_count;
    uint32_t omitted_count;
    uint32_t row_count;
    uint32_t list_total;
    uint8_t page_count;
    uint8_t selected;
    unsigned uploaded;
    unsigned skipped;
    unsigned failed;
    unsigned rate_limited;
    char files[WU_PAGE_SIZE][WU_NAME_CAPACITY];
    char chosen[WU_NAME_CAPACITY];
    char ssid[33];
    char line[WU_LINE_CAPACITY];
    size_t line_length;
    char error[48];
} WuState;

static void wu_phase(WuState* state, WuPhase phase) {
    state->phase = phase;
    state->phase_tick_set = false;
}

static void wu_redraw(const C5HostApiV3* host) {
    if(host && host->request_redraw) host->request_redraw(host->ctx);
}

static void wu_status(const C5HostApiV3* host, const char* message) {
    if(host && host->show_status) host->show_status(host->ctx, message, 1600, true);
}

static void wu_scrub(void* data, size_t length) {
    volatile unsigned char* cursor = data;
    while(length--) *cursor++ = 0;
}

static bool wu_send(const C5HostApiV3* host, const char* command, bool secret) {
    if(!host || !host->send_raw_lines || !command) return false;
    size_t length = strlen(command);
    if(!length || length + 1 > WU_COMMAND_CAPACITY || length + 1 > C5_MODULE_RAW_TX_MAX)
        return false;
    char batch[WU_COMMAND_CAPACITY];
    memcpy(batch, command, length);
    batch[length] = '\n';
    bool sent = host->send_raw_lines(host->ctx, batch, length + 1);
    if(secret) wu_scrub(batch, sizeof(batch));
    return sent;
}

static void wu_error(WuState* state, const C5HostApiV3* host, const char* message) {
    snprintf(state->error, sizeof(state->error), "%s", message);
    wu_phase(state, WuError);
    wu_redraw(host);
}

static bool wu_equal_ci(char left, char right) {
    if(left >= 'A' && left <= 'Z') left += 'a' - 'A';
    if(right >= 'A' && right <= 'Z') right += 'a' - 'A';
    return left == right;
}

static bool wu_ends_ci(const char* text, const char* suffix) {
    size_t text_length = strlen(text);
    size_t suffix_length = strlen(suffix);
    if(text_length <= suffix_length) return false;
    for(size_t i = 0; i < suffix_length; i++) {
        if(!wu_equal_ci(text[text_length - suffix_length + i], suffix[i])) return false;
    }
    return true;
}

static bool wu_candidate(C5WardriveUploadProvider provider, const char* name) {
    if(name[0] == '.' || name[0] == '_' ||
       strcmp(name, "upload_state.csv") == 0 || wu_ends_ci(name, ".fixed.log"))
        return false;
    if(wu_ends_ci(name, ".log") || wu_ends_ci(name, ".csv")) return true;
    return provider == C5WardriveUploadWigle ? wu_ends_ci(name, ".txt") :
                                             wu_ends_ci(name, ".gz");
}

static bool wu_safe_argument(const char* text, size_t max_length, bool ascii_only) {
    if(!text) return false;
    size_t length = 0;
    while(length <= max_length && text[length]) {
        unsigned char ch = (unsigned char)text[length++];
        if(ch < 0x20 || ch == 0x7f || ch == '"' || ch == '\\' ||
           (ascii_only && ch > 0x7e)) return false;
    }
    return length && length <= max_length && text[0] != ' ' && text[length - 1] != ' ';
}

static bool wu_safe_name(const char* name) {
    if(!wu_safe_argument(name, WU_NAME_CAPACITY - 1, false)) return false;
    for(const char* p = name; *p; p++) {
        if(*p == '/' || *p == '\\') return false;
    }
    return true;
}

static bool wu_decimal(const char** cursor, uint32_t* value) {
    const char* p = *cursor;
    if(*p < '0' || *p > '9') return false;
    uint32_t number = 0;
    do {
        unsigned digit = (unsigned)(*p++ - '0');
        if(number > (UINT32_MAX - digit) / 10u) return false;
        number = number * 10u + digit;
    } while(*p >= '0' && *p <= '9');
    *cursor = p;
    *value = number;
    return true;
}

static bool wu_expect(const char** cursor, const char* expected) {
    size_t length = strlen(expected);
    if(strncmp(*cursor, expected, length) != 0) return false;
    *cursor += length;
    return true;
}

/* JanOS may emit MY_LOG_INFO with an ESP log prefix. Numbered list_dir rows
 * are printed directly, so both prefixed and bare lines occur in one reply. */
static const char* wu_payload(const char* line) {
    if(!line || (line[0] != 'I' && line[0] != 'W' && line[0] != 'E') ||
       strncmp(line + 1, " (", 2) != 0) return line;
    const char* cursor = line + 3;
    if(*cursor < '0' || *cursor > '9') return line;
    while(*cursor >= '0' && *cursor <= '9') cursor++;
    const char* marker = ") projectZero: ";
    size_t marker_length = strlen(marker);
    return strncmp(cursor, marker, marker_length) == 0 ? cursor + marker_length : line;
}

static bool wu_list_start(WuState* state, const C5HostApiV3* host) {
    if(!wu_send(host, "list_dir lab/wardrives", false)) {
        wu_error(state, host, "List command failed");
        return false;
    }
    state->header_seen = false;
    state->no_files_seen = false;
    state->list_invalid = false;
    state->summary_seen = false;
    state->candidate_count = 0;
    state->omitted_count = 0;
    state->row_count = 0;
    state->list_total = 0;
    state->page_count = 0;
    state->selected = 0;
    wu_phase(state, WuListing);
    wu_redraw(host);
    return true;
}

static bool wu_list_summary(const char* line, uint32_t* count) {
    const char* cursor = line;
    if(!wu_expect(&cursor, "Found ") || !wu_decimal(&cursor, count) ||
       !wu_expect(&cursor, " file(s) in /sdcard/lab/wardrives")) return false;
    return *cursor == '\0';
}

static void wu_list_line(WuState* state, const char* line) {
    if(strcmp(line, "Files in /sdcard/lab/wardrives:") == 0) {
        state->header_seen = true;
        return;
    }
    if(strstr(line, "Failed to initialize SD card:") ||
       strstr(line, "Failed to open /sdcard/lab/wardrives") ||
       strcmp(line, "Invalid path provided.") == 0) {
        state->list_invalid = true;
        return;
    }
    if(!state->header_seen) return;
    if(strcmp(line, "No files found in /sdcard/lab/wardrives") == 0) {
        state->no_files_seen = true;
        return;
    }
    uint32_t count;
    if(wu_list_summary(line, &count)) {
        state->summary_seen = true;
        state->list_total = count;
        return;
    }
    if(line[0] < '0' || line[0] > '9') return;
    const char* cursor = line;
    uint32_t index;
    if(!wu_decimal(&cursor, &index) || !wu_expect(&cursor, " ") ||
       index != state->row_count + 1 || !*cursor || state->no_files_seen) {
        state->list_invalid = true;
        return;
    }
    state->row_count++;
    if(!wu_candidate(state->provider, cursor)) return;
    if(!wu_safe_name(cursor)) {
        state->omitted_count++;
        return;
    }
    if(state->candidate_count >= state->page_offset &&
       state->candidate_count - state->page_offset < WU_PAGE_SIZE) {
        snprintf(state->files[state->page_count], WU_NAME_CAPACITY, "%s", cursor);
        state->page_count++;
    }
    state->candidate_count++;
}

static bool wu_summary_line(
    const char* line, C5WardriveUploadProvider provider,
    unsigned* uploaded, unsigned* skipped, unsigned* failed, unsigned* rate_limited) {
    const char* cursor = line;
    uint32_t u, s, f, r = 0;
    if(!wu_expect(&cursor, "Done: ") || !wu_decimal(&cursor, &u) ||
       !wu_expect(&cursor, " uploaded, ") || !wu_decimal(&cursor, &s) ||
       !wu_expect(&cursor, " skipped, ") || !wu_decimal(&cursor, &f) ||
       !wu_expect(&cursor, " failed")) return false;
    if(provider == C5WardriveUploadWdgwars && *cursor) {
        if(!wu_expect(&cursor, ", ") || !wu_decimal(&cursor, &r) ||
           !wu_expect(&cursor, " rate_limited")) return false;
    }
    if(*cursor || u > 1 || s > 1 || f > 1 || r > 1 || u + s + f + r != 1) return false;
    *uploaded = (unsigned)u;
    *skipped = (unsigned)s;
    *failed = (unsigned)f;
    *rate_limited = (unsigned)r;
    return true;
}

static WuFileResult wu_file_result(const WuState* state, const char* line) {
    if(strncmp(line, "[1/1] ", 6) != 0) return WuFileUnknown;
    const char* cursor = line + 6;
    size_t name_length = strlen(state->chosen);
    if(strncmp(cursor, state->chosen, name_length) != 0 || cursor[name_length] != ' ')
        return WuFileUnknown;
    const char* arrow = NULL;
    for(const char* p = cursor + name_length; (p = strstr(p, " -> ")); p += 4)
        arrow = p;
    if(!arrow) return WuFileUnknown;
    const char* result = arrow + 4;
    if(strcmp(result, "OK") == 0) return WuFileOk;
    if(strncmp(result, "skipped", 7) == 0) return WuFileSkipped;
    if(strncmp(result, "FAILED", 6) == 0 || strcmp(result, "AUTH FAILED") == 0)
        return WuFileFailed;
    if(strcmp(result, "RATE LIMITED") == 0) return WuFileRateLimited;
    return WuFileUnknown;
}

static bool wu_file_matches_summary(const WuState* state) {
    if(state->file_result == WuFileUnknown) return true;
    if(state->file_result == WuFileOk) return state->uploaded == 1;
    if(state->file_result == WuFileSkipped) return state->skipped == 1;
    if(state->file_result == WuFileFailed) return state->failed == 1;
    return state->rate_limited == 1;
}

static bool wu_visible_mask_part(const char* text, size_t length) {
    if(!length || length > 4) return false;
    for(size_t i = 0; i < length; i++) {
        unsigned char ch = (unsigned char)text[i];
        if(ch < 0x21 || ch > 0x7e) return false;
    }
    return true;
}

static bool wu_masked_key(C5WardriveUploadProvider provider, const char* text) {
    size_t length = strlen(text);
    if(length < 5 || strncmp(text + length - 4, "****", 4) != 0) return false;
    if(provider == C5WardriveUploadWdgwars)
        return wu_visible_mask_part(text, length - 4);
    for(size_t first = 1; first <= 4; first++) {
        if(length < first + 4 + 1 + 1 + 4 ||
           strncmp(text + first, "****:", 5) != 0) continue;
        size_t second = length - (first + 5 + 4);
        if(wu_visible_mask_part(text, first) &&
           wu_visible_mask_part(text + first + 5, second)) return true;
    }
    return false;
}

static bool wu_request_ssid(WuState* state, const C5HostApiV3* host) {
    if(!host->request_text_input) {
        wu_error(state, host, "WiFi input unavailable");
        return false;
    }
    C5TextInputRequest request = {.capacity = sizeof(state->ssid), .minimum_length = 1};
    snprintf(request.header, sizeof(request.header), "WiFi SSID");
    snprintf(request.initial, sizeof(request.initial), "%s", state->ssid);
    if(!host->request_text_input(host->ctx, &request)) {
        wu_error(state, host, "WiFi input unavailable");
        return false;
    }
    wu_phase(state, WuSsidInput);
    wu_redraw(host);
    return true;
}

static bool wu_request_password(WuState* state, const C5HostApiV3* host) {
    if(!host->request_text_input) {
        wu_error(state, host, "WiFi input unavailable");
        return false;
    }
    C5TextInputRequest request = {.capacity = 64, .minimum_length = 8};
    snprintf(request.header, sizeof(request.header), "WiFi password");
    if(!host->request_text_input(host->ctx, &request)) {
        wu_error(state, host, "WiFi input unavailable");
        return false;
    }
    wu_phase(state, WuPasswordInput);
    wu_redraw(host);
    return true;
}

static void wu_after_key(WuState* state, const C5HostApiV3* host) {
    if(!state->tls_verified) wu_phase(state, WuTlsBlocked);
    else wu_request_ssid(state, host);
    wu_redraw(host);
}

static bool wu_begin_key(WuState* state, const C5HostApiV3* host) {
    const char* command = state->provider == C5WardriveUploadWigle ?
                              "wigle_key read" : "wdgwars_key read";
    if(!wu_send(host, command, false)) {
        wu_error(state, host, "Key command failed");
        return false;
    }
    snprintf(state->chosen, sizeof(state->chosen), "%s", state->files[state->selected]);
    state->key_result = WuKeyUnknown;
    wu_phase(state, WuKeyCheck);
    wu_redraw(host);
    return true;
}

static bool wu_begin_connect(WuState* state, const C5HostApiV3* host, const char* password) {
    char command[WU_COMMAND_CAPACITY];
    int written = password ?
        snprintf(command, sizeof(command), "wifi_connect \"%s\" \"%s\"", state->ssid, password) :
        snprintf(command, sizeof(command), "wifi_connect \"%s\" --saved", state->ssid);
    bool valid = written > 0 && (size_t)written < sizeof(command);
    bool sent = valid && wu_send(host, command, password != NULL);
    wu_scrub(command, sizeof(command));
    if(!sent) {
        wu_error(state, host, "WiFi command failed");
        return false;
    }
    state->wifi_success = false;
    state->wifi_error = false;
    wu_phase(state, WuConnecting);
    wu_redraw(host);
    return true;
}

static bool wu_begin_upload(WuState* state, const C5HostApiV3* host) {
    if(!state->tls_verified) {
        wu_phase(state, WuTlsBlocked);
        return false;
    }
    char command[WU_COMMAND_CAPACITY];
    int written = snprintf(command, sizeof(command), "%s \"%s\"",
                           state->provider == C5WardriveUploadWigle ?
                               "wigle_upload" : "wdgwars_upload", state->chosen);
    if(written <= 0 || (size_t)written >= sizeof(command) ||
       !wu_send(host, command, false)) {
        wu_error(state, host, "Upload command failed");
        return false;
    }
    state->file_result = WuFileUnknown;
    state->summary_seen = false;
    state->error[0] = '\0';
    state->uploaded = state->skipped = state->failed = state->rate_limited = 0;
    wu_phase(state, WuUploading);
    wu_redraw(host);
    return true;
}

static void wu_process_line(WuState* state, const C5HostApiV3* host) {
    state->line[state->line_length] = '\0';
    const char* line = wu_payload(state->line);
    if(state->phase == WuListing) {
        wu_list_line(state, line);
        state->phase_tick_set = false;
    } else if(state->phase == WuKeyCheck) {
        const char* prefix = state->provider == C5WardriveUploadWigle ?
                                 "WiGLE key: " : "WDGWars key: ";
        size_t prefix_length = strlen(prefix);
        if(strncmp(line, prefix, prefix_length) == 0) {
            if(strcmp(line + prefix_length, "not set") == 0)
                state->key_result = WuKeyNvsMissing;
            else if(wu_masked_key(state->provider, line + prefix_length))
                state->key_result = WuKeyPresent;
        }
    } else if(state->phase == WuConnecting || state->phase == WuConnectUncertain) {
        char expected[64];
        int written = snprintf(expected, sizeof(expected), "SUCCESS: Connected to '%s'", state->ssid);
        if(written > 0 && (size_t)written < sizeof(expected) && strcmp(line, expected) == 0)
            state->wifi_success = true;
        if(strncmp(line, "FAILED: Connection to '", 23) == 0 ||
           strncmp(line, "TIMEOUT: Connection to '", 24) == 0 ||
           strstr(line, "No IP assigned yet")) state->wifi_error = true;
    } else if(state->phase == WuUploading || state->phase == WuUploadUncertain) {
        if(strcmp(line, "NO WIGLE CREDENTIALS") == 0)
            snprintf(state->error, sizeof(state->error), "WiGLE credentials missing");
        else if(strcmp(line, "NO WDGWARS CREDENTIALS") == 0)
            snprintf(state->error, sizeof(state->error), "WDGWars key missing");
        else if(strcmp(line, "WIFI NOT CONNECTED") == 0)
            snprintf(state->error, sizeof(state->error), "WiFi disconnected");
        else if(strstr(line, "Failed to initialize SD card:"))
            snprintf(state->error, sizeof(state->error), "SD card unavailable");
        else if(strcmp(line, "WDGWARS AUTH FAILED") == 0)
            snprintf(state->error, sizeof(state->error), "WDGWars auth failed");
        WuFileResult result = wu_file_result(state, line);
        if(result != WuFileUnknown) state->file_result = result;
        if(strncmp(line, "Done:", 5) == 0) {
            state->summary_seen = wu_summary_line(
                line, state->provider, &state->uploaded, &state->skipped,
                &state->failed, &state->rate_limited);
        }
        state->phase_tick_set = false;
    }
    state->line_length = 0;
    wu_redraw(host);
}

static void wu_finish_reply(WuState* state, const C5HostApiV3* host) {
    if(state->phase == WuListing) {
        bool complete = state->header_seen && !state->list_invalid &&
                        (state->summary_seen ? state->row_count == state->list_total :
                         state->no_files_seen && state->row_count == 0);
        if(!complete || (state->page_offset && !state->page_count))
            wu_error(state, host, "List incomplete");
        else
            wu_phase(state, WuFiles);
    } else if(state->phase == WuKeyCheck) {
        if(state->key_result == WuKeyUnknown) wu_error(state, host, "Key reply missing");
        else if(state->key_result == WuKeyNvsMissing) wu_phase(state, WuKeyMissing);
        else wu_after_key(state, host);
    } else if(state->phase == WuConnecting || state->phase == WuConnectUncertain) {
        if(state->wifi_success && !state->wifi_error) wu_phase(state, WuConfirm);
        else wu_phase(state, WuWifiError);
    } else if(state->phase == WuUploading || state->phase == WuUploadUncertain) {
        if(!state->summary_seen && state->error[0]) wu_phase(state, WuError);
        else if(!state->summary_seen) wu_error(state, host, "No final summary");
        else if(!wu_file_matches_summary(state)) wu_error(state, host, "Result mismatch");
        else wu_phase(state, WuDone);
    }
    wu_redraw(host);
}

static void* wu_enter(const C5HostApiV3* host, const void* params, size_t params_size) {
    if(!host || host->version != C5_MODULE_API_VERSION ||
       host->size < sizeof(C5HostApiV3) || !host->send_raw_lines ||
       !params || params_size != sizeof(C5WardriveUploadLaunchContext)) return NULL;
    const C5WardriveUploadLaunchContext* context = params;
    if(context->version != C5_WARDRIVE_UPLOAD_LAUNCH_VERSION ||
       context->size != sizeof(C5WardriveUploadLaunchContext) ||
       (context->provider != C5WardriveUploadWigle &&
        context->provider != C5WardriveUploadWdgwars) ||
       !context->ticks_per_second || context->ticks_per_second > 1000000u) return NULL;
    WuState* state = calloc(1, sizeof(*state));
    if(!state) return NULL;
    state->provider = context->provider;
    state->ticks_per_second = context->ticks_per_second;
    state->tls_verified = context->tls_verified;
    if(!wu_list_start(state, host)) {
        free(state);
        return NULL;
    }
    return state;
}

static void wu_leave(void* opaque, const C5HostApiV3* host) {
    (void)host;
    WuState* state = opaque;
    if(!state) return;
    /* JanOS uploads synchronously. A UI unload is not a remote cancellation. */
    wu_scrub(state, sizeof(*state));
    free(state);
}

static void wu_on_bytes(
    void* opaque, const C5HostApiV3* host, const uint8_t* bytes, size_t length) {
    WuState* state = opaque;
    if(!state || !host || !bytes) return;
    for(size_t i = 0; i < length; i++) {
        char ch = (char)bytes[i];
        if(state->prompt_space) {
            state->prompt_space = false;
            if(ch == ' ') continue;
        }
        if(state->pending_cr) {
            state->pending_cr = false;
            if(ch != '\n') {
                state->discard_line = true;
                if(state->phase == WuListing) state->list_invalid = true;
            }
        }
        if(ch == '\r') {
            state->pending_cr = true;
            continue;
        }
        if(ch == '\0') {
            state->discard_line = true;
            if(state->phase == WuListing) state->list_invalid = true;
            continue;
        }
        if(ch == '\n') {
            if(!state->discard_line && state->line_length) wu_process_line(state, host);
            state->line_length = 0;
            state->discard_line = false;
            continue;
        }
        if(ch == '>' && state->line_length == 0 && !state->discard_line) {
            wu_finish_reply(state, host);
            state->prompt_space = true;
            continue;
        }
        if(state->discard_line) continue;
        if(state->line_length + 1 >= sizeof(state->line)) {
            state->line_length = 0;
            state->discard_line = true;
            if(state->phase == WuListing) state->list_invalid = true;
            continue;
        }
        state->line[state->line_length++] = ch;
    }
}

static C5InputResult wu_on_input(
    void* opaque, const C5HostApiV3* host, const InputEvent* event) {
    WuState* state = opaque;
    if(!state || !host || !event) return C5InputIgnored;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat)
        return C5InputConsumed;
    if(event->key == InputKeyBack && event->type == InputTypeShort) {
        if(state->phase == WuUploading || state->phase == WuUploadUncertain ||
           state->phase == WuConnecting || state->phase == WuConnectUncertain ||
           state->phase == WuListing || state->phase == WuKeyCheck) {
            wu_status(host, "Monster may still be busy");
            return C5InputConsumed;
        }
        if(state->phase == WuTlsBlocked || state->phase == WuKeyMissing ||
           state->phase == WuWifiChoice || state->phase == WuSsidInput ||
           state->phase == WuPasswordInput || state->phase == WuWifiError ||
           state->phase == WuConfirm) {
            wu_phase(state, WuFiles);
            wu_redraw(host);
            return C5InputConsumed;
        }
        return C5InputSwitchModule;
    }
    if(state->phase == WuFiles) {
        if(event->key == InputKeyUp && state->selected) state->selected--;
        else if(event->key == InputKeyDown && state->selected + 1 < state->page_count)
            state->selected++;
        else if(event->key == InputKeyRight && event->type == InputTypeShort &&
                state->page_offset + WU_PAGE_SIZE < state->candidate_count) {
            state->page_offset += WU_PAGE_SIZE;
            wu_list_start(state, host);
        } else if(event->key == InputKeyLeft && event->type == InputTypeShort &&
                  state->page_offset >= WU_PAGE_SIZE) {
            state->page_offset -= WU_PAGE_SIZE;
            wu_list_start(state, host);
        } else if(event->key == InputKeyOk && event->type == InputTypeShort && state->page_count) {
            wu_begin_key(state, host);
        }
    } else if(state->phase == WuKeyMissing && event->key == InputKeyOk &&
              event->type == InputTypeShort) {
        wu_begin_key(state, host);
    } else if(state->phase == WuWifiChoice && event->type == InputTypeShort) {
        if(event->key == InputKeyOk) wu_begin_connect(state, host, NULL);
        else if(event->key == InputKeyRight) wu_request_password(state, host);
    } else if(state->phase == WuWifiError && event->key == InputKeyOk &&
              event->type == InputTypeShort) {
        wu_request_password(state, host);
    } else if(state->phase == WuConfirm && event->key == InputKeyOk &&
              event->type == InputTypeShort) {
        wu_begin_upload(state, host);
    } else if((state->phase == WuError || state->phase == WuDone) &&
              event->key == InputKeyOk && event->type == InputTypeShort) {
        state->page_offset = 0;
        wu_list_start(state, host);
    }
    wu_redraw(host);
    return C5InputConsumed;
}

static void wu_on_text_input(
    void* opaque, const C5HostApiV3* host, bool accepted, const char* text) {
    WuState* state = opaque;
    if(!state || !host) return;
    if(state->phase == WuSsidInput) {
        if(!accepted) wu_phase(state, WuFiles);
        else if(!wu_safe_argument(text, 32, false)) wu_status(host, "Use 1-32 safe SSID bytes");
        else {
            snprintf(state->ssid, sizeof(state->ssid), "%s", text);
            wu_phase(state, WuWifiChoice);
        }
    } else if(state->phase == WuPasswordInput) {
        if(!accepted) wu_phase(state, WuWifiChoice);
        else if(!wu_safe_argument(text, 63, true) || strlen(text) < 8)
            wu_status(host, "Use 8-63 safe pass chars");
        else wu_begin_connect(state, host, text);
    }
    wu_redraw(host);
}

static const char* wu_result_label(WuFileResult result) {
    switch(result) {
    case WuFileOk: return "File: OK";
    case WuFileSkipped: return "File: skipped";
    case WuFileFailed: return "File: failed";
    case WuFileRateLimited: return "File: rate limited";
    default: return "File: pending";
    }
}

static void wu_draw(void* opaque, const C5HostApiV3* host, Canvas* canvas) {
    (void)host;
    const WuState* state = opaque;
    if(!state || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 3, 12, state->provider == C5WardriveUploadWigle ?
                                    "WiGLE Upload" : "WDGWars Upload");
    canvas_set_font(canvas, FontSecondary);
    char line[64];
    if(state->phase == WuListing) {
        canvas_draw_str(canvas, 3, 32, "Listing Wardrive files...");
    } else if(state->phase == WuFiles) {
        if(!state->candidate_count) {
            canvas_draw_str(canvas, 3, 32, "No Wardrive files");
        } else {
            uint32_t pages = (state->candidate_count + WU_PAGE_SIZE - 1) / WU_PAGE_SIZE;
            snprintf(line, sizeof(line), "Page %lu/%lu (%lu files)",
                     (unsigned long)(state->page_offset / WU_PAGE_SIZE + 1),
                     (unsigned long)pages, (unsigned long)state->candidate_count);
            canvas_draw_str(canvas, 3, 23, line);
            snprintf(line, sizeof(line), "> %.25s", state->files[state->selected]);
            canvas_draw_str(canvas, 3, 37, line);
        }
        if(state->omitted_count) {
            snprintf(line, sizeof(line), "omitted %lu unsafe/long", (unsigned long)state->omitted_count);
            canvas_draw_str(canvas, 3, 49, line);
        }
        canvas_draw_str(canvas, 3, 61, "OK:pick L/R:page");
    } else if(state->phase == WuKeyCheck) {
        canvas_draw_str(canvas, 3, 32, "Checking API key...");
    } else if(state->phase == WuKeyMissing) {
        canvas_draw_str(canvas, 3, 28, "NVS key missing");
        canvas_draw_str(canvas, 3, 42, "Set key in JanOS");
        canvas_draw_str(canvas, 3, 56, "OK:recheck Back:files");
    } else if(state->phase == WuTlsBlocked) {
        canvas_draw_str(canvas, 3, 30, "TLS unverified");
        canvas_draw_str(canvas, 3, 43, "Upload blocked");
        canvas_draw_str(canvas, 3, 56, "Back:files");
    } else if(state->phase == WuSsidInput) {
        canvas_draw_str(canvas, 3, 32, "Enter WiFi SSID");
    } else if(state->phase == WuWifiChoice) {
        snprintf(line, sizeof(line), "WiFi: %.26s", state->ssid);
        canvas_draw_str(canvas, 3, 30, line);
        canvas_draw_str(canvas, 3, 48, "OK:saved R:password");
    } else if(state->phase == WuPasswordInput) {
        canvas_draw_str(canvas, 3, 32, "Enter WiFi password");
    } else if(state->phase == WuConnecting || state->phase == WuConnectUncertain) {
        canvas_draw_str(canvas, 3, 31, state->phase == WuConnecting ?
                                       "Connecting WiFi..." : "WiFi result pending");
        canvas_draw_str(canvas, 3, 53, "Back waits for JanOS");
    } else if(state->phase == WuWifiError) {
        canvas_draw_str(canvas, 3, 30, "WiFi not connected");
        canvas_draw_str(canvas, 3, 52, "OK:password Back:files");
    } else if(state->phase == WuConfirm) {
        canvas_draw_str(canvas, 3, 26, "Confirm upload");
        snprintf(line, sizeof(line), "%.25s", state->chosen);
        canvas_draw_str(canvas, 3, 39, line);
        canvas_draw_str(canvas, 3, 56, "OK:send Back:files");
    } else if(state->phase == WuUploading || state->phase == WuUploadUncertain) {
        canvas_draw_str(canvas, 3, 25, state->phase == WuUploading ?
                                       "Monster uploading..." : "May still be running");
        canvas_draw_str(canvas, 3, 39, wu_result_label(state->file_result));
        canvas_draw_str(canvas, 3, 56, "Back waits; no cancel");
    } else if(state->phase == WuDone) {
        canvas_draw_str(canvas, 3, 24, "Session done");
        canvas_draw_str(canvas, 3, 36, state->file_result == WuFileUnknown ?
                                       "File: unconfirmed" : wu_result_label(state->file_result));
        snprintf(line, sizeof(line), "%u up, %u skip, %u fail", state->uploaded,
                 state->skipped, state->failed);
        canvas_draw_str(canvas, 3, 48, line);
        if(state->rate_limited) {
            snprintf(line, sizeof(line), "%u rate limited", state->rate_limited);
            canvas_draw_str(canvas, 3, 60, line);
        } else {
            canvas_draw_str(canvas, 3, 60, "Back:exit OK:files");
        }
    } else {
        canvas_draw_str(canvas, 3, 32, state->error[0] ? state->error : "Unavailable");
        canvas_draw_str(canvas, 3, 55, "Back:exit OK:retry");
    }
}

static void wu_tick(void* opaque, const C5HostApiV3* host, uint32_t now_ticks) {
    WuState* state = opaque;
    if(!state || !host) return;
    uint32_t seconds = 0;
    if(state->phase == WuListing || state->phase == WuKeyCheck) seconds = 5;
    else if(state->phase == WuConnecting) seconds = 30;
    else if(state->phase == WuUploading) seconds = 180;
    if(!seconds) return;
    if(!state->phase_tick_set) {
        state->phase_tick = now_ticks;
        state->phase_tick_set = true;
        return;
    }
    if((uint32_t)(now_ticks - state->phase_tick) < state->ticks_per_second * seconds)
        return;
    if(state->phase == WuConnecting) wu_phase(state, WuConnectUncertain);
    else if(state->phase == WuUploading) wu_phase(state, WuUploadUncertain);
    else wu_error(state, host, state->phase == WuListing ?
                                   "List reply timed out" : "Key reply timed out");
    wu_redraw(host);
}

static const C5ModuleV3 c5_wu_module = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = wu_enter,
    .leave = wu_leave,
    .on_bytes = wu_on_bytes,
    .on_input = wu_on_input,
    .on_text_input = wu_on_text_input,
    .draw = wu_draw,
    .tick = wu_tick,
};

static const FlipperAppPluginDescriptor c5_wu_descriptor = {
    .appid = C5_MODULE_APP_ID,
    .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_wu_module,
};

const FlipperAppPluginDescriptor* lab_c5_wardrive_upload_plugin_ep(void) {
    return &c5_wu_descriptor;
}
