#include "beacon_module.h"
#include "../../module_api.h"

#include <flipper_application/flipper_application.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BEACON_STORED_MAX 64u
#define BEACON_ON_AIR_MAX 32u
#define BEACON_SSID_CAPACITY 33u
#define BEACON_LINE_CAPACITY 128u
#define BEACON_COMMAND_CAPACITY 64u

typedef enum {
    BeaconLoading,
    BeaconReady,
    BeaconInput,
    BeaconRemoveConfirm,
    BeaconAdding,
    BeaconRemoving,
    BeaconStarting,
    BeaconStartUnconfirmed,
    BeaconActive,
    BeaconStopping,
    BeaconStopUnconfirmed,
    BeaconStopped,
    BeaconError,
} BeaconPhase;

typedef struct {
    BeaconPhase phase;
    uint32_t ticks_per_second;
    uint32_t phase_tick;
    bool phase_tick_set;
    bool may_be_active;
    bool list_empty_marker;
    bool list_invalid;
    bool reply_ack;
    bool discard_line;
    bool pending_cr;
    bool prompt_space;
    uint8_t count;
    uint8_t selected;
    char ssids[BEACON_STORED_MAX][BEACON_SSID_CAPACITY];
    char pending_ssid[BEACON_SSID_CAPACITY];
    char line[BEACON_LINE_CAPACITY];
    size_t line_length;
    char error[48];
} BeaconState;

static void beacon_phase(BeaconState* state, BeaconPhase phase) {
    state->phase = phase;
    state->phase_tick_set = false;
}

static void beacon_redraw(const C5HostApiV3* host) {
    if(host && host->request_redraw) host->request_redraw(host->ctx);
}

static void beacon_status(const C5HostApiV3* host, const char* message) {
    if(host && host->show_status) host->show_status(host->ctx, message, 1500, true);
}

static bool beacon_send(const C5HostApiV3* host, const char* command) {
    if(!host || !host->send_raw_lines || !command) return false;
    const size_t length = strlen(command);
    if(!length || length + 1 > BEACON_COMMAND_CAPACITY ||
       length + 1 > C5_MODULE_RAW_TX_MAX) return false;
    char batch[BEACON_COMMAND_CAPACITY];
    memcpy(batch, command, length);
    batch[length] = '\n';
    return host->send_raw_lines(host->ctx, batch, length + 1);
}

static bool beacon_ssid_valid(const char* text) {
    if(!text) return false;
    size_t length = 0;
    while(length < BEACON_SSID_CAPACITY && text[length]) {
        unsigned char ch = (unsigned char)text[length++];
        if(ch < 0x20 || ch == 0x7f || ch == '"' || ch == '\\') return false;
    }
    if(!length || length >= BEACON_SSID_CAPACITY) return false;
    if(text[0] == ' ' || text[length - 1] == ' ') return false;
    return true;
}

static void beacon_error(BeaconState* state, const C5HostApiV3* host, const char* message) {
    snprintf(state->error, sizeof(state->error), "%s", message);
    beacon_phase(state, BeaconError);
    beacon_redraw(host);
}

static bool beacon_reload(BeaconState* state, const C5HostApiV3* host) {
    if(!beacon_send(host, "list_ssids")) {
        beacon_error(state, host, "List command failed");
        return false;
    }
    state->count = 0;
    state->selected = 0;
    state->list_empty_marker = false;
    state->list_invalid = false;
    state->reply_ack = false;
    beacon_phase(state, BeaconLoading);
    beacon_redraw(host);
    return true;
}

/* JanOS prints 1-based lines as "<index> <SSID>". Gaps, duplicates and
 * truncation make remove_ssid indices unsafe, so the snapshot is rejected. */
static void beacon_list_line(BeaconState* state, const char* line) {
    if(strcmp(line, "ssids.txt is empty.") == 0 ||
       strcmp(line, "ssids.txt not found on SD card.") == 0) {
        if(state->count) state->list_invalid = true;
        state->list_empty_marker = true;
        return;
    }
    if(strstr(line, "Failed to initialize SD card:")) {
        state->list_invalid = true;
        return;
    }
    if(line[0] < '0' || line[0] > '9') return;
    const char* cursor = line;
    unsigned index = 0;
    while(*cursor >= '0' && *cursor <= '9') {
        index = index * 10u + (unsigned)(*cursor++ - '0');
        if(index > BEACON_STORED_MAX) {
            state->list_invalid = true;
            return;
        }
    }
    if(*cursor++ != ' ' || state->list_empty_marker ||
       index != (unsigned)state->count + 1 || state->count >= BEACON_STORED_MAX) {
        state->list_invalid = true;
        return;
    }
    const size_t length = strlen(cursor);
    if(!length || length >= BEACON_SSID_CAPACITY) {
        state->list_invalid = true;
        return;
    }
    for(size_t i = 0; i < length; i++) {
        unsigned char ch = (unsigned char)cursor[i];
        if(ch < 0x20 || ch == 0x7f) {
            state->list_invalid = true;
            return;
        }
    }
    memcpy(state->ssids[state->count], cursor, length + 1);
    state->count++;
}

static void beacon_process_line(BeaconState* state, const C5HostApiV3* host) {
    state->line[state->line_length] = '\0';
    const char* line = state->line;
    if((strncmp(line, "I (", 3) == 0 || strncmp(line, "W (", 3) == 0 ||
        strncmp(line, "E (", 3) == 0)) {
        const char* marker = strstr(line, ") projectZero: ");
        if(marker) line = marker + sizeof(") projectZero: ") - 1;
    }
    if(state->phase == BeaconLoading) {
        beacon_list_line(state, line);
    } else if(state->phase == BeaconAdding) {
        char expected[BEACON_COMMAND_CAPACITY];
        int written = snprintf(expected, sizeof(expected), "Added SSID: %s", state->pending_ssid);
        if(written > 0 && (size_t)written < sizeof(expected) && strcmp(line, expected) == 0)
            state->reply_ack = true;
    } else if(state->phase == BeaconRemoving) {
        char expected[BEACON_COMMAND_CAPACITY];
        int written = snprintf(expected, sizeof(expected),
                               "SSID removed. %u SSIDs remaining.", (unsigned)state->count - 1);
        if(written > 0 && (size_t)written < sizeof(expected) && strcmp(line, expected) == 0)
            state->reply_ack = true;
    } else if(state->phase == BeaconStarting || state->phase == BeaconStartUnconfirmed) {
        if(strcmp(line, "Beacon spam started. Use 'stop' to end.") == 0)
            beacon_phase(state, BeaconActive);
    } else if(state->phase == BeaconStopping || state->phase == BeaconStopUnconfirmed) {
        if(strcmp(line, "All operations stopped.") == 0) {
            state->may_be_active = false;
            beacon_phase(state, BeaconStopped);
        }
    }
    state->line_length = 0;
    beacon_redraw(host);
}

static void beacon_finish_reply(BeaconState* state, const C5HostApiV3* host) {
    if(state->phase == BeaconLoading) {
        if(state->list_invalid || (!state->count && !state->list_empty_marker))
            beacon_error(state, host, "List invalid or incomplete");
        else
            beacon_phase(state, BeaconReady);
    } else if(state->phase == BeaconAdding || state->phase == BeaconRemoving) {
        if(state->reply_ack) beacon_reload(state, host);
        else beacon_error(state, host, "Edit not confirmed");
    } else if(state->phase == BeaconStarting) {
        beacon_phase(state, BeaconStartUnconfirmed);
    } else if(state->phase == BeaconStopping) {
        snprintf(state->error, sizeof(state->error), "No stop ACK");
        beacon_phase(state, BeaconStopUnconfirmed);
    }
    beacon_redraw(host);
}

static void* beacon_enter(const C5HostApiV3* host, const void* params, size_t params_size) {
    if(!host || host->version != C5_MODULE_API_VERSION ||
       host->size < sizeof(C5HostApiV3) || !host->send_raw_lines ||
       !params || params_size != sizeof(C5BeaconLaunchContext)) return NULL;
    const C5BeaconLaunchContext* context = params;
    if(context->version != C5_BEACON_LAUNCH_VERSION ||
       context->size != sizeof(C5BeaconLaunchContext) ||
       !context->ticks_per_second || context->ticks_per_second > 1000000u) return NULL;
    BeaconState* state = calloc(1, sizeof(*state));
    if(!state) return NULL;
    state->ticks_per_second = context->ticks_per_second;
    if(!beacon_reload(state, host)) {
        free(state);
        return NULL;
    }
    return state;
}

static void beacon_leave(void* opaque, const C5HostApiV3* host) {
    BeaconState* state = opaque;
    if(!state) return;
    if(state->may_be_active) beacon_send(host, "stop");
    memset(state, 0, sizeof(*state));
    free(state);
}

static void beacon_on_bytes(
    void* opaque, const C5HostApiV3* host, const uint8_t* bytes, size_t length) {
    BeaconState* state = opaque;
    if(!state || !host || !bytes) return;
    for(size_t i = 0; i < length; i++) {
        const char ch = (char)bytes[i];
        if(state->prompt_space) {
            state->prompt_space = false;
            if(ch == ' ') continue;
        }
        if(state->pending_cr) {
            state->pending_cr = false;
            if(ch != '\n') {
                state->discard_line = true;
                if(state->phase == BeaconLoading) state->list_invalid = true;
            }
        }
        if(ch == '\r') {
            state->pending_cr = true;
            continue;
        }
        if(ch == '\0') {
            state->discard_line = true;
            if(state->phase == BeaconLoading) state->list_invalid = true;
            continue;
        }
        if(ch == '\n') {
            if(!state->discard_line && state->line_length)
                beacon_process_line(state, host);
            state->line_length = 0;
            state->discard_line = false;
            continue;
        }
        if(ch == '>' && state->line_length == 0 && !state->discard_line) {
            beacon_finish_reply(state, host);
            state->prompt_space = true;
            continue;
        }
        if(state->discard_line) continue;
        if(state->line_length + 1 >= sizeof(state->line)) {
            state->line_length = 0;
            state->discard_line = true;
            if(state->phase == BeaconLoading) state->list_invalid = true;
            continue;
        }
        state->line[state->line_length++] = ch;
    }
}

static void beacon_stop(BeaconState* state, const C5HostApiV3* host) {
    if(!beacon_send(host, "stop")) {
        snprintf(state->error, sizeof(state->error), "Stop TX failed");
        beacon_phase(state, BeaconStopUnconfirmed);
        beacon_status(host, "Stop TX failed; Back retries");
    } else {
        state->error[0] = '\0';
        beacon_phase(state, BeaconStopping);
    }
    beacon_redraw(host);
}

static C5InputResult beacon_on_input(
    void* opaque, const C5HostApiV3* host, const InputEvent* event) {
    BeaconState* state = opaque;
    if(!state || !host || !event) return C5InputIgnored;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat)
        return C5InputConsumed;
    if(event->key == InputKeyBack && event->type == InputTypeShort) {
        if(state->phase == BeaconRemoveConfirm) {
            beacon_phase(state, BeaconReady);
        } else if(state->phase == BeaconStarting || state->phase == BeaconStartUnconfirmed ||
                  state->phase == BeaconActive || state->phase == BeaconStopUnconfirmed) {
            beacon_stop(state, host);
        } else if(state->phase == BeaconStopping || state->phase == BeaconAdding ||
                  state->phase == BeaconRemoving || state->phase == BeaconLoading) {
            /* Do not leave with a command response still pending. */
        } else if(state->phase == BeaconError) {
            return C5InputSwitchModule;
        } else {
            return C5InputSwitchModule;
        }
        beacon_redraw(host);
        return C5InputConsumed;
    }
    if(state->phase == BeaconStopped && event->key == InputKeyOk &&
       event->type == InputTypeShort) {
        beacon_reload(state, host);
        return C5InputConsumed;
    }
    if(state->phase == BeaconError && event->key == InputKeyOk &&
       event->type == InputTypeShort) {
        beacon_reload(state, host);
        return C5InputConsumed;
    }
    if(state->phase == BeaconInput && event->key == InputKeyOk &&
       event->type == InputTypeShort) {
        C5TextInputRequest request = {.capacity = BEACON_SSID_CAPACITY, .minimum_length = 1};
        snprintf(request.header, sizeof(request.header), "Add beacon SSID");
        if(host->request_text_input) host->request_text_input(host->ctx, &request);
        return C5InputConsumed;
    }
    if(state->phase == BeaconRemoveConfirm && event->key == InputKeyOk &&
       event->type == InputTypeShort) {
        char command[32];
        int written = snprintf(command, sizeof(command), "remove_ssid %u",
                               (unsigned)state->selected + 1);
        if(written < 0 || (size_t)written >= sizeof(command) || !beacon_send(host, command))
            beacon_error(state, host, "Remove command failed");
        else {
            state->reply_ack = false;
            beacon_phase(state, BeaconRemoving);
        }
        beacon_redraw(host);
        return C5InputConsumed;
    }
    if(state->phase != BeaconReady) return C5InputConsumed;
    if(event->key == InputKeyUp && state->selected) state->selected--;
    else if(event->key == InputKeyDown && state->selected + 1 < state->count) state->selected++;
    else if(event->key == InputKeyOk && event->type == InputTypeShort) {
        if(state->count == BEACON_STORED_MAX) {
            beacon_status(host, "List full (64 SSIDs)");
        } else if(!host->request_text_input) {
            beacon_status(host, "Text input unavailable");
        } else {
            C5TextInputRequest request = {.capacity = BEACON_SSID_CAPACITY, .minimum_length = 1};
            snprintf(request.header, sizeof(request.header), "Add beacon SSID");
            if(host->request_text_input(host->ctx, &request))
                beacon_phase(state, BeaconInput);
            else
                beacon_status(host, "Text input unavailable");
        }
    } else if(event->key == InputKeyLeft && event->type == InputTypeShort && state->count) {
        beacon_phase(state, BeaconRemoveConfirm);
    } else if(event->key == InputKeyRight && event->type == InputTypeShort) {
        if(!state->count) {
            beacon_status(host, "Add an SSID first");
        } else if(!beacon_send(host, "start_beacon_spam_ssids")) {
            beacon_error(state, host, "Start command failed");
        } else {
            state->may_be_active = true;
            beacon_phase(state, BeaconStarting);
        }
    }
    beacon_redraw(host);
    return C5InputConsumed;
}

static void beacon_on_text_input(
    void* opaque, const C5HostApiV3* host, bool accepted, const char* text) {
    BeaconState* state = opaque;
    if(!state || !host || state->phase != BeaconInput) return;
    if(!accepted) {
        beacon_phase(state, BeaconReady);
    } else if(!beacon_ssid_valid(text)) {
        beacon_status(host, "Use 1-32 safe SSID bytes");
    } else {
        char command[BEACON_COMMAND_CAPACITY];
        int written = snprintf(command, sizeof(command), "add_ssid \"%s\"", text);
        if(written < 0 || (size_t)written >= sizeof(command) || !beacon_send(host, command)) {
            beacon_error(state, host, "Add command failed");
        } else {
            snprintf(state->pending_ssid, sizeof(state->pending_ssid), "%s", text);
            state->reply_ack = false;
            beacon_phase(state, BeaconAdding);
        }
    }
    beacon_redraw(host);
}

static void beacon_draw(void* opaque, const C5HostApiV3* host, Canvas* canvas) {
    (void)host;
    const BeaconState* state = opaque;
    if(!state || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 4, 12, "Beacon Spam");
    canvas_set_font(canvas, FontSecondary);
    if(state->phase == BeaconReady) {
        char line[48];
        snprintf(line, sizeof(line), "%u/64 stored", (unsigned)state->count);
        canvas_draw_str(canvas, 4, 23, line);
        snprintf(line, sizeof(line), "max %u on air", BEACON_ON_AIR_MAX);
        canvas_draw_str(canvas, 4, 33, line);
        if(state->count) {
            snprintf(line, sizeof(line), "> %u %.25s", (unsigned)state->selected + 1,
                     state->ssids[state->selected]);
            canvas_draw_str(canvas, 4, 45, line);
        } else {
            canvas_draw_str(canvas, 4, 45, "No SSIDs");
        }
        canvas_draw_str(canvas, 4, 58, state->count == BEACON_STORED_MAX ?
                                       "Full L:del R:start" : "OK:add L:del R:start");
    } else if(state->phase == BeaconRemoveConfirm) {
        char line[48];
        snprintf(line, sizeof(line), "Remove #%u?", (unsigned)state->selected + 1);
        canvas_draw_str(canvas, 4, 25, line);
        snprintf(line, sizeof(line), "%.29s", state->ssids[state->selected]);
        canvas_draw_str(canvas, 4, 39, line);
        canvas_draw_str(canvas, 4, 56, "OK:remove Back:cancel");
    } else if(state->phase == BeaconLoading) {
        canvas_draw_str(canvas, 4, 33, "Loading SSID list...");
    } else if(state->phase == BeaconInput) {
        canvas_draw_str(canvas, 4, 33, "Enter a new SSID");
        canvas_draw_str(canvas, 4, 56, "OK:input Back:exit");
    } else if(state->phase == BeaconAdding || state->phase == BeaconRemoving) {
        canvas_draw_str(canvas, 4, 33,
                        state->phase == BeaconAdding ? "Adding SSID..." : "Removing SSID...");
    } else if(state->phase == BeaconStarting) {
        canvas_draw_str(canvas, 4, 33, "Starting...");
        canvas_draw_str(canvas, 4, 56, "Back:stop");
    } else if(state->phase == BeaconStartUnconfirmed) {
        canvas_draw_str(canvas, 4, 30, "Start not confirmed");
        canvas_draw_str(canvas, 4, 43, "May still be active");
        canvas_draw_str(canvas, 4, 56, "Back:stop");
    } else if(state->phase == BeaconActive) {
        char line[40];
        canvas_draw_str(canvas, 4, 30, "Active (ACK)");
        snprintf(line, sizeof(line), "up to %u SSIDs on air", BEACON_ON_AIR_MAX);
        canvas_draw_str(canvas, 4, 43, line);
        canvas_draw_str(canvas, 4, 56, "Back:stop");
    } else if(state->phase == BeaconStopping) {
        canvas_draw_str(canvas, 4, 33, "Stopping...");
        canvas_draw_str(canvas, 4, 56, "Waiting for stop ACK");
    } else if(state->phase == BeaconStopUnconfirmed) {
        canvas_draw_str(canvas, 4, 30, state->error[0] ? state->error : "No stop ACK");
        canvas_draw_str(canvas, 4, 43, "May still be active");
        canvas_draw_str(canvas, 4, 56, "Back:retry stop");
    } else if(state->phase == BeaconStopped) {
        canvas_draw_str(canvas, 4, 33, "Stopped (ACK)");
        canvas_draw_str(canvas, 4, 56, "OK:reload Back:exit");
    } else {
        canvas_draw_str(canvas, 4, 33, state->error[0] ? state->error : "Unavailable");
        canvas_draw_str(canvas, 4, 56, "OK:reload Back:exit");
    }
}

static void beacon_tick(void* opaque, const C5HostApiV3* host, uint32_t now_ticks) {
    BeaconState* state = opaque;
    if(!state || !host) return;
    uint32_t seconds = 0;
    if(state->phase == BeaconLoading || state->phase == BeaconAdding ||
       state->phase == BeaconRemoving || state->phase == BeaconStopping) seconds = 5;
    else if(state->phase == BeaconStarting) seconds = 15;
    if(!seconds) return;
    if(!state->phase_tick_set) {
        state->phase_tick = now_ticks;
        state->phase_tick_set = true;
        return;
    }
    if((uint32_t)(now_ticks - state->phase_tick) < state->ticks_per_second * seconds)
        return;
    if(state->phase == BeaconStarting) beacon_phase(state, BeaconStartUnconfirmed);
    else if(state->phase == BeaconStopping) {
        snprintf(state->error, sizeof(state->error), "No stop ACK");
        beacon_phase(state, BeaconStopUnconfirmed);
    }
    else beacon_error(state, host, "Reply timed out");
    beacon_redraw(host);
}

static const C5ModuleV3 c5_beacon_module = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = beacon_enter,
    .leave = beacon_leave,
    .on_bytes = beacon_on_bytes,
    .on_input = beacon_on_input,
    .on_text_input = beacon_on_text_input,
    .draw = beacon_draw,
    .tick = beacon_tick,
};

static const FlipperAppPluginDescriptor c5_beacon_descriptor = {
    .appid = C5_MODULE_APP_ID,
    .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_beacon_module,
};

const FlipperAppPluginDescriptor* lab_c5_beacon_plugin_ep(void) {
    return &c5_beacon_descriptor;
}
