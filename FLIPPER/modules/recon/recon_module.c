#include "recon_module.h"

#include "recon_scan.h"
#include "recon_sniffer_clients.h"
#include "recon_sniffer_probe.h"
#include "recon_targets.h"
#include "../../module_api.h"

#include <flipper_application/flipper_application.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RECON_SNIFFER_RESULTS_THRESHOLD 200u
#define RECON_MAX_SELECTED_NETWORKS C5_RECON_SCAN_MAX_RESULTS

typedef enum {
    ReconScreenScanStatus,
    ReconScreenScanResults,
    ReconScreenSnifferStatus,
    ReconScreenSnifferResults,
    ReconScreenSnifferClients,
    ReconScreenProbeResults,
    ReconScreenTerminal,
} ReconScreen;

typedef enum {
    ReconModelScan,
    ReconModelSniffer,
    ReconModelProbe,
} ReconModelKind;

typedef struct {
    C5ReconMode mode;
    ReconScreen screen;
    ReconModelKind model_kind;
    union {
        C5ReconScan scan;
        C5ReconSnifferState sniffer;
        C5ReconProbeState probe;
    } model;
    C5ReconClients identity;
    uint16_t* selected_networks;
    size_t selected_network_count;
    size_t ap_index;
    size_t client_offset;
    size_t identity_cursor;
    bool identity_selected;
    uint16_t field_mask;
    uint32_t last_tick;
    bool pending_start;
    bool command_active;
    bool scan_complete;
    bool console_visible;
    bool memory_error;
    bool cleanup_done;
    bool preserve_station_selection;
} ReconState;

static void recon_redraw(const C5HostApiV3* host) {
    if(host && host->request_redraw) host->request_redraw(host->ctx);
}

static void recon_status(const C5HostApiV3* host, const char* message) {
    if(host && host->show_status) host->show_status(host->ctx, message, 1500, true);
}

static bool recon_send(const C5HostApiV3* host, const char* lines) {
    if(!host || !host->send_raw_lines || !lines) return false;
    size_t length = strlen(lines);
    return length && length <= C5_MODULE_RAW_TX_MAX &&
           host->send_raw_lines(host->ctx, lines, length);
}

static bool recon_make_start_sniffer(
    const ReconState* state, char* output, size_t capacity, bool resume) {
    if(!state || !output || capacity == 0) return false;
    if(!resume && state->selected_network_count > C5_RECON_SAFE_SELECTED_NETWORKS) return false;
    const char* command = resume ? "start_sniffer_noscan" : "start_sniffer";
    /* JanOS Resume uses every AP from its previous scan, regardless of selection. */
    if(resume || state->selected_network_count == 0) {
        int length = snprintf(output, capacity, "%s\n", command);
        return length > 0 && (size_t)length < capacity;
    }
    size_t used = 0;
    int length = snprintf(output, capacity, "select_networks");
    if(length < 0 || (size_t)length >= capacity) return false;
    used = (size_t)length;
    for(size_t i = 0; i < state->selected_network_count; i++) {
        length = snprintf(output + used, capacity - used, " %u", (unsigned)state->selected_networks[i]);
        if(length < 0 || (size_t)length >= capacity - used) return false;
        used += (size_t)length;
    }
    length = snprintf(output + used, capacity - used, "\n%s\n", command);
    return length > 0 && (size_t)length < capacity - used;
}

static bool recon_send_start_sniffer(ReconState* state, const C5HostApiV3* host, bool resume) {
    char batch[C5_MODULE_RAW_TX_MAX + 1];
    if(!recon_make_start_sniffer(state, batch, sizeof(batch), resume) ||
       !recon_send(host, batch)) return false;
    state->command_active = true;
    state->model.sniffer.running = true;
    if(resume) memcpy(state->model.sniffer.mode, "NOSCAN", sizeof("NOSCAN"));
    return true;
}

static void* recon_enter(const C5HostApiV3* host, const void* params, size_t params_size) {
    if(!host || host->version != C5_MODULE_API_VERSION || host->size < sizeof(*host) ||
       !host->send_raw_lines || !params || params_size < sizeof(C5ReconLaunchContext)) return NULL;
    const C5ReconLaunchContext* launch = params;
    if(launch->version != C5_RECON_LAUNCH_VERSION ||
       launch->size != sizeof(C5ReconLaunchContext) || launch->size > params_size ||
       launch->mode > C5ReconModeProbeResults ||
       launch->selected_count > RECON_MAX_SELECTED_NETWORKS ||
       (launch->mode == C5ReconModeSnifferStart &&
        launch->selected_count > C5_RECON_SAFE_SELECTED_NETWORKS) ||
       (launch->selected_count && !launch->selected_numbers)) return NULL;

    ReconState* state = calloc(1, sizeof(*state));
    if(!state) return NULL;
    state->mode = launch->mode;
    c5_recon_clients_init(&state->identity);
    state->field_mask = launch->field_mask ? launch->field_mask : C5ReconFieldAll;
    state->pending_start = true;
    /* A new Scanner run replaces old target selection; only Sniffer needs it. */
    if(launch->selected_count && state->mode != C5ReconModeScanner) {
        state->selected_networks = malloc(launch->selected_count * sizeof(*state->selected_networks));
        if(!state->selected_networks) { free(state); return NULL; }
        for(size_t i = 0; i < launch->selected_count; i++) {
            if(launch->selected_numbers[i] == 0 ||
               launch->selected_numbers[i] > C5_RECON_SCAN_MAX_RESULTS) {
                free(state->selected_networks);
                free(state);
                return NULL;
            }
            state->selected_networks[i] = launch->selected_numbers[i];
        }
        state->selected_network_count = launch->selected_count;
    }

    bool ready = true;
    switch(state->mode) {
    case C5ReconModeScanner:
        state->screen = ReconScreenScanStatus;
        state->model_kind = ReconModelScan;
        c5_recon_scan_init(&state->model.scan, launch->min_power_dbm);
        ready = c5_recon_scan_begin(&state->model.scan);
        break;
    case C5ReconModeSnifferStart:
    case C5ReconModeSnifferResume:
        state->screen = ReconScreenSnifferStatus;
        state->model_kind = ReconModelSniffer;
        c5_recon_sniffer_init(&state->model.sniffer);
        break;
    case C5ReconModeSnifferResults:
        state->screen = ReconScreenSnifferResults;
        state->model_kind = ReconModelSniffer;
        c5_recon_sniffer_init(&state->model.sniffer);
        ready = c5_recon_sniffer_begin_results(&state->model.sniffer);
        break;
    case C5ReconModeProbeResults:
        state->screen = ReconScreenProbeResults;
        state->model_kind = ReconModelProbe;
        c5_recon_probe_init(&state->model.probe);
        ready = c5_recon_probe_begin_results(&state->model.probe);
        break;
    }
    if(!ready) {
        switch(state->mode) {
        case C5ReconModeScanner: c5_recon_scan_deinit(&state->model.scan); break;
        case C5ReconModeProbeResults: c5_recon_probe_free(&state->model.probe); break;
        default: c5_recon_sniffer_free(&state->model.sniffer); break;
        }
        free(state->selected_networks);
        free(state);
        return NULL;
    }
    return state;
}

static void recon_leave(void* opaque, const C5HostApiV3* host) {
    ReconState* state = opaque;
    if(!state) return;
    if(!state->cleanup_done && !state->pending_start && !state->preserve_station_selection) {
        if(state->model_kind == ReconModelSniffer || state->model_kind == ReconModelProbe) {
            recon_send(host, "stop\nunselect_stations\nclear_sniffer_results\n");
        } else if(state->command_active) {
            recon_send(host, "stop\n");
        }
    }
    switch(state->model_kind) {
    case ReconModelScan: {
        if(host && host->save_session) {
            const C5ReconScan* scan = &state->model.scan;
            C5ReconTargetSession session = {
                .version = C5_RECON_TARGET_SESSION_VERSION,
                .size = sizeof(C5ReconTargetSession),
                .selected_count = scan->selected_count,
                .selected_numbers = scan->selected_numbers,
                .result_count = scan->count,
                .results = scan->results,
            };
            host->save_session(host->ctx, &session, sizeof(session));
        }
        c5_recon_scan_deinit(&state->model.scan);
        break;
    }
    case ReconModelProbe:
        c5_recon_probe_free(&state->model.probe);
        break;
    case ReconModelSniffer:
        c5_recon_sniffer_free(&state->model.sniffer);
        break;
    }
    c5_recon_clients_free(&state->identity);
    free(state->selected_networks);
    free(state);
}

static void recon_on_bytes(
    void* opaque, const C5HostApiV3* host, const uint8_t* bytes, size_t length) {
    ReconState* state = opaque;
    if(!state || !bytes || !length) return;
    switch(state->screen) {
    case ReconScreenScanStatus:
    case ReconScreenScanResults: {
        uint32_t events = c5_recon_scan_feed(&state->model.scan, bytes, length, state->last_tick);
        if(events & C5ReconScanEventNoMemory) {
            state->memory_error = true;
            recon_status(host, "OOM: scan buffers");
        }
        if(events & C5ReconScanEventStillRunning) {
            state->command_active = false;
            if(state->screen == ReconScreenScanStatus)
                recon_status(host, "Scan still running");
        }
        if(events & C5ReconScanEventError) {
            state->command_active = false;
            state->scan_complete = false;
            recon_status(host, "Scan failed");
        }
        if(state->screen == ReconScreenScanResults) {
            if(events & C5ReconScanEventStillRunning)
                recon_status(host, "Scan running - try again soon");
            else if(events & C5ReconScanEventNoResults)
                recon_status(host, "No scan results");
        }
        if(events & (C5ReconScanEventDone | C5ReconScanEventNoResults)) {
            state->command_active = false;
            if(state->screen == ReconScreenScanStatus) state->scan_complete = true;
        }
        if(events) recon_redraw(host);
        break;
    }
    case ReconScreenSnifferStatus:
    case ReconScreenSnifferResults:
        c5_recon_sniffer_feed(&state->model.sniffer, bytes, length, state->last_tick);
        recon_redraw(host);
        break;
    case ReconScreenSnifferClients:
        c5_recon_clients_feed(&state->identity, bytes, length, state->last_tick);
        recon_redraw(host);
        break;
    case ReconScreenProbeResults:
        c5_recon_probe_feed(&state->model.probe, bytes, length);
        recon_redraw(host);
        break;
    case ReconScreenTerminal:
        break;
    }
}

static void recon_on_line(void* opaque, const C5HostApiV3* host, const char* line) {
    if(!line) return;
    recon_on_bytes(opaque, host, (const uint8_t*)line, strlen(line));
    const uint8_t newline = '\n';
    recon_on_bytes(opaque, host, &newline, 1);
}

static bool recon_show_scan_results(ReconState* state, const C5HostApiV3* host) {
    if(!c5_recon_scan_begin(&state->model.scan)) {
        state->memory_error = true;
        recon_status(host, "OOM: scan buffers");
        return false;
    }
    if(!recon_send(host, "show_scan_results\n")) {
        c5_recon_scan_deinit(&state->model.scan);
        recon_status(host, "Scan command failed");
        return false;
    }
    state->screen = ReconScreenScanResults;
    state->scan_complete = false;
    return true;
}

static bool recon_show_sniffer_results(ReconState* state, const C5HostApiV3* host) {
    if(!c5_recon_sniffer_begin_results(&state->model.sniffer)) {
        state->memory_error = true;
        recon_status(host, "OOM: sniffer buffers");
        return false;
    }
    if(!recon_send(host, "stop\nshow_sniffer_results\n")) {
        c5_recon_sniffer_end_results(&state->model.sniffer);
        recon_status(host, "Sniffer command failed");
        return false;
    }
    state->command_active = false;
    state->screen = ReconScreenSnifferResults;
    state->ap_index = state->client_offset = 0;
    return true;
}

static bool recon_show_sniffer_clients(ReconState* state, const C5HostApiV3* host) {
    c5_recon_clients_begin(&state->identity, state->last_tick);
    if(!recon_send(host, "show_sniffer_clients\n")) {
        c5_recon_clients_free(&state->identity);
        recon_status(host, "Client command failed");
        return false;
    }
    c5_recon_sniffer_end_results(&state->model.sniffer);
    c5_recon_sniffer_clear_selection(&state->model.sniffer);
    state->screen = ReconScreenSnifferClients;
    state->pending_start = false;
    state->identity_cursor = 0;
    state->identity_selected = false;
    return true;
}

static const char* recon_current_mac(const ReconState* state) {
    const C5ReconSnifferState* sniffer = &state->model.sniffer;
    if(!sniffer->aps || !sniffer->clients || state->ap_index >= sniffer->ap_count)
        return NULL;
    const C5ReconSnifferAp* ap = &sniffer->aps[state->ap_index];
    if(state->client_offset >= ap->client_count) return NULL;
    size_t index = ap->client_start + state->client_offset;
    return index < sniffer->client_count ? sniffer->clients[index].mac : NULL;
}

static bool recon_stop(const ReconState* state, const C5HostApiV3* host) {
    if(state->model_kind == ReconModelScan)
        return recon_send(host, "stop\n");
    return recon_send(host, "stop\nunselect_stations\nclear_sniffer_results\n");
}

static C5InputResult recon_on_input(
    void* opaque, const C5HostApiV3* host, const InputEvent* event) {
    ReconState* state = opaque;
    if(!state || !event) return C5InputIgnored;
    if(event->type == InputTypeLong && event->key == InputKeyOk) {
        state->console_visible = !state->console_visible;
        return C5InputToggleConsole;
    }
    if(event->type != InputTypeShort &&
       !((event->type == InputTypeRepeat || event->type == InputTypeLong) &&
         (event->key == InputKeyUp || event->key == InputKeyDown ||
          event->key == InputKeyLeft || event->key == InputKeyRight)))
        return C5InputIgnored;

    if(event->key == InputKeyBack) {
        if(state->screen == ReconScreenScanResults && state->model.scan.selected_count)
            return C5InputConsumed; /* A selected target proceeds to Attacks via Right. */
        state->preserve_station_selection = false;
        state->cleanup_done = recon_stop(state, host);
        if(!state->cleanup_done) recon_status(host, "Stop command failed");
        else state->command_active = false;
        return C5InputSwitchModule;
    }

    switch(state->screen) {
    case ReconScreenScanStatus:
        if(event->key == InputKeyOk) {
            if(!c5_recon_scan_begin(&state->model.scan)) {
                state->memory_error = true;
                recon_status(host, "OOM: scan buffers");
            } else if(!recon_send(host, "scan_networks\n")) {
                recon_status(host, "Scan command failed");
            } else {
                state->command_active = true;
                state->scan_complete = false;
                state->memory_error = false;
            }
        } else if(event->key == InputKeyRight && state->scan_complete &&
                  state->model.scan.count > 0) {
            recon_show_scan_results(state, host);
        }
        break;
    case ReconScreenScanResults:
        if(event->key == InputKeyUp && state->model.scan.visible_index) {
            state->model.scan.visible_index--;
        } else if(event->key == InputKeyDown &&
                  state->model.scan.visible_index + 1 < state->model.scan.visible_count) {
            state->model.scan.visible_index++;
        } else if(event->key == InputKeyOk) {
            const C5ReconScanResult* result =
                c5_recon_scan_visible(&state->model.scan, state->model.scan.visible_index);
            if(result && !result->selected &&
               state->model.scan.selected_count >= C5_RECON_SAFE_SELECTED_NETWORKS) {
                recon_status(host, "Select at most 6 networks");
            } else {
                c5_recon_scan_toggle_visible(&state->model.scan, state->model.scan.visible_index);
            }
        } else if(event->key == InputKeyRight && state->model.scan.selected_count) {
            return C5InputOpenAttacks;
        }
        break;
    case ReconScreenSnifferStatus:
        if(event->key == InputKeyRight && state->model.sniffer.has_data &&
           state->model.sniffer.packet_count >= RECON_SNIFFER_RESULTS_THRESHOLD)
            recon_show_sniffer_results(state, host);
        break;
    case ReconScreenSnifferResults: {
        C5ReconSnifferState* sniffer = &state->model.sniffer;
        if(event->key == InputKeyRight && event->type == InputTypeLong) {
            recon_show_sniffer_clients(state, host);
        } else if(event->key == InputKeyLeft) {
            c5_recon_sniffer_end_results(sniffer);
            c5_recon_sniffer_reset_status(sniffer);
            if(recon_send_start_sniffer(state, host, false)) {
                state->screen = ReconScreenSnifferStatus;
            } else recon_status(host, "Sniffer command failed");
        } else if(event->key == InputKeyRight) {
            if(state->selected_network_count > C5_RECON_SAFE_SELECTED_NETWORKS) {
                recon_status(host, "Rescan: max 6 networks");
            } else if(!state->selected_network_count) {
                recon_status(host, "Select network first");
            } else if(!sniffer->selected_count) {
                recon_status(host, "Pick a client first");
            } else {
                char command[256];
                C5ReconSelectStatus result =
                    c5_recon_sniffer_select_command(sniffer, command, sizeof(command) - 1);
                if(result != C5ReconSelectOk) {
                    recon_status(host, result == C5ReconSelectTooMany ?
                                            "Select at most 13 clients" : "Invalid client selection");
                } else {
                    size_t length = strlen(command);
                    command[length++] = '\n';
                    command[length] = '\0';
                    if(recon_send(host, command)) {
                        state->screen = ReconScreenTerminal;
                        state->preserve_station_selection = true;
                        return C5InputOpenAttacks;
                    }
                    recon_status(host, "Client command failed");
                }
            }
        } else if(event->key == InputKeyOk) {
            const char* mac = recon_current_mac(state);
            if(mac) c5_recon_sniffer_toggle_station(sniffer, mac);
        } else if(event->key == InputKeyUp) {
            if(state->client_offset) state->client_offset--;
            else if(state->ap_index) { state->ap_index--; state->client_offset = 0; }
        } else if(event->key == InputKeyDown && state->ap_index < sniffer->ap_count) {
            const C5ReconSnifferAp* ap = &sniffer->aps[state->ap_index];
            if(state->client_offset + 1 < ap->client_count) state->client_offset++;
            else if(state->ap_index + 1 < sniffer->ap_count) {
                state->ap_index++;
                state->client_offset = 0;
            }
        }
        break;
    }
    case ReconScreenSnifferClients: {
        C5ReconClients* identity = &state->identity;
        if(event->key == InputKeyLeft) {
            if(identity->phase == C5ReconClientsReloadRequired) {
                recon_status(host, "Exit and reload clients");
            } else if(identity->phase == C5ReconClientsStarting ||
               identity->phase == C5ReconClientsActive) {
                bool sent = recon_send(host, "stop\n");
                c5_recon_clients_stop_requested(identity, sent);
            } else {
                /* Do not overlap the two result allocations on a small heap. */
                c5_recon_clients_free(identity);
                state->screen = ReconScreenSnifferResults;
                if(c5_recon_sniffer_begin_results(&state->model.sniffer) &&
                   recon_send(host, "show_sniffer_results\n")) {
                    state->ap_index = state->client_offset = 0;
                    state->memory_error = false;
                } else {
                    c5_recon_sniffer_end_results(&state->model.sniffer);
                    state->memory_error = true;
                    recon_status(host, "Legacy results failed");
                }
            }
        } else if(identity->phase == C5ReconClientsReady) {
            if(event->key == InputKeyUp && state->identity_cursor) {
                state->identity_cursor--;
                state->identity_selected = false;
            } else if(event->key == InputKeyDown &&
                      state->identity_cursor + 1 < identity->client_count) {
                state->identity_cursor++;
                state->identity_selected = false;
            } else if(event->key == InputKeyOk &&
                      state->identity_cursor < identity->client_count) {
                state->identity_selected = !state->identity_selected;
            } else if(event->key == InputKeyRight && state->identity_selected) {
                char command[80];
                if(!c5_recon_clients_command(
                       identity, state->identity_cursor, command, sizeof(command) - 1)) {
                    recon_status(host, "Invalid client identity");
                } else {
                    size_t used = strlen(command);
                    command[used++] = '\n';
                    command[used] = '\0';
                    if(recon_send(host, command)) {
                        c5_recon_clients_start_sent(
                            identity, state->identity_cursor, state->last_tick);
                        state->identity_selected = false;
                    } else {
                        identity->phase = C5ReconClientsReloadRequired;
                        snprintf(identity->error, sizeof(identity->error),
                                 "Start TX failed; reload");
                    }
                }
            }
        }
        break;
    }
    case ReconScreenProbeResults: {
        C5ReconProbeState* probe = &state->model.probe;
        if(event->key == InputKeyLeft) {
            c5_recon_probe_free(probe);
            c5_recon_sniffer_init(&state->model.sniffer);
            state->model_kind = ReconModelSniffer;
            if(c5_recon_sniffer_begin_results(&state->model.sniffer) &&
               recon_send(host, "show_sniffer_results\n")) {
                state->screen = ReconScreenSnifferResults;
                state->ap_index = state->client_offset = 0;
            } else {
                c5_recon_sniffer_end_results(&state->model.sniffer);
                state->screen = ReconScreenSnifferResults;
                state->memory_error = true;
                recon_status(host, "OOM: sniffer buffers");
            }
        } else if(event->key == InputKeyUp) {
            if(state->client_offset) state->client_offset--;
            else if(state->ap_index) { state->ap_index--; state->client_offset = 0; }
        } else if(event->key == InputKeyDown && state->ap_index < probe->ssid_count) {
            const C5ReconProbeSsid* ssid = &probe->ssids[state->ap_index];
            if(state->client_offset + 1 < ssid->client_count) state->client_offset++;
            else if(state->ap_index + 1 < probe->ssid_count) {
                state->ap_index++;
                state->client_offset = 0;
            }
        }
        break;
    }
    case ReconScreenTerminal:
        break;
    }
    recon_redraw(host);
    return C5InputConsumed;
}

static void recon_on_text_input(
    void* state, const C5HostApiV3* host, bool accepted, const char* text) {
    (void)state;
    (void)host;
    (void)accepted;
    (void)text;
}

static void recon_draw_scan_status(ReconState* state, Canvas* canvas) {
    const C5ReconScan* scan = &state->model.scan;
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "WiFi Scan");
    canvas_draw_str(canvas, 72, 12, scan->loading ? "Scanning..." :
                    scan->count ? "Finished" : state->scan_complete ? "No networks" : "Waiting...");
    if(state->memory_error) {
        canvas_draw_str(canvas, 2, 36, "OOM: scan buffers");
        return;
    }
    canvas_set_font(canvas, FontPrimary);
    char line[32];
    snprintf(line, sizeof(line), "Total: %u", (unsigned)scan->count);
    canvas_draw_str(canvas, 26, 28, line);
    canvas_set_font(canvas, FontSecondary);
    snprintf(line, sizeof(line), "2.4G:%u  5G:%u", (unsigned)scan->band_24_count,
             (unsigned)scan->band_5_count);
    canvas_draw_str(canvas, 25, 42, line);
    snprintf(line, sizeof(line), "Open:%u Hidden:%u", (unsigned)scan->open_count,
             (unsigned)scan->hidden_count);
    canvas_draw_str(canvas, 23, 54, line);
    if(state->scan_complete && scan->count) canvas_draw_str(canvas, 114, 62, "->");
}

static void recon_draw_scan_results(ReconState* state, Canvas* canvas) {
    const C5ReconScan* scan = &state->model.scan;
    canvas_set_font(canvas, FontSecondary);
    if(!scan->visible_count) {
        canvas_draw_str(canvas, 2, 20, scan->loading ? "Loading..." : "No results");
    } else {
        const C5ReconScanResult* result = c5_recon_scan_visible(scan, scan->visible_index);
        if(result) {
            char line[64];
            canvas_draw_str(canvas, 2, 12, ">");
            snprintf(line, sizeof(line), "%u%s", (unsigned)result->number,
                     result->selected ? "*" : "");
            if(state->field_mask & C5ReconFieldSsid) {
                size_t used = strlen(line);
                snprintf(line + used, sizeof(line) - used, " %s", result->ssid);
            }
            if(state->field_mask & C5ReconFieldVendor) {
                const char* vendor = c5_recon_scan_vendor(scan, result->bssid);
                if(vendor) {
                    size_t used = strlen(line);
                    snprintf(line + used, sizeof(line) - used, " (%s)", vendor);
                }
            }
            line[21] = '\0';
            canvas_draw_str(canvas, 12, 12, line);
            if(state->field_mask & C5ReconFieldBssid) {
                bool present = false;
                for(size_t i = 0; i < 6; i++) present = present || result->bssid[i];
                if(present) {
                    snprintf(line, sizeof(line), "%02X:%02X:%02X:%02X:%02X:%02X",
                             result->bssid[0], result->bssid[1], result->bssid[2],
                             result->bssid[3], result->bssid[4], result->bssid[5]);
                    canvas_draw_str(canvas, 12, 22, line);
                }
            }
            line[0] = '\0';
            if(state->field_mask & C5ReconFieldChannel)
                snprintf(line, sizeof(line), "CH%u", (unsigned)result->channel);
            if(state->field_mask & C5ReconFieldBand) {
                const char* band = result->band == C5ReconBand24 ? "2.4G" :
                                   result->band == C5ReconBand5 ? "5G" : "?";
                size_t used = strlen(line);
                snprintf(line + used, sizeof(line) - used, "%s%s", used ? " " : "", band);
            }
            if(line[0]) canvas_draw_str(canvas, 12, 32, line);
            line[0] = '\0';
            if(state->field_mask & C5ReconFieldSecurity)
                snprintf(line, sizeof(line), "%s", result->security);
            if((state->field_mask & C5ReconFieldPower) && result->power_valid) {
                size_t used = strlen(line);
                snprintf(line + used, sizeof(line) - used, "%s%d dBm", used ? " " : "",
                         (int)result->power_dbm);
            }
            if(line[0]) canvas_draw_str(canvas, 12, 42, line);
        }
    }
    char footer[40];
    if(scan->selected_count)
        snprintf(footer, sizeof(footer), "Right: actions (%u)", (unsigned)scan->selected_count);
    else
        snprintf(footer, sizeof(footer), "[Results] Selected: 0");
    canvas_draw_str(canvas, 2, 62, footer);
}

static void recon_draw_sniffer_status(ReconState* state, Canvas* canvas) {
    const C5ReconSnifferState* sniffer = &state->model.sniffer;
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "Sniffer");
    canvas_draw_str(canvas, 70, 12, sniffer->running ?
                    sniffer->scan_done ? "Monitoring" : "Scanning..." :
                    sniffer->has_data ? "Done" : "Waiting...");
    canvas_set_font(canvas, FontPrimary);
    char line[32];
    snprintf(line, sizeof(line), "Packets: %lu", (unsigned long)sniffer->packet_count);
    canvas_draw_str(canvas, 20, 28, line);
    canvas_set_font(canvas, FontSecondary);
    if(sniffer->networks) snprintf(line, sizeof(line), "Networks: %lu", (unsigned long)sniffer->networks);
    else snprintf(line, sizeof(line), "Networks: --");
    canvas_draw_str(canvas, 23, 42, line);
    snprintf(line, sizeof(line), "Mode: %s", sniffer->mode[0] ? sniffer->mode : "?");
    canvas_draw_str(canvas, 30, 54, line);
    if(strcmp(sniffer->mode, "NOSCAN") == 0)
        canvas_draw_str(canvas, 2, 62, "All networks");
    if(sniffer->has_data && sniffer->packet_count >= RECON_SNIFFER_RESULTS_THRESHOLD)
        canvas_draw_str(canvas, 114, 62, "->");
}

static void recon_draw_sniffer_results(ReconState* state, Canvas* canvas) {
    const C5ReconSnifferState* sniffer = &state->model.sniffer;
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "Sniffer");
    char line[40];
    snprintf(line, sizeof(line), "APs:%u Cli:%u Sel:%u", (unsigned)sniffer->ap_count,
             (unsigned)sniffer->client_count, (unsigned)sniffer->selected_count);
    canvas_draw_str(canvas, 40, 12, line);
    if(state->memory_error && !sniffer->aps) {
        canvas_draw_str(canvas, 15, 36, "OOM: sniffer buffers");
        return;
    }
    if(!sniffer->ap_count) {
        canvas_draw_str(canvas, 15, 36, sniffer->results_loading ? "Loading..." : "No clients yet");
        return;
    }
    if(state->ap_index >= sniffer->ap_count) state->ap_index = sniffer->ap_count - 1;
    const C5ReconSnifferAp* ap = &sniffer->aps[state->ap_index];
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 30, ap->ssid);
    canvas_set_font(canvas, FontSecondary);
    snprintf(line, sizeof(line), "CH%u  Client: %u/%u", (unsigned)ap->channel,
             (unsigned)(ap->client_count ? state->client_offset + 1 : 0),
             (unsigned)ap->client_count);
    canvas_draw_str(canvas, 2, 44, line);
    const char* mac = recon_current_mac(state);
    if(mac) {
        snprintf(line, sizeof(line), "%c %s",
                 c5_recon_sniffer_station_selected(sniffer, mac) ? '*' : ' ', mac);
        canvas_draw_str(canvas, 2, 54, line);
    }
    canvas_draw_str(canvas, 2, 62, "Hold R: clients");
    if(sniffer->selected_count && state->selected_network_count)
        canvas_draw_str(canvas, 114, 62, "->");
}

static void recon_draw_sniffer_clients(ReconState* state, Canvas* canvas) {
    const C5ReconClients* identity = &state->identity;
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "Sniffer clients v1");
    if(identity->phase == C5ReconClientsLoading) {
        canvas_draw_str(canvas, 2, 36, "Loading snapshot...");
        canvas_draw_str(canvas, 2, 62, "Left: legacy");
        return;
    }
    if(identity->phase == C5ReconClientsError ||
       identity->phase == C5ReconClientsUnsupported ||
       identity->phase == C5ReconClientsReloadRequired) {
        canvas_draw_str(canvas, 2, 34, identity->error);
        canvas_draw_str(canvas, 2, 62, identity->phase == C5ReconClientsReloadRequired ?
                        "Back: exit/reload" : "Left: legacy / Back");
        return;
    }
    if(identity->phase == C5ReconClientsStarting || identity->phase == C5ReconClientsActive) {
        canvas_draw_str(canvas, 2, 30, identity->phase == C5ReconClientsStarting ?
                        "Starting station..." : "Station deauth active");
        canvas_draw_str(canvas, 2, 44, identity->pending_bssid);
        canvas_draw_str(canvas, 2, 56, identity->pending_station);
        canvas_draw_str(canvas, 2, 62, "Left/Back: request stop");
        return;
    }
    if(identity->client_count == 0) {
        canvas_draw_str(canvas, 2, 36, "No clients in snapshot");
        canvas_draw_str(canvas, 2, 62, "Left: legacy");
        return;
    }
    if(state->identity_cursor >= identity->client_count) state->identity_cursor = 0;
    const C5ReconIdentityClient* client = &identity->clients[state->identity_cursor];
    const C5ReconIdentityAp* ap = &identity->aps[client->ap_index];
    char line[40];
    snprintf(line, sizeof(line), "Client %u/%u CH%u", (unsigned)(state->identity_cursor + 1),
             (unsigned)identity->client_count, (unsigned)ap->channel);
    canvas_draw_str(canvas, 2, 24, line);
    canvas_draw_str(canvas, 2, 34, ap->ssid[0] ? ap->ssid : "<hidden>");
    canvas_draw_str(canvas, 2, 44, ap->bssid);
    snprintf(line, sizeof(line), "%c%s", state->identity_selected ? '*' : ' ', client->station);
    canvas_draw_str(canvas, 2, 54, line);
    canvas_draw_str(canvas, 2, 62, "OK pick  R start");
}

static void recon_draw_probe_results(ReconState* state, Canvas* canvas) {
    const C5ReconProbeState* probe = &state->model.probe;
    canvas_set_font(canvas, FontSecondary);
    canvas_draw_str(canvas, 2, 12, "Probes");
    char line[40];
    snprintf(line, sizeof(line), "SSIDs:%u Req:%u", (unsigned)probe->ssid_count,
             (unsigned)probe->total);
    canvas_draw_str(canvas, 55, 12, line);
    if(!probe->ssid_count) {
        canvas_draw_str(canvas, 15, 36, probe->results_loading ? "Loading..." : "No probes found");
        return;
    }
    if(state->ap_index >= probe->ssid_count) state->ap_index = probe->ssid_count - 1;
    const C5ReconProbeSsid* ssid = &probe->ssids[state->ap_index];
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str(canvas, 2, 30, ssid->ssid);
    canvas_set_font(canvas, FontSecondary);
    snprintf(line, sizeof(line), "Client: %u/%u",
             (unsigned)(ssid->client_count ? state->client_offset + 1 : 0),
             (unsigned)ssid->client_count);
    canvas_draw_str(canvas, 2, 44, line);
    size_t client = ssid->client_start + state->client_offset;
    if(state->client_offset < ssid->client_count && client < probe->client_count)
        canvas_draw_str(canvas, 2, 54, probe->clients[client].mac);
}

static void recon_draw(void* opaque, const C5HostApiV3* host, Canvas* canvas) {
    ReconState* state = opaque;
    (void)host;
    if(!state || !canvas) return;
    canvas_set_color(canvas, ColorBlack);
    switch(state->screen) {
    case ReconScreenScanStatus: recon_draw_scan_status(state, canvas); break;
    case ReconScreenScanResults: recon_draw_scan_results(state, canvas); break;
    case ReconScreenSnifferStatus: recon_draw_sniffer_status(state, canvas); break;
    case ReconScreenSnifferResults: recon_draw_sniffer_results(state, canvas); break;
    case ReconScreenSnifferClients: recon_draw_sniffer_clients(state, canvas); break;
    case ReconScreenProbeResults: recon_draw_probe_results(state, canvas); break;
    case ReconScreenTerminal:
        canvas_set_font(canvas, FontSecondary);
        canvas_draw_str(canvas, 2, 12, "Serial output");
        break;
    }
}

static void recon_tick(void* opaque, const C5HostApiV3* host, uint32_t now_ticks) {
    ReconState* state = opaque;
    if(!state) return;
    state->last_tick = now_ticks;
    if(state->screen == ReconScreenSnifferClients) {
        C5ReconClientsTick result = c5_recon_clients_tick(&state->identity, now_ticks);
        if(result == C5ReconClientsStartTimeout) {
            bool sent = recon_send(host, "stop\n");
            c5_recon_clients_stop_requested(&state->identity, sent);
            recon_redraw(host);
        } else if(result == C5ReconClientsListTimeout) {
            recon_redraw(host);
        }
    }
    if(!state->pending_start) return;
    bool sent = false;
    switch(state->mode) {
    case C5ReconModeScanner:
        sent = recon_send(host, "scan_networks\n");
        state->command_active = sent;
        break;
    case C5ReconModeSnifferStart:
        sent = recon_send_start_sniffer(state, host, false);
        break;
    case C5ReconModeSnifferResume:
        sent = recon_send_start_sniffer(state, host, true);
        break;
    case C5ReconModeSnifferResults:
        sent = recon_send(host, "show_sniffer_results\n");
        break;
    case C5ReconModeProbeResults:
        sent = recon_send(host, "show_probes\n");
        break;
    }
    if(sent) state->pending_start = false;
    else recon_status(host, "Recon command failed");
}

static const C5ModuleV3 c5_recon_module = {
    .version = C5_MODULE_API_VERSION,
    .size = sizeof(C5ModuleV3),
    .enter = recon_enter,
    .leave = recon_leave,
    .on_line = recon_on_line,
    .on_bytes = recon_on_bytes,
    .on_input = recon_on_input,
    .on_text_input = recon_on_text_input,
    .draw = recon_draw,
    .tick = recon_tick,
};

static const FlipperAppPluginDescriptor c5_recon_descriptor = {
    .appid = C5_MODULE_APP_ID,
    .ep_api_version = C5_MODULE_API_VERSION,
    .entry_point = &c5_recon_module,
};

const FlipperAppPluginDescriptor* lab_c5_recon_plugin_ep(void) {
    return &c5_recon_descriptor;
}
