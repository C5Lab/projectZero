#include "recon_sniffer_probe.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void recon_trim(char* text) {
    if(!text) return;
    char* start = text;
    while(*start && isspace((unsigned char)*start)) start++;
    char* end = start + strlen(start);
    while(end > start && isspace((unsigned char)end[-1])) end--;
    size_t length = (size_t)(end - start);
    if(start != text) memmove(text, start, length);
    text[length] = '\0';
}

static void recon_copy(char* out, size_t capacity, const char* source, size_t length) {
    if(!out || !capacity || !source) return;
    if(length >= capacity) length = capacity - 1;
    memcpy(out, source, length);
    out[length] = '\0';
}

static bool recon_prefix_uint32(const char* line, const char* prefix, uint32_t* value) {
    if(!line || !prefix || !value) return false;
    size_t prefix_length = strlen(prefix);
    if(strncmp(line, prefix, prefix_length) != 0) return false;
    const char* digits = line + prefix_length;
    while(*digits == ' ') digits++;
    if(!isdigit((unsigned char)*digits)) return false;
    char* end = NULL;
    unsigned long parsed = strtoul(digits, &end, 10);
    if(end == digits) return false;
    *value = parsed > UINT32_MAX ? UINT32_MAX : (uint32_t)parsed;
    return true;
}

static bool recon_station_mac_valid(const char* mac) {
    if(!mac || strlen(mac) != 17) return false;
    for(size_t i = 0; i < 17; i++) {
        if(i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
            if(mac[i] != ':') return false;
        } else if(!isxdigit((unsigned char)mac[i])) {
            return false;
        }
    }
    return true;
}

void c5_recon_sniffer_init(C5ReconSnifferState* state) {
    if(state) memset(state, 0, sizeof(*state));
}

void c5_recon_sniffer_reset_status(C5ReconSnifferState* state) {
    if(!state) return;
    state->packet_count = 0;
    state->networks = 0;
    state->last_update_tick = 0;
    state->mode[0] = '\0';
    state->running = false;
    state->has_data = false;
    state->scan_done = false;
    state->line_length = 0;
    state->discard_line = false;
}

void c5_recon_sniffer_clear_selection(C5ReconSnifferState* state) {
    if(!state) return;
    state->selected_count = 0;
    memset(state->selected_macs, 0, sizeof(state->selected_macs));
}

void c5_recon_sniffer_end_results(C5ReconSnifferState* state) {
    if(!state) return;
    free(state->aps);
    free(state->clients);
    state->aps = NULL;
    state->clients = NULL;
    state->ap_count = 0;
    state->client_count = 0;
    state->results_mode = false;
    state->results_loading = false;
    state->line_length = 0;
    state->discard_line = false;
}

bool c5_recon_sniffer_begin_results(C5ReconSnifferState* state) {
    if(!state) return false;
    c5_recon_sniffer_end_results(state);
    c5_recon_sniffer_clear_selection(state);
    state->aps = calloc(C5_RECON_SNIFFER_MAX_APS, sizeof(*state->aps));
    state->clients = calloc(C5_RECON_SNIFFER_MAX_CLIENTS, sizeof(*state->clients));
    if(!state->aps || !state->clients) {
        c5_recon_sniffer_end_results(state);
        return false;
    }
    state->results_mode = true;
    state->results_loading = true;
    return true;
}

void c5_recon_sniffer_free(C5ReconSnifferState* state) {
    if(!state) return;
    c5_recon_sniffer_end_results(state);
    c5_recon_sniffer_clear_selection(state);
    c5_recon_sniffer_reset_status(state);
}

static bool recon_sniffer_parse_header(const char* line, C5ReconSnifferAp* entry) {
    if(!line || !entry) return false;
    const char* final_marker = NULL;
    unsigned long channel = 0;
    unsigned long expected = 0;
    /* JanOS prints "<SSID>, CH<channel>: <clients><optional suffix>". Search
     * every complete separator so SSIDs may themselves contain CH, ':' or ','. */
    for(const char* marker = line; *marker; marker++) {
        if(strncmp(marker, ", CH", 4) != 0) continue;
        const char* digits = marker + 4;
        if(!isdigit((unsigned char)*digits)) continue;
        char* end = NULL;
        unsigned long parsed_channel = strtoul(digits, &end, 10);
        if(end[0] != ':' || end[1] != ' ') continue;
        digits = end + 2;
        if(!isdigit((unsigned char)*digits)) continue;
        unsigned long parsed_expected = strtoul(digits, &end, 10);
        if(*end && !isspace((unsigned char)*end)) continue;
        final_marker = marker;
        channel = parsed_channel;
        expected = parsed_expected;
    }
    if(!final_marker) return false;
    memset(entry, 0, sizeof(*entry));
    recon_copy(entry->ssid, sizeof(entry->ssid), line, (size_t)(final_marker - line));
    recon_trim(entry->ssid);
    if(!entry->ssid[0]) recon_copy(entry->ssid, sizeof(entry->ssid), "<hidden>", 8);
    entry->channel = channel > UINT8_MAX ? UINT8_MAX : (uint8_t)channel;
    entry->expected_count = expected > UINT16_MAX ? UINT16_MAX : (uint16_t)expected;
    return true;
}

static bool recon_sniffer_parse_mac(const char* line, char out[C5_RECON_MAC_CAPACITY]) {
    if(!line || !out) return false;
    char buffer[64];
    recon_copy(buffer, sizeof(buffer), line, strlen(line));
    recon_trim(buffer);
    const char* start = buffer;
    while(*start && !isxdigit((unsigned char)*start)) start++;
    if(!*start) return false;
    const char* end = start;
    while(*end && !isspace((unsigned char)*end) && *end != ',' && *end != ')' && *end != '(') {
        end++;
    }
    recon_copy(out, C5_RECON_MAC_CAPACITY, start, (size_t)(end - start));
    return recon_station_mac_valid(out);
}

static void recon_sniffer_process_line(
    C5ReconSnifferState* state, const char* line, uint32_t now_ticks) {
    if(state->results_mode && state->aps && state->clients) {
        if(line[0] == '>') {
            state->results_loading = false;
            return;
        }
        C5ReconSnifferAp entry;
        if(recon_sniffer_parse_header(line, &entry)) {
            if(state->ap_count < C5_RECON_SNIFFER_MAX_APS) {
                entry.client_start = (uint16_t)state->client_count;
                state->aps[state->ap_count++] = entry;
                state->results_loading = false;
            }
            return;
        }
        char mac[C5_RECON_MAC_CAPACITY];
        if(state->ap_count && recon_sniffer_parse_mac(line, mac)) {
            if(state->client_count < C5_RECON_SNIFFER_MAX_CLIENTS) {
                C5ReconClient* client = &state->clients[state->client_count++];
                recon_copy(client->mac, sizeof(client->mac), mac, strlen(mac));
                C5ReconSnifferAp* last = &state->aps[state->ap_count - 1];
                last->client_count++;
                if(last->expected_count < last->client_count) {
                    last->expected_count = last->client_count;
                }
                state->results_loading = false;
            }
            return;
        }
    }

    uint32_t value = 0;
    if(recon_prefix_uint32(line, "Sniffer packet count:", &value)) {
        state->packet_count = value;
        state->has_data = true;
        state->running = true;
        state->last_update_tick = now_ticks;
        return;
    }
    if(recon_prefix_uint32(line, "WiFi scan completed. Found ", &value) ||
       recon_prefix_uint32(line, "Processing ", &value) ||
       recon_prefix_uint32(line, "Retrieved ", &value)) {
        state->networks = value;
        state->running = true;
        return;
    }
    if(strstr(line, "Starting sniffer using existing scan results")) {
        recon_copy(state->mode, sizeof(state->mode), "NOSCAN", 6);
        state->running = true;
        state->scan_done = true;
        state->last_update_tick = now_ticks;
        return;
    }
    const char* mode = strstr(line, "Starting sniffer in ");
    if(mode) {
        mode += strlen("Starting sniffer in ");
        size_t length = 0;
        while(mode[length] && !isspace((unsigned char)mode[length]) &&
              length < sizeof(state->mode) - 1) {
            length++;
        }
        if(length) recon_copy(state->mode, sizeof(state->mode), mode, length);
        state->running = true;
        state->scan_done = false;
        state->packet_count = 0;
        state->has_data = false;
        state->last_update_tick = now_ticks;
        return;
    }
    if(strstr(line, "Sniffer started") || strstr(line, "Starting background WiFi scan")) {
        state->running = true;
        state->last_update_tick = now_ticks;
        return;
    }
    if(strstr(line, "Sniffer: Now monitoring") || strstr(line, "Sniffer: Scan complete")) {
        state->scan_done = true;
        state->running = true;
        state->last_update_tick = now_ticks;
        return;
    }
    if(strstr(line, "Sniffer stopped")) {
        state->running = false;
        state->last_update_tick = now_ticks;
    }
}

void c5_recon_sniffer_feed(
    C5ReconSnifferState* state, const uint8_t* bytes, size_t length, uint32_t now_ticks) {
    if(!state || !bytes) return;
    for(size_t i = 0; i < length; i++) {
        char ch = (char)bytes[i];
        if(ch == '\r') continue;
        if(ch == '\n') {
            if(!state->discard_line && state->line_length) {
                state->line[state->line_length] = '\0';
                recon_sniffer_process_line(state, state->line, now_ticks);
            }
            state->line_length = 0;
            state->discard_line = false;
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

bool c5_recon_sniffer_station_selected(const C5ReconSnifferState* state, const char* mac) {
    if(!state || !mac) return false;
    for(size_t i = 0; i < state->selected_count; i++) {
        if(strcmp(state->selected_macs[i], mac) == 0) return true;
    }
    return false;
}

bool c5_recon_sniffer_toggle_station(C5ReconSnifferState* state, const char* mac) {
    if(!state || !recon_station_mac_valid(mac)) return false;
    for(size_t i = 0; i < state->selected_count; i++) {
        if(strcmp(state->selected_macs[i], mac) == 0) {
            for(size_t j = i; j + 1 < state->selected_count; j++) {
                memcpy(state->selected_macs[j], state->selected_macs[j + 1], C5_RECON_MAC_CAPACITY);
            }
            state->selected_count--;
            state->selected_macs[state->selected_count][0] = '\0';
            return true;
        }
    }
    if(state->selected_count >= C5_RECON_SELECTED_STATIONS_MAX) return false;
    recon_copy(state->selected_macs[state->selected_count], C5_RECON_MAC_CAPACITY, mac, 17);
    state->selected_count++;
    return true;
}

C5ReconSelectStatus c5_recon_sniffer_select_command(
    const C5ReconSnifferState* state, char* out, size_t out_capacity) {
    if(!state || !out || !state->selected_count) return C5ReconSelectNoStations;
    if(state->selected_count > C5_RECON_STATIONS_WIRE_MAX) return C5ReconSelectTooMany;
    const char prefix[] = "select_stations";
    const size_t required = sizeof(prefix) - 1 + state->selected_count * 18 + 1;
    if(required > out_capacity) return C5ReconSelectBufferTooSmall;
    for(size_t i = 0; i < state->selected_count; i++) {
        if(!recon_station_mac_valid(state->selected_macs[i])) {
            return C5ReconSelectInvalidMac;
        }
    }
    size_t used = sizeof(prefix) - 1;
    memcpy(out, prefix, used);
    for(size_t i = 0; i < state->selected_count; i++) {
        out[used++] = ' ';
        memcpy(out + used, state->selected_macs[i], 17);
        used += 17;
    }
    out[used] = '\0';
    return C5ReconSelectOk;
}

void c5_recon_probe_init(C5ReconProbeState* state) {
    if(state) memset(state, 0, sizeof(*state));
}

void c5_recon_probe_free(C5ReconProbeState* state) {
    if(!state) return;
    free(state->ssids);
    free(state->clients);
    state->ssids = NULL;
    state->clients = NULL;
    state->ssid_count = 0;
    state->client_count = 0;
    state->total = 0;
    state->results_loading = false;
    state->line_length = 0;
    state->discard_line = false;
}

bool c5_recon_probe_begin_results(C5ReconProbeState* state) {
    if(!state) return false;
    c5_recon_probe_free(state);
    state->ssids = calloc(C5_RECON_PROBE_MAX_SSIDS, sizeof(*state->ssids));
    state->clients = calloc(C5_RECON_PROBE_MAX_CLIENTS, sizeof(*state->clients));
    if(!state->ssids || !state->clients) {
        c5_recon_probe_free(state);
        return false;
    }
    state->results_loading = true;
    return true;
}

static void recon_probe_process_line(C5ReconProbeState* state, const char* line) {
    if(!state->ssids || !state->clients) return;
    uint32_t total = 0;
    if(recon_prefix_uint32(line, "Probe requests:", &total)) {
        state->total = total;
        return;
    }
    if(line[0] == '>' || line[0] == '\0') {
        state->results_loading = false;
        return;
    }
    /* JanOS appends the station MAC as the final " (<MAC>)". Parentheses
     * earlier in the line belong to the SSID. */
    const char* open = strrchr(line, '(');
    if(!open || open == line || open[-1] != ' ') return;
    const char* close = strchr(open + 1, ')');
    if(!close || close - open != 18) return;
    for(const char* suffix = close + 1; *suffix; suffix++) {
        if(!isspace((unsigned char)*suffix)) return;
    }

    char ssid[33];
    recon_copy(ssid, sizeof(ssid), line, (size_t)(open - line));
    recon_trim(ssid);
    if(!ssid[0]) recon_copy(ssid, sizeof(ssid), "<hidden>", 8);
    char mac[C5_RECON_MAC_CAPACITY];
    recon_copy(mac, sizeof(mac), open + 1, 17);
    if(!recon_station_mac_valid(mac)) return;

    C5ReconProbeSsid* entry = NULL;
    for(size_t i = 0; i < state->ssid_count; i++) {
        if(strcmp(state->ssids[i].ssid, ssid) == 0) {
            entry = &state->ssids[i];
            break;
        }
    }
    if(!entry && state->ssid_count < C5_RECON_PROBE_MAX_SSIDS) {
        entry = &state->ssids[state->ssid_count++];
        memset(entry, 0, sizeof(*entry));
        recon_copy(entry->ssid, sizeof(entry->ssid), ssid, strlen(ssid));
        entry->client_start = (uint16_t)state->client_count;
    }
    if(!entry) return;
    if(state->client_count < C5_RECON_PROBE_MAX_CLIENTS) {
        size_t insert_at = (size_t)entry->client_start + entry->client_count;
        if(insert_at < state->client_count) {
            memmove(
                &state->clients[insert_at + 1],
                &state->clients[insert_at],
                (state->client_count - insert_at) * sizeof(*state->clients));
            for(size_t i = 0; i < state->ssid_count; i++) {
                if(&state->ssids[i] != entry && state->ssids[i].client_start >= insert_at) {
                    state->ssids[i].client_start++;
                }
            }
        }
        C5ReconClient* client = &state->clients[insert_at];
        recon_copy(client->mac, sizeof(client->mac), mac, strlen(mac));
        state->client_count++;
        entry->client_count++;
        if(entry->expected_count < entry->client_count) {
            entry->expected_count = entry->client_count;
        }
    } else if(entry->expected_count < UINT16_MAX) {
        entry->expected_count++;
    }
    state->results_loading = false;
}

void c5_recon_probe_feed(C5ReconProbeState* state, const uint8_t* bytes, size_t length) {
    if(!state || !bytes) return;
    for(size_t i = 0; i < length; i++) {
        char ch = (char)bytes[i];
        if(ch == '\r') continue;
        if(ch == '\n') {
            if(!state->discard_line) {
                state->line[state->line_length] = '\0';
                recon_probe_process_line(state, state->line);
            }
            state->line_length = 0;
            state->discard_line = false;
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
