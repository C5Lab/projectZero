#include "recon_sniffer_clients.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* JanOS show_sniffer_clients emits flat, versioned JSON objects. The parser
 * validates whole objects; searching for field substrings would accept a
 * console line or an SSID containing protocol-looking text. */
typedef struct {
    char key[24];
    char value[72];
    bool quoted;
} C5ReconJsonField;

static const char* skip_space(const char* text) {
    while(isspace((unsigned char)*text)) text++;
    return text;
}

static const char* parse_string(const char* text, char* out, size_t capacity) {
    if(*text++ != '"') return NULL;
    size_t length = 0;
    while(*text && *text != '"') {
        /* JanOS identity fields contain only ASCII identifiers and hex.
         * Escapes and control bytes are outside this wire contract. */
        if((unsigned char)*text < 32 || (unsigned char)*text > 126 || *text == '\\' ||
           length + 1 >= capacity)
            return NULL;
        out[length++] = *text++;
    }
    if(*text != '"') return NULL;
    out[length] = '\0';
    return text + 1;
}

static int parse_object(const char* text, C5ReconJsonField fields[12]) {
    const char* at = skip_space(text);
    if(*at++ != '{') return -1;
    int count = 0;
    for(;;) {
        at = skip_space(at);
        if(*at == '}') return *skip_space(at + 1) == '\0' ? count : -1;
        if(count == 12) return -1;
        C5ReconJsonField* field = &fields[count];
        at = parse_string(at, field->key, sizeof(field->key));
        if(!at || *(at = skip_space(at)) != ':') return -1;
        for(int previous = 0; previous < count; previous++)
            if(strcmp(fields[previous].key, field->key) == 0) return -1;
        at = skip_space(at + 1);
        field->quoted = *at == '"';
        if(field->quoted) {
            at = parse_string(at, field->value, sizeof(field->value));
            if(!at) return -1;
        } else {
            size_t length = 0;
            while(*at >= '0' && *at <= '9') {
                if(length + 1 >= sizeof(field->value)) return -1;
                field->value[length++] = *at++;
            }
            if(!length || (length > 1 && field->value[0] == '0')) return -1;
            field->value[length] = '\0';
        }
        count++;
        at = skip_space(at);
        if(*at == '}') return *skip_space(at + 1) == '\0' ? count : -1;
        if(*at++ != ',' || *skip_space(at) == '}') return -1;
    }
}

static const char* string_field(
    const C5ReconJsonField* fields, int count, const char* key) {
    for(int i = 0; i < count; i++)
        if(fields[i].quoted && strcmp(fields[i].key, key) == 0) return fields[i].value;
    return NULL;
}

static bool number_field(
    const C5ReconJsonField* fields, int count, const char* key, unsigned maximum,
    unsigned* out) {
    for(int i = 0; i < count; i++) {
        if(fields[i].quoted || strcmp(fields[i].key, key) != 0) continue;
        const char* digits = fields[i].value;
        unsigned value = 0;
        for(size_t j = 0; digits[j]; j++) {
            unsigned digit = (unsigned)(digits[j] - '0');
            if(digit > maximum || value > (maximum - digit) / 10) return false;
            value = value * 10 + digit;
        }
        if(value > maximum) return false;
        *out = value;
        return true;
    }
    return false;
}

static bool normalize_mac(const char* text, char out[18]) {
    if(!text || strlen(text) != 17) return false;
    unsigned first = 0;
    bool nonzero = false;
    for(size_t i = 0; i < 17; i++) {
        if(i == 2 || i == 5 || i == 8 || i == 11 || i == 14) {
            if(text[i] != ':') return false;
            out[i] = ':';
        } else {
            if(!isxdigit((unsigned char)text[i])) return false;
            out[i] = (char)toupper((unsigned char)text[i]);
            if(out[i] != '0') nonzero = true;
            if(i == 1) first = (unsigned)(isdigit((unsigned char)out[0]) ?
                                           out[0] - '0' : out[0] - 'A' + 10) * 16 +
                               (unsigned)(isdigit((unsigned char)out[1]) ?
                                              out[1] - '0' : out[1] - 'A' + 10);
        }
    }
    out[17] = '\0';
    return nonzero && !(first & 1u);
}

static void set_phase_error(C5ReconClients* state, C5ReconClientsPhase phase, const char* text) {
    state->phase = phase;
    snprintf(state->error, sizeof(state->error), "%s", text);
}

static int find_ap(const C5ReconClients* state, const char* bssid) {
    for(size_t i = 0; i < state->ap_count; i++)
        if(strcmp(state->aps[i].bssid, bssid) == 0) return (int)i;
    return -1;
}

void c5_recon_clients_init(C5ReconClients* state) {
    if(state) memset(state, 0, sizeof(*state));
}

void c5_recon_clients_free(C5ReconClients* state) {
    if(!state) return;
    free(state->aps);
    free(state->clients);
    memset(state, 0, sizeof(*state));
}

void c5_recon_clients_begin(C5ReconClients* state, uint32_t now_ticks) {
    if(!state) return;
    c5_recon_clients_free(state);
    state->phase = C5ReconClientsLoading;
    state->started_tick = state->last_record_tick = now_ticks;
}

static void process_loading(C5ReconClients* state, const C5ReconJsonField* fields, int count,
                            const char* record, uint32_t now_ticks) {
    unsigned aps = 0, clients = 0;
    if(strcmp(record, "sniffer_clients") == 0) {
        const char* reason = string_field(fields, count, "reason");
        set_phase_error(state, C5ReconClientsError, reason ? reason : "Snapshot refused");
        return;
    }
    if(strcmp(record, "sniffer_clients_begin") == 0) {
        if(state->begun) {
            set_phase_error(state, C5ReconClientsError, "Duplicate snapshot");
            return;
        }
        if(!number_field(fields, count, "aps", C5_RECON_CLIENTS_MAX_APS, &aps) ||
           !number_field(fields, count, "clients", C5_RECON_CLIENTS_MAX_STATIONS, &clients)) {
            set_phase_error(state, C5ReconClientsError, "List exceeds Flipper limit");
            return;
        }
        state->aps = calloc(aps ? aps : 1, sizeof(*state->aps));
        state->clients = calloc(clients ? clients : 1, sizeof(*state->clients));
        if(!state->aps || !state->clients) {
            set_phase_error(state, C5ReconClientsError, "Not enough memory");
            return;
        }
        state->expected_aps = aps;
        state->expected_clients = clients;
        state->begun = true;
        state->last_record_tick = now_ticks;
        return;
    }
    if(strcmp(record, "sniffer_clients_end") == 0) {
        if(!state->begun || !number_field(fields, count, "aps", C5_RECON_CLIENTS_MAX_APS, &aps) ||
           !number_field(fields, count, "clients", C5_RECON_CLIENTS_MAX_STATIONS, &clients) ||
           aps != state->expected_aps || clients != state->expected_clients ||
           aps != state->ap_count || clients != state->client_count) {
            set_phase_error(state, C5ReconClientsError, "Incomplete snapshot");
            return;
        }
        state->phase = C5ReconClientsReady;
        state->last_record_tick = now_ticks;
        return;
    }
    bool is_ap = strcmp(record, "sniffer_ap") == 0;
    bool is_client = strcmp(record, "sniffer_client") == 0;
    if(!is_ap && !is_client) return;
    if(!state->begun) {
        set_phase_error(state, C5ReconClientsError, "Snapshot missing Begin");
        return;
    }
    const char* text_bssid = string_field(fields, count, "bssid");
    char bssid[18];
    if(!normalize_mac(text_bssid, bssid)) {
        set_phase_error(state, C5ReconClientsError, "Invalid BSSID");
        return;
    }
    int ap_index = find_ap(state, bssid);
    if(is_ap) {
        unsigned channel = 0;
        const char* hex = string_field(fields, count, "ssid_hex");
        const char* source = string_field(fields, count, "ssid_source");
        if(ap_index >= 0 || state->ap_count >= state->expected_aps || !hex || !source ||
           strlen(hex) > 64 || strlen(hex) % 2 ||
           !number_field(fields, count, "channel", 177, &channel)) {
            set_phase_error(state, C5ReconClientsError, "Invalid AP record");
            return;
        }
        C5ReconIdentityAp* ap = &state->aps[state->ap_count];
        memcpy(ap->bssid, bssid, sizeof(ap->bssid));
        ap->channel = (uint8_t)channel;
        size_t hex_length = strlen(hex);
        for(size_t i = 0; i < hex_length; i += 2) {
            int hi = isdigit((unsigned char)hex[i]) ? hex[i] - '0' :
                     isxdigit((unsigned char)hex[i]) ? toupper((unsigned char)hex[i]) - 'A' + 10 : -1;
            int lo = isdigit((unsigned char)hex[i + 1]) ? hex[i + 1] - '0' :
                     isxdigit((unsigned char)hex[i + 1]) ? toupper((unsigned char)hex[i + 1]) - 'A' + 10 : -1;
            if(hi < 0 || lo < 0) {
                set_phase_error(state, C5ReconClientsError, "Invalid SSID");
                return;
            }
            unsigned char byte = (unsigned char)((hi << 4) | lo);
            ap->ssid[i / 2] = byte >= 32 && byte <= 126 ? (char)byte : '?';
        }
        ap->ssid[hex_length / 2] = '\0';
        state->ap_count++;
    } else {
        const char* text_station = string_field(fields, count, "station");
        char station[18];
        if(ap_index < 0 || state->client_count >= state->expected_clients ||
           !normalize_mac(text_station, station) || strcmp(station, bssid) == 0) {
            set_phase_error(state, C5ReconClientsError, "Invalid client record");
            return;
        }
        for(size_t i = 0; i < state->client_count; i++)
            if(state->clients[i].ap_index == (uint8_t)ap_index &&
               strcmp(state->clients[i].station, station) == 0) {
                set_phase_error(state, C5ReconClientsError, "Duplicate client");
                return;
            }
        C5ReconIdentityClient* client = &state->clients[state->client_count++];
        memcpy(client->station, station, sizeof(client->station));
        client->ap_index = (uint8_t)ap_index;
    }
    state->last_record_tick = now_ticks;
}

static void process_line(C5ReconClients* state, const char* line, uint32_t now_ticks) {
    if(state->phase != C5ReconClientsLoading && state->phase != C5ReconClientsStarting) return;
    if(state->phase == C5ReconClientsLoading &&
       (strstr(line, "Unknown command") || strstr(line, "Unrecognized command") ||
        strstr(line, "command not found"))) {
        set_phase_error(state, C5ReconClientsUnsupported, "Update JanOS for clients");
        return;
    }
    if(state->phase == C5ReconClientsLoading && line[0] == '>') {
        set_phase_error(state, state->begun ? C5ReconClientsError : C5ReconClientsUnsupported,
                        state->begun ? "Incomplete snapshot" : "Update JanOS for clients");
        return;
    }
    bool admission = strncmp(line, "[WFACTL1] ", 10) == 0;
    const char* json = admission ? line + 10 : line;
    if(*json != '{') return;
    C5ReconJsonField fields[12] = {0};
    int count = parse_object(json, fields);
    if(count < 0) {
        set_phase_error(state, C5ReconClientsError, "Bad snapshot record");
        return;
    }
    if(admission) {
        unsigned version = 0;
        const char* type = string_field(fields, count, "type");
        const char* code = string_field(fields, count, "code");
        const char* command = string_field(fields, count, "command");
        if(number_field(fields, count, "v", 1, &version) && version == 1 && type &&
           strcmp(type, "error") == 0 && code && strcmp(code, "busy") == 0 &&
           command && strcmp(command, "console") == 0)
            set_phase_error(state, state->phase == C5ReconClientsStarting ?
                                   C5ReconClientsReloadRequired : C5ReconClientsError, "Radio busy");
        return;
    }
    const char* record = string_field(fields, count, "record_type");
    if(!record) return;
    unsigned version = 0;
    if(!number_field(fields, count, "schema_version", 65535, &version) || version != 1) {
        set_phase_error(state, C5ReconClientsUnsupported, "Unsupported JanOS snapshot");
        return;
    }
    if(state->phase == C5ReconClientsLoading) {
        process_loading(state, fields, count, record, now_ticks);
    } else if(strcmp(record, "station_deauth") == 0) {
        const char* status = string_field(fields, count, "status");
        if(status && strcmp(status, "error") == 0) {
            const char* reason = string_field(fields, count, "reason");
            set_phase_error(state, C5ReconClientsReloadRequired,
                            reason ? reason : "Station start refused");
        } else if(status && strcmp(status, "started") == 0) {
            char bssid[18], station[18];
            if(normalize_mac(string_field(fields, count, "bssid"), bssid) &&
               normalize_mac(string_field(fields, count, "station"), station) &&
               strcmp(bssid, state->pending_bssid) == 0 &&
               strcmp(station, state->pending_station) == 0) {
                state->phase = C5ReconClientsActive;
            }
        }
    }
}

void c5_recon_clients_feed(
    C5ReconClients* state, const uint8_t* bytes, size_t length, uint32_t now_ticks) {
    if(!state || !bytes) return;
    for(size_t i = 0; i < length; i++) {
        uint8_t byte = bytes[i];
        if(byte == '\r' || byte == '\n') {
            if(state->line_length && (state->phase == C5ReconClientsLoading ||
                                      state->phase == C5ReconClientsStarting)) {
                state->line[state->line_length] = '\0';
                process_line(state, state->line, now_ticks);
            }
            state->line_length = 0;
        } else if(state->phase == C5ReconClientsLoading || state->phase == C5ReconClientsStarting) {
            if(byte == 0 || state->line_length + 1 >= sizeof(state->line)) {
                state->line_length = 0;
                set_phase_error(state, C5ReconClientsError, "RX lost; reload clients");
            } else {
                state->line[state->line_length++] = (char)byte;
            }
        }
    }
}

C5ReconClientsTick c5_recon_clients_tick(C5ReconClients* state, uint32_t now_ticks) {
    if(!state) return C5ReconClientsNoTickEvent;
    if(state->phase == C5ReconClientsLoading &&
       ((uint32_t)(now_ticks - state->last_record_tick) >= 5000u ||
        (uint32_t)(now_ticks - state->started_tick) >= 300000u)) {
        set_phase_error(state, C5ReconClientsError, "Incomplete snapshot; retry");
        return C5ReconClientsListTimeout;
    }
    if(state->phase == C5ReconClientsStarting &&
       (uint32_t)(now_ticks - state->start_sent_tick) >= 15000u) {
        set_phase_error(state, C5ReconClientsReloadRequired, "Start timeout; stop requested");
        return C5ReconClientsStartTimeout;
    }
    return C5ReconClientsNoTickEvent;
}

bool c5_recon_clients_command(
    const C5ReconClients* state, size_t client_index, char* out, size_t capacity) {
    if(!state || !out || state->phase != C5ReconClientsReady ||
       client_index >= state->client_count) return false;
    const C5ReconIdentityClient* client = &state->clients[client_index];
    if(client->ap_index >= state->ap_count || !state->aps[client->ap_index].channel) return false;
    char command[80];
    int length = snprintf(command, sizeof(command), "start_deauth_station %s %s",
                          state->aps[client->ap_index].bssid, client->station);
    if(length <= 0 || (size_t)length >= sizeof(command) || (size_t)length + 1 > capacity)
        return false;
    memcpy(out, command, (size_t)length + 1);
    return true;
}

void c5_recon_clients_start_sent(C5ReconClients* state, size_t client_index, uint32_t now_ticks) {
    if(!state || state->phase != C5ReconClientsReady || client_index >= state->client_count)
        return;
    const C5ReconIdentityClient* client = &state->clients[client_index];
    if(client->ap_index >= state->ap_count) return;
    memcpy(state->pending_bssid, state->aps[client->ap_index].bssid, sizeof(state->pending_bssid));
    memcpy(state->pending_station, client->station, sizeof(state->pending_station));
    state->phase = C5ReconClientsStarting;
    state->start_sent_tick = now_ticks;
    state->error[0] = '\0';
}

void c5_recon_clients_stop_requested(C5ReconClients* state, bool tx_ok) {
    if(!state) return;
    if(state->phase == C5ReconClientsStarting || state->phase == C5ReconClientsActive || !tx_ok)
        set_phase_error(state, C5ReconClientsReloadRequired,
                        tx_ok ? "Stop requested; exit/reload" : "Stop TX failed; check link");
}
