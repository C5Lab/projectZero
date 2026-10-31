#ifndef LAB_C5_RECON_SNIFFER_PROBE_H
#define LAB_C5_RECON_SNIFFER_PROBE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define C5_RECON_SNIFFER_MAX_APS 32u
#define C5_RECON_SNIFFER_MAX_CLIENTS 64u
#define C5_RECON_SELECTED_STATIONS_MAX 32u
#define C5_RECON_STATIONS_WIRE_MAX 13u
#define C5_RECON_PROBE_MAX_SSIDS 32u
#define C5_RECON_PROBE_MAX_CLIENTS 64u
#define C5_RECON_SP_LINE_CAPACITY 96u
#define C5_RECON_MAC_CAPACITY 18u

typedef struct {
    char ssid[33];
    uint8_t channel;
    uint16_t client_start;
    uint16_t client_count;
    uint16_t expected_count;
} C5ReconSnifferAp;

typedef struct {
    char mac[C5_RECON_MAC_CAPACITY];
} C5ReconClient;

typedef struct {
    char ssid[33];
    uint16_t client_start;
    uint16_t client_count;
    uint16_t expected_count;
} C5ReconProbeSsid;

typedef struct {
    C5ReconSnifferAp* aps;
    C5ReconClient* clients;
    size_t ap_count;
    size_t client_count;
    char selected_macs[C5_RECON_SELECTED_STATIONS_MAX][C5_RECON_MAC_CAPACITY];
    size_t selected_count;
    uint32_t packet_count;
    uint32_t networks;
    uint32_t last_update_tick;
    char mode[12];
    bool running;
    bool has_data;
    bool scan_done;
    bool results_mode;
    bool results_loading;
    char line[C5_RECON_SP_LINE_CAPACITY];
    size_t line_length;
    bool discard_line;
} C5ReconSnifferState;

typedef struct {
    C5ReconProbeSsid* ssids;
    C5ReconClient* clients;
    size_t ssid_count;
    size_t client_count;
    uint32_t total;
    bool results_loading;
    char line[C5_RECON_SP_LINE_CAPACITY];
    size_t line_length;
    bool discard_line;
} C5ReconProbeState;

typedef enum {
    C5ReconSelectOk = 0,
    C5ReconSelectNoStations,
    C5ReconSelectTooMany,
    C5ReconSelectInvalidMac,
    C5ReconSelectBufferTooSmall,
} C5ReconSelectStatus;

void c5_recon_sniffer_init(C5ReconSnifferState* state);
void c5_recon_sniffer_reset_status(C5ReconSnifferState* state);
bool c5_recon_sniffer_begin_results(C5ReconSnifferState* state);
void c5_recon_sniffer_end_results(C5ReconSnifferState* state);
void c5_recon_sniffer_free(C5ReconSnifferState* state);
void c5_recon_sniffer_feed(
    C5ReconSnifferState* state, const uint8_t* bytes, size_t length, uint32_t now_ticks);
bool c5_recon_sniffer_toggle_station(C5ReconSnifferState* state, const char* mac);
bool c5_recon_sniffer_station_selected(const C5ReconSnifferState* state, const char* mac);
void c5_recon_sniffer_clear_selection(C5ReconSnifferState* state);
/* JanOS accepts at most 256 CLI bytes and each select_stations replaces prior
 * selection. A 14th MAC would exceed the line limit; never emit a partial list.
 * On failure, out is unchanged. No newline is appended on success. */
C5ReconSelectStatus c5_recon_sniffer_select_command(
    const C5ReconSnifferState* state, char* out, size_t out_capacity);

void c5_recon_probe_init(C5ReconProbeState* state);
bool c5_recon_probe_begin_results(C5ReconProbeState* state);
void c5_recon_probe_free(C5ReconProbeState* state);
void c5_recon_probe_feed(C5ReconProbeState* state, const uint8_t* bytes, size_t length);

#endif
