#include "../modules/recon/recon_sniffer_probe.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef C5_RECON_TEST_WRAP_CALLOC
static int fail_calloc_after = -1;

void* __real_calloc(size_t count, size_t size);
void* __wrap_calloc(size_t count, size_t size) {
    if(fail_calloc_after == 0) return NULL;
    if(fail_calloc_after > 0) fail_calloc_after--;
    return __real_calloc(count, size);
}
#endif

static void test_sniffer_status_split_chunks(void) {
    C5ReconSnifferState state;
    c5_recon_sniffer_init(&state);
    const char* first = "Starting sniffer in FAST mode\r\nWiFi scan completed. Found 12 net";
    const char* second =
        "works\r\nSniffer: Scan complete\nSniffer packet count: 243\r\n";
    c5_recon_sniffer_feed(&state, (const uint8_t*)first, strlen(first), 10);
    c5_recon_sniffer_feed(&state, (const uint8_t*)second, strlen(second), 20);
    assert(strcmp(state.mode, "FAST") == 0);
    assert(state.networks == 12);
    assert(state.packet_count == 243);
    assert(state.running && state.scan_done && state.has_data);
    assert(state.last_update_tick == 20);
    c5_recon_sniffer_reset_status(&state);
    assert(!state.running && !state.has_data && state.packet_count == 0);
    c5_recon_sniffer_free(&state);
}

static void test_sniffer_results_and_selection(void) {
    C5ReconSnifferState state;
    c5_recon_sniffer_init(&state);
    assert(c5_recon_sniffer_begin_results(&state));
    const char* response = "Cafe, CH6: 1\r\nAA:BB:CC:DD:EE:FF\n>\n";
    c5_recon_sniffer_feed(&state, (const uint8_t*)response, strlen(response), 30);
    assert(state.ap_count == 1 && state.client_count == 1);
    assert(strcmp(state.aps[0].ssid, "Cafe") == 0);
    assert(state.aps[0].channel == 6);
    assert(state.aps[0].client_start == 0 && state.aps[0].client_count == 1);
    assert(state.aps[0].expected_count == 1);
    assert(strcmp(state.clients[0].mac, "AA:BB:CC:DD:EE:FF") == 0);
    assert(!state.results_loading);
    assert(c5_recon_sniffer_toggle_station(&state, state.clients[0].mac));
    assert(c5_recon_sniffer_station_selected(&state, "AA:BB:CC:DD:EE:FF"));
    char command[64] = {0};
    assert(c5_recon_sniffer_select_command(&state, command, sizeof(command)) == C5ReconSelectOk);
    assert(strcmp(command, "select_stations AA:BB:CC:DD:EE:FF") == 0);
    assert(c5_recon_sniffer_toggle_station(&state, state.clients[0].mac));
    assert(state.selected_count == 0);
    c5_recon_sniffer_free(&state);
}

static void test_sniffer_header_uses_final_channel_marker(void) {
    C5ReconSnifferState state;
    c5_recon_sniffer_init(&state);
    assert(c5_recon_sniffer_begin_results(&state));
    const char* response =
        "CHROME, CH6: 1\n"
        "Cafe:WiFi, CH7: 2\n"
        "Cafe,Guest, CH8: 3\n"
        "Cafe, CH3: 9, CH11: 4\n";
    c5_recon_sniffer_feed(&state, (const uint8_t*)response, strlen(response), 30);
    assert(state.ap_count == 4);
    assert(strcmp(state.aps[0].ssid, "CHROME") == 0);
    assert(state.aps[0].channel == 6 && state.aps[0].expected_count == 1);
    assert(strcmp(state.aps[1].ssid, "Cafe:WiFi") == 0);
    assert(state.aps[1].channel == 7 && state.aps[1].expected_count == 2);
    assert(strcmp(state.aps[2].ssid, "Cafe,Guest") == 0);
    assert(state.aps[2].channel == 8 && state.aps[2].expected_count == 3);
    assert(strcmp(state.aps[3].ssid, "Cafe, CH3: 9") == 0);
    assert(state.aps[3].channel == 11 && state.aps[3].expected_count == 4);
    c5_recon_sniffer_free(&state);
}

static void test_sniffer_selection_lifecycle_matches_host(void) {
    C5ReconSnifferState state;
    c5_recon_sniffer_init(&state);
    assert(c5_recon_sniffer_begin_results(&state));
    assert(c5_recon_sniffer_toggle_station(&state, "AA:BB:CC:DD:EE:FF"));
    c5_recon_sniffer_end_results(&state);
    /* Legacy free_sniffer_buffers releases result arrays but not the selection. */
    assert(c5_recon_sniffer_station_selected(&state, "AA:BB:CC:DD:EE:FF"));
    assert(state.selected_count == 1);
    assert(c5_recon_sniffer_begin_results(&state));
    /* Legacy reset_sniffer_results starts a fresh listing with no selections. */
    assert(state.selected_count == 0);
    assert(c5_recon_sniffer_toggle_station(&state, "AA:BB:CC:DD:EE:FF"));
    c5_recon_sniffer_free(&state);
    assert(state.selected_count == 0);
}

#ifdef C5_RECON_TEST_WRAP_CALLOC
static void test_sniffer_failed_alloc_discards_stale_selection(void) {
    C5ReconSnifferState state;
    c5_recon_sniffer_init(&state);
    assert(c5_recon_sniffer_begin_results(&state));
    assert(c5_recon_sniffer_toggle_station(&state, "AA:BB:CC:DD:EE:FF"));
    fail_calloc_after = 0;
    assert(!c5_recon_sniffer_begin_results(&state));
    fail_calloc_after = -1;
    assert(!state.aps && !state.clients && !state.results_mode);
    assert(state.selected_count == 0);
    assert(!c5_recon_sniffer_station_selected(&state, "AA:BB:CC:DD:EE:FF"));

    assert(c5_recon_sniffer_begin_results(&state));
    assert(c5_recon_sniffer_toggle_station(&state, "AA:BB:CC:DD:EE:FF"));
    fail_calloc_after = 1;
    assert(!c5_recon_sniffer_begin_results(&state));
    fail_calloc_after = -1;
    assert(!state.aps && !state.clients && !state.results_mode);
    assert(state.selected_count == 0);
    c5_recon_sniffer_free(&state);
}
#endif

static void test_sniffer_caps_and_overlong_discard(void) {
    C5ReconSnifferState state;
    c5_recon_sniffer_init(&state);
    assert(c5_recon_sniffer_begin_results(&state));
    char long_line[160];
    memset(long_line, 'X', sizeof(long_line));
    long_line[sizeof(long_line) - 1] = '\n';
    c5_recon_sniffer_feed(&state, (const uint8_t*)long_line, sizeof(long_line), 1);
    assert(state.ap_count == 0);
    for(unsigned i = 0; i < 40; i++) {
        char header[40];
        snprintf(header, sizeof(header), "AP%u, CH1: 0\n", i);
        c5_recon_sniffer_feed(&state, (const uint8_t*)header, strlen(header), 2);
    }
    assert(state.ap_count == C5_RECON_SNIFFER_MAX_APS);
    for(unsigned i = 0; i < 70; i++) {
        char client[24];
        snprintf(client, sizeof(client), "02:00:00:00:00:%02X\n", i);
        c5_recon_sniffer_feed(&state, (const uint8_t*)client, strlen(client), 3);
    }
    assert(state.client_count == C5_RECON_SNIFFER_MAX_CLIENTS);
    assert(state.aps[31].client_count == C5_RECON_SNIFFER_MAX_CLIENTS);
    c5_recon_sniffer_free(&state);
}

static void test_station_command_capacity_is_atomic(void) {
    C5ReconSnifferState state;
    c5_recon_sniffer_init(&state);
    char mac[18];
    for(unsigned i = 0; i < C5_RECON_SELECTED_STATIONS_MAX; i++) {
        snprintf(mac, sizeof(mac), "02:00:00:00:00:%02X", i);
        assert(c5_recon_sniffer_toggle_station(&state, mac));
    }
    assert(state.selected_count == C5_RECON_SELECTED_STATIONS_MAX);
    assert(!c5_recon_sniffer_toggle_station(&state, "02:00:00:00:00:FF"));
    char command[512] = "unchanged";
    assert(c5_recon_sniffer_select_command(&state, command, sizeof(command)) == C5ReconSelectTooMany);
    assert(strcmp(command, "unchanged") == 0);
    for(unsigned i = 14; i < C5_RECON_SELECTED_STATIONS_MAX; i++) {
        snprintf(mac, sizeof(mac), "02:00:00:00:00:%02X", i);
        assert(c5_recon_sniffer_toggle_station(&state, mac));
    }
    assert(state.selected_count == 14);
    assert(c5_recon_sniffer_select_command(&state, command, sizeof(command)) == C5ReconSelectTooMany);
    assert(strcmp(command, "unchanged") == 0);
    snprintf(mac, sizeof(mac), "02:00:00:00:00:%02X", 13);
    assert(c5_recon_sniffer_toggle_station(&state, mac));
    assert(state.selected_count == 13);
    assert(c5_recon_sniffer_select_command(&state, command, 20) == C5ReconSelectBufferTooSmall);
    assert(strcmp(command, "unchanged") == 0);
    assert(c5_recon_sniffer_select_command(&state, command, 256) == C5ReconSelectOk);
    assert(strlen(command) == strlen("select_stations") + 13 * 18);
    c5_recon_sniffer_clear_selection(&state);
    assert(state.selected_count == 0);
    assert(c5_recon_sniffer_select_command(&state, command, sizeof(command)) == C5ReconSelectNoStations);
    c5_recon_sniffer_free(&state);
}

static void test_probe_groups_ssids_and_completes(void) {
    C5ReconProbeState state;
    c5_recon_probe_init(&state);
    assert(c5_recon_probe_begin_results(&state));
    const char* first = "Probe requests: 3\r\nCafe (AA:BB:CC:DD:EE:01)\nCa";
    const char* second = "fe (AA:BB:CC:DD:EE:02)\n (AA:BB:CC:DD:EE:03)\n>\n";
    c5_recon_probe_feed(&state, (const uint8_t*)first, strlen(first));
    c5_recon_probe_feed(&state, (const uint8_t*)second, strlen(second));
    assert(state.total == 3);
    assert(state.ssid_count == 2 && state.client_count == 3);
    assert(strcmp(state.ssids[0].ssid, "Cafe") == 0);
    assert(state.ssids[0].client_start == 0 && state.ssids[0].client_count == 2);
    assert(strcmp(state.ssids[1].ssid, "<hidden>") == 0);
    assert(state.ssids[1].client_start == 2 && state.ssids[1].client_count == 1);
    assert(!state.results_loading);
    c5_recon_probe_free(&state);
}

static void test_probe_interleaved_ssids_keep_their_clients(void) {
    C5ReconProbeState state;
    c5_recon_probe_init(&state);
    assert(c5_recon_probe_begin_results(&state));
    const char* response =
        "A (AA:BB:CC:DD:EE:01)\n"
        "B (AA:BB:CC:DD:EE:02)\n"
        "A (AA:BB:CC:DD:EE:03)\n";
    c5_recon_probe_feed(&state, (const uint8_t*)response, strlen(response));
    assert(state.ssid_count == 2 && state.client_count == 3);
    assert(strcmp(state.ssids[0].ssid, "A") == 0);
    assert(state.ssids[0].client_start == 0 && state.ssids[0].client_count == 2);
    assert(strcmp(state.clients[0].mac, "AA:BB:CC:DD:EE:01") == 0);
    assert(strcmp(state.clients[1].mac, "AA:BB:CC:DD:EE:03") == 0);
    assert(strcmp(state.ssids[1].ssid, "B") == 0);
    assert(state.ssids[1].client_start == 2 && state.ssids[1].client_count == 1);
    assert(strcmp(state.clients[2].mac, "AA:BB:CC:DD:EE:02") == 0);
    c5_recon_probe_free(&state);
}

static void test_probe_parentheses_are_part_of_ssid(void) {
    C5ReconProbeState state;
    c5_recon_probe_init(&state);
    assert(c5_recon_probe_begin_results(&state));
    const char* row = "Cafe (Guest) (AA:BB:CC:DD:EE:04)\n";
    c5_recon_probe_feed(&state, (const uint8_t*)row, strlen(row));
    assert(state.ssid_count == 1 && state.client_count == 1);
    assert(strcmp(state.ssids[0].ssid, "Cafe (Guest)") == 0);
    assert(state.ssids[0].client_start == 0 && state.ssids[0].client_count == 1);
    assert(strcmp(state.clients[0].mac, "AA:BB:CC:DD:EE:04") == 0);
    c5_recon_probe_free(&state);
}

static void test_probe_caps_and_overlong_discard(void) {
    C5ReconProbeState state;
    c5_recon_probe_init(&state);
    assert(c5_recon_probe_begin_results(&state));
    char long_line[160];
    memset(long_line, 'P', sizeof(long_line));
    long_line[sizeof(long_line) - 1] = '\n';
    c5_recon_probe_feed(&state, (const uint8_t*)long_line, sizeof(long_line));
    assert(state.ssid_count == 0);
    for(unsigned i = 0; i < 70; i++) {
        char row[64];
        snprintf(row, sizeof(row), "SSID%u (02:00:00:00:00:%02X)\n", i, i);
        c5_recon_probe_feed(&state, (const uint8_t*)row, strlen(row));
    }
    assert(state.ssid_count == C5_RECON_PROBE_MAX_SSIDS);
    assert(state.client_count == C5_RECON_PROBE_MAX_SSIDS);
    assert(c5_recon_probe_begin_results(&state));
    for(unsigned i = 0; i < 70; i++) {
        char row[64];
        snprintf(row, sizeof(row), "Same (02:00:00:00:00:%02X)\n", i);
        c5_recon_probe_feed(&state, (const uint8_t*)row, strlen(row));
    }
    assert(state.ssid_count == 1);
    assert(state.client_count == C5_RECON_PROBE_MAX_CLIENTS);
    assert(state.ssids[0].client_count == C5_RECON_PROBE_MAX_CLIENTS);
    assert(state.ssids[0].expected_count == 70);
    c5_recon_probe_free(&state);
}

int main(void) {
    test_sniffer_status_split_chunks();
    test_sniffer_results_and_selection();
    test_sniffer_header_uses_final_channel_marker();
    test_sniffer_selection_lifecycle_matches_host();
#ifdef C5_RECON_TEST_WRAP_CALLOC
    test_sniffer_failed_alloc_discards_stale_selection();
#endif
    test_sniffer_caps_and_overlong_discard();
    test_station_command_capacity_is_atomic();
    test_probe_groups_ssids_and_completes();
    test_probe_interleaved_ssids_keep_their_clients();
    test_probe_parentheses_are_part_of_ssid();
    test_probe_caps_and_overlong_discard();
    puts("recon sniffer/probe tests passed");
    return 0;
}
