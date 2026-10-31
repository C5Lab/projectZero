/* Run from FLIPPER in WSL: cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined
 *   tests/test_recon_scan.c modules/recon/recon_scan.c -o /tmp/c5_recon_scan_test
 *   /tmp/c5_recon_scan_test
 */
#include "../modules/recon/recon_scan.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint32_t feed_text(C5ReconScan* scan, const char* text, uint32_t tick) {
    return c5_recon_scan_feed(scan, (const uint8_t*)text, strlen(text), tick);
}

static void test_fragmented_rows_and_stats(void) {
    C5ReconScan scan;
    c5_recon_scan_init(&scan, -110);
    assert(c5_recon_scan_begin(&scan));
    const char* text =
        "Found 2 networks\r\n"
        "\"1\",\"Home\",\"Acme\",\"AA:BB:CC:DD:EE:01\",\"6\",\"WPA2\",\"-55\",\"2.4GHz\"\r\n"
        "\"2\",\"\",\"\",\"11:22:33:44:55:66\",\"149\",\"\",\"-120\",\"5G\"\n"
        "Scan results printed.\n";
    uint32_t events = 0;
    for(size_t i = 0; text[i]; i++) {
        events |= c5_recon_scan_feed(&scan, (const uint8_t*)&text[i], 1, 42);
    }
    assert((events & (C5ReconScanEventRow | C5ReconScanEventDone)) ==
           (C5ReconScanEventRow | C5ReconScanEventDone));
    assert(scan.capacity == 2 && scan.count == 2 && scan.visible_count == 2 && !scan.loading);
    assert(scan.band_24_count == 1 && scan.band_5_count == 1);
    assert(scan.open_count == 0 && scan.hidden_count == 1);
    assert(scan.best_rssi_valid && scan.best_rssi == -55 && strcmp(scan.best_ssid, "Home") == 0);
    assert(scan.last_update_tick == 42);
    const C5ReconScanResult* first = c5_recon_scan_visible(&scan, 0);
    const C5ReconScanResult* second = c5_recon_scan_visible(&scan, 1);
    assert(first && second && first->number == 1 && second->number == 2);
    assert(first->bssid[0] == 0xaa && first->channel == 6 && first->band == C5ReconBand24);
    assert(second->power_valid && second->power_dbm == -110 && second->band == C5ReconBand5);
    assert(strcmp(second->ssid, "Hidden") == 0 && strcmp(second->security, "Unknown") == 0);
    assert(strcmp(c5_recon_scan_vendor(&scan, first->bssid), "Acme") == 0);
    c5_recon_scan_deinit(&scan);
}

static void test_visibility_selection_and_snapshot_order(void) {
    C5ReconScan scan;
    c5_recon_scan_init(&scan, -110);
    assert(c5_recon_scan_begin(&scan));
    feed_text(&scan, "Retrieved 3 network records\n", 1);
    assert(scan.capacity == 3);
    feed_text(&scan, "\"4\",\"Weak\",\"\",\"00:00:00:00:00:04\",\"1\",\"open\",\"-85\",\"2.4\"\n", 2);
    feed_text(&scan, "\"5\",\"Strong\",\"\",\"00:00:00:00:00:05\",\"36\",\"WPA2\",\"-40\",\"5\"\n", 3);
    feed_text(&scan, "\"6\",\"Unknown\",\"\",\"00:00:00:00:00:06\",\"?\",\"WPA2\",\"?\",\"?\"\n", 4);
    assert(scan.open_count == 1);
    assert(c5_recon_scan_toggle_visible(&scan, 1)); /* 5 first */
    assert(c5_recon_scan_toggle_visible(&scan, 0)); /* 4 second */
    assert(scan.selected_count == 2);
    c5_recon_scan_set_min_power(&scan, -60);
    assert(scan.visible_count == 2 && c5_recon_scan_visible(&scan, 0)->number == 5);
    assert(c5_recon_scan_visible(&scan, 1)->number == 6); /* invalid power stays visible */
    C5ReconTarget targets[2] = {{0}};
    size_t needed = 0;
    assert(!c5_recon_scan_export_targets(&scan, targets, 1, &needed) && needed == 2);
    assert(targets[0].number == 0); /* no partial export */
    assert(c5_recon_scan_export_targets(&scan, targets, 2, &needed) && needed == 2);
    assert(targets[0].number == 5 && strcmp(targets[0].ssid, "Strong") == 0);
    assert(targets[1].number == 4 && strcmp(targets[1].ssid, "Weak") == 0);
    assert(targets[1].bssid[5] == 4 && targets[1].channel == 1);
    assert(c5_recon_scan_toggle_visible(&scan, 0));
    assert(scan.selected_count == 1 && scan.selected_numbers[0] == 4);
    c5_recon_scan_deinit(&scan);
}

static void test_limit_64_and_malformed_lines(void) {
    C5ReconScan scan;
    c5_recon_scan_init(&scan, -110);
    assert(c5_recon_scan_begin(&scan));
    feed_text(&scan, "Found 80 networks\n", 1);
    assert(scan.capacity == C5_RECON_SCAN_MAX_RESULTS);
    assert(feed_text(&scan, "\"1\",\"Only seven\",\"\",\"\",\"1\",\"open\",\"-30\"\n", 2) == 0);
    char line[160];
    for(unsigned i = 1; i <= 65; i++) {
        snprintf(line, sizeof(line), "\"%u\",\"Net%u\",\"\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"open\",\"-30\",\"2.4\"\n", i, i);
        feed_text(&scan, line, i + 2);
    }
    assert(scan.count == 64 && scan.visible_count == 64 && scan.open_count == 64);
    assert(c5_recon_scan_visible(&scan, 0)->number == 1);
    assert(c5_recon_scan_visible(&scan, 63)->number == 64);
    assert(!c5_recon_scan_toggle_visible(&scan, 64));
    c5_recon_scan_deinit(&scan);
}

static void test_overlong_line_does_not_parse_tail(void) {
    C5ReconScan scan;
    c5_recon_scan_init(&scan, -110);
    assert(c5_recon_scan_begin(&scan));
    char overlong[260];
    memset(overlong, 'x', sizeof(overlong));
    overlong[0] = '"';
    overlong[sizeof(overlong) - 2] = '\n';
    overlong[sizeof(overlong) - 1] = '\0';
    assert(feed_text(&scan, overlong, 1) == 0);
    assert(scan.count == 0);
    assert(feed_text(&scan, "\"7\",\"Next\",\"\",\"AA:BB:CC:DD:EE:07\",\"11\",\"WPA2\",\"-65\",\"2.4\"\n", 2) & C5ReconScanEventRow);
    assert(scan.count == 1 && c5_recon_scan_visible(&scan, 0)->number == 7);
    c5_recon_scan_deinit(&scan);
}

static void test_begin_resets_selection_and_empty_status(void) {
    C5ReconScan scan;
    c5_recon_scan_init(&scan, -110);
    assert(c5_recon_scan_begin(&scan));
    feed_text(&scan, "\"1\",\"One\",\"\",\"AA:BB:CC:DD:EE:01\",\"1\",\"open\",\"-20\",\"2.4\"\n", 1);
    assert(c5_recon_scan_toggle_visible(&scan, 0));
    assert(c5_recon_scan_begin(&scan));
    assert(scan.count == 0 && scan.selected_count == 0 && scan.visible_count == 0 && scan.loading);
    assert(feed_text(&scan, "No networks found\n", 2) & C5ReconScanEventNoResults);
    assert(!scan.loading);
    c5_recon_scan_deinit(&scan);
}

static void test_janos_zero_record_completion(void) {
    const char* retrieved_lines[] = {
        "Retrieved 0 network records in 2.4s\r\n",
        "Retrieved 0 network records\r\n",
    };
    for(size_t i = 0; i < sizeof(retrieved_lines) / sizeof(retrieved_lines[0]); i++) {
        C5ReconScan scan;
        c5_recon_scan_init(&scan, -110);
        assert(c5_recon_scan_begin(&scan));
        uint32_t events = feed_text(&scan, "WiFi scan completed. Found 0 networks, status: 0\r\n", 10);
        assert(events == 0 && scan.loading && scan.count == 0);
        events = feed_text(&scan, retrieved_lines[i], 20);
        assert((events & (C5ReconScanEventDone | C5ReconScanEventNoResults)) ==
               (C5ReconScanEventDone | C5ReconScanEventNoResults));
        assert(!scan.loading && scan.count == 0 && scan.visible_count == 0);
        c5_recon_scan_deinit(&scan);
    }
}

static void test_janos_failure_banners_end_loading_and_allow_retry(void) {
    const struct {
        const char* banner;
        uint32_t event;
    } cases[] = {
        {"Scan failed with status: 1\r\n", C5ReconScanEventError},
        {"E (1234) wifi: Failed to start scan: ESP_FAIL\r\n", C5ReconScanEventError},
        {"Scan already in progress. Use 'show_scan_results' to see current results or 'stop' to cancel.\r\n",
         C5ReconScanEventStillRunning},
    };
    for(size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        C5ReconScan scan;
        c5_recon_scan_init(&scan, -110);
        assert(c5_recon_scan_begin(&scan));
        uint32_t events = feed_text(&scan, cases[i].banner, 20);
        assert(events == cases[i].event);
        assert(!scan.loading && scan.count == 0);
        assert(c5_recon_scan_begin(&scan));
        assert(scan.loading && scan.count == 0);
        c5_recon_scan_deinit(&scan);
    }
}

static void test_field_boundaries_preserve_ordinary_rows(void) {
    C5ReconScan scan;
    c5_recon_scan_init(&scan, -60);
    assert(c5_recon_scan_begin(&scan));
    const char* ssid32 = "ABCDEFGHIJKLMNOP,QRSTUVWXYZ12345";
    assert(strlen(ssid32) == 32);
    const char* row =
        "\"65535\",\"ABCDEFGHIJKLMNOP,QRSTUVWXYZ12345\",\"Vendor\","
        "\"not-a-bssid\",\"999\",\"OpEn guest\",\"bad\",\"2.4GHz\"\n";
    assert(feed_text(&scan, row, 20) & C5ReconScanEventRow);
    assert(scan.count == 1 && scan.visible_count == 1);
    const C5ReconScanResult* result = c5_recon_scan_visible(&scan, 0);
    assert(result && result->number == UINT16_MAX && strcmp(result->ssid, ssid32) == 0);
    assert(result->channel == UINT8_MAX && !result->power_valid && scan.open_count == 1);
    for(size_t i = 0; i < sizeof(result->bssid); i++) assert(result->bssid[i] == 0);
    c5_recon_scan_deinit(&scan);
}

static void test_janos_nested_csv_fields(void) {
    /* Exact rows printed by ESP32C5/main/main.c: escape_csv_field() is used
     * inside another pair of quotes in print_network_csv().
     */
    const struct {
        const char* row;
        const char* ssid;
        const char* vendor_prefix;
    } cases[] = {
        {"\"2\",\"\"O'Brien, Lab\"\",\"\",\"E0:06:30:30:40:51\",\"6\",\"WPA2\",\"-52\",\"2.4GHz\"\n",
         "O'Brien, Lab", NULL},
        {"\"2\",\"\"O'Brien, \"\"Lab\"\"\"\",\"\",\"E0:06:30:30:40:51\",\"6\",\"WPA2\",\"-52\",\"2.4GHz\"\n",
         "O'Brien, \"Lab\"", NULL},
        {"\"2\",\"\"Cafe\"\",\"\"WiFi\"\",\"\",\"E0:06:30:30:40:51\",\"6\",\"WPA2\",\"-52\",\"2.4GHz\"\n",
         "Cafe\",\"WiFi", NULL},
        {"\"2\",\"O'Brien\",\"\"HUAWEI TECHNOLOGIES CO.,LTD\"\",\"E0:06:30:30:40:51\",\"6\",\"WPA2\",\"-52\",\"2.4GHz\"\n",
         "O'Brien", "HUAWEI TECHNOLOGIES CO.,LTD"},
    };
    for(size_t which = 0; which < sizeof(cases) / sizeof(cases[0]); which++) {
        C5ReconScan scan;
        c5_recon_scan_init(&scan, -110);
        assert(c5_recon_scan_begin(&scan));
        uint32_t events = 0;
        for(size_t i = 0; cases[which].row[i]; i++) {
            events |= c5_recon_scan_feed(&scan, (const uint8_t*)&cases[which].row[i], 1, 30);
        }
        assert(events & C5ReconScanEventRow);
        assert(scan.count == 1 && scan.visible_count == 1);
        const C5ReconScanResult* result = c5_recon_scan_visible(&scan, 0);
        assert(result && result->number == 2);
        assert(strcmp(result->ssid, cases[which].ssid) == 0);
        assert(result->bssid[0] == 0xe0 && result->bssid[1] == 0x06 && result->channel == 6);
        assert(result->power_valid && result->power_dbm == -52 && result->band == C5ReconBand24);
        assert(c5_recon_scan_toggle_visible(&scan, 0));
        C5ReconTarget target = {0};
        size_t target_count = 0;
        assert(c5_recon_scan_export_targets(&scan, &target, 1, &target_count));
        assert(target_count == 1 && target.number == 2 && strcmp(target.ssid, cases[which].ssid) == 0);
        if(cases[which].vendor_prefix) {
            const char* vendor = c5_recon_scan_vendor(&scan, result->bssid);
            assert(vendor && strncmp(vendor, cases[which].vendor_prefix, 23) == 0);
        }
        c5_recon_scan_deinit(&scan);
    }
}

static void test_rfc4180_escaped_quotes_preserve_scan_row(void) {
    C5ReconScan scan;
    c5_recon_scan_init(&scan, -110);
    assert(c5_recon_scan_begin(&scan));
    const char* row =
        "\"7\",\"Cafe \"\"Lab\"\", West\",\"Vendor \"\"A\"\", Inc\","
        "\"E0:06:30:30:40:51\",\"6\",\"WPA2\",\"-52\",\"2.4GHz\"\n";
    assert(feed_text(&scan, row, 30) & C5ReconScanEventRow);
    assert(scan.count == 1);
    const C5ReconScanResult* result = c5_recon_scan_visible(&scan, 0);
    assert(result && result->number == 7);
    assert(strcmp(result->ssid, "Cafe \"Lab\", West") == 0);
    assert(result->channel == 6 && result->power_dbm == -52);
    const char* vendor = c5_recon_scan_vendor(&scan, result->bssid);
    assert(vendor && strcmp(vendor, "Vendor \"A\", Inc") == 0);
    c5_recon_scan_deinit(&scan);
}

int main(void) {
    test_fragmented_rows_and_stats();
    test_visibility_selection_and_snapshot_order();
    test_limit_64_and_malformed_lines();
    test_overlong_line_does_not_parse_tail();
    test_begin_resets_selection_and_empty_status();
    test_janos_zero_record_completion();
    test_janos_failure_banners_end_loading_and_allow_retry();
    test_field_boundaries_preserve_ordinary_rows();
    test_janos_nested_csv_fields();
    test_rfc4180_escaped_quotes_preserve_scan_row();
    puts("recon scan tests passed");
    return 0;
}
