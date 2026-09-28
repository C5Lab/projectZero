#include "wifi_analyzer_core.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

static void parse_defaults_and_plans(void)
{
    char *args[] = {"wifi_analyzer", "scan"};
    wfa_options_t options;
    const char *reason = NULL;
    assert(wfa_parse_scan_args(2, args, &options, &reason));
    assert(options.band == WFA_BAND_BOTH && options.profile == WFA_QUICK);
    assert(options.limit == 64 && !options.explicit_channels);
    assert(options.channel_count == 42);
    assert(options.channels[0] == 1 && options.channels[13] == 14);
    assert(options.channels[14] == 36 && options.channels[41] == 177);
    assert(wfa_scan_deadline_ms(&options) == 23900);
    assert(wfa_channel_band(14) == WFA_BAND_24);
    assert(wfa_primary_frequency(14) == 2484);
    assert(wfa_channel_band(35) == WFA_BAND_NONE);
    assert(wfa_channel_band(177) == WFA_BAND_5);
}

static void parse_explicit_and_reject_bad_arguments(void)
{
    char *good[] = {"wifi_analyzer", "scan", "--channels", "36,149", "--profile",
                    "passive", "--limit", "128", "--band", "5"};
    char *bad_list[] = {"wifi_analyzer", "scan", "--channels", "1, 6"};
    char *duplicate_channel[] = {"wifi_analyzer", "scan", "--channels", "1,1"};
    char *unsupported[] = {"wifi_analyzer", "scan", "--channels", "35"};
    char *wrong_band[] = {"wifi_analyzer", "scan", "--channels", "1", "--band", "5"};
    char *duplicate_flag[] = {"wifi_analyzer", "scan", "--limit", "2", "--limit", "3"};
    char *signed_limit[] = {"wifi_analyzer", "scan", "--limit", "+1"};
    char *overflow[] = {"wifi_analyzer", "scan", "--limit", "999999999999999999999999"};
    char *missing[] = {"wifi_analyzer", "scan", "--band"};
    char *unknown[] = {"wifi_analyzer", "scan", "--wat", "x"};
    char *band_only[] = {"wifi_analyzer", "scan", "--band", "5"};
    wfa_options_t options;
    const char *reason = NULL;
    assert(wfa_parse_scan_args(10, good, &options, &reason));
    assert(options.channel_count == 2 && options.channels[0] == 36 && options.channels[1] == 149);
    assert(options.explicit_channels && options.band == WFA_BAND_5);
    assert(options.profile == WFA_PASSIVE && options.limit == 128);
    assert(wfa_scan_deadline_ms(&options) == 6500);
    assert(!wfa_parse_scan_args(4, bad_list, &options, &reason));
    assert(!wfa_parse_scan_args(4, duplicate_channel, &options, &reason));
    assert(!wfa_parse_scan_args(4, unsupported, &options, &reason));
    assert(!wfa_parse_scan_args(6, wrong_band, &options, &reason));
    assert(!wfa_parse_scan_args(6, duplicate_flag, &options, &reason));
    assert(!wfa_parse_scan_args(4, signed_limit, &options, &reason));
    assert(!wfa_parse_scan_args(4, overflow, &options, &reason));
    assert(!wfa_parse_scan_args(3, missing, &options, &reason));
    assert(!wfa_parse_scan_args(4, unknown, &options, &reason));
    assert(wfa_parse_scan_args(4, band_only, &options, &reason));
    assert(options.channel_count == 28 && options.channels[0] == 36 && options.channels[27] == 177);
}

static wfa_ap_t example_ap(void)
{
    wfa_ap_t ap = {0};
    ap.bssid[0] = 2;
    ap.bssid[5] = 1;
    ap.ssid[0] = 'A';
    ap.ssid[1] = 0;
    ap.ssid[2] = 0xff;
    ap.ssid_len = 3;
    ap.primary = 36;
    ap.band = WFA_BAND_5;
    ap.rssi = -55;
    ap.auth = "WPA2_PSK";
    ap.phy_mask = WFA_PHY_A | WFA_PHY_N | WFA_PHY_AC;
    ap.width = WFA_WIDTH_80;
    ap.secondary = WFA_SECOND_ABOVE;
    ap.center1_mhz = 5210;
    return ap;
}

static void normalize_geometry(void)
{
    wfa_ap_t ap = example_ap();
    ap.center1_mhz = 5290;
    wfa_normalize_geometry(&ap);
    assert(ap.width == WFA_WIDTH_UNKNOWN); /* channel 36 is outside this segment */
    assert(ap.secondary == WFA_SECOND_UNKNOWN && ap.center1_mhz == 0 && ap.center2_mhz == 0);
    ap = example_ap();
    ap.center1_mhz = 5210;
    ap.secondary = WFA_SECOND_ABOVE;
    ap.primary = 36;
    wfa_normalize_geometry(&ap);
    assert(ap.width == WFA_WIDTH_80); /* 5180 is 30 MHz below 5210 */
    ap.width = WFA_WIDTH_80P80;
    ap.center2_mhz = 5290;
    wfa_normalize_geometry(&ap);
    assert(ap.width == WFA_WIDTH_UNKNOWN); /* second segment must be >80 MHz away */
    ap = example_ap();
    ap.width = WFA_WIDTH_80P80;
    ap.center1_mhz = 5530;
    ap.center2_mhz = 5210;
    wfa_normalize_geometry(&ap);
    assert(ap.width == WFA_WIDTH_80P80);
    assert(ap.center1_mhz == 5210 && ap.center2_mhz == 5530);
    ap = example_ap();
    ap.width = WFA_WIDTH_20;
    ap.center1_mhz = 5180;
    ap.secondary = WFA_SECOND_NONE;
    wfa_normalize_geometry(&ap);
    assert(ap.width == WFA_WIDTH_20);
    ap.width = WFA_WIDTH_40;
    ap.secondary = WFA_SECOND_ABOVE;
    ap.center1_mhz = 5190;
    wfa_normalize_geometry(&ap);
    assert(ap.width == WFA_WIDTH_40);
}

static void format_records_and_bounds(void)
{
    char line[WFA_LINE_CAPACITY];
    char tiny[9] = "SENTINEL";
    char *args[] = {"wifi_analyzer", "scan", "--channels", "36"};
    wfa_options_t options;
    wfa_ap_t ap = example_ap();
    const char *reason = NULL;
    int length;
    assert(wfa_parse_scan_args(4, args, &options, &reason));
    length = wfa_format_begin(line, sizeof line, "0123456789abcdef", 1, &options, 1000);
    assert(length > 0 && line[length - 1] == '\n' && line[length] == '\0');
    assert(strcmp(line, "[WFA1] {\"v\":1,\"type\":\"begin\",\"boot\":\"0123456789abcdef\",\"scan\":1,\"limit\":64,\"band\":\"both\",\"channels\":[36],\"profile\":\"quick\",\"started_ms\":1000}\n") == 0);
    assert(wfa_format_begin(tiny, sizeof tiny, "0123456789abcdef", 1, &options, 1000) == -1);
    assert(strcmp(tiny, "SENTINEL") == 0);
    length = wfa_format_ap(line, sizeof line, "0123456789abcdef", 1, 0, &ap);
    assert(length > 0 && line[length - 1] == '\n');
    assert(strstr(line, "\"ssid_hex\":\"4100ff\"") != NULL);
    assert(strstr(line, "\"phy\":[\"11a\",\"11n\",\"11ac\"]") != NULL);
    assert(strstr(line, "\"bandwidth\":\"80\",\"secondary\":\"above\",\"center1_mhz\":5210,\"center2_mhz\":null") != NULL);
    length = wfa_format_ap(line, sizeof line, "0123456789abcdef", 1, 127, &ap);
    assert(length > 0 && strstr(line, "\"seq\":127,") != NULL);
    strcpy(line, "SENTINEL");
    assert(wfa_format_ap(line, sizeof line, "0123456789abcdef", 1, 128, &ap) == -1);
    assert(strcmp(line, "SENTINEL") == 0);
    ap.primary = 0;
    ap.band = WFA_BAND_NONE;
    assert(wfa_format_ap(line, sizeof line, "0123456789abcdef", 1, 0, &ap) == -1);
    assert(strcmp(line, "SENTINEL") == 0);
    length = wfa_format_end(line, sizeof line, "0123456789abcdef", 1, "ok", 2, 2, 1500, NULL);
    assert(length > 0 && strstr(line, "\"status\":\"ok\",\"found\":2,\"returned\":2,\"truncated\":false,\"duration_ms\":1500") != NULL);
    length = wfa_format_end(line, sizeof line, "0123456789abcdef", 1, "timeout", -1, 1, 1500, "scan_timeout");
    assert(length > 0 && strstr(line, "\"found\":null,\"returned\":1,\"truncated\":false,\"duration_ms\":1500,\"code\":\"scan_timeout\"") != NULL);
    assert(wfa_format_end(tiny, sizeof tiny, "0123456789abcdef", 1, "ok", 1, 0, 1500, NULL) == -1);
    assert(strcmp(tiny, "SENTINEL") == 0);
}

static void geometry_160_device_regression(void)
{
    wfa_ap_t ap = example_ap();
    ap.primary = 64;
    ap.width = WFA_WIDTH_160;
    ap.secondary = WFA_SECOND_BELOW;
    ap.center1_mhz = 5290; /* Observed SDK value: center of primary 80 MHz half. */
    wfa_normalize_geometry(&ap);
    assert(ap.width == WFA_WIDTH_UNKNOWN);
    assert(ap.center1_mhz == 0 && ap.center2_mhz == 0 && ap.secondary == WFA_SECOND_UNKNOWN);
    char line[WFA_LINE_CAPACITY];
    assert(wfa_format_ap(line, sizeof(line), "0123456789abcdef", 1, 0, &ap) > 0);
    assert(strstr(line, "\"bandwidth\":null,\"secondary\":null,\"center1_mhz\":null,\"center2_mhz\":null"));
    const unsigned first[] = {36, 100, 149}, centers[] = {5250, 5570, 5815};
    for (unsigned block = 0; block < 3; ++block) {
        for (unsigned slot = 0; slot < 8; ++slot) {
            ap = example_ap();
            ap.primary = first[block] + slot * 4;
            ap.width = WFA_WIDTH_160;
            ap.secondary = slot % 2 ? WFA_SECOND_BELOW : WFA_SECOND_ABOVE;
            ap.center1_mhz = centers[block];
            wfa_normalize_geometry(&ap);
            assert(ap.width == WFA_WIDTH_160 && ap.center1_mhz == centers[block]);
        }
    }
}

int main(void)
{
    parse_defaults_and_plans();
    parse_explicit_and_reject_bad_arguments();
    normalize_geometry();
    geometry_160_device_regression();
    format_records_and_bounds();
    return 0;
}
