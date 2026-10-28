"""Host check for scan_networks / show_scan_results CSV quoting.

Compiles the real escape helpers and print_network_csv from main/main.c.
Wardrive rows still use escape_csv_field, which wraps a field itself.
"""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "main" / "main.c").read_text(encoding="utf-8")


def function(source, name):
    masked = re.sub(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
        lambda match: " " * len(match.group()),
        source,
        flags=re.S,
    )
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", masked)
    if not match:
        raise AssertionError(name)
    begin = source.rfind("\n", 0, match.start()) + 1
    depth = 1
    end = match.end()
    while depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return source[begin:end]


HARNESS = r'''
#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#define VENDOR_RECORD_NAME_BYTES 60
#define MY_LOG_INFO(tag, ...) do { (void)(tag); printf(__VA_ARGS__); putchar('\n'); } while (0)
#define pdMS_TO_TICKS(ms) (ms)

typedef enum {
    WIFI_AUTH_OPEN = 0,
    WIFI_AUTH_WEP,
    WIFI_AUTH_WPA_PSK,
    WIFI_AUTH_WPA2_PSK,
    WIFI_AUTH_WPA_WPA2_PSK,
    WIFI_AUTH_WPA2_ENTERPRISE,
    WIFI_AUTH_WPA3_PSK,
    WIFI_AUTH_WPA2_WPA3_PSK,
    WIFI_AUTH_WAPI_PSK,
    WIFI_AUTH_OWE
} wifi_auth_mode_t;

typedef struct {
    uint8_t ssid[33];
    uint8_t bssid[6];
    uint8_t primary;
    wifi_auth_mode_t authmode;
    int8_t rssi;
} wifi_ap_record_t;

static const char *TAG = "scan";
static int vendor_on;
static const char *vendor_result;
static char capture_buf[1024];
static int failures;

static bool vendor_is_enabled(void) { return vendor_on; }
static const char *lookup_vendor_name(const uint8_t *mac) {
    (void)mac;
    return vendor_result;
}
static void vTaskDelay(int ticks) { (void)ticks; }

__FIRMWARE_FUNCTIONS__

static void capture(void (*fn)(void)) {
    char path[] = "/tmp/scan-csv-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    assert(unlink(path) == 0);
    fflush(stdout);
    int saved = dup(fileno(stdout));
    assert(saved >= 0);
    assert(dup2(fd, fileno(stdout)) >= 0);
    fn();
    fflush(stdout);
    assert(dup2(saved, fileno(stdout)) >= 0);
    close(saved);
    off_t end = lseek(fd, 0, SEEK_END);
    assert(end >= 0 && (size_t)end < sizeof(capture_buf));
    assert(lseek(fd, 0, SEEK_SET) == 0);
    memset(capture_buf, 0, sizeof(capture_buf));
    ssize_t got = read(fd, capture_buf, sizeof(capture_buf) - 1);
    assert(got == end);
    close(fd);
}

static wifi_ap_record_t test_ap;
static int test_index;

static void emit(void) { print_network_csv(test_index, &test_ap); }

static void setup_ap(const char *ssid, const uint8_t bssid[6], int channel,
                     int rssi, wifi_auth_mode_t auth) {
    memset(&test_ap, 0, sizeof(test_ap));
    assert(strlen(ssid) < sizeof(test_ap.ssid));
    memcpy(test_ap.ssid, ssid, strlen(ssid) + 1);
    memcpy(test_ap.bssid, bssid, 6);
    test_ap.primary = (uint8_t)channel;
    test_ap.authmode = auth;
    test_ap.rssi = (int8_t)rssi;
}

static int next_field(const char **cursor, char *out, size_t out_size) {
    const char *s = *cursor;
    if (*s != '"') return -1;
    s++;
    size_t n = 0;
    while (*s) {
        if (*s == '"') {
            if (s[1] == '"') {
                if (n + 1 >= out_size) return -1;
                out[n++] = '"';
                s += 2;
                continue;
            }
            s++;
            break;
        }
        if (n + 1 >= out_size) return -1;
        out[n++] = *s++;
    }
    out[n] = '\0';
    if (*s == ',') s++;
    *cursor = s;
    return 0;
}

static void check_eq(const char *name, const char *got, const char *expected) {
    if (strcmp(got, expected) != 0) {
        fprintf(stderr, "FAIL %s\n got: [%s]\n exp: [%s]\n", name, got, expected);
        failures++;
    }
}

static void expect_line(const char *name, const char *ssid, const char *vendor,
                        int enabled, int index, const uint8_t bssid[6],
                        int channel, int rssi, wifi_auth_mode_t auth,
                        const char *expected) {
    setup_ap(ssid, bssid, channel, rssi, auth);
    test_index = index;
    vendor_on = enabled;
    vendor_result = vendor;
    capture(emit);
    check_eq(name, capture_buf, expected);

    const char *cursor = capture_buf;
    char fields[8][160];
    for (int i = 0; i < 8; i++) {
        if (next_field(&cursor, fields[i], sizeof(fields[i])) != 0) {
            fprintf(stderr, "FAIL %s field %d\n", name, i);
            failures++;
            return;
        }
    }
    if (strcmp(cursor, "\n") != 0) {
        fprintf(stderr, "FAIL %s trailing [%s]\n", name, cursor);
        failures++;
    }
    char index_text[16];
    char channel_text[16];
    char rssi_text[16];
    snprintf(index_text, sizeof(index_text), "%d", index + 1);
    snprintf(channel_text, sizeof(channel_text), "%d", channel);
    snprintf(rssi_text, sizeof(rssi_text), "%d", rssi);
    check_eq("index", fields[0], index_text);
    check_eq("ssid", fields[1], ssid);
    check_eq("vendor", fields[2], (enabled && vendor) ? vendor : "");
    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    check_eq("bssid", fields[3], mac);
    check_eq("channel", fields[4], channel_text);
    check_eq("rssi", fields[6], rssi_text);
    check_eq("band", fields[7], channel <= 14 ? "2.4GHz" : "5GHz");
}

static void check_wigle(const char *input, const char *expected) {
    char out[128];
    memset(out, 0xA5, sizeof(out));
    escape_csv_field(input, out, sizeof(out));
    check_eq(input[0] ? input : "empty-wigle", out, expected);
}

static void check_quoted(const char *input, const char *expected) {
    char out[256];
    memset(out, 0xA5, sizeof(out));
    escape_csv_quoted_content(input, out, sizeof(out));
    check_eq(input && input[0] ? input : "empty-quoted", out, expected);
}

int main(void) {
    static const uint8_t doc_bssid[6] = {0xC4, 0x2B, 0x44, 0x12, 0x29, 0x20};
    static const uint8_t bssid[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    expect_line("plain", "AX3", NULL, 0, 0, doc_bssid, 112, -59,
                WIFI_AUTH_WPA2_WPA3_PSK,
                "\"1\",\"AX3\",\"\",\"C4:2B:44:12:29:20\",\"112\",\"WPA2/WPA3 Mixed\",\"-59\",\"5GHz\"\n");
    expect_line("comma", "foo,bar", "", 1, 0, bssid, 6, -40, WIFI_AUTH_WPA2_PSK,
                "\"1\",\"foo,bar\",\"\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-40\",\"2.4GHz\"\n");
    expect_line("quotes", "moja \"specjalna\" siec", NULL, 0, 2, bssid, 6, -40,
                WIFI_AUTH_WPA2_PSK,
                "\"3\",\"moja \"\"specjalna\"\" siec\",\"\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-40\",\"2.4GHz\"\n");
    expect_line("vendor", "CafeWiFi", "Acme, \"Labs\"", 1, 2, bssid, 6, -40,
                WIFI_AUTH_WPA2_PSK,
                "\"3\",\"CafeWiFi\",\"Acme, \"\"Labs\"\"\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-40\",\"2.4GHz\"\n");
    expect_line("both", "moja \"specjalna\" siec", "Acme, \"Labs\"", 1, 2, bssid, 6, -40,
                WIFI_AUTH_WPA2_PSK,
                "\"3\",\"moja \"\"specjalna\"\" siec\",\"Acme, \"\"Labs\"\"\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-40\",\"2.4GHz\"\n");
    expect_line("crlf", "a\r\nb", "v\n", 1, 0, bssid, 6, -40, WIFI_AUTH_WPA2_PSK,
                "\"1\",\"a\r\nb\",\"v\n\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-40\",\"2.4GHz\"\n");

    char quotes32[33];
    char quotes60[61];
    memset(quotes32, '"', 32);
    quotes32[32] = '\0';
    memset(quotes60, '"', 60);
    quotes60[60] = '\0';
    char monster[512];
    char *p = monster;
    p += sprintf(p, "\"1\",\"");
    for (int i = 0; i < 64; i++) *p++ = '"';
    p += sprintf(p, "\",\"");
    for (int i = 0; i < 120; i++) *p++ = '"';
    sprintf(p, "\",\"AA:BB:CC:DD:EE:FF\",\"6\",\"WPA2\",\"-40\",\"2.4GHz\"\n");
    expect_line("max quotes", quotes32, quotes60, 1, 0, bssid, 6, -40,
                WIFI_AUTH_WPA2_PSK, monster);

    check_wigle("CafeWiFi", "CafeWiFi");
    check_wigle("foo,bar", "\"foo,bar\"");
    check_wigle("foo\"bar", "\"foo\"\"bar\"");
    check_wigle("moja \"specjalna\" siec", "\"moja \"\"specjalna\"\" siec\"");
    check_wigle("a\r\nb", "\"a\r\nb\"");
    check_wigle("", "");

    check_quoted("CafeWiFi", "CafeWiFi");
    check_quoted("foo,bar", "foo,bar");
    check_quoted("foo\"bar", "foo\"\"bar");
    check_quoted("moja \"specjalna\" siec", "moja \"\"specjalna\"\" siec");
    check_quoted("a\r\nb", "a\r\nb");
    check_quoted("", "");
    check_quoted(NULL, "");

    char tiny[4];
    escape_csv_quoted_content("abcd\"", tiny, sizeof(tiny));
    check_eq("truncate", tiny, "abc");
    escape_csv_quoted_content("\"\"", tiny, sizeof(tiny));
    check_eq("one quote fits", tiny, "\"\"");
    char exact[3];
    escape_csv_quoted_content("\"", exact, sizeof(exact));
    check_eq("exact quote", exact, "\"\"");
    char too_small[2];
    escape_csv_quoted_content("\"x", too_small, sizeof(too_small));
    check_eq("quote needs two", too_small, "");
    char sentinel = 0x5A;
    escape_csv_quoted_content("hi", &sentinel, 0);
    assert(sentinel == 0x5A);

    if (failures) {
        fprintf(stderr, "%d scan csv escape failure(s)\n", failures);
        return 1;
    }
    puts("scan csv escape PASS");
    return 0;
}
'''


class ScanCsvEscapeSourceTest(unittest.TestCase):
    def test_scan_path_quotes_content_and_wardrive_keeps_self_wrap(self):
        body = function(MAIN, "print_network_csv")
        self.assertIn("escape_csv_quoted_content", body)
        self.assertNotIn("escape_csv_field", body)
        self.assertIn("char escaped_ssid[32 * 2 + 1]", body)
        self.assertIn(
            "char escaped_vendor[VENDOR_RECORD_NAME_BYTES * 2 + 1]", body)
        self.assertRegex(MAIN, r"#define VENDOR_RECORD_SIZE 64\b")
        self.assertRegex(
            MAIN, r"#define VENDOR_RECORD_NAME_BYTES \(VENDOR_RECORD_SIZE - 4\)")
        self.assertEqual(len(re.findall(r"\bescape_csv_field\s*\(", MAIN)), 5)
        for call in (
            "escape_csv_field(ssid, escaped_ssid",
            "escape_csv_field(wdp_seen_networks[i].ssid, escaped_ssid",
            "escape_csv_field(bt_devices[i].name, escaped_bt_name",
            "escape_csv_field((const char*)ap->ssid, escaped_ssid",
        ):
            self.assertIn(call, MAIN)
        self.assertIn("static void escape_csv_quoted_content(", MAIN)


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run the suite in Linux/WSL")
class ScanCsvEscapeHostTest(unittest.TestCase):
    def test_ssid_and_vendor_quoting(self):
        pieces = [
            function(MAIN, name)
            for name in (
                "escape_csv_field",
                "escape_csv_quoted_content",
                "authmode_to_string",
                "print_network_csv",
            )
        ]
        source = HARNESS.replace("__FIRMWARE_FUNCTIONS__", "\n".join(pieces))
        with tempfile.TemporaryDirectory(prefix="janos-scan-csv-") as temporary:
            path = Path(temporary) / "scan_csv_escape_test.c"
            executable = Path(temporary) / "scan_csv_escape_test"
            path.write_text(source, encoding="utf-8")
            compiled = subprocess.run(
                [
                    os.environ.get("CC", "gcc"),
                    "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                    str(path), "-o", str(executable),
                ],
                cwd=ROOT, capture_output=True, text=True,
            )
            if compiled.returncode != 0:
                self.fail(compiled.stderr)
            ran = subprocess.run(
                [str(executable)], cwd=ROOT, capture_output=True, text=True, timeout=10,
            )
            if ran.returncode != 0:
                self.fail(ran.stderr + ran.stdout)
            self.assertIn("scan csv escape PASS", ran.stdout)


if __name__ == "__main__":
    unittest.main()
