"""Run the production Capture Gateway session orchestrator on a C host."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def extract_session(source):
    match = re.search(
        r"static\s+int\s+capture_gateway_start_session\s*\([^;{}]*\)\s*\{",
        source,
    )
    if match is None:
        raise AssertionError("capture_gateway_start_session definition was not found")
    tail = source[match.start():]
    masked = re.sub(
        r'"(?:\\.|[^"\\])*"|/\*.*?\*/|//[^\n]*',
        lambda item: " " * len(item.group()),
        tail,
        flags=re.S,
    )
    depth = 1
    end = match.end() - match.start()
    while depth and end < len(masked):
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    if depth:
        raise AssertionError("capture_gateway_start_session has an unmatched brace")
    return tail[:end]


HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CAPTURE_GATEWAY_SSID_MAX_LEN 32
#define CAPTURE_GATEWAY_PASSWORD_MIN_LEN 8
#define CAPTURE_GATEWAY_PASSWORD_MAX_LEN 63
#define CAPTURE_GATEWAY_DEFAULT_MAX_CLIENTS 4
#define PCAP_BASENAME_MAX_LEN 95
#define ESP_OK 0
#define WIFI_MODE_STA 1
#define WIFI_MODE_APSTA 3
#define RADIO_MODE_WIFI 1
#define TAG "host"
#define MY_LOG_INFO(...) host_log(__VA_ARGS__)

typedef int esp_err_t;
typedef struct { int marker; } esp_netif_t;
typedef struct { uint8_t primary; } wifi_ap_record_t;
typedef struct { int unused; } esp_netif_ip_info_t;
typedef struct {
    const char *ssid;
    const char *password;
    uint8_t channel;
    int max_clients;
} capture_gateway_config_t;

enum {
    EV_WAIT_INITIAL = 1, EV_ENSURE_APSTA, EV_WAIT_500, EV_CONNECT,
    EV_WAIT_15000, EV_STA_NETIF, EV_GATEWAY_START, EV_PCAP_ARM,
    EV_OLED, EV_STATUS, EV_GATEWAY_STOP, EV_MODE_STA
};
enum { UPSTREAM_MISSING, UPSTREAM_FAST, UPSTREAM_RECOVERED, UPSTREAM_TIMEOUT };

static int events[16], event_count;
static int upstream_case, wifi_mode, current_radio_mode;
static int connect_calls, start_calls, stop_calls, pcap_calls, status_calls;
static int oled_calls, sta_mode_calls, gateway_start_error, pcap_arm_error;
static int configured_channel, configured_max_clients;
static bool wifi_initialized, gateway_active, pcap_active;
static bool operation_stop_requested, radio_busy, apsta_fails, sta_netif_missing;
static char pcap_next_basename[PCAP_BASENAME_MAX_LEN + 1];
static esp_netif_t ap_netif = {1}, sta_netif = {2};

static void event(int value) {
    assert(event_count < (int)(sizeof(events) / sizeof(events[0])));
    events[event_count++] = value;
}
static void host_log(const char *tag, const char *format, ...) {
    (void)tag;
    (void)format;
}
static bool capture_gateway_is_active(void) { return gateway_active; }
static void capture_gateway_print_status(void) {
    event(EV_STATUS);
    ++status_calls;
    assert(gateway_active && pcap_active);
}
static bool zig_recon_radio_busy(char *reason, size_t length) {
    if (radio_busy) snprintf(reason, length, "busy");
    return radio_busy;
}
static bool capture_gateway_wait_for_upstream(int timeout, wifi_ap_record_t *ap,
                                              esp_netif_ip_info_t *ip) {
    (void)ip;
    if (timeout == 0) {
        event(EV_WAIT_INITIAL);
        if (upstream_case == UPSTREAM_MISSING) return false;
        ap->primary = 6;
        return true;
    }
    if (timeout == 500) {
        event(EV_WAIT_500);
        if (upstream_case != UPSTREAM_FAST) return false;
        ap->primary = 6;
        return true;
    }
    assert(timeout == 15000);
    event(EV_WAIT_15000);
    if (upstream_case != UPSTREAM_RECOVERED) return false;
    ap->primary = 11;
    return true;
}
static esp_netif_t *ensure_ap_mode(void) {
    event(EV_ENSURE_APSTA);
    if (apsta_fails) return NULL;
    wifi_mode = WIFI_MODE_APSTA;
    return &ap_netif;
}
static esp_err_t analyzer_tracked_wifi_connect(void) {
    event(EV_CONNECT);
    ++connect_calls;
    assert(wifi_mode == WIFI_MODE_APSTA);
    return ESP_OK;
}
static esp_err_t esp_wifi_set_mode(int mode) {
    assert(mode == WIFI_MODE_STA);
    event(EV_MODE_STA);
    ++sta_mode_calls;
    wifi_mode = mode;
    return ESP_OK;
}
static esp_netif_t *esp_netif_get_handle_from_ifkey(const char *key) {
    event(EV_STA_NETIF);
    assert(strcmp(key, "WIFI_STA_DEF") == 0);
    return sta_netif_missing ? NULL : &sta_netif;
}
static esp_err_t capture_gateway_start(esp_netif_t *ap, esp_netif_t *sta,
                                       const capture_gateway_config_t *config) {
    event(EV_GATEWAY_START);
    ++start_calls;
    assert(ap == &ap_netif && sta == &sta_netif);
    assert(wifi_mode == WIFI_MODE_APSTA);
    assert(strcmp(config->ssid, "capture") == 0);
    assert(strcmp(config->password, "testpass123") == 0);
    configured_channel = config->channel;
    configured_max_clients = config->max_clients;
    if (gateway_start_error != ESP_OK) return gateway_start_error;
    gateway_active = true;
    return ESP_OK;
}
static esp_err_t capture_gateway_stop(void) {
    event(EV_GATEWAY_STOP);
    ++stop_calls;
    assert(gateway_active);
    gateway_active = false;
    return ESP_OK;
}
static size_t strlcpy(char *destination, const char *source, size_t capacity) {
    size_t length = strlen(source);
    if (capacity) {
        size_t copied = length < capacity - 1 ? length : capacity - 1;
        memcpy(destination, source, copied);
        destination[copied] = '\0';
    }
    return length;
}
static int cmd_start_pcap(int argc, char **argv) {
    event(EV_PCAP_ARM);
    ++pcap_calls;
    assert(argc == 2 && strcmp(argv[0], "start_pcap") == 0);
    assert(strcmp(argv[1], "gateway") == 0);
    assert(wifi_mode == WIFI_MODE_APSTA && gateway_active);
    assert(!operation_stop_requested);
    if (pcap_arm_error) return pcap_arm_error;
    pcap_active = true;
    return 0;
}
static void oled_display_update_full(const char *title, const char *ssid,
                                     const char *mode, const char *recorder) {
    event(EV_OLED);
    ++oled_calls;
    assert(gateway_active && pcap_active);
    assert(strcmp(title, "> Capture GW") == 0);
    assert(strcmp(ssid, "capture") == 0);
    assert(strcmp(mode, "  APSTA + NAPT") == 0);
    assert(strcmp(recorder, "  PCAP armed") == 0);
}
static const char *esp_err_to_name(esp_err_t error) {
    (void)error;
    return "HOST_ERROR";
}

FUNCTION

static void reset_fixture(int scenario) {
    memset(events, 0, sizeof(events));
    event_count = 0;
    upstream_case = scenario;
    wifi_mode = WIFI_MODE_STA;
    current_radio_mode = RADIO_MODE_WIFI;
    wifi_initialized = true;
    gateway_active = false;
    pcap_active = false;
    operation_stop_requested = true;
    radio_busy = false;
    apsta_fails = false;
    sta_netif_missing = false;
    connect_calls = start_calls = stop_calls = pcap_calls = 0;
    status_calls = oled_calls = sta_mode_calls = 0;
    gateway_start_error = pcap_arm_error = 0;
    configured_channel = configured_max_clients = -1;
    memset(pcap_next_basename, 0x5a, sizeof(pcap_next_basename));
}
static void assert_events(const int *expected, int count) {
    assert(event_count == count);
    assert(memcmp(events, expected, count * sizeof(events[0])) == 0);
}
static int start_session(const char *name, const char *title) {
    return capture_gateway_start_session("capture", "testpass123", name, title);
}
static void assert_no_false_active_status(void) {
    assert(!gateway_active && !pcap_active);
    assert(status_calls == 0 && oled_calls == 0);
}

int main(void) {
    /* Recovery may change the STA channel; the gateway must use the fresh one. */
    reset_fixture(UPSTREAM_RECOVERED);
    assert(start_session("session.pcap", "> Capture GW") == 0);
    assert_events((int[]){EV_WAIT_INITIAL, EV_ENSURE_APSTA, EV_WAIT_500,
                          EV_CONNECT, EV_WAIT_15000, EV_STA_NETIF,
                          EV_GATEWAY_START, EV_PCAP_ARM, EV_OLED, EV_STATUS}, 10);
    assert(connect_calls == 1 && start_calls == 1 && pcap_calls == 1);
    assert(configured_channel == 11);
    assert(configured_max_clients == CAPTURE_GATEWAY_DEFAULT_MAX_CLIENTS);
    assert(strcmp(pcap_next_basename, "session.pcap") == 0);
    assert(gateway_active && pcap_active && wifi_mode == WIFI_MODE_APSTA);
    assert(!operation_stop_requested && status_calls == 1 && oled_calls == 1);

    /* An already-stable uplink starts directly and uses automatic PCAP naming. */
    reset_fixture(UPSTREAM_FAST);
    assert(start_session("", NULL) == 0);
    assert_events((int[]){EV_WAIT_INITIAL, EV_ENSURE_APSTA, EV_WAIT_500,
                          EV_STA_NETIF, EV_GATEWAY_START, EV_PCAP_ARM,
                          EV_OLED, EV_STATUS}, 8);
    assert(connect_calls == 0 && configured_channel == 6);
    assert(pcap_next_basename[0] == '\0');
    assert(gateway_active && pcap_active && status_calls == 1);

    reset_fixture(UPSTREAM_MISSING);
    assert(start_session("", NULL) != 0);
    assert_events((int[]){EV_WAIT_INITIAL}, 1);
    assert(start_calls == 0 && pcap_calls == 0 && sta_mode_calls == 0);
    assert_no_false_active_status();

    reset_fixture(UPSTREAM_TIMEOUT);
    assert(start_session("", NULL) != 0);
    assert_events((int[]){EV_WAIT_INITIAL, EV_ENSURE_APSTA, EV_WAIT_500,
                          EV_CONNECT, EV_WAIT_15000, EV_MODE_STA}, 6);
    assert(wifi_mode == WIFI_MODE_STA && sta_mode_calls == 1);
    assert(start_calls == 0 && pcap_calls == 0);
    assert_no_false_active_status();

    reset_fixture(UPSTREAM_FAST);
    gateway_start_error = 71;
    assert(start_session("", NULL) != 0);
    assert_events((int[]){EV_WAIT_INITIAL, EV_ENSURE_APSTA, EV_WAIT_500,
                          EV_STA_NETIF, EV_GATEWAY_START, EV_MODE_STA}, 6);
    assert(start_calls == 1 && pcap_calls == 0 && stop_calls == 0);
    assert(wifi_mode == WIFI_MODE_STA && sta_mode_calls == 1);
    assert_no_false_active_status();

    reset_fixture(UPSTREAM_RECOVERED);
    pcap_arm_error = 72;
    assert(start_session("failed.pcap", NULL) != 0);
    assert_events((int[]){EV_WAIT_INITIAL, EV_ENSURE_APSTA, EV_WAIT_500,
                          EV_CONNECT, EV_WAIT_15000, EV_STA_NETIF,
                          EV_GATEWAY_START, EV_PCAP_ARM, EV_GATEWAY_STOP,
                          EV_MODE_STA}, 10);
    assert(start_calls == 1 && pcap_calls == 1 && stop_calls == 1);
    assert(wifi_mode == WIFI_MODE_STA && sta_mode_calls == 1);
    assert_no_false_active_status();

    puts("PASS: production Capture Gateway session startup and rollback");
    return 0;
}
'''


class CaptureGatewaySessionHostTest(unittest.TestCase):
    def test_session_startup_recovery_and_rollback(self):
        compiler = next(
            (shutil.which(name) for name in
             (os.environ.get("CC", ""), "cc", "gcc", "clang")
             if name and shutil.which(name)),
            None,
        )
        if compiler is None:
            self.fail("Host C compiler required; run this test under WSL if needed")

        source = (ROOT / "main" / "main.c").read_text(encoding="utf-8")
        session = extract_session(source)
        with tempfile.TemporaryDirectory(prefix="capture-gateway-session-") as directory:
            fixture = Path(directory) / "session.c"
            executable = Path(directory) / "session"
            fixture.write_text(HARNESS.replace("FUNCTION", session), encoding="utf-8")
            build = subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 str(fixture), "-o", str(executable)],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            run = subprocess.run(
                [str(executable)], capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            self.assertIn("PASS: production Capture Gateway session", run.stdout)


if __name__ == "__main__":
    unittest.main()
