"""Exercise the production Rogue GITM command's host-side preflight."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def extract_command(source):
    """Take the complete C function while ignoring braces in comments/strings."""
    match = re.search(
        r"static\s+int\s+cmd_start_rogue_gitm\s*\([^;{}]*\)\s*\{", source
    )
    if match is None:
        raise AssertionError("cmd_start_rogue_gitm definition was not found")
    function_tail = source[match.start():]
    masked = re.sub(
        r'"(?:\\.|[^"\\])*"|/\*.*?\*/|//[^\n]*',
        lambda match: " " * len(match.group()),
        function_tail,
        flags=re.S,
    )
    depth = 1
    end = match.end() - match.start()
    while depth and end < len(masked):
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    if depth:
        raise AssertionError("cmd_start_rogue_gitm has an unmatched brace")
    return function_tail[:end]


HARNESS = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CAPTURE_GATEWAY_SSID_MAX_LEN 32
#define CAPTURE_GATEWAY_PASSWORD_MIN_LEN 8
#define CAPTURE_GATEWAY_PASSWORD_MAX_LEN 63
#define PCAP_BASENAME_MAX_LEN 95
#define ESP_OK 0
#define pdPASS 1
#define TAG "host"
#define RADIO_MODE_WIFI 1
#define DEAUTH_EVIL_TWIN 2
#define IDLE 0
#define MY_LOG_INFO(...) host_log(__VA_ARGS__)
#define ESP_LOGW(...) host_log(__VA_ARGS__)

typedef int esp_err_t;
typedef int BaseType_t;
typedef struct {
    uint8_t ssid[33];
    uint8_t bssid[6];
    uint8_t primary;
} wifi_ap_record_t;
typedef struct { int unused; } esp_netif_ip_info_t;
typedef struct {
    uint8_t bssid[6];
    uint8_t channel;
} target_bssid_t;

static bool portal_active, deauth_attack_active, pcap_capture_active;
static bool rogue_gitm_mode_active, wifi_initialized, g_scan_done;
static bool upstream_available, gateway_active;
static int current_radio_mode, g_selected_count, g_selected_indices[3];
static int gateway_start_calls, gateway_start_result, task_calls, save_calls;
static int applicationState, target_bssid_count;
static uint16_t g_scan_count;
static int64_t last_channel_check_time;
static void *deauth_attack_task_handle;
static wifi_ap_record_t g_scan_results[3], upstream_record;
static target_bssid_t target_storage[3], *target_bssids = target_storage;

static void host_log(const char *tag, const char *format, ...) {
    (void)tag;
    (void)format;
}
static bool pcap_normalize_basename(const char *requested, char *out, size_t size) {
    if (strlen(requested) >= size) return false;
    strcpy(out, requested);
    return true;
}
static bool capture_gateway_is_active(void) { return gateway_active; }
static void capture_gateway_print_status(void) {}
static bool capture_gateway_wait_for_upstream(int timeout, wifi_ap_record_t *ap,
                                              esp_netif_ip_info_t *ip) {
    assert(timeout == 0);
    (void)ip;
    if (upstream_available) *ap = upstream_record;
    return upstream_available;
}
static int capture_gateway_start_session(const char *ssid, const char *password,
                                         const char *pcap_name, const char *prefix) {
    ++gateway_start_calls;
    assert(strcmp(ssid, "mirror") == 0);
    assert(strcmp(password, "testpass123") == 0);
    assert(strcmp(pcap_name, "") == 0);
    assert(strcmp(prefix, "> Rogue GITM") == 0);
    return gateway_start_result;
}
static void save_target_bssids(void) {
    ++save_calls;
    target_bssid_count = g_selected_count;
    for (int i = 0; i < g_selected_count; ++i) {
        wifi_ap_record_t *ap = &g_scan_results[g_selected_indices[i]];
        memcpy(target_bssids[i].bssid, ap->bssid, 6);
        target_bssids[i].channel = ap->primary;
    }
}
static int64_t esp_timer_get_time(void) { return 1234000; }
static void deauth_attack_task(void *argument) { (void)argument; }
static BaseType_t xTaskCreate(void (*task)(void *), const char *name,
                              int stack, void *argument, int priority,
                              void **handle) {
    assert(task == deauth_attack_task);
    assert(strcmp(name, "deauth_task") == 0);
    assert(stack == 4096 && argument == NULL && priority == 5);
    ++task_calls;
    *handle = &task_calls;
    return pdPASS;
}
static esp_err_t led_set_color(int red, int green, int blue) {
    assert(red == 255 && green == 165 && blue == 0);
    return ESP_OK;
}
static const char *esp_err_to_name(esp_err_t error) {
    (void)error;
    return "ESP_OK";
}

FUNCTION

static void reset_fixture(void) {
    portal_active = false;
    deauth_attack_active = false;
    pcap_capture_active = false;
    rogue_gitm_mode_active = false;
    wifi_initialized = true;
    g_scan_done = true;
    upstream_available = true;
    gateway_active = false;
    current_radio_mode = RADIO_MODE_WIFI;
    g_selected_count = 0;
    gateway_start_calls = 0;
    gateway_start_result = 0;
    task_calls = 0;
    save_calls = 0;
    applicationState = IDLE;
    target_bssid_count = 0;
    g_scan_count = 3;
    last_channel_check_time = 0;
    deauth_attack_task_handle = NULL;
    memset(g_selected_indices, 0, sizeof(g_selected_indices));
    memset(g_scan_results, 0, sizeof(g_scan_results));
    memset(target_storage, 0, sizeof(target_storage));
    memset(&upstream_record, 0, sizeof(upstream_record));

    const uint8_t uplink[6] = {0x02, 0, 0, 0, 0, 0x10};
    const uint8_t target_same_channel[6] = {0x02, 0, 0, 0, 0, 0x20};
    const uint8_t target_off_channel[6] = {0x02, 0, 0, 0, 0, 0x30};
    memcpy(upstream_record.bssid, uplink, 6);
    upstream_record.primary = 6;
    strcpy((char *)upstream_record.ssid, "upstream");
    g_scan_results[0] = upstream_record;
    strcpy((char *)g_scan_results[0].ssid, "renamed-uplink");
    memcpy(g_scan_results[1].bssid, target_same_channel, 6);
    g_scan_results[1].primary = 6;
    strcpy((char *)g_scan_results[1].ssid, "upstream");
    memcpy(g_scan_results[2].bssid, target_off_channel, 6);
    g_scan_results[2].primary = 11;
    strcpy((char *)g_scan_results[2].ssid, "off-channel");
}

static int run_command(void) {
    char *argv[] = {"start_rogue_gitm", "mirror", "testpass123"};
    return cmd_start_rogue_gitm(3, argv);
}
static void assert_preflight_rejection(void) {
    assert(run_command() != 0);
    assert(gateway_start_calls == 0);
    assert(!rogue_gitm_mode_active);
    assert(!deauth_attack_active);
    assert(task_calls == 0 && save_calls == 0);
}

int main(void) {
    /* A selected STA uplink BSSID must never reach SoftAP startup. */
    reset_fixture();
    g_selected_count = 1;
    g_selected_indices[0] = 0;
    assert_preflight_rejection();

    /* Channel mismatch blocks startup even though the BSSID is different. */
    reset_fixture();
    g_selected_count = 1;
    g_selected_indices[0] = 2;
    assert_preflight_rejection();

    /* Every target must pass; one valid target cannot hide a bad one. */
    reset_fixture();
    g_selected_count = 2;
    g_selected_indices[0] = 1;
    g_selected_indices[1] = 2;
    assert_preflight_rejection();
    reset_fixture();
    g_selected_count = 2;
    g_selected_indices[0] = 1;
    g_selected_indices[1] = 0;
    assert_preflight_rejection();

    reset_fixture();
    g_selected_count = 1;
    g_selected_indices[0] = 1;
    g_scan_done = false;
    assert_preflight_rejection();
    reset_fixture();
    g_selected_count = 1;
    g_selected_indices[0] = 3;
    assert_preflight_rejection();

    /* A same-channel, different-BSSID target starts GITM and deauth. */
    reset_fixture();
    g_selected_count = 1;
    g_selected_indices[0] = 1;
    assert(run_command() == 0);
    assert(gateway_start_calls == 1 && rogue_gitm_mode_active);
    assert(deauth_attack_active && task_calls == 1 && save_calls == 1);
    assert(applicationState == DEAUTH_EVIL_TWIN);
    assert(target_bssid_count == 1);
    assert(memcmp(target_bssids[0].bssid, g_scan_results[1].bssid, 6) == 0);

    /* Without a selection, GITM starts as SoftAP only. */
    reset_fixture();
    assert(run_command() == 0);
    assert(gateway_start_calls == 1 && rogue_gitm_mode_active);
    assert(!deauth_attack_active && task_calls == 0 && save_calls == 0);

    reset_fixture();
    g_selected_count = 1;
    g_selected_indices[0] = 1;
    upstream_available = false;
    assert_preflight_rejection();

    /* A failure from the start operation must not enable GITM/deauth. */
    reset_fixture();
    g_selected_count = 1;
    g_selected_indices[0] = 1;
    gateway_start_result = 7;
    assert(run_command() == 7);
    assert(gateway_start_calls == 1 && !rogue_gitm_mode_active);
    assert(!deauth_attack_active && task_calls == 0 && save_calls == 0);

    puts("PASS: Rogue GITM uplink/channel preflight and allowed startup paths");
    return 0;
}
'''


class RogueGitmHostTest(unittest.TestCase):
    def test_selection_preflight_executes_production_handler(self):
        compiler = next(
            (shutil.which(name) for name in
             (os.environ.get("CC", ""), "cc", "gcc", "clang")
             if name and shutil.which(name)),
            None,
        )
        if compiler is None:
            self.fail("Host C compiler required; run this test under WSL if needed")

        source = (ROOT / "main" / "main.c").read_text(encoding="utf-8")
        command = extract_command(source)
        with tempfile.TemporaryDirectory(prefix="rogue-gitm-host-") as directory:
            fixture = Path(directory) / "command.c"
            executable = Path(directory) / "command"
            fixture.write_text(HARNESS.replace("FUNCTION", command), encoding="utf-8")
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
            self.assertIn("PASS: Rogue GITM uplink/channel preflight", run.stdout)


if __name__ == "__main__":
    unittest.main()
