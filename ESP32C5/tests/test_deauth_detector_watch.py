"""Host checks for the real deauth_detector command and receive callback.

Run with: python3 -B -m unittest discover -s tests -p test_deauth_detector_watch.py -v
The harness extracts production functions from main.c and stubs only ESP-IDF
hardware/task calls. It never builds firmware or transmits radio frames.
"""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def function(source, name):
    masked = re.sub(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
        lambda match: " " * len(match.group()),
        source,
        flags=re.S,
    )
    match = re.search(r"\b" + name + r"\s*\([^;{}]*\)\s*\{", masked)
    if not match:
        raise ValueError(name)
    start = source.rfind("\n", 0, match.start()) + 1
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return source[start:end]


HARNESS_PREFIX = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "csa_detector_core.h"
#if defined(__has_include)
#if __has_include("deauth_target_core.h")
#include "deauth_target_core.h"
#endif
#endif

#define MAX_AP_CNT 64
static char logged[8192];
static size_t logged_size;
static bool mutate_on_monitoring_log, pending_scan_mutation, scan_mutex_locked;
static bool saw_scan_mutation;
static void replace_scan_record(void);
static void test_log(const char *format, ...) {
    if (logged_size >= sizeof(logged) - 2) return;
    size_t line_start = logged_size;
    va_list args;
    va_start(args, format);
    int written = vsnprintf(logged + logged_size, sizeof(logged) - logged_size,
                            format, args);
    va_end(args);
    if (written < 0) return;
    if ((size_t)written >= sizeof(logged) - logged_size) {
        logged_size = sizeof(logged) - 1;
        return;
    }
    logged_size += (size_t)written;
    logged[logged_size++] = '\n';
    logged[logged_size] = '\0';
    if (mutate_on_monitoring_log &&
        !strncmp(logged + line_start, "Monitoring ", 11)) {
        mutate_on_monitoring_log = false;
        if (scan_mutex_locked) pending_scan_mutation = true;
        else replace_scan_record();
    }
}
#define MY_LOG_INFO(tag, ...) test_log(__VA_ARGS__)
#define WIFI_PROMIS_FILTER_MASK_MGMT 1
#define WIFI_SECOND_CHAN_NONE 0
#define ESP_OK 0
#define ESP_ERR_INVALID_STATE 5
#define pdPASS 1
#define pdTRUE 1
#define pdMS_TO_TICKS(ms) (ms)
#define portMAX_DELAY 0xffffffffu
#define TAG "test"
typedef int esp_err_t;
typedef int BaseType_t;
typedef int TaskHandle_t;
typedef void *SemaphoreHandle_t;
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(lock) ((void)(lock))
#define portEXIT_CRITICAL(lock) ((void)(lock))
typedef enum { WIFI_PKT_MGMT, WIFI_PKT_DATA } wifi_promiscuous_pkt_type_t;
typedef struct {
    struct { unsigned sig_len, dump_len, rx_state; int8_t rssi; uint8_t channel; } rx_ctrl;
    uint8_t payload[256];
} wifi_promiscuous_pkt_t;
typedef struct { int filter_mask; } wifi_promiscuous_filter_t;
typedef struct { uint8_t bssid[6], ssid[33]; int primary; } wifi_ap_record_t;

static wifi_ap_record_t g_scan_results[MAX_AP_CNT];
static unsigned g_scan_count;
static bool g_scan_done, g_scan_in_progress, operation_stop_requested;
static bool g_scan_records_valid = true;
static SemaphoreHandle_t g_scan_results_mutex = (void *)1;
static bool sniffer_active, sniffer_dog_active, deauth_detector_active;
static int deauth_detector_current_channel, deauth_detector_channel_index;
static int64_t deauth_detector_last_channel_hop;
static TaskHandle_t deauth_detector_task_handle;
static int dual_band_channels[] = {1, 6, 11, 36};
static int g_scan_min_channel_time = 100, g_scan_max_channel_time = 200;
static int receiver_setup_calls, scan_calls;
static bool receiver_enabled;
static int64_t clock_us = 2000000;

static void replace_scan_record(void) {
    memcpy(g_scan_results[0].bssid, g_scan_results[2].bssid, 6);
    strcpy((char *)g_scan_results[0].ssid, "Changed");
    g_scan_results[0].primary = 11;
    saw_scan_mutation = true;
}
static BaseType_t xSemaphoreTake(SemaphoreHandle_t mutex, unsigned timeout)
    {(void)mutex; (void)timeout; assert(!scan_mutex_locked);
     scan_mutex_locked = true; return pdTRUE;}
static BaseType_t xSemaphoreGive(SemaphoreHandle_t mutex)
    {(void)mutex; assert(scan_mutex_locked); scan_mutex_locked = false;
     if (pending_scan_mutation) {
         pending_scan_mutation = false;
         replace_scan_record();
     }
     return pdTRUE;}

static void oled_display_update_full(const char *a, const char *b,
                                     const char *c, const char *d)
    {(void)a; (void)b; (void)c; (void)d;}
static void log_memory_info(const char *text) {(void)text;}
static bool ensure_wifi_mode(void) {return true;}
static void vTaskDelay(int ms) {(void)ms;}
static int64_t esp_timer_get_time(void) {return clock_us;}
static const char *esp_err_to_name(int err) {(void)err; return "fixture";}
static esp_err_t start_background_scan(int min, int max)
    {(void)min; (void)max; ++scan_calls; g_scan_done = true;
     g_scan_in_progress = false; return ESP_OK;}
static void esp_wifi_scan_stop(void) {}
static esp_err_t esp_wifi_set_promiscuous_filter(const wifi_promiscuous_filter_t *filter)
    {(void)filter; ++receiver_setup_calls; return ESP_OK;}
static esp_err_t esp_wifi_set_promiscuous_rx_cb(
    void (*callback)(void *, wifi_promiscuous_pkt_type_t))
    {(void)callback; ++receiver_setup_calls; return ESP_OK;}
static esp_err_t esp_wifi_set_promiscuous(bool enabled)
    {receiver_enabled = enabled; ++receiver_setup_calls; return ESP_OK;}
static esp_err_t esp_wifi_set_channel(int channel, int secondary)
    {(void)channel; (void)secondary; return ESP_OK;}
static void deauth_detector_task(void *arg) {(void)arg;}
static int xTaskCreate(void (*run)(void *), const char *name, int stack,
                       void *arg, int priority, TaskHandle_t *handle)
    {(void)run; (void)name; (void)stack; (void)arg; (void)priority;
     *handle = 1; return pdPASS;}
static void deauth_detector_promiscuous_callback(
    void *buf, wifi_promiscuous_pkt_type_t type);
"""


HARNESS_SCENARIOS = r"""
static const uint8_t AP_A[6] = {0x02, 0, 0, 0, 0, 1};
static const uint8_t AP_B[6] = {0x02, 0, 0, 0, 0, 2};
static const uint8_t AP_C[6] = {0x02, 0, 0, 0, 0, 3};

static void scan_fixture(void) {
    g_scan_done = true;
    g_scan_in_progress = false;
    g_scan_records_valid = true;
    g_scan_count = 3;
    memcpy(g_scan_results[0].bssid, AP_A, 6);
    memcpy(g_scan_results[1].bssid, AP_B, 6);
    memcpy(g_scan_results[2].bssid, AP_C, 6);
    strcpy((char *)g_scan_results[0].ssid, "Office");
    strcpy((char *)g_scan_results[1].ssid, "Office");
    strcpy((char *)g_scan_results[2].ssid, "Guest");
    g_scan_results[0].primary = 6;
    g_scan_results[1].primary = 6;
    g_scan_results[2].primary = 11;
}

static void send_deauth(const uint8_t bssid[6], uint8_t channel) {
    wifi_promiscuous_pkt_t packet = {0};
    packet.rx_ctrl.sig_len = packet.rx_ctrl.dump_len = 30;
    packet.rx_ctrl.channel = channel;
    packet.rx_ctrl.rssi = -50;
    packet.payload[0] = 0xc0;
    memcpy(packet.payload + 16, bssid, 6);
    deauth_detector_promiscuous_callback(&packet, WIFI_PKT_MGMT);
}

static void send_csa(const uint8_t bssid[6], uint8_t channel) {
    wifi_promiscuous_pkt_t packet = {0};
    packet.rx_ctrl.sig_len = packet.rx_ctrl.dump_len = 51;
    packet.rx_ctrl.channel = channel;
    packet.rx_ctrl.rssi = -51;
    packet.payload[0] = 0x80;
    memcpy(packet.payload + 10, "\x02\x11\x22\x33\x44\x55", 6);
    memcpy(packet.payload + 16, bssid, 6);
    memcpy(packet.payload + 36, "\x00\x04" "Test" "\x25\x03\x01\x0b\x03", 11);
    deauth_detector_promiscuous_callback(&packet, WIFI_PKT_MGMT);
}

static void stop_fixture(void) {
    deauth_detector_active = false;
    deauth_detector_task_handle = 0;
    deauth_detector_close_events();
    receiver_enabled = false;
    receiver_setup_calls = 0;
}

static bool line_contains(const char *start, const char *end, const char *text) {
    const char *found = strstr(start, text);
    return found && found < end;
}

static bool watch_status_has(int count, const char *bssid) {
    char count_field[32];
    snprintf(count_field, sizeof(count_field), "count=%d", count);
    const char *line = logged;
    while (*line) {
        const char *end = strchr(line, '\n');
        if (!end) end = line + strlen(line);
        if (!strncmp(line, "[DETECTOR_WATCH] ", 17) &&
            line_contains(line, end, count_field) &&
            line_contains(line, end, bssid) &&
            (size_t)(end - line) < 160) return true;
        line = *end ? end + 1 : end;
    }
    return false;
}

static int used_csa_rate_slots(void) {
    int used = 0;
    for (size_t i = 0; i < CSA_RATE_SLOTS; ++i)
        if (detector_csa_rate.slots[i].used) ++used;
    return used;
}

static void one_target(void) {
    char *args[] = {"deauth_detector", "--only", "1"};
    assert(cmd_deauth_detector(3, args) == 0);
    assert(scan_calls == 0 && receiver_enabled);
    assert(watch_status_has(1, "02:00:00:00:00:01"));
    assert(!strstr(logged, "\n[DEAUTH]") && !strstr(logged, "\n[CSA]"));
    assert(deauth_detector_selected_mode && deauth_detector_selected_channels_count == 1);
    assert(deauth_detector_selected_channels[0] == 6);
    send_deauth(AP_B, 6);
    send_csa(AP_B, 6);
    assert(detector_event_count == 0 && detector_dropped == 0);
    assert(used_csa_rate_slots() == 0 && detector_csa_rate.capacity_dropped == 0);
    send_deauth(AP_A, 6);
    send_csa(AP_A, 6);
    assert(detector_event_count == 2);
    assert(used_csa_rate_slots() == 1);
    assert(!memcmp(detector_events[0].observation.bssid, AP_A, 6));
    assert(!memcmp(detector_events[1].observation.bssid, AP_A, 6));
    assert(!detector_events[0].is_csa && detector_events[1].is_csa);
}

static void multiple_targets(void) {
    char *args[] = {"deauth_detector", "--only", "1", "3"};
    assert(cmd_deauth_detector(4, args) == 0);
    assert(scan_calls == 0 && receiver_enabled);
    assert(watch_status_has(2, "02:00:00:00:00:01"));
    assert(watch_status_has(2, "02:00:00:00:00:03"));
    assert(deauth_detector_selected_mode && deauth_detector_selected_channels_count == 2);
    assert(deauth_detector_selected_channels[0] == 6);
    assert(deauth_detector_selected_channels[1] == 11);
    send_deauth(AP_A, 6);
    send_deauth(AP_B, 6);
    send_deauth(AP_C, 11);
    assert(detector_event_count == 2);
    assert(!memcmp(detector_events[0].observation.bssid, AP_A, 6));
    assert(!memcmp(detector_events[1].observation.bssid, AP_C, 6));
}

static void invalid_requests(void) {
    char *missing[] = {"deauth_detector", "--only"};
    char *partial[] = {"deauth_detector", "--only", "1x"};
    char *mixed[] = {"deauth_detector", "--only", "1", "999"};
    char *zero[] = {"deauth_detector", "--only", "0"};
    struct { int count; char **args; } invalid[] = {
        {2, missing}, {3, partial}, {4, mixed}, {3, zero},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        assert(cmd_deauth_detector(invalid[i].count, invalid[i].args) == 1);
        assert(!deauth_detector_active && !receiver_enabled);
        assert(receiver_setup_calls == 0 && !deauth_detector_task_handle);
    }
    g_scan_done = false;
    assert(cmd_deauth_detector(3, partial) == 1);
    assert(!deauth_detector_active && !receiver_enabled && !receiver_setup_calls);
    g_scan_done = true;
    g_scan_in_progress = true;
    char *valid[] = {"deauth_detector", "--only", "1"};
    assert(cmd_deauth_detector(3, valid) == 1);
    assert(!deauth_detector_active && !receiver_enabled && !receiver_setup_calls);
    assert(scan_calls == 0);
}

static void legacy_indices(void) {
    char *args[] = {"deauth_detector", "1"};
    assert(cmd_deauth_detector(2, args) == 0);
    assert(strstr(logged,
        "Deauth Detector started - monitoring selected channels for deauth frames...\n"));
    assert(strstr(logged,
        "Output: [DEAUTH] CH: <ch> | AP: <name> (<bssid>) | RSSI: <rssi>\n"));
    assert(deauth_detector_selected_mode && deauth_detector_selected_channels_count == 1);
    send_deauth(AP_B, 6); /* same channel, different BSSID remains visible */
    assert(detector_event_count == 1);
    assert(!memcmp(detector_events[0].observation.bssid, AP_B, 6));
}

static void restart_unfiltered(void) {
    char *targeted[] = {"deauth_detector", "--only", "1"};
    char *all[] = {"deauth_detector"};
    assert(cmd_deauth_detector(3, targeted) == 0);
    send_deauth(AP_B, 6);
    assert(detector_event_count == 0);
    stop_fixture();
    assert(cmd_deauth_detector(1, all) == 0);
    assert(strstr(logged,
        "Deauth Detector started - scanning all channels for deauth frames...\n"));
    assert(scan_calls == 1 && !deauth_detector_selected_mode);
    send_deauth(AP_B, 6);
    assert(detector_event_count == 1);
}

static void invalid_scan_records(void) {
    char *args[] = {"deauth_detector", "--only", "1"};
    g_scan_records_valid = false; /* scan finished, record fetch failed */
    assert(g_scan_done && g_scan_count == 3 && !g_scan_in_progress);
    assert(cmd_deauth_detector(3, args) == 1);
    assert(!deauth_detector_active && !receiver_enabled);
    assert(receiver_setup_calls == 0 && !deauth_detector_task_handle);
}

static void replaced_scan_same_count(void) {
    char *args[] = {"deauth_detector", "--only", "1"};
    mutate_on_monitoring_log = true;
    assert(cmd_deauth_detector(3, args) == 0);
    assert(saw_scan_mutation && g_scan_count == 3 && receiver_enabled);
    /* Index 1 was Office on channel 6 at selection time. The later live
       replacement must not mix its BSSID/channel with another cache image. */
    assert(strstr(logged,
        "[DETECTOR_WATCH] count=1 ap=1/1 CH=6 BSSID=02:00:00:00:00:01 SSID=Office"));
    assert(detector_cache_count == 3);
    assert(!memcmp(detector_cache[0].bssid, AP_A, 6));
    assert(detector_cache[0].channel == 6);
    assert(!strcmp(detector_cache[0].ssid, "Office"));
    send_deauth(AP_A, 6);
    assert(detector_event_count == 1);
    assert(!strcmp(detector_events[0].legacy_ssid, "Office"));
}

static void mixed_or_misspelled_options(void) {
    char *mixed[] = {"deauth_detector", "1", "--only", "2"};
    char *misspelled[] = {"deauth_detector", "--onl", "1"};
    assert(cmd_deauth_detector(4, mixed) == 1);
    assert(!deauth_detector_active && !receiver_enabled && !receiver_setup_calls);
    assert(cmd_deauth_detector(3, misspelled) == 1);
    assert(!deauth_detector_active && !receiver_enabled && !receiver_setup_calls);
    assert(scan_calls == 0);
}

static void legacy_missing_scan_message(void) {
    char *args[] = {"deauth_detector", "1"};
    g_scan_done = false;
    assert(cmd_deauth_detector(2, args) == 1);
    assert(strstr(logged,
        "No scan results available. Run 'scan_networks' first.\n"));
    assert(!receiver_enabled && !receiver_setup_calls);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    scan_fixture();
    if (!strcmp(argv[1], "one")) one_target();
    else if (!strcmp(argv[1], "multi")) multiple_targets();
    else if (!strcmp(argv[1], "invalid")) invalid_requests();
    else if (!strcmp(argv[1], "legacy")) legacy_indices();
    else if (!strcmp(argv[1], "restart")) restart_unfiltered();
    else if (!strcmp(argv[1], "records")) invalid_scan_records();
    else if (!strcmp(argv[1], "replace")) replaced_scan_same_count();
    else if (!strcmp(argv[1], "options")) mixed_or_misspelled_options();
    else if (!strcmp(argv[1], "legacy-message")) legacy_missing_scan_message();
    else return 2;
    puts("watch PASS");
    return 0;
}
"""


class DeauthDetectorWatchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        begin = source.index("// Detector event pipeline (fixed storage")
        end = source.index("// Wardrive task", begin)
        code = HARNESS_PREFIX + source[begin:end]
        for name in (
            "deauth_detector_reset_events",
            "deauth_detector_close_events",
            "cmd_deauth_detector",
            "deauth_detector_promiscuous_callback",
        ):
            code += "\n" + function(source, name)
        code += HARNESS_SCENARIOS
        cls.temporary = tempfile.TemporaryDirectory(prefix="janos-deauth-watch-")
        cls.addClassCleanup(cls.temporary.cleanup)
        directory = Path(cls.temporary.name)
        harness = directory / "watch.c"
        cls.binary = directory / "watch"
        harness.write_text(code, encoding="utf-8")
        files = [harness, ROOT / "main/csa_detector_core.c"]
        target_core = ROOT / "main/deauth_target_core.c"
        if target_core.exists():
            files.append(target_core)
        subprocess.run(
            [
                "cc", "-std=c11", "-Wall", "-Wextra", "-Wno-unused-function",
                "-Wno-unused-variable", "-I", str(ROOT / "main"),
                *map(str, files), "-o", str(cls.binary),
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    def check_scenario(self, name):
        result = subprocess.run(
            [str(self.binary), name], capture_output=True, text=True
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "watch PASS\n")

    def test_only_one_ap_ignores_other_bssid_on_same_channel(self):
        self.check_scenario("one")

    def test_only_multiple_aps_uses_exact_bssids_and_selected_channels(self):
        self.check_scenario("multi")

    def test_only_rejects_malformed_or_unstable_scan_without_receiver(self):
        self.check_scenario("invalid")

    def test_legacy_indices_still_select_channels_without_filtering(self):
        self.check_scenario("legacy")

    def test_stop_and_restart_without_only_clears_filter(self):
        self.check_scenario("restart")

    def test_completed_scan_with_failed_record_fetch_is_not_watchable(self):
        self.check_scenario("records")

    def test_same_count_scan_replacement_keeps_one_coherent_snapshot(self):
        self.check_scenario("replace")

    def test_mixed_or_misspelled_options_do_not_start_unfiltered(self):
        self.check_scenario("options")

    def test_legacy_no_scan_message_is_unchanged(self):
        self.check_scenario("legacy-message")


if __name__ == "__main__":
    unittest.main()
