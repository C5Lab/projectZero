"""Host checks for deauth_detector, deauth_detector_v2, and their receive callback.

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
static int dual_band_channels[] = {1, 6, 11, 36, 40, 44};
static const int dual_band_channels_count =
    sizeof(dual_band_channels) / sizeof(dual_band_channels[0]);
static const int sniffer_channel_hop_delay_ms = 250;
static int g_scan_min_channel_time = 100, g_scan_max_channel_time = 200;
static int receiver_setup_calls, scan_calls;
static bool receiver_enabled;
static bool fail_channel_tune, inject_event_during_start;
static int channel_tune_calls, last_successful_channel;
static int channel_tune_history[64];
static int64_t clock_us = 2000000;
static unsigned threat_events;
#define LED_STATUS_EVENT_THREAT 1
static void led_status_notify_event(int event)
    {(void)event; ++threat_events;}
static void deauth_detector_process_events(void);
static void deauth_detector_promiscuous_callback(
    void *buf, wifi_promiscuous_pkt_type_t type);

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
    {assert(secondary == WIFI_SECOND_CHAN_NONE);
     assert(channel_tune_calls < (int)(sizeof(channel_tune_history) /
                                       sizeof(channel_tune_history[0])));
     channel_tune_history[channel_tune_calls++] = channel;
     if (fail_channel_tune) return ESP_ERR_INVALID_STATE;
     last_successful_channel = channel;
     return ESP_OK;}
static void deauth_detector_task(void *arg) {(void)arg;}
static int xTaskCreate(void (*run)(void *), const char *name, int stack,
                       void *arg, int priority, TaskHandle_t *handle)
    {(void)run; (void)name; (void)stack; (void)arg; (void)priority;
     if (inject_event_during_start) {
         wifi_promiscuous_pkt_t packet = {0};
         const uint8_t bssid[6] = {0x02, 0, 0, 0, 0, 1};
         const uint8_t tx[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
         memset(packet.payload + 4, 0xFF, 6);
         memcpy(packet.payload + 10, tx, 6);
         memcpy(packet.payload + 16, bssid, 6);
         packet.payload[0] = 0xc0;
         packet.payload[24] = 7;
         packet.rx_ctrl.sig_len = 30;
         packet.rx_ctrl.dump_len = 26;
         packet.rx_ctrl.channel = 2;
         packet.rx_ctrl.rssi = -40;
         size_t previous_log_size = logged_size;
         deauth_detector_promiscuous_callback(&packet, WIFI_PKT_MGMT);
         assert(logged_size == previous_log_size); /* callback never logs */
         deauth_detector_process_events();
         assert(logged_size == previous_log_size); /* startup output gate */
     }
     *handle = 1; return pdPASS;}
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

static void send_deauth_fields(const uint8_t bssid[6], const uint8_t tx[6],
                               const uint8_t da[6], uint8_t channel,
                               int8_t rssi, uint16_t reason, unsigned payload_length) {
    wifi_promiscuous_pkt_t packet = {0};
    packet.rx_ctrl.sig_len = payload_length + 4;
    packet.rx_ctrl.dump_len = payload_length;
    packet.rx_ctrl.channel = channel;
    packet.rx_ctrl.rssi = rssi;
    packet.payload[0] = 0xc0;
    memcpy(packet.payload + 4, da, 6);
    memcpy(packet.payload + 10, tx, 6);
    memcpy(packet.payload + 16, bssid, 6);
    packet.payload[24] = (uint8_t)reason;
    packet.payload[25] = (uint8_t)(reason >> 8);
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

static void clear_logged(void) {
    logged[0] = '\0';
    logged_size = 0;
}

static int count_lines_starting(const char *prefix) {
    int count = 0;
    size_t length = strlen(prefix);
    const char *line = logged;
    while (*line) {
        if (!strncmp(line, prefix, length)) ++count;
        const char *end = strchr(line, '\n');
        line = end ? end + 1 : line + strlen(line);
    }
    return count;
}

static const char *first_line_starting(const char *prefix) {
    size_t length = strlen(prefix);
    const char *line = logged;
    while (*line) {
        if (!strncmp(line, prefix, length)) return line;
        const char *end = strchr(line, '\n');
        line = end ? end + 1 : line + strlen(line);
    }
    return NULL;
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
    deauth_detector_process_events();
    assert(strstr(logged,
        "[DEAUTH] CH: 6 | AP: Office (02:00:00:00:00:01) | RSSI: -50\n"));
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

static void legacy_exact_output(void) {
    char *all[] = {"deauth_detector"};
    char *selected[] = {"deauth_detector", "1", "3"};
    char *only[] = {"deauth_detector", "--only", "1", "3"};
    struct { int count; char **args; bool watch; } modes[] = {
        {1, all, false}, {3, selected, false}, {4, only, true},
    };
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); ++i) {
        clear_logged();
        assert(cmd_deauth_detector(modes[i].count, modes[i].args) == 0);
        if (modes[i].watch) {
            send_deauth(AP_B, 6);
            assert(detector_event_count == 0);
            send_deauth(AP_A, 6);
        } else send_deauth(AP_B, 6);
        size_t before_process = logged_size;
        assert(count_lines_starting("[DEAUTH] CH: ") == 0);
        deauth_detector_process_events();
        assert(logged_size > before_process);
        assert(count_lines_starting("[DEAUTH] CH: ") == 1);
        assert(count_lines_starting("[DEAUTH_V2] ") == 0);
        assert(count_lines_starting("[DETECTOR_INFO] format=deauth_v2") == 0);
        const char *expected = modes[i].watch
            ? "[DEAUTH] CH: 6 | AP: Office (02:00:00:00:00:01) | RSSI: -50\n"
            : "[DEAUTH] CH: 6 | AP: Office (02:00:00:00:00:02) | RSSI: -50\n";
        const char *line = first_line_starting("[DEAUTH] CH: ");
        assert(line && !strncmp(line, expected, strlen(expected)));
        stop_fixture();
    }
}

static void details_all_and_early_event(void) {
    char *args[] = {"deauth_detector_v2"};
    inject_event_during_start = true;
    assert(cmd_deauth_detector_v2(1, args) == 0);
    assert(scan_calls == 1 && !deauth_detector_selected_mode);
    assert(detector_event_count == 1);
    assert(count_lines_starting("[DETECTOR_INFO] format=deauth_v2") == 1);
    assert(count_lines_starting("[DEAUTH_V2] ") == 0);
    deauth_detector_process_events();
    const char *marker = first_line_starting("[DETECTOR_INFO] format=deauth_v2");
    const char *event = first_line_starting("[DEAUTH_V2] ");
    assert(marker && event && marker < event);
    assert(count_lines_starting("[DEAUTH_V2] ") == 1);
    assert(count_lines_starting("[DEAUTH] CH: ") == 0);
    assert(!strncmp(event,
        "[DEAUTH_V2] CH: 2 | BSSID: 02:00:00:00:00:01 | TX: AA:BB:CC:DD:EE:FF | DA: FF:FF:FF:FF:FF:FF | RSSI: -40 | REASON: 7 | SSID: Office\n",
        strlen("[DEAUTH_V2] CH: 2 | BSSID: 02:00:00:00:00:01 | TX: AA:BB:CC:DD:EE:FF | DA: FF:FF:FF:FF:FF:FF | RSSI: -40 | REASON: 7 | SSID: Office\n")));
    const uint8_t tx[6] = {0xD8, 0xCF, 0x61, 0x5D, 0x41, 0x10};
    const uint8_t da[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    size_t before_callback = logged_size;
    send_deauth_fields(AP_C, tx, da, 11, -52, 0x1234, 26);
    assert(logged_size == before_callback);
    deauth_detector_process_events();
    assert(count_lines_starting("[DEAUTH_V2] ") == 2);
    assert(strstr(logged,
        "[DEAUTH_V2] CH: 11 | BSSID: 02:00:00:00:00:03 | TX: D8:CF:61:5D:41:10 | DA: 12:34:56:78:9A:BC | RSSI: -52 | REASON: 4660 | SSID: Guest\n"));
}

static void details_selected_indices(void) {
    char *args[] = {"deauth_detector_v2", "1", "3"};
    assert(cmd_deauth_detector_v2(3, args) == 0);
    assert(deauth_detector_selected_mode && deauth_detector_selected_channels_count == 2);
    assert(deauth_detector_selected_channels[0] == 6);
    assert(deauth_detector_selected_channels[1] == 11);
    assert(count_lines_starting("[DETECTOR_INFO] format=deauth_v2") == 1);
    send_deauth(AP_B, 6); /* bare indices select channels, not BSSIDs */
    send_deauth(AP_B, 6); /* identical observations are not deduplicated */
    assert(detector_event_count == 2);
    deauth_detector_process_events();
    assert(count_lines_starting("[DEAUTH_V2] ") == 2);
    assert(strstr(logged,
        "[DEAUTH_V2] CH: 6 | BSSID: 02:00:00:00:00:02 | TX: 00:00:00:00:00:00 | DA: 00:00:00:00:00:00 | RSSI: -50 | REASON: 0 | SSID: Office\n"));
    assert(count_lines_starting("[DEAUTH] CH: ") == 0);
}

static void details_only_filters_deauth_and_csa(void) {
    char *args[] = {"deauth_detector_v2", "--only", "1", "3"};
    assert(cmd_deauth_detector_v2(4, args) == 0);
    assert(watch_status_has(2, "02:00:00:00:00:01"));
    assert(watch_status_has(2, "02:00:00:00:00:03"));
    assert(deauth_detector_selected_mode && deauth_detector_selected_channels_count == 2);
    send_deauth(AP_B, 6);
    send_csa(AP_B, 6);
    assert(detector_event_count == 0);
    send_deauth(AP_A, 6);
    send_deauth(AP_C, 11);
    send_csa(AP_A, 6);
    assert(detector_event_count == 3);
    deauth_detector_process_events();
    assert(count_lines_starting("[DEAUTH_V2] ") == 2);
    assert(count_lines_starting("[DEAUTH] CH: ") == 0);
    assert(count_lines_starting("[CSA] ") == 1);
    assert(!strstr(logged, "[DEAUTH_V2] CH: 6 | BSSID: 02:00:00:00:00:02"));
}

static void details_short_frame_and_ssid_safety(void) {
    char *args[] = {"deauth_detector_v2"};
    const uint8_t tx[6] = {1, 2, 3, 4, 5, 6};
    const uint8_t da[6] = {7, 8, 9, 10, 11, 12};
    strcpy((char *)g_scan_results[0].ssid, "A|\x1b[31mB\nC");
    assert(cmd_deauth_detector_v2(1, args) == 0);
    send_deauth_fields(AP_A, tx, da, 6, -30, 7, 25);
    assert(detector_event_count == 0);
    deauth_detector_process_events();
    assert(count_lines_starting("[DEAUTH_V2] ") == 0);
    send_deauth_fields(AP_A, tx, da, 6, -30, 7, 26);
    deauth_detector_process_events();
    const char *line = first_line_starting("[DEAUTH_V2] ");
    assert(line && strstr(line, " | SSID: ABC\n"));
    const char *end = strchr(line, '\n');
    assert(end && (size_t)(end - line + 1) <= 256);
    stop_fixture();
    scan_fixture();
    clear_logged();
    strcpy((char *)g_scan_results[0].ssid, "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456");
    assert(cmd_deauth_detector_v2(1, args) == 0);
    send_deauth_fields(AP_A, tx, da, 6, -30, 7, 26);
    deauth_detector_process_events();
    line = first_line_starting("[DEAUTH_V2] ");
    assert(line && strstr(line, " | SSID: ABCDEFGHIJKLMNOPQRSTUVWXYZ123456\n"));
    end = strchr(line, '\n');
    assert(end && (size_t)(end - line + 1) <= 256);
    stop_fixture();
    scan_fixture();
    clear_logged();
    strcpy((char *)g_scan_results[0].ssid,
           "A\x1b(B\x1bPsecret\x1b\\Z\x1b]title\aQ|");
    assert(cmd_deauth_detector_v2(1, args) == 0);
    send_deauth_fields(AP_A, tx, da, 6, -30, 7, 26);
    deauth_detector_process_events();
    line = first_line_starting("[DEAUTH_V2] ");
    assert(line && strstr(line, " | SSID: AZQ\n"));
}

static void details_invalid_options_and_failed_start(void) {
    char *duplicate[] = {"deauth_detector_v2", "--only", "--only"};
    char *middle[] = {"deauth_detector_v2", "1", "--details", "3"};
    char *only_missing[] = {"deauth_detector_v2", "--only"};
    char *only_middle[] = {"deauth_detector_v2", "--only", "1", "--details", "3"};
    char *unknown[] = {"deauth_detector_v2", "--detail"};
    char *invalid_index[] = {"deauth_detector_v2", "--only", "999"};
    char *zero_index[] = {"deauth_detector_v2", "0"};
    char *partial_index[] = {"deauth_detector_v2", "1x"};
    char *redundant_details[] = {"deauth_detector_v2", "--details"};
    struct { int count; char **args; } invalid[] = {
        {3, duplicate}, {4, middle}, {2, only_missing}, {5, only_middle},
        {2, unknown}, {3, invalid_index}, {2, zero_index}, {2, partial_index},
        {2, redundant_details},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        clear_logged();
        assert(cmd_deauth_detector_v2(invalid[i].count, invalid[i].args) == 1);
        assert(!deauth_detector_active && !receiver_enabled && !receiver_setup_calls);
        assert(count_lines_starting("[DETECTOR_INFO] format=deauth_v2") == 0);
    }
    char *valid[] = {"deauth_detector_v2"};
    fail_channel_tune = true;
    clear_logged();
    assert(cmd_deauth_detector_v2(1, valid) == 1);
    assert(!deauth_detector_active && !receiver_enabled);
    assert(count_lines_starting("[DETECTOR_INFO] format=deauth_v2") == 0);
}

static void legacy_rejects_v2_flag(void) {
    char *args[] = {"deauth_detector", "--details"};
    assert(cmd_deauth_detector(2, args) == 1);
    assert(!deauth_detector_active && !receiver_enabled && !receiver_setup_calls);
    assert(count_lines_starting("[DETECTOR_INFO] format=deauth_v2") == 0);
}

static void details_printable_utf8_ssid(void) {
    char *args[] = {"deauth_detector_v2"};
    strcpy((char *)g_scan_results[0].ssid, "Caf\xC3\xA9");
    assert(cmd_deauth_detector_v2(1, args) == 0);
    send_deauth(AP_A, 6);
    deauth_detector_process_events();
    assert(strstr(logged, " | SSID: Caf\xC3\xA9\n"));
}

static void details_protected_reason_availability(void) {
    char *args[] = {"deauth_detector_v2"};
    assert(cmd_deauth_detector_v2(1, args) == 0);
    wifi_promiscuous_pkt_t packet = {0};
    packet.rx_ctrl.sig_len = 46; /* Header + CCMP header + body + MIC + FCS. */
    packet.rx_ctrl.dump_len = 42;
    packet.rx_ctrl.channel = 6;
    packet.rx_ctrl.rssi = -42;
    packet.payload[0] = 0xc0;
    packet.payload[1] = 0x40; /* Protected unicast body is encrypted. */
    packet.payload[4] = 0x12; /* Unicast DA. */
    memcpy(packet.payload + 16, AP_A, 6);
    packet.payload[24] = 0x34;
    packet.payload[25] = 0x12;
    deauth_detector_promiscuous_callback(&packet, WIFI_PKT_MGMT);
    deauth_detector_process_events();
    assert(count_lines_starting("[DEAUTH_V2] ") == 1);
    assert(strstr(logged, " | REASON: - | SSID: Office\n"));
    packet.payload[4] = 0xff; /* Group-addressed protected body is readable. */
    packet.rx_ctrl.sig_len = 48; /* Header + reason + MMIE + FCS. */
    packet.rx_ctrl.dump_len = 44;
    deauth_detector_promiscuous_callback(&packet, WIFI_PKT_MGMT);
    deauth_detector_process_events();
    assert(count_lines_starting("[DEAUTH_V2] ") == 2);
    assert(strstr(logged, " | REASON: 4660 | SSID: Office\n"));
}

static void details_stop_and_legacy_restart(void) {
    char *details[] = {"deauth_detector_v2"};
    char *legacy[] = {"deauth_detector"};
    assert(cmd_deauth_detector_v2(1, details) == 0);
    send_deauth(AP_A, 6);
    assert(detector_event_count == 1);
    stop_fixture();
    clear_logged();
    deauth_detector_process_events();
    send_deauth(AP_A, 6);
    assert(detector_event_count == 0 && !logged_size);
    assert(cmd_deauth_detector(1, legacy) == 0);
    send_deauth(AP_A, 6);
    deauth_detector_process_events();
    assert(count_lines_starting("[DEAUTH] CH: ") == 1);
    assert(count_lines_starting("[DEAUTH_V2] ") == 0);
    assert(count_lines_starting("[DETECTOR_INFO] format=deauth_v2") == 0);
}

static void details_copies_frame_before_task_runs(void) {
    char *args[] = {"deauth_detector_v2"};
    assert(cmd_deauth_detector_v2(1, args) == 0);
    wifi_promiscuous_pkt_t packet = {0};
    packet.rx_ctrl.sig_len = 30;
    packet.rx_ctrl.dump_len = 26;
    packet.rx_ctrl.channel = 2;
    packet.rx_ctrl.rssi = -40;
    packet.payload[0] = 0xc0;
    memset(packet.payload + 4, 0xFF, 6);
    memcpy(packet.payload + 10, "\xAA\xBB\xCC\xDD\xEE\xFF", 6);
    memcpy(packet.payload + 16, AP_A, 6);
    packet.payload[24] = 7;
    size_t before_callback = logged_size;
    deauth_detector_promiscuous_callback(&packet, WIFI_PKT_MGMT);
    assert(logged_size == before_callback && detector_event_count == 1);
    memset(packet.payload, 0, sizeof(packet.payload));
    packet.rx_ctrl.channel = 11;
    packet.rx_ctrl.rssi = -1;
    deauth_detector_process_events();
    assert(strstr(logged,
        "[DEAUTH_V2] CH: 2 | BSSID: 02:00:00:00:00:01 | TX: AA:BB:CC:DD:EE:FF | DA: FF:FF:FF:FF:FF:FF | RSSI: -40 | REASON: 7 | SSID: Office\n"));
}

static void legacy_ssid_is_captured_at_receive(void) {
    char *args[] = {"deauth_detector"};
    assert(cmd_deauth_detector(1, args) == 0);
    send_deauth(AP_A, 6);
    assert(detector_event_count == 1);
    strcpy(detector_cache[0].ssid, "Renamed");
    deauth_detector_process_events();
    assert(strstr(logged,
        "[DEAUTH] CH: 6 | AP: Office (02:00:00:00:00:01) | RSSI: -50\n"));
    assert(!strstr(logged, "[DEAUTH] CH: 6 | AP: Renamed"));
}

static void trace_all_confirms_first_queued_deauth_bssid(void) {
    char *args[] = {"deauth_detector_v2", "trace"};
    inject_event_during_start = true;
    assert(cmd_deauth_detector_v2(2, args) == 0);
    assert(scan_calls == 1 && !deauth_detector_selected_mode);
    assert(receiver_enabled && channel_tune_calls == 1);
    assert(last_successful_channel == 1 && channel_tune_history[0] == 1);
    assert(detector_event_count == 1);
    assert(count_lines_starting("[DETECTOR_INFO] format=deauth_v2") == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] armed") == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] confirming_bssid=") == 0);
    assert(count_lines_starting("[DEAUTH_V2] ") == 0);

    send_deauth(AP_C, 11); /* Second accepted frame waits in the same FIFO. */
    assert(detector_event_count == 2 && channel_tune_calls == 1);
    deauth_detector_process_events();
    assert(channel_tune_calls == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] confirming_bssid=02:00:00:00:00:01 first_channel=2 window_ms=1000") == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=") == 0);
    assert(count_lines_starting("[DEAUTH_V2] ") == 2);
    assert(count_lines_starting("[DEAUTH] ") == 0);
    const char *marker = first_line_starting("[DETECTOR_INFO] format=deauth_v2");
    const char *armed = first_line_starting("[DETECTOR_TRACE] armed");
    const char *confirming = first_line_starting("[DETECTOR_TRACE] confirming_bssid=");
    const char *event = first_line_starting("[DEAUTH_V2] ");
    assert(marker && armed && confirming && event && marker < armed && armed < confirming && confirming < event);
    assert(strstr(event,
        "[DEAUTH_V2] CH: 2 | BSSID: 02:00:00:00:00:01 | TX: AA:BB:CC:DD:EE:FF | DA: FF:FF:FF:FF:FF:FF | RSSI: -40 | REASON: 7 | SSID: Office\n"));
    assert(strstr(logged,
        "[DEAUTH_V2] CH: 11 | BSSID: 02:00:00:00:00:03 | TX: 00:00:00:00:00:00 | DA: 00:00:00:00:00:00 | RSSI: -50 | REASON: 0 | SSID: Guest\n"));

    clock_us = 3100000;
    deauth_detector_process_events();
    assert(channel_tune_calls == 2 && channel_tune_history[1] == 2);
    assert(last_successful_channel == 2 && deauth_detector_current_channel == 2);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=2") == 1);
    const char *locked = first_line_starting("[DETECTOR_TRACE] locked_channel=2");
    assert(locked && event < locked);

    send_deauth(AP_B, 6);
    assert(detector_event_count == 1 && channel_tune_calls == 2);
    deauth_detector_process_events();
    deauth_detector_channel_hop();
    assert(channel_tune_calls == 2 && last_successful_channel == 2);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=") == 1);
    assert(count_lines_starting("[DEAUTH_V2] ") == 3);
}

static void trace_confirmation_prefers_repeated_stronger_channel(void) {
    char *args[] = {"deauth_detector_v2", "trace"};
    const uint8_t zero[6] = {0};
    assert(cmd_deauth_detector_v2(2, args) == 0);
    assert(channel_tune_calls == 1 && last_successful_channel == 1);

    clock_us = 2000000;
    send_deauth_fields(AP_A, zero, zero, 1, -37, 7, 26);
    deauth_detector_process_events();
    assert(channel_tune_calls == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=") == 0);

    send_deauth_fields(AP_A, zero, zero, 2, -33, 7, 26);
    send_deauth_fields(AP_A, zero, zero, 2, -34, 7, 26);
    send_deauth_fields(AP_A, zero, zero, 2, -33, 7, 26);
    send_deauth_fields(AP_B, zero, zero, 3, -10, 7, 26);
    deauth_detector_process_events();
    assert(channel_tune_calls == 1);

    clock_us = 3100000;
    deauth_detector_process_events();
    assert(channel_tune_calls == 2);
    assert(channel_tune_history[1] == 2 && last_successful_channel == 2);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=2") == 1);
    assert(count_lines_starting("[DEAUTH_V2] ") == 5);
}

static void trace_confirmation_uses_average_rssi_then_scan_cache(void) {
    char *args[] = {"deauth_detector_v2", "trace"};
    const uint8_t zero[6] = {0};
    assert(cmd_deauth_detector_v2(2, args) == 0);

    send_deauth_fields(AP_A, zero, zero, 1, -40, 7, 26);
    send_deauth_fields(AP_A, zero, zero, 2, -30, 7, 26);
    deauth_detector_process_events();
    clock_us = 3100000;
    deauth_detector_process_events();
    assert(channel_tune_calls == 2 && channel_tune_history[1] == 2);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=2") == 1);

    stop_fixture();
    clear_logged();
    channel_tune_calls = 0;
    last_successful_channel = 0;
    clock_us = 2000000;
    assert(cmd_deauth_detector_v2(2, args) == 0);

    /* Equal count and average RSSI: the fresh scan-cache channel wins. */
    send_deauth_fields(AP_A, zero, zero, 5, -40, 7, 26);
    send_deauth_fields(AP_A, zero, zero, 6, -40, 7, 26);
    deauth_detector_process_events();
    assert(detector_trace_candidate_count == 5);
    assert(detector_trace_hop_delay_locked() == 200);
    clock_us = 3100000;
    deauth_detector_process_events();
    assert(channel_tune_calls == 2 && channel_tune_history[1] == 6);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=6") == 1);
}

static void trace_confirmation_samples_adjacent_5ghz_channels(void) {
    char *args[] = {"deauth_detector_v2", "trace"};
    const uint8_t zero[6] = {0};
    assert(cmd_deauth_detector_v2(2, args) == 0);

    send_deauth_fields(AP_C, zero, zero, 40, -50, 7, 26);
    deauth_detector_process_events();
    assert(detector_trace_confirming && detector_trace_candidate_count == 3);
    assert(detector_trace_candidates[0].channel == 36);
    assert(detector_trace_candidates[1].channel == 40);
    assert(detector_trace_candidates[2].channel == 44);

    deauth_detector_channel_hop();
    assert(channel_tune_calls == 2 && channel_tune_history[1] == 44);
    send_deauth_fields(AP_C, zero, zero, 44, -45, 7, 26);
    send_deauth_fields(AP_C, zero, zero, 44, -44, 7, 26);
    deauth_detector_process_events();
    deauth_detector_channel_hop();
    assert(channel_tune_calls == 3 && channel_tune_history[2] == 36);

    clock_us = 3100000;
    deauth_detector_process_events();
    assert(channel_tune_calls == 4 && channel_tune_history[3] == 44);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=44") == 1);
}

static void trace_stop_during_confirmation_discards_pending_lock(void) {
    char *args[] = {"deauth_detector_v2", "trace"};
    assert(cmd_deauth_detector_v2(2, args) == 0);
    send_deauth(AP_A, 2);
    deauth_detector_process_events();
    assert(detector_trace_confirming && !detector_trace_locked);
    assert(count_lines_starting("[DETECTOR_TRACE] confirming_bssid=") == 1);
    int tunes_before_stop = channel_tune_calls;

    stop_fixture();
    assert(!detector_trace_requested && !detector_trace_confirming &&
           !detector_trace_locked && detector_trace_candidate_count == 0);
    clock_us = 5000000;
    deauth_detector_process_events();
    deauth_detector_channel_hop();
    assert(channel_tune_calls == tunes_before_stop);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=") == 0);
}

static void trace_idle_release_ignores_other_bssids_and_rearms(void) {
    char *args[] = {"deauth_detector_v2", "trace"};
    assert(cmd_deauth_detector_v2(2, args) == 0);
    send_deauth(AP_A, 2);
    deauth_detector_process_events();
    clock_us = 3100000;
    deauth_detector_process_events();
    assert(detector_trace_locked && last_successful_channel == 2);

    /* Unrelated traffic remains visible but cannot keep this Trace lock alive. */
    clock_us = 21000000;
    send_deauth(AP_B, 3);
    deauth_detector_process_events();
    assert(detector_trace_locked);
    assert(count_lines_starting("[DETECTOR_TRACE] released_channel=") == 0);

    clock_us = 22001000;
    deauth_detector_process_events();
    assert(!detector_trace_locked && !detector_trace_confirming);
    assert(detector_trace_requested);
    assert(count_lines_starting(
        "[DETECTOR_TRACE] released_channel=2 reason=idle idle_ms=20000") == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] armed") == 2);
    const char *release = first_line_starting("[DETECTOR_TRACE] released_channel=");
    const char *first_armed = first_line_starting("[DETECTOR_TRACE] armed");
    const char *rearmed = first_armed ? strstr(first_armed + 1,
                                               "[DETECTOR_TRACE] armed\n") : NULL;
    assert(release && rearmed && release < rearmed);

    int tunes_after_release = channel_tune_calls;
    deauth_detector_channel_hop();
    assert(channel_tune_calls == tunes_after_release + 1);
    clock_us = 23000000;
    send_deauth(AP_B, 6);
    deauth_detector_process_events();
    assert(detector_trace_confirming && !detector_trace_locked);
    assert(count_lines_starting(
        "[DETECTOR_TRACE] confirming_bssid=02:00:00:00:00:02 first_channel=6 window_ms=1000") == 1);
}

static void trace_matching_bssid_refreshes_idle_deadline(void) {
    char *args[] = {"deauth_detector_v2", "trace"};
    assert(cmd_deauth_detector_v2(2, args) == 0);
    send_deauth(AP_A, 2);
    deauth_detector_process_events();
    clock_us = 3100000;
    deauth_detector_process_events();
    assert(detector_trace_locked);

    clock_us = 21000000;
    send_deauth(AP_A, 2);
    deauth_detector_process_events();
    clock_us = 22001000;
    deauth_detector_process_events();
    assert(detector_trace_locked);
    assert(count_lines_starting("[DETECTOR_TRACE] released_channel=") == 0);

    clock_us = 40999000;
    deauth_detector_process_events();
    assert(detector_trace_locked);
    clock_us = 41001000;
    deauth_detector_process_events();
    assert(!detector_trace_locked);
    assert(count_lines_starting(
        "[DETECTOR_TRACE] released_channel=2 reason=idle idle_ms=20000") == 1);
}

static void trace_start_announces_armed_after_v2_format(void) {
    char *args[] = {"deauth_detector_v2", "trace"};
    assert(cmd_deauth_detector_v2(2, args) == 0);
    const char *format = first_line_starting("[DETECTOR_INFO] format=deauth_v2");
    const char *armed = first_line_starting("[DETECTOR_TRACE] armed");
    assert(format && armed && format < armed);
    assert(count_lines_starting("[DETECTOR_TRACE] armed") == 1);
}

static void trace_selected_channels_waits_for_deauth(void) {
    char *args[] = {"deauth_detector_v2", "1", "3", "trace"};
    assert(cmd_deauth_detector_v2(4, args) == 0);
    assert(deauth_detector_selected_mode && deauth_detector_selected_channels_count == 2);
    assert(deauth_detector_selected_channels[0] == 6);
    assert(deauth_detector_selected_channels[1] == 11);
    assert(channel_tune_calls == 1 && last_successful_channel == 6);
    send_csa(AP_C, 11);
    deauth_detector_process_events();
    assert(count_lines_starting("[CSA] ") == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] armed") == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] confirming_bssid=") == 0);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=") == 0);
    assert(channel_tune_calls == 1 && last_successful_channel == 6);

    send_deauth(AP_B, 11); /* Bare indices select channels, not BSSIDs. */
    assert(detector_event_count == 1 && channel_tune_calls == 1);
    deauth_detector_process_events();
    assert(channel_tune_calls == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] confirming_bssid=") == 1);
    clock_us = 3100000;
    deauth_detector_process_events();
    assert(channel_tune_calls == 2 && last_successful_channel == 11);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=11") == 1);
    assert(strstr(logged,
        "[DEAUTH_V2] CH: 11 | BSSID: 02:00:00:00:00:02 | TX: 00:00:00:00:00:00 | DA: 00:00:00:00:00:00 | RSSI: -50 | REASON: 0 | SSID: Office\n"));
    deauth_detector_channel_hop();
    assert(channel_tune_calls == 2 && last_successful_channel == 11);
}

static void trace_only_ignores_rejected_and_short_frames(void) {
    char *args[] = {"deauth_detector_v2", "--only", "1", "3", "trace"};
    const uint8_t tx[6] = {1, 2, 3, 4, 5, 6};
    const uint8_t da[6] = {7, 8, 9, 10, 11, 12};
    assert(cmd_deauth_detector_v2(5, args) == 0);
    assert(watch_status_has(2, "02:00:00:00:00:01"));
    assert(watch_status_has(2, "02:00:00:00:00:03"));
    assert(channel_tune_calls == 1 && last_successful_channel == 6);
    send_deauth(AP_B, 6); /* Rejected by --only. */
    send_csa(AP_A, 6); /* Accepted announcement cannot trigger trace. */
    send_deauth_fields(AP_A, tx, da, 11, -30, 7, 25); /* Short. */
    assert(detector_event_count == 1 && channel_tune_calls == 1);
    deauth_detector_process_events();
    assert(count_lines_starting("[CSA] ") == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] armed") == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] confirming_bssid=") == 0);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=") == 0);
    assert(count_lines_starting("[DEAUTH_V2] ") == 0);
    assert(channel_tune_calls == 1 && last_successful_channel == 6);

    send_deauth(AP_C, 11);
    assert(detector_event_count == 1 && channel_tune_calls == 1);
    deauth_detector_process_events();
    assert(channel_tune_calls == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] confirming_bssid=") == 1);
    clock_us = 3100000;
    deauth_detector_process_events();
    assert(channel_tune_calls == 2 && last_successful_channel == 11);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=11") == 1);
    send_deauth(AP_A, 6);
    deauth_detector_process_events();
    deauth_detector_channel_hop();
    assert(channel_tune_calls == 2 && last_successful_channel == 11);
    assert(count_lines_starting("[DEAUTH_V2] ") == 2);
    assert(!strstr(logged, "[DEAUTH_V2] CH: 6 | BSSID: 02:00:00:00:00:02"));
}

static void trace_failed_tune_retries_then_stop_clears_lock(void) {
    char *trace[] = {"deauth_detector_v2", "trace"};
    char *plain[] = {"deauth_detector_v2"};
    assert(cmd_deauth_detector_v2(2, trace) == 0);
    assert(channel_tune_calls == 1 && last_successful_channel == 1);
    fail_channel_tune = true;
    send_deauth(AP_A, 11);
    deauth_detector_process_events();
    assert(channel_tune_calls == 1);
    clock_us = 3100000;
    deauth_detector_process_events();
    assert(channel_tune_calls == 2 && channel_tune_history[1] == 11);
    assert(last_successful_channel == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=") == 0);
    assert(count_lines_starting("[DEAUTH_V2] ") == 1);
    fail_channel_tune = false;
    deauth_detector_channel_hop();
    assert(channel_tune_calls == 3); /* Failed lock did not stop hopping. */
    send_deauth(AP_B, 6);
    deauth_detector_process_events();
    assert(channel_tune_calls == 3);
    clock_us = 4201000;
    deauth_detector_process_events();
    assert(channel_tune_calls == 4 && last_successful_channel == 6);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=6") == 1);

    stop_fixture();
    clear_logged();
    send_deauth(AP_C, 11);
    deauth_detector_process_events();
    assert(!logged_size && detector_event_count == 0);
    assert(cmd_deauth_detector_v2(1, plain) == 0);
    int started_tunes = channel_tune_calls;
    send_deauth(AP_A, 11);
    deauth_detector_process_events();
    assert(channel_tune_calls == started_tunes);
    assert(count_lines_starting("[DETECTOR_TRACE] ") == 0);
    deauth_detector_channel_hop();
    assert(channel_tune_calls == started_tunes + 1);
    stop_fixture();
    clear_logged();

    assert(cmd_deauth_detector_v2(2, trace) == 0);
    started_tunes = channel_tune_calls;
    send_deauth(AP_A, 11);
    deauth_detector_process_events();
    assert(channel_tune_calls == started_tunes);
    clock_us += 1100000;
    deauth_detector_process_events();
    assert(channel_tune_calls == started_tunes + 1);
    assert(last_successful_channel == 11);
    assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=11") == 1);
}

static void trace_failed_tune_notices_are_rate_limited(void) {
    char *trace[] = {"deauth_detector_v2", "trace"};
    assert(cmd_deauth_detector_v2(2, trace) == 0);
    assert(channel_tune_calls == 1 && last_successful_channel == 1);
    fail_channel_tune = true;
    const int64_t starts_us[] = {2000000, 3200000, 4400000};
    for (size_t i = 0; i < sizeof(starts_us) / sizeof(starts_us[0]); ++i) {
        clock_us = starts_us[i];
        size_t before_callback = logged_size;
        send_deauth(AP_A, 11);
        assert(logged_size == before_callback && detector_event_count == 1);
        deauth_detector_process_events();
        assert(channel_tune_calls == (int)i + 1);
        clock_us += 1100000;
        deauth_detector_process_events();
        assert(channel_tune_calls == (int)i + 2);
        assert(last_successful_channel == 1);
        assert(count_lines_starting("[DEAUTH_V2] ") == (int)i + 1);
        assert(count_lines_starting("[DEAUTH] ") == 0);
        assert(count_lines_starting("[DETECTOR_TRACE] locked_channel=") == 0);
        int expected_notices = i == 2 ? 2 : 1;
        assert(count_lines_starting("[DETECTOR_TRACE] lock_failed_channel=") == expected_notices);
    }
}

static void trace_rejects_bad_syntax_before_receiver_setup(void) {
    char *duplicate[] = {"deauth_detector_v2", "trace", "trace"};
    char *before_index[] = {"deauth_detector_v2", "trace", "1"};
    char *between_indices[] = {"deauth_detector_v2", "1", "trace", "3"};
    char *only_missing[] = {"deauth_detector_v2", "--only", "trace"};
    char *only_middle[] = {"deauth_detector_v2", "--only", "1", "trace", "3"};
    char *dashed[] = {"deauth_detector_v2", "--trace"};
    char *dashed_selected[] = {"deauth_detector_v2", "1", "--trace"};
    char *dashed_only[] = {"deauth_detector_v2", "--only", "1", "--trace"};
    char *legacy_trace[] = {"deauth_detector", "trace"};
    char *legacy_dashed[] = {"deauth_detector", "--trace"};
    char *legacy_mixed[] = {"deauth_detector", "1", "trace"};
    struct { int count; char **args; bool legacy; } invalid[] = {
        {3, duplicate, false}, {3, before_index, false},
        {4, between_indices, false}, {3, only_missing, false},
        {5, only_middle, false}, {2, dashed, false},
        {3, dashed_selected, false}, {4, dashed_only, false},
        {2, legacy_trace, true}, {2, legacy_dashed, true},
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        clear_logged();
        int result = invalid[i].legacy
            ? cmd_deauth_detector(invalid[i].count, invalid[i].args)
            : cmd_deauth_detector_v2(invalid[i].count, invalid[i].args);
        assert(result == 1);
        assert(!deauth_detector_active && !receiver_enabled && !receiver_setup_calls);
        assert(!deauth_detector_task_handle && channel_tune_calls == 0);
        assert(count_lines_starting("[DETECTOR_INFO] format=deauth_v2") == 0);
    }
    /* Legacy atoi/skip semantics remain intact for mixed valid/invalid tokens. */
    clear_logged();
    assert(cmd_deauth_detector(3, legacy_mixed) == 0);
    assert(deauth_detector_selected_mode && deauth_detector_selected_channels_count == 1);
    assert(deauth_detector_selected_channels[0] == 6);
    assert(channel_tune_calls == 1 && receiver_enabled);
    send_deauth(AP_A, 6);
    deauth_detector_process_events();
    assert(count_lines_starting("[DEAUTH] CH: ") == 1);
    assert(count_lines_starting("[DETECTOR_TRACE] ") == 0);
    stop_fixture();
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
    else if (!strcmp(argv[1], "legacy-exact")) legacy_exact_output();
    else if (!strcmp(argv[1], "legacy-snapshot")) legacy_ssid_is_captured_at_receive();
    else if (!strcmp(argv[1], "details-all")) details_all_and_early_event();
    else if (!strcmp(argv[1], "details-selected")) details_selected_indices();
    else if (!strcmp(argv[1], "details-only")) details_only_filters_deauth_and_csa();
    else if (!strcmp(argv[1], "details-safety")) details_short_frame_and_ssid_safety();
    else if (!strcmp(argv[1], "details-invalid")) details_invalid_options_and_failed_start();
    else if (!strcmp(argv[1], "details-stop")) details_stop_and_legacy_restart();
    else if (!strcmp(argv[1], "details-copy")) details_copies_frame_before_task_runs();
    else if (!strcmp(argv[1], "details-utf8")) details_printable_utf8_ssid();
    else if (!strcmp(argv[1], "details-protected")) details_protected_reason_availability();
    else if (!strcmp(argv[1], "legacy-v2-flag")) legacy_rejects_v2_flag();
    else if (!strcmp(argv[1], "trace-all")) trace_all_confirms_first_queued_deauth_bssid();
    else if (!strcmp(argv[1], "trace-confirm")) trace_confirmation_prefers_repeated_stronger_channel();
    else if (!strcmp(argv[1], "trace-score")) trace_confirmation_uses_average_rssi_then_scan_cache();
    else if (!strcmp(argv[1], "trace-5ghz")) trace_confirmation_samples_adjacent_5ghz_channels();
    else if (!strcmp(argv[1], "trace-stop-confirm")) trace_stop_during_confirmation_discards_pending_lock();
    else if (!strcmp(argv[1], "trace-idle-release")) trace_idle_release_ignores_other_bssids_and_rearms();
    else if (!strcmp(argv[1], "trace-idle-refresh")) trace_matching_bssid_refreshes_idle_deadline();
    else if (!strcmp(argv[1], "trace-armed")) trace_start_announces_armed_after_v2_format();
    else if (!strcmp(argv[1], "trace-selected")) trace_selected_channels_waits_for_deauth();
    else if (!strcmp(argv[1], "trace-only")) trace_only_ignores_rejected_and_short_frames();
    else if (!strcmp(argv[1], "trace-retry-stop")) trace_failed_tune_retries_then_stop_clears_lock();
    else if (!strcmp(argv[1], "trace-failure-rate")) trace_failed_tune_notices_are_rate_limited();
    else if (!strcmp(argv[1], "trace-invalid")) trace_rejects_bad_syntax_before_receiver_setup();
    else return 2;
    puts("watch PASS");
    return 0;
}
"""


class DeauthDetectorWatchTests(unittest.TestCase):
    def test_split_commands_have_distinct_help_and_registration(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        self.assertTrue(
            '{ "deauth_detector", " [index1 index2 ... | --only index1 index2 ...]" }'
            in source,
            "legacy live CLI hint changed",
        )
        self.assertTrue(
            re.search(r'\{ "deauth_detector_v2", " [^"]*\[trace\]" \}', source),
            "V2 live CLI hint must show the optional trace suffix",
        )
        self.assertEqual(len(re.findall(r'\.command\s*=\s*"deauth_detector"', source)), 1)
        self.assertEqual(len(re.findall(r'\.command\s*=\s*"deauth_detector_v2"', source)), 1)
        legacy = source.split('.command = "deauth_detector",', 1)[1].split('};', 1)[0]
        advanced = source.split('.command = "deauth_detector_v2",', 1)[1].split('};', 1)[0]
        self.assertNotIn("--details", legacy)
        self.assertIn('.hint = "[index1 index2 ... | --only index1 index2 ...]"', legacy)
        self.assertIn("deauth_v2", advanced)
        self.assertRegex(advanced, r'\.hint = "[^"]*trace[^"]*"')
        boot = source.split('static const char* boot_allowed_commands[] = {', 1)[1].split('};', 1)[0]
        self.assertIn('"deauth_detector_v2"', boot)

    @classmethod
    def setUpClass(cls):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        begin = source.index("// Detector event pipeline (fixed storage")
        end = source.index("// Wardrive task", begin)
        code = HARNESS_PREFIX + source[begin:end]
        for name in (
            "detector_trace_reset_locked",
            "detector_trace_add_candidate_locked",
            "detector_trace_build_candidates_locked",
            "detector_trace_record_locked",
            "detector_trace_observe_locked",
            "detector_trace_choose_channel_locked",
            "detector_trace_hop_delay_locked",
            "detector_trace_finish_if_due",
            "detector_trace_release_if_idle",
            "deauth_detector_reset_events",
            "deauth_detector_close_events",
            "deauth_detector_process_events",
            "deauth_detector_channel_hop",
            "cmd_deauth_detector_impl",
            "cmd_deauth_detector",
            "cmd_deauth_detector_v2",
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
        build = subprocess.run(
            [
                "cc", "-std=c11", "-Wall", "-Wextra", "-Wno-unused-function",
                "-Wno-unused-variable", "-I", str(ROOT / "main"),
                *map(str, files), "-o", str(cls.binary),
            ],
            capture_output=True,
            text=True,
        )
        if build.returncode:
            raise AssertionError(build.stdout + build.stderr)

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

    def test_legacy_event_line_is_exact_in_all_three_modes(self):
        self.check_scenario("legacy-exact")

    def test_legacy_ssid_is_captured_when_frame_arrives(self):
        self.check_scenario("legacy-snapshot")

    def test_details_all_channels_marker_precedes_early_event_and_fields_are_exact(self):
        self.check_scenario("details-all")

    def test_details_selected_indices_do_not_filter_bssids(self):
        self.check_scenario("details-selected")

    def test_details_only_filters_both_deauth_and_csa(self):
        self.check_scenario("details-only")

    def test_details_rejects_short_frames_and_sanitizes_bounded_ssid(self):
        self.check_scenario("details-safety")

    def test_details_invalid_options_and_failed_start_emit_no_format_marker(self):
        self.check_scenario("details-invalid")

    def test_details_stop_discards_queued_event_and_legacy_restart_resets_format(self):
        self.check_scenario("details-stop")

    def test_details_copies_frame_and_metadata_before_task_formats_record(self):
        self.check_scenario("details-copy")

    def test_details_preserves_printable_utf8_ssid(self):
        self.check_scenario("details-utf8")

    def test_details_does_not_invent_reason_for_protected_unicast(self):
        self.check_scenario("details-protected")

    def test_legacy_command_rejects_v2_option(self):
        self.check_scenario("legacy-v2-flag")

    def test_trace_all_channels_confirms_first_queued_bssid_after_format_marker(self):
        self.check_scenario("trace-all")

    def test_trace_confirmation_prefers_repeated_stronger_channel(self):
        self.check_scenario("trace-confirm")

    def test_trace_confirmation_uses_average_rssi_then_scan_cache_tie_break(self):
        self.check_scenario("trace-score")

    def test_trace_confirmation_samples_adjacent_5ghz_channels(self):
        self.check_scenario("trace-5ghz")

    def test_trace_stop_during_confirmation_discards_pending_lock(self):
        self.check_scenario("trace-stop-confirm")

    def test_trace_idle_release_ignores_other_bssids_and_rearms(self):
        self.check_scenario("trace-idle-release")

    def test_trace_matching_bssid_refreshes_idle_deadline(self):
        self.check_scenario("trace-idle-refresh")

    def test_trace_start_announces_armed_after_v2_format(self):
        self.check_scenario("trace-armed")

    def test_trace_selected_indices_waits_for_deauth_and_keeps_bssid_semantics(self):
        self.check_scenario("trace-selected")

    def test_trace_only_ignores_filtered_short_and_csa_frames(self):
        self.check_scenario("trace-only")

    def test_trace_failed_tune_retries_and_stop_clears_lock(self):
        self.check_scenario("trace-retry-stop")

    def test_trace_failed_tune_notices_are_rate_limited_without_dropping_events(self):
        self.check_scenario("trace-failure-rate")

    def test_trace_rejects_misplaced_duplicate_and_dashed_tokens(self):
        self.check_scenario("trace-invalid")


if __name__ == "__main__":
    unittest.main()
