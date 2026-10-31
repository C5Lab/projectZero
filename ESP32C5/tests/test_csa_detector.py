"""Host execution of real CSA parser and extracted detector callback/task helpers.

Run under Linux/WSL with python3 -m unittest discover -s tests -p test_csa_detector.py.
No firmware build or RF activity occurs.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

def function(source, name):
    masked = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
                    lambda m: " " * len(m.group()), source, flags=re.S)
    match = re.search(r'\b' + name + r'\s*\([^;{}]*\)\s*\{', masked)
    if not match:
        raise ValueError(name)
    start = source.rfind('\n', 0, match.start()) + 1
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[start:end]

class CsaDetectorTests(unittest.TestCase):
    def compile_run(self, code=None):
        with tempfile.TemporaryDirectory(prefix="janos-csa-") as tmp:
            directory = Path(tmp)
            if code is None:
                source = ROOT / "tests/csa_detector_core_test.c"
            else:
                source = directory / "integration.c"
                source.write_text(code)
            exe = directory / "csa-test"
            subprocess.run([os.environ.get("CC", "gcc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-function", "-Wno-unused-variable", "-I", str(ROOT / "main"),
                            str(source), str(ROOT / "main/csa_detector_core.c"),
                            str(ROOT / "main/deauth_target_core.c"), "-o", str(exe)], check=True)
            return subprocess.check_output([str(exe)], text=True)

    def test_parser_bounds_protocol_and_rate_lifecycle(self):
        self.assertEqual(self.compile_run(), "CSA core: PASS\n")

    def test_callback_defers_logs_bounds_overflow_and_stop_generation(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        globals_begin = source.index("// Detector event pipeline (fixed storage")
        globals_end = source.index("// Deauth detector selected mode", globals_begin)
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "csa_detector_core.h"
#include "deauth_target_core.h"
#define MAX_AP_CNT 64
#define MY_LOG_INFO(tag, ...) do { printf(__VA_ARGS__); puts(""); } while(0)
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(x) ((void)(x))
#define portEXIT_CRITICAL(x) ((void)(x))
typedef int esp_err_t;
#define ESP_OK 0
#define WIFI_SECOND_CHAN_NONE 0
typedef enum { WIFI_PKT_MGMT, WIFI_PKT_DATA } wifi_promiscuous_pkt_type_t;
typedef struct { struct { unsigned sig_len, dump_len, rx_state; int8_t rssi; uint8_t channel; } rx_ctrl; uint8_t payload[256]; } wifi_promiscuous_pkt_t;
static bool deauth_detector_active=true;
static int deauth_detector_current_channel=11;
static unsigned threat_events;
static int64_t fake_us;
static bool restart_during_callback;
static esp_err_t esp_wifi_set_channel(int channel, int secondary) {
    (void)channel; (void)secondary; return ESP_OK;
}
static const char *esp_err_to_name(int error) {
    (void)error; return "fixture";
}
static void deauth_detector_reset_events(void);
static void deauth_detector_close_events(void);
static int64_t esp_timer_get_time(void) {
    if (restart_during_callback) {
        restart_during_callback=false;
        deauth_detector_close_events();
        deauth_detector_reset_events();
    }
    return fake_us;
}
#define LED_STATUS_EVENT_THREAT 1
static void led_status_notify_event(int event) { (void)event; ++threat_events; }
'''
        code += source[globals_begin:globals_end]
        for name in ("deauth_detector_reset_events", "deauth_detector_close_events",
                     "deauth_detector_process_events", "deauth_detector_promiscuous_callback"):
            code += '\n' + function(source,name)
        code += r'''
int main(void) {
    deauth_detector_reset_events();
    detector_cache_count=1;
    memcpy(detector_cache[0].bssid,"\x06\xAA\xBB\xCC\xDD\xEE",6);
    strcpy(detector_cache[0].ssid,"Saved AP");
    wifi_promiscuous_pkt_t p={0};
    p.rx_ctrl.sig_len=45; p.rx_ctrl.dump_len=45; p.rx_ctrl.channel=6; p.rx_ctrl.rssi=-51;
    p.payload[0]=0x80;
    memcpy(p.payload+10,"\x02\x11\x22\x33\x44\x55",6);
    memcpy(p.payload+16,detector_cache[0].bssid,6);
    memcpy(p.payload+36,"\x25\x03\x01\x24\x03",5);
    deauth_detector_promiscuous_callback(&p,WIFI_PKT_MGMT);
    assert(detector_event_count==1 && threat_events==0);
    for(int i=0;i<1000;++i) deauth_detector_promiscuous_callback(&p,WIFI_PKT_MGMT);
    assert(detector_event_count==1);
    deauth_detector_process_events(); assert(detector_event_count==0);
    /* A CSA observation is not evidence of an attack. */
    assert(threat_events==0);
    p.rx_ctrl.rx_state=1; fake_us=3000000;
    deauth_detector_promiscuous_callback(&p,WIFI_PKT_MGMT); assert(!detector_event_count);
    p.rx_ctrl.rx_state=0; p.rx_ctrl.dump_len=40;
    deauth_detector_promiscuous_callback(&p,WIFI_PKT_MGMT); assert(!detector_event_count);
    p.rx_ctrl.dump_len=45;
    deauth_detector_close_events();
    deauth_detector_promiscuous_callback(&p,WIFI_PKT_MGMT); assert(!detector_event_count);
    deauth_detector_reset_events();
    restart_during_callback=true;
    deauth_detector_promiscuous_callback(&p,WIFI_PKT_MGMT);
    assert(!detector_event_count); /* stale in-flight callback cannot enter restarted session */
    deauth_detector_promiscuous_callback(&p,WIFI_PKT_MGMT); assert(detector_event_count==1);
    deauth_detector_process_events();
    p.payload[0]=0xc0; p.rx_ctrl.sig_len=30; p.rx_ctrl.dump_len=30;
    deauth_detector_promiscuous_callback(&p,WIFI_PKT_MGMT);
    assert(detector_event_count==1 && threat_events==0);
    deauth_detector_process_events(); assert(threat_events==1);
    for(int i=0;i<100;++i) deauth_detector_promiscuous_callback(&p,WIFI_PKT_MGMT);
    assert(detector_event_count==16 && detector_dropped==84);
    p.payload[0]=0x80; p.rx_ctrl.sig_len=45;p.rx_ctrl.dump_len=45;p.payload[39]=149;
    deauth_detector_promiscuous_callback(&p,WIFI_PKT_MGMT);
    assert(detector_event_count==17); /* deauth burst leaves space for first CSA */
    deauth_detector_close_events(); assert(!detector_event_count);
    deauth_detector_reset_events(); assert(!detector_dropped);
    return 0;
}
'''
        output = self.compile_run(code)
        lines = output.splitlines()
        self.assertEqual(lines, [
            "[CSA] RX: 6 | TO: 36 | BSSID: 06:AA:BB:CC:DD:EE | TX: 02:11:22:33:44:55 | RSSI: -51 | VIA: beacon | COUNT: 3 | MODE: 1 | CLASS: - | SSID: Saved AP",
            "[CSA] RX: 6 | TO: 36 | BSSID: 06:AA:BB:CC:DD:EE | TX: 02:11:22:33:44:55 | RSSI: -51 | VIA: beacon | COUNT: 3 | MODE: 1 | CLASS: - | SSID: <Unknown>",
            "[DEAUTH] CH: 6 | AP: <Unknown> (06:AA:BB:CC:DD:EE) | RSSI: -51",
        ])

    def test_real_command_selected_scan_failure_and_restart_lifecycle(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        start = source.index("// Detector event pipeline (fixed storage")
        end = source.index("// Wardrive task", start)
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "csa_detector_core.h"
#include "deauth_target_core.h"
#define MAX_AP_CNT 64
#define MY_LOG_INFO(tag, ...) do { printf(__VA_ARGS__); puts(""); } while(0)
typedef int portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED 0
#define portENTER_CRITICAL(x) ((void)(x))
#define portEXIT_CRITICAL(x) ((void)(x))
typedef int esp_err_t;
typedef int BaseType_t;
typedef void *SemaphoreHandle_t;
#define ESP_OK 0
#define ESP_ERR_INVALID_STATE 5
#define WIFI_PROMIS_FILTER_MASK_MGMT 1
#define WIFI_SECOND_CHAN_NONE 0
#define pdPASS 1
#define pdTRUE 1
#define portMAX_DELAY 0xffffffffu
#define pdMS_TO_TICKS(x) (x)
typedef struct { int filter_mask; } wifi_promiscuous_filter_t;
typedef struct { uint8_t bssid[6],ssid[33]; int primary; } wifi_ap_record_t;
static wifi_ap_record_t g_scan_results[MAX_AP_CNT];
static SemaphoreHandle_t g_scan_results_mutex=(void *)1;
static bool g_scan_records_valid=true;
static unsigned g_scan_count;
static bool g_scan_done,g_scan_in_progress,operation_stop_requested;
static bool sniffer_active,sniffer_dog_active,deauth_detector_active;
static int deauth_detector_current_channel,deauth_detector_channel_index;
static int64_t deauth_detector_last_channel_hop;
static int deauth_detector_task_handle;
static int dual_band_channels[]={1,6,36,149};
static int g_scan_min_channel_time=100,g_scan_max_channel_time=200;
static int fail_step,setup_calls,task_result=pdPASS;
static bool receiver_enabled;
static unsigned scan_calls;
static void oled_display_update_full(const char*a,const char*b,const char*c,const char*d) {(void)a;(void)b;(void)c;(void)d;}
static void log_memory_info(const char*s) {(void)s;}
static bool ensure_wifi_mode(void) {return true;}
static void vTaskDelay(int ms) {(void)ms;}
static int64_t esp_timer_get_time(void) {return 2000000;}
static BaseType_t xSemaphoreTake(SemaphoreHandle_t m,unsigned wait) {(void)m;(void)wait;return pdTRUE;}
static BaseType_t xSemaphoreGive(SemaphoreHandle_t m) {(void)m;return pdTRUE;}
static const char* esp_err_to_name(int e) {(void)e; return "fixture";}
static esp_err_t start_background_scan(int a,int b) {(void)a;(void)b; ++scan_calls; g_scan_count=1;g_scan_done=true;g_scan_in_progress=false;return ESP_OK;}
static void esp_wifi_scan_stop(void) {}
static esp_err_t esp_wifi_set_promiscuous_filter(const wifi_promiscuous_filter_t*f) {(void)f;return ++setup_calls==fail_step?9:0;}
static void deauth_detector_promiscuous_callback(void*a,int b) {(void)a;(void)b;}
static esp_err_t esp_wifi_set_promiscuous_rx_cb(void(*cb)(void*,int)) {(void)cb;return ++setup_calls==fail_step?9:0;}
static esp_err_t esp_wifi_set_promiscuous(bool enabled) {
    if (enabled && ++setup_calls==fail_step) return 9;
    receiver_enabled=enabled;return 0;
}
static esp_err_t esp_wifi_set_channel(int ch,int second) {(void)ch;(void)second;return ++setup_calls==fail_step?9:0;}
static void deauth_detector_task(void*p) {(void)p;}
static int xTaskCreate(void(*f)(void*),const char*n,int stack,void*p,int prio,int*h) {
    (void)f;(void)n;(void)stack;(void)p;(void)prio;
    if(task_result==pdPASS)*h=1;
    return task_result;
}
'''
        code += source[start:end]
        code += function(source,"deauth_detector_reset_events")
        code += function(source,"deauth_detector_close_events")
        code += function(source,"cmd_deauth_detector_impl")
        code += function(source,"cmd_deauth_detector")
        code += r'''
int main(void) {
    g_scan_count=2;g_scan_done=true;
    g_scan_results[0].primary=36;g_scan_results[1].primary=149;
    char* selected[]={"deauth_detector","1","2"};
    for(int failure=1;failure<=4;++failure) {
        fail_step=failure;setup_calls=0;
        assert(cmd_deauth_detector(3,selected)==1);
        assert(!deauth_detector_active && !detector_accepting && !receiver_enabled);
        assert(!detector_event_count && !deauth_detector_task_handle);
    }
    fail_step=0;setup_calls=0;task_result=0;
    assert(cmd_deauth_detector(3,selected)==1);
    assert(!deauth_detector_active && !detector_accepting && !receiver_enabled);
    task_result=pdPASS;setup_calls=0;
    assert(cmd_deauth_detector(3,selected)==0);
    assert(deauth_detector_active && detector_accepting && receiver_enabled);
    assert(deauth_detector_selected_mode && deauth_detector_selected_channels_count==2);
    assert(deauth_detector_selected_channels[0]==36 && deauth_detector_selected_channels[1]==149);
    assert(scan_calls==0 && detector_cache_count==2);
    assert(cmd_deauth_detector(3,selected)==1);
    deauth_detector_active=false; deauth_detector_task_handle=0;
    deauth_detector_close_events();receiver_enabled=false;setup_calls=0;
    assert(cmd_deauth_detector(1,selected)==0);
    assert(scan_calls==1 && !deauth_detector_selected_mode && detector_cache_count==1);
    puts("command lifecycle PASS");
    return 0;
}
'''
        self.assertTrue(self.compile_run(code).endswith("command lifecycle PASS\n"))

if __name__ == "__main__":
    unittest.main()
