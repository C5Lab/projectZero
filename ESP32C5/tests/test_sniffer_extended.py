"""Execute the C parser and real JanOS command bodies on host fixtures.

Run with Linux/WSL Python and gcc. Radio/RTOS primitives are the only doubles.
The frozen legacy functions are from the unmodified repository at task start.
"""
from pathlib import Path
import os
import re
import shutil
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
    begin = source.rfind('\n', 0, match.start()) + 1
    depth = 1
    end = match.end()
    while depth:
        depth += (masked[end] == '{') - (masked[end] == '}')
        end += 1
    return source[begin:end]

COMMON = r'''
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <stdatomic.h>
#include "sniffer_extended.h"
#define MAX_CLIENTS_PER_AP 50
#define MAX_SNIFFER_APS 100
#define MALLOC_CAP_SPIRAM 0
#define portMAX_DELAY 1
#define pdTRUE 1
#define pdMS_TO_TICKS(x) (x)
#define MY_LOG_INFO(tag, ...) do { printf(__VA_ARGS__); puts(""); } while (0)
typedef int wifi_auth_mode_t;
static const char *TAG = "test";
static int sniffer_data_mutex = 1;
static int sniffer_ap_count;
static bool sniffer_active, sniffer_scan_phase;
static int xSemaphoreTake(int mutex, int wait) { (void)mutex; (void)wait; return pdTRUE; }
static void xSemaphoreGive(int mutex) { (void)mutex; }
static void *heap_caps_malloc(size_t n, int caps) { (void)caps; return malloc(n); }
static int64_t esp_timer_get_time(void) { return 1200000; }
static void vTaskDelay(int ms) { (void)ms; }
static bool is_broadcast_bssid(const uint8_t *m) { return m[0] == 255; }
static bool is_own_device_mac(const uint8_t *m) { return m[5] == 99; }
static const char *vendor_label(const uint8_t *m) { return m[0] == 2 ? "random" : "Fixture Vendor"; }
'''

SETUP = r'''
int main(int argc, char **argv) {
    (void)TAG;
    sniffer_ap_count = 6;
    for (int i=0; i<6; ++i) {
        sniffer_ap_t *a = &sniffer_aps[i];
        sx_init(&a->extended);
        a->bssid[0] = 2; a->bssid[5] = (uint8_t)(i+1);
        a->channel = (uint8_t)(i+1); a->client_count = i == 1 ? 2 : 1;
        a->rssi = -50; a->last_seen = 100;
        a->rx_rssi = -50; a->rx_rssi_known = true;
        strcpy(a->ssid, i == 0 ? "" : i == 1 ? "Home [x], |" : "Tie");
        for (int j=0; j<a->client_count; ++j) {
            a->clients[j].mac[0] = 4; a->clients[j].mac[5] = (uint8_t)(10*i+j);
            a->clients[j].rssi = -40-j; a->clients[j].last_seen = 200;
            a->clients[j].rx_rssi = -40-j; a->clients[j].rx_rssi_known = true;
        }
    }
    sniffer_aps[3].client_count = 0;
    sniffer_aps[4].bssid[0] = 255;
    sniffer_aps[5].bssid[5] = 99;
    char *args[] = {"show_sniffer_results", "extended"};
    return argc > 1 && !strcmp(argv[1],"vendor") ?
        cmd_show_sniffer_results_vendor(argc > 2 ? 2 : 1,args) :
        cmd_show_sniffer_results(argc > 2 ? 2 : 1,args);
}
'''

@unittest.skipUnless(shutil.which(os.environ.get("CC","gcc")),
                     "Host C tests require GCC; run this suite in Linux/WSL")
class SnifferExtendedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="janos-sniffer-")
        cls.directory = Path(cls.tmp.name)
        cls.source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        cls.executables = {}
        for label in ("legacy", "current"):
            source = cls.source if label == "current" else (ROOT / "tests/fixtures/sniffer_legacy_commands.c").read_text()
            structs = cls.source.split("// Sniffer data structures\n",1)[1].split("// GPS data structure",1)[0]
            helpers = ""
            if label == "current" and "static sniffer_ap_t *sniffer_take_snapshot(" in source:
                helpers = function(source,"sniffer_take_snapshot")
            code = COMMON + structs + '\nstatic sniffer_ap_t storage[MAX_SNIFFER_APS];\nstatic sniffer_ap_t *sniffer_aps = storage;\n' + helpers
            code += function(source,"cmd_show_sniffer_results") + '\n' + function(source,"cmd_show_sniffer_results_vendor") + SETUP
            path = cls.directory / (label + '.c'); path.write_text(code)
            exe = cls.directory / label
            subprocess.run([os.environ.get("CC","gcc"),"-std=c11","-Wall","-Wextra","-Wno-unused-function",
                            "-Wno-unused-variable","-I",str(ROOT / "main"),str(path),
                            str(ROOT / "main/sniffer_extended.c"),"-o",str(exe)],check=True)
            cls.executables[label] = exe

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def output(self,label,vendor=False,extended=False):
        args = [str(self.executables[label]),"vendor" if vendor else "plain"]
        if extended: args.append("extended")
        return subprocess.check_output(args)

    def test_legacy_commands_identical_bytes(self):
        for vendor in (False,True):
            self.assertEqual(self.output("current",vendor),self.output("legacy",vendor))

    def test_legacy_filters_sort_ties_empty_ssid_and_vendor(self):
        self.assertEqual(self.output("current"),
            b"Home [x], |, CH2: 2\n 04:00:00:00:00:0A\n 04:00:00:00:00:0B\n"
            b", CH1: 1\n 04:00:00:00:00:00\nTie, CH3: 1\n 04:00:00:00:00:14\n")
        self.assertIn(b", CH1: 1 [random]\n 04:00:00:00:00:00 [Fixture Vendor]\n",self.output("current",True))

    def test_extended_appends_fields_to_every_existing_line(self):
        for vendor in (False,True):
            old = self.output("legacy",vendor).splitlines()
            new = self.output("current",vendor,True).splitlines()
            self.assertEqual(len(old),len(new))
            for before,after in zip(old,new):
                self.assertTrue(after.startswith(before+b" | ext_ver=1 | "),after)
            self.assertIn(b"bssid=02:00:00:00:00:02",new[0])

    def test_parser_fixtures_with_sanitizers(self):
        exe = self.directory / "parser"
        subprocess.run([os.environ.get("CC","gcc"),"-std=c11","-Wall","-Wextra","-Werror",
                        "-fsanitize=address,undefined","-g","-I",str(ROOT / "main"),
                        str(ROOT / "tests/sniffer_extended_test.c"),str(ROOT / "main/sniffer_extended.c"),
                        "-o",str(exe)],check=True)
        subprocess.run([str(exe)],check=True)
        for vendor in (False,True):
            args = [str(exe),'--examples'] + (['vendor'] if vendor else [])
            wire = subprocess.check_output(args)
            name = 'sniffer_extended_vendor_uart.txt' if vendor else 'sniffer_extended_uart.txt'
            self.assertEqual(wire,(ROOT / 'tests/fixtures' / name).read_bytes())
            self.assertEqual(len(wire.splitlines()),6)
            self.assertIn(b'resolved_ssid_hex=486F6D657C420D0A00FF',wire)
            self.assertIn(b'hidden=unknown',wire)
            self.assertIn(b'wps_present=1 | wps_state=2 | wps_config_methods=128 | wps_setup_locked=unknown',wire)

    def capture_code(self, source, legacy=False):
        structs = self.source.split("// Sniffer data structures\n",1)[1].split("// GPS data structure",1)[0]
        code = COMMON.replace('static int xSemaphoreTake(int mutex, int wait) { (void)mutex; (void)wait; return pdTRUE; }',
                              'static bool mutex_available = true;\nstatic int xSemaphoreTake(int mutex, int wait) { (void)mutex; (void)wait; return mutex_available; }')
        code += structs + r'''
static sniffer_ap_t storage[MAX_SNIFFER_APS];
static sniffer_ap_t *sniffer_aps = storage;
typedef struct { uint8_t mac[6]; char ssid[33]; int rssi; uint32_t last_seen; } probe_request_t;
static probe_request_t probe_requests[10];
static int probe_request_count;
#define MAX_PROBE_REQUESTS 10
#define WIFI_AUTH_OPEN 0
typedef int wifi_promiscuous_pkt_type_t;
enum { WIFI_PKT_MGMT, WIFI_PKT_DATA, WIFI_PKT_CTRL };
typedef struct { unsigned sig_len,dump_len,rx_state,channel; int rssi; } fake_rx_t;
typedef struct { fake_rx_t rx_ctrl; uint8_t payload[]; } wifi_promiscuous_pkt_t;
typedef struct { uint8_t bssid[6]; uint8_t ssid[33]; uint8_t primary; int rssi; int authmode; } wifi_ap_record_t;
static wifi_ap_record_t g_scan_results[5];
static int g_selected_indices[5], g_selected_count, g_scan_count;
static bool sniffer_selected_mode, sniff_oled_dirty, g_scan_done;
static uint32_t sniffer_packet_counter, sniff_oled_packets, sniffer_last_debug_packet;
typedef struct {
    uint32_t rx, mgmt, data, bad_length, rx_error, selected_reject, matched, short_dump, zero_dump;
    uint16_t last_sig_len, last_dump_len;
    uint8_t last_rx_state, last_channel;
    uint32_t assoc_rx, reassoc_rx, probe_resp_rx;
    uint32_t request_rejected, request_incomplete, request_untracked, request_named;
    uint8_t last_request_bssid[6], last_request_ssid_len;
    uint16_t last_request_sig_len, last_request_dump_len;
    bool last_request_parsed, last_request_complete;
} sniffer_rx_diagnostics_t;
static sniffer_rx_diagnostics_t sniffer_rx_diagnostics;
static atomic_uint sniffer_rx_lock_busy;
static uint8_t sniffer_selected_channels[5];
static int sniffer_selected_channels_count;
#define MAX_AP_CNT 5
static int sniffer_current_channel = 6;
static int sniff_debug;
static unsigned channel_hops;
static void sniffer_channel_hop(void) { ++channel_hops; }
static bool is_multicast_mac(const uint8_t *m) { return m[0] & 1; }
#undef MY_LOG_INFO
#define MY_LOG_INFO(...) ((void)0)
#define printf(...) ((void)0)
'''
        names = ('add_client_to_ap','sniffer_promiscuous_callback') if legacy else (
                     'sniffer_take_snapshot','sniffer_process_scan_results_locked','sniffer_process_scan_results',
                     'sniffer_merge_scan_results_locked','sniffer_merge_scan_results',
                     'sniffer_init_selected_networks_locked','sniffer_init_selected_networks','cmd_clear_sniffer_results',
                     'add_client_to_ap','sniffer_capture_legacy_locked',
                     'sniffer_capture_extended_locked','sniffer_promiscuous_callback','cmd_sniffer_debug',
                     'cmd_show_sniffer_results')
        for name in names:
            if name == 'cmd_sniffer_debug':
                code += '\n#undef printf\n'
            code += '\n' + function(source,name)
        return code + '\n#undef printf\n'

    def test_real_radio_callback(self):
        code = self.capture_code(self.source)
        code += (ROOT / 'tests/sniffer_capture_fixture.c').read_text()
        path = self.directory / 'capture.c'; path.write_text(code)
        exe = self.directory / 'capture'
        subprocess.run([os.environ.get('CC','gcc'),'-std=c11','-Wall','-Wextra','-Wno-unused-function','-Wno-unused-variable',
                        '-fsanitize=address,undefined','-I',str(ROOT / 'main'),str(path),
                        str(ROOT / 'main/sniffer_extended.c'),'-o',str(exe)],check=True)
        output = subprocess.check_output([str(exe)])
        self.assertIn(b'[SnifferCapture] pipeline=legacy-v2',output)
        self.assertIn(b'aps=1 clients=1',output)
        self.assertIn(b'Unknown_0001, CH6: 1 |',output)
        self.assertIn(b' 04:00:00:00:00:03 |',output)
        self.assertIn(b'[SnifferSSID] assoc_rx=4 reassoc_rx=2 probe_resp_rx=0 request_rejected=1 request_incomplete=1 request_untracked=1 request_named=3',output)
        self.assertIn(b'hidden=1 | resolved_ssid_hex=48696464656E54657374',output)
        self.assertIn(b'[SnifferSSIDLast] bssid=02:00:00:00:00:02 parsed=1 complete=1 ssid_len=5 sig_len=39 dump_len=35',output)

    def test_legacy_capture_decisions_identical(self):
        original = (ROOT / 'tests/fixtures/sniffer_legacy_capture.c').read_text()
        replay = (ROOT / 'tests/sniffer_legacy_capture_replay.c').read_text()
        outputs = []
        for name,source,legacy in (('before',original,True),('after',self.source,False)):
            path = self.directory / (name+'_capture.c')
            path.write_text(self.capture_code(source,legacy)+replay)
            exe = self.directory / (name+'_capture')
            subprocess.run(['gcc','-std=c11','-Wno-unused-variable','-Wno-unused-function','-I',str(ROOT / 'main'),
                            str(path),str(ROOT / 'main/sniffer_extended.c'),'-o',str(exe)],check=True)
            outputs.append(subprocess.check_output([str(exe)]))
        self.assertEqual(outputs[0],outputs[1], 'Legacy AP/client detection changed for the same received frames')

if __name__ == '__main__': unittest.main()
