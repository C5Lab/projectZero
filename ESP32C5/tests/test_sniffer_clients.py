"""Run new identity command bodies against host radio doubles; replay legacy APIs separately."""
import json
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from test_sniffer_extended import function
ROOT=Path(__file__).resolve().parents[1]

STUBS=r'''
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
#define portMAX_DELAY 1
#define pdPASS 1
#define ESP_OK 0
#define DEAUTH 1
#define IDLE 0
#define WIFI_SECOND_CHAN_NONE 0
#define WIFI_PKT_MGMT 0
#define pdMS_TO_TICKS(x) (x)
#define MALLOC_CAP_SPIRAM 0
static unsigned stops,frames,channel,task_failure,radio_failure,allocation_failure;
static uint8_t sent[26];
typedef int wifi_auth_mode_t;
typedef struct {uint8_t bssid[6]; char ssid[33]; uint8_t channel; int authmode; uint32_t last_seen; bool active;} target_bssid_t;
typedef int wifi_promiscuous_pkt_type_t;
typedef struct {struct {size_t sig_len,dump_len; uint8_t rx_state,channel;} rx_ctrl; uint8_t payload[256];} wifi_promiscuous_pkt_t;
static uint8_t deauth_frame_default[26]={0xc0};
static int sniffer_data_mutex=1,sniffer_ap_count,applicationState;
static bool sniffer_station_direct_active,operation_stop_requested,deauth_attack_active;
static uint8_t sniffer_station_direct_mac[6];
static target_bssid_t sniffer_station_direct_target,targets[1],*target_bssids=targets;
static void *deauth_attack_task_handle;
static int64_t last_channel_check_time;
static const int dual_band_channels[]={1,6,11,36,48,132};
static const int dual_band_channels_count=6;
static int selected_indices[]={3,8},selected_count=2;
static uint8_t legacy_stations[6]={4,1,2,3,4,5};
static int xSemaphoreTake(int a,int b){return 1;}
static void xSemaphoreGive(int a){}
static int64_t esp_timer_get_time(void){return 1000000;}
static bool is_broadcast_bssid(const uint8_t *m){return m[0]&1;}
static bool is_own_device_mac(const uint8_t *m){return m[5]==255;}
static void taskYIELD(void){}
static void vTaskDelay(unsigned a){}
static int esp_wifi_set_promiscuous(bool a){return radio_failure;}
static int esp_wifi_set_promiscuous_filter(const void *a){return radio_failure;}
static int esp_wifi_set_promiscuous_rx_cb(void (*cb)(void*,int)){return radio_failure;}
static int esp_wifi_set_channel(unsigned a,int b){channel=a;return radio_failure;}
static void wsl_bypasser_send_raw_frame(const uint8_t *f,int n){assert(n==26);memcpy(sent,f,n);++frames;}
static bool ensure_wifi_mode(void){return !radio_failure;}
static void deauth_attack_task(void *arg){}
static int xTaskCreate(void (*fn)(void*),const char *name,int stack,void *arg,int pri,void **handle){*handle=task_failure?NULL:(void*)1;return !task_failure;}
static int sniffer_filter;
static void sniffer_station_cleanup(void);
static int cmd_stop(int argc,char **argv){++stops;sniffer_station_cleanup();deauth_attack_active=false;return 0;}
static void *heap_caps_malloc(size_t n,int caps){return allocation_failure?NULL:malloc(n);}
'''
SETUP=r'''
static void setup(void){
 sniffer_ap_count=2;
 for(int i=0;i<2;++i){
  sniffer_ap_t *ap=&sniffer_aps[i]; sx_init(&ap->extended);
  ap->bssid[0]=2;ap->bssid[5]=i+1;ap->channel=1;ap->identity_channel=i?48:6;
  strcpy(ap->ssid,"Unknown_legacy");
  ap->client_count=1;ap->clients[0].mac[0]=4;ap->clients[0].mac[5]=i+1;
  memcpy(ap->identity_scan_ssid,"PaddysTV",8);ap->identity_scan_len=8;
 }
}
int main(int argc,char **argv){
 setup();
 if(argc>1 && !strcmp(argv[1],"list")){
  memcpy(sniffer_aps[0].extended.resolved_ssid,"A,\"\n\0Z",6);
  sniffer_aps[0].extended.resolved_len=6;sniffer_aps[0].extended.ssid_source=SX_ASSOC_REQ;
  sniffer_aps[1].identity_scan_len=0;
  char *args[]={"show_sniffer_clients"};return cmd_show_sniffer_clients(1,args);
 }
 char *start[]={"start_deauth_station","02:00:00:00:00:02","04:00:00:00:00:02"};
 char *bad[]={"start_deauth_station","02:00:00:00:00:01","04:00:00:00:00:02"};
 assert(cmd_start_deauth_station(3,bad)==1 && stops==0 && frames==0);
 assert(cmd_start_deauth_station(3,start)==0 && stops==1 && channel==48);
 assert(selected_count==2 && selected_indices[0]==3 && selected_indices[1]==8 && legacy_stations[0]==4);
 assert(!memcmp(sniffer_station_direct_target.bssid,sniffer_aps[1].bssid,6));
 sniffer_station_send(); assert(frames==1);
 assert(!memcmp(sent+4,sniffer_aps[1].clients[0].mac,6));
 assert(!memcmp(sent+10,sniffer_aps[1].bssid,6) && !memcmp(sent+16,sniffer_aps[1].bssid,6));
 wifi_promiscuous_pkt_t packet={0};
 packet.rx_ctrl.sig_len=42;packet.rx_ctrl.dump_len=38;packet.rx_ctrl.channel=132;
 packet.payload[0]=0x80;memcpy(packet.payload+10,sniffer_aps[1].bssid,6);memcpy(packet.payload+16,sniffer_aps[1].bssid,6);
 packet.payload[36]=0;packet.payload[37]=0;
 sniffer_station_rx(&packet,WIFI_PKT_MGMT);assert(sniffer_station_observed_channel==132);
 sniffer_station_send();assert(frames==2 && channel==132);
 memcpy(packet.payload+10,sniffer_aps[0].bssid,6);memcpy(packet.payload+16,sniffer_aps[0].bssid,6);packet.rx_ctrl.channel=6;
 sniffer_station_rx(&packet,WIFI_PKT_MGMT);assert(sniffer_station_observed_channel==132);
 sniffer_station_monitor();assert(channel==132); /* No observation: retain target channel. */
 operation_stop_requested=true;sniffer_station_send();assert(frames==2);
 cmd_stop(0,NULL); assert(!sniffer_station_direct_active);
 sniffer_station_send();assert(frames==2);
 sniffer_aps[1].identity_channel=0;
 unsigned before=stops;assert(cmd_start_deauth_station(3,start)==1 && stops==before);
 sniffer_aps[1].identity_channel=132;task_failure=1;
 assert(cmd_start_deauth_station(3,start)==1 && !sniffer_station_direct_active && !deauth_attack_active);
 task_failure=0;radio_failure=1;
 assert(cmd_start_deauth_station(3,start)==1 && !sniffer_station_direct_active);
 uint8_t mac[6]; assert(!sniffer_identity_mac("02:00:00:00:00:02x",mac));
 assert(!sniffer_identity_mac("FF:FF:FF:FF:FF:FF",mac));assert(!sniffer_identity_mac("00:00:00:00:00:00",mac));
 puts("command fixtures PASS");return 0;
}
'''
@unittest.skipUnless(shutil.which('cc'),'requires host C compiler')
class IdentityTests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory();cls.directory=Path(cls.tmp.name)
  source=(ROOT/'main/main.c').read_text()
  structs=source.split('// Sniffer data structures\n',1)[1].split('// GPS data structure',1)[0]
  code=STUBS+structs+'\nstatic sniffer_ap_t storage[100],*sniffer_aps=storage;\n'
  code+=function(source,'sniffer_take_snapshot')+'\n#include "sniffer_clients.inc"\n'+SETUP
  path=cls.directory/'identity.c';path.write_text(code);cls.exe=cls.directory/'identity'
  subprocess.run(['cc','-std=gnu11','-Wall','-Wextra','-Wno-unused-parameter','-Wno-unused-function','-I',str(ROOT/'main'),str(path),str(ROOT/'main/sniffer_extended.c'),'-o',str(cls.exe)],check=True)
 @classmethod
 def tearDownClass(cls):cls.tmp.cleanup()
 def test_station_pair_and_failures(self):
  self.assertIn('command fixtures PASS',subprocess.check_output([str(self.exe)],text=True))
 def test_versioned_stream_and_names(self):
  lines=subprocess.check_output([str(self.exe),'list'],text=True).splitlines()
  rows=[json.loads(x) for x in lines]
  self.assertTrue(all(len(x.encode())<1024 for x in lines))
  self.assertEqual(rows[0]['record_type'],'sniffer_clients_begin')
  self.assertEqual(rows[-1]['clients'],2)
  aps=[r for r in rows if r['record_type']=='sniffer_ap']
  self.assertEqual(bytes.fromhex(aps[0]['ssid_hex']),b'A,"\n\x00Z')
  self.assertEqual(aps[0]['ssid_source'],'association')
  self.assertEqual(aps[1]['ssid_hex'],'')
  self.assertEqual(aps[1]['ssid_source'],'none')
  self.assertEqual(aps[1]['channel'],48)
  self.assertEqual(rows[2]['bssid'],aps[0]['bssid'])

class LegacyContractTests(unittest.TestCase):
 def test_legacy_implementations_unchanged(self):
  source=(ROOT/'main/main.c').read_text()
  hashes=json.loads((ROOT/'tests/fixtures/sniffer_identity_legacy_sha256.json').read_text())
  for name,digest in hashes.items():
   with self.subTest(command=name):
    body=function(source,name)
    if name=='cmd_stop': body=body.replace('    sniffer_station_cleanup();\n\n','')
    self.assertEqual(hashlib.sha256(body.encode()).hexdigest(),digest)

class CaptureIdentityTests(unittest.TestCase):
 def test_real_scan_and_capture_identity_without_legacy_changes(self):
  from test_sniffer_extended import SnifferExtendedTests
  from types import SimpleNamespace
  source=(ROOT/'main/main.c').read_text()
  code=SnifferExtendedTests.capture_code(SimpleNamespace(source=source),source)
  code+='\nstatic void taskYIELD(void){}\n'
  api=(ROOT/'main/sniffer_clients.inc').read_text()
  for name in ('sniffer_identity_mac_text','sniffer_identity_name','sniffer_identity_error','cmd_show_sniffer_clients'):
   code+=function(api,name)+'\n'
  fixture=(ROOT/'tests/sniffer_capture_fixture.c').read_text().split('int main(void) {',1)[0]
  code+=fixture+r'''
int main(void) {
 sniffer_active=true;g_scan_done=true;g_scan_count=1;
 memcpy(g_scan_results[0].bssid,a_mac,6);strcpy((char*)g_scan_results[0].ssid,"PaddysTV");
 g_scan_results[0].primary=6;
 sniffer_process_scan_results();
 assert(sniffer_aps[0].identity_scan_len==8 && !memcmp(sniffer_aps[0].identity_scan_ssid,"PaddysTV",8));
 /* Last scan no longer contains this AP. Its identity stays in sniffer data. */
 g_scan_count=0;
 send_mgmt(0,a_mac,"HiddenTest");
 assert(!strcmp(sniffer_aps[0].ssid,"PaddysTV")); /* legacy field unchanged */
 assert(sniffer_aps[0].identity_channel==6);
 send_mgmt(0x80,a_mac,"");
 assert(sniffer_aps[0].extended.resolved_len==10); /* hidden beacon doesn't erase */
 send_mgmt(0x50,a_mac,"ResolvedName");
 assert(sniffer_aps[0].extended.ssid_source==SX_PROBE_RESP);
 packet->rx_ctrl.channel=132;
 sniffer_promiscuous_callback(packet,WIFI_PKT_MGMT);
 assert(sniffer_aps[0].channel==6 && sniffer_aps[0].identity_channel==132);
 /* A truncated dump still has RX channel metadata but cannot change the name. */
 send_mgmt(0x20,a_mac,"FinalName");
 packet->rx_ctrl.sig_len+=30;packet->rx_ctrl.channel=48;
 sniffer_promiscuous_callback(packet,WIFI_PKT_MGMT);
 assert(sniffer_aps[0].identity_channel==48);
 assert(sniffer_aps[0].extended.resolved_len==9);
 char *args[]={"show_sniffer_clients"};cmd_show_sniffer_clients(1,args);
 return 0;
}
'''
  with tempfile.TemporaryDirectory() as tmp:
   path=Path(tmp)/'capture.c';path.write_text(code);exe=Path(tmp)/'capture'
   subprocess.run(['cc','-std=gnu11','-Wno-unused-value','-I',str(ROOT/'main'),str(path),str(ROOT/'main/sniffer_extended.c'),'-o',str(exe)],check=True)
   rows=[json.loads(line) for line in subprocess.check_output([str(exe)],text=True).splitlines()]
   ap=next(r for r in rows if r['record_type']=='sniffer_ap')
   self.assertEqual(bytes.fromhex(ap['ssid_hex']),b'FinalName')
   self.assertEqual(ap['ssid_source'],'reassociation')
   self.assertEqual(ap['channel'],48)
