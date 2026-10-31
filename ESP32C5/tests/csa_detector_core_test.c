#include "csa_detector_core.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static size_t beacon(uint8_t *f, uint8_t subtype) {
    memset(f, 0, 256); f[0] = subtype;
    memcpy(f + 10, "\x02\x11\x22\x33\x44\x55", 6);
    memcpy(f + 16, "\x06\xAA\xBB\xCC\xDD\xEE", 6);
    memcpy(f + 36, "\x00\x04" "Test" "\x25\x03\x01\x24\x03", 11);
    return 47;
}
int main(void) {
    uint8_t f[256]; csa_event_t e;
    size_t n = beacon(f, 0x80);
    /* Dropping CSA extraction, using addr2 as BSSID or using a hop channel breaks this. */
    assert(csa_parse(f, n, 6, -51, &e));
    assert(e.rx_channel == 6 && e.target_channel == 36 && e.mode == 1 && e.count == 3);
    assert(e.via == CSA_VIA_BEACON && !e.has_class && e.rssi == -51);
    assert(!memcmp(e.bssid, "\x06\xAA\xBB\xCC\xDD\xEE", 6));
    assert(!memcmp(e.transmitter, "\x02\x11\x22\x33\x44\x55", 6));
    assert(!strcmp(e.ssid, "Test"));
#ifndef CSA_FIRST_RED
    f[0] = 0x50;
    memcpy(f+42, "\x3c\x04\x00\x73\x06\x00", 6);
    assert(csa_parse(f, 48, 149, -128, &e));
    assert(e.via == CSA_VIA_PROBE && e.rx_channel == 149 && e.target_channel == 6);
    assert(e.has_class && e.operating_class == 115 && e.count == 0 && e.mode == 0);
    /* Every strict prefix of a valid CSA IE must be ignored. */
    n = beacon(f, 0x80);
    for (size_t i=0; i<n; ++i) assert(!csa_parse(f, i, 6, -50, &e));
    f[n++] = 1; assert(!csa_parse(f,n,6,-50,&e));
    f[n++] = 5; assert(!csa_parse(f,n,6,-50,&e));
    n = beacon(f,0x80); f[43] = 4; assert(!csa_parse(f,n,6,-50,&e));
    n = beacon(f,0x80); f[44] = 2; assert(csa_parse(f,n,6,-50,&e) && e.mode==2);
    n = beacon(f,0x80); f[45] = 0; assert(csa_parse(f,n,6,-50,&e) && e.target_channel==0);
    n = beacon(f,0x80); f[1] = 0x40; assert(!csa_parse(f,n,6,-50,&e));
    n = beacon(f,0x80); f[1] = 0x80; assert(!csa_parse(f,n,6,-50,&e));
    n = beacon(f,0x80); f[1] = 4; assert(!csa_parse(f,n,6,-50,&e));
    n = beacon(f,0x80); f[22] = 1; assert(!csa_parse(f,n,6,-50,&e));
    n = beacon(f,0x80); memcpy(f+n,"\x3c\x04\x01\x73\x06\x03",6);
    assert(!csa_parse(f,n+6,6,-50,&e)); /* conflicting target */
    f[n+4]=36; assert(csa_parse(f,n+6,6,-50,&e) && e.has_class);
    n = beacon(f,0x80); f[0] = 0x88; assert(!csa_parse(f,n,6,-50,&e));
    f[0] = 0x81; assert(!csa_parse(f,n,6,-50,&e));
    assert(!csa_parse(NULL,n,6,-50,&e));
    assert(!csa_parse(f,n,6,-50,NULL));
    assert(!csa_parse(f,CSA_FRAME_LIMIT+1,6,-50,&e));
    /* Spectrum-management CSA action, and public ECSA fixed-body action. */
    n = beacon(f,0xd0); memcpy(f+24,"\x00\x04\x25\x03\x01\x95\x01",7);
    assert(csa_parse(f,31,36,-40,&e));
    assert(e.via == CSA_VIA_ACTION && e.target_channel == 149 && !strcmp(e.ssid,"<Unknown>"));
    memcpy(f+24,"\x04\x04\x00\x73\x24\x02",6);
    assert(csa_parse(f,30,1,-40,&e));
    assert(e.has_class && e.operating_class == 115 && e.target_channel == 36 && e.count == 2);
    for (size_t i=24; i<30; ++i) assert(!csa_parse(f,i,1,-40,&e));
    f[24]=0; f[25]=5; assert(!csa_parse(f,30,1,-40,&e));
    size_t length=999;
    assert(!csa_capture_length(51,0,0,&length));
    assert(csa_capture_length(51,55,0,&length) && length == 47);
    assert(csa_capture_length(51,47,0,&length) && length == 47);
    assert(!csa_capture_length(51,46,0,&length));
    assert(!csa_capture_length(27,0,0,&length));
    assert(!csa_capture_length(51,0,1,&length));
    assert(!csa_capture_length(5000,0,0,&length));
    char ssid[CSA_SSID_SIZE];
    csa_safe_ssid(ssid,(const uint8_t*)"A\n\r\033\x80|B",7);
    assert(!strcmp(ssid,"A?????B"));
    csa_safe_ssid(ssid,(const uint8_t*)"",0); assert(!strcmp(ssid,"<Unknown>"));
    csa_safe_ssid(ssid,(const uint8_t*)"\0AB",3); assert(!strcmp(ssid,"?AB"));
    uint8_t long_ssid[40]; memset(long_ssid,'X',40);
    csa_safe_ssid(ssid,long_ssid,40); assert(strlen(ssid)==32);
    n=beacon(f,0x80); assert(csa_parse(f,n,6,-51,&e));
    char line[CSA_LINE_SIZE];
    assert(csa_format_line(&e,line,sizeof(line)) > 0);
    assert(!strcmp(line,"[CSA] RX: 6 | TO: 36 | BSSID: 06:AA:BB:CC:DD:EE | TX: 02:11:22:33:44:55 | RSSI: -51 | VIA: beacon | COUNT: 3 | MODE: 1 | CLASS: - | SSID: Test"));
    e.rx_channel=255; e.target_channel=255; e.count=255; e.operating_class=255; e.has_class=true; e.rssi=-128;
    csa_safe_ssid(e.ssid,long_ssid,32);
    size_t written=csa_format_line(&e,line,sizeof(line));
    assert(written && written + 20 <= 220 && !strchr(line,'\n'));
    char short_line[8]; assert(!csa_format_line(&e,short_line,sizeof(short_line)) && !short_line[0]);
    csa_rate_limit_t rate={0};
    assert(csa_rate_allow(&rate,&e,0));
    e.count=1; e.rssi=-40;
    assert(!csa_rate_allow(&rate,&e,500)); /* countdown/RSSI do not flood */
    assert(!csa_rate_allow(&rate,&e,1999));
    assert(csa_rate_allow(&rate,&e,2000));
    e.target_channel=6; assert(csa_rate_allow(&rate,&e,2100));
    e.bssid[5]++; assert(csa_rate_allow(&rate,&e,2100));
    for (int i=0;i<13;++i) { ++e.bssid[5]; assert(csa_rate_allow(&rate,&e,2100)); }
    ++e.bssid[5]; assert(!csa_rate_allow(&rate,&e,2100));
    assert(rate.capacity_dropped==1);
    memset(&rate,0,sizeof(rate)); assert(csa_rate_allow(&rate,&e,0)); /* new session */
    memset(&rate,0,sizeof(rate)); assert(csa_rate_allow(&rate,&e,UINT32_MAX-100));
    assert(!csa_rate_allow(&rate,&e,100));
    assert(csa_rate_allow(&rate,&e,2000));
#endif
    puts("CSA core: PASS");
    return 0;
}
