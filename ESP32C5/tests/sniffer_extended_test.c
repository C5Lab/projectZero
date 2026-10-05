#include "sniffer_extended.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t ap_mac[6] = {2,0,0,0,0,1};
static uint8_t frame[2048];
static size_t frame_len;
static void start(uint8_t subtype) {
    memset(frame, 0, sizeof(frame));
    frame[0] = subtype;
    memcpy(frame+16, ap_mac, 6);
    memcpy(frame+(subtype == 0 || subtype == 0x20 ? 4 : 10), ap_mac, 6);
    if (subtype == 0 || subtype == 0x20) frame[10] = 4;
    frame_len = subtype == 0 ? 28 : subtype == 0x20 ? 34 : 36;
}
static void ie(uint8_t tag, const void *data, size_t len) {
    assert(len <= 255 && frame_len+2+len <= sizeof(frame));
    frame[frame_len++] = tag; frame[frame_len++] = (uint8_t)len;
    if (len) memcpy(frame+frame_len, data, len);
    frame_len += len;
}
static sx_observation_t parse(void) {
    sx_observation_t o;
    assert(sx_parse(frame, frame_len, &o));
    return o;
}
static void hidden_and_discovery(void) {
    sx_ap_t ap; sx_init(&ap); assert(ap.hidden == -1);
    start(0x80); ie(0, "", 0);
    sx_observation_t o = parse(); sx_apply(&ap, &o);
    assert(ap.hidden == 1 && ap.ssid_source == SX_NONE);
    const uint8_t name[32] = {'A',' ', ',', '[',']','|','\r','\n',0,0xff,1,2,3,4,5,6,
                              7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22};
    for (int subtype = 0; subtype <= 0x20; subtype += 0x20) {
        start((uint8_t)subtype); ie(0, name, sizeof(name)); o = parse();
        assert(o.complete && memcmp(o.bssid, ap_mac, 6) == 0);
        sx_apply(&ap, &o);
        assert(ap.resolved_len == 32 && !memcmp(ap.resolved_ssid, name, 32));
        assert(ap.ssid_source == (subtype ? SX_REASSOC_REQ : SX_ASSOC_REQ));
        assert(ap.hidden == 1);
    }
    start(0x80); ie(0, "", 0); o = parse(); sx_apply(&ap, &o);
    assert(ap.resolved_len == 32 && ap.hidden == 1);
    start(0x50); ie(0, "Home", 4); o = parse(); sx_apply(&ap, &o);
    assert(ap.ssid_source == SX_PROBE_RESP && ap.resolved_len == 4 && ap.hidden == 1);
    frame[10] ^= 1; assert(!sx_parse(frame, frame_len, &o));
    start(0); ie(0, "Wrong", 5); frame[4] ^= 1;
    assert(!sx_parse(frame, frame_len, &o));
    start(0x40); ie(0, "Wrong", 5); assert(!sx_parse(frame, frame_len, &o));
}
static const uint8_t rsn[] = {
    1,0, 0,15,172,4, 2,0, 0,15,172,4, 0x12,0x34,0x56,0xfe,
    2,0, 0,15,172,2, 0,15,172,8, 0x80,0, 0,0, 0,15,172,6
};
static void security_profiles(void) {
    start(0x80); ie(0, "X", 1); ie(48, rsn, sizeof(rsn));
    sx_observation_t o = parse(); assert(o.complete && o.rsn.status == SX_VALID);
    assert(o.rsn.pairwise_count == 2 && o.rsn.akm_count == 2);
    assert(o.rsn.pairwise[1][3] == 0xfe && o.rsn.management_present);
    assert(o.rsn.pmf_capable && !o.rsn.pmf_required);
    frame[frame_len-8] = 0xc0; o = parse(); assert(o.rsn.pmf_required);
    uint8_t wpa[64] = {0,0x50,0xf2,1};
    const uint8_t body[] = {1,0,0,0x50,0xf2,2,1,0,0,0x50,0xf2,4,1,0,0,0x50,0xf2,2};
    memcpy(wpa+4, body, sizeof(body));
    start(0x50); ie(0, "X", 1); ie(221, wpa, 4+sizeof(body)); o = parse();
    assert(o.wpa.status == SX_VALID && o.wpa.akm[0][3] == 2 && o.rsn.status == SX_ABSENT);
    start(0x80); ie(0,"",0); o = parse();
    assert(o.rsn.status == SX_ABSENT && o.wpa.status == SX_ABSENT);
    ie(48, rsn, sizeof(rsn)-1); o = parse(); assert(o.rsn.status == SX_INVALID);
}
static void wps_attributes(void) {
    const uint8_t wps[] = {0,0x50,0xf2,4, 0x10,0x44,0,1,2,
                           0x10,0x08,0,2,0,0x80, 0x10,0x57,0,1,0};
    start(0x80); ie(0,"",0); ie(221,wps,sizeof(wps));
    sx_observation_t o = parse();
    assert(o.wps.status == SX_VALID && o.wps.state == 2 && o.wps.config_methods == 128);
    assert(o.wps.setup_locked == 0 && o.wps.selected_registrar == -1);
    assert(!o.wps.manufacturer.present && !o.wps.device_name.present);
    frame[frame_len-2] = 9; o = parse(); assert(o.wps.status == SX_INVALID);
}
static void truncation_and_format(void) {
    sx_ap_t ap; sx_init(&ap);
    start(0x80); ie(0, "Home", 4); ie(48,rsn,sizeof(rsn));
    for (size_t n=24; n<36; ++n) { sx_observation_t o; assert(sx_parse(frame,n,&o)); assert(!o.complete); }
    sx_observation_t o = parse(); sx_apply(&ap, &o);
    frame[frame_len++] = 221; o = parse(); assert(!o.complete); sx_apply(&ap, &o);
    assert(ap.resolved_len == 4 && ap.rsn.status == SX_INVALID);
    char output[SX_AP_SUFFIX_BYTES];
    assert(sx_format_ap(output,sizeof(output),&ap,ap_mac,-55,true,0,true,1200));
    assert(strstr(output," | ext_ver=1 | bssid=02:00:00:00:00:01"));
    assert(strstr(output,"resolved_ssid_hex=486F6D65"));
    assert(strstr(output,"rssi=-55 | age_ms=1200"));
    assert(!sx_format_ap(output,8,&ap,ap_mac,-55,true,0,true,1200));
    assert(output[0] == 0);
    assert(sx_format_client(output,sizeof(output),-40,true,UINT32_MAX-9,10));
    assert(!strcmp(output," | ext_ver=1 | rssi=-40 | age_ms=20"));
    assert(sx_format_client(output,sizeof(output),-40,false,0,5));
    assert(!strcmp(output," | ext_ver=1 | rssi=unknown | age_ms=5"));
}

static void bounded_lists_and_optional_fields(void) {
    uint8_t large[100] = {1,0,0,15,172,4,9,0};
    size_t n = 8;
    for (unsigned i=0; i<9; ++i) { large[n++]=0; large[n++]=15; large[n++]=172; large[n++]=(uint8_t)i; }
    large[n++]=9; large[n++]=0;
    for (unsigned i=0; i<9; ++i) { large[n++]=0x12; large[n++]=0x34; large[n++]=0x56; large[n++]=(uint8_t)i; }
    start(0x80); ie(0,"X",1); ie(48,large,n);
    sx_observation_t o = parse();
    assert(o.complete && o.rsn.status == SX_VALID && o.rsn.truncated);
    assert(o.rsn.pairwise_count == 8 && o.rsn.akm_count == 8);
    assert(!o.rsn.pmf_capable && !o.rsn.pmf_required); /* omitted caps default zero */
    assert(!o.rsn.management_present);
    /* Every possible partial byte of the valid RSN must be safe at a real allocation boundary. */
    start(0x80); ie(0,"X",1); ie(48,rsn,sizeof(rsn));
    for (size_t len=0; len<=frame_len; ++len) {
        uint8_t *copy = malloc(len ? len : 1); assert(copy);
        memcpy(copy,frame,len);
        sx_observation_t part;
        bool accepted = sx_parse(copy,len,&part);
        if (accepted && len < frame_len && len > 39) assert(!part.complete);
        free(copy);
    }
    uint8_t broken[] = {1,0,0,15,172,4,0xff,0xff};
    start(0x80); ie(0,"X",1); ie(48,broken,sizeof(broken)); o=parse();
    assert(o.rsn.status == SX_INVALID);
    /* Beacon evidence is required; probe responses never classify hidden. */
    sx_ap_t ap; sx_init(&ap);
    start(0x50); ie(0,"Visible",7); o=parse(); sx_apply(&ap,&o); assert(ap.hidden == -1);
    start(0x80); ie(0,"Visible",7); o=parse(); sx_apply(&ap,&o); assert(ap.hidden == 0);
    start(0x80); const uint8_t zero[4]={0}; ie(0,zero,4); o=parse(); sx_apply(&ap,&o);
    assert(ap.hidden == 1 && ap.resolved_len == 7);
}

static void wps_fragmentation_and_limits(void) {
    const uint8_t first[] = {0,0x50,0xf2,4,0x10,0x11,0};
    const uint8_t second[] = {0,0x50,0xf2,4,4,'A','|',0,0xff,0x10,0x41,0,1,1};
    start(0x50); ie(0,"W",1); ie(221,first,sizeof(first)); ie(221,second,sizeof(second));
    sx_observation_t o=parse();
    assert(o.wps.status == SX_VALID && o.wps.device_name.len == 4 && o.wps.selected_registrar == 1);
    sx_ap_t ap; sx_init(&ap); sx_apply(&ap,&o); char out[SX_AP_SUFFIX_BYTES];
    assert(sx_format_ap(out,sizeof(out),&ap,ap_mac,0,false,0,true,0));
    assert(strstr(out,"wps_device_name_hex=417C00FF"));
    uint8_t long_text[73] = {0,0x50,0xf2,4,0x10,0x21,0,65};
    memset(long_text+8,'x',65);
    start(0x80); ie(0,"W",1); ie(221,long_text,sizeof(long_text)); o=parse();
    assert(o.wps.status == SX_VALID && o.wps.manufacturer.len == 64 && o.wps.manufacturer.truncated);
    assert(o.wps.truncated && !o.wps.model_name.present);
    uint8_t chunk[255] = {0,0x50,0xf2,4};
    start(0x80); ie(0,"W",1);
    for (unsigned i=0;i<3;++i) ie(221,chunk,sizeof(chunk));
    o=parse();
    assert(o.wps.status == SX_INVALID && o.wps.truncated && o.wps.present);
    sx_apply(&ap,&o);
    assert(sx_format_ap(out,sizeof(out),&ap,ap_mac,0,false,0,true,0));
    assert(strstr(out,"wps_present=1") && strstr(out,"wps_state=unknown"));
}

static void fuzz_and_maximum_line(void) {
    uint32_t seed = 1;
    for (unsigned trial=0;trial<5000;++trial) {
        start((uint8_t[]){0,0x20,0x50,0x80}[trial%4]);
        size_t n = 24 + trial%400;
        for(size_t i=24;i<n;++i) { seed=seed*1664525+1013904223; frame[i]=(uint8_t)(seed>>24); }
        uint8_t *copy=malloc(n); assert(copy); memcpy(copy,frame,n);
        sx_observation_t o;
        if (sx_parse(copy,n,&o)) { sx_ap_t ap; sx_init(&ap); sx_apply(&ap,&o); }
        free(copy);
    }
    sx_ap_t ap; sx_init(&ap);
    ap.hidden = 1; ap.resolved_len = 32; ap.ssid_source = SX_REASSOC_REQ;
    ap.profile_source = SX_PROBE_RESP; ap.frame_status = SX_VALID;
    ap.rsn.status = ap.wpa.status = SX_VALID;
    ap.rsn.group_present = ap.wpa.group_present = ap.rsn.management_present = true;
    ap.rsn.pairwise_known = ap.rsn.akm_known = ap.wpa.pairwise_known = ap.wpa.akm_known = true;
    ap.rsn.pairwise_count = ap.rsn.akm_count = ap.wpa.pairwise_count = ap.wpa.akm_count = 8;
    ap.wps.status = SX_VALID; ap.wps.present = true; ap.wps.config_methods = 65535;
    sx_text_t *texts[] = {&ap.wps.manufacturer,&ap.wps.model_name,&ap.wps.model_number,&ap.wps.device_name};
    for (unsigned i=0;i<4;++i) { texts[i]->present=true; texts[i]->len=64; memset(texts[i]->bytes,255,64); }
    char out[SX_AP_SUFFIX_BYTES];
    size_t n=sx_format_ap(out,sizeof(out),&ap,ap_mac,-128,true,0,true,UINT32_MAX);
    assert(n && n < SX_AP_SUFFIX_BYTES);
    assert(n + 32 + 15 + 63 + 2 <= SX_AP_LINE_MAX_BYTES);
    printf("max-value fixture suffix: %zu bytes; sx_ap_t: %zu bytes\n",n,sizeof(ap));
}
static void reject_invalid_transmitters(void) {
    for (unsigned i=0;i<2;++i) {
        sx_observation_t o;
        start(i ? 0x20 : 0); ie(0,"Wrong",5);
        frame[10] = 5;
        assert(!sx_parse(frame,frame_len,&o));
        memset(frame+10,0,6); assert(!sx_parse(frame,frame_len,&o));
        memcpy(frame+10,ap_mac,6); assert(!sx_parse(frame,frame_len,&o));
    }
}
static void binary_zero_ssid_is_not_assumed_hidden(void) {
    const uint8_t zero[32]={0};
    const uint8_t subtypes[]={0,0x20,0x50};
    for (unsigned i=0;i<3;++i) {
        sx_ap_t ap; sx_init(&ap); start(subtypes[i]); ie(0,zero,sizeof(zero));
        sx_observation_t o=parse(); sx_apply(&ap,&o);
        assert(ap.resolved_len == 32 && ap.ssid_source != SX_NONE && ap.hidden == -1);
        assert(!memcmp(ap.resolved_ssid,zero,sizeof(zero)));
    }
}
static void examples(bool vendor) {
    const uint8_t wps[] = {0,0x50,0xf2,4,0x10,0x44,0,1,2,0x10,0x08,0,2,0,0x80};
    const uint8_t binary_name[] = {'H','o','m','e','|','B','\r','\n',0,0xff};
    const char *v = vendor ? " [Fixture Vendor]" : "";
    for (unsigned i=0;i<3;++i) {
        sx_ap_t ap; sx_init(&ap); sx_observation_t o;
        uint8_t bssid[6] = {2,0,0,0,0,(uint8_t)(i+1)};
        if (i != 2) {
            start(0x80); memcpy(frame+10,bssid,6); memcpy(frame+16,bssid,6); ie(0,"",0);
            if (i == 0) frame[34] = 0x10;
            if (i == 0) ie(48,rsn,sizeof(rsn)); else ie(221,wps,sizeof(wps));
            o=parse(); sx_apply(&ap,&o);
        }
        start(i == 1 ? 0x20 : 0);
        memcpy(frame+4,bssid,6); memcpy(frame+16,bssid,6);
        if (i == 1) ie(0,binary_name,sizeof(binary_name)); else ie(0,i ? "HomeC" : "HomeA",5);
        o=parse(); sx_apply(&ap,&o);
        char out[SX_AP_SUFFIX_BYTES];
        assert(sx_format_ap(out,sizeof(out),&ap,bssid,-55,i != 2,0,true,1200));
        printf(", CH%u: 1%s%s\n",i == 0 ? 1U : i == 1 ? 6U : 11U,v,out);
        assert(sx_format_client(out,sizeof(out),-65,true,100,1200));
        printf(" 04:00:00:00:00:%02X%s%s\n",i+1,v,out);
    }
}
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1],"--examples")) { examples(argc > 2); return 0; }
    binary_zero_ssid_is_not_assumed_hidden();
    reject_invalid_transmitters();
    hidden_and_discovery(); security_profiles(); wps_attributes(); truncation_and_format();
    bounded_lists_and_optional_fields(); wps_fragmentation_and_limits(); fuzz_and_maximum_line();
    puts("sniffer extended parser fixtures: PASS");
}
