/* Linked to extracted production capture functions by test_sniffer_extended.py. */
static uint8_t packet_bytes[sizeof(wifi_promiscuous_pkt_t) + 2048];
static wifi_promiscuous_pkt_t *packet = (void *)packet_bytes;
static const uint8_t a_mac[6] = {2,0,0,0,0,1};
static const uint8_t b_mac[6] = {2,0,0,0,0,2};
static const uint8_t c_mac[6] = {4,0,0,0,0,3};
static void send_mgmt(uint8_t subtype, const uint8_t *bssid, const char *ssid) {
    memset(packet_bytes,0,sizeof(packet_bytes));
    uint8_t *f = packet->payload;
    f[0] = subtype;
    memcpy(f+16,bssid,6);
    bool request = subtype == 0 || subtype == 0x20;
    memcpy(f+4,request ? bssid : c_mac,6);
    memcpy(f+10,request ? c_mac : bssid,6);
    size_t pos = subtype == 0 ? 28 : subtype == 0x20 ? 34 : 36;
    f[pos++] = 0; f[pos++] = (uint8_t)strlen(ssid);
    memcpy(f+pos,ssid,strlen(ssid)); pos += strlen(ssid);
    packet->rx_ctrl.dump_len = (unsigned)pos;
    packet->rx_ctrl.sig_len = (unsigned)(pos+4);
    packet->rx_ctrl.rssi = -55; packet->rx_ctrl.channel = 6;
    sniffer_promiscuous_callback(packet,WIFI_PKT_MGMT);
}
int main(void) {
    sniffer_active = true;
    /* Monster RX metadata: sig_len=604, dump_len=608, rx_state=0. */
    memset(packet_bytes,0,sizeof(packet_bytes));
    packet->payload[0]=8; packet->payload[1]=1;
    memcpy(packet->payload+4,a_mac,6); memcpy(packet->payload+10,c_mac,6);
    memcpy(packet->payload+16,a_mac,6);
    packet->rx_ctrl.sig_len=604; packet->rx_ctrl.dump_len=608;
    packet->rx_ctrl.rssi=-55; packet->rx_ctrl.channel=132;
    sniffer_promiscuous_callback(packet,WIFI_PKT_DATA);
    assert(sniffer_ap_count == 1 && sniffer_aps[0].client_count == 1);
    assert(sniffer_rx_diagnostics.bad_length == 0);
    assert(sniffer_rx_diagnostics.matched == 1);
    assert(sniffer_aps[0].clients[0].rx_rssi_known);
    char *debug_argv[]={"sniffer_debug"};
    cmd_sniffer_debug(1,debug_argv);
    char *show_argv[]={"show_sniffer_results","extended"};
    cmd_show_sniffer_results(2,show_argv);
    sniffer_ap_count=0; memset(storage,0,sizeof(storage));
    memset(&sniffer_rx_diagnostics,0,sizeof(sniffer_rx_diagnostics));
    /* Hidden SSID: distinguish received, rejected, short and untracked requests. */
    sniffer_ap_count=1; memcpy(sniffer_aps[0].bssid,a_mac,6);
    sx_init(&sniffer_aps[0].extended);
    send_mgmt(0x80,a_mac,"");
    send_mgmt(0,a_mac,"HiddenTest");
    assert(sniffer_aps[0].extended.hidden == 1);
    assert(sniffer_aps[0].extended.ssid_source == SX_ASSOC_REQ);
    send_mgmt(0x20,a_mac,"HiddenTest");
    assert(sniffer_aps[0].extended.ssid_source == SX_REASSOC_REQ);
    memcpy(packet->payload+16,b_mac,6); /* Request destination/BSSID disagree. */
    sniffer_promiscuous_callback(packet,WIFI_PKT_MGMT);
    send_mgmt(0,a_mac,"HiddenTest");
    packet->rx_ctrl.sig_len+=20; /* Incomplete dump must not resolve a name. */
    sniffer_promiscuous_callback(packet,WIFI_PKT_MGMT);
    sniffer_selected_mode=true;
    send_mgmt(0,b_mac,"Other"); /* No tracked BSSID in selected mode. */
    sniffer_selected_mode=false;
    send_mgmt(0x80,a_mac,"");
    assert(sniffer_aps[0].extended.hidden == 1 && sniffer_aps[0].extended.resolved_len == 10);
    cmd_sniffer_debug(1,debug_argv);
    cmd_show_sniffer_results(2,show_argv);
    sniffer_ap_count=0; memset(storage,0,sizeof(storage));
    memset(&sniffer_rx_diagnostics,0,sizeof(sniffer_rx_diagnostics));
    /* Positive short captures must bound legacy header/SSID reads as well. */
    for (unsigned n=20;n<=26;n+=6) {
        wifi_promiscuous_pkt_t *short_packet=calloc(1,sizeof(*short_packet)+n); assert(short_packet);
        short_packet->rx_ctrl.sig_len=100; short_packet->rx_ctrl.dump_len=n;
        short_packet->payload[0]=0x40;
        if (n == 26) {
            short_packet->payload[10]=4;
            short_packet->payload[24]=0; short_packet->payload[25]=32;
        }
        sniffer_promiscuous_callback(short_packet,WIFI_PKT_MGMT);
        assert(probe_request_count == 0);
        free(short_packet);
    }
    memset(&sniffer_rx_diagnostics,0,sizeof(sniffer_rx_diagnostics));
    /* Public RX API describes payload with sig_len. dump_len may be unset. */
    send_mgmt(0,a_mac,"ZeroDump");
    sniffer_ap_count = 0; memset(storage,0,sizeof(storage));
    packet->rx_ctrl.dump_len = 0;
    sniffer_promiscuous_callback(packet,WIFI_PKT_MGMT);
    assert(sniffer_ap_count == 1 && sniffer_aps[0].client_count == 1);
    assert(sniffer_aps[0].extended.resolved_len == 8);
    sniffer_ap_count = 0; memset(storage,0,sizeof(storage));
    sniffer_ap_count = 2;
    memcpy(sniffer_aps[0].bssid,a_mac,6); memcpy(sniffer_aps[1].bssid,b_mac,6);
    sx_init(&sniffer_aps[0].extended); sx_init(&sniffer_aps[1].extended);
    strcpy(sniffer_aps[0].ssid,""); strcpy(sniffer_aps[1].ssid,"LegacyB");
    send_mgmt(0x80,a_mac,""); send_mgmt(0,a_mac,"HomeA");
    assert(sniffer_ap_count == 2 && sniffer_aps[0].client_count == 1);
    assert(sniffer_aps[1].client_count == 0 && sniffer_aps[0].extended.hidden == 1);
    assert(sniffer_aps[0].extended.resolved_len == 5 && !strcmp(sniffer_aps[0].ssid,""));
    send_mgmt(0x80,a_mac,"");
    assert(sniffer_aps[0].extended.resolved_len == 5 && sniffer_aps[0].client_count == 1);
    /* A radio dump ending on an IE boundary may still be incomplete. */
    packet->rx_ctrl.sig_len += 30;
    sniffer_promiscuous_callback(packet,WIFI_PKT_MGMT);
    assert(sniffer_aps[0].extended.frame_status == SX_INVALID);
    assert(sniffer_aps[0].extended.rsn.status == SX_INVALID && sniffer_aps[0].extended.wps.status == SX_INVALID);
    assert(sniffer_aps[0].extended.resolved_len == 5);
    send_mgmt(0,b_mac,"HomeB");
    send_mgmt(0x20,b_mac,"HomeB");
    assert(sniffer_aps[1].client_count == 1 && !strcmp(sniffer_aps[1].ssid,"LegacyB"));
    assert(sniffer_aps[1].extended.ssid_source == SX_REASSOC_REQ);
    assert(!sniffer_aps[1].rx_rssi_known); /* Association RSSI belongs to client. */
    send_mgmt(0x50,b_mac,"HomeB"); assert(sniffer_aps[1].rx_rssi_known);
    assert(sniffer_aps[1].rx_seen && sniffer_aps[1].rx_last_seen == 1200);
    char age_suffix[SX_AP_SUFFIX_BYTES];
    sx_format_ap(age_suffix,sizeof(age_suffix),&sniffer_aps[1].extended,b_mac,
                 sniffer_aps[1].rx_rssi,true,sniffer_aps[1].rx_last_seen,true,1200);
    assert(strstr(age_suffix,"age_ms=0") != NULL);
    /* Encrypted DATA still exposes addresses. Downlink RSSI is not client RSSI. */
    memset(packet_bytes,0,sizeof(packet_bytes));
    uint8_t *data = packet->payload;
    data[0] = 8; data[1] = 0x42; /* FromDS and Protected */
    memcpy(data+10,b_mac,6);
    const uint8_t downlink_client[6] = {4,0,0,0,0,8}; memcpy(data+4,downlink_client,6);
    packet->rx_ctrl.dump_len = 24; packet->rx_ctrl.sig_len = 28; packet->rx_ctrl.rssi = -35;
    sniffer_promiscuous_callback(packet,WIFI_PKT_DATA);
    assert(sniffer_aps[1].client_count == 2 && !sniffer_aps[1].clients[1].rx_rssi_known);
    assert(sniffer_aps[1].rx_rssi == -35);
    data[1] = 0x41; memcpy(data+4,b_mac,6); memcpy(data+10,downlink_client,6);
    packet->rx_ctrl.rssi = -70; sniffer_promiscuous_callback(packet,WIFI_PKT_DATA);
    assert(sniffer_aps[1].clients[1].rx_rssi_known && sniffer_aps[1].clients[1].rx_rssi == -70);
    assert(sniffer_aps[1].rx_rssi == -35);
    packet->rx_ctrl.dump_len = 0; packet->rx_ctrl.rssi = -71;
    sniffer_promiscuous_callback(packet,WIFI_PKT_DATA);
    assert(sniffer_aps[1].clients[1].rx_rssi == -71);
    assert(sniffer_rx_diagnostics.zero_dump == 2 && sniffer_rx_diagnostics.short_dump == 1);
    assert(sniffer_rx_diagnostics.last_dump_len == 0 && sniffer_rx_diagnostics.last_sig_len == 28);
    /* RX mutex contention skips packets instead of blocking the radio task. */
    mutex_available = false;
    send_mgmt(0x50,b_mac,"Wrong");
    assert(!memcmp(sniffer_aps[1].extended.resolved_ssid,"HomeB",5));
    mutex_available = true;
    assert(atomic_load(&sniffer_rx_lock_busy) == 1);
    /* Selected mode must not create an unselected BSSID. */
    sniffer_selected_mode = true; g_selected_count = 1; g_selected_indices[0] = 0;
    memcpy(g_scan_results[0].bssid,a_mac,6); g_scan_count = 1;
    const uint8_t other[6] = {2,0,0,0,0,4};
    send_mgmt(0,other,"Other"); assert(sniffer_ap_count == 2);
    send_mgmt(0x50,b_mac,"Unselected");
    /* Prior selected mode retained and continued observing existing records. */
    assert(!memcmp(sniffer_aps[1].extended.resolved_ssid,"Unselected",10));
    sniffer_active = false;
    send_mgmt(0x50,a_mac,"Stopped");
    assert(!memcmp(sniffer_aps[0].extended.resolved_ssid,"HomeA",5));
    /* Restart/scan/selected initialization preserve identity, clients and resolution. */
    g_scan_done = true; g_scan_results[0].primary = 6; g_scan_results[0].rssi = -50;
    sniffer_process_scan_results();
    sniffer_init_selected_networks();
    sniffer_merge_scan_results();
    assert(sniffer_ap_count == 2 && sniffer_aps[0].client_count == 1);
    assert(!memcmp(sniffer_aps[0].extended.resolved_ssid,"HomeA",5));
    sniffer_active = true; send_mgmt(0,a_mac,"HomeA");
    assert(sniffer_ap_count == 2 && sniffer_aps[0].client_count == 1);
    int count; uint32_t now;
    sniffer_ap_t *copy=sniffer_take_snapshot(&count,&now); assert(copy && count == 2);
    send_mgmt(0,a_mac,"Changed");
    assert(copy[0].extended.resolved_len == 5 && !memcmp(copy[0].extended.resolved_ssid,"HomeA",5));
    free(copy);
    cmd_clear_sniffer_results(0,NULL);
    assert(sniffer_ap_count == 0 && probe_request_count == 0 && sniffer_packet_counter == 0);
    assert(sniffer_rx_diagnostics.rx == 0 && atomic_load(&sniffer_rx_lock_busy) == 0);
    sniffer_init_selected_networks();
    assert(sniffer_ap_count == 1 && sniffer_aps[0].client_count == 0);
    assert(sniffer_aps[0].extended.ssid_source == SX_NONE && sniffer_aps[0].extended.hidden == -1);
    sniffer_selected_mode=false;
    send_mgmt(0,b_mac,"New");
    assert(sniffer_ap_count == 2 && sniffer_aps[1].extended.hidden == -1);
    assert(sniffer_aps[1].extended.rsn.status == SX_UNKNOWN && !sniffer_aps[1].rx_rssi_known);
    assert(!strcmp(sniffer_aps[1].ssid,"MGMT_0002"));
    puts("sniffer RX integration fixtures: PASS");
}
