/* Differential replay: primary legacy records must agree after every packet. */
static void report(unsigned step) {
    printf("step=%u aps=%d hops=%u\n",step,sniffer_ap_count,channel_hops);
    for (int i=0;i<sniffer_ap_count;++i) {
        sniffer_ap_t *a=&sniffer_aps[i];
        printf("ap=%02X ssid=%s ch=%u rssi=%d seen=%u clients=%d\n",
               a->bssid[5],a->ssid,a->channel,a->rssi,a->last_seen,a->client_count);
        for (int j=0;j<a->client_count;++j)
            printf("client=%02X rssi=%d seen=%u\n",a->clients[j].mac[5],a->clients[j].rssi,a->clients[j].last_seen);
    }
    for (int i=0;i<probe_request_count;++i)
        printf("probe=%02X ssid=%s rssi=%d seen=%u\n",probe_requests[i].mac[5],
               probe_requests[i].ssid,probe_requests[i].rssi,probe_requests[i].last_seen);
}
int main(void) {
    sniffer_active=true; sniffer_selected_mode=true;
    g_scan_count=1; g_selected_count=1; g_selected_indices[0]=0;
    const uint8_t first[6]={2,0,0,0,0,1}, retained[6]={2,0,0,0,0,2};
    memcpy(g_scan_results[0].bssid,first,6);
    sniffer_ap_count=2;
    memcpy(sniffer_aps[0].bssid,first,6); memcpy(sniffer_aps[1].bssid,retained,6);
    strcpy(sniffer_aps[0].ssid,"First"); strcpy(sniffer_aps[1].ssid,"Retained");
    sx_init(&sniffer_aps[0].extended); sx_init(&sniffer_aps[1].extended);
    for (unsigned step=0;step<14;++step) {
        uint8_t bytes[sizeof(wifi_promiscuous_pkt_t)+64]={0};
        wifi_promiscuous_pkt_t *pkt=(void*)bytes; uint8_t *f=pkt->payload;
        const uint8_t *bssid=step%2 ? retained : first;
        f[0]=8; f[1]=step%3 ? 0x41 : 0x42;
        uint8_t client[6]={4,0,0,0,0,(uint8_t)(10+step%4)};
        memcpy(f+4,(f[1]&1) ? bssid : client,6);
        memcpy(f+10,(f[1]&1) ? client : bssid,6);
        memcpy(f+16,bssid,6);
        pkt->rx_ctrl.sig_len=28; pkt->rx_ctrl.dump_len=step%4 ? 24 : 0;
        pkt->rx_ctrl.rssi=-50-(int)step; pkt->rx_ctrl.channel=6;
        sniffer_promiscuous_callback(pkt,WIFI_PKT_DATA);
        report(step);
    }
    sniffer_selected_mode=false;
    uint8_t bytes[sizeof(wifi_promiscuous_pkt_t)+64]={0};
    wifi_promiscuous_pkt_t *pkt=(void*)bytes; uint8_t *f=pkt->payload;
    f[0]=8; f[1]=1; f[4]=2; f[9]=3; f[10]=4; f[15]=42;
    pkt->rx_ctrl.sig_len=28; pkt->rx_ctrl.rssi=-70; pkt->rx_ctrl.channel=6;
    sniffer_promiscuous_callback(pkt,WIFI_PKT_DATA); report(14);
    const uint8_t subtypes[]={0x80,0x40,0,0x20,0xb0};
    for (unsigned step=0;step<5;++step) {
        memset(bytes,0,sizeof(bytes));
        f[0]=subtypes[step]; memcpy(f+4,first,6); memcpy(f+16,first,6);
        uint8_t client[6]={4,0,0,0,0,(uint8_t)(70+step)};
        memcpy(f+10,step == 0 ? first : client,6);
        unsigned offset=step == 0 ? 36 : step == 1 ? 24 : step == 3 ? 34 : 28;
        f[offset]=0; f[offset+1]=4; memcpy(f+offset+2,"Name",4);
        pkt->rx_ctrl.sig_len=offset+10; pkt->rx_ctrl.dump_len=offset+6;
        pkt->rx_ctrl.rx_state=step == 2 ? 1 : 0;
        pkt->rx_ctrl.rssi=-60; pkt->rx_ctrl.channel=6;
        sniffer_promiscuous_callback(pkt,WIFI_PKT_MGMT); report(15+step);
    }
}
