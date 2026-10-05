// Frozen pre-extension JanOS command bodies, 2026-10-05.
static int cmd_show_sniffer_results(int argc, char **argv) {
    (void)argc; (void)argv;
    
    // Allow showing results even after sniffer is stopped
    if (sniffer_active && sniffer_scan_phase) {
        MY_LOG_INFO(TAG, "Sniffer is still scanning networks. Please wait...");
        return 0;
    }
    
    if (sniffer_ap_count == 0) {
        MY_LOG_INFO(TAG, "No sniffer data available. Use 'start_sniffer' to collect data.");
        return 0;
    }
    
    // Create a sorted array of AP indices by client count (descending)
    int sorted_indices[MAX_SNIFFER_APS];
    for (int i = 0; i < sniffer_ap_count; i++) {
        sorted_indices[i] = i;
    }
    
    // Simple bubble sort by client count (descending)
    for (int i = 0; i < sniffer_ap_count - 1; i++) {
        for (int j = 0; j < sniffer_ap_count - i - 1; j++) {
            if (sniffer_aps[sorted_indices[j]].client_count < sniffer_aps[sorted_indices[j + 1]].client_count) {
                int temp = sorted_indices[j];
                sorted_indices[j] = sorted_indices[j + 1];
                sorted_indices[j + 1] = temp;
            }
        }
    }
    
    // Compact format for Flipper Zero display
    int displayed_count = 0;
    for (int i = 0; i < sniffer_ap_count; i++) {
        int idx = sorted_indices[i];
        sniffer_ap_t *ap = &sniffer_aps[idx];
        
        // Skip broadcast BSSID and our own device
        if (is_broadcast_bssid(ap->bssid) || is_own_device_mac(ap->bssid)) {
            continue;
        }
        
        // Skip APs with no clients
        if (ap->client_count == 0) {
            continue;
        }
        
        displayed_count++;
        
        // Print AP info in compact format: SSID, CH: CLIENT_COUNT
        printf("%s, CH%d: %d\n", ap->ssid, ap->channel, ap->client_count);
        
        // Print each client MAC on a separate line with 1 space indentation
        if (ap->client_count > 0) {
            for (int j = 0; j < ap->client_count; j++) {
                sniffer_client_t *client = &ap->clients[j];
                printf(" %02X:%02X:%02X:%02X:%02X:%02X\n",
                       client->mac[0], client->mac[1], client->mac[2],
                       client->mac[3], client->mac[4], client->mac[5]);
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(20)); // Small delay to avoid overwhelming UART
    }
    
    if (displayed_count == 0) {
        MY_LOG_INFO(TAG, "No APs with clients found.");
    }
    
    return 0;
}
static int cmd_show_sniffer_results_vendor(int argc, char **argv) {
    (void)argc; (void)argv;
    
    // Allow showing results even after sniffer is stopped
    if (sniffer_active && sniffer_scan_phase) {
        MY_LOG_INFO(TAG, "Sniffer is still scanning networks. Please wait...");
        return 0;
    }
    
    if (sniffer_ap_count == 0) {
        MY_LOG_INFO(TAG, "No sniffer data available. Use 'start_sniffer' to collect data.");
        return 0;
    }
    
    // Create a sorted array of AP indices by client count (descending)
    int sorted_indices[MAX_SNIFFER_APS];
    for (int i = 0; i < sniffer_ap_count; i++) {
        sorted_indices[i] = i;
    }
    
    // Simple bubble sort by client count (descending)
    for (int i = 0; i < sniffer_ap_count - 1; i++) {
        for (int j = 0; j < sniffer_ap_count - i - 1; j++) {
            if (sniffer_aps[sorted_indices[j]].client_count < sniffer_aps[sorted_indices[j + 1]].client_count) {
                int temp = sorted_indices[j];
                sorted_indices[j] = sorted_indices[j + 1];
                sorted_indices[j + 1] = temp;
            }
        }
    }
    
    // Compact format for Flipper Zero display with vendor info
    int displayed_count = 0;
    for (int i = 0; i < sniffer_ap_count; i++) {
        int idx = sorted_indices[i];
        sniffer_ap_t *ap = &sniffer_aps[idx];
        
        // Skip broadcast BSSID and our own device
        if (is_broadcast_bssid(ap->bssid) || is_own_device_mac(ap->bssid)) {
            continue;
        }
        
        // Skip APs with no clients
        if (ap->client_count == 0) {
            continue;
        }
        
        displayed_count++;
        
        // Print AP info in compact format: SSID, CH: CLIENT_COUNT [Vendor]
        const char *ap_vendor = vendor_label(ap->bssid);
        printf("%s, CH%d: %d [%s]\n", ap->ssid, ap->channel, ap->client_count,
               ap_vendor);
        
        // Print each client MAC on a separate line with 1 space indentation and vendor
        if (ap->client_count > 0) {
            for (int j = 0; j < ap->client_count; j++) {
                sniffer_client_t *client = &ap->clients[j];
                const char *client_vendor = vendor_label(client->mac);
                printf(" %02X:%02X:%02X:%02X:%02X:%02X [%s]\n",
                       client->mac[0], client->mac[1], client->mac[2],
                       client->mac[3], client->mac[4], client->mac[5],
                       client_vendor);
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(20)); // Small delay to avoid overwhelming UART
    }
    
    if (displayed_count == 0) {
        MY_LOG_INFO(TAG, "No APs with clients found.");
    }
    
    return 0;
}
