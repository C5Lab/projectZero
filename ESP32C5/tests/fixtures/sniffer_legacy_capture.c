// Frozen pre-extension capture logic from 9bcac915.
static void add_client_to_ap(int ap_index, const uint8_t *client_mac, int rssi) {
    static uint32_t add_client_counter = 0;
    add_client_counter++;
    
    if ((add_client_counter % 10) == 0) {
        //printf("ADD_CLIENT_HEARTBEAT: Call %lu, AP index %d\n", add_client_counter, ap_index);
    }
    
    if (ap_index < 0 || ap_index >= sniffer_ap_count) {
        if (sniff_debug) {
            MY_LOG_INFO(TAG, "[DEBUG] add_client_to_ap: Invalid AP index %d (max: %d)", ap_index, sniffer_ap_count);
        }
        return;
    }
    
    sniffer_ap_t *ap = &sniffer_aps[ap_index];
    
    // Check if client already exists
    for (int i = 0; i < ap->client_count; i++) {
        if (memcmp(ap->clients[i].mac, client_mac, 6) == 0) {
            // Update existing client
            ap->clients[i].rssi = rssi;
            ap->clients[i].last_seen = esp_timer_get_time() / 1000; // ms
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] add_client_to_ap: Updated existing client %02X:%02X:%02X:%02X:%02X:%02X in AP %s (RSSI: %d)", 
                           client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5], 
                           ap->ssid, rssi);
            }
            return;
        }
    }
    
    // Add new client if space available
    if (ap->client_count < MAX_CLIENTS_PER_AP) {
        int index = ap->client_count++;
        memcpy(ap->clients[index].mac, client_mac, 6);
        ap->clients[index].rssi = rssi;
        ap->clients[index].last_seen = esp_timer_get_time() / 1000; // ms
        if (sniff_debug) {
            MY_LOG_INFO(TAG, "[DEBUG] add_client_to_ap: Added NEW client %02X:%02X:%02X:%02X:%02X:%02X to AP %s (RSSI: %d, total clients: %d)", 
                       client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5], 
                       ap->ssid, rssi, ap->client_count);
        }
    } else {
        if (sniff_debug) {
            MY_LOG_INFO(TAG, "[DEBUG] add_client_to_ap: Cannot add client - AP %s is full (%d/%d clients)", 
                       ap->ssid, ap->client_count, MAX_CLIENTS_PER_AP);
        }
    }
}
static void sniffer_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    sniffer_packet_counter++;
    sniff_oled_packets = sniffer_packet_counter;
    sniff_oled_dirty = true;
    
    if (!sniffer_active || sniffer_scan_phase) {
        return; // No debug logging here - too frequent
    }
    
    // Show packet count every 20 packets when debug is OFF
    if (!sniff_debug && (sniffer_packet_counter % 20) == 0) {
        printf("Sniffer packet count: %lu\n", sniffer_packet_counter);
    }
    
    // Perform packet-based channel hopping (10 packets OR time-based task will handle it)
    if ((sniffer_packet_counter % 10) == 0) {
        //MY_LOG_INFO(TAG, "Sniffer: Packet-based channel hop (10 packets)");
        sniffer_channel_hop();
    }
    
    // Throttle debug logging - only every 100th packet when debug is on
    bool should_debug = sniff_debug && ((sniffer_packet_counter - sniffer_last_debug_packet) >= 100);
    if (should_debug) {
        sniffer_last_debug_packet = sniffer_packet_counter;
        printf("DEBUG_CHECKPOINT: Processing packet %lu\n", sniffer_packet_counter);
    }
    
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    
    if (should_debug) {
        const char* type_str = (type == WIFI_PKT_MGMT) ? "MGMT" : 
                              (type == WIFI_PKT_DATA) ? "DATA" : 
                              (type == WIFI_PKT_CTRL) ? "CTRL" : "UNKNOWN";
        
        MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Type=%s, Len=%d, Ch=%d, RSSI=%d", 
                   sniffer_packet_counter, type_str, len, sniffer_current_channel, pkt->rx_ctrl.rssi);
        
        if (len >= 24) {
            MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Addr1=%02X:%02X:%02X:%02X:%02X:%02X, Addr2=%02X:%02X:%02X:%02X:%02X:%02X, Addr3=%02X:%02X:%02X:%02X:%02X:%02X",
                       sniffer_packet_counter,
                       frame[4], frame[5], frame[6], frame[7], frame[8], frame[9],
                       frame[10], frame[11], frame[12], frame[13], frame[14], frame[15],
                       frame[16], frame[17], frame[18], frame[19], frame[20], frame[21]);
        }
    }
    
    // Filter only MGMT and DATA packets (like Marauder)
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) {
        // Skip logging for non-MGMT/DATA packets - too frequent
        return;
    }
    
    if (len < 24) { // Minimum 802.11 header size
        return; // Skip logging - too frequent
    }
    
    // Skip broadcast packets ONLY for DATA packets
    // MGMT packets (beacons, probe requests) normally have broadcast destinations
    bool is_broadcast_dest = (frame[4] == 0xff && frame[5] == 0xff && frame[6] == 0xff &&
                             frame[7] == 0xff && frame[8] == 0xff && frame[9] == 0xff);
    
    if (is_broadcast_dest && type == WIFI_PKT_DATA) {
        return; // Skip logging - too frequent
    }
    
    // Parse 802.11 header (like Marauder)
    uint8_t frame_type = frame[0] & 0xFC;
    uint8_t to_ds = (frame[1] & 0x01) != 0;
    uint8_t from_ds = (frame[1] & 0x02) != 0;
    
    // Extract addresses based on 802.11 standard
    uint8_t *addr1 = (uint8_t *)&frame[4];   // Address 1
    uint8_t *addr2 = (uint8_t *)&frame[10];  // Address 2  
    uint8_t *addr3 = (uint8_t *)&frame[16];  // Address 3
    
    if (sniff_debug) {
        // Minimal debug logging to avoid blocking
        printf("PKT_%lu: %s T=%d F=%d\n", sniffer_packet_counter, 
               (type == WIFI_PKT_MGMT) ? "MGMT" : "DATA", to_ds, from_ds);
    }
    
    // Process MGMT packets for client detection (like Marauder)
    if (type == WIFI_PKT_MGMT) {
        if (should_debug) printf("DEBUG: Processing MGMT packet %lu\n", sniffer_packet_counter);
        
        uint8_t *client_mac = NULL;
        uint8_t *ap_mac = NULL;
        bool is_client_frame = false;
        
        switch (frame_type) {
            case 0x80: // Beacon - update AP info only
                ap_mac = addr2; // Source is AP
                if (sniff_debug) {
                    MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Beacon from AP: %02X:%02X:%02X:%02X:%02X:%02X", 
                               sniffer_packet_counter, ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
                }
                // Update AP info if exists
                for (int i = 0; i < sniffer_ap_count; i++) {
                    if (memcmp(sniffer_aps[i].bssid, ap_mac, 6) == 0) {
                        sniffer_aps[i].last_seen = esp_timer_get_time() / 1000;
                        sniffer_aps[i].rssi = pkt->rx_ctrl.rssi;
                        break;
                    }
                }
                return; // Don't process beacons for client detection
                
            case 0x40: // Probe Request - client looking for networks
                client_mac = addr2; // Source is client
                is_client_frame = true;
                if (sniff_debug) {
                    MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Probe Request from client: %02X:%02X:%02X:%02X:%02X:%02X", 
                               sniffer_packet_counter, client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
                }
                break;
                
            case 0x00: // Association Request - client trying to connect to AP
                client_mac = addr2; // Source is client
                ap_mac = addr1;     // Destination is AP
                is_client_frame = true;
                if (sniff_debug) {
                    MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Association Request from client %02X:%02X:%02X:%02X:%02X:%02X to AP %02X:%02X:%02X:%02X:%02X:%02X", 
                               sniffer_packet_counter, client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
                               ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
                }
                break;
                
            case 0xB0: // Authentication - client authenticating with AP
                client_mac = addr2; // Source is client
                ap_mac = addr1;     // Destination is AP
                is_client_frame = true;
                if (sniff_debug) {
                    MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Authentication from client %02X:%02X:%02X:%02X:%02X:%02X to AP %02X:%02X:%02X:%02X:%02X:%02X", 
                               sniffer_packet_counter, client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
                               ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
                }
                break;
                
            default:
                if (sniff_debug) {
                    MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - Other MGMT frame type 0x%02X", sniffer_packet_counter, frame_type);
                }
                return;
        }
        
        // Process client frames
        if (is_client_frame && client_mac) {
            // Skip multicast/broadcast client MAC
            if (is_multicast_mac(client_mac) || is_own_device_mac(client_mac)) {
                if (sniff_debug) {
                    MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - multicast or own device MAC", sniffer_packet_counter);
                }
                return;
            }
            
            // For probe requests, extract SSID and store
            if (frame_type == 0x40) {
                // Parse probe request to extract SSID
                // Probe request format: MAC header (24 bytes) + Frame body
                // Frame body starts with fixed parameters, then tagged parameters
                // SSID is usually the first tagged parameter (Tag Number = 0)
                
                if (len > 24 && probe_request_count < MAX_PROBE_REQUESTS) {
                    const uint8_t *body = frame + 24; // Skip MAC header
                    int body_len = len - 24;
                    
                    char ssid[33] = {0};
                    bool ssid_found = false;
                    uint8_t ssid_length = 0;
                    
                    // Parse tagged parameters to find SSID (tag 0)
                    int offset = 0;
                    while (offset + 2 <= body_len) {
                        uint8_t tag_number = body[offset];
                        uint8_t tag_length = body[offset + 1];
                        
                        if (offset + 2 + tag_length > body_len) {
                            break; // Invalid tag
                        }
                        
                        if (tag_number == 0) { // SSID tag
                            ssid_length = tag_length;
                            if (tag_length > 0 && tag_length <= 32) {
                                memcpy(ssid, &body[offset + 2], tag_length);
                                ssid[tag_length] = '\0';
                                ssid_found = true;
                            } else if (tag_length == 0) {
                                strcpy(ssid, "<Broadcast>");
                                ssid_found = true;
                            }
                            break;
                        }
                        
                        offset += 2 + tag_length;
                    }
                    
                    // Store probe request if SSID found and not broadcast probe
                    if (ssid_found && ssid_length > 0) {
                        // Check if this MAC+SSID combination already exists
                        bool already_exists = false;
                        for (int i = 0; i < probe_request_count; i++) {
                            if (memcmp(probe_requests[i].mac, client_mac, 6) == 0 &&
                                strcmp(probe_requests[i].ssid, ssid) == 0) {
                                // Update existing entry
                                probe_requests[i].last_seen = esp_timer_get_time() / 1000;
                                probe_requests[i].rssi = pkt->rx_ctrl.rssi;
                                already_exists = true;
                                break;
                            }
                        }
                        
                        // Add new probe request if not exists
                        if (!already_exists) {
                            memcpy(probe_requests[probe_request_count].mac, client_mac, 6);
                            strncpy(probe_requests[probe_request_count].ssid, ssid, sizeof(probe_requests[probe_request_count].ssid) - 1);
                            probe_requests[probe_request_count].rssi = pkt->rx_ctrl.rssi;
                            probe_requests[probe_request_count].last_seen = esp_timer_get_time() / 1000;
                            probe_request_count++;
                            
                            if (sniff_debug) {
                                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Stored probe request for SSID '%s' from %02X:%02X:%02X:%02X:%02X:%02X", 
                                           sniffer_packet_counter, ssid,
                                           client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
                            }
                        }
                    }
                }
                return; // Don't process probe requests for AP client association
            }
            
            // For association/auth requests, find or create the target AP
            if (ap_mac) {
                int ap_index = -1;
                for (int i = 0; i < sniffer_ap_count; i++) {
                    if (memcmp(sniffer_aps[i].bssid, ap_mac, 6) == 0) {
                        ap_index = i;
                        break;
                    }
                }
                
                // If AP not found, create it dynamically (only in normal mode)
                // In selected mode, only monitor pre-selected networks
                if (ap_index < 0 && !sniffer_selected_mode && sniffer_ap_count < MAX_SNIFFER_APS) {
                    ap_index = sniffer_ap_count++;
                    memcpy(sniffer_aps[ap_index].bssid, ap_mac, 6);
                    snprintf(sniffer_aps[ap_index].ssid, sizeof(sniffer_aps[ap_index].ssid), 
                            "MGMT_%02X%02X", ap_mac[4], ap_mac[5]);
                    sniffer_aps[ap_index].channel = sniffer_current_channel;
                    sniffer_aps[ap_index].authmode = WIFI_AUTH_OPEN;
                    sniffer_aps[ap_index].rssi = pkt->rx_ctrl.rssi;
                    sniffer_aps[ap_index].client_count = 0;
                    sniffer_aps[ap_index].last_seen = esp_timer_get_time() / 1000;
                    
                    if (sniff_debug) {
                        MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: CREATED new AP %s from MGMT frame", 
                                   sniffer_packet_counter, sniffer_aps[ap_index].ssid);
                    }
                }
                
                if (ap_index >= 0) {
                    if (sniff_debug) {
                        MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: ACCEPTED - Adding client %02X:%02X:%02X:%02X:%02X:%02X to AP %s", 
                                   sniffer_packet_counter, client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
                                   sniffer_aps[ap_index].ssid);
                    }
                    add_client_to_ap(ap_index, client_mac, pkt->rx_ctrl.rssi);
                } else {
                    if (sniff_debug) {
                        MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - AP list full, cannot create new AP", sniffer_packet_counter);
                    }
                }
            }
        }
        return;
    }
    
    // Process DATA packets using 802.11 ToDS/FromDS logic (like Marauder)
    if (type == WIFI_PKT_DATA) {
        if (should_debug) printf("DEBUG: Processing DATA packet %lu\n", sniffer_packet_counter);
        
        uint8_t *client_mac = NULL;
        uint8_t *ap_mac = NULL;
        
        if (sniff_debug) {
            MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Processing DATA packet, ToDS=%d, FromDS=%d", 
                       sniffer_packet_counter, to_ds, from_ds);
        }
        
        // Determine AP and client MAC based on ToDS/FromDS bits (802.11 standard)
        if (to_ds && !from_ds) {
            // STA -> AP: addr1=AP, addr2=STA, addr3=DA
            ap_mac = addr1;      // Destination is AP
            client_mac = addr2;  // Source is client
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: STA->AP direction", sniffer_packet_counter);
            }
        } else if (!to_ds && from_ds) {
            // AP -> STA: addr1=STA, addr2=AP, addr3=SA  
            ap_mac = addr2;      // Source is AP
            client_mac = addr1;  // Destination is client
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: AP->STA direction", sniffer_packet_counter);
            }
        } else if (!to_ds && !from_ds) {
            // IBSS (ad-hoc): addr1=DA, addr2=SA, addr3=BSSID
            ap_mac = addr3;      // BSSID
            client_mac = addr2;  // Source
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: IBSS direction", sniffer_packet_counter);
            }
        } else {
            // WDS (to_ds && from_ds) - skip for now
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - WDS frame (ToDS=1, FromDS=1)", sniffer_packet_counter);
            }
            return;
        }
        
        if (sniff_debug) {
            MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: AP MAC: %02X:%02X:%02X:%02X:%02X:%02X, Client MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
                       sniffer_packet_counter, 
                       ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5],
                       client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
        }
        
        // Skip multicast/broadcast client MAC
        if (is_multicast_mac(client_mac)) {
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - client is multicast/broadcast", sniffer_packet_counter);
            }
            return;
        }
        
        // Skip our own device as client
        if (is_own_device_mac(client_mac)) {
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - client is our own device", sniffer_packet_counter);
            }
            return;
        }
        
        // Find the AP in our known list
        int ap_index = -1;
        if (should_debug) printf("DEBUG: Searching %d APs for match\n", sniffer_ap_count);
        
        for (int i = 0; i < sniffer_ap_count; i++) {
            if (memcmp(sniffer_aps[i].bssid, ap_mac, 6) == 0) {
                ap_index = i;
                if (should_debug) printf("DEBUG: Found AP match at index %d\n", i);
                break;
            }
        }
        
        // If AP not found, try to add it dynamically (only in normal mode)
        // In selected mode, only monitor pre-selected networks
        if (ap_index < 0 && !sniffer_selected_mode && sniffer_ap_count < MAX_SNIFFER_APS) {
            ap_index = sniffer_ap_count++;
            memcpy(sniffer_aps[ap_index].bssid, ap_mac, 6);
            snprintf(sniffer_aps[ap_index].ssid, sizeof(sniffer_aps[ap_index].ssid), 
                    "Unknown_%02X%02X", ap_mac[4], ap_mac[5]); // Use last 2 bytes for unique name
            sniffer_aps[ap_index].channel = sniffer_current_channel;
            sniffer_aps[ap_index].authmode = WIFI_AUTH_OPEN; // Unknown
            sniffer_aps[ap_index].rssi = pkt->rx_ctrl.rssi;
            sniffer_aps[ap_index].client_count = 0;
            sniffer_aps[ap_index].last_seen = esp_timer_get_time() / 1000;
            
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: CREATED new AP %s for BSSID %02X:%02X:%02X:%02X:%02X:%02X", 
                           sniffer_packet_counter, sniffer_aps[ap_index].ssid,
                           ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
            }
        }
        
        if (ap_index >= 0) {
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: ACCEPTED - Adding client %02X:%02X:%02X:%02X:%02X:%02X to AP %s", 
                           sniffer_packet_counter, client_mac[0], client_mac[1], client_mac[2], 
                           client_mac[3], client_mac[4], client_mac[5], sniffer_aps[ap_index].ssid);
            }
            add_client_to_ap(ap_index, client_mac, pkt->rx_ctrl.rssi);
        } else {
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - AP list full (%d/%d), cannot add new AP %02X:%02X:%02X:%02X:%02X:%02X", 
                           sniffer_packet_counter, sniffer_ap_count, MAX_SNIFFER_APS,
                           ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
            }
        }
    }
}
