#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef int esp_err_t;
typedef uint8_t u8;
typedef uint32_t u32;
typedef struct { int nvs_enable; } wifi_init_config_t;
typedef int wifi_mode_t;
typedef int wifi_storage_t;
typedef int wifi_second_chan_t;
typedef union {
    struct { uint8_t ssid[32]; uint8_t password[64]; uint8_t other[96]; } sta;
    uint8_t bytes[192];
} wifi_config_t;
#define WIFI_INIT_CONFIG_DEFAULT() ((wifi_init_config_t){1})
enum {
    ESP_OK = 0, ESP_FAIL = -1, ESP_ERR_NO_MEM = 1, ESP_ERR_INVALID_STATE = 2,
    ESP_ERR_WIFI_NOT_CONNECT = 3, WIFI_IF_STA = 0, WIFI_STORAGE_RAM = 1,
    WIFI_MODE_STA = 1, WIFI_APPIE_WPS_AR = 1, WPS_TYPE_DISABLE = 0,
    WPS_TYPE_PIN = 1, WPS_STATUS_DISABLE = 0, WPS_STATUS_PENDING = 1,
    MALLOC_CAP_INTERNAL = 1, MALLOC_CAP_8BIT = 2, ESP_MAC_WIFI_STA = 0,
    WIFI_STORAGE_FLASH = 0, WIFI_MODE_AP = 2, WIFI_MODE_APSTA = 3,
    WIFI_SECOND_CHAN_NONE = 0, WIFI_SECOND_CHAN_ABOVE = 1,
};
struct wps_scan_ie { int unused; };
struct wps_funcs {
    bool (*wps_parse_scan_result)(struct wps_scan_ie *);
    int (*wifi_station_wps_start)(void);
    int (*wps_sm_rx_eapol)(u8 *, u8 *, u32);
    int (*wps_start_pending)(void);
};
esp_err_t esp_wifi_init(const wifi_init_config_t *config);
esp_err_t esp_wifi_set_storage(int storage);
esp_err_t esp_wifi_set_mode(int mode);
esp_err_t esp_wifi_get_mode(wifi_mode_t *mode);
esp_err_t esp_wifi_get_config(int interface, wifi_config_t *config);
esp_err_t esp_wifi_set_config(int interface, wifi_config_t *config);
esp_err_t esp_wifi_get_channel(uint8_t *primary, wifi_second_chan_t *secondary);
esp_err_t esp_wifi_set_channel(uint8_t primary, wifi_second_chan_t secondary);
void *heap_caps_calloc(size_t count, size_t size, unsigned caps);
void heap_caps_free(void *memory);
esp_err_t esp_wifi_start(void);
esp_err_t esp_wifi_stop(void);
esp_err_t esp_wifi_deinit(void);
esp_err_t esp_wifi_set_mac(int interface, const uint8_t *mac);
esp_err_t esp_wifi_get_mac(int interface, uint8_t *mac);
esp_err_t esp_wifi_set_wps_cb_internal(struct wps_funcs *callbacks);
esp_err_t esp_wifi_set_appie_internal(uint8_t type, uint8_t *ie, uint16_t length, uint8_t flags);
esp_err_t esp_wifi_unset_appie_internal(uint8_t type);
esp_err_t esp_wifi_set_wps_start_flag_internal(bool enabled);
esp_err_t esp_wifi_set_wps_type_internal(uint32_t type);
esp_err_t esp_wifi_set_wps_status_internal(uint32_t status);
esp_err_t esp_wifi_disconnect(void);
esp_err_t esp_event_loop_create_default(void);
esp_err_t esp_read_mac(uint8_t *mac, int type);
void esp_fill_random(void *buffer, size_t size);
size_t heap_caps_get_free_size(unsigned caps);
size_t heap_caps_get_minimum_free_size(unsigned caps);
