#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CAPTURE_GATEWAY_SSID_MAX_LEN 32
#define CAPTURE_GATEWAY_PASSWORD_MIN_LEN 8
#define CAPTURE_GATEWAY_PASSWORD_MAX_LEN 63
#define CAPTURE_GATEWAY_DEFAULT_MAX_CLIENTS 4

typedef struct {
    const char *ssid;
    const char *password;
    uint8_t channel;
    uint8_t max_clients;
} capture_gateway_config_t;

typedef struct {
    bool active;
    bool upstream_ready;
    bool napt_enabled;
    uint8_t connected_clients;
    uint8_t channel;
    char ssid[CAPTURE_GATEWAY_SSID_MAX_LEN + 1];
    char upstream_ssid[CAPTURE_GATEWAY_SSID_MAX_LEN + 1];
    esp_netif_ip_info_t downstream_ip;
    esp_netif_ip_info_t upstream_ip;
    esp_netif_dns_info_t upstream_dns;
} capture_gateway_status_t;

/**
 * Configure DHCP/DNS/NAPT on already-created AP and STA netifs.
 * Wi-Fi must already be running in APSTA mode and STA must have IPv4.
 */
esp_err_t capture_gateway_start(esp_netif_t *ap_netif,
                                esp_netif_t *sta_netif,
                                const capture_gateway_config_t *config);

/** Disable NAPT and the downstream DHCP server. Does not change Wi-Fi mode. */
esp_err_t capture_gateway_stop(void);

/** Refresh default route and DNS after the STA receives or renews IPv4. */
esp_err_t capture_gateway_refresh_upstream(void);

void capture_gateway_set_upstream_ready(bool ready);
void capture_gateway_client_connected(void);
void capture_gateway_client_disconnected(void);
bool capture_gateway_is_active(void);
void capture_gateway_get_status(capture_gateway_status_t *status);
esp_netif_t *capture_gateway_get_ap_netif(void);

#ifdef __cplusplus
}
#endif
