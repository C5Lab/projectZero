#include "capture_gateway.h"

#include <string.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "lwip/ip4_addr.h"

#define CAPTURE_GATEWAY_DHCPS_OFFER_DNS 0x02

static const char *TAG = "capture_gateway";

static esp_netif_t *s_ap_netif;
static esp_netif_t *s_sta_netif;
static bool s_active;
static bool s_upstream_ready;
static bool s_napt_enabled;
static uint8_t s_connected_clients;
static uint8_t s_channel;
static char s_ssid[CAPTURE_GATEWAY_SSID_MAX_LEN + 1];
static char s_upstream_ssid[CAPTURE_GATEWAY_SSID_MAX_LEN + 1];
static esp_netif_ip_info_t s_downstream_ip;
static esp_netif_ip_info_t s_upstream_ip;
static esp_netif_dns_info_t s_upstream_dns;

static bool capture_gateway_valid_config(const capture_gateway_config_t *config)
{
    if (config == NULL || config->ssid == NULL || config->password == NULL) {
        return false;
    }

    size_t ssid_len = strlen(config->ssid);
    size_t password_len = strlen(config->password);
    return ssid_len >= 1 && ssid_len <= CAPTURE_GATEWAY_SSID_MAX_LEN &&
           password_len >= CAPTURE_GATEWAY_PASSWORD_MIN_LEN &&
           password_len <= CAPTURE_GATEWAY_PASSWORD_MAX_LEN;
}

static esp_err_t capture_gateway_stop_dhcp(esp_netif_t *ap_netif)
{
    esp_err_t err = esp_netif_dhcps_stop(ap_netif);
    if (err == ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED) {
        return ESP_OK;
    }
    return err;
}

static esp_err_t capture_gateway_start_dhcp(esp_netif_t *ap_netif)
{
    esp_err_t err = esp_netif_dhcps_start(ap_netif);
    if (err == ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED) {
        return ESP_OK;
    }
    return err;
}

static esp_err_t capture_gateway_apply_upstream(void)
{
    if (s_sta_netif == NULL || s_ap_netif == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_netif_ip_info_t sta_ip = {0};
    esp_err_t err = esp_netif_get_ip_info(s_sta_netif, &sta_ip);
    if (err != ESP_OK || sta_ip.ip.addr == 0) {
        s_upstream_ready = false;
        memset(&s_upstream_ip, 0, sizeof(s_upstream_ip));
        return err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
    }

    esp_netif_dns_info_t dns = {0};
    err = esp_netif_get_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &dns);
    if (err != ESP_OK) {
        return err;
    }

    if ((dns.ip.type != ESP_IPADDR_TYPE_V4 || dns.ip.u_addr.ip4.addr == 0) &&
        sta_ip.gw.addr != 0) {
        dns.ip.type = ESP_IPADDR_TYPE_V4;
        dns.ip.u_addr.ip4 = sta_ip.gw;
        ESP_LOGW(TAG, "Upstream DNS missing; advertising upstream gateway as DNS fallback");
    }

    err = esp_netif_set_default_netif(s_sta_netif);
    if (err != ESP_OK) {
        return err;
    }

    err = esp_netif_set_dns_info(s_ap_netif, ESP_NETIF_DNS_MAIN, &dns);
    if (err != ESP_OK) {
        return err;
    }

    s_upstream_ip = sta_ip;
    s_upstream_dns = dns;
    s_upstream_ready = true;
    return ESP_OK;
}

esp_err_t capture_gateway_start(esp_netif_t *ap_netif,
                                esp_netif_t *sta_netif,
                                const capture_gateway_config_t *config)
{
    if (s_active) {
        return ESP_ERR_INVALID_STATE;
    }
    if (ap_netif == NULL || sta_netif == NULL || !capture_gateway_valid_config(config)) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_netif_ip_info_t sta_ip = {0};
    esp_err_t err = esp_netif_get_ip_info(sta_netif, &sta_ip);
    if (err != ESP_OK || sta_ip.ip.addr == 0) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_ip4_addr_t downstream_addr = {0};
    IP4_ADDR(&downstream_addr, 10, 42, 0, 1);
    if ((sta_ip.ip.addr & sta_ip.netmask.addr) ==
        (downstream_addr.addr & sta_ip.netmask.addr)) {
        ESP_LOGE(TAG, "Upstream subnet overlaps fixed downstream 10.42.0.0/24");
        return ESP_ERR_INVALID_STATE;
    }

    wifi_ap_record_t upstream = {0};
    if (esp_wifi_sta_get_ap_info(&upstream) != ESP_OK) {
        return ESP_ERR_INVALID_STATE;
    }

    wifi_config_t ap_config = {0};
    size_t ssid_len = strlen(config->ssid);
    memcpy(ap_config.ap.ssid, config->ssid, ssid_len);
    ap_config.ap.ssid_len = ssid_len;
    strlcpy((char *)ap_config.ap.password, config->password,
            sizeof(ap_config.ap.password));
    ap_config.ap.channel = config->channel != 0 ? config->channel : upstream.primary;
    ap_config.ap.max_connection = config->max_clients != 0
                                      ? config->max_clients
                                      : CAPTURE_GATEWAY_DEFAULT_MAX_CLIENTS;
    ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ap_config.ap.pmf_cfg.capable = true;
    ap_config.ap.pmf_cfg.required = false;

    err = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    if (err != ESP_OK) {
        return err;
    }

    err = capture_gateway_stop_dhcp(ap_netif);
    if (err != ESP_OK) {
        return err;
    }

    esp_netif_ip_info_t ap_ip = {0};
    IP4_ADDR(&ap_ip.ip, 10, 42, 0, 1);
    IP4_ADDR(&ap_ip.gw, 10, 42, 0, 1);
    IP4_ADDR(&ap_ip.netmask, 255, 255, 255, 0);
    err = esp_netif_set_ip_info(ap_netif, &ap_ip);
    if (err != ESP_OK) {
        return err;
    }

    uint8_t offer_dns = CAPTURE_GATEWAY_DHCPS_OFFER_DNS;
    err = esp_netif_dhcps_option(ap_netif, ESP_NETIF_OP_SET,
                                 ESP_NETIF_DOMAIN_NAME_SERVER,
                                 &offer_dns, sizeof(offer_dns));
    if (err != ESP_OK) {
        return err;
    }

    s_ap_netif = ap_netif;
    s_sta_netif = sta_netif;
    s_downstream_ip = ap_ip;
    s_channel = ap_config.ap.channel;
    strlcpy(s_ssid, config->ssid, sizeof(s_ssid));
    strlcpy(s_upstream_ssid, (const char *)upstream.ssid, sizeof(s_upstream_ssid));

    err = capture_gateway_apply_upstream();
    if (err != ESP_OK) {
        goto fail;
    }

    err = capture_gateway_start_dhcp(ap_netif);
    if (err != ESP_OK) {
        goto fail;
    }

    err = esp_netif_napt_enable(ap_netif);
    if (err != ESP_OK) {
        capture_gateway_stop_dhcp(ap_netif);
        goto fail;
    }

    s_napt_enabled = true;
    s_connected_clients = 0;
    s_active = true;
    ESP_LOGI(TAG, "Capture gateway active: SSID='%s' channel=%u AP=" IPSTR,
             s_ssid, s_channel, IP2STR(&s_downstream_ip.ip));
    return ESP_OK;

fail:
    s_ap_netif = NULL;
    s_sta_netif = NULL;
    s_active = false;
    s_upstream_ready = false;
    s_napt_enabled = false;
    s_connected_clients = 0;
    memset(s_ssid, 0, sizeof(s_ssid));
    memset(s_upstream_ssid, 0, sizeof(s_upstream_ssid));
    memset(&s_downstream_ip, 0, sizeof(s_downstream_ip));
    memset(&s_upstream_ip, 0, sizeof(s_upstream_ip));
    memset(&s_upstream_dns, 0, sizeof(s_upstream_dns));
    return err;
}

esp_err_t capture_gateway_stop(void)
{
    esp_err_t first_error = ESP_OK;

    if (s_napt_enabled && s_ap_netif != NULL) {
        esp_err_t err = esp_netif_napt_disable(s_ap_netif);
        if (err != ESP_OK && first_error == ESP_OK) {
            first_error = err;
        }
    }

    if (s_ap_netif != NULL) {
        esp_err_t err = capture_gateway_stop_dhcp(s_ap_netif);
        if (err != ESP_OK && first_error == ESP_OK) {
            first_error = err;
        }
    }

    s_ap_netif = NULL;
    s_sta_netif = NULL;
    s_active = false;
    s_upstream_ready = false;
    s_napt_enabled = false;
    s_connected_clients = 0;
    s_channel = 0;
    memset(s_ssid, 0, sizeof(s_ssid));
    memset(s_upstream_ssid, 0, sizeof(s_upstream_ssid));
    memset(&s_downstream_ip, 0, sizeof(s_downstream_ip));
    memset(&s_upstream_ip, 0, sizeof(s_upstream_ip));
    memset(&s_upstream_dns, 0, sizeof(s_upstream_dns));
    return first_error;
}

esp_err_t capture_gateway_refresh_upstream(void)
{
    if (!s_active) {
        return ESP_ERR_INVALID_STATE;
    }
    return capture_gateway_apply_upstream();
}

void capture_gateway_set_upstream_ready(bool ready)
{
    s_upstream_ready = ready;
    if (!ready) {
        memset(&s_upstream_ip, 0, sizeof(s_upstream_ip));
    }
}

void capture_gateway_client_connected(void)
{
    if (s_active && s_connected_clients < UINT8_MAX) {
        s_connected_clients++;
    }
}

void capture_gateway_client_disconnected(void)
{
    if (s_active && s_connected_clients > 0) {
        s_connected_clients--;
    }
}

bool capture_gateway_is_active(void)
{
    return s_active;
}

void capture_gateway_get_status(capture_gateway_status_t *status)
{
    if (status == NULL) {
        return;
    }

    memset(status, 0, sizeof(*status));
    status->active = s_active;
    status->upstream_ready = s_upstream_ready;
    status->napt_enabled = s_napt_enabled;
    status->connected_clients = s_connected_clients;
    status->channel = s_channel;
    strlcpy(status->ssid, s_ssid, sizeof(status->ssid));
    strlcpy(status->upstream_ssid, s_upstream_ssid, sizeof(status->upstream_ssid));
    status->downstream_ip = s_downstream_ip;
    status->upstream_ip = s_upstream_ip;
    status->upstream_dns = s_upstream_dns;
}

esp_netif_t *capture_gateway_get_ap_netif(void)
{
    return s_active ? s_ap_netif : NULL;
}
