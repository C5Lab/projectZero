#include "capture_gateway.h"

#include <errno.h>
#include <string.h>

#include "esp_log.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/ip4_addr.h"
#include "lwip/sockets.h"

#define CAPTURE_GATEWAY_DHCPS_OFFER_DNS 0x02
#define CAPTURE_GATEWAY_DNS_PORT 53
#define CAPTURE_GATEWAY_DNS_MAX_PACKET 512

static const char *TAG = "capture_gateway";

static esp_netif_t *s_ap_netif;
static esp_netif_t *s_sta_netif;
static bool s_active;
static bool s_upstream_ready;
static bool s_napt_enabled;
static bool s_open_network;
static bool s_dns_proxy;
static uint8_t s_connected_clients;
static uint8_t s_channel;
static char s_ssid[CAPTURE_GATEWAY_SSID_MAX_LEN + 1];
static char s_upstream_ssid[CAPTURE_GATEWAY_SSID_MAX_LEN + 1];
static esp_netif_ip_info_t s_downstream_ip;
static esp_netif_ip_info_t s_upstream_ip;
static esp_netif_dns_info_t s_upstream_dns;
static esp_netif_dns_info_t s_advertised_dns;

static TaskHandle_t s_dns_task;
static volatile bool s_dns_task_running;
static int s_dns_listen_sock = -1;

static bool capture_gateway_valid_config(const capture_gateway_config_t *config)
{
    if (config == NULL || config->ssid == NULL) {
        return false;
    }

    size_t ssid_len = strlen(config->ssid);
    size_t password_len = config->password != NULL ? strlen(config->password) : 0;
    return ssid_len >= 1 && ssid_len <= CAPTURE_GATEWAY_SSID_MAX_LEN &&
           (password_len == 0 ||
            (password_len >= CAPTURE_GATEWAY_PASSWORD_MIN_LEN &&
             password_len <= CAPTURE_GATEWAY_PASSWORD_MAX_LEN));
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

static void capture_gateway_dns_forward_task(void *arg)
{
    (void)arg;
    uint8_t query[CAPTURE_GATEWAY_DNS_MAX_PACKET];
    uint8_t reply[CAPTURE_GATEWAY_DNS_MAX_PACKET];

    int listen_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (listen_fd < 0) {
        ESP_LOGE(TAG, "DNS proxy: listen socket failed errno=%d", errno);
        s_dns_task = NULL;
        s_dns_task_running = false;
        vTaskDelete(NULL);
        return;
    }

    int reuse = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in listen_addr = {0};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(CAPTURE_GATEWAY_DNS_PORT);
    listen_addr.sin_addr.s_addr = s_downstream_ip.ip.addr;

    if (bind(listen_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        ESP_LOGE(TAG, "DNS proxy: bind " IPSTR ":53 failed errno=%d",
                 IP2STR(&s_downstream_ip.ip), errno);
        close(listen_fd);
        s_dns_task = NULL;
        s_dns_task_running = false;
        vTaskDelete(NULL);
        return;
    }

    struct timeval listen_tv = {.tv_sec = 0, .tv_usec = 500000};
    setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &listen_tv, sizeof(listen_tv));

    int upstream_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (upstream_fd < 0) {
        ESP_LOGE(TAG, "DNS proxy: upstream socket failed errno=%d", errno);
        close(listen_fd);
        s_dns_task = NULL;
        s_dns_task_running = false;
        vTaskDelete(NULL);
        return;
    }
    struct timeval ups_tv = {.tv_sec = 1, .tv_usec = 500000};
    setsockopt(upstream_fd, SOL_SOCKET, SO_RCVTIMEO, &ups_tv, sizeof(ups_tv));

    s_dns_listen_sock = listen_fd;
    ESP_LOGI(TAG, "DNS proxy listening on " IPSTR ":53 -> upstream " IPSTR,
             IP2STR(&s_downstream_ip.ip),
             IP2STR(&s_upstream_dns.ip.u_addr.ip4));

    while (s_dns_task_running) {
        struct sockaddr_in client = {0};
        socklen_t client_len = sizeof(client);
        int n = recvfrom(listen_fd, query, sizeof(query), 0,
                         (struct sockaddr *)&client, &client_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            if (!s_dns_task_running) {
                break;
            }
            ESP_LOGW(TAG, "DNS proxy: recvfrom errno=%d", errno);
            continue;
        }
        if (n < 12) {
            continue;
        }

        uint32_t ups_ip = s_upstream_dns.ip.u_addr.ip4.addr;
        if (s_upstream_dns.ip.type != ESP_IPADDR_TYPE_V4 || ups_ip == 0) {
            continue;
        }

        struct sockaddr_in ups = {0};
        ups.sin_family = AF_INET;
        ups.sin_port = htons(CAPTURE_GATEWAY_DNS_PORT);
        ups.sin_addr.s_addr = ups_ip;

        if (sendto(upstream_fd, query, n, 0, (struct sockaddr *)&ups, sizeof(ups)) < 0) {
            ESP_LOGW(TAG, "DNS proxy: upstream send errno=%d", errno);
            continue;
        }

        uint16_t txid = ((uint16_t)query[0] << 8) | query[1];
        for (int attempt = 0; attempt < 4 && s_dns_task_running; attempt++) {
            struct sockaddr_in from = {0};
            socklen_t from_len = sizeof(from);
            int m = recvfrom(upstream_fd, reply, sizeof(reply), 0,
                             (struct sockaddr *)&from, &from_len);
            if (m < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    continue;
                }
                break;
            }
            if (m < 12) {
                continue;
            }
            uint16_t rtxid = ((uint16_t)reply[0] << 8) | reply[1];
            if (rtxid != txid) {
                continue;
            }
            if (sendto(listen_fd, reply, m, 0, (struct sockaddr *)&client,
                       client_len) < 0) {
                ESP_LOGW(TAG, "DNS proxy: client reply errno=%d", errno);
            }
            break;
        }
    }

    if (upstream_fd >= 0) {
        close(upstream_fd);
    }
    if (listen_fd >= 0) {
        close(listen_fd);
    }
    s_dns_listen_sock = -1;
    s_dns_task = NULL;
    s_dns_task_running = false;
    vTaskDelete(NULL);
}

static void capture_gateway_dns_stop(void)
{
    s_dns_task_running = false;
    if (s_dns_listen_sock >= 0) {
        shutdown(s_dns_listen_sock, SHUT_RDWR);
        close(s_dns_listen_sock);
        s_dns_listen_sock = -1;
    }
    for (int i = 0; i < 50 && s_dns_task != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    if (s_dns_task != NULL) {
        vTaskDelete(s_dns_task);
        s_dns_task = NULL;
    }
    s_dns_proxy = false;
}

static esp_err_t capture_gateway_dns_start(void)
{
    if (s_dns_task != NULL) {
        return ESP_OK;
    }
    if (s_downstream_ip.ip.addr == 0) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_upstream_dns.ip.type != ESP_IPADDR_TYPE_V4 ||
        s_upstream_dns.ip.u_addr.ip4.addr == 0) {
        ESP_LOGW(TAG, "DNS proxy: no upstream DNS yet; proxy not started");
        return ESP_ERR_INVALID_STATE;
    }

    s_dns_task_running = true;
    BaseType_t ok = xTaskCreate(capture_gateway_dns_forward_task,
                                "cgw_dns",
                                4096,
                                NULL,
                                5,
                                &s_dns_task);
    if (ok != pdPASS) {
        s_dns_task_running = false;
        s_dns_task = NULL;
        ESP_LOGE(TAG, "DNS proxy: task create failed");
        return ESP_ERR_NO_MEM;
    }
    s_dns_proxy = true;
    return ESP_OK;
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
        ESP_LOGW(TAG, "Upstream DNS missing; using upstream gateway as DNS fallback");
    }

    err = esp_netif_set_default_netif(s_sta_netif);
    if (err != ESP_OK) {
        return err;
    }

    /* Advertise SoftAP gateway as DNS so clients never peer with upstream LAN. */
    esp_netif_dns_info_t advertised = {0};
    advertised.ip.type = ESP_IPADDR_TYPE_V4;
    advertised.ip.u_addr.ip4 = s_downstream_ip.ip;
    err = esp_netif_set_dns_info(s_ap_netif, ESP_NETIF_DNS_MAIN, &advertised);
    if (err != ESP_OK) {
        return err;
    }

    s_upstream_ip = sta_ip;
    s_upstream_dns = dns;
    s_advertised_dns = advertised;
    s_upstream_ready = true;

    ESP_LOGI(TAG, "DNS: advertise " IPSTR " (proxy), upstream resolver " IPSTR,
             IP2STR(&s_advertised_dns.ip.u_addr.ip4),
             IP2STR(&s_upstream_dns.ip.u_addr.ip4));

    if (s_active && !s_dns_proxy) {
        (void)capture_gateway_dns_start();
    }
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
    size_t password_len = config->password != NULL ? strlen(config->password) : 0;
    if (password_len > 0) {
        strlcpy((char *)ap_config.ap.password, config->password,
                sizeof(ap_config.ap.password));
    }
    ap_config.ap.channel = config->channel != 0 ? config->channel : upstream.primary;
    ap_config.ap.max_connection = config->max_clients != 0
                                      ? config->max_clients
                                      : CAPTURE_GATEWAY_DEFAULT_MAX_CLIENTS;
    ap_config.ap.authmode = password_len > 0 ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    ap_config.ap.pmf_cfg.capable = password_len > 0;
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
    s_open_network = password_len == 0;
    s_connected_clients = 0;
    s_active = true;

    err = capture_gateway_dns_start();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "DNS proxy failed to start (%s); clients may lack DNS",
                 esp_err_to_name(err));
        /* SoftAP/NAPT still useful; do not roll back for DNS alone. */
    }

    ESP_LOGI(TAG, "Capture gateway active: SSID='%s' security=%s channel=%u AP=" IPSTR
             " dns_proxy=%s",
             s_ssid, s_open_network ? "open" : "wpa2", s_channel,
             IP2STR(&s_downstream_ip.ip),
             s_dns_proxy ? "on" : "off");
    return ESP_OK;

fail:
    capture_gateway_dns_stop();
    s_ap_netif = NULL;
    s_sta_netif = NULL;
    s_active = false;
    s_upstream_ready = false;
    s_napt_enabled = false;
    s_open_network = false;
    s_dns_proxy = false;
    s_connected_clients = 0;
    memset(s_ssid, 0, sizeof(s_ssid));
    memset(s_upstream_ssid, 0, sizeof(s_upstream_ssid));
    memset(&s_downstream_ip, 0, sizeof(s_downstream_ip));
    memset(&s_upstream_ip, 0, sizeof(s_upstream_ip));
    memset(&s_upstream_dns, 0, sizeof(s_upstream_dns));
    memset(&s_advertised_dns, 0, sizeof(s_advertised_dns));
    return err;
}

esp_err_t capture_gateway_stop(void)
{
    esp_err_t first_error = ESP_OK;

    capture_gateway_dns_stop();

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
    s_open_network = false;
    s_dns_proxy = false;
    s_connected_clients = 0;
    s_channel = 0;
    memset(s_ssid, 0, sizeof(s_ssid));
    memset(s_upstream_ssid, 0, sizeof(s_upstream_ssid));
    memset(&s_downstream_ip, 0, sizeof(s_downstream_ip));
    memset(&s_upstream_ip, 0, sizeof(s_upstream_ip));
    memset(&s_upstream_dns, 0, sizeof(s_upstream_dns));
    memset(&s_advertised_dns, 0, sizeof(s_advertised_dns));
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
    status->open_network = s_open_network;
    status->dns_proxy = s_dns_proxy;
    status->connected_clients = s_connected_clients;
    status->channel = s_channel;
    strlcpy(status->ssid, s_ssid, sizeof(status->ssid));
    strlcpy(status->upstream_ssid, s_upstream_ssid, sizeof(status->upstream_ssid));
    status->downstream_ip = s_downstream_ip;
    status->upstream_ip = s_upstream_ip;
    status->advertised_dns = s_advertised_dns;
    status->upstream_dns = s_upstream_dns;
}

esp_netif_t *capture_gateway_get_ap_netif(void)
{
    return s_active ? s_ap_netif : NULL;
}
