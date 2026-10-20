"""Exercise the real Capture Gateway lifecycle against narrow host IDF stubs.

These tests compile the complete production C file. The stubs record the
network configuration handed to ESP-IDF; they do not simulate Wi-Fi radio
acceptance or run the DNS forwarding task.
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "components/capture_gateway/capture_gateway.c"
INCLUDE = ROOT / "components/capture_gateway/include"

STUB_HEADERS = {
    "esp_err.h": r"""
#pragma once
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NO_MEM 0x105
const char *esp_err_to_name(esp_err_t error);
""",
    "esp_netif.h": r"""
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
typedef struct { uint32_t addr; } esp_ip4_addr_t;
typedef struct { esp_ip4_addr_t ip, netmask, gw; } esp_netif_ip_info_t;
typedef struct {
    struct { int type; union { esp_ip4_addr_t ip4; } u_addr; } ip;
} esp_netif_dns_info_t;
typedef struct esp_netif {
    int id;
    esp_netif_ip_info_t ip;
    esp_netif_dns_info_t dns;
} esp_netif_t;
#define ESP_IPADDR_TYPE_V4 0
#define ESP_NETIF_DNS_MAIN 0
#define ESP_NETIF_OP_SET 1
#define ESP_NETIF_DOMAIN_NAME_SERVER 2
#define ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED 0x5001
#define ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED 0x5002
esp_err_t esp_netif_get_ip_info(esp_netif_t *, esp_netif_ip_info_t *);
esp_err_t esp_netif_set_ip_info(esp_netif_t *, const esp_netif_ip_info_t *);
esp_err_t esp_netif_get_dns_info(esp_netif_t *, int, esp_netif_dns_info_t *);
esp_err_t esp_netif_set_dns_info(esp_netif_t *, int,
                                 const esp_netif_dns_info_t *);
esp_err_t esp_netif_set_default_netif(esp_netif_t *);
esp_err_t esp_netif_dhcps_stop(esp_netif_t *);
esp_err_t esp_netif_dhcps_start(esp_netif_t *);
esp_err_t esp_netif_dhcps_option(esp_netif_t *, int, int, void *, size_t);
esp_err_t esp_netif_napt_enable(esp_netif_t *);
esp_err_t esp_netif_napt_disable(esp_netif_t *);
""",
    "esp_wifi.h": r"""
#pragma once
#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
typedef struct { uint8_t ssid[33]; uint8_t primary; } wifi_ap_record_t;
typedef struct {
    struct {
        uint8_t ssid[32];
        uint8_t ssid_len;
        uint8_t password[64];
        uint8_t channel;
        uint8_t max_connection;
        int authmode;
        struct { bool capable; bool required; } pmf_cfg;
    } ap;
} wifi_config_t;
#define WIFI_IF_AP 1
#define WIFI_AUTH_OPEN 0
#define WIFI_AUTH_WPA2_PSK 3
esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *);
esp_err_t esp_wifi_set_config(int, wifi_config_t *);
""",
    "esp_log.h": r"""
#pragma once
#define ESP_LOGE(tag, ...) do { (void)(tag); } while (0)
#define ESP_LOGW(tag, ...) do { (void)(tag); } while (0)
#define ESP_LOGI(tag, ...) do { (void)(tag); } while (0)
""",
    "freertos/FreeRTOS.h": r"""
#pragma once
typedef int BaseType_t;
typedef void *TaskHandle_t;
#define pdPASS 1
#define pdFAIL 0
#define pdMS_TO_TICKS(milliseconds) (milliseconds)
""",
    "freertos/task.h": r"""
#pragma once
#include "freertos/FreeRTOS.h"
BaseType_t xTaskCreate(void (*)(void *), const char *, unsigned int,
                       void *, unsigned int, TaskHandle_t *);
void vTaskDelay(unsigned int);
void vTaskDelete(TaskHandle_t);
""",
    "lwip/ip4_addr.h": r"""
#pragma once
#include <stdint.h>
#include "esp_netif.h"
#define IP4_ADDR(ip, a, b, c, d) ((ip)->addr = \
    ((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | \
    ((uint32_t)(c) << 8) | (uint32_t)(d))
""",
    "lwip/sockets.h": r"""
#pragma once
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
""",
}

HARNESS = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "capture_gateway.h"
#include "esp_wifi.h"
#include "freertos/task.h"

static esp_netif_t ap = {.id = 1};
static esp_netif_t sta = {.id = 2};
static wifi_ap_record_t upstream;
static wifi_config_t configured_ap;
static esp_err_t wifi_error;
static esp_err_t napt_error;
static esp_err_t ip_set_error;
static int wifi_calls;
static int dhcp_stops;
static int dhcp_starts;
static int dhcp_options;
static int napt_enables;
static int napt_disables;
static int default_route_calls;
static int ap_dns_calls;
static int dns_task_creates;
static int dns_task_deletes;
static uint8_t offered_dns;
static bool napt_on;
static bool dhcp_on;
static bool dns_task_create_ok;

const char *esp_err_to_name(esp_err_t error) {
    (void)error;
    return "host error";
}
esp_err_t esp_netif_get_ip_info(esp_netif_t *netif, esp_netif_ip_info_t *out) {
    *out = netif->ip;
    return ESP_OK;
}
esp_err_t esp_netif_set_ip_info(esp_netif_t *netif,
                                const esp_netif_ip_info_t *info) {
    assert(netif == &ap);
    if (ip_set_error != ESP_OK) return ip_set_error;
    netif->ip = *info;
    return ESP_OK;
}
esp_err_t esp_netif_get_dns_info(esp_netif_t *netif, int which,
                                 esp_netif_dns_info_t *out) {
    assert(netif == &sta && which == ESP_NETIF_DNS_MAIN);
    *out = netif->dns;
    return ESP_OK;
}
esp_err_t esp_netif_set_dns_info(esp_netif_t *netif, int which,
                                 const esp_netif_dns_info_t *info) {
    assert(netif == &ap && which == ESP_NETIF_DNS_MAIN);
    netif->dns = *info;
    ap_dns_calls++;
    return ESP_OK;
}
esp_err_t esp_netif_set_default_netif(esp_netif_t *netif) {
    assert(netif == &sta);
    default_route_calls++;
    return ESP_OK;
}
esp_err_t esp_netif_dhcps_stop(esp_netif_t *netif) {
    assert(netif == &ap);
    dhcp_stops++;
    dhcp_on = false;
    return ESP_OK;
}
esp_err_t esp_netif_dhcps_start(esp_netif_t *netif) {
    assert(netif == &ap);
    dhcp_starts++;
    dhcp_on = true;
    return ESP_OK;
}
esp_err_t esp_netif_dhcps_option(esp_netif_t *netif, int op, int option,
                                 void *value, size_t length) {
    assert(netif == &ap && op == ESP_NETIF_OP_SET);
    assert(option == ESP_NETIF_DOMAIN_NAME_SERVER && length == 1);
    offered_dns = *(uint8_t *)value;
    dhcp_options++;
    return ESP_OK;
}
esp_err_t esp_netif_napt_enable(esp_netif_t *netif) {
    assert(netif == &ap);
    napt_enables++;
    if (napt_error != ESP_OK) return napt_error;
    napt_on = true;
    return ESP_OK;
}
esp_err_t esp_netif_napt_disable(esp_netif_t *netif) {
    assert(netif == &ap);
    napt_disables++;
    napt_on = false;
    return ESP_OK;
}
esp_err_t esp_wifi_sta_get_ap_info(wifi_ap_record_t *out) {
    *out = upstream;
    return ESP_OK;
}
esp_err_t esp_wifi_set_config(int interface, wifi_config_t *config) {
    assert(interface == WIFI_IF_AP);
    wifi_calls++;
    configured_ap = *config;
    return wifi_error;
}
BaseType_t xTaskCreate(void (*task)(void *), const char *name,
                       unsigned int stack, void *arg, unsigned int priority,
                       TaskHandle_t *handle) {
    (void)task; (void)name; (void)stack; (void)arg;
    (void)priority;
    dns_task_creates++;
    /* Record creation without invoking the DNS task or opening sockets. */
    if (!dns_task_create_ok) return pdFAIL;
    *handle = (TaskHandle_t)(uintptr_t)1;
    return pdPASS;
}
void vTaskDelay(unsigned int ticks) { (void)ticks; }
void vTaskDelete(TaskHandle_t handle) {
    assert(handle == (TaskHandle_t)(uintptr_t)1);
    dns_task_deletes++;
}

static capture_gateway_config_t config = {
    .ssid = "Lab-Gateway", .password = "testonly", .channel = 0,
    .max_clients = 3,
};

static void initial_network(void) {
    sta.ip.ip.addr = 0xc0a83213U;      /* 192.168.50.19 */
    sta.ip.netmask.addr = 0xffffff00U;
    sta.ip.gw.addr = 0xc0a83201U;      /* 192.168.50.1 */
    sta.dns.ip.type = ESP_IPADDR_TYPE_V4;
    sta.dns.ip.u_addr.ip4.addr = 0x09090909U;
    upstream.primary = 100;
    memcpy(upstream.ssid, "Upstream-Lab", sizeof("Upstream-Lab"));
}

static void test_start_tracks_channel_network_and_stop(void) {
    initial_network();
    assert(capture_gateway_start(&ap, &sta, &config) == ESP_OK);
    capture_gateway_status_t status;
    capture_gateway_get_status(&status);
    assert(wifi_calls == 1 && configured_ap.ap.channel == 100);
    assert(configured_ap.ap.ssid_len == strlen("Lab-Gateway"));
    assert(memcmp(configured_ap.ap.ssid, "Lab-Gateway", 11) == 0);
    assert(strcmp((char *)configured_ap.ap.password, "testonly") == 0);
    assert(configured_ap.ap.authmode == WIFI_AUTH_WPA2_PSK);
    assert(configured_ap.ap.pmf_cfg.capable && !configured_ap.ap.pmf_cfg.required);
    assert(configured_ap.ap.max_connection == 3);
    assert(ap.ip.ip.addr == 0x0a2a0001U);
    assert(ap.ip.gw.addr == 0x0a2a0001U);
    assert(ap.ip.netmask.addr == 0xffffff00U);
    assert(dhcp_stops == 1 && dhcp_starts == 1 && dhcp_options == 1);
    assert(offered_dns == 2 && dhcp_on);
    assert(default_route_calls == 1 && ap_dns_calls == 1);
    assert(ap.dns.ip.u_addr.ip4.addr == 0x0a2a0001U);
    assert(napt_enables == 1 && napt_on);
    assert(status.active && status.upstream_ready && status.napt_enabled);
    assert(!status.open_network && !status.dns_proxy);
    assert(status.channel == 100);
    assert(strcmp(status.ssid, "Lab-Gateway") == 0);
    assert(strcmp(status.upstream_ssid, "Upstream-Lab") == 0);
    assert(status.downstream_ip.ip.addr == 0x0a2a0001U);
    assert(status.upstream_ip.ip.addr == 0xc0a83213U);
    assert(status.advertised_dns.ip.u_addr.ip4.addr == 0x0a2a0001U);
    assert(status.upstream_dns.ip.u_addr.ip4.addr == 0x09090909U);
    assert(capture_gateway_get_ap_netif() == &ap);
    assert(capture_gateway_start(&ap, &sta, &config) == ESP_ERR_INVALID_STATE);
    assert(wifi_calls == 1);
    assert(capture_gateway_stop() == ESP_OK);
    capture_gateway_get_status(&status);
    assert(!status.active && !status.napt_enabled && !status.upstream_ready);
    assert(status.channel == 0 && status.ssid[0] == '\0');
    assert(capture_gateway_get_ap_netif() == NULL);
    assert(napt_disables == 1 && !napt_on);
    assert(dhcp_stops == 2 && !dhcp_on);
}

static void test_explicit_channel_open_ap_defaults(void) {
    initial_network();
    config.channel = 6;
    config.password = NULL;
    config.max_clients = 0;
    assert(capture_gateway_start(&ap, &sta, &config) == ESP_OK);
    capture_gateway_status_t status;
    capture_gateway_get_status(&status);
    assert(configured_ap.ap.channel == 6 && status.channel == 6);
    assert(configured_ap.ap.max_connection == 4);
    assert(configured_ap.ap.authmode == WIFI_AUTH_OPEN);
    assert(!configured_ap.ap.pmf_cfg.capable);
    assert(status.open_network && status.active);
    assert(capture_gateway_stop() == ESP_OK);
}

static void test_dns_task_creation_sets_proxy_status_until_stop(void) {
    initial_network();
    dns_task_create_ok = true;
    assert(capture_gateway_start(&ap, &sta, &config) == ESP_OK);
    capture_gateway_status_t status;
    capture_gateway_get_status(&status);
    assert(status.active && status.dns_proxy);
    assert(dns_task_creates == 1 && dns_task_deletes == 0);
    assert(capture_gateway_stop() == ESP_OK);
    capture_gateway_get_status(&status);
    assert(!status.active && !status.dns_proxy);
    assert(dns_task_deletes == 1);
}

static void test_dns_fallback_and_refresh(void) {
    initial_network();
    sta.dns.ip.u_addr.ip4.addr = 0;
    assert(capture_gateway_start(&ap, &sta, &config) == ESP_OK);
    capture_gateway_status_t status;
    capture_gateway_get_status(&status);
    assert(status.upstream_dns.ip.u_addr.ip4.addr == 0xc0a83201U);
    assert(status.advertised_dns.ip.u_addr.ip4.addr == 0x0a2a0001U);
    sta.ip.ip.addr = 0xac100903U;      /* 172.16.9.3 */
    sta.ip.gw.addr = 0xac100901U;
    sta.dns.ip.u_addr.ip4.addr = 0x01010101U;
    assert(capture_gateway_refresh_upstream() == ESP_OK);
    capture_gateway_get_status(&status);
    assert(status.upstream_ready);
    assert(status.upstream_ip.ip.addr == 0xac100903U);
    assert(status.upstream_dns.ip.u_addr.ip4.addr == 0x01010101U);
    assert(status.advertised_dns.ip.u_addr.ip4.addr == 0x0a2a0001U);
    assert(default_route_calls == 2 && ap_dns_calls == 2);
    sta.ip.ip.addr = 0;
    assert(capture_gateway_refresh_upstream() == ESP_ERR_INVALID_STATE);
    capture_gateway_get_status(&status);
    assert(status.active && !status.upstream_ready);
    assert(status.upstream_ip.ip.addr == 0);
    assert(capture_gateway_stop() == ESP_OK);
    assert(capture_gateway_refresh_upstream() == ESP_ERR_INVALID_STATE);
}

static void test_wifi_rejection_aborts_before_dhcp(void) {
    initial_network();
    wifi_error = 719;
    assert(capture_gateway_start(&ap, &sta, &config) == 719);
    assert(wifi_calls == 1 && configured_ap.ap.channel == 100);
    assert(dhcp_stops == 0 && dhcp_starts == 0 && dhcp_options == 0);
    assert(napt_enables == 0 && !capture_gateway_is_active());
    assert(capture_gateway_get_ap_netif() == NULL);
}

static void test_napt_failure_rolls_back_and_allows_retry(void) {
    initial_network();
    napt_error = 717;
    assert(capture_gateway_start(&ap, &sta, &config) == 717);
    capture_gateway_status_t status;
    capture_gateway_get_status(&status);
    assert(dhcp_starts == 1 && dhcp_stops == 2 && !dhcp_on);
    assert(!status.active && !status.upstream_ready && !status.napt_enabled);
    assert(status.ssid[0] == '\0' && status.upstream_ip.ip.addr == 0);
    assert(capture_gateway_get_ap_netif() == NULL);
    napt_error = ESP_OK;
    assert(capture_gateway_start(&ap, &sta, &config) == ESP_OK);
    capture_gateway_get_status(&status);
    assert(status.active && status.napt_enabled && napt_on);
    assert(capture_gateway_stop() == ESP_OK);
}

static void test_ap_ip_error_restores_previous_dhcp_service(void) {
    initial_network();
    dhcp_on = true;                   /* Existing default SoftAP DHCP service. */
    ip_set_error = 718;
    esp_err_t result = capture_gateway_start(&ap, &sta, &config);
    if (result != 718 || !dhcp_on || dhcp_starts != 1 ||
        dhcp_stops != 1 || napt_enables != 0) {
        fprintf(stderr, "AP IP error: result=%d dhcp_on=%d dhcp_stops=%d dhcp_starts=%d napt_enables=%d\n",
                result, dhcp_on, dhcp_stops, dhcp_starts, napt_enables);
    }
    assert(result == 718);
    assert(dhcp_on && dhcp_stops == 1 && dhcp_starts == 1);
    assert(napt_enables == 0 && !capture_gateway_is_active());
}

static void test_invalid_inputs_and_overlapping_subnet(void) {
    initial_network();
    config.password = "short";
    assert(capture_gateway_start(&ap, &sta, &config) == ESP_ERR_INVALID_ARG);
    config.password = NULL;
    sta.ip.ip.addr = 0;
    assert(capture_gateway_start(&ap, &sta, &config) == ESP_ERR_INVALID_STATE);
    sta.ip.ip.addr = 0x0a2a0063U;     /* 10.42.0.99/24 */
    assert(capture_gateway_start(&ap, &sta, &config) == ESP_ERR_INVALID_STATE);
    assert(wifi_calls == 0 && dhcp_stops == 0 && napt_enables == 0);
    assert(!capture_gateway_is_active());
}

static void test_narrow_upstream_subnet_overlaps_downstream(void) {
    initial_network();
    sta.ip.ip.addr = 0x0a2a0081U;     /* 10.42.0.129 */
    sta.ip.netmask.addr = 0xffffff80U; /* /25: 10.42.0.128-255 */
    sta.ip.gw.addr = 0x0a2a0081U;
    esp_err_t result = capture_gateway_start(&ap, &sta, &config);
    if (result != ESP_ERR_INVALID_STATE || wifi_calls != 0 ||
        dhcp_stops != 0 || napt_enables != 0) {
        fprintf(stderr, "overlap /25: result=%d wifi_calls=%d dhcp_stops=%d napt_enables=%d\n",
                result, wifi_calls, dhcp_stops, napt_enables);
    }
    assert(result == ESP_ERR_INVALID_STATE);
    assert(wifi_calls == 0 && dhcp_stops == 0 && napt_enables == 0);
    assert(!capture_gateway_is_active());
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (strcmp(argv[1], "start") == 0) test_start_tracks_channel_network_and_stop();
    else if (strcmp(argv[1], "override") == 0) test_explicit_channel_open_ap_defaults();
    else if (strcmp(argv[1], "dns-task") == 0) test_dns_task_creation_sets_proxy_status_until_stop();
    else if (strcmp(argv[1], "refresh") == 0) test_dns_fallback_and_refresh();
    else if (strcmp(argv[1], "wifi-error") == 0) test_wifi_rejection_aborts_before_dhcp();
    else if (strcmp(argv[1], "napt-error") == 0) test_napt_failure_rolls_back_and_allows_retry();
    else if (strcmp(argv[1], "ap-ip-error") == 0) test_ap_ip_error_restores_previous_dhcp_service();
    else if (strcmp(argv[1], "invalid") == 0) test_invalid_inputs_and_overlapping_subnet();
    else if (strcmp(argv[1], "overlap-25") == 0) test_narrow_upstream_subnet_overlaps_downstream();
    else return 2;
    return 0;
}
"""


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C compiler required; run via WSL/Linux")
class CaptureGatewayStartTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="janos-cgw-start-")
        cls.addClassCleanup(cls.temporary.cleanup)
        temporary = Path(cls.temporary.name)
        for name, content in STUB_HEADERS.items():
            header = temporary / name
            header.parent.mkdir(parents=True, exist_ok=True)
            header.write_text(content, encoding="utf-8")
        harness = temporary / "capture_gateway_host.c"
        harness.write_text(HARNESS, encoding="utf-8")
        cls.executable = temporary / "capture_gateway_host"
        compiled = subprocess.run([
            os.environ.get("CC", "gcc"), "-D_GNU_SOURCE", "-std=c11",
            "-Wall", "-Wextra", "-Werror", "-I", str(temporary),
            "-I", str(INCLUDE), str(SOURCE), str(harness), "-o",
            str(cls.executable),
        ], cwd=ROOT, capture_output=True, text=True, timeout=60)
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    def run_case(self, name):
        result = subprocess.run([str(self.executable), name], cwd=ROOT,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_start_uses_upstream_channel_and_isolated_ap_network(self):
        """Catches a fixed/wrong AP channel or lost DHCP, DNS, NAPT setup."""
        self.run_case("start")

    def test_explicit_channel_and_open_ap_defaults(self):
        """Catches ignored channel overrides and wrong open AP parameters."""
        self.run_case("override")

    def test_dns_task_creation_marks_proxy_on_until_stop(self):
        """Catches missing DNS proxy status or stop cleanup after task creation."""
        self.run_case("dns-task")

    def test_missing_dns_falls_back_and_refresh_updates_upstream(self):
        """Catches stale DNS/IP after a lease change or a lost-IP event."""
        self.run_case("refresh")

    def test_wifi_driver_rejection_is_returned_before_dhcp_changes(self):
        """Catches swallowed esp_wifi_set_config errors and partial startup."""
        self.run_case("wifi-error")

    def test_napt_failure_rolls_back_dhcp_and_can_retry(self):
        """Catches a half-active gateway after NAPT setup fails."""
        self.run_case("napt-error")

    def test_ap_ip_programming_error_restores_dhcp(self):
        """Catches a stopped DHCP service after AP IP programming fails."""
        self.run_case("ap-ip-error")

    def test_invalid_config_or_overlapping_subnet_blocks_ap_setup(self):
        """Catches validation bypass before the AP is reconfigured."""
        self.run_case("invalid")

    def test_upstream_25_overlap_blocks_ap_setup(self):
        """Catches accepting an upstream /25 inside the downstream /24."""
        self.run_case("overlap-25")


if __name__ == "__main__":
    unittest.main()
