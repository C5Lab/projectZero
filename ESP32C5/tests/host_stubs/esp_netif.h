#ifndef JANOS_TEST_ESP_NETIF_H
#define JANOS_TEST_ESP_NETIF_H

#include <stdint.h>

typedef struct esp_netif esp_netif_t;
typedef struct { uint32_t ip, netmask, gw; } esp_netif_ip_info_t;
typedef struct { struct { uint32_t addr; } ip; } esp_netif_dns_info_t;

#endif
