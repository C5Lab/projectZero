#ifndef JANOS_TEST_ESP_WIFI_TYPES_H
#define JANOS_TEST_ESP_WIFI_TYPES_H

#include <stdint.h>

typedef struct {
    uint16_t sig_len;
} wifi_pkt_rx_ctrl_t;

typedef struct {
    wifi_pkt_rx_ctrl_t rx_ctrl;
    uint8_t payload[];
} wifi_promiscuous_pkt_t;

#endif
