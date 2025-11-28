/**
 * @file sniffer.h
 * @brief Provides sniffer event declarations for frame analyzer
 */
#ifndef SNIFFER_H
#define SNIFFER_H

#include "esp_event.h"

ESP_EVENT_DECLARE_BASE(SNIFFER_EVENTS);

enum {
    SNIFFER_EVENT_CAPTURED_DATA,
    SNIFFER_EVENT_CAPTURED_MGMT,
    SNIFFER_EVENT_CAPTURED_CTRL
};

/**
 * @brief Initialize sniffer and register promiscuous callback
 */
void sniffer_init(void);

#endif

