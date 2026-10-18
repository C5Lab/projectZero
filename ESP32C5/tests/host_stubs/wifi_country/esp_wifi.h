#ifndef JANOS_TEST_WIFI_COUNTRY_ESP_WIFI_H
#define JANOS_TEST_WIFI_COUNTRY_ESP_WIFI_H

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

typedef enum {
    WIFI_COUNTRY_POLICY_AUTO,
    WIFI_COUNTRY_POLICY_MANUAL,
} wifi_country_policy_t;

typedef struct {
    char cc[3];
    uint8_t schan;
    uint8_t nchan;
    int8_t max_tx_power;
    wifi_country_policy_t policy;
} wifi_country_t;

esp_err_t esp_wifi_set_country(const wifi_country_t *country);
esp_err_t esp_wifi_set_country_code(const char *country, bool ieee80211d_enabled);
esp_err_t esp_wifi_get_country(wifi_country_t *country);

#endif
