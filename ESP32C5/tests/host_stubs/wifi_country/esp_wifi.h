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
    uint32_t wifi_5g_channel_mask;
} wifi_country_t;

#define CONFIG_SOC_WIFI_SUPPORT_5G 1
#define WIFI_MAX_SUPPORT_COUNTRY_NUM 176
#define WIFI_MAX_REGULATORY_RULE_NUM 7
#define CHANNEL_TO_BIT_NUMBER(channel) (((channel) >= 1 && (channel) <= 14) ? (channel) : \
    (((channel) >= 36 && (channel) <= 64 && ((channel) - 36) % 4 == 0) ? (((channel) - 36) / 4 + 1) : \
    (((channel) >= 100 && (channel) <= 144 && ((channel) - 100) % 4 == 0) ? (((channel) - 100) / 4 + 9) : \
    (((channel) >= 149 && (channel) <= 177 && ((channel) - 149) % 4 == 0) ? (((channel) - 149) / 4 + 21) : 0))))
#define CHANNEL_TO_BIT(channel) (1U << CHANNEL_TO_BIT_NUMBER(channel))

typedef struct {
    uint8_t start_channel, end_channel;
    uint16_t max_bandwidth : 3;
    uint16_t max_eirp : 6;
    uint16_t is_dfs : 1;
    uint16_t reserved : 6;
} wifi_reg_rule_t;
typedef struct {
    uint8_t n_reg_rules;
    wifi_reg_rule_t reg_rules[WIFI_MAX_REGULATORY_RULE_NUM];
} wifi_regulatory_t;
typedef struct {
    char cn[2];
    uint8_t regulatory_type;
} wifi_regdomain_t;

esp_err_t esp_wifi_set_country(const wifi_country_t *country);
esp_err_t esp_wifi_set_country_code(const char *country, bool ieee80211d_enabled);
esp_err_t esp_wifi_get_country(wifi_country_t *country);

#endif
