/* SPDX-License-Identifier: Apache-2.0 */
#ifndef WIFI_CHANNEL_POLICY_H
#define WIFI_CHANNEL_POLICY_H

#include "esp_wifi.h"

typedef enum {
    WIFI_CHANNEL_POLICY_UNKNOWN,
    WIFI_CHANNEL_POLICY_DISALLOWED,
    WIFI_CHANNEL_POLICY_DFS,
    WIFI_CHANNEL_POLICY_NON_DFS,
} wifi_channel_policy_t;

/* Classify the primary channel using the active country and IDF's rules.
 * NON_DFS describes the driver's regulatory policy, not RF/radar detection. */
wifi_channel_policy_t wifi_channel_policy_classify(
    const wifi_country_t *country, uint8_t channel);

#endif
