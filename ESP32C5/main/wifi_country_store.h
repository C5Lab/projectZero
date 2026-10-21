/* SPDX-License-Identifier: Apache-2.0 */
#ifndef WIFI_COUNTRY_STORE_H
#define WIFI_COUNTRY_STORE_H

#include "esp_err.h"
#include "wifi_country_policy.h"

/* A different running firmware image resets and persists PA once. Subsequent
 * boots of that image preserve the user's saved country. On storage errors,
 * load returns an error and supplies PA plus a diagnostic health string. */
esp_err_t wifi_country_store_load(wifi_country_policy_record_t *record,
                                const char **health);
esp_err_t wifi_country_store_save(const wifi_country_policy_record_t *record);

#endif
