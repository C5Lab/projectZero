/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_country_driver.h"

#include "esp_wifi.h"

esp_err_t wifi_country_driver_apply_and_verify(
    const wifi_country_policy_record_t *record)
{
    if (record == NULL || record->version != WIFI_COUNTRY_POLICY_VERSION ||
        !wifi_country_policy_is_supported(record->cc))
        return ESP_ERR_INVALID_ARG;

    esp_err_t err;
    if (wifi_country_policy_is_pa(record)) {
        const wifi_country_t country = {
            .cc = "PA",
            .schan = 1,
            .nchan = 14,
            .policy = WIFI_COUNTRY_POLICY_MANUAL,
        };
        err = esp_wifi_set_country(&country);
    } else {
        err = esp_wifi_set_country_code(record->cc, false);
    }
    if (err != ESP_OK) return err;

    wifi_country_t readback = {0};
    err = esp_wifi_get_country(&readback);
    if (err != ESP_OK) return err;

    bool mismatch = readback.cc[0] != record->cc[0] ||
                    readback.cc[1] != record->cc[1] ||
                    readback.policy != WIFI_COUNTRY_POLICY_MANUAL;
    if (wifi_country_policy_is_pa(record))
        mismatch = mismatch || readback.schan != 1 || readback.nchan != 14;
    return mismatch ? ESP_ERR_INVALID_STATE : ESP_OK;
}
