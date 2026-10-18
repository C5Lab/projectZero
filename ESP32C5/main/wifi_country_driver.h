/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#ifndef WIFI_COUNTRY_DRIVER_H
#define WIFI_COUNTRY_DRIVER_H

#include "esp_err.h"
#include "wifi_country_policy.h"

esp_err_t wifi_country_driver_apply_and_verify(
    const wifi_country_policy_record_t *record);

#endif
