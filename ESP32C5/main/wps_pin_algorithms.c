/*
 * SPDX-FileCopyrightText: 2026 JanOS contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "wps_pin_algorithms.h"

#include <stdio.h>

uint8_t jwps_pin_checksum(uint32_t seven_digits)
{
    uint32_t accumulator = 0U;
    while (seven_digits != 0U) {
        accumulator += 3U * (seven_digits % 10U);
        seven_digits /= 10U;
        accumulator += seven_digits % 10U;
        seven_digits /= 10U;
    }
    return (uint8_t)((10U - accumulator % 10U) % 10U);
}

static uint32_t finalize_pin(uint32_t raw)
{
    uint32_t seven = raw % 10000000U;
    return seven * 10U + jwps_pin_checksum(seven);
}

static uint32_t nic24(const uint8_t bssid[6])
{
    return ((uint32_t)bssid[3] << 16U) |
           ((uint32_t)bssid[4] << 8U) | bssid[5];
}

static uint32_t dlink_raw(uint32_t nic)
{
    uint32_t pin = nic ^ 0x55AA55U;
    uint32_t nibble = pin & 0x0FU;
    pin ^= (nibble << 4U) + (nibble << 8U) + (nibble << 12U) +
           (nibble << 16U) + (nibble << 20U);
    pin %= 10000000U;
    if (pin < 1000000U) {
        pin += (pin % 9U) * 1000000U + 1000000U;
    }
    return pin;
}

bool wps_pin_generate(wps_pin_algo_t algorithm, const uint8_t bssid[6], uint32_t *pin8)
{
    if (bssid == NULL || pin8 == NULL) {
        return false;
    }
    uint32_t raw = 0U;
    switch (algorithm) {
    case WPS_PIN_ALGO_ZHAO:
        raw = nic24(bssid);
        break;
    case WPS_PIN_ALGO_COMPUTEPIN_28:
        raw = (((uint32_t)bssid[2] << 24U) | ((uint32_t)bssid[3] << 16U) |
               ((uint32_t)bssid[4] << 8U) | bssid[5]) & 0x0FFFFFFFU;
        break;
    case WPS_PIN_ALGO_COMPUTEPIN_32:
        raw = ((uint32_t)bssid[2] << 24U) | ((uint32_t)bssid[3] << 16U) |
              ((uint32_t)bssid[4] << 8U) | bssid[5];
        break;
    case WPS_PIN_ALGO_DLINK:
        raw = dlink_raw(nic24(bssid));
        break;
    case WPS_PIN_ALGO_DLINK1:
        raw = dlink_raw((nic24(bssid) + 1U) & 0xFFFFFFU);
        break;
    case WPS_PIN_ALGO_ASUS: {
        uint32_t sum = 0U;
        for (size_t index = 1U; index < 6U; index++) {
            sum += bssid[index];
        }
        for (size_t index = 0U; index < 7U; index++) {
            uint32_t divisor = 10U - ((uint32_t)index + sum) % 7U;
            raw = raw * 10U + ((uint32_t)bssid[index % 6U] + bssid[5]) % divisor;
        }
        break;
    }
    case WPS_PIN_ALGO_AIROCON:
        raw = ((bssid[0] + bssid[1]) % 10U) * 1000001U +
              ((bssid[1] + bssid[2]) % 10U) * 100000U +
              ((bssid[2] + bssid[3]) % 10U) * 10000U +
              ((bssid[3] + bssid[4]) % 10U) * 1000U +
              ((bssid[4] + bssid[5]) % 10U) * 100U +
              ((bssid[5] + bssid[0]) % 10U) * 10U;
        break;
    case WPS_PIN_ALGO_TRENDNET:
        raw = (uint32_t)bssid[3] * 10000U + (uint32_t)bssid[4] * 100U + bssid[5];
        break;
    case WPS_PIN_ALGO_INVNIC:
        raw = nic24(bssid) ^ 0xFFFFFFU;
        break;
    default:
        return false;
    }
    *pin8 = finalize_pin(raw);
    return true;
}

bool wps_pin_format(uint32_t pin8, char output[9])
{
    if (output == NULL || pin8 > 99999999U) {
        return false;
    }
    return snprintf(output, 9U, "%08u", (unsigned)pin8) == 8;
}
