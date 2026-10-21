/*
 * SPDX-FileCopyrightText: 2026 JanOS contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef JANOS_WPS_PIN_ALGORITHMS_H
#define JANOS_WPS_PIN_ALGORITHMS_H

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    WPS_PIN_ALGO_ZHAO = 0,
    WPS_PIN_ALGO_COMPUTEPIN_28,
    WPS_PIN_ALGO_COMPUTEPIN_32,
    WPS_PIN_ALGO_DLINK,
    WPS_PIN_ALGO_DLINK1,
    WPS_PIN_ALGO_ASUS,
    WPS_PIN_ALGO_AIROCON,
    WPS_PIN_ALGO_TRENDNET,
    WPS_PIN_ALGO_INVNIC,
} wps_pin_algo_t;

uint8_t jwps_pin_checksum(uint32_t seven_digits);
bool wps_pin_generate(wps_pin_algo_t algorithm, const uint8_t bssid[6], uint32_t *pin8);
bool wps_pin_format(uint32_t pin8, char output[9]);

#endif
