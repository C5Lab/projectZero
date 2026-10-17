/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LAB_RESULT_STORE_H
#define LAB_RESULT_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef enum {
    LAB_STORE_OK = 0,
    LAB_STORE_DUPLICATE,
    LAB_STORE_INVALID,
    LAB_STORE_IO_ERROR,
    LAB_STORE_FULL,
} lab_store_status_t;

typedef struct {
    uint8_t bssid[6];
    const char *ssid;
    const char *pin;
    const uint8_t *network_key;
    size_t network_key_len;
    const char *recovery_source;
    const char *manufacturer;
    const char *model_name;
    const char *model_number;
    const char *device_name;
    uint32_t operation_id;
    bool authenticated_m7;
} lab_result_record_t;

typedef struct {
    uint8_t bssid[6];
    const char *ssid;
    const char *stage;
    const char *reason;
    const char *manufacturer;
    const char *model_name;
    const char *device_name;
} lab_device_observation_t;

lab_store_status_t lab_result_store_success(
    const char *root, const lab_result_record_t *record);
lab_store_status_t lab_result_store_observation(
    const char *root, const lab_device_observation_t *observation);
const char *lab_store_status_name(lab_store_status_t status);

#endif
