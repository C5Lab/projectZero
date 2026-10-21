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
    LAB_STORE_CANCELLED,
} lab_store_status_t;
typedef bool (*lab_store_commit_gate_fn)(void *context,
                                         uint32_t operation_id);

typedef enum {
    LAB_STORE_PATH_MISSING = 0,
    LAB_STORE_PATH_EXISTS,
    LAB_STORE_PATH_ERROR,
} lab_store_path_state_t;

typedef struct {
    int (*rename_path)(void *context, const char *from, const char *to);
    int (*remove_path)(void *context, const char *path);
    lab_store_path_state_t (*path_state)(void *context, const char *path);
} lab_store_file_ops_t;

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
lab_store_status_t lab_result_store_success_gated(
    const char *root, const lab_result_record_t *record,
    lab_store_commit_gate_fn commit_gate, void *commit_context,
    const lab_store_file_ops_t *file_ops, void *file_context);
lab_store_status_t lab_result_store_observation(
    const char *root, const lab_device_observation_t *observation);
const char *lab_store_status_name(lab_store_status_t status);

#endif
