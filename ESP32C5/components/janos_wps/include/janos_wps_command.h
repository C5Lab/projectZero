/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef enum {
    JANOS_WPS_OP_INVALID = 0,
    JANOS_WPS_OP_VERIFY,
    JANOS_WPS_OP_PIXIE,
    JANOS_WPS_OP_JWPS_PLAN,
    JANOS_WPS_OP_JWPS_CAMPAIGN,
    JANOS_WPS_OP_SELFTEST_DB,
    JANOS_WPS_OP_SELFTEST_FRAGMENT,
    JANOS_WPS_OP_SELFTEST_TRANSPORT,
    JANOS_WPS_OP_SELFTEST_PIXIE,
} janos_wps_operation_t;

typedef struct {
    janos_wps_operation_t operation;
    uint8_t bssid[6];
    char pin[9];
    char ssid[33];
    unsigned start_index;
    unsigned count;
    uint32_t epoch;
    bool epoch_set;
} janos_wps_command_t;

typedef enum {
    JANOS_WPS_PARSE_OK = 0,
    JANOS_WPS_PARSE_INVALID,
    JANOS_WPS_PARSE_RANGE,
} janos_wps_parse_result_t;

janos_wps_parse_result_t janos_wps_command_parse(
    int argc, char **argv, janos_wps_command_t *command);
bool janos_wps_operation_requires_radio(janos_wps_operation_t operation);
const char *janos_wps_operation_name(janos_wps_operation_t operation);
bool janos_wps_command_family_name(const char *command);
bool janos_wps_named_operation_requires_radio(const char *command,
                                               const char *subcommand);
void janos_wps_command_wipe(janos_wps_command_t *command);

