/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_console_admission.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static bool equals(const char *value, const char *expected)
{
    return value != NULL && strcmp(value, expected) == 0;
}

static bool is_status_read(const char *command, const char *subcommand)
{
    return (equals(command, "wifi_analyzer") &&
            (equals(subcommand, "caps") || equals(subcommand, "status"))) ||
           (equals(command, "wps") && equals(subcommand, "status")) ||
           (equals(command, "secret") && equals(subcommand, "status"));
}

static bool is_always_safe(const char *command, const char *subcommand)
{
    return equals(command, "stop") || equals(command, "reboot") ||
           equals(command, "help") || equals(command, "show_scan_results") ||
           is_status_read(command, subcommand);
}

janos_console_admission_result_t janos_console_admission_decide(
    janos_radio_owner_t owner,
    const char *command,
    const char *subcommand,
    uint32_t commands_inflight,
    bool analyzer_busy)
{
    if (command == NULL || command[0] == '\0' ||
        owner > JANOS_RADIO_OWNER_WPS) {
        return JANOS_CONSOLE_BUSY_RADIO_LEASE;
    }
    if (is_always_safe(command, subcommand)) return JANOS_CONSOLE_ADMIT;

    bool analyzer_command = equals(command, "wifi_analyzer");
    bool wps_command = equals(command, "wps") || equals(command, "secret");

    if (owner == JANOS_RADIO_OWNER_ANALYZER) {
        return analyzer_command ? JANOS_CONSOLE_ADMIT :
                                  JANOS_CONSOLE_BUSY_RADIO_LEASE;
    }
    if (owner == JANOS_RADIO_OWNER_WPS) {
        return wps_command ? JANOS_CONSOLE_ADMIT :
                             JANOS_CONSOLE_BUSY_RADIO_LEASE;
    }
    if (analyzer_command && commands_inflight != 0U) {
        return JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS;
    }
    if (analyzer_busy && !analyzer_command) {
        return JANOS_CONSOLE_BUSY_WIFI_ANALYZER;
    }
    return JANOS_CONSOLE_ADMIT;
}

const char *janos_console_admission_reason(
    janos_console_admission_result_t result)
{
    switch (result) {
    case JANOS_CONSOLE_ADMIT:
        return NULL;
    case JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS:
        return "command_in_progress";
    case JANOS_CONSOLE_BUSY_WIFI_ANALYZER:
        return "wifi_analyzer";
    case JANOS_CONSOLE_BUSY_RADIO_LEASE:
    default:
        return "radio_lease";
    }
}

bool janos_console_admission_format(
    char *output,
    size_t capacity,
    janos_console_admission_result_t result)
{
    const char *reason = janos_console_admission_reason(result);
    if (!output || capacity == 0U || !reason || result == JANOS_CONSOLE_ADMIT)
        return false;
    int written = snprintf(
        output, capacity,
        "[WFACTL1] {\"v\":1,\"type\":\"error\",\"command\":\"console\","
        "\"code\":\"busy\",\"reason\":\"%s\"}", reason);
    return written > 0 && (size_t)written < capacity;
}
