/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_console_admission.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "janos_wps_command.h"

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
           ((equals(command, "wps") || equals(command, "wifi_analyzer")) &&
            equals(subcommand, "stop")) || is_status_read(command, subcommand);
}

janos_console_admission_result_t janos_console_admission_decide(
    janos_radio_owner_t owner,
    const char *command,
    const char *subcommand,
    uint32_t commands_inflight,
    bool analyzer_busy)
{
    if (command == NULL || command[0] == '\0' ||
        owner < JANOS_RADIO_OWNER_NONE || owner > JANOS_RADIO_OWNER_LEGACY) {
        return JANOS_CONSOLE_BUSY_RADIO_LEASE;
    }
    if (is_always_safe(command, subcommand)) return JANOS_CONSOLE_ADMIT;

    bool analyzer_command = equals(command, "wifi_analyzer");
    bool wps_command = janos_wps_command_family_name(command);
    bool wps_uses_radio = janos_wps_named_operation_requires_radio(
        command, subcommand);

    if (owner == JANOS_RADIO_OWNER_LEGACY) {
        return analyzer_command || wps_uses_radio ||
               equals(command, "test_radio_channel") ||
               equals(command, "test_radio_channels") ?
            JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS : JANOS_CONSOLE_BUSY_RADIO_LEASE;
    }

    if (owner == JANOS_RADIO_OWNER_ANALYZER) {
        return analyzer_command || (wps_command && !wps_uses_radio) ?
            JANOS_CONSOLE_ADMIT : JANOS_CONSOLE_BUSY_RADIO_LEASE;
    }
    if (owner == JANOS_RADIO_OWNER_WPS) {
        return wps_command ? JANOS_CONSOLE_ADMIT :
                             JANOS_CONSOLE_BUSY_RADIO_LEASE;
    }
    if ((analyzer_command || wps_uses_radio ||
         equals(command, "test_radio_channel") ||
         equals(command, "test_radio_channels")) &&
        commands_inflight != 0U) {
        return JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS;
    }
    if (analyzer_busy && !analyzer_command &&
        !(wps_command && !wps_uses_radio)) {
        return JANOS_CONSOLE_BUSY_WIFI_ANALYZER;
    }
    return JANOS_CONSOLE_ADMIT;
}

janos_console_admission_result_t janos_console_admission_begin(
    janos_radio_lease_t *lease, const char *command, const char *subcommand,
    uint32_t commands_inflight, bool analyzer_busy,
    janos_console_admission_token_t *token)
{
    if (!lease || !token) return JANOS_CONSOLE_BUSY_RADIO_LEASE;
    *token = (janos_console_admission_token_t){0};
    janos_radio_lease_snapshot_t snapshot = janos_radio_lease_snapshot(lease);
    janos_console_admission_result_t result = janos_console_admission_decide(
        snapshot.owner, command, subcommand, commands_inflight, analyzer_busy);
    if (result != JANOS_CONSOLE_ADMIT) return result;
    /* WPS and analyzer acquire their long-lived lease before validating the
     * host baseline. Their own reservation rechecks any racing legacy start. */
    if (is_always_safe(command, subcommand) ||
        janos_wps_command_family_name(command) ||
        (equals(command, "wifi_analyzer") &&
                                     !equals(subcommand, "clear")))
        return JANOS_CONSOLE_ADMIT;
    if (janos_radio_lease_acquire(lease, JANOS_RADIO_OWNER_LEGACY,
                                 &token->generation) != JANOS_RADIO_LEASE_OK) {
        if (equals(command, "wifi_analyzer") && equals(subcommand, "clear") &&
            janos_radio_lease_snapshot(lease).owner == JANOS_RADIO_OWNER_ANALYZER)
            return JANOS_CONSOLE_BUSY_ANALYZER_CLEAR;
        return JANOS_CONSOLE_BUSY_RADIO_LEASE;
    }
    token->owner = JANOS_RADIO_OWNER_LEGACY;
    return JANOS_CONSOLE_ADMIT;
}

bool janos_console_admission_end(
    janos_radio_lease_t *lease, janos_console_admission_token_t token)
{
    if (token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U)
        return true;
    if (token.owner != JANOS_RADIO_OWNER_LEGACY || token.generation == 0U)
        return false;
    return janos_radio_lease_finish_startup(lease, token.owner, token.generation);
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
    case JANOS_CONSOLE_BUSY_ANALYZER_CLEAR:
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
        "[WFACTL1] {\"v\":1,\"type\":\"error\",\"command\":\"%s\","
        "\"code\":\"busy\",\"reason\":\"%s\"}",
        result == JANOS_CONSOLE_BUSY_ANALYZER_CLEAR ? "clear" : "console", reason);
    return written > 0 && (size_t)written < capacity;
}
