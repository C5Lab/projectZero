/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "janos_radio_lease.h"

typedef enum {
    JANOS_CONSOLE_ADMIT = 0,
    JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS,
    JANOS_CONSOLE_BUSY_RADIO_LEASE,
    JANOS_CONSOLE_BUSY_WIFI_ANALYZER,
    JANOS_CONSOLE_BUSY_ANALYZER_CLEAR,
} janos_console_admission_result_t;

/* Caller holds command/admission lock only for begin/end, never the handler.
 * The lease is the single owner record; a token is only a generation proof. */
typedef struct {
    janos_radio_owner_t owner;
    uint32_t generation;
} janos_console_admission_token_t;

janos_console_admission_result_t janos_console_admission_begin(
    janos_radio_lease_t *lease, const char *command, const char *subcommand,
    uint32_t commands_inflight, bool analyzer_busy,
    janos_console_admission_token_t *token);
bool janos_console_admission_end(
    janos_radio_lease_t *lease, janos_console_admission_token_t token);

janos_console_admission_result_t janos_console_admission_decide(
    janos_radio_owner_t owner,
    const char *command,
    const char *subcommand,
    uint32_t commands_inflight,
    bool analyzer_busy);

const char *janos_console_admission_reason(
    janos_console_admission_result_t result);

bool janos_console_admission_format(
    char *output,
    size_t capacity,
    janos_console_admission_result_t result);
