/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_wps_command.h"

#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static void secure_zero(void *memory, size_t size)
{
    volatile unsigned char *bytes = memory;
    while (bytes && size-- != 0U) *bytes++ = 0U;
}

void janos_wps_command_wipe(janos_wps_command_t *command)
{
    if (command) secure_zero(command, sizeof(*command));
}

static bool parse_bssid(const char *text, uint8_t output[6])
{
    if (!text || strlen(text) != 17U) return false;
    for (size_t i = 0; i < 6U; ++i) {
        size_t offset = i * 3U;
        bool first_hex = (text[offset] >= '0' && text[offset] <= '9') ||
                         (text[offset] >= 'a' && text[offset] <= 'f') ||
                         (text[offset] >= 'A' && text[offset] <= 'F');
        bool second_hex = (text[offset + 1U] >= '0' && text[offset + 1U] <= '9') ||
                          (text[offset + 1U] >= 'a' && text[offset + 1U] <= 'f') ||
                          (text[offset + 1U] >= 'A' && text[offset + 1U] <= 'F');
        if (!first_hex || !second_hex) return false;
        char pair[3] = {text[offset], text[offset + 1U], '\0'};
        char *end = NULL;
        unsigned long value = strtoul(pair, &end, 16);
        if (!end || *end != '\0' || value > 0xffUL) return false;
        output[i] = (uint8_t)value;
        if (i < 5U && text[offset + 2U] != ':') return false;
    }
    uint8_t any = 0U;
    uint8_t all_ff = 0xffU;
    for (size_t i = 0; i < 6U; ++i) {
        any |= output[i];
        all_ff &= output[i];
    }
    /* Locally administered BSSIDs are valid in real deployments.  Only the
     * IEEE group bit makes an address non-unicast. */
    return any != 0U && all_ff != 0xffU && (output[0] & 1U) == 0U;
}

static bool parse_unsigned(const char *text, unsigned long maximum,
                           unsigned long *value)
{
    if (!text || text[0] == '\0') return false;
    unsigned long parsed = 0U;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        unsigned digit = (unsigned)(*p - '0');
        if (digit > maximum || parsed > (maximum - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    *value = parsed;
    return true;
}

static bool valid_pin(const char *pin)
{
    if (!pin || strlen(pin) != 8U) return false;
    unsigned sum = 0U;
    for (size_t i = 0; i < 8U; ++i) {
        if (pin[i] < '0' || pin[i] > '9') return false;
        if (i < 7U)
            sum += (unsigned)(pin[i] - '0') * ((i & 1U) == 0U ? 3U : 1U);
    }
    return (10U - sum % 10U) % 10U == (unsigned)(pin[7] - '0');
}

static bool append_ssid(int argc, char **argv, int first, char output[33])
{
    size_t used = 0U;
    for (int i = first; i < argc; ++i) {
        const unsigned char *value = (const unsigned char *)argv[i];
        if (!value || value[0] == '\0') return false;
        size_t length = strlen((const char *)value);
        for (size_t j = 0; j < length; ++j)
            if (value[j] < 0x20U || value[j] == 0x7fU) return false;
        if (used != 0U) {
            if (used == 32U) return false;
            output[used++] = ' ';
        }
        if (length > 32U - used) return false;
        memcpy(output + used, value, length);
        used += length;
    }
    output[used] = '\0';
    return true;
}

bool janos_wps_operation_requires_radio(janos_wps_operation_t operation)
{
    return operation == JANOS_WPS_OP_VERIFY ||
           operation == JANOS_WPS_OP_PIXIE ||
           operation == JANOS_WPS_OP_JWPS_CAMPAIGN ||
           operation == JANOS_WPS_OP_SELFTEST_TRANSPORT;
}

const char *janos_wps_operation_name(janos_wps_operation_t operation)
{
    static const char *const names[] = {
        "invalid", "wps_verify", "wps_pixie", "jwps_plan",
        "jwps_campaign", "selftest_db", "selftest_fragment",
        "selftest_transport", "selftest_pixie"
    };
    return (unsigned)operation < sizeof(names) / sizeof(names[0]) ?
        names[operation] : "invalid";
}

bool janos_wps_command_family_name(const char *command)
{
    return command && (strcmp(command, "wps") == 0 ||
                       strcmp(command, "secret") == 0 ||
                       strcmp(command, "jwps") == 0 ||
                       strcmp(command, "selftest") == 0);
}

bool janos_wps_named_operation_requires_radio(const char *command,
                                               const char *subcommand)
{
    if (!command || !subcommand) return false;
    return (strcmp(command, "wps") == 0 &&
            (strcmp(subcommand, "verify") == 0 ||
             strcmp(subcommand, "pixie") == 0)) ||
           (strcmp(command, "jwps") == 0 &&
            strcmp(subcommand, "campaign") == 0) ||
           (strcmp(command, "selftest") == 0 &&
            strcmp(subcommand, "transport") == 0);
}

janos_wps_parse_result_t janos_wps_command_parse(
    int argc, char **argv, janos_wps_command_t *command)
{
    if (!command) return JANOS_WPS_PARSE_INVALID;
    janos_wps_command_wipe(command);
    if (!argv || argc < 2 || !argv[0] || !argv[1])
        return JANOS_WPS_PARSE_INVALID;

    if (strcmp(argv[0], "wps") == 0 && strcmp(argv[1], "verify") == 0) {
        if (argc != 4 || !parse_bssid(argv[2], command->bssid) ||
            !valid_pin(argv[3])) goto invalid;
        command->operation = JANOS_WPS_OP_VERIFY;
        memcpy(command->pin, argv[3], 9U);
        return JANOS_WPS_PARSE_OK;
    }
    if (strcmp(argv[0], "wps") == 0 && strcmp(argv[1], "pixie") == 0) {
        if ((argc != 3 && argc != 4) ||
            !parse_bssid(argv[2], command->bssid)) goto invalid;
        command->operation = JANOS_WPS_OP_PIXIE;
        if (argc == 4) {
            unsigned long epoch = 0U;
            if (!parse_unsigned(argv[3], UINT32_MAX, &epoch)) goto range;
            command->epoch = (uint32_t)epoch;
            command->epoch_set = true;
        }
        return JANOS_WPS_PARSE_OK;
    }
    if (strcmp(argv[0], "jwps") == 0 && strcmp(argv[1], "plan") == 0) {
        if (argc < 3 || !parse_bssid(argv[2], command->bssid) ||
            !append_ssid(argc, argv, 3, command->ssid)) goto invalid;
        command->operation = JANOS_WPS_OP_JWPS_PLAN;
        return JANOS_WPS_PARSE_OK;
    }
    if (strcmp(argv[0], "jwps") == 0 && strcmp(argv[1], "campaign") == 0) {
        unsigned long start = 0U, count = 0U;
        if (argc < 5 || !parse_bssid(argv[2], command->bssid) ||
            !parse_unsigned(argv[3], UINT_MAX, &start) ||
            !parse_unsigned(argv[4], 3U, &count) || count == 0U ||
            !append_ssid(argc, argv, 5, command->ssid)) goto range;
        command->operation = JANOS_WPS_OP_JWPS_CAMPAIGN;
        command->start_index = (unsigned)start;
        command->count = (unsigned)count;
        return JANOS_WPS_PARSE_OK;
    }
    if (strcmp(argv[0], "selftest") == 0 && argc == 2) {
        if (strcmp(argv[1], "db") == 0)
            command->operation = JANOS_WPS_OP_SELFTEST_DB;
        else if (strcmp(argv[1], "fragment") == 0)
            command->operation = JANOS_WPS_OP_SELFTEST_FRAGMENT;
        else if (strcmp(argv[1], "transport") == 0)
            command->operation = JANOS_WPS_OP_SELFTEST_TRANSPORT;
        else if (strcmp(argv[1], "pixie") == 0)
            command->operation = JANOS_WPS_OP_SELFTEST_PIXIE;
        else goto invalid;
        return JANOS_WPS_PARSE_OK;
    }
invalid:
    janos_wps_command_wipe(command);
    return JANOS_WPS_PARSE_INVALID;
range:
    janos_wps_command_wipe(command);
    return JANOS_WPS_PARSE_RANGE;
}
