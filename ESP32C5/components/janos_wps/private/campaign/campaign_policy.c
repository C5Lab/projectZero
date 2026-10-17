#include "campaign_policy.h"

#include <ctype.h>
#include <string.h>

static int hex_nibble(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    value = (char)tolower((unsigned char)value);
    return value >= 'a' && value <= 'f' ? value - 'a' + 10 : -1;
}

static bool parse_bssid(const char *text, uint8_t output[6]) {
    if (!text || strlen(text) != 17U) return false;
    char separator = text[2];
    if (separator != ':' && separator != '-') return false;
    for (unsigned i = 0; i < 6U; ++i) {
        size_t offset = i * 3U;
        int high = hex_nibble(text[offset]);
        int low = hex_nibble(text[offset + 1U]);
        if (high < 0 || low < 0 || (i < 5U && text[offset + 2U] != separator))
            return false;
        output[i] = (uint8_t)((high << 4) | low);
    }
    static const uint8_t zero[6] = {0};
    return (output[0] & 1U) == 0U && memcmp(output, zero, sizeof(zero)) != 0;
}

static bool parse_pin(const char *text, char output[9]) {
    if (!text || strlen(text) != 8U) return false;
    unsigned digits[8];
    for (unsigned i = 0; i < 8U; ++i) {
        if (!isdigit((unsigned char)text[i])) return false;
        digits[i] = (unsigned)(text[i] - '0');
    }
    unsigned sum = 3U * (digits[0] + digits[2] + digits[4] + digits[6]) +
                   digits[1] + digits[3] + digits[5] + digits[7];
    if (sum % 10U != 0U) return false;
    memcpy(output, text, 9U);
    return true;
}

static unsigned split(char *text, char *parts[], unsigned capacity) {
    unsigned count = 0;
    char *cursor = text;
    while (*cursor) {
        while (isspace((unsigned char)*cursor)) ++cursor;
        if (!*cursor) break;
        if (count == capacity) return capacity + 1U;
        parts[count++] = cursor;
        while (*cursor && !isspace((unsigned char)*cursor)) ++cursor;
        if (*cursor) *cursor++ = '\0';
    }
    return count;
}

static bool parse_unsigned(const char *text, unsigned maximum, unsigned *value) {
    unsigned parsed = 0;
    if (!*text) return false;
    for (; *text; ++text) {
        if (*text < '0' || *text > '9') return false;
        unsigned digit = (unsigned)(*text - '0');
        if (digit > maximum || parsed > (maximum - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    *value = parsed;
    return true;
}

static bool parse_command(const char *line, campaign_command_t *command) {
    char copy[128];
    memcpy(copy, line, strlen(line) + 1U);
    char *parts[6];
    unsigned count = split(copy, parts, 6U);
    if (count < 2U || !parse_bssid(parts[1], command->bssid)) return false;

    if (strcmp(parts[0], "plan") == 0 && (count == 2U || count == 3U)) {
        command->type = CAMPAIGN_COMMAND_PLAN;
        if (count == 3U) {
            if (strlen(parts[2]) > 32U) return false;
            memcpy(command->ssid, parts[2], strlen(parts[2]) + 1U);
        }
        return true;
    }
    if (strcmp(parts[0], "verify") == 0 && count == 3U &&
        parse_pin(parts[2], command->pin)) {
        command->type = CAMPAIGN_COMMAND_VERIFY;
        command->count = 1U;
        return true;
    }
    if (strcmp(parts[0], "campaign") == 0 && (count == 4U || count == 5U)) {
        unsigned start, wanted;
        if (!parse_unsigned(parts[2], 127U, &start) ||
            !parse_unsigned(parts[3], 3U, &wanted) || wanted == 0U) return false;
        command->type = CAMPAIGN_COMMAND_RUN;
        command->start_index = (unsigned)start;
        command->count = (unsigned)wanted;
        if (count == 5U) {
            if (strlen(parts[4]) > 32U) return false;
            memcpy(command->ssid, parts[4], strlen(parts[4]) + 1U);
        }
        return true;
    }
    return false;
}

bool campaign_parse_command(const char *line, campaign_command_t *command) {
    if (!command) return false;
    memset(command, 0, sizeof(*command));
    if (!line || strlen(line) >= 128U) return false;
    for (const unsigned char *p = (const unsigned char *)line; *p; ++p) {
        if ((*p < 32U && *p != '\t' && *p != '\r' && *p != '\n') || *p > 126U)
            return false;
    }
    campaign_command_t parsed = {0};
    if (!parse_command(line, &parsed)) return false;
    *command = parsed;
    return true;
}

campaign_decision_t campaign_decide(wps_session_result_t result) {
    switch (result) {
    case WPS_SESSION_SUCCESS: return CAMPAIGN_DECISION_SUCCESS;
    case WPS_SESSION_PIN_REJECTED: return CAMPAIGN_DECISION_ADVANCE;
    case WPS_SESSION_SETUP_LOCKED: return CAMPAIGN_DECISION_LOCKED;
    case WPS_SESSION_TIMEOUT:
    case WPS_SESSION_IDENTITY_LOOP:
    case WPS_SESSION_DISCONNECTED:
    case WPS_SESSION_PRE_PIN_REJECTED:
        return CAMPAIGN_DECISION_PAUSE;
    default:
        return CAMPAIGN_DECISION_FATAL;
    }
}
