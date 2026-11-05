#include "wifi_trust_store.h"

#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define READER_CHUNK 256U

typedef struct {
    const char *cur;
    const char *end;
} cursor_t;

typedef struct {
    void *handle;
    const wifi_trust_store_ops_t *ops;
    uint8_t bytes[READER_CHUNK];
    size_t pos;
    size_t length;
    size_t total;
    bool eof;
} reader_t;

typedef enum {
    LINE_OK = 0,
    LINE_EOF,
    LINE_IO,
    LINE_FORMAT,
    LINE_TOO_LARGE
} line_result_t;

static bool appendf(char *out, size_t capacity, size_t *used,
                    const char *format, ...)
{
    if (out == NULL || used == NULL || *used >= capacity) return false;
    va_list args;
    va_start(args, format);
    int length = vsnprintf(out + *used, capacity - *used, format, args);
    va_end(args);
    if (length < 0 || (size_t)length >= capacity - *used) return false;
    *used += (size_t)length;
    return true;
}

static const char *status_name(sx_status_t status)
{
    switch (status) {
    case SX_UNKNOWN: return "unknown";
    case SX_ABSENT: return "absent";
    case SX_VALID: return "valid";
    case SX_INVALID: return "invalid";
    default: return NULL;
    }
}

static const char *source_name(sx_source_t source)
{
    switch (source) {
    case SX_BEACON: return "beacon";
    case SX_PROBE_RESP: return "probe_response";
    default: return NULL;
    }
}

static bool profile_canonical(const wifi_trust_profile_t *profile)
{
    return wifi_trust_profile_valid(profile);
}

static bool append_hex(char *out, size_t capacity, size_t *used,
                       const uint8_t *bytes, size_t length, bool lower)
{
    static const char upper[] = "0123456789ABCDEF";
    static const char lower_digits[] = "0123456789abcdef";
    const char *digits = lower ? lower_digits : upper;
    if (!appendf(out, capacity, used, "\"")) return false;
    for (size_t i = 0; i < length; ++i) {
        if (!appendf(out, capacity, used, "%c%c", digits[bytes[i] >> 4],
                     digits[bytes[i] & 15U])) return false;
    }
    return appendf(out, capacity, used, "\"");
}

static bool append_nullable_hex(char *out, size_t capacity, size_t *used,
                                bool present, const uint8_t *bytes,
                                size_t length)
{
    return present ? append_hex(out, capacity, used, bytes, length, false) :
                     appendf(out, capacity, used, "null");
}

static bool append_selector_array(char *out, size_t capacity, size_t *used,
                                  bool known,
                                  const uint8_t selectors[SX_SELECTORS][4],
                                  uint8_t count)
{
    if (!known) return appendf(out, capacity, used, "null");
    if (!appendf(out, capacity, used, "[")) return false;
    for (uint8_t i = 0; i < count; ++i) {
        if (i != 0U && !appendf(out, capacity, used, ",")) return false;
        if (!append_hex(out, capacity, used, selectors[i], 4U, false))
            return false;
    }
    return appendf(out, capacity, used, "]");
}

static bool append_nullable_bool(char *out, size_t capacity, size_t *used,
                                 bool known, bool value)
{
    return appendf(out, capacity, used, known ? (value ? "true" : "false") :
                                               "null");
}

static bool append_security(char *out, size_t capacity, size_t *used,
                            const char *prefix, const sx_security_t *security)
{
    const char *status = status_name(security->status);
    if (status == NULL || !appendf(out, capacity, used, "\"%s_status\":\"%s\",",
                                   prefix, status) ||
        !appendf(out, capacity, used, "\"%s_group\":", prefix) ||
        !append_nullable_hex(out, capacity, used,
                             security->status == SX_VALID &&
                             security->group_present, security->group, 4U) ||
        !appendf(out, capacity, used, ",\"%s_pairwise\":", prefix) ||
        !append_selector_array(out, capacity, used,
                               security->status == SX_VALID &&
                               security->pairwise_known,
                               security->pairwise, security->pairwise_count) ||
        !appendf(out, capacity, used, ",\"%s_akm\":", prefix) ||
        !append_selector_array(out, capacity, used,
                               security->status == SX_VALID &&
                               security->akm_known,
                               security->akm, security->akm_count) ||
        !appendf(out, capacity, used,
                 ",\"%s_capabilities_present\":%s,\"%s_pmf_capable\":",
                 prefix, security->status == SX_VALID &&
                         security->capabilities_present ? "true" : "false",
                 prefix) ||
        !append_nullable_bool(out, capacity, used,
                              security->status == SX_VALID &&
                              security->capabilities_present,
                              security->pmf_capable) ||
        !appendf(out, capacity, used, ",\"%s_pmf_required\":", prefix) ||
        !append_nullable_bool(out, capacity, used,
                              security->status == SX_VALID &&
                              security->capabilities_present,
                              security->pmf_required) ||
        !appendf(out, capacity, used, ",\"%s_management\":", prefix) ||
        !append_nullable_hex(out, capacity, used,
                             security->status == SX_VALID &&
                             security->management_present,
                             security->management, 4U)) return false;
    return true;
}

static bool append_nullable_i32(char *out, size_t capacity, size_t *used,
                                bool known, int32_t value)
{
    return known ? appendf(out, capacity, used, "%" PRId32, value) :
                   appendf(out, capacity, used, "null");
}

static bool append_wps_text(char *out, size_t capacity, size_t *used,
                            const char *name, const sx_text_t *text,
                            bool valid_wps)
{
    bool present = valid_wps && text->present;
    if (!appendf(out, capacity, used, "\"wps_%s_hex\":", name) ||
        !append_nullable_hex(out, capacity, used, present, text->bytes,
                             present ? text->len : 0U) ||
        !appendf(out, capacity, used, ",\"wps_%s_truncated\":", name))
        return false;
    return present ? appendf(out, capacity, used,
                             text->truncated ? "true" : "false") :
                     appendf(out, capacity, used, "null");
}

int wifi_trust_store_format_ap_line(char *out, size_t capacity,
                                    const wifi_trust_profile_t *profile)
{
    if (out == NULL || capacity == 0U || !profile_canonical(profile)) return -1;
    char line[WIFI_TRUST_JSON_LINE_MAX];
    size_t used = 0U;
    const char *ssid_status = status_name(profile->ssid_status);
    const char *source = source_name(profile->source);
    const char *rsnxe_status = status_name(profile->rsnxe.status);
    const char *wps_status = status_name(profile->wps.status);
    const char *country_status = status_name(profile->country.status);
    bool wps_valid = profile->wps.status == SX_VALID;
    if (ssid_status == NULL || source == NULL || rsnxe_status == NULL ||
        wps_status == NULL || country_status == NULL ||
        !appendf(line, sizeof(line), &used,
                 "{\"v\":1,\"type\":\"ap\",\"bssid\":") ||
        !append_hex(line, sizeof(line), &used, profile->bssid, 6U, true) ||
        !appendf(line, sizeof(line), &used,
                 ",\"ssid_status\":\"%s\",\"ssid_hex\":", ssid_status) ||
        !append_nullable_hex(line, sizeof(line), &used,
                             profile->ssid_status == SX_VALID,
                             profile->ssid, profile->ssid_len) ||
        !appendf(line, sizeof(line), &used,
                 ",\"source\":\"%s\",\"privacy\":%d,",
                 source, (int)profile->privacy) ||
        !append_security(line, sizeof(line), &used, "rsn", &profile->rsn) ||
        !appendf(line, sizeof(line), &used, ",") ||
        !append_security(line, sizeof(line), &used, "wpa", &profile->wpa) ||
        !appendf(line, sizeof(line), &used,
                 ",\"rsnxe_status\":\"%s\",\"rsnxe_hex\":",
                 rsnxe_status) ||
        !append_nullable_hex(line, sizeof(line), &used,
                             profile->rsnxe.status == SX_VALID,
                             profile->rsnxe.bytes, profile->rsnxe.len) ||
        !appendf(line, sizeof(line), &used,
                 ",\"wps_status\":\"%s\",\"wps_present\":%s,"
                 "\"wps_state\":", wps_status,
                 wps_valid && profile->wps.present ? "true" : "false") ||
        !append_nullable_i32(line, sizeof(line), &used,
                             wps_valid && profile->wps.state >= 0,
                             profile->wps.state) ||
        !appendf(line, sizeof(line), &used, ",\"wps_config_methods\":") ||
        !append_nullable_i32(line, sizeof(line), &used,
                             wps_valid && profile->wps.config_methods >= 0,
                             profile->wps.config_methods) ||
        !appendf(line, sizeof(line), &used, ",\"wps_setup_locked\":") ||
        !append_nullable_bool(line, sizeof(line), &used,
                              wps_valid && profile->wps.setup_locked >= 0,
                              profile->wps.setup_locked == 1) ||
        !appendf(line, sizeof(line), &used,
                 ",\"wps_selected_registrar\":") ||
        !append_nullable_bool(line, sizeof(line), &used,
                              wps_valid &&
                              profile->wps.selected_registrar >= 0,
                              profile->wps.selected_registrar == 1) ||
        !appendf(line, sizeof(line), &used, ",") ||
        !append_wps_text(line, sizeof(line), &used, "manufacturer",
                         &profile->wps.manufacturer, wps_valid) ||
        !appendf(line, sizeof(line), &used, ",") ||
        !append_wps_text(line, sizeof(line), &used, "model_name",
                         &profile->wps.model_name, wps_valid) ||
        !appendf(line, sizeof(line), &used, ",") ||
        !append_wps_text(line, sizeof(line), &used, "model_number",
                         &profile->wps.model_number, wps_valid) ||
        !appendf(line, sizeof(line), &used, ",") ||
        !append_wps_text(line, sizeof(line), &used, "device_name",
                         &profile->wps.device_name, wps_valid) ||
        !appendf(line, sizeof(line), &used,
                 ",\"country_status\":\"%s\",\"country_hex\":",
                 country_status) ||
        !append_nullable_hex(line, sizeof(line), &used,
                             profile->country.status == SX_VALID,
                             profile->country.code, 3U) ||
        !appendf(line, sizeof(line), &used,
                 ",\"channel\":%u,\"observed_us\":%" PRIu64 "}",
                 (unsigned)profile->channel, profile->observed_us)) return -1;
    if (used >= capacity) return -1;
    memcpy(out, line, used + 1U);
    return (int)used;
}

static bool take(cursor_t *cursor, const char *literal)
{
    size_t length = strlen(literal);
    if ((size_t)(cursor->end - cursor->cur) < length ||
        memcmp(cursor->cur, literal, length) != 0) return false;
    cursor->cur += length;
    return true;
}

static bool parse_string(cursor_t *cursor, const char **start, size_t *length)
{
    if (cursor->cur == cursor->end || *cursor->cur != '"') return false;
    const char *begin = ++cursor->cur;
    while (cursor->cur != cursor->end && *cursor->cur != '"') {
        unsigned char value = (unsigned char)*cursor->cur;
        if (value < 0x20U || value == '\\') return false;
        ++cursor->cur;
    }
    if (cursor->cur == cursor->end) return false;
    *start = begin;
    *length = (size_t)(cursor->cur - begin);
    ++cursor->cur;
    return true;
}

static bool token_equals(const char *start, size_t length, const char *token)
{
    return length == strlen(token) && memcmp(start, token, length) == 0;
}

static bool parse_status(cursor_t *cursor, sx_status_t *status)
{
    const char *start;
    size_t length;
    if (!parse_string(cursor, &start, &length)) return false;
    if (token_equals(start, length, "unknown")) *status = SX_UNKNOWN;
    else if (token_equals(start, length, "absent")) *status = SX_ABSENT;
    else if (token_equals(start, length, "valid")) *status = SX_VALID;
    else if (token_equals(start, length, "invalid")) *status = SX_INVALID;
    else return false;
    return true;
}

static int hex_digit(char value, bool lower_only, bool upper_only)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (!upper_only && value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (!lower_only && value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static bool decode_hex_text(const char *start, size_t length, uint8_t *out,
                            size_t capacity, size_t *decoded,
                            bool lower_only, bool upper_only)
{
    if ((length & 1U) != 0U || length / 2U > capacity) return false;
    for (size_t i = 0; i < length / 2U; ++i) {
        int high = hex_digit(start[i * 2U], lower_only, upper_only);
        int low = hex_digit(start[i * 2U + 1U], lower_only, upper_only);
        if (high < 0 || low < 0) return false;
        out[i] = (uint8_t)((unsigned)high * 16U + (unsigned)low);
    }
    *decoded = length / 2U;
    return true;
}

static bool parse_hex(cursor_t *cursor, uint8_t *out, size_t capacity,
                      size_t *decoded, bool nullable, bool *present,
                      bool lower_only, bool upper_only)
{
    if (nullable && take(cursor, "null")) {
        *present = false;
        *decoded = 0U;
        memset(out, 0, capacity);
        return true;
    }
    const char *start;
    size_t length;
    if (!parse_string(cursor, &start, &length)) return false;
    memset(out, 0, capacity);
    if (!decode_hex_text(start, length, out, capacity, decoded,
                         lower_only, upper_only)) return false;
    *present = true;
    return true;
}

static bool parse_u64(cursor_t *cursor, uint64_t *value)
{
    if (cursor->cur == cursor->end || *cursor->cur < '0' ||
        *cursor->cur > '9') return false;
    if (*cursor->cur == '0' && cursor->cur + 1 != cursor->end &&
        cursor->cur[1] >= '0' && cursor->cur[1] <= '9') return false;
    uint64_t parsed = 0U;
    do {
        unsigned digit = (unsigned)(*cursor->cur - '0');
        if (parsed > (UINT64_MAX - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
        ++cursor->cur;
    } while (cursor->cur != cursor->end && *cursor->cur >= '0' &&
             *cursor->cur <= '9');
    *value = parsed;
    return true;
}

static bool parse_i32(cursor_t *cursor, int32_t *value)
{
    bool negative = cursor->cur != cursor->end && *cursor->cur == '-';
    if (negative) ++cursor->cur;
    uint64_t magnitude;
    if (!parse_u64(cursor, &magnitude)) return false;
    if ((!negative && magnitude > INT32_MAX) ||
        (negative && magnitude > (uint64_t)INT32_MAX + 1U)) return false;
    if (negative && magnitude == 0U) return false;
    *value = negative ?
        magnitude == (uint64_t)INT32_MAX + 1U ? INT32_MIN :
            -(int32_t)magnitude : (int32_t)magnitude;
    return true;
}

static bool parse_bool(cursor_t *cursor, bool nullable, bool *known,
                       bool *value)
{
    if (nullable && take(cursor, "null")) {
        *known = false;
        *value = false;
        return true;
    }
    *known = true;
    if (take(cursor, "true")) *value = true;
    else if (take(cursor, "false")) *value = false;
    else return false;
    return true;
}

static bool parse_nullable_i32(cursor_t *cursor, bool *known, int32_t *value)
{
    if (take(cursor, "null")) {
        *known = false;
        *value = -1;
        return true;
    }
    *known = true;
    return parse_i32(cursor, value);
}

static bool parse_selector_array(cursor_t *cursor, bool *known,
                                 uint8_t selectors[SX_SELECTORS][4],
                                 uint8_t *count)
{
    memset(selectors, 0, SX_SELECTORS * 4U);
    *count = 0U;
    if (take(cursor, "null")) {
        *known = false;
        return true;
    }
    if (!take(cursor, "[")) return false;
    *known = true;
    if (take(cursor, "]")) return true;
    for (;;) {
        if (*count >= SX_SELECTORS) return false;
        size_t decoded;
        bool present;
        if (!parse_hex(cursor, selectors[*count], 4U, &decoded, false,
                       &present, false, true) || !present || decoded != 4U)
            return false;
        ++*count;
        if (take(cursor, "]")) return true;
        if (!take(cursor, ",")) return false;
    }
}

static bool parse_security(cursor_t *cursor, const char *prefix,
                           sx_security_t *security)
{
    char key[64];
    memset(security, 0, sizeof(*security));
    snprintf(key, sizeof(key), "\"%s_status\":", prefix);
    if (!take(cursor, key) || !parse_status(cursor, &security->status))
        return false;
    snprintf(key, sizeof(key), ",\"%s_group\":", prefix);
    bool present;
    size_t decoded;
    if (!take(cursor, key) ||
        !parse_hex(cursor, security->group, 4U, &decoded, true, &present,
                   false, true) || (present && decoded != 4U)) return false;
    security->group_present = present;
    snprintf(key, sizeof(key), ",\"%s_pairwise\":", prefix);
    if (!take(cursor, key) ||
        !parse_selector_array(cursor, &security->pairwise_known,
                              security->pairwise,
                              &security->pairwise_count)) return false;
    snprintf(key, sizeof(key), ",\"%s_akm\":", prefix);
    if (!take(cursor, key) ||
        !parse_selector_array(cursor, &security->akm_known, security->akm,
                              &security->akm_count)) return false;
    snprintf(key, sizeof(key), ",\"%s_capabilities_present\":", prefix);
    bool known;
    if (!take(cursor, key) ||
        !parse_bool(cursor, false, &known, &security->capabilities_present) ||
        !known) return false;
    snprintf(key, sizeof(key), ",\"%s_pmf_capable\":", prefix);
    bool pmf_known;
    if (!take(cursor, key) ||
        !parse_bool(cursor, true, &pmf_known, &security->pmf_capable))
        return false;
    snprintf(key, sizeof(key), ",\"%s_pmf_required\":", prefix);
    bool required_known;
    if (!take(cursor, key) ||
        !parse_bool(cursor, true, &required_known, &security->pmf_required))
        return false;
    snprintf(key, sizeof(key), ",\"%s_management\":", prefix);
    if (!take(cursor, key) ||
        !parse_hex(cursor, security->management, 4U, &decoded, true, &present,
                   false, true) || (present && decoded != 4U)) return false;
    security->management_present = present;
    if (security->status != SX_VALID) {
        if (security->group_present || security->pairwise_known ||
            security->akm_known || security->capabilities_present ||
            pmf_known || required_known || security->management_present)
            return false;
    } else if (security->capabilities_present != pmf_known ||
               pmf_known != required_known) return false;
    return true;
}

static bool parse_wps_text(cursor_t *cursor, const char *name,
                           sx_text_t *text)
{
    char key[64];
    memset(text, 0, sizeof(*text));
    snprintf(key, sizeof(key), "\"wps_%s_hex\":", name);
    size_t decoded;
    bool present;
    if (!take(cursor, key) ||
        !parse_hex(cursor, text->bytes, SX_TEXT_BYTES, &decoded, true,
                   &present, false, true)) return false;
    text->present = present;
    text->len = (uint8_t)decoded;
    snprintf(key, sizeof(key), ",\"wps_%s_truncated\":", name);
    bool known;
    if (!take(cursor, key) ||
        !parse_bool(cursor, true, &known, &text->truncated)) return false;
    return present == known;
}

bool wifi_trust_store_parse_ap_line(const char *line, size_t length,
                                    wifi_trust_profile_t *profile)
{
    if (line == NULL || profile == NULL || length == 0U ||
        length >= WIFI_TRUST_JSON_LINE_MAX) return false;
    wifi_trust_profile_t parsed;
    memset(&parsed, 0, sizeof(parsed));
    parsed.privacy = -1;
    parsed.wps.state = parsed.wps.config_methods = parsed.wps.setup_locked =
        parsed.wps.selected_registrar = -1;
    cursor_t cursor = {.cur = line, .end = line + length};
    size_t decoded;
    bool present;
    const char *token;
    size_t token_length;
    if (!take(&cursor, "{\"v\":1,\"type\":\"ap\",\"bssid\":") ||
        !parse_hex(&cursor, parsed.bssid, 6U, &decoded, false, &present,
                   true, false) || !present || decoded != 6U ||
        !take(&cursor, ",\"ssid_status\":") ||
        !parse_status(&cursor, &parsed.ssid_status) ||
        !take(&cursor, ",\"ssid_hex\":") ||
        !parse_hex(&cursor, parsed.ssid, sizeof(parsed.ssid), &decoded, true,
                   &present, false, true) ||
        !take(&cursor, ",\"source\":") ||
        !parse_string(&cursor, &token, &token_length)) return false;
    parsed.ssid_len = (uint8_t)decoded;
    if (parsed.ssid_status == SX_VALID) {
        if (!present) return false;
    } else if (present) return false;
    if (token_equals(token, token_length, "beacon")) parsed.source = SX_BEACON;
    else if (token_equals(token, token_length, "probe_response"))
        parsed.source = SX_PROBE_RESP;
    else return false;
    int32_t number;
    if (!take(&cursor, ",\"privacy\":") || !parse_i32(&cursor, &number) ||
        number < INT8_MIN || number > INT8_MAX) return false;
    parsed.privacy = (int8_t)number;
    if (!take(&cursor, ",") || !parse_security(&cursor, "rsn", &parsed.rsn) ||
        !take(&cursor, ",") || !parse_security(&cursor, "wpa", &parsed.wpa) ||
        !take(&cursor, ",\"rsnxe_status\":") ||
        !parse_status(&cursor, &parsed.rsnxe.status) ||
        !take(&cursor, ",\"rsnxe_hex\":") ||
        !parse_hex(&cursor, parsed.rsnxe.bytes, SX_RSNXE_BYTES, &decoded, true,
                   &present, false, true)) return false;
    parsed.rsnxe.present = present;
    parsed.rsnxe.len = (uint8_t)decoded;
    if ((parsed.rsnxe.status == SX_VALID) != present) return false;
    if (!take(&cursor, ",\"wps_status\":") ||
        !parse_status(&cursor, &parsed.wps.status) ||
        !take(&cursor, ",\"wps_present\":")) return false;
    bool known;
    if (!parse_bool(&cursor, false, &known, &parsed.wps.present) || !known ||
        !take(&cursor, ",\"wps_state\":") ||
        !parse_nullable_i32(&cursor, &known, &number)) return false;
    parsed.wps.state = known ? number : -1;
    if (!take(&cursor, ",\"wps_config_methods\":") ||
        !parse_nullable_i32(&cursor, &known, &number)) return false;
    parsed.wps.config_methods = known ? number : -1;
    bool bool_value;
    if (!take(&cursor, ",\"wps_setup_locked\":") ||
        !parse_bool(&cursor, true, &known, &bool_value)) return false;
    parsed.wps.setup_locked = known ? (bool_value ? 1 : 0) : -1;
    if (!take(&cursor, ",\"wps_selected_registrar\":") ||
        !parse_bool(&cursor, true, &known, &bool_value)) return false;
    parsed.wps.selected_registrar = known ? (bool_value ? 1 : 0) : -1;
    if (!take(&cursor, ",") ||
        !parse_wps_text(&cursor, "manufacturer", &parsed.wps.manufacturer) ||
        !take(&cursor, ",") ||
        !parse_wps_text(&cursor, "model_name", &parsed.wps.model_name) ||
        !take(&cursor, ",") ||
        !parse_wps_text(&cursor, "model_number", &parsed.wps.model_number) ||
        !take(&cursor, ",") ||
        !parse_wps_text(&cursor, "device_name", &parsed.wps.device_name) ||
        !take(&cursor, ",\"country_status\":") ||
        !parse_status(&cursor, &parsed.country.status) ||
        !take(&cursor, ",\"country_hex\":") ||
        !parse_hex(&cursor, parsed.country.code, 3U, &decoded, true, &present,
                   false, true) ||
        (present && decoded != 3U) ||
        ((parsed.country.status == SX_VALID) != present) ||
        !take(&cursor, ",\"channel\":")) return false;
    uint64_t value;
    if (!parse_u64(&cursor, &value) || value > UINT8_MAX) return false;
    parsed.channel = (uint8_t)value;
    if (!take(&cursor, ",\"observed_us\":") ||
        !parse_u64(&cursor, &parsed.observed_us) || !take(&cursor, "}") ||
        cursor.cur != cursor.end || !profile_canonical(&parsed)) return false;
    *profile = parsed;
    return true;
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8U; ++bit)
            crc = (crc >> 1U) ^ (UINT32_C(0xedb88320) &
                                (uint32_t)-(int32_t)(crc & 1U));
    }
    return crc;
}

static bool format_header(char *out, size_t capacity, size_t count,
                          const wifi_trust_store_meta_t *meta)
{
    size_t used = 0U;
    if (!appendf(out, capacity, &used,
                 "{\"v\":1,\"type\":\"header\",\"count\":%zu,\"boot\":",
                 count) ||
        !append_hex(out, capacity, &used, meta->boot_id, 8U, true) ||
        !appendf(out, capacity, &used, ",\"created_unix\":")) return false;
    if (meta->created_unix_known) {
        if (!appendf(out, capacity, &used, "%" PRIu64, meta->created_unix))
            return false;
    } else if (!appendf(out, capacity, &used, "null")) return false;
    return appendf(out, capacity, &used, ",\"created_us\":%" PRIu64 "}",
                   meta->created_monotonic_us);
}

static bool parse_header(const char *line, size_t length, size_t *count,
                         wifi_trust_store_meta_t *meta)
{
    cursor_t cursor = {.cur = line, .end = line + length};
    uint64_t value;
    size_t decoded;
    bool present;
    if (!take(&cursor, "{\"v\":1,\"type\":\"header\",\"count\":") ||
        !parse_u64(&cursor, &value) || value > SIZE_MAX)
        return false;
    *count = (size_t)value;
    if (!take(&cursor, ",\"boot\":") ||
        !parse_hex(&cursor, meta->boot_id, 8U, &decoded, false, &present,
                   true, false) || !present || decoded != 8U ||
        !take(&cursor, ",\"created_unix\":")) return false;
    if (take(&cursor, "null")) {
        meta->created_unix_known = false;
        meta->created_unix = 0U;
    } else {
        meta->created_unix_known = true;
        if (!parse_u64(&cursor, &meta->created_unix)) return false;
    }
    return take(&cursor, ",\"created_us\":") &&
           parse_u64(&cursor, &meta->created_monotonic_us) &&
           take(&cursor, "}") && cursor.cur == cursor.end;
}

static bool format_end(char *out, size_t capacity, size_t count, uint32_t crc)
{
    int length = snprintf(out, capacity,
        "{\"v\":1,\"type\":\"end\",\"count\":%zu,\"crc32\":\"%08" PRIX32 "\"}",
        count, crc);
    return length > 0 && (size_t)length < capacity;
}

static bool parse_end(const char *line, size_t length, size_t expected_count,
                      uint32_t expected_crc)
{
    char wanted[128];
    if (!format_end(wanted, sizeof(wanted), expected_count, expected_crc))
        return false;
    return length == strlen(wanted) && memcmp(line, wanted, length) == 0;
}

static wifi_trust_recovery_action_t recovery_action(fs_recovery_result_t result)
{
    switch (result) {
    case FS_RECOVERY_CLEARED_STAGE: return WIFI_TRUST_RECOVERY_CLEARED_STAGE;
    case FS_RECOVERY_RESTORED_BACKUP:
        return WIFI_TRUST_RECOVERY_RESTORED_BACKUP;
    case FS_RECOVERY_KEPT_TARGET: return WIFI_TRUST_RECOVERY_KEPT_TARGET;
    case FS_RECOVERY_NONE:
    case FS_RECOVERY_FAILED:
    default: return WIFI_TRUST_RECOVERY_NONE;
    }
}

static bool lock_ops_valid(const wifi_trust_store_ops_t *ops)
{
    return ops != NULL && ops->enter != NULL && ops->leave != NULL &&
           ops->recover_staged != NULL;
}

static bool load_ops_valid(const wifi_trust_store_ops_t *ops)
{
    return lock_ops_valid(ops) && ops->open != NULL && ops->read != NULL &&
           ops->close != NULL;
}

static bool readonly_load_ops_valid(const wifi_trust_store_ops_t *ops)
{
    return ops != NULL && ops->enter != NULL && ops->leave != NULL &&
           ops->open != NULL && ops->read != NULL && ops->close != NULL;
}

static bool publish_ops_valid(const wifi_trust_store_ops_t *ops)
{
    return lock_ops_valid(ops) && ops->open != NULL && ops->write != NULL &&
           ops->flush != NULL && ops->sync != NULL && ops->close != NULL &&
           ops->remove_path != NULL && ops->sync_volume != NULL &&
           ops->publish_staged != NULL;
}

static bool clear_ops_valid(const wifi_trust_store_ops_t *ops)
{
    return lock_ops_valid(ops) && ops->path_state != NULL &&
           ops->rename_path != NULL && ops->remove_path != NULL &&
           ops->sync_volume != NULL;
}

static line_result_t refill(reader_t *reader)
{
    if (reader->eof) return LINE_EOF;
    size_t actual = 0U;
    wifi_trust_io_result_t result = reader->ops->read(
        reader->handle, reader->bytes, sizeof(reader->bytes), &actual);
    if (result == WIFI_TRUST_IO_EOF) {
        if (actual != 0U) return LINE_IO;
        reader->eof = true;
        return LINE_EOF;
    }
    if (result != WIFI_TRUST_IO_OK || actual == 0U ||
        actual > sizeof(reader->bytes)) return LINE_IO;
    reader->pos = 0U;
    reader->length = actual;
    return LINE_OK;
}

static line_result_t read_line(reader_t *reader, char *line, size_t capacity,
                               size_t *length)
{
    *length = 0U;
    for (;;) {
        if (reader->pos == reader->length) {
            line_result_t result = refill(reader);
            if (result == LINE_EOF)
                return *length == 0U ? LINE_EOF : LINE_FORMAT;
            if (result != LINE_OK) return result;
        }
        uint8_t value = reader->bytes[reader->pos++];
        if (++reader->total > WIFI_TRUST_FILE_MAX) return LINE_TOO_LARGE;
        if (value == '\r') return LINE_FORMAT;
        if (value == '\n') {
            if (*length == 0U) return LINE_FORMAT;
            line[*length] = '\0';
            return LINE_OK;
        }
        if (*length + 1U >= capacity) return LINE_TOO_LARGE;
        line[(*length)++] = (char)value;
    }
}

static bool write_exact(const wifi_trust_store_ops_t *ops, void *handle,
                        const char *line, size_t length)
{
    size_t actual = 0U;
    if (ops->write(handle, (const uint8_t *)line, length, &actual) !=
        WIFI_TRUST_IO_OK || actual != length) return false;
    const uint8_t lf = '\n';
    actual = 0U;
    return ops->write(handle, &lf, 1U, &actual) == WIFI_TRUST_IO_OK &&
           actual == 1U;
}

static int bssid_compare(const wifi_trust_profile_t *left,
                         const wifi_trust_profile_t *right)
{
    return memcmp(left->bssid, right->bssid, 6U);
}

static wifi_trust_store_result_t line_failure(line_result_t result)
{
    if (result == LINE_TOO_LARGE) return WIFI_TRUST_STORE_CAPACITY;
    if (result == LINE_IO) return WIFI_TRUST_STORE_IO;
    return WIFI_TRUST_STORE_FORMAT;
}

static wifi_trust_store_result_t wifi_trust_store_load_impl(
    const char *path, wifi_trust_profile_t *profiles, size_t capacity,
    size_t *count, wifi_trust_store_meta_t *meta,
    wifi_trust_recovery_action_t *recovery,
    const wifi_trust_store_ops_t *ops, bool recover)
{
    if (count != NULL) *count = 0U;
    if (meta != NULL) memset(meta, 0, sizeof(*meta));
    if (recovery != NULL) *recovery = WIFI_TRUST_RECOVERY_NONE;
    if (profiles != NULL && capacity <= WIFI_TRUST_MAX_PROFILES)
        memset(profiles, 0, capacity * sizeof(*profiles));
    if (path == NULL || strcmp(path, WIFI_TRUST_STORE_PATH) != 0 ||
        count == NULL || meta == NULL || recovery == NULL ||
        !(recover ? load_ops_valid(ops) : readonly_load_ops_valid(ops)) ||
        capacity > WIFI_TRUST_MAX_PROFILES ||
        (capacity != 0U && profiles == NULL)) return WIFI_TRUST_STORE_IO;
    if (!ops->enter(ops->context)) return WIFI_TRUST_STORE_IO;
    wifi_trust_store_result_t result = WIFI_TRUST_STORE_IO;
    void *handle = NULL;
    if (recover) {
        fs_recovery_result_t recovered = ops->recover_staged(
            ops->context, WIFI_TRUST_STAGE_PATH, WIFI_TRUST_STORE_PATH,
            WIFI_TRUST_BACKUP_PATH);
        if (recovered == FS_RECOVERY_FAILED) {
            result = WIFI_TRUST_STORE_RECOVERY;
            goto done;
        }
        *recovery = recovery_action(recovered);
    }
    wifi_trust_io_result_t opened = ops->open(ops->context, path, false,
                                               &handle);
    if (opened == WIFI_TRUST_IO_MISSING) {
        result = WIFI_TRUST_STORE_NOT_FOUND;
        goto done;
    }
    if (opened != WIFI_TRUST_IO_OK || handle == NULL) goto done;
    reader_t reader = {.handle = handle, .ops = ops};
    char line[WIFI_TRUST_JSON_LINE_MAX];
    size_t length = 0U;
    size_t expected_count = 0U;
    wifi_trust_store_meta_t parsed_meta;
    memset(&parsed_meta, 0, sizeof(parsed_meta));
    line_result_t line_result = read_line(&reader, line, sizeof(line), &length);
    if (line_result != LINE_OK ||
        !parse_header(line, length, &expected_count, &parsed_meta)) {
        result = line_failure(line_result);
        goto close;
    }
    if (expected_count > WIFI_TRUST_MAX_PROFILES || expected_count > capacity) {
        result = WIFI_TRUST_STORE_CAPACITY;
        goto close;
    }
    uint32_t crc = UINT32_MAX;
    uint8_t previous[6] = {0};
    bool have_previous = false;
    for (size_t i = 0; i < expected_count; ++i) {
        line_result = read_line(&reader, line, sizeof(line), &length);
        if (line_result != LINE_OK ||
            !wifi_trust_store_parse_ap_line(line, length, &profiles[i]) ||
            (have_previous && memcmp(previous, profiles[i].bssid, 6U) >= 0)) {
            result = line_failure(line_result);
            goto close;
        }
        memcpy(previous, profiles[i].bssid, 6U);
        have_previous = true;
        crc = crc32_update(crc, (const uint8_t *)line, length);
        const uint8_t lf = '\n';
        crc = crc32_update(crc, &lf, 1U);
    }
    crc ^= UINT32_MAX;
    line_result = read_line(&reader, line, sizeof(line), &length);
    if (line_result != LINE_OK || !parse_end(line, length, expected_count, crc)) {
        result = line_failure(line_result);
        goto close;
    }
    line_result = read_line(&reader, line, sizeof(line), &length);
    if (line_result != LINE_EOF) {
        result = line_failure(line_result);
        goto close;
    }
    *count = expected_count;
    *meta = parsed_meta;
    result = WIFI_TRUST_STORE_OK;
close:
    if (ops->close(handle) != WIFI_TRUST_IO_OK &&
        result == WIFI_TRUST_STORE_OK) result = WIFI_TRUST_STORE_IO;
    handle = NULL;
done:
    if (handle != NULL) (void)ops->close(handle);
    if (result != WIFI_TRUST_STORE_OK) {
        if (profiles != NULL) memset(profiles, 0, capacity * sizeof(*profiles));
        *count = 0U;
        memset(meta, 0, sizeof(*meta));
    }
    ops->leave(ops->context);
    return result;
}

wifi_trust_store_result_t wifi_trust_store_load(
    const char *path, wifi_trust_profile_t *profiles, size_t capacity,
    size_t *count, wifi_trust_store_meta_t *meta,
    wifi_trust_recovery_action_t *recovery,
    const wifi_trust_store_ops_t *ops)
{
    return wifi_trust_store_load_impl(path, profiles, capacity, count, meta,
                                      recovery, ops, true);
}

wifi_trust_store_result_t wifi_trust_store_load_readonly(
    const char *path, wifi_trust_profile_t *profiles, size_t capacity,
    size_t *count, wifi_trust_store_meta_t *meta,
    const wifi_trust_store_ops_t *ops)
{
    wifi_trust_recovery_action_t recovery = WIFI_TRUST_RECOVERY_NONE;
    return wifi_trust_store_load_impl(path, profiles, capacity, count, meta,
                                      &recovery, ops, false);
}

wifi_trust_store_result_t wifi_trust_store_publish(
    const wifi_trust_profile_t *profiles, size_t count,
    const wifi_trust_store_meta_t *meta,
    const wifi_trust_store_ops_t *ops)
{
    if (!publish_ops_valid(ops) || meta == NULL ||
        (!meta->created_unix_known && meta->created_unix != 0U) ||
        (count != 0U && profiles == NULL)) return WIFI_TRUST_STORE_IO;
    if (count > WIFI_TRUST_MAX_PROFILES) return WIFI_TRUST_STORE_CAPACITY;
    if (!ops->enter(ops->context)) return WIFI_TRUST_STORE_IO;
    wifi_trust_store_result_t result = WIFI_TRUST_STORE_IO;
    fs_recovery_result_t recovered = ops->recover_staged(
        ops->context, WIFI_TRUST_STAGE_PATH, WIFI_TRUST_STORE_PATH,
        WIFI_TRUST_BACKUP_PATH);
    if (recovered == FS_RECOVERY_FAILED) {
        result = WIFI_TRUST_STORE_RECOVERY;
        goto done;
    }
    if (recovered != FS_RECOVERY_NONE) {
        result = WIFI_TRUST_STORE_RECOVERED_RETRY;
        goto done;
    }
    const wifi_trust_profile_t *ordered[WIFI_TRUST_MAX_PROFILES];
    for (size_t i = 0; i < count; ++i) {
        if (!profile_canonical(&profiles[i])) {
            result = WIFI_TRUST_STORE_FORMAT;
            goto done;
        }
        size_t at = i;
        while (at != 0U && bssid_compare(ordered[at - 1U], &profiles[i]) > 0) {
            ordered[at] = ordered[at - 1U];
            --at;
        }
        ordered[at] = &profiles[i];
    }
    for (size_t i = 1U; i < count; ++i) {
        if (bssid_compare(ordered[i - 1U], ordered[i]) == 0) {
            result = WIFI_TRUST_STORE_FORMAT;
            goto done;
        }
    }
    void *handle = NULL;
    wifi_trust_io_result_t opened = ops->open(
        ops->context, WIFI_TRUST_STAGE_PATH, true, &handle);
    if (opened != WIFI_TRUST_IO_OK || handle == NULL) {
        if (handle != NULL) {
            (void)ops->close(handle);
            handle = NULL;
            result = ops->remove_path(ops->context, WIFI_TRUST_STAGE_PATH) ?
                WIFI_TRUST_STORE_IO : WIFI_TRUST_STORE_RECOVERY;
        }
        goto done;
    }
    char line[WIFI_TRUST_JSON_LINE_MAX];
    bool ok = format_header(line, sizeof(line), count, meta) &&
              write_exact(ops, handle, line, strlen(line));
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < count && ok; ++i) {
        int length = wifi_trust_store_format_ap_line(line, sizeof(line),
                                                      ordered[i]);
        ok = length > 0 && write_exact(ops, handle, line, (size_t)length);
        if (ok) {
            crc = crc32_update(crc, (const uint8_t *)line, (size_t)length);
            const uint8_t lf = '\n';
            crc = crc32_update(crc, &lf, 1U);
        }
    }
    crc ^= UINT32_MAX;
    ok = ok && format_end(line, sizeof(line), count, crc) &&
         write_exact(ops, handle, line, strlen(line));
    if (ok) ok = ops->flush(handle) == WIFI_TRUST_IO_OK;
    if (ok) ok = ops->sync(handle) == WIFI_TRUST_IO_OK;
    wifi_trust_io_result_t closed = ops->close(handle);
    handle = NULL;
    if (closed != WIFI_TRUST_IO_OK) ok = false;
    if (!ok) {
        result = ops->remove_path(ops->context, WIFI_TRUST_STAGE_PATH) ?
            WIFI_TRUST_STORE_IO : WIFI_TRUST_STORE_RECOVERY;
        goto done;
    }
    fs_publish_result_t published = ops->publish_staged(
        ops->context, WIFI_TRUST_STAGE_PATH, WIFI_TRUST_STORE_PATH,
        WIFI_TRUST_BACKUP_PATH, true);
    if (published == FS_PUBLISH_OK || published == FS_PUBLISH_BACKUP_LEFT) {
        result = published == FS_PUBLISH_BACKUP_LEFT ?
            WIFI_TRUST_STORE_OK_BACKUP_PENDING : WIFI_TRUST_STORE_OK;
        if (!ops->sync_volume(ops->context))
            result = WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN;
    } else if (published == FS_PUBLISH_ROLLBACK_FAILED) {
        result = WIFI_TRUST_STORE_RECOVERY;
    } else {
        result = WIFI_TRUST_STORE_PUBLISH;
    }
done:
    ops->leave(ops->context);
    return result;
}

wifi_trust_store_result_t wifi_trust_store_clear(
    const wifi_trust_store_ops_t *ops)
{
    if (!clear_ops_valid(ops) || !ops->enter(ops->context))
        return WIFI_TRUST_STORE_IO;
    wifi_trust_store_result_t result = WIFI_TRUST_STORE_IO;
    fs_recovery_result_t recovered = ops->recover_staged(
        ops->context, WIFI_TRUST_STAGE_PATH, WIFI_TRUST_STORE_PATH,
        WIFI_TRUST_BACKUP_PATH);
    if (recovered == FS_RECOVERY_FAILED) {
        result = WIFI_TRUST_STORE_RECOVERY;
        goto done;
    }
    if (recovered != FS_RECOVERY_NONE) {
        result = WIFI_TRUST_STORE_RECOVERED_RETRY;
        goto done;
    }
    wifi_trust_path_state_t state = ops->path_state(ops->context,
                                                     WIFI_TRUST_STORE_PATH);
    if (state == WIFI_TRUST_PATH_MISSING) {
        result = WIFI_TRUST_STORE_OK;
        goto done;
    }
    if (state != WIFI_TRUST_PATH_FILE) {
        result = state == WIFI_TRUST_PATH_ERROR ? WIFI_TRUST_STORE_IO :
                                                 WIFI_TRUST_STORE_RECOVERY;
        goto done;
    }
    if (!ops->rename_path(ops->context, WIFI_TRUST_STORE_PATH,
                          WIFI_TRUST_BACKUP_PATH)) {
        result = WIFI_TRUST_STORE_PUBLISH;
        goto done;
    }
    if (!ops->remove_path(ops->context, WIFI_TRUST_BACKUP_PATH)) {
        if (!ops->rename_path(ops->context, WIFI_TRUST_BACKUP_PATH,
                              WIFI_TRUST_STORE_PATH)) {
            result = WIFI_TRUST_STORE_RECOVERY;
        } else {
            result = ops->sync_volume(ops->context) ?
                WIFI_TRUST_STORE_PUBLISH :
                WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN;
        }
        goto done;
    }
    result = ops->sync_volume(ops->context) ? WIFI_TRUST_STORE_OK :
                                             WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN;
done:
    ops->leave(ops->context);
    return result;
}
