#include "wifi_trust_wire.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    VALUE_BYTES,
    VALUE_SCALAR,
    VALUE_ADVERTISEMENT,
    VALUE_NONE
} value_kind_t;

typedef struct {
    const char *token;
    value_kind_t kind;
} field_record_t;

typedef enum {
    SEVERITY_INFO,
    SEVERITY_WARN,
    SEVERITY_ALERT
} severity_t;

typedef struct {
    const char *token;
    severity_t severity;
} reason_record_t;

static const field_record_t fields[WIFI_TRUST_FIELD_COUNT] = {
    [WIFI_TRUST_FIELD_NONE] = {"bssid", VALUE_NONE},
    [WIFI_TRUST_FIELD_ADVERTISEMENT] = {"advertisement", VALUE_ADVERTISEMENT},
    [WIFI_TRUST_FIELD_SSID] = {"ssid", VALUE_BYTES},
    [WIFI_TRUST_FIELD_PRIVACY] = {"privacy", VALUE_SCALAR},
    [WIFI_TRUST_FIELD_AKM] = {"akm", VALUE_BYTES},
    [WIFI_TRUST_FIELD_CIPHER] = {"cipher", VALUE_BYTES},
    [WIFI_TRUST_FIELD_PMF] = {"pmf", VALUE_SCALAR},
    [WIFI_TRUST_FIELD_RSNXE] = {"rsnxe", VALUE_BYTES},
    [WIFI_TRUST_FIELD_WPS] = {"wps", VALUE_SCALAR},
    [WIFI_TRUST_FIELD_WPS_STATE] = {"wps_state", VALUE_SCALAR},
    [WIFI_TRUST_FIELD_WPS_CONFIG_METHODS] = {"wps_config_methods", VALUE_SCALAR},
    [WIFI_TRUST_FIELD_WPS_LOCK] = {"wps_lock", VALUE_SCALAR},
    [WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR] = {"wps_selected_registrar", VALUE_SCALAR},
    [WIFI_TRUST_FIELD_WPS_MANUFACTURER] = {"wps_manufacturer", VALUE_BYTES},
    [WIFI_TRUST_FIELD_WPS_MODEL_NAME] = {"wps_model_name", VALUE_BYTES},
    [WIFI_TRUST_FIELD_WPS_MODEL_NUMBER] = {"wps_model_number", VALUE_BYTES},
    [WIFI_TRUST_FIELD_WPS_DEVICE_NAME] = {"wps_device_name", VALUE_BYTES},
    [WIFI_TRUST_FIELD_COUNTRY] = {"country", VALUE_BYTES},
    [WIFI_TRUST_FIELD_CHANNEL] = {"channel", VALUE_SCALAR},
};

static const reason_record_t reasons[WIFI_TRUST_REASON_COUNT] = {
    [WIFI_TRUST_NEW_BSSID] = {"new_bssid", SEVERITY_INFO},
    [WIFI_TRUST_SSID_CHANGED] = {"ssid_changed", SEVERITY_WARN},
    [WIFI_TRUST_AKM_CHANGED] = {"akm_changed", SEVERITY_WARN},
    [WIFI_TRUST_CIPHER_CHANGED] = {"cipher_changed", SEVERITY_WARN},
    [WIFI_TRUST_PMF_DOWNGRADE] = {"pmf_downgrade", SEVERITY_ALERT},
    [WIFI_TRUST_RSNXE_CHANGED] = {"rsnxe_changed", SEVERITY_WARN},
    [WIFI_TRUST_WPS_ENABLED] = {"wps_enabled", SEVERITY_WARN},
    [WIFI_TRUST_WPS_LOCK_CHANGED] = {"wps_lock_changed", SEVERITY_WARN},
    [WIFI_TRUST_COUNTRY_CHANGED] = {"country_changed", SEVERITY_INFO},
    [WIFI_TRUST_CHANNEL_CHANGED] = {"channel_changed", SEVERITY_INFO},
    [WIFI_TRUST_ADVERTISEMENT_CONFLICT] = {"advertisement_conflict", SEVERITY_WARN},
    [WIFI_TRUST_MALFORMED_OBSERVATION] = {"malformed_observation", SEVERITY_WARN},
};

static bool append(char *line, size_t *used, const char *format, ...)
{
    if (*used >= WIFI_TRUST_LINE_MAX) return false;
    va_list args;
    va_start(args, format);
    const int length = vsnprintf(line + *used, WIFI_TRUST_LINE_MAX - *used,
                                 format, args);
    va_end(args);
    if (length < 0 || (size_t)length >= WIFI_TRUST_LINE_MAX - *used)
        return false;
    *used += (size_t)length;
    return true;
}

static bool append_hex(char *line, size_t *used, const uint8_t *bytes,
                       size_t length, bool lowercase)
{
    static const char upper[] = "0123456789ABCDEF";
    static const char lower[] = "0123456789abcdef";
    const char *alphabet = lowercase ? lower : upper;
    if (*used >= WIFI_TRUST_LINE_MAX) return false;
    if (length > (WIFI_TRUST_LINE_MAX - *used - 1U) / 2U) return false;
    for (size_t i = 0; i < length; ++i) {
        line[(*used)++] = alphabet[bytes[i] >> 4U];
        line[(*used)++] = alphabet[bytes[i] & 0x0fU];
    }
    line[*used] = '\0';
    return true;
}

static int publish(char *out, size_t capacity, const char *line, size_t length)
{
    if (out == NULL || length >= WIFI_TRUST_LINE_MAX || length >= capacity)
        return -1;
    memcpy(out, line, length + 1U);
    return (int)length;
}

static bool bytes_zero(const void *memory, size_t size)
{
    const uint8_t *bytes = memory;
    for (size_t i = 0; i < size; ++i)
        if (bytes[i] != 0U) return false;
    return true;
}

static bool valid_status(sx_status_t status)
{
    return status >= SX_UNKNOWN && status <= SX_INVALID;
}

static bool valid_bssid(const uint8_t bssid[6])
{
    uint8_t any = 0U;
    for (size_t i = 0; i < 6U; ++i) any |= bssid[i];
    return any != 0U && (bssid[0] & 1U) == 0U;
}

static bool valid_identity_value(sx_status_t status, const uint8_t *bytes,
                                 uint8_t length, size_t capacity,
                                 bool invalid_allowed)
{
    if (!valid_status(status) || (!invalid_allowed && status == SX_INVALID) ||
        length > capacity) return false;
    if (status == SX_VALID)
        return bytes_zero(bytes + length, capacity - length);
    return length == 0U && bytes_zero(bytes, capacity);
}

static bool valid_akm_encoding(const uint8_t *bytes, size_t length)
{
    size_t cursor = 0U;
    for (size_t item = 0; item < 2U; ++item) {
        if (length - cursor < 3U) return false;
        const uint8_t status = bytes[cursor++];
        const uint8_t known = bytes[cursor++];
        const uint8_t count = bytes[cursor++];
        if (status > (uint8_t)SX_VALID || known > 1U || count > SX_SELECTORS)
            return false;
        if (status != (uint8_t)SX_VALID && (known != 0U || count != 0U))
            return false;
        if ((known == 0U && count != 0U) ||
            (known != 0U && count == 0U)) return false;
        const size_t selectors = (size_t)count * 4U;
        if (selectors > length - cursor) return false;
        cursor += selectors;
    }
    return cursor == length;
}

static bool valid_cipher_encoding(const uint8_t *bytes, size_t length)
{
    size_t cursor = 0U;
    for (size_t item = 0; item < 2U; ++item) {
        if (length - cursor < 3U) return false;
        const uint8_t status = bytes[cursor++];
        const uint8_t group = bytes[cursor++];
        const uint8_t count = bytes[cursor++];
        if (status > (uint8_t)SX_VALID || group > 1U || count > SX_SELECTORS)
            return false;
        if (status != (uint8_t)SX_VALID && (group != 0U || count != 0U))
            return false;
        if (group != 0U) {
            if (length - cursor < 4U) return false;
            cursor += 4U;
        }
        const size_t selectors = (size_t)count * 4U;
        if (selectors > length - cursor) return false;
        cursor += selectors;
        if (cursor == length) return false;
        const uint8_t management = bytes[cursor++];
        if (management > 1U ||
            (status != (uint8_t)SX_VALID && management != 0U)) return false;
        if (management != 0U) {
            if (length - cursor < 4U) return false;
            cursor += 4U;
        }
    }
    return cursor == length;
}

typedef struct {
    sx_status_t status;
    bool known;
    uint8_t count;
    const uint8_t *selectors;
} akm_view_t;

typedef struct {
    sx_status_t status;
    bool group_present;
    const uint8_t *group;
    uint8_t pairwise_count;
    const uint8_t *pairwise;
    bool management_present;
    const uint8_t *management;
} cipher_view_t;

static void decode_akm_views(const wifi_trust_event_value_t *value,
                             akm_view_t views[2])
{
    size_t cursor = 0U;
    for (size_t item = 0; item < 2U; ++item) {
        views[item].status = (sx_status_t)value->bytes[cursor++];
        views[item].known = value->bytes[cursor++] != 0U;
        views[item].count = value->bytes[cursor++];
        views[item].selectors = value->bytes + cursor;
        cursor += (size_t)views[item].count * 4U;
    }
}

static void decode_cipher_views(const wifi_trust_event_value_t *value,
                                cipher_view_t views[2])
{
    size_t cursor = 0U;
    for (size_t item = 0; item < 2U; ++item) {
        views[item].status = (sx_status_t)value->bytes[cursor++];
        views[item].group_present = value->bytes[cursor++] != 0U;
        views[item].pairwise_count = value->bytes[cursor++];
        views[item].group = value->bytes + cursor;
        if (views[item].group_present) cursor += 4U;
        views[item].pairwise = value->bytes + cursor;
        cursor += (size_t)views[item].pairwise_count * 4U;
        views[item].management_present = value->bytes[cursor++] != 0U;
        views[item].management = value->bytes + cursor;
        if (views[item].management_present) cursor += 4U;
    }
}

static bool selector_multisets_equal(const uint8_t *left, uint8_t left_count,
                                     const uint8_t *right,
                                     uint8_t right_count)
{
    if (left_count != right_count) return false;
    bool used[SX_SELECTORS] = {false};
    for (size_t i = 0; i < left_count; ++i) {
        bool found = false;
        for (size_t j = 0; j < right_count; ++j) {
            if (!used[j] && memcmp(left + i * 4U, right + j * 4U, 4U) == 0) {
                used[j] = true;
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

static bool akm_semantically_changed(const wifi_trust_event_value_t *baseline,
                                     const wifi_trust_event_value_t *current)
{
    akm_view_t left[2];
    akm_view_t right[2];
    decode_akm_views(baseline, left);
    decode_akm_views(current, right);
    for (size_t item = 0; item < 2U; ++item) {
        if (left[item].status == SX_UNKNOWN ||
            right[item].status == SX_UNKNOWN) continue;
        if (left[item].status != right[item].status) return true;
        if (left[item].status == SX_VALID && left[item].known &&
            right[item].known &&
            !selector_multisets_equal(left[item].selectors, left[item].count,
                                      right[item].selectors,
                                      right[item].count)) return true;
    }
    return false;
}

static bool cipher_semantically_changed(
    const wifi_trust_event_value_t *baseline,
    const wifi_trust_event_value_t *current)
{
    cipher_view_t left[2];
    cipher_view_t right[2];
    decode_cipher_views(baseline, left);
    decode_cipher_views(current, right);
    for (size_t item = 0; item < 2U; ++item) {
        if (left[item].status == SX_UNKNOWN ||
            right[item].status == SX_UNKNOWN) continue;
        if (left[item].status != right[item].status) return true;
        if (left[item].status != SX_VALID) continue;
        if (left[item].group_present && right[item].group_present &&
            memcmp(left[item].group, right[item].group, 4U) != 0) return true;
        if (left[item].management_present && right[item].management_present &&
            memcmp(left[item].management, right[item].management, 4U) != 0)
            return true;
        if (left[item].pairwise_count != 0U &&
            right[item].pairwise_count != 0U &&
            !selector_multisets_equal(left[item].pairwise,
                                      left[item].pairwise_count,
                                      right[item].pairwise,
                                      right[item].pairwise_count)) return true;
    }
    return false;
}

static bool scalar_in_range(wifi_trust_field_t field, int32_t value)
{
    switch (field) {
    case WIFI_TRUST_FIELD_PRIVACY: return value >= 0 && value <= 1;
    case WIFI_TRUST_FIELD_PMF: return value >= 0 && value <= 2;
    case WIFI_TRUST_FIELD_WPS: return value == 1;
    case WIFI_TRUST_FIELD_WPS_STATE: return value == 1 || value == 2;
    case WIFI_TRUST_FIELD_WPS_CONFIG_METHODS:
        return value >= 0 && value <= UINT16_MAX;
    case WIFI_TRUST_FIELD_WPS_LOCK:
    case WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR:
        return value >= 0 && value <= 1;
    case WIFI_TRUST_FIELD_CHANNEL: return value >= 1 && value <= 233;
    default: return false;
    }
}

static bool status_allowed_for_field(wifi_trust_field_t field,
                                     sx_status_t status)
{
    if (field == WIFI_TRUST_FIELD_ADVERTISEMENT)
        return status == SX_UNKNOWN || status == SX_VALID || status == SX_INVALID;
    if (field == WIFI_TRUST_FIELD_NONE) return status == SX_UNKNOWN;
    if (field == WIFI_TRUST_FIELD_AKM || field == WIFI_TRUST_FIELD_CIPHER)
        return status == SX_VALID;
    if (field == WIFI_TRUST_FIELD_PRIVACY ||
        field == WIFI_TRUST_FIELD_WPS_STATE ||
        field == WIFI_TRUST_FIELD_WPS_CONFIG_METHODS ||
        field == WIFI_TRUST_FIELD_WPS_LOCK ||
        field == WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR ||
        field == WIFI_TRUST_FIELD_WPS_MANUFACTURER ||
        field == WIFI_TRUST_FIELD_WPS_MODEL_NAME ||
        field == WIFI_TRUST_FIELD_WPS_MODEL_NUMBER ||
        field == WIFI_TRUST_FIELD_WPS_DEVICE_NAME ||
        field == WIFI_TRUST_FIELD_CHANNEL)
        return status == SX_UNKNOWN || status == SX_VALID;
    return status == SX_UNKNOWN || status == SX_ABSENT || status == SX_VALID;
}

static bool valid_nonvalue_number(wifi_trust_field_t field,
                                  sx_status_t status, int32_t number,
                                  int32_t allowed_invalid_number)
{
    if (status == SX_INVALID && field == WIFI_TRUST_FIELD_ADVERTISEMENT)
        return number == 0 || number == allowed_invalid_number;
    if (status == SX_UNKNOWN &&
        (field == WIFI_TRUST_FIELD_PRIVACY ||
         field == WIFI_TRUST_FIELD_WPS_STATE ||
         field == WIFI_TRUST_FIELD_WPS_CONFIG_METHODS ||
         field == WIFI_TRUST_FIELD_WPS_LOCK ||
         field == WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR))
        return number == -1;
    return number == 0;
}

static bool valid_event_value(const wifi_trust_event_value_t *value,
                              wifi_trust_field_t field,
                              int32_t allowed_invalid_number)
{
    if (value == NULL || !valid_status(value->status) ||
        value->len > WIFI_TRUST_EVENT_VALUE_BYTES ||
        !bytes_zero(value->bytes + value->len,
                    WIFI_TRUST_EVENT_VALUE_BYTES - value->len) ||
        !status_allowed_for_field(field, value->status)) return false;
    if (value->status != SX_VALID) {
        if (value->len != 0U || !bytes_zero(value->bytes,
                                            sizeof(value->bytes))) return false;
        return valid_nonvalue_number(field, value->status, value->number,
                                     allowed_invalid_number);
    }
    if (fields[field].kind == VALUE_SCALAR)
        return value->len == 0U &&
               bytes_zero(value->bytes, sizeof(value->bytes)) &&
               scalar_in_range(field, value->number);
    if (value->number != 0) return false;
    switch (field) {
    case WIFI_TRUST_FIELD_ADVERTISEMENT:
        return value->len == 0U;
    case WIFI_TRUST_FIELD_SSID:
        return value->len <= 32U;
    case WIFI_TRUST_FIELD_AKM:
        return valid_akm_encoding(value->bytes, value->len);
    case WIFI_TRUST_FIELD_CIPHER:
        return valid_cipher_encoding(value->bytes, value->len);
    case WIFI_TRUST_FIELD_RSNXE:
        return value->len >= 1U && value->len <= SX_RSNXE_BYTES;
    case WIFI_TRUST_FIELD_WPS_MANUFACTURER:
    case WIFI_TRUST_FIELD_WPS_MODEL_NAME:
    case WIFI_TRUST_FIELD_WPS_MODEL_NUMBER:
    case WIFI_TRUST_FIELD_WPS_DEVICE_NAME:
        return value->len <= SX_TEXT_BYTES;
    case WIFI_TRUST_FIELD_COUNTRY:
        return value->len == 3U && value->bytes[0] >= 'A' &&
               value->bytes[0] <= 'Z' && value->bytes[1] >= 'A' &&
               value->bytes[1] <= 'Z' &&
               (value->bytes[2] == ' ' || value->bytes[2] == 'I' ||
                value->bytes[2] == 'O');
    default:
        return false;
    }
}

static bool event_pair_allowed(wifi_trust_reason_t reason,
                               wifi_trust_field_t field)
{
    switch (reason) {
    case WIFI_TRUST_NEW_BSSID: return field == WIFI_TRUST_FIELD_NONE;
    case WIFI_TRUST_SSID_CHANGED: return field == WIFI_TRUST_FIELD_SSID;
    case WIFI_TRUST_AKM_CHANGED: return field == WIFI_TRUST_FIELD_AKM;
    case WIFI_TRUST_CIPHER_CHANGED:
        return field == WIFI_TRUST_FIELD_PRIVACY ||
               field == WIFI_TRUST_FIELD_CIPHER;
    case WIFI_TRUST_PMF_DOWNGRADE: return field == WIFI_TRUST_FIELD_PMF;
    case WIFI_TRUST_RSNXE_CHANGED: return field == WIFI_TRUST_FIELD_RSNXE;
    case WIFI_TRUST_WPS_ENABLED: return field == WIFI_TRUST_FIELD_WPS;
    case WIFI_TRUST_WPS_LOCK_CHANGED:
        return field == WIFI_TRUST_FIELD_WPS_LOCK;
    case WIFI_TRUST_COUNTRY_CHANGED: return field == WIFI_TRUST_FIELD_COUNTRY;
    case WIFI_TRUST_CHANNEL_CHANGED: return field == WIFI_TRUST_FIELD_CHANNEL;
    case WIFI_TRUST_ADVERTISEMENT_CONFLICT:
        return field >= WIFI_TRUST_FIELD_SSID && field < WIFI_TRUST_FIELD_COUNT;
    case WIFI_TRUST_MALFORMED_OBSERVATION:
        return field == WIFI_TRUST_FIELD_ADVERTISEMENT;
    default:
        return false;
    }
}

static bool event_values_equal(const wifi_trust_event_value_t *left,
                               const wifi_trust_event_value_t *right)
{
    return left->status == right->status && left->len == right->len &&
           left->number == right->number &&
           memcmp(left->bytes, right->bytes, sizeof(left->bytes)) == 0;
}

static bool confirmed_bytes_changed(const wifi_trust_event_value_t *baseline,
                                    const wifi_trust_event_value_t *current)
{
    if (baseline->status == SX_UNKNOWN || current->status == SX_UNKNOWN)
        return false;
    if (baseline->status != current->status) return true;
    return baseline->status == SX_VALID &&
           (baseline->len != current->len ||
            memcmp(baseline->bytes, current->bytes, baseline->len) != 0);
}

static bool confirmed_scalar_changed(const wifi_trust_event_value_t *baseline,
                                     const wifi_trust_event_value_t *current)
{
    return baseline->status == SX_VALID && current->status == SX_VALID &&
           baseline->number != current->number;
}

static bool pmf_downgrade_valid(const wifi_trust_event_value_t *baseline,
                                const wifi_trust_event_value_t *current)
{
    if (baseline->status != SX_VALID ||
        (baseline->number != 1 && baseline->number != 2) ||
        current->status == SX_UNKNOWN) return false;
    if (current->status == SX_ABSENT) return true;
    if (current->status != SX_VALID) return false;
    return baseline->number == 2 ? current->number < 2 :
                                   current->number == 0;
}

static bool pmf_conflict_valid(const wifi_trust_event_value_t *baseline,
                               const wifi_trust_event_value_t *current)
{
    if (baseline->status == SX_UNKNOWN || current->status == SX_UNKNOWN)
        return false;
    const int32_t baseline_mode = baseline->status == SX_VALID ?
                                  baseline->number : 0;
    const int32_t current_mode = current->status == SX_VALID ?
                                 current->number : 0;
    return baseline_mode != current_mode;
}

static bool malformed_pair_valid(const wifi_trust_event_value_t *baseline,
                                 const wifi_trust_event_value_t *current)
{
    if (baseline->status == SX_UNKNOWN && current->status == SX_INVALID)
        return true;
    if (current->number != 0) return false;
    return (baseline->status == SX_INVALID &&
            current->status == SX_VALID) ||
           (baseline->status == SX_VALID &&
            current->status == SX_INVALID) ||
           (baseline->status == SX_INVALID &&
            current->status == SX_INVALID);
}

static bool conflict_values_valid(const wifi_trust_event_t *event)
{
    if (event->source != SX_PROBE_RESP) return false;
    switch (event->field) {
    case WIFI_TRUST_FIELD_SSID:
    case WIFI_TRUST_FIELD_RSNXE:
    case WIFI_TRUST_FIELD_COUNTRY:
        return confirmed_bytes_changed(&event->baseline, &event->current);
    case WIFI_TRUST_FIELD_PRIVACY:
    case WIFI_TRUST_FIELD_WPS_STATE:
    case WIFI_TRUST_FIELD_WPS_CONFIG_METHODS:
    case WIFI_TRUST_FIELD_WPS_LOCK:
    case WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR:
    case WIFI_TRUST_FIELD_CHANNEL:
        return confirmed_scalar_changed(&event->baseline, &event->current);
    case WIFI_TRUST_FIELD_AKM:
        return akm_semantically_changed(&event->baseline, &event->current);
    case WIFI_TRUST_FIELD_CIPHER:
        return cipher_semantically_changed(&event->baseline, &event->current);
    case WIFI_TRUST_FIELD_PMF:
        return pmf_conflict_valid(&event->baseline, &event->current);
    case WIFI_TRUST_FIELD_WPS:
        return event->baseline.status != SX_UNKNOWN &&
               event->current.status != SX_UNKNOWN &&
               event->baseline.status != event->current.status;
    case WIFI_TRUST_FIELD_WPS_MANUFACTURER:
    case WIFI_TRUST_FIELD_WPS_MODEL_NAME:
    case WIFI_TRUST_FIELD_WPS_MODEL_NUMBER:
    case WIFI_TRUST_FIELD_WPS_DEVICE_NAME:
        return event->baseline.status == SX_VALID &&
               event->current.status == SX_VALID &&
               confirmed_bytes_changed(&event->baseline, &event->current);
    default:
        return false;
    }
}

static bool reason_values_valid(const wifi_trust_event_t *event)
{
    switch (event->reason) {
    case WIFI_TRUST_NEW_BSSID:
        return event->baseline.status == SX_UNKNOWN &&
               event->current.status == SX_UNKNOWN;
    case WIFI_TRUST_SSID_CHANGED:
    case WIFI_TRUST_RSNXE_CHANGED:
    case WIFI_TRUST_COUNTRY_CHANGED:
        return confirmed_bytes_changed(&event->baseline, &event->current);
    case WIFI_TRUST_AKM_CHANGED:
        return akm_semantically_changed(&event->baseline, &event->current);
    case WIFI_TRUST_CIPHER_CHANGED:
        return event->field == WIFI_TRUST_FIELD_PRIVACY ?
            confirmed_scalar_changed(&event->baseline, &event->current) :
            cipher_semantically_changed(&event->baseline, &event->current);
    case WIFI_TRUST_PMF_DOWNGRADE:
        return pmf_downgrade_valid(&event->baseline, &event->current);
    case WIFI_TRUST_WPS_ENABLED:
        return event->baseline.status == SX_ABSENT &&
               event->current.status == SX_VALID &&
               event->current.number == 1;
    case WIFI_TRUST_WPS_LOCK_CHANGED:
    case WIFI_TRUST_CHANNEL_CHANGED:
        return confirmed_scalar_changed(&event->baseline, &event->current);
    case WIFI_TRUST_ADVERTISEMENT_CONFLICT:
        return conflict_values_valid(event);
    case WIFI_TRUST_MALFORMED_OBSERVATION:
        return malformed_pair_valid(&event->baseline, &event->current);
    default:
        return false;
    }
}

static bool event_valid(const wifi_trust_event_t *event)
{
    if (event == NULL || event->reason <= WIFI_TRUST_NO_CHANGE ||
        event->reason >= WIFI_TRUST_REASON_COUNT ||
        (int)event->field < (int)WIFI_TRUST_FIELD_NONE ||
        event->field >= WIFI_TRUST_FIELD_COUNT || event->channel > 233U ||
        !event_pair_allowed(event->reason, event->field)) return false;
    const bool malformed = event->reason == WIFI_TRUST_MALFORMED_OBSERVATION;
    if ((!malformed && !valid_bssid(event->bssid)) ||
        (!malformed && event->source != SX_BEACON &&
         event->source != SX_PROBE_RESP) ||
        (malformed && event->source != SX_NONE &&
         event->source != SX_BEACON && event->source != SX_PROBE_RESP) ||
        !valid_identity_value(event->ssid_status, event->ssid,
                              event->ssid_len, sizeof(event->ssid), malformed))
        return false;
    if (!valid_event_value(&event->baseline, event->field, 0) ||
        !valid_event_value(&event->current, event->field,
                           malformed ? (int32_t)event->channel : 0))
        return false;
    if (event->reason != WIFI_TRUST_NEW_BSSID &&
        event->reason != WIFI_TRUST_MALFORMED_OBSERVATION &&
        event_values_equal(&event->baseline, &event->current)) return false;
    return reason_values_valid(event);
}

static const char *source_token(sx_source_t source)
{
    switch (source) {
    case SX_NONE: return "unknown";
    case SX_BEACON: return "beacon";
    case SX_PROBE_RESP: return "probe_response";
    default: return NULL;
    }
}

static const char *severity_token(severity_t severity)
{
    switch (severity) {
    case SEVERITY_INFO: return "info";
    case SEVERITY_WARN: return "warn";
    case SEVERITY_ALERT: return "alert";
    default: return NULL;
    }
}

static bool append_identity(char *line, size_t *used, sx_status_t status,
                            const uint8_t *bytes, size_t length)
{
    switch (status) {
    case SX_UNKNOWN: return append(line, used, "unknown");
    case SX_ABSENT: return append(line, used, "absent");
    case SX_INVALID: return append(line, used, "invalid");
    case SX_VALID:
        return append(line, used, "hex:") &&
               append_hex(line, used, bytes, length, false);
    default: return false;
    }
}

static bool append_value(char *line, size_t *used,
                         const wifi_trust_event_value_t *value,
                         wifi_trust_field_t field)
{
    switch (value->status) {
    case SX_UNKNOWN: return append(line, used, "unknown");
    case SX_ABSENT: return append(line, used, "absent");
    case SX_INVALID: return append(line, used, "invalid");
    case SX_VALID:
        if (fields[field].kind == VALUE_SCALAR)
            return append(line, used, "num:%" PRId32, value->number);
        return append(line, used, "hex:") &&
               append_hex(line, used, value->bytes, value->len, false);
    default:
        return false;
    }
}

int wifi_trust_format_event(char *out, size_t capacity,
                            const wifi_trust_event_t *event)
{
    if (out == NULL || !event_valid(event)) return -1;
    const reason_record_t *reason = &reasons[event->reason];
    const char *source = source_token(event->source);
    const char *severity = severity_token(reason->severity);
    if (reason->token == NULL || fields[event->field].token == NULL ||
        source == NULL || severity == NULL) return -1;
    char line[WIFI_TRUST_LINE_MAX];
    size_t used = 0U;
    if (!append(line, &used,
                "[WIFI_TRUST/1] EVENT BSSID=%02x:%02x:%02x:%02x:%02x:%02x SSID=",
                (unsigned)event->bssid[0], (unsigned)event->bssid[1],
                (unsigned)event->bssid[2], (unsigned)event->bssid[3],
                (unsigned)event->bssid[4], (unsigned)event->bssid[5]) ||
        !append_identity(line, &used, event->ssid_status, event->ssid,
                         event->ssid_len)) return -1;
    if (!append(line, &used, " CHANNEL=")) return -1;
    if (event->channel == 0U) {
        if (!append(line, &used, "unknown")) return -1;
    } else if (!append(line, &used, "%u", (unsigned)event->channel)) {
        return -1;
    }
    if (!append(line, &used, " SOURCE=%s FIELD=%s BASE=", source,
                fields[event->field].token)) return -1;
    if (event->reason == WIFI_TRUST_NEW_BSSID) {
        if (!append(line, &used, "absent CURRENT=observed")) return -1;
    } else {
        if (!append_value(line, &used, &event->baseline, event->field) ||
            !append(line, &used, " CURRENT=") ||
            !append_value(line, &used, &event->current, event->field)) return -1;
    }
    if (!append(line, &used,
                " REASON=%s SEVERITY=%s CONFIDENCE=observation TS_US=%" PRIu64 "\r\n",
                reason->token, severity, event->timestamp_us)) return -1;
    return publish(out, capacity, line, used);
}

static bool encode_profile_value(const wifi_trust_profile_t *profile,
                                 wifi_trust_field_t field,
                                 wifi_trust_event_value_t *value)
{
    return wifi_trust_value_from_profile(profile, field, value) &&
           valid_event_value(value, field, 0);
}

static bool append_named_profile_value(char *line, size_t *used,
                                       const char *name,
                                       const wifi_trust_profile_t *profile,
                                       wifi_trust_field_t field)
{
    wifi_trust_event_value_t value;
    if (!encode_profile_value(profile, field, &value) ||
        !append(line, used, " %s=", name)) return false;
    return append_value(line, used, &value, field);
}

int wifi_trust_format_baseline(char *out, size_t capacity,
                               const wifi_trust_profile_t *profile,
                               const wifi_trust_store_meta_t *meta)
{
    if (out == NULL || profile == NULL || meta == NULL ||
        !wifi_trust_profile_valid(profile) ||
        (!meta->created_unix_known && meta->created_unix != 0U)) return -1;
    const char *source = source_token(profile->source);
    if (source == NULL || (profile->source != SX_BEACON &&
                           profile->source != SX_PROBE_RESP)) return -1;
    wifi_trust_event_value_t ssid;
    if (!encode_profile_value(profile, WIFI_TRUST_FIELD_SSID, &ssid)) return -1;

    char line[WIFI_TRUST_LINE_MAX];
    size_t used = 0U;
    if (!append(line, &used,
                "[WIFI_TRUST/1] BASELINE BSSID=%02x:%02x:%02x:%02x:%02x:%02x SSID=",
                (unsigned)profile->bssid[0], (unsigned)profile->bssid[1],
                (unsigned)profile->bssid[2], (unsigned)profile->bssid[3],
                (unsigned)profile->bssid[4], (unsigned)profile->bssid[5]) ||
        !append_value(line, &used, &ssid, WIFI_TRUST_FIELD_SSID) ||
        !append(line, &used, " CHANNEL=")) return -1;
    if (profile->channel == 0U) {
        if (!append(line, &used, "unknown")) return -1;
    } else if (!append(line, &used, "%u", (unsigned)profile->channel)) {
        return -1;
    }
    if (!append(line, &used, " SOURCE=%s", source) ||
        !append_named_profile_value(line, &used, "PRIVACY", profile,
                                    WIFI_TRUST_FIELD_PRIVACY) ||
        !append_named_profile_value(line, &used, "AKM", profile,
                                    WIFI_TRUST_FIELD_AKM) ||
        !append_named_profile_value(line, &used, "CIPHER", profile,
                                    WIFI_TRUST_FIELD_CIPHER) ||
        !append_named_profile_value(line, &used, "PMF", profile,
                                    WIFI_TRUST_FIELD_PMF) ||
        !append_named_profile_value(line, &used, "RSNXE", profile,
                                    WIFI_TRUST_FIELD_RSNXE) ||
        !append_named_profile_value(line, &used, "WPS", profile,
                                    WIFI_TRUST_FIELD_WPS) ||
        !append_named_profile_value(line, &used, "WPS_STATE", profile,
                                    WIFI_TRUST_FIELD_WPS_STATE) ||
        !append_named_profile_value(line, &used, "WPS_CONFIG_METHODS", profile,
                                    WIFI_TRUST_FIELD_WPS_CONFIG_METHODS) ||
        !append_named_profile_value(line, &used, "WPS_LOCK", profile,
                                    WIFI_TRUST_FIELD_WPS_LOCK) ||
        !append_named_profile_value(line, &used, "WPS_SELECTED_REGISTRAR", profile,
                                    WIFI_TRUST_FIELD_WPS_SELECTED_REGISTRAR) ||
        !append_named_profile_value(line, &used, "COUNTRY", profile,
                                    WIFI_TRUST_FIELD_COUNTRY) ||
        !append(line, &used, " OBSERVED_US=%" PRIu64 " BOOT=",
                profile->observed_us) ||
        !append_hex(line, &used, meta->boot_id, sizeof(meta->boot_id), true) ||
        !append(line, &used, "\r\n")) return -1;
    return publish(out, capacity, line, used);
}

static const char *mode_token(wifi_trust_mode_t mode)
{
    switch (mode) {
    case WIFI_TRUST_MODE_IDLE: return "idle";
    case WIFI_TRUST_MODE_CAPTURE: return "capture";
    case WIFI_TRUST_MODE_MONITOR: return "monitor";
    default: return NULL;
    }
}

static const char *store_token(wifi_trust_store_result_t result)
{
    switch (result) {
    case WIFI_TRUST_STORE_OK: return "ok";
    case WIFI_TRUST_STORE_OK_BACKUP_PENDING: return "ok_backup_pending";
    case WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN: return "published_uncertain";
    case WIFI_TRUST_STORE_RECOVERED_RETRY: return "recovered_retry";
    case WIFI_TRUST_STORE_NOT_FOUND: return "not_found";
    case WIFI_TRUST_STORE_IO: return "io";
    case WIFI_TRUST_STORE_FORMAT: return "format";
    case WIFI_TRUST_STORE_CAPACITY: return "capacity";
    case WIFI_TRUST_STORE_PUBLISH: return "publish";
    case WIFI_TRUST_STORE_RECOVERY: return "recovery";
    default: return NULL;
    }
}

static const char *recovery_token(wifi_trust_recovery_action_t recovery)
{
    switch (recovery) {
    case WIFI_TRUST_RECOVERY_NONE: return "none";
    case WIFI_TRUST_RECOVERY_CLEARED_STAGE: return "cleared_stage";
    case WIFI_TRUST_RECOVERY_RESTORED_BACKUP: return "restored_backup";
    case WIFI_TRUST_RECOVERY_KEPT_TARGET: return "kept_target";
    default: return NULL;
    }
}

static bool status_valid(const wifi_trust_status_t *status)
{
    if (status == NULL || mode_token(status->mode) == NULL ||
        store_token(status->store) == NULL ||
        recovery_token(status->recovery) == NULL || status->channel > 233U ||
        status->baseline_loaded > 1U || status->boot_known > 1U ||
        status->created_unix_known > 1U || status->running > 1U ||
        status->stopping > 1U ||
        status->baseline_count > WIFI_TRUST_MAX_PROFILES ||
        status->profiles > WIFI_TRUST_MAX_PROFILES) return false;
    if (status->baseline_loaded == 0U &&
        (status->baseline_count != 0U || status->boot_known != 0U ||
         status->created_unix_known != 0U)) return false;
    if (status->baseline_loaded != status->boot_known) return false;
    if (status->boot_known == 0U &&
        (!bytes_zero(status->boot_id, sizeof(status->boot_id)) ||
         status->created_unix_known != 0U)) return false;
    if (status->created_unix_known == 0U && status->created_unix != 0U)
        return false;
    if (status->mode == WIFI_TRUST_MODE_IDLE &&
        (status->running != 0U || status->stopping != 0U))
        return false;
    return true;
}

static int format_summary(char *out, size_t capacity,
                          const wifi_trust_status_t *status,
                          const char *outcome)
{
    if (out == NULL || !status_valid(status)) return -1;
    const char *mode = mode_token(status->mode);
    const char *store = store_token(status->store);
    const char *recovery = recovery_token(status->recovery);
    char line[WIFI_TRUST_LINE_MAX];
    size_t used = 0U;
    const bool prefix = outcome == NULL ?
        append(line, &used, "[WIFI_TRUST/1] STATUS") :
        append(line, &used, "[WIFI_TRUST/1] TERMINAL OUTCOME=%s", outcome);
    if (!prefix ||
        !append(line, &used, " MODE=%s SCOPE=current_channel CHANNEL=", mode))
        return -1;
    if (status->channel == 0U) {
        if (!append(line, &used, "unknown")) return -1;
    } else if (!append(line, &used, "%u", (unsigned)status->channel)) {
        return -1;
    }
    if (!append(line, &used,
                " BASELINE_LOADED=%u BASELINE_COUNT=%" PRIu32 " BOOT=",
                (unsigned)status->baseline_loaded, status->baseline_count))
        return -1;
    if (status->boot_known != 0U) {
        if (!append_hex(line, &used, status->boot_id,
                        sizeof(status->boot_id), true)) return -1;
    } else if (!append(line, &used, "unknown")) {
        return -1;
    }
    if (!append(line, &used, " CREATED_UNIX=")) return -1;
    if (status->created_unix_known != 0U) {
        if (!append(line, &used, "%" PRIu64, status->created_unix)) return -1;
    } else if (!append(line, &used, "unknown")) {
        return -1;
    }
    if (!append(line, &used,
                " STORE=%s RECOVERY=%s RECEIVED=%" PRIu32
                " FILTERED=%" PRIu32 " UNRELATED=%" PRIu32
                " ACCEPTED=%" PRIu32 " INVALID=%" PRIu32
                " PROFILES=%" PRIu32 " CONFLICTS=%" PRIu32
                " EVENTS_INFO=%" PRIu32 " EVENTS_WARN=%" PRIu32
                " EVENTS_ALERT=%" PRIu32 " CAPACITY_DROPS=%" PRIu32
                " RX_DROPS=%" PRIu32 " OUTPUT_FAILURES=%" PRIu32
                " STORAGE_FAILURES=%" PRIu32 " RUNNING=%u STOPPING=%u\r\n",
                store, recovery, status->received, status->filtered,
                status->unrelated, status->accepted, status->invalid,
                status->profiles, status->conflicts, status->events_info,
                status->events_warn, status->events_alert,
                status->capacity_drops, status->rx_drops,
                status->output_failures, status->storage_failures,
                (unsigned)status->running, (unsigned)status->stopping))
        return -1;
    return publish(out, capacity, line, used);
}

int wifi_trust_format_status(char *out, size_t capacity,
                             const wifi_trust_status_t *status)
{
    return format_summary(out, capacity, status, NULL);
}

int wifi_trust_format_terminal(char *out, size_t capacity,
                               const wifi_trust_status_t *status,
                               const char *outcome)
{
    static const char *const outcomes[] = {
        "ok", "stopped", "busy", "invalid", "timeout", "queue_overflow",
        "restore_failed", "storage_failed", "storage_uncertain",
        "output_failed"
    };
    if (outcome == NULL) return -1;
    for (size_t i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); ++i)
        if (strcmp(outcome, outcomes[i]) == 0)
            return format_summary(out, capacity, status, outcomes[i]);
    return -1;
}
