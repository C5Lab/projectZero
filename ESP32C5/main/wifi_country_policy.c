#include "wifi_country_policy.h"

#include <ctype.h>
#include <string.h>

/* PH is a deliberate JanOS extension. The remaining entries mirror the
 * country codes accepted by esp_wifi_set_country_code() in ESP-IDF 6.0.2. */
static const char *const supported_codes[] = {
    "PH", "01", "AT", "AU", "BE", "BG", "BR", "CA", "CH", "CN", "CY", "CZ",
    "DE", "DK", "EE", "ES", "FI", "FR", "GB", "GR", "HK", "HR", "HU", "IE",
    "IN", "IS", "IT", "JP", "KR", "LI", "LT", "LU", "LV", "MT", "MX", "NL",
    "NO", "NZ", "PL", "PT", "RO", "SE", "SI", "SK", "TW", "US"
};

wifi_country_policy_record_t wifi_country_policy_default(void)
{
    return (wifi_country_policy_record_t){WIFI_COUNTRY_POLICY_VERSION, "PH"};
}

size_t wifi_country_policy_count(void)
{
    return sizeof(supported_codes) / sizeof(supported_codes[0]);
}

const char *wifi_country_policy_at(size_t index)
{
    return index < wifi_country_policy_count() ? supported_codes[index] : NULL;
}

bool wifi_country_policy_is_supported(const char *cc)
{
    if (cc == NULL || cc[0] == '\0' || cc[1] == '\0' || cc[2] != '\0') return false;
    for (size_t i = 0; i < wifi_country_policy_count(); ++i)
        if (strcmp(cc, supported_codes[i]) == 0) return true;
    return false;
}

wifi_country_policy_status_t wifi_country_policy_normalize(
    const char *text, char out[WIFI_COUNTRY_CODE_SIZE])
{
    if (text == NULL || out == NULL) return WIFI_COUNTRY_POLICY_INVALID_ARGUMENT;
    if (text[0] == '\0' || text[1] == '\0' || text[2] != '\0')
        return WIFI_COUNTRY_POLICY_INVALID_CODE;
    char normalized[WIFI_COUNTRY_CODE_SIZE] = {
        (char)toupper((unsigned char)text[0]),
        (char)toupper((unsigned char)text[1]),
        '\0'
    };
    if (!wifi_country_policy_is_supported(normalized))
        return WIFI_COUNTRY_POLICY_UNSUPPORTED_CODE;
    memcpy(out, normalized, sizeof(normalized));
    return WIFI_COUNTRY_POLICY_OK;
}

bool wifi_country_policy_is_ph(const wifi_country_policy_record_t *record)
{
    return record != NULL && record->version == WIFI_COUNTRY_POLICY_VERSION &&
           record->cc[0] == 'P' && record->cc[1] == 'H' && record->cc[2] == '\0';
}

wifi_country_policy_status_t wifi_country_policy_encode(
    const wifi_country_policy_record_t *record, uint8_t *out, size_t length)
{
    if (record == NULL || out == NULL) return WIFI_COUNTRY_POLICY_INVALID_ARGUMENT;
    if (length != WIFI_COUNTRY_POLICY_RECORD_SIZE) return WIFI_COUNTRY_POLICY_WRONG_LENGTH;
    if (record->version != WIFI_COUNTRY_POLICY_VERSION)
        return WIFI_COUNTRY_POLICY_UNSUPPORTED_VERSION;
    if (!wifi_country_policy_is_supported(record->cc))
        return WIFI_COUNTRY_POLICY_UNSUPPORTED_CODE;
    const uint8_t encoded[WIFI_COUNTRY_POLICY_RECORD_SIZE] = {
        WIFI_COUNTRY_POLICY_VERSION, (uint8_t)record->cc[0], (uint8_t)record->cc[1]
    };
    memcpy(out, encoded, sizeof(encoded));
    return WIFI_COUNTRY_POLICY_OK;
}

wifi_country_policy_status_t wifi_country_policy_decode(
    const uint8_t *data, size_t length, wifi_country_policy_record_t *out)
{
    if (data == NULL || out == NULL) return WIFI_COUNTRY_POLICY_INVALID_ARGUMENT;
    if (length != WIFI_COUNTRY_POLICY_RECORD_SIZE) return WIFI_COUNTRY_POLICY_WRONG_LENGTH;
    if (data[0] != WIFI_COUNTRY_POLICY_VERSION)
        return WIFI_COUNTRY_POLICY_UNSUPPORTED_VERSION;
    wifi_country_policy_record_t decoded = {
        WIFI_COUNTRY_POLICY_VERSION, {(char)data[1], (char)data[2], '\0'}
    };
    if (!wifi_country_policy_is_supported(decoded.cc))
        return WIFI_COUNTRY_POLICY_UNSUPPORTED_CODE;
    *out = decoded;
    return WIFI_COUNTRY_POLICY_OK;
}
