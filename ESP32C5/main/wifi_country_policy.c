#include "wifi_country_policy.h"

#include <ctype.h>
#include <string.h>

/* Complete ESP-IDF v6.0 ESP32-C5 regdomain_table (176 profiles).
 * Source: components/esp_wifi/regulatory/esp_wifi_regulatory.c.
 * Includes territories, EU and the world-safe profile 01. Keep PA first as
 * the JanOS default; all other entries follow in alphabetical order. */
static const char *const supported_codes[] = {
    "PA", "01", "AD", "AE", "AF", "AI", "AL", "AM", "AN", "AR", "AS", "AT",
    "AU", "AW", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BL", "BM",
    "BN", "BO", "BR", "BS", "BT", "BY", "BZ", "CA", "CF", "CH", "CI", "CL",
    "CN", "CO", "CR", "CU", "CX", "CY", "CZ", "DE", "DK", "DM", "DO", "DZ",
    "EC", "EE", "EG", "ES", "ET", "EU", "FI", "FM", "FR", "GB", "GD", "GE",
    "GF", "GH", "GL", "GP", "GR", "GT", "GU", "GY", "HK", "HN", "HR", "HT",
    "HU", "ID", "IE", "IL", "IN", "IR", "IS", "IT", "JM", "JO", "JP", "KE",
    "KH", "KN", "KP", "KR", "KW", "KY", "KZ", "LB", "LC", "LI", "LK", "LS",
    "LT", "LU", "LV", "MA", "MC", "MD", "ME", "MF", "MH", "MK", "MN", "MO",
    "MP", "MQ", "MR", "MT", "MU", "MV", "MW", "MX", "MY", "NA", "NG", "NI",
    "NL", "NO", "NP", "NZ", "OM", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
    "PR", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SE",
    "SG", "SI", "SK", "SN", "SR", "SV", "SY", "TC", "TD", "TG", "TH", "TN",
    "TR", "TT", "TW", "TZ", "UA", "UG", "US", "UY", "UZ", "VC", "VE", "VI",
    "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZW",
};

wifi_country_policy_record_t wifi_country_policy_default(void)
{
    return (wifi_country_policy_record_t){WIFI_COUNTRY_POLICY_VERSION, "PA"};
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

bool wifi_country_policy_is_pa(const wifi_country_policy_record_t *record)
{
    return record != NULL && record->version == WIFI_COUNTRY_POLICY_VERSION &&
           record->cc[0] == 'P' && record->cc[1] == 'A' && record->cc[2] == '\0';
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
