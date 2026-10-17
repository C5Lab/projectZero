#ifndef WIFI_COUNTRY_POLICY_H
#define WIFI_COUNTRY_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WIFI_COUNTRY_POLICY_VERSION 1u
#define WIFI_COUNTRY_POLICY_RECORD_SIZE 3u
#define WIFI_COUNTRY_CODE_SIZE 3u

typedef struct {
    uint8_t version;
    char cc[WIFI_COUNTRY_CODE_SIZE];
} wifi_country_policy_record_t;

typedef enum {
    WIFI_COUNTRY_POLICY_OK = 0,
    WIFI_COUNTRY_POLICY_INVALID_ARGUMENT,
    WIFI_COUNTRY_POLICY_WRONG_LENGTH,
    WIFI_COUNTRY_POLICY_UNSUPPORTED_VERSION,
    WIFI_COUNTRY_POLICY_INVALID_CODE,
    WIFI_COUNTRY_POLICY_UNSUPPORTED_CODE
} wifi_country_policy_status_t;

wifi_country_policy_record_t wifi_country_policy_default(void);
wifi_country_policy_status_t wifi_country_policy_normalize(
    const char *text, char out[WIFI_COUNTRY_CODE_SIZE]);
bool wifi_country_policy_is_supported(const char *cc);
bool wifi_country_policy_is_pa(const wifi_country_policy_record_t *record);
size_t wifi_country_policy_count(void);
const char *wifi_country_policy_at(size_t index);
wifi_country_policy_status_t wifi_country_policy_encode(
    const wifi_country_policy_record_t *record, uint8_t *out, size_t length);
wifi_country_policy_status_t wifi_country_policy_decode(
    const uint8_t *data, size_t length, wifi_country_policy_record_t *out);

#endif
