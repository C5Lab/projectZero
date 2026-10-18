#include "wifi_country_driver.h"
#include "esp_wifi.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

static int set_country_calls;
static int set_country_code_calls;
static char last_country_code[3];
static bool last_ieee80211d_enabled;
static wifi_country_t readback;
static esp_err_t set_result;
static esp_err_t get_result;
static bool force_bad_cc;
static bool force_auto_policy;

esp_err_t esp_wifi_set_country(const wifi_country_t *country)
{
    ++set_country_calls;
    if (set_result != ESP_OK) return set_result;
    readback = *country;
    return ESP_OK;
}

esp_err_t esp_wifi_set_country_code(const char *country, bool ieee80211d_enabled)
{
    ++set_country_code_calls;
    if (set_result != ESP_OK) return set_result;
    memcpy(last_country_code, country, sizeof(last_country_code));
    last_ieee80211d_enabled = ieee80211d_enabled;
    readback = (wifi_country_t){
        .cc = {country[0], country[1], '\0'},
        .schan = 1,
        .nchan = 13,
        .policy = WIFI_COUNTRY_POLICY_MANUAL,
    };
    return ESP_OK;
}

esp_err_t esp_wifi_get_country(wifi_country_t *country)
{
    if (get_result != ESP_OK) return get_result;
    *country = readback;
    if (force_bad_cc) country->cc[1] = 'S';
    if (force_auto_policy) country->policy = WIFI_COUNTRY_POLICY_AUTO;
    return ESP_OK;
}

static void reset_fake(void)
{
    set_country_calls = 0;
    set_country_code_calls = 0;
    memset(last_country_code, 0, sizeof(last_country_code));
    last_ieee80211d_enabled = true;
    memset(&readback, 0, sizeof(readback));
    set_result = ESP_OK;
    get_result = ESP_OK;
    force_bad_cc = false;
    force_auto_policy = false;
}

static void test_ru_uses_idf_country_code_path_and_manual_readback(void)
{
    reset_fake();
    const wifi_country_policy_record_t ru = {WIFI_COUNTRY_POLICY_VERSION, "RU"};

    CHECK(wifi_country_driver_apply_and_verify(&ru) == ESP_OK);
    CHECK(set_country_code_calls == 1);
    CHECK(set_country_calls == 0);
    CHECK(strcmp(last_country_code, "RU") == 0);
    CHECK(!last_ieee80211d_enabled);
}

static void test_pa_keeps_explicit_manual_profile(void)
{
    reset_fake();
    const wifi_country_policy_record_t pa = {WIFI_COUNTRY_POLICY_VERSION, "PA"};

    CHECK(wifi_country_driver_apply_and_verify(&pa) == ESP_OK);
    CHECK(set_country_calls == 1);
    CHECK(set_country_code_calls == 0);
    CHECK(readback.schan == 1);
    CHECK(readback.nchan == 14);
    CHECK(readback.policy == WIFI_COUNTRY_POLICY_MANUAL);
}

static void test_invalid_records_never_reach_driver(void)
{
    reset_fake();
    const wifi_country_policy_record_t unsupported = {
        WIFI_COUNTRY_POLICY_VERSION, "ZZ"
    };
    const wifi_country_policy_record_t future_version = {
        WIFI_COUNTRY_POLICY_VERSION + 1U, "RU"
    };
    CHECK(wifi_country_driver_apply_and_verify(NULL) == ESP_ERR_INVALID_ARG);
    CHECK(wifi_country_driver_apply_and_verify(&unsupported) == ESP_ERR_INVALID_ARG);
    CHECK(wifi_country_driver_apply_and_verify(&future_version) == ESP_ERR_INVALID_ARG);
    CHECK(set_country_calls == 0);
    CHECK(set_country_code_calls == 0);
}

static void test_driver_and_readback_failures_are_propagated(void)
{
    const wifi_country_policy_record_t ru = {WIFI_COUNTRY_POLICY_VERSION, "RU"};

    reset_fake();
    set_result = 0x777;
    CHECK(wifi_country_driver_apply_and_verify(&ru) == 0x777);
    CHECK(set_country_code_calls == 1);

    reset_fake();
    get_result = 0x778;
    CHECK(wifi_country_driver_apply_and_verify(&ru) == 0x778);

    reset_fake();
    force_bad_cc = true;
    CHECK(wifi_country_driver_apply_and_verify(&ru) == ESP_ERR_INVALID_STATE);

    reset_fake();
    force_auto_policy = true;
    CHECK(wifi_country_driver_apply_and_verify(&ru) == ESP_ERR_INVALID_STATE);
}

int main(void)
{
    test_ru_uses_idf_country_code_path_and_manual_readback();
    test_pa_keeps_explicit_manual_profile();
    test_invalid_records_never_reach_driver();
    test_driver_and_readback_failures_are_propagated();
    puts("PASS: WiFi country driver adapter");
    return 0;
}
