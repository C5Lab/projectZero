/* SPDX-License-Identifier: Apache-2.0 */
#include "wifi_country_store.h"

#include <string.h>

#include "esp_app_desc.h"
#include "nvs.h"

#define WIFI_COUNTRY_NVS_NAMESPACE "wifi_country"
#define WIFI_COUNTRY_NVS_KEY "profile"

enum {
    IMAGE_ID_SIZE = sizeof(((esp_app_desc_t *)0)->app_elf_sha256),
    STORED_RECORD_SIZE = WIFI_COUNTRY_POLICY_RECORD_SIZE + IMAGE_ID_SIZE,
};

/* Keep the country and image identity in one NVS blob so an interrupted update
 * cannot associate a previous country's value with the new firmware identity. */
static esp_err_t encode_record(const wifi_country_policy_record_t *record,
                               uint8_t encoded[STORED_RECORD_SIZE])
{
    if (wifi_country_policy_encode(record, encoded,
                                  WIFI_COUNTRY_POLICY_RECORD_SIZE) != WIFI_COUNTRY_POLICY_OK)
        return ESP_ERR_INVALID_ARG;
    const esp_app_desc_t *app = esp_app_get_description();
    if (app == NULL) return ESP_ERR_INVALID_STATE;
    memcpy(encoded + WIFI_COUNTRY_POLICY_RECORD_SIZE, app->app_elf_sha256,
           IMAGE_ID_SIZE);
    return ESP_OK;
}

static esp_err_t write_record(nvs_handle_t handle,
                              const uint8_t encoded[STORED_RECORD_SIZE])
{
    esp_err_t err = nvs_set_blob(handle, WIFI_COUNTRY_NVS_KEY, encoded,
                               STORED_RECORD_SIZE);
    return err == ESP_OK ? nvs_commit(handle) : err;
}

esp_err_t wifi_country_store_save(const wifi_country_policy_record_t *record)
{
    uint8_t encoded[STORED_RECORD_SIZE];
    esp_err_t err = encode_record(record, encoded);
    if (err != ESP_OK) return err;

    nvs_handle_t handle;
    err = nvs_open(WIFI_COUNTRY_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;
    err = write_record(handle, encoded);
    nvs_close(handle);
    return err;
}

esp_err_t wifi_country_store_load(wifi_country_policy_record_t *record,
                                const char **health)
{
    if (record == NULL || health == NULL) return ESP_ERR_INVALID_ARG;
    *record = wifi_country_policy_default();
    *health = "read_error_fallback_pa";
    const esp_app_desc_t *app = esp_app_get_description();
    if (app == NULL) return ESP_ERR_INVALID_STATE;

    nvs_handle_t handle;
    esp_err_t err = nvs_open(WIFI_COUNTRY_NVS_NAMESPACE, NVS_READWRITE, &handle);
    if (err != ESP_OK) return err;

    uint8_t encoded[STORED_RECORD_SIZE];
    size_t length = sizeof(encoded);
    err = nvs_get_blob(handle, WIFI_COUNTRY_NVS_KEY, encoded, &length);
    wifi_country_policy_record_t loaded;
    const char *reset_health = "invalid_reset_pa";
    if (err == ESP_OK && length == sizeof(encoded) &&
        wifi_country_policy_decode(encoded, WIFI_COUNTRY_POLICY_RECORD_SIZE,
                                   &loaded) == WIFI_COUNTRY_POLICY_OK) {
        if (memcmp(encoded + WIFI_COUNTRY_POLICY_RECORD_SIZE,
                   app->app_elf_sha256, IMAGE_ID_SIZE) == 0) {
            *record = loaded;
            *health = "valid";
            nvs_close(handle);
            return ESP_OK;
        }
        reset_health = "firmware_reset_pa";
    } else if (err == ESP_ERR_NVS_NOT_FOUND) {
        reset_health = "default_pa";
    } else if (err == ESP_OK && length == WIFI_COUNTRY_POLICY_RECORD_SIZE) {
        /* Legacy records contain no firmware identity: migrate to PA once. */
        reset_health = "firmware_reset_pa";
    } else if (err != ESP_OK && err != ESP_ERR_NVS_INVALID_LENGTH) {
        nvs_close(handle);
        return err;
    }

    err = encode_record(record, encoded);
    if (err == ESP_OK) err = write_record(handle, encoded);
    nvs_close(handle);
    *health = err == ESP_OK ? reset_health : "write_error_fallback_pa";
    return err;
}
