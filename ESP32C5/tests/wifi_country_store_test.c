#include "wifi_country_store.h"
#include "esp_app_desc.h"
#include "nvs.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static uint8_t stored[64], pending[64];
static size_t stored_length, pending_length;
static bool present, descriptor_missing;
static int writes, commits, opens, closes;
static esp_err_t open_error, read_error, write_error, commit_error;
static esp_app_desc_t app;
static const wifi_country_policy_record_t us = {WIFI_COUNTRY_POLICY_VERSION, "US"};
static const wifi_country_policy_record_t ru = {WIFI_COUNTRY_POLICY_VERSION, "RU"};

const esp_app_desc_t *esp_app_get_description(void)
{
    return descriptor_missing ? NULL : &app;
}

esp_err_t nvs_open(const char *namespace_name, nvs_open_mode_t mode, nvs_handle_t *handle)
{
    assert(strcmp(namespace_name, "wifi_country") == 0 && mode == NVS_READWRITE);
    if (open_error) return open_error;
    ++opens;
    *handle = 1;
    return ESP_OK;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char *key, void *value, size_t *length)
{
    assert(handle == 1 && strcmp(key, "profile") == 0);
    if (read_error) return read_error;
    if (!present) return ESP_ERR_NVS_NOT_FOUND;
    size_t capacity = *length;
    *length = stored_length;
    if (capacity < stored_length) return ESP_ERR_NVS_INVALID_LENGTH;
    memcpy(value, stored, stored_length);
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char *key, const void *value, size_t length)
{
    assert(handle == 1 && strcmp(key, "profile") == 0);
    assert(length == WIFI_COUNTRY_POLICY_RECORD_SIZE + sizeof(app.app_elf_sha256));
    ++writes;
    if (write_error) return write_error;
    memcpy(pending, value, length);
    pending_length = length;
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t handle)
{
    assert(handle == 1);
    ++commits;
    if (commit_error) return commit_error;
    memcpy(stored, pending, pending_length);
    stored_length = pending_length;
    present = true;
    return ESP_OK;
}

void nvs_close(nvs_handle_t handle)
{
    assert(handle == 1);
    pending_length = 0;
    ++closes;
}

static void reset_store(void)
{
    memset(stored, 0, sizeof(stored));
    memset(&app, 0xA5, sizeof(app));
    stored_length = pending_length = 0;
    present = descriptor_missing = false;
    writes = commits = opens = closes = 0;
    open_error = read_error = write_error = commit_error = ESP_OK;
}

static void expect_load(const char *cc, const char *health, esp_err_t expected_error)
{
    wifi_country_policy_record_t record = us;
    const char *actual_health = NULL;
    assert(wifi_country_store_load(&record, &actual_health) == expected_error);
    assert(strcmp(record.cc, cc) == 0);
    assert(strcmp(actual_health, health) == 0);
    assert(opens == closes);
}

static void first_boot_and_restarts(void)
{
    reset_store();
    expect_load("PA", "default_pa", ESP_OK);
    assert(writes == 1 && commits == 1 && stored_length == 35);
    assert(memcmp(stored + WIFI_COUNTRY_POLICY_RECORD_SIZE, app.app_elf_sha256, 32) == 0);
    expect_load("PA", "valid", ESP_OK);
    assert(writes == 1);
    assert(wifi_country_store_save(&us) == ESP_OK);
    expect_load("US", "valid", ESP_OK);
    expect_load("US", "valid", ESP_OK);
    assert(writes == 2 && commits == 2);
    /* The same BIN, whether rebooted or reflashed, has the same identity. */
    expect_load("US", "valid", ESP_OK);
    assert(writes == 2);
    wifi_country_policy_record_t pa = wifi_country_policy_default();
    assert(wifi_country_store_save(&pa) == ESP_OK);
    expect_load("PA", "valid", ESP_OK);
}

static void new_firmware_ota_and_rollback(void)
{
    reset_store();
    assert(wifi_country_store_save(&us) == ESP_OK);
    /* Compare all 32 identity bytes, even when the version label is unchanged. */
    app.app_elf_sha256[31] ^= 1;
    expect_load("PA", "firmware_reset_pa", ESP_OK);
    assert(writes == 2);
    expect_load("PA", "valid", ESP_OK);
    assert(writes == 2);
    assert(wifi_country_store_save(&ru) == ESP_OK);
    expect_load("RU", "valid", ESP_OK);
    app.app_elf_sha256[31] ^= 1;
    expect_load("PA", "firmware_reset_pa", ESP_OK);
}

static void legacy_and_corrupt_records(void)
{
    reset_store();
    present = true;
    stored_length = WIFI_COUNTRY_POLICY_RECORD_SIZE;
    assert(wifi_country_policy_encode(&us, stored, stored_length) == WIFI_COUNTRY_POLICY_OK);
    expect_load("PA", "firmware_reset_pa", ESP_OK);
    expect_load("PA", "valid", ESP_OK);
    assert(writes == 1);

    stored[0] = 0xff;
    expect_load("PA", "invalid_reset_pa", ESP_OK);
    stored[1] = 'Z'; stored[2] = 'Z';
    expect_load("PA", "invalid_reset_pa", ESP_OK);
    stored_length = 2;
    expect_load("PA", "invalid_reset_pa", ESP_OK);
    stored_length = sizeof(stored);
    expect_load("PA", "invalid_reset_pa", ESP_OK);
    assert(stored_length == 35);
}

static void storage_failures_and_retry(void)
{
    reset_store();
    open_error = 0x777;
    expect_load("PA", "read_error_fallback_pa", open_error);
    assert(writes == 0);
    open_error = ESP_OK;
    assert(wifi_country_store_save(&us) == ESP_OK);
    read_error = 0x778;
    expect_load("PA", "read_error_fallback_pa", read_error);
    assert(writes == 1);
    read_error = ESP_OK;
    expect_load("US", "valid", ESP_OK);

    app.app_elf_sha256[0] ^= 1;
    write_error = 0x779;
    expect_load("PA", "write_error_fallback_pa", write_error);
    assert(commits == 1 && stored[1] == 'U');
    write_error = ESP_OK;
    commit_error = 0x780;
    expect_load("PA", "write_error_fallback_pa", commit_error);
    assert(stored[1] == 'U');
    commit_error = ESP_OK;
    expect_load("PA", "firmware_reset_pa", ESP_OK);
    int successful_writes = writes;
    expect_load("PA", "valid", ESP_OK);
    assert(writes == successful_writes);
}

static void invalid_inputs(void)
{
    reset_store();
    wifi_country_policy_record_t record;
    const char *health;
    assert(wifi_country_store_load(NULL, &health) == ESP_ERR_INVALID_ARG);
    assert(wifi_country_store_load(&record, NULL) == ESP_ERR_INVALID_ARG);
    assert(wifi_country_store_save(NULL) == ESP_ERR_INVALID_ARG);
    record = (wifi_country_policy_record_t){WIFI_COUNTRY_POLICY_VERSION, "ZZ"};
    assert(wifi_country_store_save(&record) == ESP_ERR_INVALID_ARG);
    assert(opens == 0);
    descriptor_missing = true;
    expect_load("PA", "read_error_fallback_pa", ESP_ERR_INVALID_STATE);
    assert(wifi_country_store_save(&us) == ESP_ERR_INVALID_STATE);
    assert(opens == 0);
}

int main(void)
{
    first_boot_and_restarts();
    new_firmware_ota_and_rollback();
    legacy_and_corrupt_records();
    storage_failures_and_retry();
    invalid_inputs();
    puts("PASS: country resets to PA per firmware image; reboot persistence, migration and storage failures");
    return 0;
}
