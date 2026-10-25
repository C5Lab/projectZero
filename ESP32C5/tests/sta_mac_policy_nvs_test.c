#include "sta_mac_policy_nvs.h"
#include "nvs.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #condition); \
        exit(1); \
    } \
} while (0)

enum { HANDLE = 37 };
static const uint8_t fixed_bytes[8] = {1, 2, 0x02, 0xab, 0xcd, 0xef, 0x01, 0x23};
static const sta_mac_policy_record_t fixed_record =
    {1, STA_MAC_MODE_FIXED, {0x02, 0xab, 0xcd, 0xef, 0x01, 0x23}};

typedef struct {
    uint8_t saved[16];
    size_t saved_length;
    uint8_t pending[16];
    size_t pending_length;
    int namespace_present;
    int key_present;
    int open_calls;
    int read_calls;
    int write_calls;
    int commit_calls;
    int close_calls;
    nvs_open_mode_t last_open_mode;
    esp_err_t open_error;
    esp_err_t read_error;
    esp_err_t write_error;
    esp_err_t commit_error;
} fake_nvs_t;

static fake_nvs_t fake;

static void reset_nvs(void)
{
    memset(&fake, 0, sizeof(fake));
}

esp_err_t nvs_open(const char *namespace_name, nvs_open_mode_t mode, nvs_handle_t *handle)
{
    CHECK(strcmp(namespace_name, "sta_mac") == 0);
    CHECK(mode == NVS_READONLY || mode == NVS_READWRITE);
    ++fake.open_calls;
    fake.last_open_mode = mode;
    if (fake.open_error != ESP_OK) return fake.open_error;
    if (mode == NVS_READONLY && !fake.namespace_present) return ESP_ERR_NVS_NOT_FOUND;
    if (mode == NVS_READWRITE) fake.namespace_present = 1;
    *handle = HANDLE;
    return ESP_OK;
}

esp_err_t nvs_get_blob(nvs_handle_t handle, const char *key, void *value, size_t *length)
{
    CHECK(handle == HANDLE && strcmp(key, "policy") == 0);
    CHECK(value != NULL && length != NULL);
    ++fake.read_calls;
    if (fake.read_error != ESP_OK) return fake.read_error;
    if (!fake.key_present) return ESP_ERR_NVS_NOT_FOUND;
    size_t capacity = *length;
    *length = fake.saved_length;
    if (capacity < fake.saved_length) return ESP_ERR_NVS_INVALID_LENGTH;
    memcpy(value, fake.saved, fake.saved_length);
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t handle, const char *key, const void *value, size_t length)
{
    CHECK(handle == HANDLE && strcmp(key, "policy") == 0);
    CHECK(value != NULL && length == 8);
    ++fake.write_calls;
    if (fake.write_error != ESP_OK) return fake.write_error;
    memcpy(fake.pending, value, length);
    fake.pending_length = length;
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t handle)
{
    CHECK(handle == HANDLE);
    ++fake.commit_calls;
    if (fake.commit_error != ESP_OK) return fake.commit_error;
    memcpy(fake.saved, fake.pending, fake.pending_length);
    fake.saved_length = fake.pending_length;
    fake.key_present = 1;
    return ESP_OK;
}

void nvs_close(nvs_handle_t handle)
{
    CHECK(handle == HANDLE);
    ++fake.close_calls;
    fake.pending_length = 0;
}

static void expect_load(sta_mac_store_status_t status, sta_mac_policy_status_t policy_status)
{
    sta_mac_policy_record_t out = {77, STA_MAC_MODE_FIXED, {9, 9, 9, 9, 9, 9}};
    sta_mac_store_result_t result = sta_mac_policy_load(sta_mac_policy_nvs_store(), &out);
    CHECK(result.status == status);
    CHECK(result.policy_status == policy_status);
    if (status == STA_MAC_STORE_OK) {
        CHECK(out.version == fixed_record.version && out.mode == fixed_record.mode);
        CHECK(memcmp(out.mac, fixed_record.mac, sizeof(out.mac)) == 0);
    } else {
        CHECK(out.version == 77 && out.mode == STA_MAC_MODE_FIXED);
        CHECK(out.mac[0] == 9 && out.mac[5] == 9);
    }
}

static void test_missing(void)
{
    reset_nvs();
    expect_load(STA_MAC_STORE_MISSING_NAMESPACE, STA_MAC_POLICY_OK);
    CHECK(fake.open_calls == 1 && fake.last_open_mode == NVS_READONLY);
    CHECK(fake.read_calls == 0 && fake.close_calls == 0);

    fake.namespace_present = 1;
    expect_load(STA_MAC_STORE_MISSING_KEY, STA_MAC_POLICY_OK);
    CHECK(fake.read_calls == 1 && fake.close_calls == 1);
    CHECK(fake.write_calls == 0 && fake.commit_calls == 0);
}

static void test_roundtrip(void)
{
    reset_nvs();
    CHECK(sta_mac_policy_nvs_store() == sta_mac_policy_nvs_store());
    CHECK(sta_mac_policy_save(sta_mac_policy_nvs_store(), &fixed_record).status ==
          STA_MAC_STORE_OK);
    CHECK(fake.last_open_mode == NVS_READWRITE);
    CHECK(fake.saved_length == 8 && memcmp(fake.saved, fixed_bytes, 8) == 0);
    CHECK(fake.write_calls == 1 && fake.commit_calls == 1 && fake.close_calls == 1);
    expect_load(STA_MAC_STORE_OK, STA_MAC_POLICY_OK);
    CHECK(fake.last_open_mode == NVS_READONLY);
    CHECK(fake.read_calls == 1 && fake.close_calls == 2);
    CHECK(fake.write_calls == 1 && fake.commit_calls == 1);
}

static void test_invalid_records(void)
{
    static const uint8_t corrupt[][8] = {
        {2, 2, 2, 0xab, 0xcd, 0xef, 1, 0x23},
        {1, 99, 0, 0, 0, 0, 0, 0},
        {1, 0, 2, 0, 0, 0, 0, 0}
    };
    static const sta_mac_policy_status_t errors[] = {
        STA_MAC_POLICY_UNSUPPORTED_VERSION,
        STA_MAC_POLICY_INVALID_MODE,
        STA_MAC_POLICY_INVALID_PAYLOAD
    };
    for (size_t length = 7; length <= 9; length += 2) {
        reset_nvs();
        fake.namespace_present = fake.key_present = 1;
        fake.saved_length = length;
        memcpy(fake.saved, fixed_bytes, 8);
        if (length == 9) fake.saved[8] = 0xa5;
        uint8_t original[16];
        memcpy(original, fake.saved, sizeof(original));
        expect_load(STA_MAC_STORE_INVALID_RECORD, STA_MAC_POLICY_WRONG_LENGTH);
        CHECK(fake.read_calls == 1 && fake.close_calls == 1);
        CHECK(fake.write_calls == 0 && fake.commit_calls == 0);
        CHECK(fake.saved_length == length && memcmp(fake.saved, original, sizeof(original)) == 0);
    }
    for (size_t i = 0; i < sizeof(corrupt) / sizeof(corrupt[0]); ++i) {
        reset_nvs();
        fake.namespace_present = fake.key_present = 1;
        fake.saved_length = 8;
        memcpy(fake.saved, corrupt[i], 8);
        expect_load(STA_MAC_STORE_INVALID_RECORD, errors[i]);
        CHECK(fake.write_calls == 0 && fake.commit_calls == 0);
        CHECK(memcmp(fake.saved, corrupt[i], 8) == 0);
        CHECK(fake.close_calls == 1);
    }
}

static void test_failures(void)
{
    reset_nvs();
    fake.namespace_present = 1;
    fake.open_error = ESP_FAIL;
    expect_load(STA_MAC_STORE_OPEN_FAILED, STA_MAC_POLICY_OK);
    CHECK(fake.read_calls == 0 && fake.close_calls == 0);

    reset_nvs();
    fake.namespace_present = fake.key_present = 1;
    fake.read_error = ESP_FAIL;
    expect_load(STA_MAC_STORE_READ_FAILED, STA_MAC_POLICY_OK);
    CHECK(fake.read_calls == 1 && fake.close_calls == 1);
    CHECK(fake.write_calls == 0 && fake.commit_calls == 0);

    reset_nvs();
    fake.namespace_present = fake.key_present = 1;
    fake.read_error = ESP_ERR_NVS_TYPE_MISMATCH;
    expect_load(STA_MAC_STORE_INVALID_RECORD, STA_MAC_POLICY_INVALID_PAYLOAD);
    CHECK(fake.close_calls == 1 && fake.commit_calls == 0);

    reset_nvs();
    fake.open_error = ESP_FAIL;
    CHECK(sta_mac_policy_save(sta_mac_policy_nvs_store(), &fixed_record).status ==
          STA_MAC_STORE_OPEN_FAILED);
    CHECK(fake.last_open_mode == NVS_READWRITE);
    CHECK(fake.write_calls == 0 && fake.close_calls == 0);

    reset_nvs();
    fake.write_error = ESP_FAIL;
    CHECK(sta_mac_policy_save(sta_mac_policy_nvs_store(), &fixed_record).status ==
          STA_MAC_STORE_WRITE_FAILED);
    CHECK(fake.write_calls == 1 && fake.commit_calls == 0 && fake.close_calls == 1);
    CHECK(!fake.key_present);

    reset_nvs();
    fake.commit_error = ESP_FAIL;
    CHECK(sta_mac_policy_save(sta_mac_policy_nvs_store(), &fixed_record).status ==
          STA_MAC_STORE_COMMIT_FAILED);
    CHECK(fake.write_calls == 1 && fake.commit_calls == 1 && fake.close_calls == 1);
    CHECK(!fake.key_present && fake.saved_length == 0);
}

int main(void)
{
    test_missing();
    test_roundtrip();
    test_invalid_records();
    test_failures();
    puts("PASS: STA MAC NVS adapter missing, roundtrip, invalid records, failures");
    return 0;
}
