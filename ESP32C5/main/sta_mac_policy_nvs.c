#include "sta_mac_policy_nvs.h"

#include <stdlib.h>

#include "nvs.h"

#define STA_MAC_NVS_NAMESPACE "sta_mac"
#define STA_MAC_NVS_KEY "policy"

static sta_mac_io_status_t open_store(void *context, sta_mac_store_access_t access,
                                      void **handle)
{
    (void)context;
    if (handle == NULL) return STA_MAC_IO_ERROR;
    *handle = NULL;
    nvs_handle_t *native = malloc(sizeof(*native));
    if (native == NULL) return STA_MAC_IO_ERROR;
    nvs_open_mode_t mode = access == STA_MAC_STORE_READ_ONLY ? NVS_READONLY : NVS_READWRITE;
    esp_err_t err = nvs_open(STA_MAC_NVS_NAMESPACE, mode, native);
    if (err != ESP_OK) {
        free(native);
        return err == ESP_ERR_NVS_NOT_FOUND ? STA_MAC_IO_MISSING : STA_MAC_IO_ERROR;
    }
    *handle = native;
    return STA_MAC_IO_OK;
}

static sta_mac_io_status_t read_store(void *handle, uint8_t *out, size_t capacity,
                                      size_t *actual_length)
{
    if (handle == NULL || out == NULL || actual_length == NULL) return STA_MAC_IO_ERROR;
    size_t length = capacity;
    esp_err_t err = nvs_get_blob(*(nvs_handle_t *)handle, STA_MAC_NVS_KEY, out, &length);
    if (err == ESP_OK || err == ESP_ERR_NVS_INVALID_LENGTH) {
        *actual_length = length;
        return err == ESP_ERR_NVS_INVALID_LENGTH || length > capacity
            ? STA_MAC_IO_BUFFER_TOO_SMALL : STA_MAC_IO_OK;
    }
    if (err == ESP_ERR_NVS_TYPE_MISMATCH) return STA_MAC_IO_INVALID_RECORD;
    return err == ESP_ERR_NVS_NOT_FOUND ? STA_MAC_IO_MISSING : STA_MAC_IO_ERROR;
}

static sta_mac_io_status_t write_store(void *handle, const uint8_t *data, size_t length)
{
    if (handle == NULL || data == NULL || length != STA_MAC_POLICY_RECORD_SIZE)
        return STA_MAC_IO_ERROR;
    return nvs_set_blob(*(nvs_handle_t *)handle, STA_MAC_NVS_KEY, data, length) == ESP_OK
        ? STA_MAC_IO_OK : STA_MAC_IO_ERROR;
}

static sta_mac_io_status_t commit_store(void *handle)
{
    if (handle == NULL) return STA_MAC_IO_ERROR;
    return nvs_commit(*(nvs_handle_t *)handle) == ESP_OK ? STA_MAC_IO_OK : STA_MAC_IO_ERROR;
}

static void close_store(void *handle)
{
    if (handle == NULL) return;
    nvs_close(*(nvs_handle_t *)handle);
    free(handle);
}

const sta_mac_policy_store_t *sta_mac_policy_nvs_store(void)
{
    static const sta_mac_policy_store_t store = {
        NULL, open_store, read_store, write_store, commit_store, close_store
    };
    return &store;
}
