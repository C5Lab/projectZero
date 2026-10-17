#include "sta_mac_policy_store.h"

static sta_mac_store_result_t result(sta_mac_store_status_t status)
{
    return (sta_mac_store_result_t){status, STA_MAC_POLICY_OK};
}

static sta_mac_store_result_t invalid_record(sta_mac_policy_status_t status)
{
    return (sta_mac_store_result_t){STA_MAC_STORE_INVALID_RECORD, status};
}

sta_mac_store_result_t sta_mac_policy_load(const sta_mac_policy_store_t *store, sta_mac_policy_record_t *out)
{
    if (!store || !out || !store->open || !store->read || !store->close)
        return result(STA_MAC_STORE_INVALID_ARGUMENT);
    void *handle = NULL;
    sta_mac_io_status_t io = store->open(store->context, STA_MAC_STORE_READ_ONLY, &handle);
    if (io == STA_MAC_IO_MISSING) return result(STA_MAC_STORE_MISSING_NAMESPACE);
    if (io != STA_MAC_IO_OK) return result(STA_MAC_STORE_OPEN_FAILED);
    uint8_t bytes[STA_MAC_POLICY_RECORD_SIZE];
    size_t length = 0;
    io = store->read(handle, bytes, sizeof(bytes), &length);
    sta_mac_store_result_t loaded;
    if (io == STA_MAC_IO_MISSING) loaded = result(STA_MAC_STORE_MISSING_KEY);
    else if (io == STA_MAC_IO_BUFFER_TOO_SMALL) loaded = invalid_record(STA_MAC_POLICY_WRONG_LENGTH);
    else if (io != STA_MAC_IO_OK) loaded = result(STA_MAC_STORE_READ_FAILED);
    else {
        sta_mac_policy_status_t status = sta_mac_policy_decode(bytes, length, out);
        loaded = status == STA_MAC_POLICY_OK ? result(STA_MAC_STORE_OK) : invalid_record(status);
    }
    store->close(handle);
    return loaded;
}

sta_mac_store_result_t sta_mac_policy_save(const sta_mac_policy_store_t *store, const sta_mac_policy_record_t *record)
{
    if (!store || !record || !store->open || !store->write || !store->commit || !store->close)
        return result(STA_MAC_STORE_INVALID_ARGUMENT);
    uint8_t bytes[STA_MAC_POLICY_RECORD_SIZE];
    sta_mac_policy_status_t status = sta_mac_policy_encode(record, bytes, sizeof(bytes));
    if (status != STA_MAC_POLICY_OK) return invalid_record(status);
    void *handle = NULL;
    sta_mac_io_status_t io = store->open(store->context, STA_MAC_STORE_READ_WRITE, &handle);
    if (io == STA_MAC_IO_MISSING) return result(STA_MAC_STORE_MISSING_NAMESPACE);
    if (io != STA_MAC_IO_OK) return result(STA_MAC_STORE_OPEN_FAILED);
    sta_mac_store_result_t saved;
    if (store->write(handle, bytes, sizeof(bytes)) != STA_MAC_IO_OK)
        saved = result(STA_MAC_STORE_WRITE_FAILED);
    else if (store->commit(handle) != STA_MAC_IO_OK)
        saved = result(STA_MAC_STORE_COMMIT_FAILED);
    else saved = result(STA_MAC_STORE_OK);
    store->close(handle);
    return saved;
}
