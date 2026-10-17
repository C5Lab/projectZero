#ifndef STA_MAC_POLICY_STORE_H
#define STA_MAC_POLICY_STORE_H

#include "sta_mac_policy_core.h"

typedef enum {
    STA_MAC_IO_OK = 0,
    STA_MAC_IO_MISSING,
    STA_MAC_IO_ERROR,
    STA_MAC_IO_BUFFER_TOO_SMALL
} sta_mac_io_status_t;

typedef enum {
    STA_MAC_STORE_READ_ONLY = 0,
    STA_MAC_STORE_READ_WRITE
} sta_mac_store_access_t;

/* Context identifies the namespace/key in the adapter. After successful open,
 * handle (including NULL if the adapter chooses) is passed unchanged to callbacks.
 * read sets actual_length on OK/BUFFER_TOO_SMALL, never writes beyond capacity.
 * Missing open means absent namespace; missing read means absent key.
 * close follows the NVS void-close model and must release the handle. */
typedef struct {
    void *context;
    sta_mac_io_status_t (*open)(void *context, sta_mac_store_access_t access, void **handle);
    sta_mac_io_status_t (*read)(void *handle, uint8_t *out, size_t capacity, size_t *actual_length);
    sta_mac_io_status_t (*write)(void *handle, const uint8_t *data, size_t length);
    sta_mac_io_status_t (*commit)(void *handle);
    void (*close)(void *handle);
} sta_mac_policy_store_t;

typedef enum {
    STA_MAC_STORE_OK = 0,
    STA_MAC_STORE_INVALID_ARGUMENT,
    STA_MAC_STORE_MISSING_NAMESPACE,
    STA_MAC_STORE_MISSING_KEY,
    STA_MAC_STORE_OPEN_FAILED,
    STA_MAC_STORE_READ_FAILED,
    STA_MAC_STORE_WRITE_FAILED,
    STA_MAC_STORE_COMMIT_FAILED,
    STA_MAC_STORE_INVALID_RECORD
} sta_mac_store_status_t;

typedef struct {
    sta_mac_store_status_t status;
    /* Meaningful for INVALID_RECORD; OK otherwise. */
    sta_mac_policy_status_t policy_status;
} sta_mac_store_result_t;

/* Load leaves out unchanged unless OK. Missing selects factory in the adapter;
 * this core does not hide corruption or rewrite records. */
sta_mac_store_result_t sta_mac_policy_load(const sta_mac_policy_store_t *store,
                                          sta_mac_policy_record_t *out);
sta_mac_store_result_t sta_mac_policy_save(const sta_mac_policy_store_t *store,
                                          const sta_mac_policy_record_t *record);

#endif
