#ifndef WIFI_TRUST_STORE_H
#define WIFI_TRUST_STORE_H

#include "fs_core.h"
#include "wifi_trust_core.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WIFI_TRUST_STORE_PATH "/sdcard/lab/wifi-trust/baseline-v1.jsonl"
#define WIFI_TRUST_STAGE_PATH "/sdcard/lab/wifi-trust/baseline-v1.stage"
#define WIFI_TRUST_BACKUP_PATH "/sdcard/lab/wifi-trust/baseline-v1.backup"
#define WIFI_TRUST_JSON_LINE_MAX 2048U
#define WIFI_TRUST_FILE_MAX \
    ((WIFI_TRUST_MAX_PROFILES + 2U) * WIFI_TRUST_JSON_LINE_MAX)

typedef struct {
    uint8_t boot_id[8];
    bool created_unix_known;
    uint64_t created_unix;
    uint64_t created_monotonic_us;
} wifi_trust_store_meta_t;

typedef enum {
    WIFI_TRUST_STORE_OK = 0,
    WIFI_TRUST_STORE_OK_BACKUP_PENDING,
    WIFI_TRUST_STORE_PUBLISHED_UNCERTAIN,
    WIFI_TRUST_STORE_RECOVERED_RETRY,
    WIFI_TRUST_STORE_NOT_FOUND,
    WIFI_TRUST_STORE_IO,
    WIFI_TRUST_STORE_FORMAT,
    WIFI_TRUST_STORE_CAPACITY,
    WIFI_TRUST_STORE_PUBLISH,
    WIFI_TRUST_STORE_RECOVERY
} wifi_trust_store_result_t;

typedef enum {
    WIFI_TRUST_RECOVERY_NONE = 0,
    WIFI_TRUST_RECOVERY_CLEARED_STAGE,
    WIFI_TRUST_RECOVERY_RESTORED_BACKUP,
    WIFI_TRUST_RECOVERY_KEPT_TARGET
} wifi_trust_recovery_action_t;

typedef enum {
    WIFI_TRUST_IO_OK = 0,
    WIFI_TRUST_IO_EOF,
    WIFI_TRUST_IO_MISSING,
    WIFI_TRUST_IO_ERROR
} wifi_trust_io_result_t;

typedef enum {
    WIFI_TRUST_PATH_MISSING = 0,
    WIFI_TRUST_PATH_FILE,
    WIFI_TRUST_PATH_OTHER,
    WIFI_TRUST_PATH_ERROR
} wifi_trust_path_state_t;

typedef struct {
    void *context;
    bool (*enter)(void *context);
    void (*leave)(void *context);
    wifi_trust_io_result_t (*open)(void *context, const char *path,
                                   bool truncate, void **handle);
    wifi_trust_io_result_t (*read)(void *handle, uint8_t *out,
                                   size_t capacity, size_t *actual);
    wifi_trust_io_result_t (*write)(void *handle, const uint8_t *data,
                                    size_t length, size_t *actual);
    wifi_trust_io_result_t (*flush)(void *handle);
    wifi_trust_io_result_t (*sync)(void *handle);
    /* close always consumes a non-NULL handle, even when it reports ERROR. */
    wifi_trust_io_result_t (*close)(void *handle);
    wifi_trust_path_state_t (*path_state)(void *context, const char *path);
    bool (*rename_path)(void *context, const char *from, const char *to);
    bool (*remove_path)(void *context, const char *path);
    bool (*sync_volume)(void *context);
    fs_publish_result_t (*publish_staged)(void *context, const char *stage,
                                          const char *target,
                                          const char *backup, bool replace);
    fs_recovery_result_t (*recover_staged)(void *context, const char *stage,
                                           const char *target,
                                           const char *backup);
} wifi_trust_store_ops_t;

/* Canonical AP JSON is flat. Its exact key order is:
 * v, type, bssid, ssid_status, ssid_hex, source, privacy;
 * rsn_status, rsn_group, rsn_pairwise, rsn_akm,
 * rsn_capabilities_present, rsn_pmf_capable, rsn_pmf_required,
 * rsn_management; the same eight keys with the wpa_ prefix; rsnxe_status,
 * rsnxe_hex; wps_status, wps_present, wps_state, wps_config_methods,
 * wps_setup_locked, wps_selected_registrar; then, for manufacturer,
 * model_name, model_number and device_name, wps_<name>_hex followed by
 * wps_<name>_truncated; finally country_status, country_hex, channel,
 * observed_us. Binary values use uppercase hex, except BSSID and header boot
 * ID which are lowercase. A nullable value is JSON null, never an empty
 * sentinel. Every line ends in one LF on disk; codec functions exclude it.
 */
int wifi_trust_store_format_ap_line(char *out, size_t capacity,
                                    const wifi_trust_profile_t *profile);
bool wifi_trust_store_parse_ap_line(const char *line, size_t length,
                                    wifi_trust_profile_t *profile);

wifi_trust_store_result_t wifi_trust_store_load(
    const char *path, wifi_trust_profile_t *profiles, size_t capacity,
    size_t *count, wifi_trust_store_meta_t *meta,
    wifi_trust_recovery_action_t *recovery,
    const wifi_trust_store_ops_t *ops);

/* Passive Shield baseline load. This path performs no staged recovery and
 * requires only enter/open/read/close/leave. It never invokes a mutating op. */
wifi_trust_store_result_t wifi_trust_store_load_readonly(
    const char *path, wifi_trust_profile_t *profiles, size_t capacity,
    size_t *count, wifi_trust_store_meta_t *meta,
    const wifi_trust_store_ops_t *ops);

wifi_trust_store_result_t wifi_trust_store_publish(
    const wifi_trust_profile_t *profiles, size_t count,
    const wifi_trust_store_meta_t *meta,
    const wifi_trust_store_ops_t *ops);

wifi_trust_store_result_t wifi_trust_store_clear(
    const wifi_trust_store_ops_t *ops);

#endif
