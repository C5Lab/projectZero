#ifndef JANOS_FS_CORE_H
#define JANOS_FS_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef FS_ROOT
#define FS_ROOT "/sdcard/lab"
#endif
#define FS_PATH_MAX 192U

typedef enum {
    FS_PATH_OK = 0,
    FS_PATH_BAD_BASE64,
    FS_PATH_INVALID,
    FS_PATH_TOO_LONG,
} fs_path_result_t;

bool fs_base64_encode(const unsigned char *input, size_t length,
                      char *output, size_t capacity);
bool fs_path_is_reserved(const char *path);
fs_path_result_t fs_resolve_path64(const char *encoded, bool allow_root,
                                   char *full, size_t capacity);
bool fs_parse_upload_identity(const char *size_text, const char *crc_text,
                              uint64_t *size, uint32_t *crc);

typedef enum {
    FS_PUBLISH_OK = 0,
    FS_PUBLISH_EXISTS,
    FS_PUBLISH_BAD_STAGE,
    FS_PUBLISH_BAD_TARGET,
    FS_PUBLISH_BACKUP_EXISTS,
    FS_PUBLISH_RENAME_FAILED,
    FS_PUBLISH_ROLLBACK_FAILED,
    FS_PUBLISH_IO_ERROR,
    FS_PUBLISH_BACKUP_LEFT,
} fs_publish_result_t;

typedef struct {
    int (*rename_file)(const char *from, const char *to);
    int (*remove_file)(const char *path);
} fs_publish_ops_t;

fs_publish_result_t fs_publish_staged(const char *stage, const char *target,
                                      const char *backup, bool replace,
                                      const fs_publish_ops_t *ops);

typedef enum {
    FS_RECOVERY_NONE = 0,
    FS_RECOVERY_CLEARED_STAGE,
    FS_RECOVERY_RESTORED_BACKUP,
    FS_RECOVERY_KEPT_TARGET,
    FS_RECOVERY_FAILED,
} fs_recovery_result_t;

fs_recovery_result_t fs_recover_staged(const char *stage, const char *target,
                                       const char *backup,
                                       const fs_publish_ops_t *ops);

#endif
