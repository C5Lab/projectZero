#define _FILE_OFFSET_BITS 64

#include "fs_command.h"

#include "crack_worker_core.h"
#include "crack_worker_transfer.h"
#include "fs_core.h"

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "driver/uart.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define FS_UART UART_NUM_0
#define FS_BLOCK_SIZE 1024U
#define FS_PREPARE_MS 10000U

static fs_command_hooks_t fs_hooks;

typedef struct {
    FILE *file;
    char target[FS_PATH_MAX];
    char stage[FS_PATH_MAX];
    char backup[FS_PATH_MAX];
    uint64_t size;
    uint32_t expected_crc;
    uint32_t actual_crc;
    bool replace;
    bool published;
    bool backup_pending;
    const char *failure;
} fs_put_context_t;

void fs_command_init(const fs_command_hooks_t *hooks)
{
    if (hooks) fs_hooks = *hooks;
}

static int fs_error(const char *code)
{
    printf("[FS/1] ERROR code=%s\n[FS/1] END\n", code);
    fflush(stdout);
    return 1;
}

static const char *fs_path_error(fs_path_result_t result)
{
    switch (result) {
    case FS_PATH_BAD_BASE64: return "bad_base64";
    case FS_PATH_TOO_LONG: return "path_too_long";
    default: return "invalid_path";
    }
}

static bool fs_ready(void)
{
    return fs_hooks.mount_sd && fs_hooks.mount_sd() == ESP_OK;
}

static bool fs_aux_paths(const char *target, char stage[FS_PATH_MAX],
                         char backup[FS_PATH_MAX])
{
    int stage_length = snprintf(stage, FS_PATH_MAX, "%s.fs-part", target);
    int backup_length = snprintf(backup, FS_PATH_MAX, "%s.fs-backup", target);
    return stage_length >= 0 && backup_length >= 0 &&
           stage_length < (int)FS_PATH_MAX && backup_length < (int)FS_PATH_MAX;
}

static int fs_list(const char *encoded)
{
    char path[FS_PATH_MAX];
    fs_path_result_t parsed = fs_resolve_path64(encoded, true, path, sizeof(path));
    if (parsed != FS_PATH_OK) return fs_error(fs_path_error(parsed));
    if (!fs_ready()) return fs_error("sd_unavailable");
    DIR *directory = opendir(path);
    if (!directory) return fs_error("not_directory");

    flockfile(stdout);
    printf("[FS/1] BEGIN\n");
    const char *failure = NULL;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char child[FS_PATH_MAX];
        int path_length = snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
        if (path_length < 0 || (size_t)path_length >= sizeof(child)) {
            failure = "path_too_long";
            break;
        }
        struct stat status;
        if (stat(child, &status) != 0) {
            failure = "stat_failed";
            break;
        }
        char name64[4 * FS_PATH_MAX / 3 + 8];
        if (!fs_base64_encode((const unsigned char *)entry->d_name,
                              strlen(entry->d_name), name64, sizeof(name64))) {
            failure = "name_too_long";
            break;
        }
        printf("[FS/1] ITEM type=%c size=%" PRIu64 " name64=%s\n",
               S_ISDIR(status.st_mode) ? 'd' : 'f',
               S_ISREG(status.st_mode) && status.st_size > 0 ?
                   (uint64_t)status.st_size : 0, name64);
    }
    closedir(directory);
    if (failure) printf("[FS/1] ERROR code=%s\n[FS/1] END\n", failure);
    else printf("[FS/1] END status=ok\n");
    fflush(stdout);
    funlockfile(stdout);
    return failure ? 1 : 0;
}

static int fs_get(const char *encoded)
{
    char path[FS_PATH_MAX];
    fs_path_result_t parsed = fs_resolve_path64(encoded, false, path, sizeof(path));
    if (parsed != FS_PATH_OK) return fs_error(fs_path_error(parsed));
    if (!fs_ready()) return fs_error("sd_unavailable");
    if (!fs_path_is_reserved(path)) {
        char stage[FS_PATH_MAX], backup[FS_PATH_MAX];
        if (fs_aux_paths(path, stage, backup) &&
            fs_recover_staged(stage, path, backup, NULL) == FS_RECOVERY_FAILED)
            return fs_error("recovery_failed");
    }
    struct stat status;
    if (stat(path, &status) != 0) return fs_error("not_found");
    if (!S_ISREG(status.st_mode)) return fs_error("not_file");
    if (!fs_hooks.send_file) return fs_error("unavailable");
    return fs_hooks.send_file(path);
}

static int fs_remove(const char *encoded)
{
    char path[FS_PATH_MAX];
    fs_path_result_t parsed = fs_resolve_path64(encoded, false, path, sizeof(path));
    if (parsed != FS_PATH_OK) return fs_error(fs_path_error(parsed));
    /* FatFS short-name aliases may otherwise address a recovery artifact. */
    if (strchr(path, '~') != NULL) return fs_error("unsafe_alias");
    if (fs_path_is_reserved(path)) return fs_error("reserved_path");
    if (!fs_ready()) return fs_error("sd_unavailable");

    struct stat status;
    int target_stat = stat(path, &status);
    if (target_stat == 0 && S_ISDIR(status.st_mode)) {
        /* FatFS reports a nonempty directory as EACCES (FR_DENIED), so inspect
         * it before rmdir rather than relying on the host's ENOTEMPTY errno. */
        DIR *directory = opendir(path);
        if (!directory)
            return fs_error(errno == ENOENT ? "not_found" : "delete_failed");
        bool nonempty = false;
        struct dirent *entry;
        errno = 0;
        while ((entry = readdir(directory)) != NULL) {
            if (strcmp(entry->d_name, ".") != 0 &&
                strcmp(entry->d_name, "..") != 0) {
                nonempty = true;
                break;
            }
        }
        int read_error = errno;
        int close_result = closedir(directory);
        if (read_error != 0 || close_result != 0)
            return fs_error("delete_failed");
        if (nonempty) return fs_error("dir_not_empty");
        if (rmdir(path) != 0) {
            if (errno == ENOTEMPTY || errno == EEXIST)
                return fs_error("dir_not_empty");
            return fs_error(errno == ENOENT ? "not_found" : "delete_failed");
        }
        if (fs_hooks.sync_sd) fs_hooks.sync_sd();
        printf("[FS/1] DONE type=d\n[FS/1] END\n");
        fflush(stdout);
        return 0;
    }
    if (target_stat != 0 && errno != ENOENT) return fs_error("stat_failed");
    if (target_stat == 0 && !S_ISREG(status.st_mode))
        return fs_error("unsupported_type");

    /* A pre-existing file may fit FS_PATH_MAX even when its recovery suffixes
     * do not. Keep enough room to inspect those siblings before deletion. */
    char stage[FS_PATH_MAX + sizeof(".fs-part")];
    char backup[FS_PATH_MAX + sizeof(".fs-backup")];
    int stage_length = snprintf(stage, sizeof(stage), "%s.fs-part", path);
    int backup_length = snprintf(backup, sizeof(backup), "%s.fs-backup", path);
    if (stage_length < 0 || (size_t)stage_length >= sizeof(stage) ||
        backup_length < 0 || (size_t)backup_length >= sizeof(backup))
        return fs_error("path_too_long");
    fs_recovery_result_t recovery = fs_recover_staged(stage, path, backup, NULL);
    if (recovery == FS_RECOVERY_FAILED) return fs_error("recovery_failed");
    if (recovery != FS_RECOVERY_NONE) return fs_error("recovered_retry");
    if (stat(path, &status) != 0)
        return fs_error(errno == ENOENT ? "not_found" : "stat_failed");
    if (!S_ISREG(status.st_mode)) return fs_error("unsupported_type");
    if (unlink(path) != 0)
        return fs_error(errno == ENOENT ? "not_found" : "delete_failed");
    if (fs_hooks.sync_sd) fs_hooks.sync_sd();
    printf("[FS/1] DONE type=f\n[FS/1] END\n");
    fflush(stdout);
    return 0;
}

static bool fs_is_stage_path(const char *path)
{
    static const char suffix[] = ".fs-part";
    const char *name = strrchr(path, '/');
    name = name ? name + 1 : path;
    size_t length = strlen(name);
    size_t suffix_length = sizeof(suffix) - 1;
    if (length <= suffix_length) return false;
    const char *ending = name + length - suffix_length;
    for (size_t index = 0; index < suffix_length; ++index) {
        unsigned char letter = (unsigned char)ending[index];
        if (letter >= 'A' && letter <= 'Z') letter += 'a' - 'A';
        if (letter != suffix[index]) return false;
    }
    return true;
}

static int fs_cleanup(const char *encoded)
{
    char path[FS_PATH_MAX];
    fs_path_result_t parsed = fs_resolve_path64(encoded, false, path, sizeof(path));
    if (parsed != FS_PATH_OK) return fs_error(fs_path_error(parsed));
    if (strchr(path, '~') != NULL) return fs_error("unsafe_alias");
    if (!fs_is_stage_path(path)) return fs_error("not_stage");
    if (!fs_ready()) return fs_error("sd_unavailable");

    struct stat status;
    if (stat(path, &status) != 0)
        return fs_error(errno == ENOENT ? "not_found" : "stat_failed");
    if (!S_ISREG(status.st_mode)) return fs_error("unsupported_type");
    if (unlink(path) != 0)
        return fs_error(errno == ENOENT ? "not_found" : "delete_failed");
    if (fs_hooks.sync_sd) fs_hooks.sync_sd();
    printf("[FS/1] CLEANED type=part\n[FS/1] END\n");
    fflush(stdout);
    return 0;
}

static int fs_uart_read(void *context, void *destination, size_t size,
                        uint32_t timeout_ms, size_t *received_out)
{
    (void)context;
    uint8_t *bytes = (uint8_t *)destination;
    size_t received = 0;
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (received < size && esp_timer_get_time() < deadline) {
        int64_t left_ms = (deadline - esp_timer_get_time() + 999) / 1000;
        TickType_t ticks = pdMS_TO_TICKS(left_ms > 100 ? 100 : left_ms);
        if (ticks == 0) ticks = 1;
        int got = uart_read_bytes(FS_UART, bytes + received, size - received, ticks);
        if (got < 0) {
            if (received_out) *received_out = received;
            return -1;
        }
        if (got > 0) received += (size_t)got;
    }
    if (received_out) *received_out = received;
    return received == size ? 1 : 0;
}

static bool fs_uart_write(const void *data, size_t length)
{
    const uint8_t *bytes = (const uint8_t *)data;
    while (length > 0) {
        int written = uart_write_bytes(FS_UART, bytes, length);
        if (written <= 0) return false;
        bytes += written;
        length -= (size_t)written;
    }
    return true;
}

static bool fs_transfer_write(void *context, const uint8_t *data, uint32_t length)
{
    fs_put_context_t *put = (fs_put_context_t *)context;
    return fwrite(data, 1, length, put->file) == length;
}

static void fs_transfer_crc(void *context, const uint8_t *data, uint32_t length)
{
    fs_put_context_t *put = (fs_put_context_t *)context;
    put->actual_crc = crack_worker_crc32_update(put->actual_crc, data, length);
}

static bool fs_transfer_checkpoint(void *context, uint64_t offset)
{
    (void)context;
    (void)offset;
    return true; /* FS/1 uploads always start at offset zero. */
}

static void fs_transfer_progress(void *context, uint64_t offset, uint32_t index)
{
    (void)context;
    (void)offset;
    (void)index;
}

static bool fs_transfer_finalize(void *context)
{
    fs_put_context_t *put = (fs_put_context_t *)context;
    if (put->actual_crc != put->expected_crc) {
        put->failure = "file_crc_mismatch";
        return false;
    }
    if (fflush(put->file) != 0 || fsync(fileno(put->file)) != 0) {
        put->failure = "sd_flush_failed";
        return false;
    }
    if (fclose(put->file) != 0) {
        put->file = NULL;
        put->failure = "close_failed";
        return false;
    }
    put->file = NULL;
    fs_publish_result_t published = fs_publish_staged(
        put->stage, put->target, put->backup, put->replace, NULL);
    if (published != FS_PUBLISH_OK && published != FS_PUBLISH_BACKUP_LEFT) {
        put->failure = published == FS_PUBLISH_ROLLBACK_FAILED ?
            "rollback_failed" : "publish_failed";
        return false;
    }
    put->published = true;
    put->backup_pending = published == FS_PUBLISH_BACKUP_LEFT;
    if (fs_hooks.sync_sd) fs_hooks.sync_sd();
    return true;
}

static bool fs_transfer_reply(void *context, const uint8_t frame[32])
{
    (void)context;
    return fs_uart_write(frame, 32);
}

static void fs_transfer_terminal(void *context, bool success, const char *reason)
{
    (void)context;
    (void)success;
    (void)reason;
}

static const crack_worker_transfer_ops_t fs_transfer_ops = {
    .read = fs_uart_read,
    .write = fs_transfer_write,
    .crc = fs_transfer_crc,
    .checkpoint = fs_transfer_checkpoint,
    .progress = fs_transfer_progress,
    .finalize = fs_transfer_finalize,
    .reply = fs_transfer_reply,
    .terminal = fs_transfer_terminal,
};

static uint32_t fs_rx_timeout_ms(uint32_t baud)
{
    if (baud == 0) baud = 115200;
    uint64_t wire_ms = ((uint64_t)FS_BLOCK_SIZE + 16U) * 10000ULL;
    wire_ms = (wire_ms + baud - 1U) / baud;
    uint64_t timeout = 1000U + 3U * wire_ms;
    return timeout > 30000U ? 30000U : (uint32_t)timeout;
}

static int fs_put(const char *encoded, const char *size_text,
                  const char *crc_text, bool replace)
{
    fs_put_context_t put = {.replace = replace};
    fs_path_result_t parsed = fs_resolve_path64(encoded, false,
                                                put.target, sizeof(put.target));
    if (parsed != FS_PATH_OK) return fs_error(fs_path_error(parsed));
    /* FAT short-name aliases use '~'; an upload through one could overwrite a
     * protected .fs-part/.fs-backup file without matching its long name. */
    if (strchr(put.target, '~') != NULL) return fs_error("unsafe_alias");
    if (fs_path_is_reserved(put.target)) return fs_error("reserved_path");
    if (!fs_parse_upload_identity(size_text, crc_text, &put.size,
                                  &put.expected_crc)) return fs_error("invalid_identity");
    if (!fs_aux_paths(put.target, put.stage, put.backup))
        return fs_error("path_too_long");
    if (!fs_ready()) return fs_error("sd_unavailable");
    fs_recovery_result_t recovery = fs_recover_staged(
        put.stage, put.target, put.backup, NULL);
    if (recovery == FS_RECOVERY_FAILED) return fs_error("recovery_failed");
    if (recovery != FS_RECOVERY_NONE) return fs_error("recovered_retry");
    struct stat status;
    if (stat(put.target, &status) == 0) {
        if (!S_ISREG(status.st_mode)) return fs_error("not_file");
        if (!replace) return fs_error("exists");
    } else if (errno != ENOENT) return fs_error("stat_failed");
    put.file = fopen(put.stage, "wb");
    if (!put.file) return fs_error("open_failed");
    uint8_t *payload = malloc(FS_BLOCK_SIZE);
    if (!payload) {
        fclose(put.file);
        unlink(put.stage);
        return fs_error("no_memory");
    }

    if (fs_hooks.transfer_active) fs_hooks.transfer_active(true);
    flockfile(stdout);
    if (uart_flush_input(FS_UART) != ESP_OK) {
        put.failure = "uart_flush_failed";
        goto finished;
    }
    uint32_t baud = fs_hooks.current_baud ? fs_hooks.current_baud() : 115200U;
    uint32_t rx_ms = fs_rx_timeout_ms(baud);
    printf("[FS/1] READY size=%" PRIu64 " offset=0 crc32=%08" PRIX32
           " bsize=%u ack_size=32 rx_ms=%" PRIu32 " prepare_ms=%u\n"
           "[FS/1] END\n\n", put.size, put.expected_crc, FS_BLOCK_SIZE,
           rx_ms, FS_PREPARE_MS);
    fflush(stdout);
    if (uart_wait_tx_done(FS_UART, pdMS_TO_TICKS(2000)) != ESP_OK) {
        put.failure = "uart_write_failed";
        goto finished;
    }

    crack_worker_transfer_state_t state = {
        .expected_size = put.size,
        .block_size = FS_BLOCK_SIZE,
        .ack32 = true,
    };
    crack_worker_transfer_session_t session = {
        .prepare_ms = FS_PREPARE_MS,
        .rx_ms = rx_ms,
    };
    bool received = crack_worker_transfer_receive(
        &state, &session, payload, FS_BLOCK_SIZE, &fs_transfer_ops, &put);
    if (!received && !put.failure) put.failure = session.reason;

finished:
    if (put.file) {
        if (fclose(put.file) != 0 && !put.failure) put.failure = "close_failed";
        put.file = NULL;
    }
    if (!put.published) unlink(put.stage);
    if (put.published) {
        printf("[FS/1] DONE size=%" PRIu64 " crc32=%08" PRIX32 "%s"
               "\n[FS/1] END\n", put.size, put.expected_crc,
               put.backup_pending ? " backup_pending=1" : "");
    } else {
        printf("[FS/1] ERROR code=%s\n[FS/1] END\n",
               put.failure ? put.failure : "transfer_failed");
    }
    fflush(stdout);
    funlockfile(stdout);
    if (fs_hooks.transfer_active) fs_hooks.transfer_active(false);
    free(payload);
    return put.published ? 0 : 1;
}

int fs_command_handle(int argc, char **argv)
{
    if (argc < 2) return fs_error("usage");
    if (strcmp(argv[1], "hello") == 0) {
        if (argc != 2) return fs_error("usage");
        printf("[FS/1] HELLO root=/sdcard/lab encoding=cp437 get=ftb1 put=ftb1_ack32 bsize=1024 rm=file_empty_dir cleanup=part_only\n"
               "[FS/1] END\n");
        fflush(stdout);
        return 0;
    }
    if (strcmp(argv[1], "ls") == 0)
        return argc == 3 ? fs_list(argv[2]) : fs_error("usage");
    if (strcmp(argv[1], "get") == 0)
        return argc == 3 ? fs_get(argv[2]) : fs_error("usage");
    if (strcmp(argv[1], "rm") == 0)
        return argc == 3 ? fs_remove(argv[2]) : fs_error("usage");
    if (strcmp(argv[1], "cleanup") == 0)
        return argc == 3 ? fs_cleanup(argv[2]) : fs_error("usage");
    if (strcmp(argv[1], "put") == 0) {
        if (argc != 5 && argc != 6) return fs_error("usage");
        if (argc == 6 && strcmp(argv[5], "replace") != 0) return fs_error("usage");
        return fs_put(argv[2], argv[3], argv[4], argc == 6);
    }
    return fs_error("usage");
}
