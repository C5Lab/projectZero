#define _FILE_OFFSET_BITS 64

#include "crack_worker.h"

#include "crack_worker_core.h"
#include "crack_worker_crypto.h"
#include "crack_worker_transfer.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "driver/uart.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#define CW_UART UART_NUM_0
#define CW_ROOT "/sdcard/lab/crack_worker"
#define CW_FT_HEADER_SIZE 16U
#define CW_FT_ACK 0x06U
#define CW_FT_NAK 0x15U
#define CW_FT_CAN 0x18U
#define CW_FT_BLOCK_DEFAULT 8192U
#define CW_FT_BLOCK_MIN 512U
#define CW_FT_BLOCK_MAX 32768U
#define CW_FT_MAX_NAKS 3U
#define CW_PART_CHECKPOINT_BYTES (256U * 1024U)
#define CW_MAX_RECORDS 16U
#define CW_TASK_STACK 12288U

typedef enum {
    CW_JOB_IDLE = 0,
    CW_JOB_RUNNING,
    CW_JOB_FOUND,
    CW_JOB_NOT_FOUND,
    CW_JOB_CANCELLED,
    CW_JOB_ERROR,
} cw_job_state_t;

typedef struct {
    cw_job_state_t state;
    char id[32];
    char capture_path[128];
    char wordlist_path[128];
    uint64_t range_start;
    uint64_t range_end;
    crack_worker_progress_t progress;
    int64_t started_us;
    int64_t last_progress_us;
    volatile bool cancel_requested;
    TaskHandle_t task;
    char password_hex[127];
    char error[32];
} cw_job_t;

typedef struct {
    unsigned checkpoint_calls;
} cw_checkpoint_t;

typedef struct {
    bool used;
    char path[128];
    uint64_t size;
    int64_t mtime;
    uint32_t crc32;
} cw_validated_file_t;

typedef struct {
    char phase[24];
    char reason[32];
    uint64_t header_got;
    uint64_t header_expected;
    uint64_t payload_got;
    uint64_t payload_expected;
    uint64_t offset;
    uint64_t block_index;
    uint32_t baud;
    unsigned duplicates;
    uint64_t read_calls;
    uint64_t read_bytes;
    uint64_t sd_write_calls;
    uint64_t sd_write_bytes;
    uint64_t ack_attempts;
    uint64_t acks_sent;
    uint64_t checkpoint_calls;
    uint64_t stage_us;
} cw_transfer_diag_t;

static crack_worker_ensure_sd_fn cw_ensure_sd;
static crack_worker_transfer_active_fn cw_transfer_active;
static crack_worker_current_baud_fn cw_current_baud;
static SemaphoreHandle_t cw_mutex;
static cw_job_t cw_job;
static cw_validated_file_t cw_validated[8];
static cw_transfer_diag_t cw_transfer_diag = {
    .phase = "idle",
    .reason = "none",
};

static void cw_diag_stage(const char *phase, const char *reason)
{
    snprintf(cw_transfer_diag.phase, sizeof(cw_transfer_diag.phase), "%s", phase);
    snprintf(cw_transfer_diag.reason, sizeof(cw_transfer_diag.reason), "%s", reason);
    cw_transfer_diag.stage_us = (uint64_t)esp_timer_get_time();
}

static void cw_print(const char *format, ...)
{
    flockfile(stdout);
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    fflush(stdout);
    funlockfile(stdout);
}

static bool cw_parse_u64(const char *text, int base, uint64_t *value)
{
    if (text == NULL || value == NULL || text[0] == '-' || text[0] == '\0') return false;
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, base);
    if (errno == ERANGE || end == text || *end != '\0') return false;
    *value = (uint64_t)parsed;
    return true;
}

static bool cw_kind_path(const char *kind, uint64_t size, uint32_t crc,
                         char *path, size_t path_size)
{
    const char *directory;
    const char *extension;
    if (strcmp(kind, "wordlist") == 0) {
        directory = CW_ROOT "/wordlists";
        extension = "txt";
    } else if (strcmp(kind, "capture") == 0) {
        directory = CW_ROOT "/captures";
        extension = "hccapx";
    } else {
        return false;
    }
    int written = snprintf(path, path_size, "%s/%" PRIu64 "_%08" PRIX32 ".%s",
                           directory, size, crc, extension);
    return written > 0 && (size_t)written < path_size;
}

static void cw_remember_validated(const char *path, uint64_t size, uint32_t crc,
                                  int64_t mtime)
{
    size_t slot = 0;
    for (size_t i = 0; i < sizeof(cw_validated) / sizeof(cw_validated[0]); ++i) {
        if (cw_validated[i].used && strcmp(cw_validated[i].path, path) == 0) {
            slot = i;
            goto store;
        }
        if (!cw_validated[i].used) {
            slot = i;
            goto store;
        }
    }
store:
    cw_validated[slot].used = true;
    snprintf(cw_validated[slot].path, sizeof(cw_validated[slot].path), "%s", path);
    cw_validated[slot].size = size;
    cw_validated[slot].mtime = mtime;
    cw_validated[slot].crc32 = crc;
}

static bool cw_marker_path(const char *path, char *marker, size_t marker_size)
{
    int written = snprintf(marker, marker_size, "%s.verified", path);
    return written > 0 && (size_t)written < marker_size;
}

static bool cw_record_verified_file(const char *path, uint64_t size, uint32_t crc)
{
    struct stat status;
    char marker[160];
    if (stat(path, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size < 0 || (uint64_t)status.st_size != size) {
        return false;
    }
    if (cw_marker_path(path, marker, sizeof(marker))) {
        /* A marker write failure is recoverable: this boot still trusts the
         * CRC-checked bytes in RAM, while the next boot imports them again. */
        (void)crack_worker_verified_marker_write(
            marker, size, crc, (int64_t)status.st_mtime);
    }
    cw_remember_validated(path, size, crc, (int64_t)status.st_mtime);
    return true;
}

static void cw_remove_cached_file(const char *path)
{
    char marker[160];
    unlink(path);
    if (cw_marker_path(path, marker, sizeof(marker))) unlink(marker);
    for (size_t i = 0; i < sizeof(cw_validated) / sizeof(cw_validated[0]); ++i) {
        if (cw_validated[i].used && strcmp(cw_validated[i].path, path) == 0)
            cw_validated[i].used = false;
    }
}

/* A CRC-verified transfer leaves a persistent marker, so later boots can prove
 * the content-addressed cache entry from size, CRC and mtime without blocking
 * the console to scan a large file. Legacy entries without a marker are
 * intentionally untrusted and imported again once. */
static bool cw_file_matches(const char *path, uint64_t size, uint32_t crc)
{
    struct stat status;
    char marker[160];
    bool marker_ok = cw_marker_path(path, marker, sizeof(marker));
    if (stat(path, &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0 ||
        (uint64_t)status.st_size != size) {
        if (marker_ok) unlink(marker);
        return false;
    }
    for (size_t i = 0; i < sizeof(cw_validated) / sizeof(cw_validated[0]); ++i) {
        if (cw_validated[i].used && cw_validated[i].size == size &&
            cw_validated[i].crc32 == crc &&
            cw_validated[i].mtime == (int64_t)status.st_mtime &&
            strcmp(cw_validated[i].path, path) == 0) {
            return true;
        }
    }
    if (marker_ok && crack_worker_verified_file_matches(path, marker, size, crc)) {
        cw_remember_validated(path, size, crc, (int64_t)status.st_mtime);
        return true;
    }
    if (marker_ok) unlink(marker);
    return false;
}

static bool cw_make_dirs(void)
{
    const char *directories[] = {
        "/sdcard/lab", CW_ROOT, CW_ROOT "/wordlists", CW_ROOT "/captures"
    };
    for (size_t i = 0; i < sizeof(directories) / sizeof(directories[0]); ++i) {
        if (mkdir(directories[i], 0775) != 0 && errno != EEXIST) return false;
    }
    return true;
}

static uint32_t cw_le32(const uint8_t *source)
{
    return (uint32_t)source[0] | ((uint32_t)source[1] << 8) |
           ((uint32_t)source[2] << 16) | ((uint32_t)source[3] << 24);
}

static uint32_t cw_wire_ms(uint32_t block_size, uint32_t baud)
{
    if (baud == 0) baud = 115200U;
    uint64_t bits_ms = ((uint64_t)block_size + CW_FT_HEADER_SIZE) * 10ULL * 1000ULL;
    return (uint32_t)((bits_ms + baud - 1U) / baud);
}

static uint32_t cw_receive_timeout_ms(uint32_t block_size)
{
    uint32_t baud = cw_current_baud != NULL ? cw_current_baud() : 115200U;
    uint32_t timeout = 1000U + 3U * cw_wire_ms(block_size, baud);
    return timeout > 30000U ? 30000U : timeout;
}

static bool cw_uart_write_all(const void *data, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)data;
    while (size > 0) {
        int written = uart_write_bytes(CW_UART, bytes, size);
        if (written <= 0) return false;
        bytes += written;
        size -= (size_t)written;
    }
    return true;
}

static bool cw_send_block_reply(uint8_t status, uint32_t block_index,
                                uint64_t committed_offset, bool ack32)
{
    if (!ack32) return cw_uart_write_all(&status, 1);
    uint8_t frame[CRACK_WORKER_ACK32_SIZE];
    return crack_worker_ack32_build(frame, block_index, status, committed_offset) &&
           cw_uart_write_all(frame, sizeof(frame));
}

static int cw_uart_read_exact(void *destination, size_t size, uint32_t timeout_ms,
                              size_t *received_out)
{
    uint8_t *bytes = (uint8_t *)destination;
    size_t received = 0;
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_ms * 1000;
    while (received < size && esp_timer_get_time() < deadline) {
        int read = uart_read_bytes(CW_UART, bytes + received, size - received,
                                   pdMS_TO_TICKS(100));
        if (read < 0) {
            if (received_out != NULL) *received_out = received;
            return -1;
        }
        if (read > 0) received += (size_t)read;
    }
    if (received_out != NULL) *received_out = received;
    return received == size ? 1 : 0;
}

static bool cw_partial_checkpoint(FILE *file, const char *meta_path,
                                  uint64_t expected_size, uint32_t expected_crc,
                                  uint64_t offset, uint32_t prefix_crc,
                                  uint32_t block_size)
{
    if (fflush(file) != 0) return false;
    int fd = fileno(file);
    if (fd >= 0 && fsync(fd) != 0) return false;
    crack_worker_partial_checkpoint_t checkpoint = {
        .expected_size = expected_size,
        .expected_crc32 = expected_crc,
        .offset = offset,
        .prefix_crc32 = prefix_crc,
        .block_size = block_size,
    };
    return crack_worker_partial_checkpoint_write(meta_path, &checkpoint) ==
           CRACK_WORKER_CORE_OK;
}

static int cw_diag(int argc, char **argv)
{
    (void)argv;
    if (argc != 2) {
        cw_print("[CRACK/1] REJECTED code=usage detail=diag\r\n");
        return 0;
    }
    cw_print("[CRACK/1] DIAG phase=%s reason=%s header_got=%" PRIu64
             " header_expected=%" PRIu64 " payload_got=%" PRIu64
             " payload_expected=%" PRIu64 " offset=%" PRIu64
             " block=%" PRIu64 " baud=%" PRIu32 " duplicates=%u"
             " rd=%" PRIu64 " rb=%" PRIu64 " sd=%" PRIu64
             " sb=%" PRIu64 " aa=%" PRIu64 " as=%" PRIu64
             " cp=%" PRIu64 " stage_us=%" PRIu64 "\r\n",
             cw_transfer_diag.phase, cw_transfer_diag.reason,
             cw_transfer_diag.header_got, cw_transfer_diag.header_expected,
             cw_transfer_diag.payload_got, cw_transfer_diag.payload_expected,
             cw_transfer_diag.offset, cw_transfer_diag.block_index,
             cw_transfer_diag.baud, cw_transfer_diag.duplicates,
             cw_transfer_diag.read_calls, cw_transfer_diag.read_bytes,
             cw_transfer_diag.sd_write_calls, cw_transfer_diag.sd_write_bytes,
             cw_transfer_diag.ack_attempts, cw_transfer_diag.acks_sent,
             cw_transfer_diag.checkpoint_calls, cw_transfer_diag.stage_us);
    return 0;
}

static bool cw_crc_prefix(FILE *file, uint64_t size, uint32_t *crc)
{
    uint8_t buffer[4096];
    size_t since_yield = 0;
    *crc = 0;
    if (fseeko(file, 0, SEEK_SET) != 0) return false;
    while (size > 0) {
        size_t wanted = size > sizeof(buffer) ? sizeof(buffer) : (size_t)size;
        size_t got = fread(buffer, 1, wanted, file);
        if (got != wanted) return false;
        *crc = crack_worker_crc32_update(*crc, buffer, got);
        size -= got;
        since_yield += got;
        if (since_yield >= 256U * 1024U) {
            since_yield = 0;
            vTaskDelay(1);
        }
    }
    return true;
}

static bool cw_job_running(void)
{
    bool running;
    xSemaphoreTake(cw_mutex, portMAX_DELAY);
    running = cw_job.state == CW_JOB_RUNNING;
    xSemaphoreGive(cw_mutex);
    return running;
}

static int cw_probe(int argc, char **argv)
{
    uint64_t size;
    uint64_t crc_value;
    char path[128];
    if (argc != 5 || !cw_parse_u64(argv[3], 10, &size) ||
        !cw_parse_u64(argv[4], 16, &crc_value) || crc_value > UINT32_MAX ||
        !cw_kind_path(argv[2], size, (uint32_t)crc_value, path, sizeof(path))) {
        cw_print("[CRACK/1] REJECTED code=usage detail=probe_kind_size_crc\r\n");
        return 0;
    }
    if (cw_ensure_sd == NULL || cw_ensure_sd() != ESP_OK) {
        cw_print("[CRACK/1] REJECTED code=sd_unavailable\r\n");
        return 0;
    }
    bool present = cw_file_matches(path, size, (uint32_t)crc_value);
    if (!present) cw_remove_cached_file(path);
    cw_print("[CRACK/1] FILE kind=%s state=%s size=%" PRIu64
             " crc32=%08" PRIX32 " path=%s\r\n",
             argv[2], present ? "present" : "missing",
             size, (uint32_t)crc_value, path);
    return 0;
}

static int cw_reset_partial(int argc, char **argv)
{
    uint64_t size;
    uint64_t crc_value;
    char path[128];
    char part_path[136];
    char meta_path[144];
    if (argc != 5 || !cw_parse_u64(argv[3], 10, &size) ||
        !cw_parse_u64(argv[4], 16, &crc_value) || crc_value > UINT32_MAX ||
        !cw_kind_path(argv[2], size, (uint32_t)crc_value, path, sizeof(path)) ||
        snprintf(part_path, sizeof(part_path), "%s.part", path) <= 0 ||
        snprintf(meta_path, sizeof(meta_path), "%s.meta", part_path) <= 0) {
        cw_print("[CRACK/1] REJECTED code=usage detail=reset_kind_size_crc\r\n");
        return 0;
    }
    if (cw_job_running()) {
        cw_print("[CRACK/1] REJECTED code=busy\r\n");
        return 0;
    }
    if (unlink(part_path) != 0 && errno != ENOENT) {
        cw_print("[CRACK/1] REJECTED code=reset_failed errno=%d\r\n", errno);
        return 0;
    }
    if (unlink(meta_path) != 0 && errno != ENOENT) {
        cw_print("[CRACK/1] REJECTED code=reset_failed errno=%d\r\n", errno);
        return 0;
    }
    cw_print("[CRACK/1] RESET kind=%s size=%" PRIu64 " crc32=%08" PRIX32
             "\r\n", argv[2], size, (uint32_t)crc_value);
    return 0;
}

typedef struct {
    FILE **file;
    const char *kind, *part_path, *meta_path, *final_path, *reason;
    uint64_t size, last_checkpoint;
    uint32_t expected_crc, running_crc, next_crc, block_size;
    bool partial_valid, discard_partial, success;
    crack_worker_transfer_state_t *state;
} cw_ack32_context_t;

static int cw_ack32_read(void *context, void *data, size_t size,
                          uint32_t timeout, size_t *received)
{
    (void)context;
    if (size == 1) {
        cw_diag_stage("header_first", "pending");
        cw_transfer_diag.header_got = 0;
        cw_transfer_diag.header_expected = CW_FT_HEADER_SIZE;
        cw_transfer_diag.payload_got = 0;
        cw_transfer_diag.payload_expected = 0;
    } else if (size == CW_FT_HEADER_SIZE - 1U) {
        cw_diag_stage("header_rest", "pending");
    } else {
        cw_diag_stage("payload_read", "pending");
        cw_transfer_diag.payload_got = 0;
        cw_transfer_diag.payload_expected = size;
    }
    cw_transfer_diag.read_calls++;
    int result = cw_uart_read_exact(data, size, timeout, received);
    size_t got = received != NULL ? *received : 0;
    cw_transfer_diag.read_bytes += got;
    if (size == 1) cw_transfer_diag.header_got = got;
    else if (size == CW_FT_HEADER_SIZE - 1U) cw_transfer_diag.header_got += got;
    else cw_transfer_diag.payload_got = got;
    snprintf(cw_transfer_diag.reason, sizeof(cw_transfer_diag.reason), "%s",
             result > 0 ? "ok" : (result < 0 ? "uart_read_failed" : "timeout"));
    return result;
}

static bool cw_ack32_write(void *context, const uint8_t *data, uint32_t size)
{
    cw_ack32_context_t *c = context;
    cw_diag_stage("sd_write", "pending");
    cw_transfer_diag.sd_write_calls++;
    size_t written = fwrite(data, 1, size, *c->file);
    cw_transfer_diag.sd_write_bytes += written;
    cw_diag_stage(written == size ? "sd_written" : "sd_write",
                  written == size ? "ok" : "failed");
    return written == size;
}

static void cw_ack32_crc(void *context, const uint8_t *data, uint32_t size)
{
    cw_ack32_context_t *c = context;
    c->next_crc = crack_worker_crc32_update(c->running_crc, data, size);
}

static bool cw_ack32_checkpoint(void *context, uint64_t offset)
{
    cw_ack32_context_t *c = context;
    if (offset - c->last_checkpoint < CW_PART_CHECKPOINT_BYTES && offset != c->size)
        return true;
    cw_diag_stage("checkpoint", "pending");
    cw_transfer_diag.checkpoint_calls++;
    if (!cw_partial_checkpoint(*c->file, c->meta_path, c->size, c->expected_crc,
                               offset, c->next_crc, c->block_size)) {
        c->partial_valid = false;
        cw_diag_stage("checkpoint", "failed");
        return false;
    }
    c->last_checkpoint = offset;
    cw_diag_stage("checkpoint", "ok");
    return true;
}

static void cw_ack32_progress(void *context, uint64_t offset, uint32_t index)
{
    cw_ack32_context_t *c = context;
    c->running_crc = c->next_crc;
    cw_transfer_diag.offset = offset;
    cw_transfer_diag.block_index = index;
    cw_diag_stage("ack_pending", "block_committed");
}

static bool cw_ack32_finalize(void *context)
{
    cw_ack32_context_t *c = context;
    if (c->running_crc != c->expected_crc) {
        c->reason = "file_crc_mismatch";
        c->discard_partial = true;
        return false;
    }
    FILE *file = *c->file;
    if (fflush(file) != 0 || (fileno(file) >= 0 && fsync(fileno(file)) != 0)) {
        c->reason = "sd_flush_failed";
        return false;
    }
    int closed = fclose(file);
    *c->file = NULL;
    if (closed != 0) {
        c->reason = "close_failed";
        return false;
    }
    if (rename(c->part_path, c->final_path) != 0) {
        c->reason = "rename_failed";
        return false;
    }
    unlink(c->meta_path);
    if (!cw_record_verified_file(c->final_path, c->size, c->expected_crc)) {
        c->reason = "stat_failed";
        cw_remove_cached_file(c->final_path);
        return false;
    }
    return true;
}

static bool cw_ack32_reply(void *context, const uint8_t frame[32])
{
    (void)context;
    cw_diag_stage("ack_write", "pending");
    cw_transfer_diag.ack_attempts++;
    bool sent = cw_uart_write_all(frame, CRACK_WORKER_ACK32_SIZE);
    if (sent) {
        cw_transfer_diag.acks_sent++;
        cw_diag_stage("ack_sent", "ok");
    } else {
        cw_diag_stage("ack_write", "failed");
    }
    return sent;
}

static void cw_ack32_terminal(void *context, bool success, const char *reason)
{
    cw_ack32_context_t *c = context;
    c->success = success;
    if (c->reason == NULL) c->reason = reason;
    if (success) {
        printf("[CRACK/1] SYNCED kind=%s size=%" PRIu64 " crc32=%08" PRIX32
               " path=%s\r\n[CRACK/1] END\r\n", c->kind, c->size,
               c->expected_crc, c->final_path);
    } else {
        printf("[CRACK/1] SYNC_ERROR code=%s received=%" PRIu64
               " size=%" PRIu64 "\r\n[CRACK/1] END\r\n",
               c->reason, c->state->offset, c->size);
    }
}

static const crack_worker_transfer_ops_t cw_ack32_ops = {
    .read = cw_ack32_read, .write = cw_ack32_write, .crc = cw_ack32_crc,
    .checkpoint = cw_ack32_checkpoint, .progress = cw_ack32_progress,
    .finalize = cw_ack32_finalize, .reply = cw_ack32_reply,
    .terminal = cw_ack32_terminal,
};

static int cw_receive(int argc, char **argv)
{
    uint64_t expected_size;
    uint64_t crc_value;
    uint64_t block_value = CW_FT_BLOCK_DEFAULT;
    char final_path[128];
    char part_path[136];
    char meta_path[144];
    FILE *file = NULL;
    uint8_t *payload = NULL;
    bool success = false;
    bool raw_mode = false;
    bool discard_partial = false;
    bool transfer_marked = false;
    bool partial_state_valid = false;
    bool terminal_emitted = false;
    const char *reason = "transfer_error";
    uint64_t offset = 0;
    uint32_t running_crc = 0;
    uint64_t last_checkpoint_offset = 0;
    uint32_t expected_index = 0;
    unsigned nak_count = 0;
    size_t ack_size = 0;
    uint32_t prepare_ms = 0;

    if (!crack_worker_reply_mode_parse(argc, argc == 7 ? argv[6] : NULL,
                                       &ack_size) ||
        !cw_parse_u64(argv[3], 10, &expected_size) ||
        expected_size == 0 || expected_size > (uint64_t)INT64_MAX ||
        !cw_parse_u64(argv[4], 16, &crc_value) ||
        crc_value > UINT32_MAX ||
        (argc >= 6 && !cw_parse_u64(argv[5], 10, &block_value)) ||
        !cw_kind_path(argv[2], expected_size, (uint32_t)crc_value,
                      final_path, sizeof(final_path))) {
        cw_print("[CRACK/1] REJECTED code=usage detail=receive_kind_size_crc_bsize_ackmode\r\n");
        return 0;
    }
    bool ack32 = ack_size == CRACK_WORKER_ACK32_SIZE;
    if (cw_job_running()) {
        cw_print("[CRACK/1] REJECTED code=busy\r\n");
        return 0;
    }
    if (block_value < CW_FT_BLOCK_MIN) block_value = CW_FT_BLOCK_MIN;
    if (block_value > CW_FT_BLOCK_MAX) block_value = CW_FT_BLOCK_MAX;
    uint32_t block_size = (uint32_t)block_value;
    memset(&cw_transfer_diag, 0, sizeof(cw_transfer_diag));
    snprintf(cw_transfer_diag.phase, sizeof(cw_transfer_diag.phase), "setup");
    snprintf(cw_transfer_diag.reason, sizeof(cw_transfer_diag.reason), "preparing");
    cw_transfer_diag.baud = cw_current_baud != NULL ? cw_current_baud() : 115200U;

    if (cw_ensure_sd == NULL || cw_ensure_sd() != ESP_OK || !cw_make_dirs()) {
        cw_print("[CRACK/1] REJECTED code=sd_unavailable\r\n");
        return 0;
    }
    if (cw_file_matches(final_path, expected_size, (uint32_t)crc_value)) {
        cw_print("[CRACK/1] FILE kind=%s state=present size=%" PRIu64
                 " crc32=%08" PRIX32 " path=%s\r\n",
                 argv[2], expected_size, (uint32_t)crc_value, final_path);
        return 0;
    }
    cw_remove_cached_file(final_path);
    int part_written = snprintf(part_path, sizeof(part_path), "%s.part", final_path);
    int meta_written = snprintf(meta_path, sizeof(meta_path), "%s.meta", part_path);
    if (part_written <= 0 || (size_t)part_written >= sizeof(part_path) ||
        meta_written <= 0 || (size_t)meta_written >= sizeof(meta_path)) {
        cw_print("[CRACK/1] REJECTED code=path_too_long\r\n");
        return 0;
    }

    struct stat partial_status;
    uint64_t actual_part_size = 0;
    bool checkpoint_resume = false;
    bool legacy_resume = false;
    crack_worker_partial_checkpoint_t checkpoint = {0};
    if (stat(part_path, &partial_status) == 0 && partial_status.st_size >= 0 &&
        (uint64_t)partial_status.st_size <= expected_size) {
        actual_part_size = (uint64_t)partial_status.st_size;
        if (crack_worker_partial_checkpoint_read(
                meta_path, expected_size, (uint32_t)crc_value,
                actual_part_size, &checkpoint)) {
            offset = checkpoint.offset;
            running_crc = checkpoint.prefix_crc32;
            checkpoint_resume = true;
        } else if (crack_worker_resume_prefix_allowed(actual_part_size)) {
            offset = actual_part_size;
            legacy_resume = offset > 0;
            unlink(meta_path);
        } else {
            unlink(part_path);
            unlink(meta_path);
        }
    } else {
        unlink(part_path);
        unlink(meta_path);
    }
    file = fopen(part_path, offset > 0 ? "r+b" : "w+b");
    if (file == NULL) {
        cw_print("[CRACK/1] REJECTED code=open_failed errno=%d\r\n", errno);
        return 0;
    }
    if (cw_transfer_active != NULL) {
        cw_transfer_active(true);
        transfer_marked = true;
    }
    if (checkpoint_resume && actual_part_size > offset &&
        ftruncate(fileno(file), (off_t)offset) != 0) {
        reason = "partial_truncate_failed";
        goto done;
    }
    if ((!checkpoint_resume && !cw_crc_prefix(file, offset, &running_crc)) ||
        fseeko(file, (off_t)offset, SEEK_SET) != 0) {
        reason = "partial_read_failed";
        goto done;
    }
    partial_state_valid = true;
    if (legacy_resume && !cw_partial_checkpoint(
            file, meta_path, expected_size, (uint32_t)crc_value, offset,
            running_crc, block_size)) {
        reason = "checkpoint_failed";
        goto done;
    }
    last_checkpoint_offset = offset;
    if (!crack_worker_prepare_resume(&file, part_path, meta_path,
            &offset, &running_crc, &last_checkpoint_offset, &prepare_ms)) {
        partial_state_valid = false;
        reason = "partial_reset_failed";
        goto done;
    }
    if (!ack32 && offset == expected_size) {
        if (running_crc != (uint32_t)crc_value) {
            fclose(file);
            file = NULL;
            unlink(part_path);
            unlink(meta_path);
            reason = "partial_crc_mismatch";
            goto done;
        }
        if (fclose(file) != 0) {
            file = NULL;
            reason = "close_failed";
            goto done;
        }
        file = NULL;
        if (rename(part_path, final_path) != 0) {
            reason = "rename_failed";
            goto done;
        }
        unlink(meta_path);
        if (!cw_record_verified_file(final_path, expected_size,
                                     (uint32_t)crc_value)) {
            reason = "stat_failed";
            cw_remove_cached_file(final_path);
            goto done;
        }
        if (transfer_marked && cw_transfer_active != NULL) {
            cw_transfer_active(false);
            transfer_marked = false;
        }
        cw_print("[CRACK/1] FILE kind=%s state=present size=%" PRIu64
                 " crc32=%08" PRIX32 " path=%s\r\n",
                 argv[2], expected_size, (uint32_t)crc_value, final_path);
        return 0;
    }

    payload = malloc(block_size);
    if (payload == NULL) {
        reason = "no_memory";
        goto done;
    }
    if (uart_flush_input(CW_UART) != ESP_OK) {
        reason = "uart_flush_failed";
        goto done;
    }
    raw_mode = true;
    flockfile(stdout);
    char ready[384];
    uint32_t rx_ms = cw_receive_timeout_ms(block_size);
    if (!crack_worker_ready_format(ready, sizeof(ready), argv[2], expected_size,
            (uint32_t)crc_value, offset, running_crc, block_size,
            rx_ms, ack32, prepare_ms)) {
        reason = "ready_failed";
        goto raw_done;
    }
    printf("%s[CRACK/1] END\r\n\r\n", ready);
    fflush(stdout);
    if (uart_wait_tx_done(CW_UART, pdMS_TO_TICKS(2000)) != ESP_OK) {
        reason = "uart_write_failed";
        goto raw_done;
    }

    if (ack32) {
        /* Fresh metadata for every command, including resumed and offset-zero
         * fallback transfers. A complete .part still requires FIN publication. */
        crack_worker_transfer_state_t state = {
            .expected_size = expected_size, .offset = offset,
            .block_size = block_size, .ack32 = true,
        };
        crack_worker_transfer_session_t session = {
            .prepare_ms = prepare_ms, .rx_ms = rx_ms,
        };
        cw_ack32_context_t context = {
            .file = &file, .kind = argv[2], .part_path = part_path,
            .meta_path = meta_path, .final_path = final_path,
            .size = expected_size, .last_checkpoint = last_checkpoint_offset,
            .expected_crc = (uint32_t)crc_value, .running_crc = running_crc,
            .block_size = block_size, .partial_valid = partial_state_valid,
            .state = &state,
        };
        success = crack_worker_transfer_receive(&state, &session, payload,
                                                block_size, &cw_ack32_ops, &context);
        terminal_emitted = true;
        offset = state.offset;
        expected_index = state.expected_index;
        running_crc = context.running_crc;
        last_checkpoint_offset = context.last_checkpoint;
        partial_state_valid = context.partial_valid;
        discard_partial = context.discard_partial;
        reason = context.reason;
        /* ACK32 callbacks keep the exact live phase and byte counters.  Do not
         * replace them with the transfer core's coarser terminal snapshot. */
        cw_transfer_diag.duplicates = session.duplicates;
        goto raw_done;
    }

    bool first_header_pending = true;
    while (offset < expected_size) {
        uint8_t header[CW_FT_HEADER_SIZE];
        size_t first_got = 0;
        size_t rest_got = 0;
        snprintf(cw_transfer_diag.phase, sizeof(cw_transfer_diag.phase), "header");
        snprintf(cw_transfer_diag.reason, sizeof(cw_transfer_diag.reason), "receiving");
        cw_transfer_diag.header_got = 0;
        cw_transfer_diag.header_expected = sizeof(header);
        cw_transfer_diag.payload_got = 0;
        cw_transfer_diag.payload_expected = 0;
        cw_transfer_diag.offset = offset;
        cw_transfer_diag.block_index = expected_index;
        uint32_t first_timeout_ms = crack_worker_first_byte_timeout(
            first_header_pending, prepare_ms, rx_ms);
        int header_result = cw_uart_read_exact(header, 1, first_timeout_ms,
                                               &first_got);
        cw_transfer_diag.header_got = first_got;
        if (header_result <= 0) {
            reason = header_result < 0 ? "uart_read_failed" : "block_timeout";
            break;
        }
        first_header_pending = false;
        if (header[0] == CW_FT_CAN) {
            reason = "cancelled";
            break;
        }
        header_result = cw_uart_read_exact(header + 1, sizeof(header) - 1U,
                                           rx_ms, &rest_got);
        cw_transfer_diag.header_got = first_got + rest_got;
        if (header_result <= 0) {
            reason = header_result < 0 ? "uart_read_failed" : "header_timeout";
            break;
        }
        uint32_t index = cw_le32(header + 4);
        uint32_t length = cw_le32(header + 8);
        uint32_t expected_block_crc = cw_le32(header + 12);
        bool header_ok = memcmp(header, "FTB\x01", 4) == 0 &&
                         index == expected_index && length > 0 &&
                         length <= block_size && length <= expected_size - offset;
        if (!header_ok) {
            reason = cw_send_block_reply(CW_FT_CAN, index, offset, ack32) ?
                     "invalid_header" : "uart_write_failed";
            break;
        }
        snprintf(cw_transfer_diag.phase, sizeof(cw_transfer_diag.phase), "payload");
        cw_transfer_diag.payload_expected = length;
        size_t payload_got = 0;
        int payload_result = cw_uart_read_exact(payload, length, rx_ms,
                                                &payload_got);
        cw_transfer_diag.payload_got = payload_got;
        if (payload_result <= 0) {
            if (!cw_send_block_reply(CW_FT_CAN, index, offset, ack32))
                reason = "uart_write_failed";
            else
                reason = payload_result < 0 ? "uart_read_failed" : "payload_timeout";
            break;
        }
        if (crack_worker_crc32_update(0, payload, length) != expected_block_crc) {
            if (!cw_send_block_reply(CW_FT_NAK, index, offset, ack32)) {
                reason = "uart_write_failed";
                break;
            }
            if (++nak_count >= CW_FT_MAX_NAKS) {
                reason = "block_crc_mismatch";
                break;
            }
            continue;
        }
        if (fwrite(payload, 1, length, file) != length) {
            reason = cw_send_block_reply(CW_FT_CAN, index, offset, ack32) ?
                     "sd_write_failed" : "uart_write_failed";
            break;
        }
        uint32_t next_crc = crack_worker_crc32_update(running_crc, payload, length);
        uint64_t next_offset = offset + length;
        bool checkpoint_due = next_offset - last_checkpoint_offset >=
                              CW_PART_CHECKPOINT_BYTES || next_offset == expected_size;
        if (checkpoint_due &&
            !cw_partial_checkpoint(file, meta_path, expected_size,
                                   (uint32_t)crc_value, next_offset, next_crc,
                                   block_size)) {
            partial_state_valid = false;
            reason = cw_send_block_reply(CW_FT_CAN, index, offset, ack32) ?
                     "checkpoint_failed" : "uart_write_failed";
            break;
        }
        running_crc = next_crc;
        offset = next_offset;
        expected_index++;
        cw_transfer_diag.offset = offset;
        cw_transfer_diag.block_index = expected_index;
        nak_count = 0;
        if (checkpoint_due) {
            last_checkpoint_offset = offset;
        }
        if (!cw_send_block_reply(CW_FT_ACK, index, offset, ack32)) {
            reason = "uart_write_failed";
            break;
        }
    }

    if (offset == expected_size && running_crc == (uint32_t)crc_value) {
        if (fflush(file) != 0 || (fileno(file) >= 0 && fsync(fileno(file)) != 0)) {
            reason = "sd_flush_failed";
        } else {
            int close_result = fclose(file);
            file = NULL;
            if (close_result != 0) reason = "close_failed";
            else if (rename(part_path, final_path) == 0) {
                unlink(meta_path);
                if (cw_record_verified_file(final_path, expected_size,
                                            (uint32_t)crc_value)) {
                    success = true;
                } else {
                    reason = "stat_failed";
                    cw_remove_cached_file(final_path);
                }
            } else reason = "rename_failed";
        }
    } else if (offset == expected_size) {
        reason = "file_crc_mismatch";
        discard_partial = true;
    }

raw_done:
    snprintf(cw_transfer_diag.reason, sizeof(cw_transfer_diag.reason), "%s",
             success ? "synced" : reason);
    cw_transfer_diag.offset = offset;
    cw_transfer_diag.block_index = expected_index;
    if (success)
        snprintf(cw_transfer_diag.phase, sizeof(cw_transfer_diag.phase), "done");
    if (!terminal_emitted && success) {
        printf("[CRACK/1] SYNCED kind=%s size=%" PRIu64 " crc32=%08" PRIX32
               " path=%s\r\n[CRACK/1] END\r\n",
               argv[2], expected_size, (uint32_t)crc_value, final_path);
    } else if (!terminal_emitted) {
        printf("[CRACK/1] SYNC_ERROR code=%s received=%" PRIu64
               " size=%" PRIu64 "\r\n[CRACK/1] END\r\n",
               reason, offset, expected_size);
    }
    fflush(stdout);
    funlockfile(stdout);

done:
    if (file != NULL && partial_state_valid && !discard_partial &&
        offset > last_checkpoint_offset) {
        if (cw_partial_checkpoint(file, meta_path, expected_size,
                                  (uint32_t)crc_value, offset, running_crc,
                                  block_size)) {
            last_checkpoint_offset = offset;
        }
    }
    if (file != NULL) fclose(file);
    if (transfer_marked && cw_transfer_active != NULL) cw_transfer_active(false);
    if (discard_partial) {
        unlink(part_path);
        unlink(meta_path);
    }
    free(payload);
    snprintf(cw_transfer_diag.reason, sizeof(cw_transfer_diag.reason), "%s",
             success ? "synced" : reason);
    cw_transfer_diag.offset = offset;
    if (!raw_mode && !success) {
        cw_print("[CRACK/1] SYNC_ERROR code=%s received=%" PRIu64
                 " size=%" PRIu64 "\r\n[CRACK/1] END\r\n",
                 reason, offset, expected_size);
    } else if (!raw_mode && success) {
        cw_print("[CRACK/1] SYNCED kind=%s size=%" PRIu64 " crc32=%08" PRIX32
                 " path=%s\r\n[CRACK/1] END\r\n",
                 argv[2], expected_size, (uint32_t)crc_value, final_path);
    }
    return 0;
}

static const char *cw_state_name(cw_job_state_t state)
{
    switch (state) {
        case CW_JOB_RUNNING: return "running";
        case CW_JOB_FOUND: return "found";
        case CW_JOB_NOT_FOUND: return "not_found";
        case CW_JOB_CANCELLED: return "cancelled";
        case CW_JOB_ERROR: return "error";
        default: return "idle";
    }
}

static const char *cw_phase_name(const cw_job_t *job)
{
    if (job->state == CW_JOB_RUNNING)
        return job->started_us > 0 ? "cracking" : "starting";
    if (job->state == CW_JOB_IDLE) return "idle";
    return "terminal";
}

static crack_worker_start_action_t cw_start_action_locked(
    const crack_worker_assignment_t *requested)
{
    crack_worker_assignment_t existing = {
        .id = cw_job.id,
        .capture_path = cw_job.capture_path,
        .wordlist_path = cw_job.wordlist_path,
        .range_start = cw_job.range_start,
        .range_end = cw_job.range_end,
    };
    return crack_worker_start_classify(cw_job.id[0] != '\0',
                                       cw_job.state == CW_JOB_RUNNING,
                                       &existing, requested);
}

static bool cw_start_reply_existing(crack_worker_start_action_t action,
                                    const char *requested_job,
                                    uint64_t start, uint64_t end)
{
    if (action == CRACK_WORKER_START_NEW) return false;

    char existing_job[32];
    char state[16];
    xSemaphoreTake(cw_mutex, portMAX_DELAY);
    snprintf(existing_job, sizeof(existing_job), "%s", cw_job.id);
    snprintf(state, sizeof(state), "%s", cw_state_name(cw_job.state));
    xSemaphoreGive(cw_mutex);

    if (action == CRACK_WORKER_START_REPLAY) {
        cw_print("[CRACK/1] ACCEPTED job=%s start=%" PRIu64
                 " end=%" PRIu64 " replay=1 state=%s\r\n",
                 requested_job, start, end, state);
    } else if (action == CRACK_WORKER_START_JOB_CONFLICT) {
        cw_print("[CRACK/1] REJECTED code=job_conflict job=%s\r\n",
                 requested_job);
    } else {
        cw_print("[CRACK/1] REJECTED code=busy job=%s\r\n", existing_job);
    }
    return true;
}

static bool cw_checkpoint(void *context)
{
    cw_checkpoint_t *checkpoint = (cw_checkpoint_t *)context;
    bool keep_running = !cw_job.cancel_requested;
    if ((++checkpoint->checkpoint_calls & 15U) == 0U) vTaskDelay(1);
    return keep_running;
}

static void cw_finish(cw_job_state_t state, const char *password,
                      const crack_worker_hccapx_t *record, const char *error)
{
    char job_id[32];
    char password_hex[127] = {0};
    char ssid_hex[65] = {0};
    if (password != NULL) {
        crack_worker_hex_encode((const uint8_t *)password, strlen(password),
                                password_hex, sizeof(password_hex));
    }
    if (record != NULL) {
        crack_worker_hex_encode(record->essid, record->essid_len,
                                ssid_hex, sizeof(ssid_hex));
    }
    xSemaphoreTake(cw_mutex, portMAX_DELAY);
    snprintf(job_id, sizeof(job_id), "%s", cw_job.id);
    cw_job.state = state;
    cw_job.task = NULL;
    snprintf(cw_job.password_hex, sizeof(cw_job.password_hex), "%s", password_hex);
    snprintf(cw_job.error, sizeof(cw_job.error), "%s", error != NULL ? error : "");
    uint64_t checked = cw_job.progress.checked;
    uint64_t safe_offset = cw_job.progress.safe_offset;
    xSemaphoreGive(cw_mutex);

    if (state == CW_JOB_FOUND) {
        cw_print("[CRACK/1] DONE job=%s result=found checked=%" PRIu64
                 " safe_offset=%" PRIu64 " ssid_hex=%s password_hex=%s\r\n",
                 job_id, checked, safe_offset, ssid_hex, password_hex);
    } else {
        cw_print("[CRACK/1] DONE job=%s result=%s checked=%" PRIu64
                 " safe_offset=%" PRIu64 "%s%s\r\n",
                 job_id, cw_state_name(state), checked, safe_offset,
                 error != NULL ? " code=" : "", error != NULL ? error : "");
    }
}

static void cw_task(void *unused)
{
    (void)unused;
    char capture_path[128];
    char wordlist_path[128];
    char job_id[32];
    uint64_t range_start;
    uint64_t range_end;
    xSemaphoreTake(cw_mutex, portMAX_DELAY);
    snprintf(capture_path, sizeof(capture_path), "%s", cw_job.capture_path);
    snprintf(wordlist_path, sizeof(wordlist_path), "%s", cw_job.wordlist_path);
    snprintf(job_id, sizeof(job_id), "%s", cw_job.id);
    range_start = cw_job.range_start;
    range_end = cw_job.range_end;
    cw_job.started_us = esp_timer_get_time();
    xSemaphoreGive(cw_mutex);
    cw_print("[CRACK/1] STARTED job=%s start=%" PRIu64 " end=%" PRIu64 "\r\n",
             job_id, range_start, range_end);

    FILE *capture = fopen(capture_path, "rb");
    if (capture == NULL) {
        cw_finish(CW_JOB_ERROR, NULL, NULL, "capture_open_failed");
        vTaskDelete(NULL);
        return;
    }
    crack_worker_hccapx_t records[CW_MAX_RECORDS];
    size_t record_count = fread(records, sizeof(records[0]), CW_MAX_RECORDS, capture);
    bool capture_error = ferror(capture) || record_count == 0;
    int extra = fgetc(capture);
    fclose(capture);
    if (capture_error || extra != EOF) {
        cw_finish(CW_JOB_ERROR, NULL, NULL, "capture_invalid_size");
        vTaskDelete(NULL);
        return;
    }
    for (size_t i = 0; i < record_count; ++i) {
        if (!crack_worker_hccapx_valid(&records[i])) {
            cw_finish(CW_JOB_ERROR, NULL, NULL, "capture_invalid_record");
            vTaskDelete(NULL);
            return;
        }
    }

    FILE *wordlist = fopen(wordlist_path, "rb");
    if (wordlist == NULL) {
        cw_finish(CW_JOB_ERROR, NULL, NULL, "wordlist_open_failed");
        vTaskDelete(NULL);
        return;
    }
    uint64_t aligned = 0;
    if (crack_worker_seek_range_start(wordlist, range_start, &aligned) != CRACK_WORKER_CORE_OK) {
        fclose(wordlist);
        cw_finish(CW_JOB_ERROR, NULL, NULL, "range_seek_failed");
        vTaskDelete(NULL);
        return;
    }
    xSemaphoreTake(cw_mutex, portMAX_DELAY);
    crack_worker_progress_begin(&cw_job.progress, aligned);
    if (aligned > range_start) cw_job.last_progress_us = esp_timer_get_time();
    xSemaphoreGive(cw_mutex);

    char word[64];
    cw_checkpoint_t checkpoint = {0};
    for (;;) {
        if (cw_job.cancel_requested) {
            fclose(wordlist);
            cw_finish(CW_JOB_CANCELLED, NULL, NULL, NULL);
            vTaskDelete(NULL);
            return;
        }
        uint64_t line_start = 0;
        uint64_t next_offset = 0;
        crack_worker_line_result_t line = crack_worker_read_word(
            wordlist, range_end, word, &line_start, &next_offset);
        if (line == CRACK_WORKER_LINE_END) break;
        if (line == CRACK_WORKER_LINE_IO_ERROR) {
            fclose(wordlist);
            cw_finish(CW_JOB_ERROR, NULL, NULL, "wordlist_read_failed");
            vTaskDelete(NULL);
            return;
        }
        if (line == CRACK_WORKER_LINE_SKIPPED) {
            xSemaphoreTake(cw_mutex, portMAX_DELAY);
            crack_worker_progress_commit(&cw_job.progress, next_offset, false);
            cw_job.last_progress_us = esp_timer_get_time();
            xSemaphoreGive(cw_mutex);
            continue;
        }

        int match = crack_worker_verify_candidate(word, records, record_count,
                                                  cw_checkpoint, &checkpoint);
        if (match >= -1) {
            xSemaphoreTake(cw_mutex, portMAX_DELAY);
            crack_worker_progress_commit(&cw_job.progress, next_offset, true);
            cw_job.last_progress_us = esp_timer_get_time();
            xSemaphoreGive(cw_mutex);
        }
        if (match >= 0) {
            fclose(wordlist);
            cw_finish(CW_JOB_FOUND, word, &records[match], NULL);
            memset(word, 0, sizeof(word));
            vTaskDelete(NULL);
            return;
        }
        if (match == -3) {
            fclose(wordlist);
            cw_finish(CW_JOB_CANCELLED, NULL, NULL, NULL);
            memset(word, 0, sizeof(word));
            vTaskDelete(NULL);
            return;
        }
        if (match == -2) {
            fclose(wordlist);
            cw_finish(CW_JOB_ERROR, NULL, NULL, "crypto_failed");
            memset(word, 0, sizeof(word));
            vTaskDelete(NULL);
            return;
        }
        memset(word, 0, sizeof(word));
    }
    fclose(wordlist);
    cw_finish(CW_JOB_NOT_FOUND, NULL, NULL, NULL);
    vTaskDelete(NULL);
    return;
}

static int cw_start(int argc, char **argv)
{
    uint64_t capture_size, capture_crc, wordlist_size, wordlist_crc, start, end;
    char capture_path[128];
    char wordlist_path[128];
    if (argc != 9 || !crack_worker_job_id_valid(argv[2]) ||
        !cw_parse_u64(argv[3], 10, &capture_size) ||
        !cw_parse_u64(argv[4], 16, &capture_crc) || capture_crc > UINT32_MAX ||
        !cw_parse_u64(argv[5], 10, &wordlist_size) ||
        !cw_parse_u64(argv[6], 16, &wordlist_crc) || wordlist_crc > UINT32_MAX ||
        !cw_parse_u64(argv[7], 10, &start) || !cw_parse_u64(argv[8], 10, &end) ||
        start > wordlist_size || (end != 0 && (start > end || end > wordlist_size)) ||
        !cw_kind_path("capture", capture_size, (uint32_t)capture_crc,
                      capture_path, sizeof(capture_path)) ||
        !cw_kind_path("wordlist", wordlist_size, (uint32_t)wordlist_crc,
                      wordlist_path, sizeof(wordlist_path))) {
        cw_print("[CRACK/1] REJECTED code=usage detail=start_job_capture_wordlist_range\r\n");
        return 0;
    }
    crack_worker_assignment_t requested = {
        .id = argv[2],
        .capture_path = capture_path,
        .wordlist_path = wordlist_path,
        .range_start = start,
        .range_end = end,
    };
    xSemaphoreTake(cw_mutex, portMAX_DELAY);
    crack_worker_start_action_t action = cw_start_action_locked(&requested);
    xSemaphoreGive(cw_mutex);
    if (cw_start_reply_existing(action, argv[2], start, end)) return 0;

    if (!cw_file_matches(capture_path, capture_size, (uint32_t)capture_crc)) {
        cw_remove_cached_file(capture_path);
        cw_print("[CRACK/1] REJECTED code=capture_missing\r\n");
        return 0;
    }
    if (!cw_file_matches(wordlist_path, wordlist_size, (uint32_t)wordlist_crc)) {
        cw_remove_cached_file(wordlist_path);
        cw_print("[CRACK/1] REJECTED code=wordlist_missing\r\n");
        return 0;
    }
    xSemaphoreTake(cw_mutex, portMAX_DELAY);
    action = cw_start_action_locked(&requested);
    if (action != CRACK_WORKER_START_NEW) {
        xSemaphoreGive(cw_mutex);
        (void)cw_start_reply_existing(action, argv[2], start, end);
        return 0;
    }
    memset(&cw_job, 0, sizeof(cw_job));
    cw_job.state = CW_JOB_RUNNING;
    snprintf(cw_job.id, sizeof(cw_job.id), "%s", argv[2]);
    snprintf(cw_job.capture_path, sizeof(cw_job.capture_path), "%s", capture_path);
    snprintf(cw_job.wordlist_path, sizeof(cw_job.wordlist_path), "%s", wordlist_path);
    cw_job.range_start = start;
    cw_job.range_end = end;
    cw_job.last_progress_us = esp_timer_get_time();
    /* Keep the UART REPL (priority 2) responsive so status and cancellation
     * remain control-plane operations even while this task saturates the CPU. */
    BaseType_t created = xTaskCreate(cw_task, "crack_worker", CW_TASK_STACK, NULL, 1,
                                     &cw_job.task);
    if (created != pdPASS) {
        cw_job.state = CW_JOB_ERROR;
        snprintf(cw_job.error, sizeof(cw_job.error), "task_create_failed");
        xSemaphoreGive(cw_mutex);
        cw_print("[CRACK/1] REJECTED code=task_create_failed\r\n");
        return 0;
    }
    xSemaphoreGive(cw_mutex);
    cw_print("[CRACK/1] ACCEPTED job=%s start=%" PRIu64 " end=%" PRIu64 "\r\n",
             argv[2], start, end);
    return 0;
}

static int cw_status(int argc, char **argv)
{
    if (argc > 3) {
        cw_print("[CRACK/1] REJECTED code=usage detail=status_optional_job\r\n");
        return 0;
    }
    xSemaphoreTake(cw_mutex, portMAX_DELAY);
    cw_job_t snapshot = cw_job;
    xSemaphoreGive(cw_mutex);
    if (argc == 3 && strcmp(argv[2], snapshot.id) != 0) {
        cw_print("[CRACK/1] REJECTED code=unknown_job\r\n");
        return 0;
    }
    uint64_t elapsed_ms = snapshot.started_us > 0 ?
        (uint64_t)((esp_timer_get_time() - snapshot.started_us) / 1000) : 0;
    int64_t now_us = esp_timer_get_time();
    uint64_t progress_age_ms = snapshot.last_progress_us > 0 &&
                               now_us > snapshot.last_progress_us ?
        (uint64_t)((now_us - snapshot.last_progress_us) / 1000) : 0;
    uint64_t rate_milli = elapsed_ms > 0 ?
        snapshot.progress.checked * 1000000ULL / elapsed_ms : 0;
    cw_print("[CRACK/1] STATUS job=%s state=%s checked=%" PRIu64
             " safe_offset=%" PRIu64 " elapsed_ms=%" PRIu64
             " rate_milli=%" PRIu64 " phase=%s progress_age_ms=%" PRIu64
             "%s%s%s%s\r\n",
             snapshot.id[0] ? snapshot.id : "none", cw_state_name(snapshot.state),
             snapshot.progress.checked, snapshot.progress.safe_offset,
             elapsed_ms, rate_milli, cw_phase_name(&snapshot), progress_age_ms,
             snapshot.password_hex[0] ? " password_hex=" : "",
             snapshot.password_hex,
             snapshot.error[0] ? " code=" : "", snapshot.error);
    return 0;
}

static int cw_cancel(int argc, char **argv)
{
    if (argc > 3) {
        cw_print("[CRACK/1] REJECTED code=usage detail=cancel_optional_job\r\n");
        return 0;
    }
    xSemaphoreTake(cw_mutex, portMAX_DELAY);
    if (cw_job.state != CW_JOB_RUNNING ||
        (argc == 3 && strcmp(argv[2], cw_job.id) != 0)) {
        xSemaphoreGive(cw_mutex);
        cw_print("[CRACK/1] REJECTED code=no_running_job\r\n");
        return 0;
    }
    cw_job.cancel_requested = true;
    char id[32];
    snprintf(id, sizeof(id), "%s", cw_job.id);
    xSemaphoreGive(cw_mutex);
    cw_print("[CRACK/1] CANCELLING job=%s\r\n", id);
    return 0;
}

void crack_worker_init(crack_worker_ensure_sd_fn ensure_sd,
                       crack_worker_transfer_active_fn transfer_active,
                       crack_worker_current_baud_fn current_baud)
{
    cw_ensure_sd = ensure_sd;
    cw_transfer_active = transfer_active;
    cw_current_baud = current_baud;
    if (cw_mutex == NULL) cw_mutex = xSemaphoreCreateMutex();
}

void crack_worker_cancel_all(void)
{
    if (cw_mutex == NULL) return;
    xSemaphoreTake(cw_mutex, portMAX_DELAY);
    cw_job.cancel_requested = true;
    xSemaphoreGive(cw_mutex);
}

int crack_worker_command(int argc, char **argv)
{
    if (cw_mutex == NULL) {
        cw_print("[CRACK/1] REJECTED code=not_initialized\r\n");
        return 0;
    }
    if (argc < 2) {
        cw_print("[CRACK/1] REJECTED code=usage detail=capabilities_probe_receive_reset_diag_start_status_cancel\r\n");
        return 0;
    }
    if (strcmp(argv[1], "capabilities") == 0) {
        cw_print("%s max_jobs=1 max_records=%u keyver=1,2\r\n",
                 crack_worker_capabilities(), CW_MAX_RECORDS);
        return 0;
    }
    if (strcmp(argv[1], "probe") == 0) return cw_probe(argc, argv);
    if (strcmp(argv[1], "receive") == 0) return cw_receive(argc, argv);
    if (strcmp(argv[1], "reset") == 0) return cw_reset_partial(argc, argv);
    if (strcmp(argv[1], "diag") == 0) return cw_diag(argc, argv);
    if (strcmp(argv[1], "start") == 0) return cw_start(argc, argv);
    if (strcmp(argv[1], "status") == 0) return cw_status(argc, argv);
    if (strcmp(argv[1], "cancel") == 0) return cw_cancel(argc, argv);
    cw_print("[CRACK/1] REJECTED code=unknown_subcommand\r\n");
    return 0;
}
