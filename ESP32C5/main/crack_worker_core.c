#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "crack_worker_core.h"
#include "crack_worker_transfer.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef ESP_PLATFORM
#include "esp_rom_crc.h"
#endif

const char *crack_worker_capabilities(void)
{
    return "[CRACK/1] CAPABILITIES protocol=4 sync=ftb1 ack=byte,frame32 "
           "replay=last_block finish=fin32 storage=sd start=idempotent "
           "health=phase,progress_age_ms";
}

bool crack_worker_prepare_resume(FILE **file, const char *part_path,
    const char *meta_path, uint64_t *offset, uint32_t *running_crc,
    uint64_t *checkpoint_offset, uint32_t *prepare_ms)
{
    bool allowed;
    *prepare_ms = crack_worker_prepare_ms(*offset, &allowed);
    if (allowed) return true;
    int closed = fclose(*file);
    *file = NULL;
    if (closed != 0) return false;
    *file = fopen(part_path, "w+b");
    if (*file == NULL) return false;
    if (unlink(meta_path) != 0 && errno != ENOENT) return false;
    *offset = 0;
    *running_crc = 0;
    *checkpoint_offset = 0;
    return true;
}

bool crack_worker_ready_format(char *output, size_t capacity, const char *kind,
    uint64_t size, uint32_t crc, uint64_t offset, uint32_t prefix_crc,
    uint32_t block_size, uint32_t rx_ms, bool ack32, uint32_t prepare_ms)
{
    int used = snprintf(output, capacity,
        "[CRACK/1] READY kind=%s size=%" PRIu64 " crc32=%08" PRIX32
        " offset=%" PRIu64 " prefix_crc=%08" PRIX32 " bsize=%" PRIu32
        " rx_ms=%" PRIu32 " ack_size=%u", kind, size, crc, offset, prefix_crc,
        block_size, rx_ms, ack32 ? 32U : 1U);
    if (used < 0 || (size_t)used >= capacity) return false;
    int tail;
    if (ack32) {
        tail = snprintf(output + used, capacity - (size_t)used,
            " ack_wait_ms=%u next_header_ms=%u prepare_ms=%" PRIu32
            " finish_linger_ms=%u\r\n", CRACK_WORKER_ACK_WAIT_MS,
            CRACK_WORKER_NEXT_HEADER_MS, prepare_ms, CRACK_WORKER_FINISH_LINGER_MS);
    } else {
        tail = snprintf(output + used, capacity - (size_t)used,
                        " prepare_ms=%" PRIu32 "\r\n", prepare_ms);
    }
    return tail >= 0 && (size_t)tail < capacity - (size_t)used;
}

bool crack_worker_job_id_valid(const char *job_id)
{
    if (job_id == NULL) return false;
    size_t length = strlen(job_id);
    if (length == 0 || length > 31) return false;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)job_id[i];
        if (!(isalnum(c) || c == '_' || c == '-')) return false;
    }
    return true;
}

bool crack_worker_wordlist_name_allowed(const char *name)
{
    if (name == NULL || name[0] == '.' || strchr(name, '/') || strchr(name, '\\')) {
        return false;
    }
    const char *dot = strrchr(name, '.');
    if (dot == NULL) return false;
    return strcasecmp(dot, ".txt") == 0 || strcasecmp(dot, ".lst") == 0 ||
           strcasecmp(dot, ".dic") == 0 || strcasecmp(dot, ".wordlist") == 0;
}

bool crack_worker_hex_encode(const uint8_t *input, size_t input_len,
                             char *output, size_t output_size)
{
    static const char digits[] = "0123456789ABCDEF";
    if (output == NULL || (input_len > 0 && input == NULL) ||
        input_len > (SIZE_MAX - 1U) / 2U || output_size < input_len * 2U + 1U) {
        return false;
    }
    for (size_t i = 0; i < input_len; ++i) {
        output[i * 2U] = digits[input[i] >> 4];
        output[i * 2U + 1U] = digits[input[i] & 0x0fU];
    }
    output[input_len * 2U] = '\0';
    return true;
}

uint32_t crack_worker_crc32_update(uint32_t crc, const void *data, size_t size)
{
    const uint8_t *bytes = (const uint8_t *)data;
#ifdef ESP_PLATFORM
    while (size > 0) {
        uint32_t chunk = size > UINT32_MAX ? UINT32_MAX : (uint32_t)size;
        crc = esp_rom_crc32_le(crc, bytes, chunk);
        bytes += chunk;
        size -= chunk;
    }
    return crc;
#else
    crc = ~crc;
    for (size_t i = 0; i < size; ++i) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xedb88320U & (uint32_t)-(int32_t)(crc & 1U));
        }
    }
    return ~crc;
#endif
}

bool crack_worker_ack32_build(uint8_t frame[CRACK_WORKER_ACK32_SIZE],
                              uint32_t block_index, uint8_t status,
                              uint64_t committed_offset)
{
    if (frame == NULL || (status != 0x06U && status != 0x15U && status != 0x18U))
        return false;

    memset(frame, 0, CRACK_WORKER_ACK32_SIZE);
    frame[0] = 'F';
    frame[1] = 'T';
    frame[2] = 'A';
    frame[3] = 0x01U;
    for (size_t i = 0; i < 4; ++i) frame[4U + i] = (uint8_t)(block_index >> (i * 8U));
    frame[8] = status;
    for (size_t i = 0; i < 8; ++i) frame[12U + i] = (uint8_t)(committed_offset >> (i * 8U));
    uint32_t crc = crack_worker_crc32_update(0, frame, 20);
    for (size_t i = 0; i < 4; ++i) frame[20U + i] = (uint8_t)(crc >> (i * 8U));
    return true;
}

bool crack_worker_reply_mode_parse(int argc, const char *token,
                                   size_t *ack_size)
{
    if (ack_size == NULL) return false;
    if (argc == 5 || argc == 6) {
        *ack_size = 1U;
        return true;
    }
    if (argc == 7 && token != NULL && strcmp(token, "ack32") == 0) {
        *ack_size = CRACK_WORKER_ACK32_SIZE;
        return true;
    }
    return false;
}

int crack_worker_file_id(const char *path, crack_worker_file_id_t *id)
{
    if (path == NULL || id == NULL) return CRACK_WORKER_CORE_ERROR;
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size < 0) return CRACK_WORKER_CORE_ERROR;
    FILE *file = fopen(path, "rb");
    if (file == NULL) return CRACK_WORKER_CORE_ERROR;

    uint8_t buffer[4096];
    uint32_t crc = 0;
    for (;;) {
        size_t got = fread(buffer, 1, sizeof(buffer), file);
        if (got > 0) crc = crack_worker_crc32_update(crc, buffer, got);
        if (got < sizeof(buffer)) {
            if (ferror(file)) {
                fclose(file);
                return CRACK_WORKER_CORE_ERROR;
            }
            break;
        }
    }
    if (fclose(file) != 0) return CRACK_WORKER_CORE_ERROR;
    id->size = (uint64_t)st.st_size;
    id->crc32 = crc;
    return CRACK_WORKER_CORE_OK;
}

bool crack_worker_file_id_equal(const crack_worker_file_id_t *a,
                                const crack_worker_file_id_t *b)
{
    return a != NULL && b != NULL && a->size == b->size && a->crc32 == b->crc32;
}

int crack_worker_verified_marker_write(const char *path, uint64_t size,
                                       uint32_t crc32, int64_t mtime)
{
    if (path == NULL || path[0] == '\0') return CRACK_WORKER_CORE_ERROR;
    char temporary[192];
    int length = snprintf(temporary, sizeof(temporary), "%s.tmp", path);
    if (length <= 0 || (size_t)length >= sizeof(temporary))
        return CRACK_WORKER_CORE_ERROR;

    FILE *file = fopen(temporary, "wb");
    if (file == NULL) return CRACK_WORKER_CORE_ERROR;
    bool ok = fprintf(file,
                      "CRACK_WORKER_VERIFIED 1\n"
                      "size=%" PRIu64 "\n"
                      "crc32=%08" PRIX32 "\n"
                      "mtime=%" PRId64 "\n",
                      size, crc32, mtime) > 0 &&
              fflush(file) == 0;
    int fd = fileno(file);
    if (ok && fd >= 0) ok = fsync(fd) == 0;
    if (fclose(file) != 0) ok = false;
    if (!ok) {
        unlink(temporary);
        return CRACK_WORKER_CORE_ERROR;
    }
    unlink(path);
    if (rename(temporary, path) != 0) {
        unlink(temporary);
        return CRACK_WORKER_CORE_ERROR;
    }
    return CRACK_WORKER_CORE_OK;
}

bool crack_worker_verified_marker_matches(const char *path, uint64_t size,
                                          uint32_t crc32, int64_t mtime)
{
    if (path == NULL) return false;
    FILE *file = fopen(path, "rb");
    if (file == NULL) return false;
    char line[96];
    uint64_t stored_size = 0;
    uint64_t stored_crc = 0;
    int64_t stored_mtime = 0;
    bool ok = fgets(line, sizeof(line), file) != NULL &&
              strcmp(line, "CRACK_WORKER_VERIFIED 1\n") == 0;
    if (ok) {
        char *end = NULL;
        const char *value;
        ok = fgets(line, sizeof(line), file) != NULL &&
             strncmp(line, "size=", 5) == 0;
        value = line + 5;
        if (ok && !isdigit((unsigned char)*value)) ok = false;
        errno = 0;
        if (ok) stored_size = strtoull(value, &end, 10);
        if (ok && (errno == ERANGE || end == value || strcmp(end, "\n") != 0))
            ok = false;
    }
    if (ok) {
        char *end = NULL;
        const char *value;
        ok = fgets(line, sizeof(line), file) != NULL &&
             strncmp(line, "crc32=", 6) == 0;
        value = line + 6;
        if (ok && !isxdigit((unsigned char)*value)) ok = false;
        errno = 0;
        if (ok) stored_crc = strtoull(value, &end, 16);
        if (ok && (errno == ERANGE || end == value || strcmp(end, "\n") != 0 ||
                   stored_crc > UINT32_MAX)) {
            ok = false;
        }
    }
    if (ok) {
        char *end = NULL;
        const char *value;
        long long parsed = 0;
        ok = fgets(line, sizeof(line), file) != NULL &&
             strncmp(line, "mtime=", 6) == 0;
        value = line + 6;
        if (ok && *value == '-') value++;
        if (ok && !isdigit((unsigned char)*value)) ok = false;
        value = line + 6;
        errno = 0;
        if (ok) parsed = strtoll(value, &end, 10);
        if (ok && (errno == ERANGE || end == value || strcmp(end, "\n") != 0))
            ok = false;
        if (ok) stored_mtime = (int64_t)parsed;
    }
    if (ok) ok = fgetc(file) == EOF && !ferror(file);
    fclose(file);
    return ok && stored_size == size && (uint32_t)stored_crc == crc32 &&
           stored_mtime == mtime;
}

bool crack_worker_verified_file_matches(const char *file_path,
                                        const char *marker_path,
                                        uint64_t size, uint32_t crc32)
{
    if (file_path == NULL || marker_path == NULL) return false;
    struct stat status;
    if (stat(file_path, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size < 0 || (uint64_t)status.st_size != size) {
        return false;
    }
    return crack_worker_verified_marker_matches(
        marker_path, size, crc32, (int64_t)status.st_mtime);
}

int crack_worker_partial_checkpoint_write(
    const char *path, const crack_worker_partial_checkpoint_t *checkpoint)
{
    if (path == NULL || path[0] == '\0' || checkpoint == NULL ||
        checkpoint->offset > checkpoint->expected_size ||
        checkpoint->block_size == 0U) {
        return CRACK_WORKER_CORE_ERROR;
    }
    char temporary[192];
    int length = snprintf(temporary, sizeof(temporary), "%s.tmp", path);
    if (length <= 0 || (size_t)length >= sizeof(temporary))
        return CRACK_WORKER_CORE_ERROR;

    FILE *file = fopen(temporary, "wb");
    if (file == NULL) return CRACK_WORKER_CORE_ERROR;
    bool ok = fprintf(file,
                      "CRACK_WORKER_PARTIAL 1\n"
                      "size=%" PRIu64 "\n"
                      "crc32=%08" PRIX32 "\n"
                      "offset=%" PRIu64 "\n"
                      "prefix_crc=%08" PRIX32 "\n"
                      "bsize=%" PRIu32 "\n",
                      checkpoint->expected_size, checkpoint->expected_crc32,
                      checkpoint->offset, checkpoint->prefix_crc32,
                      checkpoint->block_size) > 0 &&
              fflush(file) == 0;
    int fd = fileno(file);
    if (ok && fd >= 0) ok = fsync(fd) == 0;
    if (fclose(file) != 0) ok = false;
    if (!ok) {
        unlink(temporary);
        return CRACK_WORKER_CORE_ERROR;
    }
    unlink(path);
    if (rename(temporary, path) != 0) {
        unlink(temporary);
        return CRACK_WORKER_CORE_ERROR;
    }
    return CRACK_WORKER_CORE_OK;
}

static bool cw_partial_field(FILE *file, const char *key, int base,
                             uint64_t maximum, uint64_t *result)
{
    char line[96];
    size_t key_length = strlen(key);
    if (fgets(line, sizeof(line), file) == NULL ||
        strncmp(line, key, key_length) != 0) return false;
    const char *value = line + key_length;
    if ((base == 10 && !isdigit((unsigned char)*value)) ||
        (base == 16 && !isxdigit((unsigned char)*value))) return false;
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(value, &end, base);
    if (errno == ERANGE || end == value || strcmp(end, "\n") != 0 ||
        (uint64_t)parsed > maximum) return false;
    *result = (uint64_t)parsed;
    return true;
}

bool crack_worker_partial_checkpoint_read(
    const char *path, uint64_t expected_size, uint32_t expected_crc32,
    uint64_t actual_part_size, crack_worker_partial_checkpoint_t *checkpoint)
{
    if (path == NULL || checkpoint == NULL) return false;
    FILE *file = fopen(path, "rb");
    if (file == NULL) return false;
    char line[96];
    uint64_t size = 0, crc = 0, offset = 0, prefix_crc = 0, block_size = 0;
    bool ok = fgets(line, sizeof(line), file) != NULL &&
              strcmp(line, "CRACK_WORKER_PARTIAL 1\n") == 0 &&
              cw_partial_field(file, "size=", 10, UINT64_MAX, &size) &&
              cw_partial_field(file, "crc32=", 16, UINT32_MAX, &crc) &&
              cw_partial_field(file, "offset=", 10, UINT64_MAX, &offset) &&
              cw_partial_field(file, "prefix_crc=", 16, UINT32_MAX,
                               &prefix_crc) &&
              cw_partial_field(file, "bsize=", 10, UINT32_MAX, &block_size) &&
              fgetc(file) == EOF && !ferror(file);
    fclose(file);
    if (!ok || size != expected_size || (uint32_t)crc != expected_crc32 ||
        offset > size || offset > actual_part_size || block_size == 0U) {
        return false;
    }
    checkpoint->expected_size = size;
    checkpoint->expected_crc32 = (uint32_t)crc;
    checkpoint->offset = offset;
    checkpoint->prefix_crc32 = (uint32_t)prefix_crc;
    checkpoint->block_size = (uint32_t)block_size;
    return true;
}

bool crack_worker_resume_prefix_allowed(uint64_t partial_size)
{
    /* Only legacy .part files without durable metadata need a prefix scan.
     * Keep that migration synchronous phase short and deterministic. */
    return partial_size <= 1024U * 1024U;
}

int crack_worker_seek_range_start(FILE *file, uint64_t requested,
                                  uint64_t *aligned)
{
    if (file == NULL || aligned == NULL || requested > (uint64_t)INT64_MAX) {
        return CRACK_WORKER_CORE_ERROR;
    }
    if (requested == 0) {
        if (fseeko(file, 0, SEEK_SET) != 0) return CRACK_WORKER_CORE_ERROR;
        *aligned = 0;
        return CRACK_WORKER_CORE_OK;
    }

    if (fseeko(file, (off_t)(requested - 1U), SEEK_SET) != 0) {
        return CRACK_WORKER_CORE_ERROR;
    }
    int previous = fgetc(file);
    if (previous == EOF) {
        if (ferror(file)) return CRACK_WORKER_CORE_ERROR;
        *aligned = requested;
        return CRACK_WORKER_CORE_OK;
    }
    if (previous != '\n') {
        int c;
        do {
            c = fgetc(file);
        } while (c != EOF && c != '\n');
        if (c == EOF && ferror(file)) return CRACK_WORKER_CORE_ERROR;
    }
    off_t position = ftello(file);
    if (position < 0) return CRACK_WORKER_CORE_ERROR;
    *aligned = (uint64_t)position;
    return CRACK_WORKER_CORE_OK;
}

crack_worker_line_result_t crack_worker_read_word(FILE *file, uint64_t end_offset,
                                                  char word[64],
                                                  uint64_t *line_start,
                                                  uint64_t *next_offset)
{
    if (file == NULL || word == NULL || line_start == NULL || next_offset == NULL) {
        return CRACK_WORKER_LINE_IO_ERROR;
    }
    off_t start = ftello(file);
    if (start < 0) return CRACK_WORKER_LINE_IO_ERROR;
    *line_start = (uint64_t)start;
    if (end_offset != 0 && *line_start >= end_offset) {
        *next_offset = *line_start;
        word[0] = '\0';
        return CRACK_WORKER_LINE_END;
    }

    size_t stored = 0;
    size_t length = 0;
    bool saw_any = false;
    for (;;) {
        int c = fgetc(file);
        if (c == EOF) {
            if (ferror(file)) return CRACK_WORKER_LINE_IO_ERROR;
            if (!saw_any) {
                *next_offset = *line_start;
                word[0] = '\0';
                return CRACK_WORKER_LINE_END;
            }
            break;
        }
        saw_any = true;
        if (c == '\n') break;
        if (c == '\r') continue;
        if (stored < 63U) word[stored++] = (char)c;
        length++;
    }
    off_t after = ftello(file);
    if (after < 0) return CRACK_WORKER_LINE_IO_ERROR;
    *next_offset = (uint64_t)after;
    word[stored] = '\0';
    if (length < 8U || length > 63U) return CRACK_WORKER_LINE_SKIPPED;
    return CRACK_WORKER_LINE_CANDIDATE;
}

bool crack_worker_hccapx_valid(const crack_worker_hccapx_t *record)
{
    if (record == NULL || record->signature != CRACK_WORKER_HCCAPX_SIGNATURE ||
        record->version != 4U || (record->message_pair & 0x7fU) > 5U ||
        record->essid_len == 0U || record->essid_len > 32U ||
        (record->keyver != 1U && record->keyver != 2U) ||
        record->eapol_len < 99U || record->eapol_len > sizeof(record->eapol)) {
        return false;
    }
    uint16_t declared = ((uint16_t)record->eapol[2] << 8) | record->eapol[3];
    return record->eapol[1] == 3U && declared + 4U == record->eapol_len &&
           (record->eapol[6] & 7U) == record->keyver;
}

void crack_worker_progress_begin(crack_worker_progress_t *progress,
                                 uint64_t aligned_offset)
{
    if (progress == NULL) return;
    progress->safe_offset = aligned_offset;
    progress->checked = 0;
}

void crack_worker_progress_commit(crack_worker_progress_t *progress,
                                  uint64_t next_offset,
                                  bool candidate_checked)
{
    if (progress == NULL) return;
    if (next_offset > progress->safe_offset)
        progress->safe_offset = next_offset;
    if (candidate_checked && progress->checked < UINT64_MAX)
        progress->checked++;
}

crack_worker_start_action_t crack_worker_start_classify(
    bool slot_occupied, bool running,
    const crack_worker_assignment_t *existing,
    const crack_worker_assignment_t *requested)
{
    if (!requested || !requested->id || !requested->capture_path ||
        !requested->wordlist_path) {
        return CRACK_WORKER_START_JOB_CONFLICT;
    }
    if (!slot_occupied || !existing || !existing->id ||
        !existing->capture_path || !existing->wordlist_path) {
        return CRACK_WORKER_START_NEW;
    }
    if (strcmp(existing->id, requested->id) == 0) {
        bool identical = strcmp(existing->capture_path,
                                requested->capture_path) == 0 &&
                         strcmp(existing->wordlist_path,
                                requested->wordlist_path) == 0 &&
                         existing->range_start == requested->range_start &&
                         existing->range_end == requested->range_end;
        return identical ? CRACK_WORKER_START_REPLAY
                         : CRACK_WORKER_START_JOB_CONFLICT;
    }
    return running ? CRACK_WORKER_START_BUSY : CRACK_WORKER_START_NEW;
}
