#define _POSIX_C_SOURCE 200809L

#include "crack_worker_core.h"
#include "crack_worker_transfer.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures;

#define CHECK(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        failures++; \
    } \
} while (0)

static void write_file(const char *path, const void *data, size_t size)
{
    FILE *file = fopen(path, "wb");
    CHECK(file != NULL);
    if (!file) return;
    CHECK(fwrite(data, 1, size, file) == size);
    CHECK(fclose(file) == 0);
}

#ifdef CRACK_WORKER_PREFLIGHT_SOURCE
/* Compile the allocation-through-READY statements extracted from cw_receive.
 * The only replaced boundaries are allocation and UART/stdout I/O; this catches
 * moving/skipping allocation before the production READY output and raw mode. */
static bool preflight_allocation_fails;
static unsigned preflight_allocations, preflight_ready_outputs, preflight_flushes;
static void *preflight_allocate(size_t size)
{
    ++preflight_allocations;
    return preflight_allocation_fails ? NULL : malloc(size);
}
static int preflight_flush(int port)
{
    (void)port;
    ++preflight_flushes;
    return 0;
}
static int preflight_print(const char *format, const char *ready)
{
    (void)format;
    CHECK(strstr(ready, "[CRACK/1] READY ") == ready);
    ++preflight_ready_outputs;
    return 0;
}
static int preflight_wait(int port, uint32_t timeout)
{
    (void)port; (void)timeout;
    return 0;
}
static void test_receive_allocation_before_ready(bool ack32, bool fail)
{
    preflight_allocation_fails = fail;
    preflight_allocations = preflight_ready_outputs = preflight_flushes = 0;
    uint8_t *payload = NULL;
    bool raw_mode = false;
    const char *reason = NULL;
    char *argv[] = {"crack_worker", "receive", "wordlist"};
    uint64_t expected_size = 8, crc_value = 0, offset = 0;
    uint32_t running_crc = 0, block_size = 1024, prepare_ms = 10000;
#define malloc preflight_allocate
#define uart_flush_input preflight_flush
#define CW_UART 0
#define ESP_OK 0
#define flockfile(file) ((void)(file))
#define printf preflight_print
#define fflush(file) ((void)(file))
#define uart_wait_tx_done preflight_wait
#define pdMS_TO_TICKS(ms) (ms)
#define cw_receive_timeout_ms(size) (1273U)
#include CRACK_WORKER_PREFLIGHT_SOURCE
raw_done:
done:
#undef malloc
#undef uart_flush_input
#undef CW_UART
#undef ESP_OK
#undef flockfile
#undef printf
#undef fflush
#undef uart_wait_tx_done
#undef pdMS_TO_TICKS
#undef cw_receive_timeout_ms
    CHECK(preflight_allocations == 1);
    if (fail) {
        CHECK(preflight_ready_outputs == 0);
        CHECK(preflight_flushes == 0 && !raw_mode);
        CHECK(reason != NULL && strcmp(reason, "no_memory") == 0);
        CHECK(payload == NULL);
    } else {
        CHECK(preflight_ready_outputs == 1);
        CHECK(preflight_flushes == 1 && raw_mode);
        CHECK(reason == NULL && payload != NULL);
    }
    free(payload);
}
#endif

static void test_ids_and_hex(void)
{
    CHECK(crack_worker_job_id_valid("job_01-A"));
    CHECK(!crack_worker_job_id_valid(""));
    CHECK(!crack_worker_job_id_valid("../bad"));
    char long_id[40];
    memset(long_id, 'a', sizeof(long_id));
    long_id[sizeof(long_id) - 1] = '\0';
    CHECK(!crack_worker_job_id_valid(long_id));

    CHECK(crack_worker_wordlist_name_allowed("rock you.TXT"));
    CHECK(crack_worker_wordlist_name_allowed("common.lst"));
    CHECK(!crack_worker_wordlist_name_allowed(".cache.txt"));
    CHECK(!crack_worker_wordlist_name_allowed("words.txt.tmp"));

    char hex[16];
    const unsigned char raw[] = {'A', ' ', '"', 0xff};
    CHECK(crack_worker_hex_encode(raw, sizeof(raw), hex, sizeof(hex)));
    CHECK(strcmp(hex, "412022FF") == 0);
    CHECK(!crack_worker_hex_encode(raw, sizeof(raw), hex, 8));

    CHECK(crack_worker_crc32_update(0, "123456789", 9) == 0xCBF43926U);
}

static void test_start_assignment_classification(void)
{
    crack_worker_assignment_t existing = {
        .id = "job-a", .capture_path = "/c/11-AA",
        .wordlist_path = "/w/22-BB", .range_start = 10, .range_end = 90,
    };
    crack_worker_assignment_t same = existing;
    crack_worker_assignment_t changed_range = existing;
    changed_range.range_end = 91;
    crack_worker_assignment_t changed_capture = existing;
    changed_capture.capture_path = "/c/12-CC";
    crack_worker_assignment_t other = existing;
    other.id = "job-b";

    CHECK(crack_worker_start_classify(false, false, NULL, &same) ==
          CRACK_WORKER_START_NEW);
    CHECK(crack_worker_start_classify(true, true, &existing, &same) ==
          CRACK_WORKER_START_REPLAY);
    CHECK(crack_worker_start_classify(true, false, &existing, &same) ==
          CRACK_WORKER_START_REPLAY);
    CHECK(crack_worker_start_classify(true, true, &existing, &changed_range) ==
          CRACK_WORKER_START_JOB_CONFLICT);
    CHECK(crack_worker_start_classify(true, false, &existing, &changed_capture) ==
          CRACK_WORKER_START_JOB_CONFLICT);
    CHECK(crack_worker_start_classify(true, true, &existing, &other) ==
          CRACK_WORKER_START_BUSY);
    CHECK(crack_worker_start_classify(true, false, &existing, &other) ==
          CRACK_WORKER_START_NEW);
}

static uint32_t get_le32(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
           ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t get_le64(const uint8_t *bytes)
{
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) value |= (uint64_t)bytes[i] << (i * 8U);
    return value;
}

static void test_ack32_encoder(void)
{
    const uint8_t statuses[] = {0x06, 0x15, 0x18};
    for (size_t status_index = 0; status_index < sizeof(statuses); ++status_index) {
        uint8_t frame[CRACK_WORKER_ACK32_SIZE];
        CHECK(crack_worker_ack32_build(frame, 7, statuses[status_index], 4096));
        CHECK(memcmp(frame, "FTA\x01", 4) == 0);
        CHECK(get_le32(frame + 4) == 7);
        CHECK(frame[8] == statuses[status_index]);
        CHECK(get_le64(frame + 12) == 4096);
        CHECK(get_le32(frame + 20) == crack_worker_crc32_update(0, frame, 20));
        for (size_t i = 9; i < 12; ++i) CHECK(frame[i] == 0);
        for (size_t i = 24; i < 32; ++i) CHECK(frame[i] == 0);
    }
    uint8_t frame[CRACK_WORKER_ACK32_SIZE];
    CHECK(!crack_worker_ack32_build(frame, 0, 0x00, 0));
}

static void test_reply_mode_selection(void)
{
    size_t ack_size = 0;
    CHECK(crack_worker_reply_mode_parse(5, NULL, &ack_size));
    CHECK(ack_size == 1U);
    CHECK(crack_worker_reply_mode_parse(6, NULL, &ack_size));
    CHECK(ack_size == 1U);
    CHECK(crack_worker_reply_mode_parse(7, "ack32", &ack_size));
    CHECK(ack_size == CRACK_WORKER_ACK32_SIZE);
    CHECK(!crack_worker_reply_mode_parse(7, "byte", &ack_size));
}

static void test_fingerprint(const char *dir)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/words.txt", dir);
    write_file(path, "password-one\npassword-two\n", 26);

    crack_worker_file_id_t before;
    crack_worker_file_id_t same;
    CHECK(crack_worker_file_id(path, &before) == CRACK_WORKER_CORE_OK);
    CHECK(crack_worker_file_id(path, &same) == CRACK_WORKER_CORE_OK);
    CHECK(crack_worker_file_id_equal(&before, &same));

    write_file(path, "Xassword-one\npassword-two\n", 26);
    CHECK(crack_worker_file_id(path, &same) == CRACK_WORKER_CORE_OK);
    CHECK(!crack_worker_file_id_equal(&before, &same));
}

static void test_verified_marker_requires_exact_file_identity(const char *dir)
{
    char marker[256];
    char path[256];
    snprintf(marker, sizeof(marker), "%s/words.txt.verified", dir);
    snprintf(path, sizeof(path), "%s/verified-words.txt", dir);

    CHECK(crack_worker_verified_marker_write(
              marker, 22690149U, 0xA1B2C3D4U, 1700000000) ==
          CRACK_WORKER_CORE_OK);
    CHECK(crack_worker_verified_marker_matches(
        marker, 22690149U, 0xA1B2C3D4U, 1700000000));
    CHECK(!crack_worker_verified_marker_matches(
        marker, 22690150U, 0xA1B2C3D4U, 1700000000));
    CHECK(!crack_worker_verified_marker_matches(
        marker, 22690149U, 0xA1B2C3D5U, 1700000000));
    CHECK(!crack_worker_verified_marker_matches(
        marker, 22690149U, 0xA1B2C3D4U, 1700000001));

    write_file(marker, "broken\n", 7);
    CHECK(!crack_worker_verified_marker_matches(
        marker, 22690149U, 0xA1B2C3D4U, 1700000000));

    const char *malformed[] = {
        "CRACK_WORKER_VERIFIED 1\nsize=22690149junk\ncrc32=A1B2C3D4\nmtime=1700000000\n",
        "CRACK_WORKER_VERIFIED 1\nsize=+22690149\ncrc32=A1B2C3D4\nmtime=1700000000\n",
        "CRACK_WORKER_VERIFIED 1\nsize=22690149\ncrc32=A1B2C3D4junk\nmtime=1700000000\n",
        "CRACK_WORKER_VERIFIED 1\nsize=18446744073709551616\ncrc32=A1B2C3D4\nmtime=1700000000\n",
        "CRACK_WORKER_VERIFIED 1\ncrc32=A1B2C3D4\nsize=22690149\nmtime=1700000000\n",
        "CRACK_WORKER_VERIFIED 1\nsize=22690149\ncrc32=A1B2C3D4\nmtime=1700000000",
    };
    for (size_t i = 0; i < sizeof(malformed) / sizeof(malformed[0]); ++i) {
        write_file(marker, malformed[i], strlen(malformed[i]));
        CHECK(!crack_worker_verified_marker_matches(
            marker, 22690149U, 0xA1B2C3D4U, 1700000000));
    }

    write_file(path, "password-one\n", 13);
    struct stat status;
    CHECK(stat(path, &status) == 0);
    CHECK(crack_worker_verified_marker_write(
              marker, 13, 0x11223344U, (int64_t)status.st_mtime) ==
          CRACK_WORKER_CORE_OK);
    CHECK(crack_worker_verified_file_matches(
        path, marker, 13, 0x11223344U));
    CHECK(!crack_worker_verified_file_matches(
        path, marker, 12, 0x11223344U));
    CHECK(crack_worker_verified_marker_write(
              marker, 13, 0x11223344U, (int64_t)status.st_mtime + 1) ==
          CRACK_WORKER_CORE_OK);
    CHECK(!crack_worker_verified_file_matches(
        path, marker, 13, 0x11223344U));
    CHECK(crack_worker_verified_marker_write(
              marker, 13, 0x11223344U, (int64_t)status.st_mtime) ==
          CRACK_WORKER_CORE_OK);
    CHECK(unlink(marker) == 0);
    CHECK(!crack_worker_verified_file_matches(
        path, marker, 13, 0x11223344U));
}

static void test_reader_and_ranges(const char *dir)
{
    char path[256];
    snprintf(path, sizeof(path), "%s/ranges.txt", dir);
    const char fixture[] =
        "1234567\n"
        "password1\r\n"
        "with spaces\n"
        "12345678\n"
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890\n"
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901\n"
        "lastpass";
    write_file(path, fixture, sizeof(fixture) - 1);

    FILE *file = fopen(path, "rb");
    CHECK(file != NULL);
    if (!file) return;

    uint64_t aligned = UINT64_MAX;
    CHECK(crack_worker_seek_range_start(file, 10, &aligned) == CRACK_WORKER_CORE_OK);
    CHECK(aligned == 19);

    char word[64];
    uint64_t line_start = 0;
    uint64_t next_offset = 0;
    CHECK(crack_worker_read_word(file, 0, word, &line_start, &next_offset) ==
          CRACK_WORKER_LINE_CANDIDATE);
    CHECK(strcmp(word, "with spaces") == 0);
    CHECK(line_start == 19);
    CHECK(next_offset == 31);

    CHECK(crack_worker_read_word(file, 40, word, &line_start, &next_offset) ==
          CRACK_WORKER_LINE_CANDIDATE);
    CHECK(strcmp(word, "12345678") == 0);
    CHECK(crack_worker_read_word(file, 40, word, &line_start, &next_offset) ==
          CRACK_WORKER_LINE_END);
    fclose(file);

    file = fopen(path, "rb");
    CHECK(file != NULL);
    CHECK(crack_worker_seek_range_start(file, 0, &aligned) == CRACK_WORKER_CORE_OK);
    int candidates = 0;
    int skipped = 0;
    for (;;) {
        crack_worker_line_result_t result =
            crack_worker_read_word(file, 0, word, &line_start, &next_offset);
        if (result == CRACK_WORKER_LINE_END) break;
        if (result == CRACK_WORKER_LINE_CANDIDATE) candidates++;
        if (result == CRACK_WORKER_LINE_SKIPPED) skipped++;
        CHECK(result != CRACK_WORKER_LINE_IO_ERROR);
    }
    fclose(file);
    /* WPA2 passphrases may contain 8..63 bytes, so the 63-byte entry is valid. */
    CHECK(candidates == 5);
    CHECK(skipped == 2);
}

static void test_hccapx_validation(void)
{
    crack_worker_hccapx_t record = {0};
    record.signature = CRACK_WORKER_HCCAPX_SIGNATURE;
    record.version = 4;
    record.message_pair = 0;
    record.essid_len = 4;
    memcpy(record.essid, "Test", 4);
    record.keyver = 2;
    record.eapol_len = 99;
    record.eapol[1] = 3;
    record.eapol[2] = 0;
    record.eapol[3] = 95;
    record.eapol[6] = 2;
    CHECK(crack_worker_hccapx_valid(&record));
    record.keyver = 3;
    CHECK(!crack_worker_hccapx_valid(&record));
}

static void test_progress_is_committed_only_after_a_line_is_finished(void)
{
    crack_worker_progress_t progress;
    crack_worker_progress_begin(&progress, 19);
    CHECK(progress.safe_offset == 19);
    CHECK(progress.checked == 0);

    /* Reading a candidate may move FILE*, but the public checkpoint must stay
     * before that candidate until its expensive verification completes. */
    CHECK(progress.safe_offset == 19);
    crack_worker_progress_commit(&progress, 31, true);
    CHECK(progress.safe_offset == 31);
    CHECK(progress.checked == 1);

    /* Invalid lines are exhausted without a password check, but are still a
     * safe point from which the controller may resume the shard. */
    crack_worker_progress_commit(&progress, 72, false);
    CHECK(progress.safe_offset == 72);
    CHECK(progress.checked == 1);

    /* A stale update must never move the acknowledged checkpoint backwards. */
    crack_worker_progress_commit(&progress, 60, true);
    CHECK(progress.safe_offset == 72);
    CHECK(progress.checked == 2);
}

static void test_resume_crc_scan_is_strictly_bounded(void)
{
    CHECK(crack_worker_resume_prefix_allowed(0));
    CHECK(crack_worker_resume_prefix_allowed(1024U * 1024U));
    CHECK(!crack_worker_resume_prefix_allowed(1024U * 1024U + 1U));
    CHECK(!crack_worker_resume_prefix_allowed(UINT64_MAX));
}

static void test_partial_checkpoint_is_strict_and_supports_large_resume(const char *dir)
{
    char marker[256];
    snprintf(marker, sizeof(marker), "%s/wordlist.part.meta", dir);
    crack_worker_partial_checkpoint_t checkpoint = {
        .expected_size = 22690149U,
        .expected_crc32 = 0xA1B2C3D4U,
        .offset = 3U * 1024U * 1024U,
        .prefix_crc32 = 0x10203040U,
        .block_size = 1024U,
    };
    CHECK(crack_worker_partial_checkpoint_write(marker, &checkpoint) ==
          CRACK_WORKER_CORE_OK);

    crack_worker_partial_checkpoint_t loaded = {0};
    CHECK(crack_worker_partial_checkpoint_read(
        marker, checkpoint.expected_size, checkpoint.expected_crc32,
        checkpoint.offset, &loaded));
    CHECK(loaded.offset == checkpoint.offset);
    CHECK(loaded.prefix_crc32 == checkpoint.prefix_crc32);
    CHECK(loaded.block_size == checkpoint.block_size);
    CHECK(!crack_worker_partial_checkpoint_read(
        marker, checkpoint.expected_size + 1U, checkpoint.expected_crc32,
        checkpoint.offset, &loaded));
    CHECK(!crack_worker_partial_checkpoint_read(
        marker, checkpoint.expected_size, checkpoint.expected_crc32 + 1U,
        checkpoint.offset, &loaded));
    CHECK(!crack_worker_partial_checkpoint_read(
        marker, checkpoint.expected_size, checkpoint.expected_crc32,
        checkpoint.offset - 1U, &loaded));

    write_file(marker,
               "CRACK_WORKER_PARTIAL 1\nsize=22690149\ncrc32=A1B2C3D4\n"
               "offset=3145728junk\nprefix_crc=10203040\nbsize=1024\n",
               strlen("CRACK_WORKER_PARTIAL 1\nsize=22690149\ncrc32=A1B2C3D4\n"
                      "offset=3145728junk\nprefix_crc=10203040\nbsize=1024\n"));
    CHECK(!crack_worker_partial_checkpoint_read(
        marker, checkpoint.expected_size, checkpoint.expected_crc32,
        checkpoint.offset, &loaded));
}

static void put_le32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t)value;
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
}

static void ftb_header(uint8_t header[16], uint32_t index, uint32_t length,
                       uint32_t crc32)
{
    static const uint8_t fixture[16] = {
        'F', 'T', 'B', 1,
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0,
    };
    memcpy(header, fixture, sizeof(fixture));
    put_le32(header + 4, index);
    put_le32(header + 8, length);
    put_le32(header + 12, crc32);
}

static crack_worker_transfer_state_t transfer_state(uint64_t expected_size,
                                                    uint32_t block_size)
{
    return (crack_worker_transfer_state_t){
        .expected_size = expected_size,
        .block_size = block_size,
        .ack32 = true,
    };
}

static void test_transfer_data_and_duplicate_state(void)
{
    crack_worker_transfer_state_t state = transfer_state(4, 4);
    uint8_t header[16];
    ftb_header(header, 0, 4, 0x12345678U);
    CHECK(crack_worker_transfer_classify(&state, header) ==
          CRACK_TRANSFER_EXPECTED_DATA);

    crack_worker_transfer_commit_data(&state, 0, 4, 0x12345678U);
    CHECK(state.offset == 4);
    CHECK(state.expected_index == 1);
    CHECK(state.have_last);
    CHECK(state.last_committed_offset == 4);
    CHECK(state.last_index == 0);
    CHECK(state.last_length == 4);
    CHECK(state.last_crc32 == 0x12345678U);

    crack_worker_transfer_state_t before = state;
    CHECK(crack_worker_transfer_classify(&state, header) ==
          CRACK_TRANSFER_DUPLICATE_DATA);
    CHECK(memcmp(&state, &before, sizeof(state)) == 0);

    ftb_header(header, 0, 3, 0x12345678U);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
    ftb_header(header, 0, 4, 0x12345679U);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
}

static void test_transfer_replay_requires_immediate_previous_ack32_block(void)
{
    crack_worker_transfer_state_t state = transfer_state(8, 4);
    uint8_t header[16];

    ftb_header(header, 0, 4, 0x11111111U);
    CHECK(crack_worker_transfer_classify(&state, header) ==
          CRACK_TRANSFER_EXPECTED_DATA);
    crack_worker_transfer_commit_data(&state, 0, 4, 0x11111111U);
    ftb_header(header, 1, 4, 0x22222222U);
    CHECK(crack_worker_transfer_classify(&state, header) ==
          CRACK_TRANSFER_EXPECTED_DATA);
    crack_worker_transfer_commit_data(&state, 1, 4, 0x22222222U);

    ftb_header(header, 0, 4, 0x22222222U);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
    ftb_header(header, 3, 4, 0x22222222U);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
    ftb_header(header, 2, 4, 0x22222222U);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);

    ftb_header(header, 1, 4, 0x22222222U);
    CHECK(crack_worker_transfer_classify(&state, header) ==
          CRACK_TRANSFER_DUPLICATE_DATA);
    state.ack32 = false;
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
}

static void test_transfer_rejects_bad_data_headers(void)
{
    crack_worker_transfer_state_t state = transfer_state(16, 8);
    uint8_t header[16];

    ftb_header(header, 0, 8, 0x01020304U);
    header[0] = 'X';
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
    ftb_header(header, 0, 8, 0x01020304U);
    header[3] = 2;
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);

    ftb_header(header, 0, 0, 0);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
    ftb_header(header, 0, 9, 0x01020304U);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
    state.offset = 12;
    ftb_header(header, 0, 5, 0x01020304U);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);

    state.offset = 0;
    state.expected_index = 1;
    ftb_header(header, 0, 8, 0x01020304U);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
    ftb_header(header, 2, 8, 0x01020304U);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
    ftb_header(header, UINT32_MAX, 8, 0x01020304U);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
}

static void test_transfer_short_final_block_and_fin(void)
{
    crack_worker_transfer_state_t state = transfer_state(11, 8);
    uint8_t header[16];
    ftb_header(header, 0, 8, 0x11111111U);
    CHECK(crack_worker_transfer_classify(&state, header) ==
          CRACK_TRANSFER_EXPECTED_DATA);
    crack_worker_transfer_commit_data(&state, 0, 8, 0x11111111U);
    ftb_header(header, 1, 3, 0x22222222U);
    CHECK(crack_worker_transfer_classify(&state, header) ==
          CRACK_TRANSFER_EXPECTED_DATA);
    crack_worker_transfer_commit_data(&state, 1, 3, 0x22222222U);

    ftb_header(header, 2, 0, 0);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_FIN);
    CHECK(crack_worker_transfer_finalize(&state));
    CHECK(!crack_worker_transfer_finalize(&state));
    CHECK(crack_worker_transfer_classify(&state, header) ==
          CRACK_TRANSFER_DUPLICATE_FIN);

    ftb_header(header, 1, 0, 0);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
    ftb_header(header, 2, 1, 0);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
    ftb_header(header, 2, 0, 1);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
}

static void test_transfer_fin_requires_exact_eof_and_cancel_is_explicit(void)
{
    crack_worker_transfer_state_t state = transfer_state(4, 4);
    uint8_t header[16];
    ftb_header(header, 0, 0, 0);
    CHECK(crack_worker_transfer_classify(&state, header) == CRACK_TRANSFER_INVALID);
    CHECK(!crack_worker_transfer_finalize(&state));

    crack_worker_transfer_state_t before = state;
    CHECK(crack_worker_transfer_cancel(&state) == CRACK_TRANSFER_CANCEL);
    CHECK(memcmp(&state, &before, sizeof(state)) == 0);

    uint8_t can_at_header_boundary[16] = {
        0x18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    };
    CHECK(crack_worker_transfer_classify(&state, can_at_header_boundary) ==
          CRACK_TRANSFER_INVALID);
}

static void test_transfer_prepare_timing(void)
{
    bool resume_allowed = false;
    CHECK(crack_worker_prepare_ms(0, &resume_allowed) == 10000U);
    CHECK(resume_allowed);
    CHECK(crack_worker_prepare_ms(1, &resume_allowed) == 11000U);
    CHECK(resume_allowed);
    CHECK(crack_worker_prepare_ms(262144U, &resume_allowed) == 11000U);
    CHECK(resume_allowed);
    CHECK(crack_worker_prepare_ms(154664960U, &resume_allowed) == 600000U);
    CHECK(resume_allowed);
    CHECK(crack_worker_prepare_ms(154664961U, &resume_allowed) == 10000U);
    CHECK(!resume_allowed);
    CHECK(crack_worker_prepare_ms(UINT64_MAX, &resume_allowed) == 10000U);
    CHECK(!resume_allowed);

    CHECK(crack_worker_prepare_ms(7176192U, &resume_allowed) == 38000U);
    CHECK(resume_allowed);
    CHECK(crack_worker_first_byte_timeout(true, 38000U, 1126U) == 38000U);
    CHECK(crack_worker_first_byte_timeout(false, 38000U, 1126U) == 1126U);
    CHECK(crack_worker_first_byte_timeout(true, 1000U, 1126U) == 1126U);
}

/* These exercise the production session and action adapter: replay must not
 * repeat storage effects, and terminal output must wait for the FIN quiet gap. */
typedef struct {
    unsigned writes, crc_updates, checkpoints, progress_updates;
    unsigned finalizations, replies, terminals;
    uint8_t input[512], output[512], stored[32], payload[4];
    size_t input_size, input_pos, stored_size;
    uint64_t now, terminal_at;
    uint32_t timeouts[32];
    uint32_t header_delay;
    unsigned reads;
    bool success, fail_finalize, fail_checkpoint;
} transfer_fixture_t;

static int fixture_read(void *context, void *data, size_t size,
                        uint32_t timeout, size_t *received)
{
    transfer_fixture_t *f = context;
    CHECK(f->terminals == 0);
    CHECK(f->reads < 32);
    f->timeouts[f->reads++] = timeout;
    size_t available = f->input_size - f->input_pos;
    *received = size < available ? size : available;
    memcpy(data, f->input + f->input_pos, *received);
    f->input_pos += *received;
    if (size == 1 && *received == 1) f->now += f->header_delay;
    if (*received != size) f->now += timeout;
    return *received == size ? 1 : 0;
}

static bool fixture_write(void *context, const uint8_t *data, uint32_t size)
{
    transfer_fixture_t *f = context;
    f->writes++;
    memcpy(f->stored + f->stored_size, data, size);
    f->stored_size += size;
    return true;
}

static void fixture_crc(void *context, const uint8_t *data, uint32_t size)
{
    transfer_fixture_t *f = context;
    (void)data; (void)size;
    f->crc_updates++;
}

static bool fixture_checkpoint(void *context, uint64_t offset)
{
    transfer_fixture_t *f = context;
    CHECK(offset == f->stored_size);
    f->checkpoints++;
    return !f->fail_checkpoint;
}

static void fixture_progress(void *context, uint64_t offset, uint32_t index)
{
    transfer_fixture_t *f = context;
    CHECK(offset == f->stored_size);
    CHECK(index == f->writes);
    f->progress_updates++;
}

static bool fixture_finalize(void *context)
{
    transfer_fixture_t *f = context;
    f->finalizations++;
    return !f->fail_finalize;
}

static bool fixture_reply(void *context, const uint8_t frame[32])
{
    transfer_fixture_t *f = context;
    CHECK(f->replies < 16);
    memcpy(f->output + f->replies++ * 32, frame, 32);
    return true;
}

static void fixture_terminal(void *context, bool success, const char *reason)
{
    transfer_fixture_t *f = context;
    CHECK(reason != NULL);
    f->terminals++;
    f->success = success;
    f->terminal_at = f->now;
}

static const crack_worker_transfer_ops_t fixture_ops = {
    .read = fixture_read, .write = fixture_write, .crc = fixture_crc,
    .checkpoint = fixture_checkpoint, .progress = fixture_progress,
    .finalize = fixture_finalize, .reply = fixture_reply,
    .terminal = fixture_terminal,
};

static void fixture_frame(transfer_fixture_t *f, uint32_t index,
                           const char *data, uint32_t size, uint32_t crc)
{
    ftb_header(f->input + f->input_size, index, size, crc);
    f->input_size += 16;
    if (size) memcpy(f->input + f->input_size, data, size);
    f->input_size += size;
}

static void test_receive_session_replays_and_fin_quiet_period(void)
{
    for (unsigned replays = 0; replays <= 2; ++replays) {
        transfer_fixture_t f = {.header_delay = 1900};
        crack_worker_transfer_state_t state = transfer_state(4, 4);
        crack_worker_transfer_session_t session = {.prepare_ms = 11000, .rx_ms = 1273};
        fixture_frame(&f, 0, "1234", 4, 0x9BE3E0A3U);
        if (replays) fixture_frame(&f, 0, "xxxx", 4, 0x9BE3E0A3U);
        for (unsigned i = 0; i <= replays; ++i) fixture_frame(&f, 1, NULL, 0, 0);
        CHECK(crack_worker_transfer_receive(&state, &session, f.payload, sizeof(f.payload), &fixture_ops, &f));
        CHECK(f.input_pos == f.input_size);
        CHECK(f.writes == 1 && f.crc_updates == 1 && f.checkpoints == 1);
        CHECK(f.progress_updates == 1 && f.finalizations == 1);
        CHECK(f.stored_size == 4 && memcmp(f.stored, "1234", 4) == 0);
        CHECK(f.replies == 2 + replays + (replays != 0));
        CHECK(f.terminals == 1 && f.success);
        CHECK(f.terminal_at == 7000 + 1900 * (2 + replays + (replays != 0)));
        CHECK(f.timeouts[0] == 11000 && f.timeouts[1] == 1273);
        CHECK(f.timeouts[2] == 1273 && f.timeouts[3] == 7000);
        CHECK(state.offset == 4 && state.expected_index == 1 && state.finalized);
        CHECK(get_le32(f.output + (f.replies - 1) * 32 + 4) == 1);
        CHECK(get_le64(f.output + (f.replies - 1) * 32 + 12) == 4);
        if (replays) CHECK(memcmp(f.output, f.output + 32, 32) == 0);
    }
}

static void test_receive_initial_timeout_never_shrinks_rx_budget(void)
{
    transfer_fixture_t f = {0};
    crack_worker_transfer_state_t state = transfer_state(4, 4);
    crack_worker_transfer_session_t session = {.prepare_ms = 1000, .rx_ms = 1273};
    fixture_frame(&f, 0, "1234", 4, 0x9BE3E0A3U);
    fixture_frame(&f, 1, NULL, 0, 0);

    CHECK(crack_worker_transfer_receive(&state, &session, f.payload,
                                        sizeof(f.payload), &fixture_ops, &f));
    CHECK(f.timeouts[0] == 1273U);
}

static void test_receive_rejects_unavailable_caller_storage_before_read(void)
{
    for (unsigned missing = 0; missing < 2; ++missing) {
        transfer_fixture_t f = {0};
        crack_worker_transfer_state_t state = transfer_state(4, 4);
        crack_worker_transfer_session_t session = {.prepare_ms = 10000, .rx_ms = 1273};
        CHECK(!crack_worker_transfer_receive(&state, &session,
                  missing ? NULL : f.payload, missing ? 4 : 3, &fixture_ops, &f));
        CHECK(f.reads == 0 && f.replies == 0 && f.writes == 0);
        CHECK(f.terminals == 1 && !f.success);
        CHECK(strcmp(session.reason, "invalid_buffer") == 0);
    }
}

static void test_receive_lost_nak_and_partial_payload(void)
{
    transfer_fixture_t f = {0};
    crack_worker_transfer_state_t state = transfer_state(4, 4);
    crack_worker_transfer_session_t session = {.prepare_ms = 10000, .rx_ms = 1273};
    fixture_frame(&f, 0, "xxxx", 4, 0x9BE3E0A3U);
    fixture_frame(&f, 0, "1234", 4, 0x9BE3E0A3U);
    fixture_frame(&f, 1, NULL, 0, 0);
    CHECK(crack_worker_transfer_receive(&state, &session, f.payload, sizeof(f.payload), &fixture_ops, &f));
    CHECK(f.output[8] == 0x15 && get_le64(f.output + 12) == 0);
    CHECK(f.timeouts[3] == 7000 && f.writes == 1 && f.finalizations == 1);

    f = (transfer_fixture_t){0};
    state = transfer_state(4, 4);
    fixture_frame(&f, 0, "1234", 4, 0x9BE3E0A3U);
    f.input_size -= 2;
    CHECK(!crack_worker_transfer_receive(&state, &session, f.payload, sizeof(f.payload), &fixture_ops, &f));
    CHECK(f.writes == 0 && f.finalizations == 0 && !f.success);
    CHECK(f.output[8] == 0x18 && f.terminal_at == 1273);
    CHECK(session.payload_got == 2);
}

static void test_third_lost_nak_still_waits_for_header_boundary(void)
{
    transfer_fixture_t f = {0};
    crack_worker_transfer_state_t state = transfer_state(4, 4);
    crack_worker_transfer_session_t session = {.prepare_ms = 10000, .rx_ms = 1273};
    for (unsigned i = 0; i < 3; ++i)
        fixture_frame(&f, 0, "xxxx", 4, 0x9BE3E0A3U);
    CHECK(!crack_worker_transfer_receive(&state, &session, f.payload, sizeof(f.payload), &fixture_ops, &f));
    CHECK(f.replies == 3 && f.writes == 0 && f.finalizations == 0);
    CHECK(f.reads == 10 && f.timeouts[9] == 7000 && f.terminal_at == 7000);
    CHECK(strcmp(session.reason, "block_timeout") == 0);
}

static void test_receive_short_final_and_partial_replay(void)
{
    transfer_fixture_t f = {0};
    crack_worker_transfer_state_t state = transfer_state(7, 4);
    crack_worker_transfer_session_t session = {.prepare_ms = 10000, .rx_ms = 1273};
    fixture_frame(&f, 0, "1234", 4, 0x9BE3E0A3U);
    fixture_frame(&f, 1, "123", 3, 0x884863D2U);
    fixture_frame(&f, 1, "xxx", 3, 0x884863D2U);
    fixture_frame(&f, 2, NULL, 0, 0);
    CHECK(crack_worker_transfer_receive(&state, &session, f.payload, sizeof(f.payload), &fixture_ops, &f));
    CHECK(f.writes == 2 && f.crc_updates == 2 && f.checkpoints == 2);
    CHECK(f.stored_size == 7 && memcmp(f.stored, "1234123", 7) == 0);
    CHECK(f.finalizations == 1 && session.duplicates == 1 && state.offset == 7);

    f = (transfer_fixture_t){0};
    state = transfer_state(4, 4);
    fixture_frame(&f, 0, "1234", 4, 0x9BE3E0A3U);
    fixture_frame(&f, 0, "xxxx", 4, 0x9BE3E0A3U);
    f.input_size -= 2;
    CHECK(!crack_worker_transfer_receive(&state, &session, f.payload, sizeof(f.payload), &fixture_ops, &f));
    CHECK(f.writes == 1 && f.crc_updates == 1 && f.checkpoints == 1);
    CHECK(f.finalizations == 0 && f.output[40] == 0x18 && session.payload_got == 2);
    CHECK(state.offset == 4 && state.expected_index == 1);
}

static void test_checkpoint_failure_does_not_commit_replay_metadata(void)
{
    transfer_fixture_t f = {.fail_checkpoint = true};
    crack_worker_transfer_state_t state = transfer_state(4, 4);
    crack_worker_transfer_session_t session = {.prepare_ms = 10000, .rx_ms = 1273};
    fixture_frame(&f, 0, "1234", 4, 0x9BE3E0A3U);
    CHECK(!crack_worker_transfer_receive(&state, &session, f.payload, sizeof(f.payload), &fixture_ops, &f));
    CHECK(f.writes == 1 && f.crc_updates == 1 && f.checkpoints == 1);
    CHECK(f.progress_updates == 0 && f.finalizations == 0);
    CHECK(state.offset == 0 && state.expected_index == 0 && !state.have_last);
    CHECK(f.output[8] == 0x18 && get_le64(f.output + 12) == 0);
}

static void test_receive_boundary_can_and_failed_finalize(void)
{
    for (unsigned stage = 0; stage < 4; ++stage) {
        transfer_fixture_t f = {0};
        crack_worker_transfer_state_t state = transfer_state(stage == 1 ? 8 : 4, 4);
        crack_worker_transfer_session_t session = {.prepare_ms = 10000, .rx_ms = 1273};
        if (stage) fixture_frame(&f, 0, "1234", 4, 0x9BE3E0A3U);
        if (stage == 3) fixture_frame(&f, 1, NULL, 0, 0);
        f.input[f.input_size++] = 0x18;
        CHECK(crack_worker_transfer_receive(&state, &session, f.payload, sizeof(f.payload), &fixture_ops, &f) == (stage == 3));
        CHECK(f.input_pos == f.input_size && f.terminals == 1);
        CHECK(f.finalizations == (stage == 3));
        CHECK(state.finalized == (stage == 3));
        CHECK(f.success == (stage == 3));
    }
    transfer_fixture_t f = {.fail_finalize = true};
    crack_worker_transfer_state_t state = transfer_state(4, 4);
    crack_worker_transfer_session_t session = {.prepare_ms = 10000, .rx_ms = 1273};
    fixture_frame(&f, 0, "1234", 4, 0x9BE3E0A3U);
    fixture_frame(&f, 1, NULL, 0, 0);
    CHECK(!crack_worker_transfer_receive(&state, &session, f.payload, sizeof(f.payload), &fixture_ops, &f));
    CHECK(!state.finalized && f.output[40] == 0x18 && !f.success);
}

static void test_ready_and_capabilities_wire_contract(void)
{
    char line[384];
    CHECK(crack_worker_ready_format(line, sizeof(line), "wordlist", 8, 0x12345678,
                                    4, 0x9BE3E0A3, 1024, 1273, true, 11000));
    CHECK(strcmp(line, "[CRACK/1] READY kind=wordlist size=8 crc32=12345678 offset=4 prefix_crc=9BE3E0A3 bsize=1024 rx_ms=1273 ack_size=32 ack_wait_ms=2000 next_header_ms=7000 prepare_ms=11000 finish_linger_ms=7000\r\n") == 0);
    CHECK(crack_worker_ready_format(line, sizeof(line), "capture", 8, 0, 0, 0,
                                    8192, 3139, false, 38000));
    CHECK(strstr(line, "ack_size=1 prepare_ms=38000\r\n") != NULL);
    CHECK(strstr(crack_worker_capabilities(), "protocol=4 sync=ftb1 ack=byte,frame32 replay=last_block finish=fin32 ") != NULL);
    CHECK(strstr(crack_worker_capabilities(), "start=idempotent") != NULL);
    CHECK(strstr(crack_worker_capabilities(), "health=phase,progress_age_ms") != NULL);
}

static void test_prepare_refusal_truncates_and_resets_resume(const char *dir)
{
    char part[256], meta[256];
    snprintf(part, sizeof(part), "%s/prepare.part", dir);
    snprintf(meta, sizeof(meta), "%s/prepare.part.meta", dir);
    write_file(part, "old-prefix", 10);
    write_file(meta, "stale-checkpoint", 16);
    FILE *file = fopen(part, "r+b");
    CHECK(file != NULL);
    uint64_t offset = 154664961, checkpoint = 154664961;
    uint32_t crc = 0xABCDEF01, prepare_ms = 0;
    CHECK(crack_worker_prepare_resume(&file, part, meta, &offset, &crc,
                                      &checkpoint, &prepare_ms));
    CHECK(offset == 0 && crc == 0 && checkpoint == 0 && prepare_ms == 10000);
    CHECK(ftello(file) == 0 && fgetc(file) == EOF);
    CHECK(access(meta, F_OK) != 0);
    fclose(file);

    write_file(part, "1234", 4);
    file = fopen(part, "r+b");
    CHECK(fseeko(file, 4, SEEK_SET) == 0);
    offset = checkpoint = 4; crc = 0x9BE3E0A3;
    CHECK(crack_worker_prepare_resume(&file, part, meta, &offset, &crc,
                                      &checkpoint, &prepare_ms));
    CHECK(offset == 4 && crc == 0x9BE3E0A3 && checkpoint == 4 && prepare_ms == 11000);
    CHECK(ftello(file) == 4);
    fclose(file);
}

int main(void)
{
#ifdef CRACK_WORKER_PREFLIGHT_SOURCE
    test_receive_allocation_before_ready(true, true);
    test_receive_allocation_before_ready(true, false);
    test_receive_allocation_before_ready(false, true);
    test_receive_allocation_before_ready(false, false);
#endif
    char temp[] = "/tmp/crack-worker-XXXXXX";
    char *dir = mkdtemp(temp);
    if (!dir) {
        fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
        return 2;
    }
    test_ids_and_hex();
    test_start_assignment_classification();
    test_ack32_encoder();
    test_reply_mode_selection();
    test_fingerprint(dir);
    test_verified_marker_requires_exact_file_identity(dir);
    test_reader_and_ranges(dir);
    test_hccapx_validation();
    test_progress_is_committed_only_after_a_line_is_finished();
    test_resume_crc_scan_is_strictly_bounded();
    test_partial_checkpoint_is_strict_and_supports_large_resume(dir);
    test_transfer_data_and_duplicate_state();
    test_transfer_replay_requires_immediate_previous_ack32_block();
    test_transfer_rejects_bad_data_headers();
    test_transfer_short_final_block_and_fin();
    test_transfer_fin_requires_exact_eof_and_cancel_is_explicit();
    test_transfer_prepare_timing();
    test_receive_session_replays_and_fin_quiet_period();
    test_receive_initial_timeout_never_shrinks_rx_budget();
    test_receive_rejects_unavailable_caller_storage_before_read();
    test_receive_lost_nak_and_partial_payload();
    test_third_lost_nak_still_waits_for_header_boundary();
    test_receive_short_final_and_partial_replay();
    test_checkpoint_failure_does_not_commit_replay_metadata();
    test_receive_boundary_can_and_failed_finalize();
    test_ready_and_capabilities_wire_contract();
    test_prepare_refusal_truncates_and_resets_resume(dir);
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    puts("crack_worker_core_test: PASS");
    return 0;
}
