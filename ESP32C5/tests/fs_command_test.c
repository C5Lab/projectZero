#include "fs_command.h"
#include "fs_core.h"
#include "crack_worker_core.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static uint8_t input[4096], output[4096];
static size_t input_length, input_cursor, output_length;
static int64_t mock_clock_us;
static unsigned mounts, get_calls, active_on, active_off, syncs;
static char get_path[FS_PATH_MAX];
static bool emulate_fat_rmdir_errno;

int rmdir(const char *path)
{
    int result = (int)syscall(SYS_rmdir, path);
    if (result != 0 && errno == ENOTEMPTY && emulate_fat_rmdir_errno)
        errno = EACCES; /* FatFS maps FR_DENIED to EACCES for a nonempty dir. */
    return result;
}

int64_t esp_timer_get_time(void)
{
    mock_clock_us += 1000;
    return mock_clock_us;
}

int uart_read_bytes(int uart, void *buffer, size_t length, unsigned ticks)
{
    assert(uart == 0);
    (void)ticks;
    if (input_cursor == input_length) {
        mock_clock_us += 100000;
        return 0;
    }
    size_t available = input_length - input_cursor;
    if (length > available) length = available;
    memcpy(buffer, input + input_cursor, length);
    input_cursor += length;
    return (int)length;
}

int uart_write_bytes(int uart, const void *buffer, size_t length)
{
    assert(uart == 0 && output_length + length <= sizeof(output));
    memcpy(output + output_length, buffer, length);
    output_length += length;
    return (int)length;
}

int uart_flush_input(int uart)
{
    assert(uart == 0);
    /* Scripted bytes are what the browser sends after READY. */
    return 0;
}

int uart_wait_tx_done(int uart, unsigned ticks)
{
    assert(uart == 0);
    (void)ticks;
    return 0;
}

static esp_err_t mount_sd(void)
{
    ++mounts;
    return ESP_OK;
}

static int get_file(const char *path)
{
    ++get_calls;
    snprintf(get_path, sizeof(get_path), "%s", path);
    return 42;
}

static void transfer_active(bool active)
{
    if (active) ++active_on;
    else ++active_off;
}

static uint32_t current_baud(void) { return 115200U; }
static void sync_sd(void) { ++syncs; }

static void put_le32(uint8_t *out, uint32_t value)
{
    out[0] = (uint8_t)value;
    out[1] = (uint8_t)(value >> 8);
    out[2] = (uint8_t)(value >> 16);
    out[3] = (uint8_t)(value >> 24);
}

static void append_frame(uint32_t index, const void *payload, uint32_t length,
                         bool corrupt_crc)
{
    assert(input_length + 16 + length <= sizeof(input));
    uint8_t *frame = input + input_length;
    memcpy(frame, "FTB\x01", 4);
    put_le32(frame + 4, index);
    put_le32(frame + 8, length);
    uint32_t crc = crack_worker_crc32_update(0, payload, length);
    put_le32(frame + 12, crc ^ (corrupt_crc ? 1U : 0U));
    input_length += 16;
    if (length) {
        memcpy(input + input_length, payload, length);
        input_length += length;
    }
}

static void reset_transport(void)
{
    input_length = input_cursor = output_length = 0;
    mock_clock_us = 0;
    active_on = active_off = syncs = 0;
}

static void file_path(char *out, size_t capacity, const char *name)
{
    int length = snprintf(out, capacity, "%s/%s", FS_ROOT, name);
    assert(length > 0 && (size_t)length < capacity);
}

static void write_text(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");
    assert(file != NULL);
    assert(fwrite(text, 1, strlen(text), file) == strlen(text));
    assert(fclose(file) == 0);
}

static void expect_text(const char *path, const char *text)
{
    FILE *file = fopen(path, "rb");
    assert(file != NULL);
    char actual[32] = {0};
    size_t length = fread(actual, 1, sizeof(actual), file);
    assert(fclose(file) == 0);
    assert(length == strlen(text) && memcmp(actual, text, length) == 0);
}

static int captured_command(int argc, char **argv, char *text, size_t capacity)
{
    fflush(stdout);
    int saved_stdout = dup(fileno(stdout));
    FILE *captured = tmpfile();
    assert(saved_stdout >= 0 && captured != NULL);
    assert(dup2(fileno(captured), fileno(stdout)) >= 0);
    int result = fs_command_handle(argc, argv);
    fflush(stdout);
    assert(dup2(saved_stdout, fileno(stdout)) >= 0);
    close(saved_stdout);
    rewind(captured);
    size_t length = fread(text, 1, capacity - 1, captured);
    text[length] = '\0';
    fclose(captured);
    return result;
}

static void assert_vfs_crlf(const char *stdio_text, const char *on_wire_marker)
{
    assert(strchr(stdio_text, '\r') == NULL);
    char wire[4096];
    size_t length = 0;
    for (const char *cursor = stdio_text; *cursor; ++cursor) {
        if (*cursor == '\n') wire[length++] = '\r';
        wire[length++] = *cursor;
        assert(length + 1 < sizeof(wire));
    }
    wire[length] = '\0';
    assert(strstr(wire, "\r\r\n") == NULL);
    assert(strstr(wire, on_wire_marker) != NULL);
}

int main(void)
{
    assert(mkdir(FS_ROOT, 0700) == 0 || errno == EEXIST);
    const fs_command_hooks_t hooks = {
        .mount_sd = mount_sd, .send_file = get_file,
        .transfer_active = transfer_active, .current_baud = current_baud,
        .sync_sd = sync_sd,
    };
    fs_command_init(&hooks);

    char *hello[] = {"fs", "hello"};
    char response[4096];
    assert(captured_command(2, hello, response, sizeof(response)) == 0 && mounts == 0);
    assert(strstr(response, "rm=file_empty_dir") != NULL);
    assert(strstr(response, "cleanup=part_only") != NULL);
    assert_vfs_crlf(response, "[FS/1] END\r\n");

    const char *short_aliases[] = {"FOO~1.FS-", "dir~1/file.bin"};
    for (size_t index = 0; index < 2; ++index) {
        char alias64[96];
        assert(fs_base64_encode((const unsigned char *)short_aliases[index],
                                strlen(short_aliases[index]), alias64,
                                sizeof(alias64)));
        char *alias_put[] = {"fs", "put", alias64, "3", "6BE34445", "replace"};
        unsigned mounts_before = mounts;
        assert(fs_command_handle(6, alias_put) == 1);
        assert(mounts == mounts_before);
    }
    char path64[64];
    assert(fs_base64_encode((const unsigned char *)"target.bin", 10,
                            path64, sizeof(path64)));
    char target[FS_PATH_MAX], stage[FS_PATH_MAX], backup[FS_PATH_MAX];
    file_path(target, sizeof(target), "target.bin");
    file_path(stage, sizeof(stage), "target.bin.fs-part");
    file_path(backup, sizeof(backup), "target.bin.fs-backup");
    write_text(target, "original");

    char oem_file[FS_PATH_MAX];
    file_path(oem_file, sizeof(oem_file), "\x81");
    write_text(oem_file, "x");

    char *get[] = {"fs", "get", path64};
    assert(fs_command_handle(3, get) == 42);
    assert(get_calls == 1 && strcmp(get_path, target) == 0);

    char bad64[64];
    assert(fs_base64_encode((const unsigned char *)"../escape", 9,
                            bad64, sizeof(bad64)));
    char *bad_get[] = {"fs", "get", bad64};
    assert(fs_command_handle(3, bad_get) == 1 && get_calls == 1);

    char *list[] = {"fs", "ls", "-"};
    char listing[2048] = {0};
    assert(captured_command(3, list, listing, sizeof(listing)) == 0);
    assert(strstr(listing, "[FS/1] BEGIN") != NULL);
    assert(strstr(listing, "type=f size=8 name64=dGFyZ2V0LmJpbg==") != NULL);
    assert(strstr(listing, "type=f size=1 name64=gQ==") != NULL);
    assert_vfs_crlf(listing, "[FS/1] END status=ok\r\n");
    assert(strstr(listing, "[FS/1] END status=ok") != NULL);

    char backup64[96];
    assert(fs_base64_encode((const unsigned char *)"target.bin.fs-backup",
                            strlen("target.bin.fs-backup"), backup64, sizeof(backup64)));
    write_text(backup, "saved copy");
    char *get_backup[] = {"fs", "get", backup64};
    assert(fs_command_handle(3, get_backup) == 42);
    expect_text(backup, "saved copy");
    assert(unlink(backup) == 0);

    char reserved64[96];
    assert(fs_base64_encode((const unsigned char *)"target.bin.FS-PART",
                            strlen("target.bin.FS-PART"), reserved64, sizeof(reserved64)));
    char *reserved_put[] = {"fs", "put", reserved64, "3", "6BE34445"};
    assert(fs_command_handle(5, reserved_put) == 1);
    expect_text(target, "original");

    char mixed_backup[FS_PATH_MAX], mixed_backup64[96];
    file_path(mixed_backup, sizeof(mixed_backup), "target.bin.FS-BACKUP");
    write_text(mixed_backup, "saved again");
    assert(fs_base64_encode((const unsigned char *)"target.bin.FS-BACKUP",
                            strlen("target.bin.FS-BACKUP"), mixed_backup64,
                            sizeof(mixed_backup64)));
    char *get_mixed_backup[] = {"fs", "get", mixed_backup64};
    assert(fs_command_handle(3, get_mixed_backup) == 42);
    expect_text(mixed_backup, "saved again");
    assert(unlink(mixed_backup) == 0);

    char *put_existing[] = {"fs", "put", path64, "3", "6BE34445"};
    assert(fs_command_handle(5, put_existing) == 1);
    expect_text(target, "original");

    char *put_replace[] = {"fs", "put", path64, "3", "6BE34445", "replace"};
    assert(rename(target, backup) == 0);
    write_text(stage, "stale partial");
    assert(fs_command_handle(6, put_replace) == 1);
    expect_text(target, "original");
    assert(access(stage, F_OK) != 0 && access(backup, F_OK) != 0);

    write_text(backup, "older");
    write_text(stage, "stale partial");
    assert(fs_command_handle(6, put_replace) == 1);
    expect_text(target, "original");
    assert(access(stage, F_OK) != 0 && access(backup, F_OK) != 0);

    write_text(stage, "stale partial");
    assert(fs_command_handle(6, put_replace) == 1);
    expect_text(target, "original");
    assert(access(stage, F_OK) != 0);

    reset_transport();
    const char new_data[] = "new";
    uint32_t crc = crack_worker_crc32_update(0, new_data, 3);
    char crc_text[9];
    snprintf(crc_text, sizeof(crc_text), "%08X", crc);
    put_replace[4] = crc_text;
    append_frame(0, new_data, 3, false);
    append_frame(1, NULL, 0, false);
    assert(captured_command(6, put_replace, response, sizeof(response)) == 0);
    assert_vfs_crlf(response, "[FS/1] END\r\n\r\n");
    expect_text(target, "new");
    assert(access(stage, F_OK) != 0);
    assert(active_on == 1 && active_off == 1 && syncs == 1);
    assert(output_length == 64 && memcmp(output, "FTA\x01", 4) == 0 &&
           output[8] == 0x06 && memcmp(output + 32, "FTA\x01", 4) == 0 &&
           output[32 + 8] == 0x06);

    reset_transport();
    append_frame(0, new_data, 3, true);
    append_frame(1, NULL, 0, false);
    assert(fs_command_handle(6, put_replace) == 1);
    expect_text(target, "new");
    assert(access(stage, F_OK) != 0);
    assert(active_on == 1 && active_off == 1 && syncs == 0);
    assert(output_length >= 32 && output[8] == 0x15);

    char stage64[96];
    assert(fs_base64_encode((const unsigned char *)"target.bin.fs-part",
                            strlen("target.bin.fs-part"), stage64,
                            sizeof(stage64)));
    char *cleanup_stage[] = {"fs", "cleanup", stage64};
    char *cleanup_target[] = {"fs", "cleanup", path64};
    char *cleanup_backup[] = {"fs", "cleanup", backup64};
    reset_transport();
    write_text(stage, "abandoned upload");
    write_text(backup, "previous version");
    assert(captured_command(3, cleanup_stage, response, sizeof(response)) == 0);
    assert(strstr(response, "[FS/1] CLEANED type=part\n[FS/1] END\n") != NULL);
    assert_vfs_crlf(response, "[FS/1] CLEANED type=part\r\n[FS/1] END\r\n");
    assert(access(stage, F_OK) != 0 && syncs == 1);
    expect_text(target, "new");
    expect_text(backup, "previous version");
    assert(captured_command(3, cleanup_stage, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=not_found") != NULL && syncs == 1);
    assert(captured_command(3, cleanup_target, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=not_stage") != NULL);
    assert(captured_command(3, cleanup_backup, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=not_stage") != NULL);
    expect_text(target, "new");
    expect_text(backup, "previous version");
    assert(unlink(target) == 0);
    write_text(stage, "second abandoned upload");
    reset_transport();
    assert(captured_command(3, cleanup_stage, response, sizeof(response)) == 0);
    assert(access(stage, F_OK) != 0 && access(target, F_OK) != 0 && syncs == 1);
    expect_text(backup, "previous version");
    assert(unlink(backup) == 0);
    write_text(target, "new");

    char *cleanup_root[] = {"fs", "cleanup", "-"};
    char *cleanup_traversal[] = {"fs", "cleanup", bad64};
    char *cleanup_usage[] = {"fs", "cleanup"};
    unsigned cleanup_mounts = mounts;
    assert(captured_command(3, cleanup_root, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=invalid_path") != NULL);
    assert(captured_command(3, cleanup_traversal, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=invalid_path") != NULL);
    assert(captured_command(2, cleanup_usage, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=usage") != NULL);
    assert(mounts == cleanup_mounts);

    char alias_stage64[96];
    assert(fs_base64_encode((const unsigned char *)"FOO~1.fs-part",
                            strlen("FOO~1.fs-part"), alias_stage64,
                            sizeof(alias_stage64)));
    char *cleanup_alias[] = {"fs", "cleanup", alias_stage64};
    assert(captured_command(3, cleanup_alias, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=unsafe_alias") != NULL);
    assert(mounts == cleanup_mounts);

    char stage_dir[FS_PATH_MAX], stage_dir64[96];
    file_path(stage_dir, sizeof(stage_dir), "directory.fs-part");
    assert(mkdir(stage_dir, 0700) == 0);
    assert(fs_base64_encode((const unsigned char *)"directory.fs-part",
                            strlen("directory.fs-part"), stage_dir64,
                            sizeof(stage_dir64)));
    char *cleanup_dir[] = {"fs", "cleanup", stage_dir64};
    assert(captured_command(3, cleanup_dir, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=unsupported_type") != NULL);
    assert(access(stage_dir, F_OK) == 0 && rmdir(stage_dir) == 0);

    char mixed_stage[FS_PATH_MAX], mixed_stage64[96];
    file_path(mixed_stage, sizeof(mixed_stage), "image.jpg.FS-PART");
    write_text(mixed_stage, "partial");
    assert(fs_base64_encode((const unsigned char *)"image.jpg.FS-PART",
                            strlen("image.jpg.FS-PART"), mixed_stage64,
                            sizeof(mixed_stage64)));
    char *cleanup_mixed[] = {"fs", "cleanup", mixed_stage64};
    reset_transport();
    assert(captured_command(3, cleanup_mixed, response, sizeof(response)) == 0);
    assert(access(mixed_stage, F_OK) != 0 && syncs == 1);

    char *rm_root[] = {"fs", "rm", "-"};
    unsigned mounts_before = mounts;
    assert(captured_command(3, rm_root, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=invalid_path") != NULL);
    assert(mounts == mounts_before);
    char *rm_traversal[] = {"fs", "rm", bad64};
    assert(captured_command(3, rm_traversal, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=invalid_path") != NULL);
    assert(mounts == mounts_before);
    char *rm_usage[] = {"fs", "rm"};
    assert(captured_command(2, rm_usage, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=usage") != NULL);

    char *rm_reserved[] = {"fs", "rm", reserved64};
    write_text(stage, "protected stage");
    assert(captured_command(3, rm_reserved, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=reserved_path") != NULL);
    expect_text(stage, "protected stage");
    char *rm_mixed_backup[] = {"fs", "rm", mixed_backup64};
    write_text(mixed_backup, "protected backup");
    assert(captured_command(3, rm_mixed_backup, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=reserved_path") != NULL);
    expect_text(mixed_backup, "protected backup");
    assert(unlink(stage) == 0 && unlink(mixed_backup) == 0);
    for (size_t index = 0; index < 2; ++index) {
        char alias64[96];
        assert(fs_base64_encode((const unsigned char *)short_aliases[index],
                                strlen(short_aliases[index]), alias64,
                                sizeof(alias64)));
        char *rm_alias[] = {"fs", "rm", alias64};
        assert(captured_command(3, rm_alias, response, sizeof(response)) == 1);
        assert(strstr(response, "ERROR code=unsafe_alias") != NULL);
        assert(mounts == mounts_before);
    }

    char *rm_target[] = {"fs", "rm", path64};
    write_text(backup, "older");
    reset_transport();
    assert(captured_command(3, rm_target, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=recovered_retry") != NULL);
    expect_text(target, "new");
    assert(access(backup, F_OK) != 0 && syncs == 0);
    assert(captured_command(3, rm_target, response, sizeof(response)) == 0);
    assert(strstr(response, "[FS/1] DONE type=f\n[FS/1] END\n") != NULL);
    assert_vfs_crlf(response, "[FS/1] DONE type=f\r\n[FS/1] END\r\n");
    assert(access(target, F_OK) != 0 && syncs == 1);

    write_text(backup, "restored");
    reset_transport();
    assert(captured_command(3, rm_target, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=recovered_retry") != NULL);
    expect_text(target, "restored");
    assert(access(backup, F_OK) != 0 && syncs == 0);
    assert(captured_command(3, rm_target, response, sizeof(response)) == 0);
    assert(access(target, F_OK) != 0 && syncs == 1);

    write_text(target, "keep");
    write_text(stage, "stale");
    reset_transport();
    assert(captured_command(3, rm_target, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=recovered_retry") != NULL);
    expect_text(target, "keep");
    assert(access(stage, F_OK) != 0 && syncs == 0);
    assert(captured_command(3, rm_target, response, sizeof(response)) == 0);
    assert(access(target, F_OK) != 0 && syncs == 1);

    write_text(target, "keep");
    assert(mkdir(backup, 0700) == 0);
    reset_transport();
    assert(captured_command(3, rm_target, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=recovery_failed") != NULL);
    expect_text(target, "keep");
    assert(syncs == 0 && rmdir(backup) == 0);
    assert(unlink(target) == 0);

    char *rm_oem[] = {"fs", "rm", "gQ=="};
    reset_transport();
    assert(captured_command(3, rm_oem, response, sizeof(response)) == 0);
    assert(strstr(response, "DONE type=f") != NULL);
    assert(access(oem_file, F_OK) != 0 && syncs == 1);

    char directory[FS_PATH_MAX], child[FS_PATH_MAX];
    file_path(directory, sizeof(directory), "folder");
    file_path(child, sizeof(child), "folder/item.txt");
    assert(mkdir(directory, 0700) == 0);
    write_text(child, "nested");
    char folder64[64], nested64[64];
    assert(fs_base64_encode((const unsigned char *)"folder", 6,
                            folder64, sizeof(folder64)));
    assert(fs_base64_encode((const unsigned char *)"folder/item.txt", 15,
                            nested64, sizeof(nested64)));
    char *rm_folder[] = {"fs", "rm", folder64};
    char *rm_nested[] = {"fs", "rm", nested64};
    reset_transport();
    emulate_fat_rmdir_errno = true;
    assert(captured_command(3, rm_folder, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=dir_not_empty") != NULL);
    assert(access(directory, F_OK) == 0 && syncs == 0);
    assert(captured_command(3, rm_nested, response, sizeof(response)) == 0);
    assert(strstr(response, "DONE type=f") != NULL);
    assert(access(child, F_OK) != 0 && syncs == 1);
    assert(captured_command(3, rm_folder, response, sizeof(response)) == 0);
    assert(strstr(response, "[FS/1] DONE type=d\n[FS/1] END\n") != NULL);
    assert(access(directory, F_OK) != 0 && syncs == 2);
    assert(captured_command(3, rm_folder, response, sizeof(response)) == 1);
    assert(strstr(response, "ERROR code=not_found") != NULL);

    char long_name[161], long_file[FS_PATH_MAX];
    memset(long_name, 'x', 160);
    long_name[160] = '\0';
    file_path(long_file, sizeof(long_file), long_name);
    write_text(long_file, "long name");
    char long64[4 * FS_PATH_MAX / 3 + 8];
    assert(fs_base64_encode((const unsigned char *)long_name, strlen(long_name),
                            long64, sizeof(long64)));
    char *rm_long[] = {"fs", "rm", long64};
    reset_transport();
    assert(captured_command(3, rm_long, response, sizeof(response)) == 0);
    assert(strstr(response, "DONE type=f") != NULL);
    assert(access(long_file, F_OK) != 0 && syncs == 1);

    assert(rmdir(FS_ROOT) == 0);
    puts("PASS: FS/1 command transfer and failure preservation");
    return 0;
}
