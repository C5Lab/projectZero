#include "fs_core.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void check_path(const char *plain, bool allow_root, fs_path_result_t expected)
{
    char encoded[4 * FS_PATH_MAX / 3 + 8];
    char full[FS_PATH_MAX];
    assert(fs_base64_encode((const unsigned char *)plain, strlen(plain),
                            encoded, sizeof(encoded)));
    assert(fs_resolve_path64(encoded, allow_root, full, sizeof(full)) == expected);
    if (expected == FS_PATH_OK) {
        char wanted[FS_PATH_MAX];
        snprintf(wanted, sizeof(wanted), "%s/%s", FS_ROOT, plain);
        assert(strcmp(full, wanted) == 0);
    }
}

static void test_paths(void)
{
    check_path("handshakes/a b.pcap", false, FS_PATH_OK);
    char oem[FS_PATH_MAX];
    assert(fs_resolve_path64("gQ==", false, oem, sizeof(oem)) == FS_PATH_OK);
    assert(memcmp(oem, FS_ROOT "/\x81", strlen(FS_ROOT) + 2) == 0);
    check_path("", false, FS_PATH_INVALID);
    check_path("/etc/passwd", false, FS_PATH_INVALID);
    check_path("foo//bar", false, FS_PATH_INVALID);
    check_path("foo/./bar", false, FS_PATH_INVALID);
    check_path("foo/../bar", false, FS_PATH_INVALID);
    check_path("foo/", false, FS_PATH_INVALID);
    check_path("foo\\bar", false, FS_PATH_INVALID);
    check_path("foo\nbar", false, FS_PATH_INVALID);
    check_path("foo.", false, FS_PATH_INVALID);
    check_path("foo ", false, FS_PATH_INVALID);
    check_path("dir./file", false, FS_PATH_INVALID);
    check_path("dir /file", false, FS_PATH_INVALID);
    assert(fs_path_is_reserved("/sdcard/lab/foo.FS-PART"));
    assert(fs_path_is_reserved("/sdcard/lab/foo.Fs-BaCkUp"));
    assert(!fs_path_is_reserved("/sdcard/lab/foo.part"));
    char full[FS_PATH_MAX];
    assert(fs_resolve_path64("-", true, full, sizeof(full)) == FS_PATH_OK);
    assert(strcmp(full, FS_ROOT) == 0);
    assert(fs_resolve_path64("-", false, full, sizeof(full)) == FS_PATH_INVALID);
    assert(fs_resolve_path64("a===", false, full, sizeof(full)) == FS_PATH_BAD_BASE64);
    assert(fs_resolve_path64("Zm9v*", false, full, sizeof(full)) == FS_PATH_BAD_BASE64);
    assert(fs_resolve_path64("Zg==", false, full, sizeof(full)) == FS_PATH_OK);
    assert(fs_resolve_path64("Zh==", false, full, sizeof(full)) == FS_PATH_BAD_BASE64);
    assert(fs_resolve_path64("Zm9vAA==", false, full, sizeof(full)) == FS_PATH_INVALID);

    char long_path[FS_PATH_MAX];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    check_path(long_path, false, FS_PATH_TOO_LONG);
}

static void test_upload_identity(void)
{
    uint64_t size = 0;
    uint32_t crc = 0;
    assert(fs_parse_upload_identity("18162", "A1b2C3d4", &size, &crc));
    assert(size == 18162 && crc == 0xA1B2C3D4U);
    assert(fs_parse_upload_identity("0", "00000000", &size, &crc));
    assert(size == 0 && crc == 0);
    assert(!fs_parse_upload_identity("-1", "00000000", &size, &crc));
    assert(!fs_parse_upload_identity("1x", "00000000", &size, &crc));
    assert(!fs_parse_upload_identity("4294967296", "00000000", &size, &crc));
    assert(!fs_parse_upload_identity("1", "0000000", &size, &crc));
    assert(!fs_parse_upload_identity("1", "0000000g", &size, &crc));
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
    size_t got = fread(actual, 1, sizeof(actual), file);
    assert(fclose(file) == 0);
    assert(got == strlen(text));
    assert(memcmp(actual, text, got) == 0);
}

static const char *fail_source;
static int fail_second_rename(const char *from, const char *to)
{
    if (strcmp(from, fail_source) == 0) {
        errno = EIO;
        return -1;
    }
    return rename(from, to);
}

static int fail_backup_remove(const char *path)
{
    (void)path;
    errno = EIO;
    return -1;
}

static void test_publish(const char *directory)
{
    char target[256], stage[256], backup[256];
    snprintf(target, sizeof(target), "%s/target.bin", directory);
    snprintf(stage, sizeof(stage), "%s/stage.bin", directory);
    snprintf(backup, sizeof(backup), "%s/backup.bin", directory);
    write_text(target, "original");
    write_text(stage, "new data");

    assert(fs_publish_staged(stage, target, backup, false, NULL) == FS_PUBLISH_EXISTS);
    expect_text(target, "original");
    expect_text(stage, "new data");

    fail_source = stage;
    fs_publish_ops_t failing = {.rename_file = fail_second_rename};
    assert(fs_publish_staged(stage, target, backup, true, &failing) ==
           FS_PUBLISH_RENAME_FAILED);
    expect_text(target, "original");
    expect_text(stage, "new data");
    assert(access(backup, F_OK) != 0);

    fs_publish_ops_t no_cleanup = {.remove_file = fail_backup_remove};
    assert(fs_publish_staged(stage, target, backup, true, &no_cleanup) ==
           FS_PUBLISH_BACKUP_LEFT);
    expect_text(target, "new data");
    expect_text(backup, "original");
    assert(fs_recover_staged(stage, target, backup, NULL) == FS_RECOVERY_KEPT_TARGET);
    assert(access(backup, F_OK) != 0);

    write_text(stage, "third");
    assert(rename(target, backup) == 0);
    assert(fs_recover_staged(stage, target, backup, NULL) == FS_RECOVERY_RESTORED_BACKUP);
    expect_text(target, "new data");
    assert(access(stage, F_OK) != 0);
    assert(access(backup, F_OK) != 0);

    write_text(stage, "new data");

    assert(fs_publish_staged(stage, target, backup, true, NULL) == FS_PUBLISH_OK);
    expect_text(target, "new data");
    assert(access(stage, F_OK) != 0);
    assert(access(backup, F_OK) != 0);
    assert(unlink(target) == 0);
}

int main(void)
{
    test_paths();
    test_upload_identity();
    char directory[] = "/tmp/janos-fs-test-XXXXXX";
    assert(mkdtemp(directory) != NULL);
    test_publish(directory);
    assert(rmdir(directory) == 0);
    puts("PASS: FS/1 path and publish core");
    return 0;
}
