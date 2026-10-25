#include "fs_core.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char fs_base64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_value(char c)
{
    const char *found = strchr(fs_base64_alphabet, c);
    return found ? (int)(found - fs_base64_alphabet) : -1;
}

bool fs_base64_encode(const unsigned char *input, size_t length,
                      char *output, size_t capacity)
{
    if ((!input && length != 0) || !output || length > (SIZE_MAX - 2) / 3)
        return false;
    size_t encoded_length = ((length + 2) / 3) * 4;
    if (encoded_length >= capacity) return false;
    size_t in = 0, out = 0;
    while (in < length) {
        size_t left = length - in;
        unsigned a = input[in++];
        unsigned b = left > 1 ? input[in++] : 0;
        unsigned c = left > 2 ? input[in++] : 0;
        output[out++] = fs_base64_alphabet[a >> 2];
        output[out++] = fs_base64_alphabet[((a & 3U) << 4) | (b >> 4)];
        output[out++] = left > 1 ? fs_base64_alphabet[((b & 15U) << 2) | (c >> 6)] : '=';
        output[out++] = left > 2 ? fs_base64_alphabet[c & 63U] : '=';
    }
    output[out] = '\0';
    return true;
}

static bool suffix_equal_case_insensitive(const char *text, const char *suffix)
{
    size_t text_length = strlen(text), suffix_length = strlen(suffix);
    if (text_length < suffix_length) return false;
    text += text_length - suffix_length;
    for (size_t i = 0; i < suffix_length; ++i) {
        unsigned char a = (unsigned char)text[i];
        unsigned char b = (unsigned char)suffix[i];
        if (a >= 'A' && a <= 'Z') a = (unsigned char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = (unsigned char)(b - 'A' + 'a');
        if (a != b) return false;
    }
    return true;
}

bool fs_path_is_reserved(const char *path)
{
    return path && (suffix_equal_case_insensitive(path, ".fs-part") ||
                    suffix_equal_case_insensitive(path, ".fs-backup"));
}

static fs_path_result_t decode_path64(const char *encoded, unsigned char *out,
                                      size_t capacity, size_t *decoded_length)
{
    if (!encoded || !out || !decoded_length) return FS_PATH_INVALID;
    size_t length = strlen(encoded);
    if (length == 0) return FS_PATH_INVALID;
    if ((length & 3U) != 0) return FS_PATH_BAD_BASE64;
    size_t used = 0;
    for (size_t i = 0; i < length; i += 4) {
        int a = base64_value(encoded[i]);
        int b = base64_value(encoded[i + 1]);
        bool pad2 = encoded[i + 2] == '=';
        bool pad3 = encoded[i + 3] == '=';
        int c = pad2 ? 0 : base64_value(encoded[i + 2]);
        int d = pad3 ? 0 : base64_value(encoded[i + 3]);
        if (a < 0 || b < 0 || c < 0 || d < 0 || (pad2 && !pad3) ||
            ((pad2 || pad3) && i + 4 != length) ||
            (pad2 && (b & 15) != 0) || (pad3 && !pad2 && (c & 3) != 0))
            return FS_PATH_BAD_BASE64;
        size_t bytes = pad2 ? 1 : pad3 ? 2 : 3;
        if (bytes > capacity - used) return FS_PATH_TOO_LONG;
        out[used++] = (unsigned char)((a << 2) | (b >> 4));
        if (bytes > 1) out[used++] = (unsigned char)((b << 4) | (c >> 2));
        if (bytes > 2) out[used++] = (unsigned char)((c << 6) | d);
    }
    *decoded_length = used;
    return FS_PATH_OK;
}

fs_path_result_t fs_resolve_path64(const char *encoded, bool allow_root,
                                   char *full, size_t capacity)
{
    if (!encoded || !full || capacity == 0) return FS_PATH_INVALID;
    if (strcmp(encoded, "-") == 0) {
        if (!allow_root) return FS_PATH_INVALID;
        int written = snprintf(full, capacity, "%s", FS_ROOT);
        return written >= 0 && (size_t)written < capacity ? FS_PATH_OK : FS_PATH_TOO_LONG;
    }
    unsigned char relative[FS_PATH_MAX];
    size_t length = 0;
    fs_path_result_t result = decode_path64(encoded, relative,
                                             sizeof(relative), &length);
    if (result != FS_PATH_OK) return result;
    if (length == 0 || length >= sizeof(relative))
        return FS_PATH_INVALID;
    size_t segment_start = 0;
    for (size_t i = 0; i <= length; ++i) {
        if (i < length && (relative[i] < 0x20U || relative[i] == 0x7FU ||
                           relative[i] == '\\' || relative[i] == 0)) return FS_PATH_INVALID;
        if (i == length || relative[i] == '/') {
            size_t segment_length = i - segment_start;
            if (segment_length == 0 ||
                relative[i - 1] == '.' || relative[i - 1] == ' ' ||
                (segment_length == 1 && relative[segment_start] == '.') ||
                (segment_length == 2 && relative[segment_start] == '.' &&
                 relative[segment_start + 1] == '.')) return FS_PATH_INVALID;
            segment_start = i + 1;
        }
    }
    size_t prefix = strlen(FS_ROOT);
    if (prefix + 1 + length >= capacity) return FS_PATH_TOO_LONG;
    memcpy(full, FS_ROOT, prefix);
    full[prefix] = '/';
    memcpy(full + prefix + 1, relative, length);
    full[prefix + 1 + length] = '\0';
    return FS_PATH_OK;
}

bool fs_parse_upload_identity(const char *size_text, const char *crc_text,
                              uint64_t *size, uint32_t *crc)
{
    if (!size_text || !crc_text || !size || !crc || !*size_text ||
        strlen(crc_text) != 8) return false;
    uint64_t parsed_size = 0;
    for (const char *cursor = size_text; *cursor; ++cursor) {
        if (*cursor < '0' || *cursor > '9') return false;
        unsigned digit = (unsigned)(*cursor - '0');
        if (parsed_size > (UINT32_MAX - digit) / 10U) return false;
        parsed_size = parsed_size * 10U + digit;
    }
    uint32_t parsed_crc = 0;
    for (size_t i = 0; i < 8; ++i) {
        unsigned digit;
        char c = crc_text[i];
        if (c >= '0' && c <= '9') digit = (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f') digit = (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F') digit = (unsigned)(c - 'A' + 10);
        else return false;
        parsed_crc = (parsed_crc << 4) | digit;
    }
    *size = parsed_size;
    *crc = parsed_crc;
    return true;
}

fs_publish_result_t fs_publish_staged(const char *stage, const char *target,
                                      const char *backup, bool replace,
                                      const fs_publish_ops_t *ops)
{
    if (!stage || !target || !backup || !*stage || !*target || !*backup ||
        strcmp(stage, target) == 0 || strcmp(stage, backup) == 0 ||
        strcmp(target, backup) == 0) return FS_PUBLISH_IO_ERROR;
    int (*move)(const char *, const char *) =
        ops && ops->rename_file ? ops->rename_file : rename;
    int (*remove)(const char *) =
        ops && ops->remove_file ? ops->remove_file : unlink;
    struct stat status;
    if (stat(stage, &status) != 0 || !S_ISREG(status.st_mode))
        return FS_PUBLISH_BAD_STAGE;
    bool exists = stat(target, &status) == 0;
    if (exists && !S_ISREG(status.st_mode)) return FS_PUBLISH_BAD_TARGET;
    if (!exists && errno != ENOENT) return FS_PUBLISH_IO_ERROR;
    if (exists && !replace) return FS_PUBLISH_EXISTS;
    if (exists) {
        if (stat(backup, &status) == 0) return FS_PUBLISH_BACKUP_EXISTS;
        if (errno != ENOENT) return FS_PUBLISH_IO_ERROR;
        if (move(target, backup) != 0) return FS_PUBLISH_RENAME_FAILED;
    }
    if (move(stage, target) != 0) {
        if (exists && move(backup, target) != 0)
            return FS_PUBLISH_ROLLBACK_FAILED;
        return FS_PUBLISH_RENAME_FAILED;
    }
    if (exists && remove(backup) != 0) return FS_PUBLISH_BACKUP_LEFT;
    return FS_PUBLISH_OK;
}

fs_recovery_result_t fs_recover_staged(const char *stage, const char *target,
                                       const char *backup,
                                       const fs_publish_ops_t *ops)
{
    if (!stage || !target || !backup || !*stage || !*target || !*backup ||
        strcmp(stage, target) == 0 || strcmp(stage, backup) == 0 ||
        strcmp(target, backup) == 0) return FS_RECOVERY_FAILED;
    int (*move)(const char *, const char *) =
        ops && ops->rename_file ? ops->rename_file : rename;
    int (*remove)(const char *) =
        ops && ops->remove_file ? ops->remove_file : unlink;
    struct stat status;
    bool backup_exists = stat(backup, &status) == 0;
    if (backup_exists && !S_ISREG(status.st_mode)) return FS_RECOVERY_FAILED;
    if (!backup_exists && errno != ENOENT) return FS_RECOVERY_FAILED;
    bool target_exists = stat(target, &status) == 0;
    if (target_exists && !S_ISREG(status.st_mode)) return FS_RECOVERY_FAILED;
    if (!target_exists && errno != ENOENT) return FS_RECOVERY_FAILED;
    bool stage_exists = stat(stage, &status) == 0;
    if (stage_exists && !S_ISREG(status.st_mode)) return FS_RECOVERY_FAILED;
    if (!stage_exists && errno != ENOENT) return FS_RECOVERY_FAILED;

    if (backup_exists && !target_exists) {
        if (move(backup, target) != 0) return FS_RECOVERY_FAILED;
        if (stage_exists && remove(stage) != 0) return FS_RECOVERY_FAILED;
        return FS_RECOVERY_RESTORED_BACKUP;
    }
    if (stage_exists && remove(stage) != 0) return FS_RECOVERY_FAILED;
    if (backup_exists) {
        if (remove(backup) != 0) return FS_RECOVERY_FAILED;
        return FS_RECOVERY_KEPT_TARGET;
    }
    return stage_exists ? FS_RECOVERY_CLEARED_STAGE : FS_RECOVERY_NONE;
}
