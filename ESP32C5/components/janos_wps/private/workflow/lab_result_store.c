/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "lab_result_store.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum {
    LAB_STORE_PATH_MAX = 256,
    LAB_STORE_OBSERVATION_MAX = 131072,
    LAB_STORE_TEXT_MAX = 64,
};

static bool explicit_bssid(const uint8_t bssid[6])
{
    uint8_t any = 0, all_ff = 0xff;
    if (!bssid || (bssid[0] & 1U)) return false;
    for (size_t index = 0; index < 6; ++index) {
        any |= bssid[index];
        all_ff &= bssid[index];
    }
    return any != 0 && all_ff != 0xff;
}

static bool bounded_text(const char *text, size_t capacity)
{
    return text && memchr(text, 0, capacity) != NULL;
}

static bool valid_pin(const char *pin)
{
    if (!pin) return false;
    for (size_t index = 0; index < 8; ++index)
        if (pin[index] < '0' || pin[index] > '9') return false;
    return pin[8] == 0;
}

static bool path_join(char *output, size_t capacity,
                      const char *left, const char *right)
{
    int count = snprintf(output, capacity, "%s/%s", left, right);
    return count >= 0 && (size_t)count < capacity;
}

static bool path_suffix(char *output, size_t capacity,
                        const char *path, const char *suffix)
{
    int count = snprintf(output, capacity, "%s%s", path, suffix);
    return count >= 0 && (size_t)count < capacity;
}

static bool ensure_directory(const char *path)
{
    if (mkdir(path, 0770) == 0 || errno == EEXIST) return true;
    return false;
}

static bool ensure_tree(const char *root, char results[LAB_STORE_PATH_MAX])
{
    char current[LAB_STORE_PATH_MAX];
    size_t length = strlen(root);
    if (length == 0 || length >= sizeof(current)) return false;
    memcpy(current, root, length + 1U);
    for (size_t index = 1; index < length; ++index) {
        if (current[index] != '/') continue;
        current[index] = 0;
        if (current[0] && !ensure_directory(current)) return false;
        current[index] = '/';
    }
    if (!ensure_directory(current)) return false;
    return path_join(results, LAB_STORE_PATH_MAX, root, "results") &&
           ensure_directory(results);
}

static bool write_json_bytes(FILE *file, const uint8_t *bytes, size_t length)
{
    if (!file || (!bytes && length != 0)) return false;
    if (fputc('"', file) == EOF) return false;
    for (size_t index = 0; index < length; ++index) {
        unsigned value = bytes[index];
        if (value == '"' || value == '\\') {
            if (fputc('\\', file) == EOF || fputc((int)value, file) == EOF)
                return false;
        } else if (value >= 0x20U && value <= 0x7eU) {
            if (fputc((int)value, file) == EOF) return false;
        } else if (fprintf(file, "\\u%04x", value) < 0) {
            return false;
        }
    }
    return fputc('"', file) != EOF;
}

static bool write_json_text(FILE *file, const char *text)
{
    return write_json_bytes(file, (const uint8_t *)text, strlen(text));
}

static bool durable_close(FILE *file)
{
    bool ok = fflush(file) == 0;
    if (ok) ok = fsync(fileno(file)) == 0;
    if (fclose(file) != 0) ok = false;
    return ok;
}

/* Observation records are appended to a shared JSONL file.  Keep the stream
 * unbuffered and restore the previous durable length if any write/flush/fsync
 * step fails, otherwise a leading fingerprint can make a later retry look
 * like a duplicate even though no complete JSON record was stored. */
static bool durable_append_close(FILE *file, off_t previous_length,
                                 bool content_ok)
{
    int fd = fileno(file);
    bool durable = content_ok && fd >= 0;
    if (durable && fflush(file) != 0) durable = false;
    if (durable && fsync(fd) != 0) durable = false;

    if (!durable) {
        clearerr(file);
        if (fd >= 0) {
            (void)ftruncate(fd, previous_length);
            (void)fsync(fd);
        }
    }
    if (fclose(file) != 0) durable = false;
    return durable;
}

static void bssid_text(const uint8_t bssid[6], char output[18], char dashed[18])
{
    (void)snprintf(output, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
                   bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    (void)snprintf(dashed, 18, "%02x-%02x-%02x-%02x-%02x-%02x",
                   bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
}

static int default_rename(void *context, const char *from, const char *to)
{
    (void)context;
    return rename(from, to);
}

static int default_remove(void *context, const char *path)
{
    (void)context;
    return remove(path);
}

static lab_store_path_state_t default_path_state(void *context,
                                                 const char *path)
{
    (void)context;
    struct stat info;
    if (path && stat(path, &info) == 0) return LAB_STORE_PATH_EXISTS;
    return errno == ENOENT ? LAB_STORE_PATH_MISSING : LAB_STORE_PATH_ERROR;
}

static const lab_store_file_ops_t default_file_ops = {
    .rename_path = default_rename,
    .remove_path = default_remove,
    .path_state = default_path_state,
};

static lab_store_path_state_t path_state(const lab_store_file_ops_t *ops,
                                         void *context, const char *path)
{
    return ops->path_state ? ops->path_state(context, path) :
                             default_path_state(NULL, path);
}

static bool remove_if_present(const lab_store_file_ops_t *ops, void *context,
                              const char *path)
{
    lab_store_path_state_t state = path_state(ops, context, path);
    if (state == LAB_STORE_PATH_ERROR) return false;
    if (state == LAB_STORE_PATH_MISSING) return true;
    return ops->remove_path(context, path) == 0;
}

/* A denied or failed commit must not leave a durable credential-bearing temp
 * file.  Truncate and fsync before unlink so even an unlink failure leaves no
 * PIN/key payload behind; report failure rather than claiming cancellation. */
static bool discard_sensitive_temp(const lab_store_file_ops_t *ops,
                                   void *context, const char *path)
{
    FILE *file = fopen(path, "wb");
    if (!file) return path_state(ops, context, path) == LAB_STORE_PATH_MISSING;
    if (!durable_close(file)) return false;
    return remove_if_present(ops, context, path);
}

static bool recover_interrupted_replace(
    const char *final_path, const char *backup,
    const lab_store_file_ops_t *ops, void *context)
{
    lab_store_path_state_t backup_state = path_state(ops, context, backup);
    if (backup_state == LAB_STORE_PATH_ERROR) return false;
    if (backup_state == LAB_STORE_PATH_MISSING) return true;
    lab_store_path_state_t final_state = path_state(ops, context, final_path);
    if (final_state == LAB_STORE_PATH_ERROR) return false;
    if (final_state == LAB_STORE_PATH_EXISTS)
        return remove_if_present(ops, context, backup);
    return ops->rename_path(context, backup, final_path) == 0;
}

static lab_store_status_t replace_recoverably(
    const char *temporary, const char *final_path,
    const lab_store_file_ops_t *ops, void *context)
{
    char backup[LAB_STORE_PATH_MAX];
    if (!path_suffix(backup, sizeof(backup), final_path, ".bak"))
        return LAB_STORE_IO_ERROR;
    if (!recover_interrupted_replace(final_path, backup, ops, context) ||
        !remove_if_present(ops, context, backup))
        return LAB_STORE_IO_ERROR;
    lab_store_path_state_t final_state = path_state(ops, context, final_path);
    if (final_state == LAB_STORE_PATH_ERROR) return LAB_STORE_IO_ERROR;
    bool had_previous = final_state == LAB_STORE_PATH_EXISTS;
    if (had_previous && ops->rename_path(context, final_path, backup) != 0)
        return LAB_STORE_IO_ERROR;
    if (ops->rename_path(context, temporary, final_path) != 0) {
        lab_store_path_state_t after_failure =
            path_state(ops, context, final_path);
        if (had_previous && after_failure == LAB_STORE_PATH_MISSING)
            (void)ops->rename_path(context, backup, final_path);
        return LAB_STORE_IO_ERROR;
    }
    if (had_previous && !remove_if_present(ops, context, backup))
        return LAB_STORE_IO_ERROR;
    return LAB_STORE_OK;
}

lab_store_status_t lab_result_store_success(
    const char *root, const lab_result_record_t *record)
{
    return lab_result_store_success_gated(root, record, NULL, NULL, NULL, NULL);
}

lab_store_status_t lab_result_store_success_gated(
    const char *root, const lab_result_record_t *record,
    lab_store_commit_gate_fn commit_gate, void *commit_context,
    const lab_store_file_ops_t *file_ops, void *file_context)
{
    if (!root || !record || !record->authenticated_m7 ||
        !explicit_bssid(record->bssid) || !valid_pin(record->pin) ||
        !record->network_key || record->network_key_len == 0 ||
        record->network_key_len > 64U ||
        !bounded_text(record->ssid ? record->ssid : "", 33U) ||
        !bounded_text(record->recovery_source, 33U) ||
        !bounded_text(record->manufacturer ? record->manufacturer : "", 33U) ||
        !bounded_text(record->model_name ? record->model_name : "", 33U) ||
        !bounded_text(record->model_number ? record->model_number : "", 33U) ||
        !bounded_text(record->device_name ? record->device_name : "", 33U))
        return LAB_STORE_INVALID;

    char results[LAB_STORE_PATH_MAX];
    if (!ensure_tree(root, results)) return LAB_STORE_IO_ERROR;
    char bssid[18], dashed[18], name[48];
    bssid_text(record->bssid, bssid, dashed);
    if (snprintf(name, sizeof(name), "wps_%s.json", dashed) < 0)
        return LAB_STORE_IO_ERROR;
    char final_path[LAB_STORE_PATH_MAX], temp_path[LAB_STORE_PATH_MAX];
    if (!path_join(final_path, sizeof(final_path), results, name) ||
        !path_suffix(temp_path, sizeof(temp_path), final_path, ".tmp"))
        return LAB_STORE_IO_ERROR;

    const lab_store_file_ops_t *ops = file_ops ? file_ops : &default_file_ops;
    if (!ops->rename_path || !ops->remove_path) return LAB_STORE_INVALID;
    FILE *file = fopen(temp_path, "wb");
    if (!file) return LAB_STORE_IO_ERROR;
    bool ok = fprintf(file,
        "{\"schema\":1,\"operation_id\":%u,\"bssid\":\"%s\"," 
        "\"ssid\":", (unsigned)record->operation_id, bssid) >= 0;
    ok = ok && write_json_text(file, record->ssid ? record->ssid : "");
    ok = ok && fputs(",\"recovery_source\":", file) >= 0;
    ok = ok && write_json_text(file, record->recovery_source);
    ok = ok && fputs(",\"pin\":", file) >= 0;
    ok = ok && write_json_text(file, record->pin);
    ok = ok && fputs(",\"network_key\":", file) >= 0;
    ok = ok && write_json_bytes(file, record->network_key,
                                record->network_key_len);
    const char *identity_values[] = {
        record->manufacturer, record->model_name,
        record->model_number, record->device_name,
    };
    const char *identity_names[] = {
        "manufacturer", "model_name", "model_number", "device_name",
    };
    for (size_t index = 0; ok && index < 4; ++index) {
        ok = fprintf(file, ",\"%s\":", identity_names[index]) >= 0;
        ok = ok && write_json_text(file, identity_values[index] ?
                                             identity_values[index] : "");
    }
    ok = ok && fputs(",\"authenticated_m7\":true}\n", file) >= 0;
    bool durable = durable_close(file);
    if (!ok || !durable) {
        (void)discard_sensitive_temp(ops, file_context, temp_path);
        return LAB_STORE_IO_ERROR;
    }
    if (commit_gate && !commit_gate(commit_context, record->operation_id)) {
        return discard_sensitive_temp(ops, file_context, temp_path) ?
            LAB_STORE_CANCELLED : LAB_STORE_IO_ERROR;
    }
    lab_store_status_t promoted = replace_recoverably(
        temp_path, final_path, ops, file_context);
    if (promoted != LAB_STORE_OK) {
        (void)discard_sensitive_temp(ops, file_context, temp_path);
        return promoted;
    }
    return LAB_STORE_OK;
}

static uint32_t fingerprint(const lab_device_observation_t *item)
{
    uint32_t hash = 2166136261U;
    const char *texts[] = {item->ssid, item->stage, item->reason,
                           item->manufacturer, item->model_name,
                           item->device_name};
    for (size_t index = 0; index < 6; ++index)
        hash = (hash ^ item->bssid[index]) * 16777619U;
    for (size_t field = 0; field < sizeof(texts) / sizeof(texts[0]); ++field) {
        const unsigned char *p = (const unsigned char *)(texts[field] ? texts[field] : "");
        do { hash = (hash ^ *p) * 16777619U; } while (*p++ != 0);
    }
    return hash;
}

lab_store_status_t lab_result_store_observation(
    const char *root, const lab_device_observation_t *item)
{
    if (!root || !item || !explicit_bssid(item->bssid) ||
        !bounded_text(item->ssid ? item->ssid : "", 33U) ||
        !bounded_text(item->stage ? item->stage : "", LAB_STORE_TEXT_MAX) ||
        !bounded_text(item->reason ? item->reason : "", LAB_STORE_TEXT_MAX) ||
        !bounded_text(item->manufacturer ? item->manufacturer : "", LAB_STORE_TEXT_MAX) ||
        !bounded_text(item->model_name ? item->model_name : "", LAB_STORE_TEXT_MAX) ||
        !bounded_text(item->device_name ? item->device_name : "", LAB_STORE_TEXT_MAX))
        return LAB_STORE_INVALID;
    char results[LAB_STORE_PATH_MAX], path[LAB_STORE_PATH_MAX];
    if (!ensure_tree(root, results) ||
        !path_join(path, sizeof(path), root, "unknown_devices.jsonl"))
        return LAB_STORE_IO_ERROR;
    uint32_t id = fingerprint(item);
    char marker[32];
    (void)snprintf(marker, sizeof(marker),
                   "\"fingerprint\":\"%08" PRIx32 "\"", id);
    off_t append_offset = 0;
    FILE *existing = fopen(path, "rb");
    if (existing) {
        if (fseek(existing, 0, SEEK_END) != 0) {
            (void)fclose(existing);
            return LAB_STORE_IO_ERROR;
        }
        long size = ftell(existing);
        if (size < 0) {
            (void)fclose(existing);
            return LAB_STORE_IO_ERROR;
        }
        if ((unsigned long)size >= LAB_STORE_OBSERVATION_MAX) {
            (void)fclose(existing);
            return LAB_STORE_FULL;
        }
        append_offset = (off_t)size;
        if ((long)append_offset != size) {
            (void)fclose(existing);
            return LAB_STORE_IO_ERROR;
        }
        rewind(existing);
        char line[768];
        while (fgets(line, sizeof(line), existing)) {
            if (strstr(line, marker)) {
                (void)fclose(existing);
                return LAB_STORE_DUPLICATE;
            }
        }
        bool read_error = ferror(existing) != 0;
        bool close_error = fclose(existing) != 0;
        if (read_error || close_error) return LAB_STORE_IO_ERROR;
    }
    FILE *file = fopen(path, "ab");
    if (!file) return LAB_STORE_IO_ERROR;
    if (setvbuf(file, NULL, _IONBF, 0) != 0) {
        (void)fclose(file);
        return LAB_STORE_IO_ERROR;
    }
    char bssid[18], dashed[18];
    bssid_text(item->bssid, bssid, dashed);
    bool ok = fprintf(file,
        "{\"schema\":1,\"fingerprint\":\"%08" PRIx32 "\",\"bssid\":\"%s\"," 
        "\"oui\":\"%02x:%02x:%02x\",\"ssid\":", id, bssid,
        item->bssid[0], item->bssid[1], item->bssid[2]) >= 0;
    const char *values[] = {item->ssid, item->stage, item->reason,
                            item->manufacturer, item->model_name,
                            item->device_name};
    const char *names[] = {NULL, "stage", "reason", "manufacturer",
                           "model_name", "device_name"};
    ok = ok && write_json_text(file, values[0] ? values[0] : "");
    for (size_t index = 1; ok && index < 6; ++index) {
        ok = fprintf(file, ",\"%s\":", names[index]) >= 0;
        ok = ok && write_json_text(file, values[index] ? values[index] : "");
    }
    ok = ok && fputs("}\n", file) >= 0;
    bool durable = durable_append_close(file, append_offset, ok);
    if (!ok || !durable) return LAB_STORE_IO_ERROR;
    return LAB_STORE_OK;
}

const char *lab_store_status_name(lab_store_status_t status)
{
    switch (status) {
    case LAB_STORE_OK: return "ok";
    case LAB_STORE_DUPLICATE: return "duplicate";
    case LAB_STORE_INVALID: return "invalid";
    case LAB_STORE_FULL: return "full";
    case LAB_STORE_CANCELLED: return "cancelled";
    default: return "io_error";
    }
}
