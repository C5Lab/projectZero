#define _POSIX_C_SOURCE 200809L
#include "artifact_inventory_core.h"

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AI_CACHE_TAG UINT32_C(0x41494331)
#define AI_RECORD_SIZE 393U
#define AI_RECORDS_MAX 16U
#define AI_CHUNK_SIZE 4096U
#define AI_PROGRESS_INTERVAL 65536U

static uint32_t crc_update(uint32_t crc, const unsigned char *bytes, size_t count);
static const char *const validations[] = {"unknown", "valid", "invalid"};
static const char *const reasons[] = {"ok", "empty", "invalid_length", "truncated_record", "invalid_field",
    "unsupported_format", "unsupported_validator", "io_error", "changed", "busy", "cancelled",
    "timeout", "limit_reached", "cache_stale"};

static uint32_t cache_check(const ai_entry_t *entry)
{
    uint32_t crc = crc_update(UINT32_MAX, (const unsigned char *)&entry->metadata, sizeof(entry->metadata));
    crc = crc_update(crc, (const unsigned char *)&entry->crc32, sizeof(entry->crc32));
    crc = crc_update(crc, &entry->validation, 1);
    return crc_update(crc, &entry->reason, 1) ^ UINT32_MAX;
}

static bool cache_valid(const ai_entry_t *entry)
{
    return entry->cache_tag == AI_CACHE_TAG && entry->validation < sizeof(validations)/sizeof(*validations) &&
           entry->reason < sizeof(reasons)/sizeof(*reasons) && entry->cache_check == cache_check(entry);
}

static size_t bounded_length(const char *value, size_t maximum)
{
    size_t n = 0;
    if (!value) return maximum + 1;
    while (n <= maximum && value[n]) ++n;
    return n;
}

static bool valid_id(const char *id)
{
    size_t n = bounded_length(id, AI_ID_MAX);
    if (!n || n > AI_ID_MAX) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)id[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
    }
    return true;
}

static bool decimal(const char *text, uint32_t maximum, uint32_t *value)
{
    size_t n = bounded_length(text, 10);
    uint32_t parsed = 0;
    if (!n || n > 10) return false;
    for (size_t i = 0; i < n; ++i) {
        if (text[i] < '0' || text[i] > '9') return false;
        uint32_t digit = (uint32_t)(text[i] - '0');
        if (digit > maximum || parsed > (maximum - digit) / 10) return false;
        parsed = parsed * 10 + digit;
    }
    *value = parsed;
    return true;
}

bool ai_parse_command(int argc, const char *const *argv, ai_request_t *request)
{
    if (!request || !argv || argc < 2 || argc > 6) return false;
    for (int i = 0; i < argc; ++i)
        if (!argv[i] || bounded_length(argv[i], 32) > 32) return false;
    if (strcmp(argv[0], "artifact_inventory")) return false;
    memset(request, 0, sizeof(*request));
    if (argc == 2 && !strcmp(argv[1], "capabilities")) {
        request->operation = AI_CAPABILITIES;
        strcpy(request->id, "0");
        return true;
    }
    if (argc < 3 || !valid_id(argv[2])) return false;
    strcpy(request->id, argv[2]);
    if (argc == 3 && !strcmp(argv[1], "cancel")) {
        request->operation = AI_CANCEL;
        return true;
    }
    if (argc == 6 && !strcmp(argv[1], "list")) {
        request->operation = AI_LIST;
        if (!strcmp(argv[3], "handshakes")) request->scope = AI_HANDSHAKES;
        else if (!strcmp(argv[3], "pcaps")) request->scope = AI_PCAPS;
        else return false;
        return decimal(argv[4], AI_ENTRIES_MAX, &request->cursor) &&
               decimal(argv[5], AI_PAGE_MAX, &request->limit) && request->limit > 0;
    }
    if (argc == 5 && !strcmp(argv[1], "inspect")) {
        request->operation = AI_INSPECT;
        return decimal(argv[3], UINT32_MAX, &request->snapshot) && request->snapshot > 0 &&
               decimal(argv[4], AI_ENTRIES_MAX, &request->entry) && request->entry > 0;
    }
    return false;
}

bool ai_inventory_init(ai_inventory_t *inventory, const char *root)
{
    if (!inventory || !root || !root[0] || bounded_length(root, sizeof(inventory->root) - 1) >= sizeof(inventory->root)) return false;
    memset(inventory, 0, sizeof(*inventory));
    strcpy(inventory->root, root);
    return true;
}

static void line(const ai_hooks_t *hooks, const char *format, ...)
{
    char buffer[AI_LINE_MAX];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    if (n >= 0 && (size_t)n < sizeof(buffer)) hooks->emit(hooks->user, buffer);
}

static void end(const ai_hooks_t *hooks, const ai_request_t *request, uint32_t snapshot,
                const char *reason, uint32_t next, bool more, uint32_t count)
{
    const char *status = !strcmp(reason, "ok") ? "ok" :
                         !strcmp(reason, "cancelled") ? "cancelled" : "error";
    line(hooks, "[ARTIFACT/1] END req=%s snapshot=%" PRIu32 " status=%s reason=%s next=%" PRIu32 " more=%u count=%" PRIu32,
         request->id, snapshot, status, reason, next, more ? 1U : 0U, count);
}

static const char *scope_name(ai_scope_t scope)
{
    return scope == AI_HANDSHAKES ? "handshakes" : scope == AI_PCAPS ? "pcaps" : NULL;
}

static bool path_for(const ai_inventory_t *inventory, const char *name, char *path)
{
    const char *scope = scope_name(inventory->scope);
    if (!scope) return false;
    if (name && (!name[0] || !strcmp(name, ".") || !strcmp(name, "..") ||
                 strchr(name, '/') || strchr(name, '\\') || bounded_length(name, AI_NAME_MAX) > AI_NAME_MAX)) return false;
    int n = snprintf(path, AI_PATH_MAX, "%s/%s%s%s", inventory->root, scope, name ? "/" : "", name ? name : "");
    return n > 0 && n < (int)AI_PATH_MAX;
}

static bool file_stat(const char *path, struct stat *st)
{
#ifdef ESP_PLATFORM
    /* The device uses FatFs, which has no symlinks. */
    return stat(path, st) == 0;
#else
    return lstat(path, st) == 0;
#endif
}

static ai_metadata_t metadata(const struct stat *st)
{
    ai_metadata_t result = {0};
    result.size = (uint64_t)st->st_size;
    result.mtime = st->st_mtime < 0 ? 0 : (uint64_t)st->st_mtime;
    result.ctime = st->st_ctime < 0 ? 0 : (uint64_t)st->st_ctime;
    result.device = (uint64_t)st->st_dev;
    result.inode = (uint64_t)st->st_ino;
#if defined(__linux__) && !defined(ESP_PLATFORM)
    result.mtime_ns = (uint32_t)st->st_mtim.tv_nsec;
    result.ctime_ns = (uint32_t)st->st_ctim.tv_nsec;
#endif
    return result;
}

static bool same_metadata(const ai_metadata_t *a, const ai_metadata_t *b)
{
    return a->size == b->size && a->mtime == b->mtime && a->ctime == b->ctime &&
           a->device == b->device && a->inode == b->inode &&
           a->mtime_ns == b->mtime_ns && a->ctime_ns == b->ctime_ns;
}

static bool matches(const char *path, const ai_metadata_t *expected)
{
    struct stat st;
    if (!file_stat(path, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) return false;
    ai_metadata_t actual = metadata(&st);
    return same_metadata(expected, &actual);
}

static const char *interrupted(const ai_hooks_t *hooks, uint64_t started)
{
    if (hooks->cancelled && hooks->cancelled(hooks->user)) return "cancelled";
    if (hooks->now_ms && hooks->now_ms(hooks->user) - started >= AI_TIMEOUT_MS) return "timeout";
    return NULL;
}

static void cooperate(const ai_hooks_t *hooks)
{
    if (hooks->yield) hooks->yield(hooks->user);
}

static int compare_entries(const void *a, const void *b)
{
    return strcmp(((const ai_entry_t *)a)->name, ((const ai_entry_t *)b)->name);
}

static const char *scan(ai_inventory_t *inventory, const ai_request_t *request, const ai_hooks_t *hooks)
{
    if (inventory->snapshot == UINT32_MAX) return "limit_reached";
    ++inventory->snapshot;
    inventory->count = 0;
    inventory->limited = false;
    inventory->scope = request->scope;
    char directory[AI_PATH_MAX];
    struct stat st;
    if (!path_for(inventory, NULL, directory) || !file_stat(directory, &st) || !S_ISDIR(st.st_mode)) return "io_error";
    DIR *dir = opendir(directory);
    if (!dir) return "io_error";
    const char *reason = NULL;
    uint64_t started = hooks->now_ms ? hooks->now_ms(hooks->user) : 0;
    unsigned visited = 0;
    for (;;) {
        if ((reason = interrupted(hooks, started)) != NULL) break;
        errno = 0;
        struct dirent *item = readdir(dir);
        if (!item) { if (errno) reason = "io_error"; break; }
        if (++visited > AI_SCAN_MAX) { inventory->limited = true; break; }
        if (visited % 16 == 0) cooperate(hooks);
        char path[AI_PATH_MAX];
        if (!path_for(inventory, item->d_name, path)) continue;
        if (!file_stat(path, &st)) { reason = "io_error"; break; }
        if (!S_ISREG(st.st_mode) || st.st_size < 0) continue;
        if (inventory->count == AI_ENTRIES_MAX) { inventory->limited = true; break; }
        ai_entry_t *entry = &inventory->entries[inventory->count++];
        memset(entry, 0, sizeof(*entry));
        strcpy(entry->name, item->d_name);
        entry->metadata = metadata(&st);
    }
    if (closedir(dir) != 0 && !reason) reason = "io_error";
    if (reason) { inventory->count = 0; return reason; }
    qsort(inventory->entries, inventory->count, sizeof(*inventory->entries), compare_entries);
    return NULL;
}

static const char *format_of(const char *name)
{
    const char *extension = strrchr(name, '.');
    if (extension && !strcmp(extension, ".hccapx")) return "hccapx";
    if (extension && !strcmp(extension, ".pcap")) return "pcap";
    return "unknown";
}

static void list(ai_inventory_t *inventory, const ai_request_t *request, const ai_hooks_t *hooks)
{
    const char *reason = NULL;
    if (!request->cursor) reason = scan(inventory, request, hooks);
    else if (!inventory->snapshot || inventory->scope != request->scope) reason = "cache_stale";
    if (!reason && request->cursor > inventory->count) reason = "invalid_field";
    if (reason) { end(hooks, request, inventory->snapshot, reason, 0, false, 0); return; }
    line(hooks, "[ARTIFACT/1] BEGIN req=%s snapshot=%" PRIu32 " scope=%s cursor=%" PRIu32 " limit=%" PRIu32,
         request->id, inventory->snapshot, scope_name(inventory->scope), request->cursor, request->limit);
    uint32_t stop = request->cursor + request->limit;
    if (stop > inventory->count) stop = inventory->count;
    for (uint32_t i = request->cursor; i < stop; ++i) {
        const ai_entry_t *entry = &inventory->entries[i];
        char hex[AI_NAME_MAX * 2 + 1], path[AI_PATH_MAX];
        static const char digits[] = "0123456789abcdef";
        size_t length = strlen(entry->name);
        for (size_t n = 0; n < length; ++n) {
            unsigned char c = (unsigned char)entry->name[n];
            hex[n * 2] = digits[c >> 4]; hex[n * 2 + 1] = digits[c & 15];
        }
        hex[length * 2] = 0;
        bool cached = cache_valid(entry) &&
                      path_for(inventory, entry->name, path) && matches(path, &entry->metadata);
        line(hooks, "[ARTIFACT/1] ITEM req=%s snapshot=%" PRIu32 " entry=%" PRIu32 " name_hex=%s size=%" PRIu64 " mtime=%" PRIu64 " format=%s validation=%s reason=%s",
             request->id, inventory->snapshot, i + 1, hex, entry->metadata.size, entry->metadata.mtime,
             format_of(entry->name), cached ? validations[entry->validation] : "unknown", cached ? reasons[entry->reason] : "cache_stale");
    }
    end(hooks, request, inventory->snapshot, inventory->limited ? "limit_reached" : "ok", stop,
        stop < inventory->count, stop - request->cursor);
}

static uint32_t crc_update(uint32_t crc, const unsigned char *bytes, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        crc ^= bytes[i];
        for (unsigned bit = 0; bit < 8; ++bit) crc = (crc >> 1) ^ ((crc & 1) ? UINT32_C(0xedb88320) : 0);
    }
    return crc;
}

static const char *validate_record(const unsigned char *record)
{
    if (memcmp(record, "HCPX", 4) || record[4] != 4 || record[5] || record[6] || record[7]) return "unsupported_format";
    unsigned eapol = record[135] | ((unsigned)record[136] << 8);
    unsigned declared = ((unsigned)record[139] << 8) | record[140];
    if ((record[8] & 0x7f) > 5 || !record[9] || record[9] > 32 ||
        record[42] < 1 || record[42] > 2 || eapol < 99 || eapol > 256 ||
        record[138] != 3 || declared + 4 != eapol || (record[143] & 7) != record[42]) return "invalid_field";
    return NULL;
}

static void inspect(ai_inventory_t *inventory, const ai_request_t *request, const ai_hooks_t *hooks)
{
    const char *reason = "cache_stale", *validation = "unknown";
    char path[AI_PATH_MAX], crc_text[9] = "none";
    uint64_t processed = 0, started = hooks->now_ms ? hooks->now_ms(hooks->user) : 0;
    uint32_t crc = UINT32_MAX;
    ai_entry_t *entry = NULL;
    FILE *file = NULL;
    line(hooks, "[ARTIFACT/1] ACCEPTED req=%s snapshot=%" PRIu32 " entry=%" PRIu32,
         request->id, request->snapshot, request->entry);
    const char *stop = interrupted(hooks, started);
    if (stop) { reason = stop; goto done; }
    if (request->snapshot != inventory->snapshot || request->entry > inventory->count) goto done;
    entry = &inventory->entries[request->entry - 1];
    entry->cache_tag = 0;
    if (!path_for(inventory, entry->name, path)) { reason = "invalid_field"; goto done; }
    if (!matches(path, &entry->metadata)) { reason = "changed"; goto done; }
    if (entry->metadata.size > AI_INSPECT_MAX) { reason = "limit_reached"; goto done; }
    stop = interrupted(hooks, started);
    if (stop) { reason = stop; goto done; }
    file = fopen(path, "rb");
    if (!file) { reason = "io_error"; goto done; }
    struct stat opened;
    if (fstat(fileno(file), &opened) != 0) { reason = "io_error"; goto done; }
    ai_metadata_t opened_metadata = metadata(&opened);
    if (!S_ISREG(opened.st_mode) || !same_metadata(&opened_metadata, &entry->metadata)) { reason = "changed"; goto done; }
    bool hccapx = !strcmp(format_of(entry->name), "hccapx");
    reason = hccapx ? "ok" : !strcmp(format_of(entry->name), "pcap") ? "unsupported_validator" : "unsupported_format";
    if (hccapx && !entry->metadata.size) reason = "empty";
    else if (hccapx && entry->metadata.size < AI_RECORD_SIZE) reason = "invalid_length";
    else if (hccapx && entry->metadata.size % AI_RECORD_SIZE) reason = "truncated_record";
    else if (hccapx && entry->metadata.size / AI_RECORD_SIZE > AI_RECORDS_MAX)
        reason = "limit_reached";
    unsigned char buffer[AI_CHUNK_SIZE], record[AI_RECORD_SIZE];
    size_t record_used = 0;
    while (processed < entry->metadata.size) {
        stop = interrupted(hooks, started);
        if (stop) { reason = stop; goto done; }
        size_t take = entry->metadata.size - processed > sizeof(buffer) ? sizeof(buffer) : (size_t)(entry->metadata.size - processed);
        size_t got = fread(buffer, 1, take, file);
        if (got != take) { reason = ferror(file) ? "io_error" : "changed"; goto done; }
        crc = crc_update(crc, buffer, got);
        if (hccapx && !strcmp(reason, "ok")) {
            for (size_t i = 0; i < got; ++i) {
                record[record_used++] = buffer[i];
                if (record_used == sizeof(record)) {
                    const char *invalid = validate_record(record);
                    record_used = 0;
                    if (invalid) { reason = invalid; break; }
                }
            }
        }
        processed += got;
        if (processed == entry->metadata.size || processed % AI_PROGRESS_INTERVAL == 0)
            line(hooks, "[ARTIFACT/1] PROGRESS req=%s snapshot=%" PRIu32 " entry=%" PRIu32 " bytes=%" PRIu64 " total=%" PRIu64,
                 request->id, request->snapshot, request->entry, processed, entry->metadata.size);
        cooperate(hooks);
    }
    stop = interrupted(hooks, started);
    if (stop) { reason = stop; goto done; }
    if (fstat(fileno(file), &opened) != 0) { reason = "io_error"; goto done; }
    opened_metadata = metadata(&opened);
    if (!same_metadata(&opened_metadata, &entry->metadata) || !matches(path, &entry->metadata)) { reason = "changed"; goto done; }
    if (fclose(file) != 0) { file = NULL; reason = "io_error"; goto done; }
    file = NULL;
    snprintf(crc_text, sizeof(crc_text), "%08" PRIx32, crc ^ UINT32_MAX);
    validation = !strcmp(reason, "ok") ? "valid" :
                 !strcmp(reason, "unsupported_format") || !strcmp(reason, "unsupported_validator") ? "unknown" : "invalid";
done:
    if (file) fclose(file);
    if (hooks->finishing) hooks->finishing(hooks->user);
    stop = interrupted(hooks, started);
    if (stop && strcmp(reason, "cancelled") && strcmp(reason, "timeout")) {
        reason = stop;
        validation = "unknown";
        strcpy(crc_text, "none");
    }
    if (entry && strcmp(crc_text, "none")) {
        entry->crc32 = crc ^ UINT32_MAX;
        entry->validation = !strcmp(validation, "valid") ? 1 : !strcmp(validation, "invalid") ? 2 : 0;
        for (size_t i = 0; i < sizeof(reasons)/sizeof(*reasons); ++i)
            if (!strcmp(reason, reasons[i])) { entry->reason = (uint8_t)i; break; }
        entry->cache_check = cache_check(entry);
        entry->cache_tag = AI_CACHE_TAG;
    }
    line(hooks, "[ARTIFACT/1] RESULT req=%s snapshot=%" PRIu32 " entry=%" PRIu32 " validation=%s reason=%s crc32=%s bytes=%" PRIu64,
         request->id, request->snapshot, request->entry, validation, reason, crc_text, processed);
    const char *terminal = !strcmp(crc_text, "none") ? reason : "ok";
    end(hooks, request, request->snapshot, terminal, 0, false, 0);
}

bool ai_run(ai_inventory_t *inventory, const ai_request_t *request, const ai_hooks_t *hooks)
{
    if (!request || !hooks || !hooks->emit) return false;
    if (request->operation == AI_CAPABILITIES) {
        line(hooks, "[ARTIFACT/1] CAPABILITIES req=0 snapshot=0 artifact_inventory=1 scopes=handshakes,pcaps page_max=32 entries_max=256 name_max=255 line_max=1024 inspect_max=16777216 validator=hccapx_v1");
        end(hooks, request, 0, "ok", 0, false, 0);
    } else if (!inventory) return false;
    else if (request->operation == AI_LIST) list(inventory, request, hooks);
    else if (request->operation == AI_INSPECT && request->entry) inspect(inventory, request, hooks);
    else if (request->operation == AI_CANCEL) end(hooks, request, inventory->snapshot, "cache_stale", 0, false, 0);
    else return false;
    return true;
}
