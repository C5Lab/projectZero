/*
 * SPDX-FileCopyrightText: 2026 JanOS contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "wps_pin_db.h"

#include "wps_pin_algorithms.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define JWPS_HEADER_SIZE 96U
#define JWPS_SECTION_COUNT 8U
#define JWPS_ALGORITHM_MASK 0x03ffU
#define JWPS_UNSUPPORTED_MASK (1U << 9U)

typedef struct {
    uint32_t offset;
    uint32_t count;
    uint8_t record_size;
    uint8_t *cache;
} wps_section_t;

struct wps_pin_db {
    FILE *file;
    wps_db_alloc_fn alloc_fn;
    wps_db_free_fn free_fn;
    void *alloc_ctx;
    uint8_t *cache_block;
    uint32_t file_size;
    uint8_t version;
    wps_section_t sections[JWPS_SECTION_COUNT];
};

static uint32_t u32le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8U) |
           ((uint32_t)p[2] << 16U) | ((uint32_t)p[3] << 24U);
}

static uint32_t u24le(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8U) | ((uint32_t)p[2] << 16U);
}

static bool seek_file(FILE *file, uint32_t offset)
{
#if LONG_MAX < UINT32_MAX
    if (offset > (uint32_t)LONG_MAX) return false;
#endif
    return fseek(file, (long)offset, SEEK_SET) == 0;
}

static bool read_at(FILE *file, uint32_t offset, void *output, size_t size)
{
    return seek_file(file, offset) && fread(output, 1U, size, file) == size;
}

static uint32_t crc32_update(uint32_t crc, const uint8_t *data, size_t size)
{
    for (size_t index = 0; index < size; index++) {
        crc ^= data[index];
        for (unsigned bit = 0; bit < 8U; bit++) {
            uint32_t mask = (uint32_t)-(int32_t)(crc & 1U);
            crc = (crc >> 1U) ^ (0xedb88320U & mask);
        }
    }
    return crc;
}

static bool section_range(const wps_section_t *section, uint32_t file_size,
                          uint64_t *start, uint64_t *end)
{
    uint64_t size = (uint64_t)section->count * section->record_size;
    if (section->offset < JWPS_HEADER_SIZE || section->offset > file_size ||
        size > (uint64_t)file_size - section->offset) return false;
    *start = section->offset;
    *end = *start + size;
    return true;
}

static bool read_record(wps_pin_db_t *db, unsigned section_index, uint32_t index,
                        uint8_t *record)
{
    wps_section_t *section = &db->sections[section_index];
    if (index >= section->count) return false;
    size_t relative = (size_t)index * section->record_size;
    if (section->cache != NULL) {
        memcpy(record, section->cache + relative, section->record_size);
        return true;
    }
    return read_at(db->file, section->offset + (uint32_t)relative,
                   record, section->record_size);
}

static bool decode_pin_record(wps_pin_db_t *db, unsigned section_index,
                              uint32_t index, uint32_t *pin)
{
    uint8_t raw[4];
    if (pin == NULL || (section_index != 1U && section_index != 6U) ||
        !read_record(db, section_index, index, raw)) return false;
    if (db->version == 1U) {
        uint32_t seven = u24le(raw);
        if (seven > 9999999U) return false;
        *pin = seven * 10U + jwps_pin_checksum(seven);
        return true;
    }
    uint32_t literal = u32le(raw);
    if (literal > 99999999U) return false;
    *pin = literal;
    return true;
}

static wps_pin_db_result_t verify_crc(wps_pin_db_t *db, uint32_t expected)
{
    uint8_t buffer[4096];
    uint32_t remaining = db->file_size - JWPS_HEADER_SIZE;
    uint32_t crc = 0xffffffffU;
    if (!seek_file(db->file, JWPS_HEADER_SIZE)) return WPS_PIN_DB_IO_ERROR;
    while (remaining > 0U) {
        size_t size = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        if (fread(buffer, 1U, size, db->file) != size) return WPS_PIN_DB_IO_ERROR;
        crc = crc32_update(crc, buffer, size);
        remaining -= (uint32_t)size;
    }
    return (~crc == expected) ? WPS_PIN_DB_OK : WPS_PIN_DB_CRC_ERROR;
}

static bool pin_ref_valid(wps_pin_db_t *db, uint32_t offset, uint8_t count)
{
    return offset <= db->sections[1].count && count <= db->sections[1].count - offset;
}

static bool read_string(wps_pin_db_t *db, uint32_t offset, char output[256]);

static bool valid_utf8(const uint8_t *text, size_t length)
{
    size_t index = 0U;
    while (index < length) {
        uint8_t first = text[index++];
        if (first == 0U) return false;
        if (first < 0x80U) continue;
        unsigned continuation;
        uint32_t value;
        uint32_t minimum;
        if ((first & 0xe0U) == 0xc0U) {
            continuation = 1U; value = first & 0x1fU; minimum = 0x80U;
        } else if ((first & 0xf0U) == 0xe0U) {
            continuation = 2U; value = first & 0x0fU; minimum = 0x800U;
        } else if ((first & 0xf8U) == 0xf0U) {
            continuation = 3U; value = first & 0x07U; minimum = 0x10000U;
        } else return false;
        if (continuation > length - index) return false;
        for (unsigned part = 0U; part < continuation; part++) {
            uint8_t next = text[index++];
            if ((next & 0xc0U) != 0x80U) return false;
            value = (value << 6U) | (next & 0x3fU);
        }
        if (value < minimum || value > 0x10ffffU ||
            (value >= 0xd800U && value <= 0xdfffU)) return false;
    }
    return true;
}

static bool validate_string_table(wps_pin_db_t *db)
{
    wps_section_t *strings = &db->sections[7];
    uint8_t bytes[255];
    uint32_t cursor = 0U;
    while (cursor < strings->count) {
        uint8_t length;
        if (!read_at(db->file, strings->offset + cursor, &length, 1U) ||
            length == 0U || length > strings->count - cursor - 1U ||
            !read_at(db->file, strings->offset + cursor + 1U, bytes, length) ||
            !valid_utf8(bytes, length)) return false;
        for (uint8_t index = 0U; index < length; index++)
            if (bytes[index] >= 0x80U) return false;
        cursor += 1U + length;
    }
    return cursor == strings->count;
}

static int rule_name_compare(const char *left, const char *right)
{
    while (*left != '\0' && *right != '\0') {
        unsigned char a = (unsigned char)*left++;
        unsigned char b = (unsigned char)*right++;
        int folded_a = a < 0x80U ? tolower(a) : a;
        int folded_b = b < 0x80U ? tolower(b) : b;
        if (folded_a != folded_b) return folded_a < folded_b ? -1 : 1;
    }
    return (unsigned char)*left == (unsigned char)*right ? 0 :
           *left == '\0' ? -1 : 1;
}

static bool string_ref_valid(wps_pin_db_t *db, uint32_t wanted)
{
    wps_section_t *strings = &db->sections[7];
    uint32_t cursor = 0U;
    while (cursor < strings->count) {
        uint8_t length;
        if (!read_at(db->file, strings->offset + cursor, &length, 1U)) return false;
        if (length == 0U || length > strings->count - cursor - 1U) return false;
        if (cursor == wanted) return true;
        cursor += 1U + length;
    }
    return false;
}

static wps_pin_db_result_t validate_database(wps_pin_db_t *db)
{
    uint32_t previous = 0U;
    bool have_previous = false;
    uint8_t record[7];
    for (uint32_t index = 0; index < db->sections[0].count; index++) {
        if (!read_record(db, 0, index, record)) return WPS_PIN_DB_IO_ERROR;
        uint32_t key = ((uint32_t)record[0] << 16U) | ((uint32_t)record[1] << 8U) | record[2];
        if ((have_previous && key <= previous) || !pin_ref_valid(db, u24le(record + 3), record[6]))
            return WPS_PIN_DB_FORMAT_ERROR;
        previous = key; have_previous = true;
    }
    previous = 0U; have_previous = false;
    for (uint32_t index = 0; index < db->sections[2].count; index++) {
        if (!read_record(db, 2, index, record)) return WPS_PIN_DB_IO_ERROR;
        uint32_t key = ((uint32_t)record[0] << 16U) | ((uint32_t)record[1] << 8U) | record[2];
        uint16_t mask = (uint16_t)record[3] | (uint16_t)((uint16_t)record[4] << 8U);
        if ((have_previous && key <= previous) || (mask & ~JWPS_ALGORITHM_MASK) != 0U)
            return WPS_PIN_DB_FORMAT_ERROR;
        previous = key; have_previous = true;
    }
    for (unsigned section = 3; section <= 4; section++) {
        char previous_name[256] = {0};
        bool have_previous_name = false;
        for (uint32_t index = 0; index < db->sections[section].count; index++) {
            char current_name[256];
            if (!read_record(db, section, index, record)) return WPS_PIN_DB_IO_ERROR;
            if (!string_ref_valid(db, u24le(record)) ||
                !read_string(db, u24le(record), current_name) ||
                (have_previous_name &&
                 rule_name_compare(previous_name, current_name) >= 0) ||
                !pin_ref_valid(db, u24le(record + 3), record[6]))
                return WPS_PIN_DB_FORMAT_ERROR;
            memcpy(previous_name, current_name, sizeof(previous_name));
            have_previous_name = true;
        }
    }
    previous = 0U; have_previous = false;
    for (uint32_t index = 0; index < db->sections[5].count; index++) {
        if (!read_record(db, 5, index, record)) return WPS_PIN_DB_IO_ERROR;
        if ((have_previous && record[0] <= previous) ||
            !pin_ref_valid(db, u24le(record + 1), record[4])) return WPS_PIN_DB_FORMAT_ERROR;
        previous = record[0]; have_previous = true;
    }
    for (unsigned section = 1; section <= 6; section += 5) {
        for (uint32_t index = 0; index < db->sections[section].count; index++) {
            uint32_t pin;
            if (!decode_pin_record(db, section, index, &pin))
                return WPS_PIN_DB_FORMAT_ERROR;
        }
    }
    return validate_string_table(db) ? WPS_PIN_DB_OK : WPS_PIN_DB_FORMAT_ERROR;
}

static wps_pin_db_result_t cache_indexes(wps_pin_db_t *db)
{
    uint64_t total = 0U;
    for (unsigned index = 0; index < JWPS_SECTION_COUNT; index++) {
        if (index == 1U || index == 7U) continue;
        total += (uint64_t)db->sections[index].count * db->sections[index].record_size;
    }
    if (total == 0U) return WPS_PIN_DB_OK;
    if (total > SIZE_MAX) return WPS_PIN_DB_FORMAT_ERROR;
    db->cache_block = db->alloc_fn((size_t)total, db->alloc_ctx);
    if (db->cache_block == NULL) return WPS_PIN_DB_OK;
    size_t cursor = 0U;
    for (unsigned index = 0; index < JWPS_SECTION_COUNT; index++) {
        if (index == 1U || index == 7U) continue;
        size_t size = (size_t)db->sections[index].count * db->sections[index].record_size;
        db->sections[index].cache = db->cache_block + cursor;
        if (size != 0U && !read_at(db->file, db->sections[index].offset,
                                   db->sections[index].cache, size)) return WPS_PIN_DB_IO_ERROR;
        cursor += size;
    }
    return WPS_PIN_DB_OK;
}

void wps_pin_db_close(wps_pin_db_t *db)
{
    if (db == NULL) return;
    if (db->file != NULL) fclose(db->file);
    if (db->cache_block != NULL) db->free_fn(db->cache_block, db->alloc_ctx);
    db->free_fn(db, db->alloc_ctx);
}

wps_pin_db_t *wps_pin_db_open(const char *path, wps_db_alloc_fn alloc_fn,
                              wps_db_free_fn free_fn, void *ctx,
                              wps_pin_db_result_t *result)
{
    if (result != NULL) *result = WPS_PIN_DB_FORMAT_ERROR;
    if (path == NULL || alloc_fn == NULL || free_fn == NULL) return NULL;
    wps_pin_db_t *db = alloc_fn(sizeof(*db), ctx);
    if (db == NULL) { if (result != NULL) *result = WPS_PIN_DB_NO_MEMORY; return NULL; }
    memset(db, 0, sizeof(*db)); db->alloc_fn = alloc_fn; db->free_fn = free_fn; db->alloc_ctx = ctx;
    db->file = fopen(path, "rb");
    if (db->file == NULL) { if (result != NULL) *result = WPS_PIN_DB_IO_ERROR; wps_pin_db_close(db); return NULL; }
    if (fseek(db->file, 0, SEEK_END) != 0) { if (result != NULL) *result = WPS_PIN_DB_IO_ERROR; wps_pin_db_close(db); return NULL; }
    long length = ftell(db->file);
    if (length < (long)JWPS_HEADER_SIZE || (uint64_t)length > UINT32_MAX) {
        if (result != NULL) *result = WPS_PIN_DB_FORMAT_ERROR;
        wps_pin_db_close(db);
        return NULL;
    }
    db->file_size = (uint32_t)length;
    uint8_t header[JWPS_HEADER_SIZE];
    if (!read_at(db->file, 0U, header, sizeof(header))) {
        if (result != NULL) *result = WPS_PIN_DB_IO_ERROR;
        wps_pin_db_close(db);
        return NULL;
    }
    if (memcmp(header, "JWPS", 4U) != 0 || (header[4] != 1U && header[4] != 2U) ||
        header[5] != JWPS_HEADER_SIZE ||
        header[6] != JWPS_SECTION_COUNT || header[7] != 0U || u32le(header + 8) != db->file_size) {
        if (result != NULL) *result = WPS_PIN_DB_FORMAT_ERROR;
        wps_pin_db_close(db);
        return NULL;
    }
    for (unsigned index = 20U; index < 32U; index++) if (header[index] != 0U) {
        if (result != NULL) *result = WPS_PIN_DB_FORMAT_ERROR;
        wps_pin_db_close(db);
        return NULL;
    }
    static const uint8_t sizes_v1[JWPS_SECTION_COUNT] = {7, 3, 5, 7, 7, 5, 3, 1};
    static const uint8_t sizes_v2[JWPS_SECTION_COUNT] = {7, 4, 5, 7, 7, 5, 4, 1};
    db->version = header[4];
    const uint8_t *sizes = db->version == 1U ? sizes_v1 : sizes_v2;
    uint64_t starts[JWPS_SECTION_COUNT], ends[JWPS_SECTION_COUNT];
    for (unsigned index = 0; index < JWPS_SECTION_COUNT; index++) {
        db->sections[index].offset = u32le(header + 32U + index * 8U);
        db->sections[index].count = u32le(header + 36U + index * 8U);
        db->sections[index].record_size = sizes[index];
        if (!section_range(&db->sections[index], db->file_size, &starts[index], &ends[index])) {
            if (result != NULL) *result = WPS_PIN_DB_FORMAT_ERROR;
            wps_pin_db_close(db);
            return NULL;
        }
    }
    for (unsigned left = 0; left < JWPS_SECTION_COUNT; left++) for (unsigned right = left + 1; right < JWPS_SECTION_COUNT; right++) {
        if (starts[left] != ends[left] && starts[right] != ends[right] &&
            starts[left] < ends[right] && starts[right] < ends[left]) {
            if (result != NULL) *result = WPS_PIN_DB_FORMAT_ERROR;
            wps_pin_db_close(db);
            return NULL;
        }
    }
    wps_pin_db_result_t check = verify_crc(db, u32le(header + 12U));
    if (check == WPS_PIN_DB_OK) check = validate_database(db);
    if (check == WPS_PIN_DB_OK) check = cache_indexes(db);
    if (check != WPS_PIN_DB_OK) { if (result != NULL) *result = check; wps_pin_db_close(db); return NULL; }
    if (result != NULL) *result = WPS_PIN_DB_OK;
    return db;
}

typedef struct {
    wps_pin_candidate_t *output;
    size_t capacity;
    size_t count;
    wps_pin_query_stats_t *stats;
} candidate_list_t;

static void append_candidate(candidate_list_t *list, uint32_t pin, wps_pin_source_t source, uint16_t detail)
{
    for (size_t index = 0; index < list->count; index++) if (list->output[index].pin8 == pin) {
        if (list->stats != NULL) list->stats->duplicates_removed++;
        return;
    }
    if (list->count >= list->capacity || list->count >= WPS_PIN_CANDIDATE_MAX) {
        if (list->stats != NULL) list->stats->truncated = true;
        return;
    }
    list->output[list->count++] = (wps_pin_candidate_t){pin, source, detail};
}

static bool explicit_pin(const char *text, uint32_t *pin)
{
    if (text == NULL || strlen(text) != 8U) return false;
    uint32_t value = 0U;
    for (unsigned index = 0; index < 8U; index++) {
        if (!isdigit((unsigned char)text[index])) return false;
        value = value * 10U + (uint32_t)(text[index] - '0');
    }
    if (value % 10U != jwps_pin_checksum(value / 10U)) return false;
    *pin = value; return true;
}

static bool pool_pin(wps_pin_db_t *db, uint32_t index, uint32_t *pin)
{
    return decode_pin_record(db, 1U, index, pin);
}

static void append_pool(wps_pin_db_t *db, candidate_list_t *list, uint32_t offset,
                        uint8_t count, wps_pin_source_t source, uint16_t detail)
{
    for (uint8_t index = 0; index < count; index++) {
        uint32_t pin;
        if (pool_pin(db, offset + index, &pin)) append_candidate(list, pin, source, detail);
    }
}

static uint32_t oui_key(const uint8_t bssid[6])
{
    return ((uint32_t)bssid[0] << 16U) | ((uint32_t)bssid[1] << 8U) | bssid[2];
}

static bool find_oui(wps_pin_db_t *db, unsigned section, uint32_t wanted, uint8_t *record)
{
    uint32_t low = 0U, high = db->sections[section].count;
    while (low < high) {
        uint32_t middle = low + (high - low) / 2U;
        if (!read_record(db, section, middle, record)) return false;
        uint32_t key = ((uint32_t)record[0] << 16U) | ((uint32_t)record[1] << 8U) | record[2];
        if (key < wanted) low = middle + 1U; else if (key > wanted) high = middle; else return true;
    }
    return false;
}

static bool read_string(wps_pin_db_t *db, uint32_t offset, char output[256])
{
    if (offset >= db->sections[7].count) return false;
    uint8_t length;
    if (!read_at(db->file, db->sections[7].offset + offset, &length, 1U) ||
        length == 0U || length > db->sections[7].count - offset - 1U) return false;
    if (!read_at(db->file, db->sections[7].offset + offset + 1U, output, length)) return false;
    output[length] = '\0'; return true;
}

static bool contains_ignore_case(const char *haystack, const char *needle, size_t needle_length)
{
    if (haystack == NULL || needle_length == 0U) return false;
    for (; *haystack; haystack++) {
        size_t index = 0U;
        while (index < needle_length && haystack[index] &&
               tolower((unsigned char)haystack[index]) == tolower((unsigned char)needle[index])) index++;
        if (index == needle_length) return true;
    }
    return false;
}

static bool vendor_matches(const char *vendor, const char *rule)
{
    const char *start = rule;
    while (*start) {
        const char *end = strchr(start, '|');
        size_t length = end == NULL ? strlen(start) : (size_t)(end - start);
        if (contains_ignore_case(vendor, start, length)) return true;
        if (end == NULL) break;
        start = end + 1;
    }
    return false;
}

static bool hex_tail(const char *text, size_t prefix, size_t minimum, size_t maximum)
{
    size_t length = strlen(text);
    if (length < prefix + minimum || length > prefix + maximum) return false;
    for (size_t index = prefix; index < length; index++) if (!isxdigit((unsigned char)text[index])) return false;
    return true;
}

static bool ssid_matches(uint8_t id, const char *ssid)
{
    if (ssid == NULL) return false;
    if (id == 1U) return strncmp(ssid, "WLAN_", 5U) == 0 && hex_tail(ssid, 5U, 4U, 4U);
    if (id == 2U) return contains_ignore_case(ssid, "JAZZTEL_", 8U) && hex_tail(ssid, 8U, 2U, 4U);
    if (id == 3U) return contains_ignore_case(ssid, "MOVISTAR_", 9U) && hex_tail(ssid, 9U, 4U, 4U);
    if (id == 4U) return contains_ignore_case(ssid, "Dlink_", 6U) && hex_tail(ssid, 6U, 4U, 4U);
    if (id == 5U) return contains_ignore_case(ssid, "Vodafone", 8U) && hex_tail(ssid, 8U, 4U, 4U);
    if (id == 6U) return contains_ignore_case(ssid, "Orange-", 7U) && hex_tail(ssid, 7U, 4U, 4U);
    return false;
}

size_t wps_pin_db_candidates(wps_pin_db_t *db, const uint8_t bssid[6], const char *ssid,
                             const char *vendor, const char *model, const char *explicit_text,
                             wps_pin_candidate_t *output, size_t capacity,
                             wps_pin_query_stats_t *stats)
{
    if (stats != NULL) memset(stats, 0, sizeof(*stats));
    if (bssid == NULL || output == NULL || capacity == 0U) return 0U;
    candidate_list_t list = {output, capacity, 0U, stats};
    uint32_t pin;
    if (explicit_pin(explicit_text, &pin)) append_candidate(&list, pin, WPS_PIN_SOURCE_EXPLICIT, 0U);
    if (db == NULL) return list.count;
    uint8_t record[7];

    if (model != NULL) for (uint32_t index = 0; index < db->sections[3].count; index++) {
        if (!read_record(db, 3, index, record)) break;
        char rule[256];
        if (read_string(db, u24le(record), rule) && strcmp(model, rule) == 0)
            append_pool(db, &list, u24le(record + 3), record[6], WPS_PIN_SOURCE_MODEL, (uint16_t)index);
    }
    uint32_t oui = oui_key(bssid);
    if (find_oui(db, 0, oui, record))
        append_pool(db, &list, u24le(record + 3), record[6], WPS_PIN_SOURCE_OUI_STATIC, 0U);
    if (find_oui(db, 2, oui, record)) {
        uint16_t mask = (uint16_t)record[3] | (uint16_t)((uint16_t)record[4] << 8U);
        for (unsigned bit = 0; bit < 10U; bit++) if (mask & (1U << bit)) {
            if (bit == 9U) { if (stats != NULL) stats->unsupported_algorithms++; continue; }
            if (wps_pin_generate((wps_pin_algo_t)bit, bssid, &pin))
                append_candidate(&list, pin, WPS_PIN_SOURCE_OUI_ALGO, (uint16_t)bit);
        }
    }
    for (uint32_t index = 0; index < db->sections[5].count; index++) {
        if (!read_record(db, 5, index, record)) break;
        if (ssid_matches(record[0], ssid))
            append_pool(db, &list, u24le(record + 1), record[4], WPS_PIN_SOURCE_SSID, record[0]);
    }
    if (vendor != NULL) for (uint32_t index = 0; index < db->sections[4].count; index++) {
        if (!read_record(db, 4, index, record)) break;
        char rule[256];
        if (read_string(db, u24le(record), rule) && vendor_matches(vendor, rule))
            append_pool(db, &list, u24le(record + 3), record[6], WPS_PIN_SOURCE_VENDOR, (uint16_t)index);
    }
    if (wps_pin_generate(WPS_PIN_ALGO_ZHAO, bssid, &pin))
        append_candidate(&list, pin, WPS_PIN_SOURCE_BROAD, WPS_PIN_ALGO_ZHAO);
    if (wps_pin_generate(WPS_PIN_ALGO_AIROCON, bssid, &pin))
        append_candidate(&list, pin, WPS_PIN_SOURCE_BROAD, WPS_PIN_ALGO_AIROCON);
    for (uint32_t index = 0; index < db->sections[6].count; index++) {
        if (!decode_pin_record(db, 6U, index, &pin)) break;
        append_candidate(&list, pin, WPS_PIN_SOURCE_COMMON, 0U);
    }
    return list.count;
}
