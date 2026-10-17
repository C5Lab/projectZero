/*
 * SPDX-FileCopyrightText: 2026 JanOS contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#include "vendor_db.h"

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#define JVND_HEADER_SIZE 64U
#define JVND_VERSION 3U
#define JVND_SECTION_COUNT 4U
#define JVND_MAX_NAME_BYTES 60U
#define JVND_SECTION_TOTAL 3U

typedef struct {
    uint32_t offset;
    uint32_t count;
    uint8_t record_size;
    uint8_t prefix_bytes;
    uint8_t prefix_bits;
    uint8_t *cache;
} vendor_section_t;

struct vendor_db {
    FILE *file;
    vendor_db_alloc_fn alloc_fn;
    vendor_db_free_fn free_fn;
    void *alloc_ctx;
    uint8_t *cache_block;
    uint32_t file_size;
    uint32_t source_id;
    uint32_t names_offset;
    uint32_t names_size;
    vendor_section_t sections[JVND_SECTION_TOTAL];
};

typedef struct {
    uint64_t start;
    uint64_t end;
} checked_range_t;

static uint32_t read_u32le(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8U) |
           ((uint32_t)bytes[2] << 16U) |
           ((uint32_t)bytes[3] << 24U);
}

static uint32_t read_u24le(const uint8_t *bytes)
{
    return (uint32_t)bytes[0] |
           ((uint32_t)bytes[1] << 8U) |
           ((uint32_t)bytes[2] << 16U);
}

static bool seek_file(FILE *file, uint32_t offset)
{
#if LONG_MAX < UINT32_MAX
    if (offset > (uint32_t)LONG_MAX) {
        return false;
    }
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
            crc = (crc >> 1U) ^ (0xEDB88320U & mask);
        }
    }
    return crc;
}

static vendor_db_result_t verify_payload_crc(vendor_db_t *db, uint32_t expected)
{
    uint8_t buffer[4096];
    uint32_t remaining = db->file_size - JVND_HEADER_SIZE;
    uint32_t crc = 0xFFFFFFFFU;
    if (!seek_file(db->file, JVND_HEADER_SIZE)) {
        return VENDOR_DB_IO_ERROR;
    }
    while (remaining > 0U) {
        size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        if (fread(buffer, 1U, chunk, db->file) != chunk) {
            return VENDOR_DB_IO_ERROR;
        }
        crc = crc32_update(crc, buffer, chunk);
        remaining -= (uint32_t)chunk;
    }
    return (~crc == expected) ? VENDOR_DB_OK : VENDOR_DB_CRC_ERROR;
}

static bool checked_section(uint32_t offset, uint32_t count, uint8_t record_size,
                            uint32_t file_size, checked_range_t *range)
{
    uint64_t size = (uint64_t)count * record_size;
    if (offset < JVND_HEADER_SIZE || offset > file_size ||
        size > (uint64_t)file_size - offset) {
        return false;
    }
    range->start = offset;
    range->end = (uint64_t)offset + size;
    return true;
}

static bool ranges_overlap(checked_range_t first, checked_range_t second)
{
    if (first.start == first.end || second.start == second.end) {
        return false;
    }
    return first.start < second.end && second.start < first.end;
}

static uint64_t record_prefix(const uint8_t *record, const vendor_section_t *section,
                              bool *valid)
{
    uint64_t value = 0U;
    for (uint8_t index = 0; index < section->prefix_bytes; index++) {
        value = (value << 8U) | record[index];
    }
    if (section->prefix_bits != 24U) {
        if ((value & 0x0FU) != 0U) {
            *valid = false;
            return 0U;
        }
        value >>= 4U;
    }
    *valid = true;
    return value;
}

static bool read_section_record(vendor_db_t *db, const vendor_section_t *section,
                                uint32_t index, uint8_t record[8])
{
    uint64_t relative = (uint64_t)index * section->record_size;
    if (index >= section->count || relative > UINT32_MAX - section->offset) {
        return false;
    }
    if (section->cache != NULL) {
        memcpy(record, section->cache + relative, section->record_size);
        return true;
    }
    return read_at(db->file, section->offset + (uint32_t)relative,
                   record, section->record_size);
}

static vendor_db_result_t validate_names(vendor_db_t *db)
{
    uint32_t cursor = 0U;
    while (cursor < db->names_size) {
        uint8_t length = 0U;
        if (!read_at(db->file, db->names_offset + cursor, &length, 1U)) {
            return VENDOR_DB_IO_ERROR;
        }
        if (length == 0U || length > JVND_MAX_NAME_BYTES ||
            (uint32_t)length > db->names_size - cursor - 1U) {
            return VENDOR_DB_FORMAT_ERROR;
        }
        cursor += 1U + length;
    }
    return cursor == db->names_size ? VENDOR_DB_OK : VENDOR_DB_FORMAT_ERROR;
}

static vendor_db_result_t validate_indexes(vendor_db_t *db)
{
    for (size_t section_index = 0; section_index < JVND_SECTION_TOTAL; section_index++) {
        const vendor_section_t *section = &db->sections[section_index];
        uint64_t previous = 0U;
        bool have_previous = false;
        for (uint32_t index = 0; index < section->count; index++) {
            uint8_t record[8] = {0};
            bool valid = false;
            if (!read_section_record(db, section, index, record)) {
                return VENDOR_DB_IO_ERROR;
            }
            uint64_t prefix = record_prefix(record, section, &valid);
            if (!valid || (have_previous && prefix <= previous)) {
                return VENDOR_DB_FORMAT_ERROR;
            }
            uint32_t name_offset = read_u24le(record + section->prefix_bytes);
            if (name_offset >= db->names_size) {
                return VENDOR_DB_FORMAT_ERROR;
            }
            previous = prefix;
            have_previous = true;
        }
    }
    return VENDOR_DB_OK;
}

static vendor_db_result_t cache_indexes(vendor_db_t *db)
{
    uint64_t total = 0U;
    for (size_t index = 0; index < JVND_SECTION_TOTAL; index++) {
        total += (uint64_t)db->sections[index].count * db->sections[index].record_size;
    }
    if (total == 0U) {
        return VENDOR_DB_OK;
    }
    if (total > SIZE_MAX) {
        return VENDOR_DB_FORMAT_ERROR;
    }
    db->cache_block = db->alloc_fn((size_t)total, db->alloc_ctx);
    if (db->cache_block == NULL) {
        return VENDOR_DB_OK;
    }

    size_t cursor = 0U;
    for (size_t index = 0; index < JVND_SECTION_TOTAL; index++) {
        vendor_section_t *section = &db->sections[index];
        size_t size = (size_t)section->count * section->record_size;
        section->cache = db->cache_block + cursor;
        if (size > 0U && !read_at(db->file, section->offset, section->cache, size)) {
            return VENDOR_DB_IO_ERROR;
        }
        cursor += size;
    }
    return VENDOR_DB_OK;
}

static void set_result(vendor_db_result_t *output, vendor_db_result_t value)
{
    if (output != NULL) {
        *output = value;
    }
}

vendor_db_t *vendor_db_open(const char *path,
                            vendor_db_alloc_fn alloc_fn,
                            vendor_db_free_fn free_fn,
                            void *alloc_ctx,
                            vendor_db_result_t *result)
{
    set_result(result, VENDOR_DB_FORMAT_ERROR);
    if (path == NULL || alloc_fn == NULL || free_fn == NULL) {
        return NULL;
    }

    vendor_db_t *db = alloc_fn(sizeof(*db), alloc_ctx);
    if (db == NULL) {
        set_result(result, VENDOR_DB_NO_MEMORY);
        return NULL;
    }
    memset(db, 0, sizeof(*db));
    db->alloc_fn = alloc_fn;
    db->free_fn = free_fn;
    db->alloc_ctx = alloc_ctx;
    db->file = fopen(path, "rb");
    if (db->file == NULL) {
        set_result(result, VENDOR_DB_IO_ERROR);
        vendor_db_close(db);
        return NULL;
    }

    if (fseek(db->file, 0L, SEEK_END) != 0) {
        set_result(result, VENDOR_DB_IO_ERROR);
        vendor_db_close(db);
        return NULL;
    }
    long length = ftell(db->file);
    if (length < 0L) {
        set_result(result, VENDOR_DB_IO_ERROR);
        vendor_db_close(db);
        return NULL;
    }
    if ((uint64_t)length < JVND_HEADER_SIZE || (uint64_t)length > UINT32_MAX) {
        set_result(result, VENDOR_DB_FORMAT_ERROR);
        vendor_db_close(db);
        return NULL;
    }
    db->file_size = (uint32_t)length;

    uint8_t header[JVND_HEADER_SIZE];
    if (!read_at(db->file, 0U, header, sizeof(header))) {
        set_result(result, VENDOR_DB_IO_ERROR);
        vendor_db_close(db);
        return NULL;
    }
    if (memcmp(header, "JVND", 4U) != 0 || header[4] != JVND_VERSION ||
        header[5] != JVND_HEADER_SIZE || header[6] != JVND_SECTION_COUNT ||
        header[7] != 0U || read_u32le(header + 8U) != db->file_size) {
        set_result(result, VENDOR_DB_FORMAT_ERROR);
        vendor_db_close(db);
        return NULL;
    }
    for (size_t index = 52U; index < JVND_HEADER_SIZE; index++) {
        if (header[index] != 0U) {
            set_result(result, VENDOR_DB_FORMAT_ERROR);
            vendor_db_close(db);
            return NULL;
        }
    }

    db->source_id = read_u32le(header + 16U);
    db->names_offset = read_u32le(header + 20U);
    db->names_size = read_u32le(header + 24U);
    db->sections[0] = (vendor_section_t){read_u32le(header + 28U), read_u32le(header + 32U), 6U, 3U, 24U, NULL};
    db->sections[1] = (vendor_section_t){read_u32le(header + 36U), read_u32le(header + 40U), 7U, 4U, 28U, NULL};
    db->sections[2] = (vendor_section_t){read_u32le(header + 44U), read_u32le(header + 48U), 8U, 5U, 36U, NULL};

    checked_range_t ranges[4];
    if (!checked_section(db->sections[0].offset, db->sections[0].count, 6U, db->file_size, &ranges[0]) ||
        !checked_section(db->sections[1].offset, db->sections[1].count, 7U, db->file_size, &ranges[1]) ||
        !checked_section(db->sections[2].offset, db->sections[2].count, 8U, db->file_size, &ranges[2]) ||
        !checked_section(db->names_offset, db->names_size, 1U, db->file_size, &ranges[3])) {
        set_result(result, VENDOR_DB_FORMAT_ERROR);
        vendor_db_close(db);
        return NULL;
    }
    for (size_t left = 0; left < 4U; left++) {
        for (size_t right = left + 1U; right < 4U; right++) {
            if (ranges_overlap(ranges[left], ranges[right])) {
                set_result(result, VENDOR_DB_FORMAT_ERROR);
                vendor_db_close(db);
                return NULL;
            }
        }
    }

    vendor_db_result_t check = verify_payload_crc(db, read_u32le(header + 12U));
    if (check == VENDOR_DB_OK) {
        check = validate_names(db);
    }
    if (check == VENDOR_DB_OK) {
        check = validate_indexes(db);
    }
    if (check == VENDOR_DB_OK) {
        check = cache_indexes(db);
    }
    if (check != VENDOR_DB_OK) {
        set_result(result, check);
        vendor_db_close(db);
        return NULL;
    }

    set_result(result, VENDOR_DB_OK);
    return db;
}

static uint64_t mac_prefix(const uint8_t mac[6], uint8_t bits)
{
    size_t bytes = bits == 24U ? 3U : (bits == 28U ? 4U : 5U);
    uint64_t value = 0U;
    for (size_t index = 0; index < bytes; index++) {
        value = (value << 8U) | mac[index];
    }
    return bits == 24U ? value : value >> 4U;
}

static vendor_db_result_t find_name_offset(vendor_db_t *db,
                                            const vendor_section_t *section,
                                            uint64_t wanted,
                                            uint32_t *name_offset)
{
    uint32_t low = 0U;
    uint32_t high = section->count;
    while (low < high) {
        uint32_t middle = low + (high - low) / 2U;
        uint8_t record[8] = {0};
        bool valid = false;
        if (!read_section_record(db, section, middle, record)) {
            return VENDOR_DB_IO_ERROR;
        }
        uint64_t prefix = record_prefix(record, section, &valid);
        if (!valid) {
            return VENDOR_DB_FORMAT_ERROR;
        }
        if (prefix < wanted) {
            low = middle + 1U;
        } else if (prefix > wanted) {
            high = middle;
        } else {
            *name_offset = read_u24le(record + section->prefix_bytes);
            return VENDOR_DB_OK;
        }
    }
    return VENDOR_DB_NOT_FOUND;
}

static vendor_db_result_t read_name(vendor_db_t *db, uint32_t name_offset,
                                    char *name, size_t name_size)
{
    if (name_offset >= db->names_size) {
        return VENDOR_DB_FORMAT_ERROR;
    }
    uint8_t length = 0U;
    if (!read_at(db->file, db->names_offset + name_offset, &length, 1U)) {
        return VENDOR_DB_IO_ERROR;
    }
    if (length == 0U || length > JVND_MAX_NAME_BYTES ||
        (uint32_t)length > db->names_size - name_offset - 1U) {
        return VENDOR_DB_FORMAT_ERROR;
    }
    size_t copied = length < name_size - 1U ? length : name_size - 1U;
    if (!read_at(db->file, db->names_offset + name_offset + 1U, name, copied)) {
        return VENDOR_DB_IO_ERROR;
    }
    name[copied] = '\0';
    return VENDOR_DB_OK;
}

vendor_db_result_t vendor_db_lookup(vendor_db_t *db,
                                    const uint8_t mac[6],
                                    char *name,
                                    size_t name_size,
                                    uint8_t *matched_prefix_bits)
{
    if (db == NULL || mac == NULL || name == NULL || name_size == 0U) {
        return VENDOR_DB_FORMAT_ERROR;
    }
    name[0] = '\0';
    if (matched_prefix_bits != NULL) {
        *matched_prefix_bits = 0U;
    }
    if ((mac[0] & 0x02U) != 0U) {
        return VENDOR_DB_RANDOM_MAC;
    }

    for (int index = (int)JVND_SECTION_TOTAL - 1; index >= 0; index--) {
        const vendor_section_t *section = &db->sections[index];
        uint32_t name_offset = 0U;
        vendor_db_result_t result = find_name_offset(
            db, section, mac_prefix(mac, section->prefix_bits), &name_offset);
        if (result == VENDOR_DB_NOT_FOUND) {
            continue;
        }
        if (result != VENDOR_DB_OK) {
            return result;
        }
        result = read_name(db, name_offset, name, name_size);
        if (result == VENDOR_DB_OK && matched_prefix_bits != NULL) {
            *matched_prefix_bits = section->prefix_bits;
        }
        return result;
    }
    return VENDOR_DB_NOT_FOUND;
}

void vendor_db_close(vendor_db_t *db)
{
    if (db == NULL) {
        return;
    }
    if (db->file != NULL) {
        fclose(db->file);
        db->file = NULL;
    }
    if (db->cache_block != NULL) {
        db->free_fn(db->cache_block, db->alloc_ctx);
        db->cache_block = NULL;
    }
    db->free_fn(db, db->alloc_ctx);
}
