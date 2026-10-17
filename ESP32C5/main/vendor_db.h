/*
 * SPDX-FileCopyrightText: 2026 JanOS contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef JANOS_VENDOR_DB_H
#define JANOS_VENDOR_DB_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *(*vendor_db_alloc_fn)(size_t bytes, void *ctx);
typedef void (*vendor_db_free_fn)(void *ptr, void *ctx);

typedef enum {
    VENDOR_DB_OK = 0,
    VENDOR_DB_NOT_FOUND,
    VENDOR_DB_RANDOM_MAC,
    VENDOR_DB_IO_ERROR,
    VENDOR_DB_FORMAT_ERROR,
    VENDOR_DB_CRC_ERROR,
    VENDOR_DB_NO_MEMORY
} vendor_db_result_t;

typedef struct vendor_db vendor_db_t;

vendor_db_t *vendor_db_open(const char *path,
                            vendor_db_alloc_fn alloc_fn,
                            vendor_db_free_fn free_fn,
                            void *alloc_ctx,
                            vendor_db_result_t *result);

vendor_db_result_t vendor_db_lookup(vendor_db_t *db,
                                    const uint8_t mac[6],
                                    char *name,
                                    size_t name_size,
                                    uint8_t *matched_prefix_bits);

void vendor_db_close(vendor_db_t *db);

#ifdef __cplusplus
}
#endif

#endif
