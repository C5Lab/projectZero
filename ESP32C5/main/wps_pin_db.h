/*
 * SPDX-FileCopyrightText: 2026 JanOS contributors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef JANOS_WPS_PIN_DB_H
#define JANOS_WPS_PIN_DB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define WPS_PIN_CANDIDATE_MAX 128U

typedef enum {
    WPS_PIN_SOURCE_EXPLICIT = 0,
    WPS_PIN_SOURCE_MODEL,
    WPS_PIN_SOURCE_OUI_STATIC,
    WPS_PIN_SOURCE_OUI_ALGO,
    WPS_PIN_SOURCE_SSID,
    WPS_PIN_SOURCE_VENDOR,
    WPS_PIN_SOURCE_BROAD,
    WPS_PIN_SOURCE_COMMON,
} wps_pin_source_t;

typedef struct {
    uint32_t pin8;
    wps_pin_source_t source;
    uint16_t detail_id;
} wps_pin_candidate_t;

typedef struct wps_pin_db wps_pin_db_t;
typedef void *(*wps_db_alloc_fn)(size_t bytes, void *ctx);
typedef void (*wps_db_free_fn)(void *pointer, void *ctx);

typedef enum {
    WPS_PIN_DB_OK = 0,
    WPS_PIN_DB_NOT_FOUND,
    WPS_PIN_DB_IO_ERROR,
    WPS_PIN_DB_FORMAT_ERROR,
    WPS_PIN_DB_CRC_ERROR,
    WPS_PIN_DB_NO_MEMORY,
} wps_pin_db_result_t;

typedef struct {
    uint16_t unsupported_algorithms;
    uint16_t duplicates_removed;
    bool truncated;
} wps_pin_query_stats_t;

wps_pin_db_t *wps_pin_db_open(const char *path, wps_db_alloc_fn alloc_fn,
                              wps_db_free_fn free_fn, void *ctx,
                              wps_pin_db_result_t *result);
size_t wps_pin_db_candidates(wps_pin_db_t *db, const uint8_t bssid[6],
                             const char *ssid, const char *vendor,
                             const char *model, const char *explicit_pin,
                             wps_pin_candidate_t *output, size_t capacity,
                             wps_pin_query_stats_t *stats);
void wps_pin_db_close(wps_pin_db_t *db);

#endif
