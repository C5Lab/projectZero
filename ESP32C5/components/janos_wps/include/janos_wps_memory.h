/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#define JANOS_WPS_CAP_8BIT     (1u << 0)
#define JANOS_WPS_CAP_SPIRAM   (1u << 1)
#define JANOS_WPS_CAP_INTERNAL (1u << 2)

typedef enum {
    JANOS_WPS_MEMORY_BULK = 1,
    JANOS_WPS_MEMORY_SECRET = 2,
} janos_wps_memory_class_t;

typedef struct {
    void *(*alloc)(void *context, size_t size, uint32_t caps);
    void (*free)(void *context, void *memory, size_t size,
                 janos_wps_memory_class_t memory_class);
} janos_wps_memory_ops_t;

typedef struct {
    size_t bulk_bytes;
    size_t bulk_peak_bytes;
    size_t secret_bytes;
    size_t secret_peak_bytes;
    size_t failed_allocations;
} janos_wps_memory_snapshot_t;

typedef struct {
    atomic_size_t bulk_bytes;
    atomic_size_t bulk_peak_bytes;
    atomic_size_t secret_bytes;
    atomic_size_t secret_peak_bytes;
    atomic_size_t failed_allocations;
} janos_wps_memory_counters_t;

typedef struct {
    const janos_wps_memory_ops_t *ops;
    void *ops_context;
    janos_wps_memory_counters_t counters;
} janos_wps_memory_t;

void janos_wps_memory_init(janos_wps_memory_t *memory,
                           const janos_wps_memory_ops_t *ops,
                           void *ops_context);
void janos_wps_memory_init_esp(janos_wps_memory_t *memory);
void *janos_wps_alloc_bulk(janos_wps_memory_t *memory, size_t size);
void janos_wps_free_bulk(janos_wps_memory_t *memory, void *pointer);
void *janos_wps_alloc_secret(janos_wps_memory_t *memory, size_t size);
void janos_wps_free_secret(janos_wps_memory_t *memory, void *pointer);
void janos_wps_secure_wipe(void *memory, size_t size);
janos_wps_memory_snapshot_t janos_wps_memory_snapshot(
    const janos_wps_memory_t *memory);

