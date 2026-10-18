/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#ifndef LAB_PLATFORM_H
#define LAB_PLATFORM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sta_mac_policy_store.h"

typedef enum {
    LAB_PLATFORM_OK = 0,
    LAB_PLATFORM_INVALID_ARGUMENT,
    LAB_PLATFORM_NOT_FOUND,
    LAB_PLATFORM_IO_ERROR,
    LAB_PLATFORM_INVALID_POLICY,
    LAB_PLATFORM_NO_MEMORY,
} lab_platform_status_t;

typedef struct {
    int (*sd_mount)(void *context);
    int (*sd_unmount)(void *context);
    int (*factory_mac)(void *context, uint8_t out[STA_MAC_SIZE]);
    int (*entropy)(void *context, uint8_t *out, size_t length);
    int (*read_sta_mac)(void *context, uint8_t out[STA_MAC_SIZE]);
    void *(*psram_alloc)(void *context, size_t size);
    void (*psram_free)(void *context, void *memory);
    uint64_t (*monotonic_ms)(void *context);
    void (*reboot)(void *context);
    bool (*poll_cancel)(void *context);
    bool (*commit_gate)(void *context, uint32_t operation_id);
} lab_platform_ops_t;

typedef struct {
    const lab_platform_ops_t *ops;
    void *context;
    const sta_mac_policy_store_t *policy_store;
    sta_mac_policy_record_t boot_policy;
    uint8_t effective_boot_mac[STA_MAC_SIZE];
    bool boot_mac_resolved;
    bool sd_mounted;
} lab_platform_t;

void lab_platform_init(lab_platform_t *platform,
                       const lab_platform_ops_t *ops, void *context,
                       const sta_mac_policy_store_t *policy_store);
lab_platform_status_t lab_platform_policy_load(
    lab_platform_t *platform, sta_mac_policy_record_t *record);
lab_platform_status_t lab_platform_policy_save(
    lab_platform_t *platform, const sta_mac_policy_record_t *record);
/* Resolves once per boot. Saving a new policy never changes this cached value. */
lab_platform_status_t lab_platform_resolve_boot_mac(
    lab_platform_t *platform, uint8_t out[STA_MAC_SIZE],
    sta_mac_policy_record_t *policy_out);
lab_platform_status_t lab_platform_read_sta_mac(
    lab_platform_t *platform, uint8_t out[STA_MAC_SIZE]);
lab_platform_status_t lab_platform_sd_mount(lab_platform_t *platform);
lab_platform_status_t lab_platform_sd_unmount(lab_platform_t *platform);
void *lab_platform_psram_alloc(lab_platform_t *platform, size_t size);
void lab_platform_psram_free(lab_platform_t *platform, void *memory);
uint64_t lab_platform_now_ms(const lab_platform_t *platform);
void lab_platform_reboot(lab_platform_t *platform);
/* Nonblocking. Input other than the foreground cancel key is ignored. */
bool lab_platform_poll_cancel(lab_platform_t *platform);
bool lab_platform_commit_gate(lab_platform_t *platform,
                              uint32_t operation_id);

#endif
