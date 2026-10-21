/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "lab_platform.h"

#include <string.h>

void lab_platform_init(lab_platform_t *platform,
                       const lab_platform_ops_t *ops, void *context,
                       const sta_mac_policy_store_t *policy_store)
{
    if (!platform) return;
    memset(platform, 0, sizeof(*platform));
    platform->ops = ops;
    platform->context = context;
    platform->policy_store = policy_store;
}

static lab_platform_status_t map_store_result(sta_mac_store_result_t result)
{
    switch (result.status) {
    case STA_MAC_STORE_OK:
        return LAB_PLATFORM_OK;
    case STA_MAC_STORE_MISSING_NAMESPACE:
    case STA_MAC_STORE_MISSING_KEY:
        return LAB_PLATFORM_NOT_FOUND;
    case STA_MAC_STORE_INVALID_RECORD:
        return LAB_PLATFORM_INVALID_POLICY;
    case STA_MAC_STORE_INVALID_ARGUMENT:
        return LAB_PLATFORM_INVALID_ARGUMENT;
    default:
        return LAB_PLATFORM_IO_ERROR;
    }
}

lab_platform_status_t lab_platform_policy_load(
    lab_platform_t *platform, sta_mac_policy_record_t *record)
{
    if (!platform || !record) return LAB_PLATFORM_INVALID_ARGUMENT;
    if (!platform->policy_store) return LAB_PLATFORM_NOT_FOUND;
    return map_store_result(sta_mac_policy_load(platform->policy_store, record));
}

lab_platform_status_t lab_platform_policy_save(
    lab_platform_t *platform, const sta_mac_policy_record_t *record)
{
    if (!platform || !record || !platform->policy_store)
        return LAB_PLATFORM_INVALID_ARGUMENT;
    return map_store_result(sta_mac_policy_save(platform->policy_store, record));
}

lab_platform_status_t lab_platform_resolve_boot_mac(
    lab_platform_t *platform, uint8_t out[STA_MAC_SIZE],
    sta_mac_policy_record_t *policy_out)
{
    if (!platform || !out || !platform->ops) return LAB_PLATFORM_INVALID_ARGUMENT;
    if (platform->boot_mac_resolved) {
        memcpy(out, platform->effective_boot_mac, STA_MAC_SIZE);
        if (policy_out) *policy_out = platform->boot_policy;
        return LAB_PLATFORM_OK;
    }

    sta_mac_policy_record_t policy = {
        .version = STA_MAC_POLICY_VERSION,
        .mode = STA_MAC_MODE_FACTORY,
        .mac = {0},
    };
    lab_platform_status_t loaded = lab_platform_policy_load(platform, &policy);
    if (loaded != LAB_PLATFORM_OK && loaded != LAB_PLATFORM_NOT_FOUND) return loaded;
    if (sta_mac_policy_validate(&policy) != STA_MAC_POLICY_OK)
        return LAB_PLATFORM_INVALID_POLICY;

    uint8_t resolved[STA_MAC_SIZE] = {0};
    if (policy.mode == STA_MAC_MODE_FACTORY) {
        if (!platform->ops->factory_mac ||
            platform->ops->factory_mac(platform->context, resolved) != 0)
            return LAB_PLATFORM_IO_ERROR;
    } else if (policy.mode == STA_MAC_MODE_RANDOM_PER_BOOT) {
        uint8_t entropy[STA_MAC_SIZE] = {0};
        if (!platform->ops->entropy ||
            platform->ops->entropy(platform->context, entropy, sizeof(entropy)) != 0)
            return LAB_PLATFORM_IO_ERROR;
        sta_mac_policy_status_t status =
            sta_mac_random_from_entropy(entropy, sizeof(entropy), resolved);
        memset(entropy, 0, sizeof(entropy));
        if (status != STA_MAC_POLICY_OK) return LAB_PLATFORM_INVALID_POLICY;
    } else {
        memcpy(resolved, policy.mac, sizeof(resolved));
    }

    platform->boot_policy = policy;
    memcpy(platform->effective_boot_mac, resolved, sizeof(resolved));
    platform->boot_mac_resolved = true;
    memcpy(out, resolved, sizeof(resolved));
    if (policy_out) *policy_out = policy;
    return LAB_PLATFORM_OK;
}

lab_platform_status_t lab_platform_read_sta_mac(
    lab_platform_t *platform, uint8_t out[STA_MAC_SIZE])
{
    if (!platform || !out || !platform->ops || !platform->ops->read_sta_mac)
        return LAB_PLATFORM_INVALID_ARGUMENT;
    return platform->ops->read_sta_mac(platform->context, out) == 0
               ? LAB_PLATFORM_OK : LAB_PLATFORM_IO_ERROR;
}

lab_platform_status_t lab_platform_sd_mount(lab_platform_t *platform)
{
    if (!platform || !platform->ops || !platform->ops->sd_mount)
        return LAB_PLATFORM_INVALID_ARGUMENT;
    if (platform->sd_mounted) return LAB_PLATFORM_OK;
    if (platform->ops->sd_mount(platform->context) != 0) return LAB_PLATFORM_IO_ERROR;
    platform->sd_mounted = true;
    return LAB_PLATFORM_OK;
}

lab_platform_status_t lab_platform_sd_unmount(lab_platform_t *platform)
{
    if (!platform || !platform->ops || !platform->ops->sd_unmount)
        return LAB_PLATFORM_INVALID_ARGUMENT;
    if (!platform->sd_mounted) return LAB_PLATFORM_OK;
    if (platform->ops->sd_unmount(platform->context) != 0) return LAB_PLATFORM_IO_ERROR;
    platform->sd_mounted = false;
    return LAB_PLATFORM_OK;
}

void *lab_platform_psram_alloc(lab_platform_t *platform, size_t size)
{
    if (!platform || !size || !platform->ops || !platform->ops->psram_alloc) return NULL;
    return platform->ops->psram_alloc(platform->context, size);
}

void lab_platform_psram_free(lab_platform_t *platform, void *memory)
{
    if (platform && memory && platform->ops && platform->ops->psram_free)
        platform->ops->psram_free(platform->context, memory);
}

uint64_t lab_platform_now_ms(const lab_platform_t *platform)
{
    if (!platform || !platform->ops || !platform->ops->monotonic_ms) return 0;
    return platform->ops->monotonic_ms(platform->context);
}

void lab_platform_reboot(lab_platform_t *platform)
{
    if (platform && platform->ops && platform->ops->reboot)
        platform->ops->reboot(platform->context);
}

bool lab_platform_poll_cancel(lab_platform_t *platform)
{
    return platform && platform->ops && platform->ops->poll_cancel &&
           platform->ops->poll_cancel(platform->context);
}

bool lab_platform_commit_gate(lab_platform_t *platform,
                              uint32_t operation_id)
{
    return platform && operation_id != 0U && platform->ops &&
           platform->ops->commit_gate &&
           platform->ops->commit_gate(platform->context, operation_id);
}
