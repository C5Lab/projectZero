#include "wifi_shield_output_platform.h"

#include <limits.h>
#include <string.h>

static void increment_saturating(atomic_uint *value)
{
    unsigned current = atomic_load_explicit(value, memory_order_acquire);
    while (current != UINT_MAX &&
           !atomic_compare_exchange_weak_explicit(
               value, &current, current + 1U,
               memory_order_acq_rel, memory_order_acquire)) {
    }
}

static bool decrement_pending(wifi_shield_output_platform_t *platform)
{
    unsigned current = atomic_load_explicit(
        &platform->pending, memory_order_acquire);
    while (current != 0U) {
        if (atomic_compare_exchange_weak_explicit(
                &platform->pending, &current, current - 1U,
                memory_order_acq_rel, memory_order_acquire)) return true;
    }
    return false;
}

bool wifi_shield_output_platform_init(
    wifi_shield_output_platform_t *platform,
    const wifi_shield_output_platform_hooks_t *hooks)
{
    if (platform == NULL || hooks == NULL || hooks->lock == NULL ||
        hooks->unlock == NULL || hooks->monotonic_us == NULL) return false;
    memset(platform, 0, sizeof(*platform));
    platform->hooks = *hooks;
    atomic_init(&platform->admission, false);
    atomic_init(&platform->closed, true);
    atomic_init(&platform->pending, 0U);
    atomic_init(&platform->failures, 0U);
    return true;
}

void wifi_shield_output_platform_open(wifi_shield_output_platform_t *platform)
{
    if (platform == NULL) return;
    atomic_store_explicit(&platform->pending, 0U, memory_order_release);
    atomic_store_explicit(&platform->failures, 0U, memory_order_release);
    atomic_store_explicit(&platform->closed, false, memory_order_release);
    atomic_store_explicit(&platform->admission, true, memory_order_release);
}

bool wifi_shield_output_platform_admitted(
    const wifi_shield_output_platform_t *platform)
{
    return platform != NULL &&
        atomic_load_explicit(&platform->admission, memory_order_acquire);
}

void wifi_shield_output_platform_accepted(
    wifi_shield_output_platform_t *platform)
{
    if (platform != NULL) increment_saturating(&platform->pending);
}

bool wifi_shield_output_platform_rejected(
    wifi_shield_output_platform_t *platform)
{
    return platform != NULL && decrement_pending(platform);
}

bool wifi_shield_output_platform_published(
    wifi_shield_output_platform_t *platform, size_t expected, int written)
{
    if (platform == NULL || !decrement_pending(platform)) return false;
    bool complete = written >= 0 && (size_t)written == expected;
    if (!complete) increment_saturating(&platform->failures);
    return complete;
}

bool wifi_shield_output_platform_close(
    wifi_shield_output_platform_t *platform, uint32_t timeout_ms,
    uint32_t *remaining_ms)
{
    if (platform == NULL || remaining_ms == NULL || timeout_ms == 0U)
        return false;
    uint64_t started = platform->hooks.monotonic_us(platform->hooks.context);
    if (!platform->hooks.lock(platform->hooks.context, timeout_ms)) return false;
    atomic_store_explicit(&platform->admission, false, memory_order_release);
    atomic_store_explicit(&platform->closed, true, memory_order_release);
    platform->hooks.unlock(platform->hooks.context);
    uint64_t elapsed_us =
        platform->hooks.monotonic_us(platform->hooks.context) - started;
    uint64_t elapsed_ms = (elapsed_us + 999U) / 1000U;
    *remaining_ms = elapsed_ms < timeout_ms ?
        timeout_ms - (uint32_t)elapsed_ms : 0U;
    return true;
}

bool wifi_shield_output_platform_is_closed(
    const wifi_shield_output_platform_t *platform)
{
    return platform == NULL ||
        atomic_load_explicit(&platform->closed, memory_order_acquire);
}

unsigned wifi_shield_output_platform_pending(
    const wifi_shield_output_platform_t *platform)
{
    return platform == NULL ? 0U :
        atomic_load_explicit(&platform->pending, memory_order_acquire);
}

uint32_t wifi_shield_output_platform_take_failures(
    wifi_shield_output_platform_t *platform)
{
    return platform == NULL ? 0U : atomic_exchange_explicit(
        &platform->failures, 0U, memory_order_acq_rel);
}

bool wifi_shield_output_platform_should_sync_status(
    const char *line, size_t length, bool queue_ready, bool admitted)
{
    static const char status[] = "[SHIELD/1] STATUS ";
    static const char campaign[] = "[SHIELD/2] CAMPAIGN ";
    static const char health[] = "[SHIELD/2] AP_HEALTH ";
    static const char recommendation[] = "[SHIELD/2] RECOMMENDATION ";
    static const char log[] = "[SHIELD/2] LOG ";
    static const char storage[] = "[SHIELD/2] STORAGE ";
    if (line == NULL || (queue_ready && admitted)) return false;
#define SHIELD_PREFIX(token) \
    (length >= sizeof(token) && memcmp(line, token, sizeof(token) - 1U) == 0)
    bool allowed = SHIELD_PREFIX(status) || SHIELD_PREFIX(campaign) ||
        SHIELD_PREFIX(health) || SHIELD_PREFIX(recommendation) ||
        SHIELD_PREFIX(log) ||
        SHIELD_PREFIX(storage);
#undef SHIELD_PREFIX
    return allowed;
}
