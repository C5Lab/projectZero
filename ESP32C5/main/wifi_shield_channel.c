#include "wifi_shield_channel.h"

#include <string.h>

static bool bssid_valid(const uint8_t bssid[6])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 6; ++i)
        any |= bssid[i];
    return any != 0 && (bssid[0] & 1U) == 0;
}

bool wifi_shield_channel_plan_init(wifi_shield_channel_plan_t *plan,
                                  const wifi_shield_target_t *targets, size_t count)
{
    if (plan == NULL)
        return false;
    memset(plan, 0, sizeof(*plan));
    if (targets == NULL || count == 0 || count > WIFI_SHIELD_TARGET_MAX)
        return false;
    for (size_t i = 0; i < count; ++i) {
        if (!bssid_valid(targets[i].bssid) || targets[i].channel == 0)
            return false;
        for (size_t j = 0; j < i; ++j) {
            if (memcmp(targets[i].bssid, targets[j].bssid, 6) == 0)
                return false;
        }
    }
    memcpy(plan->targets, targets, count * sizeof(*targets));
    plan->target_count = count;
    for (size_t i = 0; i < count; ++i) {
        size_t j = 0;
        while (j < plan->channel_count && plan->channels[j] != targets[i].channel)
            ++j;
        if (j == plan->channel_count)
            plan->channels[plan->channel_count++] = targets[i].channel;
    }
    return true;
}

bool wifi_shield_target_selected(const wifi_shield_channel_plan_t *plan,
                                 const uint8_t bssid[6])
{
    if (plan == NULL || bssid == NULL)
        return false;
    for (size_t i = 0; i < plan->target_count; ++i) {
        if (memcmp(plan->targets[i].bssid, bssid, 6) == 0)
            return true;
    }
    return false;
}

uint8_t wifi_shield_channel_next(wifi_shield_channel_plan_t *plan)
{
    if (plan == NULL || plan->channel_count == 0)
        return 0;
    if (plan->locked)
        return plan->locked_channel;
    uint8_t channel = plan->channels[plan->cursor];
    plan->cursor = (plan->cursor + 1) % plan->channel_count;
    return channel;
}

bool wifi_shield_channel_lock(wifi_shield_channel_plan_t *plan,
                              const uint8_t bssid[6], uint8_t channel)
{
    if (plan == NULL || bssid == NULL || channel == 0)
        return false;
    for (size_t i = 0; i < plan->target_count; ++i) {
        if (memcmp(plan->targets[i].bssid, bssid, 6) == 0 &&
            plan->targets[i].channel == channel) {
            plan->locked_channel = channel;
            plan->locked = true;
            return true;
        }
    }
    return false;
}

void wifi_shield_channel_release(wifi_shield_channel_plan_t *plan)
{
    if (plan != NULL) {
        plan->locked = false;
        plan->locked_channel = 0;
    }
}

const char *wifi_shield_channel_coverage(const wifi_shield_channel_plan_t *plan)
{
    if (plan == NULL || plan->channel_count == 0)
        return "none";
    return plan->channel_count == 1 ? "continuous" : "sampled";
}
