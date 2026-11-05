#include "wifi_shield_time.h"

#include <string.h>

#define WIFI_SHIELD_TIME_DISCONTINUITY_US UINT64_C(5000000)

static uint64_t saturating_add(uint64_t left, uint64_t right)
{
    return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

static const wifi_shield_time_anchor_t *find_anchor(
    const wifi_shield_time_core_t *core, const uint8_t bssid[6])
{
    for (size_t i = 0; i < WIFI_SHIELD_TIME_MAX_TARGETS; ++i) {
        if (core->anchors[i].used &&
            memcmp(core->anchors[i].bssid, bssid, 6) == 0) {
            return &core->anchors[i];
        }
    }
    return NULL;
}

static void clear_stamp(wifi_shield_time_stamp_t *out, uint64_t boot_us)
{
    memset(out, 0, sizeof(*out));
    out->boot_us = boot_us;
    out->quality = WIFI_SHIELD_TIME_NONE;
}

void wifi_shield_time_init(wifi_shield_time_core_t *core,
                           uint64_t max_anchor_age_us)
{
    if (core == NULL) {
        return;
    }
    memset(core, 0, sizeof(*core));
    core->max_anchor_age_us = max_anchor_age_us;
}

bool wifi_shield_time_observe_anchor(wifi_shield_time_core_t *core,
    const uint8_t bssid[6], uint64_t ap_tsf_us, uint64_t boot_us,
    bool *new_epoch)
{
    wifi_shield_time_anchor_t *anchor = NULL;
    wifi_shield_time_anchor_t *free_anchor = NULL;
    bool reset = false;
    if (new_epoch != NULL) {
        *new_epoch = false;
    }
    if (core == NULL || bssid == NULL) {
        return false;
    }
    for (size_t i = 0; i < WIFI_SHIELD_TIME_MAX_TARGETS; ++i) {
        if (!core->anchors[i].used) {
            if (free_anchor == NULL) {
                free_anchor = &core->anchors[i];
            }
        } else if (memcmp(core->anchors[i].bssid, bssid, 6) == 0) {
            anchor = &core->anchors[i];
            break;
        }
    }
    if (anchor == NULL) {
        if (free_anchor == NULL) {
            return false;
        }
        anchor = free_anchor;
        memcpy(anchor->bssid, bssid, 6);
        anchor->used = true;
        anchor->ap_epoch = 1;
    } else {
        if (boot_us < anchor->boot_us) {
            return false;
        }
        if (ap_tsf_us < anchor->ap_tsf_us) {
            reset = true;
        } else {
            const uint64_t tsf_delta = ap_tsf_us - anchor->ap_tsf_us;
            const uint64_t boot_delta = boot_us - anchor->boot_us;
            const uint64_t difference = tsf_delta > boot_delta
                ? tsf_delta - boot_delta : boot_delta - tsf_delta;
            reset = difference > WIFI_SHIELD_TIME_DISCONTINUITY_US;
        }
        if (reset && anchor->ap_epoch < UINT32_MAX) {
            ++anchor->ap_epoch;
        }
    }
    anchor->ap_tsf_us = ap_tsf_us;
    anchor->boot_us = boot_us;
    if (new_epoch != NULL) {
        *new_epoch = reset;
    }
    return true;
}

bool wifi_shield_time_exact(wifi_shield_time_core_t *core,
    const uint8_t bssid[6], uint64_t ap_tsf_us, uint64_t boot_us,
    wifi_shield_time_stamp_t *out)
{
    if (out == NULL) {
        return false;
    }
    clear_stamp(out, boot_us);
    if (!wifi_shield_time_observe_anchor(core, bssid, ap_tsf_us, boot_us, NULL)) {
        return false;
    }
    const wifi_shield_time_anchor_t *anchor = find_anchor(core, bssid);
    out->ap_tsf_us = ap_tsf_us;
    out->ap_epoch = anchor->ap_epoch;
    out->quality = WIFI_SHIELD_TIME_EXACT;
    return true;
}

bool wifi_shield_time_resolve(const wifi_shield_time_core_t *core,
    const uint8_t bssid[6], uint64_t boot_us,
    wifi_shield_time_stamp_t *out)
{
    if (out == NULL) {
        return false;
    }
    clear_stamp(out, boot_us);
    if (core == NULL || bssid == NULL) {
        return false;
    }
    const wifi_shield_time_anchor_t *anchor = find_anchor(core, bssid);
    if (anchor == NULL || boot_us < anchor->boot_us) {
        return false;
    }
    const uint64_t age = boot_us - anchor->boot_us;
    if (age > core->max_anchor_age_us) {
        return false;
    }
    out->ap_tsf_us = saturating_add(anchor->ap_tsf_us, age);
    out->ap_epoch = anchor->ap_epoch;
    out->uncertainty_us = age;
    out->quality = WIFI_SHIELD_TIME_ESTIMATED;
    return true;
}
