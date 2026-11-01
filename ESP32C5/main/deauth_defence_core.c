#include "deauth_defence_core.h"

#include <string.h>

static deauth_defence_decision_t decision(deauth_defence_action_t action,
                                          const char *reason,
                                          bool provisional)
{
    return (deauth_defence_decision_t){
        .action = action,
        .reason = reason,
        .enter_provisional_lock = provisional,
    };
}
static void clear_active(deauth_defence_core_t *core)
{
    memset(core->active_bssid, 0, sizeof(core->active_bssid));
    core->active_channel = 0U;
    core->last_activity_us = 0;
    core->response_satisfied = false;
}

static void rollback_provisional(deauth_defence_core_t *core, bool provisional)
{
    if (!provisional) return;
    clear_active(core);
    core->state = DEF_ARMED_HOPPING;
}

static bool bytes_nonzero(const uint8_t *value, size_t length)
{
    uint8_t combined = 0U;
    for (size_t i = 0; i < length; ++i) combined |= value[i];
    return combined != 0U;
}

static bool unicast_address(const uint8_t address[6])
{
    return address && (address[0] & 1U) == 0U &&
           bytes_nonzero(address, 6U);
}

static bool known_trigger(deauth_defence_trigger_t trigger)
{
    return trigger >= DEF_TRIG_DEAUTH && trigger <= DEF_TRIG_PMKID_PROBE;
}

static deauth_defence_target_rate_t *target_rate(
    deauth_defence_core_t *core, const uint8_t bssid[6], int64_t now_us)
{
    deauth_defence_target_rate_t *free_slot = NULL;
    deauth_defence_target_rate_t *oldest = &core->targets[0];
    for (size_t i = 0; i < DEAUTH_DEFENCE_TARGET_SLOTS; ++i) {
        deauth_defence_target_rate_t *slot = &core->targets[i];
        if (slot->used && memcmp(slot->bssid, bssid, 6U) == 0) {
            slot->last_seen_us = now_us;
            return slot;
        }
        if (!slot->used && !free_slot) free_slot = slot;
        if (!slot->used || slot->last_seen_us < oldest->last_seen_us) {
            oldest = slot;
        }
    }
    deauth_defence_target_rate_t *slot = free_slot ? free_slot : oldest;
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    memcpy(slot->bssid, bssid, 6U);
    slot->last_seen_us = now_us;
    return slot;
}

static deauth_defence_station_rate_t *station_rate(
    deauth_defence_core_t *core, const uint8_t bssid[6], const uint8_t sta[6],
    int64_t now_us)
{
    deauth_defence_station_rate_t *free_slot = NULL;
    deauth_defence_station_rate_t *expired = NULL;
    for (size_t i = 0; i < DEAUTH_DEFENCE_STATION_SLOTS; ++i) {
        deauth_defence_station_rate_t *slot = &core->stations[i];
        if (slot->used && memcmp(slot->bssid, bssid, 6U) == 0 &&
            memcmp(slot->sta, sta, 6U) == 0) {
            slot->last_seen_us = now_us;
            return slot;
        }
        if (!slot->used && !free_slot) free_slot = slot;
        if (slot->used &&
            (!slot->has_pmkid ||
             now_us - slot->last_pmkid_us >=
                 DEAUTH_DEFENCE_PMKID_COOLDOWN_US) &&
            (!expired || slot->last_seen_us < expired->last_seen_us)) {
            expired = slot;
        }
    }
    deauth_defence_station_rate_t *slot = free_slot ? free_slot : expired;
    if (!slot) return NULL;
    memset(slot, 0, sizeof(*slot));
    slot->used = true;
    memcpy(slot->bssid, bssid, 6U);
    memcpy(slot->sta, sta, 6U);
    slot->last_seen_us = now_us;
    return slot;
}

void deauth_defence_core_reset(deauth_defence_core_t *core,
                               bool pmkid_decoy_enabled,
                               uint32_t generation)
{
    if (!core) return;
    memset(core, 0, sizeof(*core));
    core->state = DEF_ARMED_HOPPING;
    core->pmkid_decoy_enabled = pmkid_decoy_enabled;
    core->generation = generation;
}

deauth_defence_decision_t deauth_defence_consume(
    deauth_defence_core_t *core,
    const deauth_defence_observation_t *observation,
    int64_t now_us)
{
    if (!core || !observation) {
        return decision(DEF_ACT_OBSERVE, "invalid_observation", false);
    }
    if (now_us < 0) {
        return decision(DEF_ACT_OBSERVE, "invalid_time", false);
    }
    if (core->has_time && now_us < core->last_now_us) {
        return decision(DEF_ACT_OBSERVE, "clock_regressed", false);
    }
    core->has_time = true;
    core->last_now_us = now_us;

    if (!known_trigger(observation->trigger) ||
        !unicast_address(observation->bssid) || observation->channel == 0U) {
        return decision(DEF_ACT_OBSERVE, "invalid_observation", false);
    }
    if (!observation->selected) {
        return decision(DEF_ACT_OBSERVE, "unselected_bssid", false);
    }
    if (!observation->wpa2_psk_ccmp) {
        return decision(DEF_ACT_OBSERVE,
                        "observe_only_unsupported_akm", false);
    }
    if (observation->trigger == DEF_TRIG_PMKID_PROBE &&
        !unicast_address(observation->sta)) {
        return decision(DEF_ACT_OBSERVE, "invalid_station", false);
    }
    if (core->state == DEF_RELEASE) {
        return decision(DEF_ACT_OBSERVE, "not_armed", false);
    }
    if (core->state != DEF_ARMED_HOPPING &&
        memcmp(core->active_bssid, observation->bssid, 6U) != 0) {
        return decision(DEF_ACT_OBSERVE, "busy_other_bssid", false);
    }

    bool provisional = core->state == DEF_ARMED_HOPPING;
    if (provisional) {
        memcpy(core->active_bssid, observation->bssid, 6U);
        core->active_channel = observation->channel;
        core->state = DEF_PROVISIONAL_LOCK;
    }
    core->last_activity_us = now_us;
    if (core->response_satisfied) {
        return decision(DEF_ACT_OBSERVE, "response_satisfied", false);
    }

    if (observation->trigger == DEF_TRIG_PMKID_PROBE) {
        if (!core->pmkid_decoy_enabled) {
            rollback_provisional(core, provisional);
            return decision(DEF_ACT_OBSERVE, "pmkid_monitor", false);
        }
        deauth_defence_station_rate_t *slot = station_rate(
            core, observation->bssid, observation->sta, now_us);
        if (!slot) {
            rollback_provisional(core, provisional);
            return decision(DEF_ACT_OBSERVE, "pmkid_capacity", false);
        }
        if (slot->has_pmkid &&
            now_us - slot->last_pmkid_us < DEAUTH_DEFENCE_PMKID_COOLDOWN_US) {
            rollback_provisional(core, provisional);
            return decision(DEF_ACT_OBSERVE, "pmkid_rate_limited", false);
        }
        slot->last_pmkid_us = now_us;
        slot->has_pmkid = true;
        return decision(DEF_ACT_DECOY_PMKID, "pmkid_decoy_opt_in",
                        provisional);
    }

    deauth_defence_target_rate_t *slot = target_rate(
        core, observation->bssid, now_us);
    while (slot->pair_count > 0U &&
           now_us - slot->pair_times_us[0] >=
               DEAUTH_DEFENCE_PAIR_WINDOW_US) {
        for (size_t i = 1U; i < slot->pair_count; ++i) {
            slot->pair_times_us[i - 1U] = slot->pair_times_us[i];
        }
        --slot->pair_count;
    }
    if (slot->pair_count >= 3U) {
        rollback_provisional(core, provisional);
        return decision(DEF_ACT_OBSERVE, "rate_limited_window", false);
    }
    if (slot->pair_count > 0U &&
        now_us - slot->pair_times_us[slot->pair_count - 1U] <
            DEAUTH_DEFENCE_PAIR_COOLDOWN_US) {
        rollback_provisional(core, provisional);
        return decision(DEF_ACT_OBSERVE, "rate_limited_cooldown", false);
    }
    slot->pair_times_us[slot->pair_count] = now_us;
    ++slot->pair_count;
    return decision(DEF_ACT_DECOY_4WAY, "selected_wpa2", provisional);
}

bool deauth_defence_response_started(deauth_defence_core_t *core)
{
    if (!core || core->state != DEF_PROVISIONAL_LOCK) return false;
    core->state = DEF_FAST_RESPONSE;
    return true;
}

bool deauth_defence_confirmation_started(deauth_defence_core_t *core)
{
    if (!core || core->state != DEF_FAST_RESPONSE) return false;
    core->state = DEF_CONFIRMING;
    return true;
}

bool deauth_defence_response_succeeded(deauth_defence_core_t *core)
{
    if (!core ||
        (core->state != DEF_FAST_RESPONSE &&
         core->state != DEF_CONFIRMING &&
         core->state != DEF_CONFIRMED_LOCK)) return false;
    core->response_satisfied = true;
    return true;
}

bool deauth_defence_abort_attempt(deauth_defence_core_t *core)
{
    if (!core || (core->state != DEF_PROVISIONAL_LOCK &&
                  core->state != DEF_FAST_RESPONSE &&
                  core->state != DEF_CONFIRMING)) return false;
    clear_active(core);
    core->state = DEF_ARMED_HOPPING;
    return true;
}
bool deauth_defence_confirm_lock(deauth_defence_core_t *core,
                                 const uint8_t bssid[6], uint8_t channel,
                                 int64_t now_us)
{
    if (!core || !bssid || channel == 0U || now_us < 0 ||
        core->state != DEF_CONFIRMING ||
        memcmp(core->active_bssid, bssid, 6U) != 0 ||
        (core->has_time && now_us < core->last_now_us)) return false;
    core->state = DEF_CONFIRMED_LOCK;
    core->active_channel = channel;
    core->last_activity_us = now_us;
    core->last_now_us = now_us;
    core->has_time = true;
    return true;
}

bool deauth_defence_release_if_idle(deauth_defence_core_t *core,
                                    int64_t now_us)
{
    if (!core || core->state != DEF_CONFIRMED_LOCK || now_us < 0 ||
        (core->has_time && now_us < core->last_now_us)) return false;
    core->last_now_us = now_us;
    core->has_time = true;
    if (now_us - core->last_activity_us < DEAUTH_DEFENCE_IDLE_RELEASE_US) {
        return false;
    }
    core->state = DEF_RELEASE;
    return true;
}

bool deauth_defence_rearm(deauth_defence_core_t *core)
{
    if (!core || core->state != DEF_RELEASE) return false;
    clear_active(core);
    core->state = DEF_ARMED_HOPPING;
    return true;
}
