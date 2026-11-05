#include "sae_guard_core.h"

#include <limits.h>
#include <string.h>

static void increment(uint32_t *counter)
{
    if (*counter != UINT32_MAX) ++*counter;
}

static bool expired_window(uint64_t start_us, uint64_t now_us)
{
    return now_us >= start_us && now_us - start_us >= SAE_GUARD_WINDOW_US;
}

static uint32_t elapsed_ms(uint64_t start_us, uint64_t now_us)
{
    if (now_us < start_us) return 0;
    const uint64_t milliseconds = (now_us - start_us) / UINT64_C(1000);
    return milliseconds > UINT32_MAX ? UINT32_MAX : (uint32_t)milliseconds;
}

/* Copy named metadata only. Future parser payload fields must not flow here. */
static void copy_observation(sae_guard_observation_t *out,
                             const sae_guard_observation_t *in)
{
    memset(out, 0, sizeof(*out));
    memcpy(out->bssid, in->bssid, sizeof(out->bssid));
    memcpy(out->station, in->station, sizeof(out->station));
    out->from_ap = in->from_ap;
    out->retry = in->retry;
    out->sequence = in->sequence;
    out->transaction = in->transaction;
    out->status = in->status;
    out->group = in->group;
    out->body_len = in->body_len;
    out->kind = in->kind;
    out->reason = in->reason;
    out->timestamp_us = in->timestamp_us;
    out->channel = in->channel;
    out->rssi = in->rssi;
}

void sae_guard_core_init(sae_guard_core_t *core)
{
    if (core != NULL) memset(core, 0, sizeof(*core));
}

void sae_guard_reset(sae_guard_core_t *core)
{
    sae_guard_core_init(core);
}

void sae_guard_get_status(const sae_guard_core_t *core,
                          sae_guard_status_t *status)
{
    if (status == NULL) return;
    memset(status, 0, sizeof(*status));
    if (core == NULL) return;
    *status = core->status;
    status->active_pairs = 0;
    status->active_malformed_bssids = 0;
    for (size_t i = 0; i < SAE_GUARD_TRACKED_PAIRS; ++i) {
        if (core->pairs[i].active) increment(&status->active_pairs);
    }
    for (size_t i = 0; i < SAE_GUARD_TRACKED_MALFORMED_BSSIDS; ++i) {
        if (core->malformed_bssids[i].active)
            increment(&status->active_malformed_bssids);
    }
}

size_t sae_guard_expire(sae_guard_core_t *core, uint64_t now_us)
{
    if (core == NULL) return 0;
    size_t expired = 0;
    for (size_t i = 0; i < SAE_GUARD_TRACKED_PAIRS; ++i) {
        sae_guard_pair_t *pair = &core->pairs[i];
        if (!pair->active || !expired_window(pair->window_start_us, now_us))
            continue;
        memset(pair, 0, sizeof(*pair));
        ++expired;
    }
    for (size_t i = 0; i < SAE_GUARD_TRACKED_MALFORMED_BSSIDS; ++i) {
        sae_guard_malformed_bssid_t *entry = &core->malformed_bssids[i];
        if (!entry->active || !expired_window(entry->window_start_us, now_us))
            continue;
        memset(entry, 0, sizeof(*entry));
        ++expired;
    }
    return expired;
}

static bool same_pair(const sae_guard_pair_t *pair,
                      const sae_guard_observation_t *observation)
{
    return pair->active && pair->from_ap == observation->from_ap &&
           memcmp(pair->bssid, observation->bssid, 6) == 0 &&
           memcmp(pair->station, observation->station, 6) == 0;
}

static sae_guard_pair_t *find_pair(sae_guard_core_t *core,
                                   const sae_guard_observation_t *observation,
                                   sae_guard_pair_t **available)
{
    sae_guard_pair_t *match = NULL;
    *available = NULL;
    for (size_t i = 0; i < SAE_GUARD_TRACKED_PAIRS; ++i) {
        sae_guard_pair_t *pair = &core->pairs[i];
        if (same_pair(pair, observation)) match = pair;
        else if (!pair->active && *available == NULL) *available = pair;
    }
    return match;
}

static sae_guard_malformed_bssid_t *find_malformed_bssid(
    sae_guard_core_t *core, const sae_guard_observation_t *observation,
    sae_guard_malformed_bssid_t **available)
{
    sae_guard_malformed_bssid_t *match = NULL;
    *available = NULL;
    for (size_t i = 0; i < SAE_GUARD_TRACKED_MALFORMED_BSSIDS; ++i) {
        sae_guard_malformed_bssid_t *entry = &core->malformed_bssids[i];
        if (entry->active && memcmp(entry->bssid, observation->bssid, 6) == 0)
            match = entry;
        else if (!entry->active && *available == NULL) *available = entry;
    }
    return match;
}

static sae_guard_pair_t *matching_pair(sae_guard_core_t *core,
                                       const sae_guard_observation_t *observation)
{
    for (size_t i = 0; i < SAE_GUARD_TRACKED_PAIRS; ++i) {
        if (same_pair(&core->pairs[i], observation)) return &core->pairs[i];
    }
    return NULL;
}

static void populate_event(sae_guard_event_t *event,
                           const sae_guard_observation_t *observation,
                           sae_guard_event_reason_t reason,
                           const sae_guard_pair_t *pair,
                           uint32_t malformed,
                           uint64_t window_start_us)
{
    if (event == NULL) return;
    memset(event, 0, sizeof(*event));
    copy_observation(&event->observation, observation);
    event->reason = reason;
    event->reason_mask = SAE_GUARD_EVENT_MASK(reason);
    if (pair != NULL) {
        if ((observation->kind == SAE_GUARD_CONFIRM ||
             (observation->kind == SAE_GUARD_MALFORMED &&
              observation->transaction == 2 &&
              observation->reason == SAE_GUARD_CONFIRM_UNDERSIZE)) &&
            event->observation.group == 0) {
            event->observation.group = pair->current_group;
        }
        event->commits = pair->commits;
        event->confirms = pair->confirms;
        event->retries = pair->retries;
        event->distinct_groups = pair->distinct_groups;
    }
    event->malformed = malformed;
    event->window_ms = elapsed_ms(window_start_us, observation->timestamp_us);
}

static bool emit_event(sae_guard_core_t *core, sae_guard_event_t *event,
                       const sae_guard_observation_t *observation,
                       sae_guard_event_reason_t reason,
                       const sae_guard_pair_t *pair, uint32_t malformed,
                       uint64_t window_start_us)
{
    increment(&core->status.reason_counts[reason]);
    populate_event(event, observation, reason, pair, malformed, window_start_us);
    return true;
}

static bool emit_capacity(sae_guard_core_t *core, sae_guard_event_t *event,
                          const sae_guard_observation_t *observation,
                          bool malformed_table)
{
    increment(&core->status.capacity_drops);
    if (malformed_table) increment(&core->status.malformed_capacity_drops);
    else increment(&core->status.pair_capacity_drops);
    return emit_event(core, event, observation, SAE_GUARD_EVENT_CAPACITY,
                      NULL, 0, observation->timestamp_us);
}

static size_t known_confirm_minimum(uint16_t group)
{
    switch (group) {
    case 19: return 40U; /* 6-byte Authentication header + 2 + 32. */
    case 20: return 56U; /* 6 + 2 + 48. */
    case 21: return 72U; /* 6 + 2 + 64. */
    default: return 0;
    }
}

static bool group_seen(const sae_guard_pair_t *pair, uint16_t group)
{
    size_t used = pair->distinct_groups;
    if (used > SAE_GUARD_GROUP_CHURN_THRESHOLD)
        used = SAE_GUARD_GROUP_CHURN_THRESHOLD;
    for (size_t i = 0; i < used; ++i) {
        if (pair->groups[i] == group) return true;
    }
    return false;
}

static void record_group(sae_guard_pair_t *pair, uint16_t group)
{
    if (group_seen(pair, group) ||
        pair->distinct_groups >= SAE_GUARD_GROUP_CHURN_THRESHOLD) return;
    pair->groups[pair->distinct_groups] = group;
    increment(&pair->distinct_groups);
}

static bool record_malformed(sae_guard_core_t *core,
                             const sae_guard_observation_t *observation,
                             sae_guard_event_t *event)
{
    increment(&core->status.malformed);
    sae_guard_malformed_bssid_t *available = NULL;
    sae_guard_malformed_bssid_t *entry = find_malformed_bssid(
        core, observation, &available);
    if (entry != NULL && observation->timestamp_us < entry->last_seen_us)
        return false;
    if (entry == NULL) {
        if (available == NULL) return emit_capacity(core, event, observation, true);
        entry = available;
        memset(entry, 0, sizeof(*entry));
        memcpy(entry->bssid, observation->bssid, sizeof(entry->bssid));
        entry->window_start_us = observation->timestamp_us;
        entry->last_seen_us = observation->timestamp_us;
        entry->active = true;
    }
    if (observation->timestamp_us > entry->last_seen_us)
        entry->last_seen_us = observation->timestamp_us;
    increment(&entry->malformed);
    if (entry->malformed < SAE_GUARD_MALFORMED_THRESHOLD || entry->reported)
        return false;
    entry->reported = true;
    return emit_event(core, event, observation, SAE_GUARD_EVENT_MALFORMED,
                      matching_pair(core, observation), entry->malformed,
                      entry->window_start_us);
}

static bool observe_commit(sae_guard_core_t *core,
                           const sae_guard_observation_t *observation,
                           sae_guard_event_t *event)
{
    sae_guard_pair_t *available = NULL;
    sae_guard_pair_t *pair = find_pair(core, observation, &available);
    if (pair != NULL && observation->timestamp_us < pair->last_seen_us)
        return false;
    if (observation->retry) {
        increment(&core->status.retries);
        if (pair != NULL && pair->have_last_commit &&
            pair->last_commit_sequence == observation->sequence &&
            pair->last_commit_group == observation->group) {
            increment(&pair->retries);
            if (observation->timestamp_us > pair->last_seen_us)
                pair->last_seen_us = observation->timestamp_us;
            return false;
        }
    }
    if (pair == NULL) {
        if (available == NULL) return emit_capacity(core, event, observation, false);
        pair = available;
        memset(pair, 0, sizeof(*pair));
        memcpy(pair->bssid, observation->bssid, sizeof(pair->bssid));
        memcpy(pair->station, observation->station, sizeof(pair->station));
        pair->from_ap = observation->from_ap;
        pair->window_start_us = observation->timestamp_us;
        pair->last_seen_us = observation->timestamp_us;
        pair->active = true;
    }
    if (observation->retry) increment(&pair->retries);
    increment(&core->status.commits);
    increment(&pair->commits);
    pair->current_group = observation->group;
    pair->last_commit_sequence = observation->sequence;
    pair->last_commit_group = observation->group;
    pair->awaiting_confirm = true;
    pair->have_last_commit = true;
    record_group(pair, observation->group);
    if (observation->timestamp_us > pair->last_seen_us)
        pair->last_seen_us = observation->timestamp_us;

    const bool unconfirmed_crossing =
        pair->commits >= SAE_GUARD_UNCONFIRMED_THRESHOLD &&
        !pair->unconfirmed_reported;
    const bool group_crossing =
        pair->distinct_groups >= SAE_GUARD_GROUP_CHURN_THRESHOLD &&
        !pair->group_churn_reported;
    if (unconfirmed_crossing || group_crossing) {
        const sae_guard_event_reason_t primary = unconfirmed_crossing ?
            SAE_GUARD_EVENT_UNCONFIRMED_COMMITS : SAE_GUARD_EVENT_GROUP_CHURN;
        if (unconfirmed_crossing) pair->unconfirmed_reported = true;
        if (group_crossing) pair->group_churn_reported = true;
        (void)emit_event(core, event, observation, primary, pair, 0,
                         pair->window_start_us);
        if (unconfirmed_crossing && group_crossing) {
            increment(&core->status.reason_counts[SAE_GUARD_EVENT_GROUP_CHURN]);
            if (event != NULL) {
                event->reason_mask |= SAE_GUARD_EVENT_MASK(
                    SAE_GUARD_EVENT_GROUP_CHURN);
            }
        }
        return true;
    }
    return false;
}

static bool observe_confirm(sae_guard_core_t *core,
                            const sae_guard_observation_t *observation,
                            sae_guard_event_t *event)
{
    sae_guard_pair_t *pair = matching_pair(core, observation);
    if (pair == NULL || !pair->awaiting_confirm ||
        observation->timestamp_us < pair->last_seen_us)
        return false;
    if (observation->retry) {
        increment(&core->status.retries);
        increment(&pair->retries);
    }
    const size_t minimum = known_confirm_minimum(pair->current_group);
    if (minimum != 0 && observation->body_len < minimum)
        return record_malformed(core, observation, event);
    increment(&core->status.confirms);
    increment(&pair->confirms);
    pair->awaiting_confirm = false;
    pair->have_last_commit = false;
    pair->current_group = 0;
    pair->last_commit_sequence = 0;
    pair->last_commit_group = 0;
    pair->commits = 0;
    pair->retries = 0;
    pair->distinct_groups = 0;
    memset(pair->groups, 0, sizeof(pair->groups));
    if (observation->timestamp_us > pair->last_seen_us)
        pair->last_seen_us = observation->timestamp_us;
    return false;
}

static bool valid_kind(sae_guard_frame_kind_t kind)
{
    return kind >= SAE_GUARD_COMMIT && kind <= SAE_GUARD_MALFORMED;
}

bool sae_guard_observe(sae_guard_core_t *core,
                       const sae_guard_observation_t *observation,
                       sae_guard_event_t *event)
{
    if (event == NULL) return false;
    memset(event, 0, sizeof(*event));
    if (core == NULL || observation == NULL || !valid_kind(observation->kind))
        return false;
    (void)sae_guard_expire(core, observation->timestamp_us);
    increment(&core->status.observations);

    switch (observation->kind) {
    case SAE_GUARD_COMMIT:
        return observe_commit(core, observation, event);
    case SAE_GUARD_CONFIRM:
        return observe_confirm(core, observation, event);
    case SAE_GUARD_MALFORMED:
        return record_malformed(core, observation, event);
    case SAE_GUARD_ANTI_CLOGGING:
        increment(&core->status.anti_clogging);
        return emit_event(core, event, observation,
                          SAE_GUARD_EVENT_ANTI_CLOGGING, NULL, 0,
                          observation->timestamp_us);
    case SAE_GUARD_UNSUPPORTED_GROUP:
    case SAE_GUARD_STATUS_ONLY:
        increment(&core->status.status_failures);
        return emit_event(core, event, observation,
                          SAE_GUARD_EVENT_STATUS_FAILURE, NULL, 0,
                          observation->timestamp_us);
    default:
        return false;
    }
}
