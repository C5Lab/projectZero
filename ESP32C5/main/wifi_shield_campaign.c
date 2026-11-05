#include "wifi_shield_campaign.h"

#include <string.h>

static uint32_t saturating_add(uint32_t value, uint32_t count)
{
    return count > UINT32_MAX - value ? UINT32_MAX : value + count;
}

static size_t target_index(const wifi_shield_campaign_core_t *core,
                            const uint8_t bssid[6])
{
    if (core != NULL && bssid != NULL) {
        for (size_t i = 0; i < core->target_count; ++i) {
            if (memcmp(core->targets[i].snapshot.bssid, bssid, 6) == 0)
                return i;
        }
    }
    return WIFI_SHIELD_TARGET_MAX;
}

bool wifi_shield_campaign_init(wifi_shield_campaign_core_t *core,
                                const wifi_shield_channel_plan_t *plan)
{
    if (core == NULL)
        return false;
    memset(core, 0, sizeof(*core));
    if (plan == NULL || plan->target_count == 0 ||
        plan->target_count > WIFI_SHIELD_TARGET_MAX)
        return false;
    for (size_t i = 0; i < plan->target_count; ++i) {
        const uint8_t *bssid = plan->targets[i].bssid;
        uint8_t any = 0;
        for (size_t j = 0; j < 6; ++j)
            any |= bssid[j];
        if (any == 0 || (bssid[0] & 1U) != 0)
            return false;
        for (size_t j = 0; j < i; ++j) {
            if (memcmp(plan->targets[j].bssid, bssid, 6) == 0)
                return false;
        }
    }
    core->target_count = plan->target_count;
    core->next_id = 1;
    for (size_t i = 0; i < core->target_count; ++i)
        memcpy(core->targets[i].snapshot.bssid, plan->targets[i].bssid, 6);
    return true;
}

static bool idle(const wifi_shield_campaign_snapshot_t *snapshot, uint64_t now_us)
{
    return snapshot->active && now_us >= snapshot->last_us &&
           now_us - snapshot->last_us >= WIFI_SHIELD_CAMPAIGN_IDLE_US;
}

static void complete_campaign(wifi_shield_campaign_entry_t *entry)
{
    entry->snapshot.active = false;
    entry->snapshot.completed_campaigns = saturating_add(
        entry->snapshot.completed_campaigns, 1U);
}

static void open_campaign(wifi_shield_campaign_core_t *core,
                           wifi_shield_campaign_entry_t *entry, uint64_t now_us)
{
    wifi_shield_campaign_snapshot_t *s = &entry->snapshot;
    /* Preserve the selected address and session loss evidence only. */
    memset(s->source_events, 0, sizeof(s->source_events));
    s->sources = 0;
    s->threat = WIFI_SHIELD_THREAT_NONE;
    s->last_transition_reason = WIFI_SHIELD_CAMPAIGN_REASON_NONE;
    s->active = true;
    s->first_us = now_us;
    s->last_us = now_us;
    s->confidence = s->rx_drops != 0 || s->event_drops != 0 ||
                        s->output_failures != 0 || s->journal_drops != 0 ||
                        s->sampled
                        ? WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED
                        : WIFI_SHIELD_CAMPAIGN_CONFIDENCE_FULL;
    s->id = core->next_id;
    ++core->next_id;
    if (core->next_id == 0)
        core->next_id = 1;
    memset(entry->history, 0, sizeof(entry->history));
    memset(entry->history_count, 0, sizeof(entry->history_count));
}

static bool near(uint64_t a, uint64_t b)
{
    uint64_t delta = a >= b ? a - b : b - a;
    return delta <= WIFI_SHIELD_CAMPAIGN_CORRELATION_US;
}

static bool correlated(const wifi_shield_campaign_entry_t *entry,
                         const wifi_shield_event_t *event)
{
    for (size_t source = 0; source < WIFI_SHIELD_SOURCE_COUNT; ++source) {
        if (source == (size_t)event->source)
            continue;
        for (size_t i = 0; i < entry->history_count[source]; ++i) {
            const wifi_shield_campaign_evidence_t *stored = &entry->history[source][i];
            if ((stored->alert || event->severity == WIFI_SHIELD_SEVERITY_ALERT) &&
                near(stored->timestamp_us, event->timestamp_us))
                return true;
        }
    }
    return false;
}

static void remember(wifi_shield_campaign_entry_t *entry,
                       const wifi_shield_event_t *event)
{
    size_t source = (size_t)event->source;
    size_t count = entry->history_count[source];
    wifi_shield_campaign_evidence_t *history = entry->history[source];
    size_t oldest = 0;
    for (size_t i = 0; i < count; ++i) {
        if (history[i].timestamp_us == event->timestamp_us) {
            history[i].alert |= event->severity == WIFI_SHIELD_SEVERITY_ALERT;
            return;
        }
        if (history[i].timestamp_us < history[oldest].timestamp_us)
            oldest = i;
    }
    size_t slot;
    if (count < WIFI_SHIELD_CAMPAIGN_HISTORY_CAPACITY) {
        slot = count;
        ++entry->history_count[source];
    } else {
        entry->snapshot.confidence = WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED;
        if (event->timestamp_us < history[oldest].timestamp_us)
            return;
        slot = oldest;
    }
    history[slot].timestamp_us = event->timestamp_us;
    history[slot].alert = event->severity == WIFI_SHIELD_SEVERITY_ALERT;
}

bool wifi_shield_campaign_observe(wifi_shield_campaign_core_t *core,
                                   const wifi_shield_event_t *event,
                                   wifi_shield_campaign_transition_t *transition)
{
    if (transition != NULL)
        memset(transition, 0, sizeof(*transition));
    if (event == NULL || event->count == 0 ||
        (unsigned)event->source >= WIFI_SHIELD_SOURCE_COUNT ||
        (unsigned)event->severity > WIFI_SHIELD_SEVERITY_ALERT)
        return false;
    size_t index = target_index(core, event->bssid);
    if (index == WIFI_SHIELD_TARGET_MAX)
        return false;
    wifi_shield_campaign_entry_t *entry = &core->targets[index];
    wifi_shield_campaign_snapshot_t *s = &entry->snapshot;
    if (entry->has_completed_campaign &&
        event->timestamp_us <= entry->completed_through_us)
        return false;
    if (!s->active) {
        open_campaign(core, entry, event->timestamp_us);
    } else if (idle(s, event->timestamp_us)) {
        /* idle() proves this addition fits: now_us - last_us >= IDLE_US. */
        entry->completed_through_us = s->last_us + WIFI_SHIELD_CAMPAIGN_IDLE_US - 1;
        entry->has_completed_campaign = true;
        complete_campaign(entry);
        open_campaign(core, entry, event->timestamp_us);
    }
    uint32_t bit = 1U << (unsigned)event->source;
    size_t source = (size_t)event->source;
    s->sources |= bit;
    s->source_events[source] = saturating_add(s->source_events[source], event->count);
    if (event->timestamp_us > s->last_us)
        s->last_us = event->timestamp_us;
    wifi_shield_campaign_reason_t reason =
        WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ACTIVITY;
    wifi_shield_threat_t threat = WIFI_SHIELD_THREAT_WATCH;
    if (event->severity == WIFI_SHIELD_SEVERITY_ALERT) {
        threat = WIFI_SHIELD_THREAT_ATTACK;
        reason = WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ALERT;
    }
    if (correlated(entry, event)) {
        threat = WIFI_SHIELD_THREAT_CRITICAL;
        reason = WIFI_SHIELD_CAMPAIGN_REASON_CROSS_VECTOR;
    }
    remember(entry, event);
    if (threat <= s->threat)
        return false;
    wifi_shield_threat_t previous = s->threat;
    s->threat = threat;
    if (threat > s->session_peak)
        s->session_peak = threat;
    s->last_transition_reason = reason;
    if (transition != NULL) {
        transition->id = s->id;
        memcpy(transition->bssid, s->bssid, 6);
        transition->from = previous;
        transition->to = threat;
        transition->sources = s->sources;
        transition->confidence = s->confidence;
        transition->reason = reason;
    }
    return true;
}

void wifi_shield_campaign_note_loss(wifi_shield_campaign_core_t *core,
                                     const uint8_t bssid[6], uint32_t rx_drops,
                                     uint32_t event_drops, uint32_t output_failures)
{
    size_t index = target_index(core, bssid);
    if (index == WIFI_SHIELD_TARGET_MAX)
        return;
    wifi_shield_campaign_snapshot_t *s = &core->targets[index].snapshot;
    s->rx_drops = saturating_add(s->rx_drops, rx_drops);
    s->event_drops = saturating_add(s->event_drops, event_drops);
    s->output_failures = saturating_add(s->output_failures, output_failures);
    if (rx_drops != 0 || event_drops != 0 || output_failures != 0)
        s->confidence = WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED;
}

void wifi_shield_campaign_note_journal_loss(
    wifi_shield_campaign_core_t *core, const uint8_t bssid[6],
    uint32_t journal_drops)
{
    size_t index = target_index(core, bssid);
    if (index == WIFI_SHIELD_TARGET_MAX || journal_drops == 0U) return;
    wifi_shield_campaign_snapshot_t *s = &core->targets[index].snapshot;
    s->journal_drops = saturating_add(s->journal_drops, journal_drops);
    s->confidence = WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED;
}

void wifi_shield_campaign_note_sampled(
    wifi_shield_campaign_core_t *core, const uint8_t bssid[6], bool sampled)
{
    size_t index = target_index(core, bssid);
    if (index == WIFI_SHIELD_TARGET_MAX || !sampled) return;
    wifi_shield_campaign_snapshot_t *s = &core->targets[index].snapshot;
    s->sampled = true;
    s->confidence = WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED;
}

size_t wifi_shield_campaign_expire(wifi_shield_campaign_core_t *core, uint64_t now_us)
{
    if (core == NULL)
        return 0;
    size_t expired = 0;
    for (size_t i = 0; i < core->target_count; ++i) {
        wifi_shield_campaign_entry_t *entry = &core->targets[i];
        if (idle(&entry->snapshot, now_us)) {
            complete_campaign(entry);
            entry->completed_through_us = now_us;
            entry->has_completed_campaign = true;
            ++expired;
        }
    }
    return expired;
}

size_t wifi_shield_campaign_close(wifi_shield_campaign_core_t *core,
                                  uint64_t now_us)
{
    if (core == NULL) return 0U;
    size_t closed = 0U;
    for (size_t i = 0U; i < core->target_count; ++i) {
        wifi_shield_campaign_entry_t *entry = &core->targets[i];
        if (!entry->snapshot.active) continue;
        complete_campaign(entry);
        entry->completed_through_us = now_us >= entry->snapshot.last_us ?
            now_us : entry->snapshot.last_us;
        entry->has_completed_campaign = true;
        ++closed;
    }
    return closed;
}

bool wifi_shield_campaign_snapshot(const wifi_shield_campaign_core_t *core,
                                    const uint8_t bssid[6],
                                    wifi_shield_campaign_snapshot_t *snapshot)
{
    if (snapshot == NULL)
        return false;
    memset(snapshot, 0, sizeof(*snapshot));
    size_t index = target_index(core, bssid);
    if (index == WIFI_SHIELD_TARGET_MAX)
        return false;
    *snapshot = core->targets[index].snapshot;
    return true;
}

const char *wifi_shield_campaign_reason_token(
    wifi_shield_campaign_reason_t reason)
{
    static const char *const tokens[] = {
        NULL, "isolated_activity", "isolated_alert", "cross_vector"
    };
    if ((unsigned)reason >= sizeof(tokens) / sizeof(tokens[0])) return NULL;
    return tokens[reason];
}

bool wifi_shield_campaign_reason_valid(wifi_shield_threat_t threat,
    wifi_shield_campaign_reason_t reason, uint32_t sources)
{
    const uint32_t known = (UINT32_C(1) << WIFI_SHIELD_SOURCE_COUNT) - 1U;
    if ((sources & ~known) != 0U) return false;
    switch (threat) {
    case WIFI_SHIELD_THREAT_NONE:
        return reason == WIFI_SHIELD_CAMPAIGN_REASON_NONE && sources == 0U;
    case WIFI_SHIELD_THREAT_WATCH:
        return reason == WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ACTIVITY &&
               sources != 0U;
    case WIFI_SHIELD_THREAT_ATTACK:
        return reason == WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ALERT &&
               sources != 0U;
    case WIFI_SHIELD_THREAT_CRITICAL:
        return reason == WIFI_SHIELD_CAMPAIGN_REASON_CROSS_VECTOR &&
               sources != 0U && (sources & (sources - 1U)) != 0U;
    default:
        return false;
    }
}
