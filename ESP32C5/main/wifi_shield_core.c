#include "wifi_shield_core.h"

#include <string.h>

#define SHIELD_WINDOW_US ((uint64_t)WIFI_SHIELD_RATE_WINDOW_MS * UINT64_C(1000))

static uint32_t saturating_add(uint32_t value, uint32_t amount)
{
    return amount > UINT32_MAX - value ? UINT32_MAX : value + amount;
}

static bool unicast_identity(const uint8_t mac[6])
{
    uint8_t any = 0;
    for (size_t i = 0; i < 6; ++i)
        any |= mac[i];
    return any != 0 && (mac[0] & 1U) == 0;
}

static bool valid_event(const wifi_shield_event_t *event)
{
    if (event == NULL || event->count == 0 || event->channel == 0 ||
        (unsigned)event->wps_message > WIFI_SHIELD_WPS_DONE)
        return false;
    wifi_shield_source_t source;
    wifi_shield_severity_t severity;
    switch (event->type) {
    case WIFI_SHIELD_EVENT_DEAUTH:
    case WIFI_SHIELD_EVENT_DISASSOC:
        source = WIFI_SHIELD_SOURCE_DEAUTH;
        severity = WIFI_SHIELD_SEVERITY_ALERT;
        break;
    case WIFI_SHIELD_EVENT_CSA:
        source = WIFI_SHIELD_SOURCE_DEAUTH;
        severity = WIFI_SHIELD_SEVERITY_INFO;
        break;
    case WIFI_SHIELD_EVENT_WPS_ACTIVITY:
        source = WIFI_SHIELD_SOURCE_WPS;
        severity = WIFI_SHIELD_SEVERITY_INFO;
        break;
    case WIFI_SHIELD_EVENT_WPS_RETRY_BURST:
        source = WIFI_SHIELD_SOURCE_WPS;
        severity = WIFI_SHIELD_SEVERITY_WARN;
        break;
    case WIFI_SHIELD_EVENT_WPS_ANOMALY:
        source = WIFI_SHIELD_SOURCE_WPS;
        severity = WIFI_SHIELD_SEVERITY_ALERT;
        break;
    case WIFI_SHIELD_EVENT_SAE_ACTIVITY:
        source = WIFI_SHIELD_SOURCE_SAE;
        severity = WIFI_SHIELD_SEVERITY_INFO;
        break;
    case WIFI_SHIELD_EVENT_SAE_ANOMALY:
        source = WIFI_SHIELD_SOURCE_SAE;
        severity = WIFI_SHIELD_SEVERITY_ALERT;
        break;
    case WIFI_SHIELD_EVENT_TRUST_DRIFT:
        source = WIFI_SHIELD_SOURCE_TRUST;
        severity = WIFI_SHIELD_SEVERITY_ALERT;
        break;
    case WIFI_SHIELD_EVENT_PMKID_SEQUENCE:
        source = WIFI_SHIELD_SOURCE_PMKID;
        severity = WIFI_SHIELD_SEVERITY_INFO;
        break;
    default:
        return false;
    }
    if (event->source != source || event->severity != severity)
        return false;
    if (source == WIFI_SHIELD_SOURCE_WPS || source == WIFI_SHIELD_SOURCE_SAE ||
        source == WIFI_SHIELD_SOURCE_PMKID) {
        if (!unicast_identity(event->station) ||
            memcmp(event->station, event->bssid, 6) == 0)
            return false;
    }
    return true;
}

void wifi_shield_core_init(wifi_shield_core_t *core,
                           const wifi_shield_channel_plan_t *plan)
{
    if (core == NULL)
        return;
    memset(core, 0, sizeof(*core));
    core->plan = plan;
}

bool wifi_shield_core_selected(const wifi_shield_core_t *core,
                               const uint8_t bssid[6])
{
    return core != NULL && wifi_shield_target_selected(core->plan, bssid);
}

static bool rate_publishable(wifi_shield_core_t *core,
                             const wifi_shield_event_t *event)
{
    wifi_shield_rate_limit_t *entry = NULL, *unused = NULL;
    for (size_t i = 0; i < WIFI_SHIELD_RATE_LIMIT_CAPACITY; ++i) {
        wifi_shield_rate_limit_t *candidate = &core->rate_limits[i];
        if (!candidate->used) {
            if (unused == NULL)
                unused = candidate;
        } else if (candidate->source == event->source && candidate->type == event->type &&
                   memcmp(candidate->bssid, event->bssid, 6) == 0 &&
                   memcmp(candidate->station, event->station, 6) == 0) {
            entry = candidate;
            break;
        }
    }
    if (entry == NULL) {
        if (unused == NULL) {
            core->event_drops = saturating_add(core->event_drops, 1);
            return false;
        }
        entry = unused;
        entry->used = true;
        entry->source = event->source;
        entry->type = event->type;
        memcpy(entry->bssid, event->bssid, 6);
        memcpy(entry->station, event->station, 6);
        entry->window_started_us = event->timestamp_us;
    }
    if (event->timestamp_us < entry->window_started_us)
        return false;
    if (event->timestamp_us - entry->window_started_us >= SHIELD_WINDOW_US) {
        entry->window_started_us = event->timestamp_us;
        entry->count = 0;
        entry->threshold_published = false;
    }
    entry->count = saturating_add(entry->count, event->count);
    uint32_t threshold = event->type == WIFI_SHIELD_EVENT_WPS_RETRY_BURST ? 8U : 1U;
    if (entry->threshold_published || entry->count < threshold)
        return false;
    entry->threshold_published = true;
    return true;
}

static bool deauth_rate_publishable(wifi_shield_core_t *core,
                                    const wifi_shield_event_t *event)
{
    if (core->plan == NULL || (unsigned)event->type >=
        WIFI_SHIELD_DEAUTH_TYPE_COUNT) return false;
    size_t target_index = core->plan->target_count;
    for (size_t i = 0U; i < core->plan->target_count; ++i) {
        if (memcmp(core->plan->targets[i].bssid, event->bssid, 6U) == 0) {
            target_index = i;
            break;
        }
    }
    if (target_index >= core->plan->target_count ||
        target_index >= WIFI_SHIELD_TARGET_MAX) return false;

    wifi_shield_deauth_rate_limit_t *entry =
        &core->deauth_rate_limits[target_index];
    unsigned type = (unsigned)event->type;
    uint8_t mask = (uint8_t)(1U << type);
    if ((entry->used_mask & mask) == 0U) {
        entry->used_mask |= mask;
        entry->window_started_us[type] = event->timestamp_us;
        return true;
    }
    uint64_t started = entry->window_started_us[type];
    if (event->timestamp_us < started ||
        event->timestamp_us - started < SHIELD_WINDOW_US) return false;
    entry->window_started_us[type] = event->timestamp_us;
    return true;
}

bool wifi_shield_core_publishable(wifi_shield_core_t *core,
                                  const wifi_shield_event_t *event)
{
    if (core == NULL || !valid_event(event) ||
        !wifi_shield_core_selected(core, event->bssid))
        return false;
    core->source_events[event->source] =
        saturating_add(core->source_events[event->source], event->count);
    if ((event->source == WIFI_SHIELD_SOURCE_DEAUTH &&
         !deauth_rate_publishable(core, event)) ||
        ((event->type == WIFI_SHIELD_EVENT_WPS_ACTIVITY ||
         event->type == WIFI_SHIELD_EVENT_WPS_RETRY_BURST) &&
         !rate_publishable(core, event)))
        return false;
    if (event->severity == WIFI_SHIELD_SEVERITY_ALERT)
        core->alerts = saturating_add(core->alerts, 1);
    return true;
}

void wifi_shield_core_record_input(wifi_shield_core_t *core, bool selected,
                                   bool wps_fragment)
{
    if (core == NULL) return;
    core->received = saturating_add(core->received, 1U);
    if (!selected)
        core->filtered = saturating_add(core->filtered, 1U);
    else if (wps_fragment)
        core->wps_fragments = saturating_add(core->wps_fragments, 1U);
}

void wifi_shield_core_add_rx_drops(wifi_shield_core_t *core, uint32_t count)
{
    if (core == NULL) return;
    core->rx_drops = saturating_add(core->rx_drops, count);
}

void wifi_shield_core_status(const wifi_shield_core_t *core,
                             wifi_shield_status_t *status)
{
    if (status == NULL)
        return;
    memset(status, 0, sizeof(*status));
    if (core == NULL)
        return;
    memcpy(status->source_events, core->source_events, sizeof(status->source_events));
    status->alerts = core->alerts;
    status->received = core->received;
    status->filtered = core->filtered;
    status->wps_fragments = core->wps_fragments;
    status->rx_drops = core->rx_drops;
    status->event_drops = core->event_drops;
    status->output_failures = core->output_failures;
    status->current_channel = core->current_channel;
    status->running = core->running;
    status->stopping = core->stopping;
    status->active_defence = core->active_defence;
    status->pmkid_decoy = core->pmkid_decoy;
    status->multi_vector = core->multi_vector;
    status->protect_all = core->protect_all;
    if (core->plan != NULL) {
        status->target_count = core->plan->target_count;
        status->channel_count = core->plan->channel_count;
        memcpy(status->channels, core->plan->channels, core->plan->channel_count);
    }
}
