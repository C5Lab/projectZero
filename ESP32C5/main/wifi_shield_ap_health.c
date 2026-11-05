#include "wifi_shield_ap_health.h"
#include <limits.h>
#include <string.h>

static uint32_t add32(uint32_t a, uint32_t b)
{ return UINT32_MAX - a < b ? UINT32_MAX : a + b; }
static uint64_t add64(uint64_t a, uint64_t b)
{ return UINT64_MAX - a < b ? UINT64_MAX : a + b; }
static bool valid_bssid(const uint8_t *b)
{
    if (!b || (b[0] & 1)) return false;
    uint8_t any = 0;
    for (unsigned i = 0; i < 6; ++i) any |= b[i];
    return any != 0;
}
static wifi_shield_ap_health_entry_t *entry(wifi_shield_ap_health_core_t *c,
                                           const uint8_t *b, bool create)
{
    if (!c || !valid_bssid(b)) return NULL;
    wifi_shield_ap_health_entry_t *free_entry = NULL;
    for (size_t i = 0; i < WIFI_SHIELD_TARGET_MAX; ++i) {
        wifi_shield_ap_health_entry_t *e = &c->entries[i];
        if (e->used && memcmp(e->bssid, b, 6) == 0) return e;
        if (!e->used && !free_entry) free_entry = e;
    }
    if (!create || !free_entry) return NULL;
    free_entry->used = true;
    memcpy(free_entry->bssid, b, 6);
    return free_entry;
}
static bool channel_valid(const wifi_shield_ap_beacon_t *b)
{
    switch (b->band) {
    case WIFI_SHIELD_AP_BAND_2GHZ: return b->channel >= 1 && b->channel <= 14;
    case WIFI_SHIELD_AP_BAND_5GHZ: return b->channel >= 32 && b->channel <= 177;
    case WIFI_SHIELD_AP_BAND_6GHZ: return b->channel >= 1 && b->channel <= 233;
    default: return false;
    }
}
static bool time_valid(const wifi_shield_time_stamp_t *t)
{
    switch (t->quality) {
    case WIFI_SHIELD_TIME_NONE:
        return !t->ap_epoch && !t->ap_tsf_us && !t->uncertainty_us;
    case WIFI_SHIELD_TIME_EXACT: return t->ap_epoch && !t->uncertainty_us;
    case WIFI_SHIELD_TIME_ESTIMATED: return t->ap_epoch != 0;
    default: return false;
    }
}
void wifi_shield_ap_health_init(wifi_shield_ap_health_core_t *core)
{ if (core) memset(core, 0, sizeof(*core)); }

bool wifi_shield_ap_health_observe_beacon(wifi_shield_ap_health_core_t *core,
    const wifi_shield_ap_beacon_t *b)
{
    if (!b || !valid_bssid(b->bssid) || b->sequence > 4095 || b->rssi > 0 ||
        !b->interval_tu || !channel_valid(b) || !time_valid(&b->time)) return false;
    wifi_shield_ap_health_entry_t *e = entry(core, b->bssid, false);
    if (e && e->measurements.beacons && b->time.boot_us < e->last.time.boot_us)
        return false;
    if (!e) e = entry(core, b->bssid, true);
    if (!e) return false;
    wifi_shield_ap_health_snapshot_t *s = &e->measurements;
    if (s->beacons) {
        const wifi_shield_ap_beacon_t *p = &e->last;
        if (b->channel != p->channel || b->band != p->band)
            s->channel_changes = add32(s->channel_changes, 1);
        bool exact = b->time.quality == WIFI_SHIELD_TIME_EXACT &&
                     p->time.quality == WIFI_SHIELD_TIME_EXACT;
        bool same_epoch = b->time.ap_epoch == p->time.ap_epoch;
        if (exact && !same_epoch)
            s->epoch_changes = add32(s->epoch_changes, 1);
        uint16_t delta = (uint16_t)((b->sequence + 4096U - p->sequence) & 4095U);
        if (same_epoch && delta > 0 && delta <= 2047)
            s->sequence_gaps = add32(s->sequence_gaps, (uint32_t)delta - 1);
        else if (same_epoch && delta > 2047)
            e->continuity_limited = true;
        /* Sequence numbers also cover other management traffic, so timing
         * is independent of sequence delta. Distance to the nearest positive
         * cadence multiple uses only remainder/subtraction, avoiding overflow
         * even when the next multiple would exceed UINT64_MAX. */
        bool duplicate_tsf = same_epoch && exact &&
            b->time.ap_tsf_us == p->time.ap_tsf_us;
        if (same_epoch && exact && b->time.ap_tsf_us > p->time.ap_tsf_us &&
            b->interval_tu == p->interval_tu && b->channel == p->channel &&
            b->band == p->band && s->interval_pairs != UINT32_MAX) {
            uint64_t period = (uint64_t)b->interval_tu * 1024;
            uint64_t actual = b->time.ap_tsf_us - p->time.ap_tsf_us;
            uint64_t remainder = actual % period;
            uint64_t jitter = period - remainder;
            if (actual >= period && remainder < jitter) jitter = remainder;
            s->interval_pairs++;
            e->jitter_sum_us = add64(e->jitter_sum_us, jitter);
            if (jitter > s->jitter_max_us) s->jitter_max_us = jitter;
        } else if (same_epoch && !duplicate_tsf) e->timing_limited = true;
    } else { s->rssi_min = b->rssi; s->rssi_max = b->rssi; }
    if (s->beacons != UINT32_MAX) { s->beacons++; e->rssi_sum += b->rssi; }
    if (b->rssi < s->rssi_min) s->rssi_min = b->rssi;
    if (b->rssi > s->rssi_max) s->rssi_max = b->rssi;
    if (b->retry) s->retry_beacons = add32(s->retry_beacons, 1);
    if (b->time.quality != WIFI_SHIELD_TIME_EXACT) e->timing_limited = true;
    e->last = *b;
    return true;
}
bool wifi_shield_ap_health_note_event(wifi_shield_ap_health_core_t *core,
    const uint8_t bssid[6], wifi_shield_event_type_t type, uint32_t count)
{
    if (!count || (type != WIFI_SHIELD_EVENT_DEAUTH &&
        type != WIFI_SHIELD_EVENT_DISASSOC && type != WIFI_SHIELD_EVENT_CSA &&
        type != WIFI_SHIELD_EVENT_WPS_RETRY_BURST)) return false;
    wifi_shield_ap_health_entry_t *e = entry(core, bssid, true);
    if (!e) return false;
    uint32_t *counter;
    switch (type) {
    case WIFI_SHIELD_EVENT_DEAUTH: counter = &e->measurements.deauth_events; break;
    case WIFI_SHIELD_EVENT_DISASSOC: counter = &e->measurements.disassoc_events; break;
    case WIFI_SHIELD_EVENT_CSA: counter = &e->measurements.csa_events; break;
    default: counter = &e->measurements.retry_events; break;
    }
    *counter = add32(*counter, count);
    return true;
}
static bool fact_valid(wifi_shield_ap_fact_t f)
{ return f == WIFI_SHIELD_AP_UNKNOWN || f == WIFI_SHIELD_AP_NO || f == WIFI_SHIELD_AP_YES; }

static wifi_shield_ap_confidence_t observation_confidence(
    const wifi_shield_ap_health_snapshot_t *snapshot,
    wifi_shield_ap_confidence_t measured)
{
    if (measured != WIFI_SHIELD_AP_CONFIDENCE_NONE) return measured;
    return snapshot->sampled || snapshot->rx_drops || snapshot->event_drops ||
        snapshot->journal_drops ? WIFI_SHIELD_AP_CONFIDENCE_LIMITED :
        WIFI_SHIELD_AP_CONFIDENCE_OBSERVED;
}

static void add_recommendation(wifi_shield_ap_health_snapshot_t *snapshot,
    uint32_t action, wifi_shield_ap_recommendation_evidence_t evidence,
    wifi_shield_ap_confidence_t confidence)
{
    if (snapshot->recommendation_count >= WIFI_SHIELD_AP_RECOMMENDATION_MAX)
        return;
    snapshot->recommendations |= action;
    snapshot->recommendation_details[snapshot->recommendation_count++] =
        (wifi_shield_ap_recommendation_detail_t){action, evidence, confidence};
}
bool wifi_shield_ap_health_note_posture(wifi_shield_ap_health_core_t *core,
    const uint8_t bssid[6], const wifi_shield_ap_posture_t *p)
{
    if (!p || !fact_valid(p->wps) || !fact_valid(p->pmf_required) ||
        !fact_valid(p->wpa3_supported) || !fact_valid(p->wpa3_only) ||
        !fact_valid(p->transition_mode) || !fact_valid(p->legacy_cipher)) return false;
    wifi_shield_ap_health_entry_t *e = entry(core, bssid, true);
    if (!e) return false;
    e->posture = *p;
    return true;
}
bool wifi_shield_ap_health_note_quality(wifi_shield_ap_health_core_t *core,
    const uint8_t bssid[6], const wifi_shield_ap_quality_t *q)
{
    if (!q) return false;
    wifi_shield_ap_health_entry_t *e = entry(core, bssid, true);
    if (!e) return false;
    wifi_shield_ap_health_snapshot_t *s = &e->measurements;
    s->sampled |= q->sampled;
    s->rx_drops = add32(s->rx_drops, q->rx_drops);
    s->event_drops = add32(s->event_drops, q->event_drops);
    s->journal_drops = add32(s->journal_drops, q->journal_drops);
    return true;
}

bool wifi_shield_ap_health_snapshot(const wifi_shield_ap_health_core_t *core,
    const uint8_t bssid[6], wifi_shield_ap_health_snapshot_t *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!core || !valid_bssid(bssid)) return false;
    const wifi_shield_ap_health_entry_t *e = NULL;
    for (size_t i = 0; i < WIFI_SHIELD_TARGET_MAX; ++i)
        if (core->entries[i].used && memcmp(core->entries[i].bssid, bssid, 6) == 0)
            { e = &core->entries[i]; break; }
    if (!e) return false;
    *out = e->measurements;
    if (out->beacons) {
        /* RSSI is nonpositive: nearest integer, ties away from zero. */
        out->rssi_average = (int16_t)((e->rssi_sum - out->beacons / 2) / out->beacons);
        bool limited = out->sampled || out->rx_drops || out->event_drops || out->journal_drops;
        out->continuity_confidence = limited || e->continuity_limited ?
            WIFI_SHIELD_AP_CONFIDENCE_LIMITED : WIFI_SHIELD_AP_CONFIDENCE_OBSERVED;
        out->timing_confidence = limited || e->timing_limited ?
            WIFI_SHIELD_AP_CONFIDENCE_LIMITED : out->interval_pairs ?
            WIFI_SHIELD_AP_CONFIDENCE_OBSERVED : WIFI_SHIELD_AP_CONFIDENCE_NONE;
        for (size_t i = 0; i < WIFI_SHIELD_TARGET_MAX; ++i) {
            const wifi_shield_ap_health_entry_t *n = &core->entries[i];
            if (n == e || !n->used || n->measurements.beacons < 2 ||
                n->last.rssi < -75 || n->last.band != e->last.band) continue;
            uint64_t age = e->last.time.boot_us > n->last.time.boot_us ?
                e->last.time.boot_us - n->last.time.boot_us :
                n->last.time.boot_us - e->last.time.boot_us;
            if (age >= 30000000) continue;
            int distance = (int)n->last.channel - e->last.channel;
            if (distance == 0) out->same_channel_neighbors++;
            else if (e->last.band == WIFI_SHIELD_AP_BAND_2GHZ &&
                n->last.channel != 14 && e->last.channel != 14 &&
                distance >= -4 && distance <= 4) out->overlapping_channel_neighbors++;
        }
    }
    const wifi_shield_ap_posture_t *p = &e->posture;
    if (p->wps == WIFI_SHIELD_AP_YES)
        add_recommendation(out, WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS,
            WIFI_SHIELD_AP_EVIDENCE_WPS_ADVERTISED,
            WIFI_SHIELD_AP_CONFIDENCE_OBSERVED);
    if (p->pmf_required == WIFI_SHIELD_AP_NO)
        add_recommendation(out, WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF,
            WIFI_SHIELD_AP_EVIDENCE_PMF_NOT_REQUIRED,
            WIFI_SHIELD_AP_CONFIDENCE_OBSERVED);
    if (p->wpa3_supported == WIFI_SHIELD_AP_YES && p->wpa3_only == WIFI_SHIELD_AP_NO)
        add_recommendation(out, WIFI_SHIELD_AP_RECOMMEND_PREFER_WPA3_ONLY,
            WIFI_SHIELD_AP_EVIDENCE_WPA3_NOT_ONLY,
            WIFI_SHIELD_AP_CONFIDENCE_OBSERVED);
    if (p->transition_mode == WIFI_SHIELD_AP_YES)
        add_recommendation(out,
            WIFI_SHIELD_AP_RECOMMEND_REVIEW_TRANSITION_MODE,
            WIFI_SHIELD_AP_EVIDENCE_TRANSITION_MODE,
            WIFI_SHIELD_AP_CONFIDENCE_OBSERVED);
    if (p->legacy_cipher == WIFI_SHIELD_AP_YES)
        add_recommendation(out,
            WIFI_SHIELD_AP_RECOMMEND_REVIEW_LEGACY_CIPHER,
            WIFI_SHIELD_AP_EVIDENCE_LEGACY_CIPHER,
            WIFI_SHIELD_AP_CONFIDENCE_OBSERVED);
    if (out->channel_changes >= 2)
        add_recommendation(out, WIFI_SHIELD_AP_RECOMMEND_CHANNEL_UNSTABLE,
            WIFI_SHIELD_AP_EVIDENCE_CHANNEL_CHANGES,
            observation_confidence(out, out->continuity_confidence));
    if (out->same_channel_neighbors + out->overlapping_channel_neighbors >= 3)
        add_recommendation(out, WIFI_SHIELD_AP_RECOMMEND_CHANNEL_CONGESTED,
            WIFI_SHIELD_AP_EVIDENCE_OBSERVED_NEIGHBORS,
            observation_confidence(out, out->continuity_confidence));
    if (out->beacons >= 2 && (out->rssi_average <= -75 || out->rssi_max - out->rssi_min >= 15))
        add_recommendation(out,
            WIFI_SHIELD_AP_RECOMMEND_WEAK_OR_UNSTABLE_SIGNAL,
            WIFI_SHIELD_AP_EVIDENCE_RSSI_OBSERVATIONS,
            observation_confidence(out, out->continuity_confidence));
    if (out->epoch_changes)
        add_recommendation(out,
            WIFI_SHIELD_AP_RECOMMEND_TSF_EPOCH_CHANGE_OBSERVED,
            WIFI_SHIELD_AP_EVIDENCE_AP_TSF_EPOCH_CHANGE,
            observation_confidence(out, out->timing_confidence));
    if (p->validated_catalog_match)
        add_recommendation(out, WIFI_SHIELD_AP_RECOMMEND_FIRMWARE_REVIEW,
            WIFI_SHIELD_AP_EVIDENCE_VALIDATED_CATALOG_MATCH,
            WIFI_SHIELD_AP_CONFIDENCE_OBSERVED);
    if (out->interval_pairs) out->jitter_average_us = e->jitter_sum_us / out->interval_pairs;
    return true;
}
const char *wifi_shield_ap_recommendation_token(uint32_t recommendation)
{
    static const char *const tokens[] = {"disable_wps", "require_pmf", "prefer_wpa3_only",
        "review_transition_mode", "review_legacy_cipher", "channel_unstable",
        "channel_congested", "weak_or_unstable_signal",
        "tsf_epoch_change_observed", "firmware_review"};
    for (unsigned i = 0; i < sizeof(tokens) / sizeof(tokens[0]); ++i)
        if (recommendation == (UINT32_C(1) << i)) return tokens[i];
    return NULL;
}

const char *wifi_shield_ap_recommendation_evidence_token(
    wifi_shield_ap_recommendation_evidence_t evidence)
{
    static const char *const tokens[] = {NULL, "wps_advertised",
        "pmf_not_required", "wpa3_not_only", "transition_mode",
        "legacy_cipher", "channel_changes", "csa_activity",
        "observed_neighbors", "rssi_observations", "ap_tsf_epoch_change",
        "validated_catalog_match"};
    if ((unsigned)evidence >= sizeof(tokens) / sizeof(tokens[0])) return NULL;
    return tokens[evidence];
}

bool wifi_shield_ap_recommendation_detail_valid(
    const wifi_shield_ap_recommendation_detail_t *detail)
{
    if (detail == NULL ||
        detail->confidence < WIFI_SHIELD_AP_CONFIDENCE_OBSERVED ||
        detail->confidence > WIFI_SHIELD_AP_CONFIDENCE_LIMITED ||
        wifi_shield_ap_recommendation_token(detail->action) == NULL ||
        wifi_shield_ap_recommendation_evidence_token(detail->evidence) == NULL)
        return false;
    switch (detail->action) {
    case WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS:
        return detail->evidence == WIFI_SHIELD_AP_EVIDENCE_WPS_ADVERTISED;
    case WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF:
        return detail->evidence == WIFI_SHIELD_AP_EVIDENCE_PMF_NOT_REQUIRED;
    case WIFI_SHIELD_AP_RECOMMEND_PREFER_WPA3_ONLY:
        return detail->evidence == WIFI_SHIELD_AP_EVIDENCE_WPA3_NOT_ONLY;
    case WIFI_SHIELD_AP_RECOMMEND_REVIEW_TRANSITION_MODE:
        return detail->evidence == WIFI_SHIELD_AP_EVIDENCE_TRANSITION_MODE;
    case WIFI_SHIELD_AP_RECOMMEND_REVIEW_LEGACY_CIPHER:
        return detail->evidence == WIFI_SHIELD_AP_EVIDENCE_LEGACY_CIPHER;
    case WIFI_SHIELD_AP_RECOMMEND_CHANNEL_UNSTABLE:
        return detail->evidence == WIFI_SHIELD_AP_EVIDENCE_CHANNEL_CHANGES;
    case WIFI_SHIELD_AP_RECOMMEND_CHANNEL_CONGESTED:
        return detail->evidence ==
            WIFI_SHIELD_AP_EVIDENCE_OBSERVED_NEIGHBORS;
    case WIFI_SHIELD_AP_RECOMMEND_WEAK_OR_UNSTABLE_SIGNAL:
        return detail->evidence == WIFI_SHIELD_AP_EVIDENCE_RSSI_OBSERVATIONS;
    case WIFI_SHIELD_AP_RECOMMEND_TSF_EPOCH_CHANGE_OBSERVED:
        return detail->evidence ==
            WIFI_SHIELD_AP_EVIDENCE_AP_TSF_EPOCH_CHANGE;
    case WIFI_SHIELD_AP_RECOMMEND_FIRMWARE_REVIEW:
        return detail->evidence ==
            WIFI_SHIELD_AP_EVIDENCE_VALIDATED_CATALOG_MATCH;
    default: return false;
    }
}



