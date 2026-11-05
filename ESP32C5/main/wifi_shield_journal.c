#include "wifi_shield_journal.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static const char *const record_types[] = {"session_start", "event",
    "campaign_transition", "ap_health", "recommendation", "storage_degraded",
    "session_terminal", "session_uncertain"};
static const char *const sources[] = {"deauth", "wps", "sae", "trust", "pmkid"};
static const char *const events[] = {"deauth", "disassoc", "csa", "enrollment_activity",
    "retry_burst", "protocol_anomaly", "authentication_activity", "protocol_anomaly",
    "security_drift", "sequence"};
static const wifi_shield_source_t event_sources[] = {WIFI_SHIELD_SOURCE_DEAUTH,
    WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SOURCE_WPS,
    WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SOURCE_SAE,
    WIFI_SHIELD_SOURCE_SAE, WIFI_SHIELD_SOURCE_TRUST, WIFI_SHIELD_SOURCE_PMKID};
static const char *const threats[] = {"quiet", "watch", "attack", "critical"};
static const char *const campaign_confidence[] = {"full", "limited"};
static const char *const ap_confidence[] = {"none", "observed", "limited"};
static const char *const outcomes[] = {"stopped", "busy", "invalid", "timeout",
    "queue_overflow", "restore_failed", "output_failed", "no_mem"};
typedef struct {
    char line[WIFI_SHIELD_JOURNAL_LINE_MAX];
    size_t used;
    bool valid;
} builder_t;

static void append(builder_t *b, const char *format, ...)
{
    if (!b->valid) return;
    va_list args;
    va_start(args, format);
    int n = vsnprintf(b->line + b->used, sizeof(b->line) - b->used, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= sizeof(b->line) - b->used) b->valid = false;
    else b->used += (size_t)n;
}

static bool unicast(const uint8_t mac[6])
{
    unsigned any = 0;
    for (size_t i = 0; i < 6; ++i) any |= mac[i];
    return any != 0 && !(mac[0] & 1U);
}

static bool valid_path(const char path[WIFI_SHIELD_JOURNAL_PATH_MAX])
{
    for (size_t i = 0; i < WIFI_SHIELD_JOURNAL_PATH_MAX; ++i) {
        if (!path[i]) return true;
        if ((unsigned char)path[i] > 127U) return false;
    }
    return false;
}

static bool valid_health(const wifi_shield_ap_health_snapshot_t *s)
{
    if ((unsigned)s->continuity_confidence > WIFI_SHIELD_AP_CONFIDENCE_LIMITED ||
        (unsigned)s->timing_confidence > WIFI_SHIELD_AP_CONFIDENCE_LIMITED ||
        (s->recommendations & ~WIFI_SHIELD_JOURNAL_RECOMMENDATION_MASK) ||
        s->recommendation_count > WIFI_SHIELD_AP_RECOMMENDATION_MAX ||
        s->rssi_min < -128 || s->rssi_max > 0 ||
        s->rssi_min > s->rssi_average || s->rssi_average > s->rssi_max ||
        s->jitter_average_us > s->jitter_max_us) return false;
    uint32_t mask = 0U, previous = 0U;
    for (size_t i = 0U; i < s->recommendation_count; ++i) {
        const wifi_shield_ap_recommendation_detail_t *detail =
            &s->recommendation_details[i];
        if (!wifi_shield_ap_recommendation_detail_valid(detail) ||
            (i != 0U && detail->action <= previous) ||
            (mask & detail->action) != 0U) return false;
        mask |= detail->action;
        previous = detail->action;
    }
    return mask == s->recommendations;
}

static bool valid_record(const wifi_shield_journal_record_t *r)
{
    if (!r || (unsigned)r->type >= sizeof(record_types)/sizeof(*record_types) ||
        !r->boot_id || !r->session_id || !r->sequence ||
        (r->has_bssid && !unicast(r->bssid)) ||
        (r->gps_time_trusted ? r->epoch_ms == 0U :
         (r->epoch_ms != 0U || r->time_uncertainty_ms != 0U))) return false;
    switch (r->time.quality) {
    case WIFI_SHIELD_TIME_NONE:
        if (r->time.ap_epoch || r->time.ap_tsf_us || r->time.uncertainty_us) return false;
        break;
    case WIFI_SHIELD_TIME_EXACT:
        if (!r->time.ap_epoch || r->time.uncertainty_us) return false;
        break;
    case WIFI_SHIELD_TIME_ESTIMATED:
        if (!r->time.ap_epoch) return false;
        break;
    default: return false;
    }
    switch (r->type) {
    case WIFI_SHIELD_JOURNAL_SESSION_START:
        return r->target_count && r->target_count <= WIFI_SHIELD_TARGET_MAX;
    case WIFI_SHIELD_JOURNAL_EVENT:
        return (unsigned)r->event_type < sizeof(events)/sizeof(*events) &&
            r->event_source == event_sources[r->event_type] &&
            (r->event_count == 0U ||
             (r->has_bssid && r->event_first_boot_us <=
                  r->event_last_boot_us &&
              r->event_last_boot_us - r->event_first_boot_us <
                  WIFI_SHIELD_JOURNAL_AGGREGATE_WINDOW_US &&
              r->time.boot_us == r->event_last_boot_us));
    case WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION:
        return r->has_bssid && r->campaign.id &&
            !memcmp(r->campaign.bssid, r->bssid, 6) &&
            (unsigned)r->campaign.from <= WIFI_SHIELD_THREAT_CRITICAL &&
            (unsigned)r->campaign.to <= WIFI_SHIELD_THREAT_CRITICAL &&
            r->campaign.from < r->campaign.to && r->campaign.sources &&
            !(r->campaign.sources & ~((UINT32_C(1) << WIFI_SHIELD_SOURCE_COUNT) - 1)) &&
            (unsigned)r->campaign.confidence <= WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED &&
            wifi_shield_campaign_reason_valid(r->campaign.to,
                r->campaign.reason, r->campaign.sources);
    case WIFI_SHIELD_JOURNAL_AP_HEALTH:
        return r->has_bssid && valid_health(&r->ap_health) &&
            r->recommendation_set_index == 0U &&
            r->recommendation_set_count == r->ap_health.recommendation_count &&
            (r->recommendation_set_count == 0U ||
             r->recommendation_set_revision != 0U);
    case WIFI_SHIELD_JOURNAL_RECOMMENDATION:
        return r->has_bssid &&
            r->recommendation_set_revision != 0U &&
            r->recommendation_set_count != 0U &&
            r->recommendation_set_count <= WIFI_SHIELD_AP_RECOMMENDATION_MAX &&
            r->recommendation_set_index < r->recommendation_set_count &&
            wifi_shield_ap_recommendation_detail_valid(&r->recommendation);
    case WIFI_SHIELD_JOURNAL_STORAGE_DEGRADED:
        return r->storage.state == WIFI_SHIELD_JOURNAL_DEGRADED && valid_path(r->storage.path);
    case WIFI_SHIELD_JOURNAL_SESSION_TERMINAL:
    case WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN:
        return (unsigned)r->outcome < sizeof(outcomes)/sizeof(*outcomes);
    default: return false;
    }
}

static void escaped_path(builder_t *b, const char *path)
{
    append(b, "\"");
    for (size_t i = 0; path[i]; ++i) {
        unsigned char c = (unsigned char)path[i];
        switch (c) {
        case '"': append(b, "\\\""); break;
        case '\\': append(b, "\\\\"); break;
        case '\n': append(b, "\\n"); break;
        case '\r': append(b, "\\r"); break;
        case '\t': append(b, "\\t"); break;
        case '\b': append(b, "\\b"); break;
        case '\f': append(b, "\\f"); break;
        default:
            if (c < 32 || c == 127) append(b, "\\u%04x", (unsigned)c);
            else append(b, "%c", (int)c);
        }
    }
    append(b, "\"");
}

static void health(builder_t *b, const wifi_shield_ap_health_snapshot_t *s)
{
    append(b, ",\"beacons\":%" PRIu32 ",\"sequence_gaps\":%" PRIu32
        ",\"interval_pairs\":%" PRIu32 ",\"rssi_average\":%d,\"rssi_min\":%d,\"rssi_max\":%d"
        ",\"jitter_avg_us\":%" PRIu64 ",\"jitter_max_us\":%" PRIu64
        ",\"epoch_changes\":%" PRIu32 ",\"channel_changes\":%" PRIu32 ",\"csa_events\":%" PRIu32
        ",\"retry_beacons\":%" PRIu32 ",\"retry_events\":%" PRIu32
        ",\"deauth_events\":%" PRIu32 ",\"disassoc_events\":%" PRIu32
        ",\"rx_drops\":%" PRIu32 ",\"event_drops\":%" PRIu32 ",\"journal_drops\":%" PRIu32
        ",\"sampled\":%s,\"same_neighbors\":%" PRIu32
        ",\"overlap_neighbors\":%" PRIu32
        ",\"continuity_conf\":\"%s\",\"timing_conf\":\"%s\"",
        s->beacons, s->sequence_gaps, s->interval_pairs,
        (int)s->rssi_average, (int)s->rssi_min, (int)s->rssi_max,
        s->jitter_average_us, s->jitter_max_us, s->epoch_changes,
        s->channel_changes, s->csa_events, s->retry_beacons, s->retry_events,
        s->deauth_events, s->disassoc_events, s->rx_drops, s->event_drops,
        s->journal_drops, s->sampled ? "true" : "false",
        s->same_channel_neighbors, s->overlapping_channel_neighbors,
        ap_confidence[s->continuity_confidence], ap_confidence[s->timing_confidence]);
}

int wifi_shield_journal_encode(char *out, size_t capacity,
                               const wifi_shield_journal_record_t *r)
{
    if (!out || !valid_record(r)) return -1;
    builder_t b = {.used = 0, .valid = true};
    append(&b, "{\"schema\":1,\"type\":\"%s\",\"boot_id\":\"%08" PRIx32
        "\",\"session_id\":%" PRIu32 ",\"sequence\":%" PRIu64 ",\"boot_us\":%" PRIu64,
        record_types[r->type], r->boot_id, r->session_id, r->sequence, r->time.boot_us);
    if (r->has_bssid)
        append(&b, ",\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\"",
            (unsigned)r->bssid[0], (unsigned)r->bssid[1], (unsigned)r->bssid[2],
            (unsigned)r->bssid[3], (unsigned)r->bssid[4], (unsigned)r->bssid[5]);
    if (r->time.quality != WIFI_SHIELD_TIME_NONE)
        append(&b, ",\"ap_tsf_us\":%" PRIu64 ",\"ap_epoch\":%" PRIu32
            ",\"ap_tsf_quality\":\"%s\",\"ap_tsf_uncertainty_us\":%" PRIu64,
            r->time.ap_tsf_us, r->time.ap_epoch,
            r->time.quality == WIFI_SHIELD_TIME_EXACT ? "exact" : "estimated", r->time.uncertainty_us);
    if (r->gps_time_trusted)
        append(&b, ",\"epoch_ms\":%" PRIu64
            ",\"time_source\":\"gps\",\"time_uncertainty_ms\":%" PRIu32,
            r->epoch_ms, r->time_uncertainty_ms);
    switch (r->type) {
    case WIFI_SHIELD_JOURNAL_SESSION_START:
        append(&b, ",\"targets\":%zu", r->target_count); break;
    case WIFI_SHIELD_JOURNAL_EVENT:
        append(&b, ",\"source\":\"%s\",\"event\":\"%s\"",
               sources[r->event_source], events[r->event_type]);
        if (r->event_count != 0U)
            append(&b, ",\"count\":%" PRIu32
                ",\"first_boot_us\":%" PRIu64
                ",\"last_boot_us\":%" PRIu64
                ",\"window_us\":%" PRIu64,
                r->event_count, r->event_first_boot_us,
                r->event_last_boot_us,
                r->event_last_boot_us - r->event_first_boot_us);
        break;
    case WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION:
        append(&b, ",\"campaign_id\":%" PRIu64 ",\"from\":\"%s\",\"to\":\"%s\",\"reason\":\"%s\",\"sources\":%" PRIu32
            ",\"confidence\":\"%s\"", r->campaign.id, threats[r->campaign.from], threats[r->campaign.to],
            wifi_shield_campaign_reason_token(r->campaign.reason),
            r->campaign.sources, campaign_confidence[r->campaign.confidence]); break;
    case WIFI_SHIELD_JOURNAL_AP_HEALTH:
        health(&b, &r->ap_health);
        append(&b, ",\"rec_rev\":%" PRIu32
            ",\"recommendation_count\":%u",
            r->recommendation_set_revision,
            (unsigned)r->recommendation_set_count);
        break;
    case WIFI_SHIELD_JOURNAL_RECOMMENDATION:
        append(&b, ",\"rec_rev\":%" PRIu32
            ",\"rec_index\":%u,\"rec_count\":%u"
            ",\"action\":\"%s\",\"evidence\":\"%s\",\"confidence\":\"%s\"",
            r->recommendation_set_revision,
            (unsigned)r->recommendation_set_index,
            (unsigned)r->recommendation_set_count,
            wifi_shield_ap_recommendation_token(r->recommendation.action),
            wifi_shield_ap_recommendation_evidence_token(
                r->recommendation.evidence),
            ap_confidence[r->recommendation.confidence]);
        break;
    case WIFI_SHIELD_JOURNAL_STORAGE_DEGRADED:
        append(&b, ",\"state\":\"degraded\",\"path\":"); escaped_path(&b, r->storage.path);
        append(&b, ",\"bytes_written\":%" PRIu64 ",\"records_written\":%" PRIu32
            ",\"failures\":%" PRIu32 ",\"dropped\":%" PRIu32,
            r->storage.bytes_written, r->storage.records_written,
            r->storage.failures, r->storage.dropped); break;
    case WIFI_SHIELD_JOURNAL_SESSION_TERMINAL:
    case WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN:
        append(&b, ",\"outcome\":\"%s\"", outcomes[r->outcome]); break;
    }
    append(&b, "}\n");
    if (!b.valid || b.used >= capacity) return -1;
    memcpy(out, b.line, b.used + 1);
    return (int)b.used;
}
