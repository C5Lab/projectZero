#include "wifi_shield_wire.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    wifi_shield_source_t source;
    wifi_shield_severity_t severity;
    const char *name;
} event_kind_t;

static const event_kind_t kinds[] = {
    {WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, "deauth"},
    {WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, "disassoc"},
    {WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_INFO, "csa_announcement"},
    {WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, "enrollment_activity"},
    {WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_WARN, "retry_burst"},
    {WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_ALERT, "protocol_anomaly"},
    {WIFI_SHIELD_SOURCE_SAE, WIFI_SHIELD_SEVERITY_INFO, "authentication_activity"},
    {WIFI_SHIELD_SOURCE_SAE, WIFI_SHIELD_SEVERITY_ALERT, "protocol_anomaly"},
    {WIFI_SHIELD_SOURCE_TRUST, WIFI_SHIELD_SEVERITY_ALERT, "security_drift"},
    {WIFI_SHIELD_SOURCE_PMKID, WIFI_SHIELD_SEVERITY_INFO, "sequence"}
};
static const char *const sources[] = {"deauth", "wps", "sae", "trust", "pmkid"};
static const char *const severities[] = {"info", "warn", "alert"};
static const char *const messages[] = {
    "unknown", "M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8", "ACK", "NACK", "DONE"
};
static const char *const outcomes[] = {
    "stopped", "busy", "invalid", "timeout", "queue_overflow",
    "restore_failed", "output_failed", "no_mem"
};

static int publish(char *out, size_t capacity, const char *line, int n)
{
    if (out == NULL || n < 0 || (unsigned)n >= WIFI_SHIELD_LINE_MAX ||
        (size_t)n >= capacity)
        return -1;
    memcpy(out, line, (size_t)n + 1);
    return n;
}

static bool unicast(const uint8_t mac[6])
{
    unsigned any = 0;
    for (size_t i = 0; i < 6; ++i) any |= mac[i];
    return any != 0 && (mac[0] & 1U) == 0;
}

static bool valid_status(const wifi_shield_status_t *s)
{
    if (s == NULL || s->target_count > WIFI_SHIELD_TARGET_MAX ||
        s->channel_count > s->target_count ||
        (s->pmkid_decoy && !s->active_defence) ||
        (s->protect_all && (!s->active_defence || !s->pmkid_decoy ||
                            !s->multi_vector)))
        return false;
    if (s->target_count == 0)
        return s->channel_count == 0 && s->current_channel == 0 && !s->running;
    if (s->channel_count == 0) return false;
    bool current_found = s->current_channel == 0 && !s->running;
    for (size_t i = 0; i < s->channel_count; ++i) {
        if (s->channels[i] == 0) return false;
        if (s->channels[i] == s->current_channel) current_found = true;
        for (size_t j = 0; j < i; ++j)
            if (s->channels[i] == s->channels[j]) return false;
    }
    return current_found;
}

static const char *coverage(const wifi_shield_status_t *s)
{
    return s->channel_count == 0 ? "none" :
           s->channel_count == 1 ? "continuous" : "sampled";
}

static const char *mode(const wifi_shield_status_t *s)
{
    return s->protect_all ? "protect-all" :
           s->active_defence ? "active" : "passive";
}

int wifi_shield_format_armed(char *out, size_t capacity, const wifi_shield_status_t *s)
{
    if (!valid_status(s) || !s->running || s->stopping) return -1;
    char line[WIFI_SHIELD_LINE_MAX];
    int n = snprintf(line, sizeof(line),
        "[SHIELD/1] ARMED MODE=%.11s TARGETS=%zu CHANNELS=",
        mode(s), s->target_count);
    if (n < 0 || (size_t)n >= sizeof(line)) return -1;
    size_t used = (size_t)n;
    for (size_t i = 0; i < s->channel_count; ++i) {
        n = snprintf(line + used, sizeof(line) - used, "%.1s%u",
                     i == 0 ? "" : ",", (unsigned)s->channels[i]);
        if (n < 0 || (size_t)n >= sizeof(line) - used) return -1;
        used += (size_t)n;
    }
    n = s->protect_all ?
        snprintf(line + used, sizeof(line) - used,
                 " COVERAGE=%.10s ACTIVE=deauth,pmkid PASSIVE=wps,sae,trust\r\n",
                 coverage(s)) :
        snprintf(line + used, sizeof(line) - used,
                 " COVERAGE=%.10s\r\n", coverage(s));
    if (n < 0 || (size_t)n >= sizeof(line) - used) return -1;
    return publish(out, capacity, line, (int)used + n);
}

int wifi_shield_format_target(char *out, size_t capacity,
                              const wifi_shield_target_t *target,
                              size_t ordinal, size_t total)
{
    if (target == NULL || !unicast(target->bssid) || target->channel == 0U ||
        total == 0U || total > WIFI_SHIELD_TARGET_MAX || ordinal == 0U ||
        ordinal > total)
        return -1;
    const char *terminator = memchr(target->ssid, '\0', sizeof(target->ssid));
    if (terminator == NULL) return -1;
    size_t ssid_length = (size_t)(terminator - target->ssid);

    char line[WIFI_SHIELD_LINE_MAX];
    int n = snprintf(line, sizeof(line),
                     "[SHIELD/1] TARGET N=%zu/%zu SSID=\"",
                     ordinal, total);
    if (n < 0 || (size_t)n >= sizeof(line)) return -1;
    size_t used = (size_t)n;
    if (ssid_length == 0U) {
        static const char hidden[] = "<hidden>";
        if (used + sizeof(hidden) - 1U >= sizeof(line)) return -1;
        memcpy(line + used, hidden, sizeof(hidden) - 1U);
        used += sizeof(hidden) - 1U;
    } else {
        static const char hex[] = "0123456789abcdef";
        for (size_t i = 0U; i < ssid_length; ++i) {
            unsigned char byte = (unsigned char)target->ssid[i];
            if (byte == '"' || byte == '\\') {
                if (used + 2U >= sizeof(line)) return -1;
                line[used++] = '\\';
                line[used++] = (char)byte;
            } else if (byte >= 0x20U && byte <= 0x7eU) {
                if (used + 1U >= sizeof(line)) return -1;
                line[used++] = (char)byte;
            } else {
                if (used + 4U >= sizeof(line)) return -1;
                line[used++] = '\\';
                line[used++] = 'x';
                line[used++] = hex[byte >> 4U];
                line[used++] = hex[byte & 0x0fU];
            }
        }
    }
    n = snprintf(line + used, sizeof(line) - used,
        "\" BSSID=%02x:%02x:%02x:%02x:%02x:%02x CH=%u\r\n",
        (unsigned)target->bssid[0], (unsigned)target->bssid[1],
        (unsigned)target->bssid[2], (unsigned)target->bssid[3],
        (unsigned)target->bssid[4], (unsigned)target->bssid[5],
        (unsigned)target->channel);
    if (n < 0 || (size_t)n >= sizeof(line) - used) return -1;
    return publish(out, capacity, line, (int)used + n);
}

int wifi_shield_format_event(char *out, size_t capacity, const wifi_shield_event_t *e)
{
    if (e == NULL || (unsigned)e->type >= sizeof(kinds)/sizeof(*kinds) ||
        (unsigned)e->wps_message >= sizeof(messages)/sizeof(*messages) ||
        e->count == 0 || e->channel == 0 || !unicast(e->bssid)) return -1;
    const event_kind_t *kind = &kinds[e->type];
    if (e->source != kind->source || e->severity != kind->severity) return -1;
    if ((e->source == WIFI_SHIELD_SOURCE_WPS || e->source == WIFI_SHIELD_SOURCE_SAE ||
         e->source == WIFI_SHIELD_SOURCE_PMKID) &&
        (!unicast(e->station) || memcmp(e->station, e->bssid, 6) == 0)) return -1;
    char line[WIFI_SHIELD_LINE_MAX];
    const char *prefix = e->type == WIFI_SHIELD_EVENT_CSA ?
        "[SHIELD/2]" : "[SHIELD/1]";
    int n = snprintf(line, sizeof(line),
        "%s %.5s SOURCE=%.6s TYPE=%.24s BSSID=%02x:%02x:%02x:%02x:%02x:%02x CH=%u SEVERITY=%.5s COUNT=%" PRIu32 " WINDOW_MS=%" PRIu32,
        prefix, e->severity == WIFI_SHIELD_SEVERITY_INFO ? "EVENT" : "ALERT",
        sources[e->source], kind->name,
        (unsigned)e->bssid[0], (unsigned)e->bssid[1], (unsigned)e->bssid[2],
        (unsigned)e->bssid[3], (unsigned)e->bssid[4], (unsigned)e->bssid[5],
        (unsigned)e->channel, severities[e->severity], e->count, e->window_ms);
    if (n < 0 || (size_t)n >= sizeof(line)) return -1;
    size_t used = (size_t)n;
    n = e->source == WIFI_SHIELD_SOURCE_WPS ?
        snprintf(line + used, sizeof(line) - used, " MESSAGE=%.7s\r\n", messages[e->wps_message]) :
        snprintf(line + used, sizeof(line) - used, "\r\n");
    if (n < 0 || (size_t)n >= sizeof(line) - used) return -1;
    return publish(out, capacity, line, (int)used + n);
}

static int format_snapshot(char *out, size_t capacity, const wifi_shield_status_t *s,
                           const char *outcome)
{
    if (!valid_status(s)) return -1;
    char line[WIFI_SHIELD_LINE_MAX];
    int n = outcome == NULL ? snprintf(line, sizeof(line), "[SHIELD/1] STATUS") :
        snprintf(line, sizeof(line), "[SHIELD/1] TERMINAL OUTCOME=%.14s", outcome);
    if (n < 0 || (size_t)n >= sizeof(line)) return -1;
    size_t used = (size_t)n;
    const char *policy = s->protect_all ?
        " ACTIVE=deauth,pmkid PASSIVE=wps,sae,trust" : "";
    n = snprintf(line + used, sizeof(line) - used,
        " RUNNING=%u MODE=%.11s%.48s TARGETS=%zu CURRENT_CH=%u COVERAGE=%.10s DEAUTH=%" PRIu32
        " WPS=%" PRIu32 " SAE=%" PRIu32 " TRUST=%" PRIu32 " ALERTS=%" PRIu32
        " RX_DROPS=%" PRIu32 " EVENT_DROPS=%" PRIu32 " OUTPUT_FAILURES=%" PRIu32 "\r\n",
        (unsigned)s->running, mode(s), policy, s->target_count,
        (unsigned)s->current_channel, coverage(s), s->source_events[0], s->source_events[1],
        s->source_events[2], s->source_events[3], s->alerts, s->rx_drops,
        s->event_drops, s->output_failures);
    if (n < 0 || (size_t)n >= sizeof(line) - used) return -1;
    return publish(out, capacity, line, (int)used + n);
}

int wifi_shield_format_status(char *out, size_t capacity, const wifi_shield_status_t *s)
{
    return format_snapshot(out, capacity, s, NULL);
}

int wifi_shield_format_terminal(char *out, size_t capacity,
                               const wifi_shield_status_t *s, const char *outcome)
{
    if (outcome == NULL) return -1;
    /* Bound reads before comparing. No caller text is ever interpolated. */
    size_t length = 0;
    while (length < 15 && outcome[length] != '\0') ++length;
    if (length == 15) return -1;
    for (size_t i = 0; i < sizeof(outcomes)/sizeof(*outcomes); ++i)
        if (strlen(outcomes[i]) == length && memcmp(outcome, outcomes[i], length) == 0)
            return format_snapshot(out, capacity, s, outcomes[i]);
    return -1;
}

/* V2 shares the real UART record bound; V1 publish() and bytes are unchanged. */
static const char *const v2_threats[] = {"none", "watch", "attack", "critical"};
static const char *const v2_campaign_confidence[] = {"full", "limited"};
static const char *const v2_ap_confidence[] = {"none", "observed", "limited"};
static const char *const v2_states[] = {"unavailable", "active", "degraded",
    "quota_reached", "finalized", "incomplete"};
static int publish_v2(char *out, size_t capacity, const char *line, int n)
{
    if (!out || n < 0 || (unsigned)n >= WIFI_SHIELD_LINE_MAX ||
        (size_t)n >= capacity)
        return -1;
    memcpy(out, line, (size_t)n + 1);
    return n;
}

int wifi_shield_format_campaign_report(char *out, size_t capacity,
                                       const wifi_shield_campaign_snapshot_t *s)
{
    if (!s || !s->id || !unicast(s->bssid) ||
        !s->sources || (s->sources & ~((UINT32_C(1) << WIFI_SHIELD_SOURCE_COUNT) - 1)) ||
        (unsigned)s->threat > WIFI_SHIELD_THREAT_CRITICAL || s->threat == WIFI_SHIELD_THREAT_NONE ||
        (unsigned)s->session_peak > WIFI_SHIELD_THREAT_CRITICAL ||
        s->session_peak < s->threat ||
        (unsigned)s->confidence > WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED ||
        !wifi_shield_campaign_reason_valid(s->threat,
            s->last_transition_reason, s->sources) ||
        s->last_us < s->first_us) return -1;
    char line[WIFI_SHIELD_V2_LINE_MAX];
    int n = snprintf(line, sizeof(line),
        "[SHIELD/2] CAMPAIGN ID=%" PRIu64 " BSSID=%02x:%02x:%02x:%02x:%02x:%02x ACTIVE=%u THREAT=%s"
        " SESSION_PEAK=%s COMPLETED=%" PRIu32 " REASON=%s"
        " SOURCES=%" PRIu32 " FIRST_US=%" PRIu64 " LAST_US=%" PRIu64 " CONFIDENCE=%s"
        " SAMPLED=%u"
        " RX_DROPS=%" PRIu32 " EVENT_DROPS=%" PRIu32 " OUTPUT_FAILURES=%" PRIu32
        " JOURNAL_DROPS=%" PRIu32 "\r\n",
        s->id, (unsigned)s->bssid[0], (unsigned)s->bssid[1], (unsigned)s->bssid[2],
        (unsigned)s->bssid[3], (unsigned)s->bssid[4], (unsigned)s->bssid[5],
        (unsigned)s->active, v2_threats[s->threat],
        v2_threats[s->session_peak], s->completed_campaigns,
        wifi_shield_campaign_reason_token(s->last_transition_reason),
        s->sources, s->first_us, s->last_us,
        v2_campaign_confidence[s->confidence], (unsigned)s->sampled,
        s->rx_drops, s->event_drops,
        s->output_failures, s->journal_drops);
    return publish_v2(out, capacity, line, n);
}

static bool valid_recommendations(
    const wifi_shield_ap_health_snapshot_t *snapshot)
{
    if (snapshot->recommendation_count > WIFI_SHIELD_AP_RECOMMENDATION_MAX)
        return false;
    uint32_t mask = 0U, previous = 0U;
    for (size_t i = 0U; i < snapshot->recommendation_count; ++i) {
        const wifi_shield_ap_recommendation_detail_t *detail =
            &snapshot->recommendation_details[i];
        if (!wifi_shield_ap_recommendation_detail_valid(detail) ||
            (i != 0U && detail->action <= previous) ||
            (mask & detail->action) != 0U) return false;
        mask |= detail->action;
        previous = detail->action;
    }
    return mask == snapshot->recommendations;
}

int wifi_shield_format_ap_health(char *out, size_t capacity, const uint8_t bssid[6],
                                 const wifi_shield_ap_health_snapshot_t *s)
{
    if (!s || !bssid || !unicast(bssid) ||
        (unsigned)s->continuity_confidence > WIFI_SHIELD_AP_CONFIDENCE_LIMITED ||
        (unsigned)s->timing_confidence > WIFI_SHIELD_AP_CONFIDENCE_LIMITED ||
        (s->recommendations & ~WIFI_SHIELD_JOURNAL_RECOMMENDATION_MASK) ||
        !valid_recommendations(s) ||
        s->rssi_min < -128 || s->rssi_max > 0 || s->rssi_min > s->rssi_average ||
        s->rssi_average > s->rssi_max || s->jitter_average_us > s->jitter_max_us) return -1;
    char line[WIFI_SHIELD_V2_LINE_MAX];
    int n = snprintf(line, sizeof(line),
        "[SHIELD/2] AP_HEALTH BSSID=%02x:%02x:%02x:%02x:%02x:%02x BEACONS=%" PRIu32
        " SEQ_GAPS=%" PRIu32 " EPOCH_CHANGES=%" PRIu32
        " CHANNEL_CHANGES=%" PRIu32 " CSA_EVENTS=%" PRIu32
        " RSSI_AVG=%d RSSI_MIN=%d RSSI_MAX=%d"
        " JITTER_AVG_US=%" PRIu64 " JITTER_MAX_US=%" PRIu64 " CONTINUITY=%s TIMING=%s"
        " SAMPLED=%u RX_DROPS=%" PRIu32 " EVENT_DROPS=%" PRIu32 " JOURNAL_DROPS=%" PRIu32
        " RECOMMENDATIONS=%u\r\n",
        (unsigned)bssid[0], (unsigned)bssid[1], (unsigned)bssid[2],
        (unsigned)bssid[3], (unsigned)bssid[4], (unsigned)bssid[5],
        s->beacons, s->sequence_gaps, s->epoch_changes, s->channel_changes,
        s->csa_events, (int)s->rssi_average, (int)s->rssi_min, (int)s->rssi_max,
        s->jitter_average_us, s->jitter_max_us, v2_ap_confidence[s->continuity_confidence],
        v2_ap_confidence[s->timing_confidence], (unsigned)s->sampled,
        s->rx_drops, s->event_drops, s->journal_drops,
        (unsigned)s->recommendation_count);
    return publish_v2(out, capacity, line, n);
}

int wifi_shield_format_recommendation(char *out, size_t capacity,
    const uint8_t bssid[6],
    const wifi_shield_ap_recommendation_detail_t *detail)
{
    if (!bssid || !unicast(bssid) ||
        !wifi_shield_ap_recommendation_detail_valid(detail)) return -1;
    const char *action = wifi_shield_ap_recommendation_token(detail->action);
    const char *evidence = wifi_shield_ap_recommendation_evidence_token(
        detail->evidence);
    char line[WIFI_SHIELD_LINE_MAX];
    int n = snprintf(line, sizeof(line),
        "[SHIELD/2] RECOMMENDATION BSSID=%02x:%02x:%02x:%02x:%02x:%02x"
        " ACTION=%s EVIDENCE=%s CONFIDENCE=%s\r\n",
        (unsigned)bssid[0], (unsigned)bssid[1], (unsigned)bssid[2],
        (unsigned)bssid[3], (unsigned)bssid[4], (unsigned)bssid[5],
        action, evidence, v2_ap_confidence[detail->confidence]);
    return publish_v2(out, capacity, line, n);
}

static bool valid_log(const wifi_shield_journal_status_t *s)
{
    if (!s || (unsigned)s->state >= sizeof(v2_states)/sizeof(*v2_states)) return false;
    for (size_t i = 0; i < sizeof(s->path); ++i) {
        unsigned char c = (unsigned char)s->path[i];
        if (!c) return true;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '/' || c == '.' || c == '-' || c == '_')) return false;
    }
    return false;
}

static int format_log(char *out, size_t capacity, const wifi_shield_journal_status_t *s,
                       bool degraded)
{
    if (!out || !valid_log(s) ||
        (s->time_sources & ~WIFI_SHIELD_JOURNAL_TIME_MASK) != 0U ||
        (s->time_sources & WIFI_SHIELD_JOURNAL_TIME_MONOTONIC) == 0U ||
        (s->state == WIFI_SHIELD_JOURNAL_ACTIVE &&
         (s->path[0] == '\0' || (s->path[0] == '-' && s->path[1] == '\0'))) ||
        (degraded && s->state != WIFI_SHIELD_JOURNAL_DEGRADED)) return -1;
    if (degraded && !s->degraded_notice_pending) return 0;
    char time[32];
    size_t used = 0U;
    if (s->time_sources == 0U) {
        memcpy(time, "none", 5U);
    } else {
        static const struct { uint32_t bit; const char *token; } parts[] = {
            {WIFI_SHIELD_JOURNAL_TIME_MONOTONIC, "monotonic"},
            {WIFI_SHIELD_JOURNAL_TIME_AP_TSF, "ap_tsf"},
            {WIFI_SHIELD_JOURNAL_TIME_GPS, "gps"},
        };
        for (size_t i = 0U; i < sizeof(parts) / sizeof(parts[0]); ++i) {
            if ((s->time_sources & parts[i].bit) == 0U) continue;
            int wrote = snprintf(time + used, sizeof(time) - used, "%s%s",
                used == 0U ? "" : "+", parts[i].token);
            if (wrote < 0 || (size_t)wrote >= sizeof(time) - used) return -1;
            used += (size_t)wrote;
        }
    }
    char line[WIFI_SHIELD_LINE_MAX];
    int n = snprintf(line, sizeof(line),
        "[SHIELD/2] %s STATE=%s PATH=%s BYTES=%" PRIu64 " RECORDS=%" PRIu32
        " QUEUE_HIGH=%" PRIu32 " DROPS=%" PRIu32 " FAILURES=%" PRIu32
        " ADMISSION_DROPS=%" PRIu32 " ENCODING_FAILURES=%" PRIu32
        " WRITE_FAILURES=%" PRIu32 " SYNC_FAILURES=%" PRIu32
        " FINALIZATION_FAILURES=%" PRIu32 " TIME=%s\r\n",
        degraded ? "STORAGE" : "LOG", v2_states[s->state], s->path[0] ? s->path : "-",
        s->bytes_written, s->records_written, s->queue_high_water, s->dropped,
        s->failures, s->admission_drops, s->encoding_failures,
        s->write_failures, s->sync_failures, s->finalization_failures, time);
    return publish_v2(out, capacity, line, n);
}

int wifi_shield_format_log_status(char *out, size_t capacity, const wifi_shield_journal_status_t *s)
{ return format_log(out, capacity, s, false); }
int wifi_shield_format_storage_degraded(char *out, size_t capacity, const wifi_shield_journal_status_t *s)
{ return format_log(out, capacity, s, true); }
