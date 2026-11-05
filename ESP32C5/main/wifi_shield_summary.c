#include "wifi_shield_summary.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char *bytes;
    size_t capacity;
    size_t used;
    bool valid;
} summary_builder_t;

static void append(summary_builder_t *builder, const char *format, ...)
{
    if (!builder->valid) return;
    if (builder->used >= builder->capacity) {
        builder->valid = false;
        return;
    }
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(builder->bytes + builder->used,
        builder->capacity - builder->used, format, arguments);
    va_end(arguments);
    if (length < 0 || (size_t)length >= builder->capacity - builder->used) {
        builder->valid = false;
        return;
    }
    builder->used += (size_t)length;
}

static uint32_t saturating_add(uint32_t left, uint32_t right)
{
    return right > UINT32_MAX - left ? UINT32_MAX : left + right;
}

static void sanitized_ssid(char destination[33], const char source[33])
{
    size_t i = 0U;
    for (; i < 32U && source[i] != '\0'; ++i) {
        unsigned char value = (unsigned char)source[i];
        destination[i] = value >= 0x20U && value <= 0x7eU ?
            (char)value : '?';
    }
    destination[i] = '\0';
}

bool wifi_shield_summary_init(wifi_shield_summary_t *summary,
    const wifi_shield_summary_metadata_t *metadata,
    uint32_t boot_id, uint32_t session_id)
{
    if (summary == NULL || metadata == NULL || boot_id == 0U ||
        session_id == 0U || metadata->target_count == 0U ||
        metadata->target_count > WIFI_SHIELD_TARGET_MAX) return false;
    memset(summary, 0, sizeof(*summary));
    summary->metadata = *metadata;
    sanitized_ssid(summary->metadata.primary_ssid, metadata->primary_ssid);
    summary->boot_id = boot_id;
    summary->session_id = session_id;
    return true;
}

void wifi_shield_summary_observe(wifi_shield_summary_t *summary,
    const wifi_shield_journal_record_t *record)
{
    if (summary == NULL || record == NULL ||
        record->boot_id != summary->boot_id ||
        record->session_id != summary->session_id) return;
    if (!summary->metadata.primary_target_valid && record->has_bssid) {
        summary->metadata.primary_target_valid = true;
        memcpy(summary->metadata.primary_bssid, record->bssid, 6U);
    }
    switch (record->type) {
    case WIFI_SHIELD_JOURNAL_SESSION_START:
        summary->started = true;
        summary->started_us = record->time.boot_us;
        if (summary->metadata.target_count == 0U)
            summary->metadata.target_count = record->target_count;
        break;
    case WIFI_SHIELD_JOURNAL_EVENT:
        if ((unsigned)record->event_type <
            sizeof(summary->event_counts) / sizeof(summary->event_counts[0])) {
            uint32_t count = record->event_count == 0U ? 1U :
                                                       record->event_count;
            summary->event_counts[record->event_type] = saturating_add(
                summary->event_counts[record->event_type], count);
        }
        break;
    case WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION:
        if (record->campaign.to > summary->threat) {
            summary->threat = record->campaign.to;
            summary->reason = record->campaign.reason;
        }
        break;
    case WIFI_SHIELD_JOURNAL_AP_HEALTH:
        if (summary->metadata.primary_target_valid && record->has_bssid &&
            memcmp(record->bssid, summary->metadata.primary_bssid, 6U) == 0) {
            summary->ap_health = record->ap_health;
            summary->ap_health_valid = true;
        }
        break;
    case WIFI_SHIELD_JOURNAL_SESSION_TERMINAL:
        summary->terminal = true;
        summary->ended_us = record->time.boot_us;
        summary->outcome = record->outcome;
        break;
    default:
        break;
    }
}

static const char *outcome_token(wifi_shield_journal_outcome_t outcome)
{
    static const char *const values[] = {"stopped", "busy", "invalid",
        "timeout", "queue_overflow", "restore_failed", "output_failed",
        "no_mem"};
    return (unsigned)outcome < sizeof(values) / sizeof(values[0]) ?
        values[outcome] : "unknown";
}

static const char *threat_token(wifi_shield_threat_t threat)
{
    static const char *const values[] = {"quiet", "watch", "attack",
                                         "critical"};
    return (unsigned)threat < sizeof(values) / sizeof(values[0]) ?
        values[threat] : "unknown";
}

static const char *reason_token(wifi_shield_campaign_reason_t reason)
{
    const char *token = wifi_shield_campaign_reason_token(reason);
    return token == NULL ? "none" : token;
}

static const char *mode_token(const wifi_shield_summary_metadata_t *metadata)
{
    if (metadata->protect_all) return "protect-all";
    if (metadata->active_defence) return "active";
    return "passive";
}

static const char *confidence_token(wifi_shield_ap_confidence_t confidence)
{
    static const char *const values[] = {"none", "observed", "limited"};
    return (unsigned)confidence < sizeof(values) / sizeof(values[0]) ?
        values[confidence] : "unknown";
}

int wifi_shield_summary_format(char *out, size_t capacity,
    const wifi_shield_summary_t *summary,
    const wifi_shield_journal_status_t *journal, const char *json_path)
{
    if (out == NULL || summary == NULL || journal == NULL || json_path == NULL ||
        !summary->started || !summary->terminal || json_path[0] == '\0')
        return -1;
    if (capacity == 0U) return -1;
    summary_builder_t builder = {
        .bytes = out,
        .capacity = capacity,
        .valid = true,
    };
    const wifi_shield_summary_metadata_t *metadata = &summary->metadata;
    uint64_t duration = summary->ended_us >= summary->started_us ?
        summary->ended_us - summary->started_us : 0U;
    append(&builder, "JanOS Wi-Fi Shield - Session Summary\n");
    append(&builder, "Session: b%08" PRIx32 "-s%" PRIu32 "\n",
           summary->boot_id, summary->session_id);
    append(&builder, "Targets: %zu\n", metadata->target_count);
    if (metadata->primary_target_valid) {
        const char *ssid = metadata->primary_ssid[0] != '\0' ?
            metadata->primary_ssid : "<hidden>";
        append(&builder,
            "Primary target: %s / %02x:%02x:%02x:%02x:%02x:%02x / channel %u\n",
            ssid, (unsigned)metadata->primary_bssid[0],
            (unsigned)metadata->primary_bssid[1],
            (unsigned)metadata->primary_bssid[2],
            (unsigned)metadata->primary_bssid[3],
            (unsigned)metadata->primary_bssid[4],
            (unsigned)metadata->primary_bssid[5],
            (unsigned)metadata->primary_channel);
    }
    append(&builder, "Mode: %s\n", mode_token(metadata));
    append(&builder, "Outcome: %s\n", outcome_token(summary->outcome));
    append(&builder, "Duration: %" PRIu64 ".%03" PRIu64
        " s (monotonic; %s)\n", duration / UINT64_C(1000000),
        (duration % UINT64_C(1000000)) / UINT64_C(1000),
        (journal->time_sources & WIFI_SHIELD_JOURNAL_TIME_GPS) != 0U ?
            "trusted GPS time also recorded in JSONL" : "no trusted UTC");
    append(&builder, "Threat: %s\nReason: %s\n",
           threat_token(summary->threat), reason_token(summary->reason));
    append(&builder, "\nObserved\n");
    append(&builder, "Deauth: %" PRIu32 "\n",
           summary->event_counts[WIFI_SHIELD_EVENT_DEAUTH]);
    append(&builder, "Disassoc: %" PRIu32 "\n",
           summary->event_counts[WIFI_SHIELD_EVENT_DISASSOC]);
    append(&builder, "CSA: %" PRIu32 "\n",
           summary->event_counts[WIFI_SHIELD_EVENT_CSA]);
    append(&builder, "WPS: %" PRIu32 "\n",
           saturating_add(summary->event_counts[WIFI_SHIELD_EVENT_WPS_ACTIVITY],
               saturating_add(
                   summary->event_counts[WIFI_SHIELD_EVENT_WPS_RETRY_BURST],
                   summary->event_counts[WIFI_SHIELD_EVENT_WPS_ANOMALY])));
    append(&builder, "SAE: %" PRIu32 "\n",
           saturating_add(summary->event_counts[WIFI_SHIELD_EVENT_SAE_ACTIVITY],
                          summary->event_counts[WIFI_SHIELD_EVENT_SAE_ANOMALY]));
    append(&builder, "Trust: %" PRIu32 "\n",
           summary->event_counts[WIFI_SHIELD_EVENT_TRUST_DRIFT]);
    append(&builder, "PMKID: %" PRIu32 "\n",
           summary->event_counts[WIFI_SHIELD_EVENT_PMKID_SEQUENCE]);
    append(&builder, "\nDefence\n4-Way decoy: %s\nPMKID decoy: %s\nMulti-vector rearm: %s\n",
           metadata->active_defence ? "enabled" : "disabled",
           metadata->pmkid_decoy ? "enabled" : "disabled",
           metadata->multi_vector ? "enabled" : "disabled");
    append(&builder, "\nJournal\nIntegrity: %s\nRecords: %" PRIu32
        "\nDropped observations: %" PRIu32 "\n",
        journal->state == WIFI_SHIELD_JOURNAL_FINALIZED &&
                journal->dropped == 0U && journal->failures == 0U ?
            "complete" : "limited",
        journal->records_written, journal->dropped);
    append(&builder, "\nRecommendations\n");
    if (!summary->ap_health_valid ||
        summary->ap_health.recommendation_count == 0U) {
        append(&builder, "- None from retained AP evidence\n");
    } else {
        for (uint8_t i = 0U; i < summary->ap_health.recommendation_count; ++i) {
            const wifi_shield_ap_recommendation_detail_t *detail =
                &summary->ap_health.recommendation_details[i];
            append(&builder, "- %s (evidence: %s, confidence: %s)\n",
                wifi_shield_ap_recommendation_token(detail->action),
                wifi_shield_ap_recommendation_evidence_token(detail->evidence),
                confidence_token(detail->confidence));
        }
    }
    append(&builder, "\nJSONL: %s\n", json_path);
    if (!builder.valid || builder.used >= capacity) {
        out[0] = '\0';
        return -1;
    }
    return (int)builder.used;
}
