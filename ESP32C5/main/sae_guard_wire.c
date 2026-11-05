#include "sae_guard_wire.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef enum {
    INTERPRETATION_OBSERVATION = 1U << 0,
    INTERPRETATION_MALFORMED = 1U << 1,
    INTERPRETATION_POTENTIAL_DOS = 1U << 2
} interpretation_t;

typedef struct {
    const char *token;
    sae_guard_severity_t severity;
    interpretation_t interpretation;
} reason_record_t;

static const reason_record_t reasons[SAE_GUARD_EVENT_REASON_COUNT] = {
    [SAE_GUARD_EVENT_MALFORMED] = {
        "malformed", SAE_GUARD_SEVERITY_ALERT, INTERPRETATION_MALFORMED
    },
    [SAE_GUARD_EVENT_UNCONFIRMED_COMMITS] = {
        "unconfirmed_commits", SAE_GUARD_SEVERITY_WARN,
        INTERPRETATION_POTENTIAL_DOS
    },
    [SAE_GUARD_EVENT_GROUP_CHURN] = {
        "group_churn", SAE_GUARD_SEVERITY_WARN, INTERPRETATION_POTENTIAL_DOS
    },
    [SAE_GUARD_EVENT_ANTI_CLOGGING] = {
        "anti_clogging", SAE_GUARD_SEVERITY_INFO, INTERPRETATION_OBSERVATION
    },
    [SAE_GUARD_EVENT_STATUS_FAILURE] = {
        "status_failure", SAE_GUARD_SEVERITY_INFO, INTERPRETATION_OBSERVATION
    },
    [SAE_GUARD_EVENT_CAPACITY] = {
        "capacity", SAE_GUARD_SEVERITY_WARN, INTERPRETATION_OBSERVATION
    }
};

static bool append(char *buffer, size_t capacity, size_t *used,
                   const char *format, ...)
{
    if (*used >= capacity) return false;
    va_list args;
    va_start(args, format);
    const int length = vsnprintf(buffer + *used, capacity - *used, format, args);
    va_end(args);
    if (length < 0 || (size_t)length >= capacity - *used) return false;
    *used += (size_t)length;
    return true;
}

static int publish(char *out, size_t capacity, const char *line, int length)
{
    if (length < 0 || (size_t)length >= SAE_GUARD_LINE_MAX ||
        (size_t)length >= capacity) return -1;
    memcpy(out, line, (size_t)length + 1U);
    return length;
}

static uint32_t valid_reason_mask(void)
{
    uint32_t mask = 0;
    for (size_t reason = SAE_GUARD_EVENT_MALFORMED;
         reason < SAE_GUARD_EVENT_REASON_COUNT; ++reason) {
        mask |= SAE_GUARD_EVENT_MASK(reason);
    }
    return mask;
}

static bool valid_event_reasons(const sae_guard_event_t *event)
{
    if (event->reason < SAE_GUARD_EVENT_NONE ||
        event->reason >= SAE_GUARD_EVENT_REASON_COUNT) return false;
    if (event->reason == SAE_GUARD_EVENT_NONE)
        return event->reason_mask == 0;
    const uint32_t mask = event->reason_mask;
    if (mask == 0 || (mask & ~valid_reason_mask()) != 0 ||
        (mask & SAE_GUARD_EVENT_MASK(event->reason)) == 0) return false;
    for (size_t reason = SAE_GUARD_EVENT_MALFORMED;
         reason < (size_t)event->reason; ++reason) {
        if ((mask & SAE_GUARD_EVENT_MASK(reason)) != 0) return false;
    }
    return true;
}

static const char *interpretation_token(interpretation_t interpretation)
{
    switch (interpretation) {
    case INTERPRETATION_OBSERVATION: return "observation";
    case INTERPRETATION_MALFORMED: return "malformed_observation";
    case INTERPRETATION_POTENTIAL_DOS: return "potential_dos";
    default: return NULL;
    }
}

static bool format_reason_labels(uint32_t mask,
                                 char *reason_text, size_t reason_capacity,
                                 char *interpretation_text,
                                 size_t interpretation_capacity,
                                 sae_guard_severity_t *severity)
{
    size_t reason_used = 0;
    size_t interpretation_used = 0;
    uint32_t interpretations_seen = 0;
    bool first_reason = true;
    bool first_interpretation = true;
    *severity = SAE_GUARD_SEVERITY_INFO;
    for (size_t reason = SAE_GUARD_EVENT_MALFORMED;
         reason < SAE_GUARD_EVENT_REASON_COUNT; ++reason) {
        if ((mask & SAE_GUARD_EVENT_MASK(reason)) == 0) continue;
        const reason_record_t *record = &reasons[reason];
        if (record->token == NULL ||
            !append(reason_text, reason_capacity, &reason_used, "%s%s",
                    first_reason ? "" : "+", record->token)) return false;
        first_reason = false;
        if (record->severity > *severity) *severity = record->severity;
        if ((interpretations_seen & (uint32_t)record->interpretation) != 0)
            continue;
        const char *token = interpretation_token(record->interpretation);
        if (token == NULL ||
            !append(interpretation_text, interpretation_capacity,
                    &interpretation_used, "%s%s",
                    first_interpretation ? "" : "+", token)) return false;
        interpretations_seen |= (uint32_t)record->interpretation;
        first_interpretation = false;
    }
    return !first_reason && !first_interpretation;
}

static const char *severity_token(sae_guard_severity_t severity)
{
    switch (severity) {
    case SAE_GUARD_SEVERITY_INFO: return "info";
    case SAE_GUARD_SEVERITY_WARN: return "warn";
    case SAE_GUARD_SEVERITY_ALERT: return "alert";
    default: return NULL;
    }
}

int sae_guard_format_event(char *out, size_t capacity,
                           const sae_guard_event_t *event)
{
    if (out == NULL || event == NULL || !valid_event_reasons(event)) return -1;
    if (event->reason == SAE_GUARD_EVENT_NONE) return 0;

    char reason_text[128];
    char interpretation_text[80];
    sae_guard_severity_t severity;
    if (!format_reason_labels(event->reason_mask, reason_text,
                              sizeof(reason_text), interpretation_text,
                              sizeof(interpretation_text), &severity)) return -1;
    const char *severity_text = severity_token(severity);
    if (severity_text == NULL) return -1;

    char group_text[8];
    if (event->observation.group == 0) {
        memcpy(group_text, "unknown", sizeof("unknown"));
    } else {
        const int group_length = snprintf(group_text, sizeof(group_text), "%u",
                                          (unsigned)event->observation.group);
        if (group_length < 0 || (size_t)group_length >= sizeof(group_text))
            return -1;
    }

    const sae_guard_observation_t *observation = &event->observation;
    const char *direction = observation->from_ap ? "ap_to_sta" : "sta_to_ap";
    char line[SAE_GUARD_LINE_MAX];
    const int length = snprintf(
        line, sizeof(line),
        "[SAE_GUARD/1] BSSID=%02x:%02x:%02x:%02x:%02x:%02x"
        " STA=%02x:%02x:%02x:%02x:%02x:%02x DIR=%s CH=%u RSSI=%d"
        " TRANSACTION=%u STATUS=%u GROUP=%s COMMITS=%" PRIu32
        " CONFIRMS=%" PRIu32 " MALFORMED=%" PRIu32 " WINDOW_MS=%" PRIu32
        " REASON=%s SEVERITY=%s INTERPRETATION=%s TS_US=%" PRIu64 "\r\n",
        (unsigned)observation->bssid[0], (unsigned)observation->bssid[1],
        (unsigned)observation->bssid[2], (unsigned)observation->bssid[3],
        (unsigned)observation->bssid[4], (unsigned)observation->bssid[5],
        (unsigned)observation->station[0], (unsigned)observation->station[1],
        (unsigned)observation->station[2], (unsigned)observation->station[3],
        (unsigned)observation->station[4], (unsigned)observation->station[5],
        direction, (unsigned)observation->channel, (int)observation->rssi,
        (unsigned)observation->transaction, (unsigned)observation->status,
        group_text, event->commits, event->confirms, event->malformed,
        event->window_ms, reason_text, severity_text, interpretation_text,
        observation->timestamp_us);
    return publish(out, capacity, line, length);
}

static uint32_t active_rows(const sae_guard_status_t *status)
{
    if (UINT32_MAX - status->active_pairs < status->active_malformed_bssids)
        return UINT32_MAX;
    return status->active_pairs + status->active_malformed_bssids;
}

static int format_summary(char *out, size_t capacity,
                          const sae_guard_status_t *status,
                          const char *outcome)
{
    if (out == NULL || status == NULL) return -1;
    char line[SAE_GUARD_LINE_MAX];
    size_t used = 0;
    const bool prefix_ready = outcome == NULL ?
        append(line, sizeof(line), &used, "[SAE_GUARD/1] STATUS") :
        append(line, sizeof(line), &used,
               "[SAE_GUARD/1] TERMINAL OUTCOME=%s", outcome);
    if (!prefix_ready ||
        !append(line, sizeof(line), &used,
                " RECEIVED=%" PRIu32 " FILTERED=%" PRIu32
                " UNRELATED=%" PRIu32 " OBSERVATIONS=%" PRIu32
                " COMMITS=%" PRIu32 " CONFIRMS=%" PRIu32
                " RETRIES=%" PRIu32 " MALFORMED=%" PRIu32
                " ANTI_CLOGGING=%" PRIu32 " STATUS_FAILURES=%" PRIu32
                " CAPACITY_DROPS=%" PRIu32 " PAIR_DROPS=%" PRIu32
                " MALFORMED_DROPS=%" PRIu32 " RX_DROPS=%" PRIu32
                " OUTPUT_FAILURES=%" PRIu32 " ACTIVE=%" PRIu32
                " RUNNING=%u STOPPING=%u REASONS=",
                status->received, status->filtered, status->unrelated,
                status->observations, status->commits, status->confirms,
                status->retries, status->malformed, status->anti_clogging,
                status->status_failures, status->capacity_drops,
                status->pair_capacity_drops, status->malformed_capacity_drops,
                status->rx_drops, status->output_failures, active_rows(status),
                status->running ? 1U : 0U, status->stopping ? 1U : 0U)) return -1;
    for (size_t reason = 0; reason < SAE_GUARD_EVENT_REASON_COUNT; ++reason) {
        if (!append(line, sizeof(line), &used, "%s%" PRIu32,
                    reason == 0 ? "" : ",", status->reason_counts[reason]))
            return -1;
    }
    if (!append(line, sizeof(line), &used, "\r\n")) return -1;
    return publish(out, capacity, line, (int)used);
}

int sae_guard_format_status(char *out, size_t capacity,
                            const sae_guard_status_t *status)
{
    return format_summary(out, capacity, status, NULL);
}

int sae_guard_format_terminal(char *out, size_t capacity,
                              const sae_guard_status_t *status,
                              const char *outcome)
{
    static const char *const outcomes[] = {
        "ok", "stopped", "busy", "invalid", "timeout", "queue_overflow",
        "restore_failed", "output_failed"
    };
    if (outcome == NULL) return -1;
    for (size_t i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); ++i) {
        if (strcmp(outcome, outcomes[i]) == 0)
            return format_summary(out, capacity, status, outcomes[i]);
    }
    return -1;
}
