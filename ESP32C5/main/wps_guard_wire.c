#include "wps_guard_wire.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    const char *token;
    wps_guard_severity_t severity;
} reason_record_t;

/* No info-level anomaly: ordinary progression/completion/retries are counters.
 * INVALID_ENVELOPE is conservative uncertainty for identifiable malformed WSC.
 */
static const reason_record_t reasons[WPS_GUARD_REASON_COUNT] = {
    [WPS_GUARD_FIRST_MISSING_LENGTH] = {"first_missing_length", WPS_GUARD_SEVERITY_ALERT},
    [WPS_GUARD_DECLARED_NOT_LARGER_THAN_FIRST] = {"declared_not_larger_than_first", WPS_GUARD_SEVERITY_ALERT},
    [WPS_GUARD_DECLARED_OVER_LIMIT] = {"declared_over_limit", WPS_GUARD_SEVERITY_ALERT},
    [WPS_GUARD_REPEATED_LENGTH_FIELD] = {"repeated_length_field", WPS_GUARD_SEVERITY_ALERT},
    [WPS_GUARD_OPCODE_CHANGED] = {"opcode_changed", WPS_GUARD_SEVERITY_ALERT},
    [WPS_GUARD_EAP_ID_CONFLICT] = {"eap_id_conflict", WPS_GUARD_SEVERITY_ALERT},
    [WPS_GUARD_OBSERVED_EXCEEDS_DECLARED] = {"observed_exceeds_declared", WPS_GUARD_SEVERITY_ALERT},
    [WPS_GUARD_FINAL_LENGTH_MISMATCH] = {"final_length_mismatch", WPS_GUARD_SEVERITY_ALERT},
    [WPS_GUARD_EMPTY_MORE_FRAGMENT] = {"empty_more_fragment", WPS_GUARD_SEVERITY_ALERT},
    [WPS_GUARD_SESSION_TIMEOUT] = {"session_timeout", WPS_GUARD_SEVERITY_WARN},
    [WPS_GUARD_SESSION_CAPACITY] = {"session_capacity", WPS_GUARD_SEVERITY_WARN},
    [WPS_GUARD_FRAME_TRUNCATED] = {"frame_truncated", WPS_GUARD_SEVERITY_ALERT},
    [WPS_GUARD_INVALID_ENVELOPE] = {"invalid_envelope", WPS_GUARD_SEVERITY_WARN}
};

static int publish(char *out, size_t capacity, const char *line, int length)
{
    if (length < 0 || (size_t)length >= WPS_GUARD_LINE_MAX ||
        (size_t)length >= capacity) return -1;
    memcpy(out, line, (size_t)length + 1);
    return length;
}

int wps_guard_format_event(char *out, size_t capacity,
                           const wps_guard_event_t *event)
{
    if (out == NULL || event == NULL) return -1;
    if (event->reason < WPS_GUARD_NONE || event->reason >= WPS_GUARD_REASON_COUNT) return -1;
    if (event->reason == WPS_GUARD_NONE || event->reason == WPS_GUARD_RETRANSMISSION ||
        event->reason == WPS_GUARD_COMPLETE) return 0;
    const wps_guard_fragment_t *f = &event->fragment;
    const char *direction;
    if (f->direction == WPS_GUARD_DIR_AP_TO_STA) direction = "ap_to_sta";
    else if (f->direction == WPS_GUARD_DIR_STA_TO_AP) direction = "sta_to_ap";
    else return -1;
    const reason_record_t *reason = &reasons[event->reason];
    if (reason->token == NULL) return -1;
    const char *severity = reason->severity == WPS_GUARD_SEVERITY_ALERT ? "alert" : "warn";
    char line[WPS_GUARD_LINE_MAX];
    int length = snprintf(line, sizeof(line),
        "[WPS_GUARD/1] BSSID=%02x:%02x:%02x:%02x:%02x:%02x"
        " STA=%02x:%02x:%02x:%02x:%02x:%02x DIR=%s CH=%u RSSI=%d OPCODE=%u"
        " FRAGMENTS=%" PRIu32 " DECLARED=%u OBSERVED=%" PRIu32
        " RETRANSMITS=%" PRIu32 " REASON=%s SEVERITY=%s TRUNCATED=%u TS_US=%" PRIu64 "\r\n",
        (unsigned)f->bssid[0], (unsigned)f->bssid[1], (unsigned)f->bssid[2],
        (unsigned)f->bssid[3], (unsigned)f->bssid[4], (unsigned)f->bssid[5],
        (unsigned)f->station[0], (unsigned)f->station[1], (unsigned)f->station[2],
        (unsigned)f->station[3], (unsigned)f->station[4], (unsigned)f->station[5],
        direction, (unsigned)f->channel, (int)f->rssi, (unsigned)f->opcode,
        event->fragment_count, (unsigned)event->declared_total, event->observed_total,
        event->retransmission_count, reason->token, severity,
        f->input_truncated ? 1U : 0U, f->timestamp_us);
    return publish(out, capacity, line, length);
}

static bool append(char line[WPS_GUARD_LINE_MAX], size_t *used, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int length = vsnprintf(line + *used, WPS_GUARD_LINE_MAX - *used, format, args);
    va_end(args);
    if (length < 0 || (size_t)length >= WPS_GUARD_LINE_MAX - *used) return false;
    *used += (size_t)length;
    return true;
}

static int format_summary(char *out, size_t capacity, const wps_guard_status_t *s,
                           const char *outcome)
{
    if (out == NULL || s == NULL) return -1;
    char line[WPS_GUARD_LINE_MAX];
    size_t used = 0;
    bool ready = outcome == NULL ? append(line, &used, "[WPS_GUARD/1] STATUS") :
                 append(line, &used, "[WPS_GUARD/1] TERMINAL OUTCOME=%s", outcome);
    if (!ready || !append(line, &used,
        " RECEIVED=%" PRIu32 " FILTERED=%" PRIu32 " UNRELATED=%" PRIu32
        " FRAGMENTS=%" PRIu32 " RETRANSMISSIONS=%" PRIu32 " COMPLETIONS=%" PRIu32
        " ANOMALIES=%" PRIu32 " TIMEOUTS=%" PRIu32 " CAPACITY_DROPS=%" PRIu32
        " RX_DROPS=%" PRIu32 " OUTPUT_FAILURES=%" PRIu32
        " ACTIVE=%" PRIu32 " RUNNING=%u STOPPING=%u REASONS=",
        s->received, s->filtered, s->unrelated, s->fragments, s->retransmissions,
        s->completions, s->anomalies, s->timeouts, s->capacity_drops,
        s->rx_drops, s->output_failures, s->active_sessions,
        s->running ? 1U : 0U, s->stopping ? 1U : 0U)) return -1;
    for (size_t i = 0; i < WPS_GUARD_REASON_COUNT; ++i) {
        if (!append(line, &used, "%s%" PRIu32, i == 0 ? "" : ",", s->reason_counts[i])) return -1;
    }
    if (!append(line, &used, "\r\n")) return -1;
    return publish(out, capacity, line, (int)used);
}

int wps_guard_format_status(char *out, size_t capacity,
                            const wps_guard_status_t *status)
{
    return format_summary(out, capacity, status, NULL);
}

int wps_guard_format_terminal(char *out, size_t capacity,
                              const wps_guard_status_t *status,
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
