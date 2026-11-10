#include "wifi_shield.h"

#include "deauth_defence_runtime.h"
#include "sae_guard_core.h"
#include "csa_detector_core.h"
#include "pmkid_probe_detector.h"
#include "sniffer_extended.h"
#include "wifi_shield_cli.h"
#include "wifi_shield_ap_health.h"
#include "wifi_shield_campaign.h"
#include "wifi_shield_time.h"
#include "wifi_shield_wire.h"
#include "wifi_shield_wps.h"

#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define SHIELD_PROFILE_CANCEL_TIMEOUT_MS 5000U
#define SHIELD_PROFILE_PHASE_BITS 3U
#define SHIELD_PROFILE_MODULE_BITS 3U
#define SHIELD_PROFILE_PHASE_MASK ((1U << SHIELD_PROFILE_PHASE_BITS) - 1U)
#define SHIELD_PROFILE_MODULE_MASK ((1U << SHIELD_PROFILE_MODULE_BITS) - 1U)
#define SHIELD_PROFILE_MODULE_SHIFT SHIELD_PROFILE_PHASE_BITS
#define SHIELD_PROFILE_EPOCH_SHIFT \
    (SHIELD_PROFILE_PHASE_BITS + SHIELD_PROFILE_MODULE_BITS)
#define SHIELD_PROFILE_EPOCH_MAX (UINT32_MAX >> SHIELD_PROFILE_EPOCH_SHIFT)
#define SHIELD_PMKID_ASSOC_GRACE_US INT64_C(30000)
#define SHIELD_TIME_ANCHOR_MAX_AGE_US UINT64_C(30000000)
#define SHIELD_JOURNAL_QUOTA_BYTES (UINT64_C(8) * 1024U * 1024U)

typedef enum {
    SHIELD_PHASE_UNINITIALIZED = 0,
    SHIELD_PHASE_IDLE,
    SHIELD_PHASE_STARTING,
    SHIELD_PHASE_RUNNING,
    SHIELD_PHASE_STOPPING,
    SHIELD_PHASE_FINALIZING,
    SHIELD_PHASE_QUARANTINED,
    SHIELD_PHASE_UNCERTAINTY_PENDING,
    SHIELD_PHASE_STORAGE_PENDING
} shield_phase_t;

typedef enum {
    SHIELD_OUTCOME_NONE = 0,
    SHIELD_OUTCOME_STOPPED,
    SHIELD_OUTCOME_BUSY,
    SHIELD_OUTCOME_INVALID,
    SHIELD_OUTCOME_TIMEOUT,
    SHIELD_OUTCOME_RESTORE_FAILED,
    SHIELD_OUTCOME_OUTPUT_FAILED,
    SHIELD_OUTCOME_NO_MEM
} shield_outcome_t;

typedef enum {
    SHIELD_PROFILE_NONE = 0,
    SHIELD_PROFILE_PREPARING,
    SHIELD_PROFILE_RUNNING,
    SHIELD_PROFILE_STOPPING_PREPARE,
    SHIELD_PROFILE_STOPPING_RUNTIME,
    SHIELD_PROFILE_QUARANTINED
} shield_profile_phase_t;

_Static_assert(SHIELD_PROFILE_QUARANTINED <= SHIELD_PROFILE_PHASE_MASK,
               "profile phase must fit atomic lifecycle state");
_Static_assert(WIFI_SECURITY_MODULE_DEAUTH_V2 <= SHIELD_PROFILE_MODULE_MASK,
               "security module must fit atomic lifecycle state");

typedef struct {
    atomic_uint lifecycle;
    wifi_security_module_t module;
    uint32_t generation;
    uint8_t channels[WIFI_SHIELD_TARGET_MAX];
    size_t channel_count;
    size_t cursor;
    uint64_t next_hop_us;
} shield_profile_t;

typedef struct {
    uint8_t bssid[6];
    uint8_t station[6];
    uint8_t channel;
    int64_t rx_us;
    int64_t deadline_us;
    bool active_response;
    bool used;
} shield_pmkid_candidate_t;

typedef struct {
    uint8_t bssid[6];
    uint64_t first_us;
    uint64_t last_us;
    uint32_t count;
    bool used;
} shield_journal_aggregate_t;

struct wifi_shield_state {
    wifi_shield_target_t target_snapshot[WIFI_SHIELD_TARGET_MAX];
    wifi_shield_channel_plan_t channel_plan;
    wifi_shield_core_t core;
    wifi_shield_time_core_t time;
    wifi_shield_campaign_core_t campaigns;
    wifi_shield_ap_health_core_t ap_health;
    wps_guard_core_t wps_guard;
    wifi_shield_wps_table_t wps;
    sae_guard_core_t sae;
    pmkid_probe_detector_t pmkid;
    shield_pmkid_candidate_t pmkid_candidates[PMKID_PROBE_SLOTS];
    wifi_trust_profile_t trust_baseline[WIFI_TRUST_MAX_PROFILES];
    wifi_trust_table_t trust_observed;
    wifi_trust_profile_t trust_current;
    wifi_trust_observe_workspace_t trust_workspace;
    wifi_trust_event_t trust_events[WIFI_TRUST_REASON_COUNT];
    wifi_shield_event_t pending_events[5];
    /* Shared-worker scratch. Submission copies records before return; Stop
     * joins the worker before PSRAM wipe, so no pointer escapes this state. */
    wifi_shield_journal_record_t journal_scratch[2];
    /* Fixed per-target/type buckets live with the session arena in PSRAM.
     * Detection, campaign and UART paths still consume every observation. */
    shield_journal_aggregate_t journal_aggregates
        [WIFI_SHIELD_TARGET_MAX][WIFI_SHIELD_DEAUTH_TYPE_COUNT];
    uint64_t health_journal_us[WIFI_SHIELD_TARGET_MAX];
    uint32_t recommendation_journal_revision[WIFI_SHIELD_TARGET_MAX];
    uint8_t recommendation_journal_count[WIFI_SHIELD_TARGET_MAX];
    bool recommendation_journal_retry[WIFI_SHIELD_TARGET_MAX];
    wifi_shield_ap_recommendation_detail_t recommendation_journal_details
        [WIFI_SHIELD_TARGET_MAX][WIFI_SHIELD_AP_RECOMMENDATION_MAX];
    wifi_shield_status_t status_workspace;
    deauth_defence_runtime_t defence;
    deauth_defence_runtime_target_t
        defence_targets[DEAUTH_DEFENCE_RUNTIME_TARGETS];
    char defence_armed_line[160];
    char defence_telemetry_line[WIFI_SHIELD_LINE_MAX];
    size_t trust_count;
    size_t defence_armed_length;
    uint64_t started_us;
    uint64_t next_hop_us;
    uint32_t runtime_rx_drops;
    uint32_t quality_rx_drops_seen;
    uint32_t quality_event_drops_seen;
    uint32_t quality_output_failures_seen;
    uint32_t journal_drops_seen;
    uint32_t defence_inflight;
    uint32_t defence_generation;
    bool trust_enabled;
    bool defence_enabled;
    bool defence_admission_open;
    bool defence_buffer_telemetry;
    bool defence_action_output_accepted;
    bool defence_finished;
    uint32_t journal_boot_id;
    uint32_t journal_session_id;
    bool journal_attempted;
};

typedef struct {
    wifi_shield_status_t status;
    shield_outcome_t outcome;
} shield_terminal_snapshot_t;

typedef struct {
    wifi_shield_campaign_snapshot_t campaign;
    wifi_shield_ap_health_snapshot_t ap_health;
    wifi_shield_journal_status_t journal;
    uint8_t bssid[6];
    uint32_t boot_id;
    uint32_t session_id;
    bool campaign_valid;
    bool ap_health_valid;
    bool journal_valid;
} shield_v2_retained_t;

typedef struct {
    wifi_shield_runtime_hooks_t runtime;
    wifi_shield_output_hooks_t output;
    wifi_shield_state_t *state;
    shield_terminal_snapshot_t terminal;
    shield_v2_retained_t *v2;
    wifi_shield_presentation_snapshot_t presentation;
    atomic_int phase;
    atomic_bool initialized;
    atomic_bool stop_requested;
    atomic_bool presentation_armed_accepted;
    atomic_bool output_failed;
    atomic_bool output_admission_open;
    atomic_uint pending_output_failures;
    atomic_uint output_inflight;
    atomic_uintptr_t active_token;
    shield_profile_t profile;
    bool state_wiped;
    bool scan_reserved;
    bool radio_quiesced;
    bool output_drained;
    bool terminal_ready;
    bool radio_restored;
    bool journal_uncertain_recorded;
    bool journal_uncertain_durable;
    bool journal_uncertain_pending;
    bool journal_terminal_pending;
    uint32_t boot_id;
    uint32_t next_session_id;
} shield_control_t;

static shield_control_t shield;
static atomic_uintptr_t next_token;
static atomic_uint next_profile_epoch;

static uint32_t shield_counter_delta(uint32_t current, uint32_t previous)
{
    return current >= previous ? current - previous : current;
}

static uint32_t shield_saturating_add(uint32_t current, uint32_t amount)
{
    return amount > UINT32_MAX - current ? UINT32_MAX : current + amount;
}

/* State lock is held. Coverage/loss is session evidence, not AP packet-loss
 * attribution. Apply deltas to every selected target and keep it sticky across
 * campaign boundaries until the state arena is reset. */
static void shield_propagate_quality_locked(wifi_shield_state_t *state)
{
    if (state == NULL) return;
    uint32_t rx = shield_counter_delta(state->core.rx_drops,
                                       state->quality_rx_drops_seen);
    uint32_t events = shield_counter_delta(state->core.event_drops,
                                           state->quality_event_drops_seen);
    uint32_t output = shield_counter_delta(
        state->core.output_failures, state->quality_output_failures_seen);
    bool sampled = state->channel_plan.channel_count > 1U;
    wifi_shield_ap_quality_t quality = {
        .sampled = sampled,
        .rx_drops = rx,
        .event_drops = events,
    };
    for (size_t i = 0U; i < state->channel_plan.target_count; ++i) {
        const uint8_t *bssid = state->channel_plan.targets[i].bssid;
        wifi_shield_campaign_note_sampled(&state->campaigns, bssid, sampled);
        wifi_shield_campaign_note_loss(&state->campaigns, bssid, rx, events,
                                       output);
        (void)wifi_shield_ap_health_note_quality(&state->ap_health, bssid,
                                                 &quality);
    }
    state->quality_rx_drops_seen = state->core.rx_drops;
    state->quality_event_drops_seen = state->core.event_drops;
    state->quality_output_failures_seen = state->core.output_failures;
}

/* State lock is held. Journal loss is independent of campaign opening and
 * therefore persists into every later campaign in the same session. */
static void shield_propagate_journal_locked(
    wifi_shield_state_t *state, const wifi_shield_journal_status_t *status)
{
    if (state == NULL || status == NULL) return;
    uint32_t delta = shield_counter_delta(status->dropped,
                                          state->journal_drops_seen);
    if (delta != 0U) {
        wifi_shield_ap_quality_t quality = {.journal_drops = delta};
        for (size_t i = 0U; i < state->channel_plan.target_count; ++i) {
            const uint8_t *bssid = state->channel_plan.targets[i].bssid;
            wifi_shield_campaign_note_journal_loss(&state->campaigns, bssid,
                                                   delta);
            (void)wifi_shield_ap_health_note_quality(&state->ap_health,
                                                     bssid, &quality);
        }
    }
    state->journal_drops_seen = status->dropped;
}

static bool journal_hooks_complete(void)
{
    return shield.runtime.journal_boot_id != NULL &&
        shield.runtime.journal_start != NULL &&
        shield.runtime.journal_submit != NULL &&
        shield.runtime.journal_status != NULL &&
        shield.runtime.journal_acknowledge_degraded != NULL &&
        shield.runtime.journal_drain != NULL &&
        shield.runtime.journal_finish != NULL;
}

static wifi_shield_journal_status_t journal_status(void)
{
    wifi_shield_journal_status_t status = {0};
    if (journal_hooks_complete())
        status = shield.runtime.journal_status(shield.runtime.context);
    /* Shield always owns a monotonic clock, including before an optional
     * journal writer starts and in the supported no-journal configuration. */
    status.time_sources |= WIFI_SHIELD_JOURNAL_TIME_MONOTONIC;
    return status;
}

static bool journal_submit(const wifi_shield_journal_record_t *record)
{
    return record != NULL && journal_hooks_complete() &&
        shield.runtime.journal_submit(shield.runtime.context, record);
}

static bool shield_journal_aggregate_type(wifi_shield_event_type_t type,
                                          size_t *index)
{
    size_t value;
    switch (type) {
    case WIFI_SHIELD_EVENT_DEAUTH: value = 0U; break;
    case WIFI_SHIELD_EVENT_DISASSOC: value = 1U; break;
    case WIFI_SHIELD_EVENT_CSA: value = 2U; break;
    default: return false;
    }
    if (index != NULL) *index = value;
    return true;
}

static shield_journal_aggregate_t *shield_journal_aggregate_bucket_locked(
    wifi_shield_state_t *state, const wifi_shield_event_t *event)
{
    size_t type_index;
    if (state == NULL || event == NULL ||
        !shield_journal_aggregate_type(event->type, &type_index)) return NULL;
    for (size_t i = 0U; i < state->channel_plan.target_count; ++i)
        if (memcmp(state->channel_plan.targets[i].bssid, event->bssid, 6U) == 0)
            return &state->journal_aggregates[i][type_index];
    return NULL;
}

static void shield_journal_aggregate_record_locked(
    wifi_shield_state_t *state, size_t target_index, size_t type_index,
    wifi_shield_journal_record_t *record)
{
    shield_journal_aggregate_t *bucket =
        &state->journal_aggregates[target_index][type_index];
    static const wifi_shield_event_type_t types[WIFI_SHIELD_DEAUTH_TYPE_COUNT] = {
        WIFI_SHIELD_EVENT_DEAUTH, WIFI_SHIELD_EVENT_DISASSOC,
        WIFI_SHIELD_EVENT_CSA,
    };
    memset(record, 0, sizeof(*record));
    record->type = WIFI_SHIELD_JOURNAL_EVENT;
    record->boot_id = state->journal_boot_id;
    record->session_id = state->journal_session_id;
    record->sequence = 1U;
    record->has_bssid = true;
    memcpy(record->bssid, bucket->bssid, sizeof(record->bssid));
    record->event_source = WIFI_SHIELD_SOURCE_DEAUTH;
    record->event_type = types[type_index];
    record->event_count = bucket->count;
    record->event_first_boot_us = bucket->first_us;
    record->event_last_boot_us = bucket->last_us;
    if (!wifi_shield_time_resolve(&state->time, bucket->bssid,
                                  bucket->last_us, &record->time)) {
        record->time.boot_us = bucket->last_us;
        record->time.quality = WIFI_SHIELD_TIME_NONE;
    }
}

/* State lock is held. Each completed window gets exactly one admission
 * attempt. A rejected aggregate is already accounted by the journal platform
 * with its represented observation count, so the next window must start
 * cleanly instead of crossing the one-second schema boundary. */
static bool shield_flush_journal_aggregates_locked(
    wifi_shield_state_t *state, uint64_t now_us, bool flush_all)
{
    bool complete = true;
    if (state == NULL) return true;
    for (size_t target = 0U; target < state->channel_plan.target_count;
         ++target) {
        for (size_t type = 0U; type < WIFI_SHIELD_DEAUTH_TYPE_COUNT; ++type) {
            shield_journal_aggregate_t *bucket =
                &state->journal_aggregates[target][type];
            if (!bucket->used) continue;
            bool due = flush_all || now_us < bucket->first_us ||
                now_us - bucket->first_us >=
                    WIFI_SHIELD_JOURNAL_AGGREGATE_WINDOW_US;
            if (!due) continue;
            wifi_shield_journal_record_t *record = &state->journal_scratch[0];
            shield_journal_aggregate_record_locked(state, target, type, record);
            if (state->journal_attempted) (void)journal_submit(record);
            memset(bucket, 0, sizeof(*bucket));
        }
    }
    return complete;
}

static void shield_journal_aggregate_add_locked(
    wifi_shield_state_t *state, const wifi_shield_event_t *event)
{
    shield_journal_aggregate_t *bucket =
        shield_journal_aggregate_bucket_locked(state, event);
    if (bucket == NULL) return;
    if (bucket->used &&
        (event->timestamp_us < bucket->first_us ||
         event->timestamp_us - bucket->first_us >=
             WIFI_SHIELD_JOURNAL_AGGREGATE_WINDOW_US)) {
        (void)shield_flush_journal_aggregates_locked(
            state, event->timestamp_us, false);
    }
    bucket = shield_journal_aggregate_bucket_locked(state, event);
    if (!bucket->used) {
        bucket->used = true;
        memcpy(bucket->bssid, event->bssid, sizeof(bucket->bssid));
        bucket->first_us = event->timestamp_us;
        bucket->last_us = event->timestamp_us;
        bucket->count = event->count;
        return;
    }
    bucket->count = shield_saturating_add(bucket->count, event->count);
    if (event->timestamp_us > bucket->last_us)
        bucket->last_us = event->timestamp_us;
}

static uint32_t increment_nonzero(uint32_t value)
{
    ++value;
    return value == 0U ? 1U : value;
}

bool wifi_shield_presentation_indicator(
    wifi_shield_event_type_t event,
    wifi_shield_presentation_indicator_t *indicator)
{
    if (indicator == NULL) return false;
    switch (event) {
    case WIFI_SHIELD_EVENT_WPS_ACTIVITY:
    case WIFI_SHIELD_EVENT_SAE_ACTIVITY:
    case WIFI_SHIELD_EVENT_PMKID_SEQUENCE:
    case WIFI_SHIELD_EVENT_CSA:
        *indicator = WIFI_SHIELD_PRESENTATION_INFO;
        return true;
    case WIFI_SHIELD_EVENT_WPS_RETRY_BURST:
        *indicator = WIFI_SHIELD_PRESENTATION_WARN;
        return true;
    case WIFI_SHIELD_EVENT_DEAUTH:
    case WIFI_SHIELD_EVENT_DISASSOC:
    case WIFI_SHIELD_EVENT_WPS_ANOMALY:
    case WIFI_SHIELD_EVENT_SAE_ANOMALY:
    case WIFI_SHIELD_EVENT_TRUST_DRIFT:
        *indicator = WIFI_SHIELD_PRESENTATION_ALERT;
        return true;
    default:
        return false;
    }
}

static bool format_oled_line(char line[WIFI_SHIELD_OLED_LINE_BYTES],
                             const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(line, WIFI_SHIELD_OLED_LINE_BYTES,
                           format, arguments);
    va_end(arguments);
    if (length < 0 || length >= (int)WIFI_SHIELD_OLED_LINE_BYTES) {
        line[0] = '\0';
        return false;
    }
    return true;
}

static void format_oled_counter(char value[4], uint32_t count)
{
    if (count >= 100U)
        memcpy(value, "99+", 4U);
    else
        (void)snprintf(value, 4U, "%u", (unsigned)count);
}

static const char *presentation_alert_label(
    const wifi_shield_presentation_snapshot_t *snapshot)
{
    if (snapshot == NULL || !snapshot->latest_alert_valid) return "none";
    switch (snapshot->latest_alert_type) {
    case WIFI_SHIELD_EVENT_WPS_RETRY_BURST: return "WPS retry";
    case WIFI_SHIELD_EVENT_WPS_ANOMALY: return "WPS anomaly";
    case WIFI_SHIELD_EVENT_SAE_ANOMALY: return "SAE anomaly";
    case WIFI_SHIELD_EVENT_DEAUTH: return "Deauth";
    case WIFI_SHIELD_EVENT_DISASSOC: return "Disassoc";
    case WIFI_SHIELD_EVENT_TRUST_DRIFT: return "Trust drift";
    default: return "none";
    }
}

bool wifi_shield_presentation_format_oled(
    const wifi_shield_presentation_snapshot_t *snapshot,
    wifi_shield_oled_lines_t *lines)
{
    if (snapshot == NULL || lines == NULL) return false;
    memset(lines, 0, sizeof(*lines));
    bool ok = format_oled_line(lines->line[0], "> WiFi Shield") &&
        format_oled_line(lines->line[1], "Targets: %u  Ch: %u",
                         (unsigned)snapshot->target_count,
                         (unsigned)snapshot->current_channel);
    char counters[WIFI_SHIELD_PRESENTATION_SOURCE_COUNT][4];
    bool compact = false;
    for (size_t i = 0U; i < WIFI_SHIELD_PRESENTATION_SOURCE_COUNT; ++i) {
        format_oled_counter(counters[i], snapshot->source_events[i]);
        compact = compact || snapshot->source_events[i] >= 100U;
    }
    ok = ok && (compact ?
        format_oled_line(lines->line[2], "D:%sW:%sS:%sT:%s",
                         counters[0], counters[1], counters[2], counters[3]) :
        format_oled_line(lines->line[2], "D:%s W:%s S:%s T:%s",
                         counters[0], counters[1], counters[2], counters[3]));
    ok = ok && format_oled_line(lines->line[3], "Alert: %s",
                                presentation_alert_label(snapshot));
    if (!ok) memset(lines, 0, sizeof(*lines));
    return ok;
}

static uint64_t next_deadline(uint64_t now_us)
{
    return now_us > UINT64_MAX - WIFI_SHIELD_CHANNEL_DWELL_US ?
        UINT64_MAX : now_us + WIFI_SHIELD_CHANNEL_DWELL_US;
}

static bool same_bssid(const uint8_t left[6], const uint8_t right[6])
{
    return left != NULL && right != NULL && memcmp(left, right, 6U) == 0;
}

static bool pmkid_candidate_stage(
    wifi_shield_state_t *state, const uint8_t bssid[6],
    const uint8_t station[6], uint8_t channel, int64_t rx_us,
    int64_t now_us, bool active_response)
{
    if (state == NULL || bssid == NULL || station == NULL || channel == 0U ||
        rx_us < 0 || now_us < 0 ||
        now_us > INT64_MAX - SHIELD_PMKID_ASSOC_GRACE_US)
        return false;
    shield_pmkid_candidate_t *free_slot = NULL;
    for (size_t i = 0U; i < PMKID_PROBE_SLOTS; ++i) {
        shield_pmkid_candidate_t *candidate = &state->pmkid_candidates[i];
        if (candidate->used && same_bssid(candidate->bssid, bssid) &&
            same_bssid(candidate->station, station)) {
            free_slot = candidate;
            break;
        }
        if (!candidate->used && free_slot == NULL) free_slot = candidate;
    }
    if (free_slot == NULL) return false;
    memset(free_slot, 0, sizeof(*free_slot));
    memcpy(free_slot->bssid, bssid, sizeof(free_slot->bssid));
    memcpy(free_slot->station, station, sizeof(free_slot->station));
    free_slot->channel = channel;
    free_slot->rx_us = rx_us;
    free_slot->deadline_us = now_us + SHIELD_PMKID_ASSOC_GRACE_US;
    free_slot->active_response = active_response;
    free_slot->used = true;
    return true;
}

static bool eapol_is_pairwise_m2(const wifi_security_decoded_t *decoded)
{
    if (decoded == NULL || decoded->kind != WIFI_SEC_FRAME_EAPOL ||
        decoded->eapol == NULL || decoded->eapol_len < 99U ||
        decoded->eapol[1] != 3U || decoded->eapol[4] != 2U)
        return false;
    uint16_t declared = (uint16_t)(((uint16_t)decoded->eapol[2] << 8U) |
                                   decoded->eapol[3]);
    if (declared < 95U || (size_t)declared + 4U > decoded->eapol_len)
        return false;
    uint16_t key_info = (uint16_t)(((uint16_t)decoded->eapol[5] << 8U) |
                                   decoded->eapol[6]);
    return (key_info & 0x0008U) != 0U && /* Pairwise key. */
           (key_info & 0x0080U) == 0U && /* No Key ACK. */
           (key_info & 0x0100U) != 0U && /* MIC present. */
           (key_info & 0x0200U) == 0U && /* Not M4/Secure. */
           (key_info & 0x0c40U) == 0U;   /* No Install/Error/Request. */
}

static bool pmkid_candidate_complete(
    wifi_shield_state_t *state, const wifi_security_decoded_t *decoded,
    uint8_t channel, shield_pmkid_candidate_t *completed)
{
    if (completed != NULL) memset(completed, 0, sizeof(*completed));
    if (state == NULL || completed == NULL || channel == 0U ||
        !eapol_is_pairwise_m2(decoded))
        return false;
    for (size_t i = 0U; i < PMKID_PROBE_SLOTS; ++i) {
        shield_pmkid_candidate_t *candidate = &state->pmkid_candidates[i];
        if (candidate->used && candidate->channel == channel &&
            same_bssid(candidate->bssid, decoded->bssid) &&
            same_bssid(candidate->station, decoded->station)) {
            *completed = *candidate;
            memset(candidate, 0, sizeof(*candidate));
            return true;
        }
    }
    return false;
}

static bool pmkid_candidate_pop_due(
    wifi_shield_state_t *state, int64_t now_us,
    shield_pmkid_candidate_t *due)
{
    if (due != NULL) memset(due, 0, sizeof(*due));
    if (state == NULL || due == NULL || now_us < 0) return false;
    shield_pmkid_candidate_t *oldest = NULL;
    for (size_t i = 0U; i < PMKID_PROBE_SLOTS; ++i) {
        shield_pmkid_candidate_t *candidate = &state->pmkid_candidates[i];
        if (candidate->used && now_us >= candidate->deadline_us &&
            (oldest == NULL || candidate->deadline_us < oldest->deadline_us))
            oldest = candidate;
    }
    if (oldest == NULL) return false;
    *due = *oldest;
    memset(oldest, 0, sizeof(*oldest));
    return true;
}

static bool valid_profile_bssid(const uint8_t bssid[6])
{
    if (bssid == NULL || (bssid[0] & 1U) != 0U) return false;
    uint8_t any = 0U;
    for (size_t i = 0U; i < 6U; ++i) any |= bssid[i];
    return any != 0U;
}

static void state_enter(void)
{
    shield.runtime.state_enter(shield.runtime.context);
}

static void state_leave(void)
{
    shield.runtime.state_leave(shield.runtime.context);
}

static void presentation_sync_status_locked(
    const wifi_shield_status_t *status)
{
    if (status == NULL) return;
    shield.presentation.target_count = status->target_count > UINT8_MAX ?
        UINT8_MAX : (uint8_t)status->target_count;
    shield.presentation.current_channel = status->current_channel;
    for (size_t i = 0U; i < WIFI_SHIELD_PRESENTATION_SOURCE_COUNT; ++i)
        shield.presentation.source_events[i] = status->source_events[i];
}

static void presentation_sync_core_locked(void)
{
    if (shield.state == NULL || shield.state_wiped) return;
    wifi_shield_status_t status;
    wifi_shield_core_status(&shield.state->core, &status);
    presentation_sync_status_locked(&status);
}

static void presentation_changed_locked(void)
{
    shield.presentation.revision = increment_nonzero(
        shield.presentation.revision);
}

static void presentation_begin_locked(const wifi_shield_state_t *state)
{
    uint32_t session_id = increment_nonzero(shield.presentation.session_id);
    uint32_t revision = increment_nonzero(shield.presentation.revision);
    memset(&shield.presentation, 0, sizeof(shield.presentation));
    shield.presentation.session_id = session_id;
    shield.presentation.revision = revision;
    if (state != NULL) {
        wifi_shield_status_t status;
        wifi_shield_core_status(&state->core, &status);
        presentation_sync_status_locked(&status);
    }
}

static void presentation_set_armed(const wifi_shield_status_t *status)
{
    state_enter();
    presentation_sync_status_locked(status);
    shield.presentation.armed = true;
    shield.presentation.running = true;
    shield.presentation.stopping = false;
    presentation_changed_locked();
    state_leave();
}

static void presentation_set_stopping_locked(void)
{
    presentation_sync_core_locked();
    shield.presentation.running = false;
    shield.presentation.stopping = true;
    presentation_changed_locked();
}

static void presentation_set_finished(void)
{
    state_enter();
    shield.presentation.armed = false;
    shield.presentation.running = false;
    shield.presentation.stopping = false;
    presentation_changed_locked();
    state_leave();
    atomic_store_explicit(&shield.presentation_armed_accepted, false,
                          memory_order_release);
}

static void presentation_record_event(const wifi_shield_event_t *event,
                                      bool accepted)
{
    if (event == NULL) return;
    wifi_shield_presentation_indicator_t indicator;
    bool mapped = wifi_shield_presentation_indicator(event->type, &indicator);
    state_enter();
    presentation_sync_core_locked();
    bool armed = shield.presentation.armed || atomic_load_explicit(
        &shield.presentation_armed_accepted, memory_order_acquire);
    if (accepted && mapped && armed &&
        atomic_load_explicit(&shield.phase, memory_order_acquire) ==
            SHIELD_PHASE_RUNNING) {
        uint32_t *count = &shield.presentation.indicator_counts[indicator];
        if (*count != UINT32_MAX) ++*count;
        if (indicator == WIFI_SHIELD_PRESENTATION_WARN ||
            indicator == WIFI_SHIELD_PRESENTATION_ALERT) {
            shield.presentation.latest_alert_type = event->type;
            shield.presentation.latest_alert_valid = true;
        }
    }
    presentation_changed_locked();
    state_leave();
}

void wifi_shield_presentation_get(
    wifi_shield_presentation_snapshot_t *snapshot)
{
    if (snapshot == NULL) return;
    memset(snapshot, 0, sizeof(*snapshot));
    if (!atomic_load_explicit(&shield.initialized, memory_order_acquire))
        return;
    state_enter();
    *snapshot = shield.presentation;
    state_leave();
}

static bool radio_enter(uint32_t timeout_ms)
{
    return shield.runtime.radio_enter(shield.runtime.context, timeout_ms);
}

static void radio_leave(void)
{
    shield.runtime.radio_leave(shield.runtime.context);
}

static void secure_zero(void *memory, size_t size)
{
    volatile uint8_t *bytes = memory;
    while (bytes != NULL && size-- != 0U) *bytes++ = 0U;
}

static unsigned profile_lifecycle(unsigned epoch,
                                  wifi_security_module_t module,
                                  shield_profile_phase_t phase)
{
    return (epoch << SHIELD_PROFILE_EPOCH_SHIFT) |
        ((unsigned)module << SHIELD_PROFILE_MODULE_SHIFT) |
        (unsigned)phase;
}

static shield_profile_phase_t profile_lifecycle_phase(unsigned lifecycle)
{
    return (shield_profile_phase_t)(lifecycle & SHIELD_PROFILE_PHASE_MASK);
}

static wifi_security_module_t profile_lifecycle_module(unsigned lifecycle)
{
    return (wifi_security_module_t)(
        (lifecycle >> SHIELD_PROFILE_MODULE_SHIFT) &
        SHIELD_PROFILE_MODULE_MASK);
}

static unsigned profile_lifecycle_epoch(unsigned lifecycle)
{
    return lifecycle >> SHIELD_PROFILE_EPOCH_SHIFT;
}

static unsigned new_profile_epoch(void)
{
    unsigned observed = atomic_load_explicit(&next_profile_epoch,
                                              memory_order_relaxed);
    for (;;) {
        unsigned next = observed >= SHIELD_PROFILE_EPOCH_MAX ?
            1U : observed + 1U;
        if (atomic_compare_exchange_weak_explicit(
                &next_profile_epoch, &observed, next,
                memory_order_relaxed, memory_order_relaxed))
            return next;
    }
}

static void profile_zero_fields_locked(void)
{
    secure_zero(shield.profile.channels, sizeof(shield.profile.channels));
    shield.profile.module = WIFI_SECURITY_MODULE_NONE;
    shield.profile.generation = 0U;
    shield.profile.channel_count = 0U;
    shield.profile.cursor = 0U;
    shield.profile.next_hop_us = 0U;
}

static void profile_reset_locked(void)
{
    profile_zero_fields_locked();
    atomic_store_explicit(
        &shield.profile.lifecycle,
        profile_lifecycle(0U, WIFI_SECURITY_MODULE_NONE,
                          SHIELD_PROFILE_NONE),
                          memory_order_release);
}

static bool profile_clear_epoch_locked(unsigned epoch,
                                       wifi_security_module_t module)
{
    if (epoch == 0U || module == WIFI_SECURITY_MODULE_NONE) return false;
    unsigned observed = atomic_load_explicit(&shield.profile.lifecycle,
                                              memory_order_acquire);
    for (;;) {
        if (profile_lifecycle_epoch(observed) != epoch ||
            profile_lifecycle_module(observed) != module)
            return false;
        profile_zero_fields_locked();
        if (atomic_compare_exchange_weak_explicit(
                &shield.profile.lifecycle, &observed,
                profile_lifecycle(0U, WIFI_SECURITY_MODULE_NONE,
                                  SHIELD_PROFILE_NONE),
                memory_order_acq_rel, memory_order_acquire))
            break;
    }
    return true;
}

static bool profile_transition(unsigned epoch,
                               wifi_security_module_t module,
                               shield_profile_phase_t from,
                               shield_profile_phase_t to)
{
    unsigned expected = profile_lifecycle(epoch, module, from);
    return atomic_compare_exchange_strong_explicit(
        &shield.profile.lifecycle, &expected,
        profile_lifecycle(epoch, module, to),
        memory_order_acq_rel, memory_order_acquire);
}

static uintptr_t new_token(void)
{
    uintptr_t token = atomic_fetch_add_explicit(&next_token, 1U,
                                                 memory_order_relaxed) + 1U;
    if (token == 0U) {
        token = atomic_fetch_add_explicit(&next_token, 1U,
                                           memory_order_relaxed) + 1U;
    }
    return token;
}

static const char *outcome_text(shield_outcome_t outcome)
{
    switch (outcome) {
    case SHIELD_OUTCOME_STOPPED: return "stopped";
    case SHIELD_OUTCOME_BUSY: return "busy";
    case SHIELD_OUTCOME_TIMEOUT: return "timeout";
    case SHIELD_OUTCOME_RESTORE_FAILED: return "restore_failed";
    case SHIELD_OUTCOME_OUTPUT_FAILED: return "output_failed";
    case SHIELD_OUTCOME_NO_MEM: return "no_mem";
    case SHIELD_OUTCOME_INVALID:
    case SHIELD_OUTCOME_NONE:
    default: return "invalid";
    }
}

static bool phase_has_state(int phase)
{
    return phase == SHIELD_PHASE_STARTING || phase == SHIELD_PHASE_RUNNING ||
           phase == SHIELD_PHASE_STOPPING ||
           phase == SHIELD_PHASE_FINALIZING ||
           phase == SHIELD_PHASE_QUARANTINED ||
           phase == SHIELD_PHASE_UNCERTAINTY_PENDING ||
           phase == SHIELD_PHASE_STORAGE_PENDING;
}

static void snapshot_status_locked(void)
{
    if (shield.state != NULL && !shield.state_wiped) {
        wifi_shield_core_status(&shield.state->core, &shield.terminal.status);
    }
}

static void snapshot_status(void)
{
    state_enter();
    snapshot_status_locked();
    state_leave();
}

static wifi_shield_journal_outcome_t journal_outcome(shield_outcome_t outcome)
{
    switch (outcome) {
    case SHIELD_OUTCOME_STOPPED: return WIFI_SHIELD_JOURNAL_STOPPED;
    case SHIELD_OUTCOME_BUSY: return WIFI_SHIELD_JOURNAL_BUSY;
    case SHIELD_OUTCOME_TIMEOUT: return WIFI_SHIELD_JOURNAL_TIMEOUT;
    case SHIELD_OUTCOME_RESTORE_FAILED:
        return WIFI_SHIELD_JOURNAL_RESTORE_FAILED;
    case SHIELD_OUTCOME_OUTPUT_FAILED:
        return WIFI_SHIELD_JOURNAL_OUTPUT_FAILED;
    case SHIELD_OUTCOME_NO_MEM: return WIFI_SHIELD_JOURNAL_NO_MEM;
    case SHIELD_OUTCOME_INVALID:
    case SHIELD_OUTCOME_NONE:
    default: return WIFI_SHIELD_JOURNAL_INVALID;
    }
}

/* State lock is held. Retain one bounded representative terminal view; the
 * running report walks PSRAM one target at a time. Rank by the session peak
 * first so a later quiet campaign cannot hide earlier critical evidence. */
static void shield_capture_v2_retained_locked(void)
{
    memset(shield.v2, 0, sizeof(*shield.v2));
    if (shield.state == NULL || shield.state_wiped) return;
    wifi_shield_state_t *state = shield.state;
    shield.v2->boot_id = state->journal_boot_id;
    shield.v2->session_id = state->journal_session_id;
    for (size_t i = 0U; i < state->channel_plan.target_count; ++i) {
        const uint8_t *bssid = state->channel_plan.targets[i].bssid;
        wifi_shield_campaign_snapshot_t campaign;
        if (wifi_shield_campaign_snapshot(&state->campaigns, bssid,
                                           &campaign) && campaign.id &&
            (!shield.v2->campaign_valid ||
             campaign.session_peak > shield.v2->campaign.session_peak ||
             (campaign.session_peak == shield.v2->campaign.session_peak &&
              (campaign.threat > shield.v2->campaign.threat ||
               (campaign.threat == shield.v2->campaign.threat &&
                campaign.last_us > shield.v2->campaign.last_us))))) {
            shield.v2->campaign = campaign;
            memcpy(shield.v2->bssid, bssid, sizeof(shield.v2->bssid));
            shield.v2->campaign_valid = true;
        }
    }
    if (!shield.v2->campaign_valid && state->channel_plan.target_count != 0U)
        memcpy(shield.v2->bssid, state->channel_plan.targets[0].bssid,
               sizeof(shield.v2->bssid));
    shield.v2->ap_health_valid = wifi_shield_ap_health_snapshot(
        &state->ap_health, shield.v2->bssid, &shield.v2->ap_health);
}

static void shield_capture_v2_retained(void)
{
    wifi_shield_journal_status_t status = journal_status();
    uint64_t now_us = shield.runtime.monotonic_us(shield.runtime.context);
    state_enter();
    if (shield.state != NULL && !shield.state_wiped) {
        shield_propagate_quality_locked(shield.state);
        shield_propagate_journal_locked(shield.state, &status);
        (void)wifi_shield_campaign_close(&shield.state->campaigns, now_us);
    }
    shield_capture_v2_retained_locked();
    shield.v2->journal = status;
    shield.v2->journal_valid = journal_hooks_complete();
    state_leave();
}

static void shield_update_retained_journal(void)
{
    wifi_shield_journal_status_t status = journal_status();
    state_enter();
    uint32_t delta = shield_counter_delta(status.dropped,
                                          shield.v2->journal.dropped);
    if (delta != 0U && shield.v2->campaign_valid) {
        shield.v2->campaign.journal_drops = shield_saturating_add(
            shield.v2->campaign.journal_drops, delta);
        shield.v2->campaign.confidence =
            WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED;
    }
    if (delta != 0U && shield.v2->ap_health_valid) {
        shield.v2->ap_health.journal_drops = shield_saturating_add(
            shield.v2->ap_health.journal_drops, delta);
        if (shield.v2->ap_health.beacons != 0U) {
            shield.v2->ap_health.continuity_confidence =
                WIFI_SHIELD_AP_CONFIDENCE_LIMITED;
            shield.v2->ap_health.timing_confidence =
                WIFI_SHIELD_AP_CONFIDENCE_LIMITED;
        }
    }
    shield.v2->journal = status;
    shield.v2->journal_valid = journal_hooks_complete();
    state_leave();
}

static bool shield_submit_terminal_record(shield_outcome_t outcome)
{
    if (!journal_hooks_complete()) return true;
    wifi_shield_journal_record_t record = {
        .type = WIFI_SHIELD_JOURNAL_SESSION_TERMINAL,
        .boot_id = shield.v2->boot_id != 0U ? shield.v2->boot_id : shield.boot_id,
        .session_id = shield.v2->session_id != 0U ? shield.v2->session_id :
            shield.next_session_id,
        .sequence = 1U,
        .outcome = journal_outcome(outcome),
        .time = {
            .boot_us = shield.runtime.monotonic_us(shield.runtime.context),
            .quality = WIFI_SHIELD_TIME_NONE,
        },
    };
    return journal_submit(&record);
}

static bool shield_submit_uncertainty_record(shield_outcome_t outcome)
{
    if (!journal_hooks_complete()) return true;
    wifi_shield_journal_record_t record = {
        .type = WIFI_SHIELD_JOURNAL_SESSION_UNCERTAIN,
        .boot_id = shield.v2->boot_id != 0U ? shield.v2->boot_id : shield.boot_id,
        .session_id = shield.v2->session_id != 0U ? shield.v2->session_id :
            shield.next_session_id,
        .sequence = 1U,
        .outcome = journal_outcome(outcome),
        .time = {
            .boot_us = shield.runtime.monotonic_us(shield.runtime.context),
            .quality = WIFI_SHIELD_TIME_NONE,
        },
    };
    return journal_submit(&record);
}

static bool shield_finish_journal(bool clean, uint32_t timeout_ms)
{
    return !journal_hooks_complete() ||
        shield.runtime.journal_finish(shield.runtime.context, clean,
                                      timeout_ms);
}

static bool shield_drain_journal(uint32_t timeout_ms)
{
    return !journal_hooks_complete() ||
        shield.runtime.journal_drain(shield.runtime.context, timeout_ms);
}

/* Radio is already restored when this bounded helper is used by Stop. A full
 * healthy queue gets one drain/retry cycle; permanent storage failures remain
 * fail-open and are reflected by journal status instead of blocking cleanup. */
static bool shield_flush_all_journal_aggregates(uint32_t timeout_ms)
{
    for (unsigned attempt = 0U; attempt < 2U; ++attempt) {
        state_enter();
        bool complete = shield.state == NULL || shield.state_wiped ||
            shield_flush_journal_aggregates_locked(shield.state, UINT64_MAX,
                                                   true);
        state_leave();
        if (complete) return true;
        wifi_shield_journal_status_t status = journal_status();
        if (status.state != WIFI_SHIELD_JOURNAL_ACTIVE) return true;
        if (!shield_drain_journal(timeout_ms)) return false;
    }
    return false;
}

/* A radio-cleanup failure is earlier evidence than any later recovery
 * terminal.  A healthy writer queue may transiently reject it, so preserve a
 * pending obligation, drain/retry once, and checkpoint an accepted record
 * before returning to QUARANTINED.  Permanent fail-open storage states do not
 * hold radio recovery hostage.  Callers own the lifecycle phase exclusively. */
static bool shield_submit_uncertainty_bounded(shield_outcome_t outcome,
                                              uint32_t timeout_ms)
{
    if (!journal_hooks_complete()) {
        shield.journal_uncertain_pending = false;
        shield.journal_uncertain_durable = true;
        return true;
    }
    shield.journal_uncertain_pending = true;
    if (!shield.journal_uncertain_recorded) {
        if (!shield_submit_uncertainty_record(outcome)) {
            if (!shield_drain_journal(timeout_ms)) return false;
            if (!shield_submit_uncertainty_record(outcome)) {
                wifi_shield_journal_status_t status = journal_status();
                if (status.state == WIFI_SHIELD_JOURNAL_ACTIVE)
                    return false;
                shield.journal_uncertain_pending = false;
                shield.journal_uncertain_durable = true;
                return true;
            }
        }
        shield.journal_uncertain_recorded = true;
    }
    if (!shield.journal_uncertain_durable) {
        if (!shield_drain_journal(timeout_ms)) return false;
        shield.journal_uncertain_durable = true;
    }
    shield.journal_uncertain_pending = false;
    return true;
}

/* A healthy active writer may reject only because its bounded queue is full.
 * Drain accepted records and retry before closing admission. Store/task failure
 * remains fail-open status and must not turn successful radio cleanup into
 * quarantine. False means the active writer still owns a required terminal. */
static bool shield_submit_terminal_bounded(shield_outcome_t outcome,
                                           uint32_t timeout_ms)
{
    if (!journal_hooks_complete()) return true;
    if (shield.journal_terminal_pending &&
        !shield_drain_journal(timeout_ms)) return false;
    if (shield_submit_terminal_record(outcome)) {
        shield.journal_terminal_pending = false;
        return true;
    }
    /* Status may still be UNAVAILABLE before the writer's first poll even
     * though a healthy queue is merely full. Drain/retry once before using
     * non-ACTIVE as the fail-open classification. */
    shield.journal_terminal_pending = true;
    if (!shield_drain_journal(timeout_ms)) return false;
    if (shield_submit_terminal_record(outcome)) {
        shield.journal_terminal_pending = false;
        return true;
    }
    wifi_shield_journal_status_t status = journal_status();
    if (status.state != WIFI_SHIELD_JOURNAL_ACTIVE) {
        shield.journal_terminal_pending = false;
        return true;
    }
    return false;
}

static void merge_runtime_drops(
    const wifi_security_runtime_status_t *runtime_status)
{
    if (runtime_status == NULL) return;
    state_enter();
    if (shield.state != NULL && !shield.state_wiped) {
        wifi_shield_state_t *state = shield.state;
        uint32_t drops = runtime_status->rx_drops >= state->runtime_rx_drops ?
            runtime_status->rx_drops - state->runtime_rx_drops :
            runtime_status->rx_drops;
        state->runtime_rx_drops = runtime_status->rx_drops;
        wifi_shield_core_add_rx_drops(&state->core, drops);
        shield_propagate_quality_locked(state);
    }
    state_leave();
}

static void mark_output_failures(uint32_t count)
{
    if (count == 0U) return;
    atomic_store_explicit(&shield.output_failed, true, memory_order_release);
    state_enter();
    if (shield.state != NULL && !shield.state_wiped) {
        uint32_t current = shield.state->core.output_failures;
        shield.state->core.output_failures =
            count > UINT32_MAX - current ? UINT32_MAX : current + count;
        shield_propagate_quality_locked(shield.state);
        snapshot_status_locked();
    } else {
        uint32_t current = shield.terminal.status.output_failures;
        shield.terminal.status.output_failures =
            count > UINT32_MAX - current ? UINT32_MAX : current + count;
        if (shield.v2->campaign_valid) {
            shield.v2->campaign.output_failures = shield_saturating_add(
                shield.v2->campaign.output_failures, count);
            shield.v2->campaign.confidence =
                WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED;
        }
    }
    state_leave();
}

static void queue_output_failure(void)
{
    atomic_store_explicit(&shield.output_failed, true, memory_order_release);
    uint32_t current = atomic_load_explicit(&shield.pending_output_failures,
                                            memory_order_relaxed);
    while (current != UINT32_MAX &&
           !atomic_compare_exchange_weak_explicit(
               &shield.pending_output_failures, &current, current + 1U,
               memory_order_release, memory_order_relaxed)) {
    }
}

static void flush_output_failures(void)
{
    mark_output_failures(atomic_exchange_explicit(
        &shield.pending_output_failures, 0U, memory_order_acq_rel));
}

static void mark_output_failure(void)
{
    mark_output_failures(1U);
}

static bool output_publish_begin(void)
{
    if (!atomic_load_explicit(&shield.output_admission_open,
                              memory_order_acquire))
        return false;
    (void)atomic_fetch_add_explicit(&shield.output_inflight, 1U,
                                    memory_order_acq_rel);
    if (!atomic_load_explicit(&shield.output_admission_open,
                              memory_order_acquire)) {
        (void)atomic_fetch_sub_explicit(&shield.output_inflight, 1U,
                                        memory_order_acq_rel);
        return false;
    }
    return true;
}

static void output_publish_end(void)
{
    (void)atomic_fetch_sub_explicit(&shield.output_inflight, 1U,
                                    memory_order_acq_rel);
}

static bool publish_line_internal(const char *line, size_t length,
                                  bool armed_line)
{
    if (!output_publish_begin()) return false;
    if (line == NULL || length == 0U ||
        !shield.output.enter(shield.output.context,
                             WIFI_SHIELD_OUTPUT_TIMEOUT_MS)) {
        mark_output_failure();
        output_publish_end();
        return false;
    }
    bool written = shield.output.write(shield.output.context, line, length);
    if (!written) queue_output_failure();
    shield.output.complete(shield.output.context, written);
    if (written && armed_line)
        atomic_store_explicit(&shield.presentation_armed_accepted, true,
                              memory_order_release);
    shield.output.leave(shield.output.context);
    flush_output_failures();
    output_publish_end();
    return written;
}

static bool publish_line(const char *line, size_t length)
{
    return publish_line_internal(line, length, false);
}

static bool publish_event(const wifi_shield_event_t *event);

static bool publish_terminal_internal(shield_outcome_t outcome,
                                      bool stop_owner)
{
    if (!stop_owner && !output_publish_begin()) return false;
    wifi_shield_status_t terminal_status;
    state_enter();
    shield.terminal.outcome = outcome;
    terminal_status = shield.terminal.status;
    state_leave();
    if (!shield.output.enter(shield.output.context,
                             WIFI_SHIELD_OUTPUT_TIMEOUT_MS)) {
        mark_output_failure();
        if (!stop_owner) output_publish_end();
        return false;
    }
    bool written = shield.output.write_terminal(
        shield.output.context, &terminal_status, outcome_text(outcome));
    if (!written) queue_output_failure();
    shield.output.complete(shield.output.context, written);
    shield.output.leave(shield.output.context);
    flush_output_failures();
    if (!stop_owner) output_publish_end();
    return written;
}

static bool publish_terminal(shield_outcome_t outcome)
{
    return publish_terminal_internal(outcome, false);
}

static bool token_active(void *context)
{
    uintptr_t token = (uintptr_t)context;
    return token != 0U &&
        token == atomic_load_explicit(&shield.active_token,
                                      memory_order_acquire);
}

static void presentation_record_decoy_tx(bool accepted)
{
    if (!accepted) return;
    state_enter();
    bool armed = shield.presentation.armed || atomic_load_explicit(
        &shield.presentation_armed_accepted, memory_order_acquire);
    if (armed && shield.presentation.indicator_counts[
            WIFI_SHIELD_PRESENTATION_DECOY_TX] != UINT32_MAX) {
        ++shield.presentation.indicator_counts[
            WIFI_SHIELD_PRESENTATION_DECOY_TX];
        presentation_changed_locked();
    }
    state_leave();
}

static bool defence_random_adapter(void *opaque, uint8_t *out, size_t length)
{
    return token_active(opaque) &&
        shield.runtime.defence_random(shield.runtime.context, out, length);
}

static int defence_tx_adapter(void *opaque, const uint8_t *frame,
                              size_t length, bool en_sys_seq)
{
    if (!token_active(opaque)) return -1;
    return shield.runtime.defence_tx(shield.runtime.context, frame, length,
                                     en_sys_seq);
}

static int defence_tune_adapter(void *opaque, uint8_t channel)
{
    uint8_t bssid[6] = {0};
    state_enter();
    bool valid = token_active(opaque) && shield.state != NULL &&
        !shield.state_wiped && shield.state->defence_enabled;
    if (valid)
        memcpy(bssid, shield.state->defence.core.active_bssid,
               sizeof(bssid));
    state_leave();
    return valid && wifi_shield_channel_lock_running(opaque, bssid, channel) ?
        0 : -1;
}

static int64_t defence_now_adapter(void *opaque)
{
    if (!token_active(opaque)) return 0;
    uint64_t now = shield.runtime.monotonic_us(shield.runtime.context);
    return now > (uint64_t)INT64_MAX ? INT64_MAX : (int64_t)now;
}

static void defence_telemetry_adapter(void *opaque, const char *line)
{
    if (!token_active(opaque) || line == NULL) return;
    size_t length = 0U;
    while (length < WIFI_SHIELD_LINE_MAX && line[length] != '\0') ++length;
    if (length == 0U || length + 2U >= WIFI_SHIELD_LINE_MAX) return;

    char *wire = NULL;
    state_enter();
    bool buffered = token_active(opaque) && shield.state != NULL &&
        !shield.state_wiped && shield.state->defence_buffer_telemetry;
    if (buffered) {
        if (length < sizeof(shield.state->defence_armed_line)) {
            memcpy(shield.state->defence_armed_line, line, length);
            shield.state->defence_armed_line[length] = '\0';
            shield.state->defence_armed_length = length;
        } else {
            shield.state->defence_armed_length = 0U;
        }
        state_leave();
        return;
    }
    if (token_active(opaque) && shield.state != NULL &&
        !shield.state_wiped) {
        wire = shield.state->defence_telemetry_line;
        memcpy(wire, line, length);
        wire[length] = '\r';
        wire[length + 1U] = '\n';
    }
    state_leave();
    if (wire == NULL) return;
    length += 2U;
    bool accepted = publish_line(wire, length);
    state_enter();
    if (token_active(opaque) && shield.state != NULL &&
        !shield.state_wiped && !accepted)
        shield.state->defence_action_output_accepted = false;
    state_leave();
}

static bool defence_prepare(wifi_shield_state_t *state, uintptr_t token,
                            bool pmkid_decoy, bool multi_vector)
{
    if (state == NULL || token == 0U || state->channel_plan.target_count == 0U ||
        state->channel_plan.target_count > DEAUTH_DEFENCE_RUNTIME_TARGETS)
        return false;
    for (size_t i = 0U; i < state->channel_plan.target_count; ++i) {
        memcpy(state->defence_targets[i].bssid,
               state->channel_plan.targets[i].bssid, 6U);
        state->defence_targets[i].channel =
            state->channel_plan.targets[i].channel;
        state->defence_targets[i].wpa2_psk_ccmp =
            state->channel_plan.targets[i].wpa2_psk_ccmp;
    }
    deauth_defence_config_t config = {
        .targets = state->defence_targets,
        .target_count = state->channel_plan.target_count,
        .pmkid_decoy = pmkid_decoy,
        .multi_vector = multi_vector,
        .generation = 1U,
        .opaque = (void *)token,
        .random = defence_random_adapter,
        .tune = defence_tune_adapter,
        .tx = defence_tx_adapter,
        .now = defence_now_adapter,
        .telemetry = defence_telemetry_adapter,
        .build_pair = NULL,
        .build_pmkid = NULL,
    };
    if (!deauth_defence_runtime_start(&state->defence, &config)) return false;
    state->defence_enabled = true;
    state->defence_action_output_accepted = true;
    return true;
}

static void defence_quarantine(void)
{
    state_enter();
    if (shield.state != NULL && !shield.state_wiped) {
        shield.state->defence_admission_open = false;
        int expected = SHIELD_PHASE_RUNNING;
        (void)atomic_compare_exchange_strong_explicit(
            &shield.phase, &expected, SHIELD_PHASE_QUARANTINED,
            memory_order_acq_rel, memory_order_acquire);
    }
    state_leave();
}

static void defence_process_observation(
    void *token, deauth_defence_trigger_t trigger, const uint8_t bssid[6],
    const uint8_t station[6], uint8_t rx_channel, int64_t rx_us)
{
    wifi_shield_state_t *state = NULL;
    uint32_t generation = 0U;
    state_enter();
    if (token_active(token) && shield.state != NULL && !shield.state_wiped &&
        shield.state->defence_enabled &&
        shield.state->defence_admission_open &&
        shield.state->defence_inflight == 0U &&
        atomic_load_explicit(&shield.phase, memory_order_acquire) ==
            SHIELD_PHASE_RUNNING) {
        state = shield.state;
        state->defence_inflight = 1U;
        state->defence_action_output_accepted = true;
        generation = state->defence.core.generation;
    }
    state_leave();
    if (state == NULL) return;

    deauth_defence_runtime_observation_t observation = {
        .generation = generation,
        .trigger = trigger,
        .channel = rx_channel,
        .rx_us = rx_us,
    };
    memcpy(observation.bssid, bssid, 6U);
    if (station != NULL) memcpy(observation.sta, station, 6U);
    (void)deauth_defence_runtime_process(&state->defence, &observation);

    bool response_sent = state->defence.response_sent;
    bool confirmed = true;
    if (response_sent) {
        uint8_t target_channel = 0U;
        for (size_t i = 0U; i < state->channel_plan.target_count; ++i) {
            if (memcmp(state->channel_plan.targets[i].bssid, bssid, 6U) == 0) {
                target_channel = state->channel_plan.targets[i].channel;
                break;
            }
        }
        confirmed = target_channel != 0U && deauth_defence_runtime_confirm(
            &state->defence, bssid, target_channel);
    }

    bool release_failed = false;
    state_enter();
    bool release_attempt = token_active(token) && shield.state == state &&
        state->channel_plan.locked &&
        state->defence.core.state == DEF_ARMED_HOPPING;
    bool output_accepted = state->defence_action_output_accepted;
    state_leave();
    if (release_attempt && !wifi_shield_channel_release_running(token))
        release_failed = true;

    state_enter();
    if (shield.state == state && !shield.state_wiped &&
        state->defence_inflight != 0U)
        --state->defence_inflight;
    state_leave();
    if (!confirmed || release_failed) {
        defence_quarantine();
        return;
    }
    if (response_sent) presentation_record_decoy_tx(output_accepted);
}

static bool shield_feature_validate(void *context)
{
    state_enter();
    bool valid = token_active(context) && shield.state != NULL &&
        !shield.state_wiped &&
        atomic_load_explicit(&shield.phase, memory_order_acquire) ==
            SHIELD_PHASE_STARTING &&
        !atomic_load_explicit(&shield.stop_requested, memory_order_acquire);
    state_leave();
    return valid;
}

typedef struct {
    uint8_t bssid[6];
    uint8_t station[6];
    uint8_t channel;
    int64_t rx_us;
    bool pmkid_association_complete;
} shield_active_full_result_t;

static uint16_t read_le16_shield(const uint8_t *bytes)
{
    return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8U));
}

static bool shield_selector(const uint8_t selector[4], uint8_t oui0,
                            uint8_t oui1, uint8_t oui2, uint8_t type)
{
    return selector[0] == oui0 && selector[1] == oui1 &&
        selector[2] == oui2 && selector[3] == type;
}

static bool shield_rsn_selector(const uint8_t selector[4], uint8_t type)
{
    return shield_selector(selector, 0x00U, 0x0fU, 0xacU, type);
}

static bool shield_cipher_suite(const uint8_t selector[4], bool rsn,
                                bool *legacy)
{
    if (legacy == NULL) return false;
    bool oui = rsn ?
        selector[0] == 0x00U && selector[1] == 0x0fU &&
            selector[2] == 0xacU :
        selector[0] == 0x00U && selector[1] == 0x50U &&
            selector[2] == 0xf2U;
    if (!oui) return false;
    switch (selector[3]) {
    case 1U: /* WEP-40 */
    case 2U: /* TKIP */
    case 5U: /* WEP-104 */
        *legacy = true;
        return true;
    case 4U: /* CCMP-128 */
        return true;
    case 8U: /* GCMP-128 */
    case 9U: /* GCMP-256 */
    case 10U: /* CCMP-256 */
        return rsn;
    default:
        return false;
    }
}

static bool shield_security_ciphers(const sx_security_t *security, bool rsn,
                                    bool *legacy)
{
    if (security == NULL || legacy == NULL ||
        security->status != SX_VALID || security->truncated ||
        !security->group_present || !security->pairwise_known ||
        security->pairwise_count == 0U ||
        !shield_cipher_suite(security->group, rsn, legacy)) return false;
    for (size_t i = 0U; i < security->pairwise_count; ++i)
        if (!shield_cipher_suite(security->pairwise[i], rsn, legacy))
            return false;
    return true;
}

/* Derive only from a complete, validated Beacon/Probe Response advertisement.
 * UNKNOWN is retained whenever absence cannot be proved. */
static bool shield_posture_from_observation(
    const sx_observation_t *observation, wifi_shield_ap_posture_t *posture)
{
    if (observation == NULL || posture == NULL || !observation->complete ||
        (observation->source != SX_BEACON &&
         observation->source != SX_PROBE_RESP) ||
        observation->rsn.status == SX_INVALID ||
        observation->wpa.status == SX_INVALID ||
        observation->wps.status == SX_INVALID) return false;
    memset(posture, 0, sizeof(*posture));

    if (observation->wps.status == SX_VALID)
        posture->wps = observation->wps.present ? WIFI_SHIELD_AP_YES :
                                                  WIFI_SHIELD_AP_NO;
    else if (observation->wps.status == SX_ABSENT)
        posture->wps = WIFI_SHIELD_AP_NO;

    if (observation->rsn.status == SX_VALID &&
        observation->rsn.capabilities_present)
        posture->pmf_required = observation->rsn.pmf_required ?
            WIFI_SHIELD_AP_YES : WIFI_SHIELD_AP_NO;

    bool sae = false, psk = false, akm_complete = false;
    if (observation->rsn.status == SX_VALID &&
        observation->rsn.akm_known && !observation->rsn.truncated &&
        observation->rsn.akm_count != 0U) {
        akm_complete = true;
        for (size_t i = 0U; i < observation->rsn.akm_count; ++i) {
            const uint8_t *akm = observation->rsn.akm[i];
            if (shield_rsn_selector(akm, 8U) ||
                shield_rsn_selector(akm, 9U))
                sae = true;
            else if (shield_rsn_selector(akm, 2U) ||
                     shield_rsn_selector(akm, 4U) ||
                     shield_rsn_selector(akm, 6U))
                psk = true;
            else
                akm_complete = false;
        }
    }
    if (sae)
        posture->wpa3_supported = WIFI_SHIELD_AP_YES;
    else if (akm_complete || observation->rsn.status == SX_ABSENT)
        posture->wpa3_supported = WIFI_SHIELD_AP_NO;
    if (akm_complete)
        posture->transition_mode = sae && psk ? WIFI_SHIELD_AP_YES :
                                               WIFI_SHIELD_AP_NO;
    if (sae && (psk || observation->wpa.status == SX_VALID))
        posture->wpa3_only = WIFI_SHIELD_AP_NO;
    else if (sae && akm_complete &&
             observation->wpa.status == SX_ABSENT)
        posture->wpa3_only = WIFI_SHIELD_AP_YES;
    else if (!sae && akm_complete)
        posture->wpa3_only = WIFI_SHIELD_AP_NO;

    bool legacy = false;
    bool cipher_complete = true;
    bool security_present = false;
    if (observation->rsn.status == SX_VALID) {
        security_present = true;
        cipher_complete &= shield_security_ciphers(&observation->rsn, true,
                                                   &legacy);
    }
    if (observation->wpa.status == SX_VALID) {
        security_present = true;
        cipher_complete &= shield_security_ciphers(&observation->wpa, false,
                                                   &legacy);
    }
    if (legacy)
        posture->legacy_cipher = WIFI_SHIELD_AP_YES;
    else if ((security_present && cipher_complete) ||
             (!security_present && observation->privacy == 0))
        posture->legacy_cipher = WIFI_SHIELD_AP_NO;
    return true;
}

/* Worker-only: slot bytes are borrowed for this call and only normalized
 * scalars leave it. Neighbor beacons feed occupancy, never campaigns. */
static bool observe_beacon_locked(
    wifi_shield_state_t *state, const wifi_security_frame_slot_t *slot,
    const wifi_security_decoded_t *decoded, uint64_t now_us,
    wifi_shield_journal_record_t *health_record,
    wifi_shield_journal_record_t *recommendation_record,
    size_t *recommendation_target_index, bool *recommendation_set_due)
{
    if (recommendation_target_index != NULL)
        *recommendation_target_index = WIFI_SHIELD_TARGET_MAX;
    if (recommendation_set_due != NULL) *recommendation_set_due = false;
    if (state == NULL || slot == NULL || decoded == NULL ||
        (decoded->kind != WIFI_SEC_FRAME_BEACON &&
         decoded->kind != WIFI_SEC_FRAME_PROBE_RESPONSE) ||
        slot->captured_len < 36U || decoded->body_len < 12U ||
        slot->channel == 0U) return false;
    uint64_t tsf = 0U;
    for (unsigned i = 0U; i < 8U; ++i)
        tsf |= (uint64_t)slot->bytes[24U + i] << (i * 8U);
    bool selected = wifi_shield_core_selected(&state->core, decoded->bssid);
    wifi_shield_time_stamp_t stamp = {
        .boot_us = now_us,
        .quality = WIFI_SHIELD_TIME_NONE,
    };
    /* The fixed anchor table is reserved for selected targets. Neighbor
     * occupancy is bounded by AP-health storage and uses local ordering only,
     * so an untrusted neighbor flood cannot starve selected AP-relative time. */
    if (selected && !wifi_shield_time_exact(
            &state->time, decoded->bssid, tsf, now_us, &stamp)) return false;
    /* Probe responses update only the AP timing anchor. They are not cadence
     * samples and cannot affect beacon jitter or neighbor counts. */
    if (decoded->kind == WIFI_SEC_FRAME_PROBE_RESPONSE) return true;
    wifi_shield_ap_beacon_t beacon = {
        .sequence = decoded->sequence,
        .rssi = slot->rssi,
        .channel = slot->channel,
        .band = slot->channel <= 14U ? WIFI_SHIELD_AP_BAND_2GHZ :
                                      WIFI_SHIELD_AP_BAND_5GHZ,
        .interval_tu = read_le16_shield(slot->bytes + 32U),
        .retry = decoded->retry,
        .time = stamp,
    };
    memcpy(beacon.bssid, decoded->bssid, 6U);
    if (!wifi_shield_ap_health_observe_beacon(&state->ap_health, &beacon))
        return false;
    if (!selected || health_record == NULL || recommendation_record == NULL)
        return true;
    size_t selected_index = WIFI_SHIELD_TARGET_MAX;
    for (size_t i = 0U; i < state->channel_plan.target_count; ++i) {
        if (same_bssid(state->channel_plan.targets[i].bssid,
                       decoded->bssid)) {
            selected_index = i;
            break;
        }
    }
    if (selected_index == WIFI_SHIELD_TARGET_MAX) return true;
    wifi_shield_ap_health_snapshot_t snapshot;
    if (!wifi_shield_ap_health_snapshot(&state->ap_health, decoded->bssid,
                                        &snapshot)) return true;
    uint64_t last_health = state->health_journal_us[selected_index];
    uint8_t prior_count =
        state->recommendation_journal_count[selected_index];
    bool recommendations_changed = snapshot.recommendation_count != prior_count;
    for (uint8_t i = 0U; !recommendations_changed && i < prior_count; ++i) {
        const wifi_shield_ap_recommendation_detail_t *current =
            &snapshot.recommendation_details[i];
        const wifi_shield_ap_recommendation_detail_t *prior =
            &state->recommendation_journal_details[selected_index][i];
        recommendations_changed = current->action != prior->action ||
            current->evidence != prior->evidence ||
            current->confidence != prior->confidence;
    }
    bool retry_recommendations =
        state->recommendation_journal_retry[selected_index];
    bool recommendations_due = recommendations_changed || retry_recommendations;
    if (recommendations_due) {
        uint32_t *revision =
            &state->recommendation_journal_revision[selected_index];
        if (*revision != UINT32_MAX) ++*revision;
    }
    if (recommendations_changed) {
        state->recommendation_journal_count[selected_index] =
            snapshot.recommendation_count;
        memset(state->recommendation_journal_details[selected_index], 0,
               sizeof(state->recommendation_journal_details[selected_index]));
        memcpy(state->recommendation_journal_details[selected_index],
               snapshot.recommendation_details,
               snapshot.recommendation_count *
                   sizeof(snapshot.recommendation_details[0]));
    }
    uint32_t recommendation_revision =
        state->recommendation_journal_revision[selected_index];
    bool health_due = last_health == 0U || now_us < last_health ||
        now_us - last_health >= UINT64_C(30000000) ||
        recommendations_due;
    if (health_due) {
        *health_record = (wifi_shield_journal_record_t){
            .type = WIFI_SHIELD_JOURNAL_AP_HEALTH,
            .boot_id = state->journal_boot_id,
            .session_id = state->journal_session_id,
            .sequence = 1U,
            .time = stamp,
            .has_bssid = true,
            .ap_health = snapshot,
            .recommendation_set_revision = recommendation_revision,
            .recommendation_set_count = snapshot.recommendation_count,
        };
        memcpy(health_record->bssid, decoded->bssid, 6U);
        state->health_journal_us[selected_index] = now_us == 0U ? 1U : now_us;
    }
    if (recommendations_due && snapshot.recommendations != 0U) {
        *recommendation_record = (wifi_shield_journal_record_t){
            .type = WIFI_SHIELD_JOURNAL_RECOMMENDATION,
            .boot_id = state->journal_boot_id,
            .session_id = state->journal_session_id,
            .sequence = 1U,
            .time = stamp,
            .has_bssid = true,
            .recommendation_set_revision = recommendation_revision,
            .recommendation_set_count = snapshot.recommendation_count,
            /* PSRAM-owned scratch. The caller submits one normalized journal
             * record per deterministic detail after leaving the state lock. */
            .ap_health = snapshot,
        };
        memcpy(recommendation_record->bssid, decoded->bssid, 6U);
    }
    if (recommendation_target_index != NULL)
        *recommendation_target_index = selected_index;
    if (recommendation_set_due != NULL)
        *recommendation_set_due = recommendations_due;
    return true;
}

/* Worker/state-lock only. Consume every upstream-qualified contribution before
 * the V1 rate decision; journal submit is zero-wait and copies the normalized
 * scratch record before returning. */
static bool shield_qualify_event_locked(wifi_shield_state_t *state,
                                        const wifi_shield_event_t *event)
{
    if (state == NULL || event == NULL) return false;
    wifi_shield_campaign_transition_t transition;
    bool journal_transition = wifi_shield_campaign_observe(
        &state->campaigns, event, &transition);
    if (event->type == WIFI_SHIELD_EVENT_DEAUTH ||
        event->type == WIFI_SHIELD_EVENT_DISASSOC ||
        event->type == WIFI_SHIELD_EVENT_CSA ||
        event->type == WIFI_SHIELD_EVENT_WPS_RETRY_BURST)
        (void)wifi_shield_ap_health_note_event(
            &state->ap_health, event->bssid, event->type, event->count);

    memset(state->journal_scratch, 0, sizeof(state->journal_scratch));
    wifi_shield_journal_record_t *event_record = &state->journal_scratch[0];
    wifi_shield_journal_record_t *transition_record =
        &state->journal_scratch[1];
    wifi_shield_time_stamp_t event_time = {0};
    if (!wifi_shield_time_resolve(&state->time, event->bssid,
                                  event->timestamp_us,
                                  &event_time)) {
        event_time.boot_us = event->timestamp_us;
        event_time.quality = WIFI_SHIELD_TIME_NONE;
    }
    if (shield_journal_aggregate_type(event->type, NULL)) {
        shield_journal_aggregate_add_locked(state, event);
    } else {
        event_record->type = WIFI_SHIELD_JOURNAL_EVENT;
        event_record->boot_id = state->journal_boot_id;
        event_record->session_id = state->journal_session_id;
        event_record->sequence = 1U;
        event_record->time = event_time;
        event_record->has_bssid = true;
        memcpy(event_record->bssid, event->bssid, 6U);
        event_record->event_source = event->source;
        event_record->event_type = event->type;
        if (state->journal_attempted) (void)journal_submit(event_record);
    }
    if (journal_transition) {
        transition_record->type = WIFI_SHIELD_JOURNAL_CAMPAIGN_TRANSITION;
        transition_record->boot_id = state->journal_boot_id;
        transition_record->session_id = state->journal_session_id;
        transition_record->sequence = 1U;
        transition_record->time = event_time;
        transition_record->has_bssid = true;
        memcpy(transition_record->bssid, event->bssid, 6U);
        transition_record->campaign = transition;
        if (state->journal_attempted) (void)journal_submit(transition_record);
    }
    bool publishable = wifi_shield_core_publishable(&state->core, event);
    shield_propagate_quality_locked(state);
    return publishable;
}

static bool shield_feature_consume_modules(
    void *context, const wifi_security_frame_slot_t *slot,
    const wifi_security_decoded_t *decoded,
    shield_active_full_result_t *active)
{
    if (active != NULL) memset(active, 0, sizeof(*active));
    if (!token_active(context) || slot == NULL || decoded == NULL ||
        active == NULL ||
        atomic_load_explicit(&shield.phase, memory_order_acquire) !=
            SHIELD_PHASE_RUNNING) return false;

    uint64_t now_us = shield.runtime.monotonic_us(shield.runtime.context);
    wifi_shield_event_t *pending = NULL;
    size_t pending_count = 0U;
    state_enter();
    if (!token_active(context) || shield.state == NULL || shield.state_wiped) {
        state_leave();
        return false;
    }
    wifi_shield_state_t *state = shield.state;
    bool selected = wifi_shield_core_selected(&state->core, decoded->bssid);
    sx_observation_t observation;
    bool observation_parsed = sx_parse(slot->bytes, slot->captured_len,
                                       &observation);
    if (selected && observation_parsed) {
        wifi_shield_ap_posture_t posture;
        if (shield_posture_from_observation(&observation, &posture))
            (void)wifi_shield_ap_health_note_posture(
                &state->ap_health, decoded->bssid, &posture);
    }
    memset(state->journal_scratch, 0, sizeof(state->journal_scratch));
    wifi_shield_journal_record_t *health_record =
        &state->journal_scratch[0];
    wifi_shield_journal_record_t *recommendation_record =
        &state->journal_scratch[1];
    size_t recommendation_target_index = WIFI_SHIELD_TARGET_MAX;
    bool recommendation_set_due = false;
    pending = state->pending_events;
    (void)observe_beacon_locked(state, slot, decoded, now_us,
                                health_record, recommendation_record,
                                &recommendation_target_index,
                                &recommendation_set_due);
    bool recommendation_set_complete = true;
    if (health_record->type == WIFI_SHIELD_JOURNAL_AP_HEALTH) {
        bool accepted = !state->journal_attempted ||
            journal_submit(health_record);
        if (recommendation_set_due && !accepted)
            recommendation_set_complete = false;
    }
    if (recommendation_record->type == WIFI_SHIELD_JOURNAL_RECOMMENDATION) {
        uint8_t count = recommendation_record->ap_health.recommendation_count;
        for (uint8_t i = 0U; i < count; ++i) {
            recommendation_record->recommendation_set_index = i;
            recommendation_record->recommendation =
                recommendation_record->ap_health.recommendation_details[i];
            bool accepted = !state->journal_attempted ||
                journal_submit(recommendation_record);
            if (!accepted) recommendation_set_complete = false;
        }
    }
    if (recommendation_set_due &&
        recommendation_target_index < WIFI_SHIELD_TARGET_MAX) {
        state->recommendation_journal_retry[recommendation_target_index] =
            state->journal_attempted && !recommendation_set_complete;
    }
    if (!selected) {
        wifi_shield_core_record_input(&state->core, false, false);
        state_leave();
        return true;
    }

    shield_pmkid_candidate_t completed_candidate;
    if (pmkid_candidate_complete(state, decoded, slot->channel,
                                 &completed_candidate) &&
        completed_candidate.active_response) {
        active->pmkid_association_complete = true;
        active->channel = completed_candidate.channel;
        memcpy(active->bssid, completed_candidate.bssid,
               sizeof(active->bssid));
        memcpy(active->station, completed_candidate.station,
               sizeof(active->station));
    }

    wps_guard_fragment_t fragment;
    bool is_wps = wps_guard_decode_fragment(
        decoded, slot->truncated, now_us, &fragment);
    wifi_shield_core_record_input(&state->core, true, is_wps);
    if (is_wps) {
        fragment.channel = slot->channel;
        fragment.rssi = slot->rssi;
        const uint8_t *payload = NULL;
        size_t payload_length = 0U;
        bool payload_ok = wps_guard_payload_view(
            decoded, &fragment, &payload, &payload_length);
        wps_guard_event_t module_event;
        wps_guard_reason_t reason = wps_guard_observe(
            &state->wps_guard, &fragment, &module_event);
        wifi_shield_wps_message_t message = payload_ok ?
            wifi_shield_wps_observe(&state->wps, &fragment, payload,
                                    payload_length) :
            WIFI_SHIELD_WPS_UNKNOWN;
        wifi_shield_event_t event = {
            .source = WIFI_SHIELD_SOURCE_WPS,
            .type = WIFI_SHIELD_EVENT_WPS_ACTIVITY,
            .severity = WIFI_SHIELD_SEVERITY_INFO,
            .channel = slot->channel,
            .count = 1U,
            .window_ms = 10000U,
            .wps_message = message,
            .timestamp_us = now_us,
        };
        memcpy(event.bssid, fragment.bssid, 6U);
        memcpy(event.station, fragment.station, 6U);
        if (shield_qualify_event_locked(state, &event))
            pending[pending_count++] = event;
        if (reason == WPS_GUARD_RETRANSMISSION && pending_count < 5U) {
            event.type = WIFI_SHIELD_EVENT_WPS_RETRY_BURST;
            event.severity = WIFI_SHIELD_SEVERITY_WARN;
            if (shield_qualify_event_locked(state, &event))
                pending[pending_count++] = event;
        }
        bool anomaly = (reason >= WPS_GUARD_FIRST_MISSING_LENGTH &&
                        reason <= WPS_GUARD_EMPTY_MORE_FRAGMENT) ||
                       reason == WPS_GUARD_INVALID_ENVELOPE;
        if (anomaly && pending_count < 5U) {
            event.type = WIFI_SHIELD_EVENT_WPS_ANOMALY;
            event.severity = WIFI_SHIELD_SEVERITY_ALERT;
            if (shield_qualify_event_locked(state, &event))
                pending[pending_count++] = event;
        }
    }

    sae_guard_observation_t sae_observation;
    if (sae_guard_parse(decoded, slot->truncated, now_us,
                        &sae_observation)) {
        sae_observation.channel = slot->channel;
        sae_observation.rssi = slot->rssi;
        sae_guard_event_t module_event;
        bool qualified = sae_guard_observe(
            &state->sae, &sae_observation, &module_event);
        bool anomaly = qualified &&
            (module_event.reason == SAE_GUARD_EVENT_MALFORMED ||
             module_event.reason == SAE_GUARD_EVENT_UNCONFIRMED_COMMITS ||
             module_event.reason == SAE_GUARD_EVENT_GROUP_CHURN);
        wifi_shield_event_t event = {
            .source = WIFI_SHIELD_SOURCE_SAE,
            .type = anomaly ? WIFI_SHIELD_EVENT_SAE_ANOMALY :
                              WIFI_SHIELD_EVENT_SAE_ACTIVITY,
            .severity = anomaly ? WIFI_SHIELD_SEVERITY_ALERT :
                                  WIFI_SHIELD_SEVERITY_INFO,
            .channel = slot->channel,
            .count = 1U,
            .window_ms = 10000U,
            .timestamp_us = now_us,
        };
        memcpy(event.bssid, sae_observation.bssid, 6U);
        memcpy(event.station, sae_observation.station, 6U);
        if (pending_count < 5U &&
            shield_qualify_event_locked(state, &event))
            pending[pending_count++] = event;
    }

    if (state->trust_enabled) {
        if (observation_parsed) {
            wifi_trust_builder_t *builder = NULL;
            wifi_trust_field_mask_t conflicts = 0U;
            wifi_trust_ingest_result_t ingested =
                wifi_trust_table_observe_with_workspace(
                &state->trust_observed, &observation, slot->channel, now_us,
                &builder, &conflicts, &state->trust_workspace);
            secure_zero(&state->trust_current,
                        sizeof(state->trust_current));
            size_t differences = 0U;
            if ((ingested == WIFI_TRUST_INGEST_ACCEPTED ||
                 ingested == WIFI_TRUST_INGEST_CONFLICT) && builder != NULL &&
                wifi_trust_builder_snapshot(builder,
                                            &state->trust_current)) {
                for (size_t i = 0U; i < state->trust_count; ++i) {
                    if (memcmp(state->trust_baseline[i].bssid,
                               state->trust_current.bssid, 6U) == 0) {
                        differences = wifi_trust_diff(
                            &state->trust_baseline[i], &state->trust_current,
                            state->trust_events, WIFI_TRUST_REASON_COUNT);
                        break;
                    }
                }
            } else if (ingested == WIFI_TRUST_INGEST_MALFORMED) {
                differences = wifi_trust_malformed_events(
                    &observation, slot->channel, now_us,
                    state->trust_events, WIFI_TRUST_REASON_COUNT);
                if (differences != 0U)
                    memcpy(state->trust_current.bssid, decoded->bssid, 6U);
            } else if (ingested == WIFI_TRUST_INGEST_CONFLICT &&
                       builder != NULL) {
                differences = wifi_trust_builder_conflict_events(
                    builder, state->trust_events, WIFI_TRUST_REASON_COUNT);
                if (differences != 0U)
                    memcpy(state->trust_current.bssid, decoded->bssid, 6U);
            }
            if (differences != 0U && differences <= WIFI_TRUST_REASON_COUNT &&
                pending_count < 5U) {
                wifi_shield_event_t event = {
                    .source = WIFI_SHIELD_SOURCE_TRUST,
                    .type = WIFI_SHIELD_EVENT_TRUST_DRIFT,
                    .severity = WIFI_SHIELD_SEVERITY_ALERT,
                    .channel = slot->channel,
                    .count = (uint32_t)differences,
                    .timestamp_us = now_us,
                };
                memcpy(event.bssid, state->trust_current.bssid, 6U);
                if (shield_qualify_event_locked(state, &event))
                    pending[pending_count++] = event;
            }
        }
    }

    csa_event_t csa;
    if (pending_count < 5U &&
        csa_parse(slot->bytes, slot->captured_len, slot->channel,
                  slot->rssi, &csa) && same_bssid(csa.bssid, decoded->bssid)) {
        wifi_shield_event_t event = {
            .source = WIFI_SHIELD_SOURCE_DEAUTH,
            .type = WIFI_SHIELD_EVENT_CSA,
            .severity = WIFI_SHIELD_SEVERITY_INFO,
            .channel = slot->channel,
            .count = 1U,
            .window_ms = WIFI_SHIELD_RATE_WINDOW_MS,
            .timestamp_us = now_us,
        };
        memcpy(event.bssid, csa.bssid, 6U);
        if (shield_qualify_event_locked(state, &event))
            pending[pending_count++] = event;
    }
    state_leave();

    for (size_t i = 0U; i < pending_count; ++i) {
        wifi_shield_event_t output_event;
        state_enter();
        bool available = token_active(context) && shield.state == state &&
            !shield.state_wiped;
        if (available) output_event = pending[i];
        state_leave();
        if (!available || !publish_event(&output_event)) return false;
    }
    return true;
}

static void defence_emit_association_complete(
    void *context, const shield_active_full_result_t *active)
{
    if (active == NULL || !active->pmkid_association_complete) return;
    char line[256];
    snprintf(line, sizeof(line),
             "[DETECTOR_DEFENCE] trigger=pmkid_probe BSSID=%02X:%02X:%02X:%02X:%02X:%02X STA=%02X:%02X:%02X:%02X:%02X:%02X RX=%u decision=observe reason=association_complete",
             active->bssid[0], active->bssid[1], active->bssid[2],
             active->bssid[3], active->bssid[4], active->bssid[5],
             active->station[0], active->station[1], active->station[2],
             active->station[3], active->station[4], active->station[5],
             (unsigned)active->channel);
    defence_telemetry_adapter(context, line);
}

static bool shield_feature_consume(void *context,
                                   const wifi_security_frame_slot_t *slot,
                                   const wifi_security_decoded_t *decoded)
{
    shield_active_full_result_t active = {0};
    bool accepted = shield_feature_consume_modules(
        context, slot, decoded, &active);
    defence_emit_association_complete(context, &active);
    return accepted;
}

static bool wifi_shield_attach_trust_monitor(
    wifi_shield_state_t *state, const wifi_trust_profile_t *baseline,
    size_t count)
{
    if (state == NULL) return false;
    if (baseline == NULL || count == 0U || count > WIFI_TRUST_MAX_PROFILES) {
        secure_zero(state->trust_baseline, sizeof(state->trust_baseline));
        state->trust_count = 0U;
        state->trust_enabled = false;
        wifi_trust_table_init(&state->trust_observed);
        return false;
    }
    for (size_t i = 0U; i < count; ++i) {
        if (!wifi_trust_profile_valid(&baseline[i])) goto invalid;
        for (size_t j = 0U; j < i; ++j)
            if (same_bssid(baseline[i].bssid, baseline[j].bssid)) goto invalid;
    }
    if (baseline != state->trust_baseline)
        memcpy(state->trust_baseline, baseline, count * sizeof(*baseline));
    if (count < WIFI_TRUST_MAX_PROFILES)
        secure_zero(state->trust_baseline + count,
                    (WIFI_TRUST_MAX_PROFILES - count) * sizeof(*baseline));
    state->trust_count = count;
    state->trust_enabled = true;
    wifi_trust_table_init(&state->trust_observed);
    secure_zero(state->trust_events, sizeof(state->trust_events));
    return true;

invalid:
    secure_zero(state->trust_baseline, sizeof(state->trust_baseline));
    state->trust_count = 0U;
    state->trust_enabled = false;
    wifi_trust_table_init(&state->trust_observed);
    secure_zero(state->trust_events, sizeof(state->trust_events));
    return false;
}

static void wipe_state_locked(void)
{
    if (shield.state == NULL || shield.state_wiped) return;
    /* Stop snapshots after producer/output joins and before restoration.
     * Startup rollback has no such snapshot and captures it here instead. */
    if (!shield.terminal_ready) snapshot_status_locked();
    shield.terminal.status.running = false;
    shield.terminal.status.stopping = false;
    secure_zero(shield.state, sizeof(*shield.state));
    shield.state_wiped = true;
}

static void shield_feature_wipe(void *context)
{
    state_enter();
    if (token_active(context) && shield.state != NULL &&
        !shield.state_wiped)
        wipe_state_locked();
    state_leave();
}

static void shield_feature_uncertainty(void *context,
                                       wifi_security_session_result_t result,
                                       bool owned)
{
    (void)result;
    (void)owned;
    if (token_active(context)) {
        /* The cleanup callback is synchronous.  When Stop already owns the
         * lifecycle in STOPPING, keep that exclusive phase until the outer
         * controller has durably checkpointed SESSION_UNCERTAIN.  Publishing
         * QUARANTINED here would let a retry race the current owner. */
        int expected = SHIELD_PHASE_RUNNING;
        (void)atomic_compare_exchange_strong_explicit(
            &shield.phase, &expected, SHIELD_PHASE_QUARANTINED,
            memory_order_acq_rel, memory_order_acquire);
    }
}

static void wipe_and_release_state(void)
{
    state_enter();
    wifi_shield_state_t *released = shield.state;
    if (released != NULL) {
        wipe_state_locked();
        shield.state = NULL;
        shield.state_wiped = false;
        atomic_store_explicit(&shield.active_token, 0U,
                              memory_order_release);
    }
    state_leave();
    if (released != NULL)
        shield.runtime.storage_release(shield.runtime.context,
                                       (void **)&released,
                                       sizeof(wifi_shield_state_t));
}

static bool finish_local_failure(shield_outcome_t outcome)
{
    /* Own the sole terminal path before callbacks into abort/release hooks.
     * Reentrant Start observes FINALIZING and returns without publishing or
     * mutating the shared terminal snapshot. */
    atomic_store_explicit(&shield.phase, SHIELD_PHASE_FINALIZING,
                          memory_order_release);
    shield_capture_v2_retained();
    shield.terminal.outcome = outcome;
    if (!shield_submit_terminal_bounded(outcome, 5000U)) {
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_STORAGE_PENDING,
                              memory_order_release);
        return false;
    }
    if (!shield_finish_journal(true, 5000U)) {
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_STORAGE_PENDING,
                              memory_order_release);
        return false;
    }
    shield_update_retained_journal();
    wipe_and_release_state();
    atomic_store_explicit(&shield.stop_requested, false, memory_order_release);
    shield.radio_quiesced = false;
    shield.output_drained = false;
    shield.terminal_ready = false;
    shield.radio_restored = false;
    shield.journal_uncertain_recorded = false;
    shield.journal_uncertain_durable = false;
    shield.journal_uncertain_pending = false;
    shield.journal_terminal_pending = false;
    presentation_set_finished();
    bool written = publish_terminal(outcome);
    atomic_store_explicit(&shield.phase, SHIELD_PHASE_IDLE,
                          memory_order_release);
    return written;
}

static void release_unpublished_state(wifi_shield_state_t **candidate)
{
    if (candidate == NULL || *candidate == NULL) return;
    secure_zero(*candidate, sizeof(**candidate));
    shield.runtime.storage_release(shield.runtime.context,
                                   (void **)candidate,
                                   sizeof(wifi_shield_state_t));
}

static bool finish_prestart_failure(wifi_shield_state_t **candidate,
                                    uintptr_t token,
                                    shield_outcome_t outcome)
{
    atomic_store_explicit(&shield.phase, SHIELD_PHASE_FINALIZING,
                          memory_order_release);
    if (shield.scan_reserved) {
        if (!shield.runtime.abort_prepare(shield.runtime.context, 5000U)) {
            state_enter();
            shield.state = candidate != NULL ? *candidate : NULL;
            if (shield.state != NULL) {
                *candidate = NULL;
                shield.state_wiped = false;
                atomic_store_explicit(&shield.active_token, token,
                                      memory_order_release);
            }
            state_leave();
            atomic_store_explicit(&shield.phase, SHIELD_PHASE_QUARANTINED,
                                  memory_order_release);
            return false;
        }
        shield.scan_reserved = false;
    }
    wifi_shield_status_t terminal_status = {0};
    if (candidate != NULL && *candidate != NULL)
        wifi_shield_core_status(&(*candidate)->core, &terminal_status);
    terminal_status.running = false;
    terminal_status.stopping = false;
    state_enter();
    shield.terminal.status = terminal_status;
    shield.terminal.outcome = outcome;
    state_leave();
    if (candidate != NULL && *candidate != NULL &&
        (*candidate)->journal_attempted) {
        state_enter();
        shield.v2->boot_id = (*candidate)->journal_boot_id;
        shield.v2->session_id = (*candidate)->journal_session_id;
        shield.v2->journal_valid = true;
        state_leave();
        if (!shield_submit_terminal_bounded(outcome, 5000U)) {
            state_enter();
            shield.state = *candidate;
            *candidate = NULL;
            shield.state_wiped = false;
            shield.terminal_ready = true;
            shield.radio_restored = true;
            atomic_store_explicit(&shield.active_token, token,
                                  memory_order_release);
            state_leave();
            atomic_store_explicit(&shield.phase,
                                  SHIELD_PHASE_STORAGE_PENDING,
                                  memory_order_release);
            return false;
        }
        if (!shield_finish_journal(true, 5000U)) {
            state_enter();
            shield.state = *candidate;
            *candidate = NULL;
            shield.state_wiped = false;
            shield.terminal_ready = true;
            shield.radio_restored = true;
            atomic_store_explicit(&shield.active_token, token,
                                  memory_order_release);
            state_leave();
            atomic_store_explicit(&shield.phase,
                                  SHIELD_PHASE_STORAGE_PENDING,
                                  memory_order_release);
            return false;
        }
        shield_update_retained_journal();
    }
    release_unpublished_state(candidate);
    atomic_store_explicit(&shield.active_token, 0U, memory_order_release);
    atomic_store_explicit(&shield.stop_requested, false, memory_order_release);
    shield.radio_quiesced = false;
    shield.output_drained = false;
    shield.terminal_ready = false;
    bool written = publish_terminal(outcome);
    atomic_store_explicit(&shield.phase, SHIELD_PHASE_IDLE,
                          memory_order_release);
    return written;
}

static bool parse_index(const char *text, size_t *value)
{
    if (text == NULL || value == NULL || text[0] == '\0') return false;
    size_t parsed = 0U;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p < '0' || *p > '9') return false;
        size_t digit = (size_t)(*p - '0');
        if (parsed > (SIZE_MAX - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    if (parsed == 0U || parsed > WIFI_SHIELD_TARGET_MAX) return false;
    *value = parsed;
    return true;
}

static bool collect_indices(const wifi_shield_cli_t *cli, char **argv,
                            size_t indices[WIFI_SHIELD_TARGET_MAX])
{
    if (!cli->only) return true;
    if (cli->index_count <= 0 ||
        (size_t)cli->index_count > WIFI_SHIELD_TARGET_MAX) return false;
    for (int i = 0; i < cli->index_count; ++i) {
        size_t value;
        if (!parse_index(argv[cli->first_index_arg + i], &value)) return false;
        for (int j = 0; j < i; ++j)
            if (indices[j] == value) return false;
        indices[i] = value;
    }
    return true;
}

static shield_outcome_t result_outcome(wifi_security_session_result_t result)
{
    switch (result) {
    case WIFI_SECURITY_SESSION_BUSY:
    case WIFI_SECURITY_SESSION_BASELINE_BUSY:
        return SHIELD_OUTCOME_BUSY;
    case WIFI_SECURITY_SESSION_CANCELLED:
    case WIFI_SECURITY_SESSION_JOIN_TIMEOUT:
        return SHIELD_OUTCOME_TIMEOUT;
    case WIFI_SECURITY_SESSION_CHANNEL_FAILED:
    case WIFI_SECURITY_SESSION_RESTORE_FAILED:
    case WIFI_SECURITY_SESSION_CLEANUP_FAILED:
    case WIFI_SECURITY_SESSION_FILTER_SNAPSHOT_FAILED:
    case WIFI_SECURITY_SESSION_FILTER_APPLY_FAILED:
    case WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED:
        return SHIELD_OUTCOME_RESTORE_FAILED;
    default:
        return SHIELD_OUTCOME_INVALID;
    }
}

static bool uncertain_result(wifi_security_session_result_t result)
{
    return result == WIFI_SECURITY_SESSION_JOIN_TIMEOUT ||
           result == WIFI_SECURITY_SESSION_RESTORE_FAILED ||
           result == WIFI_SECURITY_SESSION_CLEANUP_FAILED ||
           result == WIFI_SECURITY_SESSION_FILTER_RESTORE_FAILED;
}

static int start_command(const wifi_shield_cli_t *cli, char **argv)
{
    size_t indices[WIFI_SHIELD_TARGET_MAX] = {0};
    if (!collect_indices(cli, argv, indices)) {
        (void)publish_terminal(SHIELD_OUTCOME_INVALID);
        return 1;
    }
    if (profile_lifecycle_phase(atomic_load_explicit(
            &shield.profile.lifecycle, memory_order_acquire)) !=
            SHIELD_PROFILE_NONE) {
        snapshot_status();
        (void)publish_terminal(SHIELD_OUTCOME_BUSY);
        return 1;
    }
    int observed = atomic_load_explicit(&shield.phase, memory_order_acquire);
    if (observed == SHIELD_PHASE_STOPPING ||
        observed == SHIELD_PHASE_FINALIZING) return 1;
    if (!shield.output.idle(shield.output.context)) {
        observed = atomic_load_explicit(&shield.phase, memory_order_acquire);
        if (observed == SHIELD_PHASE_STOPPING ||
            observed == SHIELD_PHASE_FINALIZING) return 1;
        snapshot_status();
        (void)publish_terminal(SHIELD_OUTCOME_BUSY);
        return 1;
    }
    int expected = SHIELD_PHASE_IDLE;
    state_enter();
    bool claimed = atomic_load_explicit(&shield.phase, memory_order_acquire) ==
        SHIELD_PHASE_IDLE;
    if (claimed) {
        atomic_store_explicit(&shield.stop_requested, false,
                              memory_order_release);
        claimed = atomic_compare_exchange_strong_explicit(
            &shield.phase, &expected, SHIELD_PHASE_STARTING,
            memory_order_acq_rel, memory_order_acquire);
    } else {
        expected = atomic_load_explicit(&shield.phase, memory_order_acquire);
    }
    state_leave();
    if (!claimed) {
        if (expected == SHIELD_PHASE_STOPPING ||
            expected == SHIELD_PHASE_FINALIZING) return 1;
        snapshot_status();
        (void)publish_terminal(SHIELD_OUTCOME_BUSY);
        return 1;
    }
    atomic_store_explicit(&shield.output_admission_open, false,
                          memory_order_release);
    if (atomic_load_explicit(&shield.output_inflight, memory_order_acquire) !=
            0U || !shield.output.idle(shield.output.context)) {
        state_enter();
        atomic_store_explicit(&shield.stop_requested, false,
                              memory_order_release);
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_IDLE,
                              memory_order_release);
        state_leave();
        atomic_store_explicit(&shield.output_admission_open, true,
                              memory_order_release);
        return 1;
    }
    atomic_store_explicit(&shield.presentation_armed_accepted, false,
                          memory_order_release);
    atomic_store_explicit(&shield.output_failed, false, memory_order_release);
    atomic_store_explicit(&shield.pending_output_failures, 0U,
                          memory_order_release);
    state_enter();
    shield.state_wiped = false;
    memset(&shield.terminal, 0, sizeof(shield.terminal));
    shield.terminal.status.active_defence = cli->defence;
    shield.terminal.status.pmkid_decoy = cli->pmkid_decoy;
    shield.terminal.status.multi_vector = cli->multi_vector;
    shield.terminal.status.protect_all = cli->protect_all;
    state_leave();
    atomic_store_explicit(&shield.output_admission_open, true,
                          memory_order_release);
    shield.scan_reserved = false;
    shield.radio_quiesced = false;
    shield.output_drained = false;
    shield.terminal_ready = false;

    void *storage = NULL;
    if (!shield.runtime.storage_acquire(shield.runtime.context,
                                        sizeof(wifi_shield_state_t), &storage) ||
        storage == NULL) {
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_FINALIZING,
                              memory_order_release);
        (void)publish_terminal(SHIELD_OUTCOME_NO_MEM);
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_IDLE,
                              memory_order_release);
        return 1;
    }
    wifi_shield_state_t *candidate = storage;
    memset(candidate, 0, sizeof(*candidate));
    candidate->core.active_defence = cli->defence;
    candidate->core.pmkid_decoy = cli->pmkid_decoy;
    candidate->core.multi_vector = cli->multi_vector;
    candidate->core.protect_all = cli->protect_all;

    if (!cli->only) {
        /* Treat reserve as potentially owning until abort proves otherwise.
         * A failed platform reserve may have retained a PREPARING lease when
         * baseline rollback could not be verified. */
        shield.scan_reserved = true;
        if (!shield.runtime.reserve_scan(shield.runtime.context)) {
            (void)finish_prestart_failure(&candidate, 0U,
                                          SHIELD_OUTCOME_BUSY);
            return 1;
        }
    }

    size_t target_count = 0U;
    bool scanned = cli->only ? shield.runtime.scan_snapshot(
        shield.runtime.context, indices, (size_t)cli->index_count,
        candidate->target_snapshot, WIFI_SHIELD_TARGET_MAX, &target_count) :
        shield.runtime.scan_all(shield.runtime.context,
        candidate->target_snapshot, WIFI_SHIELD_TARGET_MAX, &target_count);
    bool trust_ok = false;
    if (scanned && target_count != 0U) {
        trust_ok = shield.runtime.trust_snapshot(
            shield.runtime.context, candidate->trust_baseline,
            WIFI_TRUST_MAX_PROFILES, &candidate->trust_count);
    }
    if (!trust_ok || candidate->trust_count > WIFI_TRUST_MAX_PROFILES)
        candidate->trust_count = 0U;
    (void)wifi_shield_attach_trust_monitor(
        candidate, candidate->trust_count != 0U ?
            candidate->trust_baseline : NULL,
        candidate->trust_count);
    if (!scanned || target_count == 0U ||
        !wifi_shield_channel_plan_init(&candidate->channel_plan,
                                       candidate->target_snapshot,
                                       target_count)) {
        (void)finish_prestart_failure(&candidate, 0U,
                                      SHIELD_OUTCOME_INVALID);
        return 1;
    }
    wifi_shield_core_init(&candidate->core, &candidate->channel_plan);
    wifi_shield_time_init(&candidate->time, SHIELD_TIME_ANCHOR_MAX_AGE_US);
    if (!wifi_shield_campaign_init(&candidate->campaigns,
                                   &candidate->channel_plan)) {
        (void)finish_prestart_failure(&candidate, 0U,
                                      SHIELD_OUTCOME_INVALID);
        return 1;
    }
    wifi_shield_ap_health_init(&candidate->ap_health);
    const wifi_shield_ap_posture_t unknown_posture = {0};
    for (size_t i = 0U; i < candidate->channel_plan.target_count; ++i)
        (void)wifi_shield_ap_health_note_posture(
            &candidate->ap_health,
            candidate->channel_plan.targets[i].bssid, &unknown_posture);
    shield_propagate_quality_locked(candidate);
    wps_guard_core_init(&candidate->wps_guard);
    wifi_shield_wps_reset(&candidate->wps);
    sae_guard_core_init(&candidate->sae);
    pmkid_probe_reset(&candidate->pmkid);
    candidate->core.active_defence = cli->defence;
    candidate->core.pmkid_decoy = cli->pmkid_decoy;
    candidate->core.multi_vector = cli->multi_vector;
    candidate->core.protect_all = cli->protect_all;
    candidate->started_us = shield.runtime.monotonic_us(shield.runtime.context);
    state_enter();
    shield.next_session_id = increment_nonzero(shield.next_session_id);
    candidate->journal_boot_id = shield.boot_id;
    candidate->journal_session_id = shield.next_session_id;
    state_leave();
    if (journal_hooks_complete()) {
        candidate->journal_attempted = true;
        wifi_shield_summary_metadata_t summary_metadata = {
            .target_count = target_count,
            .active_defence = cli->defence,
            .pmkid_decoy = cli->pmkid_decoy,
            .multi_vector = cli->multi_vector,
            .protect_all = cli->protect_all,
        };
        if (target_count != 0U) {
            summary_metadata.primary_target_valid = true;
            memcpy(summary_metadata.primary_bssid,
                   candidate->target_snapshot[0].bssid,
                   sizeof(summary_metadata.primary_bssid));
            summary_metadata.primary_channel =
                candidate->target_snapshot[0].channel;
            memcpy(summary_metadata.primary_ssid,
                   candidate->target_snapshot[0].ssid,
                   sizeof(summary_metadata.primary_ssid));
            summary_metadata.primary_ssid[
                sizeof(summary_metadata.primary_ssid) - 1U] = '\0';
        }
        (void)shield.runtime.journal_start(
            shield.runtime.context, candidate->journal_boot_id,
            candidate->journal_session_id, SHIELD_JOURNAL_QUOTA_BYTES,
            &summary_metadata);
        wifi_shield_journal_record_t start_record = {
            .type = WIFI_SHIELD_JOURNAL_SESSION_START,
            .boot_id = candidate->journal_boot_id,
            .session_id = candidate->journal_session_id,
            .sequence = 1U,
            .target_count = target_count,
            .time = {
                .boot_us = candidate->started_us,
                .quality = WIFI_SHIELD_TIME_NONE,
            },
        };
        (void)journal_submit(&start_record);
    }

    uintptr_t token = new_token();
    if (cli->defence && !defence_prepare(candidate, token,
                                          cli->pmkid_decoy,
                                          cli->multi_vector)) {
        (void)finish_prestart_failure(&candidate, token,
                                      SHIELD_OUTCOME_INVALID);
        return 1;
    }
    uint8_t first_channel = wifi_shield_channel_next(&candidate->channel_plan);
    candidate->core.current_channel = first_channel;
    candidate->next_hop_us = next_deadline(candidate->started_us);
    /* This hook only stages/validates the requested channel. The production
     * start_radio hook applies it inside the owned radio transaction. */
    if (first_channel == 0U ||
        !shield.runtime.tune(shield.runtime.context, first_channel)) {
        (void)finish_prestart_failure(&candidate, token,
                                      SHIELD_OUTCOME_RESTORE_FAILED);
        return 1;
    }
    if (atomic_load_explicit(&shield.stop_requested, memory_order_acquire)) {
        (void)finish_prestart_failure(&candidate, token,
                                      SHIELD_OUTCOME_STOPPED);
        return 1;
    }

    state_enter();
    /* The prior terminal summary remains queryable until this new session is
     * accepted into owned state. From this point every failure path captures
     * the new session before releasing its PSRAM. */
    memset(shield.v2, 0, sizeof(*shield.v2));
    shield.v2->journal.state = WIFI_SHIELD_JOURNAL_UNAVAILABLE;
    shield.v2->journal.time_sources = WIFI_SHIELD_JOURNAL_TIME_MONOTONIC;
    shield.state = candidate;
    candidate = NULL;
    shield.state_wiped = false;
    presentation_begin_locked(shield.state);
    atomic_store_explicit(&shield.active_token, token, memory_order_release);
    state_leave();

    wifi_security_session_config_t config = {
        .module = WIFI_SECURITY_MODULE_SHIELD,
        .context = (void *)token,
        .consume = shield_feature_consume,
        .validate = shield_feature_validate,
        .wipe = shield_feature_wipe,
        .telemetry_context = (void *)token,
        .uncertainty = shield_feature_uncertainty
    };
    wifi_security_session_result_t result =
        shield.runtime.start_radio(shield.runtime.context, &config);
    /* A successful start adopts the reservation. Failed starts are required to
     * complete or retain their own radio cleanup before returning. */
    if (result != WIFI_SECURITY_SESSION_OK) {
        if (uncertain_result(result)) {
            /* For bare Start this latch deliberately remains set. The retry
             * path first asks abort_prepare to resolve a still-PREPARING
             * reservation; it is an idempotent no-op if the session already
             * adopted that generation, after which full split cleanup runs. */
            atomic_store_explicit(&shield.phase, SHIELD_PHASE_QUARANTINED,
                                  memory_order_release);
            return 1;
        }
        shield.scan_reserved = false;
        (void)finish_local_failure(result_outcome(result));
        return 1;
    }
    shield.scan_reserved = false;
    if (atomic_load_explicit(&shield.stop_requested, memory_order_acquire)) {
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_RUNNING,
                              memory_order_release);
        (void)wifi_shield_stop(5000U);
        return 1;
    }

    wifi_security_runtime_status_t running_status = {0};
    shield.runtime.runtime_status(shield.runtime.context, &running_status);
    bool defence_armed = true;
    if (cli->defence) {
        wifi_shield_state_t *arm_state = NULL;
        state_enter();
        if (shield.state != NULL && !shield.state_wiped) {
            arm_state = shield.state;
            ++arm_state->defence_inflight;
            shield.state->defence_buffer_telemetry = true;
            shield.state->defence_armed_length = 0U;
        }
        state_leave();
        defence_armed = arm_state != NULL &&
            running_status.generation != 0U &&
            deauth_defence_runtime_arm(&arm_state->defence,
                                       running_status.generation);
        state_enter();
        if (shield.state == arm_state && !shield.state_wiped) {
            arm_state->defence_buffer_telemetry = false;
            if (defence_armed)
                arm_state->defence_generation = running_status.generation;
            if (arm_state->defence_inflight != 0U)
                --arm_state->defence_inflight;
        }
        state_leave();
    }

    if (atomic_load_explicit(&shield.stop_requested, memory_order_acquire)) {
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_RUNNING,
                              memory_order_release);
        (void)wifi_shield_stop(5000U);
        return 1;
    }

    wifi_shield_status_t armed_status = {0};
    bool cancelled = false;
    state_enter();
    if (shield.state != NULL && !shield.state_wiped) {
        cancelled = atomic_load_explicit(&shield.stop_requested,
                                         memory_order_acquire);
        shield.state->core.running = !cancelled;
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_RUNNING,
                              memory_order_release);
        if (!cancelled)
            wifi_shield_core_status(&shield.state->core, &armed_status);
    }
    state_leave();
    if (cancelled) {
        (void)wifi_shield_stop(5000U);
        return 1;
    }
    char line[WIFI_SHIELD_LINE_MAX];
    int length = wifi_shield_format_armed(
        line, sizeof(line), &armed_status);
    if (length <= 0 ||
        !publish_line_internal(line, (size_t)length, true)) {
        (void)wifi_shield_stop(5000U);
        return 1;
    }
    for (size_t i = 0U; i < armed_status.target_count; ++i) {
        wifi_shield_target_t target = {0};
        bool available = false;
        state_enter();
        if (shield.state != NULL && !shield.state_wiped &&
            shield.state->channel_plan.target_count ==
                armed_status.target_count) {
            target = shield.state->channel_plan.targets[i];
            available = true;
        }
        state_leave();
        length = available ? wifi_shield_format_target(
            line, sizeof(line), &target, i + 1U,
            armed_status.target_count) : -1;
        if (length <= 0 || !publish_line(line, (size_t)length)) {
            (void)wifi_shield_stop(5000U);
            return 1;
        }
    }
    if (cli->defence) {
        char defence_line[sizeof(shield.state->defence_armed_line) + 2U];
        size_t defence_length = 0U;
        state_enter();
        if (shield.state != NULL && !shield.state_wiped && defence_armed) {
            defence_length = shield.state->defence_armed_length;
            if (defence_length < sizeof(defence_line) - 2U)
                memcpy(defence_line, shield.state->defence_armed_line,
                       defence_length);
            else
                defence_length = 0U;
        }
        state_leave();
        if (defence_length == 0U) {
            (void)wifi_shield_stop(5000U);
            return 1;
        }
        defence_line[defence_length++] = '\r';
        defence_line[defence_length++] = '\n';
        if (!publish_line(defence_line, defence_length)) {
            (void)wifi_shield_stop(5000U);
            return 1;
        }
        state_enter();
        if (shield.state != NULL && !shield.state_wiped &&
            atomic_load_explicit(&shield.phase, memory_order_acquire) ==
                SHIELD_PHASE_RUNNING)
            shield.state->defence_admission_open = true;
        state_leave();
    }
    presentation_set_armed(&armed_status);
    return 0;
}

size_t wifi_shield_state_size(void)
{
    return sizeof(wifi_shield_state_t);
}

size_t wifi_shield_retained_size(void)
{
    return sizeof(shield_v2_retained_t);
}

static bool profile_target_plan(const wifi_shield_target_t *targets,
                                size_t target_count,
                                uint8_t channels[WIFI_SHIELD_TARGET_MAX],
                                size_t *channel_count)
{
    if (targets == NULL || channels == NULL || channel_count == NULL ||
        target_count == 0U || target_count > WIFI_SHIELD_TARGET_MAX)
        return false;
    size_t unique_count = 0U;
    for (size_t i = 0U; i < target_count; ++i) {
        if (!valid_profile_bssid(targets[i].bssid) ||
            targets[i].channel == 0U)
            return false;
        for (size_t j = 0U; j < i; ++j)
            if (same_bssid(targets[i].bssid, targets[j].bssid)) return false;
        bool known = false;
        for (size_t j = 0U; j < unique_count; ++j)
            known = known || channels[j] == targets[i].channel;
        if (!known) channels[unique_count++] = targets[i].channel;
    }
    *channel_count = unique_count;
    return unique_count != 0U;
}

static bool profile_explicit_channel_plan(
    const wifi_shield_target_t *targets, size_t target_count,
    const uint8_t *requested_channels, size_t requested_channel_count,
    uint8_t channels[WIFI_SHIELD_TARGET_MAX], size_t *channel_count)
{
    if (requested_channels == NULL || channels == NULL || channel_count == NULL ||
        requested_channel_count == 0U ||
        requested_channel_count > WIFI_SHIELD_TARGET_MAX ||
        target_count > WIFI_SHIELD_TARGET_MAX ||
        (target_count != 0U && targets == NULL))
        return false;
    for (size_t i = 0U; i < requested_channel_count; ++i) {
        if (requested_channels[i] == 0U) return false;
        for (size_t j = 0U; j < i; ++j)
            if (requested_channels[j] == requested_channels[i]) return false;
        channels[i] = requested_channels[i];
    }
    for (size_t i = 0U; i < target_count; ++i) {
        if (!valid_profile_bssid(targets[i].bssid) ||
            targets[i].channel == 0U)
            return false;
        for (size_t j = 0U; j < i; ++j)
            if (same_bssid(targets[i].bssid, targets[j].bssid)) return false;
        bool channel_present = false;
        for (size_t j = 0U; j < requested_channel_count; ++j)
            channel_present = channel_present ||
                requested_channels[j] == targets[i].channel;
        if (!channel_present) return false;
    }
    *channel_count = requested_channel_count;
    return true;
}

static wifi_security_session_result_t start_profile(
    wifi_security_module_t module,
    const wifi_shield_target_t *targets, size_t target_count,
    const uint8_t *requested_channels, size_t requested_channel_count,
    const wifi_security_session_config_t *config,
    wifi_shield_deauth_scan_token_t *scan_token)
{
    uint8_t channels[WIFI_SHIELD_TARGET_MAX] = {0};
    size_t channel_count = 0U;
    bool bare_trust = module == WIFI_SECURITY_MODULE_TRUST_MONITOR &&
        targets == NULL && target_count == 0U;
    bool deauth_profile = module == WIFI_SECURITY_MODULE_DEAUTH_V2;
    if (!atomic_load_explicit(&shield.initialized, memory_order_acquire) ||
        (module != WIFI_SECURITY_MODULE_WPS_GUARD &&
         module != WIFI_SECURITY_MODULE_SAE_GUARD &&
         module != WIFI_SECURITY_MODULE_TRUST_MONITOR &&
         module != WIFI_SECURITY_MODULE_DEAUTH_V2) ||
        config == NULL || config->module != module ||
        config->consume == NULL || config->validate == NULL ||
        config->wipe == NULL || config->uncertainty == NULL ||
        (deauth_profile && !profile_explicit_channel_plan(
            targets, target_count, requested_channels, requested_channel_count,
            channels, &channel_count)) ||
        (!deauth_profile && !bare_trust && !profile_target_plan(
            targets, target_count, channels, &channel_count)))
        return WIFI_SECURITY_SESSION_INVALID;
    if (atomic_load_explicit(&shield.phase, memory_order_acquire) !=
            SHIELD_PHASE_IDLE)
        return WIFI_SECURITY_SESSION_BUSY;
    unsigned existing = atomic_load_explicit(&shield.profile.lifecycle,
                                             memory_order_acquire);
    bool adopting_scan = deauth_profile && scan_token != NULL &&
        scan_token->held && scan_token->packed_lifecycle != 0U &&
        existing == scan_token->packed_lifecycle &&
        profile_lifecycle_phase(existing) == SHIELD_PROFILE_PREPARING &&
        profile_lifecycle_module(existing) == WIFI_SECURITY_MODULE_DEAUTH_V2;
    if (scan_token != NULL && !adopting_scan)
        return WIFI_SECURITY_SESSION_CANCELLED;
    unsigned epoch = adopting_scan ? profile_lifecycle_epoch(existing) :
                                     new_profile_epoch();
    if (adopting_scan)
        *scan_token = (wifi_shield_deauth_scan_token_t){0};
    if (!adopting_scan) {
        unsigned expected = profile_lifecycle(
            0U, WIFI_SECURITY_MODULE_NONE, SHIELD_PROFILE_NONE);
        if (!atomic_compare_exchange_strong_explicit(
                &shield.profile.lifecycle, &expected,
                profile_lifecycle(epoch, module, SHIELD_PROFILE_PREPARING),
                memory_order_acq_rel, memory_order_acquire))
            return WIFI_SECURITY_SESSION_BUSY;
    }
    if (atomic_load_explicit(&shield.phase, memory_order_acquire) !=
            SHIELD_PHASE_IDLE) {
        state_enter();
        (void)profile_clear_epoch_locked(epoch, module);
        state_leave();
        return WIFI_SECURITY_SESSION_BUSY;
    }
    if (!shield.runtime.profile_gate_enter(
            shield.runtime.context, SHIELD_PROFILE_CANCEL_TIMEOUT_MS)) {
        state_enter();
        bool cleared = profile_clear_epoch_locked(epoch, module);
        unsigned failed = atomic_load_explicit(
            &shield.profile.lifecycle, memory_order_acquire);
        state_leave();
        return cleared ||
            profile_lifecycle_phase(failed) == SHIELD_PROFILE_NONE ||
            profile_lifecycle_epoch(failed) != epoch ||
            profile_lifecycle_module(failed) != module ?
            WIFI_SECURITY_SESSION_CANCELLED :
            WIFI_SECURITY_SESSION_CLEANUP_FAILED;
    }
    unsigned lifecycle = atomic_load_explicit(&shield.profile.lifecycle,
                                               memory_order_acquire);
    unsigned preparing = profile_lifecycle(
        epoch, module, SHIELD_PROFILE_PREPARING);
    if (lifecycle != preparing ||
        atomic_load_explicit(&shield.phase, memory_order_acquire) !=
            SHIELD_PHASE_IDLE) {
        state_enter();
        unsigned cancelled = atomic_load_explicit(
            &shield.profile.lifecycle, memory_order_acquire);
        shield_profile_phase_t cancelled_phase =
            profile_lifecycle_phase(cancelled);
        if (profile_lifecycle_epoch(cancelled) == epoch &&
            profile_lifecycle_module(cancelled) == module &&
            (cancelled_phase == SHIELD_PROFILE_STOPPING_PREPARE ||
             cancelled_phase == SHIELD_PROFILE_PREPARING))
            (void)profile_clear_epoch_locked(epoch, module);
        state_leave();
        shield.runtime.profile_gate_leave(shield.runtime.context);
        return lifecycle == preparing ?
            WIFI_SECURITY_SESSION_BUSY : WIFI_SECURITY_SESSION_CANCELLED;
    }

    state_enter();
    lifecycle = atomic_load_explicit(&shield.profile.lifecycle,
                                     memory_order_acquire);
    if (lifecycle != preparing) {
        if (profile_lifecycle_epoch(lifecycle) == epoch &&
            profile_lifecycle_module(lifecycle) == module &&
            profile_lifecycle_phase(lifecycle) ==
                SHIELD_PROFILE_STOPPING_PREPARE)
            (void)profile_clear_epoch_locked(epoch, module);
        state_leave();
        shield.runtime.profile_gate_leave(shield.runtime.context);
        return WIFI_SECURITY_SESSION_CANCELLED;
    }
    shield.profile.module = module;
    memcpy(shield.profile.channels, channels, channel_count);
    shield.profile.channel_count = channel_count;
    shield.profile.cursor = channel_count > 1U ? 1U : 0U;
    shield.profile.generation = 0U;
    shield.profile.next_hop_us = 0U;
    state_leave();

    wifi_security_session_config_t requested = *config;
    requested.module = module;
    requested.initial_channel = channel_count == 0U ? 0U : channels[0];
    wifi_security_session_result_t result =
        shield.runtime.profile_start_radio(shield.runtime.context,
                                           &requested);
    if (result != WIFI_SECURITY_SESSION_OK) {
        state_enter();
        for (;;) {
            lifecycle = atomic_load_explicit(&shield.profile.lifecycle,
                                             memory_order_acquire);
            shield_profile_phase_t failed_phase =
                profile_lifecycle_phase(lifecycle);
            if (profile_lifecycle_epoch(lifecycle) != epoch ||
                profile_lifecycle_module(lifecycle) != module ||
                (failed_phase != SHIELD_PROFILE_PREPARING &&
                 failed_phase != SHIELD_PROFILE_STOPPING_PREPARE))
                break;
            if (!uncertain_result(result)) {
                (void)profile_clear_epoch_locked(epoch, module);
                break;
            }
            if (profile_transition(epoch, module, failed_phase,
                                   SHIELD_PROFILE_QUARANTINED))
                break;
        }
        state_leave();
        shield.runtime.profile_gate_leave(shield.runtime.context);
        return result;
    }

    wifi_security_runtime_status_t status = {0};
    shield.runtime.runtime_status(shield.runtime.context, &status);
    bool adopted = status.running && !status.stopping &&
        status.module == module &&
        status.generation != 0U;
    if (adopted) {
        uint64_t deadline = next_deadline(
            shield.runtime.monotonic_us(shield.runtime.context));
        state_enter();
        if (atomic_load_explicit(&shield.profile.lifecycle,
                                 memory_order_acquire) == preparing) {
            shield.profile.generation = status.generation;
            shield.profile.next_hop_us = deadline;
        }
        bool armed = profile_transition(
            epoch, module, SHIELD_PROFILE_PREPARING,
            SHIELD_PROFILE_RUNNING);
        state_leave();
        if (armed) {
            shield.runtime.profile_gate_leave(shield.runtime.context);
            return WIFI_SECURITY_SESSION_OK;
        }
        lifecycle = atomic_load_explicit(&shield.profile.lifecycle,
                                         memory_order_acquire);
    } else {
        if (profile_transition(epoch, module, SHIELD_PROFILE_PREPARING,
                               SHIELD_PROFILE_QUARANTINED)) {
            shield.runtime.profile_gate_leave(shield.runtime.context);
            return WIFI_SECURITY_SESSION_CLEANUP_FAILED;
        }
        lifecycle = atomic_load_explicit(&shield.profile.lifecycle,
                                         memory_order_acquire);
    }

    bool stopped = false;
    shield_profile_phase_t profile_phase =
        profile_lifecycle_phase(lifecycle);
    bool same_reservation = profile_lifecycle_epoch(lifecycle) == epoch &&
        profile_lifecycle_module(lifecycle) == module;
    if (same_reservation &&
        profile_phase == SHIELD_PROFILE_STOPPING_PREPARE)
        stopped = shield.runtime.profile_stop_radio(
            shield.runtime.context, SHIELD_PROFILE_CANCEL_TIMEOUT_MS);
    state_enter();
    if (stopped)
        (void)profile_clear_epoch_locked(epoch, module);
    else if (same_reservation)
        (void)profile_transition(epoch, module, profile_phase,
                                 SHIELD_PROFILE_QUARANTINED);
    state_leave();
    shield.runtime.profile_gate_leave(shield.runtime.context);
    return stopped ? WIFI_SECURITY_SESSION_CANCELLED :
                     WIFI_SECURITY_SESSION_CLEANUP_FAILED;
}

static bool stop_profile(wifi_security_module_t module, uint32_t timeout_ms)
{
    if (!atomic_load_explicit(&shield.initialized, memory_order_acquire))
        return true;
    unsigned lifecycle = atomic_load_explicit(&shield.profile.lifecycle,
                                               memory_order_acquire);
    shield_profile_phase_t initial = profile_lifecycle_phase(lifecycle);
    if (initial == SHIELD_PROFILE_NONE) return true;
    if (profile_lifecycle_module(lifecycle) != module) return true;
    unsigned epoch = profile_lifecycle_epoch(lifecycle);
    if (epoch == 0U) return false;
    shield_profile_phase_t phase;
    for (;;) {
        lifecycle = atomic_load_explicit(&shield.profile.lifecycle,
                                         memory_order_acquire);
        phase = profile_lifecycle_phase(lifecycle);
        if (phase == SHIELD_PROFILE_NONE) return true;
        if (profile_lifecycle_module(lifecycle) != module ||
            profile_lifecycle_epoch(lifecycle) != epoch)
            return true;
        if (phase == SHIELD_PROFILE_STOPPING_PREPARE ||
            phase == SHIELD_PROFILE_STOPPING_RUNTIME)
            break;
        shield_profile_phase_t stopping_phase;
        if (phase == SHIELD_PROFILE_PREPARING)
            stopping_phase = SHIELD_PROFILE_STOPPING_PREPARE;
        else if (phase == SHIELD_PROFILE_RUNNING ||
                 phase == SHIELD_PROFILE_QUARANTINED)
            stopping_phase = SHIELD_PROFILE_STOPPING_RUNTIME;
        else
            return false;
        if (profile_transition(epoch, module, phase, stopping_phase)) {
            phase = stopping_phase;
            break;
        }
    }

    if (!shield.runtime.profile_gate_enter(shield.runtime.context,
                                            timeout_ms))
        return false;
    lifecycle = atomic_load_explicit(&shield.profile.lifecycle,
                                     memory_order_acquire);
    if (profile_lifecycle_epoch(lifecycle) != epoch ||
        profile_lifecycle_module(lifecycle) != module) {
        shield.runtime.profile_gate_leave(shield.runtime.context);
        return true;
    }
    shield_profile_phase_t current = profile_lifecycle_phase(lifecycle);
    if (current == SHIELD_PROFILE_QUARANTINED) {
        shield.runtime.profile_gate_leave(shield.runtime.context);
        return false;
    }
    if (current == SHIELD_PROFILE_STOPPING_PREPARE) {
        bool aborted = module != WIFI_SECURITY_MODULE_DEAUTH_V2 ||
            shield.runtime.profile_abort_prepare(
                shield.runtime.context, module, timeout_ms);
        state_enter();
        if (aborted)
            (void)profile_clear_epoch_locked(epoch, module);
        else
            (void)profile_transition(epoch, module,
                                     SHIELD_PROFILE_STOPPING_PREPARE,
                                     SHIELD_PROFILE_QUARANTINED);
        state_leave();
        shield.runtime.profile_gate_leave(shield.runtime.context);
        return aborted;
    }
    if (current != SHIELD_PROFILE_STOPPING_RUNTIME) {
        shield.runtime.profile_gate_leave(shield.runtime.context);
        return false;
    }

    if (!radio_enter(timeout_ms)) {
        (void)profile_transition(epoch, module,
                                 SHIELD_PROFILE_STOPPING_RUNTIME,
                                 SHIELD_PROFILE_QUARANTINED);
        shield.runtime.profile_gate_leave(shield.runtime.context);
        return false;
    }
    radio_leave();
    if (!shield.runtime.profile_stop_radio(shield.runtime.context,
                                            timeout_ms)) {
        (void)profile_transition(epoch, module,
                                 SHIELD_PROFILE_STOPPING_RUNTIME,
                                 SHIELD_PROFILE_QUARANTINED);
        shield.runtime.profile_gate_leave(shield.runtime.context);
        return false;
    }
    state_enter();
    (void)profile_clear_epoch_locked(epoch, module);
    state_leave();
    shield.runtime.profile_gate_leave(shield.runtime.context);
    return true;
}

wifi_security_session_result_t wifi_shield_start_wps_profile(
    const wifi_shield_target_t *targets, size_t target_count,
    const wifi_security_session_config_t *config)
{
    return start_profile(WIFI_SECURITY_MODULE_WPS_GUARD, targets,
                         target_count, NULL, 0U, config, NULL);
}

bool wifi_shield_stop_wps_profile(uint32_t timeout_ms)
{
    return stop_profile(WIFI_SECURITY_MODULE_WPS_GUARD, timeout_ms);
}

wifi_security_session_result_t wifi_shield_start_sae_profile(
    const wifi_shield_target_t *targets, size_t target_count,
    const wifi_security_session_config_t *config)
{
    return start_profile(WIFI_SECURITY_MODULE_SAE_GUARD, targets,
                         target_count, NULL, 0U, config, NULL);
}

bool wifi_shield_stop_sae_profile(uint32_t timeout_ms)
{
    return stop_profile(WIFI_SECURITY_MODULE_SAE_GUARD, timeout_ms);
}

wifi_security_session_result_t wifi_shield_start_trust_profile(
    const wifi_shield_target_t *targets, size_t target_count,
    const wifi_security_session_config_t *config)
{
    return start_profile(WIFI_SECURITY_MODULE_TRUST_MONITOR, targets,
                         target_count, NULL, 0U, config, NULL);
}

bool wifi_shield_stop_trust_profile(uint32_t timeout_ms)
{
    return stop_profile(WIFI_SECURITY_MODULE_TRUST_MONITOR, timeout_ms);
}

wifi_security_session_result_t wifi_shield_start_deauth_profile(
    const wifi_shield_target_t *targets, size_t target_count,
    const uint8_t *channels, size_t channel_count,
    const wifi_security_session_config_t *config,
    wifi_shield_deauth_scan_token_t *scan_token)
{
    return start_profile(WIFI_SECURITY_MODULE_DEAUTH_V2, targets,
                         target_count, channels, channel_count, config,
                         scan_token);
}

bool wifi_shield_stop_deauth_profile(uint32_t timeout_ms)
{
    return stop_profile(WIFI_SECURITY_MODULE_DEAUTH_V2, timeout_ms);
}

bool wifi_shield_deauth_profile_pending(void)
{
    unsigned lifecycle = atomic_load_explicit(&shield.profile.lifecycle,
                                               memory_order_acquire);
    return profile_lifecycle_module(lifecycle) ==
               WIFI_SECURITY_MODULE_DEAUTH_V2 &&
           profile_lifecycle_phase(lifecycle) != SHIELD_PROFILE_NONE;
}

bool wifi_shield_reserve_deauth_scan(wifi_shield_deauth_scan_token_t *token)
{
    if (token == NULL || token->held ||
        !atomic_load_explicit(&shield.initialized, memory_order_acquire) ||
        atomic_load_explicit(&shield.phase, memory_order_acquire) !=
            SHIELD_PHASE_IDLE)
        return false;
    unsigned epoch = new_profile_epoch();
    unsigned expected = profile_lifecycle(
        0U, WIFI_SECURITY_MODULE_NONE, SHIELD_PROFILE_NONE);
    unsigned preparing = profile_lifecycle(
        epoch, WIFI_SECURITY_MODULE_DEAUTH_V2, SHIELD_PROFILE_PREPARING);
    if (!atomic_compare_exchange_strong_explicit(
            &shield.profile.lifecycle, &expected, preparing,
            memory_order_acq_rel, memory_order_acquire))
        return false;
    if (!shield.runtime.profile_gate_enter(
            shield.runtime.context, SHIELD_PROFILE_CANCEL_TIMEOUT_MS)) {
        state_enter();
        (void)profile_clear_epoch_locked(epoch,
                                         WIFI_SECURITY_MODULE_DEAUTH_V2);
        state_leave();
        return false;
    }
    bool current = atomic_load_explicit(&shield.profile.lifecycle,
                                        memory_order_acquire) == preparing;
    bool reserved = current && shield.runtime.profile_reserve_scan(
        shield.runtime.context, WIFI_SECURITY_MODULE_DEAUTH_V2);
    unsigned retained_lifecycle = 0U;
    if (!reserved) {
        bool aborted = shield.runtime.profile_abort_prepare(
            shield.runtime.context, WIFI_SECURITY_MODULE_DEAUTH_V2,
            SHIELD_PROFILE_CANCEL_TIMEOUT_MS);
        state_enter();
        if (aborted)
            (void)profile_clear_epoch_locked(
                epoch, WIFI_SECURITY_MODULE_DEAUTH_V2);
        else {
            (void)profile_transition(
                epoch, WIFI_SECURITY_MODULE_DEAUTH_V2,
                SHIELD_PROFILE_PREPARING, SHIELD_PROFILE_QUARANTINED);
            unsigned observed = atomic_load_explicit(
                &shield.profile.lifecycle, memory_order_acquire);
            if (profile_lifecycle_epoch(observed) == epoch &&
                profile_lifecycle_module(observed) ==
                    WIFI_SECURITY_MODULE_DEAUTH_V2 &&
                profile_lifecycle_phase(observed) != SHIELD_PROFILE_NONE)
                retained_lifecycle = observed;
        }
        state_leave();
    }
    shield.runtime.profile_gate_leave(shield.runtime.context);
    if (reserved) {
        token->packed_lifecycle = preparing;
        token->held = true;
    } else if (retained_lifecycle != 0U) {
        token->packed_lifecycle = retained_lifecycle;
        token->held = true;
    }
    return reserved;
}

bool wifi_shield_abort_deauth_scan(wifi_shield_deauth_scan_token_t *token,
                                   uint32_t timeout_ms)
{
    if (token == NULL || !token->held ||
        token->packed_lifecycle == 0U)
        return false;
    unsigned lifecycle = atomic_load_explicit(&shield.profile.lifecycle,
                                               memory_order_acquire);
    unsigned token_epoch = profile_lifecycle_epoch(token->packed_lifecycle);
    if (profile_lifecycle_module(token->packed_lifecycle) !=
            WIFI_SECURITY_MODULE_DEAUTH_V2 || token_epoch == 0U) {
        *token = (wifi_shield_deauth_scan_token_t){0};
        return false;
    }
    if (profile_lifecycle_phase(lifecycle) == SHIELD_PROFILE_NONE) {
        *token = (wifi_shield_deauth_scan_token_t){0};
        return true;
    }
    if (profile_lifecycle_module(lifecycle) !=
            WIFI_SECURITY_MODULE_DEAUTH_V2 ||
        profile_lifecycle_epoch(lifecycle) != token_epoch) {
        *token = (wifi_shield_deauth_scan_token_t){0};
        return true;
    }
    unsigned epoch = token_epoch;
    if (!shield.runtime.profile_gate_enter(shield.runtime.context, timeout_ms))
        return false;
    lifecycle = atomic_load_explicit(&shield.profile.lifecycle,
                                     memory_order_acquire);
    shield_profile_phase_t phase = profile_lifecycle_phase(lifecycle);
    bool same = profile_lifecycle_epoch(lifecycle) == epoch &&
        profile_lifecycle_module(lifecycle) ==
            WIFI_SECURITY_MODULE_DEAUTH_V2;
    bool aborted = same &&
        (phase == SHIELD_PROFILE_PREPARING ||
         phase == SHIELD_PROFILE_STOPPING_PREPARE ||
         phase == SHIELD_PROFILE_QUARANTINED) &&
        shield.runtime.profile_abort_prepare(
            shield.runtime.context, WIFI_SECURITY_MODULE_DEAUTH_V2,
            timeout_ms);
    state_enter();
    if (aborted)
        (void)profile_clear_epoch_locked(epoch,
                                         WIFI_SECURITY_MODULE_DEAUTH_V2);
    else if (same && phase != SHIELD_PROFILE_QUARANTINED)
        (void)profile_transition(epoch, WIFI_SECURITY_MODULE_DEAUTH_V2,
                                 phase, SHIELD_PROFILE_QUARANTINED);
    state_leave();
    shield.runtime.profile_gate_leave(shield.runtime.context);
    if (aborted) *token = (wifi_shield_deauth_scan_token_t){0};
    return aborted;
}

bool wifi_shield_deauth_profile_radio_enter(
    uint8_t channel, wifi_shield_deauth_radio_token_t *token)
{
    if (token == NULL || token->held || channel == 0U ||
        !atomic_load_explicit(&shield.initialized, memory_order_acquire) ||
        !shield.runtime.profile_gate_enter(
            shield.runtime.context, WIFI_SHIELD_OUTPUT_TIMEOUT_MS))
        return false;
    *token = (wifi_shield_deauth_radio_token_t){0};
    unsigned lifecycle = atomic_load_explicit(
        &shield.profile.lifecycle, memory_order_acquire);
    bool current = profile_lifecycle_phase(lifecycle) ==
            SHIELD_PROFILE_RUNNING &&
        profile_lifecycle_module(lifecycle) ==
            WIFI_SECURITY_MODULE_DEAUTH_V2;
    uint32_t generation = 0U;
    if (current) {
        state_enter();
        current = atomic_load_explicit(&shield.profile.lifecycle,
                                       memory_order_acquire) == lifecycle;
        for (size_t i = 0U; current && i < shield.profile.channel_count; ++i)
            if (shield.profile.channels[i] == channel) {
                generation = shield.profile.generation;
                break;
            }
        current = current && generation != 0U;
        state_leave();
    }
    if (!current || !radio_enter(WIFI_SHIELD_OUTPUT_TIMEOUT_MS)) {
        shield.runtime.profile_gate_leave(shield.runtime.context);
        return false;
    }
    wifi_security_runtime_status_t before = {0};
    shield.runtime.runtime_status(shield.runtime.context, &before);
    current = atomic_load_explicit(&shield.profile.lifecycle,
                                   memory_order_acquire) == lifecycle &&
        before.running && !before.stopping &&
        before.module == WIFI_SECURITY_MODULE_DEAUTH_V2 &&
        before.generation == generation;
    bool tuned = current && shield.runtime.profile_retune(
        shield.runtime.context, WIFI_SECURITY_MODULE_DEAUTH_V2,
        generation, channel);
    wifi_security_runtime_status_t after = {0};
    shield.runtime.runtime_status(shield.runtime.context, &after);
    current = tuned && atomic_load_explicit(&shield.profile.lifecycle,
                                            memory_order_acquire) == lifecycle &&
        after.running && !after.stopping &&
        after.module == WIFI_SECURITY_MODULE_DEAUTH_V2 &&
        after.generation == generation;
    if (!current) {
        radio_leave();
        shield.runtime.profile_gate_leave(shield.runtime.context);
        return false;
    }
    token->packed_lifecycle = lifecycle;
    token->runtime_generation = generation;
    token->channel = channel;
    token->held = true;
    return true;
}

bool wifi_shield_deauth_profile_radio_leave(
    wifi_shield_deauth_radio_token_t *token)
{
    if (token == NULL || !token->held) return false;
    wifi_security_runtime_status_t status = {0};
    shield.runtime.runtime_status(shield.runtime.context, &status);
    bool current = atomic_load_explicit(&shield.profile.lifecycle,
                                        memory_order_acquire) ==
            token->packed_lifecycle &&
        profile_lifecycle_phase(token->packed_lifecycle) ==
            SHIELD_PROFILE_RUNNING &&
        profile_lifecycle_module(token->packed_lifecycle) ==
            WIFI_SECURITY_MODULE_DEAUTH_V2 &&
        status.running && !status.stopping &&
        status.module == WIFI_SECURITY_MODULE_DEAUTH_V2 &&
        status.generation == token->runtime_generation;
    radio_leave();
    shield.runtime.profile_gate_leave(shield.runtime.context);
    *token = (wifi_shield_deauth_radio_token_t){0};
    return current;
}

bool wifi_shield_deauth_profile_retune(uint8_t channel)
{
    wifi_shield_deauth_radio_token_t token = {0};
    return wifi_shield_deauth_profile_radio_enter(channel, &token) &&
        wifi_shield_deauth_profile_radio_leave(&token);
}

bool wifi_shield_deauth_profile_generation(uint32_t *generation)
{
    if (generation == NULL ||
        !atomic_load_explicit(&shield.initialized, memory_order_acquire))
        return false;
    unsigned lifecycle = atomic_load_explicit(
        &shield.profile.lifecycle, memory_order_acquire);
    if (profile_lifecycle_phase(lifecycle) != SHIELD_PROFILE_RUNNING ||
        profile_lifecycle_module(lifecycle) != WIFI_SECURITY_MODULE_DEAUTH_V2)
        return false;
    wifi_security_runtime_status_t status = {0};
    shield.runtime.runtime_status(shield.runtime.context, &status);
    state_enter();
    bool current = atomic_load_explicit(&shield.profile.lifecycle,
                                        memory_order_acquire) == lifecycle &&
        shield.profile.generation != 0U && status.running && !status.stopping &&
        status.module == WIFI_SECURITY_MODULE_DEAUTH_V2 &&
        status.generation == shield.profile.generation;
    uint32_t value = shield.profile.generation;
    state_leave();
    if (!current) return false;
    *generation = value;
    return true;
}

bool wifi_shield_init(const wifi_shield_runtime_hooks_t *runtime,
                      const wifi_shield_output_hooks_t *output,
                      void *retained_storage, size_t retained_bytes)
{
    bool journal_any = runtime != NULL &&
        (runtime->journal_boot_id != NULL || runtime->journal_start != NULL ||
         runtime->journal_submit != NULL || runtime->journal_status != NULL ||
         runtime->journal_acknowledge_degraded != NULL ||
         runtime->journal_drain != NULL ||
         runtime->journal_finish != NULL);
    bool journal_all = runtime != NULL &&
        runtime->journal_boot_id != NULL && runtime->journal_start != NULL &&
        runtime->journal_submit != NULL && runtime->journal_status != NULL &&
        runtime->journal_acknowledge_degraded != NULL &&
        runtime->journal_drain != NULL &&
        runtime->journal_finish != NULL;
    if (runtime == NULL || output == NULL || retained_storage == NULL ||
        retained_bytes != sizeof(shield_v2_retained_t) ||
        (uintptr_t)retained_storage % _Alignof(shield_v2_retained_t) != 0U ||
        runtime->storage_acquire == NULL || runtime->storage_release == NULL ||
        runtime->scan_all == NULL || runtime->scan_snapshot == NULL ||
        runtime->trust_snapshot == NULL || runtime->reserve_scan == NULL ||
        runtime->abort_prepare == NULL || runtime->start_radio == NULL ||
        runtime->tune == NULL || runtime->retune == NULL ||
        runtime->radio_enter == NULL || runtime->radio_leave == NULL ||
        runtime->state_enter == NULL || runtime->state_leave == NULL ||
        runtime->runtime_status == NULL || runtime->quiesce_radio == NULL ||
        runtime->finish_radio_cleanup == NULL ||
        runtime->monotonic_us == NULL || runtime->defence_random == NULL ||
        runtime->defence_tx == NULL || runtime->profile_start_radio == NULL ||
        runtime->profile_stop_radio == NULL ||
        runtime->profile_retune == NULL ||
        runtime->profile_gate_enter == NULL ||
        runtime->profile_gate_leave == NULL ||
        runtime->profile_reserve_scan == NULL ||
        runtime->profile_abort_prepare == NULL || output->enter == NULL ||
        output->leave == NULL || output->write == NULL ||
        output->write_terminal == NULL || output->complete == NULL ||
        output->idle == NULL || output->drain == NULL ||
        output->take_failures == NULL || (journal_any && !journal_all))
        return false;
    if (atomic_load_explicit(&shield.initialized, memory_order_acquire) &&
        (wifi_shield_busy() || shield.v2 != retained_storage)) return false;
    shield.runtime = *runtime;
    shield.output = *output;
    shield.v2 = retained_storage;
    uint32_t boot_id = journal_all ?
        runtime->journal_boot_id(runtime->context) : 1U;
    if (boot_id == 0U) boot_id = 1U;
    if (shield.boot_id != boot_id) shield.next_session_id = 0U;
    shield.boot_id = boot_id;
    state_enter();
    shield.state = NULL;
    shield.state_wiped = false;
    memset(&shield.terminal, 0, sizeof(shield.terminal));
    memset(&shield.presentation, 0, sizeof(shield.presentation));
    memset(shield.v2, 0, sizeof(*shield.v2));
    shield.v2->journal.state = WIFI_SHIELD_JOURNAL_UNAVAILABLE;
    shield.v2->journal.time_sources = WIFI_SHIELD_JOURNAL_TIME_MONOTONIC;
    state_leave();
    atomic_store_explicit(&shield.output_failed, false, memory_order_release);
    atomic_store_explicit(&shield.output_admission_open, true,
                          memory_order_release);
    atomic_store_explicit(&shield.pending_output_failures, 0U,
                          memory_order_release);
    atomic_store_explicit(&shield.output_inflight, 0U, memory_order_release);
    shield.scan_reserved = false;
    shield.radio_quiesced = false;
    shield.output_drained = false;
    shield.terminal_ready = false;
    shield.radio_restored = false;
    shield.journal_uncertain_recorded = false;
    shield.journal_uncertain_durable = false;
    shield.journal_uncertain_pending = false;
    shield.journal_terminal_pending = false;
    atomic_store_explicit(&shield.active_token, 0U, memory_order_release);
    atomic_store_explicit(&shield.stop_requested, false, memory_order_release);
    atomic_store_explicit(&shield.presentation_armed_accepted, false,
                          memory_order_release);
    state_enter();
    profile_reset_locked();
    state_leave();
    atomic_store_explicit(&shield.phase, SHIELD_PHASE_IDLE,
                          memory_order_release);
    atomic_store_explicit(&shield.initialized, true, memory_order_release);
    return true;
}

bool wifi_shield_busy(void)
{
    if (!atomic_load_explicit(&shield.initialized, memory_order_acquire))
        return false;
    int phase = atomic_load_explicit(&shield.phase, memory_order_acquire);
    shield_profile_phase_t profile_phase = profile_lifecycle_phase(
        atomic_load_explicit(&shield.profile.lifecycle,
                             memory_order_acquire));
    return phase_has_state(phase) || profile_phase != SHIELD_PROFILE_NONE ||
           atomic_load_explicit(&shield.output_inflight,
                                memory_order_acquire) != 0U ||
           !shield.output.idle(shield.output.context);
}

bool wifi_shield_stop(uint32_t timeout_ms)
{
    if (!atomic_load_explicit(&shield.initialized, memory_order_acquire))
        return true;
    int phase = atomic_load_explicit(&shield.phase, memory_order_acquire);
    if (phase == SHIELD_PHASE_STORAGE_PENDING) {
        /* Radio is already restored. This retry owns only the writer join and
         * must not re-enter any radio/Defence cleanup path. */
        int expected = SHIELD_PHASE_STORAGE_PENDING;
        if (!atomic_compare_exchange_strong_explicit(
                &shield.phase, &expected, SHIELD_PHASE_FINALIZING,
                memory_order_acq_rel, memory_order_acquire)) return false;
        if (!shield_flush_all_journal_aggregates(timeout_ms)) {
            expected = SHIELD_PHASE_FINALIZING;
            (void)atomic_compare_exchange_strong_explicit(
                &shield.phase, &expected, SHIELD_PHASE_STORAGE_PENDING,
                memory_order_acq_rel, memory_order_acquire);
            return false;
        }
        if (shield.journal_terminal_pending &&
            !shield_submit_terminal_bounded(shield.terminal.outcome,
                                             timeout_ms)) {
            expected = SHIELD_PHASE_FINALIZING;
            (void)atomic_compare_exchange_strong_explicit(
                &shield.phase, &expected, SHIELD_PHASE_STORAGE_PENDING,
                memory_order_acq_rel, memory_order_acquire);
            return false;
        }
        if (!shield_finish_journal(true, timeout_ms)) {
            expected = SHIELD_PHASE_FINALIZING;
            bool rolled_back = atomic_compare_exchange_strong_explicit(
                &shield.phase, &expected, SHIELD_PHASE_STORAGE_PENDING,
                memory_order_acq_rel, memory_order_acquire);
            (void)rolled_back;
            return false;
        }
        shield_update_retained_journal();
        wipe_and_release_state();
        presentation_set_finished();
        bool written = publish_terminal_internal(shield.terminal.outcome, true);
        shield.radio_quiesced = false;
        shield.radio_restored = false;
        shield.output_drained = false;
        shield.terminal_ready = false;
        shield.journal_uncertain_recorded = false;
        shield.journal_uncertain_durable = false;
        shield.journal_uncertain_pending = false;
        shield.journal_terminal_pending = false;
        atomic_store_explicit(&shield.stop_requested, false,
                              memory_order_release);
        atomic_store_explicit(&shield.output_admission_open, true,
                              memory_order_release);
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_IDLE,
                              memory_order_release);
        return written;
    }
    if (phase == SHIELD_PHASE_STARTING) {
        state_enter();
        phase = atomic_load_explicit(&shield.phase, memory_order_acquire);
        if (phase == SHIELD_PHASE_STARTING) {
            atomic_store_explicit(&shield.stop_requested, true,
                                  memory_order_release);
            state_leave();
            return false;
        }
        state_leave();
    }
    if (phase == SHIELD_PHASE_IDLE) return true;
    if (phase == SHIELD_PHASE_STOPPING) return false;
    if (phase != SHIELD_PHASE_RUNNING && phase != SHIELD_PHASE_QUARANTINED)
        return false;
    /* QUARANTINED retry owns its storage obligation and all following cleanup
     * through a distinct CAS phase.  No second/reentrant Stop can race the
     * plain journal obligation fields or cross the radio boundary. */
    if (phase == SHIELD_PHASE_QUARANTINED) {
        int quarantine = SHIELD_PHASE_QUARANTINED;
        if (!atomic_compare_exchange_strong_explicit(
                &shield.phase, &quarantine,
                SHIELD_PHASE_UNCERTAINTY_PENDING,
                memory_order_acq_rel, memory_order_acquire)) return false;
        phase = SHIELD_PHASE_UNCERTAINTY_PENDING;
        if (shield.journal_uncertain_pending &&
            !shield_submit_uncertainty_bounded(
                SHIELD_OUTCOME_RESTORE_FAILED, timeout_ms)) {
            atomic_store_explicit(&shield.phase, SHIELD_PHASE_QUARANTINED,
                                  memory_order_release);
            return false;
        }
    }
    if (!radio_enter(timeout_ms)) {
        if (phase == SHIELD_PHASE_UNCERTAINTY_PENDING)
            atomic_store_explicit(&shield.phase, SHIELD_PHASE_QUARANTINED,
                                  memory_order_release);
        return false;
    }
    int observed_phase = atomic_load_explicit(&shield.phase,
                                              memory_order_acquire);
    if (observed_phase != phase) {
        radio_leave();
        return false;
    }
    int expected = phase;
    if (!atomic_compare_exchange_strong_explicit(
            &shield.phase, &expected, SHIELD_PHASE_STOPPING,
            memory_order_acq_rel, memory_order_acquire)) {
        radio_leave();
        return false;
    }
    atomic_store_explicit(&shield.stop_requested, true, memory_order_release);
    state_enter();
    if (shield.state != NULL && !shield.state_wiped) {
        shield.state->core.running = false;
        shield.state->core.stopping = true;
        shield.state->defence_admission_open = false;
        if (shield.state->defence_enabled &&
            !shield.state->defence_finished)
            deauth_defence_runtime_request_stop(&shield.state->defence);
        presentation_set_stopping_locked();
    }
    state_leave();
    radio_leave();
    if (shield.scan_reserved) {
        if (!shield.runtime.abort_prepare(shield.runtime.context, timeout_ms)) {
            atomic_store_explicit(&shield.phase, SHIELD_PHASE_QUARANTINED,
                                  memory_order_release);
            return false;
        }
        shield.scan_reserved = false;
    }
    if (!shield.radio_quiesced) {
        if (!shield.runtime.quiesce_radio(shield.runtime.context, timeout_ms)) {
            atomic_store_explicit(&shield.phase, SHIELD_PHASE_QUARANTINED,
                                  memory_order_release);
            return false;
        }
        shield.radio_quiesced = true;
    }
    wifi_security_runtime_status_t final_runtime_status = {0};
    shield.runtime.runtime_status(shield.runtime.context,
                                  &final_runtime_status);
    merge_runtime_drops(&final_runtime_status);
    wifi_shield_state_t *defence_state = NULL;
    bool defence_joined = true;
    state_enter();
    if (shield.state != NULL && !shield.state_wiped &&
        shield.state->defence_enabled &&
        !shield.state->defence_finished) {
        defence_state = shield.state;
        defence_joined = defence_state->defence_inflight == 0U;
    }
    state_leave();
    if (defence_state != NULL)
        defence_joined = defence_joined && deauth_defence_runtime_join(
            &defence_state->defence, timeout_ms);
    if (!defence_joined) {
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_QUARANTINED,
                              memory_order_release);
        return false;
    }
    if (defence_state != NULL) {
        deauth_defence_runtime_finish_stop(
            &defence_state->defence, final_runtime_status.rx_drops);
        state_enter();
        if (shield.state == defence_state && !shield.state_wiped)
            defence_state->defence_finished = true;
        state_leave();
    }
    atomic_store_explicit(&shield.output_admission_open, false,
                          memory_order_release);
    if (!shield.output_drained) {
        if (!shield.output.drain(shield.output.context, timeout_ms)) {
            atomic_store_explicit(&shield.phase, SHIELD_PHASE_QUARANTINED,
                                  memory_order_release);
            return false;
        }
        shield.output_drained = true;
        flush_output_failures();
        mark_output_failures(
            shield.output.take_failures(shield.output.context));
    }
    flush_output_failures();
    if (atomic_load_explicit(&shield.output_inflight,
                             memory_order_acquire) != 0U) {
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_QUARANTINED,
                              memory_order_release);
        return false;
    }
    if (!shield.terminal_ready) {
        state_enter();
        snapshot_status_locked();
        shield.terminal.status.running = false;
        shield.terminal.status.stopping = false;
        shield.terminal_ready = true;
        state_leave();
    }
    /* Successful runtime restoration invokes the feature wipe callback. Flush
     * every remaining scalar bucket before that ownership boundary. Admission
     * stays zero-wait here: storage can report loss but cannot delay radio
     * restoration. */
    state_enter();
    if (shield.state != NULL && !shield.state_wiped)
        (void)shield_flush_journal_aggregates_locked(
            shield.state, UINT64_MAX, true);
    state_leave();
    /* Capture the bounded V2 view immediately before the wipe boundary. */
    shield_capture_v2_retained();
    if (!shield.runtime.finish_radio_cleanup(shield.runtime.context,
                                              timeout_ms)) {
        (void)shield_submit_uncertainty_bounded(
            SHIELD_OUTCOME_RESTORE_FAILED, timeout_ms);
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_QUARANTINED,
                              memory_order_release);
        return false;
    }
    shield.radio_restored = true;
    shield_outcome_t final_outcome =
        atomic_load_explicit(&shield.output_failed, memory_order_acquire) ?
            SHIELD_OUTCOME_OUTPUT_FAILED : SHIELD_OUTCOME_STOPPED;
    shield.terminal.outcome = final_outcome;
    if (!shield_flush_all_journal_aggregates(timeout_ms)) {
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_STORAGE_PENDING,
                              memory_order_release);
        return false;
    }
    if (!shield_submit_terminal_bounded(final_outcome, timeout_ms)) {
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_STORAGE_PENDING,
                              memory_order_release);
        return false;
    }
    if (!shield_finish_journal(true, timeout_ms)) {
        atomic_store_explicit(&shield.phase, SHIELD_PHASE_STORAGE_PENDING,
                              memory_order_release);
        return false;
    }
    shield_update_retained_journal();
    wipe_and_release_state();
    presentation_set_finished();
    atomic_store_explicit(&shield.stop_requested, false, memory_order_release);
    atomic_store_explicit(&shield.phase, SHIELD_PHASE_FINALIZING,
                          memory_order_release);
    bool written = publish_terminal_internal(final_outcome, true);
    shield.radio_quiesced = false;
    shield.radio_restored = false;
    shield.output_drained = false;
    shield.terminal_ready = false;
    shield.journal_uncertain_recorded = false;
    shield.journal_uncertain_durable = false;
    shield.journal_uncertain_pending = false;
    shield.journal_terminal_pending = false;
    atomic_store_explicit(&shield.output_admission_open, true,
                          memory_order_release);
    atomic_store_explicit(&shield.phase, SHIELD_PHASE_IDLE,
                          memory_order_release);
    return written;
}

static int publish_v2_report(void)
{
    bool wrote = false;
    char line[WIFI_SHIELD_LINE_MAX];
    for (size_t i = 0U; i < WIFI_SHIELD_TARGET_MAX; ++i) {
        wifi_shield_campaign_snapshot_t campaign = {0};
        wifi_shield_ap_health_snapshot_t health = {0};
        uint8_t bssid[6] = {0};
        bool campaign_valid = false;
        bool health_valid = false;
        state_enter();
        if (shield.state != NULL && !shield.state_wiped &&
            i < shield.state->channel_plan.target_count) {
            memcpy(bssid, shield.state->channel_plan.targets[i].bssid, 6U);
            campaign_valid = wifi_shield_campaign_snapshot(
                &shield.state->campaigns, bssid, &campaign) &&
                campaign.id != 0U;
            health_valid = wifi_shield_ap_health_snapshot(
                &shield.state->ap_health, bssid, &health);
        } else if (i == 0U && shield.v2->campaign_valid) {
            campaign = shield.v2->campaign;
            memcpy(bssid, shield.v2->bssid, 6U);
            campaign_valid = true;
            health = shield.v2->ap_health;
            health_valid = shield.v2->ap_health_valid;
        } else if (i == 0U && shield.v2->ap_health_valid) {
            health = shield.v2->ap_health;
            memcpy(bssid, shield.v2->bssid, 6U);
            health_valid = true;
        }
        state_leave();
        if (!campaign_valid && !health_valid) {
            if (i == 0U) continue;
            break;
        }
        if (campaign_valid) {
            int length = wifi_shield_format_campaign_report(
                line, sizeof(line), &campaign);
            if (length <= 0 || !publish_line(line, (size_t)length)) return 1;
            wrote = true;
        }
        if (health_valid) {
            int length = wifi_shield_format_ap_health(
                line, sizeof(line), bssid, &health);
            if (length <= 0 || !publish_line(line, (size_t)length)) return 1;
            wrote = true;
            for (uint8_t detail = 0U;
                 detail < health.recommendation_count; ++detail) {
                length = wifi_shield_format_recommendation(
                    line, sizeof(line), bssid,
                    &health.recommendation_details[detail]);
                if (length <= 0 || !publish_line(line, (size_t)length))
                    return 1;
            }
        }
    }
    return wrote ? 0 : 1;
}

static int publish_v2_log_status(void)
{
    wifi_shield_journal_status_t status = {0};
    bool retained = false;
    state_enter();
    /* Running, quarantined and storage-pending sessions still own the live
     * journal platform, even when radio cleanup has wiped the feature payload.
     * Only release clears the state pointer; use retained terminal status then. */
    if (shield.state == NULL && shield.v2->journal_valid) {
        status = shield.v2->journal;
        retained = true;
    }
    state_leave();
    if (!retained) status = journal_status();
    char line[WIFI_SHIELD_LINE_MAX];
    int length = wifi_shield_format_log_status(line, sizeof(line), &status);
    return length > 0 && publish_line(line, (size_t)length) ? 0 : 1;
}

int wifi_shield_command(int argc, char **argv)
{
    if (!atomic_load_explicit(&shield.initialized, memory_order_acquire) ||
        argv == NULL || argc < 2 || argv[0] == NULL || argv[1] == NULL ||
        strcmp(argv[0], "wifi_shield") != 0) {
        if (atomic_load_explicit(&shield.initialized, memory_order_acquire))
            (void)publish_terminal(SHIELD_OUTCOME_INVALID);
        return 1;
    }
    wifi_shield_cli_t cli;
    if (wifi_shield_parse_cli(argc, argv, &cli) != WIFI_SHIELD_CLI_OK) {
        (void)publish_terminal(SHIELD_OUTCOME_INVALID);
        return 1;
    }
    if (cli.kind == WIFI_SHIELD_COMMAND_START)
        return start_command(&cli, argv);
    if (cli.kind == WIFI_SHIELD_COMMAND_STOP)
        return wifi_shield_stop(5000U) ? 0 : 1;
    if (cli.kind == WIFI_SHIELD_COMMAND_REPORT)
        return publish_v2_report();
    if (cli.kind == WIFI_SHIELD_COMMAND_LOG_STATUS)
        return publish_v2_log_status();

    wifi_shield_status_t status;
    state_enter();
    status = shield.terminal.status;
    if (shield.state != NULL && !shield.state_wiped)
        wifi_shield_core_status(&shield.state->core, &status);
    state_leave();
    char line[WIFI_SHIELD_LINE_MAX];
    int length = wifi_shield_format_status(line, sizeof(line), &status);
    return length > 0 && publish_line(line, (size_t)length) ? 0 : 1;
}

static bool publish_event(const wifi_shield_event_t *event)
{
    char line[WIFI_SHIELD_LINE_MAX];
    int length = wifi_shield_format_event(line, sizeof(line), event);
    bool accepted = length > 0 && publish_line(line, (size_t)length);
    presentation_record_event(event, accepted);
    return accepted;
}

typedef struct {
    uint8_t bssid[6];
    uint8_t station[6];
    bool station_valid;
} shield_compact_identity_t;

static bool compact_nonzero(const uint8_t address[6])
{
    uint8_t combined = 0U;
    for (size_t i = 0U; i < 6U; ++i) combined |= address[i];
    return combined != 0U;
}

static bool compact_unicast(const uint8_t address[6])
{
    return address != NULL && (address[0] & 1U) == 0U &&
           compact_nonzero(address);
}

static bool compact_broadcast(const uint8_t address[6])
{
    if (address == NULL) return false;
    for (size_t i = 0U; i < 6U; ++i)
        if (address[i] != 0xffU) return false;
    return true;
}

static bool compact_management_identity(
    const wifi_shield_compact_event_t *input,
    shield_compact_identity_t *identity)
{
    if (input == NULL || identity == NULL || input->length < 24U ||
        input->channel == 0U || (input->bytes[0] & 0x0cU) != 0U ||
        (input->bytes[1] & 0x03U) != 0U ||
        (input->bytes[22] & 0x0fU) != 0U ||
        !compact_unicast(input->bytes + 16U))
        return false;

    uint8_t expected_subtype;
    switch (input->kind) {
    case WIFI_SHIELD_COMPACT_DEAUTH: expected_subtype = 0xc0U; break;
    case WIFI_SHIELD_COMPACT_DISASSOC: expected_subtype = 0xa0U; break;
    case WIFI_SHIELD_COMPACT_CSA:
        expected_subtype = input->bytes[0];
        if (expected_subtype != 0x80U && expected_subtype != 0x50U &&
            expected_subtype != 0xd0U) return false;
        break;
    case WIFI_SHIELD_COMPACT_AUTH: expected_subtype = 0xb0U; break;
    case WIFI_SHIELD_COMPACT_ASSOC: expected_subtype = 0x00U; break;
    case WIFI_SHIELD_COMPACT_REASSOC: expected_subtype = 0x20U; break;
    default: return false;
    }
    if (input->bytes[0] != expected_subtype) return false;

    memset(identity, 0, sizeof(*identity));
    memcpy(identity->bssid, input->bytes + 16U, sizeof(identity->bssid));
    if (input->kind == WIFI_SHIELD_COMPACT_DEAUTH ||
        input->kind == WIFI_SHIELD_COMPACT_DISASSOC) {
        if (input->length < 26U) return false;
        const uint8_t *destination = input->bytes + 4U;
        const uint8_t *transmitter = input->bytes + 10U;
        const uint8_t *station = NULL;
        if (same_bssid(transmitter, identity->bssid) &&
            (compact_unicast(destination) || compact_broadcast(destination)))
            station = destination;
        else if (same_bssid(destination, identity->bssid) &&
                 compact_unicast(transmitter))
            station = transmitter;
        else
            return false;
        if (same_bssid(station, identity->bssid)) return false;
        memcpy(identity->station, station, sizeof(identity->station));
        identity->station_valid = true;
    } else if (input->kind == WIFI_SHIELD_COMPACT_AUTH ||
               input->kind == WIFI_SHIELD_COMPACT_ASSOC ||
               input->kind == WIFI_SHIELD_COMPACT_REASSOC) {
        if (!compact_unicast(input->bytes + 10U)) return false;
        memcpy(identity->station, input->bytes + 10U,
               sizeof(identity->station));
        identity->station_valid = true;
    }
    return true;
}

bool wifi_shield_consume_compact(void *token,
                                 const wifi_shield_compact_event_t *input)
{
    if (!token_active(token) || input == NULL || input->length == 0U ||
        input->length > WIFI_SHIELD_COMPACT_BYTES ||
        (unsigned)input->kind > WIFI_SHIELD_COMPACT_REASSOC ||
        atomic_load_explicit(&shield.phase, memory_order_acquire) !=
            SHIELD_PHASE_RUNNING)
        return false;

    uint64_t now_us = shield.runtime.monotonic_us(shield.runtime.context);
    wifi_shield_event_t event = {0};
    shield_compact_identity_t identity = {0};
    bool raw_identity_valid = input->length >= 24U &&
        (input->bytes[0] & 0x0cU) == 0U &&
        compact_unicast(input->bytes + 16U);
    if (raw_identity_valid)
        memcpy(identity.bssid, input->bytes + 16U, sizeof(identity.bssid));
    bool frame_valid = raw_identity_valid &&
        compact_management_identity(input, &identity);
    bool ready = false;
    bool active_observation = false;
    deauth_defence_trigger_t active_trigger = DEF_TRIG_DEAUTH;
    state_enter();
    if (!token_active(token) || shield.state == NULL || shield.state_wiped) {
        state_leave();
        return false;
    }
    wifi_shield_state_t *state = shield.state;
    bool selected = raw_identity_valid &&
        wifi_shield_core_selected(&state->core, identity.bssid);
    wifi_shield_core_record_input(&state->core, selected, false);
    bool metadata_valid = compact_unicast(input->bssid) &&
        frame_valid && same_bssid(input->bssid, identity.bssid) &&
        (!identity.station_valid ||
         same_bssid(input->station, identity.station));
    if (!selected || !metadata_valid) {
        state_leave();
        return true;
    }
    bool active_generation_valid = !state->defence_enabled ||
        (state->defence_generation != 0U &&
         input->generation == state->defence_generation);

    event.channel = input->channel;
    event.count = 1U;
    event.window_ms = WIFI_SHIELD_RATE_WINDOW_MS;
    event.timestamp_us = now_us;
    memcpy(event.bssid, identity.bssid, 6U);
    if (identity.station_valid)
        memcpy(event.station, identity.station, 6U);
    if ((input->kind == WIFI_SHIELD_COMPACT_DEAUTH &&
         input->length >= 26U && input->bytes[0] == 0xc0U) ||
        (input->kind == WIFI_SHIELD_COMPACT_DISASSOC &&
         input->length >= 26U && input->bytes[0] == 0xa0U)) {
        event.source = WIFI_SHIELD_SOURCE_DEAUTH;
        event.type = input->kind == WIFI_SHIELD_COMPACT_DEAUTH ?
            WIFI_SHIELD_EVENT_DEAUTH : WIFI_SHIELD_EVENT_DISASSOC;
        event.severity = WIFI_SHIELD_SEVERITY_ALERT;
        ready = shield_qualify_event_locked(state, &event);
        active_observation = active_generation_valid &&
            (input->bytes[1] & 0x40U) == 0U &&
            compact_unicast(identity.station);
        active_trigger = input->kind == WIFI_SHIELD_COMPACT_DEAUTH ?
            DEF_TRIG_DEAUTH : DEF_TRIG_DISASSOC;
    } else if (input->kind == WIFI_SHIELD_COMPACT_CSA) {
        csa_event_t csa;
        if (csa_parse(input->bytes, input->length, input->channel,
                      input->rssi, &csa) && same_bssid(csa.bssid,
                                                       identity.bssid)) {
            event.source = WIFI_SHIELD_SOURCE_DEAUTH;
            event.type = WIFI_SHIELD_EVENT_CSA;
            event.severity = WIFI_SHIELD_SEVERITY_INFO;
            ready = shield_qualify_event_locked(state, &event);
        }
    } else if ((input->kind == WIFI_SHIELD_COMPACT_AUTH ||
                input->kind == WIFI_SHIELD_COMPACT_ASSOC ||
                input->kind == WIFI_SHIELD_COMPACT_REASSOC) &&
               now_us <= (uint64_t)INT64_MAX) {
        uint8_t bssid[6], station[6];
        pmkid_probe_result_t result = pmkid_probe_observe(
            &state->pmkid, input->bytes, input->length, input->channel,
            (int64_t)now_us, bssid, station);
        if (result == PMKID_PROBE_ASSOC_SEQUENCE &&
            same_bssid(bssid, identity.bssid)) {
            (void)pmkid_candidate_stage(
                state, bssid, station, input->channel, input->rx_us,
                (int64_t)now_us,
                active_generation_valid && state->defence_enabled &&
                    state->core.pmkid_decoy);
        }
    }
    state_leave();
    if (active_observation)
        defence_process_observation(token, active_trigger, event.bssid,
                                    identity.station_valid ?
                                        identity.station : event.station,
                                    input->channel, input->rx_us);
    return !ready || publish_event(&event);
}

static void pmkid_candidate_poll(void *token, uint64_t now_us)
{
    if (now_us > (uint64_t)INT64_MAX) return;
    shield_pmkid_candidate_t due = {0};
    wifi_shield_event_t event = {0};
    bool publishable = false;
    state_enter();
    if (token_active(token) && shield.state != NULL && !shield.state_wiped &&
        atomic_load_explicit(&shield.phase, memory_order_acquire) ==
            SHIELD_PHASE_RUNNING &&
        pmkid_candidate_pop_due(shield.state, (int64_t)now_us, &due)) {
        event.source = WIFI_SHIELD_SOURCE_PMKID;
        event.type = WIFI_SHIELD_EVENT_PMKID_SEQUENCE;
        event.severity = WIFI_SHIELD_SEVERITY_INFO;
        event.channel = due.channel;
        event.count = 1U;
        event.window_ms = WIFI_SHIELD_RATE_WINDOW_MS;
        event.timestamp_us = now_us;
        memcpy(event.bssid, due.bssid, sizeof(event.bssid));
        memcpy(event.station, due.station, sizeof(event.station));
        publishable = shield_qualify_event_locked(shield.state, &event);
    }
    state_leave();
    if (!due.used) return;
    if (due.active_response)
        defence_process_observation(token, DEF_TRIG_PMKID_PROBE,
                                    due.bssid, due.station,
                                    due.channel, due.rx_us);
    if (publishable) (void)publish_event(&event);
}

static void profile_worker_poll(void)
{
    unsigned running_lifecycle = atomic_load_explicit(
        &shield.profile.lifecycle, memory_order_acquire);
    if (profile_lifecycle_phase(running_lifecycle) != SHIELD_PROFILE_RUNNING)
        return;
    if (profile_lifecycle_module(running_lifecycle) ==
        WIFI_SECURITY_MODULE_DEAUTH_V2)
        return;
    uint64_t now_us = shield.runtime.monotonic_us(shield.runtime.context);
    bool due = false;
    state_enter();
    if (atomic_load_explicit(&shield.profile.lifecycle,
                             memory_order_acquire) == running_lifecycle &&
        shield.profile.channel_count > 1U &&
        now_us >= shield.profile.next_hop_us)
        due = true;
    state_leave();
    if (!due || !radio_enter(WIFI_SHIELD_OUTPUT_TIMEOUT_MS)) return;

    wifi_security_runtime_status_t status = {0};
    shield.runtime.runtime_status(shield.runtime.context, &status);
    uint8_t channel = 0U;
    size_t cursor = 0U;
    uint32_t generation = 0U;
    wifi_security_module_t module = WIFI_SECURITY_MODULE_NONE;
    state_enter();
    bool current = atomic_load_explicit(&shield.profile.lifecycle,
                                        memory_order_acquire) ==
            running_lifecycle && shield.profile.channel_count > 1U &&
        now_us >= shield.profile.next_hop_us && status.running &&
        !status.stopping &&
        status.module == shield.profile.module &&
        status.generation == shield.profile.generation;
    if (current) {
        cursor = shield.profile.cursor;
        channel = shield.profile.channels[cursor];
        generation = shield.profile.generation;
        module = shield.profile.module;
    }
    state_leave();
    if (!current) {
        radio_leave();
        return;
    }

    bool tuned = shield.runtime.profile_retune(
        shield.runtime.context, module,
        generation, channel);
    state_enter();
    current = atomic_load_explicit(&shield.profile.lifecycle,
                                   memory_order_acquire) ==
            running_lifecycle &&
        shield.profile.generation == generation &&
        shield.profile.cursor == cursor;
    if (current) {
        if (tuned)
            shield.profile.cursor = (cursor + 1U) %
                                    shield.profile.channel_count;
        shield.profile.next_hop_us = next_deadline(now_us);
    }
    state_leave();
    radio_leave();
}

static void shield_publish_storage_degraded(void)
{
    if (!journal_hooks_complete()) return;
    wifi_shield_journal_status_t status = journal_status();
    state_enter();
    if (shield.state != NULL && !shield.state_wiped) {
        wifi_shield_state_t *state = shield.state;
        shield_propagate_journal_locked(state, &status);
    }
    state_leave();
    if (!status.degraded_notice_pending) return;
    char line[WIFI_SHIELD_LINE_MAX];
    int length = wifi_shield_format_storage_degraded(
        line, sizeof(line), &status);
    if (length > 0 && publish_line(line, (size_t)length))
        shield.runtime.journal_acknowledge_degraded(shield.runtime.context);
}

void wifi_shield_worker_poll(void)
{
    if (!atomic_load_explicit(&shield.initialized, memory_order_acquire))
        return;
    profile_worker_poll();
    if (
        atomic_load_explicit(&shield.phase, memory_order_acquire) !=
            SHIELD_PHASE_RUNNING)
        return;

    shield_publish_storage_degraded();

    wifi_security_runtime_status_t runtime_status = {0};
    shield.runtime.runtime_status(shield.runtime.context, &runtime_status);
    uint64_t now_us = shield.runtime.monotonic_us(shield.runtime.context);
    state_enter();
    if (shield.state != NULL && !shield.state_wiped)
        (void)shield_flush_journal_aggregates_locked(shield.state, now_us,
                                                    false);
    state_leave();
    pmkid_candidate_poll((void *)atomic_load_explicit(
                             &shield.active_token, memory_order_acquire),
                         now_us);

    wifi_shield_state_t *defence_state = NULL;
    void *defence_token = NULL;
    state_enter();
    if (shield.state != NULL && !shield.state_wiped &&
        shield.state->defence_enabled &&
        shield.state->defence_admission_open &&
        shield.state->defence_inflight == 0U) {
        defence_state = shield.state;
        defence_state->defence_inflight = 1U;
        defence_token = (void *)atomic_load_explicit(
            &shield.active_token, memory_order_acquire);
    }
    state_leave();
    if (defence_state != NULL) {
        bool released = deauth_defence_runtime_poll_idle(
            &defence_state->defence);
        bool channel_ok = !released ||
            wifi_shield_channel_release_running(defence_token);
        state_enter();
        if (shield.state == defence_state && !shield.state_wiped &&
            defence_state->defence_inflight != 0U)
            --defence_state->defence_inflight;
        state_leave();
        if (!channel_ok) {
            defence_quarantine();
            return;
        }
    }
    if (atomic_load_explicit(&shield.phase, memory_order_acquire) !=
            SHIELD_PHASE_RUNNING)
        return;
    if (!radio_enter(WIFI_SHIELD_OUTPUT_TIMEOUT_MS)) return;
    uint8_t channel = 0U;
    size_t prior_cursor = 0U;
    bool retune_due = false;

    state_enter();
    if (shield.state != NULL && !shield.state_wiped &&
        atomic_load_explicit(&shield.phase, memory_order_acquire) ==
            SHIELD_PHASE_RUNNING) {
        wifi_shield_state_t *state = shield.state;
        uint32_t drops = runtime_status.rx_drops >= state->runtime_rx_drops ?
            runtime_status.rx_drops - state->runtime_rx_drops :
            runtime_status.rx_drops;
        state->runtime_rx_drops = runtime_status.rx_drops;
        wifi_shield_core_add_rx_drops(&state->core, drops);
        shield_propagate_quality_locked(state);
        (void)wifi_shield_campaign_expire(&state->campaigns, now_us);
        if (!state->channel_plan.locked &&
            state->channel_plan.channel_count > 1U &&
            now_us >= state->next_hop_us) {
            prior_cursor = state->channel_plan.cursor;
            channel = wifi_shield_channel_next(&state->channel_plan);
            if (channel == state->core.current_channel &&
                state->channel_plan.channel_count > 1U)
                channel = wifi_shield_channel_next(&state->channel_plan);
            state->next_hop_us = next_deadline(now_us);
            retune_due = channel != 0U &&
                         channel != state->core.current_channel;
        }
    }
    state_leave();

    if (!retune_due) {
        radio_leave();
        return;
    }
    bool tuned = shield.runtime.retune(shield.runtime.context, channel);
    state_enter();
    if (shield.state != NULL && !shield.state_wiped &&
        atomic_load_explicit(&shield.phase, memory_order_acquire) ==
            SHIELD_PHASE_RUNNING && !shield.state->channel_plan.locked) {
        if (tuned)
            shield.state->core.current_channel = channel;
        else
            shield.state->channel_plan.cursor = prior_cursor;
        if (tuned) {
            presentation_sync_core_locked();
            presentation_changed_locked();
        }
    }
    state_leave();
    radio_leave();
}

bool wifi_shield_channel_lock_running(void *token, const uint8_t bssid[6],
                                      uint8_t channel)
{
    if (!token_active(token) || bssid == NULL || channel == 0U ||
        atomic_load_explicit(&shield.phase, memory_order_acquire) !=
            SHIELD_PHASE_RUNNING)
        return false;
    if (!radio_enter(WIFI_SHIELD_OUTPUT_TIMEOUT_MS)) return false;
    bool locked = false;
    state_enter();
    bool current = token_active(token) && shield.state != NULL &&
        !shield.state_wiped &&
        atomic_load_explicit(&shield.phase, memory_order_acquire) ==
            SHIELD_PHASE_RUNNING;
    if (current)
        locked = wifi_shield_channel_lock(
            &shield.state->channel_plan, bssid, channel);
    state_leave();
    if (!locked) {
        radio_leave();
        return false;
    }

    bool tuned = shield.runtime.retune(shield.runtime.context, channel);
    state_enter();
    current = token_active(token) && shield.state != NULL &&
        !shield.state_wiped &&
        atomic_load_explicit(&shield.phase, memory_order_acquire) ==
            SHIELD_PHASE_RUNNING;
    if (current && tuned) {
        shield.state->core.current_channel = channel;
        shield.state->next_hop_us = next_deadline(
            shield.runtime.monotonic_us(shield.runtime.context));
        presentation_sync_core_locked();
        presentation_changed_locked();
    } else if (current) {
        wifi_shield_channel_release(&shield.state->channel_plan);
    }
    state_leave();
    radio_leave();
    return current && tuned;
}

bool wifi_shield_channel_release_running(void *token)
{
    if (!token_active(token) ||
        atomic_load_explicit(&shield.phase, memory_order_acquire) !=
            SHIELD_PHASE_RUNNING)
        return false;
    if (!radio_enter(WIFI_SHIELD_OUTPUT_TIMEOUT_MS)) return false;
    bool released = false;
    state_enter();
    bool current = token_active(token) && shield.state != NULL &&
        !shield.state_wiped &&
        atomic_load_explicit(&shield.phase, memory_order_acquire) ==
            SHIELD_PHASE_RUNNING;
    if (current &&
        shield.state->channel_plan.locked) {
        wifi_shield_channel_release(&shield.state->channel_plan);
        shield.state->next_hop_us =
            shield.runtime.monotonic_us(shield.runtime.context);
        released = true;
    }
    state_leave();
    radio_leave();
    return released;
}
