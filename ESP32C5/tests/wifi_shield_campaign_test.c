#include "wifi_shield_campaign.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned heap_calls;
void *__wrap_malloc(size_t size) { (void)size; ++heap_calls; return NULL; }
void *__wrap_calloc(size_t n, size_t size)
{ (void)n; (void)size; ++heap_calls; return NULL; }
void *__wrap_realloc(void *ptr, size_t size)
{ (void)ptr; (void)size; ++heap_calls; return NULL; }
void __wrap_free(void *ptr) { (void)ptr; ++heap_calls; }

static const uint8_t bssid[6] = {2, 1, 2, 3, 4, 5};

static void setup(wifi_shield_campaign_core_t *core)
{
    wifi_shield_channel_plan_t plan;
    const wifi_shield_target_t target = {{2, 1, 2, 3, 4, 5}, 6, "test", false};
    assert(wifi_shield_channel_plan_init(&plan, &target, 1));
    assert(wifi_shield_campaign_init(core, &plan));
    /* No plan or event pointer may survive the call. */
    memset(&plan, 0xa5, sizeof(plan));
}

static wifi_shield_event_t event(wifi_shield_source_t source,
                                  wifi_shield_severity_t severity, uint64_t time)
{
    wifi_shield_event_t e = {0};
    memcpy(e.bssid, bssid, 6);
    e.station[0] = 4; e.station[5] = 1;
    e.channel = 6; e.count = 1;
    e.source = source; e.severity = severity; e.timestamp_us = time;
    e.type = source == WIFI_SHIELD_SOURCE_DEAUTH ? WIFI_SHIELD_EVENT_DEAUTH :
             source == WIFI_SHIELD_SOURCE_SAE ? WIFI_SHIELD_EVENT_SAE_ACTIVITY :
             severity == WIFI_SHIELD_SEVERITY_WARN ? WIFI_SHIELD_EVENT_WPS_RETRY_BURST :
             WIFI_SHIELD_EVENT_WPS_ACTIVITY;
    return e;
}

static wifi_shield_campaign_snapshot_t snapshot(wifi_shield_campaign_core_t *core)
{
    wifi_shield_campaign_snapshot_t s;
    assert(wifi_shield_campaign_snapshot(core, bssid, &s));
    return s;
}

/* Catches missing multi-source escalation and loss erasing primary evidence. */
static void test_required_literal_scenario(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t transition;
    wifi_shield_campaign_snapshot_t snapshot;
    assert(wifi_shield_campaign_snapshot(&core, bssid, &snapshot));
    assert(snapshot.last_transition_reason == WIFI_SHIELD_CAMPAIGN_REASON_NONE);
    wifi_shield_event_t wps_info = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 100);
    wifi_shield_event_t deauth_alert = event(WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, 200);
    assert(wifi_shield_campaign_observe(&core, &wps_info, &transition));
    assert(transition.to == WIFI_SHIELD_THREAT_WATCH);
    assert(transition.reason == WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ACTIVITY);
    assert(wifi_shield_campaign_observe(&core, &deauth_alert, &transition));
    assert(transition.to == WIFI_SHIELD_THREAT_CRITICAL);
    assert(transition.reason == WIFI_SHIELD_CAMPAIGN_REASON_CROSS_VECTOR);
    assert(transition.sources ==
           ((1U << WIFI_SHIELD_SOURCE_WPS) | (1U << WIFI_SHIELD_SOURCE_DEAUTH)));
    wifi_shield_campaign_note_loss(&core, bssid, 1, 0, 0);
    assert(wifi_shield_campaign_snapshot(&core, bssid, &snapshot));
    assert(snapshot.confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED);
    assert(snapshot.source_events[0] == 1 && snapshot.source_events[1] == 1);
    assert(snapshot.threat == WIFI_SHIELD_THREAT_CRITICAL && snapshot.rx_drops == 1);
    assert(snapshot.last_transition_reason == WIFI_SHIELD_CAMPAIGN_REASON_CROSS_VECTOR);
    assert(transition.from == WIFI_SHIELD_THREAT_WATCH && transition.id != 0);
    assert(strcmp(wifi_shield_campaign_reason_token(
        WIFI_SHIELD_CAMPAIGN_REASON_CROSS_VECTOR), "cross_vector") == 0);
    assert(wifi_shield_campaign_reason_token(
        (wifi_shield_campaign_reason_t)99) == NULL);
}

/* Catches duplicate transitions, regressing states and losing repeat counts. */
static void test_alert_repeat_and_no_regression(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, 1);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.from == WIFI_SHIELD_THREAT_NONE && t.to == WIFI_SHIELD_THREAT_ATTACK);
    assert(t.reason == WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ALERT);
    e.timestamp_us = 2; e.count = 7;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.id == 0);
    e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 40000000);
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    wifi_shield_campaign_snapshot_t s = snapshot(&core);
    assert(s.threat == WIFI_SHIELD_THREAT_ATTACK && s.source_events[0] == 8);
    assert(s.last_us == 40000000 && s.first_us == 1);
}

/* Catches correlation based on lifetime source bits instead of 30 s evidence. */
static void test_correlation_boundaries_and_alert_requirement(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 0);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    e = event(WIFI_SHIELD_SOURCE_SAE, WIFI_SHIELD_SEVERITY_INFO, 100);
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).threat == WIFI_SHIELD_THREAT_WATCH);
    setup(&core);
    e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 1);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    e = event(WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, 30000002);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.to == WIFI_SHIELD_THREAT_ATTACK);
    setup(&core);
    e.timestamp_us = 1;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 30000001);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.to == WIFI_SHIELD_THREAT_CRITICAL);
}

/* Catches early expiry, zero/reused IDs and reopening with delayed evidence. */
static void test_expiry_and_nonzero_new_id(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 100);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    uint64_t id = t.id;
    assert(wifi_shield_campaign_expire(&core, 60000099) == 0);
    assert(wifi_shield_campaign_expire(&core, 60000100) == 1);
    assert(!snapshot(&core).active && snapshot(&core).source_events[1] == 1);
    e.timestamp_us = 101;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(!snapshot(&core).active);
    e.timestamp_us = 60000100;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(!snapshot(&core).active);
    e.timestamp_us = 60000101;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.id != 0 && t.id != id && snapshot(&core).source_events[1] == 1);
    assert(t.reason == WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ACTIVITY &&
           snapshot(&core).last_transition_reason ==
               WIFI_SHIELD_CAMPAIGN_REASON_ISOLATED_ACTIVITY);
    id = t.id;
    e.timestamp_us = 120000101;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.id != id && t.from == WIFI_SHIELD_THREAT_NONE);
}

/* Catches unsigned timestamp underflow and retroactive window shifts. */
static void test_out_of_order_and_extreme_time(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 20000000);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    e = event(WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, 1);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    wifi_shield_campaign_snapshot_t s = snapshot(&core);
    assert(s.first_us == 20000000 && s.last_us == 20000000);
    assert(s.source_events[0] == 1 && s.sources == 3 && s.threat == WIFI_SHIELD_THREAT_CRITICAL);
    e.timestamp_us = 40000000;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).threat == WIFI_SHIELD_THREAT_CRITICAL);
    e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 30000000);
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).first_us == 20000000 && snapshot(&core).last_us == 40000000);
    assert(wifi_shield_campaign_expire(&core, 0) == 0);
    setup(&core);
    e.timestamp_us = UINT64_MAX - 10;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    e.timestamp_us = 0;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(wifi_shield_campaign_expire(&core, UINT64_MAX) == 0);
    assert(snapshot(&core).last_us == UINT64_MAX - 10);

    /* A delayed contribution still correlates with the other source's latest
     * alert, even when this source already has a newer, distant timestamp. */
    setup(&core);
    e = event(WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, 0);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 50000000);
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    e.timestamp_us = 10000000;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.to == WIFI_SHIELD_THREAT_CRITICAL);
    assert(snapshot(&core).last_us == 50000000);
}

/* Catches target eviction, accepting unselected BSSIDs and borrowed ownership. */
static void test_fixed_capacity_and_selection(void)
{
    wifi_shield_campaign_core_t core;
    wifi_shield_channel_plan_t plan;
    wifi_shield_target_t targets[WIFI_SHIELD_TARGET_MAX] = {0};
    for (size_t i = 0; i < WIFI_SHIELD_TARGET_MAX; ++i) {
        targets[i].bssid[0] = 2; targets[i].bssid[5] = (uint8_t)i;
        targets[i].channel = 6;
    }
    assert(wifi_shield_channel_plan_init(&plan, targets, WIFI_SHIELD_TARGET_MAX));
    assert(wifi_shield_campaign_init(&core, &plan));
    memset(&plan, 0, sizeof(plan));
    wifi_shield_campaign_transition_t t;
    wifi_shield_campaign_snapshot_t s;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 1);
    for (size_t i = 0; i < WIFI_SHIELD_TARGET_MAX; ++i) {
        memcpy(e.bssid, targets[i].bssid, 6);
        assert(wifi_shield_campaign_observe(&core, &e, &t));
        assert(t.id == i + 1);
    }
    e.bssid[5] = 64;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(!wifi_shield_campaign_snapshot(&core, e.bssid, &s));
    for (size_t i = 0; i < WIFI_SHIELD_TARGET_MAX; ++i) {
        assert(wifi_shield_campaign_snapshot(&core, targets[i].bssid, &s));
        assert(s.source_events[1] == 1 && s.id == i + 1);
    }
}

/* Catches wrapping source and loss counters or zero-loss downgrades. */
static void test_saturation_and_loss(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 1);
    e.count = UINT32_MAX - 1;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    wifi_shield_campaign_note_loss(&core, bssid, 0, 0, 0);
    assert(snapshot(&core).confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_FULL);
    e.count = 10;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    wifi_shield_campaign_note_loss(&core, bssid, UINT32_MAX - 1, UINT32_MAX, 2);
    wifi_shield_campaign_note_loss(&core, bssid, 10, 1, UINT32_MAX);
    wifi_shield_campaign_note_journal_loss(&core, bssid, UINT32_MAX);
    wifi_shield_campaign_note_journal_loss(&core, bssid, 1U);
    wifi_shield_campaign_snapshot_t s = snapshot(&core);
    assert(s.source_events[1] == UINT32_MAX && s.rx_drops == UINT32_MAX);
    assert(s.event_drops == UINT32_MAX && s.output_failures == UINT32_MAX);
    assert(s.journal_drops == UINT32_MAX);
    assert(s.threat == WIFI_SHIELD_THREAT_WATCH && s.confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED);
    e.timestamp_us = 2;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED);
}

/* Catches loss arriving before evidence being silently forgotten. */
static void test_loss_before_evidence_and_session_reset(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_campaign_note_loss(&core, bssid, 0, 1, 0);
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_WARN, 1);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).event_drops == 1);
    assert(snapshot(&core).confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED);
    setup(&core);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_FULL);
}

/* Catches sampled/journal uncertainty being cleared by campaign opening. */
static void test_sampled_and_journal_loss_persist_across_campaigns(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_campaign_note_journal_loss(&core, bssid, 2U);
    wifi_shield_campaign_note_sampled(&core, bssid, true);
    wifi_shield_event_t e = event(
        WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 1U);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    wifi_shield_campaign_snapshot_t s = snapshot(&core);
    uint64_t first_id = s.id;
    assert(s.sampled && s.journal_drops == 2U &&
           s.confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED);
    assert(wifi_shield_campaign_expire(
        &core, 1U + WIFI_SHIELD_CAMPAIGN_IDLE_US) == 1U);
    e.timestamp_us = 2U + WIFI_SHIELD_CAMPAIGN_IDLE_US;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    s = snapshot(&core);
    assert(s.id != first_id && s.sampled && s.journal_drops == 2U &&
           s.confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED);
}

/* Catches invalid enum shifts, null dereferences and leaking stale outputs. */
static void test_invalid_inputs_are_inert(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_campaign_snapshot_t s;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 1);
    for (unsigned i = 0; i < 5; ++i) {
        wifi_shield_event_t bad = e;
        if (i == 0) bad.source = (wifi_shield_source_t)-1;
        if (i == 1) bad.source = (wifi_shield_source_t)5;
        if (i == 2) bad.severity = (wifi_shield_severity_t)-1;
        if (i == 3) bad.severity = (wifi_shield_severity_t)3;
        if (i == 4) bad.count = 0;
        assert(!wifi_shield_campaign_observe(&core, &bad, &t));
    }
    assert(!wifi_shield_campaign_observe(NULL, &e, &t));
    assert(!wifi_shield_campaign_observe(&core, NULL, &t));
    assert(wifi_shield_campaign_observe(&core, &e, NULL));
    memset(&s, 0xa5, sizeof(s));
    assert(!wifi_shield_campaign_snapshot(NULL, bssid, &s));
    assert(s.id == 0 && s.sources == 0);
    assert(!wifi_shield_campaign_snapshot(&core, NULL, &s));
    assert(!wifi_shield_campaign_snapshot(&core, bssid, NULL));
    wifi_shield_campaign_note_loss(NULL, bssid, 1, 2, 3);
    wifi_shield_campaign_note_loss(&core, NULL, 1, 2, 3);
    wifi_shield_campaign_note_journal_loss(NULL, bssid, 1U);
    wifi_shield_campaign_note_journal_loss(&core, NULL, 1U);
    wifi_shield_campaign_note_sampled(NULL, bssid, true);
    wifi_shield_campaign_note_sampled(&core, NULL, true);
    assert(wifi_shield_campaign_expire(NULL, 100) == 0);
    assert(!wifi_shield_campaign_init(NULL, NULL));
    assert(!wifi_shield_campaign_init(&core, NULL));
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
}

/* Catches zero IDs on wrap; ID is a bounded scalar, not an allocation. */
static void test_id_wrap_skips_zero(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    core.next_id = UINT64_MAX;
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 1);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.id == UINT64_MAX);
    e.timestamp_us = 60000001;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.id == 1);
}

/* Review issue 1: latest-only history must not hide a qualifying older pair. */
static void test_review_history_pair(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 0);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    e.timestamp_us = 40000000;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    e = event(WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, 5000000);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.to == WIFI_SHIELD_THREAT_CRITICAL);
    wifi_shield_campaign_snapshot_t s = snapshot(&core);
    assert(s.first_us == 0 && s.last_us == 40000000);
    assert(s.source_events[1] == 2 && s.source_events[0] == 1);
    assert(s.confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_FULL);
}

/* Review issue 2: first_us is not a cutoff for delayed active-campaign alerts. */
static void test_review_before_first(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 20000000);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    e = event(WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, 1000000);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.to == WIFI_SHIELD_THREAT_CRITICAL);
    assert(snapshot(&core).first_us == 20000000 && snapshot(&core).last_us == 20000000);
}

/* History exhaustion must be visible even though all source counts survive. */
static void test_review_history_overflow(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 0);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    for (uint64_t i = 1; i < 4; ++i) {
        e.timestamp_us = i * 1000000;
        assert(!wifi_shield_campaign_observe(&core, &e, &t));
    }
    assert(snapshot(&core).confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_FULL);
    assert(!wifi_shield_campaign_observe(&core, &e, &t)); /* Duplicate slot. */
    assert(snapshot(&core).confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_FULL);
    e.timestamp_us = 4000000;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_LIMITED);
    assert(snapshot(&core).source_events[1] == 6);
    e.timestamp_us = 64000000;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).confidence == WIFI_SHIELD_CAMPAIGN_CONFIDENCE_FULL);
    assert(snapshot(&core).source_events[1] == 1);
}

/* Completed-campaign evidence cannot reopen or contaminate a later campaign. */
static void test_review_expired_watermark(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 0);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(wifi_shield_campaign_expire(&core, 60000000) == 1);
    e.timestamp_us = 60000000;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(!snapshot(&core).active);
    e.timestamp_us = 90000000;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    uint64_t id = t.id;
    e = event(WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, 60000000);
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).source_events[0] == 0);
    assert(snapshot(&core).threat == WIFI_SHIELD_THREAT_WATCH);
    e.timestamp_us = 60000001;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.to == WIFI_SHIELD_THREAT_CRITICAL && t.id == id);
    assert(snapshot(&core).first_us == 90000000 && snapshot(&core).last_us == 90000000);

    /* Implicit closure also fences evidence from the completed idle interval. */
    setup(&core);
    e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 0);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    e.timestamp_us = 60000000;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).source_events[1] == 2);
    e = event(WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, 59999999);
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).source_events[0] == 0);
}

/* Stop closes every active campaign immediately without discarding its
 * retained evidence or accepting older evidence into a future campaign. */
static void test_explicit_session_close(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(WIFI_SHIELD_SOURCE_WPS,
                                  WIFI_SHIELD_SEVERITY_INFO, 1000);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(wifi_shield_campaign_close(&core, 2000) == 1);
    wifi_shield_campaign_snapshot_t s = snapshot(&core);
    assert(!s.active && s.id == t.id && s.source_events[1] == 1);
    assert(wifi_shield_campaign_close(&core, 3000) == 0);
    e.timestamp_us = 1500;
    assert(!wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).id == s.id && !snapshot(&core).active);
    e.timestamp_us = 3000;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(t.id != s.id && snapshot(&core).active);
}

/* A later quiet campaign must not erase the session's earlier peak, and every
 * explicit or implicit closure must contribute exactly once. */
static void test_session_peak_and_completed_campaigns(void)
{
    wifi_shield_campaign_core_t core; setup(&core);
    wifi_shield_campaign_transition_t t;
    wifi_shield_event_t e = event(
        WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO, 100);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).session_peak == WIFI_SHIELD_THREAT_WATCH);
    e = event(WIFI_SHIELD_SOURCE_DEAUTH, WIFI_SHIELD_SEVERITY_ALERT, 200);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    assert(snapshot(&core).session_peak == WIFI_SHIELD_THREAT_CRITICAL);
    assert(wifi_shield_campaign_expire(
        &core, 200 + WIFI_SHIELD_CAMPAIGN_IDLE_US) == 1);
    wifi_shield_campaign_snapshot_t s = snapshot(&core);
    assert(!s.active && s.completed_campaigns == 1U &&
           s.session_peak == WIFI_SHIELD_THREAT_CRITICAL);

    e = event(WIFI_SHIELD_SOURCE_WPS, WIFI_SHIELD_SEVERITY_INFO,
              201 + WIFI_SHIELD_CAMPAIGN_IDLE_US);
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    s = snapshot(&core);
    assert(s.active && s.threat == WIFI_SHIELD_THREAT_WATCH &&
           s.completed_campaigns == 1U &&
           s.session_peak == WIFI_SHIELD_THREAT_CRITICAL);

    e.timestamp_us += WIFI_SHIELD_CAMPAIGN_IDLE_US;
    assert(wifi_shield_campaign_observe(&core, &e, &t));
    s = snapshot(&core);
    assert(s.active && s.completed_campaigns == 2U &&
           s.session_peak == WIFI_SHIELD_THREAT_CRITICAL);
    assert(wifi_shield_campaign_close(&core, e.timestamp_us + 1U) == 1U);
    s = snapshot(&core);
    assert(!s.active && s.completed_campaigns == 3U &&
           s.session_peak == WIFI_SHIELD_THREAT_CRITICAL);
    assert(wifi_shield_campaign_close(&core, e.timestamp_us + 2U) == 0U);
    assert(snapshot(&core).completed_campaigns == 3U);
}

int main(int argc, char **argv)
{
    if (argc == 2) {
        if (strcmp(argv[1], "history") == 0) test_review_history_pair();
        else if (strcmp(argv[1], "before-first") == 0) test_review_before_first();
        else if (strcmp(argv[1], "overflow") == 0) test_review_history_overflow();
        else if (strcmp(argv[1], "watermark") == 0) test_review_expired_watermark();
        else assert(false);
        assert(heap_calls == 0);
        puts("wifi shield campaign regression: PASS");
        return 0;
    }
    test_required_literal_scenario();
    test_alert_repeat_and_no_regression();
    test_correlation_boundaries_and_alert_requirement();
    test_expiry_and_nonzero_new_id();
    test_out_of_order_and_extreme_time();
    test_fixed_capacity_and_selection();
    test_saturation_and_loss();
    test_loss_before_evidence_and_session_reset();
    test_sampled_and_journal_loss_persist_across_campaigns();
    test_invalid_inputs_are_inert();
    test_id_wrap_skips_zero();
    test_review_history_pair();
    test_review_before_first();
    test_review_history_overflow();
    test_review_expired_watermark();
    test_explicit_session_close();
    test_session_peak_and_completed_campaigns();
    assert(heap_calls == 0);
    puts("wifi shield campaign: PASS (17 scenarios; heap=0)");
    return 0;
}
