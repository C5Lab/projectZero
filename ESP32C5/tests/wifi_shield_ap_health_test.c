#include "wifi_shield_ap_health.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const uint8_t bssid[6] = {2, 1, 2, 3, 4, 5};

static const wifi_shield_ap_recommendation_detail_t *detail(
    const wifi_shield_ap_health_snapshot_t *snapshot, uint32_t action)
{
    for (size_t i = 0U; i < snapshot->recommendation_count; ++i)
        if (snapshot->recommendation_details[i].action == action)
            return &snapshot->recommendation_details[i];
    return NULL;
}
static wifi_shield_ap_beacon_t beacon(uint16_t sequence, int8_t rssi,
                                     uint64_t boot, uint64_t tsf)
{
    wifi_shield_ap_beacon_t b = {.rssi = rssi, .sequence = sequence,
        .channel = 1, .band = WIFI_SHIELD_AP_BAND_2GHZ, .interval_tu = 100,
        .time = {.boot_us = boot, .ap_tsf_us = tsf, .ap_epoch = 1,
                 .quality = WIFI_SHIELD_TIME_EXACT}};
    memcpy(b.bssid, bssid, 6);
    return b;
}

/* Catch incomplete fixtures, truncation of negative RSSI and advice without
 * known posture. All expectations are hand-derived from observed metadata. */
static void measurements_and_posture(void)
{
    wifi_shield_ap_health_core_t core;
    wifi_shield_ap_health_snapshot_t snapshot;
    wifi_shield_ap_health_init(&core);
    wifi_shield_ap_beacon_t beacon1 = beacon(10, -60, 1000000, 5000000);
    wifi_shield_ap_beacon_t beacon2 = beacon(11, -70, 1102400, 5102400);
    wifi_shield_ap_posture_t posture = {.wps = WIFI_SHIELD_AP_YES,
        .pmf_required = WIFI_SHIELD_AP_NO};
    assert(wifi_shield_ap_health_observe_beacon(&core, &beacon1));
    assert(wifi_shield_ap_health_observe_beacon(&core, &beacon2));
    assert(wifi_shield_ap_health_note_posture(&core, bssid, &posture));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &snapshot));
    assert(snapshot.beacons == 2);
    assert(snapshot.rssi_average == -65);
    assert(snapshot.rssi_min == -70 && snapshot.rssi_max == -60);
    assert(snapshot.recommendations & WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF);
    assert(snapshot.recommendations & WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS);
    assert(!(snapshot.recommendations & WIFI_SHIELD_AP_RECOMMEND_FIRMWARE_REVIEW));
    assert(snapshot.interval_pairs == 1 && snapshot.jitter_max_us == 0);
    assert(snapshot.continuity_confidence == WIFI_SHIELD_AP_CONFIDENCE_OBSERVED);
    assert(snapshot.timing_confidence == WIFI_SHIELD_AP_CONFIDENCE_OBSERVED);
    assert(snapshot.recommendation_count == 2U);
    const wifi_shield_ap_recommendation_detail_t *wps = detail(
        &snapshot, WIFI_SHIELD_AP_RECOMMEND_DISABLE_WPS);
    const wifi_shield_ap_recommendation_detail_t *pmf = detail(
        &snapshot, WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF);
    assert(wps && wps->evidence == WIFI_SHIELD_AP_EVIDENCE_WPS_ADVERTISED &&
           wps->confidence == WIFI_SHIELD_AP_CONFIDENCE_OBSERVED);
    assert(pmf && pmf->evidence == WIFI_SHIELD_AP_EVIDENCE_PMF_NOT_REQUIRED &&
           pmf->confidence == WIFI_SHIELD_AP_CONFIDENCE_OBSERVED);
    beacon2 = beacon(14, -71, 1410600, 5410600); /* 3 intervals + 1000 us */
    assert(wifi_shield_ap_health_observe_beacon(&core, &beacon2));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &snapshot));
    assert(snapshot.sequence_gaps == 2 && snapshot.interval_pairs == 2);
    assert(snapshot.jitter_max_us == 1000 && snapshot.jitter_average_us == 500);
    assert(snapshot.rssi_average == -67);
    assert(snapshot.rssi_min == -71 && snapshot.rssi_max == -60);
    posture = (wifi_shield_ap_posture_t){.wpa3_supported = WIFI_SHIELD_AP_YES,
        .wpa3_only = WIFI_SHIELD_AP_NO, .transition_mode = WIFI_SHIELD_AP_YES,
        .legacy_cipher = WIFI_SHIELD_AP_YES, .validated_catalog_match = true};
    assert(wifi_shield_ap_health_note_posture(&core, bssid, &posture));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &snapshot));
    assert(snapshot.recommendations == (WIFI_SHIELD_AP_RECOMMEND_PREFER_WPA3_ONLY |
        WIFI_SHIELD_AP_RECOMMEND_REVIEW_TRANSITION_MODE |
        WIFI_SHIELD_AP_RECOMMEND_REVIEW_LEGACY_CIPHER |
        WIFI_SHIELD_AP_RECOMMEND_FIRMWARE_REVIEW));
    assert(snapshot.recommendation_count == 4U);
    assert(detail(&snapshot, WIFI_SHIELD_AP_RECOMMEND_PREFER_WPA3_ONLY)->evidence ==
           WIFI_SHIELD_AP_EVIDENCE_WPA3_NOT_ONLY);
    assert(detail(&snapshot, WIFI_SHIELD_AP_RECOMMEND_REVIEW_TRANSITION_MODE)->evidence ==
           WIFI_SHIELD_AP_EVIDENCE_TRANSITION_MODE);
    assert(detail(&snapshot, WIFI_SHIELD_AP_RECOMMEND_REVIEW_LEGACY_CIPHER)->evidence ==
           WIFI_SHIELD_AP_EVIDENCE_LEGACY_CIPHER);
    assert(detail(&snapshot, WIFI_SHIELD_AP_RECOMMEND_FIRMWARE_REVIEW)->evidence ==
           WIFI_SHIELD_AP_EVIDENCE_VALIDATED_CATALOG_MATCH);
    assert(strcmp(wifi_shield_ap_recommendation_token(WIFI_SHIELD_AP_RECOMMEND_REQUIRE_PMF),
                  "require_pmf") == 0);
    assert(wifi_shield_ap_recommendation_token(0) == NULL);
    assert(strcmp(wifi_shield_ap_recommendation_evidence_token(
        WIFI_SHIELD_AP_EVIDENCE_AP_TSF_EPOCH_CHANGE),
        "ap_tsf_epoch_change") == 0);
}

/* Catch local capture limitations being promoted to AP fault or restart. */
static void quality_and_epoch(void)
{
    wifi_shield_ap_health_core_t core;
    wifi_shield_ap_health_snapshot_t s;
    wifi_shield_ap_health_init(&core);
    wifi_shield_ap_beacon_t b = beacon(4095, -80, 1, 1000000);
    assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    b = beacon(0, -79, 102401, 1102400);
    assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
    assert(s.sequence_gaps == 0 && s.rssi_average == -80);
    assert(s.recommendations == WIFI_SHIELD_AP_RECOMMEND_WEAK_OR_UNSTABLE_SIGNAL);
    wifi_shield_ap_quality_t q = {.sampled = true, .rx_drops = 1,
        .event_drops = 2, .journal_drops = 3};
    assert(wifi_shield_ap_health_note_quality(&core, bssid, &q));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
    assert(s.rx_drops == 1 && s.event_drops == 2 && s.journal_drops == 3);
    assert(s.continuity_confidence == WIFI_SHIELD_AP_CONFIDENCE_LIMITED);
    assert(s.timing_confidence == WIFI_SHIELD_AP_CONFIDENCE_LIMITED);
    assert(s.recommendations == WIFI_SHIELD_AP_RECOMMEND_WEAK_OR_UNSTABLE_SIGNAL);
    b = beacon(1, -78, 204801, 10); b.time.ap_epoch = 2;
    assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
    assert(s.epoch_changes == 1 && s.interval_pairs == 1);
    assert(s.recommendations &
           WIFI_SHIELD_AP_RECOMMEND_TSF_EPOCH_CHANGE_OBSERVED);
    const wifi_shield_ap_recommendation_detail_t *epoch_change = detail(
        &s, WIFI_SHIELD_AP_RECOMMEND_TSF_EPOCH_CHANGE_OBSERVED);
    assert(epoch_change && epoch_change->evidence ==
           WIFI_SHIELD_AP_EVIDENCE_AP_TSF_EPOCH_CHANGE &&
           epoch_change->confidence == WIFI_SHIELD_AP_CONFIDENCE_LIMITED);
    assert(strcmp(wifi_shield_ap_recommendation_token(
        WIFI_SHIELD_AP_RECOMMEND_TSF_EPOCH_CHANGE_OBSERVED),
        "tsf_epoch_change_observed") == 0);
    b = beacon(2, -77, 307201, 102410); b.time.ap_epoch = 2;
    b.time.quality = WIFI_SHIELD_TIME_ESTIMATED; b.time.uncertainty_us = 100;
    assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
    assert(s.interval_pairs == 1 && s.beacons == 4);
}

/* Catch unqualified congestion, cross-band channel collisions, mutation on
 * invalid input, table overflow, count wrapping and event type confusion. */
static void events_neighbors_and_bounds(void)
{
    wifi_shield_ap_health_core_t core;
    wifi_shield_ap_health_snapshot_t s, before;
    wifi_shield_ap_health_init(&core);
    wifi_shield_ap_beacon_t b = beacon(10, -60, 1000000, 5000000);
    assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    assert(wifi_shield_ap_health_note_event(&core, bssid, WIFI_SHIELD_EVENT_CSA, 2));
    assert(wifi_shield_ap_health_note_event(&core, bssid, WIFI_SHIELD_EVENT_DEAUTH, UINT32_MAX));
    assert(wifi_shield_ap_health_note_event(&core, bssid, WIFI_SHIELD_EVENT_DEAUTH, 1));
    assert(wifi_shield_ap_health_note_event(&core, bssid, WIFI_SHIELD_EVENT_DISASSOC, 4));
    assert(wifi_shield_ap_health_note_event(&core, bssid, WIFI_SHIELD_EVENT_WPS_RETRY_BURST, 3));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
    assert(s.deauth_events == UINT32_MAX && s.disassoc_events == 4 && s.retry_events == 3);
    assert(s.csa_events == 2);
    assert(s.channel_changes == 0);
    assert(s.recommendations == 0);
    wifi_shield_ap_recommendation_detail_t csa_advice = {
        .action = WIFI_SHIELD_AP_RECOMMEND_CHANNEL_UNSTABLE,
        .evidence = WIFI_SHIELD_AP_EVIDENCE_CSA_ACTIVITY,
        .confidence = WIFI_SHIELD_AP_CONFIDENCE_OBSERVED
    };
    assert(!wifi_shield_ap_recommendation_detail_valid(&csa_advice));
    for (unsigned i = 0; i < 3; ++i) {
        b.bssid[5] = (uint8_t)(6 + i); b.channel = (uint8_t)(1 + i * 2);
        assert(wifi_shield_ap_health_observe_beacon(&core, &b));
        b.sequence++; b.time.boot_us += 102400; b.time.ap_tsf_us += 102400;
        assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    }
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
    assert(s.same_channel_neighbors == 1 && s.overlapping_channel_neighbors == 2);
    assert(s.recommendations & WIFI_SHIELD_AP_RECOMMEND_CHANNEL_CONGESTED);
    const wifi_shield_ap_recommendation_detail_t *congested = detail(
        &s, WIFI_SHIELD_AP_RECOMMEND_CHANNEL_CONGESTED);
    assert(congested && congested->evidence ==
           WIFI_SHIELD_AP_EVIDENCE_OBSERVED_NEIGHBORS &&
           congested->confidence == WIFI_SHIELD_AP_CONFIDENCE_OBSERVED);
    before = s;
    b = beacon(9, -1, 999999, 1);
    assert(!wifi_shield_ap_health_observe_beacon(&core, &b));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
    assert(memcmp(&before, &s, sizeof(s)) == 0);
    b = beacon(11, -1, 1102400, 5102400); b.retry = true;
    assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
    assert(s.retry_beacons == 1 && (s.recommendations & WIFI_SHIELD_AP_RECOMMEND_WEAK_OR_UNSTABLE_SIGNAL));
    b = beacon(12, -60, 32000000, 36000000);
    assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
    assert(s.same_channel_neighbors == 0 && s.overlapping_channel_neighbors == 0);
    assert(!(s.recommendations & WIFI_SHIELD_AP_RECOMMEND_CHANNEL_CONGESTED));
    assert(!wifi_shield_ap_health_note_event(&core, bssid, (wifi_shield_event_type_t)99, 1));
    assert(!wifi_shield_ap_health_note_posture(&core, NULL, NULL));
    assert(!wifi_shield_ap_health_snapshot(NULL, bssid, &s));
    assert(s.beacons == 0);
    wifi_shield_ap_health_init(&core);
    for (unsigned i = 0; i < WIFI_SHIELD_TARGET_MAX; ++i) {
        b = beacon(1, -50, 1, 1); b.bssid[5] = (uint8_t)i;
        assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    }
    b.bssid[4] = 7;
    assert(!wifi_shield_ap_health_observe_beacon(&core, &b));
    b.bssid[4] = 4; b.sequence = 2; b.time.boot_us = 2;
    assert(wifi_shield_ap_health_observe_beacon(&core, &b));
}

/* Each independent local limitation must lower both confidences without
 * manufacturing security, channel, restart or packet-loss advice. */
static void isolated_limitations_and_neighbor_bands(void)
{
    for (unsigned kind = 0; kind < 4; ++kind) {
        wifi_shield_ap_health_core_t core;
        wifi_shield_ap_health_snapshot_t s;
        wifi_shield_ap_health_init(&core);
        wifi_shield_ap_beacon_t b = beacon(1, -60, 1, 1);
        assert(wifi_shield_ap_health_observe_beacon(&core, &b));
        b = beacon(2, -61, 102401, 102401);
        assert(wifi_shield_ap_health_observe_beacon(&core, &b));
        wifi_shield_ap_quality_t q = {0};
        if (kind == 0) q.sampled = true;
        if (kind == 1) q.rx_drops = UINT32_MAX;
        if (kind == 2) q.event_drops = UINT32_MAX;
        if (kind == 3) q.journal_drops = UINT32_MAX;
        assert(wifi_shield_ap_health_note_quality(&core, bssid, &q));
        assert(wifi_shield_ap_health_note_quality(&core, bssid, &q));
        assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
        assert(s.beacons == 2 && s.rssi_average == -61);
        assert(s.continuity_confidence == WIFI_SHIELD_AP_CONFIDENCE_LIMITED);
        assert(s.timing_confidence == WIFI_SHIELD_AP_CONFIDENCE_LIMITED);
        assert(s.recommendations == 0);
        assert(s.recommendation_count == 0U);
        if (kind == 1) assert(s.rx_drops == UINT32_MAX);
        if (kind == 2) assert(s.event_drops == UINT32_MAX);
        if (kind == 3) assert(s.journal_drops == UINT32_MAX);
        for (unsigned n = 0; n < 3; ++n) {
            b.bssid[5] = (uint8_t)(20 + n); b.band = WIFI_SHIELD_AP_BAND_6GHZ;
            b.sequence = 1;
            assert(wifi_shield_ap_health_observe_beacon(&core, &b));
            b.sequence = 2; b.time.boot_us++; b.time.ap_tsf_us++;
            assert(wifi_shield_ap_health_observe_beacon(&core, &b));
        }
        assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
        assert(s.same_channel_neighbors == 0 && s.overlapping_channel_neighbors == 0);
        assert(s.recommendations == 0);
        b = beacon(3, -60, 204801, 204801); b.channel = 6;
        assert(wifi_shield_ap_health_observe_beacon(&core, &b));
        b.sequence++; b.channel = 11; b.time.boot_us++; b.time.ap_tsf_us++;
        assert(wifi_shield_ap_health_observe_beacon(&core, &b));
        assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
        assert(s.channel_changes == 2);
        assert(s.recommendations == WIFI_SHIELD_AP_RECOMMEND_CHANNEL_UNSTABLE);
        wifi_shield_ap_health_snapshot_t before = s;
        b.sequence = 4096;
        assert(!wifi_shield_ap_health_observe_beacon(&core, &b));
        assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
        assert(memcmp(&before, &s, sizeof(s)) == 0);
        b.sequence = 5; b.bssid[0] = 1;
        assert(!wifi_shield_ap_health_observe_beacon(&core, &b));
        wifi_shield_ap_posture_t p = {.wps = (wifi_shield_ap_fact_t)99};
        assert(!wifi_shield_ap_health_note_posture(&core, bssid, &p));
    }
}
/* Management sequence space includes non-beacon traffic. Cadence residuals
 * must depend only on exact TSF, never the observed sequence gap. */
static void cadence_is_independent_of_management_sequence(void)
{
    static const struct {
        uint16_t sequence;
        uint64_t elapsed_us;
        uint64_t jitter_us;
        uint32_t gaps;
    } cases[] = {
        {12, 102400, 0, 1},
        {13, 204800, 0, 2},
        {12, 102900, 500, 1},
        {12, 204300, 500, 1},
        {11, 100, 102300, 0},
        {12, UINT64_MAX - 1, 16386, 1}
    };
    for (unsigned i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        wifi_shield_ap_health_core_t core;
        wifi_shield_ap_health_snapshot_t s;
        wifi_shield_ap_health_init(&core);
        wifi_shield_ap_beacon_t b = beacon(10, -60, 1, 1);
        assert(wifi_shield_ap_health_observe_beacon(&core, &b));
        b.sequence = cases[i].sequence;
        b.time.boot_us = 2;
        b.time.ap_tsf_us += cases[i].elapsed_us;
        assert(wifi_shield_ap_health_observe_beacon(&core, &b));
        assert(wifi_shield_ap_health_snapshot(&core, bssid, &s));
        assert(s.interval_pairs == 1);
        assert(s.sequence_gaps == cases[i].gaps);
        assert(s.jitter_max_us == cases[i].jitter_us);
        assert(s.jitter_average_us == cases[i].jitter_us);
        assert(s.recommendations == 0);
    }
}
/* Duplicate/retry observations do not establish another cadence interval.
 * A legitimate exact AP TSF zero remains an admissible initial anchor. */
static void duplicate_retry_preserves_cadence(void)
{
    wifi_shield_ap_health_core_t core;
    wifi_shield_ap_health_snapshot_t before, after;
    wifi_shield_ap_health_init(&core);
    wifi_shield_ap_beacon_t b = beacon(9, -60, 1, 0);
    assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    b = beacon(10, -60, 102401, 102400);
    assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &before));
    assert(before.beacons == 2 && before.interval_pairs == 1);
    assert(before.jitter_max_us == 0 && before.jitter_average_us == 0);
    b.time.boot_us++;
    b.retry = true;
    assert(wifi_shield_ap_health_observe_beacon(&core, &b));
    assert(wifi_shield_ap_health_snapshot(&core, bssid, &after));
    assert(after.beacons == 3 && after.retry_beacons == 1);
    assert(after.sequence_gaps == before.sequence_gaps);
    assert(after.interval_pairs == before.interval_pairs);
    assert(after.jitter_max_us == before.jitter_max_us);
    assert(after.jitter_average_us == before.jitter_average_us);
    assert(after.timing_confidence == before.timing_confidence);
    assert(after.continuity_confidence == before.continuity_confidence);
    assert(after.recommendations == before.recommendations);
}
int main(void)
{
    duplicate_retry_preserves_cadence();
    cadence_is_independent_of_management_sequence();
    measurements_and_posture(); quality_and_epoch(); events_neighbors_and_bounds();
    isolated_limitations_and_neighbor_bands();
    puts("wifi shield AP health: PASS");
    return 0;
}



