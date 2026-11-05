#include "sae_guard_core.h"

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static sae_guard_observation_t make_observation(sae_guard_frame_kind_t kind,
                                                uint64_t timestamp_us,
                                                uint8_t bssid_id,
                                                uint8_t station_id)
{
    sae_guard_observation_t out;
    memset(&out, 0, sizeof(out));
    const uint8_t bssid[6] = {0x02, 0x11, 0x22, 0x33, 0x44, bssid_id};
    const uint8_t station[6] = {0x06, 0xaa, 0xbb, 0xcc, 0xdd, station_id};
    memcpy(out.bssid, bssid, sizeof(out.bssid));
    memcpy(out.station, station, sizeof(out.station));
    out.kind = kind;
    out.reason = SAE_GUARD_PARSE_OK;
    out.timestamp_us = timestamp_us;
    out.channel = 11;
    out.rssi = -47;
    out.sequence = (uint16_t)timestamp_us;
    if (kind == SAE_GUARD_COMMIT) {
        out.transaction = 1;
        out.group = 19;
        out.body_len = 104;
    } else if (kind == SAE_GUARD_CONFIRM) {
        out.transaction = 2;
        out.body_len = 40;
    } else if (kind == SAE_GUARD_MALFORMED) {
        out.transaction = 1;
        out.reason = SAE_GUARD_SHORT_AUTH_BODY;
        out.body_len = 5;
    }
    return out;
}

static size_t active_pairs(const sae_guard_core_t *core)
{
    size_t count = 0;
    for (size_t i = 0; i < SAE_GUARD_TRACKED_PAIRS; ++i) {
        if (core->pairs[i].active) ++count;
    }
    return count;
}

static size_t active_malformed_bssids(const sae_guard_core_t *core)
{
    size_t count = 0;
    for (size_t i = 0; i < SAE_GUARD_TRACKED_MALFORMED_BSSIDS; ++i) {
        if (core->malformed_bssids[i].active) ++count;
    }
    return count;
}

static sae_guard_pair_t *find_pair(sae_guard_core_t *core,
                                   const sae_guard_observation_t *item)
{
    for (size_t i = 0; i < SAE_GUARD_TRACKED_PAIRS; ++i) {
        sae_guard_pair_t *pair = &core->pairs[i];
        if (pair->active && pair->from_ap == item->from_ap &&
            memcmp(pair->bssid, item->bssid, 6) == 0 &&
            memcmp(pair->station, item->station, 6) == 0) return pair;
    }
    return NULL;
}

static sae_guard_malformed_bssid_t *find_malformed_bssid(
    sae_guard_core_t *core, const sae_guard_observation_t *item)
{
    for (size_t i = 0; i < SAE_GUARD_TRACKED_MALFORMED_BSSIDS; ++i) {
        sae_guard_malformed_bssid_t *entry = &core->malformed_bssids[i];
        if (entry->active && memcmp(entry->bssid, item->bssid, 6) == 0) return entry;
    }
    return NULL;
}

static void expect_no_event(sae_guard_core_t *core,
                            const sae_guard_observation_t *item)
{
    sae_guard_event_t event;
    sae_guard_event_t zero;
    memset(&event, 0xa5, sizeof(event));
    memset(&zero, 0, sizeof(zero));
    assert(!sae_guard_observe(core, item, &event));
    assert(memcmp(&event, &zero, sizeof(event)) == 0);
}

static sae_guard_event_t expect_event(sae_guard_core_t *core,
                                      const sae_guard_observation_t *item,
                                      sae_guard_event_reason_t reason)
{
    sae_guard_event_t event;
    memset(&event, 0, sizeof(event));
    assert(sae_guard_observe(core, item, &event));
    assert(event.reason == reason);
    assert((event.reason_mask & SAE_GUARD_EVENT_MASK(reason)) != 0);
    assert(memcmp(event.observation.bssid, item->bssid, 6) == 0);
    assert(memcmp(event.observation.station, item->station, 6) == 0);
    assert(event.observation.from_ap == item->from_ap);
    assert(event.observation.channel == item->channel);
    assert(event.observation.rssi == item->rssi);
    assert(event.observation.timestamp_us == item->timestamp_us);
    return event;
}

static void test_malformed_threshold_is_per_bssid_and_rearms(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    sae_guard_observation_t item = make_observation(SAE_GUARD_MALFORMED, 100, 1, 1);
    expect_no_event(&core, &item);
    item.station[5] = 2;
    item.from_ap = true;
    item.timestamp_us = UINT64_C(1000100);
    expect_no_event(&core, &item);

    sae_guard_observation_t other = make_observation(SAE_GUARD_MALFORMED,
                                                     UINT64_C(1500100), 2, 9);
    expect_no_event(&core, &other); /* Another BSSID cannot complete the count. */
    item.station[5] = 3;
    item.from_ap = false;
    item.timestamp_us = UINT64_C(2000100);
    sae_guard_event_t event = expect_event(&core, &item, SAE_GUARD_EVENT_MALFORMED);
    assert(event.malformed == SAE_GUARD_MALFORMED_THRESHOLD);
    assert(event.commits == 0 && event.confirms == 0 && event.retries == 0);
    assert(event.window_ms == 2000);
    item.station[5] = 4;
    item.timestamp_us = UINT64_C(3000100);
    expect_no_event(&core, &item); /* One threshold event per fixed window. */
    assert(active_pairs(&core) == 0 && active_malformed_bssids(&core) == 2);

    assert(sae_guard_expire(&core, UINT64_C(10000099)) == 0);
    assert(sae_guard_expire(&core, UINT64_C(10000100)) == 1);
    assert(active_malformed_bssids(&core) == 1);
    item.timestamp_us = UINT64_C(11000100);
    expect_no_event(&core, &item);
    item.timestamp_us = UINT64_C(12000100);
    expect_no_event(&core, &item);
    item.timestamp_us = UINT64_C(13000100);
    event = expect_event(&core, &item, SAE_GUARD_EVENT_MALFORMED);
    assert(event.malformed == SAE_GUARD_MALFORMED_THRESHOLD);

    sae_guard_status_t status;
    sae_guard_get_status(&core, &status);
    assert(status.observations == 8 && status.malformed == 8);
    assert(status.reason_counts[SAE_GUARD_EVENT_MALFORMED] == 2);
    /* BSSID 2's independent window expired while BSSID 1 was rearming. */
    assert(status.active_pairs == 0 && status.active_malformed_bssids == 1);
}

static void test_unconfirmed_threshold_and_retries(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    sae_guard_observation_t item = make_observation(SAE_GUARD_COMMIT, 10, 3, 3);
    for (uint32_t i = 0; i < SAE_GUARD_UNCONFIRMED_THRESHOLD - 1; ++i) {
        item.timestamp_us = 10 + (uint64_t)i * UINT64_C(1000000);
        item.sequence = (uint16_t)i;
        expect_no_event(&core, &item);
    }
    item.timestamp_us = UINT64_C(7000010);
    item.sequence = 7;
    sae_guard_event_t event = expect_event(&core, &item,
                                            SAE_GUARD_EVENT_UNCONFIRMED_COMMITS);
    assert(event.commits == SAE_GUARD_UNCONFIRMED_THRESHOLD);
    assert(event.window_ms == 7000 && event.distinct_groups == 1);
    item.timestamp_us = UINT64_C(8000010);
    expect_no_event(&core, &item);

    item.retry = true;
    for (uint32_t i = 0; i < 5; ++i) {
        item.timestamp_us += 100;
        expect_no_event(&core, &item);
    }
    sae_guard_pair_t *pair = find_pair(&core, &item);
    assert(pair != NULL && pair->commits == 9 && pair->retries == 5);
    sae_guard_status_t status;
    sae_guard_get_status(&core, &status);
    assert(status.commits == 9 && status.retries == 5);
    assert(status.reason_counts[SAE_GUARD_EVENT_UNCONFIRMED_COMMITS] == 1);

    sae_guard_observation_t confirm = make_observation(
        SAE_GUARD_CONFIRM, UINT64_C(8501000), 3, 3);
    expect_no_event(&core, &confirm);
    pair = find_pair(&core, &confirm);
    assert(pair != NULL && !pair->awaiting_confirm && pair->commits == 0);
    for (uint32_t i = 0; i < SAE_GUARD_UNCONFIRMED_THRESHOLD; ++i) {
        item = make_observation(SAE_GUARD_COMMIT, UINT64_C(8600000) + i, 3, 3);
        expect_no_event(&core, &item); /* Still the already-reported window. */
    }
    assert(sae_guard_expire(&core, UINT64_C(10000009)) == 0);
    assert(sae_guard_expire(&core, UINT64_C(10000010)) == 1);
    for (uint32_t i = 0; i < SAE_GUARD_UNCONFIRMED_THRESHOLD - 1; ++i) {
        item = make_observation(SAE_GUARD_COMMIT,
                                UINT64_C(11000000) + (uint64_t)i * UINT64_C(1000000),
                                3, 3);
        expect_no_event(&core, &item);
    }
    item.timestamp_us = UINT64_C(18000000);
    expect_event(&core, &item, SAE_GUARD_EVENT_UNCONFIRMED_COMMITS);
    sae_guard_get_status(&core, &status);
    assert(status.commits == 25 && status.confirms == 1 && status.retries == 5);
    assert(status.reason_counts[SAE_GUARD_EVENT_UNCONFIRMED_COMMITS] == 2);
}

static void test_commit_confirm_correlation_and_known_minimums(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    sae_guard_observation_t confirm = make_observation(SAE_GUARD_CONFIRM, 50, 4, 4);
    expect_no_event(&core, &confirm); /* Confirm before Commit. */

    sae_guard_observation_t commit = make_observation(SAE_GUARD_COMMIT, 100, 4, 4);
    commit.group = 20;
    expect_no_event(&core, &commit);
    assert(active_pairs(&core) == 1);
    confirm.timestamp_us = 101;
    confirm.station[5] = 5;
    expect_no_event(&core, &confirm);
    confirm.station[5] = 4;
    confirm.bssid[5] = 5;
    expect_no_event(&core, &confirm);
    confirm.bssid[5] = 4;
    confirm.from_ap = true;
    expect_no_event(&core, &confirm);
    confirm.from_ap = false;
    assert(active_pairs(&core) == 1);

    confirm.body_len = 55; /* Group 20 needs 6 + 50 bytes. */
    confirm.timestamp_us = 102;
    expect_no_event(&core, &confirm);
    confirm.timestamp_us = 103;
    expect_no_event(&core, &confirm);
    confirm.timestamp_us = 104;
    sae_guard_event_t malformed_event = expect_event(
        &core, &confirm, SAE_GUARD_EVENT_MALFORMED);
    assert(malformed_event.observation.group == 20);
    assert(malformed_event.malformed == SAE_GUARD_MALFORMED_THRESHOLD);
    sae_guard_pair_t *pair = find_pair(&core, &commit);
    sae_guard_malformed_bssid_t *malformed = find_malformed_bssid(&core, &commit);
    assert(pair != NULL && pair->confirms == 0);
    assert(malformed != NULL && malformed->malformed == 3);

    confirm.body_len = 56;
    confirm.timestamp_us = 105;
    expect_no_event(&core, &confirm);
    assert(active_pairs(&core) == 1);
    pair = find_pair(&core, &commit);
    assert(pair != NULL && !pair->awaiting_confirm && pair->commits == 0);
    sae_guard_status_t status;
    sae_guard_get_status(&core, &status);
    assert(status.commits == 1 && status.confirms == 1 && status.malformed == 3);

    sae_guard_reset(&core);
    commit = make_observation(SAE_GUARD_COMMIT, 200, 4, 4);
    commit.group = UINT16_C(65000); /* Unknown is not malformed. */
    expect_no_event(&core, &commit);
    confirm = make_observation(SAE_GUARD_CONFIRM, 201, 4, 4);
    confirm.body_len = 40;
    expect_no_event(&core, &confirm);
    sae_guard_get_status(&core, &status);
    assert(status.commits == 1 && status.confirms == 1 && status.malformed == 0);
    assert(active_pairs(&core) == 1 && active_malformed_bssids(&core) == 0);
}

static void test_retry_identity_does_not_hide_unique_commits(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    sae_guard_observation_t item = make_observation(SAE_GUARD_COMMIT, 100, 16, 16);
    item.retry = true;
    item.sequence = 42;
    expect_no_event(&core, &item); /* First-seen Retry is still one Commit. */
    sae_guard_pair_t *pair = find_pair(&core, &item);
    assert(pair != NULL && pair->commits == 1 && pair->retries == 1);

    item.timestamp_us = 101;
    expect_no_event(&core, &item); /* Same sequence/group is a retransmission. */
    assert(pair->commits == 1 && pair->retries == 2);
    item.sequence = 43;
    item.timestamp_us = 102;
    expect_no_event(&core, &item); /* Changed sequence is unique despite Retry. */
    assert(pair->commits == 2 && pair->retries == 3);
    item.group = 20;
    item.timestamp_us = 103;
    expect_no_event(&core, &item); /* Changed group is independently unique. */
    assert(pair->commits == 3 && pair->retries == 4);
    assert(pair->distinct_groups == 2 && pair->current_group == 20);
    sae_guard_status_t status;
    sae_guard_get_status(&core, &status);
    assert(status.commits == 3 && status.retries == 4);
}

static void test_group_direction_and_monotonic_correlation(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    sae_guard_observation_t item = make_observation(SAE_GUARD_COMMIT, 1000, 5, 5);
    expect_no_event(&core, &item);
    item.timestamp_us = 999;
    item.group = 20;
    expect_no_event(&core, &item);
    sae_guard_pair_t *pair = find_pair(&core, &item);
    assert(pair != NULL && pair->commits == 1 && pair->current_group == 19);

    item.timestamp_us = 1000; /* Equal timestamps are monotonic. */
    item.group = 20;
    expect_no_event(&core, &item);
    assert(pair->commits == 2 && pair->current_group == 20);
    sae_guard_observation_t confirm = make_observation(SAE_GUARD_CONFIRM, 1000, 5, 5);
    confirm.body_len = 55;
    expect_no_event(&core, &confirm);
    assert(active_pairs(&core) == 1);
    confirm.body_len = 56;
    expect_no_event(&core, &confirm);
    assert(active_pairs(&core) == 1);
    pair = find_pair(&core, &item);
    assert(pair != NULL && !pair->awaiting_confirm);
}

static void test_all_known_group_confirm_minimums(void)
{
    static const struct {
        uint16_t group;
        uint16_t total_body_minimum;
    } cases[] = {{19, 40}, {20, 56}, {21, 72}};
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        sae_guard_core_t core;
        sae_guard_core_init(&core);
        sae_guard_observation_t commit = make_observation(
            SAE_GUARD_COMMIT, 100, 15, (uint8_t)(i + 1));
        commit.group = cases[i].group;
        expect_no_event(&core, &commit);
        sae_guard_observation_t confirm = make_observation(
            SAE_GUARD_CONFIRM, 101, 15, (uint8_t)(i + 1));
        confirm.body_len = (uint16_t)(cases[i].total_body_minimum - 1U);
        expect_no_event(&core, &confirm);
        sae_guard_pair_t *pair = find_pair(&core, &commit);
        assert(pair != NULL && pair->awaiting_confirm);
        confirm.timestamp_us = 102;
        confirm.body_len = cases[i].total_body_minimum;
        expect_no_event(&core, &confirm);
        pair = find_pair(&core, &commit);
        assert(pair != NULL && !pair->awaiting_confirm);
        sae_guard_status_t status;
        sae_guard_get_status(&core, &status);
        assert(status.confirms == 1 && status.malformed == 1);
    }
}

static void test_parser_malformed_confirm_keeps_correlated_group(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    sae_guard_observation_t commit = make_observation(SAE_GUARD_COMMIT,
                                                       100, 19, 19);
    commit.group = 21;
    expect_no_event(&core, &commit);
    sae_guard_observation_t malformed = make_observation(SAE_GUARD_MALFORMED,
                                                          101, 19, 19);
    malformed.transaction = 2;
    malformed.reason = SAE_GUARD_CONFIRM_UNDERSIZE;
    malformed.group = 0;
    malformed.body_len = 39;
    expect_no_event(&core, &malformed);
    malformed.timestamp_us = 102;
    expect_no_event(&core, &malformed);
    malformed.timestamp_us = 103;
    sae_guard_event_t event = expect_event(&core, &malformed,
                                            SAE_GUARD_EVENT_MALFORMED);
    assert(event.observation.kind == SAE_GUARD_MALFORMED);
    assert(event.observation.transaction == 2);
    assert(event.observation.group == 21);
    assert(event.commits == 1 && event.malformed == 3);
}

static void test_group_churn_and_informational_status(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    sae_guard_observation_t item = make_observation(SAE_GUARD_COMMIT, 1, 6, 6);
    const uint16_t groups[] = {19, UINT16_C(65000), 20, 21};
    for (size_t i = 0; i < 2; ++i) {
        item.group = groups[i];
        item.timestamp_us = 1 + i;
        expect_no_event(&core, &item);
    }
    item.group = groups[2];
    item.timestamp_us = 3;
    sae_guard_event_t event = expect_event(&core, &item, SAE_GUARD_EVENT_GROUP_CHURN);
    assert(event.distinct_groups == SAE_GUARD_GROUP_CHURN_THRESHOLD);
    assert(event.malformed == 0 && event.commits == 3);
    item.group = groups[3];
    item.timestamp_us = 4;
    expect_no_event(&core, &item);

    sae_guard_reset(&core);
    item = make_observation(SAE_GUARD_ANTI_CLOGGING, 10, 6, 6);
    item.transaction = 1;
    item.status = 76;
    item.group = 19;
    event = expect_event(&core, &item, SAE_GUARD_EVENT_ANTI_CLOGGING);
    assert(event.commits == 0 && event.malformed == 0);
    assert(active_pairs(&core) == 0 && active_malformed_bssids(&core) == 0);
    item = make_observation(SAE_GUARD_UNSUPPORTED_GROUP, 11, 6, 6);
    item.transaction = 1;
    item.status = 77;
    expect_event(&core, &item, SAE_GUARD_EVENT_STATUS_FAILURE);
    item = make_observation(SAE_GUARD_STATUS_ONLY, 12, 6, 6);
    item.transaction = 2;
    item.status = 1;
    expect_event(&core, &item, SAE_GUARD_EVENT_STATUS_FAILURE);

    sae_guard_status_t status;
    sae_guard_get_status(&core, &status);
    assert(status.anti_clogging == 1 && status.status_failures == 2);
    assert(status.malformed == 0 && status.capacity_drops == 0);
    assert(status.reason_counts[SAE_GUARD_EVENT_ANTI_CLOGGING] == 1);
    assert(status.reason_counts[SAE_GUARD_EVENT_STATUS_FAILURE] == 2);
}

static void test_simultaneous_thresholds_are_preserved_in_one_event(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    sae_guard_observation_t item = make_observation(SAE_GUARD_COMMIT, 100, 17, 17);
    item.group = 19;
    item.sequence = 1;
    expect_no_event(&core, &item);
    item.group = 20;
    item.sequence = 2;
    item.timestamp_us = 101;
    expect_no_event(&core, &item);
    for (uint16_t sequence = 3; sequence <= 7; ++sequence) {
        item.sequence = sequence;
        item.timestamp_us = 100 + sequence;
        expect_no_event(&core, &item);
    }
    item.group = 21;
    item.sequence = 8;
    item.timestamp_us = 108;
    sae_guard_event_t event = expect_event(
        &core, &item, SAE_GUARD_EVENT_UNCONFIRMED_COMMITS);
    assert(event.reason_mask ==
           (SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_UNCONFIRMED_COMMITS) |
            SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_GROUP_CHURN)));
    assert(event.commits == 8 && event.distinct_groups == 3);
    sae_guard_pair_t *pair = find_pair(&core, &item);
    assert(pair != NULL && pair->unconfirmed_reported && pair->group_churn_reported);

    sae_guard_observation_t confirm = make_observation(SAE_GUARD_CONFIRM, 109, 17, 17);
    confirm.body_len = 72;
    expect_no_event(&core, &confirm); /* No pending reason can be erased here. */
    sae_guard_status_t status;
    sae_guard_get_status(&core, &status);
    assert(status.reason_counts[SAE_GUARD_EVENT_UNCONFIRMED_COMMITS] == 1);
    assert(status.reason_counts[SAE_GUARD_EVENT_GROUP_CHURN] == 1);
}

static void test_separate_capacities_expiry_and_clock_boundaries(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    for (size_t i = 0; i < SAE_GUARD_TRACKED_PAIRS; ++i) {
        sae_guard_observation_t item = make_observation(SAE_GUARD_COMMIT, 100, 7,
                                                        (uint8_t)(i + 1));
        expect_no_event(&core, &item);
    }
    sae_guard_observation_t overflow = make_observation(SAE_GUARD_COMMIT, 101, 8, 99);
    expect_event(&core, &overflow, SAE_GUARD_EVENT_CAPACITY);
    assert(active_pairs(&core) == SAE_GUARD_TRACKED_PAIRS);
    for (size_t i = 0; i < SAE_GUARD_TRACKED_PAIRS; ++i) {
        assert(core.pairs[i].bssid[5] == 7); /* No live evidence was evicted. */
    }

    for (size_t i = 0; i < SAE_GUARD_TRACKED_MALFORMED_BSSIDS; ++i) {
        sae_guard_observation_t item = make_observation(SAE_GUARD_MALFORMED, 100,
                                                        (uint8_t)(20 + i), 1);
        expect_no_event(&core, &item);
    }
    sae_guard_observation_t malformed_overflow = make_observation(
        SAE_GUARD_MALFORMED, 101, 99, 1);
    expect_event(&core, &malformed_overflow, SAE_GUARD_EVENT_CAPACITY);
    assert(active_malformed_bssids(&core) == SAE_GUARD_TRACKED_MALFORMED_BSSIDS);
    for (size_t i = 0; i < SAE_GUARD_TRACKED_MALFORMED_BSSIDS; ++i) {
        assert(core.malformed_bssids[i].bssid[5] != 99);
    }
    sae_guard_status_t status;
    sae_guard_get_status(&core, &status);
    assert(status.capacity_drops == 2);
    assert(status.pair_capacity_drops == 1);
    assert(status.malformed_capacity_drops == 1);

    assert(sae_guard_expire(&core, 99) == 0);
    assert(sae_guard_expire(&core, UINT64_C(10000099)) == 0);
    assert(sae_guard_expire(&core, UINT64_C(10000100)) ==
           SAE_GUARD_TRACKED_PAIRS + SAE_GUARD_TRACKED_MALFORMED_BSSIDS);
    assert(active_pairs(&core) == 0 && active_malformed_bssids(&core) == 0);
    expect_no_event(&core, &overflow); /* Expiry before capacity. */
    expect_no_event(&core, &malformed_overflow);

    sae_guard_reset(&core);
    sae_guard_observation_t edge = make_observation(
        SAE_GUARD_COMMIT, UINT64_MAX - SAE_GUARD_WINDOW_US, 9, 9);
    expect_no_event(&core, &edge);
    assert(sae_guard_expire(&core, UINT64_MAX) == 1);
    sae_guard_reset(&core);
    edge.timestamp_us = 0;
    expect_no_event(&core, &edge);
    assert(sae_guard_expire(&core, UINT64_MAX) == 1);
}

static void test_saturating_counters_and_adapter_fields(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    core.status.observations = UINT32_MAX - 1;
    core.status.commits = UINT32_MAX - 1;
    core.status.confirms = UINT32_MAX;
    core.status.retries = UINT32_MAX - 1;
    core.status.malformed = UINT32_MAX - 1;
    core.status.anti_clogging = UINT32_MAX - 1;
    core.status.status_failures = UINT32_MAX - 1;
    core.status.capacity_drops = UINT32_MAX;
    core.status.pair_capacity_drops = UINT32_MAX;
    core.status.malformed_capacity_drops = UINT32_MAX;
    core.status.received = UINT32_MAX;
    core.status.filtered = UINT32_MAX;
    core.status.unrelated = UINT32_MAX;
    core.status.rx_drops = UINT32_MAX;
    core.status.output_failures = UINT32_MAX;
    core.status.running = true;
    core.status.stopping = true;
    for (size_t i = 0; i < SAE_GUARD_EVENT_REASON_COUNT; ++i) {
        core.status.reason_counts[i] = UINT32_MAX - 1;
    }

    sae_guard_observation_t item = make_observation(SAE_GUARD_COMMIT, 1, 10, 10);
    expect_no_event(&core, &item);
    item.retry = true;
    item.timestamp_us = 2;
    expect_no_event(&core, &item);
    expect_no_event(&core, &item);
    sae_guard_pair_t *pair = find_pair(&core, &item);
    assert(pair != NULL);
    pair->commits = UINT32_MAX;
    pair->retries = UINT32_MAX;
    item.retry = false;
    item.timestamp_us = 3;
    expect_event(&core, &item, SAE_GUARD_EVENT_UNCONFIRMED_COMMITS);

    item = make_observation(SAE_GUARD_MALFORMED, 4, 10, 10);
    expect_no_event(&core, &item);
    sae_guard_malformed_bssid_t *malformed = find_malformed_bssid(&core, &item);
    assert(malformed != NULL);
    malformed->malformed = UINT32_MAX;
    item.timestamp_us = 5;
    expect_event(&core, &item, SAE_GUARD_EVENT_MALFORMED);
    item = make_observation(SAE_GUARD_ANTI_CLOGGING, 6, 11, 11);
    item.status = 76;
    expect_event(&core, &item, SAE_GUARD_EVENT_ANTI_CLOGGING);
    expect_event(&core, &item, SAE_GUARD_EVENT_ANTI_CLOGGING);
    item = make_observation(SAE_GUARD_STATUS_ONLY, 7, 11, 11);
    item.status = 1;
    expect_event(&core, &item, SAE_GUARD_EVENT_STATUS_FAILURE);
    expect_event(&core, &item, SAE_GUARD_EVENT_STATUS_FAILURE);

    item = make_observation(SAE_GUARD_COMMIT, 8, 12, 12);
    item.group = 19;
    expect_no_event(&core, &item);
    item.group = 20;
    item.timestamp_us = 9;
    expect_no_event(&core, &item);
    item.group = 21;
    item.timestamp_us = 10;
    expect_event(&core, &item, SAE_GUARD_EVENT_GROUP_CHURN);
    for (uint8_t i = 0; i < 30; ++i) {
        item = make_observation(SAE_GUARD_COMMIT, 11, 13, (uint8_t)(i + 1));
        expect_no_event(&core, &item);
    }
    item = make_observation(SAE_GUARD_COMMIT, 12, 14, 1);
    expect_event(&core, &item, SAE_GUARD_EVENT_CAPACITY);

    sae_guard_status_t status;
    sae_guard_get_status(&core, &status);
    assert(status.observations == UINT32_MAX && status.commits == UINT32_MAX);
    assert(status.confirms == UINT32_MAX && status.retries == UINT32_MAX);
    assert(status.malformed == UINT32_MAX && status.anti_clogging == UINT32_MAX);
    assert(status.status_failures == UINT32_MAX && status.capacity_drops == UINT32_MAX);
    assert(status.pair_capacity_drops == UINT32_MAX);
    assert(status.malformed_capacity_drops == UINT32_MAX);
    assert(status.received == UINT32_MAX && status.filtered == UINT32_MAX);
    assert(status.unrelated == UINT32_MAX && status.rx_drops == UINT32_MAX);
    assert(status.output_failures == UINT32_MAX && status.running && status.stopping);
    assert(pair->commits == UINT32_MAX && pair->retries == UINT32_MAX);
    assert(malformed->malformed == UINT32_MAX);
    for (size_t i = 1; i < SAE_GUARD_EVENT_REASON_COUNT; ++i) {
        assert(status.reason_counts[i] == UINT32_MAX);
    }
}

static void test_null_reset_and_fixed_storage(void)
{
    sae_guard_core_t core;
    memset(&core, 0xa5, sizeof(core));
    sae_guard_core_init(&core);
    const uint8_t *bytes = (const uint8_t *)&core;
    for (size_t i = 0; i < sizeof(core); ++i) assert(bytes[i] == 0);
    assert(!sae_guard_observe(NULL, NULL, NULL));
    assert(sae_guard_expire(NULL, UINT64_MAX) == 0);
    sae_guard_event_t event;
    sae_guard_event_t zero_event;
    memset(&event, 0xa5, sizeof(event));
    memset(&zero_event, 0, sizeof(zero_event));
    assert(!sae_guard_observe(&core, NULL, &event));
    assert(memcmp(&event, &zero_event, sizeof(event)) == 0);
    sae_guard_status_t status;
    sae_guard_status_t zero_status;
    memset(&status, 0xa5, sizeof(status));
    memset(&zero_status, 0, sizeof(zero_status));
    sae_guard_get_status(NULL, &status);
    assert(memcmp(&status, &zero_status, sizeof(status)) == 0);
    assert(sizeof(core.pairs) / sizeof(core.pairs[0]) == SAE_GUARD_TRACKED_PAIRS);
    assert(sizeof(core.malformed_bssids) / sizeof(core.malformed_bssids[0]) ==
           SAE_GUARD_TRACKED_MALFORMED_BSSIDS);
    sae_guard_reset(&core);
    bytes = (const uint8_t *)&core;
    for (size_t i = 0; i < sizeof(core); ++i) assert(bytes[i] == 0);
}

static void test_null_event_cannot_consume_threshold_evidence(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    sae_guard_observation_t item = make_observation(SAE_GUARD_MALFORMED,
                                                     100, 18, 1);
    expect_no_event(&core, &item);
    item.station[5] = 2;
    item.timestamp_us = 101;
    expect_no_event(&core, &item);
    item.station[5] = 3;
    item.timestamp_us = 102;
    assert(!sae_guard_observe(&core, &item, NULL));
    sae_guard_status_t status;
    sae_guard_get_status(&core, &status);
    assert(status.observations == 2 && status.malformed == 2);
    sae_guard_malformed_bssid_t *entry = find_malformed_bssid(&core, &item);
    assert(entry != NULL && entry->malformed == 2 && !entry->reported);
    expect_event(&core, &item, SAE_GUARD_EVENT_MALFORMED);
}

static uint32_t next_random(uint32_t *state)
{
    *state = *state * UINT32_C(1664525) + UINT32_C(1013904223);
    return *state;
}

static void test_one_hundred_thousand_random_observations(void)
{
    sae_guard_core_t core;
    sae_guard_core_init(&core);
    uint32_t random = UINT32_C(0x53ae19c7);
    uint64_t now = 0;
    for (size_t i = 0; i < 100000; ++i) {
        uint32_t value = next_random(&random);
        if ((value & 31U) == 0) now = now > 100 ? now - 100 : 0;
        else if ((value & 127U) == 1) now = UINT64_MAX;
        else if (now != UINT64_MAX) now += value % UINT32_C(250000);
        sae_guard_frame_kind_t kind;
        switch ((value >> 8) % 7U) {
        case 0: kind = SAE_GUARD_COMMIT; break;
        case 1: kind = SAE_GUARD_CONFIRM; break;
        case 2: kind = SAE_GUARD_MALFORMED; break;
        case 3: kind = SAE_GUARD_ANTI_CLOGGING; break;
        case 4: kind = SAE_GUARD_UNSUPPORTED_GROUP; break;
        case 5: kind = SAE_GUARD_STATUS_ONLY; break;
        default: kind = SAE_GUARD_NOT_SAE; break;
        }
        sae_guard_observation_t item = make_observation(
            kind, now, (uint8_t)(1 + ((value >> 16) & 63U)),
            (uint8_t)(1 + ((value >> 24) & 63U)));
        item.from_ap = (value & 1U) != 0;
        item.retry = (value & 2U) != 0;
        item.group = (uint16_t)((value & 3U) == 0 ? 19 + (value % 3U) : value);
        item.body_len = (uint16_t)(value % 240U);
        item.status = (uint16_t)(value >> 16);
        sae_guard_event_t event;
        bool emitted = sae_guard_observe(&core, &item, &event);
        if (emitted) {
            assert(event.reason > SAE_GUARD_EVENT_NONE);
            assert(event.reason < SAE_GUARD_EVENT_REASON_COUNT);
            assert(event.observation.timestamp_us == item.timestamp_us);
        } else {
            sae_guard_event_t zero;
            memset(&zero, 0, sizeof(zero));
            assert(memcmp(&event, &zero, sizeof(event)) == 0);
        }
        if ((value & 15U) == 0) (void)sae_guard_expire(&core, now);
        assert(active_pairs(&core) <= SAE_GUARD_TRACKED_PAIRS);
        assert(active_malformed_bssids(&core) <= SAE_GUARD_TRACKED_MALFORMED_BSSIDS);
    }
}

int main(void)
{
    test_malformed_threshold_is_per_bssid_and_rearms();
    test_unconfirmed_threshold_and_retries();
    test_commit_confirm_correlation_and_known_minimums();
    test_retry_identity_does_not_hide_unique_commits();
    test_group_direction_and_monotonic_correlation();
    test_all_known_group_confirm_minimums();
    test_parser_malformed_confirm_keeps_correlated_group();
    test_group_churn_and_informational_status();
    test_simultaneous_thresholds_are_preserved_in_one_event();
    test_separate_capacities_expiry_and_clock_boundaries();
    test_saturating_counters_and_adapter_fields();
    test_null_reset_and_fixed_storage();
    test_null_event_cannot_consume_threshold_evidence();
    test_one_hundred_thousand_random_observations();
    puts("PASS: bounded passive SAE correlation, thresholds, saturation");
    return 0;
}
