#include "wifi_trust_core.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t bssid_a[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};

static sx_observation_t observation(sx_source_t source, uint8_t marker)
{
    sx_observation_t item;
    memset(&item, 0, sizeof(item));
    memcpy(item.bssid, bssid_a, sizeof(item.bssid));
    item.source = source;
    item.complete = true;
    item.ssid_present = true;
    item.ssid_len = 3;
    item.ssid[0] = 0;
    item.ssid[1] = 0xff;
    item.ssid[2] = marker;
    item.privacy = 1;
    item.rsn.status = SX_VALID;
    memcpy(item.rsn.group, "\x00\x0f\xac\x04", 4);
    item.rsn.group_present = true;
    item.rsn.pairwise_known = true;
    item.rsn.pairwise_count = 2;
    memcpy(item.rsn.pairwise[0], "\x00\x0f\xac\x04", 4);
    memcpy(item.rsn.pairwise[1], "\x00\x0f\xac\x08", 4);
    item.rsn.akm_known = true;
    item.rsn.akm_count = 2;
    memcpy(item.rsn.akm[0], "\x00\x0f\xac\x08", 4);
    memcpy(item.rsn.akm[1], "\x00\x0f\xac\x02", 4);
    item.rsn.pmf_capable = true;
    item.rsn.pmf_required = true;
    item.rsn.capabilities_present = true;
    item.wpa.status = SX_ABSENT;
    item.rsnxe.status = SX_VALID;
    item.rsnxe.present = true;
    item.rsnxe.len = 1;
    item.rsnxe.bytes[0] = marker;
    item.wps.status = SX_VALID;
    item.wps.present = true;
    item.wps.state = 2;
    item.wps.config_methods = -1;
    item.wps.setup_locked = 1;
    item.wps.selected_registrar = -1;
    item.wps.manufacturer.present = true;
    item.wps.manufacturer.len = 2;
    item.wps.manufacturer.bytes[0] = 'A';
    item.wps.manufacturer.bytes[1] = marker;
    item.country.status = SX_VALID;
    item.country.code[0] = 'P';
    item.country.code[1] = 'L';
    item.country.code[2] = ' ';
    return item;
}

static void assert_zero(const void *value, size_t size)
{
    const uint8_t *bytes = value;
    for (size_t i = 0; i < size; ++i) assert(bytes[i] == 0);
}

static void test_normalization_and_invalid_atomicity(void)
{
    sx_observation_t item = observation(SX_BEACON, 0x21);
    wifi_trust_profile_t profile;
    memset(&profile, 0xa5, sizeof(profile));
    assert(wifi_trust_profile_from_observation(&item, 11, 1234, &profile));
    assert(!memcmp(profile.bssid, bssid_a, 6));
    assert(profile.ssid_status == SX_VALID && profile.ssid_len == 3);
    assert(!memcmp(profile.ssid, item.ssid, 3));
    assert(profile.source == SX_BEACON && profile.privacy == 1);
    assert(profile.channel == 11 && profile.observed_us == 1234);
    assert(profile.rsn.akm_count == 2 && profile.rsn.pairwise_count == 2);
    assert(profile.rsn.capabilities_present);
    assert(profile.rsnxe.status == SX_VALID && profile.rsnxe.bytes[0] == 0x21);
    assert(profile.wps.manufacturer.bytes[1] == 0x21);
    assert(!memcmp(profile.country.code, "PL ", 3));

    item.ssid_len = 0;
    memset(item.ssid, 0, sizeof(item.ssid));
    assert(wifi_trust_profile_from_observation(&item, 1, 2, &profile));
    assert(profile.ssid_status == SX_VALID && profile.ssid_len == 0);

    item.ssid_present = false;
    assert(wifi_trust_profile_from_observation(&item, 1, 3, &profile));
    assert(profile.ssid_status == SX_ABSENT && profile.ssid_len == 0);

    item.complete = false;
    memset(&profile, 0xa5, sizeof(profile));
    assert(!wifi_trust_profile_from_observation(&item, 1, 4, &profile));
    assert_zero(&profile, sizeof(profile));
    item.complete = true;
    item.source = SX_ASSOC_REQ;
    memset(&profile, 0xa5, sizeof(profile));
    assert(!wifi_trust_profile_from_observation(&item, 1, 5, &profile));
    assert_zero(&profile, sizeof(profile));
    assert(!wifi_trust_profile_from_observation(NULL, 1, 5, &profile));
    assert(!wifi_trust_profile_from_observation(&item, 1, 5, NULL));
}

static wifi_trust_builder_t *find_builder(wifi_trust_table_t *table,
                                          const uint8_t bssid[6])
{
    for (size_t i = 0; i < WIFI_TRUST_MAX_PROFILES; ++i)
        if (table->entries[i].used &&
            memcmp(table->entries[i].bssid, bssid, 6) == 0)
            return &table->entries[i];
    return NULL;
}

static void test_builder_merge_conflict_and_snapshot(void)
{
    wifi_trust_table_t table;
    wifi_trust_table_init(&table);
    sx_observation_t beacon = observation(SX_BEACON, 0x21);
    wifi_trust_field_mask_t newly = UINT32_MAX;
    wifi_trust_builder_t *builder = NULL;
    assert(wifi_trust_table_observe(&table, &beacon, 6, 100,
                                    &builder, &newly) ==
           WIFI_TRUST_INGEST_ACCEPTED);
    assert(builder != NULL && newly == 0 && builder->have_beacon);
    assert(find_builder(&table, bssid_a) == builder);
    wifi_trust_profile_t snapshot;
    assert(wifi_trust_builder_snapshot(builder, &snapshot));
    assert(snapshot.source == SX_BEACON && snapshot.rsnxe.bytes[0] == 0x21);

    /* Unknown same-source fields preserve confirmed values while metadata and
     * explicit valid SSID continue to advance. */
    sx_observation_t unknown = beacon;
    unknown.rsn = (sx_security_t){.status = SX_UNKNOWN};
    unknown.wpa = (sx_security_t){.status = SX_UNKNOWN};
    unknown.rsnxe = (sx_rsnxe_t){.status = SX_UNKNOWN};
    unknown.wps = (sx_wps_t){.status = SX_UNKNOWN, .state = -1,
                             .config_methods = -1, .setup_locked = -1,
                             .selected_registrar = -1};
    unknown.country = (sx_country_t){.status = SX_UNKNOWN};
    unknown.privacy = -1;
    assert(wifi_trust_table_observe(&table, &unknown, 6, 200,
                                    &builder, &newly) ==
           WIFI_TRUST_INGEST_ACCEPTED);
    assert(builder->beacon.observed_us == 200);
    assert(builder->beacon.rsnxe.status == SX_VALID &&
           builder->beacon.rsnxe.bytes[0] == 0x21);
    assert(builder->beacon.wps.setup_locked == 1 &&
           builder->beacon.privacy == 1);

    /* Unknown nested fields in a valid WPS/RSN observation preserve only the
     * unknown subfields, not explicit replacements. */
    sx_observation_t partial = beacon;
    partial.rsn.group_present = false;
    memset(partial.rsn.group, 0, sizeof(partial.rsn.group));
    partial.rsn.pairwise_known = false;
    partial.rsn.pairwise_count = 0;
    memset(partial.rsn.pairwise, 0, sizeof(partial.rsn.pairwise));
    partial.rsn.akm_known = false;
    partial.rsn.akm_count = 0;
    memset(partial.rsn.akm, 0, sizeof(partial.rsn.akm));
    partial.wps.setup_locked = -1;
    partial.wps.manufacturer = (sx_text_t){0};
    partial.wps.state = 1;
    assert(wifi_trust_table_observe(&table, &partial, 6, 300,
                                    &builder, &newly) ==
           WIFI_TRUST_INGEST_ACCEPTED);
    assert(builder->beacon.rsn.group_present &&
           builder->beacon.rsn.pairwise_known &&
           builder->beacon.rsn.akm_known);
    assert(builder->beacon.wps.setup_locked == 1 &&
           builder->beacon.wps.manufacturer.present &&
           builder->beacon.wps.state == 1);

    /* Confirmed absence replaces a formerly valid field. */
    sx_observation_t absent = partial;
    absent.rsnxe = (sx_rsnxe_t){.status = SX_ABSENT};
    assert(wifi_trust_table_observe(&table, &absent, 6, 400,
                                    &builder, &newly) ==
           WIFI_TRUST_INGEST_ACCEPTED);
    assert(builder->beacon.rsnxe.status == SX_ABSENT);

    wifi_trust_builder_t before = *builder;
    wifi_trust_builder_t *existing = builder;
    sx_observation_t invalid = beacon;
    invalid.rsnxe.status = SX_INVALID;
    assert(wifi_trust_table_observe(&table, &invalid, 6, 500,
                                    &builder, &newly) ==
           WIFI_TRUST_INGEST_MALFORMED);
    assert(builder == NULL && !memcmp(existing, &before, sizeof(before)));
    invalid = beacon;
    invalid.complete = false;
    assert(wifi_trust_table_observe(&table, &invalid, 6, 500,
                                    &builder, &newly) ==
           WIFI_TRUST_INGEST_MALFORMED);
    assert(builder == NULL && !memcmp(existing, &before, sizeof(before)));

    /* Backwards source time cannot replace the latest slot. */
    assert(wifi_trust_table_observe(&table, &beacon, 6, 399,
                                    &builder, &newly) ==
           WIFI_TRUST_INGEST_UNRELATED);
    assert(builder == existing && !memcmp(existing, &before, sizeof(before)));

    sx_observation_t probe = observation(SX_PROBE_RESP, 0x31);
    assert(wifi_trust_table_observe(&table, &probe, 6, 600,
                                    &builder, &newly) ==
           WIFI_TRUST_INGEST_CONFLICT);
    assert(newly != 0 && builder->have_probe && builder->conflict_mask != 0);
    assert(!wifi_trust_builder_snapshot(builder, &snapshot));
    assert(builder->beacon.rsnxe.bytes[0] == 0x21 ||
           builder->beacon.rsnxe.status == SX_ABSENT);
    assert(builder->probe.rsnxe.bytes[0] == 0x31);

    probe = beacon;
    probe.source = SX_PROBE_RESP;
    probe.rsnxe = (sx_rsnxe_t){.status = SX_ABSENT};
    probe.wps.state = 1;
    assert(wifi_trust_table_observe(&table, &probe, 6, 700,
                                    &builder, &newly) ==
           WIFI_TRUST_INGEST_ACCEPTED);
    assert(newly == 0 && builder->conflict_mask == 0);
    assert(wifi_trust_builder_snapshot(builder, &snapshot));
    assert(snapshot.source == SX_PROBE_RESP && snapshot.observed_us == 700);
}

static void test_caller_workspace_preserves_transactional_table_semantics(void)
{
    wifi_trust_table_t legacy, bounded;
    wifi_trust_table_init(&legacy);
    wifi_trust_table_init(&bounded);
    wifi_trust_observe_workspace_t workspace;
    memset(&workspace, 0xa5, sizeof(workspace));
    sx_observation_t beacon = observation(SX_BEACON, 0x21);
    sx_observation_t probe = observation(SX_PROBE_RESP, 0x31);
    wifi_trust_builder_t *legacy_builder = NULL, *bounded_builder = NULL;
    wifi_trust_field_mask_t legacy_conflicts = 0U, bounded_conflicts = 0U;

    assert(wifi_trust_table_observe(
               &legacy, &beacon, 6U, 100U, &legacy_builder,
               &legacy_conflicts) == WIFI_TRUST_INGEST_ACCEPTED);
    assert(wifi_trust_table_observe_with_workspace(
               &bounded, &beacon, 6U, 100U, &bounded_builder,
               &bounded_conflicts, &workspace) == WIFI_TRUST_INGEST_ACCEPTED);
    assert(legacy_conflicts == bounded_conflicts);
    assert(legacy_builder != NULL && bounded_builder != NULL);
    assert(memcmp(&legacy, &bounded, sizeof(legacy)) == 0);

    wifi_trust_table_t before = bounded;
    sx_observation_t malformed = beacon;
    malformed.rsn.status = SX_INVALID;
    bounded_builder = (wifi_trust_builder_t *)(uintptr_t)1U;
    bounded_conflicts = UINT32_MAX;
    assert(wifi_trust_table_observe_with_workspace(
               &bounded, &malformed, 6U, 101U, &bounded_builder,
               &bounded_conflicts, &workspace) == WIFI_TRUST_INGEST_MALFORMED);
    assert(bounded_builder == NULL && bounded_conflicts == 0U);
    assert(memcmp(&before, &bounded, sizeof(before)) == 0);

    assert(wifi_trust_table_observe(
               &legacy, &probe, 11U, 200U, &legacy_builder,
               &legacy_conflicts) == WIFI_TRUST_INGEST_CONFLICT);
    assert(wifi_trust_table_observe_with_workspace(
               &bounded, &probe, 11U, 200U, &bounded_builder,
               &bounded_conflicts, &workspace) == WIFI_TRUST_INGEST_CONFLICT);
    assert(legacy_conflicts == bounded_conflicts);
    assert(memcmp(&legacy, &bounded, sizeof(legacy)) == 0);
}

static void test_validation_and_unused_builder_canary(void)
{
    sx_observation_t item = observation(SX_BEACON, 0x21);
    wifi_trust_profile_t profile;

    item.rsnxe.len = 0;
    assert(!wifi_trust_profile_from_observation(&item, 1, 1, &profile));
    item = observation(SX_BEACON, 0x21);
    item.rsnxe.present = false;
    assert(!wifi_trust_profile_from_observation(&item, 1, 1, &profile));
    item = observation(SX_BEACON, 0x21);
    item.country.code[0] = 'p';
    assert(!wifi_trust_profile_from_observation(&item, 1, 1, &profile));
    item = observation(SX_BEACON, 0x21);
    item.wps.present = false;
    assert(!wifi_trust_profile_from_observation(&item, 1, 1, &profile));
    item = observation(SX_BEACON, 0x21);
    item.wps.setup_locked = 2;
    assert(!wifi_trust_profile_from_observation(&item, 1, 1, &profile));

    /* used=false is the only live discriminator; stale bytes in an available
     * fixed-table row must not turn it into a backwards-time rejection. */
    wifi_trust_builder_t builder;
    memset(&builder, 0xa5, sizeof(builder));
    builder.used = false;
    item = observation(SX_BEACON, 0x21);
    assert(wifi_trust_builder_observe(&builder, &item, 1, 1,
                                      NULL) == WIFI_TRUST_INGEST_ACCEPTED);
    assert(builder.used && builder.have_beacon &&
           !memcmp(builder.bssid, item.bssid, 6));
    assert(wifi_trust_builder_observe(NULL, &item, 1, 1, NULL) ==
           WIFI_TRUST_INGEST_MALFORMED);
    assert(wifi_trust_table_observe(NULL, &item, 1, 1, NULL, NULL) ==
           WIFI_TRUST_INGEST_MALFORMED);
    assert(!wifi_trust_builder_snapshot(NULL, &profile));
    assert(!wifi_trust_builder_snapshot(&builder, NULL));
    assert(wifi_trust_diff(&profile, NULL, NULL, 0) == 0);
    assert(wifi_trust_builder_conflict_events(NULL, NULL, 0) == 0);
    assert(wifi_trust_malformed_events(NULL, 1, 1, NULL, 0) == 0);
    wifi_trust_table_init(NULL);
}

static void test_table_capacity_is_non_destructive(void)
{
    wifi_trust_table_t table;
    wifi_trust_table_init(&table);
    sx_observation_t item = observation(SX_BEACON, 1);
    for (size_t i = 0; i < WIFI_TRUST_MAX_PROFILES; ++i) {
        item.bssid[0] = 0x02;
        item.bssid[1] = (uint8_t)i;
        item.bssid[5] = (uint8_t)(i + 1U);
        assert(wifi_trust_table_observe(&table, &item, 1, i + 1U,
                                        NULL, NULL) ==
               WIFI_TRUST_INGEST_ACCEPTED);
    }
    wifi_trust_table_t before = table;
    item.bssid[0] = 0x04;
    item.bssid[1] = 0xee;
    item.bssid[5] = 0xff;
    assert(wifi_trust_table_observe(&table, &item, 1, 1000,
                                    NULL, NULL) ==
           WIFI_TRUST_INGEST_CAPACITY);
    assert(table.capacity_drops == before.capacity_drops + 1U);
    before.capacity_drops = table.capacity_drops;
    assert(!memcmp(&table, &before, sizeof(table)));

    /* Existing rows remain writable when the table is full. */
    item.bssid[0] = 0x02;
    item.bssid[1] = 0;
    item.bssid[5] = 1;
    assert(wifi_trust_table_observe(&table, &item, 1, 2000,
                                    NULL, NULL) ==
           WIFI_TRUST_INGEST_ACCEPTED);
}

static wifi_trust_profile_t profile_fixture(void)
{
    sx_observation_t item = observation(SX_BEACON, 0x21);
    wifi_trust_profile_t out;
    assert(wifi_trust_profile_from_observation(&item, 6, 100, &out));
    return out;
}

static void assert_event_identity(const wifi_trust_event_t *event,
                                  const wifi_trust_profile_t *profile)
{
    assert(!memcmp(event->bssid, profile->bssid, sizeof(event->bssid)));
    assert(event->source == profile->source);
    assert(event->ssid_status == profile->ssid_status);
    assert(event->ssid_len == profile->ssid_len);
    assert(!memcmp(event->ssid, profile->ssid, sizeof(event->ssid)));
    assert(event->channel == profile->channel);
}

static void set_max_security(sx_security_t *security, bool rsn)
{
    memset(security, 0, sizeof(*security));
    security->status = SX_VALID;
    security->group_present = true;
    memcpy(security->group, "\x00\x0f\xac\x04", 4);
    security->management_present = true;
    memcpy(security->management, "\x00\x0f\xac\x06", 4);
    security->pairwise_known = true;
    security->pairwise_count = SX_SELECTORS;
    security->akm_known = true;
    security->akm_count = SX_SELECTORS;
    for (size_t i = 0; i < SX_SELECTORS; ++i) {
        security->pairwise[i][0] = 0x00;
        security->pairwise[i][1] = 0x0f;
        security->pairwise[i][2] = 0xac;
        security->pairwise[i][3] = (uint8_t)(i + 1U);
        security->akm[i][0] = 0x00;
        security->akm[i][1] = 0x0f;
        security->akm[i][2] = 0xac;
        security->akm[i][3] = (uint8_t)(i + 8U);
    }
    security->capabilities_present = rsn;
    security->pmf_capable = rsn;
}

static void test_public_value_encoder(void)
{
    wifi_trust_profile_t profile = profile_fixture();
    wifi_trust_profile_t before = profile;
    for (wifi_trust_field_t field = WIFI_TRUST_FIELD_NONE;
         field < WIFI_TRUST_FIELD_COUNT; ++field) {
        wifi_trust_event_value_t first;
        wifi_trust_event_value_t second;
        memset(&first, 0xa5, sizeof(first));
        memset(&second, 0x5a, sizeof(second));
        assert(wifi_trust_value_from_profile(&profile, field, &first));
        assert(wifi_trust_value_from_profile(&profile, field, &second));
        assert(!memcmp(&first, &second, sizeof(first)));
    }
    assert(!memcmp(&profile, &before, sizeof(profile)));

    wifi_trust_event_value_t canary;
    memset(&canary, 0xa5, sizeof(canary));
    wifi_trust_event_value_t untouched = canary;
    assert(!wifi_trust_value_from_profile(NULL, WIFI_TRUST_FIELD_SSID,
                                          &canary));
    assert(!memcmp(&canary, &untouched, sizeof(canary)));
    assert(!wifi_trust_value_from_profile(&profile, WIFI_TRUST_FIELD_COUNT,
                                          &canary));
    assert(!wifi_trust_value_from_profile(
        &profile, (wifi_trust_field_t)-1, &canary));
    assert(!memcmp(&canary, &untouched, sizeof(canary)));
    assert(!wifi_trust_value_from_profile(&profile, WIFI_TRUST_FIELD_SSID,
                                          NULL));
    wifi_trust_profile_t invalid = profile;
    invalid.rsn.akm_count = UINT8_MAX;
    assert(!wifi_trust_value_from_profile(&invalid, WIFI_TRUST_FIELD_AKM,
                                          &canary));
    assert(!memcmp(&canary, &untouched, sizeof(canary)));

    set_max_security(&profile.rsn, true);
    set_max_security(&profile.wpa, false);
    assert(wifi_trust_profile_valid(&profile));
    assert(wifi_trust_value_from_profile(&profile, WIFI_TRUST_FIELD_AKM,
                                         &canary));
    assert(canary.status == SX_VALID && canary.len == 70U);
    assert(canary.bytes[2] == SX_SELECTORS &&
           canary.bytes[37] == SX_SELECTORS);
    assert(wifi_trust_value_from_profile(&profile, WIFI_TRUST_FIELD_CIPHER,
                                         &canary));
    assert(canary.status == SX_VALID && canary.len == 88U);
}

static void test_event_identity_snapshots(void)
{
    bool seen[WIFI_TRUST_REASON_COUNT] = {false};
    wifi_trust_profile_t baseline = profile_fixture();
    wifi_trust_profile_t current = baseline;
    current.source = SX_PROBE_RESP;
    current.observed_us = 200;
    current.ssid[2] = 0x80;
    current.rsn.akm_count = 1;
    memset(current.rsn.akm[1], 0, sizeof(current.rsn.akm[1]));
    current.rsn.pairwise_count = 1;
    memset(current.rsn.pairwise[1], 0, sizeof(current.rsn.pairwise[1]));
    current.rsn.pmf_required = false;
    current.rsnxe.bytes[0] ^= 1U;
    current.wps.setup_locked = 0;
    memcpy(current.country.code, "US ", 3);
    current.channel = 11;

    wifi_trust_event_t events[WIFI_TRUST_REASON_COUNT];
    size_t count = wifi_trust_diff(NULL, &current, events,
                                   WIFI_TRUST_REASON_COUNT);
    assert(count == 1 && events[0].reason == WIFI_TRUST_NEW_BSSID);
    assert_event_identity(&events[0], &current);
    seen[events[0].reason] = true;

    count = wifi_trust_diff(&baseline, &current, events,
                            WIFI_TRUST_REASON_COUNT);
    assert(count == 8U);
    for (size_t i = 0; i < count; ++i) {
        assert_event_identity(&events[i], &current);
        seen[events[i].reason] = true;
    }

    wifi_trust_profile_t wps_baseline = current;
    wps_baseline.wps = (sx_wps_t){.status = SX_ABSENT, .state = -1,
        .config_methods = -1, .setup_locked = -1,
        .selected_registrar = -1};
    count = wifi_trust_diff(&wps_baseline, &current, events,
                            WIFI_TRUST_REASON_COUNT);
    assert(count == 1 && events[0].reason == WIFI_TRUST_WPS_ENABLED);
    assert_event_identity(&events[0], &current);
    seen[events[0].reason] = true;

    wifi_trust_profile_t empty = current;
    memset(empty.ssid, 0, sizeof(empty.ssid));
    empty.ssid_len = 0;
    count = wifi_trust_diff(&current, &empty, events,
                            WIFI_TRUST_REASON_COUNT);
    assert(count == 1 && events[0].reason == WIFI_TRUST_SSID_CHANGED);
    assert_event_identity(&events[0], &empty);
    assert(events[0].ssid_status == SX_VALID && events[0].ssid_len == 0);

    wifi_trust_profile_t channel_unknown = current;
    channel_unknown.channel = 0;
    channel_unknown.ssid[2] ^= 1U;
    count = wifi_trust_diff(&current, &channel_unknown, events,
                            WIFI_TRUST_REASON_COUNT);
    assert(count == 1 && events[0].reason == WIFI_TRUST_SSID_CHANGED);
    assert_event_identity(&events[0], &channel_unknown);
    assert(events[0].channel == 0U);

    wifi_trust_table_t table;
    wifi_trust_table_init(&table);
    sx_observation_t beacon = observation(SX_BEACON, 0x21);
    sx_observation_t probe = observation(SX_PROBE_RESP, 0x31);
    wifi_trust_builder_t *builder = NULL;
    assert(wifi_trust_table_observe(&table, &beacon, 6, 1,
                                    &builder, NULL) ==
           WIFI_TRUST_INGEST_ACCEPTED);
    assert(wifi_trust_table_observe(&table, &probe, 11, 2,
                                    &builder, NULL) ==
           WIFI_TRUST_INGEST_CONFLICT);
    count = wifi_trust_builder_conflict_events(
        builder, events, WIFI_TRUST_REASON_COUNT);
    assert(count != 0U);
    for (size_t i = 0; i < count; ++i) {
        assert(events[i].source == SX_PROBE_RESP && events[i].channel == 11U);
        assert(events[i].ssid_status == SX_VALID && events[i].ssid_len == 3U);
        assert(events[i].ssid[0] == 0 && events[i].ssid[1] == 0xff &&
               events[i].ssid[2] == 0x31);
        seen[events[i].reason] = true;
    }

    sx_observation_t malformed = observation(SX_BEACON, 0x41);
    malformed.rsn.status = SX_INVALID;
    count = wifi_trust_malformed_events(&malformed, 9, 300, events,
                                        WIFI_TRUST_REASON_COUNT);
    assert(count == 1 &&
           events[0].reason == WIFI_TRUST_MALFORMED_OBSERVATION);
    assert(events[0].source == SX_BEACON && events[0].channel == 9U);
    assert(events[0].ssid_status == SX_VALID && events[0].ssid_len == 3U);
    assert(!memcmp(events[0].ssid, malformed.ssid, 3));
    seen[events[0].reason] = true;

    malformed = observation(SX_ASSOC_REQ, 0x41);
    malformed.ssid_len = UINT8_MAX;
    count = wifi_trust_malformed_events(&malformed, UINT8_MAX, 301, events,
                                        WIFI_TRUST_REASON_COUNT);
    assert(count == 1 && events[0].source == SX_NONE &&
           events[0].channel == 0U && events[0].ssid_status == SX_INVALID &&
           events[0].ssid_len == 0U);
    for (size_t i = 0; i < sizeof(events[0].ssid); ++i)
        assert(events[0].ssid[i] == 0U);

    sx_observation_t canonical = observation(SX_BEACON, 0x51);
    assert(wifi_trust_malformed_events(&canonical, 0, 302, events,
                                       WIFI_TRUST_REASON_COUNT) == 0U);
    const uint8_t invalid_channels[] = {234U, UINT8_MAX};
    for (size_t i = 0; i < sizeof(invalid_channels); ++i) {
        memset(events, 0xa5, sizeof(events));
        count = wifi_trust_malformed_events(
            &canonical, invalid_channels[i], 303U + i, events,
            WIFI_TRUST_REASON_COUNT);
        assert(count == 1U &&
               events[0].reason == WIFI_TRUST_MALFORMED_OBSERVATION &&
               events[0].field == WIFI_TRUST_FIELD_ADVERTISEMENT);
        assert(events[0].channel == 0U && events[0].source == SX_BEACON &&
               events[0].ssid_status == SX_VALID &&
               events[0].ssid_len == canonical.ssid_len);
        assert(!memcmp(events[0].bssid, canonical.bssid,
                       sizeof(events[0].bssid)));
        assert(!memcmp(events[0].ssid, canonical.ssid,
                       sizeof(events[0].ssid)));

        wifi_trust_event_t canary;
        memset(&canary, 0xa5, sizeof(canary));
        wifi_trust_event_t untouched = canary;
        assert(wifi_trust_malformed_events(
            &canonical, invalid_channels[i], 303U + i, &canary, 0) == 1U);
        assert(!memcmp(&canary, &untouched, sizeof(canary)));
    }

    for (uint32_t i = 0; i < 10000U; ++i) {
        canonical = observation((i & 1U) ? SX_BEACON : SX_PROBE_RESP,
                                (uint8_t)i);
        uint8_t invalid_channel = (i & 1U) ? 234U : UINT8_MAX;
        assert(wifi_trust_malformed_events(
            &canonical, invalid_channel, i, events,
            WIFI_TRUST_REASON_COUNT) == 1U);
        assert(events[0].channel == 0U &&
               events[0].source == canonical.source &&
               events[0].ssid_status == SX_VALID &&
               events[0].ssid_len == canonical.ssid_len);
    }

    for (wifi_trust_reason_t reason = WIFI_TRUST_NEW_BSSID;
         reason <= WIFI_TRUST_MALFORMED_OBSERVATION; ++reason)
        assert(seen[reason]);
}

static void test_diff_order_multisets_unknown_and_capacity(void)
{
    wifi_trust_profile_t baseline = profile_fixture();
    wifi_trust_profile_t current = baseline;
    wifi_trust_event_t events[WIFI_TRUST_REASON_COUNT];

    size_t count = wifi_trust_diff(NULL, &current, events,
                                   WIFI_TRUST_REASON_COUNT);
    assert(count == 1 && events[0].reason == WIFI_TRUST_NEW_BSSID);
    assert(!memcmp(events[0].bssid, baseline.bssid, 6));
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 0);

    /* Order-only changes do not drift; multiplicity still does. */
    memcpy(current.rsn.akm[0], baseline.rsn.akm[1], 4);
    memcpy(current.rsn.akm[1], baseline.rsn.akm[0], 4);
    memcpy(current.rsn.pairwise[0], baseline.rsn.pairwise[1], 4);
    memcpy(current.rsn.pairwise[1], baseline.rsn.pairwise[0], 4);
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 0);
    memcpy(current.rsn.akm[1], current.rsn.akm[0], 4);
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 1);
    assert(events[0].reason == WIFI_TRUST_AKM_CHANGED);

    current = baseline;
    current.ssid[2] ^= 0x7f;
    current.rsn.akm_count = 1;
    memset(current.rsn.akm[1], 0, sizeof(current.rsn.akm[1]));
    current.rsn.pairwise_count = 1;
    memset(current.rsn.pairwise[1], 0,
           sizeof(current.rsn.pairwise[1]));
    current.rsn.pmf_required = false;
    current.rsnxe.bytes[0] ^= 1U;
    current.wps.setup_locked = 0;
    current.country.code[0] = 'U';
    current.country.code[1] = 'S';
    current.channel = 11;
    const wifi_trust_reason_t expected[] = {
        WIFI_TRUST_SSID_CHANGED,
        WIFI_TRUST_AKM_CHANGED,
        WIFI_TRUST_CIPHER_CHANGED,
        WIFI_TRUST_PMF_DOWNGRADE,
        WIFI_TRUST_RSNXE_CHANGED,
        WIFI_TRUST_WPS_LOCK_CHANGED,
        WIFI_TRUST_COUNTRY_CHANGED,
        WIFI_TRUST_CHANNEL_CHANGED,
    };
    count = wifi_trust_diff(&baseline, &current, events,
                            WIFI_TRUST_REASON_COUNT);
    assert(count == sizeof(expected) / sizeof(expected[0]));
    for (size_t i = 0; i < count; ++i) assert(events[i].reason == expected[i]);

    /* Insufficient capacity reports required size without touching output. */
    wifi_trust_event_t canary[WIFI_TRUST_REASON_COUNT];
    memset(canary, 0xa5, sizeof(canary));
    wifi_trust_event_t untouched[WIFI_TRUST_REASON_COUNT];
    memcpy(untouched, canary, sizeof(canary));
    assert(wifi_trust_diff(&baseline, &current, canary, count - 1U) == count);
    assert(!memcmp(canary, untouched, sizeof(canary)));
    assert(wifi_trust_diff(&baseline, &current, NULL, 0) == count);

    /* Unknown current evidence cannot invent a drift. */
    current = baseline;
    current.ssid_status = SX_UNKNOWN;
    current.ssid_len = 0;
    memset(current.ssid, 0, sizeof(current.ssid));
    current.rsn = (sx_security_t){.status = SX_UNKNOWN};
    current.wpa = (sx_security_t){.status = SX_UNKNOWN};
    current.rsnxe = (sx_rsnxe_t){.status = SX_UNKNOWN};
    current.wps = (sx_wps_t){.status = SX_UNKNOWN, .state = -1,
                             .config_methods = -1, .setup_locked = -1,
                             .selected_registrar = -1};
    current.country = (sx_country_t){.status = SX_UNKNOWN};
    current.privacy = -1;
    current.channel = 0;
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 0);

    /* Confirmed absence is evidence, not unknown. */
    current = baseline;
    current.rsnxe = (sx_rsnxe_t){.status = SX_ABSENT};
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 1);
    assert(events[0].reason == WIFI_TRUST_RSNXE_CHANGED);

    baseline = profile_fixture();
    current = baseline;
    baseline.wps = (sx_wps_t){.status = SX_UNKNOWN, .state = -1,
                              .config_methods = -1, .setup_locked = -1,
                              .selected_registrar = -1};
    assert(wifi_trust_profile_valid(&baseline));
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 0);

    baseline = profile_fixture();
    current = baseline;
    baseline.wps = (sx_wps_t){.status = SX_ABSENT, .state = -1,
                              .config_methods = -1, .setup_locked = -1,
                              .selected_registrar = -1};
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 1);
    assert(events[0].reason == WIFI_TRUST_WPS_ENABLED);

    /* Every frozen PMF downgrade edge is observable, while strengthening is
     * not mislabeled as a downgrade. */
    baseline = profile_fixture();
    current = baseline;
    current.rsn.pmf_required = false;
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 1);
    assert(events[0].reason == WIFI_TRUST_PMF_DOWNGRADE);
    current = baseline;
    current.rsn = (sx_security_t){.status = SX_ABSENT};
    count = wifi_trust_diff(&baseline, &current, events,
                            WIFI_TRUST_REASON_COUNT);
    assert(count == 3 && events[0].reason == WIFI_TRUST_AKM_CHANGED &&
           events[1].reason == WIFI_TRUST_CIPHER_CHANGED &&
           events[2].reason == WIFI_TRUST_PMF_DOWNGRADE);
    baseline.rsn.pmf_required = false;
    current = baseline;
    current.rsn.pmf_capable = false;
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 1);
    assert(events[0].reason == WIFI_TRUST_PMF_DOWNGRADE);
    baseline.rsn.pmf_capable = false;
    current = baseline;
    current.rsn.pmf_capable = true;
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 0);
    baseline = profile_fixture();
    current = baseline;
    current.rsn.capabilities_present = false;
    current.rsn.pmf_capable = false;
    current.rsn.pmf_required = false;
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 0);

    baseline = profile_fixture();
    current = baseline;
    current.privacy = 0;
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 1);
    assert(events[0].reason == WIFI_TRUST_CIPHER_CHANGED &&
           events[0].field == WIFI_TRUST_FIELD_PRIVACY);

    baseline = profile_fixture();
    current = baseline;
    current.privacy = 0;
    current.rsn.akm_count = 1;
    memset(current.rsn.akm[1], 0, sizeof(current.rsn.akm[1]));
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 2);
    assert(events[0].reason == WIFI_TRUST_AKM_CHANGED &&
           events[0].field == WIFI_TRUST_FIELD_AKM);
    assert(events[1].reason == WIFI_TRUST_CIPHER_CHANGED &&
           events[1].field == WIFI_TRUST_FIELD_PRIVACY);

    /* Invalid current evidence produces only malformed_observation. */
    baseline = profile_fixture();
    current = baseline;
    current.rsnxe.status = SX_INVALID;
    current.ssid[0] ^= 1U;
    assert(wifi_trust_diff(&baseline, &current, events,
                           WIFI_TRUST_REASON_COUNT) == 1);
    assert(events[0].reason == WIFI_TRUST_MALFORMED_OBSERVATION);
}

static void expect_invalid_profile(const wifi_trust_profile_t *baseline,
                                   const wifi_trust_profile_t *current,
                                   bool baseline_invalid,
                                   bool current_invalid)
{
    wifi_trust_event_t event;
    memset(&event, 0xa5, sizeof(event));
    assert(wifi_trust_diff(baseline, current, &event, 1) == 1);
    assert(event.reason == WIFI_TRUST_MALFORMED_OBSERVATION &&
           event.field == WIFI_TRUST_FIELD_ADVERTISEMENT);
    assert(event.baseline.status ==
           (baseline_invalid ? SX_INVALID : SX_VALID));
    assert(event.current.status ==
           (current_invalid ? SX_INVALID : SX_VALID));

    wifi_trust_event_t canary;
    memset(&canary, 0xa5, sizeof(canary));
    wifi_trust_event_t before = canary;
    assert(wifi_trust_diff(baseline, current, &canary, 0) == 1);
    assert(!memcmp(&canary, &before, sizeof(canary)));
}

static void test_invalid_baseline_and_current_are_bounded(void)
{
    wifi_trust_profile_t valid = profile_fixture();
    wifi_trust_profile_t bad = valid;

    bad.source = SX_ASSOC_REQ;
    expect_invalid_profile(&bad, &valid, true, false);
    expect_invalid_profile(&valid, &bad, false, true);

    bad = valid; bad.channel = 234;
    expect_invalid_profile(&bad, &valid, true, false);
    bad = valid; bad.privacy = -2;
    expect_invalid_profile(&bad, &valid, true, false);
    expect_invalid_profile(&valid, &bad, false, true);
    bad = valid; bad.privacy = 2;
    expect_invalid_profile(&bad, &valid, true, false);
    expect_invalid_profile(&valid, &bad, false, true);
    bad = valid; bad.ssid_status = SX_ABSENT; bad.ssid_len = 1;
    expect_invalid_profile(&bad, &valid, true, false);
    bad = valid; bad.ssid[31] = 1;
    expect_invalid_profile(&bad, &valid, true, false);
    bad = valid; bad.rsn.akm_count = UINT8_MAX;
    expect_invalid_profile(&bad, &valid, true, false);
    expect_invalid_profile(&valid, &bad, false, true);
    bad = valid; bad.rsn.pairwise_count = UINT8_MAX;
    expect_invalid_profile(&bad, &valid, true, false);
    expect_invalid_profile(&valid, &bad, false, true);
    bad = valid; bad.rsn.pairwise_known = false; bad.rsn.pairwise_count = 1;
    expect_invalid_profile(&bad, &valid, true, false);
    bad = valid; bad.rsn.capabilities_present = false;
    expect_invalid_profile(&bad, &valid, true, false);
    bad = valid; bad.rsn.status = SX_ABSENT; bad.rsn.group_present = true;
    expect_invalid_profile(&bad, &valid, true, false);
    bad = valid; bad.wps.status = SX_ABSENT; bad.wps.present = true;
    expect_invalid_profile(&bad, &valid, true, false);
    bad = valid; bad.rsnxe.status = SX_ABSENT; bad.rsnxe.present = true;
    expect_invalid_profile(&bad, &valid, true, false);
    bad = valid; bad.country.status = SX_ABSENT; bad.country.code[0] = 'P';
    expect_invalid_profile(&bad, &valid, true, false);
    bad = valid; bad.rsn.status = (sx_status_t)99;
    expect_invalid_profile(&bad, &valid, true, false);

    for (uint32_t i = 0; i < 10000U; ++i) {
        bad = valid;
        switch (i % 8U) {
        case 0: bad.rsn.akm_count = (uint8_t)(9U + i % 247U); break;
        case 1: bad.rsn.pairwise_count = (uint8_t)(9U + i % 247U); break;
        case 2: bad.wpa.akm_count = UINT8_MAX; break;
        case 3: bad.wpa.pairwise_count = UINT8_MAX; break;
        case 4: bad.rsnxe.len = UINT8_MAX; break;
        case 5: bad.wps.manufacturer.len = UINT8_MAX; break;
        case 6: bad.privacy = -2; break;
        default: bad.privacy = 2; break;
        }
        wifi_trust_event_t event;
        size_t count = (i & 1U) ?
            wifi_trust_diff(&bad, &valid, &event, 1) :
            wifi_trust_diff(&valid, &bad, &event, 1);
        assert(count == 1 &&
               event.reason == WIFI_TRUST_MALFORMED_OBSERVATION);
        wifi_trust_event_value_t encoded;
        memset(&encoded, 0xa5, sizeof(encoded));
        wifi_trust_event_value_t untouched = encoded;
        assert(!wifi_trust_value_from_profile(
            &bad, (wifi_trust_field_t)(i % WIFI_TRUST_FIELD_COUNT),
            &encoded));
        assert(!memcmp(&encoded, &untouched, sizeof(encoded)));
    }
}

static void test_malformed_and_conflict_batches_are_atomic(void)
{
    sx_observation_t invalid = observation(SX_BEACON, 0x21);
    invalid.rsn.status = SX_INVALID;
    wifi_trust_event_t event;
    memset(&event, 0xa5, sizeof(event));
    assert(wifi_trust_malformed_events(&invalid, 6, 99, &event, 1) == 1);
    assert(event.reason == WIFI_TRUST_MALFORMED_OBSERVATION &&
           event.field == WIFI_TRUST_FIELD_ADVERTISEMENT);

    wifi_trust_table_t table;
    wifi_trust_table_init(&table);
    sx_observation_t beacon = observation(SX_BEACON, 0x21);
    sx_observation_t probe = observation(SX_PROBE_RESP, 0x31);
    wifi_trust_builder_t *builder = NULL;
    assert(wifi_trust_table_observe(&table, &beacon, 6, 1,
                                    &builder, NULL) ==
           WIFI_TRUST_INGEST_ACCEPTED);
    assert(wifi_trust_table_observe(&table, &probe, 11, 2,
                                    &builder, NULL) ==
           WIFI_TRUST_INGEST_CONFLICT);
    size_t required = wifi_trust_builder_conflict_events(builder, NULL, 0);
    assert(required == 4);
    wifi_trust_event_t batch[WIFI_TRUST_REASON_COUNT];
    wifi_trust_event_t *out = batch;
    memset(out, 0xa5, sizeof(batch));
    wifi_trust_event_t copy[WIFI_TRUST_REASON_COUNT];
    memcpy(copy, out, sizeof(copy));
    assert(wifi_trust_builder_conflict_events(builder, out,
                                              required - 1U) == required);
    assert(!memcmp(out, copy, sizeof(copy)));
    assert(wifi_trust_builder_conflict_events(builder, out,
                                              WIFI_TRUST_REASON_COUNT) ==
           required);
    for (size_t i = 0; i < required; ++i)
        assert(out[i].reason == WIFI_TRUST_ADVERTISEMENT_CONFLICT);
    assert(out[0].field == WIFI_TRUST_FIELD_SSID &&
           out[1].field == WIFI_TRUST_FIELD_RSNXE &&
           out[2].field == WIFI_TRUST_FIELD_WPS_MANUFACTURER &&
           out[3].field == WIFI_TRUST_FIELD_CHANNEL);
    assert(out[0].baseline.len == 3 && out[0].current.len == 3 &&
           out[0].baseline.bytes[2] == 0x21 &&
           out[0].current.bytes[2] == 0x31);
    assert(out[2].baseline.len == 2 && out[2].current.len == 2 &&
           out[2].baseline.bytes[1] == 0x21 &&
           out[2].current.bytes[1] == 0x31);

    wifi_trust_builder_t extra_bits = *builder;
    extra_bits.conflict_mask |= WIFI_TRUST_FIELD_MASK(WIFI_TRUST_FIELD_NONE) |
                                UINT32_C(0x80000000);
    memset(out, 0xa5, sizeof(batch));
    memcpy(copy, out, sizeof(copy));
    assert(wifi_trust_builder_conflict_events(&extra_bits, NULL, 0U) ==
           required);
    assert(wifi_trust_builder_conflict_events(
               &extra_bits, out, WIFI_TRUST_REASON_COUNT) == required);
    assert(out[0].field == WIFI_TRUST_FIELD_SSID &&
           out[1].field == WIFI_TRUST_FIELD_RSNXE &&
           out[2].field == WIFI_TRUST_FIELD_WPS_MANUFACTURER &&
           out[3].field == WIFI_TRUST_FIELD_CHANNEL);
    assert(!memcmp(&out[required], &copy[required],
                   (WIFI_TRUST_REASON_COUNT - required) * sizeof(*out)));

    wifi_trust_builder_t corrupt = *builder;
    corrupt.probe.source = SX_BEACON;
    memset(out, 0xa5, sizeof(batch));
    memcpy(copy, out, sizeof(copy));
    assert(wifi_trust_builder_conflict_events(
        &corrupt, out, WIFI_TRUST_REASON_COUNT) == 0U);
    assert(!memcmp(out, copy, sizeof(copy)));
    corrupt = *builder;
    corrupt.probe.ssid_len = UINT8_MAX;
    assert(wifi_trust_builder_conflict_events(
        &corrupt, out, WIFI_TRUST_REASON_COUNT) == 0U);
    assert(!memcmp(out, copy, sizeof(copy)));
}

static uint32_t rng_state = UINT32_C(0x12345678);
static uint32_t random_u32(void)
{
    rng_state = rng_state * UINT32_C(1664525) + UINT32_C(1013904223);
    return rng_state;
}

static void randomized_safety(void)
{
    wifi_trust_table_t table;
    wifi_trust_table_init(&table);
    for (uint32_t i = 0; i < 100000U; ++i) {
        sx_observation_t item = observation(
            (random_u32() & 1U) ? SX_BEACON : SX_PROBE_RESP,
            (uint8_t)random_u32());
        item.bssid[1] = (uint8_t)(random_u32() % 140U);
        item.bssid[5] = (uint8_t)(item.bssid[1] + 1U);
        if ((random_u32() & 31U) == 0U) item.rsnxe.status = SX_INVALID;
        (void)wifi_trust_table_observe(&table, &item,
                                       (uint8_t)(1U + random_u32() % 14U),
                                       i + 1U, NULL, NULL);
        wifi_trust_profile_t a = profile_fixture();
        wifi_trust_profile_t b = a;
        b.channel = (uint8_t)(random_u32() % 15U);
        wifi_trust_event_t batch[WIFI_TRUST_REASON_COUNT];
        (void)wifi_trust_diff(&a, &b, batch, WIFI_TRUST_REASON_COUNT);
    }
}

int main(void)
{
    test_normalization_and_invalid_atomicity();
    test_builder_merge_conflict_and_snapshot();
    test_caller_workspace_preserves_transactional_table_semantics();
    test_validation_and_unused_builder_canary();
    test_table_capacity_is_non_destructive();
    test_public_value_encoder();
    test_event_identity_snapshots();
    test_diff_order_multisets_unknown_and_capacity();
    test_invalid_baseline_and_current_are_bounded();
    test_malformed_and_conflict_batches_are_atomic();
    randomized_safety();
    puts("PASS: Wi-Fi trust profiles, source builders, deterministic drift");
    return 0;
}
