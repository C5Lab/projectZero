#include "wifi_shield_core.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned tx_calls, heap_calls;

/* Link-time spies catch direct SDK TX and heap calls made by the real core. */
int esp_wifi_80211_tx(int interface, const void *buffer, int length, bool sequence)
{
    (void)interface; (void)buffer; (void)length; (void)sequence;
    ++tx_calls;
    return 0;
}
void *__wrap_malloc(size_t size) { (void)size; ++heap_calls; return NULL; }
void *__wrap_calloc(size_t count, size_t size)
{ (void)count; (void)size; ++heap_calls; return NULL; }
void *__wrap_realloc(void *ptr, size_t size)
{ (void)ptr; (void)size; ++heap_calls; return NULL; }
void __wrap_free(void *ptr) { (void)ptr; ++heap_calls; }

typedef int (*tx_hook_t)(int, const void *, int, bool);
typedef struct {
    wifi_shield_channel_plan_t plan;
    wifi_shield_core_t core;
    tx_hook_t tx;
} fixture_t;

static void setup(fixture_t *f)
{
    const wifi_shield_target_t targets[] = {
        {{2, 1, 2, 3, 4, 5}, 6, "first", false},
        {{2, 1, 2, 3, 4, 6}, 11, "second", false}
    };
    memset(f, 0, sizeof(*f));
    f->tx = esp_wifi_80211_tx; /* Injected into the higher-level passive fixture. */
    assert(wifi_shield_channel_plan_init(&f->plan, targets, 2));
    wifi_shield_core_init(&f->core, &f->plan);
}

static wifi_shield_event_t event(wifi_shield_event_type_t type)
{
    wifi_shield_event_t e = {0};
    const uint8_t bssid[] = {2, 1, 2, 3, 4, 5}, station[] = {4, 6, 7, 8, 9, 10};
    memcpy(e.bssid, bssid, 6);
    memcpy(e.station, station, 6);
    e.type = type;
    e.channel = 6;
    e.count = 1;
    e.timestamp_us = 100;
    switch (type) {
    case WIFI_SHIELD_EVENT_DEAUTH:
    case WIFI_SHIELD_EVENT_DISASSOC:
        e.source = WIFI_SHIELD_SOURCE_DEAUTH; e.severity = WIFI_SHIELD_SEVERITY_ALERT; break;
    case WIFI_SHIELD_EVENT_CSA:
        e.source = WIFI_SHIELD_SOURCE_DEAUTH; e.severity = WIFI_SHIELD_SEVERITY_INFO; break;
    case WIFI_SHIELD_EVENT_WPS_ACTIVITY:
        e.source = WIFI_SHIELD_SOURCE_WPS; e.severity = WIFI_SHIELD_SEVERITY_INFO; break;
    case WIFI_SHIELD_EVENT_WPS_RETRY_BURST:
        e.source = WIFI_SHIELD_SOURCE_WPS; e.severity = WIFI_SHIELD_SEVERITY_WARN; break;
    case WIFI_SHIELD_EVENT_WPS_ANOMALY:
        e.source = WIFI_SHIELD_SOURCE_WPS; e.severity = WIFI_SHIELD_SEVERITY_ALERT; break;
    case WIFI_SHIELD_EVENT_SAE_ACTIVITY:
        e.source = WIFI_SHIELD_SOURCE_SAE; e.severity = WIFI_SHIELD_SEVERITY_INFO; break;
    case WIFI_SHIELD_EVENT_SAE_ANOMALY:
        e.source = WIFI_SHIELD_SOURCE_SAE; e.severity = WIFI_SHIELD_SEVERITY_ALERT; break;
    case WIFI_SHIELD_EVENT_TRUST_DRIFT:
        e.source = WIFI_SHIELD_SOURCE_TRUST; e.severity = WIFI_SHIELD_SEVERITY_ALERT; break;
    case WIFI_SHIELD_EVENT_PMKID_SEQUENCE:
        e.source = WIFI_SHIELD_SOURCE_PMKID; e.severity = WIFI_SHIELD_SEVERITY_INFO; break;
    }
    return e;
}

static bool submit(fixture_t *f, const wifi_shield_event_t *e)
{
    /* The aggregate API deliberately has no TX hook argument. */
    bool publish = wifi_shield_core_publishable(&f->core, e);
    assert(f->tx == esp_wifi_80211_tx && tx_calls == 0 && heap_calls == 0);
    return publish;
}

static void test_selection_and_plan_lifetime(void)
{
    fixture_t f; setup(&f);
    wifi_shield_channel_plan_t before = f.plan;
    wifi_shield_event_t e = event(WIFI_SHIELD_EVENT_DEAUTH);
    assert(f.core.plan == &f.plan);
    assert(wifi_shield_core_selected(&f.core, e.bssid));
    assert(submit(&f, &e));
    e.bssid[5] = 6; e.channel = 11;
    assert(wifi_shield_core_selected(&f.core, e.bssid));
    assert(submit(&f, &e));
    e.bssid[5] = 7;
    assert(!wifi_shield_core_selected(&f.core, e.bssid));
    assert(!submit(&f, &e));
    assert(f.core.source_events[0] == 2 && f.core.alerts == 2);
    assert(memcmp(&before, &f.plan, sizeof(before)) == 0);
    assert(!wifi_shield_core_selected(NULL, e.bssid));
    assert(!wifi_shield_core_selected(&f.core, NULL));
}

static void test_severity_source_mapping_and_passive_tx(void)
{
    fixture_t f; setup(&f);
    for (int type = 0; type < 10; ++type) {
        wifi_shield_event_t e = event((wifi_shield_event_type_t)type);
        if (type == 4) e.count = 8;
        wifi_shield_core_t before = f.core;
        e.severity = (wifi_shield_severity_t)((e.severity + 1) % 3);
        assert(!submit(&f, &e));
        assert(memcmp(&before, &f.core, sizeof(before)) == 0);
        e = event((wifi_shield_event_type_t)type);
        e.source = (wifi_shield_source_t)((e.source + 1) % 5);
        assert(!submit(&f, &e));
        assert(memcmp(&before, &f.core, sizeof(before)) == 0);
        e = event((wifi_shield_event_type_t)type);
        if (type == 4) e.count = 8;
        assert(submit(&f, &e));
    }
    assert(f.core.source_events[0] == 3);
    assert(f.core.source_events[1] == 10);
    assert(f.core.source_events[2] == 2);
    assert(f.core.source_events[3] == 1);
    assert(f.core.source_events[4] == 1);
    assert(f.core.alerts == 5);
}

static void test_wps_activity_identity_and_exact_window(void)
{
    fixture_t f; setup(&f);
    wifi_shield_event_t e = event(WIFI_SHIELD_EVENT_WPS_ACTIVITY);
    assert(submit(&f, &e));
    e.wps_message = WIFI_SHIELD_WPS_M3; /* Message Type does not change the key. */
    e.timestamp_us = 10000099;
    assert(!submit(&f, &e));
    e.timestamp_us = 10000100;
    assert(submit(&f, &e));
    assert(!submit(&f, &e));
    ++e.station[5];
    assert(submit(&f, &e));
    e.bssid[5] = 6; e.channel = 11;
    assert(submit(&f, &e));
    assert(f.core.source_events[1] == 6 && f.core.alerts == 0);
}

static void test_deauth_alert_is_published_once_per_window(void)
{
    fixture_t f; setup(&f);
    wifi_shield_event_t e = event(WIFI_SHIELD_EVENT_DEAUTH);
    assert(submit(&f, &e));
    for (uint64_t i = 1; i < 100; ++i) {
        e.timestamp_us = 100U + i;
        assert(!submit(&f, &e));
    }
    assert(f.core.source_events[0] == 100 && f.core.alerts == 1);
    e.timestamp_us = 10000099U;
    assert(!submit(&f, &e));
    e.timestamp_us = 10000100U;
    assert(submit(&f, &e));
    assert(f.core.source_events[0] == 102 && f.core.alerts == 2);

    e.type = WIFI_SHIELD_EVENT_CSA;
    e.severity = WIFI_SHIELD_SEVERITY_INFO;
    assert(submit(&f, &e));
    assert(!submit(&f, &e));
    assert(f.core.source_events[0] == 104 && f.core.alerts == 2);
    e.timestamp_us += 10000000U;
    e.severity = WIFI_SHIELD_SEVERITY_ALERT;
    assert(!submit(&f, &e));
    assert(f.core.source_events[0] == 104 && f.core.alerts == 2);
}

static void test_retry_threshold_contributions_and_window(void)
{
    fixture_t f; setup(&f);
    wifi_shield_event_t e = event(WIFI_SHIELD_EVENT_WPS_RETRY_BURST);
    for (size_t i = 0; i < 7; ++i) assert(!submit(&f, &e));
    assert(submit(&f, &e));
    assert(!submit(&f, &e));
    e.timestamp_us = 10000099;
    assert(!submit(&f, &e));
    e.timestamp_us = 10000100; e.count = 7;
    assert(!submit(&f, &e));
    e.count = 1;
    assert(submit(&f, &e));
    ++e.station[5]; e.count = 8;
    assert(submit(&f, &e));
    assert(f.core.source_events[1] == 26 && f.core.alerts == 0);
    /* Activity and retry have separate policy keys on the same flow. */
    e.type = WIFI_SHIELD_EVENT_WPS_ACTIVITY; e.severity = WIFI_SHIELD_SEVERITY_INFO;
    assert(submit(&f, &e));
}

static void test_backwards_time_does_not_reopen_or_underflow(void)
{
    fixture_t f; setup(&f);
    wifi_shield_event_t e = event(WIFI_SHIELD_EVENT_WPS_ACTIVITY);
    e.timestamp_us = 20000000;
    assert(submit(&f, &e));
    e.timestamp_us = 1;
    assert(!submit(&f, &e));
    assert(f.core.rate_limits[0].window_started_us == 20000000);
    e.timestamp_us = 29999999;
    assert(!submit(&f, &e));
    e.timestamp_us = 30000000;
    assert(submit(&f, &e));
    e = event(WIFI_SHIELD_EVENT_WPS_RETRY_BURST);
    e.timestamp_us = UINT64_MAX - 20; e.count = 7;
    assert(!submit(&f, &e));
    e.timestamp_us = 0; e.count = 1;
    assert(!submit(&f, &e)); /* Out-of-order retry cannot complete a later window. */
    e.timestamp_us = UINT64_MAX;
    assert(submit(&f, &e));
}

static void test_fixed_capacity_preserves_all_identities(void)
{
    fixture_t f; setup(&f);
    wifi_shield_event_t e = event(WIFI_SHIELD_EVENT_WPS_ACTIVITY);
    for (size_t i = 0; i < 64; ++i) {
        e.station[5] = (uint8_t)(20 + i);
        assert(submit(&f, &e));
    }
    wifi_shield_rate_limit_t before[64];
    memcpy(before, f.core.rate_limits, sizeof(before));
    e.station[5] = 100; e.timestamp_us = UINT64_MAX;
    assert(!submit(&f, &e));
    assert(f.core.event_drops == 1);
    assert(memcmp(before, f.core.rate_limits, sizeof(before)) == 0);
    f.core.event_drops = UINT32_MAX - 1;
    assert(!submit(&f, &e)); assert(!submit(&f, &e));
    assert(f.core.event_drops == UINT32_MAX);
    for (size_t i = 0; i < 64; ++i) {
        e.station[5] = (uint8_t)(20 + i); e.timestamp_us = 100;
        assert(!submit(&f, &e));
    }
    e = event(WIFI_SHIELD_EVENT_TRUST_DRIFT);
    assert(submit(&f, &e)); /* Unbounded identity diversity cannot block alerts. */
    e = event(WIFI_SHIELD_EVENT_DEAUTH);
    assert(submit(&f, &e));
    assert(!submit(&f, &e)); /* Activity-key exhaustion cannot starve alerts. */
    assert(f.core.alerts == 2 && f.core.source_events[0] == 2 &&
           f.core.source_events[1] == 131);
}

static void test_saturating_counts(void)
{
    fixture_t f; setup(&f);
    wifi_shield_event_t e = event(WIFI_SHIELD_EVENT_DEAUTH);
    f.core.source_events[0] = UINT32_MAX - 2;
    f.core.alerts = UINT32_MAX - 1;
    e.count = 3;
    assert(submit(&f, &e)); assert(!submit(&f, &e));
    assert(f.core.source_events[0] == UINT32_MAX && f.core.alerts == UINT32_MAX);
    e = event(WIFI_SHIELD_EVENT_WPS_RETRY_BURST);
    e.count = UINT32_MAX - 1;
    assert(submit(&f, &e));
    e.count = 10;
    assert(!submit(&f, &e));
    assert(f.core.source_events[1] == UINT32_MAX);
    assert(f.core.rate_limits[0].count == UINT32_MAX);
}

static void test_malformed_events_are_inert(void)
{
    fixture_t f; setup(&f);
    wifi_shield_core_t before = f.core;
    for (int change = 0; change < 14; ++change) {
        wifi_shield_event_t e = event(WIFI_SHIELD_EVENT_WPS_ACTIVITY);
        switch (change) {
        case 0: e.source = (wifi_shield_source_t)-1; break;
        case 1: e.source = (wifi_shield_source_t)5; break;
        case 2: e.type = (wifi_shield_event_type_t)-1; break;
        case 3: e.type = (wifi_shield_event_type_t)10; break;
        case 4: e.severity = (wifi_shield_severity_t)-1; break;
        case 5: e.severity = (wifi_shield_severity_t)3; break;
        case 6: e.wps_message = (wifi_shield_wps_message_t)-1; break;
        case 7: e.wps_message = (wifi_shield_wps_message_t)13; break;
        case 8: e.channel = 0; break;
        case 9: e.count = 0; break;
        case 10: e.station[0] = 5; break;
        case 11: memset(e.station, 0, 6); break;
        case 12: memcpy(e.station, e.bssid, 6); break;
        default: e.source = WIFI_SHIELD_SOURCE_TRUST; break;
        }
        assert(!submit(&f, &e));
        assert(memcmp(&before, &f.core, sizeof(before)) == 0);
    }
    assert(!submit(&f, NULL));
    wifi_shield_event_t e = event(WIFI_SHIELD_EVENT_DEAUTH);
    assert(!wifi_shield_core_publishable(NULL, &e));
    wifi_shield_core_init(&f.core, NULL);
    assert(!submit(&f, &e));
}

static void test_status_reset_and_compact_contract(void)
{
    fixture_t f; setup(&f);
    wifi_shield_event_t e = event(WIFI_SHIELD_EVENT_DEAUTH);
    assert(submit(&f, &e));
    f.core.running = true; f.core.stopping = true;
    f.core.active_defence = true; f.core.pmkid_decoy = true;
    f.core.multi_vector = true;
    f.core.protect_all = true;
    f.core.current_channel = 11;
    f.core.rx_drops = 3; f.core.event_drops = 4; f.core.output_failures = 5;
    wifi_shield_status_t s;
    memset(&s, 0xa5, sizeof(s));
    wifi_shield_core_status(&f.core, &s);
    assert(s.source_events[0] == 1 && s.source_events[1] == 0 && s.alerts == 1);
    assert(s.rx_drops == 3 && s.event_drops == 4 && s.output_failures == 5);
    assert(s.target_count == 2 && s.channel_count == 2);
    assert(s.channels[0] == 6 && s.channels[1] == 11 && s.channels[2] == 0);
    assert(s.current_channel == 11 && s.running && s.stopping &&
           s.active_defence && s.pmkid_decoy && s.multi_vector &&
           s.protect_all);
    wifi_shield_core_init(&f.core, &f.plan);
    wifi_shield_core_t want = {0}; want.plan = &f.plan;
    assert(memcmp(&want, &f.core, sizeof(want)) == 0);
    assert(submit(&f, &e));
    wifi_shield_core_status(NULL, &s);
    wifi_shield_status_t zero = {0};
    assert(memcmp(&s, &zero, sizeof(s)) == 0);
    wifi_shield_core_status(&f.core, NULL);
    wifi_shield_core_init(NULL, &f.plan);
    /* Public callback storage capacities are required ABI, not private details. */
    wifi_shield_compact_event_t lane[WIFI_SHIELD_COMPACT_EVENT_CAPACITY] = {0};
    wifi_shield_compact_event_t deauth[WIFI_SHIELD_DEAUTH_EVENT_CAPACITY] = {0};
    assert(sizeof(lane) / sizeof(lane[0]) == 24);
    assert(sizeof(deauth) / sizeof(deauth[0]) == 16);
    assert(sizeof(lane[0].bytes) == 64);
    lane[23].kind = WIFI_SHIELD_COMPACT_REASSOC;
    lane[23].generation = UINT32_MAX; lane[23].length = 64; lane[23].rx_us = -1;
    assert(lane[23].generation == UINT32_MAX && lane[23].length == 64 && lane[23].rx_us == -1);
}

static void test_internal_routing_counters_and_runtime_drops(void)
{
    fixture_t f; setup(&f);
    wifi_shield_core_record_input(&f.core, true, false);
    wifi_shield_core_record_input(&f.core, false, false);
    wifi_shield_core_record_input(&f.core, true, true);
    wifi_shield_core_add_rx_drops(&f.core, 3U);
    wifi_shield_core_add_rx_drops(&f.core, UINT32_MAX);
    wifi_shield_status_t status;
    wifi_shield_core_status(&f.core, &status);
    assert(status.received == 3U);
    assert(status.filtered == 1U);
    assert(status.wps_fragments == 1U);
    assert(status.rx_drops == UINT32_MAX);
    wifi_shield_core_record_input(NULL, true, true);
    wifi_shield_core_add_rx_drops(NULL, 1U);
}

int main(void)
{
    test_selection_and_plan_lifetime();
    test_severity_source_mapping_and_passive_tx();
    test_wps_activity_identity_and_exact_window();
    test_deauth_alert_is_published_once_per_window();
    test_retry_threshold_contributions_and_window();
    test_backwards_time_does_not_reopen_or_underflow();
    test_fixed_capacity_preserves_all_identities();
    test_saturating_counts();
    test_malformed_events_are_inert();
    test_status_reset_and_compact_contract();
    test_internal_routing_counters_and_runtime_drops();
    assert(tx_calls == 0 && heap_calls == 0);
    puts("wifi shield core: PASS (11 scenarios; TX=0; heap=0)");
    return 0;
}
