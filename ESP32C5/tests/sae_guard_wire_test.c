#include "sae_guard_wire.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define EVENT_BASE \
    "[SAE_GUARD/1] BSSID=02:01:02:03:04:05" \
    " STA=04:06:07:08:09:0a DIR=ap_to_sta CH=6 RSSI=-51" \
    " TRANSACTION=1 STATUS=0 GROUP=19 COMMITS=8 CONFIRMS=2" \
    " MALFORMED=3 WINDOW_MS=7000 "

#define STATUS_FIELDS \
    " RECEIVED=101 FILTERED=7 UNRELATED=8 OBSERVATIONS=86" \
    " COMMITS=9 CONFIRMS=10 RETRIES=11 MALFORMED=12" \
    " ANTI_CLOGGING=13 STATUS_FAILURES=14 CAPACITY_DROPS=15" \
    " PAIR_DROPS=16 MALFORMED_DROPS=17" \
    " RX_DROPS=18 OUTPUT_FAILURES=19 ACTIVE=5" \
    " RUNNING=1 STOPPING=0 REASONS=0,1,2,3,4,5,6\r\n"

#define MAX_STATUS_FIELDS \
    " RECEIVED=4294967295 FILTERED=4294967295 UNRELATED=4294967295" \
    " OBSERVATIONS=4294967295 COMMITS=4294967295 CONFIRMS=4294967295" \
    " RETRIES=4294967295 MALFORMED=4294967295 ANTI_CLOGGING=4294967295" \
    " STATUS_FAILURES=4294967295 CAPACITY_DROPS=4294967295" \
    " PAIR_DROPS=4294967295 MALFORMED_DROPS=4294967295" \
    " RX_DROPS=4294967295 OUTPUT_FAILURES=4294967295 ACTIVE=4294967295" \
    " RUNNING=1 STOPPING=1" \
    " REASONS=4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295\r\n"

static const char secret_marker[] =
    "SAE_GUARD_SECRET_scalar_element_token_password_identifier_payload_XYZ";

static void privacy(const char *line)
{
    static const char *const forbidden[] = {
        "scalar", "SCALAR", "element", "ELEMENT", "token", "TOKEN",
        "password", "PASSWORD", "identifier", "IDENTIFIER", "payload",
        "PAYLOAD", "attack_confirmed", "password_broken", "wpa3_broken",
        "attribution", "ATTRIBUTION", "deadbeef", "DEADBEEF"
    };
    assert(strstr(line, secret_marker) == NULL);
    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i)
        assert(strstr(line, forbidden[i]) == NULL);
    const size_t length = strlen(line);
    assert(length >= 2 && line[length - 2] == '\r' && line[length - 1] == '\n');
    for (size_t i = 0; i + 2 < length; ++i)
        assert(line[i] != '\r' && line[i] != '\n');
}

static void untouched(const char *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        assert((unsigned char)bytes[i] == 0xa5);
}

static void exact(int result, const char *line, const char *want)
{
    if (result != (int)strlen(want) || strcmp(line, want) != 0) {
        fprintf(stderr, "record mismatch result=%d want=%zu\nactual: %s\nexpect: %s\n",
                result, strlen(want), line, want);
    }
    assert(result == (int)strlen(want));
    assert(strcmp(line, want) == 0);
    privacy(line);
}

static sae_guard_event_t event_fixture(void)
{
    sae_guard_event_t event = {0};
    const uint8_t bssid[] = {2, 1, 2, 3, 4, 5};
    const uint8_t station[] = {4, 6, 7, 8, 9, 10};
    memcpy(event.observation.bssid, bssid, sizeof(bssid));
    memcpy(event.observation.station, station, sizeof(station));
    event.observation.from_ap = true;
    event.observation.channel = 6;
    event.observation.rssi = -51;
    event.observation.transaction = 1;
    event.observation.status = 0;
    event.observation.group = 19;
    event.observation.timestamp_us = UINT64_C(123456789);
    event.commits = 8;
    event.confirms = 2;
    event.malformed = 3;
    event.window_ms = 7000;
    return event;
}

static sae_guard_status_t status_fixture(void)
{
    sae_guard_status_t status = {0};
    status.received = 101;
    status.filtered = 7;
    status.unrelated = 8;
    status.observations = 86;
    status.commits = 9;
    status.confirms = 10;
    status.retries = 11;
    status.malformed = 12;
    status.anti_clogging = 13;
    status.status_failures = 14;
    status.capacity_drops = 15;
    status.pair_capacity_drops = 16;
    status.malformed_capacity_drops = 17;
    status.rx_drops = 18;
    status.output_failures = 19;
    status.active_pairs = 2;
    status.active_malformed_bssids = 3;
    status.running = true;
    for (size_t i = 0; i < SAE_GUARD_EVENT_REASON_COUNT; ++i)
        status.reason_counts[i] = (uint32_t)i;
    return status;
}

static void test_exact_single_reason_events(void)
{
    static const struct {
        sae_guard_event_reason_t reason;
        const char *suffix;
    } cases[] = {
        {SAE_GUARD_EVENT_MALFORMED,
         "REASON=malformed SEVERITY=alert INTERPRETATION=malformed_observation TS_US=123456789\r\n"},
        {SAE_GUARD_EVENT_UNCONFIRMED_COMMITS,
         "REASON=unconfirmed_commits SEVERITY=warn INTERPRETATION=potential_dos TS_US=123456789\r\n"},
        {SAE_GUARD_EVENT_GROUP_CHURN,
         "REASON=group_churn SEVERITY=warn INTERPRETATION=potential_dos TS_US=123456789\r\n"},
        {SAE_GUARD_EVENT_ANTI_CLOGGING,
         "REASON=anti_clogging SEVERITY=info INTERPRETATION=observation TS_US=123456789\r\n"},
        {SAE_GUARD_EVENT_STATUS_FAILURE,
         "REASON=status_failure SEVERITY=info INTERPRETATION=observation TS_US=123456789\r\n"},
        {SAE_GUARD_EVENT_CAPACITY,
         "REASON=capacity SEVERITY=warn INTERPRETATION=observation TS_US=123456789\r\n"}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        sae_guard_event_t event = event_fixture();
        event.reason = cases[i].reason;
        event.reason_mask = SAE_GUARD_EVENT_MASK(cases[i].reason);
        char out[SAE_GUARD_LINE_MAX];
        char want[SAE_GUARD_LINE_MAX];
        const int length = snprintf(want, sizeof(want), "%s%s", EVENT_BASE,
                                    cases[i].suffix);
        assert(length > 0 && (size_t)length < sizeof(want));
        exact(sae_guard_format_event(out, sizeof(out), &event), out, want);
    }
}

static void test_combined_reasons_are_complete_and_deterministic(void)
{
    sae_guard_event_t event = event_fixture();
    event.reason = SAE_GUARD_EVENT_UNCONFIRMED_COMMITS;
    event.reason_mask =
        SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_UNCONFIRMED_COMMITS) |
        SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_GROUP_CHURN);
    char out[SAE_GUARD_LINE_MAX];
    exact(sae_guard_format_event(out, sizeof(out), &event), out,
          EVENT_BASE
          "REASON=unconfirmed_commits+group_churn SEVERITY=warn"
          " INTERPRETATION=potential_dos TS_US=123456789\r\n");

    event.reason = SAE_GUARD_EVENT_MALFORMED;
    event.reason_mask = 0;
    for (size_t reason = SAE_GUARD_EVENT_MALFORMED;
         reason < SAE_GUARD_EVENT_REASON_COUNT; ++reason) {
        event.reason_mask |= SAE_GUARD_EVENT_MASK(reason);
    }
    exact(sae_guard_format_event(out, sizeof(out), &event), out,
          EVENT_BASE
          "REASON=malformed+unconfirmed_commits+group_churn+anti_clogging+status_failure+capacity"
          " SEVERITY=alert"
          " INTERPRETATION=malformed_observation+potential_dos+observation"
          " TS_US=123456789\r\n");
}

static void test_unknown_group_and_direction(void)
{
    sae_guard_event_t event = event_fixture();
    event.reason = SAE_GUARD_EVENT_CAPACITY;
    event.reason_mask = SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_CAPACITY);
    event.observation.from_ap = false;
    event.observation.group = 0;
    char out[SAE_GUARD_LINE_MAX];
    exact(sae_guard_format_event(out, sizeof(out), &event), out,
          "[SAE_GUARD/1] BSSID=02:01:02:03:04:05"
          " STA=04:06:07:08:09:0a DIR=sta_to_ap CH=6 RSSI=-51"
          " TRANSACTION=1 STATUS=0 GROUP=unknown COMMITS=8 CONFIRMS=2"
          " MALFORMED=3 WINDOW_MS=7000 REASON=capacity SEVERITY=warn"
          " INTERPRETATION=observation TS_US=123456789\r\n");
}

static void test_suppression_and_invalid_reason_contract(void)
{
    sae_guard_event_t event = event_fixture();
    char out[SAE_GUARD_LINE_MAX];
    memset(out, 0xa5, sizeof(out));
    event.reason = SAE_GUARD_EVENT_NONE;
    event.reason_mask = 0;
    assert(sae_guard_format_event(out, sizeof(out), &event) == 0);
    untouched(out, sizeof(out));

    static const struct {
        sae_guard_event_reason_t reason;
        uint32_t mask;
    } invalid[] = {
        {(sae_guard_event_reason_t)-1, SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_MALFORMED)},
        {SAE_GUARD_EVENT_REASON_COUNT, SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_MALFORMED)},
        {SAE_GUARD_EVENT_MALFORMED, 0},
        {SAE_GUARD_EVENT_MALFORMED, SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_NONE) |
                                    SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_MALFORMED)},
        {SAE_GUARD_EVENT_MALFORMED, UINT32_C(0x80000000) |
                                    SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_MALFORMED)},
        {SAE_GUARD_EVENT_GROUP_CHURN,
         SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_UNCONFIRMED_COMMITS) |
         SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_GROUP_CHURN)},
        {SAE_GUARD_EVENT_UNCONFIRMED_COMMITS,
         SAE_GUARD_EVENT_MASK(SAE_GUARD_EVENT_GROUP_CHURN)}
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        memset(out, 0xa5, sizeof(out));
        event.reason = invalid[i].reason;
        event.reason_mask = invalid[i].mask;
        assert(sae_guard_format_event(out, sizeof(out), &event) == -1);
        untouched(out, sizeof(out));
    }
    assert(sae_guard_format_event(NULL, sizeof(out), &event) == -1);
    assert(sae_guard_format_event(out, sizeof(out), NULL) == -1);
}

static void test_exact_status_and_terminal(void)
{
    sae_guard_status_t status = status_fixture();
    char out[SAE_GUARD_LINE_MAX];
    exact(sae_guard_format_status(out, sizeof(out), &status), out,
          "[SAE_GUARD/1] STATUS" STATUS_FIELDS);
    static const char *const outcomes[] = {
        "ok", "stopped", "busy", "invalid", "timeout", "queue_overflow",
        "restore_failed", "output_failed"
    };
    for (size_t i = 0; i < sizeof(outcomes) / sizeof(outcomes[0]); ++i) {
        char want[SAE_GUARD_LINE_MAX];
        const int length = snprintf(want, sizeof(want),
                                    "[SAE_GUARD/1] TERMINAL OUTCOME=%s%s",
                                    outcomes[i], STATUS_FIELDS);
        assert(length > 0 && (size_t)length < sizeof(want));
        exact(sae_guard_format_terminal(out, sizeof(out), &status, outcomes[i]),
              out, want);
    }
    status = (sae_guard_status_t){0};
    exact(sae_guard_format_status(out, sizeof(out), &status), out,
          "[SAE_GUARD/1] STATUS RECEIVED=0 FILTERED=0 UNRELATED=0"
          " OBSERVATIONS=0 COMMITS=0 CONFIRMS=0 RETRIES=0 MALFORMED=0"
          " ANTI_CLOGGING=0 STATUS_FAILURES=0 CAPACITY_DROPS=0"
          " PAIR_DROPS=0 MALFORMED_DROPS=0 RX_DROPS=0"
          " OUTPUT_FAILURES=0 ACTIVE=0 RUNNING=0 STOPPING=0"
          " REASONS=0,0,0,0,0,0,0\r\n");
}

static void test_terminal_injection_and_invalid_arguments(void)
{
    sae_guard_status_t status = status_fixture();
    char out[SAE_GUARD_LINE_MAX];
    const char *const invalid[] = {
        NULL, "", "OK", "ok ", " ok", "ok\n", "ok\r\n[SAE_GUARD/1]",
        "ok\t", "ok\x01", "start_failed", "storage_failed", "stopping",
        "ok OUTCOME=stopped", secret_marker
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        memset(out, 0xa5, sizeof(out));
        assert(sae_guard_format_terminal(out, sizeof(out), &status,
                                         invalid[i]) == -1);
        untouched(out, sizeof(out));
    }
    memset(out, 0xa5, sizeof(out));
    assert(sae_guard_format_status(out, sizeof(out), NULL) == -1);
    assert(sae_guard_format_status(NULL, sizeof(out), &status) == -1);
    assert(sae_guard_format_terminal(out, sizeof(out), NULL, "ok") == -1);
    assert(sae_guard_format_terminal(NULL, sizeof(out), &status, "ok") == -1);
    untouched(out, sizeof(out));
}

static void test_capacity_maximum_fields_and_adjacent_secret(void)
{
    struct {
        sae_guard_event_t event;
        char secret[sizeof(secret_marker)];
    } wrapped = {0};
    wrapped.event = event_fixture();
    memcpy(wrapped.secret, secret_marker, sizeof(secret_marker));
    sae_guard_event_t *event = &wrapped.event;
    memset(event->observation.bssid, 0xff, sizeof(event->observation.bssid));
    memset(event->observation.station, 0xff, sizeof(event->observation.station));
    event->observation.from_ap = false;
    event->observation.channel = UINT8_MAX;
    event->observation.rssi = INT8_MIN;
    event->observation.transaction = UINT16_MAX;
    event->observation.status = UINT16_MAX;
    event->observation.group = UINT16_MAX;
    event->observation.timestamp_us = UINT64_MAX;
    event->commits = event->confirms = event->malformed = event->window_ms = UINT32_MAX;
    event->reason = SAE_GUARD_EVENT_MALFORMED;
    event->reason_mask = 0;
    for (size_t reason = SAE_GUARD_EVENT_MALFORMED;
         reason < SAE_GUARD_EVENT_REASON_COUNT; ++reason) {
        event->reason_mask |= SAE_GUARD_EVENT_MASK(reason);
    }

    sae_guard_status_t status = {0};
    status.received = status.filtered = status.unrelated = UINT32_MAX;
    status.observations = status.commits = status.confirms = UINT32_MAX;
    status.retries = status.malformed = status.anti_clogging = UINT32_MAX;
    status.status_failures = status.capacity_drops = UINT32_MAX;
    status.pair_capacity_drops = status.malformed_capacity_drops = UINT32_MAX;
    status.rx_drops = status.output_failures = UINT32_MAX;
    status.active_pairs = status.active_malformed_bssids = UINT32_MAX;
    status.running = status.stopping = true;
    for (size_t i = 0; i < SAE_GUARD_EVENT_REASON_COUNT; ++i)
        status.reason_counts[i] = UINT32_MAX;

    char out[SAE_GUARD_LINE_MAX + 16];
    int lengths[3];
    lengths[0] = sae_guard_format_event(out, 511, event);
    assert(lengths[0] == 408);
    exact(lengths[0], out,
          "[SAE_GUARD/1] BSSID=ff:ff:ff:ff:ff:ff"
          " STA=ff:ff:ff:ff:ff:ff DIR=sta_to_ap CH=255 RSSI=-128"
          " TRANSACTION=65535 STATUS=65535 GROUP=65535 COMMITS=4294967295"
          " CONFIRMS=4294967295 MALFORMED=4294967295 WINDOW_MS=4294967295"
          " REASON=malformed+unconfirmed_commits+group_churn+anti_clogging+status_failure+capacity"
          " SEVERITY=alert"
          " INTERPRETATION=malformed_observation+potential_dos+observation"
          " TS_US=18446744073709551615\r\n");
    lengths[1] = sae_guard_format_status(out, 511, &status);
    exact(lengths[1], out, "[SAE_GUARD/1] STATUS" MAX_STATUS_FIELDS);
    assert(lengths[1] == 484);
    lengths[2] = sae_guard_format_terminal(out, 511, &status, "restore_failed");
    exact(lengths[2], out,
          "[SAE_GUARD/1] TERMINAL OUTCOME=restore_failed" MAX_STATUS_FIELDS);
    assert(lengths[2] == 509);

    for (size_t kind = 0; kind < 3; ++kind) {
        for (size_t capacity = 0; capacity <= (size_t)lengths[kind]; ++capacity) {
            memset(out, 0xa5, sizeof(out));
            const int result = kind == 0 ?
                sae_guard_format_event(out, capacity, event) :
                kind == 1 ? sae_guard_format_status(out, capacity, &status) :
                sae_guard_format_terminal(out, capacity, &status, "restore_failed");
            assert(result == -1);
            untouched(out, sizeof(out));
        }
        memset(out, 0xa5, sizeof(out));
        const size_t capacity = (size_t)lengths[kind] + 1;
        const int result = kind == 0 ?
            sae_guard_format_event(out, capacity, event) :
            kind == 1 ? sae_guard_format_status(out, capacity, &status) :
            sae_guard_format_terminal(out, capacity, &status, "restore_failed");
        assert(result == lengths[kind]);
        privacy(out);
        untouched(out + capacity, sizeof(out) - capacity);
    }
}

int main(void)
{
    test_exact_single_reason_events();
    test_combined_reasons_are_complete_and_deterministic();
    test_unknown_group_and_direction();
    test_suppression_and_invalid_reason_contract();
    test_exact_status_and_terminal();
    test_terminal_injection_and_invalid_arguments();
    test_capacity_maximum_fields_and_adjacent_secret();
    puts("PASS: SAE Guard exact wire records, combined reasons, privacy, capacity; max lengths event=408 status=484 terminal=509");
    return 0;
}
