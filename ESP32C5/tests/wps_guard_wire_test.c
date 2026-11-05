#include "wps_guard_wire.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#define EVENT_BASE "[WPS_GUARD/1] BSSID=02:01:02:03:04:05 STA=04:06:07:08:09:0a DIR=ap_to_sta CH=6 RSSI=-51 OPCODE=4 FRAGMENTS=3 DECLARED=10 OBSERVED=11 RETRANSMITS=2 "
#define STATUS_FIELDS " RECEIVED=101 FILTERED=7 UNRELATED=8 FRAGMENTS=86 RETRANSMISSIONS=2 COMPLETIONS=3 ANOMALIES=4 TIMEOUTS=5 CAPACITY_DROPS=6 RX_DROPS=10 OUTPUT_FAILURES=9 ACTIVE=2 RUNNING=1 STOPPING=0 REASONS=0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15\r\n"
#define MAX_STATUS_FIELDS " RECEIVED=4294967295 FILTERED=4294967295 UNRELATED=4294967295 FRAGMENTS=4294967295 RETRANSMISSIONS=4294967295 COMPLETIONS=4294967295 ANOMALIES=4294967295 TIMEOUTS=4294967295 CAPACITY_DROPS=4294967295 RX_DROPS=4294967295 OUTPUT_FAILURES=4294967295 ACTIVE=8 RUNNING=1 STOPPING=1 REASONS=4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295,4294967295\r\n"

static const char marker[] = "WPS_GUARD_PRIVATE_PAYLOAD_0123456789_abcdefghijklmnopqrstuvwxyz_XYZ";

static void privacy(const char *line)
{
    static const char *const forbidden[] = {
        "PAYLOAD", "payload", "HASH", "hash", "EAP_ID=", "eap_id=",
        "ATTRIBUTE", "attribute", "NONCE", "nonce", "AUTH_TAG", "auth_tag",
        "PIN=", "pin=", "KEY=", "key=", "CREDENTIAL", "credential",
        "deadbeef", "DEADBEEF", "5750535f47554152445f50524956415445"
    };
    assert(strstr(line, marker) == NULL);
    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i)
        assert(strstr(line, forbidden[i]) == NULL);
    size_t n = strlen(line);
    assert(n >= 2 && line[n - 2] == '\r' && line[n - 1] == '\n');
    for (size_t i = 0; i + 2 < n; ++i) assert(line[i] != '\r' && line[i] != '\n');
}

static void exact(int result, const char *line, const char *want)
{
    if (result != (int)strlen(want) || strcmp(line, want) != 0)
        fprintf(stderr, "record mismatch result=%d want=%zu\nactual: %s\nexpect: %s\n", result, strlen(want), line, want);
    assert(result == (int)strlen(want));
    assert(strcmp(line, want) == 0);
    privacy(line);
}

static wps_guard_event_t event_fixture(void)
{
    wps_guard_event_t e = {0};
    const uint8_t ap[] = {2, 1, 2, 3, 4, 5}, sta[] = {4, 6, 7, 8, 9, 10};
    memcpy(e.fragment.bssid, ap, 6);
    memcpy(e.fragment.station, sta, 6);
    e.fragment.channel = 6;
    e.fragment.rssi = -51;
    e.fragment.opcode = 4;
    e.fragment.eap_id = 237;
    e.fragment.payload_hash = UINT32_C(0xdeadbeef);
    e.fragment.timestamp_us = UINT64_C(123456789);
    e.fragment_count = 3;
    e.declared_total = 10;
    e.observed_total = 11;
    e.retransmission_count = 2;
    return e;
}

static wps_guard_status_t status_fixture(void)
{
    wps_guard_status_t s = {0};
    s.received = 101; s.filtered = 7; s.unrelated = 8; s.fragments = 86;
    s.retransmissions = 2; s.completions = 3; s.anomalies = 4;
    s.timeouts = 5; s.capacity_drops = 6; s.rx_drops = 10; s.output_failures = 9;
    s.active_sessions = 2; s.running = true;
    for (size_t i = 0; i < WPS_GUARD_REASON_COUNT; ++i) s.reason_counts[i] = (uint32_t)i;
    return s;
}

static void test_exact_events_and_severities(void)
{
    /* These literals catch reordered fields, wrong mappings, or LF-only output. */
    static const struct { wps_guard_reason_t reason; const char *want; } cases[] = {
        {WPS_GUARD_FIRST_MISSING_LENGTH, EVENT_BASE "REASON=first_missing_length SEVERITY=alert TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_DECLARED_NOT_LARGER_THAN_FIRST, EVENT_BASE "REASON=declared_not_larger_than_first SEVERITY=alert TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_DECLARED_OVER_LIMIT, EVENT_BASE "REASON=declared_over_limit SEVERITY=alert TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_REPEATED_LENGTH_FIELD, EVENT_BASE "REASON=repeated_length_field SEVERITY=alert TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_OPCODE_CHANGED, EVENT_BASE "REASON=opcode_changed SEVERITY=alert TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_EAP_ID_CONFLICT, EVENT_BASE "REASON=eap_id_conflict SEVERITY=alert TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_OBSERVED_EXCEEDS_DECLARED, EVENT_BASE "REASON=observed_exceeds_declared SEVERITY=alert TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_FINAL_LENGTH_MISMATCH, EVENT_BASE "REASON=final_length_mismatch SEVERITY=alert TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_EMPTY_MORE_FRAGMENT, EVENT_BASE "REASON=empty_more_fragment SEVERITY=alert TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_SESSION_TIMEOUT, EVENT_BASE "REASON=session_timeout SEVERITY=warn TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_SESSION_CAPACITY, EVENT_BASE "REASON=session_capacity SEVERITY=warn TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_FRAME_TRUNCATED, EVENT_BASE "REASON=frame_truncated SEVERITY=alert TRUNCATED=0 TS_US=123456789\r\n"},
        {WPS_GUARD_INVALID_ENVELOPE, EVENT_BASE "REASON=invalid_envelope SEVERITY=warn TRUNCATED=0 TS_US=123456789\r\n"}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char out[WPS_GUARD_LINE_MAX];
        wps_guard_event_t e = event_fixture();
        e.reason = cases[i].reason;
        exact(wps_guard_format_event(out, sizeof(out), &e), out, cases[i].want);
    }
    wps_guard_event_t e = event_fixture();
    e.reason = WPS_GUARD_FRAME_TRUNCATED;
    e.fragment.direction = WPS_GUARD_DIR_STA_TO_AP;
    e.fragment.input_truncated = true;
    char out[WPS_GUARD_LINE_MAX];
    exact(wps_guard_format_event(out, sizeof(out), &e), out,
          "[WPS_GUARD/1] BSSID=02:01:02:03:04:05 STA=04:06:07:08:09:0a DIR=sta_to_ap CH=6 RSSI=-51 OPCODE=4 FRAGMENTS=3 DECLARED=10 OBSERVED=11 RETRANSMITS=2 REASON=frame_truncated SEVERITY=alert TRUNCATED=1 TS_US=123456789\r\n");
}

static void untouched(const char *bytes, size_t size)
{
    for (size_t i = 0; i < size; ++i) assert((unsigned char)bytes[i] == 0xa5);
}

static void test_suppressed_and_invalid_events(void)
{
    wps_guard_event_t e = event_fixture();
    char out[WPS_GUARD_LINE_MAX];
    const wps_guard_reason_t suppressed[] = {WPS_GUARD_NONE, WPS_GUARD_RETRANSMISSION, WPS_GUARD_COMPLETE};
    for (size_t i = 0; i < sizeof(suppressed) / sizeof(suppressed[0]); ++i) {
        memset(out, 0xa5, sizeof(out)); e.reason = suppressed[i];
        assert(wps_guard_format_event(out, sizeof(out), &e) == 0);
        untouched(out, sizeof(out));
    }
    const wps_guard_reason_t invalid[] = {(wps_guard_reason_t)-1, WPS_GUARD_REASON_COUNT, (wps_guard_reason_t)INT_MAX};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        memset(out, 0xa5, sizeof(out)); e.reason = invalid[i];
        assert(wps_guard_format_event(out, sizeof(out), &e) == -1);
        untouched(out, sizeof(out));
    }
    memset(out, 0xa5, sizeof(out)); e.reason = WPS_GUARD_INVALID_ENVELOPE;
    e.fragment.direction = (wps_guard_direction_t)2;
    assert(wps_guard_format_event(out, sizeof(out), &e) == -1);
    untouched(out, sizeof(out));
    assert(wps_guard_format_event(out, sizeof(out), NULL) == -1);
    assert(wps_guard_format_event(NULL, 10, &e) == -1);
    untouched(out, sizeof(out));
}

static void test_exact_status_and_terminal(void)
{
    wps_guard_status_t s = status_fixture();
    char out[WPS_GUARD_LINE_MAX];
    exact(wps_guard_format_status(out, sizeof(out), &s), out, "[WPS_GUARD/1] STATUS" STATUS_FIELDS);
    static const struct { const char *outcome, *want; } cases[] = {
        {"ok", "[WPS_GUARD/1] TERMINAL OUTCOME=ok" STATUS_FIELDS},
        {"stopped", "[WPS_GUARD/1] TERMINAL OUTCOME=stopped" STATUS_FIELDS},
        {"busy", "[WPS_GUARD/1] TERMINAL OUTCOME=busy" STATUS_FIELDS},
        {"invalid", "[WPS_GUARD/1] TERMINAL OUTCOME=invalid" STATUS_FIELDS},
        {"timeout", "[WPS_GUARD/1] TERMINAL OUTCOME=timeout" STATUS_FIELDS},
        {"queue_overflow", "[WPS_GUARD/1] TERMINAL OUTCOME=queue_overflow" STATUS_FIELDS},
        {"restore_failed", "[WPS_GUARD/1] TERMINAL OUTCOME=restore_failed" STATUS_FIELDS},
        {"output_failed", "[WPS_GUARD/1] TERMINAL OUTCOME=output_failed" STATUS_FIELDS}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i)
        exact(wps_guard_format_terminal(out, sizeof(out), &s, cases[i].outcome), out, cases[i].want);
    s = (wps_guard_status_t){0};
    exact(wps_guard_format_status(out, sizeof(out), &s), out,
          "[WPS_GUARD/1] STATUS RECEIVED=0 FILTERED=0 UNRELATED=0 FRAGMENTS=0 RETRANSMISSIONS=0 COMPLETIONS=0 ANOMALIES=0 TIMEOUTS=0 CAPACITY_DROPS=0 RX_DROPS=0 OUTPUT_FAILURES=0 ACTIVE=0 RUNNING=0 STOPPING=0 REASONS=0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0\r\n");
}

static void test_terminal_injection_and_invalid_arguments(void)
{
    wps_guard_status_t s = status_fixture();
    char out[WPS_GUARD_LINE_MAX];
    const char *const invalid[] = {NULL, "", "OK", "ok ", " ok", "ok\n", "ok\r\n[WPS_GUARD/1]", "ok\t", "ok\x01", "start_failed", "storage_failed", "stopping", "ok OUTCOME=stopped", marker};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        memset(out, 0xa5, sizeof(out));
        assert(wps_guard_format_terminal(out, sizeof(out), &s, invalid[i]) == -1);
        untouched(out, sizeof(out));
    }
    memset(out, 0xa5, sizeof(out));
    assert(wps_guard_format_status(out, sizeof(out), NULL) == -1);
    assert(wps_guard_format_status(NULL, sizeof(out), &s) == -1);
    assert(wps_guard_format_terminal(out, sizeof(out), NULL, "ok") == -1);
    assert(wps_guard_format_terminal(NULL, sizeof(out), &s, "ok") == -1);
    untouched(out, sizeof(out));
}

static void test_capacity_and_maximum_fields(void)
{
    wps_guard_event_t e = event_fixture();
    e.reason = WPS_GUARD_DECLARED_NOT_LARGER_THAN_FIRST;
    memset(e.fragment.bssid, 0xff, 6); memset(e.fragment.station, 0xff, 6);
    e.fragment.direction = WPS_GUARD_DIR_STA_TO_AP;
    e.fragment.channel = UINT8_MAX; e.fragment.rssi = INT8_MIN;
    e.fragment.opcode = UINT8_MAX; e.fragment.timestamp_us = UINT64_MAX;
    e.fragment_count = UINT32_MAX; e.declared_total = UINT16_MAX;
    e.observed_total = UINT32_MAX; e.retransmission_count = UINT32_MAX;
    e.fragment.input_truncated = true;
    wps_guard_status_t s = {0};
    s.received = s.filtered = s.unrelated = s.fragments = UINT32_MAX;
    s.retransmissions = s.completions = s.anomalies = UINT32_MAX;
    s.timeouts = s.capacity_drops = s.rx_drops = s.output_failures = UINT32_MAX;
    s.active_sessions = WPS_GUARD_MAX_SESSIONS; s.running = s.stopping = true;
    for (size_t i = 0; i < WPS_GUARD_REASON_COUNT; ++i) s.reason_counts[i] = UINT32_MAX;
    char out[WPS_GUARD_LINE_MAX + 16];
    int lengths[3];
    lengths[0] = wps_guard_format_event(out, 511, &e);
    assert(lengths[0] > 0 && lengths[0] < 511); privacy(out);
    assert(strcmp(out, "[WPS_GUARD/1] BSSID=ff:ff:ff:ff:ff:ff STA=ff:ff:ff:ff:ff:ff DIR=sta_to_ap CH=255 RSSI=-128 OPCODE=255 FRAGMENTS=4294967295 DECLARED=65535 OBSERVED=4294967295 RETRANSMITS=4294967295 REASON=declared_not_larger_than_first SEVERITY=alert TRUNCATED=1 TS_US=18446744073709551615\r\n") == 0);
    lengths[1] = wps_guard_format_status(out, 511, &s);
    exact(lengths[1], out, "[WPS_GUARD/1] STATUS" MAX_STATUS_FIELDS);
    assert(lengths[1] > 0 && lengths[1] < 511);
    lengths[2] = wps_guard_format_terminal(out, 511, &s, "restore_failed");
    exact(lengths[2], out, "[WPS_GUARD/1] TERMINAL OUTCOME=restore_failed" MAX_STATUS_FIELDS);
    assert(lengths[2] > 0 && lengths[2] < 511);
    for (size_t kind = 0; kind < 3; ++kind) {
        for (size_t cap = 0; cap <= (size_t)lengths[kind]; ++cap) {
            memset(out, 0xa5, sizeof(out));
            int n = kind == 0 ? wps_guard_format_event(out, cap, &e) :
                    kind == 1 ? wps_guard_format_status(out, cap, &s) :
                    wps_guard_format_terminal(out, cap, &s, "restore_failed");
            assert(n == -1); untouched(out, sizeof(out));
        }
        memset(out, 0xa5, sizeof(out));
        size_t cap = (size_t)lengths[kind] + 1;
        int n = kind == 0 ? wps_guard_format_event(out, cap, &e) :
                kind == 1 ? wps_guard_format_status(out, cap, &s) :
                wps_guard_format_terminal(out, cap, &s, "restore_failed");
        assert(n == lengths[kind]); privacy(out);
        untouched(out + cap, sizeof(out) - cap);
    }
}

int main(void)
{
    test_exact_events_and_severities();
    test_suppressed_and_invalid_events();
    test_exact_status_and_terminal();
    test_terminal_injection_and_invalid_arguments();
    test_capacity_and_maximum_fields();
    puts("PASS: WPS Guard exact wire records, severity, privacy, capacity");
    return 0;
}
