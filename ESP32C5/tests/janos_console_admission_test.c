/* SPDX-FileCopyrightText: 2026 JanOS contributors */
/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_console_admission.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    janos_radio_owner_t owner;
    const char *command;
    const char *subcommand;
    uint32_t inflight;
    bool analyzer_busy;
    janos_console_admission_result_t expected;
} admission_case_t;

static void policy_matrix(void)
{
    static const admission_case_t cases[] = {
        {JANOS_RADIO_OWNER_NONE, "wifi_analyzer", "scan", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "wifi_analyzer", "scan", 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_NONE, "test_radio_channel", "52", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "test_radio_channel", "52", 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_ANALYZER, "test_radio_channel", "52", 0, true, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_WPS, "test_radio_channel", "52", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_NONE, "test_radio_channel", "52", 0, true, JANOS_CONSOLE_BUSY_WIFI_ANALYZER},
        {JANOS_RADIO_OWNER_NONE, "test_radio_channels", NULL, 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "test_radio_channels", NULL, 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_ANALYZER, "test_radio_channels", NULL, 0, true, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_WPS, "test_radio_channels", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_NONE, "test_radio_channels", NULL, 0, true, JANOS_CONSOLE_BUSY_WIFI_ANALYZER},
        {JANOS_RADIO_OWNER_ANALYZER, "wifi_analyzer", "status", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "wifi_analyzer", "caps", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "wifi_analyzer", "stop", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "wifi_analyzer", "scan", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "wps", "status", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "secret", "status", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "show_scan_results", NULL, 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "wps", "verify", 0, true, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_ANALYZER, "jwps", "plan", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "selftest", "db", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "selftest", "fragment", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "selftest", "pixie", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "selftest", "transport", 0, true, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_ANALYZER, "jwps", "campaign", 0, true, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_ANALYZER, "wps", "stop", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "wps", "status", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "wps", "stop", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "wps", "verify", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "wps", "pixie", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "jwps", "campaign", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "jwps", "plan", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "selftest", "db", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "secret", "status", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "secret", "reveal", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "secret", "erase", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "wifi_analyzer", "caps", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "wifi_analyzer", "status", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "wifi_analyzer", "scan", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_WPS, "wifi_analyzer", "stop", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "show_scan_results", NULL, 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "stop", NULL, 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "reboot", NULL, 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "help", NULL, 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "channel_view", NULL, 0, true, JANOS_CONSOLE_BUSY_WIFI_ANALYZER},
        {JANOS_RADIO_OWNER_NONE, "show_scan_results", NULL, 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "wps", "status", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "secret", "status", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "wps", "verify", 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_LEGACY, "wps", "verify", 0, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_LEGACY, "wps", "stop", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_LEGACY, "wifi_analyzer", "stop", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_LEGACY, "start_portal", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        janos_console_admission_result_t actual = janos_console_admission_decide(
            cases[i].owner, cases[i].command, cases[i].subcommand,
            cases[i].inflight, cases[i].analyzer_busy);
        if (actual != cases[i].expected) {
            fprintf(stderr, "case %zu failed: got %d want %d\n", i,
                    (int)actual, (int)cases[i].expected);
            assert(actual == cases[i].expected);
        }
    }
}

static void invalid_inputs_fail_closed(void)
{
    assert(janos_console_admission_decide(JANOS_RADIO_OWNER_NONE, NULL, NULL,
                                          0, false) ==
           JANOS_CONSOLE_BUSY_RADIO_LEASE);
    assert(janos_console_admission_decide(JANOS_RADIO_OWNER_NONE, "", NULL,
                                          0, false) ==
           JANOS_CONSOLE_BUSY_RADIO_LEASE);
    assert(janos_console_admission_decide((janos_radio_owner_t)99, "status",
                                          NULL, 0, false) ==
           JANOS_CONSOLE_BUSY_RADIO_LEASE);
}

static void reasons_are_stable(void)
{
    assert(janos_console_admission_reason(JANOS_CONSOLE_ADMIT) == NULL);
    assert(strcmp(janos_console_admission_reason(
                      JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS),
                  "command_in_progress") == 0);
    assert(strcmp(janos_console_admission_reason(
                      JANOS_CONSOLE_BUSY_RADIO_LEASE),
                  "radio_lease") == 0);
    assert(strcmp(janos_console_admission_reason(
                      JANOS_CONSOLE_BUSY_WIFI_ANALYZER),
                  "wifi_analyzer") == 0);
    assert(strcmp(janos_console_admission_reason(
                      (janos_console_admission_result_t)99),
                  "radio_lease") == 0);
}

static void busy_wire_is_byte_stable(void)
{
    char line[160] = {0};
    assert(janos_console_admission_format(
        line, sizeof(line), JANOS_CONSOLE_BUSY_RADIO_LEASE));
    assert(strcmp(line,
        "[WFACTL1] {\"v\":1,\"type\":\"error\",\"command\":\"console\","
        "\"code\":\"busy\",\"reason\":\"radio_lease\"}") == 0);
    assert(janos_console_admission_format(
        line, sizeof(line), JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS));
    assert(strcmp(line,
        "[WFACTL1] {\"v\":1,\"type\":\"error\",\"command\":\"console\","
        "\"code\":\"busy\",\"reason\":\"command_in_progress\"}") == 0);
    assert(janos_console_admission_format(
        line, sizeof(line), JANOS_CONSOLE_BUSY_WIFI_ANALYZER));
    assert(strcmp(line,
        "[WFACTL1] {\"v\":1,\"type\":\"error\",\"command\":\"console\","
        "\"code\":\"busy\",\"reason\":\"wifi_analyzer\"}") == 0);
    assert(!janos_console_admission_format(
        line, sizeof(line), JANOS_CONSOLE_ADMIT));
    assert(!janos_console_admission_format(
        line, 8U, JANOS_CONSOLE_BUSY_WIFI_ANALYZER));
    assert(!janos_console_admission_format(
        NULL, sizeof(line), JANOS_CONSOLE_BUSY_WIFI_ANALYZER));
}

static void stale_startup_tokens_cannot_release_or_cancel_new_owners(void)
{
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    janos_console_admission_token_t old, current;
    assert(janos_console_admission_begin(&lease, "start_portal", NULL,
                                         0, false, &old) == JANOS_CONSOLE_ADMIT);
    assert(old.owner == JANOS_RADIO_OWNER_LEGACY && old.generation != 0U);
    assert(janos_console_admission_end(&lease, old));
    assert(janos_console_admission_begin(&lease, "test_radio_channels", NULL,
                                         0, false, &current) == JANOS_CONSOLE_ADMIT);
    assert(current.generation != old.generation);
    assert(!janos_console_admission_end(&lease, old));
    assert(!janos_radio_lease_request_cancel(&lease, old.owner, old.generation));
    janos_console_admission_token_t wrong_owner = current;
    wrong_owner.owner = JANOS_RADIO_OWNER_WPS;
    assert(!janos_console_admission_end(&lease, wrong_owner));
    assert(!janos_radio_lease_request_cancel(&lease, wrong_owner.owner,
                                             wrong_owner.generation));
    assert(!janos_radio_lease_cancel_requested(&lease, current.owner,
                                               current.generation));
    assert(janos_console_admission_end(&lease, current));

    assert(janos_console_admission_begin(&lease, "start_portal", NULL,
                                         0, false, &current) == JANOS_CONSOLE_ADMIT);
    assert(janos_radio_lease_mark_running(&lease, current.owner, current.generation));
    /* A startup token must never silently release an unexpected running owner. */
    assert(!janos_console_admission_end(&lease, current));
    assert(janos_radio_lease_snapshot(&lease).state == JANOS_RADIO_LEASE_RUNNING);
}

int main(void)
{
    policy_matrix();
    invalid_inputs_fail_closed();
    reasons_are_stable();
    busy_wire_is_byte_stable();
    stale_startup_tokens_cannot_release_or_cancel_new_owners();
    puts("PASS: JanOS console admission policy");
    return 0;
}
