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

#define SHIELD_OWNER JANOS_RADIO_OWNER_SHIELD

static void shield_policy_and_controls(void)
{
    static const struct { const char *command; const char *subcommand; } safe[] = {
        {"wifi_shield", "status"}, {"wifi_shield", "report"},
        {"wifi_shield", "log"}, {"wifi_shield", "stop"},
        {"stop", NULL}, {"help", NULL}, {"ping", NULL}, {"version", NULL},
        {"show_scan_results", NULL}, {"wifi_analyzer", "caps"},
        {"wifi_analyzer", "status"}, {"wps", "status"},
        {"secret", "status"}, {"sta_mac", "status"},
        {"wps_guard", "status"}, {"sae_guard", "status"},
        {"wifi_trust", "status"}, {"client_isolation_audit", "status"},
        {"router_audit", "status"}, {"router_audit", "db_status"},
    };
    static const struct { const char *command; const char *subcommand; } blocked[] = {
        {"wifi_shield", "start"}, {"wifi_shield", NULL},
        {"scan_networks", NULL}, {"channel_view", NULL},
        {"wifi_analyzer", "scan"}, {"wifi_analyzer", "clear"},
        {"wifi_analyzer", "stop"}, {"wps", "verify"}, {"wps", "pixie"},
        {"wps", "stop"}, {"jwps", "campaign"}, {"selftest", "transport"},
        {"wps_guard", "start"}, {"wps_guard", "stop"},
        {"sae_guard", "start"}, {"sae_guard", "stop"},
        {"wifi_trust", "baseline"}, {"wifi_trust", "stop"},
        {"client_isolation_audit", "start"}, {"router_audit", "scan_passive"},
        {"router_audit", "scan_standard"}, {"router_audit", "db_verify"},
        {"router_audit", "db_install"}, {"deauth_detector_v2", "defence"},
        {"start_portal", NULL}, {"sta_mac", "set"},
        {"test_radio_channel", "6"}, {"test_radio_channels", NULL},
        {"reboot", NULL}, {"unknown_command", NULL},
    };
    /* Exercise policy before acquisition so RED identifies the missing row. */
    for (size_t i = 0; i < sizeof(safe) / sizeof(safe[0]); ++i) {
        janos_console_admission_result_t result = janos_console_admission_decide(
            SHIELD_OWNER, safe[i].command, safe[i].subcommand, 1U, true);
        if (result != JANOS_CONSOLE_ADMIT)
            fprintf(stderr, "Shield safe command rejected: %s %s\n", safe[i].command,
                    safe[i].subcommand ? safe[i].subcommand : "");
        assert(result == JANOS_CONSOLE_ADMIT);
    }
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    janos_console_admission_token_t token = {0};
    assert(janos_console_admission_begin(&lease, "wifi_shield", "start",
                                         0U, false, &token) == JANOS_CONSOLE_ADMIT);
    assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
    assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
    assert(janos_console_admission_begin(&lease, "wifi_shield", "start",
                                         1U, false, &token) ==
           JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS);
    assert(janos_console_admission_begin(&lease, "wifi_shield", "start",
                                         0U, true, &token) ==
           JANOS_CONSOLE_BUSY_WIFI_ANALYZER);
    uint32_t generation = 0U;
    assert(janos_radio_lease_acquire(&lease, SHIELD_OWNER, &generation) ==
           JANOS_RADIO_LEASE_OK);
    assert(janos_radio_lease_mark_running(&lease, SHIELD_OWNER, generation));
    for (size_t i = 0; i < sizeof(safe) / sizeof(safe[0]); ++i) {
        assert(janos_console_admission_begin(&lease, safe[i].command,
                                             safe[i].subcommand, 1U, true,
                                             &token) == JANOS_CONSOLE_ADMIT);
        assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
        assert(janos_console_admission_end(&lease, token));
    }
    for (size_t i = 0; i < sizeof(blocked) / sizeof(blocked[0]); ++i) {
        janos_console_admission_result_t result = janos_console_admission_begin(
            &lease, blocked[i].command, blocked[i].subcommand, 0U, false, &token);
        if (result != JANOS_CONSOLE_BUSY_RADIO_LEASE)
            fprintf(stderr, "Shield mutation admitted: %s %s\n", blocked[i].command,
                    blocked[i].subcommand ? blocked[i].subcommand : "");
        assert(result == JANOS_CONSOLE_BUSY_RADIO_LEASE);
        char line[160];
        assert(janos_console_admission_format(line, sizeof(line), result));
        assert(strcmp(line,
            "[WFACTL1] {\"v\":1,\"type\":\"error\",\"command\":\"console\","
            "\"code\":\"busy\",\"reason\":\"radio_lease\"}") == 0);
    }
    /* Bare download is an explicit terminal request. It preserves the active
     * owner for cmd_download(), which must stop it before arming ROM boot. */
    assert(janos_console_admission_begin(&lease, "download", NULL, 0U, true,
                                         &token) == JANOS_CONSOLE_ADMIT);
    assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
    assert(janos_console_admission_begin(&lease, "download", NULL, 1U, true,
                                         &token) != JANOS_CONSOLE_ADMIT);
    assert(janos_console_admission_begin(&lease, "download", "extra", 0U,
                                         true, &token) != JANOS_CONSOLE_ADMIT);
    janos_radio_lease_snapshot_t snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == SHIELD_OWNER);
    assert(snapshot.state == JANOS_RADIO_LEASE_RUNNING);
    assert(snapshot.generation == generation);
    assert(!snapshot.cancel_requested && snapshot.callbacks_open);
    assert(janos_radio_lease_begin_cleanup(&lease, SHIELD_OWNER, generation));
    assert(janos_radio_lease_finish_cleanup(&lease, SHIELD_OWNER, generation, true));
}

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
        {JANOS_RADIO_OWNER_ANALYZER, "sta_mac", "status", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "sta_mac", "set", 0, true, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_ANALYZER, "show_scan_results", NULL, 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "wps", "verify", 0, true, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_ANALYZER, "jwps", "plan", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "selftest", "db", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "selftest", "fragment", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "selftest", "pixie", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "selftest", "transport", 0, true, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_ANALYZER, "jwps", "campaign", 0, true, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_ANALYZER, "wps", "stop", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "ping", NULL, 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "version", NULL, 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "wps", "status", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "wps", "stop", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "wps", "verify", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "wps", "pixie", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "jwps", "campaign", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "jwps", "plan", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "selftest", "db", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "secret", "status", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "sta_mac", "status", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "sta_mac", "set", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
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
        {JANOS_RADIO_OWNER_WPS, "ping", NULL, 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "version", NULL, 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "channel_view", NULL, 0, true, JANOS_CONSOLE_BUSY_WIFI_ANALYZER},
        {JANOS_RADIO_OWNER_NONE, "show_scan_results", NULL, 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "wps", "status", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "secret", "status", 0, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "sta_mac", "status", 1, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "sta_mac", "set", 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_NONE, "sta_mac", "set", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "wps", "verify", 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_LEGACY, "wps", "verify", 0, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_LEGACY, "sta_mac", "status", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_LEGACY, "sta_mac", "set", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_LEGACY, "wps", "stop", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_LEGACY, "wifi_analyzer", "stop", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_LEGACY, "start_portal", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_LEGACY, "ping", NULL, 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_LEGACY, "version", NULL, 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_DEFENCE, "stop", NULL, 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_DEFENCE, "help", NULL, 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_DEFENCE, "ping", NULL, 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_DEFENCE, "version", NULL, 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_DEFENCE, "show_scan_results", NULL, 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_DEFENCE, "wps", "status", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_DEFENCE, "wifi_analyzer", "status", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_DEFENCE, "reboot", NULL, 1, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_DEFENCE, "wps", "stop", 1, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_DEFENCE, "wifi_analyzer", "stop", 1, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_DEFENCE, "deauth_detector_v2", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_DEFENCE, "scan_networks", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_DEFENCE, "wifi_analyzer", "scan", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_DEFENCE, "wps", "verify", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_DEFENCE, "start_portal", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_DEFENCE, "sta_mac", "set", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_DEFENCE, "test_radio_channel", "6", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_NONE, "client_isolation_audit", "start", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "client_isolation_audit", "start", 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_NONE, "client_isolation_audit", "start", 0, true, JANOS_CONSOLE_BUSY_WIFI_ANALYZER},
        {JANOS_RADIO_OWNER_LEGACY, "client_isolation_audit", "start", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_ANALYZER, "client_isolation_audit", "start", 0, true, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_WPS, "client_isolation_audit", "start", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_DEFENCE, "client_isolation_audit", "start", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "client_isolation_audit", "start", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_NONE, "client_isolation_audit", "status", 1, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_LEGACY, "client_isolation_audit", "status", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "client_isolation_audit", "status", 1, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "client_isolation_audit", "status", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_DEFENCE, "client_isolation_audit", "status", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "client_isolation_audit", "status", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "client_isolation_audit", "stop", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "router_audit", "status", 1, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_ANALYZER, "router_audit", "status", 1, true, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_WPS, "router_audit", "db_status", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "router_audit", "status", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "router_audit", "scan_passive", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "router_audit", "scan_passive", 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_NONE, "router_audit", "scan_standard", 0, true, JANOS_CONSOLE_BUSY_WIFI_ANALYZER},
        {JANOS_RADIO_OWNER_LEGACY, "router_audit", "scan_passive", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_NONE, "router_audit", "db_verify", 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_NONE, "router_audit", "db_install", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_DEFENCE, "router_audit", "db_install", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
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

static void security_policy_matrix(void)
{
    static const admission_case_t cases[] = {
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wps_guard", "status", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "wps_guard", "start", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "wps_guard", "start", 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_NONE, "wps_guard", "start", 0, true, JANOS_CONSOLE_BUSY_WIFI_ANALYZER},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wps_guard", "stop", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wps_guard", "start", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wps_guard", "caps", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wps_guard", "clear", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wps_guard", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_NONE, "sae_guard", "start", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "sae_guard", "start", 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_NONE, "sae_guard", "start", 0, true, JANOS_CONSOLE_BUSY_WIFI_ANALYZER},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "sae_guard", "status", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "sae_guard", "stop", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "sae_guard", "start", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "sae_guard", "caps", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "sae_guard", "clear", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "sae_guard", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_NONE, "wifi_trust", "baseline", 0, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_NONE, "wifi_trust", "baseline", 1, false, JANOS_CONSOLE_BUSY_COMMAND_IN_PROGRESS},
        {JANOS_RADIO_OWNER_NONE, "wifi_trust", "baseline", 0, true, JANOS_CONSOLE_BUSY_WIFI_ANALYZER},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wifi_trust", "status", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wifi_trust", "stop", 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wifi_trust", "baseline", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wifi_trust", "caps", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wifi_trust", "clear", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wifi_trust", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "stop", NULL, 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "help", NULL, 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "ping", NULL, 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "version", NULL, 1, false, JANOS_CONSOLE_ADMIT},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "scan_networks", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wifi_analyzer", "scan", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wifi_analyzer", "status", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wifi_analyzer", "stop", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wps", "verify", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wps", "status", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "wps", "stop", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "deauth_detector_v2", "defence", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "start_portal", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "sta_mac", "set", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "test_radio_channel", "6", 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "test_radio_channels", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "reboot", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
        {JANOS_RADIO_OWNER_SECURITY_MONITOR, "show_scan_results", NULL, 0, false, JANOS_CONSOLE_BUSY_RADIO_LEASE},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const admission_case_t *c = &cases[i];
        janos_console_admission_result_t actual = janos_console_admission_decide(
            c->owner, c->command, c->subcommand, c->inflight, c->analyzer_busy);
        if (actual != c->expected) {
            fprintf(stderr, "security case %zu (%s %s owner=%d) failed: got %d want %d\n",
                    i, c->command, c->subcommand ? c->subcommand : "",
                    (int)c->owner, (int)actual, (int)c->expected);
            assert(actual == c->expected);
        }
    }
}

static void security_controls_preserve_long_lived_owner(void)
{
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    janos_console_admission_token_t token = {0};
    const char *families[] = {"wps_guard", "sae_guard", "wifi_trust"};
    for (size_t i = 0; i < 3; ++i) {
        const char *subcommand = strcmp(families[i], "wifi_trust") == 0 ?
            "baseline" : "start";
        assert(janos_console_admission_begin(&lease, families[i], subcommand,
                                             0, false, &token) == JANOS_CONSOLE_ADMIT);
        /* Each passive handler reserves its own long-lived lease. */
        assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
        assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_NONE);
    }
    uint32_t generation;
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_SECURITY_MONITOR,
                                     &generation) == JANOS_RADIO_LEASE_OK);
    assert(janos_radio_lease_mark_running(&lease, JANOS_RADIO_OWNER_SECURITY_MONITOR,
                                          generation));
    for (int quarantined = 0; quarantined <= 1; ++quarantined) {
        if (quarantined) {
            assert(janos_radio_lease_begin_cleanup(&lease, JANOS_RADIO_OWNER_SECURITY_MONITOR,
                                                     generation));
            assert(!janos_radio_lease_finish_cleanup(&lease, JANOS_RADIO_OWNER_SECURITY_MONITOR,
                                                       generation, false));
        }
        for (size_t i = 0; i < 3; ++i) {
            const char *subcommand = strcmp(families[i], "wifi_trust") == 0 ?
                "baseline" : "start";
            assert(janos_console_admission_begin(&lease, families[i], subcommand,
                                                 0, false, &token) == JANOS_CONSOLE_BUSY_RADIO_LEASE);
            const char *controls[] = {"status", "stop"};
            for (size_t j = 0; j < 2; ++j) {
                assert(janos_console_admission_begin(&lease, families[i], controls[j],
                                                     1, false, &token) == JANOS_CONSOLE_ADMIT);
                assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
                assert(janos_console_admission_end(&lease, token));
            }
        }
        const char *safe[] = {"stop", "help", "ping", "version"};
        for (size_t i = 0; i < 4; ++i) {
            assert(janos_console_admission_begin(&lease, safe[i], NULL,
                                                 1, false, &token) == JANOS_CONSOLE_ADMIT);
            assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
        }
        assert(janos_console_admission_begin(&lease, "reboot", NULL, 0, false, &token) ==
               (quarantined ? JANOS_CONSOLE_ADMIT : JANOS_CONSOLE_BUSY_RADIO_LEASE));
        assert(janos_console_admission_begin(&lease, "reboot", "now", 0, false, &token) ==
               JANOS_CONSOLE_BUSY_RADIO_LEASE);
        assert(janos_console_admission_begin(&lease, "reboot", NULL, 1, false, &token) ==
               JANOS_CONSOLE_BUSY_RADIO_LEASE);
        assert(janos_console_admission_begin(&lease, "reboot", NULL, 0, true, &token) ==
               JANOS_CONSOLE_BUSY_RADIO_LEASE);
        const char *blocked[] = {"scan_networks", "show_scan_results"};
        for (size_t i = 0; i < 2; ++i)
            assert(janos_console_admission_begin(&lease, blocked[i], NULL,
                                                 0, false, &token) == JANOS_CONSOLE_BUSY_RADIO_LEASE);
        assert(janos_console_admission_begin(&lease, "download", NULL,
                                             0, false, &token) == JANOS_CONSOLE_ADMIT);
        assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
        janos_radio_lease_snapshot_t snapshot = janos_radio_lease_snapshot(&lease);
        assert(snapshot.owner == JANOS_RADIO_OWNER_SECURITY_MONITOR);
        assert(snapshot.generation == generation);
        assert(snapshot.state == (quarantined ? JANOS_RADIO_LEASE_QUARANTINED :
                                                JANOS_RADIO_LEASE_RUNNING));
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

static void bare_download_preempts_active_owners_without_releasing_lease(void)
{
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    janos_console_admission_token_t token = {0};
    uint32_t generation = 0U;
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_WPS,
                                     &generation) == JANOS_RADIO_LEASE_OK);
    assert(janos_radio_lease_mark_running(&lease, JANOS_RADIO_OWNER_WPS,
                                          generation));
    assert(janos_console_admission_begin(&lease, "download", NULL, 0, false,
                                         &token) == JANOS_CONSOLE_ADMIT);
    assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
    assert(janos_radio_lease_begin_cleanup(&lease, JANOS_RADIO_OWNER_WPS,
                                            generation));
    assert(!janos_radio_lease_finish_cleanup(&lease, JANOS_RADIO_OWNER_WPS,
                                              generation, false));

    assert(janos_console_admission_begin(&lease, "download", NULL, 0, false,
                                         &token) == JANOS_CONSOLE_ADMIT);
    assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
    assert(janos_console_admission_end(&lease, token));
    janos_radio_lease_snapshot_t snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_WPS);
    assert(snapshot.state == JANOS_RADIO_LEASE_QUARANTINED);
    assert(snapshot.generation == generation);
    assert(janos_console_admission_begin(&lease, "download", NULL, 1, false,
                                         &token) == JANOS_CONSOLE_BUSY_RADIO_LEASE);
    assert(janos_console_admission_begin(&lease, "download", NULL, 0, true,
                                         &token) == JANOS_CONSOLE_ADMIT);
    assert(janos_console_admission_begin(&lease, "download", "extra", 0, false,
                                         &token) == JANOS_CONSOLE_BUSY_RADIO_LEASE);

    janos_radio_lease_t analyzer;
    janos_radio_lease_init(&analyzer);
    assert(janos_radio_lease_acquire(&analyzer, JANOS_RADIO_OWNER_ANALYZER,
                                     NULL) == JANOS_RADIO_LEASE_OK);
    assert(janos_console_admission_begin(&analyzer, "download", NULL, 0, true,
                                         &token) == JANOS_CONSOLE_ADMIT);
    janos_radio_lease_t legacy;
    janos_radio_lease_init(&legacy);
    assert(janos_radio_lease_acquire(&legacy, JANOS_RADIO_OWNER_LEGACY,
                                     NULL) == JANOS_RADIO_LEASE_OK);
    assert(janos_console_admission_begin(&legacy, "download", NULL, 0, false,
                                         &token) == JANOS_CONSOLE_ADMIT);
}

static void defence_command_reserves_its_own_long_lived_owner(void)
{
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    janos_console_admission_token_t token = {0};
    assert(janos_console_admission_begin(
        &lease, "deauth_detector_v2", "defence", 0U, false, &token) ==
        JANOS_CONSOLE_ADMIT);
    assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
    janos_radio_lease_snapshot_t snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_NONE);
    assert(snapshot.state == JANOS_RADIO_LEASE_IDLE);
    assert(janos_console_admission_end(&lease, token));

    assert(janos_console_admission_begin(
        &lease, "deauth_detector_v2", "--only", 0U, false, &token) ==
        JANOS_CONSOLE_ADMIT);
    assert(token.owner == JANOS_RADIO_OWNER_LEGACY && token.generation != 0U);
    assert(janos_console_admission_end(&lease, token));
}

static void client_isolation_holds_a_legacy_transaction(void)
{
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    janos_console_admission_token_t token = {0};
    assert(janos_console_admission_begin(
        &lease, "client_isolation_audit", "start", 0U, false, &token) ==
        JANOS_CONSOLE_ADMIT);
    assert(token.owner == JANOS_RADIO_OWNER_LEGACY);
    assert(token.generation != 0U);
    assert(janos_radio_lease_snapshot(&lease).owner ==
           JANOS_RADIO_OWNER_LEGACY);
    assert(janos_console_admission_begin(
        &lease, "client_isolation_audit", "status", 1U, false, &token) ==
        JANOS_CONSOLE_ADMIT);
    assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
    janos_console_admission_token_t owner = {
        .owner = JANOS_RADIO_OWNER_LEGACY,
        .generation = janos_radio_lease_snapshot(&lease).generation,
    };
    assert(janos_console_admission_end(&lease, owner));
}

static void only_quarantined_defence_can_reboot(void)
{
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    janos_console_admission_token_t token = {0};
    uint32_t generation = 0U;
    assert(janos_radio_lease_acquire(&lease, JANOS_RADIO_OWNER_DEFENCE,
                                     &generation) == JANOS_RADIO_LEASE_OK);
    assert(janos_radio_lease_mark_running(&lease, JANOS_RADIO_OWNER_DEFENCE,
                                          generation));
    assert(janos_console_admission_begin(&lease, "reboot", NULL, 0U, false,
                                         &token) ==
           JANOS_CONSOLE_BUSY_RADIO_LEASE);
    assert(janos_radio_lease_begin_cleanup(&lease, JANOS_RADIO_OWNER_DEFENCE,
                                           generation));
    assert(!janos_radio_lease_finish_cleanup(&lease,
                                              JANOS_RADIO_OWNER_DEFENCE,
                                              generation, false));
    assert(janos_console_admission_begin(&lease, "reboot", NULL, 0U, false,
                                         &token) == JANOS_CONSOLE_ADMIT);
    assert(token.owner == JANOS_RADIO_OWNER_NONE && token.generation == 0U);
    assert(janos_console_admission_begin(&lease, "reboot", "now", 0U, false,
                                         &token) ==
           JANOS_CONSOLE_BUSY_RADIO_LEASE);
    assert(janos_console_admission_begin(&lease, "reboot", NULL, 1U, false,
                                         &token) ==
           JANOS_CONSOLE_BUSY_RADIO_LEASE);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "shield-policy") == 0) {
        shield_policy_and_controls();
        puts("PASS: JanOS Shield admission policy and lifecycle");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "security-policy") == 0) {
        security_policy_matrix();
        puts("PASS: JanOS security admission policy");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "security-lifecycle") == 0) {
        security_controls_preserve_long_lived_owner();
        puts("PASS: JanOS security admission lifecycle");
        return 0;
    }
    policy_matrix();
    invalid_inputs_fail_closed();
    reasons_are_stable();
    busy_wire_is_byte_stable();
    stale_startup_tokens_cannot_release_or_cancel_new_owners();
    bare_download_preempts_active_owners_without_releasing_lease();
    defence_command_reserves_its_own_long_lived_owner();
    client_isolation_holds_a_legacy_transaction();
    only_quarantined_defence_can_reboot();
    puts("PASS: JanOS console admission policy");
    return 0;
}
