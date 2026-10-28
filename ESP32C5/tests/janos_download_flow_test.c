/* SPDX-License-Identifier: Apache-2.0 */
#include "janos_download_flow.h"
#include "janos_console_admission.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    char calls[32];
    size_t used;
    bool wait_ready;
    bool arm_ready;
    bool wipe_ready;
    int stop_result;
    uint32_t wait_timeout;
} fixture_t;

static void call(fixture_t *fixture, char letter)
{
    assert(fixture->used + 1U < sizeof(fixture->calls));
    fixture->calls[fixture->used++] = letter;
    fixture->calls[fixture->used] = '\0';
}

static bool wait_wps(void *context, uint32_t timeout_ms)
{
    fixture_t *fixture = context;
    fixture->wait_timeout = timeout_ms;
    call(fixture, 'W');
    return fixture->wait_ready;
}

static int stop_all(void *context)
{
    fixture_t *fixture = context;
    call(fixture, 'S');
    return fixture->stop_result;
}

static void stop_wifi(void *context) { call(context, 'F'); }
static void drain_uart(void *context) { call(context, 'D'); }

static bool arm_rom(void *context)
{
    fixture_t *fixture = context;
    call(fixture, 'A');
    return fixture->arm_ready;
}

static void restore_rom(void *context) { call(context, 'U'); }

static bool terminal_wipe(void *context)
{
    fixture_t *fixture = context;
    call(fixture, 'X');
    return fixture->wipe_ready;
}

static void reset_rom(void *context) { call(context, 'R'); }

static janos_download_flow_ops_t ops(fixture_t *fixture)
{
    janos_download_flow_ops_t result = {
        .context = fixture,
        .rom_supported = true,
        .wait_wps_quarantined = wait_wps,
        .stop_all = stop_all,
        .stop_wifi = stop_wifi,
        .drain_uart = drain_uart,
        .arm_rom = arm_rom,
        .restore_rom = restore_rom,
        .terminal_wipe = terminal_wipe,
        .reset_rom = reset_rom,
    };
    return result;
}

static janos_radio_lease_snapshot_t quarantine(janos_radio_lease_t *lease)
{
    janos_radio_lease_init(lease);
    uint32_t generation = 0U;
    assert(janos_radio_lease_acquire(lease, JANOS_RADIO_OWNER_WPS,
                                     &generation) == JANOS_RADIO_LEASE_OK);
    assert(janos_radio_lease_mark_running(lease, JANOS_RADIO_OWNER_WPS,
                                          generation));
    assert(janos_radio_lease_begin_cleanup(lease, JANOS_RADIO_OWNER_WPS,
                                            generation));
    assert(!janos_radio_lease_finish_cleanup(lease, JANOS_RADIO_OWNER_WPS,
                                              generation, false));
    return janos_radio_lease_snapshot(lease);
}

static void quarantine_download_runs_wipe_before_reset_and_retains_lease(void)
{
    janos_radio_lease_t lease;
    janos_radio_lease_snapshot_t before = quarantine(&lease);
    janos_console_admission_token_t token = {0};
    assert(janos_console_admission_begin(&lease, "download", NULL, 0, false,
                                         &token) == JANOS_CONSOLE_ADMIT);
    fixture_t fixture = {.wait_ready = true, .arm_ready = true,
                         .wipe_ready = true};
    janos_download_flow_ops_t hooks = ops(&fixture);
    assert(janos_download_flow_run(before, &hooks, 5000U) ==
           JANOS_DOWNLOAD_RESET_RETURNED);
    assert(strcmp(fixture.calls, "WDAXRU") == 0);
    assert(fixture.wait_timeout == 5000U);
    assert(janos_console_admission_end(&lease, token));
    janos_radio_lease_snapshot_t after = janos_radio_lease_snapshot(&lease);
    assert(after.owner == JANOS_RADIO_OWNER_WPS);
    assert(after.state == JANOS_RADIO_LEASE_QUARANTINED);
    assert(after.generation == before.generation);
}

static void quarantine_failures_never_reset(void)
{
    janos_radio_lease_t lease;
    janos_radio_lease_snapshot_t snapshot = quarantine(&lease);
    fixture_t fixture = {.arm_ready = true, .wipe_ready = true};
    janos_download_flow_ops_t hooks = ops(&fixture);
    hooks.terminal_wipe = NULL;
    assert(janos_download_flow_run(snapshot, &hooks, 40U) ==
           JANOS_DOWNLOAD_INVALID_HOOKS);
    assert(fixture.used == 0U);

    hooks = ops(&fixture);
    assert(janos_download_flow_run(snapshot, &hooks, 40U) ==
           JANOS_DOWNLOAD_WPS_NOT_QUIESCENT);
    assert(strcmp(fixture.calls, "W") == 0);

    fixture = (fixture_t){.wait_ready = true, .wipe_ready = true};
    hooks = ops(&fixture);
    assert(janos_download_flow_run(snapshot, &hooks, 40U) ==
           JANOS_DOWNLOAD_ARM_FAILED);
    assert(strcmp(fixture.calls, "WDA") == 0);

    fixture = (fixture_t){.wait_ready = true, .arm_ready = true};
    hooks = ops(&fixture);
    assert(janos_download_flow_run(snapshot, &hooks, 40U) ==
           JANOS_DOWNLOAD_WIPE_FAILED);
    assert(strcmp(fixture.calls, "WDAXU") == 0);
    assert(janos_radio_lease_snapshot(&lease).owner == JANOS_RADIO_OWNER_WPS);
}

static void normal_download_stops_before_reset_and_never_wipes(void)
{
    janos_radio_lease_t lease;
    janos_radio_lease_init(&lease);
    janos_console_admission_token_t token = {0};
    assert(janos_console_admission_begin(&lease, "download", NULL, 0, false,
                                         &token) == JANOS_CONSOLE_ADMIT);
    janos_radio_lease_snapshot_t snapshot = janos_radio_lease_snapshot(&lease);
    assert(snapshot.owner == JANOS_RADIO_OWNER_LEGACY);
    assert(snapshot.state == JANOS_RADIO_LEASE_PREPARING);
    fixture_t fixture = {.arm_ready = true, .wipe_ready = true};
    janos_download_flow_ops_t hooks = ops(&fixture);
    hooks.terminal_wipe = NULL;
    assert(janos_download_flow_run(snapshot, &hooks, 5000U) ==
           JANOS_DOWNLOAD_RESET_RETURNED);
    assert(strcmp(fixture.calls, "SFDARU") == 0);
    assert(janos_console_admission_end(&lease, token));

    janos_radio_lease_init(&lease);
    assert(janos_console_admission_begin(&lease, "download", NULL, 0, false,
                                         &token) == JANOS_CONSOLE_ADMIT);
    snapshot = janos_radio_lease_snapshot(&lease);
    fixture = (fixture_t){.stop_result = 1, .arm_ready = true,
                          .wipe_ready = true};
    hooks = ops(&fixture);
    assert(janos_download_flow_run(snapshot, &hooks, 5000U) ==
           JANOS_DOWNLOAD_STOP_FAILED);
    assert(strcmp(fixture.calls, "S") == 0);
    assert(janos_console_admission_end(&lease, token));
}

static void unsupported_or_unowned_download_fails_before_side_effects(void)
{
    fixture_t fixture = {.wait_ready = true, .arm_ready = true,
                         .wipe_ready = true};
    janos_download_flow_ops_t hooks = ops(&fixture);
    janos_radio_lease_snapshot_t snapshot = {
        .owner = JANOS_RADIO_OWNER_WPS,
        .state = JANOS_RADIO_LEASE_RUNNING,
        .generation = 2U,
    };
    assert(janos_download_flow_run(snapshot, &hooks, 5000U) ==
           JANOS_DOWNLOAD_REFUSED_OWNER);
    assert(fixture.used == 0U);
    snapshot.owner = JANOS_RADIO_OWNER_ANALYZER;
    assert(janos_download_flow_run(snapshot, &hooks, 5000U) ==
           JANOS_DOWNLOAD_REFUSED_OWNER);
    hooks.rom_supported = false;
    assert(janos_download_flow_run(snapshot, &hooks, 5000U) ==
           JANOS_DOWNLOAD_UNSUPPORTED);
    assert(fixture.used == 0U);
}

int main(void)
{
    quarantine_download_runs_wipe_before_reset_and_retains_lease();
    quarantine_failures_never_reset();
    normal_download_stops_before_reset_and_never_wipes();
    unsupported_or_unowned_download_fails_before_side_effects();
    puts("PASS: JanOS ROM download flow");
    return 0;
}
