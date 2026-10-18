"""The console's own startup reservation must not make OTA reject itself."""
from pathlib import Path
import os
import tempfile
import unittest

from wps_host.host_build import compile_and_run
from test_janos_console_transaction import production_function

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "components/janos_wps"


HARNESS = r'''
#define _GNU_SOURCE
#include "janos_console_admission.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
typedef int BaseType_t;
typedef struct { char tag[32]; bool use_tag, force_latest, use_dev, rf; } ota_check_args_t;
static janos_radio_lease_t janos_radio_lease;
static bool ota_check_in_progress;
static const char *ota_channel = "stable";
static unsigned tasks;
#define TAG "test"
#define JANOS_VERSION "test"
#define OTA_TASK_STACK_SIZE 1024
#define OTA_TASK_PRIORITY 1
#define pdPASS 1
#define MY_LOG_INFO(...) ((void)0)
static bool ota_boot_is_ready(void) { return true; }
static bool ota_is_connected(void) { return true; }
static bool ota_rf_layout_compatible(void) { return true; }
static bool ensure_wifi_mode(void) { return true; }
static bool ota_parse_version(const char *tag, int *a, int *b, int *c)
{ (void)tag; (void)a; (void)b; (void)c; return true; }
static void oled_display_update_full(const char *a, const char *b, const char *c, const char *d)
{ (void)a; (void)b; (void)c; (void)d; }
static void ota_check_task(void *arg) { (void)arg; }
static int xTaskCreate(void (*task)(void *), const char *name, unsigned stack,
                       void *arg, unsigned priority, void *out)
{
    (void)task; (void)name; (void)stack; (void)priority; (void)out;
    ++tasks; free(arg); return pdPASS;
}
FUNCTIONS
int main(void)
{
    janos_radio_lease_init(&janos_radio_lease);
    janos_console_admission_token_t token;
    assert(janos_console_admission_begin(&janos_radio_lease, "ota_check", NULL,
                                         0U, false, &token) == JANOS_CONSOLE_ADMIT);
    char *args[] = {"ota_check"};
    assert(cmd_ota_check(1, args) == 0);
    assert(tasks == 1U);
    ota_check_in_progress = false;
    assert(!ota_start_check(NULL, false)); /* Automatic path cannot borrow it. */
    assert(tasks == 1U);
    assert(janos_console_admission_end(&janos_radio_lease, token));
    assert(!ota_start_check_source(NULL, false, false, &token));
    assert(tasks == 1U); /* An expired proof must fail even when radio is idle. */
    assert(ota_start_check(NULL, false));
    assert(tasks == 2U);
    puts("PASS: OTA console startup reservation and automatic isolation");
}
'''


class JanosOtaAdmissionTest(unittest.TestCase):
    def test_console_reservation_does_not_block_its_own_ota_start(self):
        code = HARNESS.replace("FUNCTIONS", "\n".join(production_function(name) for name in
            ("ota_start_check_source", "ota_start_check", "cmd_ota_check")))
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "ota.c"
            fixture.write_text(code)
            flags = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if (
                os.environ.get("JANOS_TEST_SANITIZERS")) else []
            compile_and_run(self, "ota", [fixture,
                ROOT / "main/janos_console_admission.c", COMPONENT / "janos_radio_lease.c",
                COMPONENT / "janos_wps_command.c"],
                [ROOT / "main", COMPONENT / "include"], extra_flags=flags, expected=
                "PASS: OTA console startup reservation and automatic isolation")


if __name__ == "__main__":
    unittest.main()
