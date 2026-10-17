"""Execute the real diagnostic handler against driver errors and readback."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]

HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int esp_err_t;
typedef int wifi_mode_t;
typedef int wifi_second_chan_t;
enum { ESP_OK, DRIVER_ERROR, WIFI_MODE_NULL, WIFI_MODE_STA, WIFI_MODE_AP,
       WIFI_MODE_APSTA, WIFI_SECOND_CHAN_NONE = 0 };
#define pdMS_TO_TICKS(ms) (ms)
static int mode, primary, secondary, set_error, read_error, mode_error;
static int set_calls, init_calls;
static uint8_t requested_channels[256];
static int rejected_channel_one, rejected_channel_two;
static bool init_ok, wrong_readback;
static const char *busy;
static const char *analyzer_host_busy_reason(void) { return busy; }
static bool ensure_wifi_mode(void) { ++init_calls; return init_ok; }
static const char *esp_err_to_name(int error) {
    return error == ESP_OK ? "ESP_OK" : "DRIVER_ERROR";
}
static int esp_wifi_get_mode(int *out) { *out = mode; return mode_error; }
static int esp_wifi_set_channel(uint8_t requested, int second) {
    requested_channels[set_calls++] = requested;
    assert(second == WIFI_SECOND_CHAN_NONE);
    if (requested == rejected_channel_one || requested == rejected_channel_two)
        return DRIVER_ERROR;
    if (!set_error && !wrong_readback) { primary = requested; secondary = second; }
    return set_error;
}
static int esp_wifi_get_channel(uint8_t *out, int *second) {
    *out = primary; *second = secondary; return read_error;
}
static void vTaskDelay(int ticks) { assert(ticks == 20); }
FUNCTION
static int run(char *input) {
    char *argv[] = {"test_radio_channel", input, "extra"};
    return cmd_test_radio_channel(2, argv);
}
int main(void) {
    init_ok = true; primary = 1; mode = WIFI_MODE_APSTA;
    char *invalid[] = {"", "abc", "6x", "6.0", "0", "-1", "256",
                       "9999999999999999999999999999999999999999999999999"};
    for (unsigned i = 0; i < sizeof(invalid)/sizeof(invalid[0]); ++i)
        assert(run(invalid[i]) != 0);
    char *argv[] = {"test_radio_channel", "6", "extra"};
    assert(cmd_test_radio_channel(1, argv) != 0);
    assert(cmd_test_radio_channel(3, argv) != 0);
    assert(init_calls == 0 && set_calls == 0);

    busy = "handshake";
    assert(run("52") != 0 && init_calls == 0 && set_calls == 0);
    busy = NULL; init_ok = false;
    assert(run("52") != 0 && set_calls == 0);
    init_ok = true; mode_error = DRIVER_ERROR;
    assert(run("52") != 0 && set_calls == 0);
    mode_error = 0;

    assert(run("52") == 0 && primary == 52 && mode == WIFI_MODE_APSTA);
    mode = WIFI_MODE_STA;
    assert(run("6") == 0 && primary == 6 && mode == WIFI_MODE_STA);
    mode = WIFI_MODE_AP;
    assert(run("149") == 0 && primary == 149 && mode == WIFI_MODE_AP);
    assert(run("255") == 0 && primary == 255);

    set_error = DRIVER_ERROR;
    assert(run("6") != 0 && primary == 255);
    set_error = 0; read_error = DRIVER_ERROR;
    assert(run("6") != 0);
    read_error = 0; wrong_readback = true;
    assert(run("52") != 0 && primary == 6);
    secondary = 1;
    assert(run("6") != 0);
    puts("PASS: channel diagnostic failure and readback cases");

    char *batch_argv[] = {"test_radio_channels", "unexpected"};
    int before = set_calls;
    assert(cmd_test_radio_channels(2, batch_argv) != 0 && set_calls == before);
    busy = "handshake";
    int initializations = init_calls;
    assert(cmd_test_radio_channels(1, batch_argv) != 0 && set_calls == before);
    assert(init_calls == initializations);
    busy = NULL; init_ok = false;
    assert(cmd_test_radio_channels(1, batch_argv) != 0 && set_calls == before);

    init_ok = true; wrong_readback = false; secondary = 0;
    mode = WIFI_MODE_APSTA;
    rejected_channel_one = 144; rejected_channel_two = 169;
    assert(cmd_test_radio_channels(1, batch_argv) != 0);
    static const uint8_t expected[] = {
        36,40,44,48,52,56,60,64,100,104,108,112,116,120,
        124,128,132,136,140,144,149,153,157,161,165,169,173,177
    };
    assert(set_calls - before == 28);
    assert(memcmp(requested_channels + before, expected, sizeof(expected)) == 0);
    assert(primary == 177 && mode == WIFI_MODE_APSTA);

    rejected_channel_one = 0; rejected_channel_two = 0;
    assert(cmd_test_radio_channels(1, batch_argv) == 0);
    set_error = DRIVER_ERROR;
    assert(cmd_test_radio_channels(1, batch_argv) != 0);
    puts("PASS: batch channel order, continuation and aggregate results");
    return 0;
}
'''


class RadioChannelCommandTest(unittest.TestCase):
    def test_single_and_batch_handlers(self):
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            self.skipTest("host C compiler required")
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        masked = re.sub(r'"(?:\\.|[^"\\])*"|/\*.*?\*/|//[^\n]*',
                        lambda match: " " * len(match.group()), source, flags=re.S)
        functions = []
        for name in ("cmd_test_radio_channel", "cmd_test_radio_channels"):
            match = re.search(r"static int " + name + r"\([^;{}]*\)\s*\{", masked)
            self.assertIsNotNone(match)
            depth, end = 1, match.end()
            while depth:
                depth += (masked[end] == "{") - (masked[end] == "}")
                end += 1
            functions.append(source[match.start():end])
        code = HARNESS.replace("FUNCTION", "\n".join(functions))
        with tempfile.TemporaryDirectory(prefix="radio-channel-") as directory:
            fixture = Path(directory) / "command.c"
            binary = Path(directory) / "command"
            fixture.write_text(code, encoding="utf-8")
            build = subprocess.run(
                [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", str(fixture), "-o", str(binary)],
                capture_output=True, text=True)
            self.assertEqual(build.returncode, 0, build.stdout + build.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True,
                                    timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("set=ESP_OK read=ESP_OK actual=52 secondary=0 result=PASS",
                          result.stdout)
            self.assertIn("set=DRIVER_ERROR", result.stdout)
            self.assertIn("read=DRIVER_ERROR", result.stdout)
            self.assertIn("[RADIO-SUMMARY] total=28 passed=26 failed=2 result=FAIL",
                          result.stdout)
            self.assertIn("[RADIO-FAIL] channels=144,169\n", result.stdout)
            self.assertIn("[RADIO-SUMMARY] total=28 passed=28 failed=0 result=PASS",
                          result.stdout)
            self.assertIn("[RADIO-FAIL] channels=none\n", result.stdout)
            self.assertIn("[RADIO-SUMMARY] total=28 passed=0 failed=28 result=FAIL",
                          result.stdout)
            self.assertIn("[RADIO-PASS] channels=none\n", result.stdout)


if __name__ == "__main__":
    unittest.main()
