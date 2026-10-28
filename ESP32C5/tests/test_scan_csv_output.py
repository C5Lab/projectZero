"""Execute JanOS's legacy scan printer against controlled AP records.

Run with ``python tests/test_scan_csv_output.py``. On Windows the test uses
WSL's C compiler; it never builds or changes the firmware.
"""

import csv
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def production_function(source: str, name: str) -> str:
    """Extract a complete C definition, retaining the production body."""
    masked = re.sub(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
        lambda match: " " * len(match.group()),
        source,
        flags=re.DOTALL,
    )
    definition = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", masked)
    if definition is None:
        raise AssertionError(f"production function missing: {name}")
    start = source.rfind("\n", 0, definition.start()) + 1
    depth = 1
    end = definition.end()
    while depth and end < len(masked):
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    if depth:
        raise AssertionError(f"production function unclosed: {name}")
    return source[start:end]


PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint8_t ssid[33];
    uint8_t bssid[6];
    int primary;
    int authmode;
    int rssi;
} wifi_ap_record_t;

static wifi_ap_record_t g_scan_results[3];
static int g_scan_count = 3;
static const char *TAG = "scan-test";
static bool vendor_enabled;

#define pdMS_TO_TICKS(ms) (ms)
#define MY_LOG_INFO(tag, ...) do { (void)(tag); printf(__VA_ARGS__); putchar('\n'); } while (0)
static void vTaskDelay(int ticks) { (void)ticks; }
static bool vendor_is_enabled(void) { return vendor_enabled; }
static const char *lookup_vendor_name(const uint8_t *bssid) {
    return bssid[0] == 0xE0 && bssid[1] == 0x06 && bssid[2] == 0x30
               ? "HUAWEI TECHNOLOGIES CO.,LTD" : NULL;
}
static const char *authmode_to_string(int authmode) {
    (void)authmode;
    return "WPA2";
}
'''


SETUP = r'''
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    const char *names[] = {"Before", "O'Brien", "After"};
    vendor_enabled = strcmp(argv[1], "vendor") == 0;
    if (strcmp(argv[1], "plain") != 0 &&
        strcmp(argv[1], "vendor") != 0 &&
        strcmp(argv[1], "ssid") != 0 &&
        strcmp(argv[1], "ssid_comma") != 0 &&
        strcmp(argv[1], "ssid32") != 0 &&
        strcmp(argv[1], "quotes32") != 0) return 2;
    for (int i = 0; i < g_scan_count; ++i) {
        wifi_ap_record_t *ap = &g_scan_results[i];
        if (i == 1 && strcmp(argv[1], "quotes32") == 0) {
            memset(ap->ssid, '"', 32);
            ap->ssid[32] = '\0';
        } else {
            const char *name = names[i];
            if (i == 1 && strcmp(argv[1], "ssid") == 0) name = "O'Brien, \"Lab\"";
            if (i == 1 && strcmp(argv[1], "ssid_comma") == 0) name = "O'Brien, Lab";
            if (i == 1 && strcmp(argv[1], "ssid32") == 0)
                name = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
            strcpy((char *)ap->ssid, name);
        }
        ap->bssid[0] = i == 1 ? 0xE0 : 0x00;
        ap->bssid[1] = i == 0 ? 0x10 : i == 1 ? 0x06 : 0x12;
        ap->bssid[2] = i == 0 ? 0x20 : i == 1 ? 0x30 : 0x24;
        ap->bssid[3] = 0x30;
        ap->bssid[4] = 0x40; ap->bssid[5] = (uint8_t)(0x50 + i);
        ap->primary = i == 0 ? 1 : i == 1 ? 6 : 11;
        ap->rssi = -41 - 11 * i;
    }
    print_scan_results();
    return 0;
}
'''


class ScanCsvOutputTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="janos-scan-csv-")
        directory = Path(cls.temporary.name)
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        functions = "\n\n".join(
            production_function(source, name)
            for name in ("escape_csv_field", "print_network_csv", "print_scan_results")
        )
        c_file = directory / "scan_csv_test.c"
        c_file.write_text(PRELUDE + functions + SETUP, encoding="utf-8")
        executable = directory / "scan_csv_test"
        if os.name == "nt":
            if not shutil.which("wsl"):
                raise unittest.SkipTest("WSL with a C compiler is required on Windows")
            cls.executable = subprocess.check_output(
                ["wsl", "--exec", "wslpath", "-a", str(executable)], text=True
            ).strip()
            c_path = subprocess.check_output(
                ["wsl", "--exec", "wslpath", "-a", str(c_file)], text=True
            ).strip()
            cls.command_prefix = ["wsl", "--exec"]
            compile_command = cls.command_prefix + [
                "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", c_path,
                "-o", cls.executable,
            ]
        else:
            compiler = shutil.which("cc") or shutil.which("gcc")
            if not compiler:
                raise unittest.SkipTest("A C compiler is required")
            cls.executable = str(executable)
            cls.command_prefix = []
            compile_command = [
                compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", str(c_file),
                "-o", cls.executable,
            ]
        subprocess.run(compile_command, check=True, capture_output=True, text=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def output(self, scenario: str) -> str:
        return subprocess.check_output(
            self.command_prefix + [self.executable, scenario], text=True
        )

    def parsed_rows(self, scenario: str) -> list[list[str]]:
        lines = self.output(scenario).splitlines()
        self.assertEqual(lines[-1], "Scan results printed.")
        try:
            rows = list(csv.reader(io.StringIO("\n".join(lines[:-1])), strict=True))
        except csv.Error as exc:
            self.fail(f"Invalid scan CSV for {scenario}: {exc}; rows={lines[:-1]!r}")
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(len(row) == 8 for row in rows), rows)
        return rows

    @staticmethod
    def expected_rows(middle_ssid: str, middle_vendor: str = "") -> list[list[str]]:
        return [
            ["1", "Before", "", "00:10:20:30:40:50", "1", "WPA2", "-41", "2.4GHz"],
            ["2", middle_ssid, middle_vendor, "E0:06:30:30:40:51", "6", "WPA2", "-52", "2.4GHz"],
            ["3", "After", "", "00:12:24:30:40:52", "11", "WPA2", "-63", "2.4GHz"],
        ]

    def test_apostrophe_and_neighbours_keep_exact_legacy_output(self) -> None:
        self.assertEqual(
            self.output("plain"),
            '"1","Before","","00:10:20:30:40:50","1","WPA2","-41","2.4GHz"\n'
            '"2","O\'Brien","","E0:06:30:30:40:51","6","WPA2","-52","2.4GHz"\n'
            '"3","After","","00:12:24:30:40:52","11","WPA2","-63","2.4GHz"\n'
            "Scan results printed.\n",
        )
        self.assertEqual(self.parsed_rows("plain"), self.expected_rows("O'Brien"))

    # Known printer defects: keep these assertions active without breaking CI
    # before the planned production fix. Remove the decorators with that fix.
    @unittest.expectedFailure
    def test_comma_in_oui_vendor_preserves_eight_fields_and_network_identity(self) -> None:
        self.assertEqual(
            self.parsed_rows("vendor"),
            self.expected_rows("O'Brien", "HUAWEI TECHNOLOGIES CO.,LTD"),
        )

    @unittest.expectedFailure
    def test_comma_and_quote_in_ssid_preserve_eight_fields_and_network_identity(self) -> None:
        self.assertEqual(
            self.parsed_rows("ssid"),
            self.expected_rows('O\'Brien, "Lab"'),
        )

    @unittest.expectedFailure
    def test_comma_without_quote_in_ssid_preserves_network_identity(self) -> None:
        self.assertEqual(
            self.parsed_rows("ssid_comma"),
            self.expected_rows("O'Brien, Lab"),
        )

    def test_plain_32_byte_ssid_is_complete(self) -> None:
        self.assertEqual(
            self.parsed_rows("ssid32"),
            self.expected_rows("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
        )

    @unittest.expectedFailure
    def test_32_quotes_in_ssid_are_escaped_without_truncation(self) -> None:
        self.assertEqual(
            self.parsed_rows("quotes32"),
            self.expected_rows('"' * 32),
        )


if __name__ == "__main__":
    unittest.main()
