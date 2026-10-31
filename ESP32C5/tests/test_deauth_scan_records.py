"""Host test for the real scan-record publication helper in main.c.

Run with python3 -B -m unittest discover -s tests -p test_deauth_scan_records.py -v.
No ESP-IDF firmware build or radio operation occurs.
"""

from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def extract_function(source, name):
    masked = re.sub(
        r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
        lambda match: " " * len(match.group()),
        source,
        flags=re.S,
    )
    match = re.search(r"\b" + name + r"\s*\([^;{}]*\)\s*\{", masked)
    if not match:
        return None
    start = source.rfind("\n", 0, match.start()) + 1
    end, depth = match.end(), 1
    while depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return source[start:end]


class ScanRecordsPublicationTests(unittest.TestCase):
    def test_scan_records_are_published_only_after_success(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        function = extract_function(source, "detector_publish_scan_records")
        self.assertIsNotNone(function, "scan-record publication helper is missing")
        code = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#define MAX_AP_CNT 64
typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_STATE 5
#define pdTRUE 1
#define ESP_FAIL -1
#define ESP_ERR_INVALID_STATE 5
#define pdTRUE 1
typedef void *SemaphoreHandle_t;
typedef struct { uint8_t bssid[6]; uint8_t ssid[33]; uint8_t primary; } wifi_ap_record_t;
static wifi_ap_record_t g_scan_results[MAX_AP_CNT];
static uint16_t g_scan_count;
static bool g_scan_records_valid;
static SemaphoreHandle_t g_scan_results_mutex = (void *)1;
static bool locked;
static int takes, gives, fetches;
static esp_err_t fetch_error;
#define portMAX_DELAY 1000
static int xSemaphoreTake(SemaphoreHandle_t mutex, int timeout) {
    assert(mutex == g_scan_results_mutex && timeout == portMAX_DELAY);
    assert(!locked); locked = true; ++takes; return 1;
}
static int xSemaphoreGive(SemaphoreHandle_t mutex) {
    assert(mutex == g_scan_results_mutex && locked);
    locked = false; ++gives; return 1;
}
static esp_err_t esp_wifi_scan_get_ap_records(uint16_t *count, wifi_ap_record_t *results) {
    assert(locked && count == &g_scan_count && results == g_scan_results);
    assert(*count == MAX_AP_CNT);
    ++fetches;
    *count = 2; /* An API error must not publish this partial count. */
    return fetch_error;
}
'''
        code += function
        code += r'''
int main(void) {
    g_scan_count = 9; g_scan_records_valid = false;
    fetch_error = ESP_OK;
    assert(detector_publish_scan_records(0) == ESP_OK);
    assert(g_scan_records_valid && g_scan_count == 2);
    assert(fetches == 1 && takes == 1 && gives == 1 && !locked);

    g_scan_count = 9; g_scan_records_valid = true;
    fetch_error = 7;
    assert(detector_publish_scan_records(0) != ESP_OK);
    assert(!g_scan_records_valid && g_scan_count == 0);
    assert(fetches == 2 && takes == 2 && gives == 2 && !locked);

    g_scan_count = 9; g_scan_records_valid = true;
    detector_publish_scan_records(8);
    assert(!g_scan_records_valid && g_scan_count == 0);
    assert(fetches == 2 && takes == 3 && gives == 3 && !locked);
    puts("scan records: PASS");
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix="janos-scan-records-") as tmp:
            source_file = Path(tmp) / "scan_records.c"
            executable = Path(tmp) / "scan_records"
            source_file.write_text(code, encoding="utf-8")
            subprocess.run(
                ["gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", str(source_file), "-o", str(executable)],
                check=True,
            )
            self.assertEqual(
                subprocess.check_output([str(executable)], text=True),
                "scan records: PASS\n",
            )


if __name__ == "__main__":
    unittest.main()
