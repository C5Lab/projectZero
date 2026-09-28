"""Offline source guards for JanOS analyzer integration.

These checks inspect C wiring and exercise the Python wire reader. They do not
compile firmware, run ESP-IDF callbacks, or prove radio behavior on a C5.
"""

import ast
import hashlib
import json
from pathlib import Path
import re
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from wifi_analyzer_contract import SnapshotReader

MAIN = (ROOT / "main/main.c").read_text(encoding="utf-8")
ADAPTER = (ROOT / "main/wifi_analyzer.c").read_text(encoding="utf-8")
CORE = (ROOT / "main/wifi_analyzer_core.c").read_text(encoding="utf-8")
HEADER = (ROOT / "main/wifi_analyzer_core.h").read_text(encoding="utf-8")
CMAKE = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")

# SHA-256 of the extracted function bodies in HEAD:main/main.c, with LF newlines.
# This freezes only the three legacy presentation paths promised unchanged.
LEGACY_BODY_SHA256 = {
    "print_network_csv": "fb84404ef727dee679cbcd7775440a552de765f2ef5729811973e70e73a399dd",
    "print_scan_results": "accb6ae470203be6a018fade70b3eef94b90b2277e564e51bddab752c8fc56cf",
    "cmd_show_scan_results": "535a7680dd0ef3c5c63d17ee9f5cd24a11f505d83df55d8079dbb31a5bd78d7c",
}

_C_NONCODE = re.compile(
    r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
    re.DOTALL,
)


def code_only(source):
    """Mask C comments and literals while retaining offsets and newlines."""
    return _C_NONCODE.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), source)


def function_body(source, name):
    masked = code_only(source)
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", masked, re.DOTALL)
    if match is None:
        raise AssertionError(f"function definition not found: {name}")
    opening = match.end() - 1
    depth = 0
    for pos in range(opening, len(masked)):
        if masked[pos] == "{":
            depth += 1
        elif masked[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1:pos]
    raise AssertionError(f"unclosed function: {name}")


def tokens(source):
    return code_only(source)


def wire(*records):
    return b"".join(b"[WFA1] " + json.dumps(record, separators=(",", ":")).encode() + b"\n"
                    for record in records)


class AnalyzerIntegrationSourceTest(unittest.TestCase):
    def test_160_geometry_requires_aligned_full_channel_center(self):
        body = function_body(CORE, "wfa_normalize_geometry")
        guard = body.split("center1 != 5250U", 1)
        self.assertEqual(len(guard), 2)
        self.assertIn("ap->width == WFA_WIDTH_160", guard[0])
        rejected = guard[1].split("span =", 1)[0]
        for text in ("center1 != 5570U", "center1 != 5815U", "unknown_geometry(ap)", "return;"):
            self.assertIn(text, rejected)

    def test_status_never_publishes_zero_scan_identity(self):
        status = function_body(ADAPTER, "show_status")
        self.assertIn('if (state == WFA_IDLE || scan == 0) strcpy(active, "null")', status)

    def test_legacy_presentation_bodies_match_head_fixture(self):
        for name, expected in LEGACY_BODY_SHA256.items():
            with self.subTest(name=name):
                digest = hashlib.sha256(function_body(MAIN, name).encode()).hexdigest()
                self.assertEqual(digest, expected)

    def test_analyzer_event_claim_precedes_legacy_record_write(self):
        scan_case = MAIN.split("case WIFI_EVENT_SCAN_DONE:", 1)[1].split(
            "case WIFI_EVENT_STA_DISCONNECTED:", 1)[0]
        body = tokens(scan_case)
        claim = body.index("if (wifi_analyzer_on_scan_done(e)) break;")
        legacy_write = body.index("esp_wifi_scan_get_ap_records(&g_scan_count, g_scan_results)")
        self.assertLess(claim, legacy_write)
        self.assertLess(claim, body.index("g_last_scan_status = e->status"))

    def test_event_callback_only_claims_and_records_completion(self):
        callback = tokens(function_body(ADAPTER, "wifi_analyzer_on_scan_done"))
        self.assertIn("owned && s_armed && !s_done && event", callback)
        self.assertIn("s_driver_status = event->status", callback)
        self.assertIn("s_done = true", callback)
        self.assertIn("return owned", callback)
        self.assertNotRegex(callback, r"\b(?:malloc|calloc|free|printf|fwrite|emit_line|"
                                      r"control_error|heap_caps_\w+|esp_wifi_\w+|xTask\w+)\s*\(")
        self.assertNotRegex(callback, r"\b(?:MY_LOG_\w+|ESP_LOG\w+)\s*\(")

    def test_bulk_buffers_require_psram_and_reserve(self):
        allocation = tokens(function_body(ADAPTER, "allocate_buffers"))
        self.assertIn("MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT", allocation)
        self.assertIn("WFA_PSRAM_CEILING", allocation)
        self.assertIn("WFA_PSRAM_RESERVE", allocation)
        self.assertRegex(allocation, r"heap_caps_calloc\(capacity,\s*sizeof\(\*working\),\s*caps\)")
        self.assertRegex(allocation, r"heap_caps_calloc\(capacity,\s*sizeof\(\*committed\),\s*caps\)")
        self.assertEqual(allocation.count("heap_caps_calloc("), 2)
        self.assertNotIn("MALLOC_CAP_INTERNAL", allocation)
        self.assertNotRegex(allocation, r"(?<!heap_caps_)\b(?:malloc|calloc|realloc)\s*\(")

    def test_analyzer_does_not_write_legacy_scan_or_selection_cache(self):
        adapter = tokens(ADAPTER)
        for legacy_symbol in ("g_scan_results", "g_scan_count", "g_selected_indices", "g_selected_count"):
            with self.subTest(symbol=legacy_symbol):
                self.assertNotRegex(adapter, r"\b" + legacy_symbol + r"\b")

    def test_command_is_registered_and_both_sources_are_linked(self):
        registration = function_body(MAIN, "register_commands")
        analyzer = re.search(r"const esp_console_cmd_t analyzer_cmd\s*=\s*\{(.*?)\};",
                             registration, re.DOTALL)
        self.assertIsNotNone(analyzer)
        self.assertRegex(analyzer.group(1), r'\.command\s*=\s*"wifi_analyzer"')
        self.assertRegex(analyzer.group(1), r'\.func\s*=\s*&wifi_analyzer_command')
        self.assertIn("esp_console_cmd_register(&analyzer_cmd)", registration)
        for source in ('"wifi_analyzer.c"', '"wifi_analyzer_core.c"'):
            self.assertIn(source, CMAKE)

    def test_capacity_contract_agrees_with_caps_and_python_reader(self):
        self.assertRegex(HEADER, r"#define WFA_DEFAULT_LIMIT 64U\b")
        self.assertRegex(HEADER, r"#define WFA_MAX_APS 128U\b")
        parser = tokens(function_body(CORE, "wfa_parse_scan_args"))
        self.assertIn("out->limit = WFA_DEFAULT_LIMIT", parser)
        self.assertIn("WFA_MAX_APS", parser)
        caps_body = function_body(ADAPTER, "wifi_analyzer_command")
        caps_decl = re.search(r"static const char caps\[\]\s*=\s*(.*?);", caps_body, re.DOTALL)
        self.assertIsNotNone(caps_decl)
        pieces = re.findall(r'"(?:\\.|[^"\\])*"', caps_decl.group(1))
        caps = json.loads("".join(ast.literal_eval(piece) for piece in pieces).split(" ", 1)[1])
        self.assertEqual((caps["default_records"], caps["max_records"], caps["max_line_bytes"]),
                         (64, 128, 1024))
        begin = {"v": 1, "type": "begin", "boot": "0123456789abcdef", "scan": 1,
                 "band": "both", "channels": [1], "profile": "quick", "started_ms": 0}
        end = {"v": 1, "type": "end", "boot": begin["boot"], "scan": 1,
               "status": "ok", "found": 0, "returned": 0,
               "truncated": False, "duration_ms": 1}
        for limit in (64, 128):
            reader = SnapshotReader()
            reader.feed(wire(dict(begin, limit=limit), end))
            self.assertEqual(reader.errors, [])
            self.assertEqual(reader.last_snapshot["limit"], limit)
        reader = SnapshotReader()
        reader.feed(wire(dict(begin, limit=129), end))
        self.assertTrue(reader.errors)
        self.assertIsNone(reader.last_snapshot)

    def test_worker_waits_for_creator_publication_before_scan_start(self):
        command = tokens(function_body(ADAPTER, "wifi_analyzer_command"))
        worker = tokens(function_body(ADAPTER, "analyzer_worker"))
        self.assertLess(command.index("xTaskCreate(analyzer_worker"),
                        command.index("s_worker = worker"))
        self.assertLess(command.index("s_worker = worker"), command.index("xTaskNotifyGive(worker)"))
        self.assertLess(worker.index("ulTaskNotifyTake(pdTRUE, portMAX_DELAY)"),
                        worker.index("wfa_format_begin("))
        self.assertLess(worker.index("wfa_format_begin("), worker.index("s_armed = true"))
        self.assertLess(worker.index("s_armed = true"), worker.index("esp_wifi_scan_start("))

    def test_global_stop_joins_analyzer_before_legacy_cleanup(self):
        stop = tokens(function_body(MAIN, "cmd_stop"))
        self.assertLess(stop.index("wifi_analyzer_stop(5000)"),
                        stop.index("operation_stop_requested = true"))
        self.assertLess(stop.index("wifi_analyzer_stop(5000)"), stop.index("packet_monitor_stop()"))
        join = tokens(function_body(ADAPTER, "wifi_analyzer_stop"))
        self.assertIn("while (wifi_analyzer_busy()", join)
        self.assertIn("return !wifi_analyzer_busy()", join)

    def test_legacy_callback_drain_counter_blocks_admission(self):
        start = tokens(function_body(MAIN, "start_background_scan"))
        scan_case = tokens(MAIN.split("case WIFI_EVENT_SCAN_DONE:", 1)[1].split(
            "case WIFI_EVENT_STA_DISCONNECTED:", 1)[0])
        busy = tokens(function_body(MAIN, "analyzer_host_busy_reason"))
        self.assertLess(start.index("++analyzer_legacy_scan_pending"),
                        start.index("esp_wifi_scan_start(&scan_cfg, false)"))
        self.assertLess(start.index("esp_wifi_scan_start(&scan_cfg, false)"),
                        start.index("analyzer_legacy_scan_finished()"))
        self.assertGreater(scan_case.index("analyzer_legacy_scan_finished()"),
                           scan_case.index("g_scan_teardown_in_progress = false"))
        self.assertIn("analyzer_legacy_scan_pending != 0", busy)
        self.assertIn('return "legacy_scan_draining"',
                      function_body(MAIN, "analyzer_host_busy_reason"))
        self.assertNotRegex(tokens(MAIN), r"\banalyzer_legacy_scan_pending\s*=")
        self.assertEqual(tokens(MAIN).count("analyzer_legacy_scan_finished()"), 2)

    def test_analyzer_wifi_preparation_returns_errors_and_cleans_up(self):
        prepare = tokens(function_body(MAIN, "analyzer_host_prepare_wifi"))
        self.assertNotIn("ESP_ERROR_CHECK", prepare)
        self.assertNotIn("wifi_init_ap_sta(", prepare)
        self.assertNotIn("esp_netif_create_default_wifi_sta(", prepare)
        self.assertLess(prepare.index("esp_netif_new(&netif_config)"),
                        prepare.index("if (netif == NULL) return ESP_ERR_NO_MEM"))
        self.assertIn("esp_netif_destroy_default_wifi(netif)", prepare)
        self.assertLess(prepare.index("err = esp_wifi_start()"),
                        prepare.index("current_radio_mode = RADIO_MODE_WIFI"))
        self.assertIn("esp_wifi_deinit() != ESP_OK", prepare)
        self.assertIn("analyzer_legacy_radio_uncertain = true", prepare)
        self.assertRegex(prepare, r"failed\s*:\s*\(void\)esp_wifi_stop\(\)")

    def test_legacy_dispatch_releases_lock_while_inflight_blocks_analyzer(self):
        dispatch = tokens(function_body(MAIN, "janos_console_cmd_dispatch"))
        self.assertIn("analyzer_command && janos_commands_inflight != 0", dispatch)
        self.assertLess(dispatch.index("++janos_commands_inflight"),
                        dispatch.index("xSemaphoreGiveRecursive(janos_command_mutex)",
                                       dispatch.index("++janos_commands_inflight")))
        unlocked = dispatch.index("xSemaphoreGiveRecursive(janos_command_mutex)",
                                  dispatch.index("++janos_commands_inflight"))
        handler = dispatch.index("int result = cmd_context->func")
        relocked = dispatch.index("xSemaphoreTakeRecursive(janos_command_mutex", handler)
        self.assertLess(unlocked, handler)
        self.assertLess(handler, relocked)
        self.assertLess(relocked, dispatch.index("--janos_commands_inflight"))
        self.assertIn('strcmp(cmd_context->command, "stop") != 0',
                      function_body(MAIN, "janos_console_cmd_dispatch"))

    def test_uncertain_legacy_radio_blocks_scan_after_forced_delete_or_connect_failure(self):
        stop = tokens(function_body(MAIN, "cmd_stop"))
        forced = stop.index("if (wardrive_task_handle != NULL) {")
        deleted = stop.index("vTaskDelete(wardrive_task_handle)", forced)
        self.assertIn("analyzer_legacy_radio_uncertain = true", stop[forced:deleted])
        connect = tokens(function_body(MAIN, "cmd_wifi_connect"))
        self.assertLess(connect.index("for (int i = 0; i < 150 && wifi_connect_result == 0"),
                        connect.index("if (wifi_connect_result != 1)"))
        failed = connect.index("if (wifi_connect_result != 1)")
        self.assertIn("analyzer_legacy_radio_uncertain = true", connect[failed:])
        busy = tokens(function_body(MAIN, "analyzer_host_busy_reason"))
        self.assertIn("bool uncertain = analyzer_legacy_radio_uncertain", busy)
        self.assertIn("if (uncertain) return", busy)

    def test_every_main_wifi_connect_uses_tracked_driver_wrapper(self):
        wrapper = tokens(function_body(MAIN, "analyzer_tracked_wifi_connect"))
        self.assertEqual(len(re.findall(r"\besp_wifi_connect\s*\(", tokens(MAIN))), 1)
        self.assertLess(wrapper.index("analyzer_sta_connect_pending = true"),
                        wrapper.index("esp_wifi_connect()"))
        self.assertIn("if (err != ESP_OK)", wrapper)
        self.assertIn("analyzer_sta_connect_pending = false", wrapper)
        self.assertGreater(len(re.findall(r"\banalyzer_tracked_wifi_connect\s*\(", tokens(MAIN))), 1)
        busy = tokens(function_body(MAIN, "analyzer_host_busy_reason"))
        self.assertIn("if (connecting) return", busy)


if __name__ == "__main__":
    unittest.main()
