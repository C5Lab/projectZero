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
        caps_body = function_body(ADAPTER, "wifi_analyzer_command_with_startup")
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
        command = tokens(function_body(ADAPTER, "wifi_analyzer_command_with_startup"))
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

    def test_every_wifi_init_applies_and_verifies_configured_country(self):
        country_source = function_body(MAIN, "wifi_apply_configured_country")
        country = tokens(country_source)
        self.assertIn("wifi_country_configured", country)
        self.assertIn("wifi_country_driver_apply_and_verify", country)
        self.assertIn('"wifi_country_driver.c"', CMAKE)

        wrapper = tokens(function_body(MAIN, "wifi_init_with_configured_country"))
        self.assertLess(wrapper.index("esp_wifi_init(config)"),
                        wrapper.index("wifi_apply_configured_country()"))
        self.assertIn("esp_wifi_deinit()", wrapper)
        self.assertEqual(len(re.findall(r"\besp_wifi_init\s*\(", tokens(MAIN))), 1)

        legacy = tokens(function_body(MAIN, "wifi_init_ap_sta"))
        analyzer = tokens(function_body(MAIN, "analyzer_host_prepare_wifi"))
        self.assertIn("wifi_init_with_configured_country(&cfg)", legacy)
        self.assertIn("wifi_init_with_configured_country(&init)", analyzer)

    def test_handshake_reasserts_configured_country_before_starting_worker(self):
        handshake_source = function_body(MAIN, "cmd_start_handshake")
        handshake = tokens(handshake_source)
        ready = handshake.index("ensure_wifi_mode()")
        country = handshake.index("wifi_apply_configured_country()")
        worker = handshake.index("xTaskCreate(")
        self.assertLess(ready, country)
        self.assertLess(country, worker)
        self.assertIn("Failed to enforce configured WiFi country", handshake_source)

    def test_ducb_handshake_uses_single_apsta_radio_path(self):
        command = tokens(function_body(MAIN, "cmd_start_handshake"))
        worker = tokens(function_body(MAIN, "handshake_attack_task_sniffer"))
        prepare = tokens(function_body(MAIN, "handshake_prepare_sniffer_channel"))
        target_prepare = tokens(function_body(MAIN, "handshake_prepare_target_radio"))
        deauth = tokens(function_body(MAIN, "hs_deauth_burst_tx"))
        deauth_send = tokens(function_body(MAIN, "hs_send_targeted_deauth"))
        callback = tokens(function_body(MAIN, "hs_sniffer_promiscuous_cb"))
        packet = tokens(function_body(MAIN, "hs_sniffer_process_packet"))
        cleanup = tokens(function_body(MAIN, "handshake_cleanup"))
        stop_source = function_body(MAIN, "cmd_stop")
        stop = tokens(stop_source)
        task = tokens(function_body(MAIN, "handshake_attack_task"))

        # Handshake capture uses one legacy-compatible radio contract for all
        # channels.  APSTA is established once before either selected-target
        # or scan-all work starts.
        country = command.index("wifi_apply_configured_country()")
        busy = command.index("handshake_attack_active || handshake_attack_task_handle != NULL")
        apsta = command.index("ensure_ap_mode()")
        worker_start = command.index("xTaskCreate(")
        self.assertLess(country, apsta)
        self.assertLess(busy, apsta)
        self.assertLess(apsta, worker_start)

        # Every D-UCB arm is prepared and verified before dwell/reward/TX.
        self.assertIn("handshake_prepare_sniffer_channel(channel)", worker)
        self.assertLess(worker.index("handshake_prepare_sniffer_channel(channel)"),
                        worker.index("vTaskDelay(pdMS_TO_TICKS(HS_DWELL_TIME_MS))"))
        self.assertIn("continue", worker.split(
            "if (!handshake_prepare_sniffer_channel(channel))", 1
        )[1].split("vTaskDelay(pdMS_TO_TICKS(HS_DWELL_TIME_MS))", 1)[0])
        compact_worker = re.sub(r"\s+", "", worker)
        self.assertIn("hs_send_targeted_deauth(target->client,target->bssid,target->channel)",
                      compact_worker)

        # D-UCB and explicit-target paths verify APSTA and channel readback;
        # neither performs per-channel STA/APSTA transitions.
        self.assertIn("WIFI_MODE_APSTA", prepare)
        self.assertIn("esp_wifi_get_mode", prepare)
        self.assertIn("esp_wifi_set_channel", prepare)
        self.assertIn("esp_wifi_get_channel", prepare)
        self.assertIn("esp_wifi_set_promiscuous_rx_cb(hs_sniffer_promiscuous_cb)", prepare)
        self.assertNotIn("WIFI_MODE_STA", prepare)
        self.assertNotIn("handshake_radio_path_for_channel", prepare)
        self.assertIn("WIFI_MODE_APSTA", target_prepare)
        self.assertNotIn("ensure_ap_mode()", target_prepare)
        self.assertNotIn("WIFI_MODE_STA", target_prepare)
        self.assertNotIn("handshake_radio_path_for_channel", target_prepare)

        # Both directions of targeted deauth retain the historical AP TX path.
        self.assertEqual(deauth.count("esp_wifi_80211_tx(WIFI_IF_AP"), 1)
        self.assertIn("ap_to_client ? context->station_mac : context->ap_bssid",
                      deauth)
        self.assertIn("ap_to_client ? context->ap_bssid : context->station_mac",
                      deauth)
        self.assertNotIn("WIFI_IF_STA", deauth)
        self.assertIn("esp_wifi_get_mode", deauth_send)
        self.assertIn("esp_wifi_get_channel", deauth_send)
        self.assertLess(deauth_send.index("esp_wifi_get_mode"),
                        deauth_send.index("hs_ducb_run_burst"))
        self.assertLess(deauth_send.index("esp_wifi_get_channel"),
                        deauth_send.index("hs_ducb_run_burst"))

        self.assertNotIn('"handshake_radio_policy.c"', CMAKE)

        # The Wi-Fi callback and worker serialize access to the AP/client
        # tables and capture serializers.  The callback never blocks the Wi-Fi
        # task when the worker owns the snapshot.
        self.assertIn("SemaphoreHandle_t sniffer_mutex = hs_sniffer_mutex", callback)
        self.assertIn("hs_sniffer_lock(sniffer_mutex, 0)", callback)
        self.assertIn("hs_sniffer_unlock(sniffer_mutex)", callback)
        self.assertIn("atomic_fetch_add_explicit(&hs_sniffer_callbacks_inflight", callback)
        self.assertIn("atomic_fetch_sub_explicit(&hs_sniffer_callbacks_inflight", callback)
        self.assertNotIn("check_handshake_file_exists", packet)
        self.assertIn("check_handshake_file_exists", worker)
        self.assertIn("hs_sniffer_lock(hs_sniffer_mutex, portMAX_DELAY)", worker)
        self.assertIn("hs_sniffer_unlock(hs_sniffer_mutex)", worker)
        first_worker_lock = worker.index("hs_sniffer_lock(hs_sniffer_mutex, portMAX_DELAY)")
        self.assertLess(first_worker_lock, worker.index("hs_dwell_new_clients = 0"))
        self.assertIn("hs_sniffer_lock(hs_sniffer_mutex, portMAX_DELAY)", cleanup)
        self.assertIn("hs_sniffer_unlock(hs_sniffer_mutex)", cleanup)

        # Stop disables promiscuous reception and waits only to a bounded
        # deadline. The worker remains sole owner of cleanup and self-delete.
        stop_trigger = stop.index("handshake_attack_active = false")
        promisc_off = stop.index("esp_wifi_set_promiscuous(false)", stop_trigger)
        self.assertLess(stop_trigger, promisc_off)
        self.assertIn("HS_STOP_WAIT_MS", stop[promisc_off:])
        self.assertIn("stop_pending", stop_source)
        self.assertNotIn("vTaskDelete(handshake_attack_task_handle)", stop)
        self.assertGreater(stop.index("handshake_quiesce_sniffer_callbacks",
                                      stop_trigger), promisc_off)
        self.assertNotIn("handshake_attack_task_handle = NULL", cleanup)
        self.assertLess(task.index("handshake_cleanup()"),
                        task.index("handshake_attack_task_handle = NULL"))
        self.assertNotIn("vTaskDelay(pdMS_TO_TICKS(2000))", worker)

    def test_handshake_tx_done_telemetry_is_filtered_and_fully_unwound(self):
        command = tokens(function_body(MAIN, "cmd_start_handshake"))
        callback = tokens(function_body(MAIN, "handshake_tx_done_callback"))
        start = tokens(function_body(MAIN, "handshake_tx_telemetry_start"))
        stop_telemetry = tokens(function_body(MAIN, "handshake_tx_telemetry_stop"))
        cleanup = tokens(function_body(MAIN, "handshake_cleanup"))
        stop_source = function_body(MAIN, "cmd_stop")
        stop = tokens(stop_source)

        self.assertIn("tx_info == NULL || tx_info->data == NULL", callback)
        self.assertIn("(tx_info->data[0] & 0xfcU) != 0xc0U", callback)
        self.assertIn("tx_info->tx_status == WIFI_SEND_SUCCESS", callback)
        self.assertIn("handshake_tx_telemetry_record", callback)
        self.assertNotRegex(callback, r"\b(?:printf|puts|MY_LOG_\w+|ESP_LOG\w+)\s*\(")

        self.assertIn("handshake_tx_telemetry_reset", start)
        self.assertIn("esp_wifi_register_80211_tx_cb(handshake_tx_done_callback)", start)
        self.assertIn("esp_wifi_register_80211_tx_cb(NULL)", stop_telemetry)
        self.assertIn("handshake_tx_telemetry_snapshot", stop_telemetry)
        self.assertIn("tx_done_success", stop_telemetry)
        self.assertIn("tx_done_fail", stop_telemetry)

        telemetry_start = command.index("handshake_tx_telemetry_start()")
        worker_start = command.index("xTaskCreate(")
        self.assertLess(telemetry_start, worker_start)
        failed_create = command.split("if (result != pdPASS)", 1)[1]
        self.assertIn("handshake_tx_telemetry_stop", failed_create)

        self.assertLess(cleanup.index("attack_handshake_stop()"),
                        cleanup.index("handshake_tx_telemetry_stop"))
        self.assertNotIn("vTaskDelete(handshake_attack_task_handle)", stop)
        self.assertIn("handshake_tx_telemetry_stop", stop)
        self.assertIn('"handshake_tx_telemetry.c"', CMAKE)

    def test_ducb_pcap_is_bounded_rotated_and_cleanup_is_mode_scoped(self):
        packet_source = function_body(MAIN, "hs_sniffer_process_packet")
        packet = tokens(packet_source)
        worker = tokens(function_body(MAIN, "handshake_attack_task_sniffer"))
        compact_worker = re.sub(r"\s+", "", worker)
        rotate = tokens(function_body(MAIN, "hs_pcap_rotate_if_pending"))
        record = tokens(function_body(MAIN, "hs_pcap_record_append_result"))
        cleanup = tokens(function_body(MAIN, "handshake_cleanup"))

        self.assertIn("HS_PCAP_INITIAL_CAPACITY", MAIN)
        self.assertIn("HS_PCAP_MAX_BYTES", MAIN)
        self.assertIn("(512U * 1024U)", MAIN)
        self.assertIn("pcap_serializer_init_bounded(HS_PCAP_INITIAL_CAPACITY,HS_PCAP_MAX_BYTES,true)",
                      compact_worker)

        # The callback records only status. Rotation, allocation and logging
        # remain worker responsibilities.
        self.assertIn("PCAP_SERIALIZER_APPEND_LIMIT", record)
        self.assertIn("PCAP_SERIALIZER_APPEND_ALLOC_FAILED", record)
        self.assertNotIn("MY_LOG", record)
        self.assertNotIn("printf", record)
        self.assertNotIn("sdcard", record.lower())
        self.assertIn("hs_pcap_rotate_if_pending()", worker)
        self.assertIn("!hs_pcap_rotation_pending", worker)
        self.assertIn("hs_capture_snapshot_create", worker)
        self.assertIn("hs_save_handshake_snapshot_to_sd", worker)
        self.assertIn("hs_capture_snapshot_release", worker)
        self.assertNotIn("handshake_attack_active = false", worker.split(
            "hs_pcap_rotate_if_pending()", 1)[1])

        # Capture flags and HCCAPX state can advance only when the same frame
        # was committed to the PCAP buffer.
        self.assertIn("pcap_serializer_append_frame_checked", packet)
        beacon_ok = packet.index("PCAP_SERIALIZER_APPEND_OK")
        self.assertLess(beacon_ok, packet.index("beacon_captured = true", beacon_ok))
        eapol_append = packet.rindex("pcap_serializer_append_frame_checked")
        self.assertLess(eapol_append, packet.index("captured_m1 = true", eapol_append))
        self.assertLess(eapol_append, packet.index("hccapx_serializer_add_frame", eapol_append))

        # Rotation invalidates every partial capture and starts both serializers
        # from a clean state. Selected/manual mode retains legacy ownership.
        for marker in ("beacon_captured = false", "captured_m1 = false",
                       "captured_m2 = false", "captured_m3 = false",
                       "captured_m4 = false", "complete = false"):
            self.assertIn(marker, rotate)
        self.assertIn("hccapx_serializer_init", rotate)
        self.assertIn("pcap_serializer_deinit()", cleanup)
        self.assertIn("!handshake_selected_mode", cleanup)

        stop_source = function_body(MAIN, "cmd_stop")
        stop = tokens(stop_source)
        self.assertNotIn("vTaskDelete(handshake_attack_task_handle)", stop)
        self.assertIn("stop_pending", stop_source)

    def test_wifi_country_cli_is_persistent_and_additive(self):
        registration = function_body(MAIN, "register_commands")
        self.assertIn('.command = "wifi_country"', registration)
        self.assertIn("cmd_wifi_country", registration)
        command = tokens(function_body(MAIN, "cmd_wifi_country"))
        self.assertIn("wifi_country_save", command)
        self.assertIn("applies_after_reboot", function_body(MAIN, "cmd_wifi_country"))
        self.assertIn('"wifi_country_policy.c"', CMAKE)

    def test_legacy_dispatch_releases_lock_while_inflight_blocks_analyzer(self):
        dispatch = tokens(function_body(MAIN, "janos_console_cmd_dispatch"))
        decision = dispatch.index("janos_console_admission_begin(")
        self.assertIn("janos_commands_inflight", dispatch[decision:])
        self.assertLess(dispatch.index("++janos_commands_inflight"),
                        dispatch.index("xSemaphoreGiveRecursive(janos_command_mutex)",
                                       dispatch.index("++janos_commands_inflight")))
        unlocked = dispatch.index("xSemaphoreGiveRecursive(janos_command_mutex)",
                                  dispatch.index("++janos_commands_inflight"))
        handler = dispatch.index("int result =")
        relocked = dispatch.index("xSemaphoreTakeRecursive(janos_command_mutex", handler)
        self.assertLess(unlocked, handler)
        self.assertLess(handler, relocked)
        self.assertLess(relocked, dispatch.index("--janos_commands_inflight"))

    def test_radio_contention_keeps_v1_busy_error_and_nonzero_result(self):
        dispatch = function_body(MAIN, "janos_console_cmd_dispatch")
        busy_branch = dispatch.split(
            "if (admission != JANOS_CONSOLE_ADMIT)", 1
        )[1].split("++janos_commands_inflight", 1)[0]
        self.assertIn("janos_console_admission_format(", busy_branch)
        self.assertIn("puts(response)", busy_branch)
        self.assertIn("return 1;", busy_branch)
        self.assertNotIn("return 0;", busy_branch)

    def test_dispatch_uses_portable_admission_before_handler_and_inflight(self):
        dispatch = function_body(MAIN, "janos_console_cmd_dispatch")
        self.assertIn("janos_console_admission_begin(", dispatch)
        self.assertIn("janos_console_admission_format(", dispatch)
        decision = dispatch.index("janos_console_admission_begin(")
        formatted = dispatch.index("janos_console_admission_format(", decision)
        refusal = dispatch.index("return 1;", formatted)
        inflight = dispatch.index("++janos_commands_inflight")
        handler = dispatch.index("int result =")
        self.assertLess(decision, formatted)
        self.assertLess(formatted, refusal)
        self.assertLess(refusal, inflight)
        self.assertLess(inflight, handler)
        self.assertIn("argc > 1 ? argv[1] : NULL", dispatch)
        self.assertIn("janos_commands_inflight", dispatch[decision:formatted])
        self.assertIn("wifi_analyzer_busy()", dispatch[decision:formatted])
        self.assertNotIn("lease_command_allowed", dispatch)

        cmake = (ROOT / "main" / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn('"janos_console_admission.c"', cmake)

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
