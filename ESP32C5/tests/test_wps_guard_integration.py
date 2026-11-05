"""Compile the real WPS Guard CLI/runtime adapter against deterministic hooks."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


class WpsGuardIntegrationTest(unittest.TestCase):
    def test_manuals_document_wps_guard_safety_and_interpretation_contract(self):
        command_manual = (ROOT / "docs/command-manual.md").read_text(
            encoding="utf-8")
        runtime_manual = (ROOT / "docs/wifi-security-runtime.md").read_text(
            encoding="utf-8")
        self.assertIn("### `wps_guard`", command_manual)
        self.assertIn("### WPS Guard module registration", runtime_manual)
        command_guard = command_manual.split("### `wps_guard`", 1)[1].split(
            "\n### ", 1)[0]
        runtime_guard = runtime_manual.split(
            "### WPS Guard module registration", 1)[1].split("\n## ", 1)[0]
        scoped = command_guard + "\n" + runtime_guard
        normalized = re.sub(r"\s+", " ", scoped)

        for command in (
                "wps_guard start",
                "wps_guard start --only <scan-index> [scan-index ...]",
                "wps_guard status",
                "wps_guard stop"):
            self.assertIn(f"`{command}`", command_guard)
        self.assertIn(
            "Passive WPS fragment forensics: start [--only indexes...] | status | stop",
            command_guard)

        expected_reasons = {
                "first_missing_length",
                "declared_not_larger_than_first",
                "declared_over_limit",
                "repeated_length_field",
                "opcode_changed",
                "eap_id_conflict",
                "observed_exceeds_declared",
                "final_length_mismatch",
                "empty_more_fragment",
                "session_timeout",
                "session_capacity",
                "frame_truncated",
                "invalid_envelope"}
        wire = (ROOT / "main/wps_guard_wire.c").read_text(encoding="utf-8")
        production_reasons = set(re.findall(
            r'\{"([a-z_]+)",\s*WPS_GUARD_SEVERITY_(?:ALERT|WARN)\}', wire))
        self.assertEqual(production_reasons, expected_reasons,
                         "documentation test must track the production token map")
        for reason in production_reasons:
            self.assertIn(f"`{reason}`", command_guard)

        core_header = (ROOT / "main/wps_guard_core.h").read_text(encoding="utf-8")
        for macro, value in (("WPS_GUARD_MAX_SESSIONS", "8"),
                             ("WPS_GUARD_MAX_DECLARED", "4096"),
                             ("WPS_GUARD_TIMEOUT_MS", "5000")):
            match = re.search(rf"#define\s+{macro}\s+(\d+)U", core_header)
            self.assertIsNotNone(match, macro)
            self.assertEqual(match.group(1), value)

        for exact_contract in (
                "at most eight live flows",
                "4096-byte declared WSC length",
                "5000 ms inactivity timeout",
                "strictly greater than 5000 ms",
                "5000001 us",
                "not at 5000000 us",
                "one completed scan",
                "one-based scan indexes",
                "Identical retransmissions are counted as telemetry, not anomalies.",
                "does not prove WPSplinter",
                "does not prove that a device is exploitable",
                "Disabled WPS advertisement does not prove that legacy WPS code is unreachable."):
            self.assertIn(exact_contract, normalized)

        for passive_non_goal in (
                "Fragment ACK", "EAP response", "enrollment", "PIN verification",
                "association", "raw TX"):
            self.assertIn(passive_non_goal, normalized)
        for private_item in (
                "payload bytes", "WSC attributes", "nonces", "keys", "PINs",
                "credentials", "authentication tags"):
            self.assertIn(private_item, normalized)

        self.assertIn("evidence-only", normalized)
        self.assertIn("does not attribute", normalized)
        self.assertIn("failed cleanup keeps the radio owner quarantined", normalized)
        self.assertIn("A later `wps_guard stop` or global `stop` retries cleanup",
                      normalized)
        self.assertIn("no terminal success is emitted while cleanup is uncertain",
                      normalized)
        self.assertIn("WIFI_SECURITY_MODULE_WPS_GUARD", runtime_guard)

        for copy_boundary in (
                "temporarily copies MAC-frame payload bytes",
                "borrowed and read only by the worker consumer",
                "hashed immediately into metadata",
                "does not decode WSC attributes",
                "never retained in WPS Guard flow/session state or telemetry"):
            self.assertIn(copy_boundary, normalized)

        for outcome in ("stopped", "busy", "invalid", "timeout",
                        "queue_overflow", "restore_failed", "output_failed"):
            self.assertIn(f"`{outcome}`", command_guard)
        for loss_contract in (
                "`RX_DROPS` is the saturated sum of shared-runtime `dropped_pool` and `dropped_queue`",
                "`CAPACITY_DROPS` remains the distinct WPS flow-table capacity counter",
                "successful cleanup reports `queue_overflow`"):
            self.assertIn(loss_contract, normalized)
        for channel_contract in (
                "currently received/tuned channel",
                "one effective selected channel remains pinned",
                "multiple unique selected channels are sampled in scan order",
                "250 ms per-channel dwell",
                "silence on a channel is not evidence of absence",
                "does not guarantee complete multi-channel coverage"):
            self.assertIn(channel_contract, normalized)
        wps_channel_scope = command_guard + "\n" + runtime_guard.split(
            "### SAE Guard module registration", 1)[0]
        self.assertNotIn("does not hop channels",
                         re.sub(r"\s+", " ", wps_channel_scope))
        self.assertIn("scan mutex, output gate and publisher-queue admission each wait at most 250 ms", normalized)
        self.assertIn("Lifecycle callers never wait for the UART driver", normalized)
        self.assertIn("dedicated publisher writes each complete record in one UART transaction", normalized)
        self.assertIn("new Start remains busy until prior-session publications resolve", normalized)
        self.assertIn("one terminal per cleanup attempt", normalized)
        self.assertIn("a later retry receives a new terminal", normalized)
        self.assertIn("persistent output-failure evidence", normalized)
        self.assertIn("the retry result remains `output_failed`", normalized)

    def test_cli_filter_worker_lifecycle_and_failure_rollback(self):
        with tempfile.TemporaryDirectory(prefix="janos-wps-guard-integration-") as directory:
            executable = Path(directory) / "wps_guard_integration_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                     "-pthread"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined",
                          "-fno-sanitize-recover=all",
                          "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/wps_guard_integration_test.c",
                       ROOT / "main/wps_guard.c",
                       ROOT / "main/wps_guard_core.c",
                       ROOT / "main/wps_guard_wire.c",
                       ROOT / "main/wifi_security_runtime.c",
                       ROOT / "main/wifi_security_frame.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"),
                                     "host C compiler required (native or WSL)")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(),
                             "PASS: WPS Guard CLI, filtering, lifecycle, rollback")

    def test_main_registers_exact_command_help_and_only_supplies_hooks(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        wps_adapter = source.split(
            "static portMUX_TYPE wps_guard_state_lock", 1)[1].split(
            "static portMUX_TYPE sae_guard_state_lock", 1)[0]
        self.assertNotIn("portMAX_DELAY", wps_adapter)
        self.assertNotIn("fwrite", wps_adapter)
        self.assertNotIn("uart_tx_chars", wps_adapter)
        match = re.search(
            r"const\s+esp_console_cmd_t\s+wps_guard_cmd\s*=\s*\{(.*?)\n\s*\};",
            source, flags=re.S)
        self.assertIsNotNone(match, "wps_guard command is not registered")
        body = match.group(1)
        self.assertIn('.command = "wps_guard"', body)
        self.assertIn(
            '.help = "Passive WPS fragment forensics: start [--only indexes...] | status | stop"',
            body)
        self.assertRegex(body, r"\.func\s*=\s*&?wps_guard_command")
        self.assertEqual(len(re.findall(r"wps_guard_command\s*\(", source)), 0,
                         "main.c must not contain or directly invoke an inline parser")
        self.assertEqual(len(re.findall(
            r"esp_console_cmd_register\s*\(\s*&wps_guard_cmd\s*\)", source)), 1)
        self.assertIn("wps_guard_init(&wps_guard_runtime_hooks, &wps_guard_output_hooks)",
                      source)
        runtime_hooks = re.search(
            r"static const wps_guard_runtime_hooks_t wps_guard_runtime_hooks\s*=\s*\{(.*?)\};",
            source, flags=re.S)
        self.assertIsNotNone(runtime_hooks)
        self.assertIn(".status_snapshot = wps_guard_runtime_status_snapshot",
                      runtime_hooks.group(1))
        output_hooks = re.search(
            r"static const wps_guard_output_hooks_t wps_guard_output_hooks\s*=\s*\{(.*?)\};",
            source, flags=re.S)
        self.assertIsNotNone(output_hooks)
        self.assertIn(".enter = wps_guard_output_enter", output_hooks.group(1))
        self.assertIn(".leave = wps_guard_output_leave", output_hooks.group(1))
        self.assertIn(".write_terminal = wps_guard_output_write_terminal",
                      output_hooks.group(1))
        self.assertIn(".complete = wps_guard_output_complete",
                      output_hooks.group(1))
        self.assertIn(".idle = wps_guard_output_idle", output_hooks.group(1))
        create_output_mutex = source.find(
            "xSemaphoreCreateMutexStatic(&wps_guard_output_mutex_storage)")
        initialize_guard = source.find(
            "wps_guard_init(&wps_guard_runtime_hooks, &wps_guard_output_hooks)")
        self.assertGreaterEqual(create_output_mutex, 0)
        self.assertGreater(initialize_guard, create_output_mutex,
                           "output serialization must exist before Guard init")
        self.assertNotRegex(
            source, r"assert\s*\(\s*xSemaphore(?:Take|Give)\s*\(",
            "FreeRTOS mutex side effects must execute when assertions are disabled")
        enter_body = re.search(
            r"static bool wps_guard_output_enter\([^)]*\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        leave_body = re.search(
            r"static void wps_guard_output_leave\([^)]*\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(enter_body)
        self.assertIsNotNone(leave_body)
        self.assertIn("xSemaphoreTake", enter_body.group(1))
        self.assertIn("pdMS_TO_TICKS(timeout_ms)", enter_body.group(1))
        self.assertNotIn("portMAX_DELAY", enter_body.group(1))
        self.assertIn("xSemaphoreGive", leave_body.group(1))
        snapshot_body = re.search(
            r"static bool wps_guard_scan_snapshot\(.*?\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(snapshot_body)
        self.assertIn("wifi_shield_target_t (**targets)",
                      snapshot_body.group(0))
        self.assertIn("pdMS_TO_TICKS(WPS_GUARD_SCAN_TIMEOUT_MS)",
                      snapshot_body.group(1))
        self.assertNotIn("portMAX_DELAY", snapshot_body.group(1))
        self.assertIn("heap_caps_calloc", snapshot_body.group(1))
        self.assertIn("MALLOC_CAP_SPIRAM", snapshot_body.group(1))
        self.assertIn("MALLOC_CAP_8BIT", snapshot_body.group(1))
        self.assertIn("wifi_shield_copy_target", snapshot_body.group(1))
        self.assertNotRegex(snapshot_body.group(1), r"(?<!heap_caps_)calloc\s*\(")
        self.assertNotRegex(snapshot_body.group(1), r"\bmalloc\s*\(")
        release_body = re.search(
            r"static void wps_guard_scan_release\(.*?\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(release_body)
        self.assertIn("wifi_shield_target_t *targets", release_body.group(0))
        self.assertIn("heap_caps_free", release_body.group(1))
        profile_start = re.search(
            r"static wifi_security_session_result_t wps_guard_runtime_start"
            r"\(.*?\)\s*\{(.*?)\n\}", source, flags=re.S)
        profile_stop = re.search(
            r"static bool wps_guard_runtime_stop\(.*?\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(profile_start)
        self.assertIsNotNone(profile_stop)
        self.assertIn("wifi_shield_start_wps_profile", profile_start.group(1))
        self.assertIn("wifi_shield_stop_wps_profile", profile_stop.group(1))
        write_body = re.search(
            r"static bool wps_guard_output_write\([^)]*\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(write_body)
        self.assertIn("xQueueSend", write_body.group(1))
        self.assertIn("pdMS_TO_TICKS(WPS_GUARD_OUTPUT_TIMEOUT_MS)",
                      write_body.group(1))
        self.assertNotIn("uart_tx_chars", write_body.group(1))
        self.assertNotIn("uart_write_bytes", write_body.group(1))
        self.assertNotIn("portMAX_DELAY", write_body.group(1))
        self.assertNotIn("fwrite", write_body.group(1))
        self.assertNotIn("atomic_fetch_sub_explicit", write_body.group(1),
                         "failed admission must retain pending until failure recording")
        terminal_write_body = re.search(
            r"static bool wps_guard_output_write_terminal\(.*?\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        complete_body = re.search(
            r"static void wps_guard_output_complete\([^)]*\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(terminal_write_body)
        self.assertIsNotNone(complete_body)
        self.assertNotIn("atomic_fetch_sub_explicit",
                         terminal_write_body.group(1))
        self.assertIn("atomic_fetch_sub_explicit", complete_body.group(1))
        guard_source = (ROOT / "main/wps_guard.c").read_text(encoding="utf-8")
        for function_name in ("publish", "publish_armed",
                              "publish_lifecycle_terminal"):
            function_body = re.search(
                rf"static .*?\b{function_name}\(.*?\)\s*\{{(.*?)\n\}}",
                guard_source, flags=re.S)
            self.assertIsNotNone(function_body, function_name)
            self.assertLess(function_body.group(1).find(
                "record_output_failure"), function_body.group(1).find(
                "output.complete"), function_name)
        publisher_body = re.search(
            r"static bool wps_guard_output_publish_record\([^)]*\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(publisher_body)
        self.assertIn("uart_write_bytes", publisher_body.group(1))
        self.assertEqual(publisher_body.group(1).count("uart_write_bytes"), 1)
        self.assertNotIn("uart_tx_chars", publisher_body.group(1))
        publisher_task = re.search(
            r"static void wps_guard_output_publisher\([^)]*\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(publisher_task)
        self.assertIn("wps_guard_format_terminal_for_output",
                      publisher_task.group(1))
        self.assertLess(publisher_task.group(1).find(
            "wps_guard_report_output_failure"), publisher_task.group(1).find(
            "atomic_fetch_sub_explicit"))
        create_output_queue = source.find(
            "wps_guard_output_queue = xQueueCreateStatic(")
        create_output_task = source.find("xTaskCreateStatic(wps_guard_output_publisher")
        self.assertGreaterEqual(create_output_queue, 0)
        self.assertGreater(create_output_task, create_output_queue)
        self.assertGreater(initialize_guard, create_output_task,
                           "publisher queue/task must exist before Guard init")
        stop = source.split("static int cmd_stop", 1)[1].split(
            'MY_LOG_INFO(TAG, "Stop command received', 1)[0]
        guard_stop = stop.find("wps_guard_stop(5000)")
        generic_stop = stop.find("wifi_security_runtime_stop(5000)")
        self.assertGreaterEqual(guard_stop, 0,
                                "global Stop must latch feature-local Start cancellation")
        self.assertGreater(generic_stop, guard_stop,
                           "feature Stop must precede the generic future-module cleanup")


if __name__ == "__main__":
    unittest.main()
