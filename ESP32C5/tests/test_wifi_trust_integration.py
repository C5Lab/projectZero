"""Compile the real Wi-Fi Trust controller against shared-runtime hooks."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


class WifiTrustIntegrationTest(unittest.TestCase):
    def test_cli_runtime_storage_deadline_and_monitor(self):
        with tempfile.TemporaryDirectory(prefix="janos-wifi-trust-") as directory:
            executable = Path(directory) / "wifi_trust_integration_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                     "-pthread"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/wifi_trust_integration_test.c",
                       ROOT / "main/wifi_trust.c",
                       ROOT / "main/wifi_trust_core.c",
                       ROOT / "main/wifi_trust_store.c",
                       ROOT / "main/wifi_trust_wire.c",
                       ROOT / "main/sniffer_extended.c",
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
            self.assertEqual(
                result.stdout.strip(),
                "PASS: Wi-Fi Trust CLI, runtime, storage, deadline, monitor")

    def test_main_wires_static_control_output_storage_and_registration(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        self.assertIn('#include "wifi_trust.h"', source)
        self.assertIn('#include "wifi_trust_deadline.h"', source)
        match = __import__("re").search(
            r"const\s+esp_console_cmd_t\s+wifi_trust_cmd\s*=\s*\{(.*?)\n\s*\};",
            source, flags=__import__("re").S)
        self.assertIsNotNone(match)
        body = match.group(1)
        self.assertIn('.command = "wifi_trust"', body)
        self.assertIn(
            '.help = "Wi-Fi trust baseline: baseline capture/list/clear | monitor [--only indexes...] | status | stop"',
            body)
        self.assertRegex(body, r"\.func\s*=\s*&?wifi_trust_command")
        self.assertEqual(len(__import__("re").findall(
            r"esp_console_cmd_register\s*\(\s*&wifi_trust_cmd\s*\)", source)), 1)
        self.assertEqual(len(__import__("re").findall(
            r"wifi_trust_command\s*\(", source)), 0)

        adapter = source.split(
            "static portMUX_TYPE wifi_trust_state_lock", 1)[1].split(
            "static void analyzer_legacy_scan_finished", 1)[0]
        self.assertNotIn("portMAX_DELAY", adapter)
        output_adapter = adapter.split(
            "static bool wifi_trust_output_write", 1)[1].split(
            "static bool wifi_trust_arena_acquire", 1)[0]
        self.assertNotIn("fwrite", output_adapter)
        self.assertIn("#define WIFI_TRUST_OUTPUT_QUEUE_DEPTH 8U", adapter)
        publisher = __import__("re").search(
            r"static bool wifi_trust_output_publish_record\([^)]*\)\s*\{(.*?)\n\}",
            adapter, flags=__import__("re").S)
        self.assertIsNotNone(publisher)
        self.assertEqual(publisher.group(1).count("uart_write_bytes"), 1)
        publisher_task = __import__("re").search(
            r"static void wifi_trust_output_publisher\([^)]*\)\s*\{(.*?)\n\}",
            adapter, flags=__import__("re").S)
        self.assertIsNotNone(publisher_task)
        self.assertIn("wifi_trust_format_terminal_for_output",
                      publisher_task.group(1))
        self.assertLess(publisher_task.group(1).find(
            "wifi_trust_report_output_failure"), publisher_task.group(1).find(
            "atomic_fetch_sub_explicit"))

        scan = __import__("re").search(
            r"static bool wifi_trust_scan_snapshot\([^)]*\)\s*\{(.*?)\n\}",
            adapter, flags=__import__("re").S)
        self.assertIsNotNone(scan)
        scan_declaration = adapter[
            adapter.find("static bool wifi_trust_scan_snapshot"):
            adapter.find("{", adapter.find("static bool wifi_trust_scan_snapshot"))]
        self.assertIn("wifi_shield_target_t *entries", scan_declaration)
        self.assertIn("pdMS_TO_TICKS(WIFI_TRUST_SCAN_TIMEOUT_MS)", scan.group(1))
        self.assertIn(
            "wifi_shield_copy_target(&entries[i], &g_scan_results[i])",
            scan.group(1))
        self.assertNotIn("malloc", scan.group(1))

        runtime_start = __import__("re").search(
            r"static wifi_security_session_result_t wifi_trust_runtime_start"
            r"\([^)]*\)\s*\{(.*?)\n\}", adapter,
            flags=__import__("re").S)
        runtime_stop = __import__("re").search(
            r"static bool wifi_trust_runtime_stop\([^)]*\)\s*\{(.*?)\n\}",
            adapter, flags=__import__("re").S)
        self.assertIsNotNone(runtime_start)
        self.assertIsNotNone(runtime_stop)
        self.assertIn(
            "wifi_shield_start_trust_profile(targets, target_count, config)",
            runtime_start.group(1))
        self.assertIn("wifi_shield_stop_trust_profile(timeout_ms)",
                      runtime_stop.group(1))
        self.assertNotIn("wifi_security_runtime_platform_start",
                         runtime_start.group(1))
        self.assertNotIn("wifi_security_runtime_stop", runtime_stop.group(1))

        acquire = __import__("re").search(
            r"static bool wifi_trust_arena_acquire\([^)]*\)\s*\{(.*?)\n\}",
            adapter, flags=__import__("re").S)
        self.assertIsNotNone(acquire)
        self.assertIn("heap_caps_calloc", acquire.group(1))
        self.assertIn("MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT", acquire.group(1))
        self.assertNotIn("MALLOC_CAP_DEFAULT", acquire.group(1))

        timer_callback = __import__("re").search(
            r"static void wifi_trust_deadline_timer_callback\([^)]*\)\s*\{(.*?)\n\}",
            adapter, flags=__import__("re").S)
        control_task = __import__("re").search(
            r"static void wifi_trust_control_task\([^)]*\)\s*\{(.*?)\n\}",
            adapter, flags=__import__("re").S)
        self.assertIsNotNone(timer_callback)
        self.assertIsNotNone(control_task)
        self.assertIn("xQueueSend", timer_callback.group(1))
        self.assertIn(", 0)", timer_callback.group(1))
        self.assertIn("wifi_trust_deadline_state_timer_fired",
                      timer_callback.group(1))
        self.assertIn("esp_timer_get_time", timer_callback.group(1))
        self.assertNotIn("wifi_trust_stop", timer_callback.group(1))
        self.assertNotIn("callback(", timer_callback.group(1))
        self.assertNotIn("wifi_trust_deadline_epoch", timer_callback.group(1))
        self.assertIn("wifi_trust_deadline_state_take_pending",
                      control_task.group(1))
        self.assertIn("pdMS_TO_TICKS(1000U)", control_task.group(1))
        self.assertIn("callback(callback_context, message.epoch)",
                      control_task.group(1))

        arm = __import__("re").search(
            r"static bool wifi_trust_deadline_arm\([^)]*\)\s*\{(.*?)\n\}",
            adapter, flags=__import__("re").S)
        cancel = __import__("re").search(
            r"static void wifi_trust_deadline_cancel\([^)]*\)\s*\{(.*?)\n\}",
            adapter, flags=__import__("re").S)
        self.assertIsNotNone(arm)
        self.assertIsNotNone(cancel)
        self.assertIn("wifi_trust_deadline_operation_mutex", arm.group(1))
        self.assertIn("wifi_trust_deadline_state_arm", arm.group(1))
        self.assertIn("wifi_trust_deadline_operation_mutex", cancel.group(1))
        self.assertIn("wifi_trust_deadline_state_cancel", cancel.group(1))
        self.assertLess(cancel.group(1).find("wifi_trust_deadline_state_cancel"),
                        cancel.group(1).find("esp_timer_stop"))

        create_queue = source.find("wifi_trust_output_queue = xQueueCreateStatic(")
        create_publisher = source.find("xTaskCreateStatic(wifi_trust_output_publisher")
        create_control_queue = source.find("wifi_trust_control_queue = xQueueCreateStatic(")
        create_control_task = source.find("xTaskCreateStatic(wifi_trust_control_task")
        create_deadline_mutex = source.find(
            "wifi_trust_deadline_operation_mutex = xSemaphoreCreateMutexStatic(")
        initialize_deadline_state = source.find(
            "wifi_trust_deadline_state_init(&wifi_trust_deadline_state)")
        create_timer = source.find("esp_timer_create(&wifi_trust_deadline_timer_args")
        initialize = source.find(
            "wifi_trust_init(&wifi_trust_runtime_hooks, &wifi_trust_storage_hooks, &wifi_trust_output_hooks)")
        for position in (create_queue, create_publisher, create_control_queue,
                         create_control_task, create_deadline_mutex,
                         initialize_deadline_state, create_timer, initialize):
            self.assertGreaterEqual(position, 0)
        self.assertLess(create_queue, create_publisher)
        self.assertLess(create_publisher, initialize)
        self.assertLess(create_control_queue, create_deadline_mutex)
        self.assertLess(create_deadline_mutex, initialize_deadline_state)
        self.assertLess(initialize_deadline_state, create_control_task)
        self.assertLess(create_control_task, create_timer)
        self.assertLess(create_timer, initialize)
        self.assertEqual(len(__import__("re").findall(
            r"wifi_trust_init\s*\(", source)), 1)

        self.assertIn(".sync_volume = wifi_trust_sd_sync_checked", adapter)
        directory_bodies = __import__("re").findall(
            r"static esp_err_t create_sd_directories\(void\)\s*\{(.*?)\n\}",
            source, flags=__import__("re").S)
        self.assertEqual(len(directory_bodies), 1)
        self.assertIn('"/sdcard/lab/wifi-trust"', directory_bodies[0])
        stop = source.split("static int cmd_stop", 1)[1].split(
            'MY_LOG_INFO(TAG, "Stop command received', 1)[0]
        sae = stop.find("sae_guard_stop(5000)")
        trust = stop.find("wifi_trust_stop(5000)")
        generic = stop.find("wifi_security_runtime_stop(5000)")
        self.assertGreaterEqual(sae, 0)
        self.assertGreater(trust, sae)
        self.assertGreater(generic, trust)

        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")
        self.assertEqual(cmake.count('"wifi_trust.c"'), 1)
        self.assertEqual(cmake.count('"wifi_trust_deadline.c"'), 1)

    def test_documentation_freezes_cli_storage_evidence_and_boundaries(self):
        manual = (ROOT / "docs/command-manual.md").read_text(encoding="utf-8")
        sniffer = (ROOT / "docs/sniffer-extended-uart.md").read_text(
            encoding="utf-8")
        runtime = (ROOT / "docs/wifi-security-runtime.md").read_text(
            encoding="utf-8")

        for command in (
                "wifi_trust baseline capture [--seconds <5..120>] [--only <scan-index> [scan-index ...]]",
                "wifi_trust baseline list",
                "wifi_trust baseline clear",
                "wifi_trust monitor [--only <scan-index> [scan-index ...]]",
                "wifi_trust status",
                "wifi_trust stop"):
            self.assertIn(command, manual)
        for token in (
                "default is 15 seconds",
                "/sdcard/lab/wifi-trust/baseline-v1.jsonl",
                "128 profiles",
                "unknown`, `absent`, `valid`, and `invalid",
                "new_bssid", "ssid_changed", "akm_changed",
                "cipher_changed", "pmf_downgrade", "rsnxe_changed",
                "wps_enabled", "wps_lock_changed", "country_changed",
                "channel_changed", "advertisement_conflict",
                "malformed_observation",
                "[WIFI_TRUST/1] EVENT", "[WIFI_TRUST/1] BASELINE",
                "[WIFI_TRUST/1] STATUS", "[WIFI_TRUST/1] TERMINAL",
                "ok_backup_pending", "published_uncertain",
                "recovered_retry", "storage_uncertain",
                "current channel only", "scan_networks",
                "250 ms sampled residence",
                "Bare capture and monitor remain current channel only",
                "mesh and extender deployments", "evidence, not attribution",
                "does not prove firmware compilation", "real SD durability"):
            self.assertIn(token, manual)

        self.assertIn("RSNXE and Country IE evidence", sniffer)
        self.assertIn("is not added to the legacy", sniffer)
        self.assertIn("or `extended` UART suffix", sniffer)
        self.assertIn("### Wi-Fi Trust Baseline module registration", runtime)
        self.assertNotIn(
            "remains an admission policy name for a later integration", runtime)
        for token in (
                "WIFI_SECURITY_MODULE_TRUST_MONITOR",
                "SCOPE=current_channel",
                "no scan, initial tune or retune",
                "250 ms sampled residence",
                "never writes baseline storage before",
                "monotonic due-time fence",
                "stale cancellation cannot stop a rearmed timer",
                "serializes physical timer arm and cancel",
                "does not attribute an",
                "sends no probe, authentication, association, deauthentication",
                "real SD power-loss recovery"):
            self.assertIn(token, runtime)


if __name__ == "__main__":
    unittest.main()
