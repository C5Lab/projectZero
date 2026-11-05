"""Compile the real SAE Guard CLI/runtime adapter against deterministic hooks."""
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


class SaeGuardIntegrationTest(unittest.TestCase):
    def test_cli_filter_worker_lifecycle_and_failure_rollback(self):
        with tempfile.TemporaryDirectory(prefix="janos-sae-guard-integration-") as directory:
            executable = Path(directory) / "sae_guard_integration_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                     "-pthread"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined",
                          "-fno-sanitize-recover=all",
                          "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/sae_guard_integration_test.c",
                       ROOT / "main/sae_guard.c",
                       ROOT / "main/sae_guard_parser.c",
                       ROOT / "main/sae_guard_core.c",
                       ROOT / "main/sae_guard_wire.c",
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
                             "PASS: SAE Guard CLI, filtering, lifecycle, rollback")

    def test_main_registers_exact_command_and_bounded_publisher(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        self.assertIn('#include "sae_guard.h"', source)
        match = re.search(
            r"const\s+esp_console_cmd_t\s+sae_guard_cmd\s*=\s*\{(.*?)\n\s*\};",
            source, flags=re.S)
        self.assertIsNotNone(match, "sae_guard command is not registered")
        body = match.group(1)
        self.assertIn('.command = "sae_guard"', body)
        self.assertIn(
            '.help = "Passive SAE authentication forensics: start [--only indexes...] | status | stop"',
            body)
        self.assertRegex(body, r"\.func\s*=\s*&?sae_guard_command")
        self.assertEqual(len(re.findall(r"sae_guard_command\s*\(", source)), 0)
        self.assertEqual(len(re.findall(
            r"esp_console_cmd_register\s*\(\s*&sae_guard_cmd\s*\)", source)), 1)
        self.assertIn(
            "sae_guard_init(&sae_guard_runtime_hooks, &sae_guard_output_hooks)",
            source)

        adapter = source.split(
            "static portMUX_TYPE sae_guard_state_lock", 1)[1].split(
            "static portMUX_TYPE wifi_trust_state_lock", 1)[0]
        self.assertNotIn("portMAX_DELAY", adapter)
        self.assertNotIn("fwrite", adapter)
        self.assertNotIn("uart_tx_chars", adapter)
        write_body = re.search(
            r"static bool sae_guard_output_write\([^)]*\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(write_body)
        self.assertIn("xQueueSend", write_body.group(1))
        self.assertIn("pdMS_TO_TICKS(SAE_GUARD_OUTPUT_TIMEOUT_MS)",
                      write_body.group(1))
        self.assertNotIn("uart_write_bytes", write_body.group(1))
        self.assertNotIn("atomic_fetch_sub_explicit", write_body.group(1))
        terminal_write = re.search(
            r"static bool sae_guard_output_write_terminal\(.*?\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        complete = re.search(
            r"static void sae_guard_output_complete\([^)]*\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(terminal_write)
        self.assertIsNotNone(complete)
        self.assertNotIn("atomic_fetch_sub_explicit", terminal_write.group(1))
        self.assertIn("atomic_fetch_sub_explicit", complete.group(1))
        scan = re.search(
            r"static bool sae_guard_scan_snapshot\(.*?\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        enter = re.search(
            r"static bool sae_guard_output_enter\([^)]*\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(scan)
        self.assertIsNotNone(enter)
        self.assertIn("pdMS_TO_TICKS(SAE_GUARD_SCAN_TIMEOUT_MS)", scan.group(1))
        self.assertIn("pdMS_TO_TICKS(timeout_ms)", enter.group(1))
        self.assertNotIn("portMAX_DELAY", scan.group(1) + enter.group(1))
        self.assertIn("wifi_shield_target_t (**targets)", scan.group(0))
        self.assertIn("MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT", scan.group(1))
        self.assertIn("wifi_shield_copy_target", scan.group(1))
        publisher = re.search(
            r"static bool sae_guard_output_publish_record\([^)]*\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(publisher)
        self.assertEqual(publisher.group(1).count("uart_write_bytes"), 1)
        publisher_task = re.search(
            r"static void sae_guard_output_publisher\([^)]*\)\s*\{(.*?)\n\}",
            source, flags=re.S)
        self.assertIsNotNone(publisher_task)
        self.assertIn("sae_guard_format_terminal_for_output",
                      publisher_task.group(1))
        self.assertLess(publisher_task.group(1).find(
            "sae_guard_report_output_failure"), publisher_task.group(1).find(
            "atomic_fetch_sub_explicit"))
        create_queue = source.find("sae_guard_output_queue = xQueueCreateStatic(")
        create_task = source.find("xTaskCreateStatic(sae_guard_output_publisher")
        initialize = source.find(
            "sae_guard_init(&sae_guard_runtime_hooks, &sae_guard_output_hooks)")
        self.assertGreaterEqual(create_queue, 0)
        self.assertGreater(create_task, create_queue)
        self.assertGreater(initialize, create_task)
        stop = source.split("static int cmd_stop", 1)[1].split(
            'MY_LOG_INFO(TAG, "Stop command received', 1)[0]
        local_stop = stop.find("sae_guard_stop(5000)")
        generic_stop = stop.find("wifi_security_runtime_stop(5000)")
        self.assertGreaterEqual(local_stop, 0)
        self.assertGreater(generic_stop, local_stop)

        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")
        self.assertEqual(len(re.findall(r'"sae_guard\.c"', cmake)), 1)

    def test_documentation_freezes_passive_evidence_and_acceptance_contract(self):
        manual = (ROOT / "docs/command-manual.md").read_text(encoding="utf-8")
        runtime = (ROOT / "docs/wifi-security-runtime.md").read_text(
            encoding="utf-8")
        combined = manual + "\n" + runtime
        normalized = re.sub(r"\s+", " ", combined)
        normalized_manual = re.sub(r"\s+", " ", manual)
        normalized_runtime = re.sub(r"\s+", " ", runtime)
        sae_manual = re.sub(
            r"\s+", " ", manual.split("### `sae_guard`", 1)[1].split(
                "### `wifi_trust`", 1)[0])
        sae_runtime = re.sub(
            r"\s+", " ", runtime.split("### SAE Guard module registration", 1)[1].split(
                "### Wi-Fi Trust Baseline module registration", 1)[0])

        for command in (
                "sae_guard start",
                "sae_guard start --only <scan-index> [scan-index ...]",
                "sae_guard status",
                "sae_guard stop"):
            self.assertIn(command, manual)
        self.assertIn(
            "Passive SAE authentication forensics: start [--only indexes...] | status | stop",
            manual)

        for phrase in (
                "three malformed SAE frames for one BSSID",
                "eight unconfirmed Commit observations",
                "three distinct group identifiers",
                "half-open ten-second window",
                "32 `(BSSID, station, direction)` pairs",
                "32 independent malformed-BSSID rows",
                "groups 19, 20 and 21",
                "40, 56 and 72 bytes",
                "status 126 (Hash-to-Element)",
                "status 127 (SAE-PK)",
                "status 76 anti-clogging",
                "status 77 unsupported-group",
                "Unknown groups remain observable and are not malformed merely because the group is unknown"):
            self.assertIn(phrase, normalized)

        for section in (sae_manual, sae_runtime):
            self.assertIn("immutable whole-target snapshot", section)
            self.assertIn("byte-addressable PSRAM", section)
            self.assertIn("one effective selected channel remains pinned", section)
            self.assertIn(
                "multiple unique selected channels are sampled in scan order with a 250 ms per-channel dwell",
                section)
            self.assertIn("silence on a channel is not evidence of absence", section)
            self.assertNotIn("does not hop channels", section)
            self.assertNotIn("immutable BSSID snapshot", section)

        for phrase in (
                "[SAE_GUARD/1]",
                "PAIR_DROPS",
                "MALFORMED_DROPS",
                "RX_DROPS",
                "output_failed > restore_failed > queue_overflow > stopped",
                "combined reasons",
                "global `stop`"):
            self.assertIn(phrase, normalized)

        self.assertIn("passive and evidence-only", normalized)
        self.assertIn(
            "sends no SAE Commit, SAE Confirm, anti-clogging token, status response, deauthentication, disassociation or channel-switch announcement",
            normalized)
        self.assertIn("CVE-2026-72003", normalized)
        for boundary in (
                "cannot identify a vulnerable driver",
                "cannot prove exploitation or code execution",
                "cannot prove attribution, password compromise or that WPA3 is broken",
                "possible resource pressure, not a broken password exchange"):
            self.assertIn(boundary, normalized)

        self.assertIn("`sae_overflow` keeps its existing syntax, help and behavior",
                      normalized_manual)
        self.assertIn("Host tests do not prove firmware compilation",
                      normalized_runtime)
        self.assertIn("No RF/device validation is claimed", normalized_runtime)
        self.assertIn("owned WPA3-Personal APs", normalized_runtime)
        self.assertIn("zero JanOS TX", normalized_runtime)
        self.assertIn("AP-side evidence", normalized_runtime)


if __name__ == "__main__":
    unittest.main()
