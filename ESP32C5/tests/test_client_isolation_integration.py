"""Host contract for the Client Isolation Audit command and ESP-IDF wiring."""
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


class ClientIsolationIntegrationTest(unittest.TestCase):
    def _assert_documentation_contract(self, manual, runtime):
        required_manual = (
            "### `client_isolation_audit`",
            "client_isolation_audit start <peer-ipv4> <32-hex-token> [--port <1024..65535>] [--count <1..10>]",
            "client_isolation_audit status",
            "python tools/client_isolation_peer.py --bind 0.0.0.0 --port 48731",
            "[ISO_PEER_TOKEN/1]",
            "[ISO_PEER/1]",
            "[ISO_AUDIT/1] BEGIN",
            "[ISO_AUDIT/1] PROBE",
            "[ISO_AUDIT/1] END",
            "[ISO_AUDIT/1] STATUS",
            "peer_reachable",
            "inconclusive_no_reply",
            "local_error",
            "cancelled",
            "32 datagrams per probe",
            "1000 ms per probe",
            "15000 ms total",
        )
        for text in required_manual:
            self.assertIn(text, manual)

        compact = " ".join(manual.split())
        exact_record_contracts = (
            "`[ISO_AUDIT/1] BEGIN` owns `BSSID`, `LOCAL`, `PEER`, `PORT`, `COUNT` and `RUN`;",
            "`[ISO_AUDIT/1] PROBE` owns `SEQ`, `SEND`, `VALID`, `INVALID`, `TIMEOUT` and `RTT_MS`;",
            "`[ISO_AUDIT/1] END` owns `SENT`, `VALID`, `INVALID`, `TIMEOUTS`, `DURATION_MS` and `OUTCOME`;",
            "`[ISO_AUDIT/1] STATUS` is either `AVAILABLE=0` or `AVAILABLE=1 SENT=<n> VALID=<n> INVALID=<n> TIMEOUTS=<n> DURATION_MS=<n> OUTCOME=<token>`.",
        )
        for text in exact_record_contracts:
            self.assertIn(text, compact)

        self.assertIn("The default port is `48731` and the default probe count is `3`.",
                      compact)
        self.assertIn("Retain the paired JanOS `RUN` value and peer JSONL `run` value",
                      compact)
        self.assertIn("isolation both off and on", compact)
        self.assertIn("an independent capture", compact)
        self.assertIn("three repeated paired runs", compact)
        self.assertIn("a second owned AP/SSID topology", compact)

        self.assertRegex(
            manual,
            r"(?i)one authenticated(?: matching)? reply[^.]*proves[^.]*reachable")
        self.assertRegex(
            manual,
            r"(?i)(?:no|zero) authenticated replies?[^.]*inconclusive[^.]*never proves? isolation")
        self.assertRegex(manual, r"(?i)same (?:SSID/)?BSSID")
        self.assertRegex(manual, r"(?i)host firewall")
        self.assertRegex(manual, r"(?i)(?:sleep|awake)")
        self.assertRegex(manual, r"(?i)token[^.]*never[^.]*\[ISO_PEER/1\]")
        self.assertRegex(manual, r"(?i)host-only[^.]*does not prove[^.]*device")

        required_runtime = (
            "### Client Isolation Audit module registration",
            "JISO/1",
            "HMAC-SHA256/16",
            "peer_reachable > local_error > cancelled > inconclusive_no_reply",
            "No firmware build, flash, owned-AP run, or device/network acceptance",
        )
        for text in required_runtime:
            self.assertIn(text, runtime)

    def test_documentation_freezes_owned_peer_workflow_and_evidence_boundary(self):
        manual = (ROOT / "docs/command-manual.md").read_text(encoding="utf-8")
        runtime = (ROOT / "docs/wifi-security-runtime.md").read_text(
            encoding="utf-8")

        self._assert_documentation_contract(manual, runtime)

        with self.assertRaises(AssertionError):
            self._assert_documentation_contract(
                manual.replace("`RTT_MS`;", "`RTT_MISSING`;", 1), runtime)
        with self.assertRaises(AssertionError):
            self._assert_documentation_contract(
                manual.replace("three repeated paired runs",
                               "repeated paired runs", 1), runtime)

    def test_command_parser_preconditions_hygiene_and_records(self):
        with tempfile.TemporaryDirectory(prefix="janos-client-isolation-") as directory:
            executable = Path(directory) / "client_isolation_integration_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/client_isolation_integration_test.c",
                       ROOT / "main/client_isolation_command.c"]
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
                             "PASS: client isolation CLI, hygiene, records")

    def test_main_wiring_admission_and_dispatch_scrub(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        admission = (ROOT / "main/janos_console_admission.c").read_text(
            encoding="utf-8")
        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")

        self.assertIn('#include "client_isolation_command.h"', main)
        match = re.search(
            r"const\s+esp_console_cmd_t\s+client_isolation_cmd\s*=\s*\{(.*?)\n\s*\};",
            main, flags=re.S)
        self.assertIsNotNone(match)
        body = match.group(1)
        self.assertIn('.command = "client_isolation_audit"', body)
        self.assertIn(
            '.help = "Owned peer isolation audit: start <peer-ipv4> <32-hex-token> [--port 1024..65535] [--count 1..10] | status"',
            body)
        self.assertRegex(body, r"\.func\s*=\s*&?client_isolation_command")
        self.assertEqual(len(re.findall(
            r"esp_console_cmd_register\s*\(\s*&client_isolation_cmd\s*\)", main)), 1)
        self.assertEqual(len(re.findall(r"client_isolation_command\s*\(", main)), 0)
        self.assertEqual(cmake.count('"client_isolation_command.c"'), 1)
        self.assertIn("client_isolation_command_init(&client_isolation_hooks)", main)

        dispatch = re.search(
            r"static int janos_console_cmd_dispatch\([^)]*\)\s*\{(.*?)\n\}",
            main, flags=re.S)
        self.assertIsNotNone(dispatch)
        dispatch = dispatch.group(1)
        self.assertIn('strcmp(cmd_context->command, "client_isolation_audit")',
                      dispatch)
        self.assertGreaterEqual(dispatch.count("client_isolation_scrub_cli_token"), 2)
        rejection = dispatch.split("if (admission != JANOS_CONSOLE_ADMIT)", 1)[1].split(
            "bool analyzer_scan", 1)[0]
        self.assertIn("client_isolation_scrub_cli_token", rejection)
        self.assertIn("linenoiseHistoryFree", rejection)
        self.assertIn("client_isolation_audit", admission)
        self.assertIn("is_client_isolation_status", admission)

        adapter = main.split("static bool client_isolation_platform_snapshot", 1)[1].split(
            "static portMUX_TYPE wps_guard_state_lock", 1)[0]
        self.assertIn("esp_wifi_sta_get_ap_info", adapter)
        self.assertIn("esp_netif_get_ip_info", adapter)
        self.assertIn("mbedtls_md_hmac", adapter)
        self.assertIn("recvfrom", adapter)
        self.assertIn("sendto", adapter)
        self.assertIn("uart_write_bytes", adapter)
        self.assertNotIn("gethostbyname", adapter)
        self.assertNotIn("getaddrinfo", adapter)


if __name__ == "__main__":
    unittest.main()
