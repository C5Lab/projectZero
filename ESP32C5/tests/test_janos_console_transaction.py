"""Race the actual dispatcher against the actual WPS service, without firmware."""
from pathlib import Path
import os
import re
import tempfile
import unittest

from wps_host.host_build import compile_and_run

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "components/janos_wps"


def production_function(name, path=ROOT / "main/main.c"):
    source = path.read_text(encoding="utf-8")
    masked = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
                    lambda m: " " * len(m.group()), source, flags=re.S)
    start = re.search(r"(?:static )?(?:int|bool|void|uint32_t) " + re.escape(name) + r"\([^;{}]*\)\s*\{",
                      masked)
    assert start
    depth, end = 1, start.end()
    while depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return source[start.start():end]


class JanosConsoleTransactionTest(unittest.TestCase):
    def run_fixture(self, mode):
        code = (ROOT / "tests/janos_console_transaction_test.c").read_text()
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "transaction.c"
            fixture.write_text(code.replace("/* DISPATCHER */", production_function(
                "janos_console_cmd_dispatch")).replace("/* ANALYZER_ACQUIRE */",
                production_function("analyzer_host_lease_acquire")))
            extra = ["-pthread"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                extra += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            output = compile_and_run(
                self, "transaction", [fixture, ROOT / "main/janos_console_admission.c",
                    COMPONENT / "janos_radio_lease.c",
                    COMPONENT / "janos_wps_service.c",
                    COMPONENT / "janos_wps_command.c",
                    COMPONENT / "janos_wps_memory.c",
                    COMPONENT / "private/workflow/lab_secret.c"],
                [ROOT / "main", COMPONENT / "include"],
                extra_flags=extra, run_args=[mode])
            self.assertIn(f"PASS: console radio transaction {mode}", output)

    def test_legacy_reserves_before_publishing_state(self):
        self.run_fixture("legacy-first")

    def test_wps_reserves_before_baseline_inspection(self):
        self.run_fixture("wps-first")

    def test_single_channel_reserves_and_keeps_stop_available(self):
        self.run_fixture("single-channel")

    def test_batch_channel_reserves_and_keeps_stop_available(self):
        self.run_fixture("batch-channel")

    def test_rejected_wps_baseline_releases_reservation(self):
        self.run_fixture("admit-failure")

    def test_safe_commands_remain_available_while_wps_owns_radio(self):
        self.run_fixture("wps-owned")

    def test_analyzer_clear_excludes_concurrent_scan_startup(self):
        self.run_fixture("analyzer-clear")

    def test_published_legacy_state_blocks_wps_after_startup_token_release(self):
        self.run_fixture("published")


if __name__ == "__main__":
    unittest.main()
