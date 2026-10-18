"""Exercise actual analyzer command startup ordering and busy output."""
from pathlib import Path
import os
import re
import tempfile
import unittest

from test_janos_console_transaction import production_function
from wps_host.host_build import compile_and_run

ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "components/janos_wps"


def global_stop_admission_prefix():
    """Keep only the real WPS/analyzer quiesce gates from cmd_stop.

    Locate the analyzer guard structurally.  Presentation strings and later
    legacy teardown text are intentionally not extraction boundaries.
    """
    function = production_function("cmd_stop")
    masked = re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*',
                    lambda match: " " * len(match.group()), function,
                    flags=re.S)
    guard = re.search(r"if\s*\(\s*!\s*wifi_analyzer_stop\s*\([^)]*\)\s*\)\s*\{",
                      masked)
    assert guard, "cmd_stop must keep the analyzer quiesce gate"
    depth, end = 1, guard.end()
    while depth:
        depth += (masked[end] == "{") - (masked[end] == "}")
        end += 1
    return function[:end] + "\n    ++radio_teardowns; return 0;\n}"


class JanosAnalyzerAdmissionTest(unittest.TestCase):
    def run_fixture(self, mode, expected):
        functions = "\n".join(production_function(name, ROOT / "main/wifi_analyzer.c")
                              for name in ("control_error", "wifi_analyzer_busy",
                                           "wifi_analyzer_stop", "wifi_analyzer_startup_begin",
                                           "wifi_analyzer_startup_end", "reserve", "release",
                                           "wifi_analyzer_command_with_startup",
                                           "wifi_analyzer_command"))
        stop_prefix = global_stop_admission_prefix()
        code = (ROOT / "tests/janos_analyzer_admission_test.c").read_text().replace(
            "/* ANALYZER_FUNCTIONS */", functions).replace(
            "/* GLOBAL_STOP_PREFIX */", stop_prefix).replace(
            "/* DISPATCHER */", production_function("janos_console_cmd_dispatch"))
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "analyzer.c"
            fixture.write_text(code)
            flags = ["-pthread"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            output = compile_and_run(self, "analyzer", [fixture,
                ROOT / "main/janos_console_admission.c", ROOT / "main/wifi_analyzer_core.c",
                COMPONENT / "janos_radio_lease.c", COMPONENT / "janos_wps_command.c"],
                [ROOT / "main", COMPONENT / "include"], extra_flags=flags,
                run_args=[mode], expected=None if mode in (
                    "pending-stop", "dispatch-boundary") else expected)
            self.assertIn(expected, output)

    def test_startup_reserves_before_baseline_and_rolls_back_busy(self):
        self.run_fixture("baseline", "PASS: analyzer reserve before baseline, busy wire and rollback")

    def test_pending_startup_blocks_global_stop_teardown(self):
        self.run_fixture("pending-stop", "PASS: analyzer pending startup blocks global stop teardown")

    def test_pending_startup_can_finish_while_global_stop_waits_unlocked(self):
        self.run_fixture("pending-stop-release", "PASS: analyzer pending startup blocks global stop teardown")

    def test_dispatch_unlock_publishes_intent_before_scan_handler(self):
        self.run_fixture("dispatch-boundary", "PASS: analyzer pending startup blocks global stop teardown")

    def test_dispatch_announced_startup_can_complete_during_stop_wait(self):
        self.run_fixture("dispatch-boundary-release", "PASS: analyzer pending startup blocks global stop teardown")

    def test_unconsumed_announcements_rollback_and_stale_cleanup_cannot_release_new_start(self):
        self.run_fixture("announcement", "PASS: analyzer announcements rollback, consume and reject stale cleanup")

    def test_active_analyzer_clear_preserves_handler_busy_wire(self):
        self.run_fixture("clear-busy", "PASS: analyzer clear busy wire compatibility")

    def test_stop_fixture_boundary_is_structural_not_presentation_text(self):
        prefix = global_stop_admission_prefix()
        self.assertIn("janos_wps_runtime_stop", prefix)
        self.assertIn("wifi_analyzer_stop", prefix)
        self.assertNotIn("oled_display_update_full", prefix)
        self.assertNotIn("Stop command received", prefix)


if __name__ == "__main__":
    unittest.main()
