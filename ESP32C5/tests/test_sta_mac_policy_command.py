"""Strict STA MAC text validation through the production policy API."""
from pathlib import Path
import unittest

from wps_host.host_build import compile_and_run


ROOT = Path(__file__).resolve().parents[1]


class CommandParserTest(unittest.TestCase):
    def test_fixed_mac_text_validation_and_unchanged_error_output(self):
        compile_and_run(
            self, "sta_mac_fixed_test",
            [ROOT / "tests" / "sta_mac_policy_test.c",
             ROOT / "main" / "sta_mac_policy_core.c",
             ROOT / "main" / "sta_mac_policy_store.c"],
            [ROOT / "main"], run_args=("fixed",),
            expected="PASS: STA MAC policy/storage", extra_flags=("-pedantic",))


if __name__ == "__main__":
    unittest.main()
