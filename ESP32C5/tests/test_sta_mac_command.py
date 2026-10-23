"""Compile and run the portable STA MAC command parser contract."""
from pathlib import Path
import unittest

from wps_host.host_build import compile_and_run


ROOT = Path(__file__).resolve().parents[1]


class StaMacCommandTest(unittest.TestCase):
    def test_command_grammar_and_error_output(self):
        compile_and_run(
            self,
            "sta_mac_command_test",
            [ROOT / "tests" / "sta_mac_command_test.c",
             ROOT / "main" / "sta_mac_command.c",
             ROOT / "main" / "sta_mac_policy_core.c"],
            [ROOT / "main"],
            expected="PASS: STA MAC command parser",
            extra_flags=("-pedantic",),
        )


if __name__ == "__main__":
    unittest.main()
