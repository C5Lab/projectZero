"""Portable state, allowlist and rate-limit tests for Deauth Defence."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeauthDefenceCoreTests(unittest.TestCase):
    def test_state_filters_rate_limits_and_idle_release(self):
        with tempfile.TemporaryDirectory(prefix="janos-deauth-defence-core-") as tmp:
            executable = Path(tmp) / "deauth-defence-core-test"
            command = [
                os.environ.get("CC", "gcc"),
                "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT / "main"),
                str(ROOT / "tests/deauth_defence_core_test.c"),
                str(ROOT / "main/deauth_defence_core.c"),
                "-o", str(executable),
            ]
            built = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            completed = subprocess.run(
                [str(executable)], capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(completed.returncode, 0,
                             completed.stdout + completed.stderr)
            self.assertEqual(completed.stdout, "deauth defence core: PASS\n")


if __name__ == "__main__":
    unittest.main()
