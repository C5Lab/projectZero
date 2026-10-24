"""Compile the LED CLI classifier with a host C compiler."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LedCliActivityTest(unittest.TestCase):
    def test_registered_cli_actions(self):
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            self.skipTest("host C compiler required")
        with tempfile.TemporaryDirectory(prefix="janos-led-cli-") as directory:
            executable = Path(directory) / "led_cli_activity_test"
            compiled = subprocess.run(
                [
                    compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-I", str(ROOT / "main"),
                    str(ROOT / "tests/led_cli_activity_test.c"),
                    str(ROOT / "main/led_cli_activity.c"), "-o", str(executable),
                ],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run(
                [str(executable)], capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertIn("LED_CLI_ACTIVITY_PASS", executed.stdout)


if __name__ == "__main__":
    unittest.main()
