"""Compile and run the portable LED first-seen BSSID cache tests."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LedTargetCacheTest(unittest.TestCase):
    def test_first_seen_and_capacity(self):
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            self.skipTest("host C compiler required")
        with tempfile.TemporaryDirectory(prefix="janos-led-target-") as directory:
            executable = Path(directory) / "led_target_cache_test"
            compiled = subprocess.run(
                [
                    compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-I", str(ROOT / "main"),
                    str(ROOT / "tests/led_target_cache_test.c"),
                    str(ROOT / "main/led_target_cache.c"), "-o", str(executable),
                ],
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run(
                [str(executable)], capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertIn("LED_TARGET_CACHE_PASS", executed.stdout)


if __name__ == "__main__":
    unittest.main()
