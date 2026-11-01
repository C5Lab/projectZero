"""Byte-exact structural tests for JanOS WPA decoy frames."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WpaDecoyTests(unittest.TestCase):
    def test_pair_pmkid_m1_mic_and_rejections(self):
        with tempfile.TemporaryDirectory(prefix="janos-wpa-decoy-") as tmp:
            executable = Path(tmp) / "wpa-decoy-test"
            command = [
                os.environ.get("CC", "gcc"),
                "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT / "main"),
                str(ROOT / "tests/wpa_decoy_test.c"),
                str(ROOT / "main/wpa_decoy.c"),
                str(ROOT / "main/wpa_crypto_primitives.c"),
                str(ROOT / "main/crack_worker_sw_sha1.c"),
                "-o", str(executable),
            ]
            built = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            completed = subprocess.run(
                [str(executable)], capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(completed.returncode, 0,
                             completed.stdout + completed.stderr)
            self.assertEqual(completed.stdout, "WPA decoy frames: PASS\n")


if __name__ == "__main__":
    unittest.main()
