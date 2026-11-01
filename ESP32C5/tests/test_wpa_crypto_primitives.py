"""Known-answer and invalid-input tests for shared JanOS WPA primitives."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WpaCryptoPrimitivesTests(unittest.TestCase):
    def test_ptk_mic_pmkid_vectors_and_zeroization(self):
        with tempfile.TemporaryDirectory(prefix="janos-wpa-primitives-") as tmp:
            executable = Path(tmp) / "wpa-crypto-primitives-test"
            command = [
                os.environ.get("CC", "gcc"),
                "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT / "main"),
                str(ROOT / "tests/wpa_crypto_primitives_test.c"),
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
            self.assertEqual(completed.stdout, "WPA crypto primitives: PASS\n")


if __name__ == "__main__":
    unittest.main()
