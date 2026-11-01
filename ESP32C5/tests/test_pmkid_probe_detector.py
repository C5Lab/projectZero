"""Compile and run the bounded Authentication-to-Association correlator."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class PmkidProbeDetectorTests(unittest.TestCase):
    def test_sequences_timeouts_malformed_and_eviction(self):
        with tempfile.TemporaryDirectory(prefix="janos-pmkid-probe-") as tmp:
            executable = Path(tmp) / "pmkid-probe-detector-test"
            command = [
                os.environ.get("CC", "gcc"),
                "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT / "main"),
                str(ROOT / "tests/pmkid_probe_detector_test.c"),
                str(ROOT / "main/pmkid_probe_detector.c"),
                "-o", str(executable),
            ]
            built = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            completed = subprocess.run(
                [str(executable)], capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(completed.returncode, 0,
                             completed.stdout + completed.stderr)
            self.assertEqual(completed.stdout, "PMKID probe detector: PASS\n")


if __name__ == "__main__":
    unittest.main()
