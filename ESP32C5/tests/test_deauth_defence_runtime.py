"""Fast-response runtime tests with fake clock, radio, random source and TX."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeauthDefenceRuntimeTests(unittest.TestCase):
    def test_fast_pair_pmkid_failures_stop_and_telemetry(self):
        with tempfile.TemporaryDirectory(prefix="janos-deauth-defence-runtime-") as tmp:
            executable = Path(tmp) / "deauth-defence-runtime-test"
            command = [
                os.environ.get("CC", "gcc"),
                "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-pthread",
                "-I", str(ROOT / "main"),
                str(ROOT / "tests/deauth_defence_runtime_test.c"),
                str(ROOT / "main/deauth_defence_runtime.c"),
                str(ROOT / "main/deauth_defence_core.c"),
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
            self.assertEqual(completed.stdout, "deauth defence runtime: PASS\n")


if __name__ == "__main__":
    unittest.main()
