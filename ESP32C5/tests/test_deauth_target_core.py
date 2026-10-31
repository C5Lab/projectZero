"""Run the real deauth target parser and BSSID filter as a host C program."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeauthTargetCoreTests(unittest.TestCase):
    def test_index_and_bssid_filter(self):
        with tempfile.TemporaryDirectory(prefix="janos-deauth-target-") as tmp:
            exe = Path(tmp) / "deauth-target-test"
            subprocess.run(
                [
                    os.environ.get("CC", "gcc"),
                    "-std=c11", "-Wall", "-Wextra", "-Werror",
                    "-I", str(ROOT / "main"),
                    str(ROOT / "tests/deauth_target_core_test.c"),
                    str(ROOT / "main/deauth_target_core.c"),
                    "-o", str(exe),
                ],
                check=True,
            )
            self.assertEqual(
                subprocess.check_output([str(exe)], text=True),
                "deauth target core: PASS\n",
            )


if __name__ == "__main__":
    unittest.main()
