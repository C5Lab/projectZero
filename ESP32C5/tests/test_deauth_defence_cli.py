"""Compile and execute the portable Deauth Detector V2 option parser."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeauthDefenceCliTests(unittest.TestCase):
    def test_passive_trace_defence_and_rejection_contract(self):
        with tempfile.TemporaryDirectory(prefix="janos-deauth-defence-cli-") as tmp:
            executable = Path(tmp) / "deauth-defence-cli-test"
            subprocess.run(
                [
                    os.environ.get("CC", "gcc"),
                    "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(ROOT / "main"),
                    str(ROOT / "tests/deauth_defence_cli_test.c"),
                    str(ROOT / "main/deauth_defence_cli.c"),
                    "-o", str(executable),
                ],
                check=True,
            )
            self.assertEqual(
                subprocess.check_output([str(executable)], text=True),
                "deauth defence CLI: PASS\n",
            )


if __name__ == "__main__":
    unittest.main()
