"""Known-answer and failure-path tests for JanOS software WPA crypto."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                     "host C tests require GCC; run the suite in Linux/WSL")
class CrackWorkerSoftwareSha1Test(unittest.TestCase):
    def test_known_answers_validation_and_cancellation_under_sanitizers(self):
        with tempfile.TemporaryDirectory(prefix="janos-sw-sha1-") as temporary:
            executable = Path(temporary) / "crack_worker_sw_sha1_test"
            command = [
                os.environ.get("CC", "gcc"),
                "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(ROOT / "main"),
                str(ROOT / "tests" / "crack_worker_sw_sha1_test.c"),
                str(ROOT / "main" / "crack_worker_sw_sha1.c"),
                "-o", str(executable),
            ]
            subprocess.run(command, cwd=ROOT, check=True, capture_output=True,
                           text=True)
            subprocess.run([str(executable)], cwd=ROOT, check=True,
                           capture_output=True, text=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
