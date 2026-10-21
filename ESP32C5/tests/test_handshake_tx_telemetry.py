"""Execute the portable handshake TX-completion counters."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = path.resolve()
    return f"/mnt/{path.drive.rstrip(':').lower()}/{path.relative_to(path.anchor).as_posix()}"


class HandshakeTxTelemetryTest(unittest.TestCase):
    def test_success_failure_and_reset_contract(self):
        compiler = next((shutil.which(candidate) for candidate in
                         (os.environ.get("CC", ""), "cc", "gcc", "clang")
                         if candidate and shutil.which(candidate)), None)
        with tempfile.TemporaryDirectory(prefix="janos-handshake-tx-") as directory:
            executable = Path(directory) / "handshake_tx_telemetry_test"
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            sources = [ROOT / "tests/handshake_tx_telemetry_test.c",
                       ROOT / "main/handshake_tx_telemetry.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            elif shutil.which("wsl.exe"):
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            else:
                self.fail("Host C compiler required (native or WSL)")

            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            executed = subprocess.run(run, cwd=ROOT, capture_output=True,
                                      text=True, timeout=10)
            self.assertEqual(executed.returncode, 0,
                             executed.stdout + executed.stderr)


if __name__ == "__main__":
    unittest.main()
