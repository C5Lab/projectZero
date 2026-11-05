"""Portable state, allowlist and rate-limit tests for Deauth Defence."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


class DeauthDefenceCoreTests(unittest.TestCase):
    def test_state_filters_rate_limits_and_idle_release(self):
        with tempfile.TemporaryDirectory(prefix="janos-deauth-defence-core-") as tmp:
            executable = Path(tmp) / "deauth-defence-core-test"
            compiler = next((shutil.which(name) for name in
                             (os.environ.get("CC"), "cc", "gcc", "clang")
                             if name and shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                     "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                     "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/deauth_defence_core_test.c",
                       ROOT / "main/deauth_defence_core.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertTrue(shutil.which("wsl.exe"), "host C compiler required")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            built = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            completed = subprocess.run(
                run, capture_output=True, text=True, timeout=15,
            )
            self.assertEqual(completed.returncode, 0,
                             completed.stdout + completed.stderr)
            self.assertEqual(completed.stdout, "deauth defence core: PASS\n")


if __name__ == "__main__":
    unittest.main()
