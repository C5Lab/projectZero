"""Compile and execute the portable BSSID protection policy contract."""

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


class BssidProtectionTest(unittest.TestCase):
    def test_protection_contract(self):
        compiler = next((shutil.which(c) for c in
                         (os.environ.get("CC", ""), "cc", "gcc", "clang")
                         if c and shutil.which(c)), None)
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "bssid_protection_test"
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            sources = [ROOT / "tests/bssid_protection_test.c",
                       ROOT / "main/bssid_protection.c"]
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
            built = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS: BSSID protection policy", result.stdout)


if __name__ == "__main__":
    unittest.main()
