"""Compile and execute the portable policy/storage contract, without ESP-IDF."""
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


class StaMacPolicyTest(unittest.TestCase):
    def test_policy_and_storage_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "sta_mac_policy_test"
            compiler = next((shutil.which(c) for c in
                             (os.environ.get("CC", ""), "cc", "gcc", "clang")
                             if c and shutil.which(c)), None)
            sources = [ROOT / "tests/sta_mac_policy_test.c",
                       ROOT / "main/sta_mac_policy_core.c",
                       ROOT / "main/sta_mac_policy_store.c"]
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
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
            for group in ("records", "fixed", "random", "store"):
                with self.subTest(group=group):
                    result = subprocess.run([*run, group], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("PASS: STA MAC policy/storage", result.stdout)


if __name__ == "__main__":
    unittest.main()
