"""Run the real deauth target parser and BSSID filter as a host C program."""

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


class DeauthTargetCoreTests(unittest.TestCase):
    def test_index_and_bssid_filter(self):
        with tempfile.TemporaryDirectory(prefix="janos-deauth-target-") as tmp:
            exe = Path(tmp) / "deauth-target-test"
            compiler = next((shutil.which(name) for name in
                             (os.environ.get("CC"), "cc", "gcc", "clang")
                             if name and shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror",
                     "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                     "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/deauth_target_core_test.c",
                       ROOT / "main/deauth_target_core.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(exe)]
                run = [str(exe)]
            else:
                self.assertTrue(shutil.which("wsl.exe"), "host C compiler required")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(exe)]
                run = ["wsl.exe", wsl_path(exe)]
            subprocess.run(command, check=True)
            self.assertEqual(
                subprocess.check_output(run, text=True),
                "deauth target core: PASS\n",
            )


if __name__ == "__main__":
    unittest.main()
