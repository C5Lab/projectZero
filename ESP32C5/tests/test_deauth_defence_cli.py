"""Compile and execute the portable Deauth Detector V2 option parser."""

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


class DeauthDefenceCliTests(unittest.TestCase):
    def test_passive_trace_defence_and_rejection_contract(self):
        with tempfile.TemporaryDirectory(prefix="janos-deauth-defence-cli-") as tmp:
            executable = Path(tmp) / "deauth-defence-cli-test"
            compiler = next((shutil.which(name) for name in
                             (os.environ.get("CC"), "cc", "gcc", "clang")
                             if name and shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                     "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                     "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/deauth_defence_cli_test.c",
                       ROOT / "main/deauth_defence_cli.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertTrue(shutil.which("wsl.exe"), "host C compiler required")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            subprocess.run(command, check=True)
            self.assertEqual(
                subprocess.check_output(run, text=True),
                "deauth defence CLI: PASS\n",
            )


if __name__ == "__main__":
    unittest.main()
