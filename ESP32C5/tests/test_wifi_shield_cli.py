"""Compile and execute the portable Wi-Fi Shield CLI grammar test."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    resolved = Path(path).resolve()
    return (f"/mnt/{resolved.drive.rstrip(':').lower()}/"
            f"{resolved.relative_to(resolved.anchor).as_posix()}")


class WifiShieldCliTests(unittest.TestCase):
    def test_strict_start_status_stop_grammar(self):
        with tempfile.TemporaryDirectory(prefix="janos-wifi-shield-cli-") as tmp:
            executable = Path(tmp) / "wifi-shield-cli-test"
            requested = os.environ.get("CC", "")
            compiler = shutil.which(requested) if requested else None
            if compiler is None:
                compiler = next((shutil.which(name) for name in
                                 ("cc", "gcc", "clang") if shutil.which(name)), None)
            flags = [
                    "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
            ]
            sources = [ROOT / "tests/wifi_shield_cli_test.c",
                       ROOT / "main/wifi_shield_cli.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"),
                                     "host C compiler required (native or WSL)")
                command = ["wsl.exe", "cc", *flags,
                           "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            subprocess.run(command, check=True)
            self.assertEqual(
                subprocess.check_output(run, text=True),
                "wifi shield CLI: PASS\n",
            )


if __name__ == "__main__":
    unittest.main()
