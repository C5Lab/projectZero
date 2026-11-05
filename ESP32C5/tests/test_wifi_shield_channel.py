"""Compile and exercise the real portable immutable channel planner."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return f"/mnt/{path.drive.rstrip(':').lower()}/{path.relative_to(path.anchor).as_posix()}"


class WifiShieldChannelTests(unittest.TestCase):
    def test_immutable_targets_and_deterministic_schedule(self):
        with tempfile.TemporaryDirectory(prefix="janos-shield-channel-") as directory:
            executable = Path(directory) / "channel-test"
            requested = os.environ.get("CC", "")
            compiler = shutil.which(requested) if requested else None
            if compiler is None:
                compiler = next((shutil.which(name) for name in
                                 ("cc", "gcc", "clang") if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                          "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/wifi_shield_channel_test.c",
                       ROOT / "main/wifi_shield_channel.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"),
                                     "host C compiler required (native or WSL)")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            built = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "wifi shield channel: PASS\n")


if __name__ == "__main__":
    unittest.main()
