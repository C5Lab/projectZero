"""Compile and exercise the hardware-independent LED status policy."""

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


class LedStatusCoreTest(unittest.TestCase):
    def test_status_patterns(self):
        requested = os.environ.get("CC", "")
        compiler = shutil.which(requested) if requested else None
        compiler = compiler or next((shutil.which(name) for name in
                                     ("cc", "gcc", "clang")
                                     if shutil.which(name)), None)
        with tempfile.TemporaryDirectory(prefix="janos-led-status-") as directory:
            executable = Path(directory) / "led_status_core_test"
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined",
                          "-fno-sanitize-recover=all",
                          "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/led_status_core_test.c",
                       ROOT / "main/led_status_core.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"),
                                     "host C compiler required")
                command = ["wsl.exe", "cc", *flags, "-I",
                           wsl_path(ROOT / "main"), *map(wsl_path, sources),
                           "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            compiled = subprocess.run(
                command, capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            executed = subprocess.run(
                run, capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(executed.returncode, 0, executed.stdout + executed.stderr)
            self.assertIn("LED_STATUS_CORE_PASS", executed.stdout)


if __name__ == "__main__":
    unittest.main()
