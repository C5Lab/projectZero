"""Deterministic producer/drain and asynchronous UART failure coverage."""

from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


class WifiShieldOutputPlatformTest(unittest.TestCase):
    def test_idle_status_adapter_has_a_synchronous_uart_path(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        block = source.split("static bool wifi_shield_output_write(", 1)[1]
        block = block.split("static bool wifi_shield_output_write_terminal(", 1)[0]
        self.assertIn("wifi_shield_output_platform_should_sync_status", block)
        self.assertIn("uart_write_bytes", block)

    def test_writer_drain_race_and_uart_failures(self):
        with tempfile.TemporaryDirectory(prefix="janos-shield-output-") as directory:
            executable = Path(directory) / "wifi_shield_output_platform_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            sources = [ROOT / "tests/wifi_shield_output_platform_test.c",
                       ROOT / "main/wifi_shield_output_platform.c"]
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                     "-pthread"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                          "-fno-sanitize-recover=all"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"),
                                     "host C compiler required")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            self.assertEqual(built.stdout + built.stderr, "")
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "wifi shield output platform: PASS\n")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
