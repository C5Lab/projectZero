"""Compile and execute the Wi-Fi country driver adapter contract."""

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


class WifiCountryDriverTest(unittest.TestCase):
    def test_driver_adapter_contract(self):
        compiler = next((shutil.which(c) for c in
                         (os.environ.get("CC", ""), "cc", "gcc", "clang")
                         if c and shutil.which(c)), None)
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "wifi_country_driver_test"
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            include_dirs = [ROOT / "tests/host_stubs/wifi_country", ROOT / "main"]
            sources = [ROOT / "tests/wifi_country_driver_test.c",
                       ROOT / "main/wifi_country_driver.c",
                       ROOT / "main/wifi_country_policy.c"]
            if compiler:
                command = [compiler, *flags]
                for include_dir in include_dirs:
                    command.extend(["-I", str(include_dir)])
                command.extend([*map(str, sources), "-o", str(executable)])
                run = [str(executable)]
            elif shutil.which("wsl.exe"):
                command = ["wsl.exe", "cc", *flags]
                for include_dir in include_dirs:
                    command.extend(["-I", wsl_path(include_dir)])
                command.extend([*map(wsl_path, sources), "-o", wsl_path(executable)])
                run = ["wsl.exe", wsl_path(executable)]
            else:
                self.fail("Host C compiler required (native or WSL)")
            built = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS: WiFi country driver adapter", result.stdout)


if __name__ == "__main__":
    unittest.main()
