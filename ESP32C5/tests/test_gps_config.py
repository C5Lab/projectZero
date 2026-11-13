"""Compile and execute the portable GPS source-selection contract."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = path.resolve()
    return f"/mnt/{path.drive.rstrip(':').lower()}/{path.relative_to(path.anchor).as_posix()}"


class GpsConfigTest(unittest.TestCase):
    def test_gps_config_contract(self):
        compiler = next((shutil.which(c) for c in
                         (os.environ.get("CC", ""), "cc", "gcc", "clang")
                         if c and shutil.which(c)), None)
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "gps_config_test"
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            sources = [ROOT / "tests/gps_config_test.c",
                       ROOT / "main/gps_config.c"]
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
            self.assertIn("PASS: GPS config", result.stdout)

    def test_firmware_uses_module_specific_uart_pins(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")

        self.assertRegex(
            source,
            re.compile(
                r"uart_set_pin\s*\(\s*GPS_UART_NUM\s*,\s*"
                r"gps_get_uart_tx_pin\s*\(\s*current_gps_module\s*\)\s*,\s*"
                r"gps_get_uart_rx_pin\s*\(\s*current_gps_module\s*\)",
                re.MULTILINE,
            ),
        )
        self.assertNotIn("#define GPS_TX_PIN", source)
        self.assertNotIn("#define GPS_RX_PIN", source)

    def test_rf_cap_is_registered_and_persisted(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")

        self.assertIn('"gps_config.c"', cmake)
        self.assertIn('<m5|atgm|external|cap|rf_cap>', source)
        self.assertIn("gps_module_is_valid_persisted(module_val)", source)
        self.assertIn("gps_save_state_to_nvs();", source)

    def test_manual_documents_the_rf_cap_uart_contract(self):
        manual = (ROOT / "docs/command-manual.md").read_text(encoding="utf-8")

        self.assertIn("`gps_set [module]`", manual)
        self.assertIn("`rf_cap`", manual)
        self.assertIn("115200 baud", manual)
        self.assertIn("GPIO4", manual)
        self.assertIn("GPIO5", manual)


if __name__ == "__main__":
    unittest.main()
