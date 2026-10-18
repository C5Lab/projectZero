"""Validate channel/DFS policy with fixtures and the installed IDF regulatory tables."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WifiChannelPolicyTest(unittest.TestCase):
    def compile_and_run(self, regulatory_source):
        compiler = shutil.which(os.environ.get("CC", "cc"))
        if compiler is None:
            self.skipTest("host C compiler required")
        with tempfile.TemporaryDirectory(prefix="wifi-channel-policy-") as directory:
            executable = Path(directory) / "policy"
            regulatory_object = Path(directory) / "regulatory.o"
            # Compile upstream separately: newer Clang warns about IDF's valid
            # two-byte country arrays initialized from two-character strings.
            result = subprocess.run([
                compiler, "-std=c11", "-fsanitize=address,undefined",
                "-I", str(ROOT / "tests/host_stubs/wifi_country"),
                "-c", str(regulatory_source), "-o", str(regulatory_object),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([
                compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined",
                "-I", str(ROOT / "tests/host_stubs/wifi_country"),
                "-I", str(ROOT / "main"),
                str(ROOT / "tests/wifi_channel_policy_test.c"),
                str(ROOT / "main/wifi_channel_policy.c"), str(regulatory_object),
                "-o", str(executable),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([str(executable)], capture_output=True,
                                    text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS: US 12 non-DFS/16 DFS; PA 24 non-DFS/4 excluded", result.stdout)

    def test_regulatory_fixtures(self):
        self.compile_and_run(ROOT / "tests/host_stubs/wifi_country/regulatory_fixture.c")

    def test_installed_idf_regulatory_tables(self):
        idf_path = os.environ.get("IDF_PATH")
        description = ROOT / "build/project_description.json"
        if not idf_path and description.is_file():
            idf_path = json.loads(description.read_text()).get("idf_path")
        if not idf_path:
            self.skipTest("ESP-IDF checkout unavailable")
        source = Path(idf_path) / "components/esp_wifi/regulatory/esp_wifi_regulatory.c"
        if not source.is_file():
            self.skipTest("ESP-IDF regulatory source unavailable")
        self.compile_and_run(source)


if __name__ == "__main__":
    unittest.main()
