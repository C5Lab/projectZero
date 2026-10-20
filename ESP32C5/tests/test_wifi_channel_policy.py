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
    def compile_and_run(self, regulatory_source, extended_pa=False):
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
                f"-DTEST_PA_EXTENDED={int(extended_pa)}",
                "-I", str(ROOT / "tests/host_stubs/wifi_country"),
                "-c", str(regulatory_source), "-o", str(regulatory_object),
            ], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            result = subprocess.run([
                compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined",
                f"-DTEST_PA_EXTENDED={int(extended_pa)}",
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
            pa_summary = "PA 28 non-DFS/0 excluded" if extended_pa else "PA 24 non-DFS/4 excluded"
            self.assertIn(f"PASS: US 12 non-DFS/16 DFS; {pa_summary}", result.stdout)

    def test_regulatory_fixtures(self):
        source = ROOT / "tests/host_stubs/wifi_country/regulatory_fixture.c"
        for extended_pa in (False, True):
            with self.subTest(extended_pa=extended_pa):
                self.compile_and_run(source, extended_pa=extended_pa)

    def test_installed_idf_regulatory_tables(self):
        idf_path = os.environ.get("IDF_PATH")
        description = ROOT / "build/project_description.json"
        if not idf_path and description.is_file():
            idf_path = json.loads(description.read_text()).get("idf_path")
        if not idf_path:
            self.skipTest("ESP-IDF checkout unavailable")
        source = Path(idf_path) / "components/esp_wifi/regulatory/esp_wifi_regulatory.c"
        text = Path(idf_path) / "components/esp_wifi/regulatory/esp_wifi_regulatory.txt"
        if not source.is_file():
            self.skipTest("ESP-IDF regulatory source unavailable")
        if not text.is_file():
            self.skipTest("ESP-IDF regulatory text unavailable")
        stanza = text.read_text(encoding="utf-8").split("country PA:", 1)[1].split("\n\n", 1)[0]
        extended_pa = "(5470 - 5730 @ 160), (30)" in stanza and "(5725 - 5895 @ 80), (36)" in stanza
        original_pa = "(5470 - 5725 @ 160), (30)" in stanza and "(5725 - 5850 @ 80), (36)" in stanza
        self.assertTrue(extended_pa or original_pa, "unknown country PA regulatory stanza")
        self.compile_and_run(source, extended_pa=extended_pa)


if __name__ == "__main__":
    unittest.main()
