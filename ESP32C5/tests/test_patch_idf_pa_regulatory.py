"""Exercise the PA regulatory configure hook against disposable IDF trees."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "tools" / "patch_idf_pa_regulatory.cmake"

OLD_PA = (
    "country PA: DFS-FCC\n"
    "\t(2400 - 2483.5 @ 40), (36)\n"
    "\t(5150 - 5250 @ 80), (36), AUTO-BW\n"
    "\t(5250 - 5350 @ 80), (30), AUTO-BW\n"
    "\t(5470 - 5725 @ 160), (30)\n"
    "\t(5725 - 5850 @ 80), (36)\n"
    "\t(57000 - 64000 @ 2160), (43)"
)
NEW_PA = (
    "country PA: DFS-FCC\n"
    "\t(2400 - 2483.5 @ 40), (36)\n"
    "\t(5150 - 5250 @ 80), (36), AUTO-BW\n"
    "\t(5250 - 5350 @ 80), (30), AUTO-BW\n"
    "\t(5470 - 5730 @ 160), (30)\n"
    "\t(5725 - 5895 @ 80), (36)\n"
    "\t(57000 - 64000 @ 2160), (43)"
)
OLD_ROW_1 = b"{ 100, 140, 4, 30, 0, 0 }"
OLD_ROW_2 = b"{ 149, 165, 3, 36, 0, 0 }"
NEW_ROW_1 = b"{ 100, 144, 4, 30, 0, 0 }"
NEW_ROW_2 = b"{ 149, 177, 3, 36, 0, 0 }"
OLD_C_RULE_1 = OLD_ROW_1 + b",  /* chan:100~140, max_bw:160M, max_power:30(dBm), dfs:0, reserved.*/"
OLD_C_RULE_2 = OLD_ROW_2 + b",  /* chan:149~165, max_bw:80M, max_power:36(dBm), dfs:0, reserved.*/"
NEW_C_RULE_1 = NEW_ROW_1 + b",  /* chan:100~144, max_bw:160M, max_power:30(dBm), dfs:0, reserved.*/"
NEW_C_RULE_2 = NEW_ROW_2 + b",  /* chan:149~177, max_bw:80M, max_power:36(dBm), dfs:0, reserved.*/"

FAKE_GENERATOR = r'''
from pathlib import Path

directory = Path(__file__).resolve().parent
assert Path.cwd() == directory, "reg2fw.py needs regulatory as cwd"
text = (directory / "esp_wifi_regulatory.txt").read_text(encoding="utf-8")
assert "(5470 - 5730 @ 160), (30)" in text
assert "(5725 - 5895 @ 80), (36)" in text
counter = directory / "generator_runs"
counter.write_text(str(int(counter.read_text()) + 1 if counter.exists() else 1))
(directory / "esp_wifi_regulatory.c").write_text(
    "#ifdef CONFIG_SOC_WIFI_SUPPORT_5G\n"
    "/* ESP_WIFI_REGULATORY_TYPE_PA */\n"
    "    {\n        5,  /* Number of rules */\n        {\n"
    "            { 1, 13, 2, 36, 0, 0 },\n"
    "            { 36, 48, 3, 36, 0, 0 },\n"
    "            { 52, 64, 3, 30, 0, 0 },\n"
    "            { 100, 144, 4, 30, 0, 0 },  /* chan:100~144, max_bw:160M, max_power:30(dBm), dfs:0, reserved.*/\n"
    "            { 149, 177, 3, 36, 0, 0 },  /* chan:149~177, max_bw:80M, max_power:36(dBm), dfs:0, reserved.*/\n"
    "        }\n    },\n"
    "/* ESP_WIFI_REGULATORY_TYPE_PH */\n"
    "#else\nKEEP_2G\n#endif\n",
    encoding="utf-8",
)
print("esp_wifi_regulatory.c generated successfully.")
'''
FAKE_ORIGINAL_C = (
    b"#ifdef CONFIG_SOC_WIFI_SUPPORT_5G\n"
    b"/* ESP_WIFI_REGULATORY_TYPE_PA */\n"
    b"    {\n        5,  /* Number of rules */\n        {\n"
    b"            { 1, 13, 2, 36, 0, 0 },\n"
    b"            { 36, 48, 3, 36, 0, 0 },\n"
    b"            { 52, 64, 3, 30, 0, 0 },\n"
    b"            { 100, 140, 4, 30, 0, 0 },  /* chan:100~140, max_bw:160M, max_power:30(dBm), dfs:0, reserved.*/\n"
    b"            { 149, 165, 3, 36, 0, 0 },  /* chan:149~165, max_bw:80M, max_power:36(dBm), dfs:0, reserved.*/\n"
    b"        }\n    },\n"
    b"/* ESP_WIFI_REGULATORY_TYPE_PH */\n"
    b"#else\nKEEP_2G\n#endif\n"
)


class PatchIdfPaRegulatoryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cmake = os.environ.get("CMAKE") or shutil.which("cmake")
        if not cls.cmake:
            raise unittest.SkipTest("CMake is required")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="idf-pa-regulatory-")
        self.addCleanup(self.temp.cleanup)
        self.idf = Path(self.temp.name) / "esp-idf"
        self.reg = self.idf / "components" / "esp_wifi" / "regulatory"
        self.reg.mkdir(parents=True)
        version = self.idf / "tools" / "cmake" / "version.cmake"
        version.parent.mkdir(parents=True)
        version.write_text(
            "set(IDF_VERSION_MAJOR 6)\n"
            "set(IDF_VERSION_MINOR 0)\n"
            "set(IDF_VERSION_PATCH 0)\n",
            encoding="utf-8",
        )
        self.source = self.reg / "esp_wifi_regulatory.txt"
        self.generated = self.reg / "esp_wifi_regulatory.c"
        self.original_text = "country NZ: DFS-FCC\n\t(2400 - 2483.5 @ 40), (30)\n\n" + OLD_PA + "\n\ncountry PE: DFS-FCC\n"
        self.source.write_bytes(self.original_text.encode("utf-8"))
        self.original_c = FAKE_ORIGINAL_C
        self.generated.write_bytes(self.original_c)
        (self.reg / "reg2fw.py").write_text(FAKE_GENERATOR, encoding="utf-8")
        (self.reg / "reg_parse.py").write_text("", encoding="utf-8")

    def run_patch(self):
        env = os.environ.copy()
        env["IDF_PATH"] = str(self.idf)
        return subprocess.run(
            [str(self.cmake), f"-DPYTHON={sys.executable}", "-P", str(PATCH)],
            cwd=self.temp.name, env=env, capture_output=True, text=True,
        )

    def test_patches_only_pa_generates_c_and_second_run_is_noop(self):
        first = self.run_patch()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertEqual(self.source.read_text(encoding="utf-8"),
                         self.original_text.replace(OLD_PA, NEW_PA))
        generated = self.generated.read_bytes()
        self.assertIn(NEW_ROW_1, generated)
        self.assertIn(NEW_ROW_2, generated)
        self.assertIn(b"#else\nKEEP_2G\n#endif", generated)
        self.assertNotIn(b"\r\n", generated)
        self.assertEqual((self.reg / "generator_runs").read_text(), "1")
        self.assertFalse((Path(self.temp.name) / "esp_wifi_regulatory.c").exists())

        second = self.run_patch()
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        self.assertEqual(self.generated.read_bytes(), generated)
        self.assertEqual((self.reg / "generator_runs").read_text(), "1")

    def test_rejects_unsupported_idf_without_writes(self):
        version = self.idf / "tools" / "cmake" / "version.cmake"
        version.write_text(version.read_text().replace("PATCH 0", "PATCH 2"))
        result = self.run_patch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("6.0.0", result.stdout + result.stderr)
        self.assertEqual(self.source.read_text(encoding="utf-8"), self.original_text)
        self.assertEqual(self.generated.read_bytes(), self.original_c)

    def test_rejects_unknown_pa_block_without_writes(self):
        changed = self.original_text.replace("(5470 - 5725 @ 160)", "(5470 - 5710 @ 160)")
        self.source.write_text(changed, encoding="utf-8", newline="\n")
        result = self.run_patch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("country PA", result.stdout + result.stderr)
        self.assertEqual(self.source.read_text(encoding="utf-8"), changed)
        self.assertEqual(self.generated.read_bytes(), self.original_c)

    def test_generator_failure_restores_both_idf_files(self):
        (self.reg / "reg2fw.py").write_text(
            "from pathlib import Path\n"
            "Path('esp_wifi_regulatory.c').write_text('partial')\n"
            "raise SystemExit(7)\n",
            encoding="utf-8",
        )
        result = self.run_patch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("reg2fw.py", result.stdout + result.stderr)
        self.assertEqual(self.source.read_text(encoding="utf-8"), self.original_text)
        self.assertEqual(self.generated.read_bytes(), self.original_c)

    def test_regenerates_when_text_is_patched_but_c_is_stale(self):
        patched = self.original_text.replace(OLD_PA, NEW_PA)
        self.source.write_bytes(patched.encode("utf-8"))
        result = self.run_patch()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.source.read_bytes(), patched.encode("utf-8"))
        self.assertIn(NEW_ROW_1, self.generated.read_bytes())
        self.assertEqual((self.reg / "generator_runs").read_text(), "1")

    def test_invalid_generated_table_restores_both_idf_files(self):
        (self.reg / "reg2fw.py").write_text(
            "from pathlib import Path\n"
            "Path('esp_wifi_regulatory.c').write_text('invalid table')\n"
            "print('esp_wifi_regulatory.c generated successfully.')\n",
            encoding="utf-8",
        )
        result = self.run_patch()
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stdout + result.stderr, r"unexpected\s+PA table")
        self.assertEqual(self.source.read_text(encoding="utf-8"), self.original_text)
        self.assertEqual(self.generated.read_bytes(), self.original_c)

    def test_unrelated_local_c_edit_is_not_overwritten(self):
        local_c = self.original_c.replace(b"KEEP_2G", b"LOCAL_2G_CHANGE")
        self.generated.write_bytes(local_c)
        result = self.run_patch()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unrelated", result.stdout + result.stderr)
        self.assertEqual(self.source.read_text(encoding="utf-8"), self.original_text)
        self.assertEqual(self.generated.read_bytes(), local_c)

    def test_real_generator_changes_only_the_two_pa_rows(self):
        installed = os.environ.get("IDF_PATH")
        if not installed:
            self.skipTest("Set IDF_PATH to a pristine ESP-IDF 6.0.0 or 6.0.1 checkout")
        upstream = Path(installed) / "components" / "esp_wifi" / "regulatory"
        for name in ("esp_wifi_regulatory.txt", "esp_wifi_regulatory.c", "reg2fw.py", "reg_parse.py"):
            shutil.copy2(upstream / name, self.reg / name)
        shutil.copy2(Path(installed) / "tools" / "cmake" / "version.cmake",
                     self.idf / "tools" / "cmake" / "version.cmake")
        original_text = self.source.read_bytes()
        original_c = self.generated.read_bytes()
        if original_text.count(OLD_PA.encode()) != 1:
            self.skipTest("Installed ESP-IDF PA block differs from pristine 6.0.x")
        marker = b"/* ESP_WIFI_REGULATORY_TYPE_PA */"
        next_marker = b"/* ESP_WIFI_REGULATORY_TYPE_PH */"
        start = original_c.index(marker)
        end = original_c.index(next_marker, start)
        old_pa_c = original_c[start:end]
        self.assertEqual(old_pa_c.count(OLD_C_RULE_1), 1)
        self.assertEqual(old_pa_c.count(OLD_C_RULE_2), 1)
        new_pa_c = old_pa_c.replace(OLD_C_RULE_1, NEW_C_RULE_1).replace(OLD_C_RULE_2, NEW_C_RULE_2)

        result = self.run_patch()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.source.read_bytes(), original_text.replace(OLD_PA.encode(), NEW_PA.encode()))
        self.assertEqual(self.generated.read_bytes(),
                         original_c[:start] + new_pa_c + original_c[end:])


if __name__ == "__main__":
    unittest.main()
