"""Run production ota_info against fake read-only IDF I/O and, locally, Tab5's parser."""

from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from test_ota_flow import extract_function


ROOT = Path(__file__).resolve().parents[1]
TAB5 = ROOT.parent.parent / "M5MonsterC5-Tab5"


class OtaInfoContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            raise RuntimeError("host C compiler required")
        cls.temp = tempfile.TemporaryDirectory(prefix="janos-ota-info-")
        cls.addClassCleanup(cls.temp.cleanup)
        temp = Path(cls.temp.name)
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        macro_names = (
            "OTA_GITHUB_OWNER", "OTA_GITHUB_REPO", "OTA_RF_GITHUB_OWNER",
            "OTA_RF_GITHUB_REPO", "OTA_RF_PARTITION_TABLE_OFFSET",
        )
        macro_lines = []
        for name in macro_names:
            matches = re.findall(rf"(?m)^#define {name}\b[^\n]*", source)
            if len(matches) != 1:
                raise RuntimeError(f"expected one production definition for {name}")
            macro_lines.append(matches[0])
        (temp / "ota_definitions_production.inc").write_text(
            "\n".join(macro_lines) + "\n", encoding="utf-8"
        )
        (temp / "ota_info_production.inc").write_text(
            extract_function(source, "ota_diag_log_line") + "\n" +
            extract_function(source, "cmd_ota_info"), encoding="utf-8"
        )
        (temp / "ota_rf_layout_production.inc").write_text(
            extract_function(source, "ota_rf_layout_compatible"), encoding="utf-8"
        )
        diag_source = ROOT / "main/ota_diag.c"
        diag_header = ROOT / "main/ota_diag.h"
        if diag_source.exists() and diag_header.exists():
            # Keep the production logic verbatim; the host adapter supplies the IDF types.
            body = diag_header.read_text(encoding="utf-8") + "\n" + diag_source.read_text(encoding="utf-8")
            body = re.sub(r"(?m)^#include[^\n]*\n", "", body)
        else:
            body = ""
        (temp / "ota_diag_production.inc").write_text(body, encoding="utf-8")
        cls.parser_available = (TAB5 / "main/ota_rf.c").exists() and (TAB5 / "main/ota_rf.h").exists()
        cls.executables = {}
        for profile, offset, rf in (("classic", "0x8000", "0"), ("rf", "0x10000", "1")):
            executable = temp / f"ota_info_{profile}"
            command = [
                compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                f"-DCONFIG_PARTITION_TABLE_OFFSET={offset}", f"-DTEST_RF_PROFILE={rf}",
                "-I", str(temp),
            ]
            if cls.parser_available:
                command += ["-DTEST_TAB5_PARSER", "-I", str(TAB5 / "main")]
            command += [str(ROOT / "tests/ota_info_host.c")]
            if cls.parser_available:
                command += [str(TAB5 / "main/ota_rf.c")]
            command += ["-o", str(executable)]
            build = subprocess.run(command, capture_output=True, text=True)
            if build.returncode:
                raise RuntimeError(f"{profile} host compile failed:\n{build.stdout}\n{build.stderr}")
            cls.executables[profile] = executable

    def report(self, profile, scenario):
        run = subprocess.run(
            [str(self.executables[profile]), scenario], capture_output=True, text=True, timeout=5
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        lines = run.stdout.splitlines()
        parser = dict(line.split("=", 1) for line in run.stderr.splitlines()) if self.parser_available else {}
        return lines, parser

    def expected_legacy(self, profile):
        offset = "0x10000" if profile == "rf" else "0x8000"
        layout = "compatible (release files still require verification)" if profile == "rf" else "incompatible"
        lines = [
            "OTA default source: classic (C5Lab/projectZero), channel=main",
            "OTA RF source: elpadrino26/janosrf-web-flasher (one-shot: ota_check rf <tag>)",
            f"OTA partition table offset: {offset}",
        ]
        if profile == "classic":
            lines.append("OTA RF: incompatible partition table offset 0x8000 (requires 0x10000); restore RF layout over USB")
        lines.extend([
            f"OTA RF layout: {layout}",
            "OTA boot: ota_0",
            "OTA running: ota_0 state=-1",
            "OTA next: ota_1",
            "APP[0]: ota_0 state=-1 ver=1.7.7",
            "APP[1]: ota_1 state=-1 ver=1.7.7",
        ])
        return lines

    def test_legacy_lines_remain_exact_and_diagnostics_are_separate(self):
        for profile in ("classic", "rf"):
            with self.subTest(profile=profile):
                lines, _ = self.report(profile, "ok_undefined")
                legacy = self.expected_legacy(profile)
                self.assertEqual(lines[:len(legacy)], legacy)
                diag = lines[len(legacy):]
                self.assertTrue(diag, "ota_info must append diagnostic lines")
                self.assertLessEqual(len(diag), 16)
                self.assertTrue(all(line.startswith("OTA_DIAG:") for line in diag), diag)
                self.assertTrue(all(len(line.encode("utf-8")) <= 511 for line in lines), lines)

    def test_ok_undefined_and_not_found_keep_legacy_value_but_explain_difference(self):
        ok_lines, _ = self.report("rf", "ok_undefined")
        missing_lines, _ = self.report("rf", "not_found")
        legacy = self.expected_legacy("rf")
        self.assertEqual(ok_lines[:len(legacy)], missing_lines[:len(legacy)])
        self.assertEqual(ok_lines[:len(legacy)], legacy)
        self.assertNotEqual(ok_lines[len(legacy):], missing_lines[len(legacy):])
        self.assertIn("unknown", " ".join(missing_lines[len(legacy):]).lower())
        self.assertIn("not_found", " ".join(missing_lines[len(legacy):]).lower())

    def test_current_tab5_parser_accepts_legacy_and_ignores_diagnostics(self):
        if not self.parser_available:
            self.skipTest("sibling Tab5 checkout unavailable")
        for profile in ("classic", "rf"):
            with self.subTest(profile=profile):
                _, parsed = self.report(profile, "ok_undefined")
                self.assertEqual(parsed["TAB5_DEFAULT"], "1")
                self.assertEqual(parsed["TAB5_RF"], "1")
                self.assertEqual(parsed["TAB5_OFFSET"], str(0x10000 if profile == "rf" else 0x8000))
                self.assertEqual(parsed["TAB5_LAYOUT"], "1" if profile == "rf" else "2")
                self.assertEqual(parsed["TAB5_BOOT"], "ota_0")
                self.assertEqual(parsed["TAB5_RUNNING"], "ota_0")
                self.assertEqual(parsed["TAB5_STATE"], "-1")
                self.assertEqual(parsed["TAB5_NEXT"], "ota_1")
                self.assertEqual(parsed["TAB5_APP0"], "1.7.7")
                self.assertEqual(parsed["TAB5_APP0_STATE"], "-1")
                self.assertEqual(parsed["TAB5_APP1"], "1.7.7")
                self.assertEqual(parsed["TAB5_APP1_STATE"], "-1")
                self.assertEqual(parsed["TAB5_DIAG_CONSUMED"], "0")


if __name__ == "__main__":
    unittest.main()
