"""Run production OTA diagnostics against controlled partition and state reads."""

import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class OtaDiagHostTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc")
        if compiler is None:
            raise RuntimeError("Host C compiler required; run under Debian WSL")
        cls.temp = tempfile.TemporaryDirectory(prefix="janos-ota-diag-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.executable = Path(cls.temp.name) / "ota_diag_host"
        build = subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
             str(ROOT / "tests/ota_diag_host.c"), "-o", str(cls.executable)],
            capture_output=True, text=True,
        )
        if build.returncode:
            raise RuntimeError(f"OTA diagnostic host compile failed:\n{build.stdout}\n{build.stderr}")

    def lines(self, scenario):
        run = subprocess.run([str(self.executable), scenario], capture_output=True,
                             text=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stderr)
        lines = run.stdout.splitlines()
        self.assertEqual(len(lines), 7)
        self.assertTrue(all(line.startswith("OTA_DIAG: ") and len(line.encode()) <= 511
                            for line in lines))
        return lines

    def test_empty_otadata_uses_runtime_layout_for_rf_and_classic(self):
        for scenario, offset in (("empty_rf", "0x00017000"),
                                 ("empty_classic", "0x0000f000")):
            with self.subTest(scenario=scenario):
                lines = self.lines(scenario)
                self.assertIn(f"offset={offset}", lines[3])
                self.assertIn("record[0] empty=yes", lines[4])
                self.assertIn("record[1] empty=yes", lines[5])
                self.assertIn("selection=none reason=both_records_rejected boot=ota_0", lines[6])

    def test_bad_crc_does_not_select_nonempty_record(self):
        lines = self.lines("bad_crc")
        self.assertIn("record[0] empty=no seq=1", lines[4])
        self.assertIn("crc_stored=0x4743989b crc_calc=0x4743989a crc_ok=no selectable=no", lines[4])
        self.assertIn("selection=none reason=no_valid_record boot=ota_0", lines[6])

    def test_one_valid_and_one_corrupt_selects_valid_record(self):
        lines = self.lines("one_good_one_bad")
        self.assertIn("record[0] empty=no seq=1", lines[4])
        self.assertIn("crc_ok=yes selectable=yes", lines[4])
        self.assertIn("crc_ok=no selectable=no", lines[5])
        self.assertIn("selection=entry0 slot=ota_0 boot_match=yes", lines[6])

    def test_two_valid_records_select_higher_sequence_and_tie_prefers_zero(self):
        self.assertIn("selection=entry1 slot=ota_1 boot_match=yes", self.lines("two_good")[6])
        self.assertIn("selection=entry0 slot=ota_0 boot_match=yes", self.lines("tie")[6])

    def test_invalid_and_aborted_are_not_selectable_even_with_good_crc(self):
        lines = self.lines("invalid_aborted")
        self.assertIn("state=0x00000003", lines[4])
        self.assertIn("crc_ok=yes selectable=no", lines[4])
        self.assertIn("state=0x00000004", lines[5])
        self.assertIn("crc_ok=yes selectable=no", lines[5])
        self.assertIn("selection=none reason=both_records_rejected boot=ota_0", lines[6])

    def test_missing_and_short_partition_do_not_guess_records(self):
        for scenario, reason in (("missing_partition", "partition_missing"),
                                 ("short_partition", "partition_geometry")):
            with self.subTest(scenario=scenario):
                lines = self.lines(scenario)
                self.assertIn(f"otadata=unknown reason={reason}", lines[3])
                self.assertIn(f"record[0]=unknown reason={reason}", lines[4])
                self.assertIn(f"record[1]=unknown reason={reason}", lines[5])
                self.assertIn(f"selection=unknown reason={reason}", lines[6])

    def test_read_error_keeps_good_record_but_selection_unknown(self):
        lines = self.lines("read_error")
        self.assertIn("record[0] empty=no seq=1", lines[4])
        self.assertIn("record[1]=unknown reason=read_error", lines[5])
        self.assertIn("selection=unknown reason=record_read_error", lines[6])

    def test_esp_ok_undefined_is_distinct_from_not_found_and_other_error(self):
        self.assertIn("state running result=ok value=undefined(0xffffffff)",
                      self.lines("state_undefined")[0])
        self.assertIn("state running result=not_found value=unknown reason=ESP_ERR_NOT_FOUND",
                      self.lines("state_not_found")[0])
        self.assertIn("state running result=error value=unknown err=0xffffffff",
                      self.lines("state_error")[0])
        self.assertIn("reason=state_api_error", self.lines("state_error")[0])
        self.assertIn("state running result=ok value=unknown(0x12345678) reason=unrecognized_state",
                      self.lines("state_unrecognized")[0])
        self.assertIn("selection=entry0 slot=ota_0 boot_match=yes anomaly=state_unrecognized",
                      self.lines("state_unrecognized")[6])

    def test_seq_zero_uses_idf_unsigned_wraparound_with_anomaly(self):
        self.assertIn("selection=entry0 slot=ota_1 boot_match=no anomaly=seq_zero",
                      self.lines("seq_zero")[6])

    def test_missing_apps_keeps_selection_unknown(self):
        self.assertIn("selection=unknown reason=no_ota_apps", self.lines("no_apps")[6])

    def test_boot_selection_mismatch_is_visible(self):
        self.assertIn("selection=entry1 slot=ota_1 boot_match=no",
                      self.lines("boot_mismatch")[6])
        self.assertIn("selection=entry0 slot=ota_0 boot_match=no",
                      self.lines("boot_external_chip")[6])

    def test_missing_boot_partition_does_not_claim_why_idf_returned_null(self):
        self.assertIn("selection=none reason=both_records_rejected boot=unknown boot_reason=boot_unavailable",
                      self.lines("boot_unavailable")[6])

    def test_diagnostic_has_no_flash_writer_calls(self):
        source = (ROOT / "main/ota_diag.c").read_text(encoding="utf-8")
        forbidden = ("esp_partition_write", "esp_partition_erase_range", "esp_ota_begin",
                     "esp_ota_set_boot_partition", "esp_ota_mark_app_valid_cancel_rollback",
                     "esp_ota_mark_app_invalid_rollback", "esp_restart")
        for name in forbidden:
            with self.subTest(name=name):
                self.assertIsNone(re.search(r"\b" + name + r"\s*\(", source))

    def test_host_undefined_value_matches_selected_idf_header(self):
        idf_path = os.environ.get("IDF_PATH")
        description = ROOT / "build/project_description.json"
        if not idf_path and description.exists():
            idf_path = json.loads(description.read_text(encoding="utf-8"))["idf_path"]
        if not idf_path:
            self.skipTest("selected ESP-IDF checkout unavailable")
        if os.name != "nt" and re.match(r"^[A-Za-z]:[/\\]", idf_path):
            idf_path = "/mnt/" + idf_path[0].lower() + "/" + idf_path[3:].replace("\\", "/")
        header = Path(idf_path) / "components/bootloader_support/include/esp_flash_partitions.h"
        self.assertTrue(header.is_file(), f"ESP-IDF header missing: {header}")
        self.assertRegex(header.read_text(encoding="utf-8"),
                         r"ESP_OTA_IMG_UNDEFINED\s*=\s*0xFFFFFFFFU")


if __name__ == "__main__":
    unittest.main()
