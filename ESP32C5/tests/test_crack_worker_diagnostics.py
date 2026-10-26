import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class CrackWorkerDiagnosticsContractTest(unittest.TestCase):
    def test_janos_version_matches_between_cmake_and_main(self):
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        cmake_version = re.search(r'(?m)^set\(JANOS_VERSION "(\d+\.\d+\.\d+)"\)$', cmake)
        main_version = re.search(r'(?m)^#define JANOS_VERSION "(\d+\.\d+\.\d+)"$', main)
        self.assertIsNotNone(cmake_version)
        self.assertIsNotNone(main_version)
        self.assertEqual(cmake_version.group(1), main_version.group(1))

    def test_ack32_receiver_records_live_component_boundaries(self):
        source = (ROOT / "main/crack_worker.c").read_text(encoding="utf-8")
        for phase in (
            "header_first",
            "header_rest",
            "payload_read",
            "sd_write",
            "checkpoint",
            "ack_write",
            "ack_sent",
        ):
            self.assertIn(f'cw_diag_stage("{phase}"', source)

        for field in (
            "read_calls",
            "read_bytes",
            "sd_write_calls",
            "sd_write_bytes",
            "ack_attempts",
            "acks_sent",
            "checkpoint_calls",
            "stage_us",
        ):
            self.assertIn(field, source)

    def test_diag_wire_record_stays_single_line_and_machine_readable(self):
        source = (ROOT / "main/crack_worker.c").read_text(encoding="utf-8")
        diag = re.search(
            r"static int cw_diag\(.*?\n\}", source, flags=re.DOTALL
        )
        self.assertIsNotNone(diag)
        text = diag.group(0)
        for token in ("rd=", "rb=", "sd=", "sb=", "aa=", "as=", "cp=", "stage_us="):
            self.assertIn(token, text)

    def test_ack32_completion_does_not_clobber_the_precise_live_phase(self):
        source = (ROOT / "main/crack_worker.c").read_text(encoding="utf-8")
        tail = re.search(
            r"success = crack_worker_transfer_receive\(.*?goto raw_done;",
            source,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(tail)
        self.assertNotIn("cw_transfer_diag.phase", tail.group(0))


if __name__ == "__main__":
    unittest.main()
