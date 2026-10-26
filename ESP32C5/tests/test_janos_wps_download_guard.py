"""Compile and run the WPS quarantine-to-download guard on a host."""
from pathlib import Path
import unittest

from tests.wps_host.host_build import compile_and_run


ROOT = Path(__file__).resolve().parents[1]
WPS = ROOT / "components" / "janos_wps"


class JanosWpsDownloadGuardTest(unittest.TestCase):
    def test_only_joined_quarantined_owner_can_reset_to_rom(self):
        compile_and_run(
            self,
            "janos_wps_download_guard_test",
            [WPS / "test/janos_wps_download_guard_test.c"],
            [WPS / "include", ROOT / "tests/host_stubs"],
            expected="PASS: JanOS WPS quarantined download guard",
        )


if __name__ == "__main__":
    unittest.main()
