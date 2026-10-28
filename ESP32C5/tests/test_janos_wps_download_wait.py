"""Run the bounded WPS quarantine wait with simulated worker state."""
from pathlib import Path
import unittest

from tests.wps_host.host_build import compile_and_run


ROOT = Path(__file__).resolve().parents[1]
WPS = ROOT / "components" / "janos_wps"


class JanosWpsDownloadWaitTest(unittest.TestCase):
    def test_worker_completion_timeout_and_mismatched_lease(self):
        compile_and_run(
            self,
            "janos_wps_download_wait_test",
            [WPS / "test/janos_wps_download_wait_test.c"],
            [WPS / "private", WPS / "include", ROOT / "tests/host_stubs"],
            expected="PASS: JanOS WPS bounded download wait",
        )


if __name__ == "__main__":
    unittest.main()
