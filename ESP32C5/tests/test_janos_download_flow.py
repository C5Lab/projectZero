"""Host integration for console admission and ROM download sequencing."""
from pathlib import Path
import unittest

from tests.wps_host.host_build import compile_and_run


ROOT = Path(__file__).resolve().parents[1]
WPS = ROOT / "components" / "janos_wps"


class JanosDownloadFlowTest(unittest.TestCase):
    def test_admission_and_download_sequences(self):
        compile_and_run(
            self,
            "janos_download_flow_test",
            [ROOT / "tests/janos_download_flow_test.c",
             ROOT / "main/janos_download_flow.c",
             ROOT / "main/janos_console_admission.c",
             WPS / "janos_radio_lease.c",
             WPS / "janos_wps_command.c"],
            [ROOT / "main", WPS / "include"],
            expected="PASS: JanOS ROM download flow",
        )


if __name__ == "__main__":
    unittest.main()
