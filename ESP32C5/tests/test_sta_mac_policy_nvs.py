"""Exercise the production STA MAC NVS adapter through a fake NVS boundary."""
from pathlib import Path
import unittest

from wps_host.host_build import compile_and_run

ROOT = Path(__file__).resolve().parents[1]


class StaMacPolicyNvsTest(unittest.TestCase):
    def test_nvs_store(self):
        compile_and_run(
            self,
            "sta_mac_policy_nvs_test",
            [ROOT / "tests/sta_mac_policy_nvs_test.c",
             ROOT / "main/sta_mac_policy_nvs.c",
             ROOT / "main/sta_mac_policy_store.c",
             ROOT / "main/sta_mac_policy_core.c"],
            [ROOT / "tests/host_stubs/sta_mac_nvs", ROOT / "main"],
            extra_flags=("-pedantic",),
            expected="PASS: STA MAC NVS adapter missing, roundtrip, invalid records, failures",
        )


if __name__ == "__main__":
    unittest.main()
