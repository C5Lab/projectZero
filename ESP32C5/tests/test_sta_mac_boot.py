"""Compile and exercise the portable STA MAC boot state against a memory store."""
from pathlib import Path
import unittest

from wps_host.host_build import compile_and_run


ROOT = Path(__file__).resolve().parents[1]


class StaMacBootTest(unittest.TestCase):
    def test_boot_state_and_driver_application(self):
        compile_and_run(
            self, "sta_mac_boot_test",
            [ROOT / "tests/sta_mac_boot_test.c",
             ROOT / "main/sta_mac_boot.c",
             ROOT / "main/sta_mac_policy_core.c",
             ROOT / "main/sta_mac_policy_store.c"],
            [ROOT / "main"], expected="PASS: STA MAC boot",
            extra_flags=("-pedantic",))


if __name__ == "__main__":
    unittest.main()
