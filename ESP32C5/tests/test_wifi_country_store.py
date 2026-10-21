"""Exercise real NVS country storage across firmware changes and ordinary boots."""
from pathlib import Path
import unittest

from wps_host.host_build import compile_and_run

ROOT = Path(__file__).resolve().parents[1]


class WifiCountryStoreTest(unittest.TestCase):
    def test_firmware_reset_and_persistence(self):
        compile_and_run(
            self, "wifi_country_store_test",
            [ROOT / "tests/wifi_country_store_test.c",
             ROOT / "main/wifi_country_store.c",
             ROOT / "main/wifi_country_policy.c"],
            [ROOT / "tests/host_stubs/wifi_country", ROOT / "main"],
            extra_flags=("-pedantic", "-fsanitize=address,undefined"),
            expected="PASS: country resets to PA per firmware image; reboot persistence, migration and storage failures",
        )


if __name__ == "__main__":
    unittest.main()
