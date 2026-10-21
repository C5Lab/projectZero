"""Keep the former probe test command as a production WPS-DB policy gate."""
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import test_wps_pin_db


def load_tests(loader, tests, pattern):
    # This stable fixture covers ranked lookups with/without SSIDs, direct-file
    # fallback, cache equivalence and reopen against the production C reader.
    return unittest.TestSuite([test_wps_pin_db.WpsPinDbCTest(
        "test_ranking_cache_fallback_and_ssid_rules")])


if __name__ == "__main__":
    unittest.main()
