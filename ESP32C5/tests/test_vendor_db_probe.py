"""Keep the former probe test command as a production vendor-DB policy gate."""
import unittest

import test_vendor_db


def load_tests(loader, tests, pattern):
    # The removed prompt had no production parser. Exercise its useful lookup,
    # fallback and remount policies through the real production reader instead.
    return unittest.TestSuite(test_vendor_db.VendorDbCTest(name) for name in (
        "test_longest_prefix_cached_lookup",
        "test_allocation_failure_uses_direct_file_fallback",
        "test_close_and_reopen",
    ))


if __name__ == "__main__":
    unittest.main()
