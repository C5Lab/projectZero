from pathlib import Path
import unittest

from tools.rfdb.wps_sources import (
    ALGO_ALIASES,
    load_airgeddon,
    load_default_wps,
    normalize_oui,
    normalize_pin,
    normalize_source_pin,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


class WpsSourceTest(unittest.TestCase):
    def test_pin_normalization_is_strict_and_preserves_leading_zero(self):
        self.assertEqual(normalize_pin("1234567"), "12345670")
        self.assertEqual(normalize_pin("0000000"), "00000000")
        self.assertEqual(normalize_pin("00000000"), "00000000")
        self.assertIsNone(normalize_pin("12345678"))
        self.assertIsNone(normalize_pin("12-34567"))
        self.assertIsNone(normalize_pin("123456"))
        self.assertIsNone(normalize_pin("abcdefgh"))
        self.assertEqual(normalize_source_pin("12345678"), "12345678")
        self.assertEqual(normalize_source_pin("1234567"), "12345670")

    def test_oui_normalization_accepts_common_separators(self):
        self.assertEqual(normalize_oui("00:aa:BB"), "00AABB")
        self.assertEqual(normalize_oui("00-aa-bb"), "00AABB")
        self.assertEqual(normalize_oui("00AABB"), "00AABB")
        self.assertIsNone(normalize_oui("00:11"))
        self.assertIsNone(normalize_oui("zz:11:22"))

    def test_airgeddon_deduplicates_in_first_seen_order(self):
        parsed, report = load_airgeddon(
            (FIXTURES / "known_pins_sample.db").read_text(encoding="utf-8")
        )
        self.assertEqual(parsed["00AABB"], ["12345670", "00000000"])
        self.assertEqual(parsed["00CCDD"], ["76543210", "12345678"])
        self.assertEqual(report.accepted, 4)
        self.assertEqual(report.duplicates, 1)
        self.assertEqual(report.invalid_checksums_preserved, 1)
        self.assertEqual(report.malformed, 2)

    def test_default_source_merges_pins_and_algorithm_aliases(self):
        existing = {"00AABB": ["12345670"]}
        pins, algorithms, report = load_default_wps(
            (FIXTURES / "default_wps_pins_sample.csv").read_text(encoding="utf-8"),
            existing,
        )
        self.assertEqual(pins["00AABB"], ["12345670", "00000000"])
        self.assertEqual(pins["00CCDD"], ["23456785", "12345678"])
        self.assertEqual(algorithms["00AABB"], ["zhao"])
        self.assertEqual(algorithms["00CCDD"], ["asus", "arcadyan"])
        self.assertEqual(report.duplicates, 2)
        self.assertEqual(report.invalid_checksums_preserved, 1)
        self.assertEqual(report.unknown_algorithms, {"unknownalgo": 1})
        self.assertEqual(report.malformed, 1)

    def test_alias_table_is_stable(self):
        self.assertEqual(ALGO_ALIASES["thirtytwo"], "computepin_32")
        self.assertEqual(ALGO_ALIASES["twentyeight"], "computepin_28")
        self.assertEqual(ALGO_ALIASES["trend"], "trendnet")
        self.assertEqual(ALGO_ALIASES["arcady"], "arcadyan")


if __name__ == "__main__":
    unittest.main()
