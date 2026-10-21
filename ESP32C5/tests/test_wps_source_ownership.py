"""Guard production WPS sources against dependencies on standalone test projects."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
REMOVED_PROJECTS = {
    "c5_wps_probe", "c5_wps_m3", "c5_wps_pin_session", "c5_wps_pixie",
    "c5_wps_pixie_session", "c5_wps_campaign", "c5_wps_lab_suite",
    "c5_wps_transport", "c5_wps_fragment_replay", "c5_wps_db_probe",
    "c5_vendor_db_probe", "c5_sta_mac_policy", "c5_crypto_bench",
}
SOURCE_SUFFIXES = {".c", ".h", ".cc", ".cpp", ".cxx", ".hh", ".hpp",
                   ".hxx", ".s", ".cmake", ".txt"}


class WpsSourceOwnershipTest(unittest.TestCase):
    def test_standalone_projects_are_removed(self):
        present = sorted(
            name for name in REMOVED_PROJECTS if (ROOT / "tests" / name).exists()
        )
        self.assertEqual([], present)

    def test_production_does_not_consume_tests(self):
        offenders = []
        for root in (ROOT / "components", ROOT / "main"):
            for path in root.rglob("*"):
                if path.suffix.lower() not in SOURCE_SUFFIXES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                if "tests/c5_" in text or "tests\\c5_" in text:
                    offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual([], offenders)


if __name__ == "__main__":
    unittest.main()
