from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LicensingTest(unittest.TestCase):
    def test_required_license_files_and_markers(self):
        expected = {
            "LICENSE": "Apache License",
            "LICENSES/Apache-2.0.txt": "Apache License",
            "LICENSES/GPL-2.0-only.txt": "GNU GENERAL PUBLIC LICENSE",
            "LICENSES/GPL-2.0-or-later.txt": "GNU GENERAL PUBLIC LICENSE",
            "LICENSES/GPL-3.0-only.txt": "GNU GENERAL PUBLIC LICENSE",
            "THIRD_PARTY_NOTICES.md": "RF database artifacts",
        }
        for relative, marker in expected.items():
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text(encoding="utf-8")
                self.assertIn(marker, text, relative)

    def test_notices_declare_artifacts_separately(self):
        text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        self.assertIn("vendors.bin", text)
        self.assertIn("GPL-2.0-or-later", text)
        self.assertIn("wps_pin.bin", text)
        self.assertIn("GPL-3.0-only", text)
        self.assertIn("Wifite3", text)

    def test_apache_license_is_scoped_to_esp32c5(self):
        text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        self.assertIn("ESP32C5", text)
        self.assertIn("parent repository remains licensed under MIT", text)

    def test_root_license_matches_canonical_apache_text(self):
        self.assertEqual(
            (ROOT / "LICENSE").read_bytes(),
            (ROOT / "LICENSES" / "Apache-2.0.txt").read_bytes(),
        )


if __name__ == "__main__":
    unittest.main()
