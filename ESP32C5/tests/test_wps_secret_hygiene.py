from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCANNED_ROOTS = (
    ROOT / "components" / "janos_wps" / "test",
    ROOT / "tests",
    ROOT / "docs",
)

# Do not spell known lab credentials in source.  Constructing these probes at
# runtime keeps this regression test from becoming the leak it is detecting.
FORBIDDEN = (
    "6098" + "0465",
    "4698" + "0229",
    "Sara" + "1980",
)
TEXT_SUFFIXES = {".c", ".h", ".py", ".md", ".txt", ".json"}


class WpsSecretHygieneTest(unittest.TestCase):
    def test_known_lab_credentials_are_absent_from_tests_and_docs(self):
        findings = []
        for root in SCANNED_ROOTS:
            for path in root.rglob("*"):
                if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                for secret in FORBIDDEN:
                    if secret in text:
                        findings.append(str(path.relative_to(ROOT)))
        self.assertEqual([], sorted(set(findings)))


if __name__ == "__main__":
    unittest.main()
