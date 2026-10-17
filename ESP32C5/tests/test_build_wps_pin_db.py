import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.rfdb.build_wps_pin_db import build_wps_pin_database
from tools.rfdb.provenance import SourceRecord, canonical_lock_bytes
from tools.rfdb.wps_format import parse_wps_blob


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


class BuildWpsPinDatabaseTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.output = self.root / "out" / "wps_pin.bin"
        self.report = self.root / "out" / "wps_pin.report.json"
        inputs = [
            ("airgeddon_known_pins", "known_pins_sample.db"),
            ("default_wps_pins", "default_wps_pins_sample.csv"),
        ]
        self.records = []
        for source_id, filename in inputs:
            payload = (FIXTURES / filename).read_bytes()
            record = SourceRecord(
                id=source_id,
                project=source_id,
                url=f"https://example.invalid/{filename}",
                revision="fixture-v1",
                retrieved_utc="2026-10-13T00:00:00Z",
                sha256=hashlib.sha256(payload).hexdigest(),
                license="GPL-3.0-only",
                license_file="LICENSES/GPL-3.0-only.txt",
                local_name=filename,
            )
            self.records.append(record)
            (self.cache / filename).write_bytes(payload)
        self.lock = self.root / "sources.lock.json"
        self.lock.write_bytes(canonical_lock_bytes(self.records))

    def test_offline_build_reports_unsupported_arcadyan(self):
        result = build_wps_pin_database(
            self.lock, self.cache, self.output, self.report,
            allow_unsupported_report=True,
        )
        report = json.loads(self.report.read_text(encoding="utf-8"))
        self.assertEqual(report["format"], "JWPS-2")
        self.assertEqual(report["invalid_checksum_rows_preserved"], 2)
        self.assertEqual(report["invalid_checksum_associations_preserved"], 1)
        self.assertEqual(report["unsupported_algorithm_mappings"], 1)
        self.assertEqual(report["unsupported_ouis"], ["00CCDD"])
        self.assertEqual(result.sha256, hashlib.sha256(self.output.read_bytes()).hexdigest())
        image = parse_wps_blob(self.output.read_bytes())
        self.assertEqual(image.dataset.oui_algorithms["00CCDD"], ["asus", "arcadyan"])

    def test_refuses_publish_with_unsupported_mapping_by_default(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            build_wps_pin_database(self.lock, self.cache, self.output, self.report)
        self.assertFalse(self.output.exists())

    def test_repeated_build_is_byte_identical(self):
        kwargs = {"allow_unsupported_report": True}
        build_wps_pin_database(self.lock, self.cache, self.output, self.report, **kwargs)
        blob, report = self.output.read_bytes(), self.report.read_bytes()
        build_wps_pin_database(self.lock, self.cache, self.output, self.report, **kwargs)
        self.assertEqual(blob, self.output.read_bytes())
        self.assertEqual(report, self.report.read_bytes())

    def test_missing_cache_does_not_contact_network(self):
        (self.cache / self.records[0].local_name).unlink()
        with mock.patch("tools.rfdb.build_wps_pin_db.download_source",
                        side_effect=AssertionError("network disabled")) as downloader:
            with self.assertRaisesRegex(FileNotFoundError, "offline"):
                build_wps_pin_database(self.lock, self.cache, self.output, self.report,
                                       allow_unsupported_report=True)
        downloader.assert_not_called()

    def test_hash_mismatch_is_rejected_before_output(self):
        (self.cache / self.records[0].local_name).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            build_wps_pin_database(self.lock, self.cache, self.output, self.report,
                                   allow_unsupported_report=True)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
