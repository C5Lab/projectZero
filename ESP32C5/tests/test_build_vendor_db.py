import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.rfdb.build_vendor_db import build_vendor_database
from tools.rfdb.provenance import SourceRecord, canonical_lock_bytes
from tools.rfdb.vendor_format import parse_vendor_blob


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "vendor_manuf_sample.txt"


class BuildVendorDatabaseTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.output = self.root / "out" / "vendors.bin"
        self.report = self.root / "out" / "vendors.report.json"
        self.payload = FIXTURE.read_bytes()
        self.record = SourceRecord(
            id="wireshark_manuf",
            project="Wireshark",
            url="https://example.invalid/manuf",
            revision="fixture-v1",
            retrieved_utc="2026-10-13T00:00:00Z",
            sha256=hashlib.sha256(self.payload).hexdigest(),
            license="GPL-2.0-only",
            license_file="LICENSES/GPL-2.0-only.txt",
            local_name="wireshark-manuf.txt",
        )
        self.lock = self.root / "sources.lock.json"
        self.lock.write_bytes(canonical_lock_bytes([self.record]))
        (self.cache / self.record.local_name).write_bytes(self.payload)

    def test_offline_fixture_build_and_report(self):
        result = build_vendor_database(
            self.lock, self.cache, self.output, self.report
        )
        report = json.loads(self.report.read_text(encoding="utf-8"))
        self.assertEqual(report["format"], "JVND-3")
        self.assertEqual(report["counts"], {"24": 2, "28": 1, "36": 1})
        self.assertEqual(report["unsupported_prefixes"], 0)
        self.assertEqual(len(report["sha256"]), 64)
        self.assertEqual(report["sha256"], hashlib.sha256(self.output.read_bytes()).hexdigest())
        self.assertEqual(result.sha256, report["sha256"])
        image = parse_vendor_blob(self.output.read_bytes())
        self.assertEqual(image.counts, {24: 2, 28: 1, 36: 1})

    def test_repeated_build_is_byte_identical(self):
        build_vendor_database(self.lock, self.cache, self.output, self.report)
        first_blob = self.output.read_bytes()
        first_report = self.report.read_bytes()
        build_vendor_database(self.lock, self.cache, self.output, self.report)
        self.assertEqual(self.output.read_bytes(), first_blob)
        self.assertEqual(self.report.read_bytes(), first_report)

    def test_refuses_source_hash_mismatch(self):
        (self.cache / self.record.local_name).write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            build_vendor_database(self.lock, self.cache, self.output, self.report)
        self.assertFalse(self.output.exists())

    def test_missing_cache_never_contacts_network_without_refresh_flag(self):
        (self.cache / self.record.local_name).unlink()
        with mock.patch(
            "tools.rfdb.build_vendor_db.download_source",
            side_effect=AssertionError("network must remain disabled"),
        ) as downloader:
            with self.assertRaisesRegex(FileNotFoundError, "offline"):
                build_vendor_database(
                    self.lock,
                    self.cache,
                    self.output,
                    self.report,
                    refresh_source=False,
                )
        downloader.assert_not_called()

    def test_refresh_verifies_payload_before_updating_cache(self):
        (self.cache / self.record.local_name).unlink()
        with mock.patch(
            "tools.rfdb.build_vendor_db.download_source",
            return_value=b"wrong payload",
        ):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                build_vendor_database(
                    self.lock,
                    self.cache,
                    self.output,
                    self.report,
                    refresh_source=True,
                )
        self.assertFalse((self.cache / self.record.local_name).exists())
        self.assertFalse(self.output.exists())

    def test_requires_exactly_one_wireshark_source(self):
        self.lock.write_bytes(canonical_lock_bytes([]))
        with self.assertRaisesRegex(ValueError, "wireshark_manuf"):
            build_vendor_database(self.lock, self.cache, self.output, self.report)


if __name__ == "__main__":
    unittest.main()
