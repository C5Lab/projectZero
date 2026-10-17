import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from tools.rfdb.provenance import (
    SourceRecord,
    canonical_lock_bytes,
    load_lock,
    verify_bytes,
)


def valid_record(**overrides):
    payload = b"fixture"
    record = {
        "id": "fixture",
        "project": "Fixture",
        "url": "https://example.invalid/a",
        "revision": "fixture-1",
        "retrieved_utc": "2026-10-13T00:00:00Z",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "license": "GPL-2.0-only",
        "license_file": "LICENSES/GPL-2.0-only.txt",
        "local_name": "fixture.txt",
    }
    record.update(overrides)
    return record


class ProvenanceTest(unittest.TestCase):
    def write_lock(self, document):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "sources.lock.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def test_loads_valid_record(self):
        records = load_lock(
            self.write_lock({"schema": 1, "sources": [valid_record()]})
        )
        self.assertEqual(len(records), 1)
        self.assertIsInstance(records[0], SourceRecord)
        self.assertEqual(records[0].id, "fixture")

    def test_hash_match_and_mismatch(self):
        record = valid_record()
        verify_bytes(record, b"fixture")
        with self.assertRaises(ValueError):
            verify_bytes(record, b"changed")

    def test_rejects_missing_and_unknown_fields(self):
        missing = valid_record()
        missing.pop("project")
        with self.assertRaises(ValueError):
            load_lock(self.write_lock({"schema": 1, "sources": [missing]}))

        unknown = valid_record(extra="nope")
        with self.assertRaises(ValueError):
            load_lock(self.write_lock({"schema": 1, "sources": [unknown]}))

    def test_rejects_duplicate_ids(self):
        duplicate = valid_record(local_name="other.txt")
        with self.assertRaises(ValueError):
            load_lock(
                self.write_lock(
                    {"schema": 1, "sources": [valid_record(), duplicate]}
                )
            )

    def test_rejects_non_https_url(self):
        with self.assertRaises(ValueError):
            load_lock(
                self.write_lock(
                    {"schema": 1, "sources": [valid_record(url="http://example/a")]}
                )
            )

    def test_rejects_bad_hash(self):
        for digest in ("ABC", "A" * 64, "g" * 64):
            with self.subTest(digest=digest):
                with self.assertRaises(ValueError):
                    load_lock(
                        self.write_lock(
                            {"schema": 1, "sources": [valid_record(sha256=digest)]}
                        )
                    )

    def test_rejects_unsupported_license(self):
        with self.assertRaises(ValueError):
            load_lock(
                self.write_lock(
                    {"schema": 1, "sources": [valid_record(license="MIT")]}
                )
            )

    def test_accepts_gpl_2_or_later(self):
        record = valid_record(
            license="GPL-2.0-or-later",
            license_file="LICENSES/GPL-2.0-or-later.txt",
        )
        loaded = load_lock(self.write_lock({"schema": 1, "sources": [record]}))
        self.assertEqual(loaded[0].license, "GPL-2.0-or-later")

    def test_rejects_unsafe_local_name(self):
        for name in ("../fixture.txt", "/fixture.txt", "nested/fixture.txt", "C:\\fixture.txt"):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    load_lock(
                        self.write_lock(
                            {"schema": 1, "sources": [valid_record(local_name=name)]}
                        )
                    )

    def test_rejects_floating_revision(self):
        for revision in ("main", "master", "HEAD"):
            with self.subTest(revision=revision):
                with self.assertRaises(ValueError):
                    load_lock(
                        self.write_lock(
                            {"schema": 1, "sources": [valid_record(revision=revision)]}
                        )
                    )

    def test_canonical_json_is_stable_and_has_final_newline(self):
        first = SourceRecord(**valid_record())
        second = SourceRecord(
            **valid_record(id="another", local_name="another.txt", revision="v2")
        )
        encoded = canonical_lock_bytes([first, second])
        self.assertTrue(encoded.endswith(b"\n"))
        self.assertEqual(encoded, canonical_lock_bytes([first, second]))
        document = json.loads(encoded)
        self.assertEqual(document["schema"], 1)
        self.assertEqual([row["id"] for row in document["sources"]], ["another", "fixture"])


if __name__ == "__main__":
    unittest.main()
