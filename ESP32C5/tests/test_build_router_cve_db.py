import json
import hashlib
from pathlib import Path
import tempfile
import unittest

from tools.cvedb.build_catalog import build_catalog_file, main
from tools.cvedb.catalog_format import parse_catalog


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "tests" / "fixtures" / "router_cve_manifest_v1.json"
FIXTURE = ROOT / "tests" / "fixtures" / "router_cve_v1.bin"


class BuildRouterCveDbTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root / "catalog.bin"
        self.report = self.root / "catalog.report.json"

    def test_offline_build_is_atomic_and_reports_provenance(self):
        result = build_catalog_file(MANIFEST, self.output, self.report)
        self.assertEqual(self.output.read_bytes(), FIXTURE.read_bytes())
        report = json.loads(self.report.read_text(encoding="utf-8"))
        image = parse_catalog(self.output.read_bytes())
        self.assertEqual(report["format"], "JCVE/1")
        self.assertEqual(report["serial"], 7)
        self.assertEqual(report["sha256"], result.sha256)
        self.assertEqual(report["provenance_sha256"], image.provenance_sha256.hex())
        self.assertEqual(report["counts"], {
            "advisories": 2,
            "aliases": 2,
            "firmware_rules": 4,
            "models": 2,
            "sources": 1,
        })

    def test_failed_manifest_leaves_existing_outputs_unchanged(self):
        self.output.write_bytes(b"old-catalog")
        self.report.write_bytes(b"old-report")
        bad = self.root / "bad.json"
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        data["sources"][0]["url"] = "http://not-reviewed.invalid/source"
        bad.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError):
            build_catalog_file(bad, self.output, self.report)
        self.assertEqual(self.output.read_bytes(), b"old-catalog")
        self.assertEqual(self.report.read_bytes(), b"old-report")

    def test_source_metadata_must_match_the_offline_lock(self):
        changed = self.root / "changed-source.json"
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        data["sources"][0]["revision"] = "unreviewed-revision"
        changed.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source lock"):
            build_catalog_file(changed, self.output, self.report)
        self.assertFalse(self.output.exists())
        self.assertFalse(self.report.exists())

    def test_source_lock_and_manifest_order_do_not_change_output(self):
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        second = dict(data["sources"][0])
        second.update({
            "id": "test-second-source",
            "url": "https://second.example.invalid/advisories",
            "revision": "fixture-rev-2",
            "sha256": "f" * 64,
        })
        data["sources"].append(second)
        lock_data = {
            "schema": "janos-router-cve-sources-lock-v1",
            "status": "test-fixture-only",
            "sources": list(reversed(data["sources"])),
        }
        changed = self.root / "two-sources.json"
        lock = self.root / "two-sources.lock.json"
        changed.write_text(json.dumps(data), encoding="utf-8")
        lock.write_text(json.dumps(lock_data), encoding="utf-8")
        result = build_catalog_file(changed, self.output, self.report, lock)
        first = self.output.read_bytes()
        data["sources"].reverse()
        changed.write_text(json.dumps(data), encoding="utf-8")
        build_catalog_file(changed, self.output, self.report, lock)
        self.assertEqual(self.output.read_bytes(), first)
        self.assertEqual(result.size, len(first))

    def test_cli_requires_local_manifest_and_never_has_network_option(self):
        with self.assertRaises(SystemExit) as missing:
            main([])
        self.assertNotEqual(missing.exception.code, 0)
        code = main([
            "--manifest", str(MANIFEST),
            "--output", str(self.output),
            "--report", str(self.report),
        ])
        self.assertEqual(code, 0)
        self.assertEqual(self.output.read_bytes(), FIXTURE.read_bytes())

    def test_reviewed_source_lock_requires_explicit_official_governance(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        manifest["sources"][0]["revision"] = "1" * 40
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        source = manifest["sources"][0]
        lock = {
            "schema": "janos-router-cve-sources-lock-v2",
            "status": "reviewed",
            "sources": [source],
            "governance": [{
                "id": source["id"],
                "authority": "cna",
                "redistribution": False,
                "license_file": None,
            }],
        }
        lock_path = self.root / "sources.lock.json"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        build_catalog_file(manifest_path, self.output, self.report, lock_path)
        self.assertEqual(parse_catalog(self.output.read_bytes()).serial, 7)
        report = json.loads(self.report.read_text(encoding="utf-8"))
        canonical_lock = (json.dumps(lock, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")) + "\n").encode("utf-8")
        self.assertEqual(report["source_lock_schema"], lock["schema"])
        self.assertEqual(report["source_lock_status"], "reviewed")
        self.assertEqual(report["source_lock_sha256"],
                         hashlib.sha256(canonical_lock).hexdigest())

        for field, value in (("authority", "community"),
                             ("authority", ""),
                             ("license_file", "LICENSES/missing.txt")):
            changed = json.loads(json.dumps(lock))
            changed["governance"][0][field] = value
            if field == "license_file":
                changed["governance"][0]["redistribution"] = True
            lock_path.write_text(json.dumps(changed), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source governance"):
                build_catalog_file(manifest_path, self.output, self.report, lock_path)

        traversal = json.loads(json.dumps(lock))
        traversal["governance"][0]["redistribution"] = True
        traversal["governance"][0]["license_file"] = "../outside-license.txt"
        lock_path.write_text(json.dumps(traversal), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source governance"):
            build_catalog_file(manifest_path, self.output, self.report, lock_path)

        invalid_revisions = (
            "latest", "main", "master", "trunk", "development",
            "refs/heads/main", "refs/tags/v1.2.3", "origin/main",
            "heads/main", "tags/v1.2.3", "HEAD", "deadbeef", "A" * 40,
            "snapshot-20261103T120000Z-" + "a" * 63,
            "snapshot-20261303T120000Z-" + "a" * 64,
            "snapshot-20261103-" + "a" * 64,
        )
        for revision in invalid_revisions:
            moving_manifest = json.loads(json.dumps(manifest))
            moving_manifest["sources"][0]["revision"] = revision
            manifest_path.write_text(json.dumps(moving_manifest), encoding="utf-8")
            moving_lock = json.loads(json.dumps(lock))
            moving_lock["sources"][0]["revision"] = revision
            lock_path.write_text(json.dumps(moving_lock), encoding="utf-8")
            with self.subTest(revision=revision):
                with self.assertRaisesRegex(ValueError, "source governance"):
                    build_catalog_file(manifest_path, self.output, self.report,
                                       lock_path)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        valid_revisions = (
            "2" * 64,
            "snapshot-20261103T120000Z-" + "a" * 64,
        )
        for revision in valid_revisions:
            pinned = json.loads(json.dumps(lock))
            pinned["sources"][0]["revision"] = revision
            pinned_manifest = json.loads(json.dumps(manifest))
            pinned_manifest["sources"][0]["revision"] = revision
            manifest_path.write_text(json.dumps(pinned_manifest), encoding="utf-8")
            lock_path.write_text(json.dumps(pinned), encoding="utf-8")
            with self.subTest(valid_revision=revision):
                build_catalog_file(manifest_path, self.output, self.report,
                                   lock_path)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        licenses = self.root / "LICENSES"
        licenses.mkdir()
        (licenses / "source-license.txt").write_text("fixture license\n", encoding="utf-8")
        lock["governance"][0]["redistribution"] = True
        lock["governance"][0]["license_file"] = "LICENSES/source-license.txt"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        build_catalog_file(manifest_path, self.output, self.report, lock_path)

    def test_reviewed_status_is_not_accepted_under_test_only_lock_schema(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        manifest_path = self.root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        lock = json.loads((ROOT / "tools/cvedb/sources.lock.json").read_text(
            encoding="utf-8"))
        lock["status"] = "reviewed"
        lock_path = self.root / "sources.lock.json"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source governance"):
            build_catalog_file(manifest_path, self.output, self.report, lock_path)

    def test_repository_default_remains_synthetic_fixture_only(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        lock = json.loads((ROOT / "tools/cvedb/sources.lock.json").read_text(
            encoding="utf-8"))
        self.assertEqual(lock["status"], "test-fixture-only")
        self.assertTrue(all(item["cve"].startswith("CVE-2099-")
                            for item in manifest["advisories"]))
        self.assertTrue(all(".invalid/" in item["url"]
                            for item in manifest["sources"]))
        self.assertEqual(list((ROOT / "tools/cvedb").glob("*.bin")), [])
        self.assertEqual(list((ROOT / "tools/cvedb").glob("*.sig")), [])


if __name__ == "__main__":
    unittest.main()
