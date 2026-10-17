import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

from tools.rfdb.build_source_bundle import build_bundle


class SourceBundleTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "tools" / "rfdb").mkdir(parents=True)
        (self.root / "LICENSES").mkdir()
        (self.root / "inputs").mkdir()
        (self.root / "tools" / "rfdb" / "generator.py").write_text(
            "# generator fixture\n", encoding="utf-8"
        )
        (self.root / "LICENSES" / "GPL-2.0-only.txt").write_text(
            "GNU GENERAL PUBLIC LICENSE\n", encoding="utf-8"
        )
        (self.root / "THIRD_PARTY_NOTICES.md").write_text(
            "# Notices\n", encoding="utf-8"
        )
        self.payload = b"fixture payload\n"
        (self.root / "inputs" / "fixture.txt").write_bytes(self.payload)
        self.lock = self.root / "tools" / "rfdb" / "sources.lock.json"
        self.lock.write_text(
            json.dumps(
                {
                    "schema": 1,
                    "sources": [
                        {
                            "id": "fixture",
                            "project": "Fixture",
                            "url": "https://example.invalid/fixture.txt",
                            "revision": "fixture-v1",
                            "retrieved_utc": "2026-10-13T00:00:00Z",
                            "sha256": hashlib.sha256(self.payload).hexdigest(),
                            "license": "GPL-2.0-only",
                            "license_file": "LICENSES/GPL-2.0-only.txt",
                            "local_name": "fixture.txt",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    def test_bundle_is_byte_identical_and_has_normalized_metadata(self):
        first = build_bundle(
            self.lock,
            self.root / "inputs",
            self.root / "a.tar",
            project_root=self.root,
        )
        second = build_bundle(
            self.lock,
            self.root / "inputs",
            self.root / "b.tar",
            project_root=self.root,
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())

        with tarfile.open(first, "r:") as archive:
            members = archive.getmembers()
            names = [member.name for member in members]
            self.assertEqual(names, sorted(names))
            self.assertEqual(len(names), len(set(names)))
            self.assertIn("inputs/fixture.txt", names)
            self.assertIn("generators/generator.py", names)
            self.assertIn("sources.lock.json", names)
            self.assertIn("LICENSES/GPL-2.0-only.txt", names)
            self.assertIn("THIRD_PARTY_NOTICES.md", names)
            self.assertIn("BUILD.md", names)
            self.assertIn("MANIFEST.sha256", names)
            for member in members:
                self.assertFalse(Path(member.name).is_absolute())
                self.assertNotIn("..", Path(member.name).parts)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertEqual(member.uname, "")
                self.assertEqual(member.gname, "")
                self.assertEqual(member.mode, 0o644)
                self.assertEqual(member.mtime, 0)

    def test_manifest_hashes_every_member_except_itself(self):
        bundle = build_bundle(
            self.lock,
            self.root / "inputs",
            self.root / "bundle.tar",
            project_root=self.root,
        )
        with tarfile.open(bundle, "r:") as archive:
            manifest = archive.extractfile("MANIFEST.sha256")
            self.assertIsNotNone(manifest)
            entries = {}
            for line in manifest.read().decode("utf-8").splitlines():
                digest, name = line.split("  ", 1)
                entries[name] = digest

            expected_names = {
                member.name
                for member in archive.getmembers()
                if member.name != "MANIFEST.sha256"
            }
            self.assertEqual(set(entries), expected_names)
            for name, digest in entries.items():
                payload = archive.extractfile(name)
                self.assertIsNotNone(payload)
                self.assertEqual(hashlib.sha256(payload.read()).hexdigest(), digest)

    def test_rejects_changed_input(self):
        (self.root / "inputs" / "fixture.txt").write_bytes(b"changed")
        with self.assertRaises(ValueError):
            build_bundle(
                self.lock,
                self.root / "inputs",
                self.root / "bundle.tar",
                project_root=self.root,
            )

    def test_script_can_be_invoked_directly(self):
        project_root = Path(__file__).resolve().parents[1]
        result = subprocess.run(
            [
                sys.executable,
                str(project_root / "tools" / "rfdb" / "build_source_bundle.py"),
                "--help",
            ],
            cwd=project_root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--inputs", result.stdout)


if __name__ == "__main__":
    unittest.main()
