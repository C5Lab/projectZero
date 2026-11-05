"""Compile and execute the bounded firmware-side JCVE/1 reader."""
from pathlib import Path
import binascii
import copy
import hashlib
import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest

from tools.cvedb.catalog_format import build_catalog


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/router_cve_v1.bin"
MANIFEST = ROOT / "tests/fixtures/router_cve_manifest_v1.json"
CANONICAL_STRINGS = ROOT / "tests/fixtures/router_cve_canonical_strings_v1.json"
HEADER_SIZE = 192


def _rewrite_integrity(blob):
    payload = blob[HEADER_SIZE:]
    struct.pack_into("<I", blob, 16, binascii.crc32(payload) & 0xFFFFFFFF)
    blob[48:80] = hashlib.sha256(payload).digest()


def _rewrite_provenance(blob, sources):
    canonical = (json.dumps({"sources": sorted(sources, key=lambda item: item["id"])},
                            ensure_ascii=False, sort_keys=True,
                            separators=(",", ":")) + "\n").encode("utf-8")
    blob[80:112] = hashlib.sha256(canonical).digest()


def _source_string_location(blob, field):
    source_offset = struct.unpack_from("<I", blob, 128)[0]
    strings_offset = struct.unpack_from("<I", blob, 168)[0]
    relative = struct.unpack_from("<I", blob, source_offset + field * 4)[0]
    length = blob[strings_offset + relative]
    return strings_offset + relative + 1, length


def write_semantic_mutations(directory):
    original = bytearray(FIXTURE.read_bytes())
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    corpus = json.loads(CANONICAL_STRINGS.read_text(encoding="utf-8"))
    cases = [
        ("bad_retrieved.bin", 2, "2099-99-99T99:99:99Z", "retrieved_utc"),
        ("bad_port.bin", 1, "https://security.example:9999999/advisories", "url"),
    ]
    for filename, field, replacement, key in cases:
        changed = bytearray(original)
        start, length = _source_string_location(changed, field)
        encoded = replacement.encode("ascii")
        assert len(encoded) == length
        changed[start:start + length] = encoded
        sources = copy.deepcopy(manifest["sources"])
        sources[0][key] = replacement
        _rewrite_provenance(changed, sources)
        _rewrite_integrity(changed)
        (Path(directory) / filename).write_bytes(changed)

    mutations = {}
    changed = bytearray(original)
    changed[20] = 1
    mutations["reserved.bin"] = changed
    changed = bytearray(original)
    struct.pack_into("<I", changed, 136, 192)
    _rewrite_integrity(changed)
    mutations["overlap.bin"] = changed
    changed = bytearray(original)
    source_offset = struct.unpack_from("<I", changed, 128)[0]
    struct.pack_into("<I", changed, source_offset, 0xFFFFFFFE)
    _rewrite_integrity(changed)
    mutations["bad_string_offset.bin"] = changed
    changed = bytearray(original)
    alias_offset = struct.unpack_from("<I", changed, 144)[0]
    struct.pack_into("<I", changed, alias_offset + 12, 1)
    _rewrite_integrity(changed)
    mutations["alias_primary_collision.bin"] = changed
    changed = bytearray(original)
    advisory_offset = struct.unpack_from("<I", changed, 152)[0]
    changed[advisory_offset + 31] = 1
    _rewrite_integrity(changed)
    mutations["advisory_reserved.bin"] = changed
    changed = bytearray(original)
    strings_offset = struct.unpack_from("<I", changed, 168)[0]
    published_relative = struct.unpack_from("<I", changed, advisory_offset + 12)[0]
    published_start = strings_offset + published_relative + 1
    changed[published_start:published_start + 10] = b"+099-01-02"
    _rewrite_integrity(changed)
    mutations["bad_published.bin"] = changed
    changed = bytearray(original)
    changed[published_start:published_start + 10] = b"0000-01-02"
    _rewrite_integrity(changed)
    mutations["zero_year.bin"] = changed
    changed = bytearray(original)
    strings_offset = struct.unpack_from("<I", changed, 168)[0]
    changed[strings_offset + 1] = 0xFF
    _rewrite_integrity(changed)
    mutations["invalid_utf8.bin"] = changed
    changed = bytearray(original)
    firmware_offset = struct.unpack_from("<I", changed, 160)[0]
    firmware_count = struct.unpack_from("<I", changed, 164)[0]
    last_rule = firmware_offset + (firmware_count - 1) * 12
    firmware_relative = struct.unpack_from("<I", changed, last_rule + 8)[0]
    firmware_start = strings_offset + firmware_relative + 1
    changed[firmware_start:firmware_start + 5] = "é$00".encode("utf-8")
    _rewrite_integrity(changed)
    mutations["nonascii_punct_identity.bin"] = changed
    changed = bytearray(original)
    changed[80] ^= 1
    mutations["provenance_hash.bin"] = changed
    for filename, changed in mutations.items():
        (Path(directory) / filename).write_bytes(changed)

    for index, replacement in enumerate(corpus["url_reject"]):
        changed = bytearray(original)
        start, length = _source_string_location(changed, 1)
        encoded = replacement.encode("ascii")
        assert len(encoded) == length
        changed[start:start + length] = encoded
        sources = copy.deepcopy(manifest["sources"])
        sources[0]["url"] = replacement
        _rewrite_provenance(changed, sources)
        _rewrite_integrity(changed)
        (Path(directory) / f"bad_url_{index}.bin").write_bytes(changed)

    for index, accepted in enumerate(corpus["url_accept"][2:], start=2):
        changed_manifest = copy.deepcopy(manifest)
        changed_manifest["sources"][0]["url"] = accepted
        (Path(directory) / f"accepted_url_{index}.bin").write_bytes(
            build_catalog(changed_manifest))

    changed = bytearray(original)
    firmware_offset = struct.unpack_from("<I", changed, 160)[0]
    firmware_count = struct.unpack_from("<I", changed, 164)[0]
    last_rule = firmware_offset + (firmware_count - 1) * 12
    firmware_relative = struct.unpack_from("<I", changed, last_rule + 8)[0]
    strings_offset = struct.unpack_from("<I", changed, 168)[0]
    firmware_start = strings_offset + firmware_relative + 1
    changed[firmware_start:firmware_start + 5] = "é000".encode("utf-8")
    _rewrite_integrity(changed)
    (Path(directory) / "nonascii_identity.bin").write_bytes(changed)
    (Path(directory) / "trailing.bin").write_bytes(original + b"\0")
    (Path(directory) / "oversize.bin").write_bytes(
        original + bytes(4 * 1024 * 1024 - len(original) + 1))

    near = copy.deepcopy(manifest)
    near["products"] = []
    for index in range(128):
        near["products"].append({
            "id": f"fixture-router-{index:03d}",
            "vendor": "Fixture Networks",
            "model": f"Router {index:03d}",
            "aliases": [f"R{index:03d}A", f"R{index:03d}B"],
        })
    near["advisories"] = []
    for index in range(256):
        affected = []
        for lane in range(4):
            product = (index * 4 + lane) % 128
            affected.append({
                "product": f"fixture-router-{product:03d}",
                "firmware": [f"1.{index:03d}.{lane}"],
            })
        near["advisories"].append({
            "cve": f"CVE-2099-{10000 + index}",
            "source": near["sources"][0]["id"],
            "url": f"https://security.example.invalid/advisories/CVE-2099-{10000 + index}",
            "published": "2099-01-02",
            "severity": "medium",
            "kev_date": None,
            "eol": False,
            "fixed_version": "Test fixed release",
            "affected": affected,
        })
    (Path(directory) / "near_limit.bin").write_bytes(build_catalog(near))

    adversarial = copy.deepcopy(near)
    common = "x" * 220
    adversarial["sources"][0]["license"] = common + " license"
    adversarial["sources"][0]["revision"] = common + " revision"
    for index, product in enumerate(adversarial["products"]):
        product["vendor"] = common + " vendor"
        product["model"] = f"{common} model {index:03d}"
        product["aliases"] = [
            f"{common} alias {index:03d} a",
            f"{common} alias {index:03d} b",
        ]
    for index, advisory in enumerate(adversarial["advisories"]):
        advisory["url"] = (
            "https://security.example.invalid/" + "x" * 190 +
            f"/CVE-2099-{10000 + index}")
        advisory["fixed_version"] = (
            f"{common} fixed {index:03d}" if index < 118 else
            common + " fixed common")
        for lane, affected in enumerate(advisory["affected"]):
            affected["firmware"] = [f"{common} firmware {index:03d} {lane}"]
    adversarial_blob = bytearray(build_catalog(adversarial))
    strings_offset, strings_size = struct.unpack_from("<II", adversarial_blob, 168)
    entries = []
    cursor = strings_offset
    while cursor < strings_offset + strings_size:
        length = adversarial_blob[cursor]
        entries.append((cursor, length))
        cursor += 1 + length
    assert len(entries) == 2048
    (Path(directory) / "adversarial_strings.bin").write_bytes(adversarial_blob)
    pair = next((a, b) for pos, a in enumerate(entries)
                for b in entries[pos + 1:]
                if a[1] == b[1] and a[1] >= 220 and
                adversarial_blob[a[0] + 1:a[0] + 1 + a[1]] !=
                adversarial_blob[b[0] + 1:b[0] + 1 + b[1]])
    duplicate = bytearray(adversarial_blob)
    duplicate[pair[1][0] + 1:pair[1][0] + 1 + pair[1][1]] = (
        duplicate[pair[0][0] + 1:pair[0][0] + 1 + pair[0][1]])
    _rewrite_integrity(duplicate)
    (Path(directory) / "adversarial_duplicate.bin").write_bytes(duplicate)


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


class RouterCveDbTest(unittest.TestCase):
    def test_source_is_registered_once(self):
        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")
        self.assertEqual(cmake.count('"router_cve_db.c"'), 1)

    def test_strict_validation_immutable_snapshot_and_exact_lookup(self):
        with tempfile.TemporaryDirectory(prefix="janos-router-cve-db-") as directory:
            write_semantic_mutations(directory)
            executable = Path(directory) / "router_cve_db_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/router_cve_db_test.c",
                       ROOT / "main/router_cve_db.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable), str(FIXTURE), str(Path(directory))]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"),
                                     "host C compiler required (native or WSL)")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable), wsl_path(FIXTURE),
                       wsl_path(Path(directory))]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                result.stdout.strip(),
                "PASS: bounded JCVE/1 validation and evidence-only exact lookup")


if __name__ == "__main__":
    unittest.main()
