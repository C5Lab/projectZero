import binascii
import copy
import hashlib
import json
from pathlib import Path
import struct
import unittest

from tools.cvedb.catalog_format import (
    ADVISORY_RECORD_SIZE,
    ALIAS_RECORD_SIZE,
    FIRMWARE_RECORD_SIZE,
    HEADER_SIZE,
    MAX_ADVISORIES,
    MAX_ALIASES,
    MAX_CATALOG_BYTES,
    MAX_FIRMWARE_RULES,
    MAX_MODELS,
    MAX_SOURCES,
    MAX_STRING_ENTRIES,
    MODEL_RECORD_SIZE,
    SOURCE_RECORD_SIZE,
    build_catalog,
    parse_catalog,
)


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "tests" / "fixtures" / "router_cve_manifest_v1.json"
FIXTURE_PATH = ROOT / "tests" / "fixtures" / "router_cve_v1.bin"
CANONICAL_STRINGS_PATH = ROOT / "tests" / "fixtures" / "router_cve_canonical_strings_v1.json"
HEADER = struct.Struct("<4sHHIIIIQQQ32s32s16s12I16s")


def manifest():
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def rewrite_integrity(blob):
    changed = bytearray(blob)
    payload = changed[HEADER_SIZE:]
    struct.pack_into("<I", changed, 16, binascii.crc32(payload) & 0xFFFFFFFF)
    changed[48:80] = hashlib.sha256(payload).digest()
    return bytes(changed)


def rewrite_provenance(blob, sources):
    changed = bytearray(blob)
    canonical = (json.dumps({"sources": sorted(sources, key=lambda item: item["id"])},
                            ensure_ascii=False, sort_keys=True,
                            separators=(",", ":")) + "\n").encode("utf-8")
    changed[80:112] = hashlib.sha256(canonical).digest()
    return bytes(changed)


class RouterCveFormatTest(unittest.TestCase):
    def test_esp32_safe_work_limits_are_frozen(self):
        self.assertEqual(
            (MAX_SOURCES, MAX_MODELS, MAX_ALIASES, MAX_ADVISORIES,
             MAX_FIRMWARE_RULES, MAX_STRING_ENTRIES),
            (16, 128, 256, 256, 1024, 2048),
        )

    def test_header_and_record_layout_are_frozen(self):
        self.assertEqual(HEADER.size, 192)
        self.assertEqual(
            (SOURCE_RECORD_SIZE, MODEL_RECORD_SIZE, ALIAS_RECORD_SIZE,
             ADVISORY_RECORD_SIZE, FIRMWARE_RECORD_SIZE),
            (24, 16, 8, 32, 12),
        )
        blob = build_catalog(manifest())
        fields = HEADER.unpack_from(blob)
        self.assertEqual(fields[0:4], (b"JCVE", 1, 192, 0))
        self.assertEqual(fields[4], len(blob))
        self.assertEqual(fields[5], binascii.crc32(blob[192:]) & 0xFFFFFFFF)
        self.assertEqual(fields[6], 0)
        self.assertEqual(fields[7:10], (4070908800, 4083782400, 7))
        self.assertEqual(fields[10], hashlib.sha256(blob[192:]).digest())
        self.assertEqual(fields[12], bytes.fromhex("00112233445566778899aabbccddeeff"))
        descriptors = fields[13:25]
        self.assertEqual(descriptors[0], 192)
        self.assertEqual(descriptors[1], 1)
        self.assertEqual(descriptors[3], 2)
        self.assertEqual(descriptors[5], 2)
        self.assertEqual(descriptors[7], 2)
        self.assertEqual(descriptors[9], 4)
        self.assertGreater(descriptors[11], 0)
        self.assertEqual(fields[25], bytes(16))

    def test_equivalent_manifest_order_is_byte_identical(self):
        ordered = manifest()
        shuffled = copy.deepcopy(ordered)
        shuffled["products"].reverse()
        shuffled["advisories"].reverse()
        shuffled["products"][1]["aliases"].reverse()
        shuffled["advisories"][1]["affected"].reverse()
        shuffled["advisories"][1]["affected"][1]["firmware"].reverse()
        self.assertEqual(build_catalog(ordered), build_catalog(shuffled))

    def test_round_trip_preserves_normalized_records_and_provenance(self):
        image = parse_catalog(build_catalog(manifest()))
        self.assertEqual(image.serial, 7)
        self.assertEqual(len(image.sources), 1)
        self.assertEqual(
            [(model.vendor, model.model) for model in image.models],
            [("fixture networks", "router one"),
             ("fixture networks", "router two")],
        )
        self.assertEqual(
            [(alias.alias, alias.model_index) for alias in image.aliases],
            [("r1 test", 0), ("router one", 0)],
        )
        self.assertEqual([item.cve for item in image.advisories],
                         ["CVE-2099-0001", "CVE-2099-0002"])
        self.assertEqual(len(image.firmware_rules), 4)
        self.assertEqual(image.provenance_sha256, image.recomputed_provenance_sha256)

    def test_provenance_digest_changes_for_each_normalized_source_field(self):
        original = manifest()
        baseline = parse_catalog(build_catalog(original)).provenance_sha256
        cases = {
            "url": "https://security.example.invalid/other",
            "retrieved_utc": "2099-01-03T00:00:01Z",
            "license": "MIT-test-fixture",
            "revision": "fixture-rev-2",
            "sha256": "f" * 64,
        }
        for field, value in cases.items():
            changed = copy.deepcopy(original)
            changed["sources"][0][field] = value
            with self.subTest(field=field):
                self.assertNotEqual(
                    parse_catalog(build_catalog(changed)).provenance_sha256,
                    baseline,
                )

    def test_manifest_rejects_ambiguous_or_unreviewed_input(self):
        cases = []
        duplicate_cve = manifest()
        duplicate_cve["advisories"].append(copy.deepcopy(duplicate_cve["advisories"][0]))
        cases.append(duplicate_cve)
        duplicate_product = manifest()
        duplicate_product["products"].append(copy.deepcopy(duplicate_product["products"][0]))
        cases.append(duplicate_product)
        ambiguous_alias = manifest()
        ambiguous_alias["products"][1]["aliases"] = ["ROUTER_ONE"]
        cases.append(ambiguous_alias)
        bad_url = manifest()
        bad_url["advisories"][0]["url"] = "http://security.example.invalid/CVE-2099-0001"
        cases.append(bad_url)
        missing_license = manifest()
        missing_license["sources"][0]["license"] = ""
        cases.append(missing_license)
        bad_hash = manifest()
        bad_hash["sources"][0]["sha256"] = "00"
        cases.append(bad_hash)
        uppercase_hash = manifest()
        uppercase_hash["sources"][0]["sha256"] = uppercase_hash["sources"][0]["sha256"].upper()
        cases.append(uppercase_hash)
        uppercase_scheme = manifest()
        uppercase_scheme["sources"][0]["url"] = uppercase_scheme["sources"][0]["url"].replace(
            "https://", "HTTPS://")
        cases.append(uppercase_scheme)
        default_port = manifest()
        default_port["sources"][0]["url"] = "https://security.example.invalid:443/advisories"
        cases.append(default_port)
        for whitespace in (" ", "\t", "\r", "\n"):
            bad_whitespace = manifest()
            bad_whitespace["sources"][0]["url"] = (
                "https://security.example.invalid/" + whitespace + "advisories")
            cases.append(bad_whitespace)
        too_old = manifest()
        too_old["expires_epoch"] = too_old["created_epoch"] + 181 * 86400
        cases.append(too_old)
        empty_firmware = manifest()
        empty_firmware["advisories"][0]["affected"][0]["firmware"] = []
        cases.append(empty_firmware)
        duplicate_firmware = manifest()
        duplicate_firmware["advisories"][0]["affected"][0]["firmware"] = ["1.0.0", "1-0-0"]
        cases.append(duplicate_firmware)
        for case in cases:
            with self.subTest(case=cases.index(case)), self.assertRaises(ValueError):
                build_catalog(case)

    def test_shared_canonical_ascii_and_url_corpus(self):
        corpus = json.loads(CANONICAL_STRINGS_PATH.read_text(encoding="utf-8"))
        for text in corpus["text_accept"]:
            changed = manifest()
            changed["sources"][0]["license"] = text
            build_catalog(changed)
        for text in corpus["text_reject"]:
            changed = manifest()
            changed["sources"][0]["license"] = text
            with self.subTest(text=text), self.assertRaises(ValueError):
                build_catalog(changed)
        for url in corpus["url_accept"]:
            changed = manifest()
            changed["sources"][0]["url"] = url
            build_catalog(changed)
        for url in corpus["url_reject"]:
            changed = manifest()
            changed["sources"][0]["url"] = url
            with self.subTest(url=url), self.assertRaises(ValueError):
                build_catalog(changed)

    def test_binary_mutations_fail_closed(self):
        blob = build_catalog(manifest())
        mutations = []
        for offset, replacement in ((0, b"BAD!"), (4, b"\x02\x00"),
                                    (6, b"\x80\x00"), (8, b"\x01\x00\x00\x00"),
                                    (20, b"\x01\x00\x00\x00"),
                                    (176, b"\x01")):
            changed = bytearray(blob)
            changed[offset:offset + len(replacement)] = replacement
            mutations.append(bytes(changed))
        changed = bytearray(blob)
        changed[-1] ^= 1
        mutations.append(bytes(changed))
        changed = bytearray(blob)
        struct.pack_into("<I", changed, 12, len(blob) + 1)
        mutations.append(bytes(changed))
        changed = bytearray(blob)
        struct.pack_into("<I", changed, 128 + 8, 192)
        mutations.append(rewrite_integrity(changed))
        changed = bytearray(blob)
        source_offset = struct.unpack_from("<I", changed, 128)[0]
        struct.pack_into("<I", changed, source_offset, 0xFFFFFFFE)
        mutations.append(rewrite_integrity(changed))

        # Stored provenance text must itself be canonical, not silently folded.
        changed = bytearray(blob)
        strings_offset = struct.unpack_from("<I", changed, 168)[0]
        source_hash_offset = struct.unpack_from("<I", changed, source_offset + 20)[0]
        hash_start = strings_offset + source_hash_offset + 1
        hash_end = hash_start + changed[strings_offset + source_hash_offset]
        changed[hash_start:hash_end] = bytes(changed[hash_start:hash_end]).upper()
        mutations.append(rewrite_integrity(changed))

        # URL spelling is provenance: a parser must not normalize its scheme.
        changed = bytearray(blob)
        source_url_offset = struct.unpack_from("<I", changed, source_offset + 4)[0]
        url_start = strings_offset + source_url_offset + 1
        changed[url_start:url_start + 5] = b"HTTPS"
        changed_sources = copy.deepcopy(manifest()["sources"])
        changed_sources[0]["url"] = changed_sources[0]["url"].replace("https://", "HTTPS://")
        changed = bytearray(rewrite_provenance(changed, changed_sources))
        mutations.append(rewrite_integrity(changed))

        # Duplicate an alias entry while preserving CRC and payload SHA.
        changed = bytearray(blob)
        alias_offset = struct.unpack_from("<I", changed, 144)[0]
        first_alias = changed[alias_offset:alias_offset + ALIAS_RECORD_SIZE]
        changed[alias_offset + ALIAS_RECORD_SIZE:alias_offset + 2 * ALIAS_RECORD_SIZE] = first_alias
        mutations.append(rewrite_integrity(changed))

        # Alias "router one" may not be reassigned to the "router two" model.
        changed = bytearray(blob)
        struct.pack_into("<I", changed,
                         alias_offset + ALIAS_RECORD_SIZE + 4, 1)
        mutations.append(rewrite_integrity(changed))

        # Corrupt advisory reserved bytes while preserving outer integrity.
        changed = bytearray(blob)
        advisory_offset = struct.unpack_from("<I", changed, 152)[0]
        changed[advisory_offset + ADVISORY_RECORD_SIZE - 1] = 1
        mutations.append(rewrite_integrity(changed))

        # Invalid UTF-8 at a referenced string boundary must fail closed.
        changed = bytearray(blob)
        strings_offset = struct.unpack_from("<I", changed, 168)[0]
        changed[strings_offset + 1] = 0xFF
        mutations.append(rewrite_integrity(changed))

        # JCVE/1 firmware strings are printable ASCII only even though the
        # containing file is binary-safe.
        changed = bytearray(blob)
        firmware_offset = struct.unpack_from("<I", changed, 160)[0]
        firmware_count = struct.unpack_from("<I", changed, 164)[0]
        last_rule = firmware_offset + (firmware_count - 1) * FIRMWARE_RECORD_SIZE
        firmware_relative = struct.unpack_from("<I", changed, last_rule + 8)[0]
        firmware_start = strings_offset + firmware_relative + 1
        changed[firmware_start:firmware_start + 5] = "é000".encode("utf-8")
        mutations.append(rewrite_integrity(changed))

        changed = bytearray(blob)
        advisory_offset = struct.unpack_from("<I", changed, 152)[0]
        fixed_relative = struct.unpack_from("<I", changed, advisory_offset + 24)[0]
        fixed_start = strings_offset + fixed_relative + 1
        changed[fixed_start:fixed_start + 14] = "é fixture fix".encode("utf-8")
        mutations.append(rewrite_integrity(changed))

        # Equal string values at distinct boundaries are a noncanonical encoding.
        changed = bytearray(blob)
        source_id_offset = struct.unpack_from("<I", changed, source_offset)[0]
        source_license_offset = struct.unpack_from("<I", changed, source_offset + 12)[0]
        id_start = strings_offset + source_id_offset + 1
        license_start = strings_offset + source_license_offset + 1
        id_length = changed[strings_offset + source_id_offset]
        self.assertEqual(id_length, changed[strings_offset + source_license_offset])
        source_id = bytes(changed[id_start:id_start + id_length])
        changed[license_start:license_start + id_length] = source_id
        changed_sources = copy.deepcopy(manifest()["sources"])
        changed_sources[0]["license"] = changed_sources[0]["id"]
        changed = bytearray(rewrite_provenance(changed, changed_sources))
        mutations.append(rewrite_integrity(changed))

        # Provenance is independently recomputed, not trusted from the header.
        changed = bytearray(blob)
        changed[80] ^= 1
        mutations.append(bytes(changed))

        # Trailing bytes and the absolute format bound are both rejected.
        mutations.append(blob + b"\x00")
        mutations.append(blob + bytes(MAX_CATALOG_BYTES - len(blob) + 1))
        for mutated in mutations:
            with self.subTest(sha=hashlib.sha256(mutated).hexdigest()[:12]):
                with self.assertRaises(ValueError):
                    parse_catalog(mutated)

    def test_checked_fixture_reproduces_exactly_and_has_literal_digest(self):
        blob = build_catalog(manifest())
        self.assertEqual(blob, FIXTURE_PATH.read_bytes())
        self.assertEqual(len(blob), struct.unpack_from("<I", blob, 12)[0])
        self.assertLessEqual(len(blob), MAX_CATALOG_BYTES)
        self.assertEqual(
            hashlib.sha256(blob).hexdigest(),
            "358820ebc02abf664b52b2cfc1052d72b1d705a2a726d7f8eca5a86952b518b6",
        )


if __name__ == "__main__":
    unittest.main()
