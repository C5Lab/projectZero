import binascii
from pathlib import Path
import struct
import tempfile
import unittest

from tools.rfdb.vendor_format import (
    HEADER_SIZE,
    VendorRecord,
    build_vendor_blob,
    parse_manuf,
    parse_manuf_data_c,
    parse_vendor_blob,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_TEXT = ROOT / "tests" / "fixtures" / "vendor_manuf_sample.txt"
FIXTURE_BIN = ROOT / "tests" / "fixtures" / "vendors_v3.bin"
HEADER = struct.Struct("<4sBBBB11I12s")


class VendorFormatTest(unittest.TestCase):
    def sample_records(self):
        return parse_manuf(FIXTURE_TEXT.read_text(encoding="utf-8"))

    def test_parse_manuf_supports_24_28_and_36_bit_prefixes(self):
        records = self.sample_records()
        self.assertEqual(
            records,
            [
                VendorRecord(24, 0x001122, "Vendor Twenty Four"),
                VendorRecord(28, 0x0011223, "Vendor Twenty Eight"),
                VendorRecord(36, 0x001122334, "Vendor Thirty Six"),
                VendorRecord(24, 0xAABBCC, "Another Vendor"),
            ],
        )

    def test_parse_current_wireshark_manuf_data_c(self):
        source = r'''
static const manuf_oui24_t global_manuf_oui24_table[] = {
    { { 0x00, 0x11, 0x22 }, "Short24", "Vendor Twenty Four" },
};
static const manuf_oui28_t global_manuf_oui28_table[] = {
    { { 0x00, 0x11, 0x22, 0x30 }, "Short28", "Vendor \"Twenty\" Eight" },
};
static const manuf_oui36_t global_manuf_oui36_table[] = {
    { { 0x00, 0x11, 0x22, 0x33, 0x40 }, "Short36", "Vendor Thirty Six" },
};
'''
        self.assertEqual(
            parse_manuf_data_c(source),
            [
                VendorRecord(24, 0x001122, "Vendor Twenty Four"),
                VendorRecord(28, 0x0011223, 'Vendor "Twenty" Eight'),
                VendorRecord(36, 0x001122334, "Vendor Thirty Six"),
            ],
        )

    def test_manuf_data_c_requires_all_three_tables(self):
        with self.assertRaisesRegex(ValueError, "table"):
            parse_manuf_data_c("static const manuf_oui24_t broken[] = {};")

    def test_blob_is_deterministic_and_matches_checked_fixture(self):
        first = build_vendor_blob(self.sample_records(), source_id=0)
        second = build_vendor_blob(self.sample_records(), source_id=0)
        self.assertEqual(first, second)
        self.assertEqual(first, FIXTURE_BIN.read_bytes())

    def test_header_offsets_counts_crc_and_source_id(self):
        blob = build_vendor_blob(self.sample_records(), source_id=0x78563412)
        fields = HEADER.unpack_from(blob)
        (
            magic,
            version,
            header_size,
            section_count,
            flags,
            file_size,
            payload_crc,
            source_id,
            names_offset,
            names_size,
            index24_offset,
            index24_count,
            index28_offset,
            index28_count,
            index36_offset,
            index36_count,
            reserved,
        ) = fields
        self.assertEqual((magic, version, header_size, section_count, flags), (b"JVND", 3, 64, 4, 0))
        self.assertEqual(file_size, len(blob))
        self.assertEqual(payload_crc, binascii.crc32(blob[HEADER_SIZE:]) & 0xFFFFFFFF)
        self.assertEqual(source_id, 0x78563412)
        self.assertEqual((index24_offset, index24_count), (64, 2))
        self.assertEqual((index28_offset, index28_count), (76, 1))
        self.assertEqual((index36_offset, index36_count), (83, 1))
        self.assertEqual(names_offset, 91)
        self.assertGreater(names_size, 0)
        self.assertEqual(names_offset + names_size, len(blob))
        self.assertEqual(reserved, bytes(12))

    def test_indexes_are_sorted_and_names_are_interned(self):
        records = [
            VendorRecord(24, 0xAABBCC, "Shared"),
            VendorRecord(24, 0x001122, "Shared"),
        ]
        blob = build_vendor_blob(records, source_id=0)
        fields = HEADER.unpack_from(blob)
        names_offset = fields[8]
        index24_offset = fields[10]
        first = blob[index24_offset : index24_offset + 6]
        second = blob[index24_offset + 6 : index24_offset + 12]
        self.assertEqual(first[:3], bytes.fromhex("001122"))
        self.assertEqual(second[:3], bytes.fromhex("aabbcc"))
        self.assertEqual(first[3:], second[3:])
        self.assertEqual(int.from_bytes(first[3:], "little"), 0)
        self.assertEqual(blob[names_offset], len("Shared"))

    def test_utf8_name_is_truncated_on_character_boundary(self):
        name = "ą" * 40
        image = parse_vendor_blob(
            build_vendor_blob([VendorRecord(24, 0x001122, name)], source_id=0)
        )
        self.assertEqual(image.records[0].name, "ą" * 30)
        self.assertEqual(len(image.records[0].name.encode("utf-8")), 60)

    def test_duplicate_prefix_keeps_first_and_reports_it(self):
        text = "00:11:22 First Vendor\n00:11:22 Second Vendor\n"
        with self.assertLogs("tools.rfdb.vendor_format", level="WARNING") as captured:
            records = parse_manuf(text)
        self.assertEqual(records, [VendorRecord(24, 0x001122, "First Vendor")])
        self.assertIn("duplicate", " ".join(captured.output).lower())

    def test_invalid_prefixes_are_rejected(self):
        invalid = (
            "00:11/16 Vendor",
            "00:11:22:3/24 Vendor",
            "00:11:22:GG/28 Vendor",
            "00:11:22:33:4/35 Vendor",
            "00:11:22:33:44/36 Vendor",
            "00:11:22",
        )
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_manuf(text)

    def test_corrupt_crc_is_rejected(self):
        blob = bytearray(build_vendor_blob(self.sample_records(), source_id=0))
        blob[-1] ^= 0x01
        with self.assertRaisesRegex(ValueError, "CRC"):
            parse_vendor_blob(bytes(blob))

    def test_nonzero_reserved_bytes_are_rejected(self):
        blob = bytearray(build_vendor_blob(self.sample_records(), source_id=0))
        blob[52] = 1
        with self.assertRaisesRegex(ValueError, "reserved"):
            parse_vendor_blob(bytes(blob))

    def test_truncation_and_declared_size_mismatch_are_rejected(self):
        blob = build_vendor_blob(self.sample_records(), source_id=0)
        with self.assertRaises(ValueError):
            parse_vendor_blob(blob[:-1])

        changed = bytearray(blob)
        struct.pack_into("<I", changed, 8, len(blob) + 1)
        with self.assertRaisesRegex(ValueError, "file_size"):
            parse_vendor_blob(bytes(changed))

    def test_overlapping_sections_are_rejected(self):
        blob = bytearray(build_vendor_blob(self.sample_records(), source_id=0))
        index24_offset = struct.unpack_from("<I", blob, 28)[0]
        struct.pack_into("<I", blob, 36, index24_offset)
        payload_crc = binascii.crc32(blob[HEADER_SIZE:]) & 0xFFFFFFFF
        struct.pack_into("<I", blob, 12, payload_crc)
        with self.assertRaisesRegex(ValueError, "overlap"):
            parse_vendor_blob(bytes(blob))


if __name__ == "__main__":
    unittest.main()
