import binascii
import struct
import unittest

from tools.rfdb.wps_format import (
    HEADER_SIZE,
    WpsDataset,
    build_wps_blob,
    parse_wps_blob,
)


class WpsFormatTest(unittest.TestCase):
    def setUp(self):
        self.dataset = WpsDataset(
            oui_pins={"00AABB": ["12345670", "00000000"], "00CCDD": ["23456785"]},
            oui_algorithms={"00AABB": ["zhao", "asus"], "00CCDD": ["arcadyan"]},
            model_pins={"DIR-TEST": ["12345670"]},
            vendor_pins={"tp-link": ["12345670", "23456785"]},
            ssid_pins={1: ["00000000"]},
            common_pins=["12345670", "00000000"],
        )

    def test_deterministic_round_trip_and_exact_header(self):
        first = build_wps_blob(self.dataset, 0x12345678)
        second = build_wps_blob(self.dataset, 0x12345678)
        self.assertEqual(first, second)
        self.assertEqual(first[:4], b"JWPS")
        self.assertEqual(first[4], 2)
        self.assertEqual(first[5], HEADER_SIZE)
        self.assertEqual(len(first), struct.unpack_from("<I", first, 8)[0])
        self.assertEqual(
            binascii.crc32(first[HEADER_SIZE:]) & 0xFFFFFFFF,
            struct.unpack_from("<I", first, 12)[0],
        )
        image = parse_wps_blob(first)
        self.assertEqual(image.source_id, 0x12345678)
        self.assertEqual(image.dataset, self.dataset)

    def test_leading_zero_survives_packed_pin_pool(self):
        image = parse_wps_blob(build_wps_blob(self.dataset, 1))
        self.assertIn("00000000", image.dataset.oui_pins["00AABB"])

    def test_v2_preserves_literal_invalid_checksum_and_v1_remains_readable(self):
        dataset = WpsDataset(oui_pins={"00AABB": ["12345678"]},
                             common_pins=["00000001", "99999999"])
        image = parse_wps_blob(build_wps_blob(dataset, 1, validate_checksums=False))
        self.assertEqual(image.dataset.oui_pins["00AABB"], ["12345678"])
        self.assertEqual(image.dataset.common_pins, ["00000001", "99999999"])
        with self.assertRaisesRegex(ValueError, "invalid WPS PIN"):
            build_wps_blob(dataset, 1, version=1)
        with self.assertRaisesRegex(ValueError, "invalid WPS PIN"):
            build_wps_blob(dataset, 1, version=1, validate_checksums=False)
        legacy = build_wps_blob(self.dataset, 1, version=1)
        self.assertEqual(legacy[4], 1)
        self.assertEqual(parse_wps_blob(legacy).dataset, self.dataset)

    def test_unknown_and_unsupported_algorithms_are_rejected_or_reported(self):
        unknown = WpsDataset(oui_algorithms={"00AABB": ["mystery"]})
        with self.assertRaisesRegex(ValueError, "unknown algorithm"):
            build_wps_blob(unknown, 1)
        image = parse_wps_blob(build_wps_blob(
            WpsDataset(oui_algorithms={"00AABB": ["arcadyan"]}), 1
        ))
        self.assertEqual(image.unsupported_algorithm_mappings, 1)

    def test_max_255_candidates_per_rule(self):
        pins = [f"{value:07d}{0}" for value in range(256)]
        with self.assertRaisesRegex(ValueError, "255"):
            build_wps_blob(WpsDataset(oui_pins={"00AABB": pins}), 1,
                           validate_checksums=False)

    def test_rule_names_reject_embedded_nul(self):
        with self.assertRaisesRegex(ValueError, "rule key"):
            build_wps_blob(WpsDataset(model_pins={"DIR\x00TEST": ["12345670"]}), 1)
        with self.assertRaisesRegex(ValueError, "ASCII"):
            build_wps_blob(WpsDataset(model_pins={"Straße": ["12345670"]}), 1)

        blob = bytearray(build_wps_blob(self.dataset, 1))
        strings_offset = struct.unpack_from("<I", blob, 88)[0]
        blob[strings_offset + 1:strings_offset + 3] = b"\xc3\x9f"
        self._refresh_crc(blob)
        with self.assertRaisesRegex(ValueError, "ASCII"):
            parse_wps_blob(bytes(blob))

    def test_corruption_and_layout_errors_are_rejected(self):
        blob = bytearray(build_wps_blob(self.dataset, 1))
        blob[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC"):
            parse_wps_blob(bytes(blob))

        blob = bytearray(build_wps_blob(self.dataset, 1))
        blob[32:36] = (len(blob) + 10).to_bytes(4, "little")
        self._refresh_crc(blob)
        with self.assertRaisesRegex(ValueError, "outside"):
            parse_wps_blob(bytes(blob))

        blob = bytearray(build_wps_blob(self.dataset, 1))
        first_offset = struct.unpack_from("<I", blob, 32)[0]
        struct.pack_into("<I", blob, 40, first_offset)
        self._refresh_crc(blob)
        with self.assertRaisesRegex(ValueError, "overlap"):
            parse_wps_blob(bytes(blob))

        blob = bytearray(build_wps_blob(self.dataset, 1))
        blob[20] = 1
        with self.assertRaisesRegex(ValueError, "reserved"):
            parse_wps_blob(bytes(blob))

        blob = bytearray(build_wps_blob(self.dataset, 1))
        blob[4] = 3
        with self.assertRaisesRegex(ValueError, "unsupported"):
            parse_wps_blob(bytes(blob))

    def test_version_specific_pin_bounds_cover_pool_and_common(self):
        legacy = bytearray(build_wps_blob(self.dataset, 1, version=1))
        pool_offset = struct.unpack_from("<I", legacy, 40)[0]
        legacy[pool_offset:pool_offset + 3] = (10_000_000).to_bytes(3, "little")
        self._refresh_crc(legacy)
        with self.assertRaisesRegex(ValueError, "seven digits"):
            parse_wps_blob(bytes(legacy))

        current = bytearray(build_wps_blob(self.dataset, 1))
        pool_offset = struct.unpack_from("<I", current, 40)[0]
        current[pool_offset:pool_offset + 4] = (100_000_000).to_bytes(4, "little")
        self._refresh_crc(current)
        with self.assertRaisesRegex(ValueError, "eight digits"):
            parse_wps_blob(bytes(current))

        current = bytearray(build_wps_blob(self.dataset, 1))
        common_offset = struct.unpack_from("<I", current, 80)[0]
        current[common_offset:common_offset + 4] = (0xffffffff).to_bytes(4, "little")
        self._refresh_crc(current)
        with self.assertRaisesRegex(ValueError, "eight digits"):
            parse_wps_blob(bytes(current))

    @staticmethod
    def _refresh_crc(blob):
        struct.pack_into("<I", blob, 12, binascii.crc32(blob[HEADER_SIZE:]) & 0xFFFFFFFF)


if __name__ == "__main__":
    unittest.main()
