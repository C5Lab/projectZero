"""Behavioral tests of the proposed protocol's host reference, without a compiler.

These do not execute JanOS, the Flipper parsers, or the ESP-IDF driver.
"""

import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from wifi_analyzer_contract import ContractError, MAX_LINE_BYTES, SnapshotReader


BEGIN = {
    "v": 1, "type": "begin", "boot": "0123456789abcdef", "scan": 1,
    "limit": 64, "band": "both", "channels": [1, 6, 36],
    "profile": "quick", "started_ms": 1000,
}
AP = {
    "v": 1, "type": "ap", "boot": "0123456789abcdef", "scan": 1,
    "seq": 0, "bssid": "02:00:00:00:00:01", "ssid_hex": "486f6d65",
    "band": "2.4", "primary": 6, "rssi": -55, "auth": "WPA2_PSK",
    "phy": ["11n"], "bandwidth": None, "secondary": None,
    "center1_mhz": None, "center2_mhz": None,
}
END = {
    "v": 1, "type": "end", "boot": "0123456789abcdef", "scan": 1,
    "status": "ok", "found": 1, "returned": 1, "truncated": False,
    "duration_ms": 1500,
}


def wire(*records):
    return b"".join(b"[WFA1] " + json.dumps(r, separators=(",", ":")).encode() + b"\r\n"
                    for r in records)


class SnapshotContractTest(unittest.TestCase):
    def reader_with_snapshot(self):
        reader = SnapshotReader()
        reader.feed(wire(BEGIN, AP, END))
        self.assertIsNotNone(reader.last_snapshot)
        return reader

    def assert_rejected(self, *records):
        reader = SnapshotReader()
        self.assertEqual(reader.feed(wire(*records)), [])
        self.assertIsNone(reader.last_snapshot)
        self.assertTrue(reader.errors)

    def test_commits_only_at_end(self):
        reader = SnapshotReader()
        self.assertEqual(reader.feed(wire(BEGIN, AP)), [])
        self.assertIsNone(reader.last_snapshot)
        result = reader.feed(wire(END))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["aps"][0]["rssi"], -55)

    def test_every_possible_two_chunk_split(self):
        data = wire(BEGIN, AP, END)
        for split in range(len(data) + 1):
            reader = SnapshotReader()
            result = reader.feed(data[:split]) + reader.feed(data[split:])
            self.assertEqual(len(result), 1, split)
            self.assertEqual(reader.errors, [])

    def test_bytewise_reads_and_unrelated_legacy_logs(self):
        reader = SnapshotReader()
        data = b'JanOS> scan\r\n"1","Legacy"\r\nScan results printed.\n' + wire(BEGIN, AP, END)
        result = []
        for byte in data:
            result.extend(reader.feed(bytes([byte])))
        self.assertEqual(len(result), 1)
        self.assertEqual(reader.errors, [])

    def test_empty_success_replaces_previous_snapshot(self):
        reader = self.reader_with_snapshot()
        result = reader.feed(wire(dict(BEGIN, scan=2), dict(END, scan=2, found=0, returned=0)))
        self.assertEqual(result[0]["aps"], [])
        self.assertEqual(reader.last_snapshot["scan"], 2)

    def test_failed_and_cancelled_scans_keep_previous_snapshot(self):
        for status in ("error", "cancelled", "timeout"):
            reader = self.reader_with_snapshot()
            previous = copy.deepcopy(reader.last_snapshot)
            terminal = dict(END, scan=2, status=status, found=None, returned=0, truncated=False,
                            code="scan_failed")
            self.assertEqual(reader.feed(wire(dict(BEGIN, scan=2), terminal)), [])
            self.assertEqual(reader.last_snapshot, previous)
            self.assertEqual(reader.errors, [])

    def test_missing_end_is_incomplete_not_empty(self):
        reader = SnapshotReader()
        reader.feed(wire(BEGIN, AP))
        with self.assertRaises(ContractError):
            reader.finish()

    def test_fragment_of_first_protocol_line_is_incomplete(self):
        reader = SnapshotReader()
        reader.feed(b"[WFA1] {\"v\":1")
        with self.assertRaises(ContractError):
            reader.finish()

    def test_wrong_scan_cannot_complete_transaction(self):
        self.assert_rejected(BEGIN, AP, dict(END, scan=2))

    def test_reboot_requires_a_new_reader(self):
        reader = self.reader_with_snapshot()
        reader.feed(wire(dict(BEGIN, boot="fedcba9876543210", scan=2)))
        self.assertTrue(reader.errors)
        self.assertEqual(reader.last_snapshot["scan"], 1)

    def test_reused_scan_id_is_rejected(self):
        reader = self.reader_with_snapshot()
        self.assertEqual(reader.feed(wire(BEGIN, AP, END)), [])
        self.assertTrue(reader.errors)

    def test_missing_record_rejects_entire_snapshot(self):
        self.assert_rejected(BEGIN, AP, dict(END, found=2, returned=2))

    def test_out_of_order_record_is_rejected(self):
        self.assert_rejected(BEGIN, dict(AP, seq=1), END)

    def test_duplicate_bssid_is_rejected_case_insensitively(self):
        first = dict(AP, bssid="02:aa:bb:cc:dd:ee")
        second = dict(first, seq=1, bssid="02:AA:BB:CC:DD:EE")
        self.assert_rejected(BEGIN, first, second, dict(END, found=2, returned=2))

    def test_same_ssid_different_bssid_is_preserved(self):
        reader = SnapshotReader()
        second = dict(AP, seq=1, bssid="02:00:00:00:00:02")
        result = reader.feed(wire(BEGIN, AP, second, dict(END, found=2, returned=2)))
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0]["aps"]), 2)

    def test_channel_outside_requested_scope_is_rejected(self):
        self.assert_rejected(BEGIN, dict(AP, primary=11), END)

    def test_channel_band_mismatch_is_rejected(self):
        self.assert_rejected(BEGIN, dict(AP, band="5"), END)

    def test_unknown_width_stays_unknown(self):
        reader = self.reader_with_snapshot()
        self.assertIsNone(reader.last_snapshot["aps"][0]["bandwidth"])
        self.assertIsNone(reader.last_snapshot["aps"][0]["center1_mhz"])

    def test_width_needs_consistent_centers(self):
        for changes in (
            {"bandwidth": "40", "center1_mhz": None},
            {"bandwidth": "20", "center1_mhz": 2462, "secondary": "none"},
            {"bandwidth": "80", "center1_mhz": 2447, "secondary": "above"},
            {"center1_mhz": 2437},
        ):
            self.assert_rejected(BEGIN, dict(AP, **changes), END)

    def test_40mhz_geometry_and_5ghz_80mhz_geometry(self):
        for changes in (
            {"bandwidth": "40", "secondary": "above", "center1_mhz": 2447},
            {"bandwidth": "40", "secondary": "below", "center1_mhz": 2427},
            {"band": "5", "primary": 36, "bandwidth": "80",
             "secondary": "above", "center1_mhz": 5210},
        ):
            reader = SnapshotReader()
            self.assertEqual(len(reader.feed(wire(BEGIN, dict(AP, **changes), END))), 1)

    def test_channel_14_has_special_frequency(self):
        reader = SnapshotReader()
        ap = dict(AP, primary=14, bandwidth="20", secondary="none", center1_mhz=2484)
        self.assertEqual(len(reader.feed(wire(dict(BEGIN, channels=[14]), ap, END))), 1)
        self.assert_rejected(dict(BEGIN, channels=[14]), dict(ap, center1_mhz=2477), END)

    def test_truncation_is_explicit_and_not_limited_to_event_uint8(self):
        reader = SnapshotReader()
        result = reader.feed(wire(dict(BEGIN, limit=1), AP,
                                 dict(END, found=300, truncated=True)))
        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["truncated"])
        self.assertEqual(result[0]["found"], 300)
        self.assert_rejected(BEGIN, AP, dict(END, found=300))

    def test_capacity_overflow_is_rejected(self):
        self.assert_rejected(dict(BEGIN, limit=1), AP,
                             dict(AP, seq=1, bssid="02:00:00:00:00:02"),
                             dict(END, found=2, returned=2))

    def test_ssid_bytes_preserve_quotes_commas_and_non_utf8(self):
        reader = SnapshotReader()
        result = reader.feed(wire(BEGIN, dict(AP, ssid_hex="412c2242ff"), END))
        self.assertEqual(len(result), 1)
        self.assertEqual(bytes.fromhex(result[0]["aps"][0]["ssid_hex"]), b'A,"B\xff')

    def test_empty_ssid_is_supported(self):
        reader = SnapshotReader()
        result = reader.feed(wire(BEGIN, dict(AP, ssid_hex=""), END))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["aps"][0]["ssid_hex"], "")

    def test_invalid_ssid_is_rejected(self):
        for ssid in ("f", "zz", "00" * 33):
            self.assert_rejected(BEGIN, dict(AP, ssid_hex=ssid), END)

    def test_bool_is_not_an_integer_field(self):
        self.assert_rejected(dict(BEGIN, limit=True), AP, END)
        self.assert_rejected(BEGIN, dict(AP, rssi=True), END)

    def test_unsupported_version_is_rejected(self):
        self.assert_rejected(dict(BEGIN, v=2), AP, END)

    def test_oversize_line_discards_snapshot_and_recovers_at_next_begin(self):
        reader = SnapshotReader()
        reader.feed(wire(BEGIN))
        reader.feed(b"[WFA1] " + b"x" * MAX_LINE_BYTES + b"\n")
        self.assertIsNone(reader.last_snapshot)
        self.assertTrue(reader.errors)
        result = reader.feed(wire(dict(BEGIN, scan=2), dict(AP, scan=2), dict(END, scan=2)))
        self.assertEqual(len(result), 1)

    def test_malformed_json_and_duplicate_keys_are_rejected(self):
        for payload in (b"{broken}", b'{"v":1,"v":1,"type":"begin"}',
                        b'{"v":1,"type":"begin","started_ms":NaN}'):
            reader = SnapshotReader()
            reader.feed(b"[WFA1] " + payload + b"\n")
            self.assertTrue(reader.errors)

    def test_unknown_additive_fields_are_accepted(self):
        reader = SnapshotReader()
        self.assertEqual(len(reader.feed(wire(dict(BEGIN, extension=42), AP, END))), 1)

    def test_end_extensions_cannot_overwrite_validated_ap_records(self):
        reader = SnapshotReader()
        result = reader.feed(wire(BEGIN, AP, dict(END, aps=[])))
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0]["aps"]), 1)

    def test_partial_cancel_discards_received_aps(self):
        reader = self.reader_with_snapshot()
        result = reader.feed(wire(dict(BEGIN, scan=2), dict(AP, scan=2),
            dict(END, scan=2, status="cancelled", found=None, code="stopped")))
        self.assertEqual(result, [])
        self.assertEqual(reader.last_snapshot["scan"], 1)
        self.assertEqual(reader.errors, [])

    def test_corrupt_update_preserves_previous_good_snapshot(self):
        reader = self.reader_with_snapshot()
        reader.feed(wire(dict(BEGIN, scan=2), dict(AP, scan=2, seq=2), dict(END, scan=2)))
        self.assertTrue(reader.errors)
        self.assertEqual(reader.last_snapshot["scan"], 1)

    def test_full_128_record_snapshot(self):
        reader = SnapshotReader()
        aps = [dict(AP, seq=i, bssid=f"02:00:00:00:01:{i:02x}") for i in range(128)]
        result = reader.feed(wire(dict(BEGIN, limit=128), *aps,
                                  dict(END, found=128, returned=128)))
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0]["aps"]), 128)
        self.assertEqual(result[0]["aps"][-1]["seq"], 127)

    def test_capacity_129_is_rejected(self):
        self.assert_rejected(dict(BEGIN, limit=129), AP, END)

    def test_160_and_noncontiguous_80mhz_segments(self):
        for width, c1, c2 in (("160", 5250, None), ("80+80", 5210, 5530)):
            reader = SnapshotReader()
            ap = dict(AP, band="5", primary=36, bandwidth=width,
                      secondary="above", center1_mhz=c1, center2_mhz=c2)
            self.assertEqual(len(reader.feed(wire(BEGIN, ap, END))), 1)
        ap = dict(AP, band="5", primary=36, bandwidth="80+80",
                  secondary="above", center1_mhz=5210, center2_mhz=5290)
        self.assert_rejected(BEGIN, ap, END)

    def test_exact_line_limit_is_accepted(self):
        record = dict(BEGIN, padding="")
        # Deliberately pad the serialized record to the public byte boundary.
        size = len(wire(record)) - 2
        record["padding"] = "x" * (MAX_LINE_BYTES - size)
        reader = SnapshotReader()
        self.assertEqual(len(reader.feed(wire(record, AP, END))), 1)

    def test_160_rejects_primary_80_segment_center_from_device_capture(self):
        begin = dict(BEGIN, band="5", channels=[64])
        ap = dict(AP, band="5", primary=64, bandwidth="160", secondary="below",
                  center1_mhz=5290, center2_mhz=None)
        self.assert_rejected(begin, ap, END)

    def test_160_accepts_every_primary_in_supported_aligned_blocks(self):
        for first, center in ((36, 5250), (100, 5570), (149, 5815)):
            for slot in range(8):
                primary = first + 4 * slot
                with self.subTest(primary=primary, center=center):
                    begin = dict(BEGIN, band="5", channels=[primary])
                    ap = dict(AP, band="5", primary=primary, bandwidth="160",
                              secondary="above" if slot % 2 == 0 else "below",
                              center1_mhz=center, center2_mhz=None)
                    reader = SnapshotReader()
                    self.assertEqual(len(reader.feed(wire(begin, ap, END))), 1)

    def test_documented_fixture_keeps_last_success_after_timeout(self):
        reader = SnapshotReader()
        fixture = (ROOT / "tests/fixtures/wifi_analyzer_v1.ndjson").read_bytes()
        snapshots = reader.feed(fixture)
        reader.finish()
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(reader.terminal_count, 2)
        self.assertEqual(reader.last_snapshot["scan"], 1)
        self.assertEqual(len(reader.last_snapshot["aps"]), 2)
        self.assertEqual(reader.errors, [])

    def test_cli_accepts_fixture_and_rejects_incomplete_input(self):
        script = ROOT / "tools/wifi_analyzer_contract.py"
        good = subprocess.run([sys.executable, str(script)], input=wire(BEGIN, AP, END),
                              capture_output=True)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertTrue(good.stdout, "validator must return a JSON summary")
        self.assertEqual(json.loads(good.stdout)["snapshots"], 1)
        bad = subprocess.run([sys.executable, str(script)], input=wire(BEGIN, AP),
                             capture_output=True)
        self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()
