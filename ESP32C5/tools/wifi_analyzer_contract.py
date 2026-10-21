"""Validate WFA/1 snapshot streams, without ESP-IDF or a compiler.

This is a host reference reader, not a JanOS driver implementation.
Read a capture from stdin or a file and exit nonzero for malformed/incomplete
snapshots. Control replies and unrelated console lines are outside this validator.
"""

import argparse
import copy
import json
import re
import sys

PREFIX = b"[WFA1] "
MAX_LINE_BYTES = 1024  # Includes the prefix; excludes CR/LF.
CHANNELS_5 = tuple(range(36, 65, 4)) + tuple(range(100, 145, 4)) + tuple(range(149, 178, 4))


class ContractError(ValueError):
    """A wire record or transaction violates the WFA/1 contract."""


def require(condition, message):
    if not condition:
        raise ContractError(message)


def integer(record, key, low, high):
    value = record.get(key)
    require(type(value) is int and low <= value <= high, f"invalid {key}")
    return value


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_constant(value):
    raise ContractError(f"non-JSON number: {value}")


def channel_band(channel):
    require(type(channel) is int, "channel must be an integer")
    if 1 <= channel <= 14:
        return "2.4"
    require(channel in CHANNELS_5, "unsupported primary channel")
    return "5"


def primary_frequency(channel):
    if channel == 14:
        return 2484
    return 2407 + 5 * channel if channel <= 13 else 5000 + 5 * channel


def validate_width(record):
    for field in ("bandwidth", "secondary", "center1_mhz", "center2_mhz"):
        require(field in record, f"missing {field}")
    width = record["bandwidth"]
    secondary = record["secondary"]
    c1, c2 = record["center1_mhz"], record["center2_mhz"]
    if width is None:
        require(secondary is None and c1 is None and c2 is None,
                "unknown width must have unknown geometry")
        return
    require(width in ("20", "40", "80", "160", "80+80"), "unsupported bandwidth")
    require(type(c1) is int, "known width requires center1_mhz")
    require(2400 <= c1 <= 2500 if record["band"] == "2.4" else 5000 <= c1 <= 5900,
            "center frequency outside band")
    frequency = primary_frequency(record["primary"])
    if width == "20":
        require(c1 == frequency and secondary == "none" and c2 is None,
                "invalid 20 MHz geometry")
        return
    require(secondary in ("above", "below"), "wide channel requires secondary")
    sign = 1 if secondary == "above" else -1
    other = record["primary"] + sign * 4
    require(channel_band(other) == record["band"] and other != 14 and record["primary"] != 14,
            "invalid secondary channel")
    if width == "40":
        require(c1 == frequency + sign * 10 and c2 is None, "invalid 40 MHz geometry")
        return
    require(record["band"] == "5", "80/160 MHz requires 5 GHz")
    if width == "160":
        require(c1 in (5250, 5570, 5815), "160 MHz requires an aligned full-channel center")
    offsets = (10, 30, 50, 70) if width == "160" else (10, 30)
    require(abs(frequency - c1) in offsets, "primary outside wide channel")
    # Primary and its HT40 partner must belong to the same 40 MHz sub-block.
    low = c1 - (80 if width == "160" else 40)
    primary_slot = (frequency - low - 10) // 20
    require(secondary == ("above" if primary_slot % 2 == 0 else "below"),
            "secondary disagrees with primary sub-block")
    if width == "80+80":
        require(type(c2) is int and 5000 <= c2 <= 5900 and abs(c2 - c1) > 80,
                "80+80 requires a separate non-adjacent second segment")
    else:
        require(c2 is None, "contiguous width must not have center2_mhz")


class SnapshotReader:
    """One reader per transport/boot. Commit only a complete, valid snapshot.

    Protocol errors invalidate the working snapshot, preserve the previous one,
    and recover at a later valid begin. Error messages are bounded to 32 entries.
    Call finish() on EOF/disconnect; feed() accepts arbitrarily fragmented bytes.
    """

    def __init__(self):
        self.last_snapshot = None
        self.errors = []
        self.error_count = 0
        self.terminal_count = 0
        self.snapshot_count = 0
        self._line = bytearray()
        self._dropping = False
        self._pending = None
        self._boot = None
        self._last_scan = 0
        self._bssids = set()

    def _error(self, message):
        self.error_count += 1
        if len(self.errors) < 32:
            self.errors.append(message)
        self._pending = None
        self._bssids.clear()

    def feed(self, chunk):
        published = []
        for byte in chunk:
            if byte in (10, 13):
                if not self._dropping and self._line:
                    snapshot = self._process_line(bytes(self._line))
                    if snapshot is not None:
                        published.append(snapshot)
                self._line.clear()
                self._dropping = False
            elif not self._dropping:
                if len(self._line) == MAX_LINE_BYTES:
                    if self._line.startswith(PREFIX) or self._pending is not None:
                        self._error("line exceeds 1024 bytes")
                    self._line.clear()
                    self._dropping = True
                else:
                    self._line.append(byte)
        return published

    def _process_line(self, line):
        if not line.startswith(PREFIX):
            return None
        try:
            record = json.loads(line[len(PREFIX):].decode("utf-8"),
                                object_pairs_hook=unique_keys, parse_constant=reject_constant)
            require(isinstance(record, dict), "record must be an object")
            integer(record, "v", 1, 1)
            require(isinstance(record.get("boot"), str) and
                    re.fullmatch(r"[0-9a-f]{16}", record["boot"]), "invalid boot identity")
            integer(record, "scan", 1, 0xFFFFFFFF)
            kind = record.get("type")
            if kind == "begin":
                self._begin(record)
            else:
                require(self._pending is not None, "record without begin")
                require(record["boot"] == self._pending["boot"] and
                        record["scan"] == self._pending["scan"], "transaction identity mismatch")
                if kind == "ap":
                    self._ap(record)
                elif kind == "end":
                    return self._end(record)
                else:
                    raise ContractError("unknown record type")
        except (ContractError, ValueError, TypeError, RecursionError) as error:
            self._error(str(error))
        return None

    def _begin(self, record):
        require(self._boot in (None, record["boot"]), "boot changed; reconnect with a new reader")
        require(record["scan"] > self._last_scan, "scan identity reused or out of order")
        integer(record, "limit", 1, 128)
        integer(record, "started_ms", 0, (1 << 63) - 1)
        require(record.get("band") in ("2.4", "5", "both"), "invalid band")
        require(record.get("profile") in ("quick", "detailed", "passive"), "invalid profile")
        channels = record.get("channels")
        require(isinstance(channels, list) and 0 < len(channels) <= 42, "invalid channel list")
        for channel in channels:
            band = channel_band(channel)
            require(record["band"] in ("both", band), "channel outside band")
        require(len(set(channels)) == len(channels), "duplicate channels")
        if self._pending is not None:
            self._error("new begin interrupted an incomplete snapshot")
        self._boot = record["boot"]
        self._last_scan = record["scan"]
        self._pending = copy.deepcopy(record)
        self._pending["aps"] = []
        self._bssids.clear()

    def _ap(self, record):
        pending = self._pending
        seq = integer(record, "seq", 0, 127)
        require(seq == len(pending["aps"]), "missing or out-of-order AP record")
        require(seq < pending["limit"], "snapshot exceeds capacity")
        bssid = record.get("bssid")
        require(isinstance(bssid, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", bssid),
                "invalid BSSID")
        require(bssid.lower() not in self._bssids, "duplicate BSSID")
        ssid = record.get("ssid_hex")
        require(isinstance(ssid, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,32}", ssid),
                "invalid SSID bytes")
        require(channel_band(record.get("primary")) == record.get("band"), "channel/band mismatch")
        require(record["primary"] in pending["channels"], "channel outside scan scope")
        integer(record, "rssi", -127, 20)
        require(isinstance(record.get("auth"), str) and 0 < len(record["auth"]) <= 32,
                "invalid auth label")
        phy = record.get("phy")
        require(isinstance(phy, list) and all(isinstance(item, str) and item in
                ("11a", "11b", "11g", "11n", "11ac", "11ax", "lr") for item in phy),
                "invalid PHY list")
        require(len(phy) == len(set(phy)), "duplicate PHY flags")
        validate_width(record)
        self._bssids.add(bssid.lower())
        pending["aps"].append(copy.deepcopy(record))

    def _end(self, record):
        pending = self._pending
        integer(record, "duration_ms", 0, (1 << 63) - 1)
        returned = integer(record, "returned", 0, pending["limit"])
        require(returned == len(pending["aps"]), "returned count disagrees with wire records")
        require(type(record.get("truncated")) is bool, "truncated must be boolean")
        status = record.get("status")
        require(status in ("ok", "error", "cancelled", "timeout"), "invalid terminal status")
        if status == "ok":
            found = integer(record, "found", 0, 65535)
            require(found >= returned, "found less than returned")
            require(record["truncated"] == (found > returned), "incorrect truncation flag")
            require(returned == min(found, pending["limit"]), "unexpected missing results")
        else:
            require("found" in record and record["found"] is None and not record["truncated"],
                    "failed scan must not claim a complete count")
            require(isinstance(record.get("code"), str) and 0 < len(record["code"]) <= 64,
                    "failed scan requires code")
        self._pending = None
        self._bssids.clear()
        self.terminal_count += 1
        if status != "ok":
            return None
        snapshot = copy.deepcopy(pending)
        for key in ("status", "found", "returned", "truncated", "duration_ms"):
            snapshot[key] = record[key]
        snapshot["type"] = "snapshot"
        self.last_snapshot = snapshot
        self.snapshot_count += 1
        return copy.deepcopy(snapshot)

    def finish(self):
        partial_protocol = self._line.startswith(PREFIX) or (
            bool(self._line) and PREFIX.startswith(self._line))
        if self._pending is not None or partial_protocol or self._dropping:
            self._error("incomplete snapshot or line at end of stream")
            self._line.clear()
            self._dropping = False
            raise ContractError("incomplete snapshot or line at end of stream")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", nargs="?", help="capture file; default: stdin")
    args = parser.parse_args()
    reader = SnapshotReader()
    stream = open(args.capture, "rb") if args.capture else sys.stdin.buffer
    try:
        while chunk := stream.read(4096):
            reader.feed(chunk)
        try:
            reader.finish()
        except ContractError:
            pass  # Already counted by finish().
    finally:
        if args.capture:
            stream.close()
    print(json.dumps({"snapshots": reader.snapshot_count, "terminals": reader.terminal_count,
                      "errors": reader.error_count, "details": reader.errors}))
    return 1 if reader.error_count or not reader.terminal_count else 0


if __name__ == "__main__":
    sys.exit(main())
