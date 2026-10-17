#!/usr/bin/env python3
"""Build and validate the compact JanOS JVND v3 vendor database format."""

from __future__ import annotations

import argparse
import binascii
from dataclasses import dataclass
import logging
from pathlib import Path
import re
import struct
from typing import Iterable


LOGGER = logging.getLogger(__name__)

MAGIC = b"JVND"
VERSION = 3
HEADER_SIZE = 64
SECTION_COUNT = 4
MAX_NAME_BYTES = 60
MAX_U24 = 0xFFFFFF
HEADER = struct.Struct("<4sBBBB11I12s")
RECORD_SIZE = {24: 6, 28: 7, 36: 8}
PREFIX_BYTES = {24: 3, 28: 4, 36: 5}
PREFIX_PATTERN = re.compile(r"^[0-9A-Fa-f]+$")
C_ENTRY_PATTERN = re.compile(
    r'^\s*\{\s*\{\s*(?P<bytes>(?:0x[0-9A-Fa-f]{2}\s*,?\s*)+)'
    r'\}\s*,\s*"(?P<short>(?:\\.|[^"\\])*)"\s*,\s*'
    r'"(?P<long>(?:\\.|[^"\\])*)"\s*\}\s*,\s*$'
)


@dataclass(frozen=True, order=True)
class VendorRecord:
    prefix_bits: int
    prefix: int
    name: str


@dataclass(frozen=True)
class VendorImage:
    source_id: int
    records: tuple[VendorRecord, ...]
    counts: dict[int, int]


def _normalize_name(name: str) -> str:
    normalized = " ".join(name.split())
    if not normalized:
        raise ValueError("vendor name must not be empty")
    encoded = normalized.encode("utf-8")
    if len(encoded) > MAX_NAME_BYTES:
        encoded = encoded[:MAX_NAME_BYTES]
        while True:
            try:
                normalized = encoded.decode("utf-8")
                break
            except UnicodeDecodeError:
                encoded = encoded[:-1]
    return normalized


def _validate_record(record: VendorRecord) -> VendorRecord:
    if record.prefix_bits not in RECORD_SIZE:
        raise ValueError(f"unsupported prefix length: {record.prefix_bits}")
    if not isinstance(record.prefix, int) or not 0 <= record.prefix < (1 << record.prefix_bits):
        raise ValueError(f"prefix does not fit /{record.prefix_bits}: {record.prefix!r}")
    if not isinstance(record.name, str):
        raise ValueError("vendor name must be text")
    return VendorRecord(record.prefix_bits, record.prefix, _normalize_name(record.name))


def _parse_prefix(token: str) -> tuple[int, int]:
    if "/" in token:
        address, suffix = token.rsplit("/", 1)
        try:
            bits = int(suffix, 10)
        except ValueError as exc:
            raise ValueError(f"invalid prefix length: {token}") from exc
    else:
        address = token
        bits = 24

    if bits not in RECORD_SIZE:
        raise ValueError(f"unsupported prefix length: {bits}")
    compact = re.sub(r"[:-]", "", address)
    if len(compact) != bits // 4 or not PREFIX_PATTERN.fullmatch(compact):
        raise ValueError(f"prefix width does not match /{bits}: {token}")
    return bits, int(compact, 16)


def parse_manuf(text: str) -> list[VendorRecord]:
    """Parse supported Wireshark manuf prefixes, keeping the first duplicate."""
    records: list[VendorRecord] = []
    seen: set[tuple[int, int]] = set()
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            raise ValueError(f"line {line_number}: missing vendor name")
        bits, prefix = _parse_prefix(fields[0])
        record = _validate_record(VendorRecord(bits, prefix, fields[1]))
        key = (record.prefix_bits, record.prefix)
        if key in seen:
            LOGGER.warning(
                "line %d: duplicate /%d prefix %x ignored; first entry wins",
                line_number,
                record.prefix_bits,
                record.prefix,
            )
            continue
        seen.add(key)
        records.append(record)
    return records


def _unescape_generated_c_string(value: str) -> str:
    return value.replace(r'\"', '"')


def parse_manuf_data_c(text: str) -> list[VendorRecord]:
    """Parse the three generated vendor tables in current Wireshark sources."""
    records: list[VendorRecord] = []
    seen: set[tuple[int, int]] = set()
    for bits in (24, 28, 36):
        declaration = (
            rf"static const manuf_oui{bits}_t "
            rf"global_manuf_oui{bits}_table\[\] = \{{(?P<body>.*?)\n\}};"
        )
        sections = list(re.finditer(declaration, text, re.DOTALL))
        if len(sections) != 1:
            raise ValueError(f"expected exactly one Wireshark /{bits} table")
        body = sections[0].group("body")
        for line_number, line in enumerate(body.splitlines(), 1):
            if not line.strip():
                continue
            match = C_ENTRY_PATTERN.fullmatch(line)
            if match is None:
                raise ValueError(f"invalid entry in Wireshark /{bits} table at row {line_number}")
            octets = [int(value, 16) for value in re.findall(r"0x([0-9A-Fa-f]{2})", match.group("bytes"))]
            if len(octets) != PREFIX_BYTES[bits]:
                raise ValueError(f"wrong byte count in Wireshark /{bits} table")
            packed = int.from_bytes(bytes(octets), "big")
            if bits != 24:
                if packed & 0x0F:
                    raise ValueError(f"/{bits} prefix has non-zero unused nibble")
                prefix = packed >> 4
            else:
                prefix = packed
            long_name = _unescape_generated_c_string(match.group("long"))
            short_name = _unescape_generated_c_string(match.group("short"))
            record = _validate_record(VendorRecord(bits, prefix, long_name or short_name))
            key = (bits, prefix)
            if key in seen:
                LOGGER.warning(
                    "duplicate /%d prefix %x ignored; first entry wins", bits, prefix
                )
                continue
            seen.add(key)
            records.append(record)
    return records


def _prefix_bytes(record: VendorRecord) -> bytes:
    byte_count = PREFIX_BYTES[record.prefix_bits]
    value = record.prefix if record.prefix_bits == 24 else record.prefix << 4
    return value.to_bytes(byte_count, "big")


def _u24le(value: int) -> bytes:
    if not 0 <= value <= MAX_U24:
        raise ValueError("name offset exceeds 24-bit field")
    return value.to_bytes(3, "little")


def build_vendor_blob(records: Iterable[VendorRecord], source_id: int) -> bytes:
    if not isinstance(source_id, int) or not 0 <= source_id <= 0xFFFFFFFF:
        raise ValueError("source_id must fit uint32")

    unique: dict[tuple[int, int], VendorRecord] = {}
    for raw_record in records:
        record = _validate_record(raw_record)
        key = (record.prefix_bits, record.prefix)
        if key in unique:
            LOGGER.warning(
                "duplicate /%d prefix %x ignored; first entry wins",
                record.prefix_bits,
                record.prefix,
            )
            continue
        unique[key] = record
    ordered = sorted(unique.values(), key=lambda item: (item.prefix_bits, item.prefix))

    names = bytearray()
    name_offsets: dict[str, int] = {}
    indexes = {24: bytearray(), 28: bytearray(), 36: bytearray()}
    counts = {24: 0, 28: 0, 36: 0}

    for record in ordered:
        encoded_name = record.name.encode("utf-8")
        if record.name not in name_offsets:
            offset = len(names)
            if offset > MAX_U24:
                raise ValueError("name table exceeds 24-bit offsets")
            name_offsets[record.name] = offset
            names.append(len(encoded_name))
            names.extend(encoded_name)
        indexes[record.prefix_bits].extend(_prefix_bytes(record))
        indexes[record.prefix_bits].extend(_u24le(name_offsets[record.name]))
        counts[record.prefix_bits] += 1

    index24_offset = HEADER_SIZE
    index28_offset = index24_offset + len(indexes[24])
    index36_offset = index28_offset + len(indexes[28])
    names_offset = index36_offset + len(indexes[36])
    payload = bytes(indexes[24] + indexes[28] + indexes[36] + names)
    file_size = HEADER_SIZE + len(payload)
    if file_size > 0xFFFFFFFF:
        raise ValueError("vendor database exceeds uint32 file size")

    header = HEADER.pack(
        MAGIC,
        VERSION,
        HEADER_SIZE,
        SECTION_COUNT,
        0,
        file_size,
        binascii.crc32(payload) & 0xFFFFFFFF,
        source_id,
        names_offset,
        len(names),
        index24_offset,
        counts[24],
        index28_offset,
        counts[28],
        index36_offset,
        counts[36],
        bytes(12),
    )
    return header + payload


def _checked_range(offset: int, size: int, file_size: int, label: str) -> tuple[int, int]:
    if offset < HEADER_SIZE or offset > file_size:
        raise ValueError(f"{label} offset outside payload")
    if size < 0 or size > file_size - offset:
        raise ValueError(f"{label} size outside file")
    return offset, offset + size


def _parse_names(blob: bytes, start: int, end: int) -> dict[int, str]:
    names: dict[int, str] = {}
    cursor = start
    while cursor < end:
        relative = cursor - start
        length = blob[cursor]
        cursor += 1
        if length == 0 or length > MAX_NAME_BYTES or length > end - cursor:
            raise ValueError("invalid or truncated name table entry")
        try:
            name = blob[cursor : cursor + length].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid UTF-8 in name table") from exc
        names[relative] = name
        cursor += length
    if cursor != end:
        raise ValueError("truncated name table")
    return names


def _parse_index(
    blob: bytes,
    start: int,
    count: int,
    bits: int,
    names: dict[int, str],
) -> list[VendorRecord]:
    records: list[VendorRecord] = []
    size = RECORD_SIZE[bits]
    prefix_bytes = PREFIX_BYTES[bits]
    previous = -1
    for position in range(count):
        offset = start + position * size
        raw_prefix = blob[offset : offset + prefix_bytes]
        packed_prefix = int.from_bytes(raw_prefix, "big")
        if bits != 24:
            if packed_prefix & 0x0F:
                raise ValueError(f"/{bits} prefix has non-zero unused nibble")
            prefix = packed_prefix >> 4
        else:
            prefix = packed_prefix
        if prefix <= previous:
            raise ValueError(f"/{bits} index is not strictly sorted")
        previous = prefix
        name_offset = int.from_bytes(
            blob[offset + prefix_bytes : offset + prefix_bytes + 3], "little"
        )
        if name_offset not in names:
            raise ValueError("index name offset is not an entry boundary")
        records.append(VendorRecord(bits, prefix, names[name_offset]))
    return records


def parse_vendor_blob(blob: bytes) -> VendorImage:
    if len(blob) < HEADER_SIZE:
        raise ValueError("truncated JVND header")
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
    ) = HEADER.unpack_from(blob)

    if magic != MAGIC or version != VERSION:
        raise ValueError("unsupported JVND magic or version")
    if header_size != HEADER_SIZE or section_count != SECTION_COUNT or flags != 0:
        raise ValueError("invalid JVND header metadata")
    if file_size != len(blob):
        raise ValueError("declared file_size differs from actual length")
    if reserved != bytes(12):
        raise ValueError("reserved header bytes must be zero")
    if binascii.crc32(blob[HEADER_SIZE:]) & 0xFFFFFFFF != payload_crc:
        raise ValueError("payload CRC mismatch")

    ranges = [
        (*_checked_range(index24_offset, index24_count * RECORD_SIZE[24], file_size, "index24"), "index24"),
        (*_checked_range(index28_offset, index28_count * RECORD_SIZE[28], file_size, "index28"), "index28"),
        (*_checked_range(index36_offset, index36_count * RECORD_SIZE[36], file_size, "index36"), "index36"),
        (*_checked_range(names_offset, names_size, file_size, "names"), "names"),
    ]
    nonempty = sorted((start, end, label) for start, end, label in ranges if start != end)
    for previous, current in zip(nonempty, nonempty[1:]):
        if current[0] < previous[1]:
            raise ValueError(f"section overlap: {previous[2]} and {current[2]}")

    names = _parse_names(blob, names_offset, names_offset + names_size)
    records = []
    records.extend(_parse_index(blob, index24_offset, index24_count, 24, names))
    records.extend(_parse_index(blob, index28_offset, index28_count, 28, names))
    records.extend(_parse_index(blob, index36_offset, index36_count, 36, names))
    return VendorImage(
        source_id=source_id,
        records=tuple(records),
        counts={24: index24_count, 28: index28_count, 36: index36_count},
    )


def _source_id(value: str) -> int:
    if not re.fullmatch(r"[0-9A-Fa-f]{8}", value):
        raise argparse.ArgumentTypeError("source id must be exactly eight hexadecimal digits")
    return int(value, 16)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-id", type=_source_id, required=True)
    args = parser.parse_args()

    records = parse_manuf(args.input.read_text(encoding="utf-8"))
    blob = build_vendor_blob(records, args.source_id)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(blob)
    image = parse_vendor_blob(blob)
    print(
        f"JVND-3 bytes={len(blob)} /24={image.counts[24]} "
        f"/28={image.counts[28]} /36={image.counts[36]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
