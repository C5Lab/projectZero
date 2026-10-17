#!/usr/bin/env python3
"""Build JWPS v2 candidate databases and validate v1/v2 images."""

# SPDX-FileCopyrightText: 2026 JanOS contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import binascii
from dataclasses import dataclass, field
import struct
from typing import Iterable

from .wps_sources import normalize_oui, normalize_pin, wps_checksum


MAGIC = b"JWPS"
VERSION = 2
HEADER_SIZE = 96
SECTION_COUNT = 8
MAX_U24 = 0xFFFFFF
HEADER = struct.Struct("<4sBBBBIII12s16I")

ALGORITHM_BITS = {
    "zhao": 0,
    "computepin_28": 1,
    "computepin_32": 2,
    "dlink": 3,
    "dlink1": 4,
    "asus": 5,
    "airocon": 6,
    "trendnet": 7,
    "invnic": 8,
    "arcadyan": 9,
}
SUPPORTED_ALGORITHMS = set(ALGORITHM_BITS) - {"arcadyan"}
RECORD_SIZES = {
    1: (7, 3, 5, 7, 7, 5, 3, 1),
    2: (7, 4, 5, 7, 7, 5, 4, 1),
}


@dataclass(eq=True)
class WpsDataset:
    oui_pins: dict[str, list[str]] = field(default_factory=dict)
    oui_algorithms: dict[str, list[str]] = field(default_factory=dict)
    model_pins: dict[str, list[str]] = field(default_factory=dict)
    vendor_pins: dict[str, list[str]] = field(default_factory=dict)
    ssid_pins: dict[int, list[str]] = field(default_factory=dict)
    common_pins: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class WpsImage:
    version: int
    source_id: int
    dataset: WpsDataset
    unsupported_algorithm_mappings: int


def _u24(value: int) -> bytes:
    if not 0 <= value <= MAX_U24:
        raise ValueError("value exceeds 24-bit field")
    return value.to_bytes(3, "little")


def _pack_pin(pin: str, version: int, *, validate_checksum: bool = True) -> bytes:
    normalized = normalize_pin(pin) if validate_checksum or version == 1 else pin
    if normalized is None or len(pin) != 8 or not pin.isascii() or not pin.isdigit():
        raise ValueError(f"invalid WPS PIN: {pin!r}")
    if version == 1:
        return _u24(int(pin[:7]))
    if version == 2:
        return int(pin).to_bytes(4, "little")
    raise ValueError(f"unsupported JWPS version: {version}")


def _unpack_pin(raw: bytes, version: int) -> str:
    value = int.from_bytes(raw, "little")
    if version == 1:
        if value > 9_999_999:
            raise ValueError("packed PIN exceeds seven digits")
        seven = f"{value:07d}"
        return seven + str(wps_checksum(value))
    if version == 2:
        if value > 99_999_999:
            raise ValueError("packed PIN exceeds eight digits")
        return f"{value:08d}"
    raise ValueError(f"unsupported JWPS version: {version}")


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _validated_rules(rules: dict, key_kind: str, version: int,
                     validate_checksums: bool) -> dict:
    result = {}
    for raw_key, raw_pins in rules.items():
        if key_kind == "oui":
            key = normalize_oui(raw_key)
            if key is None:
                raise ValueError(f"invalid OUI: {raw_key!r}")
        elif key_kind == "ssid":
            if not isinstance(raw_key, int) or not 0 <= raw_key <= 255:
                raise ValueError("SSID rule id must fit uint8")
            key = raw_key
        else:
            if (not isinstance(raw_key, str) or not raw_key or "\0" in raw_key or
                    len(raw_key.encode("utf-8")) > 255):
                raise ValueError(f"invalid {key_kind} rule key")
            if not raw_key.isascii():
                raise ValueError(f"{key_kind} rule key must be ASCII")
            key = raw_key
        pins = _unique(raw_pins)
        if len(pins) > 255:
            raise ValueError("a rule may contain at most 255 candidates")
        for pin in pins:
            _pack_pin(pin, version, validate_checksum=validate_checksums)
        result[key] = pins
    return result


def build_wps_blob(dataset: WpsDataset, source_id: int,
                   *, validate_checksums: bool = True,
                   version: int = VERSION) -> bytes:
    if not isinstance(source_id, int) or not 0 <= source_id <= 0xFFFFFFFF:
        raise ValueError("source_id must fit uint32")
    if version not in RECORD_SIZES:
        raise ValueError(f"unsupported JWPS version: {version}")
    pin_size = RECORD_SIZES[version][1]
    oui_pins = _validated_rules(dataset.oui_pins, "oui", version, validate_checksums)
    model_pins = _validated_rules(dataset.model_pins, "model", version, validate_checksums)
    vendor_pins = _validated_rules(dataset.vendor_pins, "vendor", version, validate_checksums)
    ssid_pins = _validated_rules(dataset.ssid_pins, "ssid", version, validate_checksums)
    common = _unique(dataset.common_pins)
    if len(common) > 0xFFFFFFFF:
        raise ValueError("too many common candidates")
    for pin in common:
        _pack_pin(pin, version, validate_checksum=validate_checksums)

    algorithms: dict[str, list[str]] = {}
    for raw_oui, names in dataset.oui_algorithms.items():
        oui = normalize_oui(raw_oui)
        if oui is None:
            raise ValueError(f"invalid OUI: {raw_oui!r}")
        unique = _unique(names)
        unknown = [name for name in unique if name not in ALGORITHM_BITS]
        if unknown:
            raise ValueError(f"unknown algorithm: {unknown[0]}")
        algorithms[oui] = unique

    pin_pool = bytearray()
    pool_offsets: dict[tuple[str, ...], tuple[int, int]] = {}

    def pool_ref(pins: list[str]) -> tuple[int, int]:
        key = tuple(pins)
        if key not in pool_offsets:
            offset = len(pin_pool) // pin_size
            for pin in pins:
                pin_pool.extend(_pack_pin(pin, version,
                                          validate_checksum=validate_checksums))
            pool_offsets[key] = (offset, len(pins))
        return pool_offsets[key]

    strings = bytearray()
    string_offsets: dict[str, int] = {}

    def string_ref(value: str) -> int:
        if value not in string_offsets:
            encoded = value.encode("utf-8")
            offset = len(strings)
            strings.append(len(encoded))
            strings.extend(encoded)
            string_offsets[value] = offset
        return string_offsets[value]

    static_index = bytearray()
    for oui in sorted(oui_pins):
        offset, count = pool_ref(oui_pins[oui])
        static_index.extend(bytes.fromhex(oui))
        static_index.extend(_u24(offset))
        static_index.append(count)

    algo_index = bytearray()
    for oui in sorted(algorithms):
        mask = sum(1 << ALGORITHM_BITS[name] for name in algorithms[oui])
        algo_index.extend(bytes.fromhex(oui))
        algo_index.extend(mask.to_bytes(2, "little"))

    def make_string_rules(rules: dict[str, list[str]]) -> bytearray:
        records = bytearray()
        for name in sorted(rules, key=lambda value: value.casefold()):
            offset, count = pool_ref(rules[name])
            records.extend(_u24(string_ref(name)))
            records.extend(_u24(offset))
            records.append(count)
        return records

    model_index = make_string_rules(model_pins)
    vendor_index = make_string_rules(vendor_pins)
    ssid_index = bytearray()
    for rule_id in sorted(ssid_pins):
        offset, count = pool_ref(ssid_pins[rule_id])
        ssid_index.append(rule_id)
        ssid_index.extend(_u24(offset))
        ssid_index.append(count)
    common_blob = b"".join(_pack_pin(pin, version,
                                     validate_checksum=validate_checksums) for pin in common)

    sections = [static_index, pin_pool, algo_index, model_index, vendor_index,
                ssid_index, bytearray(common_blob), strings]
    offsets = []
    cursor = HEADER_SIZE
    counts = [len(static_index) // 7, len(pin_pool) // pin_size, len(algo_index) // 5,
              len(model_index) // 7, len(vendor_index) // 7, len(ssid_index) // 5,
              len(common_blob) // pin_size, len(strings)]
    for section in sections:
        offsets.append(cursor)
        cursor += len(section)
    payload = b"".join(bytes(section) for section in sections)
    pairs = [item for pair in zip(offsets, counts) for item in pair]
    header = HEADER.pack(MAGIC, version, HEADER_SIZE, SECTION_COUNT, 0,
                         HEADER_SIZE + len(payload), binascii.crc32(payload) & 0xFFFFFFFF,
                         source_id, bytes(12), *pairs)
    return header + payload


def _ranges(blob: bytes, pairs: list[tuple[int, int]],
            record_sizes: tuple[int, ...]) -> list[tuple[int, int]]:
    ranges = []
    for index, ((offset, count), size) in enumerate(zip(pairs, record_sizes)):
        length = count if index == 7 else count * size
        if offset < HEADER_SIZE or offset > len(blob) or length > len(blob) - offset:
            raise ValueError(f"section {index} outside file")
        ranges.append((offset, offset + length))
    nonempty = sorted(pair for pair in ranges if pair[0] != pair[1])
    for previous, current in zip(nonempty, nonempty[1:]):
        if current[0] < previous[1]:
            raise ValueError("section overlap")
    return ranges


def parse_wps_blob(blob: bytes) -> WpsImage:
    if len(blob) < HEADER_SIZE:
        raise ValueError("truncated JWPS header")
    unpacked = HEADER.unpack_from(blob)
    magic, version, header_size, section_count, flags = unpacked[:5]
    file_size, payload_crc, source_id, reserved = unpacked[5:9]
    if magic != MAGIC or version not in RECORD_SIZES or header_size != HEADER_SIZE or section_count != SECTION_COUNT or flags:
        raise ValueError("unsupported JWPS header")
    if reserved != bytes(12):
        raise ValueError("reserved header bytes must be zero")
    if file_size != len(blob):
        raise ValueError("declared file size differs from actual length")
    if binascii.crc32(blob[HEADER_SIZE:]) & 0xFFFFFFFF != payload_crc:
        raise ValueError("payload CRC mismatch")
    raw_pairs = unpacked[9:]
    pairs = list(zip(raw_pairs[::2], raw_pairs[1::2]))
    record_sizes = RECORD_SIZES[version]
    ranges = _ranges(blob, pairs, record_sizes)

    pool_start, pool_end = ranges[1]
    pin_size = record_sizes[1]
    pool = [_unpack_pin(blob[pos:pos + pin_size], version)
            for pos in range(pool_start, pool_end, pin_size)]

    strings_start, strings_end = ranges[7]
    strings: dict[int, str] = {}
    cursor = strings_start
    while cursor < strings_end:
        relative = cursor - strings_start
        length = blob[cursor]
        cursor += 1
        if length == 0 or length > strings_end - cursor:
            raise ValueError("invalid string table")
        try:
            value = blob[cursor:cursor + length].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid string table UTF-8") from exc
        if not value.isascii():
            raise ValueError("string rule key must be ASCII")
        strings[relative] = value
        cursor += length

    def pins_at(offset: int, count: int) -> list[str]:
        if offset > len(pool) or count > len(pool) - offset:
            raise ValueError("candidate pool reference outside section")
        return pool[offset:offset + count]

    oui_pins = {}
    start, end = ranges[0]
    previous = -1
    for pos in range(start, end, 7):
        key = int.from_bytes(blob[pos:pos + 3], "big")
        if key <= previous:
            raise ValueError("OUI static index is not sorted")
        previous = key
        offset = int.from_bytes(blob[pos + 3:pos + 6], "little")
        oui_pins[f"{key:06X}"] = pins_at(offset, blob[pos + 6])

    oui_algorithms = {}
    unsupported = 0
    start, end = ranges[2]
    previous = -1
    bit_names = {bit: name for name, bit in ALGORITHM_BITS.items()}
    for pos in range(start, end, 5):
        key = int.from_bytes(blob[pos:pos + 3], "big")
        if key <= previous:
            raise ValueError("OUI algorithm index is not sorted")
        previous = key
        mask = int.from_bytes(blob[pos + 3:pos + 5], "little")
        if mask & ~sum(1 << bit for bit in bit_names):
            raise ValueError("unknown algorithm bit")
        names = [bit_names[bit] for bit in sorted(bit_names) if mask & (1 << bit)]
        unsupported += sum(name not in SUPPORTED_ALGORITHMS for name in names)
        oui_algorithms[f"{key:06X}"] = names

    def parse_string_rules(section_index: int) -> dict[str, list[str]]:
        output = {}
        start, end = ranges[section_index]
        previous = None
        for pos in range(start, end, 7):
            string_offset = int.from_bytes(blob[pos:pos + 3], "little")
            if string_offset not in strings:
                raise ValueError("string reference is not an entry boundary")
            name = strings[string_offset]
            order = name.casefold()
            if previous is not None and order <= previous:
                raise ValueError("string rule index is not sorted")
            previous = order
            pool_offset = int.from_bytes(blob[pos + 3:pos + 6], "little")
            output[name] = pins_at(pool_offset, blob[pos + 6])
        return output

    ssid_pins = {}
    start, end = ranges[5]
    previous = -1
    for pos in range(start, end, 5):
        rule_id = blob[pos]
        if rule_id <= previous:
            raise ValueError("SSID rule index is not sorted")
        previous = rule_id
        offset = int.from_bytes(blob[pos + 1:pos + 4], "little")
        ssid_pins[rule_id] = pins_at(offset, blob[pos + 4])

    start, end = ranges[6]
    common = [_unpack_pin(blob[pos:pos + pin_size], version)
              for pos in range(start, end, pin_size)]
    dataset = WpsDataset(oui_pins, oui_algorithms, parse_string_rules(3),
                         parse_string_rules(4), ssid_pins, common)
    return WpsImage(version, source_id, dataset, unsupported)
