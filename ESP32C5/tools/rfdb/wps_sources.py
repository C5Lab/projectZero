#!/usr/bin/env python3
"""Parse and normalize the locked WPS PIN source datasets."""

# SPDX-FileCopyrightText: 2026 JanOS contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
import csv
import io
import re
from typing import MutableMapping


ALGO_ALIASES = {
    "zhao": "zhao",
    "computepin": "zhao",
    "asus": "asus",
    "dlink": "dlink",
    "dlink1": "dlink1",
    "airocon": "airocon",
    "thirtytwo": "computepin_32",
    "twentyeight": "computepin_28",
    "trend": "trendnet",
    "arcady": "arcadyan",
}

AIRGEDDON_ROW = re.compile(r'^\s*PINDB\["(?P<oui>[^"]+)"\]="(?P<items>[^"]*)"\s*$')


@dataclass
class SourceReport:
    accepted: int = 0
    duplicates: int = 0
    malformed: int = 0
    invalid_checksums_preserved: int = 0
    unknown_algorithms: dict[str, int] = field(default_factory=dict)


def wps_checksum(seven_digits: int) -> int:
    if not 0 <= seven_digits <= 9_999_999:
        raise ValueError("WPS PIN payload must contain at most seven digits")
    accumulator = 0
    value = seven_digits
    while value:
        accumulator += 3 * (value % 10)
        value //= 10
        accumulator += value % 10
        value //= 10
    return (10 - accumulator % 10) % 10


def normalize_pin(text: str) -> str | None:
    if not isinstance(text, str) or not text.isascii() or not text.isdigit():
        return None
    if len(text) == 7:
        return text + str(wps_checksum(int(text)))
    if len(text) != 8:
        return None
    return text if int(text[-1]) == wps_checksum(int(text[:7])) else None


def normalize_source_pin(text: str) -> str | None:
    """Normalize source data without rewriting literal eight-digit values."""
    if not isinstance(text, str) or not text.isascii() or not text.isdigit():
        return None
    if len(text) == 7:
        return text + str(wps_checksum(int(text)))
    return text if len(text) == 8 else None


def normalize_oui(text: str) -> str | None:
    if not isinstance(text, str):
        return None
    compact = text.replace(":", "").replace("-", "")
    if re.fullmatch(r"[0-9A-Fa-f]{6}", compact) is None:
        return None
    return compact.upper()


def _append_unique(table: MutableMapping[str, list[str]], key: str, value: str,
                   report: SourceReport) -> None:
    values = table.setdefault(key, [])
    if value in values:
        report.duplicates += 1
        return
    values.append(value)
    report.accepted += 1


def load_airgeddon(text: str) -> tuple[dict[str, list[str]], SourceReport]:
    pins: dict[str, list[str]] = defaultdict(list)
    report = SourceReport()
    for raw_line in text.splitlines():
        if "PINDB[" not in raw_line:
            continue
        match = AIRGEDDON_ROW.fullmatch(raw_line)
        if match is None:
            report.malformed += 1
            continue
        oui = normalize_oui(match.group("oui"))
        if oui is None:
            report.malformed += 1
            continue
        for raw_pin in match.group("items").split():
            pin = normalize_source_pin(raw_pin)
            if pin is None:
                report.malformed += 1
                continue
            if normalize_pin(pin) is None:
                report.invalid_checksums_preserved += 1
            _append_unique(pins, oui, pin, report)
    return dict(pins), report


def load_default_wps(
    text: str,
    existing: MutableMapping[str, list[str]] | None = None,
) -> tuple[dict[str, list[str]], dict[str, list[str]], SourceReport]:
    pins = {key: list(values) for key, values in (existing or {}).items()}
    algorithms: dict[str, list[str]] = defaultdict(list)
    report = SourceReport()
    unknown: dict[str, int] = defaultdict(int)

    for row in csv.reader(io.StringIO(text)):
        if not row or all(not field.strip() for field in row):
            continue
        if len(row) != 2:
            report.malformed += 1
            continue
        item = row[0].strip()
        oui = normalize_oui(row[1].strip())
        if oui is None or not item:
            report.malformed += 1
            continue
        alias = ALGO_ALIASES.get(item.lower())
        if alias is not None:
            _append_unique(algorithms, oui, alias, report)
            continue
        pin = normalize_source_pin(item)
        if pin is not None:
            if normalize_pin(pin) is None:
                report.invalid_checksums_preserved += 1
            _append_unique(pins, oui, pin, report)
            continue
        if item.isascii() and item.isalpha():
            unknown[item.lower()] += 1
        else:
            report.malformed += 1

    report.unknown_algorithms = dict(sorted(unknown.items()))
    return pins, dict(algorithms), report
