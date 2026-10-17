#!/usr/bin/env python3
"""Build a JWPS v1 database from locked Airgeddon and Default-WPS-PINs inputs."""

# SPDX-FileCopyrightText: 2026 JanOS contributors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from urllib.request import Request, urlopen

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.rfdb.provenance import SourceRecord, canonical_lock_bytes, load_lock, verify_bytes
from tools.rfdb.wps_format import WpsDataset, build_wps_blob, parse_wps_blob
from tools.rfdb.wps_sources import load_airgeddon, load_default_wps, normalize_pin


SOURCE_IDS = ("airgeddon_known_pins", "default_wps_pins")
MAX_SOURCE_BYTES = 2 * 1024 * 1024

MODEL_PINS = {
    "DIR-615": ["12345670", "68175542"],
    "DIR-645": ["12345670"],
    "DSL-2740R": ["68175542"],
    "WNR2000": ["12345670"],
    "HG532c": ["12345670"],
    "TD-W8961ND": ["12345670"],
    "TD-W8951ND": ["12345670"],
}

VENDOR_PINS = {
    "comtrend": ["18811728", "20172527", "18836486", "49385052", "12715657"],
    "adb": ["16538061", "88202907", "13409708", "47148826", "77828491"],
    "netgear": ["12345670", "37380342", "42375852", "30022645", "49945386"],
    "d-link": ["46264848", "20172527", "21464065", "68175542", "76229909"],
    "belkin|arcadyan": ["12885381", "14989346", "53704825", "40770765"],
    "tp-link": ["61116597", "11997870", "41236079", "54080812"],
    "huawei": ["12345670", "25905892", "85275560", "24684323"],
    "askey": ["12345670", "20859978", "51327330", "23659391"],
    "zyxel": ["11866428", "38163289", "15843128", "66202240"],
    "linksys|cisco": ["70066647", "66026402", "04387411", "13317249"],
    "thomson|technicolor": ["67958146", "59762454", "74673841", "83712630"],
    "edimax": ["35611530", "58227046", "85521162"],
    "upvel": ["20854836", "43977680", "05294176"],
    "tenda": ["40881768", "28818885", "01756401"],
}

SSID_PINS = {
    1: ["12345670", "11866428", "18836486", "88478760"],
    2: ["20329761", "12345670"],
    3: ["12345670", "71537573"],
    4: ["20172527", "21464065"],
    5: ["71537573", "12345670"],
    6: ["12345670"],
}

COMMON_PINS = ["12345670", "00000000", "20172527", "28296607"]
@dataclass(frozen=True)
class WpsBuildResult:
    output: Path
    report: Path
    sha256: str
    size: int
    static_ouis: int
    static_associations: int
    algorithm_ouis: int
    algorithm_mappings: int


def download_source(record: SourceRecord, *, timeout: float = 30.0) -> bytes:
    request = Request(record.url, headers={"User-Agent": "JanOS-RFDB/1"})
    with urlopen(request, timeout=timeout) as response:
        payload = response.read(MAX_SOURCE_BYTES + 1)
    if len(payload) > MAX_SOURCE_BYTES:
        raise ValueError("WPS source exceeds 2 MiB safety limit")
    return payload


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile("wb", prefix=f".{path.name}.",
                                         dir=path.parent, delete=False) as handle:
            handle.write(payload)
            handle.flush()
            temporary_name = handle.name
        Path(temporary_name).replace(path)
    finally:
        if temporary_name is not None and Path(temporary_name).exists():
            Path(temporary_name).unlink()


def _records(lock_path: Path) -> tuple[dict[str, SourceRecord], bytes]:
    all_records = load_lock(lock_path)
    selected = {record.id: record for record in all_records if record.id in SOURCE_IDS}
    if set(selected) != set(SOURCE_IDS):
        raise ValueError("sources lock requires exactly airgeddon_known_pins and default_wps_pins")
    return selected, canonical_lock_bytes(all_records)


def _checked_rules(rules: dict) -> dict:
    for values in rules.values():
        for pin in values:
            if normalize_pin(pin) != pin:
                raise ValueError(f"built-in candidate is not checksum-valid: {pin}")
    return rules


def build_wps_pin_database(
    lock_path: Path,
    cache_dir: Path,
    output_path: Path,
    report_path: Path,
    *,
    refresh_source: bool = False,
    allow_unsupported_report: bool = False,
) -> WpsBuildResult:
    lock_path = lock_path.resolve(strict=True)
    cache_dir = cache_dir.resolve(strict=True)
    output_path = output_path.resolve(strict=False)
    report_path = report_path.resolve(strict=False)
    records, canonical_lock = _records(lock_path)
    payloads = {}
    for source_id in SOURCE_IDS:
        record = records[source_id]
        cache_path = cache_dir / record.local_name
        if refresh_source:
            payload = download_source(record)
            verify_bytes(record, payload)
            _atomic_write(cache_path, payload)
        else:
            if not cache_path.is_file():
                raise FileNotFoundError(
                    f"offline WPS source is missing: {cache_path}; network access requires --refresh-source"
                )
            payload = cache_path.read_bytes()
            verify_bytes(record, payload)
        try:
            payloads[source_id] = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"{source_id} is not valid UTF-8") from exc

    oui_pins, air_report = load_airgeddon(payloads["airgeddon_known_pins"])
    oui_pins, oui_algorithms, default_report = load_default_wps(
        payloads["default_wps_pins"], oui_pins
    )
    dataset = WpsDataset(
        oui_pins=oui_pins,
        oui_algorithms=oui_algorithms,
        model_pins=_checked_rules(MODEL_PINS),
        vendor_pins=_checked_rules(VENDOR_PINS),
        ssid_pins=_checked_rules(SSID_PINS),
        common_pins=_checked_rules({0: COMMON_PINS})[0],
    )
    lock_digest = hashlib.sha256(canonical_lock).digest()
    source_id = int.from_bytes(lock_digest[:4], "little")
    blob = build_wps_blob(dataset, source_id, validate_checksums=False)
    image = parse_wps_blob(blob)
    unsupported_ouis = sorted(
        oui for oui, names in oui_algorithms.items() if "arcadyan" in names
    )
    if unsupported_ouis and not allow_unsupported_report:
        raise ValueError(
            f"unsupported algorithm mappings for {len(unsupported_ouis)} OUI(s); "
            "use --allow-unsupported-report to produce an explicitly incomplete artifact"
        )

    blob_sha = hashlib.sha256(blob).hexdigest()
    report = {
        "algorithm_mappings": sum(len(values) for values in oui_algorithms.values()),
        "algorithm_ouis": len(oui_algorithms),
        "format": "JWPS-2",
        "lock_sha256": lock_digest.hex(),
        "malformed_rows": air_report.malformed + default_report.malformed,
        "duplicates_removed": air_report.duplicates + default_report.duplicates,
        "invalid_checksum_rows_preserved": (
            air_report.invalid_checksums_preserved +
            default_report.invalid_checksums_preserved
        ),
        "invalid_checksum_associations_preserved": sum(
            normalize_pin(pin) is None
            for pins in oui_pins.values()
            for pin in pins
        ),
        "sha256": blob_sha,
        "size": len(blob),
        "source_id": f"{source_id:08x}",
        "source_revisions": {key: records[key].revision for key in SOURCE_IDS},
        "static_associations": sum(len(values) for values in oui_pins.values()),
        "static_ouis": len(oui_pins),
        "unknown_algorithm_names": default_report.unknown_algorithms,
        "unsupported_algorithm_mappings": image.unsupported_algorithm_mappings,
        "unsupported_ouis": unsupported_ouis,
    }
    _atomic_write(output_path, blob)
    _atomic_write(report_path, (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
    return WpsBuildResult(
        output_path, report_path, blob_sha, len(blob), len(oui_pins),
        sum(len(values) for values in oui_pins.values()), len(oui_algorithms),
        sum(len(values) for values in oui_algorithms.values()),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--refresh-source", action="store_true")
    parser.add_argument("--allow-unsupported-report", action="store_true")
    args = parser.parse_args()
    result = build_wps_pin_database(
        args.lock, args.cache, args.output, args.report,
        refresh_source=args.refresh_source,
        allow_unsupported_report=args.allow_unsupported_report,
    )
    print(f"{result.output} bytes={result.size} sha256={result.sha256} "
          f"static={result.static_ouis}/{result.static_associations} "
          f"algorithms={result.algorithm_ouis}/{result.algorithm_mappings}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
