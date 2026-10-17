#!/usr/bin/env python3
"""Build a JVND v3 vendor database from one locked Wireshark manuf input."""

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

from tools.rfdb.provenance import (
    SourceRecord,
    canonical_lock_bytes,
    load_lock,
    verify_bytes,
)
from tools.rfdb.vendor_format import (
    build_vendor_blob,
    parse_manuf,
    parse_manuf_data_c,
    parse_vendor_blob,
)


SOURCE_ID = "wireshark_manuf"
MAX_SOURCE_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True)
class VendorBuildResult:
    output: Path
    report: Path
    sha256: str
    size: int
    counts: dict[int, int]


def download_source(record: SourceRecord, *, timeout: float = 30.0) -> bytes:
    """Download bytes only; callers must verify them before writing to cache."""
    request = Request(record.url, headers={"User-Agent": "JanOS-RFDB/1"})
    with urlopen(request, timeout=timeout) as response:
        payload = response.read(MAX_SOURCE_BYTES + 1)
    if len(payload) > MAX_SOURCE_BYTES:
        raise ValueError("vendor source exceeds the 16 MiB safety limit")
    return payload


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{path.name}.", dir=path.parent, delete=False
        ) as handle:
            handle.write(payload)
            handle.flush()
            temporary_name = handle.name
        Path(temporary_name).replace(path)
    finally:
        if temporary_name is not None:
            temporary = Path(temporary_name)
            if temporary.exists():
                temporary.unlink()


def _vendor_record(lock_path: Path) -> tuple[SourceRecord, bytes]:
    records = load_lock(lock_path)
    matches = [record for record in records if record.id == SOURCE_ID]
    if len(matches) != 1:
        raise ValueError("sources lock must contain exactly one wireshark_manuf record")
    return matches[0], canonical_lock_bytes(records)


def build_vendor_database(
    lock_path: Path,
    cache_dir: Path,
    output_path: Path,
    report_path: Path,
    *,
    refresh_source: bool = False,
) -> VendorBuildResult:
    lock_path = lock_path.resolve(strict=True)
    cache_dir = cache_dir.resolve(strict=True)
    output_path = output_path.resolve(strict=False)
    report_path = report_path.resolve(strict=False)
    record, canonical_lock = _vendor_record(lock_path)
    cached_input = cache_dir / record.local_name

    if refresh_source:
        downloaded = download_source(record)
        verify_bytes(record, downloaded)
        _atomic_write(cached_input, downloaded)
        payload = downloaded
    else:
        if not cached_input.is_file():
            raise FileNotFoundError(
                f"offline vendor source is missing: {cached_input}; "
                "network access requires --refresh-source"
            )
        payload = cached_input.read_bytes()
        verify_bytes(record, payload)

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Wireshark manuf input is not valid UTF-8") from exc

    if "static const manuf_oui24_t global_manuf_oui24_table[]" in text:
        records = parse_manuf_data_c(text)
        source_format = "wireshark-manuf-data-c"
    else:
        records = parse_manuf(text)
        source_format = "legacy-manuf-text"
    lock_digest = hashlib.sha256(canonical_lock).digest()
    source_id = int.from_bytes(lock_digest[:4], "little")
    blob = build_vendor_blob(records, source_id)
    image = parse_vendor_blob(blob)
    blob_sha256 = hashlib.sha256(blob).hexdigest()
    report = {
        "counts": {str(bits): image.counts[bits] for bits in (24, 28, 36)},
        "format": "JVND-3",
        "lock_sha256": lock_digest.hex(),
        "sha256": blob_sha256,
        "size": len(blob),
        "source_id": f"{source_id:08x}",
        "source_format": source_format,
        "source_revision": record.revision,
        "unsupported_prefixes": 0,
    }
    report_bytes = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")

    _atomic_write(output_path, blob)
    _atomic_write(report_path, report_bytes)
    return VendorBuildResult(
        output=output_path,
        report=report_path,
        sha256=blob_sha256,
        size=len(blob),
        counts=image.counts,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--refresh-source",
        action="store_true",
        help="explicitly allow HTTPS refresh of the already locked source",
    )
    args = parser.parse_args()

    result = build_vendor_database(
        args.lock,
        args.cache,
        args.output,
        args.report,
        refresh_source=args.refresh_source,
    )
    print(
        f"{result.output} bytes={result.size} sha256={result.sha256} "
        f"/24={result.counts[24]} /28={result.counts[28]} /36={result.counts[36]}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
