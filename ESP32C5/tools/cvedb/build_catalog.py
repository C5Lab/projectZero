#!/usr/bin/env python3
"""Build a JCVE/1 catalog from one reviewed local manifest without network I/O."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
import tempfile

from tools.cvedb.catalog_format import build_catalog, normalize_source_records, parse_catalog


DEFAULT_LOCK = Path(__file__).with_name("sources.lock.json")


def _immutable_revision(value: str) -> bool:
    if re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value):
        return True
    match = re.fullmatch(
        r"snapshot-([0-9]{8}T[0-9]{6}Z)-([0-9a-f]{64})", value)
    if match is None:
        return False
    try:
        parsed = datetime.strptime(match.group(1), "%Y%m%dT%H%M%SZ")
    except ValueError:
        return False
    return parsed.strftime("%Y%m%dT%H%M%SZ") == match.group(1)


@dataclass(frozen=True)
class CatalogBuildResult:
    output: Path
    report: Path
    sha256: str
    size: int


def _load_json(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read canonical {label}") from exc


def _verify_governance(lock: dict[str, object], sources: list[dict[str, str]],
                       lock_root: Path) -> None:
    governance = lock.get("governance")
    if not isinstance(governance, list) or len(governance) != len(sources):
        raise ValueError("invalid source governance")
    source_ids = {source["id"] for source in sources}
    governed: set[str] = set()
    for item in governance:
        if (not isinstance(item, dict) or
                set(item) != {"id", "authority", "redistribution", "license_file"} or
                not isinstance(item["id"], str) or item["id"] not in source_ids or
                item["id"] in governed or
                item["authority"] not in ("official-vendor", "cna", "cisa") or
                not isinstance(item["redistribution"], bool)):
            raise ValueError("invalid source governance")
        governed.add(item["id"])
        license_file = item["license_file"]
        if item["redistribution"]:
            if not isinstance(license_file, str) or not license_file:
                raise ValueError("invalid source governance")
            candidate = Path(license_file)
            if candidate.is_absolute() or candidate.as_posix() != license_file or \
                    ".." in candidate.parts:
                raise ValueError("invalid source governance")
            resolved_root = lock_root.resolve()
            resolved = (lock_root / candidate).resolve(strict=False)
            if resolved_root not in resolved.parents or not resolved.is_file() or \
                    resolved.stat().st_size == 0:
                raise ValueError("invalid source governance")
        elif license_file is not None:
            raise ValueError("invalid source governance")
    if governed != source_ids:
        raise ValueError("invalid source governance")
    if any(not _immutable_revision(source["revision"]) for source in sources):
        raise ValueError("invalid source governance")


def _verify_source_lock(manifest: object, lock: object, lock_root: Path) -> None:
    if not isinstance(lock, dict) or not isinstance(manifest, dict):
        raise ValueError("invalid source lock")
    schema = lock.get("schema")
    status = lock.get("status")
    if schema == "janos-router-cve-sources-lock-v1":
        if set(lock) != {"schema", "status", "sources"} or status != "test-fixture-only":
            raise ValueError("invalid source governance")
    elif schema == "janos-router-cve-sources-lock-v2":
        if set(lock) != {"schema", "status", "sources", "governance"} or \
                status != "reviewed":
            raise ValueError("invalid source governance")
    else:
        raise ValueError("invalid source lock")
    if not isinstance(lock["sources"], list):
        raise ValueError("invalid source lock")
    try:
        manifest_sources = normalize_source_records(manifest.get("sources"))
        locked_sources = normalize_source_records(lock["sources"])
    except ValueError as exc:
        raise ValueError("invalid source lock") from exc
    if manifest_sources != locked_sources:
        raise ValueError("manifest sources do not exactly match source lock")
    if schema == "janos-router-cve-sources-lock-v2":
        _verify_governance(lock, locked_sources, lock_root)


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix=f".{path.name}.",
                                         dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
        temporary.replace(path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def build_catalog_file(manifest_path: Path, output_path: Path, report_path: Path,
                       lock_path: Path = DEFAULT_LOCK) -> CatalogBuildResult:
    manifest_path = Path(manifest_path).resolve(strict=True)
    lock_path = Path(lock_path).resolve(strict=True)
    output_path = Path(output_path).resolve(strict=False)
    report_path = Path(report_path).resolve(strict=False)
    manifest = _load_json(manifest_path, "manifest")
    source_lock = _load_json(lock_path, "source lock")
    _verify_source_lock(manifest, source_lock, lock_path.parent)
    blob = build_catalog(manifest)
    image = parse_catalog(blob)
    digest = hashlib.sha256(blob).hexdigest()
    canonical_lock = (json.dumps(source_lock, ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":")) + "\n").encode("utf-8")
    report = {
        "counts": {
            "advisories": len(image.advisories),
            "aliases": len(image.aliases),
            "firmware_rules": len(image.firmware_rules),
            "models": len(image.models),
            "sources": len(image.sources),
        },
        "format": "JCVE/1",
        "provenance_sha256": image.provenance_sha256.hex(),
        "serial": image.serial,
        "sha256": digest,
        "size": len(blob),
        "source_lock_schema": source_lock["schema"],
        "source_lock_sha256": hashlib.sha256(canonical_lock).hexdigest(),
        "source_lock_status": source_lock["status"],
    }
    report_bytes = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
    _atomic_write(output_path, blob)
    _atomic_write(report_path, report_bytes)
    return CatalogBuildResult(output_path, report_path, digest, len(blob))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    result = build_catalog_file(args.manifest, args.output, args.report, args.lock)
    print(f"JCVE/1 bytes={result.size} sha256={result.sha256}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
