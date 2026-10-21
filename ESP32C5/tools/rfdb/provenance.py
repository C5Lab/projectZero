"""Strict validation for locked RF database source provenance."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath, PureWindowsPath
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse


SCHEMA_VERSION = 1
FIELDS = (
    "id",
    "project",
    "url",
    "revision",
    "retrieved_utc",
    "sha256",
    "license",
    "license_file",
    "local_name",
)
SUPPORTED_LICENSES = {
    "Apache-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
}
FLOATING_REVISIONS = {"head", "main", "master", "trunk", "latest"}
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
UTC_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


@dataclass(frozen=True)
class SourceRecord:
    id: str
    project: str
    url: str
    revision: str
    retrieved_utc: str
    sha256: str
    license: str
    license_file: str
    local_name: str


def _require_string(record: Mapping[str, Any], field: str) -> str:
    value = record[field]
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be a non-empty, trimmed string")
    return value


def _safe_relative_file(value: str, field: str, *, allow_directories: bool) -> None:
    posix = PurePosixPath(value)
    windows = PureWindowsPath(value)
    if posix.is_absolute() or windows.is_absolute():
        raise ValueError(f"{field} must be relative")
    if ".." in posix.parts or ".." in windows.parts:
        raise ValueError(f"{field} must not contain '..'")
    if not allow_directories and (len(posix.parts) != 1 or len(windows.parts) != 1):
        raise ValueError(f"{field} must be a filename without directories")


def _validate_record(raw: Mapping[str, Any] | SourceRecord) -> SourceRecord:
    if isinstance(raw, SourceRecord):
        record: Mapping[str, Any] = asdict(raw)
    elif isinstance(raw, Mapping):
        record = raw
    else:
        raise ValueError("source record must be an object")

    keys = set(record)
    expected = set(FIELDS)
    if keys != expected:
        missing = sorted(expected - keys)
        unknown = sorted(keys - expected)
        raise ValueError(f"invalid source fields; missing={missing}, unknown={unknown}")

    values = {field: _require_string(record, field) for field in FIELDS}

    if not ID_PATTERN.fullmatch(values["id"]):
        raise ValueError("id must contain only lowercase letters, digits, '.', '_' or '-'")

    parsed_url = urlparse(values["url"])
    if parsed_url.scheme != "https" or not parsed_url.netloc or parsed_url.username:
        raise ValueError("url must be an HTTPS URL without credentials")

    if values["revision"].lower() in FLOATING_REVISIONS:
        raise ValueError("revision must be immutable, not a floating branch name")
    if any(character.isspace() for character in values["revision"]):
        raise ValueError("revision must not contain whitespace")

    if not UTC_PATTERN.fullmatch(values["retrieved_utc"]):
        raise ValueError("retrieved_utc must use YYYY-MM-DDTHH:MM:SSZ")
    if not SHA256_PATTERN.fullmatch(values["sha256"]):
        raise ValueError("sha256 must be 64 lowercase hexadecimal characters")
    if values["license"] not in SUPPORTED_LICENSES:
        raise ValueError(f"unsupported license identifier: {values['license']}")

    _safe_relative_file(values["license_file"], "license_file", allow_directories=True)
    expected_license_file = f"LICENSES/{values['license']}.txt"
    if PurePosixPath(values["license_file"]).as_posix() != expected_license_file:
        raise ValueError(f"license_file must be {expected_license_file}")
    _safe_relative_file(values["local_name"], "local_name", allow_directories=False)

    return SourceRecord(**values)


def load_lock(path: Path) -> list[SourceRecord]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read provenance lock: {path}") from exc

    if not isinstance(document, dict) or set(document) != {"schema", "sources"}:
        raise ValueError("lock must contain exactly 'schema' and 'sources'")
    if document["schema"] != SCHEMA_VERSION:
        raise ValueError(f"unsupported lock schema: {document['schema']!r}")
    if not isinstance(document["sources"], list):
        raise ValueError("sources must be a list")

    records = [_validate_record(raw) for raw in document["sources"]]
    ids = [record.id for record in records]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate source id")
    local_names = [record.local_name for record in records]
    if len(local_names) != len(set(local_names)):
        raise ValueError("duplicate local_name")
    return records


def verify_bytes(record: Mapping[str, Any] | SourceRecord, payload: bytes) -> None:
    validated = _validate_record(record)
    actual = hashlib.sha256(payload).hexdigest()
    if actual != validated.sha256:
        raise ValueError(
            f"SHA-256 mismatch for {validated.id}: expected {validated.sha256}, got {actual}"
        )


def canonical_lock_bytes(records: Iterable[Mapping[str, Any] | SourceRecord]) -> bytes:
    validated = [_validate_record(record) for record in records]
    ids = [record.id for record in validated]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate source id")
    local_names = [record.local_name for record in validated]
    if len(local_names) != len(set(local_names)):
        raise ValueError("duplicate local_name")

    document = {
        "schema": SCHEMA_VERSION,
        "sources": [asdict(record) for record in sorted(validated, key=lambda item: item.id)],
    }
    return (json.dumps(document, sort_keys=True, indent=2) + "\n").encode("utf-8")
