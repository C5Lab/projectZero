#!/usr/bin/env python3
"""Build and strictly validate the bounded JCVE/1 catalog format."""

from __future__ import annotations

import binascii
from dataclasses import dataclass
from datetime import date, datetime
import hashlib
import json
import re
import struct
import unicodedata
from urllib.parse import urlsplit


MAGIC = b"JCVE"
VERSION = 1
HEADER_SIZE = 192
MAX_CATALOG_BYTES = 4 * 1024 * 1024
MAX_VALIDITY_SECONDS = 180 * 86400
MAX_STRING_BYTES = 255
NO_STRING = 0xFFFFFFFF

MAX_SOURCES = 16
MAX_MODELS = 128
MAX_ALIASES = 256
MAX_ADVISORIES = 256
MAX_FIRMWARE_RULES = 1024
MAX_STRING_ENTRIES = 2048
MAX_RULES_PER_MODEL = 256
MAX_ADVISORIES_PER_MODEL = 128

HEADER = struct.Struct("<4sHHIIIIQQQ32s32s16s12I16s")
SOURCE_RECORD = struct.Struct("<6I")
MODEL_RECORD = struct.Struct("<4I")
ALIAS_RECORD = struct.Struct("<2I")
ADVISORY_RECORD = struct.Struct("<7I4B")
FIRMWARE_RECORD = struct.Struct("<3I")

SOURCE_RECORD_SIZE = SOURCE_RECORD.size
MODEL_RECORD_SIZE = MODEL_RECORD.size
ALIAS_RECORD_SIZE = ALIAS_RECORD.size
ADVISORY_RECORD_SIZE = ADVISORY_RECORD.size
FIRMWARE_RECORD_SIZE = FIRMWARE_RECORD.size

SCHEMA = "janos-router-cve-manifest-v1"
SOURCE_FIELDS = ("id", "url", "retrieved_utc", "license", "revision", "sha256")
SEVERITIES = frozenset(("unknown", "none", "low", "medium", "high", "critical"))
ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}\Z")
HASH_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class CatalogSource:
    id: str
    url: str
    retrieved_utc: str
    license: str
    revision: str
    sha256: str


@dataclass(frozen=True)
class CatalogModel:
    vendor: str
    model: str
    first_firmware_rule: int
    firmware_rule_count: int


@dataclass(frozen=True)
class CatalogAlias:
    alias: str
    model_index: int


@dataclass(frozen=True)
class CatalogAdvisory:
    source_index: int
    cve: str
    url: str
    published: str
    severity: str
    kev_date: str | None
    fixed_version: str
    eol: bool


@dataclass(frozen=True)
class CatalogFirmwareRule:
    model_index: int
    advisory_index: int
    firmware: str


@dataclass(frozen=True)
class CatalogImage:
    created_epoch: int
    expires_epoch: int
    serial: int
    key_id: bytes
    payload_sha256: bytes
    provenance_sha256: bytes
    recomputed_provenance_sha256: bytes
    sources: tuple[CatalogSource, ...]
    models: tuple[CatalogModel, ...]
    aliases: tuple[CatalogAlias, ...]
    advisories: tuple[CatalogAdvisory, ...]
    firmware_rules: tuple[CatalogFirmwareRule, ...]


def _exact_keys(value: object, expected: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{label} must contain exactly {sorted(expected)}")
    return value


def _list(value: object, label: str, maximum: int, *, nonempty: bool = True) -> list:
    if not isinstance(value, list) or (nonempty and not value) or len(value) > maximum:
        raise ValueError(f"{label} has invalid count")
    return value


def _text(value: object, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise ValueError(f"{label} must be nonempty text")
    if "\x00" in value or unicodedata.normalize("NFC", value) != value:
        raise ValueError(f"{label} must be canonical NFC text without NUL")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8") from exc
    if len(encoded) > MAX_STRING_BYTES:
        raise ValueError(f"{label} exceeds {MAX_STRING_BYTES} UTF-8 bytes")
    if any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise ValueError(f"{label} must use printable ASCII in JCVE/1")
    return value


def _identifier(value: object, label: str) -> str:
    text = _text(value, label)
    if ID_PATTERN.fullmatch(text) is None:
        raise ValueError(f"{label} is not a canonical identifier")
    return text


def _https_url(value: object, label: str) -> str:
    text = _text(value, label)
    if (not text.startswith("https://") or
            any(ord(character) <= 0x20 or ord(character) == 0x7F for character in text)):
        raise ValueError(f"{label} must use exact canonical https:// without whitespace")
    parsed = urlsplit(text)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or
            parsed.password is not None or parsed.query or parsed.fragment or
            parsed.hostname.endswith(".")):
        raise ValueError(f"{label} must be an uncredentialed HTTPS URL without fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{label} has an invalid port") from exc
    hostname = parsed.hostname
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} hostname must be canonical ASCII") from exc
    if (hostname != hostname.lower() or not re.fullmatch(r"[a-z0-9.-]+", hostname) or
            ".." in hostname or hostname.startswith((".", "-")) or
            hostname.endswith((".", "-"))):
        raise ValueError(f"{label} hostname is not canonical")
    if any(not label_part or label_part.startswith("-") or label_part.endswith("-")
           for label_part in hostname.split(".")):
        raise ValueError(f"{label} hostname label is not canonical")
    if port in (0, 443):
        raise ValueError(f"{label} has a forbidden HTTPS port")
    canonical_netloc = hostname if port is None else f"{hostname}:{port}"
    if parsed.netloc != canonical_netloc:
        raise ValueError(f"{label} authority is not canonically encoded")
    if re.fullmatch(r"[A-Za-z0-9._~:@/-]*", parsed.path) is None:
        raise ValueError(f"{label} path is outside the canonical JCVE/1 subset")
    return text


def _calendar_date(value: object, label: str) -> str:
    text = _text(value, label)
    if len(text) != 10:
        raise ValueError(f"{label} must use YYYY-MM-DD")
    try:
        if date.fromisoformat(text).isoformat() != text:
            raise ValueError
    except ValueError as exc:
        raise ValueError(f"{label} must be a real YYYY-MM-DD date") from exc
    return text


def _retrieved(value: object, label: str) -> str:
    text = _text(value, label)
    if len(text) != 20 or not text.endswith("Z"):
        raise ValueError(f"{label} must use YYYY-MM-DDTHH:MM:SSZ")
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError(f"{label} is not a real UTC timestamp") from exc
    return text


def _u64(value: object, label: str, *, nonzero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < int(nonzero) or value > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"{label} must fit uint64")
    return value


def _canonical_identity(value: object, label: str) -> str:
    text = _text(value, label)
    output: list[str] = []
    separator = False
    for character in text:
        code = ord(character)
        if code < 128 and not character.isalnum():
            if output:
                separator = True
            continue
        if separator:
            output.append(" ")
            separator = False
        output.append(character.lower() if "A" <= character <= "Z" else character)
    normalized = "".join(output)
    if not normalized or len(normalized.encode("utf-8")) > MAX_STRING_BYTES:
        raise ValueError(f"{label} has empty or oversized normalized identity")
    return normalized


def _normalized_source(raw: object, label: str) -> dict[str, str]:
    item = _exact_keys(raw, set(SOURCE_FIELDS), label)
    digest = _text(item["sha256"], f"{label}.sha256")
    if HASH_PATTERN.fullmatch(digest) is None:
        raise ValueError(f"{label}.sha256 must be 64 hexadecimal characters")
    return {
        "id": _identifier(item["id"], f"{label}.id"),
        "url": _https_url(item["url"], f"{label}.url"),
        "retrieved_utc": _retrieved(item["retrieved_utc"], f"{label}.retrieved_utc"),
        "license": _text(item["license"], f"{label}.license"),
        "revision": _text(item["revision"], f"{label}.revision"),
        "sha256": digest,
    }


def normalize_source_records(raw_sources: object) -> list[dict[str, str]]:
    """Validate and canonically order source records for lock comparison."""
    sources = [_normalized_source(item, f"sources[{index}]")
               for index, item in enumerate(_list(raw_sources, "sources", MAX_SOURCES))]
    sources.sort(key=lambda item: item["id"])
    if len({item["id"] for item in sources}) != len(sources):
        raise ValueError("duplicate source id")
    return sources


def canonical_provenance_bytes(sources: list[dict[str, str]] | tuple[CatalogSource, ...]) -> bytes:
    values = [dict((field, getattr(item, field) if isinstance(item, CatalogSource) else item[field])
                   for field in SOURCE_FIELDS) for item in sources]
    values.sort(key=lambda item: item["id"])
    return (json.dumps({"sources": values}, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":")) + "\n").encode("utf-8")


def _normalize_manifest(raw: object) -> dict:
    top = _exact_keys(raw, {"schema", "created_epoch", "expires_epoch", "serial",
                            "key_id", "sources", "products", "advisories"}, "manifest")
    if top["schema"] != SCHEMA:
        raise ValueError("unsupported manifest schema")
    created = _u64(top["created_epoch"], "created_epoch")
    expires = _u64(top["expires_epoch"], "expires_epoch")
    if expires <= created or expires - created > MAX_VALIDITY_SECONDS:
        raise ValueError("catalog validity must be positive and no longer than 180 days")
    serial = _u64(top["serial"], "serial", nonzero=True)
    key_id_text = _text(top["key_id"], "key_id")
    if re.fullmatch(r"[0-9a-fA-F]{32}", key_id_text) is None:
        raise ValueError("key_id must be exactly 16 hexadecimal bytes")
    key_id = bytes.fromhex(key_id_text)
    if key_id == bytes(16):
        raise ValueError("key_id must not be all zero")

    sources = normalize_source_records(top["sources"])

    products = []
    product_ids: set[str] = set()
    model_keys: set[tuple[str, str]] = set()
    primary_owner: dict[str, str] = {}
    aliases_seen: dict[str, str] = {}
    for index, raw_product in enumerate(_list(top["products"], "products", MAX_MODELS)):
        item = _exact_keys(raw_product, {"id", "vendor", "model", "aliases"}, f"products[{index}]")
        product_id = _identifier(item["id"], f"products[{index}].id")
        if product_id in product_ids:
            raise ValueError("duplicate product id")
        product_ids.add(product_id)
        vendor = _canonical_identity(item["vendor"], f"products[{index}].vendor")
        model = _canonical_identity(item["model"], f"products[{index}].model")
        if (vendor, model) in model_keys:
            raise ValueError("duplicate normalized vendor/model")
        model_keys.add((vendor, model))
        if model in primary_owner and primary_owner[model] != product_id:
            raise ValueError("ambiguous normalized primary model")
        primary_owner[model] = product_id
        aliases = []
        for alias_index, raw_alias in enumerate(_list(item["aliases"], f"products[{index}].aliases",
                                                       MAX_ALIASES, nonempty=False)):
            alias = _canonical_identity(raw_alias, f"products[{index}].aliases[{alias_index}]")
            if alias in aliases:
                raise ValueError("duplicate normalized alias in product")
            aliases.append(alias)
        products.append({"id": product_id, "vendor": vendor, "model": model,
                         "aliases": tuple(sorted(aliases))})

    for product in products:
        for alias in product["aliases"]:
            owner = aliases_seen.get(alias) or primary_owner.get(alias)
            if owner is not None and owner != product["id"]:
                raise ValueError("ambiguous normalized alias")
            aliases_seen[alias] = product["id"]
    products.sort(key=lambda item: (item["vendor"], item["model"], item["id"]))

    source_ids = {item["id"] for item in sources}
    advisories = []
    cves: set[str] = set()
    for index, raw_advisory in enumerate(_list(top["advisories"], "advisories", MAX_ADVISORIES)):
        item = _exact_keys(raw_advisory, {"cve", "source", "url", "published", "severity",
                                         "kev_date", "eol", "fixed_version", "affected"},
                           f"advisories[{index}]")
        cve = _text(item["cve"], f"advisories[{index}].cve")
        if CVE_PATTERN.fullmatch(cve) is None or cve in cves:
            raise ValueError("malformed or duplicate CVE")
        cves.add(cve)
        source = _identifier(item["source"], f"advisories[{index}].source")
        if source not in source_ids:
            raise ValueError("advisory references missing source")
        severity = _text(item["severity"], f"advisories[{index}].severity")
        if severity not in SEVERITIES:
            raise ValueError("invalid severity")
        kev_date = None if item["kev_date"] is None else _calendar_date(
            item["kev_date"], f"advisories[{index}].kev_date")
        if not isinstance(item["eol"], bool):
            raise ValueError("eol must be boolean")
        affected = []
        affected_ids: set[str] = set()
        for affected_index, raw_affected in enumerate(_list(
                item["affected"], f"advisories[{index}].affected", MAX_MODELS)):
            entry = _exact_keys(raw_affected, {"product", "firmware"},
                                f"advisories[{index}].affected[{affected_index}]")
            product = _identifier(entry["product"], "affected.product")
            if product not in product_ids or product in affected_ids:
                raise ValueError("missing or duplicate affected product")
            affected_ids.add(product)
            firmware_values = []
            for firmware_index, raw_firmware in enumerate(_list(
                    entry["firmware"], "affected.firmware", MAX_FIRMWARE_RULES)):
                firmware = _canonical_identity(raw_firmware, f"firmware[{firmware_index}]")
                if firmware in firmware_values:
                    raise ValueError("duplicate normalized exact firmware")
                firmware_values.append(firmware)
            affected.append({"product": product, "firmware": tuple(sorted(firmware_values))})
        affected.sort(key=lambda entry: entry["product"])
        advisories.append({
            "cve": cve,
            "source": source,
            "url": _https_url(item["url"], f"advisories[{index}].url"),
            "published": _calendar_date(item["published"], f"advisories[{index}].published"),
            "severity": severity,
            "kev_date": kev_date,
            "eol": item["eol"],
            "fixed_version": _text(item["fixed_version"], f"advisories[{index}].fixed_version"),
            "affected": tuple(affected),
        })
    advisories.sort(key=lambda item: item["cve"])
    return {"created": created, "expires": expires, "serial": serial, "key_id": key_id,
            "sources": sources, "products": products, "advisories": advisories}


class _Strings:
    def __init__(self) -> None:
        self.data = bytearray()
        self.offsets: dict[str, int] = {}

    def add(self, value: str) -> int:
        if value in self.offsets:
            return self.offsets[value]
        encoded = value.encode("utf-8")
        if not 1 <= len(encoded) <= MAX_STRING_BYTES:
            raise ValueError("invalid string table entry length")
        offset = len(self.data)
        self.offsets[value] = offset
        if len(self.offsets) > MAX_STRING_ENTRIES:
            raise ValueError("string table entry count exceeds ESP32 work bound")
        self.data.append(len(encoded))
        self.data.extend(encoded)
        return offset


def build_catalog(manifest: object) -> bytes:
    normalized = _normalize_manifest(manifest)
    sources = normalized["sources"]
    products = normalized["products"]
    advisories = normalized["advisories"]
    source_indexes = {item["id"]: index for index, item in enumerate(sources)}
    product_indexes = {item["id"]: index for index, item in enumerate(products)}
    advisory_indexes = {item["cve"]: index for index, item in enumerate(advisories)}

    rules = []
    for advisory in advisories:
        for affected in advisory["affected"]:
            for firmware in affected["firmware"]:
                rules.append((product_indexes[affected["product"]],
                              advisory_indexes[advisory["cve"]], firmware))
    rules.sort()
    if not rules or len(rules) > MAX_FIRMWARE_RULES:
        raise ValueError("firmware rule count is outside bounds")

    mutable_ranges = [[0, 0] for _ in products]
    for rule_index, rule in enumerate(rules):
        model_range = mutable_ranges[rule[0]]
        if model_range[1] == 0:
            model_range[0] = rule_index
        model_range[1] += 1
    ranges = {index: (values[0], values[1])
              for index, values in enumerate(mutable_ranges)}
    for model_index in range(len(products)):
        owned = [rule for rule in rules if rule[0] == model_index]
        if len(owned) > MAX_RULES_PER_MODEL or len({rule[1] for rule in owned}) > MAX_ADVISORIES_PER_MODEL:
            raise ValueError("per-model rule/advisory work bound exceeded")

    strings = _Strings()
    source_bytes = bytearray()
    for source in sources:
        source_bytes.extend(SOURCE_RECORD.pack(*(strings.add(source[field]) for field in SOURCE_FIELDS)))

    model_bytes = bytearray()
    for index, product in enumerate(products):
        first, count = ranges[index]
        model_bytes.extend(MODEL_RECORD.pack(strings.add(product["vendor"]),
                                             strings.add(product["model"]), first, count))

    alias_rows = sorted((alias, product_indexes[product["id"]])
                        for product in products for alias in product["aliases"])
    if len(alias_rows) > MAX_ALIASES:
        raise ValueError("alias count exceeds bound")
    alias_bytes = bytearray()
    for alias, model_index in alias_rows:
        alias_bytes.extend(ALIAS_RECORD.pack(strings.add(alias), model_index))

    advisory_bytes = bytearray()
    for advisory in advisories:
        kev_offset = NO_STRING if advisory["kev_date"] is None else strings.add(advisory["kev_date"])
        advisory_bytes.extend(ADVISORY_RECORD.pack(
            source_indexes[advisory["source"]], strings.add(advisory["cve"]),
            strings.add(advisory["url"]), strings.add(advisory["published"]),
            strings.add(advisory["severity"]), kev_offset,
            strings.add(advisory["fixed_version"]), int(advisory["eol"]), 0, 0, 0))

    firmware_bytes = bytearray()
    for model_index, advisory_index, firmware in rules:
        firmware_bytes.extend(FIRMWARE_RECORD.pack(model_index, advisory_index, strings.add(firmware)))

    sections = (bytes(source_bytes), bytes(model_bytes), bytes(alias_bytes),
                bytes(advisory_bytes), bytes(firmware_bytes), bytes(strings.data))
    counts = (len(sources), len(products), len(alias_rows), len(advisories), len(rules), len(strings.data))
    descriptors: list[int] = []
    cursor = HEADER_SIZE
    for section, count in zip(sections, counts):
        descriptors.extend((cursor, count))
        cursor += len(section)
    if cursor > MAX_CATALOG_BYTES or cursor > 0xFFFFFFFF:
        raise ValueError("catalog exceeds 4 MiB bound")
    payload = b"".join(sections)
    provenance = hashlib.sha256(canonical_provenance_bytes(sources)).digest()
    header = HEADER.pack(
        MAGIC, VERSION, HEADER_SIZE, 0, cursor,
        binascii.crc32(payload) & 0xFFFFFFFF, 0,
        normalized["created"], normalized["expires"], normalized["serial"],
        hashlib.sha256(payload).digest(), provenance, normalized["key_id"],
        *descriptors, bytes(16),
    )
    return header + payload


def _parse_strings(blob: bytes, start: int, size: int) -> dict[int, str]:
    values: dict[int, str] = {}
    seen_values: set[str] = set()
    cursor = start
    end = start + size
    while cursor < end:
        relative = cursor - start
        length = blob[cursor]
        cursor += 1
        if length == 0 or length > end - cursor:
            raise ValueError("invalid string table entry length")
        raw = blob[cursor:cursor + length]
        if any(byte < 0x20 or byte > 0x7E for byte in raw):
            raise ValueError("JCVE/1 string table must use printable ASCII")
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid UTF-8 in string table") from exc
        if "\x00" in value or unicodedata.normalize("NFC", value) != value:
            raise ValueError("noncanonical string table entry")
        if value in seen_values:
            raise ValueError("duplicate string table value")
        seen_values.add(value)
        values[relative] = value
        cursor += length
    if cursor != end or not values:
        raise ValueError("invalid string table coverage")
    return values


def parse_catalog(blob: bytes) -> CatalogImage:
    if not isinstance(blob, bytes) or len(blob) < HEADER_SIZE or len(blob) > MAX_CATALOG_BYTES:
        raise ValueError("catalog size is outside bounds")
    fields = HEADER.unpack_from(blob)
    (magic, version, header_size, flags, file_size, payload_crc, reserved0,
     created, expires, serial, payload_hash, provenance_hash, key_id) = fields[:13]
    descriptors = fields[13:25]
    reserved = fields[25]
    if magic != MAGIC or version != VERSION or header_size != HEADER_SIZE:
        raise ValueError("unsupported JCVE header")
    if flags != 0 or reserved0 != 0 or reserved != bytes(16):
        raise ValueError("nonzero reserved JCVE header field")
    if file_size != len(blob) or file_size > MAX_CATALOG_BYTES:
        raise ValueError("declared catalog size differs from actual length")
    if expires <= created or expires - created > MAX_VALIDITY_SECONDS or serial == 0:
        raise ValueError("invalid catalog lifetime or serial")
    if key_id == bytes(16):
        raise ValueError("zero key id")
    payload = blob[HEADER_SIZE:]
    if binascii.crc32(payload) & 0xFFFFFFFF != payload_crc:
        raise ValueError("payload CRC mismatch")
    if hashlib.sha256(payload).digest() != payload_hash:
        raise ValueError("payload SHA-256 mismatch")

    counts = descriptors[1::2]
    limits = (MAX_SOURCES, MAX_MODELS, MAX_ALIASES, MAX_ADVISORIES,
              MAX_FIRMWARE_RULES, MAX_CATALOG_BYTES)
    sizes = (SOURCE_RECORD_SIZE, MODEL_RECORD_SIZE, ALIAS_RECORD_SIZE,
             ADVISORY_RECORD_SIZE, FIRMWARE_RECORD_SIZE, 1)
    cursor = HEADER_SIZE
    ranges = []
    for index, (offset, count, limit, unit) in enumerate(
            zip(descriptors[0::2], counts, limits, sizes)):
        if count > limit or offset != cursor:
            raise ValueError("section descriptor is out of order or outside bounds")
        size = count if index == 5 else count * unit
        if size > file_size - cursor:
            raise ValueError("section exceeds file bounds")
        ranges.append((cursor, count))
        cursor += size
    if cursor != file_size:
        raise ValueError("sections do not cover payload exactly")
    if counts[0] == 0 or counts[1] == 0 or counts[3] == 0 or counts[4] == 0 or counts[5] == 0:
        raise ValueError("required catalog section is empty")

    string_start, string_size = ranges[5]
    strings = _parse_strings(blob, string_start, string_size)
    if len(strings) > MAX_STRING_ENTRIES:
        raise ValueError("string table entry count exceeds ESP32 work bound")
    referenced: set[int] = set()

    def string_at(offset: int, label: str, *, optional: bool = False) -> str | None:
        if optional and offset == NO_STRING:
            return None
        if offset not in strings:
            raise ValueError(f"{label} offset is not a string boundary")
        referenced.add(offset)
        return strings[offset]

    sources = []
    start, count = ranges[0]
    for index in range(count):
        offsets = SOURCE_RECORD.unpack_from(blob, start + index * SOURCE_RECORD_SIZE)
        values = [string_at(offset, f"source[{index}]") for offset in offsets]
        source = CatalogSource(*values)
        normalized = _normalized_source(source.__dict__, f"source[{index}]")
        if source.__dict__ != normalized:
            raise ValueError("source record is not canonically encoded")
        sources.append(CatalogSource(**normalized))
    if list(sources) != sorted(sources, key=lambda item: item.id) or len({item.id for item in sources}) != len(sources):
        raise ValueError("source records are not strictly sorted and unique")

    models = []
    start, count = ranges[1]
    for index in range(count):
        vendor_off, model_off, first_rule, rule_count = MODEL_RECORD.unpack_from(
            blob, start + index * MODEL_RECORD_SIZE)
        vendor = string_at(vendor_off, "model.vendor")
        model = string_at(model_off, "model.model")
        if _canonical_identity(vendor, "model.vendor") != vendor or _canonical_identity(model, "model.model") != model:
            raise ValueError("model identity is not canonical")
        models.append(CatalogModel(vendor, model, first_rule, rule_count))
    if [(item.vendor, item.model) for item in models] != sorted((item.vendor, item.model) for item in models):
        raise ValueError("models are not sorted")
    if len({(item.vendor, item.model) for item in models}) != len(models):
        raise ValueError("duplicate model")
    primary_model_owner: dict[str, int] = {}
    for index, model in enumerate(models):
        if model.model in primary_model_owner:
            raise ValueError("ambiguous normalized primary model")
        primary_model_owner[model.model] = index

    aliases = []
    start, count = ranges[2]
    for index in range(count):
        alias_off, model_index = ALIAS_RECORD.unpack_from(blob, start + index * ALIAS_RECORD_SIZE)
        if model_index >= len(models):
            raise ValueError("alias references missing model")
        alias = string_at(alias_off, "alias")
        if _canonical_identity(alias, "alias") != alias:
            raise ValueError("alias is not canonical")
        if alias in primary_model_owner and primary_model_owner[alias] != model_index:
            raise ValueError("alias collides with another primary model")
        aliases.append(CatalogAlias(alias, model_index))
    if [(item.alias, item.model_index) for item in aliases] != sorted(
            (item.alias, item.model_index) for item in aliases):
        raise ValueError("aliases are not sorted")
    if len({item.alias for item in aliases}) != len(aliases):
        raise ValueError("ambiguous duplicate alias")

    advisories = []
    start, count = ranges[3]
    for index in range(count):
        values = ADVISORY_RECORD.unpack_from(blob, start + index * ADVISORY_RECORD_SIZE)
        source_index, cve_off, url_off, published_off, severity_off, kev_off, fixed_off = values[:7]
        flags, reserved_a, reserved_b, reserved_c = values[7:]
        if source_index >= len(sources) or flags & ~1 or reserved_a or reserved_b or reserved_c:
            raise ValueError("invalid advisory reference, flags, or reserved bytes")
        cve = string_at(cve_off, "advisory.cve")
        url = string_at(url_off, "advisory.url")
        published = string_at(published_off, "advisory.published")
        severity = string_at(severity_off, "advisory.severity")
        kev = string_at(kev_off, "advisory.kev", optional=True)
        fixed = string_at(fixed_off, "advisory.fixed")
        if CVE_PATTERN.fullmatch(cve) is None:
            raise ValueError("malformed CVE in catalog")
        _https_url(url, "advisory.url")
        _calendar_date(published, "advisory.published")
        if severity not in SEVERITIES:
            raise ValueError("invalid advisory severity")
        if kev is not None:
            _calendar_date(kev, "advisory.kev")
        advisories.append(CatalogAdvisory(source_index, cve, url, published, severity,
                                            kev, fixed, bool(flags & 1)))
    if [item.cve for item in advisories] != sorted(item.cve for item in advisories) or len({item.cve for item in advisories}) != len(advisories):
        raise ValueError("advisories are not strictly sorted and unique")

    rules = []
    start, count = ranges[4]
    for index in range(count):
        model_index, advisory_index, firmware_off = FIRMWARE_RECORD.unpack_from(
            blob, start + index * FIRMWARE_RECORD_SIZE)
        if model_index >= len(models) or advisory_index >= len(advisories):
            raise ValueError("firmware rule references missing record")
        firmware = string_at(firmware_off, "firmware")
        if _canonical_identity(firmware, "firmware") != firmware:
            raise ValueError("firmware identity is not canonical")
        rules.append(CatalogFirmwareRule(model_index, advisory_index, firmware))
    rule_keys = [(item.model_index, item.advisory_index, item.firmware) for item in rules]
    if rule_keys != sorted(rule_keys) or len(set(rule_keys)) != len(rule_keys):
        raise ValueError("firmware rules are not strictly sorted and unique")

    rule_cursor = 0
    for index, model in enumerate(models):
        first = rule_cursor
        while rule_cursor < len(rules) and rules[rule_cursor].model_index == index:
            rule_cursor += 1
        expected = ((first, rule_cursor - first) if rule_cursor > first else (0, 0))
        if (model.first_firmware_rule, model.firmware_rule_count) != expected:
            raise ValueError("model firmware range is inconsistent")
        owned_advisories = {rule.advisory_index for rule in rules if rule.model_index == index}
        if model.firmware_rule_count > MAX_RULES_PER_MODEL or len(owned_advisories) > MAX_ADVISORIES_PER_MODEL:
            raise ValueError("per-model rule/advisory work bound exceeded")
    if rule_cursor != len(rules):
        raise ValueError("firmware model ranges do not cover rules")
    if len({rule.advisory_index for rule in rules}) != len(advisories):
        raise ValueError("advisory without exact firmware rule")
    if len(referenced) != len(strings):
        raise ValueError("unreferenced string table entry")

    provenance = hashlib.sha256(canonical_provenance_bytes(tuple(sources))).digest()
    if provenance != provenance_hash:
        raise ValueError("provenance SHA-256 mismatch")
    return CatalogImage(created, expires, serial, key_id, payload_hash,
                        provenance_hash, provenance, tuple(sources), tuple(models),
                        tuple(aliases), tuple(advisories), tuple(rules))
