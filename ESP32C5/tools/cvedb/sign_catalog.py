"""Create a detached low-S JCSG/1 signature with an external OpenSSL key."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from tools.cvedb.catalog_format import parse_catalog


HEADER_SIZE = 80
MAX_CATALOG = 4 * 1024 * 1024
P256_ORDER = int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)


def _decode_der(data: bytes) -> tuple[int, int]:
    if len(data) < 8 or len(data) > 72 or data[0] != 0x30 or data[1] >= 0x80:
        raise ValueError("signature is not strict short-form DER")
    if data[1] + 2 != len(data):
        raise ValueError("signature has trailing or truncated data")
    position = 2
    values = []
    for _ in range(2):
        if position + 2 > len(data) or data[position] != 0x02:
            raise ValueError("signature integer is missing")
        length = data[position + 1]
        position += 2
        if not 1 <= length <= 33 or position + length > len(data):
            raise ValueError("signature integer has invalid length")
        encoded = data[position:position + length]
        position += length
        if encoded[0] == 0:
            if len(encoded) == 1 or not encoded[1] & 0x80:
                raise ValueError("signature integer is not minimally encoded")
            encoded = encoded[1:]
        elif encoded[0] & 0x80:
            raise ValueError("signature integer is negative")
        value = int.from_bytes(encoded, "big")
        if not 0 < value < P256_ORDER:
            raise ValueError("signature integer is out of P-256 range")
        values.append(value)
    if position != len(data):
        raise ValueError("signature has extra values")
    return values[0], values[1]


def _integer_der(value: int) -> bytes:
    encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
    if encoded[0] & 0x80:
        encoded = b"\0" + encoded
    return b"\x02" + bytes([len(encoded)]) + encoded


def canonical_low_s_der(data: bytes) -> bytes:
    r, s = _decode_der(data)
    if s > P256_ORDER // 2:
        s = P256_ORDER - s
    body = _integer_der(r) + _integer_der(s)
    result = b"\x30" + bytes([len(body)]) + body
    _decode_der(result)
    return result


def _inside(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def enforce_key_location(key: Path, repository: Path, test_key: bool) -> None:
    key = key.resolve()
    repository = repository.resolve()
    fixtures = repository / "tests" / "fixtures"
    if _inside(key, repository) and not (test_key and _inside(key, fixtures)):
        raise ValueError("private keys under the repository are refused")


def sign_catalog(catalog_path: Path, key_path: Path, output_path: Path,
                 expected_key_id: str, test_key: bool = False,
                 openssl: str = "openssl") -> tuple[str, str]:
    repository = Path(__file__).resolve().parents[2]
    enforce_key_location(key_path, repository, test_key)
    catalog = catalog_path.read_bytes()
    if not 192 <= len(catalog) <= MAX_CATALOG or catalog[:4] != b"JCVE":
        raise ValueError("catalog is not bounded JCVE/1")
    parse_catalog(catalog)
    try:
        key_id = bytes.fromhex(expected_key_id)
    except ValueError as error:
        raise ValueError("key ID must be 32 hexadecimal characters") from error
    if len(key_id) != 16 or expected_key_id != expected_key_id.lower():
        raise ValueError("key ID must be 32 lowercase hexadecimal characters")
    if catalog[112:128] != key_id:
        raise ValueError("expected key ID differs from catalog")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="janos-jcsg-") as directory:
        raw_path = Path(directory) / "signature.der"
        subprocess.run([openssl, "dgst", "-sha256", "-sign", str(key_path),
                        "-out", str(raw_path), str(catalog_path)],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        der = canonical_low_s_der(raw_path.read_bytes())
    digest = hashlib.sha256(catalog).digest()
    header = bytearray(HEADER_SIZE)
    header[:4] = b"JCSG"
    struct.pack_into("<HHII", header, 4, 1, HEADER_SIZE, 0, HEADER_SIZE + len(der))
    header[16:32] = key_id
    header[32:64] = digest
    struct.pack_into("<H", header, 64, len(der))
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="wb", dir=output_path.parent,
                prefix=output_path.name + ".", suffix=".tmp",
                delete=False) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(header + der)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, output_path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return digest.hex(), key_id.hex()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--test-key", action="store_true")
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    digest, key_id = sign_catalog(args.catalog, args.private_key, args.output,
                                  args.key_id, args.test_key, args.openssl)
    print(f"catalog_sha256={digest}")
    print(f"key_id={key_id}")
    print(f"signature={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
