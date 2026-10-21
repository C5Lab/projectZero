#!/usr/bin/env python3
"""Build a deterministic source TAR for separately distributed RF databases."""

from __future__ import annotations

import argparse
import hashlib
import io
from pathlib import Path, PurePosixPath
import sys
import tarfile

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.rfdb.provenance import canonical_lock_bytes, load_lock, verify_bytes


def _safe_member_name(name: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe archive member name: {name}")


def _build_instructions(lock_sha256: str) -> bytes:
    return (
        "# Rebuilding the RF databases\n\n"
        "This archive contains the exact locked inputs, generator scripts, license "
        "texts, and notices used for the separately distributed RF database artifacts.\n\n"
        f"Source lock SHA-256: `{lock_sha256}`\n\n"
        "1. Verify every file in `inputs/` against `sources.lock.json`.\n"
        "2. Run the applicable generator from `generators/` using only those inputs.\n"
        "3. Compare the generated artifact hash with the corresponding release hash.\n\n"
        "The generators must not execute downloaded input data. Compression of this "
        "TAR is a packaging step and does not change the manifest.\n"
    ).encode("utf-8")


def _add_file(files: dict[str, bytes], name: str, payload: bytes) -> None:
    _safe_member_name(name)
    if name in files:
        raise ValueError(f"duplicate archive member: {name}")
    files[name] = payload


def build_bundle(
    lock_path: Path,
    inputs_dir: Path,
    output_path: Path,
    *,
    project_root: Path | None = None,
) -> Path:
    """Verify all locked inputs and create a byte-reproducible uncompressed TAR."""
    lock_path = lock_path.resolve(strict=True)
    inputs_dir = inputs_dir.resolve(strict=True)
    if project_root is None:
        project_root = lock_path.parents[2]
    project_root = project_root.resolve(strict=True)
    output_path = output_path.resolve(strict=False)

    records = load_lock(lock_path)
    canonical_lock = canonical_lock_bytes(records)
    files: dict[str, bytes] = {}

    for record in records:
        source_path = (inputs_dir / record.local_name).resolve(strict=True)
        try:
            source_path.relative_to(inputs_dir)
        except ValueError as exc:
            raise ValueError(f"input escapes input directory: {record.local_name}") from exc
        payload = source_path.read_bytes()
        verify_bytes(record, payload)
        _add_file(files, f"inputs/{record.local_name}", payload)

    generator_dir = project_root / "tools" / "rfdb"
    for generator in sorted(generator_dir.glob("*.py"), key=lambda path: path.name):
        _add_file(files, f"generators/{generator.name}", generator.read_bytes())

    _add_file(files, "sources.lock.json", canonical_lock)

    license_dir = project_root / "LICENSES"
    for license_path in sorted(license_dir.glob("*.txt"), key=lambda path: path.name):
        _add_file(files, f"LICENSES/{license_path.name}", license_path.read_bytes())
    for record in records:
        if record.license_file not in files:
            raise ValueError(f"missing required license text: {record.license_file}")

    notices = project_root / "THIRD_PARTY_NOTICES.md"
    _add_file(files, "THIRD_PARTY_NOTICES.md", notices.read_bytes())
    _add_file(
        files,
        "BUILD.md",
        _build_instructions(hashlib.sha256(canonical_lock).hexdigest()),
    )

    manifest = "".join(
        f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
        for name, payload in sorted(files.items())
    ).encode("utf-8")
    _add_file(files, "MANIFEST.sha256", manifest)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output_path, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in sorted(files.items()):
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))

    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--lock", type=Path, default=Path("tools/rfdb/sources.lock.json"))
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve(strict=True)

    def rooted(path: Path) -> Path:
        return path if path.is_absolute() else root / path

    result = build_bundle(
        rooted(args.lock),
        rooted(args.inputs),
        rooted(args.output),
        project_root=root,
    )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
