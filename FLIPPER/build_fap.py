#!/usr/bin/env python3
"""
CI-friendly FAP builder for lab_c5.

Ported from upstream (development branch) with tweaks:
- Skips interactive upload when running in CI or when --no-upload is passed.
- Allows optional --sdk-dir override; defaults to FLIPPER/sdk.
- Builds from a temporary source snapshot and publishes validated artifacts as
  lab_c5_v<version>_<variant>[_<artifact-suffix>].fap without deleting existing FAPs.

Expected layout:
  FLIPPER/
    Lab_C5.c              (contains LAB_C5_VERSION_TEXT)
    sdk/*.zip             (Momentum / Unleashed SDK zips)
    dist/                 (build outputs)
"""

from __future__ import annotations

import argparse
import importlib.util
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parent
DIST_DIR = ROOT / "dist"
SOURCE_FILE = ROOT / "Lab_C5.c"

VARIANTS = (
    ("momentum_dev", ("mntm-dev", "momentum dev", "momentum-dev", "momentum_dev"), ()),
    ("momentum", ("mntm", "momentum"), ("mntm-dev",)),
    ("unleashed", ("unlsh", "unlshed", "unleashed"), ()),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build lab_c5 FAP variants")
    parser.add_argument(
        "--sdk-dir",
        type=Path,
        default=ROOT / "sdk",
        help="Directory containing Momentum/Unleashed SDK zips (default: FLIPPER/sdk)",
    )
    parser.add_argument(
        "--no-upload",
        action="store_true",
        help="Do not prompt or attempt upload after build",
    )
    parser.add_argument(
        "--variant",
        choices=[name for name, _, _ in VARIANTS],
        help="Build only one firmware variant (default: every available SDK)",
    )
    parser.add_argument(
        "--artifact-suffix",
        help="Append a safe trial suffix to the FAP filename, preserving the regular build",
    )
    return parser.parse_args()


def read_version() -> str:
    text = SOURCE_FILE.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r'#define\s+LAB_C5_VERSION_TEXT\s+"([^"]+)"', text)
    if not match:
        raise RuntimeError("Could not find LAB_C5_VERSION_TEXT in Lab_C5.c")
    return match.group(1)


def artifact_target(dist_dir: Path, version: str, variant: str, suffix: Optional[str]) -> Path:
    if suffix is not None and not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", suffix):
        raise ValueError("Artifact suffix must contain only lowercase letters, digits, _ or -")
    name = f"lab_c5_v{version}_{variant}"
    if suffix:
        name += f"_{suffix}"
    return dist_dir / f"{name}.fap"


def pick_sdk(
    sdk_dir: Path, patterns: Iterable[str], exclude: Iterable[str] = ()
) -> Optional[Path]:
    candidates = [
        path
        for path in sdk_dir.glob("*.zip")
        if any(token in path.name.lower() for token in patterns)
        and not any(token in path.name.lower() for token in exclude)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def run_cmd(cmd: list[str], cwd: Path = ROOT) -> None:
    print(f"\n>> {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=cwd)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def update_sdk(sdk_path: Path) -> None:
    url = sdk_path.resolve().as_uri()
    run_cmd(["ufbt", "update", "--hw", "f7", "--url", url])


def build_app(project_dir: Path) -> None:
    run_cmd(["ufbt"], cwd=project_dir)


def load_deployer():
    script = DIST_DIR / "deploy_fap.py"
    spec = importlib.util.spec_from_file_location("lab_c5_deploy_fap", script)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Could not load deployer: {script}")
    deployer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(deployer)
    return deployer


def upload_app(fap: Path) -> None:
    """Upload the published FAP with the existing serial deployer prompts."""
    if not fap.is_file():
        raise FileNotFoundError(f"Published FAP not found: {fap}")
    deployer = load_deployer()
    port = deployer.pick_port()
    flipper_dir = deployer.prompt_flipper_path("/ext/apps")
    purge = deployer.prompt_yes_no("Remove old lab_c5*.fap from device before upload?", default=True)
    run_after = deployer.prompt_yes_no("Start the app after upload?", default=True)
    deployer.upload_via_serial(fap, port, flipper_dir, purge, run_after)


def validate_artifact(candidate: Path) -> None:
    """Reject missing or structurally truncated ELF32 output before publishing."""
    blob = candidate.read_bytes()
    if len(blob) < 52 or blob[:6] != b"\x7fELF\x01\x01":
        raise ValueError(f"Not a little-endian ELF32 FAP: {candidate}")
    section_offset = struct.unpack_from("<I", blob, 32)[0]
    section_stride, section_count = struct.unpack_from("<HH", blob, 46)
    if section_offset < 52 or section_stride < 40 or section_count == 0:
        raise ValueError(f"Invalid ELF section table: {candidate}")
    if section_offset + section_stride * section_count > len(blob):
        raise ValueError(f"Truncated ELF section table: {candidate}")


def validate_embedded_plugin(candidate: Path) -> None:
    """Check all embedded FALs inside this FAP, independent of loose dist files."""
    checker = ROOT / "tests" / "check_embedded_plugin.py"
    result = subprocess.run(
        [
            sys.executable,
            str(checker),
            str(candidate),
            "--require-recon",
            "--require-rogue",
            "--require-arp",
            "--require-plugin",
            "lab_c5_wardrive",
            "--require-plugin",
            "lab_c5_beacon",
            "--require-plugin",
            "lab_c5_mitm_pcap",
            "--require-plugin",
            "lab_c5_wardrive_upload",
            "--require-plugin",
            "lab_c5_nmap",
            "--require-plugin",
            "lab_c5_wpasec",
            "--require-plugin",
            "lab_c5_connect",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise ValueError(f"Embedded plugin check failed: {detail}")
    print(result.stdout.strip())


def publish_artifact(candidate: Path, target: Path) -> None:
    """Copy into dist, then replace one target atomically on the same volume."""
    validate_artifact(candidate)
    target.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{target.stem}-", suffix=".tmp", dir=target.parent, delete=False
        ) as temp_file:
            temp_path = Path(temp_file.name)
            with candidate.open("rb") as source:
                shutil.copyfileobj(source, temp_file)
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_path, target)
        print(f"Published {target}")
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def copy_project_for_build(stage_root: Path) -> None:
    """Build from a source snapshot without writing into the live dist directory."""
    excluded = {"dist", "sdk", ".git", ".vscode", "knowledge", "tests", "__pycache__"}

    def ignore(directory: str, names: list[str]) -> set[str]:
        if Path(directory).resolve() == ROOT.resolve():
            return set(names) & excluded
        return set(names) & {"__pycache__"}

    shutil.copytree(ROOT, stage_root, ignore=ignore)


def ensure_dependencies() -> None:
    if shutil.which("ufbt"):
        return

    print("ufbt not found. Installing via pip...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "-U", "ufbt"], cwd=ROOT
    )
    if result.returncode != 0:
        raise SystemExit(result.returncode)
    if not shutil.which("ufbt"):
        raise RuntimeError(
            "ufbt still not available after installation. "
            "Ensure your Python Scripts directory is in PATH."
        )
    print("ufbt installed successfully.")


def prompt_upload_choice(
    built: list[tuple[str, Path, Path]],
) -> Optional[tuple[str, Path, Path]]:
    if not built:
        return None

    print("\nWhich variant do you want to upload to Flipper?")
    for idx, (variant, sdk, _) in enumerate(built, start=1):
        print(f"  {idx}) {variant} (SDK: {sdk.name})")
    print("  n) none / skip")

    while True:
        choice = input("Select [1-9 or n]: ").strip().lower()
        if choice in ("n", "no", "none", ""):
            return None
        if choice.isdigit():
            i = int(choice)
            if 1 <= i <= len(built):
                return built[i - 1]
        print("Invalid choice, try again.")


def main() -> None:
    args = parse_args()
    ensure_dependencies()
    version = read_version()
    selected_variant = getattr(args, "variant", None)
    artifact_suffix = getattr(args, "artifact_suffix", None)
    # Fail before the first SDK update or build when the target name is invalid.
    artifact_target(DIST_DIR, version, "unleashed", artifact_suffix)
    print(f"Detected version: {version}")
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    built_variants: list[tuple[str, Path, Path]] = []
    with tempfile.TemporaryDirectory(prefix="lab-c5-build-") as temporary:
        source_snapshot = Path(temporary) / "source"
        copy_project_for_build(source_snapshot)
        for variant, patterns, exclude in VARIANTS:
            if selected_variant and variant != selected_variant:
                continue
            sdk = pick_sdk(args.sdk_dir, patterns, exclude)
            if not sdk:
                print(f"Skipping {variant}: no matching SDK zip in {args.sdk_dir}")
                continue
            print(f"\n=== {variant.upper()} ===")
            print(f"Using SDK: {sdk.name}")
            stage_root = Path(temporary) / variant / "FLIPPER"
            shutil.copytree(source_snapshot, stage_root)
            staged_fap = stage_root / "dist" / "lab_c5.fap"
            update_sdk(sdk)
            build_app(stage_root)
            target = artifact_target(DIST_DIR, version, variant, artifact_suffix)
            validate_embedded_plugin(staged_fap)
            publish_artifact(staged_fap, target)
            built_variants.append((variant, sdk, target))

        if not built_variants:
            print("No variants built (missing SDK zips?).")
            return

        should_upload = not args.no_upload and not os.getenv("CI")
        if should_upload:
            selected = prompt_upload_choice(built_variants)
            if selected:
                _, _, target = selected
                print(f"\nUploading {target.name}...")
                upload_app(target)
                print("Upload finished. Ensure your Flipper is connected over USB and unlocked.")
        else:
            print("Upload skipped (CI or --no-upload).")

    print("\nDone.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
