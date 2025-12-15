#!/usr/bin/env python3
"""
CI-friendly FAP builder for lab_c5.

Ported from upstream (development branch) with tweaks:
- Skips interactive upload when running in CI or when --no-upload is passed.
- Allows optional --sdk-dir override; defaults to FLIPPER/sdk.
- Renames artifacts to lab_c5_v<version>_<variant>.fap.

Expected layout:
  FLIPPER/
    Lab_C5.c              (contains LAB_C5_VERSION_TEXT)
    sdk/*.zip             (Momentum / Unleashed SDK zips)
    dist/                 (build outputs)
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parent
DIST_DIR = ROOT / "dist"
DIST_FAP = DIST_DIR / "lab_c5.fap"
SOURCE_FILE = ROOT / "Lab_C5.c"

VARIANTS = (
    ("momentum", ("mntm", "momentum")),
    ("unleashed", ("unlsh", "unlshed", "unleashed")),
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
    return parser.parse_args()


def read_version() -> str:
    text = SOURCE_FILE.read_text(encoding="utf-8", errors="ignore")
    match = re.search(r'#define\s+LAB_C5_VERSION_TEXT\s+"([^"]+)"', text)
    if not match:
        raise RuntimeError("Could not find LAB_C5_VERSION_TEXT in Lab_C5.c")
    return match.group(1)


def pick_sdk(sdk_dir: Path, patterns: Iterable[str]) -> Optional[Path]:
    candidates = [
        path
        for path in sdk_dir.glob("*.zip")
        if any(token in path.name.lower() for token in patterns)
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_mtime)


def run_cmd(cmd: list[str]) -> None:
    print(f"\n>> {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def update_sdk(sdk_path: Path) -> None:
    url = sdk_path.resolve().as_uri()
    run_cmd(["ufbt", "update", "--hw", "f7", "--url", url])


def build_app() -> None:
    run_cmd(["ufbt"])


def upload_app() -> None:
    run_cmd(["ufbt", "launch"])


def rename_artifact(version: str, variant: str) -> None:
    target = DIST_DIR / f"lab_c5_v{version}_{variant}.fap"
    if not DIST_FAP.exists():
        raise FileNotFoundError(f"Build output not found: {DIST_FAP}")
    if target.exists():
        target.unlink()
    DIST_FAP.replace(target)
    print(f"Renamed to {target}")


def cleanup_dist_faps() -> None:
    removed = 0
    for fap in DIST_DIR.glob("*.fap"):
        try:
            fap.unlink()
            removed += 1
        except OSError as exc:
            print(f"Warning: could not remove {fap.name}: {exc}")
    if removed:
        print(f"Removed {removed} existing .fap file(s) from dist/")


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


def prompt_upload_choice(built: list[tuple[str, Path]]) -> Optional[tuple[str, Path]]:
    if not built:
        return None

    print("\nWhich variant do you want to upload to Flipper?")
    for idx, (variant, sdk) in enumerate(built, start=1):
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
    print(f"Detected version: {version}")
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    cleanup_dist_faps()

    built_variants: list[tuple[str, Path]] = []

    for variant, patterns in VARIANTS:
        sdk = pick_sdk(args.sdk_dir, patterns)
        if not sdk:
            print(f"Skipping {variant}: no matching SDK zip in {args.sdk_dir}")
            continue
        print(f"\n=== {variant.upper()} ===")
        print(f"Using SDK: {sdk.name}")
        update_sdk(sdk)
        build_app()
        rename_artifact(version, variant)
        built_variants.append((variant, sdk))

    if not built_variants:
        print("No variants built (missing SDK zips?).")
        return

    should_upload = not args.no_upload and not os.getenv("CI")
    if should_upload:
        selected = prompt_upload_choice(built_variants)
        if selected:
            variant, sdk = selected
            print(f"\nUploading {variant} build using SDK {sdk.name}...")
            update_sdk(sdk)
            upload_app()
            print("Upload finished. Ensure your Flipper is connected over USB and unlocked.")
    else:
        print("Upload skipped (CI or --no-upload).")

    print("\nDone.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
