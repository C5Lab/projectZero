#!/usr/bin/env python3
"""
Build AtomS3 client firmware inside the official ESP-IDF docker image.
Creates a temporary copy of the repo, builds the AtomS3 client app, then
copies artifacts into ESP32C5/tests/AtomS3_client/docker_bin_output.

Usage:
    python ESP32C5/tests/AtomS3_client/build_bin_docker.py
    python ESP32C5/tests/AtomS3_client/build_bin_docker.py --image espressif/idf:v6.0-beta1
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--image",
        default="espressif/idf:v6.0-beta1",
        help="Docker image to use (default: espressif/idf:v6.0-beta1)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[3]
    app_dir = repo_root / "ESP32C5" / "tests" / "AtomS3_client"

    tmpdir = Path(tempfile.mkdtemp(prefix="projectzero-atom-build-"))
    workspace = tmpdir / "src"
    print(f"Creating temporary workspace at {workspace}")

    try:
        shutil.copytree(
            repo_root,
            workspace,
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns(
                ".git",
                "__pycache__",
                "ESP32C5/build",
                "ESP32C5/managed_components",
                "ESP32C5/binaries-esp32c5",
                "ESP32C5/tests/AtomS3_client/build",
                "ESP32C5/tests/AtomS3_client/sdkconfig",
                "ESP32C5/tests/AtomS3_client/sdkconfig.old",
            ),
        )
    except Exception as exc:
        print(f"Failed to prepare workspace: {exc}", file=sys.stderr)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return 1

    # Ensure defaults are used for a clean config.
    for filename in ("sdkconfig", "sdkconfig.old"):
        try:
            (workspace / "ESP32C5" / "tests" / "AtomS3_client" / filename).unlink()
        except FileNotFoundError:
            pass

    cmd = [
        "docker",
        "run",
        "--rm",
        "-it",
        "-v",
        f"{workspace.as_posix()}:/project",
        "-w",
        "/project/ESP32C5/tests/AtomS3_client",
        "-e",
        "IDF_TARGET=esp32s3",
        args.image,
        "bash",
        "-lc",
        ". /opt/esp/idf/export.sh >/dev/null 2>&1; idf.py -D SDKCONFIG_DEFAULTS=sdkconfig.defaults build",
    ]

    print("Running build inside docker:")
    print(" ".join(cmd))
    try:
        subprocess.run(cmd, check=True)
    except FileNotFoundError:
        print("docker not found. Please install Docker and ensure it's on PATH.", file=sys.stderr)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return 1
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(tmpdir, ignore_errors=True)
        return exc.returncode

    src_build = workspace / "ESP32C5" / "tests" / "AtomS3_client" / "build"
    dest = app_dir / "docker_bin_output"
    dest.mkdir(parents=True, exist_ok=True)
    copied = []
    if src_build.is_dir():
        for item in src_build.iterdir():
            if not item.is_file():
                continue
            if item.name.lower() == "readme.md":
                continue
            if item.suffix.lower() not in {".bin", ".elf", ".map", ".json", ".txt"}:
                continue
            shutil.copy2(item, dest / item.name)
            copied.append(item.name)

    shutil.rmtree(tmpdir, ignore_errors=True)

    print("\nBuild finished.")
    if copied:
        print(f"Copied artifacts to: {dest}")
        print("Files:")
        for name in copied:
            print(f"  - {name}")
    else:
        print("No artifacts were found to copy.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
