#!/usr/bin/env python3
"""
Flash AtomS3 client binaries using esptool and flasher args from the build.
Defaults to reading flasher_args.json from docker_bin_output or build/.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", required=True, help="Serial port (e.g. COM6 or /dev/ttyUSB0)")
    parser.add_argument("--baud", default="460800", help="Baud rate (default: 460800)")
    parser.add_argument(
        "--out-dir",
        default=None,
        help="Directory with build artifacts (default: docker_bin_output or build)",
    )
    parser.add_argument("--chip", default="esp32s3", help="Chip type (default: esp32s3)")
    return parser.parse_args()


def _find_output_dir(app_dir: Path, override: str | None) -> Path:
    if override:
        return Path(override).resolve()
    docker_out = app_dir / "docker_bin_output"
    if docker_out.is_dir():
        return docker_out
    return app_dir / "build"


def _load_flasher_args(out_dir: Path) -> dict:
    json_path = out_dir / "flasher_args.json"
    if json_path.is_file():
        return json.loads(json_path.read_text(encoding="utf-8"))
    raise FileNotFoundError(f"flasher_args.json not found in {out_dir}")


def _build_esptool_args(data: dict, out_dir: Path, chip: str) -> list[str]:
    args = ["--chip", chip]
    extra = data.get("extra_esptool_args", [])
    if isinstance(extra, list):
        args.extend(extra)

    write_args = data.get("write_flash_args")
    if isinstance(write_args, list):
        args.extend(write_args)
    else:
        flash_settings = data.get("flash_settings", {})
        if flash_settings:
            if "flash_mode" in flash_settings:
                args += ["--flash-mode", flash_settings["flash_mode"]]
            if "flash_freq" in flash_settings:
                args += ["--flash-freq", flash_settings["flash_freq"]]
            if "flash_size" in flash_settings:
                args += ["--flash-size", flash_settings["flash_size"]]

    args.append("write-flash")

    flash_files = data.get("flash_files", {})
    if isinstance(flash_files, dict):
        for addr in sorted(flash_files.keys(), key=lambda v: int(v, 0)):
            path = out_dir / flash_files[addr]
            args.extend([addr, str(path)])
    elif isinstance(flash_files, list):
        for item in flash_files:
            if isinstance(item, list) and len(item) == 2:
                addr, name = item
                args.extend([addr, str(out_dir / name)])
    else:
        raise ValueError("Unsupported flash_files format in flasher_args.json")

    return args


def main() -> int:
    args = parse_args()
    app_dir = Path(__file__).resolve().parent
    out_dir = _find_output_dir(app_dir, args.out_dir)
    data = _load_flasher_args(out_dir)
    esptool_args = _build_esptool_args(data, out_dir, args.chip)

    cmd = [sys.executable, "-m", "esptool", "-p", args.port, "-b", str(args.baud)] + esptool_args
    print("Flashing with:")
    print(" ".join(cmd))
    result = subprocess.run(cmd, check=False)
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
