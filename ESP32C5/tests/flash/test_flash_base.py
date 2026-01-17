import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


OFFSETS = {
    "bootloader.bin": "0x2000",
    "partition-table.bin": "0x8000",
    "projectZero.bin": "0x20000",
}


def _default_base_dir():
    return Path(__file__).resolve().parents[2] / "tools" / "SW"


def _load_manifest(base_dir):
    manifest_path = os.environ.get("ESP32C5_FLASH_MANIFEST")
    if not manifest_path:
        return [(offset, base_dir / name) for name, offset in OFFSETS.items()]

    path = Path(manifest_path)
    if not path.exists():
        pytest.fail(f"Flash manifest not found: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        pytest.fail(f"Invalid flash manifest JSON: {path} ({exc})")

    files = data.get("files", [])
    if not files:
        pytest.fail(f"Flash manifest has no files: {path}")

    result = []
    for entry in files:
        offset = entry.get("offset")
        file_path = entry.get("path")
        if not offset or not file_path:
            pytest.fail(f"Invalid manifest entry: {entry}")
        resolved = Path(file_path)
        if not resolved.is_absolute():
            resolved = base_dir / resolved
        result.append((offset, resolved))
    return result


def _require_files(files):
    missing = [str(path) for _, path in files if not path.exists()]
    if missing:
        pytest.fail("Missing base firmware files: " + ", ".join(missing))


def _run_esptool(args):
    cmd = [sys.executable, "-m", "esptool"] + args
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        pytest.fail(f"esptool failed: {' '.join(cmd)} (code {result.returncode})")


@pytest.mark.flash
def test_flash_base_firmware(dut_port):
    base_dir = Path(os.environ.get("ESP32C5_BASE_SW_DIR", _default_base_dir()))
    files = _load_manifest(base_dir)
    _require_files(files)

    chip = os.environ.get("ESP32C5_CHIP", "esp32c5")
    baud = os.environ.get("ESP32C5_BAUD", "460800")
    flash_mode = os.environ.get("ESP32C5_FLASH_MODE", "dio")
    flash_freq = os.environ.get("ESP32C5_FLASH_FREQ", "80m")
    skip_erase = os.environ.get("ESP32C5_SKIP_ERASE", "").lower() in {"1", "true", "yes"}

    if not skip_erase:
        _run_esptool([
            "-p",
            dut_port,
            "-b",
            baud,
            "--before",
            "default-reset",
            "--after",
            "no_reset",
            "--chip",
            chip,
            "erase_flash",
        ])

    write_args = [
        "-p",
        dut_port,
        "-b",
        baud,
        "--before",
        "default-reset",
        "--after",
        "hard_reset",
        "--chip",
        chip,
        "write-flash",
        "--flash-mode",
        flash_mode,
        "--flash-freq",
        flash_freq,
        "--flash-size",
        "detect",
    ]
    for offset, path in files:
        write_args.extend([offset, str(path)])
    _run_esptool(write_args)
