import os
import subprocess
import sys
from pathlib import Path

import pytest


REQUIRED_FILES = ["bootloader.bin", "partition-table.bin", "projectZero.bin"]

OFFSETS = {
    "bootloader.bin": "0x2000",
    "partition-table.bin": "0x8000",
    "projectZero.bin": "0x20000",
}


def _default_base_dir():
    return Path(__file__).resolve().parents[1] / "SW"


def _require_files(base_dir):
    missing = [
        str(base_dir / name)
        for name in REQUIRED_FILES
        if not (base_dir / name).exists()
    ]
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
    _require_files(base_dir)

    chip = os.environ.get("ESP32C5_CHIP", "esp32c5")
    baud = os.environ.get("ESP32C5_BAUD", "460800")
    flash_mode = os.environ.get("ESP32C5_FLASH_MODE", "dio")
    flash_freq = os.environ.get("ESP32C5_FLASH_FREQ", "80m")

    _run_esptool([
        "-p",
        dut_port,
        "-b",
        baud,
        "--before",
        "default_reset",
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
        "default_reset",
        "--after",
        "watchdog_reset",
        "--chip",
        chip,
        "write_flash",
        "--flash_mode",
        flash_mode,
        "--flash_freq",
        flash_freq,
        "--flash_size",
        "detect",
    ]
    for name, offset in OFFSETS.items():
        write_args.extend([offset, str(base_dir / name)])
    _run_esptool(write_args)
