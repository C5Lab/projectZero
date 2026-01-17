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


def _default_target_dir():
    return Path(__file__).resolve().parents[2] / "binaries-esp32c5"


def _require_files(target_dir):
    missing = [
        str(target_dir / name)
        for name in REQUIRED_FILES
        if not (target_dir / name).exists()
    ]
    if missing:
        pytest.fail("Missing target firmware files: " + ", ".join(missing))


def _run_esptool(args):
    cmd = [sys.executable, "-m", "esptool"] + args
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        pytest.fail(f"esptool failed: {' '.join(cmd)} (code {result.returncode})")


@pytest.mark.mandatory
@pytest.mark.flash
def test_flash_target_firmware(dut_port, settings_config):
    target_dir = Path(os.environ.get("ESP32C5_TARGET_SW_DIR", _default_target_dir()))
    _require_files(target_dir)

    chip = os.environ.get("ESP32C5_CHIP", "esp32c5")
    baud = str(settings_config.get("flash_baud", 460800))
    flash_mode = os.environ.get("ESP32C5_FLASH_MODE", "dio")
    flash_freq = os.environ.get("ESP32C5_FLASH_FREQ", "80m")

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
        "erase-flash",
    ])

    write_args = [
        "-p",
        dut_port,
        "-b",
        baud,
        "--before",
        "default-reset",
        "--after",
        "watchdog-reset",
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
    for name, offset in OFFSETS.items():
        write_args.extend([offset, str(target_dir / name)])
    _run_esptool(write_args)
