import os
import subprocess
import sys
from pathlib import Path

import pytest


REQUIRED_FILES = [
    "bootloader.bin",
    "partition-table.bin",
    "projectZero.bin",
]


def _default_base_dir():
    return Path(__file__).resolve().parents[1] / "SW"


def _flash_script_path():
    return Path(__file__).resolve().parents[2] / "binaries-esp32c5" / "flash_board.py"


def _require_files(base_dir):
    missing = [str(base_dir / name) for name in REQUIRED_FILES if not (base_dir / name).exists()]
    if missing:
        pytest.fail("Missing base firmware files: " + ", ".join(missing))


def _run_flash_script(port, baud, erase, base_dir):
    script = _flash_script_path()
    if not script.exists():
        pytest.fail(f"Flash script not found: {script}")

    cmd = [sys.executable, str(script), "--port", port]
    if erase:
        cmd.append("--erase")
    if baud:
        cmd.append(str(baud))

    result = subprocess.run(cmd, cwd=base_dir, check=False)
    if result.returncode != 0:
        pytest.fail(f"flash_board.py failed: {' '.join(cmd)} (code {result.returncode})")


@pytest.mark.flash
def test_flash_base_firmware(dut_port):
    base_dir = Path(os.environ.get("ESP32C5_BASE_SW_DIR", _default_base_dir()))
    _require_files(base_dir)

    baud = os.environ.get("ESP32C5_BAUD", "460800")

    _run_flash_script(dut_port, baud, erase=True, base_dir=base_dir)
