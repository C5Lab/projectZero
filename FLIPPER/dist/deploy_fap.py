#!/usr/bin/env python3
"""
Upload an existing .fap from dist/ to a connected Flipper over USB CDC (serial, like qFlipper).
- Lists .fap files in this directory and lets you pick one.
- Pushes the file to /ext/apps/<name>.fap via Flipper CLI.
"""

from __future__ import annotations

import sys
import subprocess
from pathlib import Path
from typing import List

HERE = Path(__file__).resolve().parent


def find_faps() -> List[Path]:
    return sorted(HERE.glob("*.fap"), key=lambda p: p.stat().st_mtime, reverse=True)


def pick_fap(faps: List[Path]) -> Path:
    print("Available .fap files:")
    for idx, fap in enumerate(faps, start=1):
        size_kb = fap.stat().st_size // 1024
        print(f"  {idx}) {fap.name} ({size_kb} KB)")

    while True:
        choice = input("Select file number: ").strip()
        if choice.isdigit():
            i = int(choice)
            if 1 <= i <= len(faps):
                return faps[i - 1]
        print("Invalid choice, try again.")


def prompt_yes_no(question: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        choice = input(f"{question} {suffix}: ").strip().lower()
        if choice == "" and default is not None:
            return default
        if choice in ("y", "yes"):
            return True
        if choice in ("n", "no"):
            return False
        print("Please answer y or n.")


def ensure_ufbt_in_path() -> None:
    """Make sure ufbt scripts (and flipper.storage) are importable."""
    ufbt_scripts = Path.home() / ".ufbt" / "current" / "scripts"
    if str(ufbt_scripts) not in sys.path:
        sys.path.insert(0, str(ufbt_scripts))


def ensure_ufbt_installed() -> None:
    """Verify ufbt toolchain (flipper.storage) is available; install if missing."""
    try:
        import flipper.storage  # noqa: F401
        return
    except ImportError:
        pass

    print("ufbt (flipper.storage) not detected. Installing with pip ...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-U", "ufbt"])
    except Exception as exc:
        raise RuntimeError(
            "ufbt is required but could not be installed automatically. "
            "Install it manually with `python -m pip install -U ufbt` and retry."
        ) from exc


def ensure_pyserial_installed() -> None:
    """Verify pyserial is available; install it if missing."""
    try:
        import serial  # noqa: F401
        return
    except ImportError:
        pass

    print("pyserial not detected. Installing with pip ...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyserial"])
    except Exception as exc:
        raise RuntimeError(
            "pyserial is required but could not be installed automatically. "
            "Install it manually with `python -m pip install pyserial` and retry."
        ) from exc


def pick_port() -> str:
    ensure_pyserial_installed()
    from serial.tools import list_ports

    ports = list(list_ports.comports())
    if not ports:
        raise RuntimeError("No serial ports detected. Connect Flipper (CDC) and try again.")

    def is_flipper(p):
        desc = (p.description or "").lower()
        return "flipper" in desc or (p.vid == 0x0483 and p.pid == 0x5740)

    ports.sort(key=lambda p: (not is_flipper(p), p.device))

    print("\nDetected serial ports:")
    for idx, p in enumerate(ports, start=1):
        hint = " [Flipper?]" if is_flipper(p) else ""
        print(f"  {idx}) {p.device} ({p.description}){hint}")

    while True:
        choice = input("Select port [number] (default=1): ").strip()
        if not choice:
            return ports[0].device
        if choice.isdigit():
            i = int(choice)
            if 1 <= i <= len(ports):
                return ports[i - 1].device
        print("Invalid choice, try again.")


def prompt_flipper_path(default: str = "/ext/apps") -> str:
    while True:
        raw = input(f"Destination path on Flipper [{default}]: ").strip()
        if not raw:
            return default
        raw = raw.replace("\\", "/")
        if not raw.startswith("/"):
            print("Path must start with '/'. Example: /ext/apps")
            continue
        return raw.rstrip("/")


def purge_old_versions(storage, flipper_dir: str) -> None:
    """Remove all lab_c5*.fap in target dir (including prior version of the one being uploaded)."""
    removed = 0
    try:
        for path, _, files in storage.walk(flipper_dir):
            for fname in files:
                name_lower = fname.lower()
                if name_lower.startswith("lab_c5") and name_lower.endswith(".fap"):
                    target = f"{path}/{fname}".replace("//", "/")
                    print(f"Removing old version on device: {target}")
                    storage.remove(target)
                    removed += 1
    except Exception as exc:  # pragma: no cover - defensive
        print(f"Warning: could not purge old versions: {exc}")
    if removed == 0:
        print("No old lab_c5*.fap found to remove.")


def run_app(storage, flipper_path: str) -> None:
    try:
        storage.send_and_wait_prompt(f'loader open "{flipper_path}"\r')
        print("Launch command sent.")
    except Exception as exc:  # pragma: no cover - defensive
        print(f"Warning: could not start app automatically: {exc}")


def upload_via_serial(fap: Path, port: str, flipper_dir: str, purge: bool, run_after: bool) -> None:
    ensure_ufbt_installed()
    ensure_ufbt_in_path()
    try:
        from flipper.storage import FlipperStorage, FlipperStorageOperations
        from serial.serialutil import SerialException
    except ImportError as exc:
        raise RuntimeError(
            "Could not import flipper.storage from ufbt toolchain. "
            "Run `python -m pip install -U ufbt` and try again."
        ) from exc

    flipper_path = f"{flipper_dir}/{fap.name}".replace("//", "/")
    print(f"\nConnecting to {port} and uploading to {flipper_path} ...")

    try:
        with FlipperStorage(port) as storage:
            ops = FlipperStorageOperations(storage)
            ops.mkpath(flipper_dir)
            if purge:
                purge_old_versions(storage, flipper_dir)
            ops.send_file_to_storage(flipper_path, str(fap), force=True)
            if run_after:
                run_app(storage, flipper_path)
    except SerialException as exc:
        raise RuntimeError(
            f"Port {port} is busy or unavailable. "
            "Close qFlipper/serial console/IDE and try again, or pick another COM."
        ) from exc
    except PermissionError as exc:
        raise RuntimeError(
            f"Permission denied on port {port}. Close apps using it and try again."
        ) from exc
    print("Upload complete.")


def main() -> None:
    faps = find_faps()
    if not faps:
        print("No .fap files found in dist/. Build first, then rerun.")
        return

    selected = pick_fap(faps)
    port = pick_port()
    flipper_dir = prompt_flipper_path("/ext/apps")
    purge = prompt_yes_no("Remove old lab_c5*.fap from device before upload?", default=True)
    run_after = prompt_yes_no("Start the app after upload?", default=True)
    upload_via_serial(selected, port, flipper_dir, purge, run_after)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        print(f"\nERROR: {exc}")
        sys.exit(1)
