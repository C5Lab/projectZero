#!/usr/bin/env python3
import time
import sys
import subprocess
import os
import argparse
try:
    from importlib import metadata as importlib_metadata
except ImportError:
    importlib_metadata = None

# Colors
RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; CYAN = "\033[96m"; RESET = "\033[0m"

VERSION = "v04"
MIN_ESPTOOL_VERSION = "5.2.0"
DEFAULT_BAUD = 460800  # Original default; can be overridden via CLI
REQUIRED_FILES = ["bootloader.bin", "partition-table.bin", "projectZero.bin"]
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.environ.get("FLASH_BOARD_VENV", os.path.join(SCRIPT_DIR, ".venv"))

def parse_version(version):
    parts = []
    prerelease = False
    for part in version.split("."):
        digits = []
        for ch in part:
            if ch.isdigit():
                digits.append(ch)
            else:
                prerelease = True
                break
        parts.append(int("".join(digits) or 0))
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3]), prerelease

def is_version_at_least(installed, required):
    installed_tuple, installed_prerelease = parse_version(installed)
    required_tuple, _ = parse_version(required)
    if installed_tuple != required_tuple:
        return installed_tuple > required_tuple
    return not installed_prerelease

def get_esptool_version(esptool_module):
    if importlib_metadata is not None:
        try:
            return importlib_metadata.version("esptool")
        except importlib_metadata.PackageNotFoundError:
            pass
    return getattr(esptool_module, "__version__", None)

def in_virtualenv():
    return (
        getattr(sys, "base_prefix", sys.prefix) != sys.prefix
        or getattr(sys, "real_prefix", None) is not None
    )

def get_venv_python(venv_dir=VENV_DIR):
    if os.name == "nt":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python")

def create_local_venv(venv_dir=VENV_DIR):
    venv_python = get_venv_python(venv_dir)
    if os.path.exists(venv_python):
        return venv_python
    print(f"{YELLOW}Creating local virtual environment: {venv_dir}{RESET}")
    try:
        subprocess.check_call([sys.executable, "-m", "venv", venv_dir])
    except subprocess.CalledProcessError:
        print(f"{RED}Failed to create virtual environment at {venv_dir}.{RESET}")
        print(f"{YELLOW}Install Python venv support (for Debian/Ubuntu: apt install python3-venv) and retry.{RESET}")
        sys.exit(1)
    return venv_python

def ensure_pip(python_executable):
    probe = subprocess.run(
        [python_executable, "-m", "pip", "--version"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if probe.returncode == 0:
        return
    subprocess.check_call([python_executable, "-m", "ensurepip", "--upgrade"])

def install_with_python(python_executable, packages):
    ensure_pip(python_executable)
    print(f"{YELLOW}Installing/upgrading packages: {', '.join(packages)}{RESET}")
    subprocess.check_call([python_executable, "-m", "pip", "install", "--upgrade"] + packages)

def reexec_with_python(python_executable):
    os.execv(python_executable, [python_executable] + sys.argv)

def ensure_packages():
    missing = []
    try:
        import serial.tools.list_ports  # noqa
    except ImportError:
        missing.append("pyserial")
    try:
        import esptool
    except ImportError:
        missing.append(f"esptool>={MIN_ESPTOOL_VERSION}")
    else:
        installed_version = get_esptool_version(esptool)
        if not installed_version or not is_version_at_least(installed_version, MIN_ESPTOOL_VERSION):
            missing.append(f"esptool>={MIN_ESPTOOL_VERSION}")
    if missing:
        target_python = sys.executable if in_virtualenv() else create_local_venv()
        install_with_python(target_python, missing)
        reexec_with_python(target_python)

ensure_packages()
import serial
import serial.tools.list_ports

# Keep these offsets in sync with partitions.csv.
OFFSETS = {
    "bootloader.bin": "0x2000",       # as requested
    "partition-table.bin": "0x8000",
    # partitions.csv defines ota_0 at 0x20000, so app must be flashed there
    "projectZero.bin": "0x20000",
    # Optional: seed ota_1 so both OTA slots are bootable after a UART flash
    "projectZero_ota1.bin": "0x410000",
}

def check_files():
    missing = [f for f in REQUIRED_FILES if not os.path.exists(f)]
    if missing:
        print(f"{RED}Missing files: {', '.join(missing)}{RESET}")
        sys.exit(1)
    print(f"{GREEN}All required files found.{RESET}")

def list_ports():
    return set(p.device for p in serial.tools.list_ports.comports())

def wait_for_new_port(before, timeout=20.0):
    print(f"{CYAN}Hold BOOT and connect the board to enter ROM mode.{RESET}")
    spinner = ['|','/','-','\\']
    print(f"{YELLOW}Waiting for new serial port...{RESET}")
    t0 = time.time()
    i = 0
    while time.time() - t0 < timeout:
        after = list_ports()
        new_ports = after - before
        sys.stdout.write(f"\r{spinner[i % len(spinner)]} "); sys.stdout.flush()
        i += 1
        if new_ports:
            sys.stdout.write("\r"); sys.stdout.flush()
            return new_ports.pop()
        time.sleep(0.15)
    print(f"\n{RED}No new serial port detected.{RESET}")
    sys.exit(1)

def erase_all(port, baud=DEFAULT_BAUD):
    cmd = [sys.executable, "-m", "esptool", "-p", port, "-b", str(baud),
           "--before", "default-reset", "--after", "no_reset", "--chip", "esp32c5",
           "erase_flash"]
    print(f"{CYAN}Erasing full flash:{RESET} {' '.join(cmd)}")
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print(f"{RED}Erase failed with code {res.returncode}.{RESET}")
        sys.exit(res.returncode)

def do_flash(port, baud=DEFAULT_BAUD, flash_mode="dio", flash_freq="80m", seed_ota1=True):
    cmd = [
        sys.executable, "-m", "esptool",
        "-p", port,
        "-b", str(baud),
        "--before", "default-reset",
        "--after", "watchdog-reset",            # we'll do a precise reset pattern ourselves
        "--chip", "esp32c5",
        "write-flash",
        "--flash-mode", flash_mode,       # default "dio"
        "--flash-freq", flash_freq,       # default "80m"
        "--flash-size", "detect",
        OFFSETS["bootloader.bin"], "bootloader.bin",
        OFFSETS["partition-table.bin"], "partition-table.bin",
        OFFSETS["projectZero.bin"], "projectZero.bin",
    ]
    if seed_ota1:
        cmd.extend([OFFSETS["projectZero_ota1.bin"], "projectZero.bin"])
    print(f"{CYAN}Flashing command:{RESET} {' '.join(cmd)}")
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print(f"{RED}Flash failed with code {res.returncode}.{RESET}")
        sys.exit(res.returncode)

def pulse(ser, dtr=None, rts=None, delay=0.06):
    if dtr is not None:
        ser.dtr = dtr
    if rts is not None:
        ser.rts = rts
    time.sleep(delay)

def reset_to_app(port):
    """
    Typical ESP auto-reset wiring:
      RTS -> EN (inverted)
      DTR -> GPIO0 (inverted)

    To boot the *application*:
      - DTR=False  (GPIO0 HIGH, i.e., not in ROM)
      - pulse EN low via RTS=True then RTS=False
    """
    print(f"{YELLOW}Issuing post-flash reset (RTS/DTR) to run app...{RESET}")
    try:
        with serial.Serial(port, 115200, timeout=0.1) as ser:
            # Make sure BOOT is released
            pulse(ser, dtr=False, rts=None)
            # Short EN reset
            pulse(ser, rts=True)
            pulse(ser, rts=False)
        print(f"{GREEN}Reset sent. If not Press the board's RESET button manually.{RESET}")
        
    except Exception as e:
        print(f"{RED}RTS/DTR reset failed: {e}{RESET}")
        print(f"{YELLOW}Press the board's RESET button manually.{RESET}")

def monitor(port, baud=DEFAULT_BAUD):
    print(f"{CYAN}Opening serial monitor on {port} @ {baud} (Ctrl+C to exit)...{RESET}")
    try:
        # A brief delay to let the port re-enumerate after reset
        time.sleep(0.3)
        with serial.Serial(port, baud, timeout=0.2) as ser:
            while True:
                try:
                    data = ser.read(1024)
                    if data:
                        sys.stdout.write(data.decode(errors="replace"))
                        sys.stdout.flush()
                except KeyboardInterrupt:
                    break
    except Exception as e:
        print(f"{RED}Monitor failed: {e}{RESET}")

def main():
    parser = argparse.ArgumentParser(description="ESP32-C5 flasher with robust reboot handling")
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    parser.add_argument("--port", help="Known serial port (e.g., COM10 or /dev/ttyACM0)")
    parser.add_argument("baud", nargs="?", type=int, default=DEFAULT_BAUD,
                        help=f"Optional baud rate (default: {DEFAULT_BAUD})")
    parser.add_argument("--monitor", action="store_true", help="Open serial monitor after flashing")
    parser.add_argument("--erase", action="store_true", help="Full erase before flashing (fixes stale NVS/partitions)")
    parser.add_argument("--no-seed-ota1", action="store_true",
                        help="Do not flash projectZero.bin into ota_1 at 0x410000")
    parser.add_argument("--flash-mode", default="dio", choices=["dio", "qio", "dout", "qout"],
                        help="Flash mode (default: dio)")
    parser.add_argument("--flash-freq", default="80m", choices=["80m", "60m", "40m", "26m", "20m"],
                        help="Flash frequency (default: 80m). If you see boot loops, try 40m.")
    args = parser.parse_args()

    check_files()

    print(f"{CYAN}ESP32-C5 flasher version: {VERSION}{RESET}")
    print(f"{CYAN}Using baud rate: {args.baud}{RESET}")

    if args.port:
        port = args.port
    else:
        before = list_ports()
        port = wait_for_new_port(before)

    print(f"{GREEN}Detected serial port: {port}{RESET}")
    print(f"{YELLOW}Tip: release the BOOT button before programming finishes.{RESET}")
    seed_ota1 = not args.no_seed_ota1
    if seed_ota1:
        print(f"{YELLOW}Seeding both OTA slots: ota_0 @ {OFFSETS['projectZero.bin']} and ota_1 @ {OFFSETS['projectZero_ota1.bin']}{RESET}")

    if args.erase:
        erase_all(port, args.baud)

    do_flash(port, baud=args.baud, flash_mode=args.flash_mode, flash_freq=args.flash_freq,
             seed_ota1=seed_ota1)

    reset_to_app(port)

    if args.monitor:
        monitor(port, args.baud)

if __name__ == "__main__":
    main()
