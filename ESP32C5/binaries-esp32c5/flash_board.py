import time
import sys
import subprocess
import os
import argparse
import re

MIN_ESPTOOL = "5.0.0"
VERSION = "0.2"

# Require Python 3.8+ (esptool and subprocess.run rely on it)
if sys.version_info < (3, 8):
    sys.stderr.write("This tool requires Python 3.8+. Run with `python3` (3.8+) or create a venv.\n")
    sys.exit(1)

def ensure_packages():
    missing = []
    try:
        import serial.tools.list_ports  # noqa
    except ImportError:
        missing.append("pyserial")

    try:
        import colorama  # noqa
    except ImportError:
        missing.append("colorama")

    def version_ok(installed, minimum):
        try:
            from packaging.version import Version  # type: ignore
            return Version(installed) >= Version(minimum)
        except Exception:
            def _split(ver):
                return tuple(int(p) for p in re.split(r"[^\d]+", ver) if p)

            return _split(installed) >= _split(minimum)

    esptool_req = "esptool>={}".format(MIN_ESPTOOL)
    try:
        import importlib.metadata as importlib_metadata  # type: ignore
    except ImportError:  # pragma: no cover - Python <3.8 fallback
        import importlib_metadata as importlib_metadata  # type: ignore

    try:
        import esptool  # noqa
        installed_version = importlib_metadata.version("esptool")
        if not version_ok(installed_version, MIN_ESPTOOL):
            missing.append(esptool_req)
    except ImportError:
        missing.append(esptool_req)
    if missing:
        print("\033[93mInstalling missing packages: " + ", ".join(missing) + "\033[0m")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
        except subprocess.CalledProcessError as e:
            sys.stderr.write(
                "Automatic install failed (externally managed env?). "
                "Try a virtualenv:\n"
                "  python3 -m venv .venv && source .venv/bin/activate\n"
                "  pip install {}\n".format(" ".join(missing))
            )
            sys.exit(e.returncode)
        os.execv(sys.executable, [sys.executable] + sys.argv)

ensure_packages()
import colorama
import serial
import serial.tools.list_ports
# Older colorama versions may not have just_fix_windows_console
if hasattr(colorama, "just_fix_windows_console"):
    colorama.just_fix_windows_console()
else:
    colorama.init()

# Colors
RED = "\033[91m"; GREEN = "\033[92m"; YELLOW = "\033[93m"; CYAN = "\033[96m"; RESET = "\033[0m"

REQUIRED_FILES = ["bootloader.bin", "partition-table.bin", "projectZero.bin"]

# >>> DO NOT CHANGE: keep your original offsets <<<
OFFSETS = {
    "bootloader.bin": "0x2000",       # as requested
    "partition-table.bin": "0x8000",
    "projectZero.bin": "0x10000",
}

def check_files():
    missing = [f for f in REQUIRED_FILES if not os.path.exists(f)]
    if missing:
        print("{}Missing files: {}{}".format(RED, ", ".join(missing), RESET))
        sys.exit(1)
    print("{}All required files found.{}".format(GREEN, RESET))

def list_ports():
    return set(p.device for p in serial.tools.list_ports.comports())

def wait_for_new_port(before, timeout=20.0):
    print("{}Hold BOOT and connect the board to enter ROM mode.{}".format(CYAN, RESET))
    spinner = ['|','/','-','\\']
    print("{}Waiting for new serial port...{}".format(YELLOW, RESET))
    t0 = time.time()
    i = 0
    while time.time() - t0 < timeout:
        after = list_ports()
        new_ports = after - before
        sys.stdout.write("\r{} ".format(spinner[i % len(spinner)])); sys.stdout.flush()
        i += 1
        if new_ports:
            sys.stdout.write("\r"); sys.stdout.flush()
            return new_ports.pop()
        time.sleep(0.15)
    print("\n{}No new serial port detected.{}".format(RED, RESET))
    sys.exit(1)

def erase_all(port, baud):
    cmd = [sys.executable, "-m", "esptool", "-p", port, "-b", str(baud),
           "--before", "default-reset", "--after", "no_reset", "--chip", "esp32c5",
           "erase_flash"]
    print("{}Erasing full flash:{} {}".format(CYAN, RESET, " ".join(cmd)))
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print("{}Erase failed with code {}.{}".format(RED, res.returncode, RESET))
        sys.exit(res.returncode)

def do_flash(port, baud, flash_mode, flash_freq):
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
    print("{}Flashing command:{} {}".format(CYAN, RESET, " ".join(cmd)))
    res = subprocess.run(cmd)
    if res.returncode != 0:
        print("{}Flash failed with code {}.{}".format(RED, res.returncode, RESET))
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
    print("{}Issuing post-flash reset (RTS/DTR) to run app...{}".format(YELLOW, RESET))
    try:
        with serial.Serial(port, 115200, timeout=0.1) as ser:
            # Make sure BOOT is released
            pulse(ser, dtr=False, rts=None)
            # Short EN reset
            pulse(ser, rts=True)
            pulse(ser, rts=False)
        print("{}Reset sent. If not Press the board's RESET button manually.{}".format(GREEN, RESET))
        
    except Exception as e:
        print("{}RTS/DTR reset failed: {}{}".format(RED, e, RESET))
        print("{}Press the board's RESET button manually.{}".format(YELLOW, RESET))

def monitor(port, baud=115200):
    print("{}Opening serial monitor on {} @ {} (Ctrl+C to exit)...{}".format(CYAN, port, baud, RESET))
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
        print("{}Monitor failed: {}{}".format(RED, e, RESET))

def main():
    parser = argparse.ArgumentParser(description="ESP32-C5 flasher with robust reboot handling")
    parser.add_argument("--version", action="version", version="%(prog)s {}".format(VERSION))
    parser.add_argument("--port", help="Known serial port (e.g., COM10 or /dev/ttyACM0)")
    parser.add_argument("--baud", type=int, default=460800)
    parser.add_argument("--monitor", action="store_true", help="Open serial monitor after flashing")
    parser.add_argument("--erase", action="store_true", help="Full erase before flashing (fixes stale NVS/partitions)")
    parser.add_argument("--flash-mode", default="dio", choices=["dio", "qio", "dout", "qout"],
                        help="Flash mode (default: dio)")
    parser.add_argument("--flash-freq", default="80m", choices=["80m", "60m", "40m", "26m", "20m"],
                        help="Flash frequency (default: 80m). If you see boot loops, try 40m.")
    args = parser.parse_args()

    check_files()

    if args.port:
        port = args.port
    else:
        before = list_ports()
        port = wait_for_new_port(before)

    print("{}Detected serial port: {}{}".format(GREEN, port, RESET))
    print("{}Tip: release the BOOT button before programming finishes.{}".format(YELLOW, RESET))

    if args.erase:
        erase_all(port, args.baud)

    do_flash(port, args.baud, args.flash_mode, args.flash_freq)

    reset_to_app(port)

    if args.monitor:
        monitor(port, 115200)

if __name__ == "__main__":
    main()
