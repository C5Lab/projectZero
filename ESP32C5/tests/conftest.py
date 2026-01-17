import json
import os
import re
import time
from pathlib import Path

import pytest
import serial
from serial.tools import list_ports


THIS_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = THIS_DIR / "config" / "devices.json"
REQUIRED_BASE_FILES = ["bootloader.bin", "partition-table.bin", "projectZero.bin"]
REQUIRED_TARGET_FILES = ["bootloader.bin", "partition-table.bin", "projectZero.bin"]
RESULTS_DIR = Path(os.environ.get("ESP32C5_RESULTS_DIR", THIS_DIR / "results"))
PROMPT = ">"


def _normalize_hex(value):
    if value is None:
        return None
    return str(value).lower().replace("0x", "").zfill(4)


def _load_devices_config():
    config_path = Path(os.environ.get("ESP32C5_DEVICES_CONFIG", DEFAULT_CONFIG))
    if not config_path.exists():
        pytest.fail(f"Devices config not found: {config_path}")
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        pytest.fail(f"Invalid devices config JSON: {config_path} ({exc})")


def _match_port(port_info, spec):
    if not spec:
        return False
    port_override = spec.get("port")
    if port_override:
        return port_info.device == port_override

    vid = _normalize_hex(spec.get("vid"))
    pid = _normalize_hex(spec.get("pid"))
    serial = spec.get("serial")

    port_vid = _normalize_hex(port_info.vid) if port_info.vid is not None else None
    port_pid = _normalize_hex(port_info.pid) if port_info.pid is not None else None
    port_serial = port_info.serial_number

    if vid and port_vid != vid:
        return False
    if pid and port_pid != pid:
        return False
    if serial and port_serial != serial:
        return False
    return True


def _find_matching_ports(spec):
    matches = []
    for port in list_ports.comports():
        if _match_port(port, spec):
            matches.append(port.device)
    return matches


@pytest.fixture(scope="session")
def devices_config():
    return _load_devices_config()


@pytest.fixture(scope="session")
def settings_config(devices_config):
    return devices_config.get("settings", {})


def _write_line(config, message):
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter:
        reporter.write_line(message)
    else:
        print(message)


def _resolve_base_dir():
    return Path(os.environ.get("ESP32C5_BASE_SW_DIR", THIS_DIR / "SW"))


def _resolve_target_dir():
    return Path(os.environ.get("ESP32C5_TARGET_SW_DIR", THIS_DIR.parent / "binaries-esp32c5"))


def _check_base_files(base_dir):
    missing = [str(base_dir / name) for name in REQUIRED_BASE_FILES if not (base_dir / name).exists()]
    if missing:
        pytest.exit("Missing base firmware files: " + ", ".join(missing))


def _check_target_files(target_dir):
    missing = [str(target_dir / name) for name in REQUIRED_TARGET_FILES if not (target_dir / name).exists()]
    if missing:
        pytest.exit("Missing target firmware files: " + ", ".join(missing))


def _read_until_marker(ser, marker, timeout):
    end = time.time() + timeout
    buffer = ""
    while time.time() < end:
        chunk = ser.read(1024)
        if chunk:
            buffer += chunk.decode(errors="replace")
            if marker in buffer:
                break
        else:
            time.sleep(0.05)
    return buffer


def _capture_ota_info(port, settings):
    baud = int(settings.get("uart_baud", 115200))
    ready_marker = settings.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings.get("ready_timeout", 20))
    response_timeout = float(settings.get("ota_info_timeout", 6))
    command = settings.get("ota_info_cmd", "ota_info")

    with serial.Serial(port, baud, timeout=0.2) as ser:
        ser.reset_input_buffer()
        if ready_marker:
            _read_until_marker(ser, ready_marker, ready_timeout)
        ser.write((command + "\n").encode("ascii"))
        ser.flush()
        output = _read_until_marker(ser, PROMPT, response_timeout)

    return output


def _write_results_files(output, config):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    ota_path = RESULTS_DIR / "ota_info.txt"
    ota_path.write_text(output, encoding="utf-8")

    build_match = re.search(r"ver=([^\s]+)\s+build=([^\r\n]+)", output)
    if build_match:
        version = build_match.group(1)
        build = build_match.group(2).strip()
        meta_path = RESULTS_DIR / "metadata.txt"
        meta_path.write_text(f"version={version}\nbuild={build}\n", encoding="utf-8")
        _write_line(config, f"Preflight: build version: {version}")
        _write_line(config, f"Preflight: build time: {build}")
    else:
        _write_line(config, "Preflight: ota_info build line not found")


def write_results_file(name, content):
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / name
    path.write_text(content, encoding="utf-8")


def pytest_sessionstart(session):
    config = session.config
    devices_config = _load_devices_config()
    settings = devices_config.get("settings", {})
    spec = devices_config.get("devices", {}).get("dut")
    if not spec:
        pytest.exit("Missing 'dut' device in devices config.")

    env_port = os.environ.get("ESP32C5_DUT_PORT")
    matches = _find_matching_ports(spec)
    if env_port:
        port = env_port
    elif len(matches) == 1:
        port = matches[0]
    elif not matches:
        pytest.exit("No matching DUT found. Check USB connection and devices config.")
    else:
        pytest.exit(f"Multiple DUT ports matched: {matches}. Use ESP32C5_DUT_PORT.")

    base_dir = _resolve_base_dir()
    target_dir = _resolve_target_dir()
    _check_base_files(base_dir)
    _check_target_files(target_dir)

    _write_line(config, f"Preflight: DUT port: {port}")
    _write_line(config, f"Preflight: base dir: {base_dir}")
    _write_line(config, f"Preflight: target dir: {target_dir}")
    _write_line(config, f"Preflight: flash baud: {settings.get('flash_baud', 460800)}")
    _write_line(config, f"Preflight: uart baud: {settings.get('uart_baud', 115200)}")

    try:
        output = _capture_ota_info(port, settings)
        _write_results_files(output, config)
    except Exception as exc:
        _write_line(config, f"Preflight: ota_info capture failed: {exc}")


def pytest_configure(config):
    if not hasattr(config, "_scan_summaries"):
        config._scan_summaries = []


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    summaries = getattr(config, "_scan_summaries", [])
    if summaries:
        terminalreporter.write_line("Scan summaries:")
        for line in summaries:
            terminalreporter.write_line(line)

    stats = terminalreporter.stats or {}
    suite_totals = {}

    def _suite_from_nodeid(nodeid):
        path = nodeid.split("::", 1)[0]
        parts = Path(path).parts
        if "flash" in parts:
            return "flash"
        if "scan" in parts:
            return "scan"
        if "system" in parts:
            return "system"
        return "other"

    for outcome, reports in stats.items():
        if outcome not in {"passed", "failed", "skipped"}:
            continue
        for report in reports:
            suite = _suite_from_nodeid(report.nodeid)
            suite_totals.setdefault(suite, {"passed": 0, "failed": 0, "skipped": 0})
            suite_totals[suite][outcome] += 1

    if suite_totals:
        terminalreporter.write_line("Suite summary:")
        for suite in sorted(suite_totals.keys()):
            totals = suite_totals[suite]
            terminalreporter.write_line(
                f"{suite}: {totals['passed']} passed, {totals['failed']} failed, {totals['skipped']} skipped"
            )

@pytest.fixture(scope="session")
def dut_port(devices_config):
    env_port = os.environ.get("ESP32C5_DUT_PORT")
    if env_port:
        return env_port

    spec = devices_config.get("devices", {}).get("dut")
    if not spec:
        pytest.fail("Missing 'dut' device in devices config.")

    matches = _find_matching_ports(spec)
    if not matches:
        pytest.fail(
            "No matching DUT found. Check USB connection and devices config."
        )
    if len(matches) > 1:
        pytest.fail(
            f"Multiple DUT ports matched: {matches}. "
            "Specify ESP32C5_DUT_PORT or tighten devices config."
        )
    return matches[0]
