import json
import os
import html
import re
import time
from pathlib import Path
from datetime import datetime
import zipfile

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


def _find_client_spec(devices_config, name):
    clients = devices_config.get("devices", {}).get("clients", [])
    for client in clients:
        if client.get("name") == name:
            return client
    return None


def _resolve_client_port(devices_config, name, env_var):
    env_port = os.environ.get(env_var)
    if env_port:
        return env_port

    spec = _find_client_spec(devices_config, name)
    if not spec:
        pytest.fail(f"Missing '{name}' in devices config.")

    matches = _find_matching_ports(spec)
    if not matches:
        pytest.fail(f"No matching {name} device found. Check USB connection and devices config.")
    if len(matches) > 1:
        pytest.fail(f"Multiple {name} ports matched: {matches}. Use {env_var}.")
    return matches[0]


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


@pytest.fixture
def cli_log(request):
    def _log(name, content):
        write_results_file(name, content)
        request.node.user_properties.append(("cli_log", (name, content)))
    return _log


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when != "call":
        return

    pytest_html = item.config.pluginmanager.get_plugin("html")
    if not pytest_html:
        return

    extras = getattr(report, "extras", [])
    for key, value in item.user_properties:
        if key == "cli_log":
            name, content = value
            escaped = html.escape(content)
            extras.append(pytest_html.extras.html(f"<h4>{name}</h4><pre>{escaped}</pre>"))
            report.sections.append((f"CLI log: {name}", content))
    report.extras = extras


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
    reporter = config.pluginmanager.get_plugin("terminalreporter")
    if reporter and not hasattr(config, "_raw_log_file"):
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        archive_dir = RESULTS_DIR / "archive"
        archive_dir.mkdir(parents=True, exist_ok=True)

        # Move old zip artifacts to archive and clean loose files
        for path in RESULTS_DIR.glob("results_*.zip"):
            try:
                path.replace(archive_dir / path.name)
            except OSError:
                pass
        for ext in ("*.txt", "*.html"):
            for path in RESULTS_DIR.glob(ext):
                try:
                    path.unlink()
                except OSError:
                    pass

        raw_path = RESULTS_DIR / "pytest_raw.txt"
        raw_file = raw_path.open("w", encoding="utf-8")
        config._raw_log_file = raw_file

        orig_write = reporter._tw.write
        orig_line = reporter._tw.line

        def write_proxy(s, **kwargs):
            raw_file.write(str(s))
            raw_file.flush()
            return orig_write(s, **kwargs)

        def line_proxy(s="", **kwargs):
            raw_file.write(str(s) + "\n")
            raw_file.flush()
            return orig_line(s, **kwargs)

        reporter._tw.write = write_proxy
        reporter._tw.line = line_proxy


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


@pytest.hookimpl(hookwrapper=True, trylast=True)
def pytest_sessionfinish(session, exitstatus):
    yield
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    meta_path = RESULTS_DIR / "metadata.txt"
    version = "unknown"
    build = "unknown"
    if meta_path.exists():
        meta = meta_path.read_text(encoding="utf-8")
        for line in meta.splitlines():
            if line.startswith("version="):
                version = line.split("=", 1)[1].strip() or version
            if line.startswith("build="):
                build = line.split("=", 1)[1].strip() or build

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_version = re.sub(r"[^A-Za-z0-9._-]+", "_", version)
    safe_build = re.sub(r"[^A-Za-z0-9._-]+", "_", build)
    zip_name = f"results_{timestamp}_{safe_version}_{safe_build}.zip"
    zip_path = RESULTS_DIR / zip_name

    files = []
    for ext in ("*.txt", "*.html"):
        files.extend(RESULTS_DIR.glob(ext))

    raw_file = getattr(session.config, "_raw_log_file", None)
    if raw_file:
        try:
            raw_file.close()
        except OSError:
            pass

    if files:
        with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for path in files:
                zf.write(path, arcname=path.name)
        for path in files:
            try:
                path.unlink()
            except OSError:
                pass

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


@pytest.fixture(scope="session")
def client_janosmini_port(devices_config):
    return _resolve_client_port(devices_config, "client_janosmini", "ESP32C5_CLIENT_JANOSMINI_PORT")
