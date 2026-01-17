import json
import os
from pathlib import Path

import pytest
from serial.tools import list_ports


THIS_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = THIS_DIR / "config" / "devices.json"


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
