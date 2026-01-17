import os
import re
import time

import pytest
import serial


SUMMARY_MARKER = "Summary:"
READY_MARKER_DEFAULT = "BOARD READY"


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


def _wait_for_ready(ser, marker, timeout):
    if not marker:
        return ""
    return _read_until_marker(ser, marker, timeout)


@pytest.mark.mandatory
@pytest.mark.ble
def test_scan_bt(dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", READY_MARKER_DEFAULT)
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    scan_timeout = float(settings_config.get("ble_scan_timeout", 20))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        ser.reset_input_buffer()
        ser.write(b"scan_bt\n")
        ser.flush()
        output = _read_until_marker(ser, "Summary:", scan_timeout + 5)

    assert "BLE scan starting" in output, f"Missing BLE scan start.\n{output}"
    assert "=== BLE Scan Results ===" in output, f"Missing BLE results header.\n{output}"
    assert "Found " in output, f"Missing BLE device count.\n{output}"

    summary_match = re.search(r"Summary:\s+(\d+)\s+AirTags,\s+(\d+)\s+SmartTags,\s+(\d+)\s+total devices", output)
    assert summary_match, f"Missing BLE summary line.\n{output}"

    total_devices = int(summary_match.group(3))
    assert total_devices >= 0, f"Invalid BLE device count.\n{output}"

    # Optional expected BT client from devices.json
    expected_mac = None
    expected_name = None
    try:
        import json
        from pathlib import Path
        config_path = Path(os.environ.get("ESP32C5_DEVICES_CONFIG", "/workspace/ESP32C5/tests/config/devices.json"))
        if config_path.exists():
            data = json.loads(config_path.read_text(encoding="utf-8"))
            clients = data.get("devices", {}).get("clients", [])
            for client in clients:
                if client.get("name") == "client_bt":
                    expected_mac = client.get("mac")
                    expected_name = client.get("name_hint")
                    break
    except Exception:
        pass

    if expected_mac:
        normalized = expected_mac.upper()
        assert normalized in output.upper(), f"Expected BT MAC {expected_mac} not found.\n{output}"
        if expected_name:
            assert expected_name in output, f"Expected BT name {expected_name} not found.\n{output}"


@pytest.mark.mandatory
@pytest.mark.ble
def test_scan_airtag(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", READY_MARKER_DEFAULT)
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    poll_count = int(settings_config.get("airtag_poll_count", 5))
    poll_timeout = float(settings_config.get("airtag_poll_timeout", 25))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        ser.reset_input_buffer()
        ser.write(b"scan_airtag\n")
        ser.flush()

        output = _read_until_marker(ser, "Use 'stop' command", 8.0)
        samples = []
        end = time.time() + poll_timeout
        while len(samples) < poll_count and time.time() < end:
            line = ser.readline().decode(errors="replace").strip()
            if re.match(r"^\d+,\d+$", line):
                samples.append(line)

        ser.write(b"stop\n")
        ser.flush()
        output += "\n" + _read_until_marker(ser, "All operations stopped.", 6.0)

    cli_log("scan_airtag.txt", output + "\n" + "\n".join(samples))
    assert samples, f"No AirTag samples received.\n{output}"
