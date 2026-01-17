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
        output = _read_until_marker(ser, SUMMARY_MARKER, scan_timeout + 5)

    assert "BLE scan starting" in output, f"Missing BLE scan start.\n{output}"
    assert "=== BLE Scan Results ===" in output, f"Missing BLE results header.\n{output}"
    assert "Found " in output, f"Missing BLE device count.\n{output}"

    summary_match = re.search(r"Summary:\s+(\d+)\s+AirTags,\s+(\d+)\s+SmartTags,\s+(\d+)\s+total devices", output)
    assert summary_match, f"Missing BLE summary line.\n{output}"

    total_devices = int(summary_match.group(3))
    assert total_devices >= 0, f"Invalid BLE device count.\n{output}"
