import re
import time

import pytest
import serial


RESULT_MARKER = "Scan results printed."


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


def _report(pytestconfig, message):
    reporter = pytestconfig.pluginmanager.get_plugin("terminalreporter")
    if reporter:
        reporter.write_line(message)
    else:
        print(message)


@pytest.mark.mandatory
@pytest.mark.scan
def test_wifi_scan(dut_port, settings_config, pytestconfig):
    baud = int(settings_config.get("uart_baud", 115200))
    command = settings_config.get("scan_cmd", "scan_networks")
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    scan_timeout = float(settings_config.get("scan_timeout", 60))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        ser.reset_input_buffer()
        _wait_for_ready(ser, ready_marker, ready_timeout)
        ser.write((command + "\n").encode("ascii"))
        ser.flush()
        output = _read_until_marker(ser, RESULT_MARKER, scan_timeout)

    found_match = re.search(r"Found\s+(\d+)\s+networks", output)
    retrieved_match = re.search(r"Retrieved\s+(\d+)\s+network records in\s+([0-9.]+)s", output)

    assert found_match, f"Missing scan summary.\n{output}"
    assert retrieved_match, f"Missing retrieval summary.\n{output}"

    found_count = int(found_match.group(1))
    retrieved_count = int(retrieved_match.group(1))
    retrieved_time = retrieved_match.group(2)

    _report(pytestconfig, f"Scan summary: Found {found_count} networks")
    _report(pytestconfig, f"Retrieved {retrieved_count} network records in {retrieved_time}s")

    assert found_count >= 1, f"Found count < 1.\n{output}"
    assert retrieved_count >= 1, f"Retrieved count < 1.\n{output}"
