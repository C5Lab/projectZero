import csv
import io
import re
import time

import pytest
import serial


RESULT_MARKER = "Scan results printed."
PROMPT = ">"


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


def _run_scan(ser, command, marker, timeout):
    ser.reset_input_buffer()
    ser.write((command + "\n").encode("ascii"))
    ser.flush()
    start = time.time()
    output = _read_until_marker(ser, marker, timeout)
    elapsed = time.time() - start
    return output, elapsed


def _parse_scan_summary(output):
    found_match = re.search(r"Found\s+(\d+)\s+networks", output)
    retrieved_match = re.search(r"Retrieved\s+(\d+)\s+network records in\s+([0-9.]+)s", output)
    status_match = re.search(r"status:\s*(-?\d+)", output)
    if not found_match or not retrieved_match:
        return None
    found_count = int(found_match.group(1))
    retrieved_count = int(retrieved_match.group(1))
    retrieved_time = float(retrieved_match.group(2))
    status = int(status_match.group(1)) if status_match else None
    return found_count, retrieved_count, retrieved_time, status


def _extract_csv_lines(output):
    return [line.strip() for line in output.splitlines() if line.strip().startswith('"')]


def _read_until_prompt(ser, timeout):
    return _read_until_marker(ser, PROMPT, timeout)


def _parse_first_int(output):
    match = re.search(r"(-?\d+)", output)
    return int(match.group(1)) if match else None


@pytest.fixture(scope="session")
def scan_once_result(dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    command = settings_config.get("scan_cmd", "scan_networks")
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    scan_timeout = float(settings_config.get("scan_timeout", 60))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        output, elapsed = _run_scan(ser, command, RESULT_MARKER, scan_timeout)

    summary = _parse_scan_summary(output)
    return {
        "output": output,
        "elapsed": elapsed,
        "summary": summary,
        "csv_lines": _extract_csv_lines(output),
    }


@pytest.mark.mandatory
@pytest.mark.scan
def test_scan_networks_basic(scan_once_result, pytestconfig):
    output = scan_once_result["output"]
    summary = scan_once_result["summary"]
    assert summary, f"Missing scan summary.\n{output}"
    found_count, retrieved_count, retrieved_time, status = summary
    assert found_count >= 1, f"Found count < 1.\n{output}"
    assert retrieved_count >= 1, f"Retrieved count < 1.\n{output}"
    assert status == 0, f"Scan status not zero.\n{output}"

    summaries = getattr(pytestconfig, "_scan_summaries", [])
    summaries.append(f"Found {found_count} networks")
    summaries.append(f"Retrieved {retrieved_count} network records in {retrieved_time:.1f}s")
    pytestconfig._scan_summaries = summaries


@pytest.mark.mandatory
@pytest.mark.scan
def test_scan_networks_repeatability(dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    command = settings_config.get("scan_cmd", "scan_networks")
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    scan_timeout = float(settings_config.get("scan_timeout", 60))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        first_output, _ = _run_scan(ser, command, RESULT_MARKER, scan_timeout)
        second_output, _ = _run_scan(ser, command, RESULT_MARKER, scan_timeout)

    first_summary = _parse_scan_summary(first_output)
    second_summary = _parse_scan_summary(second_output)
    assert first_summary and second_summary, "Missing scan summaries for repeatability."
    for summary, output in [(first_summary, first_output), (second_summary, second_output)]:
        found_count, retrieved_count, _retrieved_time, status = summary
        assert found_count >= 1, f"Found count < 1.\n{output}"
        assert retrieved_count >= 1, f"Retrieved count < 1.\n{output}"
        assert status == 0, f"Scan status not zero.\n{output}"


@pytest.mark.mandatory
@pytest.mark.scan
def test_show_scan_results_after_scan(scan_once_result, dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    response_timeout = float(settings_config.get("scan_timeout", 60))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        ser.write(b"show_scan_results\n")
        ser.flush()
        output = _read_until_prompt(ser, response_timeout)

    csv_lines = _extract_csv_lines(output)
    assert csv_lines, f"No CSV scan results found.\n{output}"


@pytest.mark.mandatory
@pytest.mark.scan
def test_scan_channel_time_defaults(dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        ser.write(b"channel_time read min\n")
        ser.flush()
        min_out = _read_until_prompt(ser, 4.0)
        ser.write(b"channel_time read max\n")
        ser.flush()
        max_out = _read_until_prompt(ser, 4.0)

    min_val = _parse_first_int(min_out)
    max_val = _parse_first_int(max_out)
    assert min_val is not None and min_val >= 1, f"Invalid min channel time.\n{min_out}"
    assert max_val is not None and max_val >= 1, f"Invalid max channel time.\n{max_out}"


@pytest.mark.mandatory
@pytest.mark.scan
def test_scan_networks_timeout_guard(scan_once_result, settings_config):
    scan_timeout = float(settings_config.get("scan_timeout", 60))
    elapsed = scan_once_result["elapsed"]
    assert elapsed <= scan_timeout + 5, f"Scan took too long: {elapsed:.1f}s"


@pytest.mark.mandatory
@pytest.mark.scan
def test_scan_networks_output_fields(scan_once_result):
    output = scan_once_result["output"]
    csv_lines = scan_once_result["csv_lines"]
    assert csv_lines, f"No CSV lines found.\n{output}"

    for line in csv_lines[:3]:
        row = next(csv.reader(io.StringIO(line)))
        assert len(row) == 8, f"Unexpected CSV field count ({len(row)}).\n{line}"
