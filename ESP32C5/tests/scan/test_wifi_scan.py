import csv
import io
import re
import time

import pytest
import serial

from conftest import write_results_file

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


def _reboot_and_wait(ser, ready_marker, ready_timeout):
    ser.write(b"reboot\n")
    ser.flush()
    return _read_until_marker(ser, ready_marker, ready_timeout)


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


def _min_networks(settings_config):
    return int(settings_config.get("scan_min_networks", 10))


def _extract_csv_lines(output):
    return [line.strip() for line in output.splitlines() if line.strip().startswith('"')]


def _read_until_prompt(ser, timeout):
    return _read_until_marker(ser, PROMPT, timeout)


def _parse_first_int(output):
    match = re.search(r"(-?\d+)", output)
    return int(match.group(1)) if match else None


def _send_and_read(ser, command, timeout):
    ser.write((command + "\n").encode("ascii"))
    ser.flush()
    return _read_until_prompt(ser, timeout)


def _ensure_vendor_enabled(ser):
    output = _send_vendor_command(ser, "vendor set on")
    if "Vendor scan: on" not in output:
        pytest.fail(f"Vendor did not enable.\n{output}")
    if "Vendor file: available" not in output:
        pytest.fail(f"Vendor file not available.\n{output}")
    write_results_file("vendor.txt", output)


def _send_vendor_command(ser, command):
    ser.write((command + "\n").encode("ascii"))
    ser.flush()
    return _read_until_marker(ser, PROMPT, 6.0)


@pytest.fixture(scope="session")
def scan_once_result(dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    command = settings_config.get("scan_cmd", "scan_networks")
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    scan_timeout = float(settings_config.get("scan_timeout", 60))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        _ensure_vendor_enabled(ser)
        output, elapsed = _run_scan(ser, command, RESULT_MARKER, scan_timeout)

    summary = _parse_scan_summary(output)
    write_results_file("scan_networks.txt", output)
    return {
        "output": output,
        "elapsed": elapsed,
        "summary": summary,
        "csv_lines": _extract_csv_lines(output),
    }


@pytest.mark.mandatory
@pytest.mark.scan
def test_scan_networks_basic(scan_once_result, pytestconfig, settings_config):
    output = scan_once_result["output"]
    summary = scan_once_result["summary"]
    assert summary, f"Missing scan summary.\n{output}"
    found_count, retrieved_count, retrieved_time, status = summary
    min_networks = _min_networks(settings_config)
    assert found_count >= min_networks, f"Found count < {min_networks}.\n{output}"
    assert retrieved_count >= min_networks, f"Retrieved count < {min_networks}.\n{output}"
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
    repeat_count = int(settings_config.get("scan_repeat_count", 10))
    max_variation_pct = float(settings_config.get("scan_repeat_max_variation_pct", 25))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        results = []
        outputs = []
        for _ in range(repeat_count):
            _reboot_and_wait(ser, ready_marker, ready_timeout)
            output, _ = _run_scan(ser, command, RESULT_MARKER, scan_timeout)
            summary = _parse_scan_summary(output)
            assert summary, f"Missing scan summary.\n{output}"
            found_count, retrieved_count, _retrieved_time, status = summary
            assert found_count >= _min_networks(settings_config), f"Found count below minimum.\n{output}"
            assert retrieved_count >= _min_networks(settings_config), f"Retrieved count below minimum.\n{output}"
            assert status == 0, f"Scan status not zero.\n{output}"
            results.append(found_count)
            outputs.append(output)

    min_count = min(results)
    max_count = max(results)
    avg_count = sum(results) / len(results)
    variation_pct = ((max_count - min_count) / avg_count) * 100 if avg_count else 0.0
    assert variation_pct <= max_variation_pct, (
        f"Scan variation {variation_pct:.1f}% exceeds {max_variation_pct:.1f}%.\n"
        f"counts={results}"
    )


@pytest.mark.mandatory
@pytest.mark.scan
def test_show_scan_results_after_scan(scan_once_result, dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    response_timeout = float(settings_config.get("scan_timeout", 60))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        scan_output, _ = _run_scan(ser, "scan_networks", RESULT_MARKER, response_timeout)
        scan_summary = _parse_scan_summary(scan_output)
        assert scan_summary, f"Missing scan summary.\n{scan_output}"
        _found_count, retrieved_count, _retrieved_time, status = scan_summary
        assert status == 0, f"Scan status not zero.\n{scan_output}"

        ser.write(b"show_scan_results\n")
        ser.flush()
        output = _read_until_prompt(ser, response_timeout)
    write_results_file("show_scan_results.txt", output)

    csv_lines = _extract_csv_lines(output)
    assert csv_lines, f"No CSV scan results found.\n{output}"
    assert retrieved_count == len(csv_lines), (
        f"Retrieved count mismatch: scan={retrieved_count} show_scan_results={len(csv_lines)}"
    )


@pytest.mark.mandatory
@pytest.mark.scan
def test_scan_channel_time_defaults(dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    scan_timeout = float(settings_config.get("scan_timeout", 60))
    min_low = int(settings_config.get("scan_channel_min_low", 10))
    max_low = int(settings_config.get("scan_channel_max_low", 30))
    max_high = int(settings_config.get("scan_channel_max_high", 100))
    min_default = int(settings_config.get("scan_channel_min_default", 100))
    max_default = int(settings_config.get("scan_channel_max_default", 300))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        min_out = _send_and_read(ser, "channel_time read min", 4.0)
        max_out = _send_and_read(ser, "channel_time read max", 4.0)

        min_val = _parse_first_int(min_out)
        max_val = _parse_first_int(max_out)
        assert min_val is not None and min_val >= 1, f"Invalid min channel time.\n{min_out}"
        assert max_val is not None and max_val >= 1, f"Invalid max channel time.\n{max_out}"

        _send_and_read(ser, f"channel_time set min {min_low}", 4.0)
        _send_and_read(ser, f"channel_time set max {max_low}", 4.0)
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        low_output, _ = _run_scan(ser, "scan_networks", RESULT_MARKER, scan_timeout)
        low_summary = _parse_scan_summary(low_output)
        assert low_summary, f"Missing scan summary.\n{low_output}"
        low_count, _retrieved_count, _retrieved_time, status = low_summary
        assert status == 0, f"Scan status not zero.\n{low_output}"

        _send_and_read(ser, f"channel_time set max {max_high}", 4.0)
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        high_output, _ = _run_scan(ser, "scan_networks", RESULT_MARKER, scan_timeout)
        high_summary = _parse_scan_summary(high_output)
        assert high_summary, f"Missing scan summary.\n{high_output}"
        high_count, _retrieved_count, _retrieved_time, status = high_summary
        assert status == 0, f"Scan status not zero.\n{high_output}"
        assert high_count >= low_count, (
            f"Expected more or equal networks with higher max time. low={low_count} high={high_count}"
        )

        _send_and_read(ser, f"channel_time set max {max_default}", 4.0)
        _send_and_read(ser, f"channel_time set min {min_default}", 4.0)
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        default_output, _ = _run_scan(ser, "scan_networks", RESULT_MARKER, scan_timeout)
        assert f"Background scan started (min: {min_default} ms, max: {max_default} ms per channel)" in default_output, (
            f"Default channel_time not applied.\n{default_output}"
        )


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

    has_vendor = False
    for line in csv_lines:
        row = next(csv.reader(io.StringIO(line)))
        if len(row) >= 3 and row[2].strip():
            has_vendor = True
            break
    assert has_vendor, f"No vendor names found in scan output.\n{output}"


@pytest.mark.mandatory
@pytest.mark.scan
def test_vendor_toggle_affects_scan(dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    command = settings_config.get("scan_cmd", "scan_networks")
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    scan_timeout = float(settings_config.get("scan_timeout", 60))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)

        on_out = _send_vendor_command(ser, "vendor set on")
        assert "Vendor scan: on" in on_out, f"Vendor on failed.\n{on_out}"

        _reboot_and_wait(ser, ready_marker, ready_timeout)
        scan_on, _ = _run_scan(ser, command, RESULT_MARKER, scan_timeout)
        csv_lines_on = _extract_csv_lines(scan_on)
        has_vendor = False
        for line in csv_lines_on:
            row = next(csv.reader(io.StringIO(line)))
            if len(row) >= 3 and row[2].strip():
                has_vendor = True
                break
        assert has_vendor, f"No vendor names found with vendor on.\n{scan_on}"

        off_out = _send_vendor_command(ser, "vendor set off")
        assert "Vendor scan: off" in off_out, f"Vendor off failed.\n{off_out}"

        _reboot_and_wait(ser, ready_marker, ready_timeout)
        scan_off, _ = _run_scan(ser, command, RESULT_MARKER, scan_timeout)
        csv_lines_off = _extract_csv_lines(scan_off)
        has_vendor_off = False
        for line in csv_lines_off:
            row = next(csv.reader(io.StringIO(line)))
            if len(row) >= 3 and row[2].strip():
                has_vendor_off = True
                break
        assert not has_vendor_off, f"Vendor names present with vendor off.\n{scan_off}"
