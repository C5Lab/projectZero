import re
import time

import pytest
import serial


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


def _send_and_read(ser, command, timeout):
    ser.write((command + "\n").encode("ascii"))
    ser.flush()
    return _read_until_marker(ser, PROMPT, timeout)


def _wait_for_packet_count(ser, min_packets, timeout):
    deadline = None if timeout <= 0 else (time.time() + timeout)
    buffer = ""
    last_count = 0
    while True:
        chunk = ser.read(1024)
        if chunk:
            buffer += chunk.decode(errors="replace")
            for match in re.finditer(r"Sniffer packet count:\s*(\d+)", buffer):
                last_count = int(match.group(1))
                if last_count >= min_packets:
                    return last_count, buffer
            if len(buffer) > 8192:
                buffer = buffer[-4096:]
        else:
            time.sleep(0.05)
        if deadline is not None and time.time() >= deadline:
            return last_count, buffer


def _run_sniffer(ser, min_packets, timeout):
    ser.reset_input_buffer()
    ser.write(b"start_sniffer\n")
    ser.flush()
    last_count, _ = _wait_for_packet_count(ser, min_packets, timeout)
    ser.write(b"stop\n")
    ser.flush()
    _read_until_marker(ser, "All operations stopped.", 6.0)
    return last_count


@pytest.mark.mandatory
@pytest.mark.scan
def test_show_sniffer_results_and_clear(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    min_packets = int(settings_config.get("sniffer_min_packets", 200))
    wait_seconds = float(settings_config.get("sniffer_wait_seconds", 12))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        last_count = _run_sniffer(ser, min_packets, wait_seconds)
        show_out = _send_and_read(ser, "show_sniffer_results", 8.0)
        clear_out = _send_and_read(ser, "clear_sniffer_results", 6.0)
        show_after = _send_and_read(ser, "show_sniffer_results", 6.0)

    cli_log("show_sniffer_results.txt", show_out)
    cli_log("clear_sniffer_results.txt", clear_out + "\n" + show_after)

    assert last_count >= min_packets, f"Sniffer packets below minimum ({min_packets})."
    assert "No sniffer data available" not in show_out, f"No sniffer data captured.\n{show_out}"
    assert "Sniffer results cleared." in clear_out, f"Clear sniffer failed.\n{clear_out}"
    assert "No sniffer data available" in show_after, f"Sniffer results not cleared.\n{show_after}"


@pytest.mark.mandatory
@pytest.mark.scan
def test_show_sniffer_results_vendor(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    min_packets = int(settings_config.get("sniffer_min_packets", 600))
    wait_seconds = float(settings_config.get("sniffer_wait_seconds", 0))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _send_and_read(ser, "vendor set on", 6.0)
        last_count = _run_sniffer(ser, min_packets, wait_seconds)
        show_out = _send_and_read(ser, "show_sniffer_results_vendor", 8.0)

    cli_log("show_sniffer_results_vendor.txt", show_out)
    assert last_count >= min_packets, f"Sniffer packets below minimum ({min_packets})."
    assert "[" in show_out and "]" in show_out, f"Missing vendor info in sniffer results.\n{show_out}"


@pytest.mark.mandatory
@pytest.mark.scan
def test_sniffer_debug_toggle(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        on_out = _send_and_read(ser, "sniffer_debug 1", 4.0)
        off_out = _send_and_read(ser, "sniffer_debug 0", 4.0)

    cli_log("sniffer_debug.txt", on_out + "\n" + off_out)
    assert "Sniffer debug mode ENABLED" in on_out, f"sniffer_debug enable failed.\n{on_out}"
    assert "Sniffer debug mode DISABLED" in off_out, f"sniffer_debug disable failed.\n{off_out}"


@pytest.mark.mandatory
@pytest.mark.scan
def test_start_sniffer_noscan(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        start_out = _send_and_read(ser, "start_sniffer_noscan", 6.0)
        stop_out = _send_and_read(ser, "stop", 6.0)

    cli_log("sniffer_noscan.txt", start_out + "\n" + stop_out)
    assert "Sniffer: Now monitoring" in start_out, f"start_sniffer_noscan failed.\n{start_out}"
    assert "All operations stopped." in stop_out, f"stop failed.\n{stop_out}"
