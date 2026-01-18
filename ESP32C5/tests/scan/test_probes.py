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


def _reboot_and_wait(ser, marker, timeout):
    ser.write(b"reboot\n")
    ser.flush()
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


def _step(message):
    print(f"[scan] {message}", flush=True)


@pytest.mark.mandatory
@pytest.mark.scan
def test_list_probes_after_sniffer(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    min_packets = int(settings_config.get("sniffer_min_packets", 200))
    wait_seconds = float(settings_config.get("sniffer_wait_seconds", 12))
    min_entries = int(settings_config.get("probes_min_entries", 1))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _step("probes: wait for ready")
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _step("probes: start_sniffer")
        last_count = _run_sniffer(ser, min_packets, wait_seconds)
        _step("probes: list_probes")
        output = _send_and_read(ser, "list_probes", 6.0)

    cli_log("list_probes.txt", output)
    assert last_count >= min_packets, f"Sniffer packets below minimum ({min_packets})."
    if "No probe requests captured" in output:
        pytest.fail(f"No probes captured.\n{output}")

    count = 0
    for line in output.splitlines():
        line = line.strip()
        if line and line[0].isdigit():
            count += 1
    assert count >= min_entries, f"Probe entries below minimum ({min_entries}).\n{output}"


@pytest.mark.mandatory
@pytest.mark.scan
def test_show_probes_vendor_after_sniffer(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    min_packets = int(settings_config.get("sniffer_min_packets", 200))
    wait_seconds = float(settings_config.get("sniffer_wait_seconds", 12))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _step("probes_vendor: wait for ready")
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _step("probes_vendor: vendor set on")
        _send_and_read(ser, "vendor set on", 6.0)
        _step("probes_vendor: start_sniffer")
        last_count = _run_sniffer(ser, min_packets, wait_seconds)
        _step("probes_vendor: show_probes_vendor")
        output = _send_and_read(ser, "show_probes_vendor", 6.0)

    cli_log("show_probes_vendor.txt", output)
    assert last_count >= min_packets, f"Sniffer packets below minimum ({min_packets})."
    if "No probe requests captured" in output:
        pytest.fail(f"No probes captured.\n{output}")

    formatted = [
        line for line in output.splitlines()
        if "(" in line and ")" in line and "[" in line and "]" in line
    ]
    assert formatted, f"No vendor-formatted probe lines found.\n{output}"


@pytest.mark.mandatory
@pytest.mark.scan
def test_list_probes_vendor_after_sniffer(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    min_packets = int(settings_config.get("sniffer_min_packets", 200))
    wait_seconds = float(settings_config.get("sniffer_wait_seconds", 12))
    min_entries = int(settings_config.get("probes_min_entries", 1))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _step("list_probes_vendor: wait for ready")
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _step("list_probes_vendor: vendor set on")
        _send_and_read(ser, "vendor set on", 6.0)
        _step("list_probes_vendor: start_sniffer")
        last_count = _run_sniffer(ser, min_packets, wait_seconds)
        _step("list_probes_vendor: list_probes_vendor")
        output = _send_and_read(ser, "list_probes_vendor", 6.0)

    cli_log("list_probes_vendor.txt", output)
    assert last_count >= min_packets, f"Sniffer packets below minimum ({min_packets})."
    if "No probe requests captured" in output:
        pytest.fail(f"No probes captured.\n{output}")

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    entries = [line for line in lines if line[0].isdigit() and "[" in line and "]" in line]
    assert entries, f"No vendor-formatted probe entries found.\n{output}"
    assert len(entries) >= min_entries, f"Probe entries below minimum ({min_entries}).\n{output}"


@pytest.mark.mandatory
@pytest.mark.scan
def test_show_probes_after_sniffer(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    min_packets = int(settings_config.get("sniffer_min_packets", 200))
    wait_seconds = float(settings_config.get("sniffer_wait_seconds", 12))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _step("show_probes: wait for ready")
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _step("show_probes: reboot")
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        _step("show_probes: start_sniffer")
        last_count = _run_sniffer(ser, min_packets, wait_seconds)
        _step("show_probes: show_probes")
        output = _send_and_read(ser, "show_probes", 6.0)

    cli_log("show_probes.txt", output)
    assert last_count >= min_packets, f"Sniffer packets below minimum ({min_packets})."
    assert "No probe requests captured" not in output, f"No probes captured.\n{output}"
    assert "(" in output and ")" in output, f"Probe lines missing MAC format.\n{output}"
