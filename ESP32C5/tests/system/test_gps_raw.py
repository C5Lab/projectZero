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


def _step(message):
    print(f"[gps] {message}", flush=True)


def _read_gps_lines(ser, duration):
    end = time.time() + duration
    lines = []
    while time.time() < end:
        line = ser.readline().decode(errors="replace").strip()
        if line:
            lines.append(line)
    return lines


@pytest.mark.mandatory
@pytest.mark.system
def test_gps_raw_mode_outputs_nmea(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    sample_seconds = float(settings_config.get("gps_raw_seconds", 6))
    module = settings_config.get("gps_raw_module", "m5")

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _step("gps_raw: wait for ready")
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _step("gps_raw: reboot")
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        _step(f"gps_raw: gps_set {module}")
        set_out = _send_and_read(ser, f"gps_set {module}", 4.0)
        _step("gps_raw: start_gps_raw")
        ser.write(b"start_gps_raw\n")
        ser.flush()
        header = _read_until_marker(ser, "GPS raw reader started", 4.0)
        lines = _read_gps_lines(ser, sample_seconds)
        _step("gps_raw: stop")
        stop_out = _send_and_read(ser, "stop", 6.0)

    output = "\n".join([set_out, header, *lines, stop_out])
    cli_log("gps_raw.txt", output)
    assert "GPS raw reader started" in output, f"Missing GPS raw start.\n{output}"
    assert any(re.search(r"\$GN|\$GP|\$BD", line) for line in lines), (
        f"No NMEA sentences detected in raw mode.\n{output}"
    )


@pytest.mark.mandatory
@pytest.mark.system
def test_gps_wrong_mode_is_quiet(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    sample_seconds = float(settings_config.get("gps_wrong_seconds", 6))
    wrong_module = settings_config.get("gps_wrong_module", "atgm")

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _step("gps_wrong: wait for ready")
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _step("gps_wrong: reboot")
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        _step(f"gps_wrong: gps_set {wrong_module}")
        set_out = _send_and_read(ser, f"gps_set {wrong_module}", 4.0)
        _step("gps_wrong: start_gps_raw")
        ser.write(b"start_gps_raw\n")
        ser.flush()
        header = _read_until_marker(ser, "GPS raw reader started", 4.0)
        lines = _read_gps_lines(ser, sample_seconds)
        _step("gps_wrong: stop")
        stop_out = _send_and_read(ser, "stop", 6.0)

    output = "\n".join([set_out, header, *lines, stop_out])
    cli_log("gps_wrong_module.txt", output)
    # Allow junk, but no valid NMEA sentences should appear for the wrong module.
    assert not any(re.search(r"\$GN|\$GP|\$BD", line) for line in lines), (
        f"Unexpected NMEA output in wrong module mode.\n{output}"
    )
