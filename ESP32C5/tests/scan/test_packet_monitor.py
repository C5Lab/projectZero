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
    print(f"[scan] {message}", flush=True)


@pytest.mark.mandatory
@pytest.mark.scan
def test_packet_monitor_basic(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _step("packet_monitor: wait for ready")
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _step("packet_monitor: reboot")
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        ser.reset_input_buffer()
        _step("packet_monitor: start on channel 6")
        ser.write(b"packet_monitor 6\n")
        ser.flush()
        output = _read_until_marker(ser, PROMPT, 6.0)
        _step("packet_monitor: stop")
        stop_out = _send_and_read(ser, "stop", 6.0)

    cli_log("packet_monitor.txt", output + "\n" + stop_out)
    assert "Usage: packet_monitor" not in output, f"packet_monitor usage error.\n{output}"
    assert "Invalid channel" not in output, f"packet_monitor invalid channel.\n{output}"
    assert "All operations stopped." in stop_out, f"stop failed.\n{stop_out}"
