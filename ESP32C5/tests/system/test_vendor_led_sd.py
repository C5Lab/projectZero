import random
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


@pytest.mark.mandatory
@pytest.mark.system
def test_vendor_read(dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        output = _send_and_read(ser, "vendor read", 4.0)
        if "Vendor scan: off" in output:
            output = _send_and_read(ser, "vendor set on", 6.0)
        output = _send_and_read(ser, "vendor read", 4.0)

    assert "Vendor scan: on" in output, f"Vendor not enabled.\n{output}"
    assert "Vendor file: available" in output, f"Vendor file not available.\n{output}"


@pytest.mark.mandatory
@pytest.mark.system
def test_led_set_and_read(dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        on_out = _send_and_read(ser, "led set on", 4.0)
        read_on = _send_and_read(ser, "led read", 4.0)
        level = random.randint(1, 5)
        level_out = _send_and_read(ser, f"led level {level}", 4.0)
        read_level = _send_and_read(ser, "led read", 4.0)
        off_out = _send_and_read(ser, "led set off", 4.0)
        read_off = _send_and_read(ser, "led read", 4.0)

    assert "LED turned on" in on_out, f"LED did not turn on.\n{on_out}"
    assert "LED status: on" in read_on, f"LED read not on.\n{read_on}"
    assert "LED brightness set to" in level_out, f"LED level not set.\n{level_out}"
    assert f"brightness {level}%" in read_level, f"LED level not reflected.\n{read_level}"
    assert "LED turned off" in off_out, f"LED did not turn off.\n{off_out}"
    assert "LED status: off" in read_off, f"LED read not off.\n{read_off}"


@pytest.mark.mandatory
@pytest.mark.system
def test_list_sd(dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        output = _send_and_read(ser, "list_sd", 6.0)

    assert "Failed to initialize SD card" not in output, f"SD init failed.\n{output}"
    assert (
        "No HTML files found on SD card." in output
        or "HTML files found on SD card:" in output
    ), f"Unexpected list_sd output.\n{output}"


@pytest.mark.mandatory
@pytest.mark.system
def test_select_html(dut_port, settings_config):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        output = _send_and_read(ser, "list_sd", 6.0)

        if "No HTML files found on SD card." in output:
            pytest.skip("No HTML files on SD card.")

        index = None
        for line in output.splitlines():
            line = line.strip()
            if line and line[0].isdigit():
                parts = line.split(maxsplit=1)
                if parts:
                    index = parts[0]
                    break

        assert index, f"Could not find HTML index.\n{output}"

        select_out = _send_and_read(ser, f"select_html {index}", 6.0)

    assert "Loaded HTML file:" in select_out, f"select_html failed.\n{select_out}"
    assert "Portal will now use this custom HTML." in select_out, f"Missing portal update.\n{select_out}"


@pytest.mark.mandatory
@pytest.mark.system
def test_vendor_persistence(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _send_and_read(ser, "vendor set on", 6.0)
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        output = _send_and_read(ser, "vendor read", 6.0)

    cli_log("vendor_persistence.txt", output)
    assert "Vendor scan: on" in output, f"Vendor not persisted.\n{output}"
    assert "Vendor file: available" in output, f"Vendor file not available.\n{output}"

