import os
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


@pytest.mark.flash
def test_flash_validate_ota_info(dut_port):
    baud = int(os.environ.get("ESP32C5_UART_BAUD", "115200"))
    command = os.environ.get("ESP32C5_OTA_INFO_CMD", "ota_info")
    ready_marker = os.environ.get("ESP32C5_READY_MARKER", "BOARD READY")
    ready_timeout = float(os.environ.get("ESP32C5_READY_TIMEOUT", "15"))
    response_timeout = float(os.environ.get("ESP32C5_OTA_INFO_TIMEOUT", "6"))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        ser.reset_input_buffer()
        _wait_for_ready(ser, ready_marker, ready_timeout)
        ser.write((command + "\n").encode("ascii"))
        ser.flush()

        output = _read_until_marker(ser, PROMPT, response_timeout)

    has_legacy = "OTA boot:" in output and "OTA running:" in output and "OTA next:" in output
    has_new = (
        "OTA: boot partition=" in output
        and "OTA: running partition=" in output
        and "OTA: next update partition=" in output
    )
    assert has_legacy or has_new, f"Missing OTA info.\n{output}"
