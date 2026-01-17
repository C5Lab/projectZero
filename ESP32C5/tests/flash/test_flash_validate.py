import os
import time

import pytest
import serial


PROMPT = ">"


def _read_until_prompt(ser, timeout=6.0):
    end = time.time() + timeout
    buffer = ""
    while time.time() < end:
        chunk = ser.read(1024)
        if chunk:
            buffer += chunk.decode(errors="replace")
            if PROMPT in buffer:
                break
        else:
            time.sleep(0.05)
    return buffer


@pytest.mark.flash
def test_flash_validate_ota_info(dut_port):
    baud = int(os.environ.get("ESP32C5_UART_BAUD", "115200"))
    command = os.environ.get("ESP32C5_OTA_INFO_CMD", "ota_info")

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        ser.reset_input_buffer()
        ser.write((command + "\n").encode("ascii"))
        ser.flush()

        output = _read_until_prompt(ser)

    assert "OTA boot:" in output, f"Missing OTA boot info.\n{output}"
    assert "OTA running:" in output, f"Missing OTA running info.\n{output}"
    assert "OTA next:" in output, f"Missing OTA next info.\n{output}"
    assert "APP[0]:" in output, f"Missing APP[0] info.\n{output}"
