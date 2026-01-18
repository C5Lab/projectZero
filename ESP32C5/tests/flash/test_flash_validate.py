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


@pytest.mark.mandatory
@pytest.mark.flash
def test_flash_validate_ota_info(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    command = settings_config.get("ota_info_cmd", "ota_info")
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 15))
    response_timeout = float(settings_config.get("ota_info_timeout", 6))

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
    cli_log("ota_info.txt", output)
    assert has_legacy or has_new, f"Missing OTA info.\n{output}"
