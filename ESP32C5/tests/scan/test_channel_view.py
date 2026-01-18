import time

import pytest
import serial


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
@pytest.mark.scan
def test_channel_view(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    timeout = float(settings_config.get("channel_view_timeout", 20))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        ser.reset_input_buffer()
        ser.write(b"channel_view\n")
        ser.flush()

        output = _read_until_marker(ser, "channel_view_end", timeout)
        ser.write(b"stop\n")
        ser.flush()
        output += "\n" + _read_until_marker(ser, "All operations stopped.", 6.0)

    cli_log("channel_view.txt", output)
    assert "channel_view_start" in output, f"Missing channel_view_start.\n{output}"
    assert "channel_view_end" in output, f"Missing channel_view_end.\n{output}"
    assert "channel_view_error:timeout" not in output, f"channel_view timeout.\n{output}"
    assert "ch6:" in output, f"Missing 2.4GHz channel 6.\n{output}"
    assert "ch36:" in output, f"Missing 5GHz channel 36.\n{output}"
