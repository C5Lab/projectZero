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
def test_list_probes_after_sniffer(dut_port, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    wait_seconds = float(settings_config.get("probes_wait_seconds", 12))
    min_entries = int(settings_config.get("probes_min_entries", 1))

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        ser.reset_input_buffer()
        ser.write(b"start_sniffer\n")
        ser.flush()
        time.sleep(wait_seconds)
        ser.write(b"stop\n")
        ser.flush()
        _read_until_marker(ser, "All operations stopped.", 6.0)

        ser.write(b"list_probes\n")
        ser.flush()
        output = _read_until_marker(ser, ">", 6.0)

    cli_log("list_probes.txt", output)
    if "No probe requests captured" in output:
        pytest.fail(f"No probes captured.\n{output}")

    count = 0
    for line in output.splitlines():
        line = line.strip()
        if line and line[0].isdigit():
            count += 1
    assert count >= min_entries, f"Probe entries below minimum ({min_entries}).\n{output}"
