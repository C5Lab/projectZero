import csv
import time

import pytest
import serial


RESULT_MARKER = "Scan results printed."
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


def _read_until_prompt(ser, timeout):
    return _read_until_marker(ser, PROMPT, timeout)


def _extract_csv_lines(output):
    return [line.strip() for line in output.splitlines() if line.strip().startswith('"')]


def _select_target_index(csv_lines, target_ssid, target_bssid):
    target_bssid = target_bssid.lower() if target_bssid else ""
    by_ssid = None
    for line in csv_lines:
        row = next(csv.reader([line]))
        if len(row) < 4:
            continue
        index = row[0].strip()
        ssid = row[1].strip()
        bssid = row[3].strip().lower()
        if target_bssid and bssid == target_bssid:
            return index
        if ssid == target_ssid and not by_ssid:
            by_ssid = index
    return by_ssid


def _step(message):
    print(f"[deauth] {message}", flush=True)


@pytest.mark.mandatory
@pytest.mark.deauth
def test_unselect_networks_clears_selection(dut_port, devices_config, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    scan_timeout = float(settings_config.get("scan_timeout", 60))

    target = devices_config.get("target_ap", {})
    ssid = target.get("ssid")
    bssid = target.get("bssid")
    if not ssid or not bssid:
        pytest.fail("Missing target_ap.ssid/bssid in devices config.")

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _step("unselect_networks: wait for ready")
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _step("unselect_networks: reboot")
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        _step("unselect_networks: scan_networks")
        ser.write(b"scan_networks\n")
        ser.flush()
        scan_output = _read_until_marker(ser, RESULT_MARKER, scan_timeout)
        cli_log("unselect_networks_scan.txt", scan_output)

        csv_lines = _extract_csv_lines(scan_output)
        assert csv_lines, f"No scan CSV lines found.\n{scan_output}"
        index = _select_target_index(csv_lines, ssid, bssid)
        assert index, f"Target AP not found in scan output.\n{scan_output}"

        _step(f"unselect_networks: select_networks {index}")
        ser.write(f"select_networks {index}\n".encode("ascii"))
        ser.flush()
        select_out = _read_until_prompt(ser, 6.0)
        cli_log("unselect_networks_select.txt", select_out)
        assert "Selected Networks" in select_out, f"Missing selection output.\n{select_out}"

        _step("unselect_networks: unselect_networks")
        ser.write(b"unselect_networks\n")
        ser.flush()
        clear_out = _read_until_prompt(ser, 6.0)
        cli_log("unselect_networks_clear.txt", clear_out)
        assert "Network selection cleared" in clear_out, f"Selection not cleared.\n{clear_out}"


@pytest.mark.mandatory
@pytest.mark.deauth
def test_select_unselect_stations(dut_port, devices_config, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))

    mac = None
    for client in devices_config.get("devices", {}).get("clients", []):
        if client.get("mac"):
            mac = client["mac"]
            break
    mac = mac or "AA:BB:CC:DD:EE:FF"

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _step("select_stations: wait for ready")
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _step("select_stations: reboot")
        _reboot_and_wait(ser, ready_marker, ready_timeout)
        _step(f"select_stations: {mac}")
        ser.write(f"select_stations {mac}\n".encode("ascii"))
        ser.flush()
        select_out = _read_until_prompt(ser, 6.0)
        cli_log("select_stations.txt", select_out)
        assert "Added station" in select_out, f"Station not added.\n{select_out}"

        _step("unselect_stations")
        ser.write(b"unselect_stations\n")
        ser.flush()
        clear_out = _read_until_prompt(ser, 6.0)
        cli_log("unselect_stations.txt", clear_out)
        assert "Station selection cleared" in clear_out, f"Stations not cleared.\n{clear_out}"
