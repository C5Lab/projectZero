import csv
import time

import pytest
import serial


RESULT_MARKER = "Scan results printed."
DUT_PROMPT = ">"


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


def _read_until_prompt(ser, prompt, timeout):
    return _read_until_marker(ser, prompt, timeout)


def _wait_for_ready(ser, marker, timeout):
    if not marker:
        return ""
    return _read_until_marker(ser, marker, timeout)


def _reboot_and_wait(ser, ready_marker, ready_timeout):
    ser.write(b"reboot\n")
    ser.flush()
    return _read_until_marker(ser, ready_marker, ready_timeout)


def _run_scan(ser, timeout):
    ser.reset_input_buffer()
    ser.write(b"scan_networks\r\n")
    ser.flush()
    return _read_until_marker(ser, RESULT_MARKER, timeout)


def _ensure_prompt(ser, prompt, timeout):
    ser.write(b"\n")
    ser.flush()
    return _read_until_prompt(ser, prompt, timeout)


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


def _client_send(ser, command, prompt, timeout):
    ser.reset_input_buffer()
    ser.write((command + "\n").encode("ascii"))
    ser.flush()
    return _read_until_prompt(ser, prompt, timeout)


@pytest.mark.mandatory
@pytest.mark.deauth
def test_deauth_disconnects_client(
    dut_port,
    client_janosmini_port,
    devices_config,
    settings_config,
    cli_log,
):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    scan_timeout = float(settings_config.get("scan_timeout", 60))

    client_prompt = settings_config.get("client_prompt", "JanOSmini>")
    disconnect_timeout = float(settings_config.get("client_disconnect_timeout", 20))
    reconnect_timeout = float(settings_config.get("client_reconnect_timeout", 20))

    target = devices_config.get("target_ap", {})
    ssid = target.get("ssid")
    password = target.get("password")
    bssid = target.get("bssid")
    if not ssid or not password or not bssid:
        pytest.fail("Missing target_ap.ssid/password/bssid in devices config.")

    with serial.Serial(client_janosmini_port, baud, timeout=0.2) as client_ser:
        _read_until_prompt(client_ser, client_prompt, 6.0)
        hold_out = _client_send(client_ser, "sta_hold on", client_prompt, 4.0)
        cli_log("deauth_client_hold.txt", hold_out)

        connect_out = _client_send(client_ser, f"sta_connect {ssid} {password}", client_prompt, 8.0)
        cli_log("deauth_client_connect.txt", connect_out)

        status_out = _client_send(client_ser, "sta_status", client_prompt, 6.0)
        cli_log("deauth_client_status.txt", status_out)
        assert "connected=1" in status_out, f"Client not connected.\n{status_out}"

        with serial.Serial(dut_port, baud, timeout=0.2) as dut_ser:
            _wait_for_ready(dut_ser, ready_marker, ready_timeout)
            reboot_out = _reboot_and_wait(dut_ser, ready_marker, ready_timeout)
            if ready_marker and ready_marker not in reboot_out:
                reboot_out += "\n\n--- no ready marker ---\n"
            prompt_out = _read_until_prompt(dut_ser, DUT_PROMPT, 6.0)
            if not prompt_out.strip():
                prompt_out = _ensure_prompt(dut_ser, DUT_PROMPT, 6.0)
            reboot_out += "\n\n--- prompt ---\n" + prompt_out
            cli_log("deauth_reboot.txt", reboot_out)

            scan_output = _run_scan(dut_ser, scan_timeout)
            if "Unrecognized command" in scan_output:
                _ensure_prompt(dut_ser, DUT_PROMPT, 4.0)
                scan_output = _run_scan(dut_ser, scan_timeout)
            if RESULT_MARKER not in scan_output:
                _ensure_prompt(dut_ser, DUT_PROMPT, 4.0)
                scan_output = _run_scan(dut_ser, scan_timeout)
            cli_log("deauth_scan.txt", scan_output)

            csv_lines = _extract_csv_lines(scan_output)
            assert csv_lines, f"No scan CSV lines found.\n{scan_output}"
            index = _select_target_index(csv_lines, ssid, bssid)
            assert index, f"Target AP not found in scan output (ssid={ssid} bssid={bssid}).\n{scan_output}"

            dut_ser.write(f"select_networks {index}\n".encode("ascii"))
            dut_ser.flush()
            select_out = _read_until_prompt(dut_ser, DUT_PROMPT, 6.0)
            cli_log("deauth_select.txt", select_out)
            assert "Selected Networks" in select_out, f"Missing selection output.\n{select_out}"

            dut_ser.write(b"start_deauth\n")
            dut_ser.flush()
            start_out = _read_until_prompt(dut_ser, DUT_PROMPT, 6.0)
            cli_log("deauth_start.txt", start_out)
            assert "Deauth attack started" in start_out, f"Missing deauth start.\n{start_out}"

        disconnect_out = _client_send(client_ser, f"wait_disconnect {int(disconnect_timeout)}", client_prompt, disconnect_timeout + 5)
        cli_log("deauth_client_disconnect.txt", disconnect_out)
        assert "DISCONNECTED" in disconnect_out, f"Client did not disconnect.\n{disconnect_out}"

        with serial.Serial(dut_port, baud, timeout=0.2) as dut_ser:
            dut_ser.write(b"stop\n")
            dut_ser.flush()
            stop_out = _read_until_prompt(dut_ser, DUT_PROMPT, 10.0)
            cli_log("deauth_stop.txt", stop_out)
            assert "All operations stopped" in stop_out, f"Missing stop confirmation.\n{stop_out}"

        time.sleep(2.0)
        status_after = _client_send(client_ser, "sta_status", client_prompt, reconnect_timeout + 5)
        cli_log("deauth_client_status_after.txt", status_after)
        assert "connected=1" in status_after, f"Client did not reconnect.\n{status_after}"
