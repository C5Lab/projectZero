import csv
import re
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


def _reboot_and_wait(ser, ready_marker, ready_timeout):
    ser.write(b"reboot\n")
    ser.flush()
    return _read_until_marker(ser, ready_marker, ready_timeout)


def _run_scan(ser, timeout):
    ser.reset_input_buffer()
    ser.write(b"scan_networks\n")
    ser.flush()
    return _read_until_marker(ser, RESULT_MARKER, timeout)


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


def _extract_saved_paths(output):
    pcap_match = re.search(r"PCAP saved:\s+(\S+\.pcap)", output)
    hccapx_match = re.search(r"HCCAPX saved:\s+(\S+\.hccapx)", output)
    pcap_path = pcap_match.group(1) if pcap_match else None
    hccapx_path = hccapx_match.group(1) if hccapx_match else None
    return pcap_path, hccapx_path


@pytest.mark.mandatory
@pytest.mark.handshake
def test_handshake_capture_selected(dut_port, client_janosmini_port, devices_config, settings_config, cli_log):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    scan_timeout = float(settings_config.get("scan_timeout", 60))
    handshake_timeout = float(settings_config.get("handshake_timeout", 180))
    client_prompt = settings_config.get("client_prompt", "JanOSmini>")
    disconnect_timeout = float(settings_config.get("client_disconnect_timeout", 20))
    reconnect_timeout = float(settings_config.get("client_reconnect_timeout", 20))

    target = devices_config.get("target_ap", {})
    ssid = target.get("ssid")
    bssid = target.get("bssid")
    password = target.get("password")
    if not ssid or not bssid or not password:
        pytest.fail("Missing target_ap.ssid/password/bssid in devices config.")

    with serial.Serial(client_janosmini_port, baud, timeout=0.2) as client_ser:
        client_ser.reset_input_buffer()
        client_ser.write(b"sta_hold on\n")
        client_ser.flush()
        hold_out = _read_until_prompt(client_ser, 4.0)
        cli_log("handshake_client_hold.txt", hold_out)

        client_ser.write(f"sta_connect {ssid} {password}\n".encode("ascii"))
        client_ser.flush()
        connect_out = _read_until_prompt(client_ser, 8.0)
        cli_log("handshake_client_connect.txt", connect_out)

        client_ser.write(b"sta_status\n")
        client_ser.flush()
        status_out = _read_until_prompt(client_ser, 6.0)
        cli_log("handshake_client_status.txt", status_out)
        assert "connected=1" in status_out, f"Client not connected.\n{status_out}"

    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        _reboot_and_wait(ser, ready_marker, ready_timeout)

        scan_output = _run_scan(ser, scan_timeout)
        cli_log("handshake_scan.txt", scan_output)
        csv_lines = _extract_csv_lines(scan_output)
        assert csv_lines, f"No scan CSV lines found.\n{scan_output}"

        index = _select_target_index(csv_lines, ssid, bssid)
        assert index, f"Target AP not found in scan output (ssid={ssid} bssid={bssid}).\n{scan_output}"

        ser.write(f"select_networks {index}\n".encode("ascii"))
        ser.flush()
        select_out = _read_until_prompt(ser, 6.0)
        cli_log("handshake_select.txt", select_out)
        assert "Selected Networks" in select_out, f"Missing selection output.\n{select_out}"
        assert ssid in select_out, f"Selected network does not include target SSID.\n{select_out}"

        ser.write(b"start_handshake\n")
        ser.flush()
        handshake_out = _read_until_marker(ser, "Handshake attack task finished.", handshake_timeout)
        if "Handshake attack task finished." not in handshake_out:
            ser.write(b"stop\n")
            ser.flush()
            stop_out = _read_until_prompt(ser, 8.0)
            handshake_out += "\n\n--- stop ---\n" + stop_out
        cli_log("handshake_start.txt", handshake_out)

    if "SAVE FAILED" in handshake_out:
        pytest.fail(f"Handshake save failed.\n{handshake_out}")

    success = (
        "HANDSHAKE IS COMPLETE AND VALID" in handshake_out
        or "Handshake #1 captured" in handshake_out
        or "All selected networks captured" in handshake_out
    )
    assert success, f"Handshake did not complete.\n{handshake_out}"

    with serial.Serial(client_janosmini_port, baud, timeout=0.2) as client_ser:
        client_ser.write(f"wait_disconnect {int(disconnect_timeout)}\n".encode("ascii"))
        client_ser.flush()
        disconnect_out = _read_until_prompt(client_ser, disconnect_timeout + 5)
        cli_log("handshake_client_disconnect.txt", disconnect_out)

        time.sleep(2.0)
        client_ser.write(b"sta_status\n")
        client_ser.flush()
        status_after = _read_until_prompt(client_ser, reconnect_timeout + 5)
        cli_log("handshake_client_status_after.txt", status_after)
        assert "connected=1" in status_after, f"Client did not reconnect.\n{status_after}"

    pcap_path, hccapx_path = _extract_saved_paths(handshake_out)
    if not pcap_path or not hccapx_path:
        pytest.fail(f"Missing saved handshake paths.\n{handshake_out}")

    dir_path = pcap_path.rsplit("/", 1)[0]
    with serial.Serial(dut_port, baud, timeout=0.2) as ser:
        _wait_for_ready(ser, ready_marker, ready_timeout)
        ser.write(f"list_dir {dir_path}\n".encode("ascii"))
        ser.flush()
        list_out = _read_until_prompt(ser, 8.0)

        delete_out = ""
        for path in (hccapx_path, pcap_path):
            ser.write(f"file_delete {path}\n".encode("ascii"))
            ser.flush()
            delete_out += _read_until_prompt(ser, 6.0)

        ser.write(f"list_dir {dir_path}\n".encode("ascii"))
        ser.flush()
        list_after = _read_until_prompt(ser, 8.0)

    cli_log("handshake_list_dir.txt", list_out + "\n\n--- after ---\n" + list_after)
    cli_log("handshake_delete.txt", delete_out)

    assert pcap_path.split("/")[-1] in list_out, f"PCAP not listed before delete.\n{list_out}"
    assert hccapx_path.split("/")[-1] in list_out, f"HCCAPX not listed before delete.\n{list_out}"
    assert pcap_path.split("/")[-1] not in list_after, f"PCAP still present after delete.\n{list_after}"
    assert hccapx_path.split("/")[-1] not in list_after, f"HCCAPX still present after delete.\n{list_after}"
