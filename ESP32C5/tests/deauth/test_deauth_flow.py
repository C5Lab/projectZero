import csv
import time
import re

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
    output = ""
    for _ in range(2):
        ser.reset_input_buffer()
        ser.write(b"scan_networks\n")
        ser.flush()
        chunk = _read_until_marker(ser, RESULT_MARKER, timeout)
        output += chunk
        if RESULT_MARKER in chunk:
            break
        if "Unrecognized command" in chunk:
            output += _ensure_prompt(ser, DUT_PROMPT, 4.0, attempts=1)
        time.sleep(0.5)
    return output


def _ensure_prompt(ser, prompt, timeout, attempts=3):
    collected = ""
    for _ in range(attempts):
        ser.write(b"\n")
        ser.flush()
        out = _read_until_prompt(ser, prompt, timeout)
        collected += out
        if prompt in out:
            break
        time.sleep(0.2)
    return collected


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


def _step(message):
    print(f"[deauth] {message}", flush=True)


def _parse_client_status(output):
    connected = None
    ip = None
    match = re.search(r"connected=(\d+)\s+ip=([0-9.]+)", output)
    if match:
        connected = int(match.group(1))
        ip = match.group(2)
    return connected, ip


def _client_reboot_and_wait(ser, prompt, timeout):
    ser.reset_input_buffer()
    ser.write(b"reboot\n")
    ser.flush()
    return _read_until_prompt(ser, prompt, timeout)


def _client_wait_reconnect(ser, prompt, timeout):
    end = time.time() + timeout
    last_output = ""
    while time.time() < end:
        last_output = _client_send(ser, "sta_status", prompt, 6.0)
        connected, ip = _parse_client_status(last_output)
        if connected == 1 and ip and ip != "0.0.0.0":
            return last_output
        time.sleep(1.0)
    return last_output


def _dut_scan_select_target(ser, scan_timeout, ssid, bssid):
    scan_output = _run_scan(ser, scan_timeout)
    if RESULT_MARKER not in scan_output:
        _ensure_prompt(ser, DUT_PROMPT, 4.0)
        scan_output = _run_scan(ser, scan_timeout)

    csv_lines = _extract_csv_lines(scan_output)
    if not csv_lines:
        pytest.fail(f"No scan CSV lines found.\n{scan_output}")
    index = _select_target_index(csv_lines, ssid, bssid)
    if not index:
        pytest.fail(
            f"Target AP not found in scan output (ssid={ssid} bssid={bssid}).\n{scan_output}"
        )
    ser.write(f"select_networks {index}\n".encode("ascii"))
    ser.flush()
    select_out = _read_until_prompt(ser, DUT_PROMPT, 6.0)
    if "Selected Networks" not in select_out:
        pytest.fail(f"Missing selection output.\n{select_out}")
    if ssid not in select_out or bssid.lower() not in select_out.lower():
        pytest.fail(f"Selected network missing SSID/BSSID.\n{select_out}")
    return scan_output, select_out, index


def _dut_start_deauth(ser):
    ser.write(b"start_deauth\n")
    ser.flush()
    start_out = _read_until_prompt(ser, DUT_PROMPT, 6.0)
    if "Deauth attack started" not in start_out:
        pytest.fail(f"Missing deauth start.\n{start_out}")
    return start_out


def _dut_stop(ser):
    ser.write(b"stop\n")
    ser.flush()
    stop_out = _read_until_prompt(ser, DUT_PROMPT, 10.0)
    if "All operations stopped" not in stop_out:
        pytest.fail(f"Missing stop confirmation.\n{stop_out}")
    return stop_out


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
        _step("client: reboot")
        reboot_out = _client_reboot_and_wait(client_ser, client_prompt, 10.0)
        cli_log("deauth_client_reboot.txt", reboot_out)
        _step("client: wait for prompt")
        _read_until_prompt(client_ser, client_prompt, 6.0)
        _step("client: sta_hold on")
        hold_out = _client_send(client_ser, "sta_hold on", client_prompt, 4.0)
        cli_log("deauth_client_hold.txt", hold_out)

        _step("client: sta_connect")
        connect_out = _client_send(client_ser, f"sta_connect {ssid} {password}", client_prompt, 8.0)
        cli_log("deauth_client_connect.txt", connect_out)

        _step("client: sta_status")
        status_out = _client_send(client_ser, "sta_status", client_prompt, 6.0)
        cli_log("deauth_client_status.txt", status_out)
        assert "connected=1" in status_out, f"Client not connected.\n{status_out}"

        with serial.Serial(dut_port, baud, timeout=0.2) as dut_ser:
            _step("dut: wait for ready")
            _wait_for_ready(dut_ser, ready_marker, ready_timeout)
            _step("dut: reboot")
            reboot_out = _reboot_and_wait(dut_ser, ready_marker, ready_timeout)
            cli_log("deauth_reboot.txt", reboot_out)
            dut_ser.reset_input_buffer()
            _step("dut: wait for prompt")
            prompt_out = _ensure_prompt(dut_ser, DUT_PROMPT, 6.0)

            _step("dut: scan_networks")
            scan_output, select_out, index = _dut_scan_select_target(dut_ser, scan_timeout, ssid, bssid)
            cli_log("deauth_scan.txt", scan_output)
            _step(f"dut: select_networks {index}")
            cli_log("deauth_select.txt", select_out)

            dut_ser.write(b"start_deauth\n")
            dut_ser.flush()
            _step("dut: start_deauth")
            start_out = _dut_start_deauth(dut_ser)
            cli_log("deauth_start.txt", start_out)

        _step("client: wait_disconnect")
        disconnect_out = _client_send(client_ser, f"wait_disconnect {int(disconnect_timeout)}", client_prompt, disconnect_timeout + 5)
        cli_log("deauth_client_disconnect.txt", disconnect_out)
        assert "DISCONNECTED" in disconnect_out, f"Client did not disconnect.\n{disconnect_out}"

        with serial.Serial(dut_port, baud, timeout=0.2) as dut_ser:
            _step("dut: stop")
            stop_out = _dut_stop(dut_ser)
            cli_log("deauth_stop.txt", stop_out)

        time.sleep(2.0)
        _step("client: sta_status after deauth")
        status_after = _client_wait_reconnect(client_ser, client_prompt, reconnect_timeout + 5)
        cli_log("deauth_client_status_after.txt", status_after)
        assert "connected=1" in status_after, f"Client did not reconnect.\n{status_after}"


@pytest.mark.mandatory
@pytest.mark.deauth
def test_deauth_disconnect_reconnect_latency(
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
        _step("client: reboot")
        reboot_out = _client_reboot_and_wait(client_ser, client_prompt, 10.0)
        cli_log("deauth_latency_client_reboot.txt", reboot_out)
        _step("client: sta_hold on")
        hold_out = _client_send(client_ser, "sta_hold on", client_prompt, 4.0)
        cli_log("deauth_latency_client_hold.txt", hold_out)
        _step("client: sta_connect")
        connect_out = _client_send(client_ser, f"sta_connect {ssid} {password}", client_prompt, 8.0)
        cli_log("deauth_latency_client_connect.txt", connect_out)
        _step("client: sta_status")
        status_out = _client_send(client_ser, "sta_status", client_prompt, 6.0)
        cli_log("deauth_latency_client_status.txt", status_out)
        assert "connected=1" in status_out, f"Client not connected.\n{status_out}"

        with serial.Serial(dut_port, baud, timeout=0.2) as dut_ser:
            _step("dut: wait for ready")
            _wait_for_ready(dut_ser, ready_marker, ready_timeout)
            _step("dut: reboot")
            reboot_out = _reboot_and_wait(dut_ser, ready_marker, ready_timeout)
            cli_log("deauth_latency_reboot.txt", reboot_out)
            _step("dut: scan_networks")
            scan_output, select_out, index = _dut_scan_select_target(dut_ser, scan_timeout, ssid, bssid)
            cli_log("deauth_latency_scan.txt", scan_output)
            cli_log("deauth_latency_select.txt", select_out)
            _step(f"dut: start_deauth (index={index})")
            start_out = _dut_start_deauth(dut_ser)
            cli_log("deauth_latency_start.txt", start_out)

        _step("client: wait_disconnect")
        start = time.time()
        disconnect_out = _client_send(
            client_ser,
            f"wait_disconnect {int(disconnect_timeout)}",
            client_prompt,
            disconnect_timeout + 5,
        )
        disconnect_seconds = time.time() - start
        cli_log("deauth_latency_client_disconnect.txt", disconnect_out)
        assert "DISCONNECTED" in disconnect_out, f"Client did not disconnect.\n{disconnect_out}"

        with serial.Serial(dut_port, baud, timeout=0.2) as dut_ser:
            _step("dut: stop")
            stop_out = _dut_stop(dut_ser)
            cli_log("deauth_latency_stop.txt", stop_out)

        _step("client: wait reconnect")
        start = time.time()
        status_after = _client_wait_reconnect(client_ser, client_prompt, reconnect_timeout + 5)
        reconnect_seconds = time.time() - start
        cli_log("deauth_latency_client_reconnect.txt", status_after)
        assert "connected=1" in status_after, f"Client did not reconnect.\n{status_after}"

        report = (
            f"disconnect_seconds={disconnect_seconds:.2f}\n"
            f"reconnect_seconds={reconnect_seconds:.2f}\n"
        )
        cli_log("deauth_latency.txt", report)


@pytest.mark.mandatory
@pytest.mark.deauth
def test_deauth_client_hold_mode(
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
        _step("client: reboot")
        reboot_out = _client_reboot_and_wait(client_ser, client_prompt, 10.0)
        cli_log("deauth_hold_client_reboot.txt", reboot_out)
        _step("client: sta_hold on")
        hold_on_out = _client_send(client_ser, "sta_hold on", client_prompt, 4.0)
        cli_log("deauth_hold_on.txt", hold_on_out)
        _step("client: sta_connect")
        connect_out = _client_send(client_ser, f"sta_connect {ssid} {password}", client_prompt, 8.0)
        cli_log("deauth_hold_connect.txt", connect_out)
        _step("client: sta_status")
        status_out = _client_send(client_ser, "sta_status", client_prompt, 6.0)
        cli_log("deauth_hold_status.txt", status_out)
        assert "connected=1" in status_out, f"Client not connected.\n{status_out}"

        with serial.Serial(dut_port, baud, timeout=0.2) as dut_ser:
            _step("dut: wait for ready")
            _wait_for_ready(dut_ser, ready_marker, ready_timeout)
            _step("dut: reboot")
            reboot_out = _reboot_and_wait(dut_ser, ready_marker, ready_timeout)
            cli_log("deauth_hold_reboot.txt", reboot_out)
            _step("dut: scan_networks")
            scan_output, select_out, index = _dut_scan_select_target(dut_ser, scan_timeout, ssid, bssid)
            cli_log("deauth_hold_scan.txt", scan_output)
            cli_log("deauth_hold_select.txt", select_out)
            _step(f"dut: start_deauth (index={index})")
            start_out = _dut_start_deauth(dut_ser)
            cli_log("deauth_hold_start.txt", start_out)

        _step("client: wait_disconnect")
        disconnect_out = _client_send(
            client_ser,
            f"wait_disconnect {int(disconnect_timeout)}",
            client_prompt,
            disconnect_timeout + 5,
        )
        cli_log("deauth_hold_disconnect.txt", disconnect_out)
        assert "DISCONNECTED" in disconnect_out, f"Client did not disconnect.\n{disconnect_out}"

        with serial.Serial(dut_port, baud, timeout=0.2) as dut_ser:
            _step("dut: stop")
            stop_out = _dut_stop(dut_ser)
            cli_log("deauth_hold_stop.txt", stop_out)

        _step("client: sta_status (hold on)")
        status_after = _client_send(client_ser, "sta_status", client_prompt, 6.0)
        cli_log("deauth_hold_status_after.txt", status_after)
        connected, _ip = _parse_client_status(status_after)
        assert connected == 0, f"Client reconnected while hold on.\n{status_after}"

        _step("client: sta_hold off")
        hold_off_out = _client_send(client_ser, "sta_hold off", client_prompt, 4.0)
        cli_log("deauth_hold_off.txt", hold_off_out)

        _step("client: wait reconnect")
        status_reconnect = _client_wait_reconnect(client_ser, client_prompt, reconnect_timeout + 5)
        cli_log("deauth_hold_reconnect.txt", status_reconnect)
        assert "connected=1" in status_reconnect, f"Client did not reconnect.\n{status_reconnect}"


@pytest.mark.mandatory
@pytest.mark.deauth
def test_deauth_repeat_cycles(
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

    cycles = 3
    report_lines = []
    with serial.Serial(client_janosmini_port, baud, timeout=0.2) as client_ser:
        _step("client: reboot")
        reboot_out = _client_reboot_and_wait(client_ser, client_prompt, 10.0)
        cli_log("deauth_repeat_client_reboot.txt", reboot_out)
        _step("client: sta_hold on")
        hold_out = _client_send(client_ser, "sta_hold on", client_prompt, 4.0)
        cli_log("deauth_repeat_client_hold.txt", hold_out)
        _step("client: sta_connect")
        connect_out = _client_send(client_ser, f"sta_connect {ssid} {password}", client_prompt, 8.0)
        cli_log("deauth_repeat_client_connect.txt", connect_out)
        _step("client: wait initial reconnect")
        initial_status = _client_wait_reconnect(client_ser, client_prompt, reconnect_timeout + 5)
        cli_log("deauth_repeat_client_status_initial.txt", initial_status)
        assert "connected=1" in initial_status, f"Client not connected.\n{initial_status}"

        for idx in range(cycles):
            _step(f"cycle {idx+1}: ensure connected")
            status_out = _client_wait_reconnect(client_ser, client_prompt, reconnect_timeout + 5)
            assert "connected=1" in status_out, f"Client not connected.\n{status_out}"

            with serial.Serial(dut_port, baud, timeout=0.2) as dut_ser:
                _step(f"cycle {idx+1}: dut wait for ready")
                _wait_for_ready(dut_ser, ready_marker, ready_timeout)
                _step(f"cycle {idx+1}: dut reboot")
                _reboot_and_wait(dut_ser, ready_marker, ready_timeout)
                _step(f"cycle {idx+1}: dut scan_networks")
                scan_output, select_out, index = _dut_scan_select_target(dut_ser, scan_timeout, ssid, bssid)
                cli_log(f"deauth_repeat_scan_{idx+1}.txt", scan_output)
                cli_log(f"deauth_repeat_select_{idx+1}.txt", select_out)
                _step(f"cycle {idx+1}: dut start_deauth")
                _dut_start_deauth(dut_ser)

            _step(f"cycle {idx+1}: client wait_disconnect")
            disconnect_out = _client_send(
                client_ser,
                f"wait_disconnect {int(disconnect_timeout)}",
                client_prompt,
                disconnect_timeout + 5,
            )
            assert "DISCONNECTED" in disconnect_out, f"Client did not disconnect.\n{disconnect_out}"

            with serial.Serial(dut_port, baud, timeout=0.2) as dut_ser:
                _step(f"cycle {idx+1}: dut stop")
                _dut_stop(dut_ser)

            _step(f"cycle {idx+1}: client wait reconnect")
            status_after = _client_wait_reconnect(client_ser, client_prompt, reconnect_timeout + 5)
            assert "connected=1" in status_after, f"Client did not reconnect.\n{status_after}"
            report_lines.append(f"cycle {idx+1}: ok")

    cli_log("deauth_repeat_cycles.txt", "\n".join(report_lines) + "\n")
