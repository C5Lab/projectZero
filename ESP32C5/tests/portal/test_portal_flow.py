import re
import time

import pytest
import serial


DUT_PROMPT = ">"
CLIENT_PROMPT = "JanOSmini>"


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


def _reboot_and_wait(ser, marker, timeout):
    ser.write(b"reboot\n")
    ser.flush()
    return _read_until_marker(ser, marker, timeout)


def _send_and_read(ser, command, timeout, prompt=DUT_PROMPT):
    ser.write((command + "\n").encode("ascii"))
    ser.flush()
    return _read_until_prompt(ser, prompt, timeout)


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


def _step(message):
    print(f"[portal] {message}", flush=True)


def _parse_list_sd(output):
    entries = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.+)\.html", line.strip(), re.IGNORECASE)
        if match:
            entries.append((match.group(1), match.group(2)))
    return entries


def _parse_client_status(output):
    match = re.search(r"connected=(\d+)\s+ip=([0-9.]+)", output)
    if not match:
        return None, None
    return int(match.group(1)), match.group(2)


@pytest.mark.mandatory
@pytest.mark.portal
def test_portal_post_flow(
    dut_port,
    client_janosmini_port,
    devices_config,
    settings_config,
    cli_log,
):
    baud = int(settings_config.get("uart_baud", 115200))
    ready_marker = settings_config.get("ready_marker", "BOARD READY")
    ready_timeout = float(settings_config.get("ready_timeout", 20))
    portal_ssid = settings_config.get("portal_ssid", "openweb")
    portal_html_index = str(settings_config.get("portal_html_index", "1"))
    portal_http_url = settings_config.get("portal_http_url", "http://172.0.0.1/login")
    portal_user = settings_config.get("portal_user", "test_user")
    portal_password = settings_config.get("portal_password", "test_pass")

    with serial.Serial(dut_port, baud, timeout=0.2) as dut_ser:
        _step("dut: wait for ready")
        _wait_for_ready(dut_ser, ready_marker, ready_timeout)
        _step("dut: reboot")
        _reboot_and_wait(dut_ser, ready_marker, ready_timeout)
        _ensure_prompt(dut_ser, DUT_PROMPT, 6.0)

        _step("dut: list_sd")
        list_sd = _send_and_read(dut_ser, "list_sd", 6.0)
        cli_log("portal_list_sd.txt", list_sd)
        entries = _parse_list_sd(list_sd)
        if not entries:
            pytest.fail(f"No HTML files listed on SD.\n{list_sd}")

        _step(f"dut: select_html {portal_html_index}")
        select_html = _send_and_read(dut_ser, f"select_html {portal_html_index}", 6.0)
        cli_log("portal_select_html.txt", select_html)
        if "Loaded HTML file" not in select_html:
            pytest.fail(f"select_html failed.\n{select_html}")

        _step(f"dut: start_portal {portal_ssid}")
        dut_ser.write(f"start_portal {portal_ssid}\n".encode("ascii"))
        dut_ser.flush()
        start_out = _read_until_marker(dut_ser, "Captive portal started successfully", 12.0)
        start_out += _read_until_prompt(dut_ser, DUT_PROMPT, 6.0)
        cli_log("portal_start.txt", start_out)
        if "HTTP server started successfully" not in start_out:
            pytest.fail(f"Portal did not start HTTP server.\n{start_out}")

        with serial.Serial(client_janosmini_port, baud, timeout=0.2) as client_ser:
            _step("client: wait for prompt")
            _read_until_prompt(client_ser, CLIENT_PROMPT, 6.0)
            _step(f"client: sta_connect {portal_ssid}")
            connect_out = _send_and_read(client_ser, f"sta_connect {portal_ssid}", 10.0, CLIENT_PROMPT)
            cli_log("portal_client_connect.txt", connect_out)

            _step("client: sta_status")
            status_out = _send_and_read(client_ser, "sta_status", 6.0, CLIENT_PROMPT)
            cli_log("portal_client_status.txt", status_out)
            connected, ip = _parse_client_status(status_out)
            if connected != 1:
                pytest.fail(f"Client did not connect to portal.\n{status_out}")

            _step("client: http_post")
            post_out = _send_and_read(
                client_ser,
                f"http_post {portal_http_url} {portal_user} {portal_password}",
                12.0,
                CLIENT_PROMPT,
            )
            cli_log("portal_client_post.txt", post_out)

        _step("dut: wait for POST")
        post_out = _read_until_marker(dut_ser, "Portal password received", 10.0)
        if "Portal password received" not in post_out:
            post_out += _read_until_marker(dut_ser, "Portal data saved to portals.txt", 6.0)
        cli_log("portal_dut_post.txt", post_out)
        if "Received POST data" not in post_out:
            pytest.fail(f"DUT did not log POST data.\n{post_out}")

        _step("dut: stop")
        stop_out = _send_and_read(dut_ser, "stop", 10.0)
        cli_log("portal_stop.txt", stop_out)
        if "All operations stopped" not in stop_out:
            pytest.fail(f"Missing stop confirmation.\n{stop_out}")
