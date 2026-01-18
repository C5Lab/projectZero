#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TESTS_DIR="${ROOT_DIR}/ESP32C5/tests"
CONFIG_PATH="${ESP32C5_DEVICES_CONFIG:-${TESTS_DIR}/config/devices.json}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found. Install Python 3 to run this script." >&2
  exit 1
fi

if ! python3 -c "import serial" >/dev/null 2>&1; then
  echo "python3-serial not found. Install it with: sudo apt install python3-serial" >&2
  exit 1
fi

map_devices="$(
python3 - <<'PY'
import json
import os
import sys
from serial.tools import list_ports

config_path = os.environ.get("ESP32C5_DEVICES_CONFIG")
if not config_path:
    raise SystemExit("ESP32C5_DEVICES_CONFIG not set")

try:
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)
except FileNotFoundError:
    raise SystemExit(f"devices.json not found: {config_path}")
    config = json.load(f)

def normalize_hex(value):
    if value is None:
        return None
    return str(value).lower().replace("0x", "").zfill(4)

def match_port(port_info, spec):
    if not spec:
        return False
    port_override = spec.get("port")
    if port_override:
        return port_info.device == port_override
    vid = normalize_hex(spec.get("vid"))
    pid = normalize_hex(spec.get("pid"))
    serial = spec.get("serial")
    port_vid = normalize_hex(port_info.vid) if port_info.vid is not None else None
    port_pid = normalize_hex(port_info.pid) if port_info.pid is not None else None
    port_serial = port_info.serial_number
    if vid and port_vid != vid:
        return False
    if pid and port_pid != pid:
        return False
    if serial and port_serial != serial:
        return False
    return True

def find_port(spec):
    port_override = spec.get("port")
    if port_override:
        return port_override
    matches = [p.device for p in list_ports.comports() if match_port(p, spec)]
    if not matches:
        return None
    if len(matches) > 1:
        raise SystemExit(f"Multiple ports matched for {spec}: {matches}")
    return matches[0]

devices = config.get("devices", {})
dut = devices.get("dut", {})
dut_port = find_port(dut)

client_port = None
clients = devices.get("clients", [])
for client in clients:
    if client.get("name") == "client_janosmini":
        client_port = find_port(client)
        break

print(dut_port or "")
print(client_port or "")
PY
)"

if [ -z "${map_devices}" ]; then
  echo "Failed to resolve device ports from ${CONFIG_PATH}" >&2
  exit 1
fi

dut_port="$(printf '%s\n' "${map_devices}" | sed -n '1p')"
client_port="$(printf '%s\n' "${map_devices}" | sed -n '2p')"

if [ -z "${dut_port}" ]; then
  echo "DUT port not found (check devices.json or USB connection)." >&2
  exit 1
fi

args=(
  "docker" "compose" "-f" "${TESTS_DIR}/docker-compose.yml"
  "run" "--rm"
  "-e" "ESP32C5_DUT_PORT=${dut_port}"
  "-e" "ESP32C5_TEST_DEVICE=${dut_port}"
)

if [ -n "${client_port}" ]; then
  args+=("-e" "ESP32C5_CLIENT_JANOSMINI_PORT=${client_port}")
  args+=("-e" "ESP32C5_CLIENT_DEVICE=${client_port}")
fi

args+=("tests")

if [ $# -gt 0 ]; then
  args+=("$@")
fi

echo "Running: ${args[*]}"
exec "${args[@]}"
