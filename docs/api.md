JanOS UART API (v1)
===================

Overview
--------
This document describes the binary UART API used between JanOS (ESP32) and the
Flipper FAP. The scanner flow has both a binary API and a legacy ASCII CLI.
The FAP auto-enables the API when it detects the board.

JanOS API Behavior (General)
----------------------------
- Transport: UART0, 115200 baud, 8N1.
- Framing: binary frames with magic bytes and XOR checksum.
- Endianness: all multi-byte integers are little-endian.
- Versioning: HELLO includes API version; current version is 1.
- Mode: API is OFF by default. Enable with "api on".
- Coexistence: when API is ON, scan outputs are binary only for scan commands.
- Scope: currently implemented for WiFi scan results. Other commands stay ASCII.

JanOS Command Surface
---------------------
- api on
  Enables API mode and sends a HELLO frame immediately.
- api off
  Disables API mode and returns to ASCII outputs.
- api status
  Prints current API mode (ON/OFF) to ASCII console.

When API is ON:
- scan_results_page returns SCAN_SUMMARY + SCAN_ROW(s) + SCAN_END frames.
- scan_networks_quiet triggers background scan (no ASCII scan dump).
- scan_networks (non-quiet) still prints ASCII console logs, but scan rows are
  delivered via API only.

Frame Format
------------
All frames use the same structure:

  A5 5A <type> <len> <payload...> <crc>

- A5 5A: Magic bytes
- type: Message type
- len: Payload length in bytes (0-255)
- payload: Message-specific data
- crc: XOR of type, len, and all payload bytes

Handshake
---------
1) FAP sends: "api on"
2) JanOS replies with HELLO frame.

Types
-----
0x01 HELLO
  payload: [version, flags]
  - version: API version (1)
  - flags: bit0=1 means scan API supported

0x10 SCAN_SUMMARY
  payload:
    total u16
    offset u16
    count u16
    band24 u16
    band5 u16
    open u16
    hidden u16
    best_rssi i16
    ssid_len u8
    ssid bytes

0x11 SCAN_ROW
  payload:
    number u16
    bssid[6]
    channel u8
    auth u8
    rssi i8
    band u8 (0=2.4, 1=5)
    ssid_len u8
    ssid bytes
    vendor_len u8
    vendor bytes

0x12 SCAN_END
  payload: status u8
  status:
    0 = OK
    1 = IN_PROGRESS
    2 = NO_SCAN

Auth Codes (SCAN_ROW.auth)
--------------------------
0 Open
1 WEP
2 WPA
3 WPA2
4 WPA/WPA2 Mixed
5 WPA3
6 WPA2/WPA3 Mixed
255 Unknown

Scan Flow
---------
- FAP sends "scan_networks_quiet"
- JanOS runs scan
- FAP requests pages: "scan_results_page <offset> <limit>"
- JanOS sends SCAN_SUMMARY, SCAN_ROW(s), SCAN_END

Legacy ASCII Fallback
---------------------
If API is disabled, JanOS sends ASCII lines:
- SRH|... (summary)
- SR|... (row)
- SRE|... (end/error)

Note: the current FAP build does not parse ASCII scan output. API mode must be ON.

JanOS Scan API Details
----------------------
scan_results_page <offset> <limit>
- If scan is in progress:
  - API: SCAN_END status=1 (IN_PROGRESS)
  - ASCII: SRE|ERR|IN_PROGRESS
- If no scan has been completed:
  - API: SCAN_END status=2 (NO_SCAN)
  - ASCII: SRE|ERR|NO_SCAN
- If scan results are empty:
  - API: SCAN_SUMMARY with total=0 + SCAN_END OK
  - ASCII: SRH|0|... + SRE|OK
- If results exist:
  - API: SCAN_SUMMARY + N*SCAN_ROW + SCAN_END OK
  - ASCII: SRH + SR + SRE

Field Semantics
---------------
SCAN_SUMMARY:
- total: number of networks in the last scan
- offset: page start index requested
- count: number of rows returned in this page
- band24, band5: per-band counts in full scan
- open: number of open networks in full scan
- hidden: number of hidden SSIDs in full scan
- best_rssi: strongest RSSI in full scan
- ssid: SSID for best_rssi (may be empty)

SCAN_ROW:
- number: 1-based index in the full scan list
- bssid: AP MAC (6 bytes)
- channel: WiFi primary channel
- auth: mapped security code
- rssi: signed RSSI in dBm
- band: 0=2.4GHz, 1=5GHz
- ssid: SSID bytes (ASCII sanitized on JanOS side)
- vendor: vendor string if enabled on JanOS (may be empty)

Manual Init
-----------
From a UART console (or Flipper console), you can control API mode:
- Enable:  api on
- Disable: api off
- Status:  api status

When enabled, scan outputs use binary frames instead of SRH/SR/SRE.

Communication Summary
---------------------
1) FAP -> JanOS: "api on"
2) JanOS -> FAP: HELLO frame (version + flags)
3) FAP -> JanOS: "scan_networks_quiet"
4) FAP -> JanOS: "scan_results_page <offset> <limit>"
5) JanOS -> FAP: SCAN_SUMMARY + SCAN_ROW (0..N) + SCAN_END

If API is disabled, steps 3-5 return ASCII SRH/SR/SRE lines.

Test Checklist
--------------
- Build and flash JanOS.
- Build and run FAP.
- On FAP boot, verify "Board ready" and that API is enabled (no SRH/SR/SRE spam).
- Scanner: run a scan, verify list fills and paging works.
- Force fallback: run "api off" in console, scan again, verify SRH/SR/SRE and FAP still works.
- Re-enable: run "api on", scan again, verify binary flow.

Troubleshooting
---------------
- No HELLO frame after "api on":
  - Verify JanOS firmware includes the API code and command.
  - Make sure UART speed is 115200 and lines are not filtered.
- FAP stuck in ASCII mode:
  - Ensure "api on" was sent; run "api status" to confirm.
  - Check that HELLO frame is sent (version=1).
- CRC or garbled frames:
  - Check cabling/USB stability and UART baud.
  - Disable noisy logging on the same UART during tests.
- FAP shows "No board" or reboots:
  - Increase ping timeout or check UART reliability.
  - Confirm the board is responding to "ping" with "pong".

Example Frames (Manual Verification)
-----------------------------------
Use these hex sequences to recognize frames on the UART:

HELLO (type 0x01, version=1, flags=1)
  A5 5A 01 02 01 01 03
  crc = 01 ^ 02 ^ 01 ^ 01 = 03

SCAN_END OK (type 0x12, status=0)
  A5 5A 12 01 00 13
  crc = 12 ^ 01 ^ 00 = 13

SCAN_END IN_PROGRESS (type 0x12, status=1)
  A5 5A 12 01 01 12
  crc = 12 ^ 01 ^ 01 = 12

Minimal SCAN_SUMMARY (all zeros, empty SSID)
  Fields: total=0, offset=0, count=0, band24=0, band5=0, open=0, hidden=0, best_rssi=0, ssid_len=0
  Payload (17 bytes):
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  Frame:
    A5 5A 10 11 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
  crc = 10 ^ 11 ^ (17x 00) = 01

Notes:
- These are example frames you should see from JanOS when API is enabled.
- To validate, use a UART monitor that can display hex bytes.
