JanOS UART API (v1)
===================

Overview
--------
This document describes the binary UART API used between JanOS (ESP32) and the
Flipper FAP. WiFi scanning and Bluetooth scanning have both a binary API and a
legacy ASCII CLI. The FAP auto-enables the API when it detects the board.

JanOS API Behavior (General)
----------------------------
- Transport: UART0, 115200 baud, 8N1.
- Framing: binary frames with magic bytes and XOR checksum.
- Endianness: all multi-byte integers are little-endian.
- Versioning: HELLO includes API version; current version is 1.
- Mode: API is OFF by default. Enable with "api on".
- Coexistence: when API is ON, scan outputs are binary only for scan commands.
- Scope: WiFi scan results, Bluetooth scan/locator updates, and sniffer paging. Other commands stay ASCII.

JanOS Command Surface
---------------------
- api on
  Enables API mode and sends a HELLO frame immediately.
- api off
  Disables API mode and returns to ASCII outputs.
- api status
  Prints current API mode (ON/OFF) to ASCII console.
- sniffer_results_page <offset> <limit>
  Sniffer AP paging (API only).
- sniffer_clients_page <ap_index> <offset> <limit>
  Sniffer client paging for a given AP (API only).

When API is ON:
- scan_results_page returns SCAN_SUMMARY + SCAN_ROW(s) + SCAN_END frames.
- scan_networks_quiet triggers background scan (no ASCII scan dump).
- scan_networks (non-quiet) still prints ASCII console logs, but scan rows are
  delivered via API only.
- scan_bt returns BT_SCAN_SUMMARY + BT_SCAN_ROW(s) + BT_SCAN_END frames.
- scan_airtag returns BT_SCAN_SUMMARY frames (running counts) and BT_SCAN_END on stop.
- scan_bt <mac> returns BT_LOCATOR_UPDATE frames and BT_SCAN_END on stop.
- sniffer_results_page returns SNIFFER_AP_SUMMARY + SNIFFER_AP_ROW(s) + SNIFFER_END.
- sniffer_clients_page returns SNIFFER_CLIENT_SUMMARY + SNIFFER_CLIENT_ROW(s) + SNIFFER_END.

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
  - flags: bit0=1 scan API supported, bit1=1 BT API supported, bit2=1 sniffer API supported

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

0x20 BT_SCAN_SUMMARY
  payload:
    mode u8 (0=scan, 1=airtag, 2=locator)
    running u8 (0/1)
    total u16
    airtag u16
    smarttag u16

0x21 BT_SCAN_ROW
  payload:
    number u16
    rssi i8
    flags u8
      bit0 = airtag
      bit1 = smarttag
      bit2 = scan_rsp
      bit3 = name_present
      bit4 = tx_power_present
      bit5 = adv_flags_present
      bit6 = company_id_present
    adv_type u8
    addr_type u8
    adv_flags u8
    tx_power i8
    company_id u16
    adv_data_len u8
    uuid16_count u8
    uuid32_count u8
    uuid128_count u8
    mac[6]
    name_len u8
    name bytes

0x22 BT_SCAN_END
  payload: status u8 (0=OK)

0x23 BT_LOCATOR_UPDATE
  payload:
    mac[6]
    rssi i8
    flags u8
      bit0 = has_rssi
      bit1 = scan_rsp
      bit2 = name_present
      bit3 = tx_power_present
      bit4 = adv_flags_present
      bit5 = company_id_present
    adv_type u8
    addr_type u8
    adv_flags u8
    tx_power i8
    company_id u16
    adv_data_len u8
    uuid16_count u8
    uuid32_count u8
    uuid128_count u8
    name_len u8
    name bytes

0x30 SNIFFER_AP_SUMMARY
  payload:
    total_aps u16
    total_clients u16
    offset u16
    count u16

0x31 SNIFFER_AP_ROW
  payload:
    index u16 (1-based in sorted list)
    channel u8
    client_count u16
    ssid_len u8
    ssid bytes

0x32 SNIFFER_CLIENT_SUMMARY
  payload:
    ap_index u16 (1-based in sorted list)
    total_clients u16
    offset u16
    count u16

0x33 SNIFFER_CLIENT_ROW
  payload:
    ap_index u16
    client_index u16 (1-based within AP)
    mac[6]

0x34 SNIFFER_END
  payload: status u8
  status:
    0 = OK
    1 = IN_PROGRESS
    2 = NO_DATA

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

BT Scan Flow
------------
- FAP sends "scan_bt"
- JanOS runs 10s scan
- JanOS sends BT_SCAN_SUMMARY, BT_SCAN_ROW(s), BT_SCAN_END
Note: BT scan currently streams all rows for a scan (no paging).

BT AirTag Flow
--------------
- FAP sends "scan_airtag"
- JanOS continuously scans in 10s cycles
- JanOS sends BT_SCAN_SUMMARY (running=1) each cycle
- FAP sends "stop" when done
- JanOS sends BT_SCAN_END

BT Locator Flow
---------------
- FAP sends "scan_bt XX:XX:XX:XX:XX:XX"
- JanOS continuously scans in 10s cycles for that MAC
- JanOS sends BT_LOCATOR_UPDATE (has_rssi=1/0) each cycle
- FAP sends "stop" when done
- JanOS sends BT_SCAN_END

Sniffer Paging Flow
-------------------
- FAP sends "sniffer_results_page <offset> <limit>"
- JanOS sends SNIFFER_AP_SUMMARY + SNIFFER_AP_ROW(s) + SNIFFER_END
- FAP sends "sniffer_clients_page <ap_index> <offset> <limit>"
- JanOS sends SNIFFER_CLIENT_SUMMARY + SNIFFER_CLIENT_ROW(s) + SNIFFER_END

Notes:
- AP list is sorted by client count (descending), same as show_sniffer_results.
- ap_index is 1-based in the sorted/filtered list (broadcast/own MAC and empty APs omitted).

Legacy ASCII Fallback
---------------------
If API is disabled, JanOS sends ASCII lines:
- SRH|... (summary)
- SR|... (row)
- SRE|... (end/error)

Note: the current FAP build does not parse ASCII scan output. API mode must be ON.
Bluetooth still supports ASCII parsing when API is OFF.

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
- Bluetooth: run scan_bt, verify list fills and summary appears.
- Bluetooth: run scan_airtag, verify running counts update and stop works.
- Bluetooth: run scan_bt <mac>, verify locator RSSI updates.
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

HELLO (type 0x01, version=1, flags=7)
  A5 5A 01 02 01 07 05
  crc = 01 ^ 02 ^ 01 ^ 07 = 05

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

BT_SCAN_SUMMARY (mode=scan, running=0, total=1, airtag=0, smarttag=0)
  Payload (8 bytes):
    00 00 01 00 00 00 00 00
  Frame:
    A5 5A 20 08 00 00 01 00 00 00 00 00 29
  crc = 20 ^ 08 ^ 00 ^ 00 ^ 01 ^ 00 ^ 00 ^ 00 ^ 00 ^ 00 = 29

Notes:
- These are example frames you should see from JanOS when API is enabled.
- To validate, use a UART monitor that can display hex bytes.
