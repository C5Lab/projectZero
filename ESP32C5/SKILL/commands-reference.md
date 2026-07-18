# JanOS UART Command Reference

Complete reference of all commands supported by JanOS firmware on ESP32C5.
Commands are sent over UART as plain text terminated with `\r\n`. Responses are line-based text.

**Indexing convention**: All indices in JanOS are **1-based** (not 0-based).

---

## WiFi Scanning

### `scan_networks`
- **Syntax**: `scan_networks`
- **Description**: Starts background WiFi scan on all channels.
- **Output**: `"Background scan started (min: X ms, max: Y ms per channel)"`
- **Completion marker**: Wait for `"Scan results printed"` in the output of `show_scan_results` (auto-triggered after scan completes).
- **Response format** (each network is a CSV line):
```
"1","AX3","","C4:2B:44:12:29:20","112","WPA2/WPA3 Mixed","-59","5GHz"
"2","BRW","","64:7C:34:41:8F:EC","7","WPA/WPA2 Mixed","-72","2.4GHz"
Scan results printed.
```
- **CSV fields**: `"index","SSID","(empty)","BSSID","channel","security","RSSI","band"`
- **Notes**: Wardrive must be stopped first. Results are auto-printed; wait for `"Scan results printed"`.

### `show_scan_results`
- **Syntax**: `show_scan_results`
- **Description**: Prints results from last `scan_networks`. Same CSV format as above.
- **Completion marker**: `"Scan results printed"`

### `inspect_network`
- **Syntax**: `inspect_network <index>`
- **Description**: Passively captures beacons from the AP at the given 1-based index (from last `scan_networks`) on its primary channel for ~1.5 s. Parses the beacon to expose data not available in `scan_networks`:
  - **MFP (802.11w / Management Frame Protection)** — read from RSN IE (tag 48) RSN Capabilities field: `mfp_capable` (bit 7 = MFPC) and `mfp_required` (bit 6 = MFPR).
  - **AP uptime** — TSF timestamp from beacon body (microseconds since AP boot).
- **Output** (single line, prefixed with `[INSPECT]`):
```
[INSPECT] index=1 bssid=C4:2B:44:12:29:20 channel=112 ssid="AX3" mfp_capable=1 mfp_required=0 uptime_us=1234567890 uptime_str=14d 06:56:07 beacon_interval_tu=100 beacons_seen=3
```
- **No-RSN AP** (open / WPA-only — MFP not applicable):
```
[INSPECT] index=2 bssid=... mfp_capable=- mfp_required=- uptime_us=... uptime_str=... beacon_interval_tu=100 beacons_seen=2 note=no_rsn_ie
```
- **Timeout** (no beacon received within ~1.5 s):
```
[INSPECT] index=1 bssid=... channel=... ssid="..." beacons_seen=0 error=timeout
```
- **Completion marker**: any line containing `"[INSPECT]"`.
- **Notes**: Requires prior `scan_networks`. Refuses to run while sniffer / wardrive / beacon spam is active. Switches the radio to the target channel during the capture; previous promiscuous state is restored afterward.

### `select_networks`
- **Syntax**: `select_networks <index1> [index2] ...`
- **Description**: Selects networks by 1-based index for targeted attacks/operations.
- **Example**: `select_networks 1 3 5`
- **Output**: Selection confirmation per network.
- **Notes**: Requires prior `scan_networks`.

### `unselect_networks`
- **Syntax**: `unselect_networks`
- **Description**: Stops all operations and clears network selection. Keeps scan results intact.

---

## Sniffing & Network Observer

### `start_sniffer`
- **Syntax**: `start_sniffer`
- **Description**: Starts client sniffer. If networks selected, sniffs only those; otherwise does full scan first.
- **Continuous output**: `"Sniffer packet count: 60"`, `"Sniffer packet count: 80"`, ...
- **Stop**: Send `stop`.

### `start_sniffer_noscan`
- **Syntax**: `start_sniffer_noscan`
- **Description**: Starts sniffer using existing scan results (no new scan).
- **Notes**: Requires prior `scan_networks`.

### `show_sniffer_results`
- **Syntax**: `show_sniffer_results`
- **Description**: Shows discovered APs and their associated clients, sorted by client count.
- **Output format**:
```
AX3, CH40: 2
 6E:0B:45:01:15:9E
 EA:7A:33:04:3C:50
NETIASPOT-2.4GHz-Eh82, CH7: 1
 BC:30:7E:BB:52:71
```
- **Empty result**: `"No APs with clients found."`
- **Notes**: AP lines have no leading space; client MAC lines have leading space.

### `show_sniffer_results_vendor`
- **Syntax**: `show_sniffer_results_vendor`
- **Description**: Same as `show_sniffer_results` but includes vendor names for MACs.

### `clear_sniffer_results`
- **Syntax**: `clear_sniffer_results`
- **Description**: Clears all sniffer results (clients, probes, counters).

### `show_probes`
- **Syntax**: `show_probes`
- **Description**: Shows captured probe requests with SSIDs and source MACs.
- **Output format**:
```
Probe requests: 5
Orange_Swiatlowod_BA62 (B0:98:2B:CC:BA:62)
ZCS (0E:64:69:05:09:FC)
TP-Link_F5F8 (64:57:25:BB:90:6A)
```

### `show_probes_vendor`
- **Syntax**: `show_probes_vendor`
- **Description**: Same as `show_probes` with vendor names.

### `list_probes`
- **Syntax**: `list_probes`
- **Description**: Lists probe SSIDs with 1-based index (for use with `start_karma`).
- **Output format**:
```
1 multimedia_siecBursztynowa1
2 multimedia_siecBursztynowa2
3 jakasInnaSieci
```

### `list_probes_vendor`
- **Syntax**: `list_probes_vendor`
- **Description**: Same as `list_probes` with vendor names.

### `sniffer_debug`
- **Syntax**: `sniffer_debug <0|1>`
- **Description**: Enables (`1`) or disables (`0`) verbose sniffer debug logging.

### `start_sniffer_dog`
- **Syntax**: `start_sniffer_dog`
- **Description**: Sniffer Dog mode -- captures AP-STA pairs and immediately sends targeted deauth.
- **Continuous output**:
```
[SnifferDog #2] DEAUTH sent: AP=30:AA:E4:3C:3F:64 -> STA=A6:02:A5:BA:DA:AB (Ch=1, RSSI=-69)
[SnifferDog #3] DEAUTH sent: AP=30:AA:E4:3C:3F:64 -> STA=A6:02:A5:BA:DA:AB (Ch=1, RSSI=-69)
```
- **Parse**: Extract `#N` for counter, `AP=`, `STA=`, `Ch=`, `RSSI=` fields.
- **Stop**: Send `stop`.

### `start_pcap`
- **Syntax**: `start_pcap [radio|net]`
- **Description**: Captures WiFi traffic to PCAP file on SD card. Default mode: `radio`.
  - **Radio mode** (linktype 105): Promiscuous mode capturing all management/data/control frames on all channels.
  - **Net mode** (linktype 1): Requires WiFi STA connection. Captures outbound packets and performs ARP spoofing MITM on detected hosts.
- **Example**: `start_pcap radio` or `start_pcap net`
- **Output**:
```
PCAP radio capture started -> /sdcard/lab/pcaps/sniff_1.pcap
```
- **On stop**:
```
PCAP saved: /sdcard/lab/pcaps/sniff_1.pcap (1530 frames, 2 drops)
```
- **Error outputs**:
  - `"Usage: start_pcap radio|net"` (invalid argument)
  - `"Not connected to WiFi. Use 'wifi_connect' first."` (net mode, not connected)
  - `"Failed to initialize SD card: <error>"` (SD init fail)
  - `"Failed to create /sdcard/lab/pcaps directory"` (directory fail)
  - `"Failed to open <filepath> for writing"` (file fail)
- **Prerequisites**: SD card. For net mode: WiFi connected via `wifi_connect`.
- **Stop**: Send `stop`.
- **Notes**: Files are saved at `/sdcard/lab/pcaps/sniff_N.pcap` (N auto-increments).

---

## Attacks

### `start_deauth`
- **Syntax**: `start_deauth`
- **Description**: Starts deauth attack on selected networks.
- **Prerequisite**: `select_networks`
- **Stop**: Send `stop`.

### `start_evil_twin`
- **Syntax**: `start_evil_twin`
- **Description**: Starts Evil Twin attack. Creates AP cloning first selected network, deauths all selected.
- **Prerequisite**: `select_networks` (first index = clone target), optionally `select_html`.
- **Output sequence**:
```
Starting captive portal for Evil Twin attack on: AX3_2.4
Captive portal started successfully
Attacking 2 network(s):
Target BSSID[0]: AX3_2.4, BSSID: C4:2B:44:12:29:1C, Channel: 1
```
- **Success markers** (monitor continuously):
  - Client connect: `"AP: Client connected - MAC: XX:XX:XX:XX:XX:XX"`
  - Password received: `"Password received: <password>"`
  - Verified: `"Wi-Fi: connected to SSID='<SSID>' with password='<password>'"` followed by `"Password verified!"`
  - Shutdown: `"Evil Twin portal shut down successfully!"`
- **Stop**: Send `stop`.

### `sae_overflow`
- **Syntax**: `sae_overflow`
- **Description**: SAE (WPA3) client overflow attack on selected network.
- **Prerequisite**: `select_networks` (exactly one network).
- **Stop**: Send `stop`.

### `start_handshake`
- **Syntax**: `start_handshake`
- **Description**: Captures WPA handshakes. With selection = targeted; without = scans every 5 min and attacks all.
- **Success markers** (monitor continuously):
```
HANDSHAKE IS COMPLETE AND VALID
PCAP saved: /sdcard/lab/handshakes/AX3_2.4_12291C_79868.pcap (1186 bytes)
Complete 4-way handshake saved for SSID: AX3_2.4 (MAC: 12291C, message_pair: 2)
Handshake #1 captured!
```
- **Key lines to parse**:
  - `strstr("HANDSHAKE IS COMPLETE AND VALID")` -- handshake validated
  - `strstr("PCAP saved:")` -- file saved, extract path after `/sdcard/`
  - `strstr("handshake saved for SSID:")` -- extract SSID after `"SSID: "`
- **Stop**: Send `stop`.

### `save_handshake`
- **Syntax**: `save_handshake`
- **Description**: Manually saves captured handshake to SD (only if complete 4-way available).

### `start_blackout`
- **Syntax**: `start_blackout`
- **Description**: Blackout attack -- scans all networks every 3 min, deauths everything.
- **Stop**: Send `stop`.

### `start_beacon_spam`
- **Syntax**: `start_beacon_spam "SSID1" "SSID2" ...`
- **Description**: Broadcasts fake beacon frames with specified SSIDs. Sets WiFi to APSTA mode and iterates through 2.4GHz channels (1-11), sending beacons for each SSID per channel. Max 32 SSIDs, each 1-32 characters.
- **Example**: `start_beacon_spam "Free WiFi" "Starbucks" "Airport"`
- **Output**:
```
Starting beacon spam with 3 SSIDs:
  1: Free WiFi
  2: Starbucks
  3: Airport
WiFi initialized for beacon spam...
Beacon spam started. Use 'stop' to end.
```
- **Error outputs**:
  - `"Usage: start_beacon_spam \"SSID1\" \"SSID2\" ..."` (no arguments)
  - `"Beacon spam already running. Use 'stop' first."` (already active)
  - `"Warning: SSID N invalid length (M), skipping"` (SSID too long/empty)
  - `"No valid SSIDs provided"` (all SSIDs invalid)
- **Stop**: Send `stop`.

### `start_beacon_spam_ssids`
- **Syntax**: `start_beacon_spam_ssids`
- **Description**: Same as `start_beacon_spam` but loads SSIDs from `/sdcard/lab/ssids.txt` (one SSID per line). Max 32 SSIDs loaded.
- **Prerequisite**: SD card with `/sdcard/lab/ssids.txt` containing SSIDs (one per line). Manage the file with `add_ssid`, `remove_ssid`, `list_ssids`.
- **Output**: Same as `start_beacon_spam` after loading SSIDs from file.
- **Error outputs**:
  - `"Beacon spam already running. Use 'stop' first."` (already active)
  - `"Failed to initialize SD card: <error>"` (SD init fail)
  - `"ssids.txt not found on SD card."` (file missing)
  - `"ssids.txt is empty - no SSIDs to broadcast"` (file empty)
- **Stop**: Send `stop`.

### `start_karma`
- **Syntax**: `start_karma <index>`
- **Description**: Karma attack using SSID from probe list at given 1-based index.
- **Prerequisite**: `list_probes` to get indices, `select_html` for portal page.
- **Output**:
```
Captive portal started successfully!
AP Name: multimedia_siecBursztynowa1
```
- **Monitor for**:
  - `"AP: Client connected - MAC: <MAC>"`
  - `"Password: <password>"`
  - `"Portal data saved to portals.txt"`
- **Stop**: Send `stop`.

### `start_rogueap`
- **Syntax**: `start_rogueap <SSID> <password>`
- **Description**: WPA2 Rogue AP with captive portal. Deauths selected networks if any.
- **Args**: SSID (1-32 chars), password (8-63 chars).
- **Prerequisite**: `select_html` for portal page.
- **Output**:
```
Rogue AP started successfully!
AP Name: duap (WPA2 protected)
Password: 12345678
Custom HTML loaded (4841 bytes)
Connect to 'duap' WiFi network to access the captive portal
```
- **Monitor for**:
  - `"AP: Client connected - MAC: <MAC>"`
  - `"Password: <password>"`
  - `"Portal data saved to portals.txt"`
  - `"AP: Client disconnected - MAC: <MAC>"`
- **Stop**: Send `stop`.

### `start_portal`
- **Syntax**: `start_portal <SSID>`
- **Description**: Open captive portal (no password required to join).
- **Args**: SSID (1-32 chars).
- **Prerequisite**: Optionally `select_html` for custom HTML.
- **Output**:
```
Captive portal started successfully!
AP Name: MojaSiec
Connect to 'MojaSiec' WiFi network to access the portal
```
- **Monitor for**:
  - `"AP: Client connected - MAC: <MAC>"`
  - `"Portal: Client count = N"`
  - `"Password: <value>"` (form submission data)
  - `"Portal data saved to portals.txt"`
- **Stop**: Send `stop`.

---

## Station Selection

### `select_stations`
- **Syntax**: `select_stations <MAC1> [MAC2] ...`
- **Description**: Selects specific client MACs for targeted deauth (instead of broadcast).
- **Example**: `select_stations AA:BB:CC:DD:EE:FF 11:22:33:44:55:66`

### `unselect_stations`
- **Syntax**: `unselect_stations`
- **Description**: Clears station selection, reverts to broadcast deauth.

---

## WiFi Connection (STA Mode)

### `wifi_connect`
- **Syntax**: `wifi_connect <SSID> [Password|--saved] [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]`
- **Description**: Connects to an AP as STA. If password is omitted, firmware tries open auth. Use `--saved` to explicitly load a saved password from `/sdcard/lab/eviltwin.txt` or `/sdcard/lab/portals.txt`. Optional static IP config.
- **Examples**:
  - WPA2 network: `wifi_connect AX4 ruletka2022`
  - Open network: `wifi_connect BRW`
  - Saved password: `wifi_connect AX4 --saved`
  - With OTA: `wifi_connect AX4 ruletka2022 ota`
  - Static IP: `wifi_connect AX4 ruletka2022 192.168.1.50 255.255.255.0 192.168.1.1`
- **Output**:
```
Connecting to AP 'AX4'...
Initializing WiFi...
MAC Address: 30:ED:A0:E3:EC:18
WiFi initialized OK
Waiting for connection result...
Wi-Fi: connected to SSID='AX4'
SUCCESS: Connected to 'AX4'
DHCP IP: 192.168.0.5, Netmask: 255.255.255.0, GW: 192.168.0.1
```
- **Success marker**: `strstr("SUCCESS")`
- **Failure markers**: `strstr("FAILED")` or `strstr("TIMEOUT")`
- **Notes**: When password is omitted, firmware sets `authmode = WIFI_AUTH_OPEN`. Saved credentials are used only when `--saved` is passed. The `ota` flag triggers OTA check after successful connection.

### `wifi_disconnect`
- **Syntax**: `wifi_disconnect`
- **Description**: Disconnects from current AP.

---

## ARP Operations

### `list_hosts`
- **Syntax**: `list_hosts`
- **Description**: ARP scans local network and lists discovered hosts.
- **Prerequisite**: `wifi_connect` (must be connected to a network).
- **Output**:
```
Our IP: 192.168.3.39, Netmask: 255.255.255.0
Scanning 254 hosts on network...
Sent 254 ARP requests, waiting for responses...
=== Discovered Hosts ===
  192.168.3.61  ->  C4:2B:44:12:29:15
  192.168.3.1  ->  60:AA:EF:45:71:45
  192.168.3.9  ->  D6:FD:01:EC:14:18
```
- **Completion marker**: `strstr("Discovered Hosts")`
- **Parse**: Lines containing `"->"` have format `  IP  ->  MAC`.

### `list_hosts_vendor`
- **Syntax**: `list_hosts_vendor`
- **Description**: Same as `list_hosts` with vendor names appended.

### `arp_ban`
- **Syntax**: `arp_ban <MAC> [IP]`
- **Description**: ARP poisons target device to disconnect it from network.
- **Example**: `arp_ban C4:2B:44:12:29:15 192.168.3.61`
- **Prerequisite**: `wifi_connect`.
- **Stop**: Send `stop`.

---

## Network Scanning (NMAP)

### `start_nmap`
- **Syntax**: `start_nmap [quick|medium|heavy] [IP]`
- **Description**: TCP port scanner. Discovers live hosts on the LAN (ARP + ICMP) then probes each host's ports with non-blocking TCP connect (500ms timeout per port). Can scan a single IP or the full subnet.
- **Scan levels**:
  - `quick` (default): 20 most common ports (FTP, SSH, HTTP, SMB, RDP, etc.)
  - `medium`: 50 ports (adds LDAP, MQTT, Docker, Redis, etc.)
  - `heavy`: 100 ports (adds TFTP, BGP, Modbus, MongoDB, Minecraft, etc.)
- **Examples**:
  - `start_nmap` -- quick scan of entire subnet
  - `start_nmap heavy` -- 100-port scan of entire subnet
  - `start_nmap medium 192.168.0.4` -- 50-port scan of single host
- **Prerequisite**: `wifi_connect` (must be connected to a network).
- **Stop**: Send `stop` (checked between each port probe).
- **Output phases** (in order):

**Phase 1 -- Host Discovery (only when not in single-host mode)**:
```
[MEM] start_nmap: Internal=125/251KB, DMA=109/235KB, PSRAM=7944/8192KB
Scan level: heavy (100 ports)
Our IP: 192.168.0.5, Netmask: 255.255.255.0
Phase 1: ARP scan (254 hosts)...
Sent 254 ARP requests, polling table for 4 seconds...
ARP: found 3 hosts
Phase 2: sent 251 ICMP pings, waiting for replies...
ICMP: found 1 additional hosts
Total: 4 hosts discovered (3 ARP + 1 ICMP)
```

**Phase 2 -- Port Scanning** (repeated per host):
```
Scanning 4 host(s), 100 ports each (heavy)...
=== NMAP Scan Results ===
Host: 192.168.0.1  (00:0B:00:00:AD:D0)
  Scanning 192.168.0.1 ports 21-143 [1/100] ...
     80/tcp  open  HTTP
  Scanning 192.168.0.1 ports 443-8443 [11/100] ...
  Scanning 192.168.0.1 ports 111-636 [21/100] ...
  ...
Host: 192.168.0.4  (00:C0:CA:B4:E6:3F)
  Scanning 192.168.0.4 ports 21-143 [1/100] ...
    135/tcp  open  MSRPC
    139/tcp  open  NetBIOS
  Scanning 192.168.0.4 ports 443-8443 [11/100] ...
    445/tcp  open  SMB
  ...
Host: 192.168.0.128  (5C:D8:9E:8C:0C:B2)
  Scanning 192.168.0.128 ports 21-143 [1/100] ...
  ...
  (no open ports)
=========================
Scanned 4 hosts, found 4 open ports
```

- **Key line formats for parsing**:

| Line pattern | Meaning | Regex |
|---|---|---|
| `Scan level: <level> (<N> ports)` | Scan started, extract level and total port count | `Scan level: (\w+) \((\d+) ports\)` |
| `Our IP: <IP>, Netmask: <mask>` | Local IP info | `Our IP: ([\d.]+), Netmask: ([\d.]+)` |
| `Total: <N> hosts discovered` | Host discovery complete, extract host count | `Total: (\d+) hosts discovered` |
| `Scanning <N> host(s), <M> ports each (<level>)...` | Port scan phase starting | `Scanning (\d+) host.*?(\d+) ports` |
| `=== NMAP Scan Results ===` | Results header (marks start of per-host output) | literal match |
| `Host: <IP>  (<MAC>)` | New host block starts | `Host: ([\d.]+)\s+\(([0-9A-Fa-f:]+)\)` |
| `Host: <IP>  (MAC unknown)` | New host block, no MAC | `Host: ([\d.]+)\s+\(MAC unknown\)` |
| `  Scanning <IP> ports <from>-<to> [<current>/<total>] ...` | Progress: current port batch | `Scanning ([\d.]+) ports (\d+)-(\d+) \[(\d+)/(\d+)\]` |
| `  <port>/tcp  open  <service>` | Open port found | `(\d+)/tcp\s+open\s+(\S+)` |
| `  (no open ports)` | Host has no open ports | literal match |
| `  (scan stopped by user)` | User sent `stop` during scan | literal match |
| `=========================` | Results footer | literal match |
| `Scanned <N> hosts, found <M> open ports` | Final summary | `Scanned (\d+) hosts, found (\d+) open ports` |

- **Completion marker**: `strstr("Scanned") && strstr("open ports")` -- this is the last line of output.
- **Progress tracking**: The `Scanning <IP> ports <from>-<to> [<current>/<total>]` lines are emitted every 10 ports. Use `current` and `total` to calculate percentage. Combine with the host index from counting `Host:` lines vs total from the `Scanning N host(s)` line for overall progress.
- **Single-host mode**: When an IP argument is given, host discovery is skipped entirely. Output starts with `Single-host mode, skipping host discovery.` followed directly by the port scan.

---

## Bluetooth

### `scan_bt`
- **Syntax**: `scan_bt` or `scan_bt <MAC>`
- **Description**: Without MAC: one-time BLE scan (10s). With MAC: continuous tracking of one device.
- **One-time output**:
```
=== BLE Scan Results ===
Found 27 devices:

  1. 09:2B:56:0E:1C:E0  RSSI: -82 dBm
  2. 28:39:5E:3C:CD:46  RSSI: -97 dBm  Name: [TV] Samsung 7 Series (65)
  3. F1:2E:71:9F:C8:68  RSSI: -95 dBm  Name: Forerunner 935

Summary: 0 AirTags, 0 SmartTags, 27 total devices
```
- **Tracking output** (continuous):
```
F1:2E:71:9F:C8:68  RSSI: -93 dBm  Name: Forerunner 935
F1:2E:71:9F:C8:68  RSSI: -90 dBm  Name: Forerunner 935
```
- **Stop**: Send `stop`.

### `scan_airtag`
- **Syntax**: `scan_airtag`
- **Description**: Continuous AirTag/SmartTag scan, outputs counts periodically.
- **Continuous output** (every ~30s):
```
2,3
2,4
```
- **Format**: `<airtag_count>,<smarttag_count>`
- **Stop**: Send `stop`.

---

## GPS

### `gps_set`
- **Syntax**: `gps_set <module>` or `gps_set` (no args = read current)
- **Modules**: `m5` (m5stack GPS), `atgm` (ATGM336H), `external`/`ext`/`usb`/`tab`/`tab5`, `cap`/`external_cap`
- **Example**: `gps_set tab5`
- **Output** (terminated by `[GPSCFG] END`):
```
[GPSCFG] module=External
[GPSCFG] baud=9600
[GPSCFG] external=yes
[GPSCFG] position_command=set_gps_position
[GPSCFG] END
```
- **Completion marker**: `strstr("[GPSCFG] END")`.

### `set_gps_position`
- **Syntax**: `set_gps_position <lat> <lon> [alt] [acc]` or `set_gps_position` (no args = clear fix)
- **Description**: Sets external GPS fix for wardrive.
- **Output**: `"External GPS updated: Lat=... Lon=... Alt=... Acc=..."`

### `set_gps_position_cap`
- **Syntax**: `set_gps_position_cap <lat> <lon> [alt] [acc]`
- **Description**: Same as `set_gps_position` for CAP GPS feed.

### `start_gps_raw`
- **Syntax**: `start_gps_raw [baud]`
- **Description**: Prints raw NMEA sentences from GPS module.
- **Stop**: Send `stop`.

---

## Wardrive

### `start_wardrive`
- **Syntax**: `start_wardrive`
- **Description**: Standard wardrive with GPS logging to SD card.
- **Output sequence**:
  1. `"Waiting for GPS fix..."` (wait phase)
  2. `"GPS fix obtained: Lat=... Lon=..."` (fix acquired)
  3. CSV network lines: `BSSID,SSID,[security],timestamp,channel,RSSI,lat,lon,alt,acc,WIFI`
  4. `"Logged N networks to /sdcard/lab/wardrives/wN.log"`
- **GPS events**:
  - `"GPS fix lost! Pausing wardrive..."` -- GPS signal lost
  - `"GPS fix recovered: Lat=... Lon=.... Resuming wardrive."` -- GPS signal recovered
- **Stop**: Send `stop`.

### `start_wardrive_promisc`
- **Syntax**: `start_wardrive_promisc`
- **Description**: Promiscuous wardrive with D-UCB channel selection. Logs Wi-Fi APs **and** BLE devices to a WigleWifi-1.6 CSV at `/sdcard/lab/wardrives/wN.log`. Behaviour is controlled by the wardrive config block (see `get_wardrive_config` and the `set_wardrive_*` commands). Reads the config at start.
- **Startup line** (after GPS fix): echoes the active config, e.g.
```
Wardrive config: bands=wifi24,wifi5,ble channels=popular wifi_delta=5 ble_delta=15 cooldown=0s memcap=40000
Promiscuous wardrive started. Bands: wifi24,wifi5,ble, WiFi channels: 12
```
- **Periodic status**:
```
Wardrive promisc: 58 unique networks, 48 BT devices, 12 relogs, D-UCB best ch: 1 (34 visits), GPS: valid, sats: 5, dist: 1240.0m
```
  - `relogs` = re-observation rows written (RSSI/position re-logging; rises with distance while driving).
- **Notes**: Console prints first sightings live; re-logged rows go to the file only (BLE re-logs also print). With `bands=ble` only, runs a BLE-only wardrive (no channel hopping).
- **Stop**: Send `stop`.

### `start_wardrive_promisc_trace`
- **Syntax**: `start_wardrive_promisc_trace`
- **Description**: Same as `start_wardrive_promisc` plus a per-session KML track at `/sdcard/lab/wardrives/wN_track.kml`.
- **Stop**: Send `stop`.

### `get_wardrive_config`
- **Syntax**: `get_wardrive_config`
- **Description**: Prints the active wardrive configuration (stored in NVS).
- **Output** (terminated by `[WDCFG] END`):
```
[WDCFG] bands=wifi24,wifi5,ble
[WDCFG] channels=popular
[WDCFG] custom=
[WDCFG] wifi_rssi_delta=5
[WDCFG] ble_rssi_delta=15
[WDCFG] startup_cooldown=0
[WDCFG] mem_cap=40000
[WDCFG] antisurv_sensitivity=med
[WDCFG] END
```
- **Completion marker**: `strstr("[WDCFG] END")`.
- **Parse**: split each `[WDCFG] key=value` line on `=`.

### `set_wardrive_bands`
- **Syntax**: `set_wardrive_bands <wifi24|wifi5|ble>[,...]`
- **Description**: Choose which radios the wardrive uses (any comma-separated mix). `ble` only = BLE-only wardrive.
- **Examples**: `set_wardrive_bands wifi24,wifi5,ble`, `set_wardrive_bands wifi24,ble`, `set_wardrive_bands ble`
- **Output**: `Wardrive bands set: wifi24,wifi5,ble`
- **Errors**: `Unknown band '<x>'. Valid: wifi24, wifi5, ble`

### `set_wardrive_channels`
- **Syntax**: `set_wardrive_channels <popular|all|custom> [c1:c2:...]`
- **Description**: Channel selection. `popular` = 2.4 GHz 1/6/11 + 5 GHz non-DFS; `all` = every tier (default); `custom` = colon-separated list (validated, tier auto-classified).
- **Examples**: `set_wardrive_channels popular`, `set_wardrive_channels all`, `set_wardrive_channels custom 1:6:11:36:149`
- **Output**: `Wardrive channels set: custom 1:6:11:36:149`

### `set_wardrive_rssi_delta`
- **Syntax**: `set_wardrive_rssi_delta <wifi|ble> <0-50>`
- **Description**: Re-log threshold in dBm. A network/device is re-written when its RSSI changes by ≥ this (or after moving beyond GPS accuracy). `0` = legacy "log once".
- **Examples**: `set_wardrive_rssi_delta wifi 5`, `set_wardrive_rssi_delta ble 15`, `set_wardrive_rssi_delta wifi 0`
- **Output**: `Wardrive RSSI delta set: wifi=5 ble=15 (0=log once)`

### `set_wardrive_memcap`
- **Syntax**: `set_wardrive_memcap <1000-200000>`
- **Description**: Max Wi-Fi entries in RAM before the oldest already-written entries are evicted. Default 40000.
- **Output**: `Wardrive memory cap set: 40000 entries`

### `set_wardrive_cooldown`
- **Syntax**: `set_wardrive_cooldown <0-600>`
- **Description**: Drop all scans during the first N seconds of a run (after GPS fix) so the start area is not logged. `0` = off (default).
- **Output**: `Wardrive startup cooldown set: 30 s`

### `wardrive_blacklist`
- **Syntax**: `wardrive_blacklist <add|remove|list|clear> [MAC]`
- **Description**: MAC blacklist (max 64) excluded from wardrive results, exports, and anti-surveillance. Stored in NVS.
- **Examples**: `wardrive_blacklist add AA:BB:CC:DD:EE:FF`, `wardrive_blacklist list`, `wardrive_blacklist clear`
- **List output** (terminated by `Blacklist END`):
```
Blacklist: 1/64 entries
  AA:BB:CC:DD:EE:FF
Blacklist END
```

---

## Anti-Surveillance

### `start_antisurveillance`
- **Syntax**: `start_antisurveillance`
- **Description**: Detects a BLE device that moves along with you (a possible tail). Runs a continuous BLE scan + GPS; flags a device as a follower when it has been present long enough AND you have travelled far enough while it stayed in range AND it was seen in the last 30 s. Does not log networks to SD. Thresholds come from `set_antisurv_sensitivity`. Blacklisted MACs are ignored.
- **Alert line** (per newly flagged device):
```
[FOLLOWER] MAC=AA:BB:CC:DD:EE:FF name="Smart Tag" type=SmartTag rssi=-60 seen=240s travel=2100m
```
- **Parse**: `MAC=`, `name="..."`, `type=` (AirTag|SmartTag|device), `rssi=`, `seen=Ns`, `travel=Nm`.
- **Notes**: Needs a GPS fix and movement. A loop back to start can flag a stationary device near the origin — blacklist your own devices; most reliable on a one-way route.
- **Stop**: Send `stop`.

### `set_antisurv_sensitivity`
- **Syntax**: `set_antisurv_sensitivity <low|med|high>`
- **Description**: Follower-detection sensitivity. Stored in NVS; also shown by `get_wardrive_config`.

| Level | Min duration | Min travel | Randomized MACs |
|-------|-------------|-----------|-----------------|
| low   | 300 s       | 1000 m    | excluded |
| med   | 180 s       | 500 m     | excluded |
| high  | 120 s       | 300 m     | included |

- **Output**: `Anti-surveillance sensitivity: high (>=120s present, >=300m travel, randoms=yes)`

---

## SD Card Operations

### `sd_status`
- **Syntax**: `sd_status`
- **Description**: Fast SD card presence check. Does NOT initialize or mount SD — only checks if already accessible.
- **Output**: `"SD_OK"` if SD is mounted and accessible, `"SD_NONE"` otherwise.
- **Completion marker**: Either `strstr("SD_OK")` or `strstr("SD_NONE")`
- **Notes**: Returns within ~200ms. Use this instead of `list_sd` when you only need to know if SD is present.

### `list_sd`
- **Syntax**: `list_sd`
- **Description**: Lists HTML portal files on SD card.
- **Output**:
```
HTML files found on SD card:
1 PLAY.html
2 SocialMedium.html
3 ryanair.html
```
- **Header marker**: `strstr("HTML files found")`
- **Parse**: `sscanf(line, "%d %63s", &index, filename)`

### `select_html`
- **Syntax**: `select_html <index>`
- **Description**: Loads HTML file by 1-based index for portal/rogue AP/evil twin.
- **Example**: `select_html 4`
- **Output**: `"Loaded HTML file: voda.html (3315 bytes)"`

### `set_html`
- **Syntax**: `set_html <html_string>`
- **Description**: Sets portal HTML directly from command line.

### `list_dir`
- **Syntax**: `list_dir [path]`
- **Description**: Lists files in a directory. Default path: `lab/handshakes`.
- **Example**: `list_dir /sdcard/lab/handshakes`
- **Output**:
```
Files in /sdcard/lab/handshakes:
1 VMA84A66C-2.4_83C73F_91148.hccapx
2 VMA84A66C-2.4_83C73F_91148.pcap
3 AX3_2.4_3C3F64_405785.pcap
Found 6 file(s) in /sdcard/lab/handshakes
```
- **Parse**: Filter `.pcap` files, skip `.hccapx`. Strip extension for display name.

### `file_delete`
- **Syntax**: `file_delete <path>`
- **Description**: Deletes a file on SD card.
- **Example**: `file_delete lab/handshakes/sample.pcap`

### `list_ssids`
- **Syntax**: `list_ssids`
- **Description**: Lists SSIDs from `/sdcard/lab/ssids.txt` with 1-based index.
- **Output**:
```
1 WiFi1
2 TestNet
3 FreeHotspot
```
- **Error outputs**:
  - `"Failed to initialize SD card: <error>"` (SD init fail)
  - `"ssids.txt not found on SD card."` (file missing)
  - `"ssids.txt is empty."` (file empty)
- **Notes**: No explicit completion marker — output ends after last indexed line.

### `add_ssid`
- **Syntax**: `add_ssid <SSID>`
- **Description**: Appends a new SSID to `/sdcard/lab/ssids.txt`.
- **Example**: `add_ssid FreeWiFi`
- **Output**: `"Added SSID: FreeWiFi"`
- **Error outputs**:
  - `"Usage: add_ssid <SSID>"` (no argument)
  - `"SSID length must be 1-32 characters"` (length invalid)
  - `"Failed to initialize SD card: <error>"` (SD init fail)
  - `"Failed to open ssids.txt for writing"` (file open fail)
- **Notes**: SSID must be 1-32 characters. File is created if it doesn't exist.

### `remove_ssid`
- **Syntax**: `remove_ssid <index>`
- **Description**: Removes SSID at given 1-based index from `/sdcard/lab/ssids.txt`. Use `list_ssids` to see indices.
- **Example**: `remove_ssid 2`
- **Output**:
```
Removing SSID 2: TestNet
SSID removed. 2 SSIDs remaining.
```
- **Error outputs**:
  - `"Usage: remove_ssid <index>"` (no argument)
  - `"Index must be >= 1"` (invalid index)
  - `"Failed to initialize SD card: <error>"` (SD init fail)
  - `"ssids.txt not found on SD card."` (file missing)
  - `"Index N out of range (1-M)"` (index exceeds count)
  - `"Failed to open ssids.txt for writing"` (file write fail)
- **Notes**: Remaining SSIDs are reindexed after removal.

---

## Compromised Data

### `show_pass`
- **Syntax**: `show_pass [portal|evil]`
- **Description**: Prints captured passwords from SD card. Default: `portal`.
- **Evil Twin output** (`show_pass evil`):
```
"VMA84A66C-2.4", "Ruletka2022"
"BRW", "ruletka2022"
```
- **Format**: `"SSID", "password"` per line.
- **Portal output** (`show_pass portal`):
```
"AX4", "fb_user=dupa", "password=zupa"
"MojaSiec", "email=Lalala", "password=ulalala"
"FH-Raftevold-guest", "password=dupa"
```
- **Format**: `"SSID", "field1=val1", "field2=val2", ...` (variable number of fields per line).

---

## WPA-SEC Integration

### `wpasec_key`
- **Syntax**: `wpasec_key set <key>` or `wpasec_key read`
- **Description**: Set or read wpa-sec.stanev.org API key.
- **Read output (key set)**: `"WPA-SEC key: 4c96****"`
- **Read output (no key)**: `"WPA-SEC key: not set"` followed by `"Get your key at: https://wpa-sec.stanev.org/?get_key"`

### `wpasec_upload`
- **Syntax**: `wpasec_upload`
- **Description**: Uploads all `.pcap` handshakes to wpa-sec.stanev.org.
- **Prerequisite**: WiFi connected, `wpasec_key` set, SD card with handshakes.
- **Output**: `"Done: %d uploaded, %d duplicate, %d failed"`
- **Parse**: Look for `"Done:"` and extract three integers.

---

## WiGLE Integration

### `wigle_key`
- **Syntax**: `wigle_key set <api_name> <api_token>` or `wigle_key set <api_name:api_token>` or `wigle_key read` or `wigle_key clear`
- **Description**: Set, read, or clear WiGLE API credentials from NVS. If either credential is missing at boot, `/sdcard/lab/wigle.txt` is loaded and persisted to NVS; a complete NVS credential pair takes precedence.

### `wigle_upload`
- **Syntax**: `wigle_upload` or `wigle_upload [file1 file2 ...]` or `wigle_upload all`
- **Description**: Uploads wardrive files to WiGLE. No args = upload files not marked `wigle=done` in `/sdcard/lab/wardrives/upload_state.csv`; `all` ignores the local manifest.
- **Prerequisite**: WiFi connected, `wigle_key` set.
- **Output markers**: Upload state is also exposed via `upload_state` / `wardrive_files`.

### `wdgwars_key`
- **Syntax**: `wdgwars_key set <key>` or `wdgwars_key read` or `wdgwars_key clear`
- **Description**: Set, read, or clear WDGWars API key from NVS. If NVS has no key at boot, `/sdcard/lab/wdgwars.txt` is loaded and persisted to NVS; an existing NVS key takes precedence.

### `wdgwars_upload`
- **Syntax**: `wdgwars_upload` or `wdgwars_upload [file1 file2 ...]` or `wdgwars_upload all`
- **Description**: Uploads wardrive files to WDGWars. No args = upload files not marked `wdgwars=done`; `all` ignores the local manifest. Uses the v2 queued CSV upload API and local WigleWifi-1.6 preflight/sanitization. HTTP 429 opens a local circuit breaker/backoff and stops the batch.
- **Prerequisite**: WiFi connected, `wdgwars_key` set.
- **Output**: `"Done: U uploaded, S skipped, F failed, R rate_limited"`. A rate-limited stop is a controlled pause and should not be treated as a fatal command error.

### `upload_state`
- **Syntax**: `upload_state` or `upload_state clear`
- **Description**: Prints or clears `/sdcard/lab/wardrives/upload_state.csv`. Clearing does not delete wardrive files.
- **Output**:
```
[UPLOAD_STATE] BEGIN
[UPLOAD_STATE] service=wdgwars filename=w21.log size=123456 hash=8F3A91C2 status=done wifi=900 ble=334 bt=0 bad=0
[UPLOAD_STATE] END
```
Status may be `done`, `failed`, or `rate_limited`.

### `wardrive_files`
- **Syntax**: `wardrive_files`
- **Description**: Lists local wardrive files with streaming hash, local row stats, and upload status for WiGLE/WDGWars.
- **Output**:
```
[WARD_FILE] BEGIN
[WARD_FILE] filename=w21.log size=123456 hash=8F3A91C2 wifi=900 ble=334 bt=0 bad=0 wigle=done wdgwars=pending
[WARD_FILE] SUMMARY files=1 bytes=123456 rows=1234 devices=1234 wifi=900 ble=334 bt=0 bad=0 wigle_ok=1 wigle_pending=0 wigle_failed=0 wigle_rate_limited=0 wdgwars_ok=0 wdgwars_pending=1 wdgwars_failed=0 wdgwars_rate_limited=0
[WARD_FILE] END
```
Upload status may be `pending`, `done`, `failed`, or `rate_limited`. The `SUMMARY` line appears before `END`; `*_ok` means files marked `done`, and `devices` is an alias for valid data `rows`.

### `wardrive_cleanup`
- **Syntax**: `wardrive_cleanup <wigle|wdgwars|all> <pending|done|ok|failed|fail|rate_limited> [move [destination]]`
- **Description**: Dry-run or move wardrive files by local upload status. Matching files are moved to `/sdcard/lab/wardrives/uploaded/<service>/<status>/` only when `move` is passed, or to `/sdcard/lab/wardrives/uploaded/<service>/<status>/<destination>/` when a safe destination token is supplied. `ok` = `done`; `fail` = `failed`. For `all`, both WiGLE and WDGWars statuses must match.
- **Output**:
```
[WARD_CLEANUP] BEGIN service=wdgwars status=done mode=dry-run target=/sdcard/lab/wardrives/uploaded/wdgwars/done
[WARD_CLEANUP] filename=w21.log size=123456 hash=8F3A91C2 wigle=pending wdgwars=done action=would_move target=/sdcard/lab/wardrives/uploaded/wdgwars/done/w21.log
[WARD_CLEANUP] SUMMARY scanned=23 matched=4 moved=0 failed=0 dry_run=1
[WARD_CLEANUP] END
```

### `wardrive_fix`
- **Syntax**: `wardrive_fix <file>`
- **Description**: Creates a soft-fixed `.fixed.log` copy with canonical WigleWifi-1.6 headers and only valid 14-field `WIFI/BLE/BT` rows. Original file is unchanged.
- **Output**:
```
[WARD_FIX] BEGIN
[WARD_FIX] filename=w21.log output=w21.fixed.log size=120000 hash=41D2A003 kept=11880 dropped=80 wifi=9000 ble=2880 bt=0 bad=80 status=ok
[WARD_FIX] END
```

---

## Detection & Monitoring

### `start_zig_recon`
- **Syntax**: `start_zig_recon [all|11,15,20] [dwell_ms]`
- **Description**: Starts passive IEEE 802.15.4 recon on native ESP32-C5 radio. Hops channels 11-26 by default and discovers PANs/nodes for Zigbee/Thread-style networks without joining or transmitting.
- **Examples**:
  - `start_zig_recon` -- all channels, 250 ms dwell
  - `start_zig_recon all 500` -- all channels, 500 ms dwell
  - `start_zig_recon 11,15,20 250` -- selected channels
- **Output**:
```
802.15.4 recon started. channels=11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26 dwell_ms=250 mode=passive. Use 'stop' to end.
```
- **Error outputs**:
  - `FAILED: radio busy (<mode>). Use 'stop' first.`
  - `dwell_ms must be 50-5000`
  - `FAILED: zig_recon_start: <esp_err>`
- **Stop**: Send `stop`.
- **Notes**: Exclusive radio mode. Refuses to start while Wi-Fi sniffing/wardrive/BLE scan/nRF24 or another active operation owns the radio.

### `zig_recon_status`
- **Syntax**: `zig_recon_status`
- **Description**: Prints human-readable recon status and one machine-readable `[ZIG] status` line.
- **Output**:
```
802.15.4 Recon: running
Channel: 11  Packets: 55  Networks: 4  Dropped: 0
Hopping: 11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26 dwell=250ms  Mode: passive
[ZIG] status active=1 channel=11 packets=55 pans=4 nodes=6 dropped=0 dwell_ms=250 channels=0x07fff800
[ZIG] END
```
- **Completion marker**: `"[ZIG] END"`.

### `zig_recon_list`
- **Syntax**: `zig_recon_list [all]`
- **Description**: Lists discovered 802.15.4 PANs. Without `all`, hides broadcast PAN `0xFFFF` and prints at most 20 network PANs to avoid UART flooding.
- **Output**:
```
PAN       Proto       Ch                 Nodes  Packets  RSSI  Last
0x1A62    Zigbee      11,15                  6       48   -63  2s
[ZIG] pan id=0x1A62 kind=network proto=zigbee confidence=probable channels=0x00008800 nodes=6 packets=48 best_rssi=-63 last_rssi=-67 last_seen_ms=123456 age_ms=2000
[ZIG] END
```
- **Machine fields**: `id`, `kind`, `proto`, `confidence`, `channels`, `nodes`, `packets`, `best_rssi`, `last_rssi`, `last_seen_ms`, `age_ms`.
- **Notes**: `kind=broadcast` is used for `PAN 0xFFFF`; it appears only with `zig_recon_list all`.
- **Protocol tokens**: `ieee802154`, `zigbee`, `thread`, `matter_thread`. `matter_thread` is a best-effort passive hint and should be displayed as `Matter/Thread?` unless later evidence confirms it.
- **Completion marker**: `"[ZIG] END"`.

### `zig_recon_nodes`
- **Syntax**: `zig_recon_nodes <pan_id|all>`
- **Description**: Lists nodes seen in a PAN, or all nodes across all PANs for UI sync.
- **Example**: `zig_recon_nodes 0x1A62`
- **Output**:
```
PAN 0x1A62  Proto: Zigbee  Channels: 11,15  Packets: 48
ADDR      ROLE         PKTS  RSSI  LAST
0x0000    Coordinator    42   -63  2s
[ZIG] node pan=0x1A62 addr_type=short short=0x0000 ext=na role=coordinator packets=42 last_rssi=-63 best_rssi=-58 avg_rssi=-61 lqi=172 sample_count=42 last_channel=11 vendor=na device_hint=na battery=na last_seen_ms=123456 age_ms=2000
[ZIG] END
```
- **Machine fields**: `pan`, `addr_type`, `short`, `ext`, `role`, `packets`, `last_rssi`, `best_rssi`, `avg_rssi`, `lqi`, `sample_count`, `last_channel`, `vendor`, `device_hint`, `battery`, `last_seen_ms`, `age_ms`.
- **Notes**: `last_seen_ms` is device uptime timestamp in milliseconds; `age_ms` is the age of the observation and is the preferred UI field for "last seen".
- **Signal notes**: `best_rssi`, `avg_rssi`, `sample_count`, `last_channel`, and `lqi` are passive signal hints, not distance. `vendor`, `device_hint`, and `battery` are `na` unless a later parser can prove them from observed frames.
- **Locate/track UI guidance**: A UI may pin a node and refresh this line from repeated `zig_recon_nodes all` polling. Use `last_rssi`, `avg_rssi`, `best_rssi`, `lqi`, `sample_count`, `last_channel`, and `age_ms` to show a passive "Locate" panel. Suggested trend labels:
  - `warming up`: `sample_count < 2`
  - `closer`: `last_rssi >= avg_rssi + 4`
  - `farther`: `last_rssi <= avg_rssi - 4`
  - `steady`: otherwise
  These labels mean relative signal trend only. Do not display meters or claim physical distance from RSSI.
- **Locate UX contract**: selecting a node starts passive locate for that node; selecting the same node again stops locate. Selecting another PAN/network or leaving/collapsing the expanded network view must clear the current locate target.
- **Addressing**: `addr_type=short` means `short` is a real 16-bit node address. `addr_type=ext` means no short address was present; use `ext` as the node key and display address. `short=na` must not be rendered as `0xFFFF`.
- **Completion marker**: `"[ZIG] END"`.

### `zig_recon_clear`
- **Syntax**: `zig_recon_clear`
- **Description**: Clears current 802.15.4 recon counters and discovered PAN/node tables.
- **Output**:
```
[ZIG] cleared
[ZIG] END
```
- **Completion marker**: `"[ZIG] END"`.

### `deauth_detector`
- **Syntax**: `deauth_detector` or `deauth_detector [index1 index2 ...]`
- **Description**: Detects deauth frames. No args = all channels; with indices = selected channels.
- **Continuous output**:
```
[DEAUTH] CH: 6 | AP: MyNetwork (AA:BB:CC:DD:EE:FF) | RSSI: -45
[DEAUTH] CH: 1 | AP: AX3_2.4 (30:AA:E4:3C:3F:64) | RSSI: -72
```
- **Parse fields**: `CH:` (int), `AP:` (string until `(`), BSSID (inside parens), `RSSI:` (int).
- **Stop**: Send `stop`.

### `start_ap_locator`
- **Syntax**: `start_ap_locator`
- **Description**: Locks onto the channel of exactly one AP selected with `select_networks`, listens for its beacon frames, and prints RSSI once per second.
- **Prerequisite**: Exactly one selected network from prior `scan_networks` + `select_networks <index>`.
- **Continuous output**:
```
[AP Locator] CH: 6 | AP: MyNetwork (AA:BB:CC:DD:EE:FF) | RSSI: -47 dBm | beacons: 10
[AP Locator] CH: 6 | AP: MyNetwork (AA:BB:CC:DD:EE:FF) | RSSI: N/A | no beacon
```
- **Notes**:
  - Uses the selected AP's last scanned primary channel; no channel hopping.
  - If no matching beacon is seen during the last second, it still prints a status line with `RSSI: N/A | no beacon`.
  - Conflicts with other monitoring or attack modes that take over WiFi promiscuous mode or channel control.
- **Stop**: Send `stop`.

### `packet_monitor`
- **Syntax**: `packet_monitor <channel>`
- **Description**: Monitors packets per second on a specific channel (1-14).
- **Stop**: Send `stop`.

### `channel_view`
- **Syntax**: `channel_view`
- **Description**: Continuously scans and prints WiFi channel utilization.
- **Stop**: Send `stop`.

---

## Settings

### `channel_time`
- **Syntax**: `channel_time set <min|max> <ms>` or `channel_time read <min|max>`
- **Description**: Sets or reads scan dwell time per channel.
- **Examples**: `channel_time set min 100`, `channel_time set max 300`, `channel_time read min`
- **Constraints**: 100-1500 ms, min < max.

### `vendor`
- **Syntax**: `vendor set <on|off>` or `vendor read`
- **Description**: Enables/disables MAC vendor lookup in scan results.

### `display`
- **Syntax**: `display set <auto|ssd1306|sh1107|sh1106|unit_lcd>` or `display read`
- **Description**: Sets or reads display mode for attached OLED/LCD.

### `boot_button`
- **Syntax**: `boot_button read` | `boot_button list` | `boot_button set <short|long> <command[, command...]>` | `boot_button status <short|long> <on|off>`
- **Description**: Configures boot button press actions. Multiple commands can be chained with commas, for example `list_sd, select_html 1, start_portal FreeWifi`.
- **Allowed commands**: `start_blackout`, `start_sniffer_dog`, `channel_view`, `packet_monitor`, `start_sniffer`, `scan_networks`, `start_gps_raw`, `start_wardrive`, `deauth_detector`, `list_sd`, `select_html`, `start_portal`

### `led`
- **Syntax**: `led set <on|off>` | `led level <1-100>` | `led read`
- **Description**: Controls status LED brightness.

---

## OTA Updates

### `ota_check`
- **Syntax**: `ota_check` or `ota_check [latest|<tag>]`
- **Description**: Checks GitHub for firmware update and applies it.
- **Prerequisite**: WiFi connected.

### `ota_list`
- **Syntax**: `ota_list`
- **Description**: Lists recent GitHub releases (first 5).
- **Output**: `"OTA[n]: <tag> (main|dev) <date> <title>"`
- **Prerequisite**: WiFi connected.

### `ota_channel`
- **Syntax**: `ota_channel` or `ota_channel [main|dev]`
- **Description**: Gets or sets OTA update channel.

### `ota_info`
- **Syntax**: `ota_info`
- **Description**: Shows OTA partition info (boot/running/next partition, APP slot details).

### `ota_boot`
- **Syntax**: `ota_boot <ota_0|ota_1>`
- **Description**: Sets boot partition and reboots.

---

## System

### `stop`
- **Syntax**: `stop`
- **Description**: Stops ALL running operations (scans, attacks, sniffers, wardrives, etc.).
- **Output**: `"Stop command received - stopping all operations..."`
- **Notes**: This is the universal cancel command. Always send before starting a new operation if one might be running.

### `reboot`
- **Syntax**: `reboot`
- **Description**: Reboots the ESP32C5 device.

### `ping`
- **Syntax**: `ping`
- **Description**: Connectivity test.
- **Output**: `"pong"`
- **Notes**: Use to verify UART connection is alive.

### `download`
- **Syntax**: `download`
- **Description**: Reboots into ROM download (UART flashing) mode.

### `version`
- **Syntax**: `version`
- **Description**: Prints the current JanOS firmware version.
- **Output**: `"JanOS version: X.Y.Z"`
- **Notes**: Use to check which firmware version is running on the device.

### `help`
- **Syntax**: `help` or `help <command>`
- **Description**: Lists all commands or shows help for a specific command.

---

## nRF24 Jammer

Requires an external nRF24L01+ module wired to the ESP32C5. It shares the SD card's SPI2 bus (SCK=GPIO6, MOSI=GPIO7, MISO=GPIO2) and uses dedicated CSN=GPIO3 and CE=GPIO4 (the control lines previously used for a CC1101). A clean 3.3 V supply (e.g. AMS1117 + 100 uF capacitor) is recommended for the PA+LNA variant.

### `init_nrf24`
- **Syntax**: `init_nrf24`
- **Description**: Initializes the SPI device and probes the single nRF24 module (writes/reads back the RF_CH register). Run this once before `start_jammer24`. Safe to re-run.
- **Output (detected)**: `"[NRF24] detected (init OK) - SCK=6 MOSI=7 MISO=2 CS=3 CE=4"`
- **Output (not detected)**: `"[NRF24] not detected - check wiring/power (3.3V + cap)"`
- **Completion marker**: any line containing `"[NRF24]"`.

### `start_jammer24`
- **Syntax**: `start_jammer24 [ble|bt|wifi|drone|all]`
- **Description**: Starts the nRF24 jammer. The band argument is optional and defaults to `all` (full 2.4 GHz constant-carrier sweep, channels 0-125). Bands:
  - `ble` - BLE advertising channels (2/26/80), packet spam.
  - `bt` - Bluetooth channel list, constant carrier.
  - `wifi` - sweep across all WiFi channels, packet spam.
  - `drone` - constant-carrier sweep 0-125 (RC / drone 2.4 GHz).
  - `all` - full 2.4 GHz constant-carrier sweep 0-125 (default).
- **Output (success)**: `"nRF24 jammer started (band=<name>). Use 'stop' to end."`
- **Output (failure)**: `"[NRF24] failed to start - run init_nrf24 first, or jammer already running"` or `"[NRF24] unknown band '<arg>' (use ble|bt|wifi|drone|all)"`
- **Prerequisite**: `init_nrf24` must report the module as detected.
- **Completion marker**: `"nRF24 jammer started"`.
- **Notes**: Stopped with `stop`. While jamming, WiFi throughput on the ESP32C5 will degrade until stopped.

### `stop`
- The universal `stop` command (see System) also halts an active nRF24 jammer and returns the radio to idle.
