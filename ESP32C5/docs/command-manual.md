# JanOS / MonsterC5 — Command Manual

Complete operator manual for the JanOS firmware running on the ESP32‑C5 ("Monster").
Part 1 covers the **new Wardrive 2.0 and Anti‑Surveillance** commands in detail.
Part 2 is the **full catalog** of every other command.

---

## How to invoke commands

JanOS exposes a plain‑text CLI over **UART (115200 baud, 8N1)** and over the USB serial console.

- Type a command and press **Enter**. Over a raw UART link, terminate each command with `\r\n`.
- Responses are **line‑based text**. Many long‑running commands stream output until stopped.
- **`stop`** is the universal cancel — it halts every running operation (scan, attack, wardrive, anti‑surveillance, jammer…). Always send it before starting a new mode if one might be active.
- **`help`** lists all commands; **`help <command>`** shows help for one.
- All indices are **1‑based**.
- Tab completion and command history (UP/DOWN) are available on the interactive console.

Configuration commands persist their settings in **NVS** (survive reboot). The wardrive engine reads its configuration at start, so the pattern is: *configure once, then `start_wardrive_promisc`*.

---

# Part 1 — Wardrive 2.0 (new)

The promiscuous wardrive (`start_wardrive_promisc`) is a Kismet‑style scanner that hops Wi‑Fi channels with a **D‑UCB** (discounted upper‑confidence‑bound) algorithm, logs Wi‑Fi APs **and** BLE devices to a WigleWifi‑1.6 CSV on the SD card, and records a KML track. The behaviour below is controlled by a configuration block stored in NVS and shown by `get_wardrive_config`.

## How the engine works

- **Bands** — the radio can scan any mix of 2.4 GHz Wi‑Fi, 5 GHz Wi‑Fi and Bluetooth LE. The band selection maps to the ESP‑IDF Wi‑Fi *band mode* (2.4‑only / 5‑only / auto) and is restored to *auto* when the run stops.
- **Channels** — `popular` (1/6/11 + the common 5 GHz channels), `all` (every tier including DFS), or a `custom` list.
- **Re‑logging (RSSI/position delta)** — a network is re‑written to the CSV whenever its signal changes by ≥ the configured delta **or** you have travelled far enough since the last row. This produces the multiple observations WiGLE needs to trilaterate AP positions. Set the delta to `0` for legacy "log once" behaviour.
- **Memory cap** — the in‑RAM table is capped; when full, the oldest **already‑written** entries are evicted (their data is safely on the SD card), so a drive can run indefinitely.
- **Startup cooldown** — drop everything seen during the first N seconds so your starting location (e.g. home) is not logged.
- **Blacklist** — exclude your own devices by MAC from results and exports.

Output file: `/sdcard/lab/wardrives/wN.log` (N auto‑increments). Console shows first sightings live; re‑logs go to the file.

---

### `start_wardrive_promisc`
- **Syntax**: `start_wardrive_promisc`
- **Description**: Starts the promiscuous wardrive using the current config. Waits for a GPS fix, then logs Wi‑Fi + BLE to SD with a KML track.
- **Startup log** (shows the active config):
```
Wardrive config: bands=wifi24,wifi5,ble channels=popular wifi_delta=5 ble_delta=15 cooldown=0s memcap=40000
...
Promiscuous wardrive started. Bands: wifi24,wifi5,ble, WiFi channels: 12
```
- **Periodic status**:
```
Wardrive promisc: 58 unique networks, 48 BT devices, 12 relogs, D-UCB best ch: 1 (34 visits), GPS: valid, sats: 5, dist: 1240.0m
```
- **Stop**: `stop`.

### `start_wardrive_promisc_trace`
- **Syntax**: `start_wardrive_promisc_trace`
- **Description**: Same as `start_wardrive_promisc` but also writes a per‑session KML track at `/sdcard/lab/wardrives/wN_track.kml`.

### `start_wardrive`
- **Syntax**: `start_wardrive`
- **Description**: The classic (non‑promiscuous) wardrive — a scan‑based GPS logger. Simpler than the promisc engine; the config block above does not apply.
- **Stop**: `stop`.

### `get_wardrive_config`
- **Syntax**: `get_wardrive_config`
- **Description**: Prints the active wardrive configuration. Machine‑parseable, terminated by `[WDCFG] END`.
- **Output**:
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

### `set_wardrive_bands`
- **Syntax**: `set_wardrive_bands <wifi24|wifi5|ble>[,...]`
- **Description**: Choose which radios the wardrive uses. Any combination, comma‑separated. Selecting only `ble` runs a BLE‑only wardrive (no channel hopping).
- **Examples**:
  - `set_wardrive_bands wifi24,wifi5,ble` — everything (default)
  - `set_wardrive_bands wifi24,ble` — 2.4 GHz + Bluetooth
  - `set_wardrive_bands wifi5` — 5 GHz only
  - `set_wardrive_bands ble` — Bluetooth only
- **Output**: `Wardrive bands set: wifi24,wifi5,ble`

### `set_wardrive_channels`
- **Syntax**: `set_wardrive_channels <popular|all|custom> [c1:c2:...]`
- **Description**: Channel selection.
  - `popular` — 2.4 GHz 1/6/11 + 5 GHz non‑DFS (fast cycle, best for driving)
  - `all` — every tier including 5 GHz DFS (default)
  - `custom` — explicit colon‑separated list; channels are validated and classified automatically (≤14 → 2.4, DFS set → DFS, else 5 GHz)
- **Examples**:
  - `set_wardrive_channels popular`
  - `set_wardrive_channels all`
  - `set_wardrive_channels custom 1:6:11:36:149`
- **Output**: `Wardrive channels set: custom 1:6:11:36:149`

### `set_wardrive_rssi_delta`
- **Syntax**: `set_wardrive_rssi_delta <wifi|ble> <0-50>`
- **Description**: Re‑log threshold in dBm. A network/device is re‑written when its signal changes by at least this much (or after you move beyond GPS accuracy). `0` disables re‑logging (legacy "log once").
- **Examples**:
  - `set_wardrive_rssi_delta wifi 5` — default for Wi‑Fi
  - `set_wardrive_rssi_delta ble 15` — default for BLE
  - `set_wardrive_rssi_delta wifi 0` — log each Wi‑Fi AP only once
- **Output**: `Wardrive RSSI delta set: wifi=5 ble=15 (0=log once)`

### `set_wardrive_memcap`
- **Syntax**: `set_wardrive_memcap <1000-200000>`
- **Description**: Maximum Wi‑Fi entries held in RAM before the oldest already‑written entries are evicted. Default 40000 (≈2.5 MB PSRAM). A normal drive never reaches this; it is a safety net for marathon sessions.
- **Example**: `set_wardrive_memcap 40000`
- **Output**: `Wardrive memory cap set: 40000 entries`

### `set_wardrive_cooldown`
- **Syntax**: `set_wardrive_cooldown <0-600>`
- **Description**: Drop all scans during the first N seconds of a run (counted after the GPS fix), so your start area is not logged. `0` = off (default).
- **Example**: `set_wardrive_cooldown 30`
- **Output**: `Wardrive startup cooldown set: 30 s`

### `wardrive_blacklist`
- **Syntax**: `wardrive_blacklist <add|remove|list|clear> [MAC]`
- **Description**: Maintain a MAC blacklist (max 64). Blacklisted devices are excluded from both Wi‑Fi and BLE wardrive results, exports, and anti‑surveillance detection. Stored in NVS.
- **Examples**:
  - `wardrive_blacklist add AA:BB:CC:DD:EE:FF`
  - `wardrive_blacklist remove AA:BB:CC:DD:EE:FF`
  - `wardrive_blacklist list`
  - `wardrive_blacklist clear`
- **List output** (terminated by `Blacklist END`):
```
Blacklist: 1/64 entries
  AA:BB:CC:DD:EE:FF
Blacklist END
```

### Recommended driving profile
```
set_wardrive_bands wifi24,wifi5,ble
set_wardrive_channels popular
set_wardrive_rssi_delta wifi 5
start_wardrive_promisc
```

---

# Anti‑Surveillance (new)

Detects a BLE device that **moves along with you** — a possible tail. It runs a continuous BLE scan, tracks how long each device stays in range and how far you travel while it does, and raises an alert when a device qualifies as a follower. It does **not** log networks to SD; it is a live detector.

## How it works

For every BLE device it records first/last seen time, an origin position, and the maximum distance you have travelled from that origin while the device stayed visible. A device is flagged as a **follower** when all of:
1. it has been present for at least *min‑duration* seconds, **and**
2. you have travelled at least *min‑distance* metres since first seeing it, **and**
3. it was seen within the last 30 s (still in range).

Randomized (locally‑administered) BLE MACs rotate ~every 15 minutes and can't be tracked long‑term; the **sensitivity** setting decides whether to consider them. Blacklisted MACs (your own devices) are ignored.

**Sensitivity thresholds**

| Level | Min duration | Min travel | Randomized MACs |
|-------|-------------|-----------|-----------------|
| low   | 300 s       | 1000 m    | excluded (stable only) |
| med   | 180 s       | 500 m     | excluded |
| high  | 120 s       | 300 m     | included |

**Limitation**: driving a loop back to your start can flag a stationary device near the origin (e.g. your home router) once you return into range. Mitigation: blacklist your own devices; detection is most reliable on a one‑way route. This is a pattern detector, not proof.

---

### `start_antisurveillance`
- **Syntax**: `start_antisurveillance`
- **Description**: Starts follower detection (BLE scan + GPS). Requires a GPS fix and movement to be useful.
- **Alert line** (per newly flagged device):
```
[FOLLOWER] MAC=AA:BB:CC:DD:EE:FF name="Smart Tag" type=SmartTag rssi=-60 seen=240s travel=2100m
```
- **OLED/LED**: shows device/follower counts; flashes red and `! FOLLOWER !` on a detection.
- **Stop**: `stop`.

### `set_antisurv_sensitivity`
- **Syntax**: `set_antisurv_sensitivity <low|med|high>`
- **Description**: Sets follower‑detection sensitivity (see table). Stored in NVS; also shown by `get_wardrive_config`.
- **Example**: `set_antisurv_sensitivity high`
- **Output**: `Anti-surveillance sensitivity: high (>=120s present, >=300m travel, randoms=yes)`

---

# Part 2 — Full command catalog

## WiFi scanning

### `scan_networks`
- `scan_networks` — background Wi‑Fi scan on all channels. Results auto‑print as CSV; wait for `Scan results printed`. CSV: `"index","SSID","","BSSID","channel","security","RSSI","band"`. Wardrive must be stopped first.

### `show_scan_results`
- `show_scan_results` — reprint the last scan results (same CSV).

### `inspect_network`
- `inspect_network <index>` — passively capture beacons from one AP (~1.5 s) and report MFP (802.11w) capability/required flags and AP uptime (TSF). Output prefixed `[INSPECT]`.

### `select_networks` / `unselect_networks`
- `select_networks <i1> [i2] ...` — select APs by index for targeted operations, e.g. `select_networks 1 3 5`.
- `unselect_networks` — stop operations and clear the selection (keeps scan results).

## Station selection

- `select_stations <MAC1> [MAC2] ...` — select specific client MACs for targeted deauth.
- `unselect_stations` — clear station selection (revert to broadcast).

## Sniffing & monitoring

- `start_sniffer` — client sniffer; sniffs selected networks or scans first. Streams `Sniffer packet count: N`.
- `start_sniffer_noscan` — sniffer using existing scan results (no new scan).
- `show_sniffer_results` / `show_sniffer_results_vendor` — APs with associated clients (vendor variant adds MAC vendor names).
- `clear_sniffer_results` — clear clients/probes/counters.
- `show_probes` / `show_probes_vendor` — captured probe requests (SSID + source MAC).
- `list_probes` / `list_probes_vendor` — probe SSIDs with 1‑based index (for `start_karma`).
- `sniffer_debug <0|1>` — toggle verbose sniffer logging.
- `start_sniffer_dog` — capture AP‑STA pairs and immediately send targeted deauth (`[SnifferDog #N] DEAUTH sent: ...`).
- `deauth_detector [i1 i2 ...]` — detect deauth frames (all channels, or selected). Output `[DEAUTH] CH: .. | AP: .. (BSSID) | RSSI: ..`.
- `start_ap_locator` — lock onto one selected AP's channel and print its RSSI once per second (`[AP Locator] ...`). Needs exactly one selected network.
- `packet_monitor <channel>` — packets‑per‑second on one channel (1‑14).
- `channel_view` — continuous Wi‑Fi channel utilization.
- `start_pcap [radio|net]` — capture to PCAP on SD. `radio` = promiscuous all‑frame capture; `net` = requires `wifi_connect`, captures + ARP‑spoof MITM. Stop with `stop`; saves to `/sdcard/lab/pcaps/sniff_N.pcap`.

## Attacks

- `start_deauth` — deauth selected networks. Prereq `select_networks`.
- `start_evil_twin` — clone first selected AP + deauth others, captive portal harvests password. Optional `select_html`.
- `sae_overflow` — WPA3 SAE client‑overflow on exactly one selected AP.
- `start_handshake` — capture WPA handshakes (targeted with selection, else scan‑and‑attack loop). Saves PCAP/HCCAPX.
- `save_handshake` — manually save a captured complete 4‑way handshake.
- `start_blackout` — scan all networks every 3 min and deauth everything.
- `start_beacon_spam "SSID1" "SSID2" ...` — broadcast fake beacons (max 32 SSIDs, 1‑32 chars each).
- `start_beacon_spam_ssids` — same, loading SSIDs from `/sdcard/lab/ssids.txt`.
- `start_portal <SSID>` — open captive portal (no password to join). Optional `select_html`.
- `start_rogueap <SSID> <password>` — WPA2 rogue AP with captive portal (password 8‑63 chars).
- `start_karma <index>` — Karma attack using a probe‑list SSID (`list_probes` for indices). Needs `select_html`.
- `start_darksword` — advanced attack/exfil module. Run `help start_darksword` for current options. Stop with `stop`.

All attacks stop with `stop`.

## WiFi connection (STA)

- `wifi_connect <SSID> [Password|--saved] [ota] [<IP> <Mask> <GW> [DNS1] [DNS2]]` — join an AP. If password is omitted, tries open auth. Use `--saved` to explicitly load a saved password from `/sdcard/lab/eviltwin.txt` or `/sdcard/lab/portals.txt`. `ota` triggers an update check; optional static IP. Success marker `SUCCESS`, failure `FAILED`/`TIMEOUT`.
- `wifi_disconnect` — disconnect from the current AP.

## ARP & LAN

- `list_hosts` / `list_hosts_vendor` — ARP‑scan the LAN and list `IP -> MAC` (vendor variant adds names). Prereq `wifi_connect`.
- `arp_ban <MAC> [IP]` — ARP‑poison a host off the network. Prereq `wifi_connect`. Stop with `stop`.
- `start_nmap [quick|medium|heavy] [IP]` — TCP port scanner. Discovers hosts (ARP+ICMP) then probes ports. `quick`=20, `medium`=50, `heavy`=100 ports. Optional single IP skips discovery. Prereq `wifi_connect`. Stop with `stop`.

## Bluetooth

- `scan_bt` — one‑time 10 s BLE scan (lists devices, AirTag/SmartTag counts).
- `scan_bt <MAC>` — continuous RSSI tracking of one device. Stop with `stop`.
- `scan_airtag` — continuous AirTag/SmartTag scan; prints `<airtags>,<smarttags>` every ~30 s. Stop with `stop`.

(See Part 1 for `start_antisurveillance`.)

## 802.15.4 Recon

- `start_zig_recon [all|11,15,20] [dwell_ms]` — passive IEEE 802.15.4 recon on ESP32-C5 native radio. Default is all channels 11-26 with 250 ms dwell. Refuses to start if another radio operation is active.
- `zig_recon_status` — human status plus machine line, terminated by `[ZIG] END`.
- `zig_recon_list [all]` — list discovered PANs. Without `all`, hides broadcast PAN `0xFFFF` and limits output to 20 network PANs. Each PAN also emits `[ZIG] pan ...`.
- `zig_recon_nodes <pan_id|all>` — list nodes for a PAN or all nodes for UI sync, emits `[ZIG] node ...`.
- `zig_recon_clear` — clear current recon counters and PAN/node tables.
- `stop` — stops recon and releases the 802.15.4 radio.

Protocol tokens are `ieee802154`, `zigbee`, `thread`, and `matter_thread`. `matter_thread` is a passive best-effort hint and should be shown as `Matter/Thread?`, not as confirmed Matter.

Machine output example:
```
[ZIG] status active=1 channel=11 packets=55 pans=4 nodes=6 dropped=0 dwell_ms=250 channels=0x07fff800
[ZIG] pan id=0x1A62 kind=network proto=zigbee confidence=probable channels=0x00008800 nodes=6 packets=48 best_rssi=-63 last_rssi=-67 last_seen_ms=123456 age_ms=2000
[ZIG] node pan=0x1A62 addr_type=short short=0x0000 ext=na role=coordinator packets=42 last_rssi=-63 best_rssi=-58 avg_rssi=-61 lqi=172 sample_count=42 last_channel=11 vendor=na device_hint=na battery=na last_seen_ms=123456 age_ms=2000
[ZIG] END
```

`zig_recon_nodes` keeps legacy fields and appends richer passive-recon metadata for UI use. `best_rssi`, `avg_rssi`, `sample_count`, `last_channel`, and `lqi` are signal-quality hints, not distance. Unknown metadata is emitted as `na`; do not infer vendor, device type, or battery unless a later parser can prove it from observed frames.

Recon PAN/node tables and CLI snapshots are allocated in PSRAM. The RX queue remains a normal FreeRTOS queue because it is used from the IEEE 802.15.4 RX ISR.

## GPS

- `gps_set [module]` — set/read GPS module: `m5`, `atgm`, `external`/`ext`/`usb`/`tab`/`tab5`, `cap`/`external_cap`. No arg = read. Machine-readable output is terminated by `[GPSCFG] END`.
- `set_gps_position <lat> <lon> [alt] [acc]` — provide an external GPS fix (no arg = clear). Used when GPS module is an external feed.
- `set_gps_position_cap <lat> <lon> [alt] [acc]` — same for the CAP feed.
- `start_gps_raw [baud]` — print raw NMEA sentences. Stop with `stop`.

## SD card

- `sd_status` — fast presence check; `SD_OK` or `SD_NONE` (~200 ms, no mount).
- `list_sd` — list HTML portal files (`N filename.html`). Header `HTML files found`.
- `select_html <index>` — load an HTML file by index for portal / rogue AP / evil twin.
- `set_html <html_string>` — set portal HTML directly from the command line.
- `list_dir [path]` — list files in a directory (default `lab/handshakes`).
- `file_delete <path>` — delete a file, e.g. `file_delete lab/handshakes/sample.pcap`.
- `list_ssids` (alias `list_ssid`) — list SSIDs from `/sdcard/lab/ssids.txt` with index.
- `add_ssid <SSID>` — append an SSID (1‑32 chars) to the file.
- `remove_ssid <index>` — remove SSID by index; remaining are reindexed.

## Captured data & uploads

- `show_pass [portal|evil]` — print captured passwords from SD. `evil` → `"SSID","password"`; `portal` → `"SSID","field=val",...`.
- `wpasec_key set <key>` / `wpasec_key read` — wpa‑sec.stanev.org API key.
- `wpasec_upload` — upload all `.pcap` handshakes to wpa‑sec. Prereq WiFi + key. Result `Done: U uploaded, D duplicate, F failed`.
- `wigle_key set <name> <token>` (or `set <name:token>`) / `wigle_key read` / `wigle_key clear` — WiGLE credentials. `clear` removes the NVS-stored credentials. When either credential is missing in NVS at boot, `/sdcard/lab/wigle.txt` is loaded and saved to NVS; a complete NVS credential pair takes precedence.
- `wigle_upload [file ...|all]` — upload wardrive files to WiGLE. No args = only files not marked `wigle=done` in `/sdcard/lab/wardrives/upload_state.csv`; `all` ignores the local manifest. Prereq WiFi + key.
- `wdgwars_key set <key>` / `wdgwars_key read` / `wdgwars_key clear` plus `wdgwars_upload [file ...|all]` — WardrivingWars integration. `clear` removes the NVS-stored key. When no key is present in NVS at boot, `/sdcard/lab/wdgwars.txt` is loaded and saved to NVS; an existing NVS key takes precedence. Uses `X-API-Key` and multipart field `file`; accepts `.log`, `.csv`, and `.gz` wardrive files through the v2 queued upload API (max 60 MB). Before upload, validates the WigleWifi-1.6 schema and prints local `wifi/ble/bt/bad` row counts; if needed, uploads a temporary sanitized copy with bad rows removed and canonical headers added, leaving the original file unchanged. No args = only files not marked `wdgwars=done`; `all` ignores the local manifest. HTTP 429 opens a local circuit breaker/backoff and stops the batch to avoid Cloudflare spam. After upload, checks `/api/upload-history?limit=5` and prints the import counters when the file appears there.
- `upload_state [clear]` — print or clear the local upload manifest. Output is marker-delimited with `[UPLOAD_STATE] ...` lines for ADV/Tab5 parsing.
- `wardrive_files` — list local wardrive files with `size`, `hash`, `wifi/ble/bt/bad`, and `wigle`/`wdgwars` status. Output is marker-delimited with `[WARD_FILE] ...` lines and includes a final `[WARD_FILE] SUMMARY ...` before `END` with total `files/bytes/rows/wifi/ble/bt/bad` plus per-service `ok/pending/failed/rate_limited` counts.
- `wardrive_cleanup <wigle|wdgwars|all> <pending|done|ok|failed|fail|rate_limited> [move [destination]]` — dry-run or move matching wardrive files to `/sdcard/lab/wardrives/uploaded/<service>/<status>/`, or with a safe destination token to `/sdcard/lab/wardrives/uploaded/<service>/<status>/<destination>/`. Without `move`, only prints `[WARD_CLEANUP] ... action=would_move`. `ok` = `done`, `fail` = `failed`. `all done` matches only files done for both WiGLE and WDGWars.
- `wardrive_fix <file>` — create a soft-fixed `.fixed.log` copy with canonical WigleWifi-1.6 headers and only valid 14-field `WIFI/BLE/BT` rows. The original file is unchanged. Output is marker-delimited with `[WARD_FIX] ...` lines.

## Settings

- `channel_time set <min|max> <ms>` / `channel_time read <min|max>` — scan dwell per channel (100‑1500 ms, min<max).
- `vendor set <on|off>` / `vendor read` — MAC vendor lookup in results.
- `display set <auto|ssd1306|sh1107|sh1106|unit_lcd>` / `display read` — OLED/LCD type.
- `led set <on|off>` / `led level <1-100>` / `led read` — status LED.
- `boot_button read|list|set <short|long> <cmd[,cmd...]>|status <short|long> <on|off>` — map boot‑button presses to commands (comma‑chained).

## OTA updates

- `ota_check [latest|<tag>]` — check GitHub and apply a firmware update. Prereq WiFi.
- `ota_list` — list recent releases (`OTA[n]: <tag> (main|dev) <date> <title>`).
- `ota_channel [main|dev]` — get/set update channel.
- `ota_info` — partition info (boot/running/next).
- `ota_boot <ota_0|ota_1>` — set boot partition and reboot.

## nRF24 jammer (external module)

Requires an nRF24L01+ wired to SPI2 (SCK=6, MOSI=7, MISO=2, CSN=3, CE=4).

- `init_nrf24` — initialize and probe the module (run once before jamming). `[NRF24] detected ...` or `[NRF24] not detected ...`.
- `start_jammer24 [ble|bt|wifi|drone|all]` — start the jammer (default `all` = full 2.4 GHz sweep). Prereq `init_nrf24` detected. Stop with `stop`.

## System

- `stop` — stop ALL running operations. The universal cancel.
- `reboot` — reboot the device.
- `ping` — connectivity test; replies `pong`.
- `version` — print firmware version (`JanOS version: X.Y.Z`).
- `download` — reboot into ROM download (UART flashing) mode.
- `help [command]` — list all commands or show help for one.

---

*Generated for the MonsterC5 / ESP32‑C5 build. New in this build: the `set_wardrive_*`, `wardrive_blacklist`, `get_wardrive_config`, `start_antisurveillance` and `set_antisurv_sensitivity` commands (Part 1).*
