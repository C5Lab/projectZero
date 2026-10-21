# JanOS / MonsterC5 — Command Manual

Complete operator manual for the JanOS firmware running on the ESP32‑C5 ("Monster").
Part 1 covers the **new Wardrive 2.0 and Anti‑Surveillance** commands in detail.
Part 2 is the **full catalog** of every other command.

---

## How to invoke commands

JanOS exposes a CLI over **UART (115200 baud after boot, 8N1)** and over the USB serial console.

- Type a command and press **Enter**. Over a raw UART link, terminate each command with `\r\n`.
- Responses are normally **line‑based text**. `send_file` temporarily switches the UART0 console to a framed binary stream after its text header.
- **`stop`** is the universal cancel — it halts every running operation (scan, attack, wardrive, anti‑surveillance, jammer…). Always send it before starting a new mode if one might be active.
- **`help`** lists all commands; **`help <command>`** shows help for one.
- All indices are **1‑based**.
- Tab completion and command history (UP/DOWN) are available on the interactive console.

Configuration commands persist their settings in **NVS** (survive reboot). The wardrive engine reads its configuration at start, so the pattern is: *configure once, then `start_wardrive_promisc`*.

---

# Part 1 — Wardrive 2.0 (new)

The promiscuous wardrive (`start_wardrive_promisc`) is a Kismet‑style scanner that hops Wi‑Fi channels with a **D‑UCB** (discounted upper‑confidence‑bound) algorithm and logs Wi‑Fi APs **and** BLE devices to a WigleWifi‑1.6 CSV on the SD card. The `start_wardrive_promisc_trace` variant additionally records a KML track plus Wi‑Fi and BLE POIs (see its entry). The behaviour below is controlled by a configuration block stored in NVS and shown by `get_wardrive_config`.

## How the engine works

- **Bands** — the radio can scan any mix of 2.4 GHz Wi‑Fi, 5 GHz Wi‑Fi and Bluetooth LE. The band selection maps to the ESP‑IDF Wi‑Fi *band mode* (2.4‑only / 5‑only / auto) and is restored to *auto* when the run stops.
- **Channels** — `popular` (1/6/11 + the common 5 GHz channels), `all` (every tier including DFS), or a `custom` list.
- **Re‑logging (RSSI/position delta)** — a network is re‑written to the CSV whenever its signal changes by ≥ the configured delta **or** you have travelled far enough since the last row. This produces the multiple observations WiGLE needs to trilaterate AP positions. Set the delta to `0` for legacy "log once" behaviour.
- **Memory cap** — the in‑RAM table is capped; when full, the oldest **already‑written** entries are evicted (their data is safely on the SD card), so a drive can run indefinitely.
- **Startup cooldown** — drop everything seen during the first N seconds so your starting location (e.g. home) is not logged.
- **Blacklist** — exclude your own devices by MAC from results and exports.

Output file: `/sdcard/lab/wardrives/<base>.log`. The `<base>` is decided **after** the GPS fix: real UTC time `YYYYMMDD_HHMMSS` (from `$GxRMC`, same clock as the CSV `FirstSeen`, so files sort chronologically). If the module never sends time, it falls back to the legacy `wN` counter. A numeric suffix (`_2`, `_3`, …) is added if that base is already taken, so nothing is overwritten. Console shows first sightings live; re‑logs go to the file.

---

### `start_wardrive_promisc`
- **Syntax**: `start_wardrive_promisc`
- **Description**: Starts the promiscuous wardrive using the current config. Waits for a GPS fix, then logs Wi‑Fi + BLE to a WigleWifi‑1.6 CSV on SD. No KML is produced — use `start_wardrive_promisc_trace` for that.
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
- **Description**: Same as `start_wardrive_promisc` (still writes the WigleWifi CSV) **and** builds a single per‑session KML that contains the drive track, one Wi‑Fi POI per unique BSSID, and one BLE POI per unique advertiser address.
  - **Track**: written as successive complete `<Placemark><LineString>` segments (buffered ~16 points / 15 s, new vertex every ≥3 m). Consecutive segments share a point so the line is continuous; a GPS jump above 100 m starts a new segment without a misleading straight connector.
  - **POI**: one `<Point>` placemark per first‑seen BSSID, captured with the GPS snapshot from the moment the beacon was seen (name = SSID or `<hidden>`; description = BSSID, RSSI, channel, auth, timestamp, altitude, accuracy). No POI is written without a valid GPS fix, and re‑logs of the same BSSID never add another POI. Markers are coloured by security: Open green, WPA/WPA2 mixed purple, WPA2 blue, WPA3/mixed WPA2-WPA3 red, WEP orange, unknown grey.
  - **BLE POI**: one `<Point>` per first‑seen advertiser, using its detected name or `BLE <address>` when unnamed. The description contains address, type, RSSI, optional manufacturer ID, timestamp and GPS snapshot. BLE is cyan; AirTag purple and SmartTag amber.
  - **File naming**: the KML shares the CSV base (see `start_wardrive_promisc`): `<base>_track.kml`, e.g. `20260719_100647_track.kml`.
  - **Crash tolerance**: during the run the file is `/sdcard/lab/wardrives/<base>_track.inprogress.kml`. On a normal `stop` it is closed and atomically renamed to the final `/sdcard/lab/wardrives/<base>_track.kml` — the single artifact you keep. Because every track segment and POI is a **complete, closed `<Placemark>`** inside one open `<Folder>`, an `.inprogress.kml` left behind by a power loss can be repaired by Tab5/ADV: find the last `</Placemark>`, cut the truncated tail, and append `</Folder></Document></kml>`.
- **Stop log**: reports the number of track segments, POIs written, POIs dropped (queue full), and the final KML path.
- **Note**: only `start_wardrive_promisc_trace` produces KML/POI; plain `start_wardrive_promisc` does not. `wardrive_cleanup` moves the finalized `<base>_track.kml` together with `<base>.log`; it never moves `.inprogress.kml`.

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

## New CLI commands in the WPS/radio update

The following top-level commands are new relative to the preceding passive
Wi-Fi reporting release. This is the quick reference; the detailed entries
later in this manual define output, persistence, admission and error behavior.

| Command | Purpose | Detailed documentation |
| --- | --- | --- |
| `wps verify <bssid> <8-digit-pin>` | Start asynchronous verification of one known WPS PIN against an explicitly owned AP. | [JanOS WPS laboratory workflows](janos-wps.md) |
| `wps pixie <bssid> [epoch]` | Run capture, bounded Pixie search and authenticated candidate verification. | [JanOS WPS laboratory commands](janos-wps.md) |
| `wps status` | Read WPS phase, run/generation, result, cleanup and memory telemetry. | [JanOS WPS laboratory workflows](janos-wps.md#status-stop-and-cancellation) |
| `wps stop` | Cooperatively cancel WPS and wait for radio cleanup. | [JanOS WPS laboratory workflows](janos-wps.md#status-stop-and-cancellation) |
| `jwps plan <bssid> [ssid]` | Generate the bounded candidate plan offline. | [JanOS WPS laboratory commands](janos-wps.md#commands) |
| `jwps campaign <bssid> <start-index> <count:1-3> [ssid]` | Run a bounded online candidate campaign. | [JanOS WPS laboratory commands](janos-wps.md#commands) |
| `selftest db\|fragment\|transport\|pixie` | Run one deterministic WPS component self-test. | [JanOS WPS laboratory commands](janos-wps.md#commands) |
| `secret status` | Inspect the volatile credential-vault state without revealing data. | [JanOS WPS laboratory workflows](janos-wps.md#secret-lifecycle-and-memory) |
| `secret reveal` | Reveal the recovered PIN/key once, then wipe the retained copy. | [JanOS WPS laboratory workflows](janos-wps.md#secret-lifecycle-and-memory) |
| `secret erase` | Explicitly wipe the volatile WPS result. | [JanOS WPS laboratory workflows](janos-wps.md#secret-lifecycle-and-memory) |
| `wifi_country status` | Show configured and active Wi-Fi country information. | [Settings](#settings) |
| `wifi_country list` | List accepted two-character country profiles. | [Settings](#settings) |
| `wifi_country set <CC>` | Persist a country profile for application after reboot. | [Settings](#settings) |
| `wifi_country reset` | Restore the default `PA` profile for the next boot. | [Settings](#settings) |
| `radio_protect add <BSSID>` | Add a protected BSSID to `/sdcard/lab/white.txt`. | [Attacks](#attacks) |
| `radio_protect remove <BSSID>` | Remove a protected BSSID. | [Attacks](#attacks) |
| `radio_protect list` | List active protected BSSIDs. | [Attacks](#attacks) |
| `radio_protect clear` | Clear the persisted and active protection list. | [Attacks](#attacks) |

`wifi_analyzer` is not new in this update. Its shared-radio admission and
cleanup behavior changed, while its existing `caps`, `scan`, `status`, `stop`
and `clear` CLI remains compatible. Likewise, `start_handshake` keeps its
existing syntax while adding protected-BSSID filtering and stricter radio
cleanup. Pixie and JWPS/campaign are production component commands now; the
removed standalone mini-OS is not required. Persistent `sta_mac` policy remains
outside this command family.

## WiFi scanning

### `test_radio_channel`
- **Syntax**: `test_radio_channel <integer>` (1..255).
- **Description**: Initialize Wi-Fi if needed, enable APSTA and verify the mode,
  then attempt to set the requested primary channel with no secondary channel.
  Preserve the current band mode and country profile. The driver decides whether
  the channel is supported under those settings. Also check the active country's
  rules in the linked ESP-IDF regulatory table, including its DFS flag and any
  manual 5 GHz channel mask.
- **Result**: Print the current mode, set/read error names, actual channel and
  `PASS`/`FAIL`, plus `country`, `allowed`, `dfs` and `reason`. Success requires
  both API calls to succeed, channel readback to match (including no secondary
  channel), and the channel to be allowed without DFS. DFS channels fail with
  `reason=dfs_required` even when setting/readback succeeds. Channels outside the
  country's rules fail with `reason=country_disallowed`. Unknown rules or a
  failed country read cannot pass. `dfs=unknown` means the channel is disallowed
  or its rules are unknown. This checks driver configuration and policy; it does
  not measure radar activity, interference or successful packet transmission.
  Return nonzero on invalid input, refusal or failure.
- **State**: Leave Wi-Fi in APSTA on the resulting channel. Failure to enable or
  verify APSTA returns `reason=apsta_init` or `reason=apsta_mode` before setting a
  channel. Refuse while another command
  is in progress, the radio is in use, or STA is connected; use `stop` first for
  active operations. BLE/802.15.4 modes are refused.
- **Example**: `test_radio_channel 52` with active country `US`
```
[RADIO] requested=52 mode=APSTA(3) set=ESP_OK read=ESP_OK actual=52 secondary=0 result=FAIL country=US allowed=1 dfs=1 reason=dfs_required
```

### `test_radio_channels`

- **Syntax**: `test_radio_channels` (no arguments).
- **Description**: Run `test_radio_channel` for each of the following 28 channels,
  in this order, continuing after channel failures:
  `36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165,169,173,177`.
- **Output**: Individual `[RADIO]` records followed by `[RADIO-SUMMARY]` with
  `total`, `passed`, `failed` and `result`, then `[RADIO-PASS]` and `[RADIO-FAIL]`
  channel lists (`none` for an empty list).
- **State**: Enable and retain APSTA; preserve the current band mode and country profile;
  leave the radio on the last successfully set channel. The same radio admission
  restrictions as `test_radio_channel` apply. Return zero only if all 28 tests pass.
- **Expected policy results** with the current ESP-IDF tables and successful
  driver/readback checks: `US` has 12 PASS and 16 DFS failures (52–64 and 100–144);
  `PA` has 24 PASS and 4 disallowed channels (144,169,173,177), with no DFS on its
  allowed channels. Both summaries therefore return nonzero.

### `wifi_analyzer`

- `wifi_analyzer caps` / `status` — analyzer capabilities and lifecycle status.
- `wifi_analyzer scan [--band 2.4|5|both] [--channels 1,6,11] [--profile quick|detailed|passive] [--limit 1..128]` — one AP survey, default 64 records, using separate PSRAM buffers and `[WFA1]` JSON lines. Existing scan results and selections are preserved.
- `wifi_analyzer stop` / `clear` — cancel analyzer work or release its idle buffers. This surveys AP signal/channel overlap; it does not measure percentage airtime or spectrum power.

See the [protocol and admission rules](wifi-analyzer-protocol.md), [shared-radio
contract](janos-radio-lease.md), [hardware smoke-test runbook](wifi-analyzer-smoke-test.md)
and [device evidence](wifi-analyzer-device-validation.md).

### `wps`, `jwps`, `selftest` and `secret`

- `wps verify <bssid> <8-digit-pin>` — asynchronously verify one known WPS PIN
  against an explicitly owned AP. A successful start emits a schema-v1
  `accepted` record followed later by exactly one `terminal` record. Invalid or
  refused input returns nonzero. The REPL can visibly echo the supplied PIN.
- `wps pixie <bssid> [epoch]` — capture Pixie material from one explicit owned
  BSSID, search using tracked PSRAM, then verify the candidate online. Optional
  `epoch` is unsigned decimal Unix seconds in `1577836800..4102444800`.
- `wps status` — safe status read: phase, run/generation, operation/cleanup result
  and current/peak WPS allocation counters.
- `wps stop` — cooperatively stop WPS only and wait for cleanup. It does not stop
  an analyzer-owned radio.
- `jwps plan <bssid> [ssid]` — offline candidate generation; an SSID with spaces
  may be quoted or passed as trailing words (joined length at most 32 bytes).
- `jwps campaign <bssid> <start-index> <count:1-3> [ssid]` — bounded online
  campaign through the shared WPS lease and exact radio restore.
- `selftest db`, `selftest fragment`, `selftest pixie` — serialized offline
  deterministic tests. `selftest transport` borrows and restores the radio.
- `secret status` — report the volatile WPS result as `empty`, `available` or
  `expired` without exposing it.
- `secret reveal` — print and consume the retained PIN/network key once. Empty or
  expired state is a JSON result, not a generic command error.
- `secret erase` — wipe the retained result; it prints no dedicated acknowledgement.

Bulk WPS scratch is PSRAM-only; secret allocations/vault are internal RAM and
wiped. The vault TTL is five minutes. Authenticated-M7 results are also exported
as sensitive plaintext JSON below `/sdcard/lab/wps/results/`; current production
terminal records remain unchanged for compatibility. A persistence attempt
emits a separate additive `wps_storage` record immediately before `terminal`.
Failed sessions may append a
secret-free, deduplicated device observation to
`/sdcard/lab/wps/unknown_devices.jsonl`; this still contains potentially
sensitive BSSID/SSID and identity metadata, but never PIN candidates, keys or
cryptographic session material. See [JanOS WPS laboratory workflows](janos-wps.md)
and the [radio compatibility runbook](janos-radio-compatibility-validation.md).

These commands reuse the production `janos_wps` component engines; no standalone
mini-OS image is required. `sta_mac ...` remains outside this command family.

Radio-mutating legacy commands, `test_radio_channel(s)`, analyzer startup and
online WPS/JWPS reserve an owner plus generation before the dispatcher unlocks:
`LEGACY`, `ANALYZER` or `WPS`. Analyzer `clear` is a short legacy transaction;
manual OTA may use only its own exact legacy token, while event-triggered OTA
remains idle-only. Status/read and stop exceptions stay available, and no
admission lock spans handler execution. Conflicts retain the exact legacy
WFACTL1 busy line and nonzero console result documented in
[shared radio ownership](janos-radio-lease.md).

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

- `start_sniffer` — client sniffer; sniffs selected networks or scans first. Passive enrichment collects SSID/security/WPS during capture; packet processing does not log or print from the radio callback.
- `start_sniffer_noscan` — sniffer using existing scan results (no new scan).
- `show_sniffer_results` / `show_sniffer_results_vendor` — APs with associated clients (vendor variant adds MAC vendor names).
- `show_sniffer_results extended` / `show_sniffer_results_vendor extended` — append versioned passive metadata to the same AP/client lines. No extra capture or radio switching. See [exact UART contract and manual test](sniffer-extended-uart.md).
- `clear_sniffer_results` — clear clients/probes/counters.
- `show_probes` / `show_probes_vendor` — captured probe requests (SSID + source MAC).
- `list_probes` / `list_probes_vendor` — probe SSIDs with 1‑based index (for `start_karma`).
- `sniffer_debug` — read `[SnifferRX]` packet/rejection counters and last RX metadata. `sniffer_debug <0|1>` retains the debug flag; packet callbacks do not print. The channel task reports `Sniffer packet count` progress.
- `start_sniffer_dog` — capture AP‑STA pairs and immediately send targeted deauth (`[SnifferDog #N] DEAUTH sent: ...`).
- `deauth_detector [i1 i2 ...]` — detect deauth frames (all channels, or selected). Output `[DEAUTH] CH: .. | AP: .. (BSSID) | RSSI: ..`.
- `start_ap_locator` — lock onto one selected AP's channel and print its RSSI once per second (`[AP Locator] ...`). Needs exactly one selected network.
- `packet_monitor <channel>` — packets‑per‑second on one channel (1‑14).
- `channel_view` — continuous Wi‑Fi channel utilization.
- `start_pcap [radio|net|gateway]` — capture to PCAP on SD. `radio` = promiscuous all-frame capture; `net` = ARP-spoof MITM after `wifi_connect`, retained for observing devices already present on an authorized LAN; `gateway` = compatibility/idempotency command because `capture_gateway start` now arms downstream capture automatically. Stop with `stop`; saves to `/sdcard/lab/pcaps/sniff_N.pcap`.

## Attacks

- `start_deauth` — deauth selected networks. WPA2 stays classic deauth; WPA3 uses Channel Switch Announcement (CSA); WPA2/WPA3 mixed sends both. Prereq `select_networks`. Syntax unchanged.
- `start_evil_twin` — clone first selected AP + deauth others, captive portal harvests password. Optional `select_html`.
- `sae_overflow` — WPA3 SAE client‑overflow on exactly one selected AP.
- `start_handshake` — capture WPA handshakes (targeted with selection, else scan-and-attack loop). Saves PCAP/HCCAPX. Before every run it reloads `/sdcard/lab/white.txt`; each non-empty line may contain one BSSID using `:` or `-` separators. Protected BSSIDs are removed from an explicit selection and are neither learned nor deauthenticated by the automatic D-UCB path. A mixed selection continues with its unprotected entries; a selection containing only protected entries is rejected without starting the worker. Both explicit targets and automatic D-UCB use one legacy-compatible radio path: APSTA mode with raw transmission through `WIFI_IF_AP`. APSTA is established once before the worker starts; D-UCB changes only the channel, verifies mode and channel before dwell, and repeats the readback immediately before TX. An arm that cannot be prepared records zero reward and does not transmit. The D-UCB worker copies BSSID, client, slot/session generation, SSID and channel under a short RX-state lock, then releases it before raw TX, burst delays and filesystem work; reconnect EAPOL can therefore arrive during the burst. Commit revalidates the immutable identity, so a stale or reused FIFO slot cannot publish. Each attempt owns a target-only PCAP plus AP/client/ESSID-bound HCCAPX. After RX is quiesced, complete bytes are copied into an immutable snapshot; `.part` files are flushed and synchronized outside the RX lock, HCCAPX is promoted first and PCAP last as the completion marker. PCAP-only or mismatched data is never reported as success. `stop` is cooperative and bounded: synchronous storage can yield additive `[HS-STOP] ... stop_pending`, and a later stop completes after worker exit; the worker is not force-deleted while it owns capture data. The automatic diagnostic PCAP remains PSRAM-backed, grows geometrically from 4 KiB to a hard 512 KiB limit and cannot suppress the independent target EAPOL path. `[HS-PCAP]` reports bounded-buffer rotation/allocation telemetry, `[HS-DUCB]` reports contention/stale-generation/snapshot/lock-hold telemetry, and `[HS-TX] tx_done_success=N tx_done_fail=N ...` reports deauthentication TX completions after callback unregister. `tx_done_success` confirms driver/MAC completion, not client reception. Existing CardputerADV/Tab5/FlipperLight success strings are unchanged and are printed only after both committed files exist. DFS availability depends on the exact ESP-IDF/driver; the handshaker never switches to a separate STA/`WIFI_IF_STA` path.
- `radio_protect add <BSSID>` — add a protected BSSID to `/sdcard/lab/white.txt`. Accepts `:` or `-` separators, rejects group/broadcast addresses, avoids duplicates and reloads the active list immediately.
- `radio_protect remove <BSSID>` — remove a protected BSSID and reload the list. Removing an absent entry is an idempotent success with `result:"not_found"`.
- `radio_protect list` — print the active protected BSSID entries and their count.
- `radio_protect clear` — clear the protection file and active list.
- `save_handshake` — manually save a captured complete 4‑way handshake.
- `start_blackout` — scan all networks every 3 min and deauth everything.
- `start_beacon_spam "SSID1" "SSID2" ...` — broadcast fake beacons (max 32 SSIDs, 1‑32 chars each).
- `start_beacon_spam_ssids` — same, loading SSIDs from `/sdcard/lab/ssids.txt`.
- `start_portal <SSID>` — open captive portal (no password to join). Optional `select_html`.
- `start_admin_portal <password>` — WPA2 AP `JanOS-Admin` serving a web file manager for `/sdcard/lab` (directory tree, upload/download, rename/delete, text editing). Stop with `stop`.
- `start_rogueap <SSID> <password>` — WPA2 rogue AP with captive portal (password 8‑63 chars).
- `start_rogue_gitm <SSID> <password> [--pcap-name <name>]` — WPA2 SoftAP mirror + Capture Gateway (GITM) instead of a captive portal. Requires prior `wifi_connect` with IPv4 (uplink BSSID must not be a deauth target). Optional `select_networks` starts same-channel deauth; other-channel targets or the STA uplink BSSID are refused. No `select_html`. DHCP DNS is `10.42.0.1` (proxied to upstream). PCAP records SoftAP IPv4 involving `10.42.0.0/24` only — not ARP-spoof on the upstream LAN. Status via `capture_gateway status`; stop with universal `stop`.
- `start_karma <index>` — Karma attack using a probe‑list SSID (`list_probes` for indices). Needs `select_html`.
- `start_darksword` — advanced attack/exfil module. Run `help start_darksword` for current options. Stop with `stop`.

All attacks stop with `stop`.

## WiFi connection (STA)

- `wifi_connect <SSID> [Password|--saved] [ota] [<IP> <Mask> <GW> [DNS1] [DNS2]]` — join an AP. If password is omitted, tries open auth. Use `--saved` to explicitly load a saved password from `/sdcard/lab/eviltwin.txt` or `/sdcard/lab/portals.txt`. `ota` triggers an update check; optional static IP. Success marker `SUCCESS`, failure `FAILED`/`TIMEOUT`.
- `wifi_disconnect` — disconnect from the current AP.

## JanOS Capture Gateway

- `capture_gateway start <capture_ssid> [capture_password] [--pcap-name <name>]` — after `wifi_connect`, starts a dedicated SoftAP on `10.42.0.1/24`, DHCP/DNS advertisement and IPv4 NAPT through the current STA connection, and immediately arms downstream PCAP before reporting ready. It does not wait for a client. Omit the password for an open SSID; supply 8-63 bytes for WPA2-PSK. Tab5 can pass a dated custom basename such as `--pcap-name office_20260812_143000`; `.pcap` is appended if absent. Safe basename characters are letters, digits, `.`, `_` and `-`. Existing files are not overwritten. Without the option, the filename remains `sniff_N.pcap`. Capture Gateway always applies a firmware-fixed aggregate upload+download ceiling of 4096 kbps. Its adaptive token bucket automatically reduces the effective rate when the recorder queue reaches 50/75%, pauses above 90%, and resumes after it drains to 50%. If recorder or limiter setup fails, gateway startup is rolled back.
- `capture_gateway status` — prints human status plus machine-readable `[CGW]` lines: `security=open|wpa2`, upstream, NAPT, clients, channel, AP/STA addresses, advertised SoftAP `dns` (normally `10.42.0.1`), `dns_proxy=on|off`, real `upstream_dns`, capture filename, `packets`, total recorder `drops`, exact serialized `file_bytes`, split `drop_alloc|drop_queue|drop_write`, recorder queue depth/high-water, configured `rate_limit_kbps`, live `rate_effective_kbps`, adaptive throttle/pause counters, limiter queue depth/high-water/drops, `pcap_scope=softap_10_42` with `filter_drops`, and the current `client_isolation=off` capability state. The legacy-equivalent `frames` field is retained for parsers. Each currently associated client gets a `[CGW_CLIENT] mac=... ip=...` line. Passwords are never returned.
- `capture_gateway stop` — disables NAPT/DHCP and returns to STA-only mode when PCAP is not running. During `start_pcap gateway`, use universal `stop` so capture hooks and the writer are finalized first.
- Recommended flow: `wifi_connect ...` -> `capture_gateway start ...` -> clients may join at any later time -> `stop`.
- The mode captures routed IPv4 for authorized clients connected to the dedicated SSID. It complements rather than replaces `start_pcap net`, is not a TLS proxy, and does not yet guarantee SoftAP client isolation. HTTPS/QUIC/VPN payloads remain encrypted. Plain HTTP payloads can be viewed offline in ESPShark's Follow Stream view. See [JanOS Capture Gateway](janos-capture-gateway.md) for architecture, limits and acceptance tests.

## ARP & LAN

- `list_hosts` / `list_hosts_vendor` — ARP‑scan the LAN and list `IP -> MAC` (vendor variant adds names). Prereq `wifi_connect`.
- `arp_ban <MAC> [IP]` — ARP‑poison a host off the network. Prereq `wifi_connect`. Stop with `stop`.
- `start_nmap [quick|medium|heavy] [IP]` — TCP port scanner. Discovers hosts (ARP+ICMP) then probes ports. `quick`=20, `medium`=50, `heavy`=100 ports. Optional single IP skips discovery. Prereq `wifi_connect`. Stop with `stop`.

## Bluetooth

- `scan_bt` — one‑time 10 s BLE scan (lists devices, AirTag/SmartTag counts).
- `scan_bt <MAC>` — continuous RSSI tracking of one device. Stop with `stop`.
- `scan_airtag` — continuous AirTag/SmartTag scan; prints `<airtags>,<smarttags>` every ~30 s. Stop with `stop`.
- `start_blespam [20|50|100|200|500]` — BLE spam mixing Apple Action Modal (Continuity Nearby Action) and Samsung Watch Pair (EasySetup Watch). Default interval 20 ms. Prints `[BLESPAM] packets=N apple=X samsung=Y delay=M` about once a second. Stop with `stop`.

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

## Console UART and binary file transfer

These commands operate on UART0, the same line used by the interactive console. The selected baud rate is deliberately not stored in NVS: every boot starts at 115200 so bootloader and JanOS startup messages remain readable.

- `uart_baud <rate>` — change the UART0 console rate. Allowed rates are `115200`, `230400`, `460800`, `921600`, `1000000`, `1500000`, `2000000`, `3000000`, and `4000000`. Everything above `2000000` is offered to be measured, not because the link is known to carry it: the C5 divider reaches far past the top of this list, so the ceiling is set by the wiring between the boards. An unconfirmed switch reverts by itself (see below), so a rate the cable cannot carry costs one failed transfer and nothing more. JanOS first sends the following response at the old rate, waits until TX is empty, and only then changes the UART rate:
  ```text
  [UARTB] switching rate=<rate> confirm_within=10s
  [UARTB] END
  ```
  Change the client/terminal rate after receiving `[UARTB] END`, then issue `uart_baud_confirm`. If JanOS does not receive confirmation within 10 seconds, it automatically returns to 115200.
- `uart_baud_confirm` — accept the current rate and cancel the automatic fallback:
  ```text
  [UARTB] confirmed rate=<rate>
  [UARTB] END
  ```
  After confirmation, JanOS also returns to 115200 if no valid console command is executed for 60 seconds. The idle fallback is completely suspended while `send_file` is active, so neither a baud-rate change nor an `[UARTB]` message can interrupt the binary stream. Every transmitted block refreshes activity, and the 60-second window starts again when the transfer finishes or is cancelled. The fallback is announced at 115200 with `[UARTB] idle revert rate=115200`.
- `uart_baud_status` — report the current rate and whether the confirmation window is active:
  ```text
  [UARTB] status rate=<rate> pending=<yes|no>
  [UARTB] END
  ```
- `send_file <path> [offset] [bsize]` — read a file from the SD card and transfer it over UART0. Relative paths are rooted at `/sdcard`; `offset` defaults to `0` and permits resuming a partial download. The command does not modify the file or SD card.

`bsize` is the payload size of one block, in bytes. It is chosen by the *receiver* because the receiver is the side with the RAM constraint — its UART receive ring has to comfortably exceed one block. A request below `512` or above `32768` is clamped rather than refused, and the value actually used is reported back as `bsize=`, so a caller must read that field instead of assuming it got what it asked for. Omitting the argument keeps the historical `4096`.

A JanOS predating this argument rejects a three-argument `send_file` outright with `[FT] error usage: send_file <path> [offset]`. A receiver that wants a block size should therefore retry once without the third argument when it sees `usage` in the refusal.

On success, `send_file` emits a text header followed by an empty line:

```text
[FT] begin size=<total-file-size> offset=<offset> bsize=<block-size> crc32=00000000 prefix_crc=<crc32-of-bytes-before-offset> ack_ms=<ack-timeout-ms>
[FT] END

```

The opening CRC32 is intentionally zero so transmission can begin immediately without reading the file twice. Verify the received data using the authoritative running CRC32 reported by the final `[FT] done` line.

`prefix_crc` is the CRC32 of the byte range `[0, offset)` — everything JanOS is *not* about to send — and is `00000000` when `offset` is `0`. It is always present, so its absence identifies a JanOS too old to provide it. A resuming receiver checksums its own partial file and compares it against this value before the first block arrives, which turns a stale or corrupted partial into an immediate restart from zero instead of a CRC failure discovered after the whole remainder has crossed the wire.

`ack_ms` is how long JanOS will wait for the response byte after each block, in milliseconds. Both ends size their per-block patience from the same two numbers — the negotiated block size and the rate the line is running at — because no fixed constant is right across the range: one 4 KiB block is 21 ms of wire time at 2 MBaud, while one 32 KiB block is 2.8 s at 115200. The relationship is:

```text
wire_ms  = (bsize + 16) * 10 bits / baud        one block on an ideal line
receiver = 1000 + 3 * wire_ms                   capped at 30000
ack_ms   = max(8000, receiver + 2000)
```

The sender's window therefore exceeds the receiver's by at least 2000 ms, so a receiver that is merely slow still gets its NAK in before JanOS abandons the transfer. **A receiver must keep its own per-block deadline strictly below `ack_ms`** — subtracting the 2000 ms margin reproduces the `receiver` line above. Receivers predating this field wait a fixed 6 s for a block payload, which the older fixed 5 s ACK timeout sat *inside*: between 5 s and 6 s JanOS had already printed `[FT] error ACK timeout` and returned to the REPL while the far end was still preparing a NAK, desynchronising the two unrecoverably. The 8000 ms floor exists to keep those receivers inside the window. A receiver that does not see `ack_ms` is talking to a JanOS with the old fixed 5 s timeout and must stay well inside it.

Fields in the `[FT] begin` line must not be reordered, and no new field may contain the substring `crc32=`. Receivers locate values by searching for `<key>=`, so a field named e.g. `pre_crc32=`, or `prefix_crc=` placed ahead of `crc32=`, would be picked up by a search for `crc32=` and silently return the wrong number. This is why `bsize=` is safe only where it is: `size=` occurs earlier in the line.

After the empty line, each block is binary and is not escaped:

| Field | Size | Encoding |
|---|---:|---|
| magic | 4 bytes | `FTB\x01` |
| index | 4 bytes | little-endian, starting at 0 |
| length | 4 bytes | little-endian, payload length up to the negotiated `bsize` |
| crc32 | 4 bytes | little-endian CRC32 of this payload only |
| payload | `length` bytes | raw file bytes |

After every block, the receiver must send exactly one response byte within `ack_ms` milliseconds:

- `0x06` (ACK) — accept the block and continue.
- `0x15` (NAK) — retransmit the same block, up to three total attempts.
- `0x18` (CAN) — cancel the transfer.

If no response byte arrives within `ack_ms`, JanOS ends the transfer with `[FT] error ACK timeout` followed by `[FT] END`, releases the file and transfer buffer, and returns control to the console REPL.

A completed transfer ends with:

```text
[FT] done sent=<bytes-from-offset> crc32=<crc32-from-offset>
[FT] END
```

Cancellation ends with `[FT] cancelled` and `[FT] END`. Validation, SD, open, seek, read, UART, or retry-limit failures use `[FT] error <reason>` followed by `[FT] END`. The console resumes normal line-oriented command handling after any of these endings.

## SD card

- `sd_status` — fast presence check; `SD_OK` or `SD_NONE` (~200 ms, no mount).
- `sd_benchmark [size_mb]` — destructive only to JanOS's own temporary file `/sdcard/lab/.janos_sd_benchmark.tmp`; measures sequential SD writes using the same 64 KiB chunk/buffer size as the PCAP path, then deletes the file. Size range is 1-256 MiB, default 32 MiB. Reports durable average KiB/s and kbps, `p50/p95/p99/max` `fwrite` latency, final `fflush`/`fsync` latency and a heuristic `conservative_50pct_kbps`. It refuses to run while PCAP, Capture Gateway or wardrive is active. Run `stop` first. The 50% number is a starting point for gateway tests, not a lossless guarantee.
- `list_sd` — list HTML portal files (`N filename.html`). Header `HTML files found`.
- `select_html <index>` — load an HTML file by index for portal / rogue AP / evil twin.
- `set_html <html_string>` — set portal HTML directly from the command line.
- `list_dir [path] [-s]` — list files in a directory (default `lab/handshakes`); `-s` adds the decimal byte size before each filename.
- `send_file <path> [offset] [bsize]` — transfer an SD file over UART0 using the resumable binary protocol documented above. `bsize` is the receiver-selected block size, clamped to 512-32768 and echoed back as `bsize=`.
- `file_delete <path> [path2 ...]` — delete one or more files, e.g. `file_delete lab/handshakes/sample.pcap`. Each path produces the human line `Deleted <path>` plus a machine-readable `[FILE_DELETE] path=<path> result=ok|not_found|is_dir|failed`. The result is printed before the card is synced, and a batch is synced once at the end. Exactly one marker line is emitted per path, in the order the paths were given, whatever happens to any of them — the host maps results positionally, so a missing or reordered line would attribute a result to the wrong file. Quote any path containing a space; `esp_console_split_argv` undoes the quoting, so it arrives as one argument. An absolute path that does not start with `/sdcard` is rebased onto it, so `/lab/handshakes` and `/sdcard/lab/handshakes` now mean the same directory.
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
- `wardrive_files` — list local wardrive files with `size`, `hash`, `wifi/ble/bt/bad`, and `wigle`/`wdgwars` status. Output is marker-delimited with `[WARD_FILE] ...` lines and includes a final `[WARD_FILE] SUMMARY ...` before `END` with total `files/bytes/rows/wifi/ble/bt/bad` plus per-service `ok/pending/failed/rate_limited` counts. `BEGIN` carries the count of files that will actually be listed (`[WARD_FILE] BEGIN count=63`) — it is taken after every filter, and every file it counts produces exactly one `filename=` line, so a host comparing the two can trust a mismatch. A file that stats as a candidate but cannot be read is still listed, with the size from `stat()`, `hash=00000000`, zeroed counts and a trailing `error=read`, rather than being dropped. `BEGIN`/`SUMMARY`/`END` are printed on every path — a failure to mount the card or open the directory emits a `[WARD_FILE] ERROR reason=...` line inside that frame instead of returning silently. Before each file a progress line `[WARD_FILE] SCANNING <i>/<n> name=<filename>` is emitted (key `name=`, not `filename=`, so it does not disturb a host counting listing entries); on a cold cache it is the only sign the module is alive while a large log is hashed. Per-file results are cached in `/sdcard/lab/wardrives/.scan_cache.csv`, keyed on `(filename, size, mtime)`, so a warm listing costs one `stat()` per file instead of reading and rewriting every byte in the directory; delete that file to force a full rescan. The active wardrive session's own log is never cached.
- `wardrive_cleanup <wigle|wdgwars|all> <pending|done|ok|failed|fail|rate_limited> [move [destination]]` — dry-run or move matching wardrive files to `/sdcard/lab/wardrives/uploaded/<service>/<status>/`, or with a safe destination token to `/sdcard/lab/wardrives/uploaded/<service>/<status>/<destination>/`. Without `move`, only prints `[WARD_CLEANUP] ... action=would_move`. `ok` = `done`, `fail` = `failed`. `all done` matches only files done for both WiGLE and WDGWars. `BEGIN` carries a count equal to the `scanned` the SUMMARY will report, and, like `wardrive_files`, the `BEGIN`/`SUMMARY`/`END` frame is emitted even when the card or directory cannot be opened. Each file is preceded by `[WARD_CLEANUP] SCANNING <i>/<n> name=<filename>`. A file that cannot be read is counted in `scanned` and reported as `action=skipped reason=read_error`, but is never matched or moved — its status would be keyed on a zero hash. Uses the same `.scan_cache.csv` and drops rows for files it has moved away.
- `wardrive_fix <file>` — create a soft-fixed `.fixed.log` copy with canonical WigleWifi-1.6 headers and only valid 14-field `WIFI/BLE/BT` rows. The original file is unchanged. The repaired copy is written to `/sdcard/lab/wardrives/fixed/`, not next to the original, and `*.fixed.log` is excluded from the upload and cleanup directory scans — otherwise the repaired file became a second upload candidate for the same data and was uploaded alongside the file it came from. Output is marker-delimited with `[WARD_FIX] ...` lines; `output=` now carries the `fixed/` prefix and a `[WARD_FIX] note=output_dir=... excluded_from_uploads=yes` line follows it. Explicitly naming a `.fixed.log` file in `wigle_upload`/`wdgwars_upload`/`wardrive_fix` still works — only the directory scans skip it.

## Settings

- `wifi_country status` — show the configured profile and, when the Wi-Fi
  driver is active, its read-back country, channel range and policy.
- `wifi_country list` — list all 176 profiles from the ESP-IDF 6.0 ESP32-C5
  regulatory table, including countries/territories, `EU` and world-safe `01`.
  `PA` remains the JanOS default and fallback.
- `wifi_country set <CC>` — validate and persist a profile in NVS. Lowercase is
  normalized to uppercase. The new profile is applied after reboot.
- `wifi_country reset` — persist the default `PA` profile for the next boot.

At the first boot of a different firmware image (UART/USB flash, OTA or a return
to another image), JanOS resets and saves `PA` in NVS. The country and the
running image's full ELF SHA-256 are stored together in `wifi_country/profile`.
Later boots of the same image preserve a profile selected with `wifi_country set`.
Reflashing the identical BIN does not trigger a reset. On first upgrading from
the old three-byte country record, the previous choice is replaced by `PA` once.
After a firmware-triggered reset, `status` reports
`record_health="firmware_reset_pa"`; subsequent boots report `valid`. Empty NVS
is initialized with a saved `PA` profile (`default_pa`). Storage failures use PA
in memory and report a fallback health value; the reset is retried on a later boot.
Other NVS settings are preserved.

Country configuration is applied centrally after every Wi-Fi driver
initialization and read back before the radio is accepted. `PA` uses the JanOS
manual profile `schan=1`, `nchan=14`; other profiles use the corresponding IDF
regulatory table in manual mode. Changing a country profile does not bypass
DFS restrictions or permit SoftAP/APSTA operation on DFS channels.

`RU` is already present in the ESP-IDF 6.0.0 profile list. For that pinned
version it covers 2.4 GHz channels 1–13 and 5 GHz channels 36–64 plus 132–165;
channels 100–128 are not part of the profile. The lowercase command is accepted
and normalized, for example:

```text
wifi_country set ru
# reboot
wifi_country status
```

After reboot verify `configured_cc="RU"`, `active_cc="RU"` and
`active_policy="manual"`. This profile does not bypass ESP32-C5 DFS/SoftAP
hardware or driver restrictions and must only be used where the selected
regulatory domain is applicable.

- `channel_time set <min|max> <ms>` / `channel_time read <min|max>` — scan dwell per channel (100‑1500 ms, min<max).
- `vendor set <on|off>` / `vendor read` — MAC vendor lookup in results.
- `display set <auto|ssd1306|sh1107|sh1106|unit_lcd>` / `display read` — OLED/LCD type.
- `led set <on|off>` / `led level <1-100>` / `led read` — status LED.
- `boot_button read|list|set <short|long> <cmd[,cmd...]>|status <short|long> <on|off>` — map boot‑button presses to commands (comma‑chained).

## OTA updates

- `ota_check [rf] [latest|<tag>]` — check GitHub and apply a firmware update.
  `rf` selects the RF-support release path. Prereq WiFi; an active analyzer/WPS
  lease refuses OTA before worker creation.
- `ota_list` — list recent releases (`OTA[n]: <tag> (main|dev) <date> <title>`).
- `ota_channel [main|dev]` — get/set update channel.
- `ota_info` — partition info (boot/running/next).
- `ota_boot <ota_0|ota_1>` — set boot partition and reboot.

## nRF24 jammer (external module)

Requires an nRF24L01+ wired to SPI2 (SCK=6, MOSI=7, MISO=2, CSN=3, CE=4).

- `init_nrf24` — initialize and probe the module (run once before jamming). `[NRF24] detected ...` or `[NRF24] not detected ...`.
- `start_jammer24 [ble|bt|wifi|drone|all]` — start the jammer (default `all` = full 2.4 GHz sweep). Prereq `init_nrf24` detected. Stop with `stop`.

## System

- `stop` — stop ALL running operations. The universal cancel. Always acknowledges with `[WARDRIVE] STOPPED running=0|1`, including when nothing was running, so a host can wait for a known idle state instead of flushing the UART and assuming; `running=1` means a wardrive was active when the stop arrived. The human-readable "Wardrive promisc stopped ..." line is unchanged and still comes from the task itself.
- `reboot` — reboot the device.
- `ping` — connectivity test; replies `pong`.
- `version` — print firmware version (`JanOS version: X.Y.Z`).
- `download` — reboot into ROM download (UART flashing) mode.
- `help [command]` — list all commands or show help for one.

---

*Generated for the MonsterC5 / ESP32‑C5 build. New in this build: the `set_wardrive_*`, `wardrive_blacklist`, `get_wardrive_config`, `start_antisurveillance` and `set_antisurv_sensitivity` commands (Part 1).*
