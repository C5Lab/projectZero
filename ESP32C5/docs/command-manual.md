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
| `wps_guard start` | Start passive WPS fragmentation forensics for BSSIDs from one completed scan. | [WPS Guard](#wps_guard) |
| `wps_guard start --only <scan-index> [scan-index ...]` | Start the same passive monitor for selected scan BSSIDs only. | [WPS Guard](#wps_guard) |
| `wps_guard status` | Read bounded fragment, anomaly, loss and lifecycle counters. | [WPS Guard](#wps_guard) |
| `wps_guard stop` | Stop WPS Guard and retry any retained cleanup. | [WPS Guard](#wps_guard) |
| `sae_guard start` | Start passive SAE authentication forensics for BSSIDs from one completed scan. | [SAE Guard](#sae_guard) |
| `sae_guard start --only <scan-index> [scan-index ...]` | Start SAE Guard for an immutable selected BSSID set. | [SAE Guard](#sae_guard) |
| `sae_guard status` | Read bounded SAE observation, loss and lifecycle counters. | [SAE Guard](#sae_guard) |
| `sae_guard stop` | Stop SAE Guard and retry any retained cleanup. | [SAE Guard](#sae_guard) |
| `wifi_trust baseline capture [--seconds <5..120>] [--only <scan-index> [scan-index ...]]` | Capture a bounded advertisement baseline on the current channel or sampled selected channels. | [Wi-Fi Trust Baseline](#wifi_trust) |
| `wifi_trust baseline list` | Validate and print the stored baseline. | [Wi-Fi Trust Baseline](#wifi_trust) |
| `wifi_trust baseline clear` | Recover and remove the stored baseline transactionally. | [Wi-Fi Trust Baseline](#wifi_trust) |
| `wifi_trust monitor [--only <scan-index> [scan-index ...]]` | Compare current-channel or sampled selected-channel advertisements with the stored baseline. | [Wi-Fi Trust Baseline](#wifi_trust) |
| `wifi_trust status` | Print bounded capture, monitor, storage and loss telemetry. | [Wi-Fi Trust Baseline](#wifi_trust) |
| `wifi_trust stop` | Stop Trust capture/monitor and retry retained cleanup. | [Wi-Fi Trust Baseline](#wifi_trust) |
| `wifi_shield start` | Start the combined passive evidence monitor after one bounded Shield-owned scan. | [Wi-Fi Shield](#wifi_shield) |
| `wifi_shield start --only <scan-index> [scan-index ...]` | Start passive Shield on an immutable selected BSSID/channel snapshot. | [Wi-Fi Shield](#wifi_shield) |
| `wifi_shield start --only <scan-index> [scan-index ...] --defence decoy-4way` | Explicitly enable the bounded selected-target Defence bridge. | [Wi-Fi Shield](#wifi_shield) |
| `wifi_shield start --only <scan-index> [scan-index ...] --defence decoy-4way --pmkid-decoy` | Also enable the explicit experimental PMKID decoy. | [Wi-Fi Shield](#wifi_shield) |
| `wifi_shield start --only <scan-index> [scan-index ...] --defence decoy-4way --pmkid-decoy --multi-vector` | Opt in to at most one successful decoy response per enabled attack vector in one BSSID campaign. | [Wi-Fi Shield](#wifi_shield) |
| `wifi_shield start --only <scan-index> [scan-index ...] --protect-all` | Start the autonomous preset: active bounded Deauth/PMKID deception plus passive WPS/SAE/Trust monitoring. | [Wi-Fi Shield](#wifi_shield) |
| `wifi_shield status` | Read aggregate targets, coverage, source counters, drops and lifecycle state. | [Wi-Fi Shield](#wifi_shield) |
| `wifi_shield report` | Read the bounded V2 campaign and AP-health snapshot without changing radio or session state. | [Wi-Fi Shield](#wifi_shield) |
| `wifi_shield log status` | Read the bounded V2 journal state and counters without mounting storage or changing session state. | [Wi-Fi Shield](#wifi_shield) |
| `wifi_shield stop` | Stop Shield or retry retained quarantined cleanup. | [Wi-Fi Shield](#wifi_shield) |
| `client_isolation_audit start <peer-ipv4> <32-hex-token> [--port <1024..65535>] [--count <1..10>]` | Test an explicitly owned same-subnet peer with authenticated bounded UDP challenges. | [Client Isolation Audit](#client_isolation_audit) |
| `client_isolation_audit status` | Read the last sanitized isolation-audit summary. | [Client Isolation Audit](#client_isolation_audit) |
| `router_audit scan passive` | Inventory the connected gateway from cached/local evidence with zero network transmission. | [Router Audit and signed CVE catalog](#router_audit) |
| `router_audit scan standard --owned` | Run bounded gateway-only discovery against an explicitly owned router. | [Router Audit and signed CVE catalog](#router_audit) |
| `router_audit status` | Read the last bounded audit outcome plus a fresh trusted installed-catalog validation. | [Router Audit and signed CVE catalog](#router_audit) |
| `router_audit db status` | Revalidate the trusted commit/journal/pair, signature, catalog structure and current time state. | [Router Audit and signed CVE catalog](#router_audit) |
| `router_audit db verify` | Verify the staged pair, or recover and verify the installed pair when no stage exists. | [Router Audit and signed CVE catalog](#router_audit) |
| `router_audit db install` | Verify and install the staged signed catalog using trusted time. | [Router Audit and signed CVE catalog](#router_audit) |
| `router_audit db install --allow-time-unknown` | Explicitly permit install when trusted time is unavailable and persist that fact. | [Router Audit and signed CVE catalog](#router_audit) |
| `wifi_country status` | Show configured and active Wi-Fi country information. | [Settings](#settings) |
| `wifi_country list` | List accepted two-character country profiles. | [Settings](#settings) |
| `wifi_country set <CC>` | Persist a country profile for application after reboot. | [Settings](#settings) |
| `wifi_country reset` | Restore the default `PA` profile for the next boot. | [Settings](#settings) |
| `sta_mac status` | Read configured, boot and active STA identities. | [STA MAC boot policy](#sta-mac-boot-policy) |
| `sta_mac set factory` | Use the factory STA MAC on the next application boot. | [STA MAC boot policy](#sta-mac-boot-policy) |
| `sta_mac set random` | Generate one STA MAC on the next application boot. | [STA MAC boot policy](#sta-mac-boot-policy) |
| `sta_mac set fixed <MAC>` | Use a validated local unicast STA MAC on the next application boot. | [STA MAC boot policy](#sta-mac-boot-policy) |
| `radio_protect add <BSSID>` | Add a protected BSSID to `/sdcard/lab/white.txt`. | [Attacks](#attacks) |
| `radio_protect remove <BSSID>` | Remove a protected BSSID. | [Attacks](#attacks) |
| `radio_protect list` | List active protected BSSIDs. | [Attacks](#attacks) |
| `radio_protect clear` | Clear the persisted and active protection list. | [Attacks](#attacks) |

`wifi_analyzer` is not new in this update. Its shared-radio admission and
cleanup behavior changed, while its existing `caps`, `scan`, `status`, `stop`
and `clear` CLI remains compatible. Likewise, `start_handshake` keeps its
existing syntax while adding protected-BSSID filtering and stricter radio
cleanup. Pixie and JWPS/campaign are production component commands now; the
removed standalone mini-OS is not required. The production `sta_mac` commands
are described under [STA MAC boot policy](#sta-mac-boot-policy).

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

### `wps_guard`

Built-in help is exactly:
`Passive WPS fragment forensics: start [--only indexes...] | status | stop`.

- **Commands**: `wps_guard start`,
  `wps_guard start --only <scan-index> [scan-index ...]`, `wps_guard status`,
  and `wps_guard stop`. No alias is provided. The existing active `wps`,
  `jwps`, `selftest` and `secret` commands keep their syntax and behavior.
- **Targets and channel scope**: Start resolves whole target records from one
  completed scan before acquiring the security-monitor lease. Scan indexes are
  one-based scan indexes. Bare `start` snapshots every result; `--only`
  snapshots only the listed targets. The owned BSSID filter and channel plan
  are immutable for the session, so a later scan-cache change cannot retarget
  or retune the monitor. Missing, duplicate, nonnumeric or out-of-range indexes
  and zero or group BSSIDs are rejected. Observations always describe the
  currently received/tuned channel. When one effective selected channel remains
  pinned, coverage is continuous for that channel; multiple unique selected
  channels are sampled in scan order with a 250 ms per-channel dwell. Failed
  retunes do not advance the plan and are retried later. This sampling does not
  guarantee complete multi-channel coverage, and silence on a channel is not
  evidence of absence.
- **Bounds**: WPS Guard tracks at most eight live flows, accepts at most a
  4096-byte declared WSC length and applies a 5000 ms inactivity timeout.
  Expiry requires inactivity strictly greater than 5000 ms: the first expired
  instant is 5000001 us, not at 5000000 us. A flow is keyed by BSSID, station
  and direction. Identical retransmissions are counted as telemetry, not
  anomalies.

The monitor recognizes unprotected EAPOL/EAP Expanded WSC fragmentation and
publishes bounded `[WPS_GUARD/1]` evidence records. Event fields are BSSID,
station, direction, channel, RSSI, opcode, fragment count, declared and observed
lengths, retransmission count, reason, severity, truncation and monotonic
timestamp. `status` and terminal records add received, filtered, unrelated,
completion, anomaly, timeout, capacity, RX-drop, output-failure, active-flow and
lifecycle counters. `RX_DROPS` is the saturated sum of shared-runtime
`dropped_pool` and `dropped_queue`; `CAPACITY_DROPS` remains the distinct WPS
flow-table capacity counter. The public event reason tokens are:

- `first_missing_length`;
- `declared_not_larger_than_first`;
- `declared_over_limit`;
- `repeated_length_field`;
- `opcode_changed`;
- `eap_id_conflict`;
- `observed_exceeds_declared`;
- `final_length_mismatch`;
- `empty_more_fragment`;
- `session_timeout`;
- `session_capacity`;
- `frame_truncated`;
- `invalid_envelope`.

The status `REASONS` vector also reserves its first positions for internal
`none`, `retransmission` and `complete` counters; these three do not produce
event records. Timeout/capacity records express bounded uncertainty, not a
claim that all RF traffic was received.

WPS Guard is passive and evidence-only. It sends no Fragment ACK, EAP response,
enrollment message, PIN verification, association request or raw TX. It neither
reuses the active WPS reassembly path nor materializes a WSC message. Its
flow/session state and telemetry retain and print no payload bytes, WSC
attributes, nonces, keys, PINs, credentials or authentication tags. The shared
runtime temporarily owns the bounded frame copy described in the runtime
manual; the metadata-only core keeps only bounded lengths, counters and a
non-cryptographic fragment fingerprint used to compare observed fragments.

Current operator terminal outcomes are:

| Outcome | Meaning |
| --- | --- |
| `stopped` | A requested cancellation/Stop completed verified cleanup. |
| `busy` | Another session, radio owner or mutable legacy-radio baseline prevented Start. |
| `invalid` | CLI, scan snapshot, target validation or startup setup failed; any acquired resources are rolled back first. |
| `timeout` | Startup cancellation/lifecycle contention or worker join did not complete in the allowed time. |
| `queue_overflow` | Verified cleanup completed, but shared-runtime pool/queue drops make the received observation set incomplete. |
| `restore_failed` | Saved channel/filter state or the cleanup/release sequence could not be verified. |
| `output_failed` | The bounded record sink failed; feature processing fail-closes until Stop. |

When a cleanup produces a lifecycle result, deduplication permits one terminal
per cleanup attempt. Concurrent Start rollback, Stop and uncertainty reporting
share that attempt. If uncertainty retains the context, a later retry receives
a new terminal. The session retains persistent output-failure evidence in its
live/final status, so the retry result remains `output_failed` even when that
retry finishes radio cleanup successfully.

On successful session cleanup, any retained `RX_DROPS` evidence and no
higher-priority output or cleanup failure means successful cleanup reports
`queue_overflow`, not `stopped`. The scan mutex and output gate each wait at
most 250 ms, and publisher-queue admission has the same bound. In full: the
scan mutex, output gate and publisher-queue admission each wait at most 250 ms.
Lifecycle callers never wait for the UART driver. A dedicated publisher writes
each complete record in one UART transaction; a full queue or publisher failure
marks output failure and fail-closes the live monitor without holding the
feature state critical section across I/O. To keep asynchronous publication
failure scoped to the session that produced it, a new Start remains busy until
prior-session publications resolve.

`wps_guard stop` and global `stop` close callback admission, drain accepted
frames, join the worker, restore the saved promiscuous filter and channel,
zeroize the module state and release the radio owner. No new timeout event is
created after callback closure. A worker-join or filter/channel restore failure
retains the context and target snapshot: failed cleanup keeps the radio owner
quarantined. A later `wps_guard stop` or global `stop` retries cleanup, and no
terminal success is emitted while cleanup is uncertain. Conflicting radio
commands remain refused until verified cleanup succeeds.

An alert describes a malformed or inconsistent sequence observed by JanOS. It
does not attribute a sender, does not prove WPSplinter, and does not prove that
a device is exploitable. Disabled WPS advertisement does not prove that legacy
WPS code is unreachable. Conversely, observing a malformed sequence does not
prove that a particular router accepts it or is vulnerable. Establishing that
requires separately approved, controlled-device and RF evidence.

### `sae_guard`

Built-in help is exactly:
`Passive SAE authentication forensics: start [--only indexes...] | status | stop`.

- **Commands**: `sae_guard start`,
  `sae_guard start --only <scan-index> [scan-index ...]`, `sae_guard status`,
  and `sae_guard stop`. The existing active `sae_overflow` keeps its existing syntax, help and behavior; SAE Guard is a separate passive mode.
- **Targets**: Start copies BSSID, sanitized SSID evidence, scan channel and
  eligibility from one completed scan into a private immutable whole-target
  snapshot in byte-addressable PSRAM. Indexes are one-based. Missing,
  duplicate, nonnumeric, zero, overflowing or out-of-range indexes, zero or
  group BSSIDs, and zero channels are rejected. A later scan-cache change
  cannot retarget the monitor.
- **Coverage**: one effective selected channel remains pinned for continuous
  coverage; multiple unique selected channels are sampled in scan order with a
  250 ms per-channel dwell. Failed retunes retry the same channel. Evidence is
  accepted only on the currently tuned channel through the single shared
  callback. Sampling does not claim complete RF reception, and silence on a
  channel is not evidence of absence.

SAE Guard accepts only selected, unprotected Authentication management frames
whose authentication algorithm is SAE (3). Transaction 1 is classified as a
Commit and transaction 2 as a Confirm. For groups 19, 20 and 21, the parser
validates the bounded scalar/element minima; matching Confirm bodies have
minimum total lengths of 40, 56 and 72 bytes. Transaction-1 status 126 (Hash-to-Element) and status 127 (SAE-PK) remain Commit-bearing modes and undergo the same known-group checks. Transaction-1 status 76 anti-clogging requires a complete group and keeps any token opaque; status 77 unsupported-group remains a distinct response without an inferred group. Unknown groups remain observable and are not malformed merely because the group is unknown. Protected Authentication bodies are hidden and cannot be classified as SAE evidence.

The core has two independent fixed tables: 32 `(BSSID, station, direction)` pairs for Commit/Confirm correlation and 32 independent malformed-BSSID rows for aggregation across stations and directions. It emits evidence at these conservative thresholds:

- three malformed SAE frames for one BSSID in a half-open ten-second window;
- eight unconfirmed Commit observations for one pair in that window;
- three distinct group identifiers for one uncompleted pair in that window.

The window expires exactly at ten seconds. An identical sequence/group retry is
retry telemetry; a first-seen or changed retry counts once as a Commit. A
matching successful Confirm clears the attempt counts while the per-window
alert cooldown remains until expiry. Simultaneous threshold crossings retain
combined reasons in deterministic enum order.

Every event, status and terminal line uses `[SAE_GUARD/1]` and CRLF. Event
records include BSSID, station, direction, channel, RSSI, transaction, status,
group or `unknown`, Commit/Confirm/malformed counts, window, reason, severity,
interpretation and monotonic timestamp. Status and terminal records include
aggregate `CAPACITY_DROPS` plus independent `PAIR_DROPS` and
`MALFORMED_DROPS`. `RX_DROPS` is the saturated sum of shared-runtime pool and
queue loss; it expresses incomplete reception rather than detector capacity.
The public interpretations are `observation`, `malformed_observation` and
`potential_dos`. Terminal precedence is exactly `output_failed > restore_failed > queue_overflow > stopped`; diagnostic `busy`, `invalid` and `timeout` outcomes remain available for their defined lifecycle failures.

SAE Guard is passive and evidence-only. It sends no SAE Commit, SAE Confirm, anti-clogging token, status response, deauthentication, disassociation or channel-switch announcement. It retains and prints no scalar, element, token, password identifier, password, PMK or raw payload. `sae_guard stop` and global `stop` use the shared cleanup order and retry quarantined cleanup; output failure fail-closes the feature until Stop. When SAE Guard is inactive, existing scan, sniffer, deauth detector, help, `sae_overflow` and global Stop behavior remains compatible.

Short or malformed SAE evidence may resemble parser-risk conditions such as
CVE-2026-72003, but the observation cannot identify a vulnerable driver and
cannot prove exploitation or code execution. It cannot prove attribution, password compromise or that WPA3 is broken. Commit bursts indicate possible resource pressure, not a broken password exchange. These are evidence labels, not a live CVE-catalog match or a statement that a target executes vulnerable code.

### `wifi_trust`

Built-in help is exactly:
`Wi-Fi trust baseline: baseline capture/list/clear | monitor [--only indexes...] | status | stop`.

The accepted command forms are:

```text
wifi_trust baseline capture [--seconds <5..120>] [--only <scan-index> [scan-index ...]]
wifi_trust baseline list
wifi_trust baseline clear
wifi_trust monitor [--only <scan-index> [scan-index ...]]
wifi_trust status
wifi_trust stop
```

Capture duration must be 5 through 120 seconds; the default is 15 seconds.
Scan indexes are one-based, unique decimal entries from the most recent
completed scan. Bare capture and monitor remain current channel only: they use
no scan snapshot, no initial tune and no channel hopping, and capture observes
all received BSSIDs. `--only` freezes immutable complete selected target
records, tunes to the first selected channel, and uses 250 ms sampled residence
over the distinct selected channels. A failed retune is retried without moving
the channel cursor. The existing `SCOPE=current_channel` wire value is
unchanged; `CHANNEL` follows the actually resident selected channel. Sampled
silence is not proof that a selected BSSID or event is absent. Trust remains
passive: neither mode probes, associates nor transmits a raw frame.

Bare capture and monitor remain current-channel only. `--only` uses sampled
residence, while `SCOPE=current_channel` remains byte-for-byte unchanged. The
runtime migration changes ownership only; it adds no Trust CLI token, wire
field, Shield output or presentation path.

An operator workflow is:

1. Run `scan_networks` and inspect the current scan results.
2. In a known-good network state, run `wifi_trust baseline capture`, optionally
   with `--only` scan indexes and a bounded `--seconds` value.
3. Run `wifi_trust baseline list` to validate and inspect the published rows.
4. Run `wifi_trust monitor`, with the same optional target selection, then use
   `wifi_trust status` and `wifi_trust stop` as needed.

The primary identity is BSSID. An SSID change is evidence; a new BSSID is not
automatically merged with an existing same-SSID row. BSSID changes can be
legitimate in mesh and extender deployments, after hardware replacement, or
after administrator reconfiguration. Every result is evidence, not attribution:
drift does not identify an attacker, an evil twin, compromise or exploitability.

The baseline contains at most 128 profiles and is stored at
`/sdcard/lab/wifi-trust/baseline-v1.jsonl`. Its strict, LF-only schema is one
version-1 header, zero to 128 canonical AP records sorted by BSSID, then one end
record. The end record carries record count and CRC32 over the exact AP lines,
including each LF. Binary SSID, selector, RSNXE, WPS text and Country values are
bounded hex; they are not treated as UTF-8. A boot ID and optional trusted Unix
creation time distinguish boot-relative observation timestamps. The `PRIVACY`
value is only the advertised 802.11 Capability Information privacy bit; it is
not a claim about user privacy, negotiated client security or confidentiality.

The states `unknown`, `absent`, `valid`, and `invalid` remain distinct.
`unknown` never overwrites confirmed evidence or becomes a downgrade. `absent`
requires a complete advertisement. A malformed advertisement can emit
`malformed_observation`, but it does not mutate the saved baseline. Capture
publishes only complete, conflict-free profiles after verified radio cleanup;
cancel, startup failure or cleanup uncertainty preserves the previous file.

Publication uses stage, target and backup paths plus checked file and volume
sync operations. Recovery runs before load, publish and clear. `ok_backup_pending`
means the new target is readable but backup removal was not completed;
`published_uncertain` means publication may have taken effect but final durable
state was not proved; `recovered_retry` means recovery changed the filesystem
and the operator must retry the requested operation. These map to terminal
`storage_uncertain` or `storage_failed` rather than false success. The host model
checks rollback preservation, but real SD durability and FAT power-loss behavior
remain device acceptance work; the manual does not claim power-loss atomicity.

Versioned UART records are `[WIFI_TRUST/1] EVENT`, `[WIFI_TRUST/1] BASELINE`,
`[WIFI_TRUST/1] STATUS`, and `[WIFI_TRUST/1] TERMINAL`. Events own BSSID, bounded
SSID evidence, channel, Beacon/Probe source, changed field, baseline/current
value, reason, severity, `CONFIDENCE=observation` and monotonic timestamp. Public
reason tokens are `new_bssid`, `ssid_changed`, `akm_changed`, `cipher_changed`,
`pmf_downgrade`, `rsnxe_changed`, `wps_enabled`, `wps_lock_changed`,
`country_changed`, `channel_changed`, `advertisement_conflict`, and
`malformed_observation`.

Status and terminal lines include `SCOPE=current_channel`, channel, baseline
metadata, storage/recovery state, receive/filter/invalid/profile/conflict counts,
severity counts, capacity/RX drops, output/storage failures, and running/stopping
state. Terminal outcomes are `ok`, `stopped`, `busy`, `invalid`, `timeout`,
`queue_overflow`, `restore_failed`, `storage_failed`, `storage_uncertain`, and
`output_failed`. Output failure has highest precedence; verified cleanup cannot
claim a complete observation set after capacity or shared-runtime loss.

Trust is passive and evidence-only. It sends no probe, authentication,
association, deauthentication, disassociation or raw frame and stores no packet
payload or credential. When inactive, ordinary and extended sniffer rows,
scanning, selection, help, and legacy global Stop bytes remain compatible.
Current validation is host-only: it does not prove firmware compilation,
FreeRTOS scheduling, driver callback fencing, RF reception, on-device channel
restore, PSRAM behavior or real SD durability. Firmware build, flash, controlled
RF work and real-SD/power-loss testing require separate approval.

### `wifi_shield`

See the dedicated [Wi-Fi Shield operator guide](wifi-shield.md) for mode and
evidence interpretation, and [Wi-Fi Shield validation](wifi-shield-validation.md)
for the TDD methodology, controlled-session ledger and remaining RF test matrix.

Built-in help is exactly:
`Wi-Fi Shield: start [--only indexes...] [--protect-all | --defence decoy-4way [--pmkid-decoy [--multi-vector]]] | status | report | log status | stop`.

The accepted command forms are exactly:

```text
wifi_shield start
wifi_shield start --only <scan-index> [scan-index ...]
wifi_shield start --only <scan-index> [scan-index ...] --defence decoy-4way
wifi_shield start --only <scan-index> [scan-index ...] --defence decoy-4way --pmkid-decoy
wifi_shield start --only <scan-index> [scan-index ...] --defence decoy-4way --pmkid-decoy --multi-vector
wifi_shield start --only <scan-index> [scan-index ...] --protect-all
wifi_shield status
wifi_shield report
wifi_shield log status
wifi_shield stop
```

Bare `start` performs one bounded scan while Shield owns its preparing lease,
then monitors the immutable valid BSSID/channel results. `--only` resolves
one-based indexes from a completed scan before radio mutation. Invalid,
duplicate or stale indexes reject the entire command. `status`, `report` and
`log status` are read-only. `report` emits bounded `[SHIELD/2] CAMPAIGN` and
`[SHIELD/2] AP_HEALTH` records followed by zero or more
`[SHIELD/2] RECOMMENDATION` records; `log status` emits one bounded
`[SHIELD/2] LOG` record. Both commands remain usable while Shield owns the
radio lease; the central admission gate treats them as read-only Shield
control, while the Shield parser still rejects malformed subcommands. After
cleanup they read a retained scalar snapshot
from a separate permanent PSRAM block rather than the wiped per-session PSRAM
state. That retained block is reset on the next accepted Shield start, and
neither command mounts storage,
writes the journal, tunes a channel, transmits, or admits radio work. Their
behavior is covered by the executable CLI and lifecycle harnesses, not only by
documentation string checks.

After the unchanged `[SHIELD/1] ARMED` record, a successful start publishes one
bounded target-identity record for every immutable selected target:

```text
[SHIELD/1] TARGET N=1/1 SSID="TP-Link_0E90" BSSID=b0:be:76:70:0e:90 CH=4
```

`N=<ordinal>/<total>` follows selection order. An empty SSID is printed as
`SSID="<hidden>"`; quotes, backslashes and non-printable SSID bytes are escaped
inside the quoted value, so scan evidence cannot inject another UART record.
The formatter uses the existing bounded start buffer and does not allocate.

Campaigns are keyed only by selected BSSID and retain normalized source
evidence. Threat order is `quiet -> watch -> attack -> critical`. The
correlation window is 30 seconds and the idle deadline is 60 seconds. An
isolated informational observation produces `REASON=isolated_activity`; an
isolated alert produces `REASON=isolated_alert`; correlated evidence from at
least two sources produces `REASON=cross_vector`. Loss lowers confidence but
never erases an observed event. `RX_DROPS`, `EVENT_DROPS`,
`OUTPUT_FAILURES`, `JOURNAL_DROPS` and sampled channel coverage therefore make
confidence limited without inventing or deleting source facts. Campaign IDs
are local to one Shield session and do not identify a transmitter.
`SESSION_PEAK` retains the highest threat reached by that BSSID during the
current Shield session, while `COMPLETED` is the saturating number of campaigns
closed by idle expiry or Stop. A later quiet campaign therefore cannot hide an
earlier Critical result in the operator report.

AP Health is a passive advisor for selected BSSIDs. It uses validated Beacon
and Probe Response posture plus observed beacon timing, RSSI, channel/CSA,
retry, Deauth/Disassoc and fresh neighbor evidence. It never changes router
settings. Beacon sequence gaps and jitter are local observations, not AP-side
packet-loss measurements; sampled coverage and local drops visibly limit their
confidence. Each advice item is a separate bounded record:
`[SHIELD/2] RECOMMENDATION BSSID=<mac> ACTION=<token> EVIDENCE=<token>
CONFIDENCE=<observed|limited>`. A recommendation reports its evidence and
uncertainty; it does not claim a vulnerability or a successful defence.
`EPOCH_CHANGES`, `CHANNEL_CHANGES` and `CSA_EVENTS` are reported separately.
CSA activity alone does not establish channel instability because the
announcement is spoofable; `channel_unstable` requires at least two observed
channel/band changes. `tsf_epoch_change_observed` likewise reports a spoofable
TSF discontinuity and does not claim that the selected AP restarted. The
JSONL recommendation state is a complete replacement set. A new
revision/index/count envelope makes a partially lost set detectable, an
unchanged periodic revision is only a reference, and count zero explicitly
withdraws the previous set. If admission loses any member of a replacement
set, the next selected Beacon opens a newer revision and retries the complete
set; the original admission loss remains counted.

Shield publishes an accepted standalone CSA observation as
`[SHIELD/2] EVENT SOURCE=deauth TYPE=csa_announcement BSSID=<mac> CH=<channel>
SEVERITY=info COUNT=1 WINDOW_MS=10000`. In the Stage 0 policy, a lone CSA
announcement never authorizes Defence TX, never increments `ALERTS`, and does
not by itself raise a campaign above informational activity. This Shield-only
policy does not change legacy `deauth_detector`, `deauth_detector_v2`, raw
`[CSA]` evidence, or the standalone Defence trigger API.

Every accepted Shield start makes one automatic journal attempt at
`/sdcard/lab/shield/shield-b<boot_id>-s<session_id>.jsonl.part`. The per-session
ceiling is 8 MiB. A dedicated writer owns the file and drains a fixed PSRAM
queue. The same transactional session bundle owns its journal coordinator and
writer stack; partial allocation rolls back without an internal-RAM fallback.
The journal queue depth is 32 PSRAM records. High-rate Deauth, Disassoc and CSA
observations are coalesced per selected BSSID/type into one-second windows
before queue admission. Their JSONL records add `count`, `first_boot_us`,
`last_boot_us` and `window_us`; detector, campaign, AP-health and `[SHIELD/1]`
counters still consume every observation. WPS, SAE, Trust and PMKID events stay
individually journaled. This bounds an RF burst without hiding its total and
still leaves room for AP health and a complete recommendation set. An aggregate
rejected by the zero-wait queue is closed and its represented observation count
is added once to `DROPS`/`ADMISSION_DROPS`; it is never merged into the next
one-second window.
The radio callback never formats JSON or calls the filesystem. Clean
Stop appends the actual terminal result, flushes and synchronizes the file and
SD metadata, closes it, and renames `.jsonl.part` to `.jsonl`. The same clean
finalization then creates:

```text
/sdcard/lab/shield/shield-b<boot_id>-s<session_id>-summary.txt
/sdcard/lab/shield/00-LATEST.txt
```

The summary is a human-readable scalar view with target/SSID, BSSID, channel,
mode, outcome, monotonic duration, threat, event totals, Defence options,
journal integrity and AP recommendations. For a multi-target session, the named
primary target is the first selected target and recommendations are scoped only
to that BSSID. It never contains WPS PINs, PSKs,
nonces, MIC/key material or station identities. `00-LATEST.txt` names the most
recent clean JSONL and summary. It is a convenience pointer updated from a
synced temporary file; the uniquely named JSONL files remain authoritative if
power is lost while that pointer is replaced.

Missing SD,
open/write/encode/sync failure, a full queue, or the quota is fail-open for
monitoring and Defence. `wifi_shield log status` reports state, path, bytes,
queue high-water, aggregate drops/failures, separate admission/encoding/write/
sync/finalization domains, sidecar failures through the aggregate failure count,
and available time sources. A summary/latest failure never rolls back a
finalized JSONL. Storage has no
in-session retry, and Shield never deletes older journals to make room; repair
or replace storage before the next session.

Radio cleanup uncertainty is different from a storage failure. A failed radio
restore durably checkpoints `session_uncertain`, retains the `.part` session,
PSRAM and writer, and reports `SHIELD/QUARANTINED`. A later
`wifi_shield stop` may recover the same radio generation, append its one actual
terminal, and finalize that same journal. A terminal admission or writer join
timeout retains a storage-pending owner; its later retry is storage-only and
does not repeat radio cleanup. A permanently unavailable/degraded journal is
reported but cannot by itself quarantine a radio that restored cleanly.

The authoritative journal ordering is `boot_id`, `session_id`, `sequence` and
monotonic `boot_us`. AP TSF is AP-relative and spoofable, never UTC. Exact TSF
comes from a Beacon/Probe Response; a fresh matching anchor may produce a
bounded estimated TSF. JSONL names these quality fields `ap_tsf_quality` and
`ap_tsf_uncertainty_us`. Calendar `epoch_ms` appears only with an already trusted
GPS clock and is always emitted as the complete `epoch_ms`, `time_source=gps`
and `time_uncertainty_ms` tuple. The current whole-second `time(NULL)` adapter
uses a conservative 1000 ms uncertainty. Untrusted time clears both scalar
fields and emits none of the tuple; Shield does not associate, start SNTP, or
fabricate wall time. AP-health JSONL keeps every measurement while using the
bounded schema keys `jitter_avg_us`, `same_neighbors`, `overlap_neighbors`,
`continuity_conf` and `timing_conf`.
Journal records contain normalized scalar evidence only: no raw frames, WPS
PINs, PSKs, PMKs, nonces, MIC/key material, station identities, or complete
decoy material.

Use this hardware acceptance flow only for an owned or explicitly authorized
AP; `--protect-all` enables bounded active Deauth/PMKID deception:

```text
scan_networks
wifi_shield start --only <scan-index> --protect-all
wifi_shield status
wifi_shield report
wifi_shield log status
wifi_shield stop
wifi_shield report
wifi_shield log status
list_dir lab/shield -s
```

Expected legacy indicators remain `[SHIELD/1] ARMED`, `[SHIELD/1] STATUS` and
one `[SHIELD/1] TERMINAL`; their existing bytes are unchanged. Successful start
adds one `[SHIELD/1] TARGET` record per selected target immediately after
`ARMED`, so consumers must ignore additive versioned record types they do not
use.
Read-only V2 commands produce `[SHIELD/2] CAMPAIGN`, `[SHIELD/2] AP_HEALTH`,
`[SHIELD/2] RECOMMENDATION` and `[SHIELD/2] LOG` as evidence becomes available.
A healthy clean run ends with `STATE=finalized`, a `.jsonl`, a matching
`-summary.txt`, and `00-LATEST.txt`. With no SD,
`LOG STATE=unavailable` is expected while Shield continues. Verify an
interrupted `.part`, full-card behavior, RF results and on-device task
high-water separately; a successful firmware build or host harness does not
prove them.

`stop` is idempotent and can retry retained cleanup; global stop does the same
before legacy Wi-Fi teardown. The internal `wifi_shield_start_*_profile`
functions, module enums and roadmap items are not public CLI.

Passive Shield makes exactly zero TX calls, including malformed input, queue
pressure, hopping and Stop. Defence requires `--only` and the exact
`--defence decoy-4way` value. It can act only for an immutable selected BSSID
and snapshotted channel whose scan evidence is WPA2-PSK/CCMP. Unknown,
unselected, multicast, malformed and unsupported-AKM observations stay
observe-only. `--pmkid-decoy` is separately explicit and experimental in the
granular form: `--defence decoy-4way` alone never implies it. The explicit
`--protect-all` preset is the exception and enables it as part of the complete
policy. In Shield, a selected Open Authentication plus Association sequence is
first a bounded PMKID candidate, not immediate attack proof. Shield waits 30 ms
for a matching standards-shaped EAPOL M2 from the same BSSID/station/channel.
M2 cancels the candidate, produces
`decision=observe reason=association_complete`, and causes no PMKID event,
counter contribution or decoy TX. Only a candidate still incomplete at the
deadline publishes `SOURCE=pmkid TYPE=sequence` and, when explicitly enabled,
reaches the existing PMKID-decoy policy. This grace gate uses fixed session
state in the Shield PSRAM arena and performs no heap allocation. It does not
change the legacy `deauth_detector_v2` wire or response timing.
`--multi-vector` is valid only after that complete granular active form.
Without it, the first successful PMKID or four-way decoy retains the existing
cross-action satisfied latch until 20 seconds of matching-BSSID inactivity.
With it, one successful PMKID decoy and one successful four-way decoy may run,
in either order, during the same BSSID campaign. Repeats of an already
completed action remain suppressed, a failed TX does not complete that action,
and the existing PMKID and four-way rate limits still bound retries. Another
BSSID remains observe-only while the campaign lock is active. The opt-in mode
announces `policy=multi_vector`; its release record keeps the compatible last
`response=` token and adds `completed=decoy_pmkid+decoy_4way` when both
responses completed. `--protect-all` is an explicit preset for the complete
selected-target active form: it enables `decoy-4way`, `pmkid-decoy` and
`multi-vector` while retaining the already combined passive WPS, SAE and Trust
monitors. It cannot be combined with granular Defence options. Its records
identify `MODE=protect-all`, `ACTIVE=deauth,pmkid` and
`PASSIVE=wps,sae,trust`. WPS, SAE and Trust never trigger an active response.

A one-channel plan reports `COVERAGE=continuous`, subject to driver and RX-drop
uncertainty. A multi-channel plan reports `COVERAGE=sampled`; only the current
resident channel is observed, so silence is not proof of absence. WPS activity
does not prove Pixie Dust, exploitation or a vulnerable router. SAE evidence
does not identify an attacker, and Trust drift does not prove an evil twin.
A completed decoy TX does not prove prevention, client retention or that a real
handshake was not captured. PMF/802.11w remains the protocol control for
protected management frames.

Large Shield state, frame slots, target snapshots, histories, queues and task
stacks are allocated in PSRAM with
`MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT` and `portBYTE_ALIGNMENT`. There is no
fallback to internal SRAM. Allocation is transactional; a failure prevents
`ARMED`. Successful cleanup closes callback and TX admission, joins workers,
drains output, restores radio state, wipes PSRAM and verifies lease release
before successful terminal publication. Uncertain callback close, join, TX
quiescence, filter/channel restore or lease release retains
`SHIELD/QUARANTINED`; `wifi_shield stop` or global stop retries it, and no
successful terminal is emitted while uncertainty remains.

Shield is an evidence and bounded-deception sensor, not a firewall. Host tests
do not prove firmware compilation, device behavior, physical PSRAM/SD behavior
or RF behavior. Firmware build, flash, physical storage, controlled passive RF
and separately authorized active Defence remain distinct acceptance gates.

### `client_isolation_audit`

Built-in help is exactly:
`Owned peer isolation audit: start <peer-ipv4> <32-hex-token> [--port 1024..65535] [--count 1..10] | status`.

The accepted command forms are:

```text
client_isolation_audit start <peer-ipv4> <32-hex-token> [--port <1024..65535>] [--count <1..10>]
client_isolation_audit status
```

`start` is a synchronous, owned-lab transaction. The default port is `48731`
and the default probe count is `3`. Count is limited to 1 through 10. Each
probe is limited to 32 datagrams per probe and 1000 ms per probe; setup and all
probes share a 15000 ms total command deadline. The peer must be a numeric IPv4
address in the connected STA subnet. JanOS accepts contiguous prefixes `/1`
through `/30` and rejects the local address, gateway, network, broadcast,
multicast, unspecified and limited-broadcast addresses. It snapshots BSSID,
local address, netmask, gateway and interface twice before socket I/O; any
connection change rejects the run.

Use this copy-ready owned-lab workflow:

1. On the second owned client, start the peer:
   `python tools/client_isolation_peer.py --bind 0.0.0.0 --port 48731`.
   Without `--token`, its generated secret is printed once to stderr as
   `[ISO_PEER_TOKEN/1] <32-uppercase-hex>`. An explicit test secret may instead
   be supplied with `--token <32-hex-token>` and is not echoed.
2. Copy that token to JanOS without saving it in shell history or evidence.
   The token is an authentication secret and never appears in `[ISO_PEER/1]`
   JSONL or any `[ISO_AUDIT/1]` record. JanOS overwrites the CLI token, frees
   console history and wipes its fixed 16-byte internal copies on every exit.
3. Confirm both owned clients are on the same SSID/BSSID, or record the exact
   intended multi-AP topology. Confirm the peer IPv4 is in the same subnet and
   the host firewall permits the selected UDP port.
4. Run `client_isolation_audit start <peer-ipv4> <token>`, adding matching
   `--port` and an optional `--count`. Keep the peer awake; client sleep, a host
   firewall, packet loss or an incorrect topology can all suppress replies.
5. Retain the paired JanOS `RUN` value and peer JSONL `run` value, then stop the
   peer with Ctrl+C. The peer binds to the first authenticated run and suppresses
   replayed challenges in a bounded window; restart it before a different run.

The peer emits secret-free `[ISO_PEER/1]` JSON objects with `monotonic_ms`,
`valid`, `replied`, `run`, `sequence`, `source_ip`, `source_port` and `type`.
JanOS emits complete CRLF records:

- `[ISO_AUDIT/1] BEGIN` owns `BSSID`, `LOCAL`, `PEER`, `PORT`, `COUNT` and
  `RUN`;
- `[ISO_AUDIT/1] PROBE` owns `SEQ`, `SEND`, `VALID`, `INVALID`, `TIMEOUT` and
  `RTT_MS`;
- `[ISO_AUDIT/1] END` owns `SENT`, `VALID`, `INVALID`, `TIMEOUTS`,
  `DURATION_MS` and `OUTCOME`;
- `[ISO_AUDIT/1] STATUS` is either `AVAILABLE=0` or
  `AVAILABLE=1 SENT=<n> VALID=<n> INVALID=<n> TIMEOUTS=<n> DURATION_MS=<n> OUTCOME=<token>`.

One authenticated matching reply proves that the tested client-to-client path
was reachable and produces `peer_reachable`; for an AP expected to isolate
clients, that is a tested isolation failure. No authenticated replies is
`inconclusive_no_reply` and never proves isolation. Invalid or unrelated
datagrams are telemetry only. Final evidence precedence is
`peer_reachable > local_error > cancelled > inconclusive_no_reply`: proof is
retained even if a later local error or cancellation occurs, while
`local_error` outranks cancellation without proof. `status` does not repeat a
token, nonce or tag, and there is deliberately no feature-specific Stop command.

Current evidence is host-only and does not prove firmware compilation, device
socket behavior, AP isolation, RF delivery or a real network result. Separate
device/network acceptance requires explicit approval and an owned AP tested
with isolation both off and on, an owned peer kept awake, documented host
firewall state, an independent capture, three repeated paired runs, and a
second owned AP/SSID topology where supported. Silence remains inconclusive in
every device run.

### `router_audit`

Built-in help is exactly:
`Gateway inventory/CVE audit: scan passive | scan standard --owned | status | db status|verify|install [--allow-time-unknown]`.

The accepted forms are exactly:

```text
router_audit scan passive
router_audit scan standard --owned
router_audit status
router_audit db status
router_audit db verify
router_audit db install
router_audit db install --allow-time-unknown
```

`scan passive` uses the connected STA/IP snapshot, cached gateway ARP entry and
local OUI evidence only; passive mode performs zero network I/O. `scan standard
--owned` is authorized only for a router you own or are permitted to test. It
sends one unicast SSDP M-SEARCH to the literal gateway, accepts at most four
gateway-source responses within one 2000 ms transaction budget, follows at
most one strictly validated gateway HTTP location, and sends one bounded HEAD
request. It never multicasts, resolves a host name, follows a redirect, tries
credentials, changes configuration or contacts an off-gateway address.

Identity is evidence, not attribution. Only a confirmed, nonconflicting,
nontruncated exact vendor/model identity is eligible for catalog lookup.
`EXACT_FIRMWARE` means that the exact normalized firmware string occurs in one
reviewed rule; `MODEL_CANDIDATE` means only that the exact model matched and a
person must review the advisory. The command never claims that a router is
vulnerable or exploitable, safe, patched or compromised.

The versioned `[ROUTER_AUDIT/1]` records, source-governance policy, signed
`JCVE/1`/`JCSG/1` release process, pair-atomic install/recovery behavior and
separate build/device acceptance gates are specified in
[Router CVE catalog governance](router-cve-catalog.md). Untrusted text is
percent-escaped and each complete record is published in one bounded write.
The firmware performs no download of vulnerability data.

`db install --allow-time-unknown` is an explicit exception, not a freshness
claim. Its `TIME_UNKNOWN=1` state is bound into the trusted commit and remains
visible after recovery. A release must provision an approved production trust
anchor by key ID; this repository deliberately provisions none, so an
unprovisioned build returns `UNKNOWN_KEY` rather than accepting a test key.

Current validation is host-only. It includes no firmware build, no real
router, no real SD/NVS and no physical power-cut. The host Mbed TLS development
package was unavailable, so the production adapter has a source gate rather
than an ESP-IDF compile result. Firmware build, trust-anchor provisioning and
owned-router testing each require separate approval.

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
mini-OS image is required. The separate production `sta_mac` command configures
the boot STA identity used by WPS; see [STA MAC boot policy](#sta-mac-boot-policy).

Radio-mutating legacy commands, `test_radio_channel(s)`, analyzer startup and
online WPS/JWPS reserve an owner plus generation before the dispatcher unlocks:
`LEGACY`, `ANALYZER` or `WPS`. Analyzer `clear` is a short legacy transaction;
manual OTA may use only its own exact legacy token, while event-triggered OTA
remains idle-only. Status/read and stop exceptions stay available, and no
admission lock spans handler execution. Conflicts retain the exact legacy
WFACTL1 busy line and nonzero console result documented in
[shared radio ownership](janos-radio-lease.md).

### `scan_networks`
- `scan_networks` — background Wi‑Fi scan on all channels. Results auto‑print as CSV; wait for `Scan results printed`. CSV: `"index","SSID","","BSSID","channel","security","RSSI","band"`. The third field is the vendor name (empty when vendor lookup is off). SSID and vendor are each enclosed in exactly one pair of double quotes. A `"` inside either field is written as `""` (RFC 4180). A comma, CR, or LF stays inside that same pair. Example: SSID `moja "specjalna" siec` is the field `"moja ""specjalna"" siec"`. Wardrive must be stopped first.

### `show_scan_results`
- `show_scan_results` — reprint the last scan results (same CSV, including the SSID and vendor quoting rule above).

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
- `deauth_detector [i1 i2 ...]` — observe deauth frames and CSA/ECSA channel-switch announcements on all hopping channels, or channels from selected scan indices. Stop with `stop`. The existing no-argument startup scan is unchanged; CSA observation sends no countermeasure frames.
  - `deauth_detector --only <i1> [i2 ...]` — watch only the exact BSSIDs at these 1-based indices from the current completed scan cache. Run `scan_networks` immediately before selection; another scan can replace the cache. For example, `deauth_detector --only 1 3` filters both `[DEAUTH]` and `[CSA]` events to those two APs and hops only their distinct scan channels. The short `[DETECTOR_WATCH]` startup lines show the captured BSSID, SSID and channel for confirmation. A missing/in-progress/failed scan or any invalid index rejects the whole command. The filter is fixed at startup; rescan and restart if an AP changes channel. Select every relevant index when several APs share an SSID. A frame's BSSID is claimed and can be spoofed.
  - Bare indices without `--only` keep their previous channel-only meaning: events from any BSSID on those channels can appear.
  - Legacy output syntax/order is unchanged: `[DEAUTH] CH: .. | AP: .. (BSSID) | RSSI: ..`. `CH` now uses the actual C5 receive channel, so tuning failures cannot mislabel a received deauth.
  - CSA output: `[CSA] RX: 6 | TO: 36 | BSSID: AA:BB:CC:DD:EE:FF | TX: 02:11:22:33:44:55 | RSSI: -51 | VIA: beacon | COUNT: 3 | MODE: 1 | CLASS: - | SSID: Example`.
  - `RX` is the actual C5 receive channel. `TO`, `COUNT`, `MODE` and ECSA `CLASS` are raw advertised bytes, including anomalous values. `CLASS` is `-` for plain CSA. `TX` is claimed Address 2; `BSSID` is Address 3. Neither identity is authenticated by this observation. `VIA` is `beacon`, `probe`, or `action`. SSIDs are at most 32 printable characters; controls/non-ASCII/`|` become `?`. Absent/empty names are `<Unknown>`. SSID fallback uses a bounded scan snapshot for the run.
  - Supports IE 37/60 in complete beacons/probe responses, spectrum-management CSA actions (category 0/action 4), and public ECSA actions (category 4/action 4). Truncated/error/encrypted/fragmented/HT-Control frames, malformed IE streams and conflicting announcements are ignored. Requires a positive complete C5 `dump_len`.
  - Repeated BSSID/TX/RX/target/mode/class announcements are limited to once per two seconds regardless of countdown/RSSI/source subtype. First announcements for up to 16 distinct keys can be emitted per two-second window. Extra observations exceeding this capacity and event-queue overflow are reported separately. Stop/restart clears queued events and rate state.
  - Announcements can be legitimate AP channel changes, including DFS; they do not establish an attack. Hopping coverage depends on band mode, connection state, regulatory settings and dwell time. Initial tuning failures abort startup; later tuning failures are reported at most every two seconds. The detector does not force a band-mode change on an existing connection.
- `deauth_detector_v2 [i1 i2 ... | --only i1 i2 ...] [trace] [defence [pmkid-decoy]]` — use the same no-argument startup scan, channel selection, `--only` BSSID filtering, CSA output, and `stop` behavior with detailed deauth records. Versioned deauth/disassoc forensic evidence is enabled by default in every V2 form and has no separate command token. Supported passive forms remain `deauth_detector_v2`, `deauth_detector_v2 1 3`, and `deauth_detector_v2 --only 1 3`. Active Defence is accepted only with a fresh, completed `--only` selection; otherwise startup fails with `Defence requires --only protected scan indices.`
  - V2 now runs as a Deauth-only compatibility profile of the shared Wi-Fi Shield runtime. This ownership migration does not change legacy V2 record bytes, ordering, Forensics, Trace, Defence, LED or OLED behavior. The legacy `deauth_detector` remains on its direct established path.
  - Trace examples: `deauth_detector_v2 trace`, `deauth_detector_v2 1 3 trace`, and `deauth_detector_v2 --only 1 3 trace`. A successful trace start reports `[DETECTOR_TRACE] armed` immediately after `[DETECTOR_INFO] format=deauth_v2`. The first queued DEAUTH event accepted by the current selection starts a one-second confirmation and reports `[DETECTOR_TRACE] confirming_bssid=<bssid> first_channel=<ch> window_ms=1000`. Only observations claiming that first BSSID contribute to the choice; other accepted DEAUTH records are still emitted normally. Confirmation samples receive channels within ±2 on 2.4 GHz, or the previous/current/next entries in the detector's 5 GHz channel list. It selects the channel with the most frames, then the strongest average RSSI; the BSSID's startup scan-cache channel wins an exact tie, followed by the first receive channel. The final result is `[DETECTOR_TRACE] locked_channel=<ch>` and stops detector-initiated hopping. Locking can therefore occur after several `[DEAUTH_V2]` records rather than before the first one.
  - After passive Trace locks, an unknown BSSID gets a 750 ms SSID-resolution window on that channel. A matching beacon or probe response with a non-empty SSID fills a detector-only eight-entry cache without scanning. If the window expires unresolved, JanOS performs exactly one active scan limited to that BSSID and locked channel, with 20–60 ms active dwell, then drains its private result without replacing the main scan cache or changing `--only` indices. A miss is not retried during the same Trace lock. The first event can therefore remain `SSID: <Unknown>` while later records use the resolved name. Hidden/empty SSIDs and absent responses remain unknown. This resolver is disabled in Defence mode. The fallback active scan can transmit 802.11 probe requests; it is not a countermeasure and sends no deauthentication, disassociation, jamming, CSA, or decoy handshake frame.
  - During confirmation, selected-channel forms can temporarily sample nearby channels; `--only` still filters by the captured BSSIDs. CSA/ECSA announcements, short frames, and filtered DEAUTH frames do not start or score confirmation, and advertised CSA `TO` is never used as the lock channel. Queue-overflow losses are not scored and can bias the sample. A spoofed DEAUTH can start confirmation, including under `--only` if it claims a watched BSSID. A failed final tune reports `[DETECTOR_TRACE] lock_failed_channel=<ch> error=<name>` at a limited rate, returns to hopping, and lets a later accepted DEAUTH begin a new confirmation.
  - While locked, only an accepted DEAUTH claiming the confirmed BSSID refreshes the idle deadline. After 20 seconds without such an observation, Trace emits `[DETECTOR_TRACE] released_channel=<ch> reason=idle idle_ms=20000`, immediately emits `[DETECTOR_TRACE] armed`, and resumes detector-initiated hopping. CSA/ECSA and other BSSIDs do not keep the lock alive. Queue overflow can drop the matching observations that would have refreshed the deadline and can therefore cause an early release. A later eligible DEAUTH starts a new one-second confirmation. `stop` clears pending confirmation, the idle deadline, and an established lock; a new run starts armed but unlocked. A connected Wi-Fi mode can still let the driver control the physical radio channel, so continuous residency is not guaranteed. A DEAUTH observation alone does not establish an attack, prove that it ended, or prove a client disconnected. Trace provides no active defense and transmits no countermeasure frames; only the bounded SSID fallback above may actively probe. The legacy `deauth_detector` command is unchanged.
  - Defence examples are `deauth_detector_v2 --only 1 3 trace` (passive Trace), `deauth_detector_v2 --only 1 3 trace defence` (bounded decoy four-way response), and `deauth_detector_v2 --only 1 3 trace defence pmkid-decoy` (also the experimental PMKID decoy). `defence` implies fast Trace even when the explicit `trace` token is omitted. JanOS copies the selected BSSIDs and channels from the completed scan, emits `[DETECTOR_WATCH]` proof lines, then starts `WIFI_SECURITY_MODULE_DEAUTH_V2` under `JANOS_RADIO_OWNER_SECURITY_MONITOR`. Unknown or unselected BSSIDs are observe-only and can never reach raw TX. Active response TX and its Trace lock stay pinned to the selected BSSID's startup scan channel; an overlapping receive observed while Trace samples an adjacent 2.4 GHz channel cannot steer a response away from the protected AP. Passive Trace channel scoring is unchanged.
  - The default active response is limited to scan entries confirmed as WPA2-PSK/CCMP. It sends a coherent decoy EAPOL M1+M2 made from a fresh random 256-bit PMK; it does not send deauthentication, disassociation, jamming, or corrective/reverse CSA. WPA3-SAE-only, OWE, mixed/unsupported, open, WEP, and non-CCMP profiles report `observe_only_unsupported_akm`. The decoy does not prevent a real handshake from also being captured and must not be described as proof that an attack ended.
  - The first successful decoy PMKID or four-way response latches that BSSID as satisfied. Further eligible triggers refresh activity but remain observe-only until 20 seconds of inactivity releases and rearms the BSSID. This cross-action latch prevents a PMKID success from being followed by an unnecessary four-way decoy. The underlying failure limits remain one pair per 1000 ms and at most three attempts in a rolling 10 second window; they still bound retries when a response does not complete. `pmkid-decoy` additionally correlates one Open Authentication Request with Association/Reassociation from the same station within 2000 ms and retains its per-BSSID/station 5000 ms limit. A full PMKID station table fails closed instead of evicting a still-active cooldown. PMKID mode is experimental because a legitimate client join has the same observable sequence; it is never enabled by ordinary Defence.
  - Defence telemetry is emitted only by the worker as `[DETECTOR_DEFENCE] armed`, `trigger`, `provisional_bssid`, `tx`, `suppressed`, `released_bssid`, and `stopped` records. Repeated `rate_limited_cooldown`, `rate_limited_window`, and `pmkid_rate_limited` observations are aggregated per BSSID for one second as `[DETECTOR_DEFENCE] suppressed=<n> reason=<token> BSSID=<mac> window_ms=1000`. A satisfied latch stays silent while traffic continues: `response_satisfied` never produces a periodic serial line. Its observations are counted and reported once when that campaign becomes idle as `[DETECTOR_DEFENCE] released_bssid=<mac> channel=<ch> reason=idle idle_ms=20000 response=<decoy_4way|decoy_pmkid> suppressed=<n>`. Stop reports `[DETECTOR_DEFENCE] stopped observations=<n> tx_pairs=<n> pmkid_m1=<n> responses=<n> satisfied=<n> errors=<n> dropped=<n> outcome=<responded|observed|idle>`. `responded` means that at least one decoy TX completed, `observed` means selected-target traffic was processed without a successful response, and `idle` means no selected-target observation was processed. None of these values proves that an attack was prevented or that a real handshake was not captured. Duplicate active-mode `[DEAUTH_V2]` lines remain omitted, while default `[DEAUTH_FORENSIC/1]` evidence remains visible and OLED detection counters remain complete. Passive V2 and passive Trace output are unchanged. No PMK, PTK, KCK, nonce, or other raw secret is printed. `stop` first closes the RX generation, disables further response TX, disables promiscuous receive, joins the worker, restores the saved channel, zeroizes material, and releases the lease. Failed or uncertain restore remains fail-closed under the shared radio lease.
  - Validation boundary: host tests cover parsing, allowlists, state/rate policy, exact frame bytes, crypto known-answer vectors, callback bounds, lifecycle rollback, telemetry, and Stop ordering. They do not prove ESP32-C5 driver acceptance, over-the-air timing, receiver behavior, campaign interruption, or client impact. Those claims require separate controlled RF validation on the operator's own APs; this source change has not performed RF validation or firmware/device testing.
  - After a successful start, `[DETECTOR_INFO] format=deauth_v2` precedes the first new event. Each queued deauth frame produces one record, with no parallel legacy line: `[DEAUTH_V2] CH: 2 | BSSID: D8:CF:61:5D:41:10 | TX: AA:BB:CC:DD:EE:FF | DA: FF:FF:FF:FF:FF:FF | RSSI: -40 | REASON: 7 | SSID: Example`. `CH` and `RSSI` come from receive metadata; `BSSID`, `TX`, and `DA` are frame Addresses 3, 2, and 1, respectively. `REASON` is the little-endian 16-bit reason code; it is `-` for protected unicast frames whose body is encrypted. `SSID` is the last field and normally comes from the BSSID-matched startup scan snapshot, not the deauth frame; Trace can later enrich it through the bounded resolver described above. It is limited to 32 characters: printable UTF-8 is retained, while controls, ANSI sequences, `|`, and malformed UTF-8 are removed. An empty result is `<Unknown>`. Each record is at most 256 bytes. Queue overflow can drop observations.
  - For each accepted deauth or disassoc frame, V2 first emits one strict evidence record: `[DEAUTH_FORENSIC/1] FRAME=<deauth|disassoc> CH=<1..233|-> BSSID=<mac> TX=<mac> DA=<mac> RSSI=<-127..0|-> REASON=<0..65535|-> SEQ=<0..4095|-> RETRY=<0|1|-> PROTECTED=<0|1|-> FC=<0x0000..0xFFFF|-> TS_US=<0..UINT64_MAX>`. `BSSID`, `TX`, and `DA` are Addresses 3, 2, and 1 from the received header. `SEQ` is the raw 12-bit sequence number; `RETRY`, `PROTECTED`, and `FC` come from frame control; `TS_US` is monotonic JanOS boot time captured at receive. `REASON` is `-` when a protected unicast body cannot be interpreted, and unavailable channel/RSSI metadata is also rendered as `-`. The callback performs only bounded copying; the detector task owns formatting and output. Short or rejected frames, BSSIDs excluded by `--only`, stale generations, and queue-overflow losses emit no forensic record. Passive disassoc evidence does not create a normal V2 event, OLED threat count, sound, alarm, Trace decision, or Defence response. Legacy `deauth_detector` never emits this marker.
  - Forensic records are evidence only. The claimed transmitter, retry bit, protection bit, sequence continuity, and burst shape do not identify an attacker, prove that the AP sent a frame, prove client disconnection, or prove that Defence prevented an attack. No PMK, PTK, KCK, nonce, payload, or other secret is included.
  - `TX` identifies only the claimed transmitter, not a verified attacker. `DA` can be broadcast and does not prove that any particular client disconnected. V2 forms without `defence`, including Trace, provide no active defense or countermeasure; Trace may only send the single targeted probe scan documented above to resolve an unknown SSID.
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
- PMKID capture runs alongside `start_handshake` in both selected-target and automatic D-UCB modes. It actively initiates two STA authentication/association attempts per AP before deauth, then observes unencrypted PMKID KDEs in EAPOL-Key and PMKID lists in association/reassociation request/response RSN elements. It respects target selection and `white.txt`. Original received frames are automatically saved as `/sdcard/lab/handshakes/{SSID}_{MAC_suffix}_{timestamp}_pmkid.pcap`, even without a complete handshake. Each file contains the PMKID-bearing frame plus a previously observed beacon/probe response for that BSSID when available. Missing SSID/beacon context is reported; received frames are never synthesized. `PMKID saved: <path>` means the PCAP was committed successfully, and does not mean a complete handshake was captured. PMKID files do not cause handshake targets to be skipped, and capture continues after saving them. There is no PMKID HCCAPX or `.22000` export.
- PMKID reception uses eight reusable frame slots (maximum 2500 bytes per frame), an eight-BSSID beacon cache, and a separate SD writer. Deduplication keeps up to 256 successfully saved `(full BSSID, client MAC, PMKID)` tuples per run; after this limit, new tuples are dropped without evicting saved identities. Writes use `.part`, checked flush/sync/close and rename; failed writes do not enter deduplication, so another received copy can retry. `stop` quiesces producers and drains accepted frames before releasing the session; slow SD writes may leave the existing `[HS-STOP] ... stop_pending` response until cleanup finishes. Final `[HS-PMKID]` counters report saved files, queue/RX drops, dedup-capacity drops and write failures. Files contain only frames actually received on the currently monitored channel.
- PMKID diagnostics are printed directly to UART, independently of the ESP-IDF log level. `[HS-PMKID] started mode=selected|D-UCB sources=EAPOL-Key,RSN output=*_pmkid.pcap` confirms successful detector/writer initialization. `[HS-PMKID] detected bssid=... new_pmkids=N` confirms new PMKIDs reached the writer; `PMKID saved: <path>` confirms successful publication. `[HS-PMKID] write_failed` reports storage failure. On `stop` or automatic completion, `[HS-PMKID] stopped frames_checked=N pmkid_frames=N saved=N ...` reports parser invocations (before target filtering, excluding cached beacon/probe frames), frames containing PMKID accepted by target/whitelist filters (including retransmissions), and successfully saved files. A startup marker alone does not prove any PMKID was received.
- Before any client deauthentication, every selected or D-UCB-discovered WPA AP gets two clientless active PMKID attempts. JanOS temporarily uses its STA MAC to run authentication/association with the target BSSID, listens 2500 ms for M1/RSN, disconnects, and repeats. D-UCB performs this AP-first stage even when no client has been discovered and does not make an AP's clients eligible for deauth until both attempts finish. UART prints `phase=before_clients` in D-UCB and `[HS-PMKID] attempt=N active_try=1/2|2/2 ... method=sta_auth_assoc`, followed after pending writes drain by `result=success reason=pmkid_saved|already_saved` or `result=failed reason=no_pmkid_received|write_failed|capture_dropped|stopped|sta_auth_assoc_start_failed`. Afterwards the normal client/deauth handshake phase begins. `no_pmkid_received` describes that observation window only.
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

The USB file manager uses `fs hello`, `fs ls`, `fs get`, `fs put`, `fs rm` and
`fs cleanup` on UART0.
Paths are Base64-encoded OEM CP437 bytes relative to `/sdcard/lab`; uploads use
an ACK32 binary stream. `fs rm <path64>` removes one regular file or empty
directory and never deletes recursively. `fs cleanup <path64>` removes only an
abandoned `.fs-part` upload staging file. See the [FS/1 protocol](fs-protocol.md)
for the exact wire format, error responses and recovery safeguards.

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

### RGB status LED

The single RGB LED shows the **type of active operation**. Commands in the same
group share a color and pattern; it does not identify an individual command.
The pattern changes automatically when an operation starts or finishes.

| Operation | Color and pattern | Examples |
| --- | --- | --- |
| Idle | Steady green | No active operation after boot or a completed `stop`. |
| Scan and discovery | Blue, slow 2 s pulse | Wi-Fi/BLE/802.15.4 surveys and network discovery. |
| Passive monitoring | Cyan, 500 ms blink cycle (250 ms on / 250 ms off) | Sniffers, packet monitor, deauth detector, anti-surveillance. |
| Capture and recording | Cyan, two short 120 ms flashes every 2 s | Handshake, PCAP, wardrive, Capture Gateway recording. |
| Active transmission | Red, 150 ms on / 150 ms off | Deauthentication, beacon/BLE spam, blackout, jammer, ARP ban. |
| AP and portal | Magenta, slow 2 s pulse | Captive/admin portals, Evil Twin, Karma, Rogue AP/GITM. |
| WPS | Amber, slow 2 s pulse | WPS verify/Pixie/campaign. |
| Transfer and computation | Amber, 500 ms blink cycle (250 ms on / 250 ms off) | Active uploads, file transfers, `crack_worker start`. |
| OTA installation | Red, slow 2 s breathing pulse | Firmware installation after an update has been selected. |

If operations overlap, the visible pattern follows this priority: OTA,
transmission, AP/portal, capture, WPS, monitoring, scan, transfer/computation,
then idle. Short event flashes temporarily replace the active pattern except
for OTA installation, then it resumes:

| Event | Flash |
| --- | --- |
| Handshake successfully saved to SD | Three white flashes, 100 ms each. |
| WPS verification succeeds | Two green flashes, 150 ms each. |
| A `scan_networks` Wi-Fi scan observes a first-seen BSSID, or a BLE scan records a first-seen device | One 100 ms white flash, at most once every 2 s. Wi-Fi emits at most one discovery event per scan. |
| A deauth or anti-surveillance follower alert is detected | Three 100 ms red flashes, at most one sequence every 2 s. |

The handshake confirmation fires after both PCAP and HCCAPX are saved. In
selected/manual capture, both files must pass complete write, flush, sync, and
close checks. Automatic capture reports success only after publishing both
files.

Wi-Fi discovery remembers up to 128 BSSIDs per boot. Once full, the cache
suppresses further Wi-Fi discovery flashes; repeated BSSIDs never flash again
during that boot.

`led set off` suppresses all patterns and discards pending event flashes.
`led set on` restores the pattern for the current operation, or idle green if
none is active.
`led level <1-100>` changes brightness, including while the LED is off;
enablement and brightness persist in NVS. `led read` reports enablement and
brightness, not the current operation. `stop` returns the LED to idle only
after the operation actually ends; a short event flash returns to the
underlying pattern. Read-only `help`, `list`, `read`, and `status` commands do
not establish a lasting LED pattern.

### STA MAC boot policy

The production STA MAC command accepts exactly these forms, with no aliases or
extra arguments:

```text
sta_mac status
sta_mac set factory
sta_mac set random
sta_mac set fixed 02:11:22:33:44:55
```

`factory` selects the factory STA address. `random` generates one locally
administered unicast address per application boot and keeps it through Wi-Fi
driver stop/reinitialization. `fixed` requires exactly six colon-separated
hexadecimal octets; the first octet must satisfy `first_octet & 3 == 2`
(locally administered and unicast). The policy affects the STA interface, not
the SoftAP, BLE or IEEE 802.15.4 identities.

`set` saves the policy to NVS after a checked commit. It takes effect on the
next application boot: it neither reboots nor changes the running STA MAC.
Successful set output is JSON with `schema_version:1`,
`record_type:"sta_mac_result"`, `result:"set"` and
`applies_after_reboot:true`.
Missing or extra arguments and an invalid MAC return nonzero without changing
the saved policy. A failed NVS write or commit also leaves the configured
policy unchanged. Unlike `wifi_country`, this NVS record is not tied to the
firmware image.

`status` is read-only, available while another radio owner is active or
quarantined, and does not initialize Wi-Fi. Its JSON has `schema_version:1`,
`record_type:"sta_mac_status"`, and the fields
`configured_mode`, `boot_mode`, `configured_mac`, `effective_boot_mac`,
`active_sta_mac`, `record_health`, `identity_ready` and `pending_reboot`. `configured_mode` is the
saved next-boot choice; `boot_mode` and `effective_boot_mac` describe this
boot. `configured_mode` is `null` when the saved choice is invalid or could not
be read.
`active_sta_mac` is `null` when the driver is unavailable. `record_health`
describes the boot read (`valid`, `missing`, `invalid_record`,
`unsupported_version`, or `read_error`); `identity_ready:false` blocks Wi-Fi
startup. A missing NVS
record selects factory; an invalid or future record reports its health and
falls back to factory without rewriting the record. An NVS read I/O error is
reported separately and prevents Wi-Fi startup under an unverified identity.

`set` uses a short serialized radio transaction and is refused while a radio
owner is active or quarantined; the normal busy result is nonzero. WPS may use
a temporary session MAC and restores the effective boot STA MAC after an exact
readback. Host tests exercise parsing, persistence, boot caching and restore
logic; firmware build and on-device radio behavior require separate validation.

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
- `ping` — connectivity test; replies `pong` even while another operation owns the radio.
- `version` — print firmware version (`JanOS version: X.Y.Z`) even while another operation owns the radio.
- `download` — force a transition into ROM download (UART flashing) mode. A bare command is admitted while a radio owner is active, runs the universal `stop` path, and arms ROM boot only after every affected worker reports a safe stop; a failed or uncertain Stop refuses the transition without setting the ROM flag. Extra arguments and a genuinely concurrent command remain blocked. The retained `WPS/QUARANTINED` recovery remains a separate terminal path: once callbacks are closed and the WPS worker has finished, it wipes retained buffers and resets directly to ROM without claiming in-place radio recovery.
- `help [command]` — list all commands or show help for one.

---

*Generated for the MonsterC5 / ESP32‑C5 build. New in this build: the `set_wardrive_*`, `wardrive_blacklist`, `get_wardrive_config`, `start_antisurveillance` and `set_antisurv_sensitivity` commands (Part 1).*
