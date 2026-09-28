# WFA/1: JanOS Wi-Fi analyzer protocol

Status: implemented in JanOS source as a one-shot scanner, pending firmware build
and device validation. `tools/wifi_analyzer_contract.py` validates the **snapshot
stream** from a capture. It does not validate CLI/control replies or scan hardware.
See the [architecture and compatibility design](wifi-analyzer-design.md).

## Commands

These new commands do not change `scan_networks`, `show_scan_results` or
`channel_view`. Options are per request, never saved in NVS.

```text
wifi_analyzer caps
wifi_analyzer scan [--band 2.4|5|both] [--channels 1,6,11] [--profile quick|detailed|passive] [--limit 1..128]
wifi_analyzer status
wifi_analyzer stop
wifi_analyzer clear
```

Defaults: `band=both`, all candidate channels in that band subject to the
driver's regulatory filtering, `profile=quick`, `limit=64`. Reject duplicate
options, malformed lists, channels outside the selected band or an explicitly
known country restriction, unknown arguments, or unsupported profiles.
An explicit list is nonempty and duplicate-free. It is not a set of UI filters.

Only one scan may be outstanding. `stop` cancels only analyzer work and is
idempotent. `clear` frees cached analyzer resources only while idle; it does not
clear legacy scan results. There is no v1 `start` or `results` command: Tab5
implements repeat scans, and reconnects request a fresh scan.

## Control replies

Control lines start with `[WFACTL1] ` and contain one JSON object followed by LF
(CRLF accepted). All have integer `v:1`. They are separate from snapshot records
so a busy command or status request cannot terminate an in-flight snapshot.

Examples of required shapes:

```text
[WFACTL1] {"v":1,"type":"caps","protocol":"WFA/1","default_records":64,"max_records":128,"max_line_bytes":1024,"bands":["2.4","5"],"profiles":["quick","detailed","passive"],"width_metadata":"sdk_unverified","channel_scope":"requested_driver_filtered"}
[WFACTL1] {"v":1,"type":"status","state":"idle","boot":"0123456789abcdef","active_scan":null,"last_success_scan":1,"last_error":null,"psram_bytes":65536,"capacity":64,"driver_scan_id":1}
[WFACTL1] {"v":1,"type":"error","command":"scan","code":"busy","reason":"wardrive"}
[WFACTL1] {"v":1,"type":"stopped","state":"idle"}
[WFACTL1] {"v":1,"type":"cleared","state":"idle"}
```

`psram_bytes` is an actual owned allocation total; example memory, capacity and
driver scan ID values are illustrative. `width_metadata=sdk_unverified` means the
C adapter maps raw SDK width/center fields and sanitizes inconsistent geometry;
those values have not been checked against target APs. Individual APs may have
unknown width. `channel_scope=requested_driver_filtered` means reported channels
are the requested plan after filtering through current driver country settings.
They are not proof of dwell or observed RF coverage. Status states
are `idle`, `preparing`, `scanning`, `collecting`, `publishing`, `cancelling`,
`quarantined`. Failed stop returns an error with `code:radio_fault`. Missing scan
completion keeps radio ownership reserved until a late completion allows cleanup
or the device restarts.

Pre-admission error codes: `invalid_argument`, `unsupported_channel`, `busy`,
`no_psram`, `no_internal_memory`, `radio_fault`, `wifi_init_failed`,
`radio_config_failed`, `restore_failed`, `unavailable`. They produce no `begin`. `caps` and `status` do not allocate
bulk buffers or change radio mode. Stop/clear acknowledgements are emitted only
after the respective action is complete. Unknown additive control fields may be
ignored. Unsupported versions must be rejected by the host.

`busy` reasons include `wifi_analyzer`, `command_in_progress`,
`legacy_scan_draining`, `wifi_connect`, `radio_busy`, and
`legacy_radio_uncertain`. A forced legacy wardrive deletion or failed/timed-out
`wifi_connect`, or a failed Wi-Fi initialization cleanup, leaves radio ownership uncertain; analyzer admission stays
blocked until reboot. A normal legacy asynchronous scan stays pending until its
completion callback finishes. A successful analyzer `end` precedes worker
release, so a scan started immediately afterward may briefly receive `busy`.
Use a short delay (at least 100 ms) or a bounded retry after `status=idle`.

## Snapshot framing

Every record starts at a line boundary with `[WFA1] ` and one strict JSON object.
Maximum line length is **1024 bytes including the prefix, excluding CR/LF**.
Reject duplicate JSON keys, NaN/Infinity, invalid UTF-8 and invalid required types.
Integer fields do not accept JSON booleans. Unknown additive fields are ignored;
they must not overwrite validated host model fields. Unknown record types or
protocol versions invalidate the transaction.

Unrelated complete console lines, including control replies, may appear between
records and are ignored by the snapshot reader. A partial line is not a record.
On line overflow discard through the next CR/LF, invalidate the working snapshot,
and recover at a new `begin`. Never interpret the suffix of an overlong line as
a new frame. Transport writers must prevent log bytes interleaving within a line.

All snapshot records share:

| Field | Contract |
| --- | --- |
| `v` | Integer `1`. |
| `type` | `begin`, `ap`, or `end`. |
| `boot` | 16 lowercase hex digits, generated once per boot; scopes scan IDs. |
| `scan` | Integer 1..4294967295, strictly increasing per boot for admitted requests. Never the driver's 8-bit ID. |

A new boot requires a new reader/context and discarding partial state. Do not
silently merge old/new boot history. IDs do not wrap: reject new requests with
`radio_fault` at exhaustion until restart. Cached result replay is not part of v1.

## Begin record

```text
[WFA1] {"v":1,"type":"begin","boot":"0123456789abcdef","scan":1,"limit":64,"band":"both","channels":[1,6,36],"profile":"quick","started_ms":1000}
```

| Field | Contract |
| --- | --- |
| `limit` | Integer 1..128; maximum AP records in this response. |
| `band` | `2.4`, `5`, or `both`. |
| `channels` | Nonempty, unique effective channel plan after capability/regulatory validation. At most 42 entries. |
| `profile` | `quick`, `detailed`, or `passive`. |
| `started_ms` | Nonnegative monotonic milliseconds since boot, up to signed 64-bit max; not UTC. |

The reference reader recognizes 1..14, 36..64 step 4, 100..144 step 4,
and 149..177 step 4. This is a representable set, not permission to scan every
channel. Firmware filters the requested plan using the driver's current country
settings and submits a channel bitmap. It does not install a broader country
setting for the analyzer. `channels` is requested scope after that filtering,
not verified dwell-time telemetry.

`begin` reserves an empty working snapshot. A new valid `begin` may resynchronize
after a lost end, but the incomplete previous transaction must be reported as an
error. The previous published snapshot remains visible until successful commit.

## AP record

```text
[WFA1] {"v":1,"type":"ap","boot":"0123456789abcdef","scan":1,"seq":0,"bssid":"02:00:00:00:00:01","ssid_hex":"486f6d65","band":"2.4","primary":6,"rssi":-55,"auth":"WPA2_PSK","phy":["11n"],"bandwidth":null,"secondary":null,"center1_mhz":null,"center2_mhz":null}
```

| Field | Contract |
| --- | --- |
| `seq` | Contiguous zero-based wire position, 0..127. Not a legacy network index. |
| `bssid` | Six hexadecimal octets separated by colons. Identity comparison is case-insensitive. Unique per snapshot. |
| `ssid_hex` | 0..32 SDK-exposed bytes encoded as 0..64 hex digits. Empty means no exposed SSID. |
| `band`, `primary` | `2.4` or `5`, and matching primary channel present in the begin plan. |
| `rssi` | Integer dBm, -127..20. Positive values are not automatically clamped. |
| `auth` | Nonempty canonical auth label, at most 32 characters; unknown SDK modes map to `UNKNOWN`. Not an SDK enum ordinal. |
| `phy` | Unique list from `11a`, `11b`, `11g`, `11n`, `11ac`, `11ax`, `lr`; empty means no exposed flags. |
| `bandwidth` | String `20`, `40`, `80`, `160`, `80+80`, or JSON null. |
| `secondary` | `none`, `above`, `below`, or JSON null. |
| `center1_mhz`, `center2_mhz` | Integer center frequencies in MHz, or JSON null. |

All listed fields are required, including nullable ones. SSID hex avoids transport
escaping ambiguity and permits non-UTF-8 bytes; Tab5 converts for display with an
explicit replacement policy. The underlying SDK string/embedded-NUL limitation
is documented in the design. Matching SSIDs with different BSSIDs stay separate.

Geometry rules:

- Unknown width: all four geometry fields are null. Never synthesize 20 MHz.
- Primary frequency: channels 1..13 use `2407 + 5*channel`, channel 14 uses 2484,
  and supported 5 GHz primaries use `5000 + 5*channel` MHz.
- 20 MHz: center1 is primary frequency, secondary is `none`, center2 is null.
- 40 MHz: center1 is primary frequency +/-10 MHz according to secondary direction;
  the partner primary is +/-4 channel numbers. No 40 MHz geometry involving ch14.
- 80/160 MHz: 5 GHz only; primary offset from center1 is +/-10/30 MHz for 80,
  or +/-10/30/50/70 for 160. Secondary direction must match the primary's HT40
  sub-block. Center2 is null. For 160 MHz, full-channel centers in the supported
  5 GHz plan are 5250, 5570 and 5815 MHz. A primary-80 segment center such as
  5290 MHz must not be published as the full 160 MHz center. Firmware converts
  that inconsistent geometry to all-null, preserving the AP record; the host
  rejects known-width wire records that violate this constraint.
- 80+80: center1 always denotes the **primary-containing** segment, even when the
  raw SDK field order differs. Center2 denotes the other segment, more than
  80 MHz from center1. The primary follows 80 MHz geometry within center1.
- Geometry validation is not certification of regulatory channel legality or
  of actual advertised values. Firmware maps inconsistent/unsupported data to null.

Return the strongest `min(found, limit)` driver records, retaining driver RSSI
order and assigning wire `seq`. Do not filter by RSSI/auth/SSID before counting:
those are Tab5 display filters. A duplicate BSSID or inconsistent count from
the adapter fails normalization rather than silently losing entries.

## Terminal record and publication

Successful result:

```text
[WFA1] {"v":1,"type":"end","boot":"0123456789abcdef","scan":1,"status":"ok","found":1,"returned":1,"truncated":false,"duration_ms":1500}
```

Successful empty result: `status=ok`, `found=0`, `returned=0`, `truncated=false`.
It still requires begin/end and replaces the previous snapshot with an empty one.

Truncated result example: `found=300`, `returned=128`, `truncated=true` with
exactly 128 AP records and `limit=128`. `found` is the 16-bit driver total (0..65535),
not an estimate of every AP physically present. `returned=min(found,limit)`;
`truncated` must equal `found > returned`. Channel counts from this snapshot are
lower bounds in the observed environment, and biased toward stronger records.

Failure/cancellation:

```text
[WFA1] {"v":1,"type":"end","boot":"0123456789abcdef","scan":1,"status":"timeout","found":null,"returned":0,"truncated":false,"duration_ms":20000,"code":"scan_timeout"}
```

Non-success status is `error`, `cancelled`, or `timeout`. `found` is null,
`truncated` is false, and `code` is a nonempty string of at most 64 characters.
`returned` always counts complete AP records already emitted, including partial
publication before cancellation. `duration_ms` is nonnegative elapsed milliseconds
from admission to terminal generation, up to signed 64-bit max; includes retrieval
and earlier TX, not the transmission time of this final line.

Initial runtime codes: `scan_start_failed`, `scan_failed`, `scan_timeout`,
`records_failed`, `invalid_record`, `stopped`, `tx_timeout`, `radio_fault`,
`restore_failed`, `tx_failed`. On transport failure a terminal response may itself be lost;
host timeout/disconnect is mandatory. Never publish success before retrieval,
normalization, required radio restoration, and complete AP-line writes succeed.

Only a valid `ok` terminal with matching identity, sequence/counts and metadata
commits the working snapshot. Failed, malformed, partial or cancelled transactions
preserve the last good snapshot and expose stale/error state. A scan's failure is
valid protocol traffic; it is not a parser error.

## Executable reference and fixture

```powershell
python -B -m unittest tests.test_wifi_analyzer_contract tests.test_wifi_analyzer_integration -v
python -B tools/wifi_analyzer_contract.py tests/fixtures/wifi_analyzer_v1.ndjson
```

The 53 focused Python tests include 39 wire checks and 14 source-integration
guards; they do not compile firmware. The fixture contains one two-AP success followed by a timeout. Expected validator
summary: `snapshots=1`, `terminals=2`, `errors=0`. `last_snapshot` remains scan 1.
The 80 MHz record is a synthetic valid geometry example, not evidence of C5 support.

Without a filename the validator reads stdin. It exits 0 for at least one valid
terminal and no protocol errors, even if a valid terminal reports radio failure.
It exits 1 for malformed/incomplete traffic or no snapshot terminal. It does not
open serial ports, execute CLI commands, allocate PSRAM, or simulate Flipper.
The fixture is a reference for future Tab5 parser tests. The portable C harness
uses its own formatter inputs and assertions; it was not executed in this pass.
The source implementation and host reference require device
validation before treating hardware behavior as verified.
