# Tab5 Wi-Fi analyzer integration prompt

The companion implementation now exists in the sibling Tab5 project at
`C:\Users\mati\Documents\GitHub\M5MonsterC5-Tab5\main`. Its usage, test commands
and device acceptance checks are in `../docs/wifi-analyzer.md` relative to that
directory. This prompt remains an architectural handoff reference. Read
[WFA/1](wifi-analyzer-protocol.md) and the [JanOS design](wifi-analyzer-design.md)
before extending the Tab5 application. Firmware builds and hardware validation
remain deferred to the user.

Implement a separate Wi-Fi Analyzer screen and serial snapshot reader. Keep the
existing legacy scan screen and Flipper-compatible serial parsing intact. The
firmware exposes `wifi_analyzer caps`, `scan`, `status`, `stop`, and `clear`.
`caps` advertises `default_records=64`, `max_records=128`,
`width_metadata=sdk_unverified`, and
`channel_scope=requested_driver_filtered`. A `scan` is one-shot. There is no
firmware auto-repeat or cached replay command.

## Reader and transaction model

- Probe `wifi_analyzer caps` once per connection with a bounded timeout. If the
  firmware does not support WFA/1, retain the existing legacy experience and
  label unavailable analyzer fields as unknown. Do not infer an empty scan from
  a probe timeout.
- Parse `[WFA1] ` JSON lines with a bounded 1024-byte line limit (prefix
  included, CR/LF excluded). Treat `[WFACTL1] ` as separate control traffic and
  ignore unrelated legacy/log lines for this reader. Preserve byte fragments
  across reads and discard through the next newline on overflow.
- Use one reader per transport and boot identity. Require version 1, matching
  `boot`/`scan`, increasing scan IDs, contiguous AP `seq` values 0..127, unique
  BSSIDs, in-scope primary channels, valid counts and terminal status. Ignore
  unknown additive fields; reject malformed required fields and unknown versions.
- Hold APs in a working snapshot. Publish only after a valid `status=ok` end;
  a valid empty success replaces the view with an empty result. On timeout,
  cancellation, parser error or disconnect, keep the last good snapshot and
  show that it is stale. A truncated success is still usable; display both
  `returned` and the 16-bit `found` count, which may exceed 255.
- Decode `ssid_hex` as bytes with an explicit display replacement policy.
  Preserve BSSID as the identity. Never reuse analyzer `seq` as a legacy
  `select_networks` index. Do not start the legacy enrichment/credential flow
  from an analyzer AP row.

## Screen behavior

- Provide a list or chart of APs with SSID, BSSID, raw RSSI dBm, primary
  channel, band, security/auth label, and PHY flags. Local filters must include
  2.4 GHz / 5 GHz, RSSI threshold, and security. Filtering must not launch a
  scan or alter the snapshot.
- Add primary-channel and channel-width filters (including an explicit Unknown
  option), SSID/BSSID search, a visible filtered/total count, and Reset filters.
  Keep acquisition settings (band/channel scan plan, profile, limit) separate
  from local display filters. Applying acquisition settings starts a new scan
  only after the current one is stopped or complete.
- Provide a channel view of primary-channel AP counts and RSSI. Label counts
  as observed APs, with a truncation notice when applicable. For overlap
  drawing use `bandwidth`, `secondary`, `center1_mhz`, and `center2_mhz` only
  when the full geometry is present. Render unknown width explicitly; do not
  assume 20 MHz. Mark width metadata as SDK derived and unverified on target.
- Use the supplied UniFi-style screenshot as a layout reference: a compact
  filter panel, channel summary tiles, the main channel/RSSI plot, and a
  sortable AP list. Adapt it to Tab5 touch targets and existing UI components.
  Use frequency in MHz for horizontal geometry so 5 GHz channel gaps and
  2.4 GHz overlap remain accurate; channel labels are ticks. Use stable colors
  derived from BSSID. AP tap highlights its footprint and opens readable
  details. Draw 80+80 as two segments, and unknown width as a primary marker.
  Never infer an 'own AP' highlight when the firmware has not identified one.
- Show requested channel scope from `begin.channels`, not guaranteed RF
  coverage. Do not show spectrum power, interference strength, airtime usage,
  or channel-utilization percentages inferred from AP counts.
- Offer one-shot Scan, Stop, and an optional user-controlled refresh interval.
  Schedule each repeat after the prior terminal response plus at least 100 ms.
  An immediate request can briefly receive `busy` because the worker releases
  ownership after writing `end`; use a bounded retry after `status=idle`.
  Stop scheduling when the screen closes. A reconnect starts a fresh scan.
  Surface `busy`, `no_psram`, timeout, radio fault and parser errors clearly.
  `legacy_radio_uncertain` requires a device reboot before analyzer admission.
- Keep live view as the default. If history is added, use bounded storage and
  only offer ranges actually collected since screen/session start. Do not
  copy the screenshot's 1-day/1-month options without real retained history.

Use the synthetic capture from this ESP32C5 repository at
`tests/fixtures/wifi_analyzer_v1.ndjson` and focused
parser tests for fragmentation, malformed/overlong lines, reordered or duplicate
records, empty success, failure, truncation above 255, and reconnect/boot change.
Check old Tab5 scan flows after integration. The current user instruction for
this work is **no compilation, firmware build, flash, or serial/hardware test**;
carry that constraint into the Tab5 task unless the user changes it.

Before editing, read the Tab5 repository instructions and existing UI/transport
architecture. Keep the implementation additive and reuse its UART ownership and
UI-thread mechanisms. Write English documentation and tests, run the tests that
do not require compilation, and report exactly what remains for device testing.
