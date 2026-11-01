# Prompt for the Tab5 Deauth Forensics implementation agent

Work in `C:\Users\mati\Documents\GitHub\M5MonsterC5-Tab5`.

Implement an additive forensic model and UI for the existing Deauth Detector
V2, Trace, and Defence screen. This work extends, but does not replace, the
Defence contract in:

`C:\Users\mati\Documents\GitHub\projectZero\ESP32C5\docs\agent-prompts\2026-11-01-tab5-deauth-defence.md`

Do not modify JanOS or Cardputer ADV. Do not build, flash, publish, or deploy
firmware/emulator artifacts unless separately requested. Read the base prompt,
`docs/deauth-detector-v2.md`, the production detector model/UI, its transport
binding tests, and the emulator/browser detector implementation before
editing. Run `git status --short --branch` and preserve unrelated user work.
Use TDD: production model tests first, then firmware UI, emulator parity, and
browser acceptance.

## Purpose and evidence boundary

The feature exposes received-frame evidence for long-running passive research.
It must never convert a MAC claim or heuristic into an attribution. Use neutral
labels such as `Claimed TX`, `Frame recipient`, `Repeated sequence`,
`Retransmission`, and `Insufficient evidence`. Never display `Attacker MAC`,
`AP definitely sent`, or `Attack prevented`.

The existing strict `[DEAUTH_V2]` record remains the only source of detector
events, history, CSV rows, latest-observation cards, counters, sounds, and
alarms. Forensic telemetry must not duplicate an observation.

## Additive JanOS wire contract

Strictly consume this optional versioned line after the existing serial prompt
normalization:

```text
[DEAUTH_FORENSIC/1] FRAME=<deauth|disassoc> CH=<1..233|-> BSSID=<mac> TX=<mac> DA=<mac> RSSI=<-127..0|-> REASON=<0..65535|-> SEQ=<0..4095|-> RETRY=<0|1|-> PROTECTED=<0|1|-> FC=<0x0000..0xFFFF|-> TS_US=<0..UINT64_MAX>
```

Field order and spelling are normative. Reject missing, duplicate, reordered,
extra, truncated, oversized, out-of-range, or malformed fields. MAC addresses
must contain exactly six hexadecimal octets. Never find this marker as a
substring. Accept only the repository's existing single serial-prompt prefix;
embedded or repeated prompt text is malformed.

`TS_US` is monotonic JanOS boot time, not wall-clock time. `SEQ` is the raw
12-bit 802.11 sequence number. `RETRY`, `PROTECTED`, and `FC` describe the
received frame. Preserve `-` as unknown. Do not infer missing fields from V2,
Trace, Defence, CSA, or a neighboring row, and do not require adjacency to a
V2 record.

Some JanOS builds will not emit this marker. Keep full V2/Trace/Defence
operation and show `Forensics unavailable for this firmware`; do not treat
absence as a protocol failure. Existing `[CSA]`, `[DETECTOR_TRACE]`, and
`[DETECTOR_DEFENCE]` contracts remain independent. This task does not add an
active command or a CSA attack verdict.

## Session ownership and bounded model

Bind forensic input to the detector session captured at Start: `tab_id_t`,
UART port, Grove/USB/MBus identity, USB generation, command generation, and
selected BSSIDs. Visible-tab changes must not rebind input. Cross-tab,
cross-port, pre-arm, stale-generation, and post-final-Stop records are ignored
by the active model and covered by tests.

Use bounded storage. Reuse the detector history capacity where appropriate or
define a smaller documented forensic limit. Eviction increments a saturating
local `forensic dropped` counter. Do not allocate an unbounded event list in
firmware, emulator, or browser models.

For a valid row, group bursts by `(FRAME, BSSID, TX, DA)`. A gap greater than
20,000,000 us starts a new burst; exactly 20,000,000 us remains in the current
burst. A key change starts a new burst. Existing Trace lock/release remains
independent and is not manufactured from a forensic burst.

Track with saturating counters:

- accepted and locally dropped forensic rows;
- burst count and largest burst;
- unique BSSID and DA counts within the bounded model;
- reason-code distribution;
- RSSI minimum, rounded integer average, and maximum;
- protected, unprotected, retry, and unknown counts;
- per-stream sequence deltas and repeated sequence numbers.

Use modular 12-bit sequence delta. Identical `SEQ` plus `RETRY=1` is a
`Retransmission`; identical `SEQ` plus `RETRY=0` is a `Repeated sequence`;
other values display only the delta. With fewer than two comparable rows show
`Insufficient sequence data`. These are evidence labels, never proof of an
attack. Do not compare against beacon sequencing because no beacon reference
exists in this contract.

Reset only after the existing model confirms a new run. Preserve the last
summary through Stop pending, missing ACK, write failure, timeout, disconnect,
and remote uncertainty. Finalize it only on exact `All operations stopped.`.

## Tab5 UI

Add a Forensics section inside the existing Deauth Detector V2 screen, not a
new global application tab. Follow current responsive layout and theme tokens.

Provide:

- a session summary card: duration observed locally, rows, bursts, largest
  burst, unique BSSID/DA, RSSI min/avg/max, retry/protected counts, and local
  drops;
- a bounded forensic evidence list showing frame type, channel, BSSID,
  `Claimed TX`, recipient, reason, sequence/delta, retry, protected state,
  frame control, and monotonic gap;
- filters for BSSID, recipient, reason, and frame type using the existing UI
  interaction pattern;
- an always-visible `Evidence only — not transmitter attribution` note;
- explicit empty states for unsupported firmware, no observations, and all
  rows removed by a filter.

Do not use red danger styling solely because a frame is unprotected, repeated,
or discontinuous. Forensic rows never enter normal history/CSV/latest cards
and never trigger sound or alarms. Existing mixed DEAUTH/CSA history must keep
its current portrait and landscape layout.

## Production host tests

Extend the extracted real production model and transport tests with at least:

1. Exact valid v1 deauth/disassoc records, numeric boundaries, and `-` values.
2. Strict rejection of reordered, missing, duplicate, extra, truncated,
   malformed, overflowed, and out-of-range fields/MACs.
3. Existing single prompt normalization versus embedded/repeated prefixes.
4. No duplication of history, CSV, latest observation, counters, sound, or
   alarms.
5. Bounded eviction and saturating local-drop/counter behavior.
6. Burst boundary at exactly and just above 20,000,000 us plus key changes.
7. Modular sequence delta, retry retransmission, repeated non-retry sequence,
   and insufficient data.
8. RSSI aggregates, reason distribution, protected/unprotected/unknown counts,
   and unique identity counts.
9. Interleaved V2, Trace, Defence, CSA, and forensic records retain independent
   states.
10. Start/Stop ownership across Grove, USB, and MBus after the visible tab
    changes, including reconnect generations.
11. Stop uncertainty preserves the summary; exact final acknowledgement
    finalizes it; stale and late rows cannot revive or contaminate a session.
12. Firmware without forensic markers preserves existing screen snapshots and
    behavior except for the explicit compatibility empty state.

Run the repository's current production detector suites, including at least:

```powershell
python -B -m unittest discover -s tests -p "test_detector_watch_logic.py" -v
python -B -m unittest discover -s tests -p "test_detector_history.py" -v
```

## Emulator and browser parity

Implement the same bounded model and strict grammar in the emulator. The
emulator simulates protocol records, not RF physics. Add deterministic
fixtures for:

- the observed long-run sample: 23 rows, 11 bursts, sizes
  `2,2,3,2,3,1,1,3,3,2,1`, RSSI `-80..-87`, one BSSID/DA, reason 6;
- valid sequence continuity and retry retransmissions;
- repeated non-retry sequences and unknown fields;
- malformed, late, cross-tab, and cross-generation records;
- bounded overflow and Stop uncertainty/recovery;
- a firmware session with no forensic markers.

Update the native emulator runtime, JS device/bridge model, README, and parity
inventory as required by the repository. Extend browser acceptance for the
summary card, filters, evidence rows, neutral labels, empty states, responsive
portrait/landscape layout, captured-transport ownership, and the guarantee
that forensic rows do not enter normal history or trigger alarms.

Run:

```powershell
node --test tests/test_emulator_detectors.mjs
tools\ui_emulator\.venv\Scripts\python.exe -u tests\test_deauth_detector_v2_browser.py -v
```

If the active emulator environment differs or a browser dependency is absent,
report that boundary rather than claiming proof. Emulator success is not
firmware, UART, RF, SD-card, or flashed-device validation.

Update `docs/deauth-detector-v2.md` with the exact optional grammar, session
ownership, burst/stat definitions, evidence boundary, compatibility behavior,
and validation limits. Finish with changed files, exact commands/results,
unresolved risks, and explicit host/emulator-only evidence. Do not commit or
push without explicit authorization.
