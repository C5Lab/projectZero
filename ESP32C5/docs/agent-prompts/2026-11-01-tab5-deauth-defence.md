# Prompt for the Tab5 implementation agent

Work in `C:\Users\mati\Documents\GitHub\M5MonsterC5-Tab5`.

Your task is to extend the existing Tab5 Deauth Detector V2 UI, model, and
emulator for JanOS autonomous Defence. Do not modify JanOS or Cardputer ADV.
Do not build, flash, or publish firmware/emulator artifacts unless separately
requested. Read first:

1. `C:\Users\mati\Documents\GitHub\projectZero\ESP32C5\docs\superpowers\specs\2026-11-01-deauth-detector-v2-autonomous-defence-design.md`
2. `docs/deauth-detector-v2.md`
3. The detector model and UI regions in `main/main.c` beginning at
   `// Detector watch model begin`, `// Detector watch logic begin`, and the
   Deauth Detector screen functions near `deauth_detector_send_bound()`.
4. `tests/detector_watch_logic_test.c`,
   `tests/detector_transport_binding_test.c`,
   `tests/deauth_detector_test.c`, and the current detector browser tests.
5. `tools/ui_emulator/model/device.mjs`,
   `tools/ui_emulator/model/bridge.mjs`,
   `tools/ui_emulator/runtime/detectors.c`, and
   `tools/ui_emulator/README.md`.

Before editing, run `git status --short --branch`; preserve unrelated changes.
Use test-driven development. The production firmware model, emulator device
model, native emulator runtime, and browser acceptance tests must agree on the
same wire contract.

## Required UI and command behavior

Keep Passive and Trace modes unchanged. Add a Defence control beside the
current Trace control. When Defence is enabled:

- Trace becomes on and locked because JanOS Defence implies fast Trace.
- Selected networks are mandatory; disable active Start in All networks and
  explain `Select protected networks first`.
- The session sends
  `deauth_detector_v2 --only <fresh indices> trace defence`.
- A separate advanced `PMKID Lab` control is off by default. Enabling it shows
  a warning that legitimate joins are indistinguishable from harvesting at
  this layer and requires explicit confirmation. The command then ends with
  `trace defence pmkid-decoy`.
- Controls cannot change while Start/Stop is pending, the session is running,
  or the remote state is uncertain.

Never add active tokens to legacy `deauth_detector`. When Defence was
requested, exact `Unrecognized command` means `Defence unsupported`; do not
silently fall back to a passive legacy run. Preserve the existing exact
fallback only for Passive/Trace. Timeouts, disconnects, missing format/WATCH
proofs, malformed output, or ambiguous output preserve visible uncertainty.

## Session ownership is mandatory

At Start capture and retain:

- `tab_id_t`;
- the actual UART port;
- Grove/USB/MBus transport identity;
- USB connection generation where applicable;
- selected BSSIDs and fresh scan indices;
- requested Trace/Defence/PMKID mode.

Bind scan, Start, all replies, WATCH verification, Stop, Stop retry, and remote
uncertainty to that captured session even when the visible tab changes. Never
send follow-up traffic through the newly visible tab. A reconnect cannot
silently clear or reclaim an uncertain session without the existing transport
generation rules and an exact confirmed Stop.

## Wire parser and display

Consume every `[DETECTOR_DEFENCE]` line before event parsing. Strictly support:

```text
[DETECTOR_DEFENCE] armed targets=<n> trace=fast pmkid=<monitor|decoy>
[DETECTOR_DEFENCE] trigger=<deauth|disassoc|csa|pmkid_probe> BSSID=<mac> STA=<mac|-> RX=<ch> decision=<decoy_4way|decoy_pmkid|observe> reason=<token>
[DETECTOR_DEFENCE] provisional_bssid=<mac> channel=<ch>
[DETECTOR_DEFENCE] tx=<decoy_4way|decoy_pmkid> stage=<m1_m2|m1_pmkid> result=<ok|error> frames=<0..2> latency_us=<n> error=<none|token>
[DETECTOR_DEFENCE] suppressed=<n> reason=<rate-token> BSSID=<mac> window_ms=1000
[DETECTOR_DEFENCE] released_bssid=<mac> channel=<ch> reason=idle idle_ms=20000 response=<decoy_4way|decoy_pmkid> suppressed=<n>
[DETECTOR_DEFENCE] stopped observations=<n> tx_pairs=<n> pmkid_m1=<n> responses=<n> satisfied=<n> errors=<n> dropped=<n> outcome=<responded|observed|idle>
```

Render JanOS-confirmed states: waiting, armed, provisional RX channel,
responding, TX success/error, confirmed Trace lock, released/rearmed,
unsupported, and remote state uncertain. Only exact `tx ... result=ok` counts
as a response. Trigger/decision/suppressed telemetry is not proof of
TX. Status markers never enter detector history, DEAUTH/CSA counters, CSV,
sound/alarm, or latest-observation cards. Existing semantic labels such as
`Claimed TX`, `Frame recipient (DA)`, and unknown encrypted reason remain.
After one successful PMKID or four-way decoy, JanOS silently counts later
eligible traffic until the 20-second idle release. Treat the release
`response` and `suppressed` fields as a completed campaign summary, not another
TX. The stop `responses` and `satisfied` fields are run-wide totals.
`outcome=responded` proves only that at least one decoy TX completed;
`observed` means selected-target traffic without a successful response, and
`idle` means no selected-target observation. None proves attack prevention or
excludes capture of a real handshake. Active
Defence stays pinned to the selected AP's startup scan channel; this does not
change passive Trace channel scoring.

Keep `[DETECTOR_TRACE]` state independent but show the relationship: Defence
can report TX success before Trace confirms a lock. Interleaved Trace, Defence,
DEAUTH, and CSA lines must not reorder or overwrite unrelated state. Preserve
mixed DEAUTH/CSA history layout without overlaps in portrait and landscape.

Only the exact final `All operations stopped.` clears the active/uncertain
session. A missing ACK, write failure, timeout, disconnect, or only
`Deauth Detector stopped.` keeps the last state visible and offers bound Stop
retry.

## Production host tests

Extend the extracted production model tests:

- `tests/detector_watch_logic_test.c` and
  `tests/test_detector_watch_logic.py` for mode commands, strict state machine,
  no active legacy fallback, malformed/duplicate/late markers, TX counting,
  and confirmed Stop.
- `tests/detector_transport_binding_test.c` for start and stop on captured
  Grove, USB, and MBus tab/port/generation after the visible tab changes.
- `tests/deauth_detector_test.c` and history tests to prove status lines never
  become observations/CSV rows or alarms.

Run at minimum:

```powershell
python -B -m unittest discover -s tests -p "test_detector_watch_logic.py" -v
python -B -m unittest discover -s tests -p "test_detector_history.py" -v
```

## Emulator and browser parity

Update the emulator models so they simulate the protocol contract, not radio
physics:

- `tools/ui_emulator/model/device.mjs` accepts the exact Defence commands and
  emits deterministic valid marker sequences, error sequences, interleaving,
  release/rearm, and exact Stop.
- `tools/ui_emulator/model/bridge.mjs` routes events on the captured transport.
- `tools/ui_emulator/runtime/detectors.c` mirrors native state transitions.
- Update `tools/ui_emulator/README.md` and coverage inventory if required by the
  repository's existing parity checks.

Extend `tests/test_emulator_detectors.mjs` and
`tests/test_deauth_detector_v2_browser.py`. Add browser acceptance for:

1. Defence requires selected networks and forces Trace.
2. Exact normal and PMKID Lab commands.
3. PMKID warning/confirmation.
4. TX success versus trigger/error counting.
5. Interleaved Trace/Defence/DEAUTH/CSA state.
6. Malformed, duplicate, prompt-prefixed, late, and cross-tab markers.
7. Captured transport after visible-tab change.
8. Stop timeout/disconnect uncertainty and exact ACK recovery.
9. Portrait/landscape layout and mixed history without overlap.
10. Status lines excluded from history, sound, CSV, and latest cards.

Run:

```powershell
node --test tests/test_emulator_detectors.mjs
tools\ui_emulator\.venv\Scripts\python.exe -u tests\test_deauth_detector_v2_browser.py -v
```

If the repository uses a different active emulator environment, report the
missing dependency rather than claiming browser proof. Do not label emulator
success as firmware, RF, physical UART, SD-card, or flashed-device validation.

Update `docs/deauth-detector-v2.md` with exact commands, session binding,
markers, PMKID warning, fallback boundary, Stop semantics, and validation
boundary. Finish with changed files, exact commands/results, unresolved risks,
and explicit host/emulator-only evidence. Do not commit or push without user
authorization.
