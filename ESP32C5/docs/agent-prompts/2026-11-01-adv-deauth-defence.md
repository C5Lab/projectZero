# Prompt for the Cardputer ADV implementation agent

Work in `C:\Users\mati\Documents\GitHub\M5MonsterC5-CardputerADV`.

Your task is to extend the existing Cardputer ADV Deauth Detector screen for
the JanOS V2 autonomous Defence contract. Do not modify the JanOS or Tab5
repositories. Do not build or flash firmware unless the user separately asks.
Start by reading:

1. `C:\Users\mati\Documents\GitHub\projectZero\ESP32C5\docs\superpowers\specs\2026-11-01-deauth-detector-v2-autonomous-defence-design.md`
2. `docs/deauth-detector.md`
3. `main/screens/deauth_detector_screen.c`
4. `tests/deauth_detector_screen_test.c`
5. `tests/test_deauth_detector_screen.py`

Before editing, run `git status --short --branch` and preserve every unrelated
user change. Use test-driven development: add failing host cases first, run
them, implement the smallest production change, then rerun the complete ADV
detector host suite.

## Required behavior

Keep all current Passive and Trace behavior intact. Replace the opening binary
Trace choice with a four-mode selector:

```text
Passive
Trace
Defence
Defence + PMKID Lab
```

Space cycles the mode, Enter starts, and Esc/Q exits without a command. Active
Defence requires a fresh selected-network scan; do not offer or claim an
all-network active mode. If the user chooses Defence from the opening screen,
lead them through the existing Stop -> fresh scan -> exact BSSID selection
flow before Start. `Defence + PMKID Lab` must show a separate warning that it
can interfere with legitimate client joins and require explicit confirmation.

Generate exact commands:

```text
deauth_detector_v2
deauth_detector_v2 trace
deauth_detector_v2 --only <indices>
deauth_detector_v2 --only <indices> trace
deauth_detector_v2 --only <indices> trace defence
deauth_detector_v2 --only <indices> trace defence pmkid-decoy
```

Never send `--trace`, never put suffix tokens among scan indices, and never add
active tokens to `deauth_detector`. When Defence was requested, the exact
`Unrecognized command` response must produce `Defence unsupported`; it must not
automatically fall back to a passive legacy detector. Preserve the existing
one-time legacy fallback only for Passive/Trace under its current exact rules.
A timeout, ambiguous line, or disconnect never authorizes fallback.

Parse `[DETECTOR_DEFENCE]` lines strictly and consume every line with that
prefix before event parsing. Support these exact records:

```text
[DETECTOR_DEFENCE] armed targets=<n> trace=fast pmkid=<monitor|decoy>
[DETECTOR_DEFENCE] trigger=<deauth|disassoc|csa|pmkid_probe> BSSID=<mac> STA=<mac|-> RX=<ch> decision=<decoy_4way|decoy_pmkid|observe> reason=<token>
[DETECTOR_DEFENCE] provisional_bssid=<mac> channel=<ch>
[DETECTOR_DEFENCE] tx=<decoy_4way|decoy_pmkid> stage=<m1_m2|m1_pmkid> result=<ok|error> frames=<0..2> latency_us=<n> error=<none|token>
[DETECTOR_DEFENCE] suppressed=<n> reason=<rate-token> BSSID=<mac> window_ms=1000
[DETECTOR_DEFENCE] released_bssid=<mac> channel=<ch> reason=idle idle_ms=20000 response=<decoy_4way|decoy_pmkid> suppressed=<n>
[DETECTOR_DEFENCE] stopped observations=<n> tx_pairs=<n> pmkid_m1=<n> responses=<n> satisfied=<n> errors=<n> dropped=<n> outcome=<responded|observed|idle>
```

Do not infer success from `trigger`, `provisional`, `suppressed`, a received DEAUTH/CSA row,
or a Trace lock. Only `tx ... result=ok` increments the visible response count.
After the first successful PMKID or four-way decoy, JanOS silently counts later
eligible traffic until the BSSID is idle for 20 seconds. The `released_bssid`
record reports the served response type and campaign `suppressed` total; the
`stopped` record reports run-wide `responses` and `satisfied` totals. Treat
`outcome=responded` only as proof that at least one decoy TX completed;
`observed` means selected-target traffic without a successful response, and
`idle` means no selected-target observation. None proves attack prevention or
excludes capture of a real handshake.
Active Defence remains pinned to the selected AP's startup scan channel;
passive Trace keeps its existing channel-scoring behavior.
Show compact confirmed states suitable for the Cardputer display: waiting for
arm, armed, provisional CH, responding, response OK/error, Trace confirmed CH,
released/rearmed, unsupported, and remote state uncertain. Defence status must
not increment DEAUTH/CSA counters, play the detection alarm, or become an
event/history row.

Preserve current semantics:

- `TX` remains claimed transmitter, not attacker identity.
- CSA remains an observed announcement, not proof of an attack.
- Existing `[DETECTOR_TRACE]` strict parsing remains independent and compatible.
- Stop state stays visible until exact `All operations stopped.`; the earlier
  `Deauth Detector stopped.`, send failure, or timeout keeps uncertainty and
  provides a retry.
- Selected WATCH proofs still use BSSID identity and the fresh scan indices.
- Malformed, out-of-order, prompt-prefixed, duplicated, and late status lines
  cannot activate a run, count an action, or revive a stopped session.

## Files and tests

Prefer keeping the production change in
`main/screens/deauth_detector_screen.c`; do not introduce a broad UI refactor.
Extend `tests/deauth_detector_screen_test.c` with at least these scenarios:

1. Exact command for every mode and selected mode.
2. Defence cannot start without a selected protected BSSID.
3. PMKID Lab warning and explicit confirmation.
4. Strict valid/malformed marker parsing, prefixes, ordering, duplicates, and
   oversized numeric/token fields.
5. Trigger does not count; only exact TX success counts.
6. TX error stays visible and does not count success.
7. Unknown/unselected BSSID markers do not replace selected-session context.
8. Trace and Defence markers can interleave without corrupting either state.
9. Exact Stop acknowledgement clears state; missing acknowledgement preserves
   uncertainty and last confirmed Defence/Trace context.
10. No legacy fallback for Defence; existing fallback remains byte-for-byte for
    passive modes.
11. Redraw remains incremental and text fits the 30-column display.

Update `tests/test_deauth_detector_screen.py` only as needed to compile the real
screen with stubs. Run:

```powershell
python -B -m unittest discover -s tests -p "test_deauth_detector_screen.py" -v
```

Expected: `ADV detector contract PASS` and the Python test PASS. Update
`docs/deauth-detector.md` with exact commands, warning, status meanings,
fallback boundary, and a statement that host tests do not prove radio TX or
flashed-device behavior.

Finish with a concise report containing changed files, exact tests and results,
unresolved risks, and a clear host-only validation boundary. Do not commit or
push unless the user explicitly authorizes it.
