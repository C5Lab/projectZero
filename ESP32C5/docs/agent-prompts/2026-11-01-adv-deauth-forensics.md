# Prompt for the Cardputer ADV Deauth Forensics implementation agent

Work in `C:\Users\mati\Documents\GitHub\M5MonsterC5-CardputerADV`.

Implement an additive forensic view for the existing Deauth Detector V2 and
Trace UI. This work extends, but does not replace, the Defence contract in:

`C:\Users\mati\Documents\GitHub\projectZero\ESP32C5\docs\agent-prompts\2026-11-01-adv-deauth-defence.md`

Do not modify JanOS, Tab5, or the strict `[DEAUTH_V2]` grammar. Do not build or
flash firmware unless the user separately asks. Before editing, read the base
prompt above, `docs/deauth-detector.md`, the real detector screen source, and
its host tests. Run `git status --short --branch` and preserve every unrelated
user change. Use test-driven development: add failing host cases first, run
them, make the smallest production change, then run the complete detector host
suite.

## Purpose and evidence boundary

The forensic view helps distinguish repeated legitimate AP/client state
problems from possible injected management frames. It must show evidence, not
an accusation. Never label the claimed transmitter as an attacker, never say
that the AP definitely sent a frame, and never claim that an attack was
prevented. `TX` remains the address claimed by the received frame.

The existing strict `[DEAUTH_V2]` record remains the only source of detector
event/history/alarm counts. A forensic record enriches evidence and must never
create a second observation, history entry, notification, alarm, or sound.

## Additive JanOS wire contract

Strictly consume this optional, versioned record after the repository's
existing serial prompt normalization:

```text
[DEAUTH_FORENSIC/1] FRAME=<deauth|disassoc> CH=<1..233|-> BSSID=<mac> TX=<mac> DA=<mac> RSSI=<-127..0|-> REASON=<0..65535|-> SEQ=<0..4095|-> RETRY=<0|1|-> PROTECTED=<0|1|-> FC=<0x0000..0xFFFF|-> TS_US=<0..UINT64_MAX>
```

Field order and spelling are normative. Reject missing, duplicate, reordered,
extra, truncated, oversized, out-of-range, or malformed fields. MAC addresses
must contain exactly six hexadecimal octets. Do not substring-match the
marker. Honor only the same single prompt prefix already accepted for valid
JanOS status records; embedded or repeated prefixes remain malformed.

`TS_US` is monotonic JanOS boot time, not wall-clock time. `SEQ` is the raw
12-bit 802.11 sequence number. `RETRY`, `PROTECTED`, and `FC` are received-frame
evidence. A `-` value means unavailable and must stay visibly unknown; do not
replace it with zero or infer it from another line.

JanOS does not yet emit this marker in every firmware build. Absence is a
supported compatibility state: keep normal V2/Trace operation and show
`Forensics unavailable`, not an error and not simulated data.

Keep existing `[CSA]`, `[DETECTOR_TRACE]`, and `[DETECTOR_DEFENCE]` parsing
independent. This prompt does not authorize a new CSA verdict or any active TX.

## Local session and burst model

Maintain a bounded forensic session owned by the same detector run as the
existing V2 state. Do not allocate per-event objects without a fixed limit.
Use the repository's existing bounded history limit, or a smaller explicit
limit if required by the Cardputer memory budget, and expose a saturated
`forensic dropped` count when old detail rows are evicted.

For valid forensic rows, group a burst by the exact key
`(FRAME, BSSID, TX, DA)` and monotonic time. Start a new burst when the key
changes or the gap from the previous matching row exceeds 20,000,000 us. Do
not manufacture a burst from a Trace lock alone. Existing Trace confirmation
and release state stays authoritative for Trace UI.

Track, with saturating counters:

- forensic rows accepted and locally dropped;
- unique BSSID and DA counts within the bounded model;
- burst count and largest burst;
- RSSI minimum, rounded integer average, and maximum;
- reason-code counts;
- protected, unprotected, retry, and unknown counts;
- repeated sequence numbers for the same stream.

Sequence interpretation must remain neutral:

- identical sequence plus `RETRY=1`: display `retransmission`;
- identical sequence plus `RETRY=0`: display `repeated sequence`;
- any other jump: display the modular 12-bit delta only;
- fewer than two comparable rows: display `insufficient sequence data`.

None of these states is proof of injection. Do not compare a deauth sequence
to beacon numbering because this wire contract does not carry a beacon
sequence reference.

Reset the local session only when the existing state machine confirms a new
run. Preserve the last summary through Stop pending, timeout, disconnect, and
remote uncertainty. Finalize it only on exact `All operations stopped.`. Late
forensic rows from an old/uncertain generation cannot enter a new session.

## Cardputer UI

Keep the normal detector screen incremental and within the current 30-column
layout. Add a compact Forensics view reachable through the screen's existing
navigation pattern; do not add another JanOS command or a new detector mode.

The running view should show at least:

```text
FORENSICS v1
Rows 23  Bursts 11
RSSI -87/-84/-80
Seq 1234 d+2 R0
Unprot 23 Retry 0
```

Use the repository's established abbreviations and colors, but keep unknown
values explicit. The stopped summary must show rows, bursts, largest burst,
RSSI min/avg/max, protected/unprotected/retry counts, locally dropped detail,
and `Evidence only`. If no v1 row was accepted, show `Forensics unavailable`.
Do not use red danger styling solely for unprotected or discontinuous frames.

Forensic rows must not alter existing DEAUTH/CSA counters, the latest V2 row,
history ordering, alarms, sounds, Trace scoring, Defence response counts, or
Stop acknowledgement behavior.

## Required host tests

Extend the real production screen host tests with at least:

1. One exact valid v1 deauth record and one exact valid disassoc record.
2. Minimum/maximum valid numeric values and explicit `-` unknowns.
3. Rejection of reordered, missing, duplicate, extra, malformed, overflowed,
   and out-of-range fields and MAC addresses.
4. Existing single prompt normalization versus embedded/repeated prefixes.
5. A forensic row never increments event/history/alarm/sound counters.
6. Bounded storage eviction increments a saturating local dropped count.
7. Burst grouping at 20,000,000 us: equal is the same burst; greater starts a
   new burst. Also cover key changes.
8. Modular sequence delta, retransmission, repeated non-retry sequence, and
   insufficient-data states.
9. RSSI min/average/max and saturated counter behavior.
10. Interleaved V2, Trace, Defence, CSA, and forensic records preserve every
    independent state machine.
11. Stop pending/timeout/disconnect preserves the summary; exact final Stop
    acknowledgement finalizes it; late old-generation rows are ignored.
12. No-marker compatibility leaves all existing Passive, Trace, and Defence
    snapshots byte-for-byte unchanged where the current tests require it.
13. Every rendered line fits the physical display and redraw remains
    incremental.

Run the repository's current detector test command, expected to include:

```powershell
python -B -m unittest discover -s tests -p "test_deauth_detector_screen.py" -v
```

Update `docs/deauth-detector.md` with the optional v1 grammar, evidence
boundary, summary meanings, compatibility behavior, and the fact that host
tests do not prove UART, radio, or flashed-device behavior.

Finish with changed files, exact commands and results, unresolved risks, and a
clear host-only validation boundary. Do not commit or push unless the user
explicitly authorizes it.
