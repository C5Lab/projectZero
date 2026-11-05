# JanOS Wi-Fi Shield

Wi-Fi Shield is JanOS's combined Wi-Fi security evidence, health and bounded
deception service for ESP32-C5. It coordinates Deauth/Disassociation/CSA,
PMKID, WPS, SAE and Wi-Fi Trust processing behind one radio owner and one
operator-facing command family.

Shield is not a firewall. It observes selected radio activity, correlates
bounded evidence, records uncertainty and can optionally emit the existing
selected-target WPA2 decoys. It cannot guarantee that a client stayed
connected, prevent capture of a real handshake, authenticate a claimed
transmitter or replace PMF/802.11w.

Use Shield only with networks that you own or are explicitly authorized to
test.

For implementation and lifecycle details, see
[Wi-Fi security runtime](wifi-security-runtime.md). For the test history,
evidence levels and remaining validation work, see
[Wi-Fi Shield validation](wifi-shield-validation.md).

## Capabilities at a glance

| Source | Passive behavior | Active behavior in `--protect-all` | Important limit |
|---|---|---|---|
| Deauth/Disassociation | Counts and correlates selected-BSSID activity. | May emit one bounded decoy four-way response for an eligible selected WPA2 target. | A claimed BSSID or transmitter address is spoofable. |
| PMKID/association | Applies a grace window and reports incomplete selected association sequences. | May emit the explicit experimental PMKID decoy. | An observation does not prove credential capture or prevention. |
| WPS | Parses bounded enrollment activity, fragmentation and anomaly evidence. | None. | Activity does not prove Pixie Dust or a vulnerable router. |
| SAE | Monitors bounded WPA3-SAE activity and thresholds. | None. | Activity does not identify a physical attacker. |
| Trust | Compares AP posture with a baseline and reports drift. | None. | Drift does not prove an evil twin. |
| AP Health | Measures selected-AP timing, RSSI, channel and posture evidence. | None. | Advice is evidence-bounded and never reconfigures the AP. |

`--protect-all` means active bounded Deauth/PMKID deception plus passive WPS,
SAE and Trust analysis. It does not authorize active WPS, SAE or Trust traffic.

## Operating modes

### Passive Shield

```text
wifi_shield start
wifi_shield start --only <scan-index> [scan-index ...]
```

Bare `start` performs a bounded Shield-owned scan and snapshots its valid
BSSID/channel results. `--only` uses one-based indexes from the current
completed scan. The snapshot is immutable for the run: a later scan cannot
silently retarget Shield.

Passive Shield makes no countermeasure or decoy transmissions. Multi-channel
coverage is sampled because one radio cannot observe every selected channel at
the same instant. Silence under sampled coverage is not evidence that activity
was absent.

### Granular Defence

```text
wifi_shield start --only <scan-index> --defence decoy-4way
wifi_shield start --only <scan-index> --defence decoy-4way --pmkid-decoy
wifi_shield start --only <scan-index> --defence decoy-4way --pmkid-decoy --multi-vector
```

Active Defence requires an explicit selected target. The normal four-way decoy
is limited to eligible WPA2-PSK/CCMP scan evidence. The PMKID decoy is
experimental and remains a separate opt-in in the granular form.
`--multi-vector` permits at most one successful response per enabled action
class during the same selected-BSSID campaign; repeated completed actions stay
suppressed until the normal idle release.

### Protect-all preset

```text
wifi_shield start --only <scan-index> --protect-all
```

This is the explicit shortcut for the complete selected-target Defence policy:

```text
ACTIVE=deauth,pmkid PASSIVE=wps,sae,trust
```

It enables the four-way decoy, experimental PMKID decoy and multi-vector
policy while retaining the passive WPS, SAE and Trust paths. It cannot be
combined with the granular Defence flags.

## Operator workflow

Run a fresh scan and identify the owned target:

```text
scan_networks
```

Start the desired mode and confirm both the immutable identity and coverage:

```text
wifi_shield start --only <scan-index> --protect-all
```

Expected startup records include:

```text
[SHIELD/1] ARMED MODE=protect-all TARGETS=1 CHANNELS=<channel> COVERAGE=continuous ACTIVE=deauth,pmkid PASSIVE=wps,sae,trust
[SHIELD/1] TARGET N=1/1 SSID="<sanitized-ssid>" BSSID=<bssid> CH=<channel>
```

During the run, use the read-only controls:

```text
wifi_shield status
wifi_shield report
wifi_shield log status
```

Stop cleanly and inspect the retained terminal evidence:

```text
wifi_shield stop
wifi_shield report
wifi_shield log status
list_dir lab/shield -s
```

`status`, `report` and `log status` do not tune the radio, transmit, mount
storage or alter the active session. `stop` is idempotent and may retry
retained cleanup. A successful terminal is emitted only after verified radio
release.

## Interpreting Shield records

### `[SHIELD/1]`

- `ARMED` confirms accepted mode, target count, channel plan and coverage.
- `TARGET` confirms the immutable SSID/BSSID/channel snapshot.
- `EVENT` is informational normalized evidence.
- `ALERT` is an observation that crossed a bounded policy threshold.
- `STATUS` exposes source, alert and loss counters.
- `TERMINAL` is the final lifecycle result after Stop.

The counters are session evidence, not complete RF packet counts. Local RX,
event or output drops remain separate so missing evidence is visible.

### `[SHIELD/2]`

- `CAMPAIGN` correlates selected-BSSID observations into `quiet`, `watch`,
  `attack` or `critical` state.
- `SESSION_PEAK` retains the highest state reached during the session.
- `COMPLETED` counts campaigns closed by idle expiry or Stop.
- `AP_HEALTH` reports bounded passive measurements and confidence.
- `RECOMMENDATION` reports one action, its evidence token and confidence.
- `LOG` reports journal state, path, bytes, queue high-water and distinct
  storage failure counters.

A `critical` campaign means that the configured correlation rules observed
cross-vector evidence. It is not attribution and does not prove compromise.
Loss can lower confidence but never erase an event that was already observed.

## Trust and Evil Twin indicators

Trust compares observed AP posture with its accepted baseline. It can report:

- a new BSSID relative to the baseline;
- SSID, AKM, privacy, pairwise/group cipher or PMF drift;
- RSNXE changes;
- WPS appearing or its lock state changing;
- country or channel drift;
- conflicting Beacon and Probe Response posture for the same claimed BSSID.

These checks detect many configurations consistent with an Evil Twin, but
Trust does not prove an evil twin. A legitimate multi-AP ESS, router upgrade,
roaming change or operator configuration change may create drift. A carefully
cloned transmitter that matches the BSSID and all compared fields may evade the
current profile comparison. The physical transmitter is not identified.

Treat Trust as a baseline-drift sensor. Confirm important alerts with an
independent monitor, AP configuration records and the surrounding RF evidence.

## Beacon sequence continuity

AP Health accepts the 12-bit management sequence range `0..4095`, including
the normal `4095 -> 0` wrap. A forward delta contributes `delta - 1` management
sequence gaps. Duplicate retry observations do not manufacture additional
gaps, and large ambiguous backward deltas lower continuity confidence instead
of becoming huge loss counts.

Management sequence numbers are shared with other management traffic. As a
result, `SEQ_GAPS` is not AP-side packet loss and does not count missing Beacons.
Beacon cadence and jitter are evaluated independently from exact same-epoch AP
TSF observations. Sampled channel coverage and local receiver drops limit both
continuity and timing confidence.

Use an independent capture adapter when validating sequence behavior on air.
Compare the complete management stream, not only Beacons, and record receiver
drops on both capture devices.

## CSA interpretation

Shield accepts only supported, structurally complete CSA/ECSA observations and
rejects truncated, encrypted, fragmented, malformed or internally conflicting
announcements. It records the actual C5 receive channel separately from the
advertised destination channel and preserves the announcement path, countdown
and mode evidence.

Shield cannot authenticate a CSA transmitter. Address 2 and the BSSID are
claims carried by the received management frame. A spoofed announcement can
therefore create CSA evidence.

For this reason Shield keeps these facts separate:

- `CSA_EVENTS`: accepted channel-switch announcements were observed;
- `CHANNEL_CHANGES`: later selected-BSSID Beacon evidence was observed on a
  different channel or band.

CSA activity alone never establishes channel instability. The AP Health
recommendation requires at least two observed channel/band changes. Even a
matching follow-up Beacon is correlation, not cryptographic proof, because
management evidence may also be spoofed. PMF can protect applicable robust
management exchanges for associated clients, but a passive Shield cannot use
it to authenticate every Beacon, Probe Response or public action announcement.

## WPS, SAE, Deauth and PMKID interpretation

### WPS

Shield reports enrollment messages and bounded anomaly/retry evidence. It does
not recover, retain or log WPS PINs, PSKs, WSC credentials, nonces or key
material. An M1 or other WSC message proves only that related enrollment
traffic was observed.

### SAE

Shield monitors bounded SAE activity and thresholds. SAE activity can be
spoofed and does not establish a physical attacker or successful WPA3 attack.

### Deauth and Disassociation

Selected-BSSID bursts are evidence of claimed management traffic. Without
independent authentication they do not identify the sender or prove that a
client disconnected. Active Defence emits only the bounded decoy response; it
does not counter-deauthenticate, jam or transmit reverse CSA.

### PMKID and association activity

An Open Authentication plus Association sequence first becomes a bounded
candidate. A matching standards-shaped EAPOL M2 during the grace window
classifies it as a completed association and cancels the PMKID observation. An
incomplete candidate may become PMKID sequence evidence. This reduces ordinary
association false positives but does not prove an attack or credential capture.

## Journal and time model

Each accepted Shield start attempts an automatic journal under:

```text
/sdcard/lab/shield/shield-b<boot_id>-s<session_id>.jsonl.part
```

Clean Stop finalizes the file to `.jsonl` and creates:

```text
/sdcard/lab/shield/shield-b<boot_id>-s<session_id>-summary.txt
/sdcard/lab/shield/00-LATEST.txt
```

`00-LATEST.txt` is the convenience pointer; the uniquely named JSONL remains
authoritative. Missing or failed SD storage is fail-open for monitoring and
Defence. It never creates a radio quarantine by itself.

Authoritative ordering uses `boot_id`, `session_id`, `sequence` and monotonic
`boot_us`. AP TSF is AP-relative and spoofable, never UTC. Calendar time is
included only when an already trusted GPS clock is available.

The journal stores normalized scalar evidence, not raw frames, station
identities or protected credential material. High-rate Deauth, Disassociation
and CSA evidence is aggregated into bounded windows before journal admission.

## Evidence boundaries

Shield output supports investigation, but none of the following claims may be
made from one record alone:

- a Trust change proves an Evil Twin;
- a claimed transmitter address identifies a physical device;
- a sequence gap proves Beacon loss or AP packet loss;
- a CSA event proves that the real AP requested or completed a channel change;
- WPS activity proves Pixie Dust or router exploitability;
- a Deauth record proves that a client disconnected;
- a successful decoy TX proves prevention or client retention;
- silence under sampled coverage proves absence;
- AP TSF provides calendar time or authentic AP identity.

Use the confidence and loss fields, retain negative controls, and correlate
UART, independent PCAP and SD journal evidence before drawing a stronger
conclusion.

## Troubleshooting

- `code=busy reason=radio_lease`: another radio owner is active, or the command
  is not one of Shield's read-only controls. Stop the owner and verify cleanup.
- `SHIELD/QUARANTINED`: radio restoration is uncertain. Retry
  `wifi_shield stop`; reboot remains the final recovery path.
- `LOG STATE=unavailable`: Shield continues without SD evidence. Repair storage
  before the next session; there is no in-session retry storm.
- nonzero `RX_DROPS`, `EVENT_DROPS` or journal `DROPS`: evidence is incomplete.
  Preserve the counters and lower the conclusion's confidence.
- `COVERAGE=sampled`: only the current channel was observable at each instant.
- no `TARGET` identity or unexpected channel: stop before active testing and
  repeat a fresh scan/selection.

## Further validation

The controlled-session ledger, exact evidence levels and the next test matrix
are maintained in [Wi-Fi Shield validation](wifi-shield-validation.md). New RF
claims should be added there only with firmware provenance, topology, ground
truth and retained artifacts.
