# JanOS Wi-Fi Shield Validation

This document records how Wi-Fi Shield was evaluated during the development
sessions that produced the current implementation. It separates reproducible
host evidence, operator-observed device behavior and conclusions that still
require controlled RF validation.

All lab identities are anonymized. `LAB-AP-A` and `LAB-AP-B` refer to owned
WPA2-PSK/CCMP access points used during controlled work. This document does not
retain their SSIDs, BSSIDs, credentials, WPS PINs or station addresses.

For operation and interpretation, see [JanOS Wi-Fi Shield](wifi-shield.md).
For the normative design, see
[JanOS Wi-Fi Shield design](superpowers/specs/2026-11-03-janos-wifi-shield-design.md).

## Evidence levels

Every result uses one of four lower-case status labels:

| Status | Meaning |
|---|---|
| `verified` | Reproducible evidence was executed in the stated gate and the retained artifact directly supports the narrow claim. |
| `observed` | Device/UART/operator evidence was seen, but provenance or an independent ground-truth artifact is incomplete. |
| `inconclusive` | Evidence exists but cannot separate the competing explanations or has material loss/coverage limitations. |
| `not run` | The scenario has not been executed with the required setup. |

These labels are gate-specific. A host-`verified` parser does not make RF or
device behavior verified. A firmware build does not verify a flash, physical
PSRAM, SD durability, transmitter timing or client impact.

## Methodology

### 1. Contract and threat boundary

Before implementation, each feature received an explicit CLI, target,
transmit, memory, lifecycle and evidence boundary. Important negative claims
were treated as requirements: passive means zero Shield TX; claimed addresses
are not attribution; sequence gaps are not AP packet loss; Trust is not an
Evil Twin verdict; CSA is not authenticated; decoy completion is not
prevention.

### 2. Red-Green-Refactor

Production behavior followed the repository TDD workflow:

1. add the smallest focused portable or source/integration test;
2. run it and confirm RED for the intended missing behavior;
3. implement the minimum behavior for GREEN;
4. refactor while the focused suite remains green;
5. run affected compatibility and documentation gates.

Portable C cores were preferred for parsing, policy, campaign correlation, AP
health, time, journal encoding and storage state. Python wrappers compile and
run the real C harnesses. Runtime/source tests cover ESP-IDF integration points
that the host cannot physically execute.

### 3. Separate acceptance gates

Evidence is never promoted across these gates without a new test:

1. **Host gate:** portable unit/integration tests, CLI/wire fixtures, lifecycle
   harnesses, source audits and documentation contract.
2. **Firmware-build gate:** accepted ESP-IDF toolchain, size/HP-SRAM report,
   artifact path and firmware SHA-256.
3. **Device gate:** booted firmware identity, physical PSRAM/SD behavior,
   selected AP and sanitized UART transcript.
4. **Controlled RF gate:** owned AP, declared topology, independent monitor,
   retained PCAP and a ground-truth action.
5. **Cross-artifact gate:** UART, PCAP and JSONL are correlated to one run by
   firmware identity, target/channel, monotonic order and experiment timing.

### 4. Ground truth and negative controls

Every RF experiment should state what the AP or traffic generator actually did,
not infer it from Shield. A legitimate configuration change and an idle
baseline are included as negative controls. The expected false-positive and
false-negative cases are written before the test.

### 5. Loss and coverage accounting

`RX_DROPS`, `EVENT_DROPS`, `OUTPUT_FAILURES`, journal drops and sampled channel
coverage are recorded with every conclusion. Loss lowers confidence but does
not delete already observed evidence. A no-event result with unknown loss or
sampled coverage is inconclusive, not a pass.

### 6. Privacy and retained artifacts

Public documentation uses `LAB-AP-A/B`. Private lab records may retain the
minimum identity needed for reproduction. Published artifacts must remove
credentials, recovered PINs, station identities and decoy secret material.
Normalized evidence should include:

- exact source revision and firmware SHA-256;
- ESP-IDF/toolchain version and device revision;
- Shield command, mode and immutable target/channel record;
- sanitized UART transcript;
- independent monitor PCAP when an RF claim is made;
- finalized Shield JSONL and summary when storage is under test;
- AP/traffic-generator ground-truth log;
- observed loss and coverage counters.

### 7. CSA Stage 0 hardware gate

Stage 0 changes only Shield classification and authorization. The physical gate
must use one owned selected AP, one independent monitor and the exact firmware
SHA-256. Run an idle baseline, one legitimate AP-controlled CSA, one authorized
spoofed CSA and one Deauth control. Retain synchronized UART, PCAP, JSONL and AP
or generator ground truth.

Both CSA cases must emit
`[SHIELD/2] EVENT SOURCE=deauth TYPE=csa_announcement`, retain the appropriate
`CSA_EVENTS` evidence and produce zero CSA-triggered Defence telemetry or TX.
In other words, a lone CSA announcement never authorizes Defence TX. The
Deauth control must still produce its existing bounded response when the
selected target and active policy authorize it. This gate is `not run` until
those artifacts are returned; host GREEN alone is not RF proof.

## Host test coverage

The current test families include:

- CLI grammar, exact help, target selection and compatibility;
- channel pinning, hopping, sampled/continuous coverage and restoration;
- combined module routing and zero-TX passive policy;
- Deauth/PMKID Defence authorization, rate limits and multi-vector behavior;
- PMKID candidate grace, matching-M2 cancellation and unrelated-EAPOL rejection;
- WPS selected-channel routing and bounded event formatting;
- campaign correlation, threat transitions, peaks and idle completion;
- AP-health sequence, TSF, RSSI, channel, posture and recommendation rules;
- journal schema, aggregation, queue admission, failure domains and finalization;
- PSRAM capability, alignment, rollback, wipe and stack-budget contracts;
- stop/retry/quarantine, retained reports and read-only active-session controls;
- exact Shield wire bounds and legacy command compatibility.

Useful focused commands are:

```text
python -B tests/test_wifi_shield_core.py
python -B tests/test_wifi_shield_integration.py
python -B tests/test_wifi_shield_runtime_integration.py
python -B tests/test_wifi_shield_cli.py
python -B tests/test_wifi_shield_wire.py
python -B tests/test_wifi_shield_campaign.py
python -B tests/test_wifi_shield_ap_health.py
python -B tests/test_wifi_shield_journal.py
python -B tests/test_wifi_shield_journal_store.py
python -B tests/test_wifi_shield_storage_bundle.py
python -B tests/test_wifi_shield_documentation.py
```

Host success is evidence only for the contracts exercised by those harnesses.

## Controlled session evidence

The following ledger summarizes the development sessions from 2026-11-03
through 2026-11-05. `Observed` rows came from operator-provided UART and SD
output. At the time this document was written, the referenced raw RF capture
set was not available in this checkout, so no PCAP-dependent claim is promoted
to `verified` here.

| Scenario | Retained or reported evidence | Result | Status and boundary |
|---|---|---|---|
| Legacy scan/connect after Shield PSRAM integration | Device UART and operator confirmation | Scan and connection worked again after the allocation regression was corrected. | `observed`; compatibility on the tested build only. |
| Passive selected-target startup | `ARMED`, target/channel and repeated `STATUS` output | A single selected channel reported continuous coverage and received Deauth, PMKID and WPS evidence. | `observed`; no independent zero-TX capture. |
| Long passive run | Status counters | An early run exposed local RX drops, which stayed visible rather than being hidden. | `observed`; absence conclusions from that run are inconclusive. |
| Granular multi-vector Defence | UART Defence trigger/TX/release records | Deauth and PMKID actions could each receive one bounded decoy response in either observed sequence during one campaign. | `observed`; TX completion does not prove attacker receipt or protection. |
| Protect-all startup | `MODE=protect-all ACTIVE=deauth,pmkid PASSIVE=wps,sae,trust` | The complete preset armed on one immutable selected target. | `observed`; active authorization remained selected-target scoped. |
| Controlled Deauth stimulus | UART trigger, two-frame decoy result and Shield alert | Shield classified the selected-BSSID stimulus and the TX API reported success. | `observed`; client impact and prevention were not measured. |
| Controlled PMKID stimulus | UART candidate/trigger, one-frame decoy result and Shield event | The explicit PMKID decoy path executed and later released normally. | `observed`; capture outcome was not independently verified. |
| WPS enrollment/brute-force traffic | Traffic-generator log plus Shield WPS M1/enrollment activity | Passive WPS processing saw bounded enrollment evidence while active Defence handled only Deauth/PMKID. | `observed`; this does not prove Pixie Dust detection or WPS blocking. |
| Active-session read-only controls | Running-session `status` and `log status` output | Read-only commands worked while Shield retained the radio lease after an earlier admission bug was corrected. | `observed`; covered separately by host lifecycle tests. |
| Campaign correlation | Terminal `CAMPAIGN` report | Correlated Deauth/PMKID/WPS evidence produced a Critical `cross_vector` session peak. | `observed`; severity is a policy state, not compromise proof. |
| AP Health report | `AP_HEALTH` and recommendations | Beacon/RSSI/posture evidence produced bounded advice such as disabling WPS or requiring PMF. | `observed`; AP configuration was not changed and signal advice is local. |
| Early journal burst | Active log status with nonzero admission drops | Per-event journaling exposed queue pressure without stopping radio monitoring. | `observed`; the run contains incomplete journal evidence. |
| Aggregated journal follow-up | Active/final log status, finalized JSONL and file listing | High-rate aggregation reduced the later demonstrated run to zero journal drops and clean finalization. | `observed`; not a maximum-rate stress qualification. |
| Human summary and latest pointer | SD file listing | Clean Stop created JSONL, a bounded summary and `00-LATEST.txt`. | `observed`; power-loss atomicity was not exercised. |
| Download while Shield owns radio | UART lifecycle output | Bare download was changed to stop the active owner before entering ROM download mode. | `observed`; failure-injection paths remain host-tested only. |
| Firmware build and flash | Operator-reported successful build/device run | The tested firmware ran on ESP32-C5. | `observed`; artifact path and firmware SHA-256 were not retained in this ledger. |

### What these sessions did not prove

The sessions did not independently prove passive zero TX, prevention of a real
handshake, client retention, physical attacker identity, Evil Twin detection,
authentic CSA origin, AP-side packet loss, SAE attack detection, SD behavior
during sudden power loss or maximum sustained RF/journal throughput.

## Recommended next tests

### A. Trust and Evil Twin indicators

Use one owned baseline AP plus a separately controlled transmitter. Preserve an
independent monitor PCAP and the AP configuration for every case.

| ID | Stimulus | Expected Shield result | Ground-truth purpose |
|---|---|---|---|
| ET-01 | Idle baseline AP | No unexplained Trust drift. | Negative control and false-positive rate. |
| ET-02 | Same SSID, different BSSID and same security posture | Current Shield Trust may remain silent; record the false-negative boundary. | Establish the input for Stage 1 same-SSID candidate work. |
| ET-03 | Claimed same BSSID with AKM/cipher/PMF downgrade | Exact posture drift fields. | Same-identity security downgrade. |
| ET-04 | Claimed same BSSID with WPS or RSNXE drift | Exact WPS/RSNXE evidence. | Optional-security-field coverage. |
| ET-05 | Conflicting Beacon and Probe Response posture | Conflict evidence for the same claimed BSSID. | Cross-frame consistency. |
| ET-06 | Legitimate multi-AP ESS and roaming | Evidence remains explainable and is not labelled Evil Twin. | Negative control for enterprise/mesh layouts. |
| ET-07 | Deliberately perfect advertised clone | Document whether Trust remains quiet. | Expected false-negative boundary. |
| ET-08 | Local capture loss and sampled hopping | Confidence is limited without manufactured drift. | Receiver limitation control. |

Acceptance requires the correct drift fields and uncertainty. It does not
require a physical-attacker classification because the passive evidence cannot
support one.

### B. Beacon management-sequence continuity

Run deterministic replay first, then an owned-AP RF test with the complete
management stream recorded by an independent monitor.

| ID | Sequence/capture condition | Expected result |
|---|---|---|
| SQ-01 | `10 -> 11 -> 14` | Two management sequence gaps. |
| SQ-02 | `4095 -> 0` | Valid wrap with zero gaps. |
| SQ-03 | Duplicate frame with Retry | Retry count changes; gaps/cadence do not. |
| SQ-04 | Duplicate without Retry | No invented forward loss; evidence remains bounded. |
| SQ-05 | Large backward/ambiguous delta | Limited continuity rather than a huge gap count. |
| SQ-06 | Other management frames interleaved between Beacons | Shield gaps are compared with the full management sequence space. |
| SQ-07 | Injected local capture drops | Drop counters/confidence expose the limitation. |
| SQ-08 | Same sequence inputs with exact TSF cadence changes | TSF jitter changes independently from sequence gaps. |

For the RF case, compare Shield with the independent PCAP and report both
adapters' loss. The acceptance statement is “management sequence continuity
matched the retained capture within stated loss,” never “AP packet loss was
measured.”

### C. Real and spoofed CSA

Use an AP whose channel can be changed through its owned management interface
and a separate authorized frame generator.

| ID | Stimulus | Expected result |
|---|---|---|
| CSA-01 | Legitimate administrator-requested channel change | CSA evidence plus independently confirmed channel transition, without origin attribution. |
| CSA-02 | Spoofed CSA with no AP change | `CSA_EVENTS` increases while `CHANNEL_CHANGES` remains unchanged. |
| CSA-03 | Malformed, truncated or conflicting CSA/ECSA | Parser rejects the observation. |
| CSA-04 | Valid countdown progression with later transition | Raw countdown and subsequent channel evidence remain separately visible. |
| CSA-05 | Valid countdown with no transition | Announcement-only evidence; no channel-instability conclusion. |
| CSA-06 | Beacon, Probe Response and supported Action variants | Correct `VIA`/raw fields for every accepted source. |
| CSA-07 | Spoofed CSA followed by spoofed follow-up Beacons | Demonstrate the remaining passive-authentication limit. |
| CSA-08 | PMF optional and required configurations | Record which applicable robust action traffic is protected; do not generalize that result to Beacon/Probe CSA. |
| CSA-09 | Legitimate automatic channel selection | Negative control for operational AP behavior. |

For the Stage 0 gate, `CSA-01` and `CSA-02` must both produce informational
`csa_announcement` evidence with zero CSA-triggered Defence telemetry and zero
Shield-originated CSA response frames. Run `CSA-02` only with an authorized
generator. Add one Deauth control in the same firmware build to prove that the
bounded active response path was not disabled globally.

A real AP management log and independent monitor establish the test's ground
truth. Shield itself must continue to describe evidence, not declare a CSA
transmitter authentic.

### D. Additional priority validation

1. **Passive zero TX:** monitor every channel used by a passive run with an
   independent adapter and fail on any Shield-originated 802.11 transmission.
2. **Decoy capture correlation:** match a non-secret decoy artifact/tag in the
   independent PCAP while also checking whether a real handshake remained
   capturable.
3. **WPS coverage:** replay/observe M1-M8, ACK, NACK, DONE, fragments,
   retransmissions and retry bursts; verify that no PIN or credential enters
   UART/JSONL.
4. **SAE controls:** idle WPA3 baseline, normal commit/confirm, bounded flood
   and local-drop conditions; verify no sender attribution.
5. **Trust persistence:** capture, reboot, load, legitimate baseline update,
   corruption and transactional-store failure.
6. **Storage faults:** no SD, mount/open failure, full card, quota, short write,
   sync failure, sudden power loss and recovery of `.part` evidence.
7. **Lifecycle soak:** repeated scan/start/status/report/log/stop/connect and
   forced download cycles with task-stack and PSRAM high-water evidence.
8. **Queue stress:** controlled Deauth/CSA bursts with exact represented-count
   accounting and no RX starvation.
9. **Multi-channel sampling:** simultaneous activity on two owned channels to
   quantify expected detection latency and silence limitations.

## Reproducible experiment record

Use this template for each new controlled RF claim:

```text
Test ID:
Date/time zone:
Source revision:
Firmware artifact:
Firmware SHA-256:
ESP-IDF/toolchain:
Device/revision:
Shield command:
Mode and selected LAB target:
Channel plan and coverage:
AP configuration/ground truth:
Traffic generator and action:
Independent monitor and channel(s):
UART artifact:
PCAP artifact:
JSONL/summary artifact:
RX/EVENT/OUTPUT/JOURNAL drops:
Expected result:
Observed result:
Status: verified | observed | inconclusive | not run
Limitations:
```

Do not reuse a previous run's firmware identity or target snapshot. If PCAP,
UART and JSONL cannot be tied to the same run, keep cross-artifact conclusions
inconclusive.

## Completion criteria

Shield validation is not “complete” as one global state. Each narrow claim is
complete only when its required gate and artifact are present. In particular:

- parser/policy claims require repeatable host fixtures;
- build claims require an artifact and SHA-256;
- device claims require sanitized UART and firmware provenance;
- RF transmit/receive claims require an independent monitor PCAP;
- AP-origin claims require independent AP ground truth;
- storage durability claims require the corresponding injected physical fault;
- absence claims require continuous coverage and known loss.

Until then, the result remains `observed`, `inconclusive` or `not run` rather
than being upgraded by inference.
