# JanOS shared radio ownership

JanOS coordinates legacy radio commands, the Wi-Fi analyzer, WPS, passive
security monitoring and active Deauth Defence through
one owner/generation lease. The coordinator prevents overlapping mutation of
the ESP32-C5 Wi-Fi driver while preserving the established WFA/1, console and
WPS schema-v1 contracts used by existing clients.

## Owners and lifecycle

Owners are `NONE`, `LEGACY`, `ANALYZER`, `WPS`, `DEFENCE`,
`SECURITY_MONITOR` and `SHIELD`. The matching public enum names include
`JANOS_RADIO_OWNER_DEFENCE`, `JANOS_RADIO_OWNER_SECURITY_MONITOR` and
`JANOS_RADIO_OWNER_SHIELD`. `QUARANTINED` is a lease state, not an owner:

```text
IDLE/NONE -> PREPARING/<owner> -> RUNNING/<owner> -> CLEANUP/<owner> -> IDLE/NONE
                                                        |
                                                        +-> QUARANTINED/<owner>
```

- Acquisition atomically changes `IDLE/NONE` into `PREPARING/<owner>` and
  assigns a nonzero monotonically increasing generation. A loser publishes no
  partial state; generation exhaustion fails closed.
- `LEGACY` is a short startup transaction for mutating legacy handlers,
  `test_radio_channel(s)`, analyzer `clear` and manual OTA. It closes only
  after the handler has either published its subsystem state or failed.
- Analyzer scan startup is announced before the dispatcher releases its
  admission lock. The handler consumes the same generation; invalid arguments,
  initialization failure or scan-ID exhaustion roll it back. A stale token
  cannot release or cancel a newer owner.
- WPS, security-monitor profiles including active `deauth_detector_v2`
  Defence, and direct analyzer callers acquire their long-lived owner before
  checking the mutable host baseline, closing the opposite admission race.
- `DEFENCE` remains the owner for legacy standalone active Detector Defence. It
  is long-lived from the validated fresh `--only` selected BSSID allowlist
  through raw TX, worker join, saved-channel restoration and cleanup. Passive
  detector and Trace runs do not acquire this owner and do not transmit.
- Callbacks are accepted only for the current owner, generation and `RUNNING`
  state while the callback gate is open. Cleanup closes callback admission.
- Successful exact restoration releases owner/generation. Failed or uncertain
  restoration retains them in `QUARANTINED`; a later global `stop` can retry
  verified restoration, while a bare `reboot` is the fail-safe recovery path.
- Snapshot reads are bounded and fail conservatively busy during the tiny
  publication windows rather than spinning indefinitely.
- `SECURITY_MONITOR` is the passive security foundation's long-lived owner,
  from channel snapshot through callback shutdown, worker join, channel restore
  and verified cleanup. Failed cleanup retains this owner/generation for retry.
  Its fixed receive bounds, callback restrictions, exact Stop ordering, borrowed
  consumer lifetime and host-only evidence boundary are defined in the
  [passive security runtime contract](wifi-security-runtime.md). It adds no
  feature CLI or active-response engine.
- The `wps_guard`, `sae_guard`, `wifi_trust` and `deauth_detector_v2`
  compatibility profiles use `JANOS_RADIO_OWNER_SECURITY_MONITOR` through the
  shared runtime. Their established command names, help, return codes and wire
  records remain owned by those commands.
- The combined `wifi_shield` command uses `JANOS_RADIO_OWNER_SHIELD` from its
  bounded scan reservation through receive/TX closure, worker and publisher
  joins, filter/channel restoration, PSRAM wipe and verified release. Cleanup
  uncertainty retains `SHIELD/QUARANTINED` and no successful terminal.

The dispatcher never holds its admission lock while invoking a handler. The
lock order for short control-plane sections is:

```text
command/admission lock -> radio coordinator lock -> subsystem state lock
```

None of these locks may span handler execution, join/wait, raw TX, delays,
filesystem I/O or long driver probes. The D-UCB data-plane boundary is
documented in the [command manual](command-manual.md#attacks).

## Stable refusal contract

Dispatcher refusal preserves the WFACTL1 v1 wire line byte-for-byte and returns
nonzero:

```text
[WFACTL1] {"v":1,"type":"error","command":"console","code":"busy","reason":"radio_lease"}
Command returned non-zero error code: 0x1 (ERROR)
```

The reason may also be `command_in_progress` or `wifi_analyzer`. Active analyzer
`clear` retains its established `command:"clear"`, `reason:"wifi_analyzer"`
record. There is no positive `type:"busy"`, `owner`/`retryable` field or
zero-return special case. Existing ADV Tab5 and serial consumers may continue
treating the generic console error line as part of a rejection.

## Executable admission matrix

This table summarizes `tests/janos_console_admission_test.c` and the analyzer,
transaction and OTA fixtures. `ADMIT` means only that dispatcher admission
passed; the handler can still report validation, duplicate work or idempotent
stop.

| Current owner/state | Command family | Decision |
| --- | --- | --- |
| idle | legacy mutation, `test_radio_channel(s)` | reserve `LEGACY/PREPARING`, then run unlocked |
| idle | `sta_mac set factory`, `set random`, `set fixed <MAC>` | reserve short `LEGACY/PREPARING` transaction to persist the next-boot choice |
| idle | analyzer `scan` | announce `ANALYZER/PREPARING` before dispatcher unlock |
| idle | analyzer `clear` | short `LEGACY` transaction |
| idle | `wps verify`, `wps pixie`, `jwps campaign`, `selftest transport` | WPS service acquires `WPS/PREPARING` before baseline validation |
| idle | `deauth_detector_v2 --only ... defence [pmkid-decoy]` | handler validates the fresh selected BSSID allowlist, then acquires `SECURITY_MONITOR/PREPARING` as the Deauth V2 compatibility profile |
| idle | combined `wifi_shield start ...` | acquire `SHIELD/PREPARING`; bare Start keeps that reservation across its bounded scan |
| idle | `wps_guard`, `sae_guard`, `wifi_trust` and `deauth_detector_v2` compatibility profiles | acquire `SECURITY_MONITOR/PREPARING` through the shared runtime |
| any owner | `jwps plan`, `selftest db`, `selftest fragment`, `selftest pixie` | ADMIT; serialized offline WPS service, no radio lease |
| active owner | bare `download` with no other command in flight | ADMIT as a terminal control; the handler runs universal Stop and arms ROM boot only after safe quiescence. Retained `WPS/QUARANTINED` uses its guarded wait-and-wipe path instead |
| combined Shield | `wifi_shield status`, `report`, `log status`, `stop` | ADMIT; the first three are read-only and the Shield parser validates the complete subcommand before producing output |
| analyzer | WPS/JWPS operation requiring radio | busy: `radio_lease` |
| WPS | analyzer scan/clear or other radio mutation | busy: `radio_lease` |
| legacy preparing | analyzer or radio-using WPS/JWPS | busy: `command_in_progress` |
| analyzer or WPS | status/read commands, `show_scan_results`, built-in `help`, `reboot`, global `stop` | ADMIT |
| running legacy standalone Defence | `ping`, `version`, built-in `help`, `show_scan_results`, status reads, global `stop` | ADMIT; reboot and every radio mutation remain busy |
| quarantined legacy standalone Defence | bare `reboot`, global `stop` | ADMIT; `stop` retries cleanup and reboot remains the fail-safe recovery path |
| any owner, including quarantine | `sta_mac status` | ADMIT; read-only, no Wi-Fi initialization |
| active or quarantined owner | `sta_mac set ...` | busy: `radio_lease`; no NVS change |
| analyzer or WPS | `wps stop` / `wifi_analyzer stop` | ADMIT; each handler affects only its own subsystem and is otherwise idempotent |
| any mutation | nonzero console command already in flight | busy: `command_in_progress` where covered by legacy admission |
| idle with legacy analyzer-busy state | unrelated radio mutation | busy: `wifi_analyzer` |

Null/empty commands and invalid owner values fail closed with `radio_lease`.
The `SECURITY_MONITOR` allowlist in Stop and handoff semantics takes precedence
over the broad status-read rows above, including `sta_mac status`; those rows
retain their prior-owner semantics.
`wps status`, `secret status`, analyzer `status/caps` and prior legacy scan
results remain readable while another owner runs. Analyzer result records never
become legacy selection indices.

Manual `ota_check` may use only the exact `LEGACY` owner/generation token
reserved for that console invocation. Event-triggered IP OTA supplies no token
and remains `NONE`-only. An expired token cannot borrow a subsequently idle
lease.

## Stop and handoff semantics

- `wifi_analyzer stop` cannot stop WPS; `wps stop` cannot stop the analyzer.
- Global `stop` is admitted and stops the combined Shield first, then joins WPS
  and analyzer cleanup before compatibility-profile and legacy teardown.
  Security runtime cleanup follows profile-specific Stop and must succeed
  before legacy teardown. It refuses unsafe teardown while analyzer startup is
  still only announced; if startup publishes within the bounded wait, cancellation is
  directed to that generation.
- Analyzer `end` and WPS `terminal` can precede the final worker handoff by a
  short interval. Check status and use a bounded retry rather than rebooting for
  a transient busy result.
- Owner-specific stop output retains its subsystem contract. WPS can report
  `stopped`, `stop_pending` or `quarantined`; analyzer retains WFACTL1 records.
- Combined Shield Stop closes callback and active-TX admission, joins radio and
  output producers, restores filter/channel state and verifies
  `JANOS_RADIO_OWNER_SHIELD` release before its one actual terminal record,
  writer finalization, PSRAM wipe and successful V1 terminal publication.
  Uncertain cleanup durably checkpoints a provisional journal record while the
  `.part` file and PSRAM remain owned; it then publishes
  `SHIELD/QUARANTINED`. A later `wifi_shield stop` or global `stop` exclusively
  retries the retained generation. Queue pressure is handled with bounded
  drain/retry before writer ownership can be released. Missing or degraded SD
  remains fail-open and cannot by itself quarantine a cleanly restored radio.
- Legacy standalone Defence Stop closes its event generation before requesting worker stop,
  disables promiscuous receive, waits for TX to quiesce, restores the saved
  channel, zeroizes response material, and only then completes `CLEANUP` and
  emits `[DETECTOR_DEFENCE] stopped ...`. An unverified restore retains the
  `DEFENCE` owner in `QUARANTINED`; it is never reported as a successful stop.
  A later global `stop` may re-enter cleanup for the same owner/generation and
  emits `stopped` only after verified restoration and release.
- Security Stop closes callback admission, unregisters the callback, disables
  promiscuous RX, requests core stop/cancellation, signals and joins the worker,
  restores the saved promiscuous filter, restores the saved channel, finishes/wipes
  the core, completes exact lease cleanup and verified release, and only then
  wipes module context. Security
  checks the legacy host baseline after acquiring its reservation, snapshots the
  prior filter and installs exactly MGMT|DATA before enabling receive. A busy
  baseline releases the reservation without touching the existing radio session
  or feature context. Even failed filter apply requires restore; failed filter
  restore retains ownership/context for retry. Failed join/restore/unregister/disable retains
  unresolved state and ownership in quarantine for retry; uncertainty never
  permits terminal success or legacy reset. While `SECURITY_MONITOR` owns the
  lease, only its security status/stop policy names, global `stop`, `help`,
  `ping` and `version` are admitted. A bare `reboot` is the quarantine recovery
  exception only with a nonzero generation, no command in flight and no analyzer
  busy baseline. Feature handlers still validate active-family arguments before
  starting passive work; admission policy does not register those commands.

## Exact idle-STA WPS restore

The supported WPS baseline is the canonical initialized, running, idle STA
established by the existing host preparation hook. On a cold boot, preparation
may initialize/start that STA while WPS already owns the lease. Snapshot occurs
after preparation and before the transport's first borrowed mutation.

The internal snapshot captures the tracked Wi-Fi storage policy (`FLASH` or
`RAM`), mode, complete STA configuration, primary/secondary channel and STA
MAC. Secret-bearing configuration lives in wiped internal 8-bit RAM, never
PSRAM, SD or NVS. Stopped STA, AP and APSTA baselines are rejected before any
transport mutation.

Restore proceeds through stop, temporary RAM storage, mode/config/MAC, start,
channel and original storage policy, followed by complete readback of mode,
configuration, both channel fields and MAC plus tracked lifecycle/storage
invariants. A failed phase keeps the snapshot and lease for retry. Only exact
readback sets `restore_verified`, wipes/frees the snapshot and permits release;
otherwise service cleanup quarantines the owner.

The separate production `sta_mac` policy selects the effective STA identity
once per application boot: factory, one cached random address, or a fixed
locally administered unicast address. WPS may use a temporary session MAC; exact
restore targets the effective boot MAC, even after a next-boot policy change
has been saved. `sta_mac set` commits that change to NVS without rebooting or
mutating the active radio, and is busy while an owner is active or quarantined.
`sta_mac status` remains a read-only exception. Host tests cover admission and
restore paths; device radio behavior needs separate validation.

## Memory boundaries

WPS session scratch and the 160000-byte Pixie cache use tracked 8-bit PSRAM
without an internal-RAM fallback. WPS request/vault data and the Wi-Fi restore
snapshot stay in internal RAM and are wiped. Analyzer snapshots use their own
lazy PSRAM buffers. Allocation failures remain explicit in telemetry and fail
closed.

See [JanOS WPS laboratory workflows](janos-wps.md), the
[WFA/1 protocol](wifi-analyzer-protocol.md), the
[command manual](command-manual.md) and the
[integrated validation runbook](janos-radio-compatibility-validation.md).
