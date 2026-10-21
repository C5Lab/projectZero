# JanOS shared radio ownership

JanOS coordinates legacy radio commands, the Wi-Fi analyzer and WPS through
one owner/generation lease. The coordinator prevents overlapping mutation of
the ESP32-C5 Wi-Fi driver while preserving the established WFA/1, console and
WPS schema-v1 contracts used by existing clients.

## Owners and lifecycle

Owners are `NONE`, `LEGACY`, `ANALYZER` and `WPS`. `QUARANTINED` is a lease
state, not an owner:

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
- WPS and direct analyzer callers acquire their long-lived owner before
  checking the mutable host baseline, closing the opposite admission race.
- Callbacks are accepted only for the current owner, generation and `RUNNING`
  state while the callback gate is open. Cleanup closes callback admission.
- Successful exact restoration releases owner/generation. Failed or uncertain
  restoration retains them in `QUARANTINED`; reboot is the recovery path.
- Snapshot reads are bounded and fail conservatively busy during the tiny
  publication windows rather than spinning indefinitely.

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
| idle | analyzer `scan` | announce `ANALYZER/PREPARING` before dispatcher unlock |
| idle | analyzer `clear` | short `LEGACY` transaction |
| idle | `wps verify`, `wps pixie`, `jwps campaign`, `selftest transport` | WPS service acquires `WPS/PREPARING` before baseline validation |
| any owner | `jwps plan`, `selftest db`, `selftest fragment`, `selftest pixie` | ADMIT; serialized offline WPS service, no radio lease |
| analyzer | WPS/JWPS operation requiring radio | busy: `radio_lease` |
| WPS | analyzer scan/clear or other radio mutation | busy: `radio_lease` |
| legacy preparing | analyzer or radio-using WPS/JWPS | busy: `command_in_progress` |
| analyzer or WPS | status/read commands, `show_scan_results`, built-in `help`, `reboot`, global `stop` | ADMIT |
| analyzer or WPS | `wps stop` / `wifi_analyzer stop` | ADMIT; each handler affects only its own subsystem and is otherwise idempotent |
| any mutation | nonzero console command already in flight | busy: `command_in_progress` where covered by legacy admission |
| idle with legacy analyzer-busy state | unrelated radio mutation | busy: `wifi_analyzer` |

Null/empty commands and invalid owner values fail closed with `radio_lease`.
`wps status`, `secret status`, analyzer `status/caps` and prior legacy scan
results remain readable while another owner runs. Analyzer result records never
become legacy selection indices.

Manual `ota_check` may use only the exact `LEGACY` owner/generation token
reserved for that console invocation. Event-triggered IP OTA supplies no token
and remains `NONE`-only. An expired token cannot borrow a subsequently idle
lease.

## Stop and handoff semantics

- `wifi_analyzer stop` cannot stop WPS; `wps stop` cannot stop the analyzer.
- Global `stop` is admitted and joins WPS, then analyzer cleanup, before legacy
  teardown. It refuses unsafe teardown while analyzer startup is still only
  announced; if startup publishes within the bounded wait, cancellation is
  directed to that generation.
- Analyzer `end` and WPS `terminal` can precede the final worker handoff by a
  short interval. Check status and use a bounded retry rather than rebooting for
  a transient busy result.
- Owner-specific stop output retains its subsystem contract. WPS can report
  `stopped`, `stop_pending` or `quarantined`; analyzer retains WFACTL1 records.

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

This restores the current boot identity but does not implement the unrelated
persistent `sta_mac` policy or CLI.

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
