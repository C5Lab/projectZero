# JanOS shared radio ownership

The Wi-Fi analyzer and known-PIN WPS runtime share one owner/generation lease.
The lease prevents two mutating workflows from borrowing the ESP32-C5 Wi-Fi
driver at the same time while preserving the established WFA/1 and console
contracts used by existing clients.

## Lifecycle

```text
IDLE -> PREPARING -> RUNNING -> CLEANUP -> IDLE
                                  |
                                  +-> QUARANTINED
```

- Acquisition atomically compares and swaps owner `NONE` to `ANALYZER` or
  `WPS`. Exactly one contender wins; a loser does not publish partial state.
- Every successful acquisition receives a nonzero, monotonically increasing
  generation. Exhaustion fails closed rather than reusing a generation.
- All generation-sensitive mutators are serialized as one short critical
  section (a portable atomic gate in host tests). Validation and publication
  therefore cannot be split by cleanup/reacquire of the same owner; a stale
  operation cannot mutate the next generation.
- Callbacks are accepted only for the current owner, current generation and
  `RUNNING` state while the callback gate is open.
- Cancellation closes callback admission and cleanup closes it again before
  releasing resources.
- Successful restoration publishes `IDLE`, clears generation and releases the
  owner. Failed restoration retains owner/generation in `QUARANTINED`.
- Reboot is the recovery path for quarantine. The implementation does not force
  task deletion or pretend that uncertain callback/radio state is safe.
- Snapshot reads use bounded retries and then return a conservative busy state
  during the tiny claim/release publication windows, so a preempted publisher
  cannot make a single-core ESP32-C5 reader spin indefinitely.

## Stable refusal contract

Dispatcher refusal preserves the WFACTL1 v1 wire line byte-for-byte and returns
nonzero:

```text
[WFACTL1] {"v":1,"type":"error","command":"console","code":"busy","reason":"radio_lease"}
Command returned non-zero error code: 0x1 (ERROR)
```

The reason can also be `command_in_progress` or `wifi_analyzer`. There is no
positive `type:"busy"` reply, `owner` field, `retryable` field or zero-return
special case. Existing Tab5/serial consumers may continue treating the generic
ESP console error line as part of a rejected command.

## Admission matrix

This table is transcribed from `tests/janos_console_admission_test.c`, the
portable executable policy fixture. `ADMIT` means only that dispatcher-level
admission passed; the selected service may still return its own idempotent/busy
or validation result.

| Owner | Command | Subcommand | In-flight | Analyzer busy | Decision |
| --- | --- | --- | ---: | --- | --- |
| none | `wifi_analyzer` | `scan` | 0 | no | ADMIT |
| none | `wifi_analyzer` | `scan` | 1 | no | busy: `command_in_progress` |
| analyzer | `wifi_analyzer` | `status` | 0 | yes | ADMIT |
| analyzer | `wifi_analyzer` | `caps` | 0 | yes | ADMIT |
| analyzer | `wifi_analyzer` | `stop` | 0 | yes | ADMIT |
| analyzer | `wifi_analyzer` | `scan` | 0 | yes | ADMIT; analyzer handler decides duplicate-work behavior |
| analyzer | `wps` | `status` | 0 | yes | ADMIT |
| analyzer | `secret` | `status` | 0 | yes | ADMIT |
| analyzer | `show_scan_results` | — | 0 | yes | ADMIT |
| analyzer | `wps` | `verify` | 0 | yes | busy: `radio_lease` |
| analyzer | `wps` | `stop` | 0 | yes | busy: `radio_lease` |
| WPS | `wps` | `status` | 0 | no | ADMIT |
| WPS | `wps` | `stop` | 0 | no | ADMIT |
| WPS | `wps` | `verify` | 0 | no | ADMIT; WPS handler refuses a duplicate run |
| WPS | `secret` | `status` | 0 | no | ADMIT |
| WPS | `secret` | `reveal` | 0 | no | ADMIT |
| WPS | `secret` | `erase` | 0 | no | ADMIT |
| WPS | `wifi_analyzer` | `caps` | 0 | no | ADMIT |
| WPS | `wifi_analyzer` | `status` | 0 | no | ADMIT |
| WPS | `wifi_analyzer` | `scan` | 0 | no | busy: `radio_lease` |
| WPS | `wifi_analyzer` | `stop` | 0 | no | busy: `radio_lease` |
| WPS | `show_scan_results` | — | 0 | no | ADMIT |
| WPS | global `stop` | — | 0 | no | ADMIT |
| WPS | `reboot` | — | 0 | no | ADMIT |
| WPS | built-in `help` | — | 0 | no | ADMIT |
| none | `channel_view` | — | 0 | yes | busy: `wifi_analyzer` |
| none | `show_scan_results` | — | 0 | yes | ADMIT |
| none | `wps` | `status` | 0 | yes | ADMIT |
| none | `secret` | `status` | 0 | yes | ADMIT |

Null/empty commands and an invalid owner fail closed with `radio_lease`.

## Stop and status semantics

- `wifi_analyzer stop` is analyzer-specific and cannot stop WPS.
- `wps stop` is WPS-specific and cannot stop the analyzer.
- Global `stop` is always admitted. It first joins WPS, then joins analyzer
  cleanup, before running legacy teardown.
- `reboot`, built-in `help`, `show_scan_results`, `wifi_analyzer caps/status`,
  `wps status` and `secret status` remain available while either owner runs.
- `show_scan_results` is read-only and exposes only the prior legacy scan
  snapshot. Analyzer records never become legacy selection indices.

An owner-specific stop may print its own completion/pending/quarantine record.
A cross-owner stop is a normal dispatcher busy error with nonzero return.

## Bounded handoff and isolation

Analyzer `end` and WPS `terminal` are emitted before or during final worker
handoff, so an immediate next mutation can briefly be busy. Check the relevant
status and use a bounded retry; do not reboot merely for a transient busy result.

WPS-owned Wi-Fi/IP events are consumed before legacy state-machine side effects.
Automatic and manual OTA check shared ownership before worker creation. An
active or quarantined owner prevents OTA start; rejection does not mark OTA as
started. Legacy analyzer scan snapshots, selections, country policy and NVS
settings remain in their original domain.

## MAC and memory boundaries

Before a workflow, the JanOS runtime reads the active STA MAC and requires it to
match the boot baseline supplied to the WPS radio wrapper. The transport records
that verified baseline, applies a temporary session identity, then restores the
exact baseline before successful cleanup/release. Host tests cover factory-like,
fixed and random-per-boot locally administered starting addresses across success,
cancellation, timeout/failure and consecutive runs. WPS/analyzer do not write
the standalone STA-MAC policy NVS record.

Current JanOS does not expose the standalone `sta_mac` CLI or apply its
persistent factory/random/fixed UI at boot. Therefore the transport restoration
contract is ready for those starting addresses, but production policy selection
is not part of this release.

WPS bulk scratch uses PSRAM. Secret request/vault data stays in internal RAM and
is wiped. Analyzer snapshots use their own lazy PSRAM buffers. Allocation failure
does not silently fall back to a different memory class.

See [JanOS known-PIN WPS](janos-wps.md), the
[WFA/1 protocol](wifi-analyzer-protocol.md), and the
[integrated validation runbook](janos-radio-compatibility-validation.md).
