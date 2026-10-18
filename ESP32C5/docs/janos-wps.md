# JanOS WPS laboratory commands

JanOS exposes the component-owned WPS/Pixie/JWPS engines for authorized,
explicitly selected laboratory access points. Online operations always target
one explicit unicast BSSID and use the shared WPS radio owner. Offline planning
and deterministic self-tests are serialized by the same service without taking
the physical radio lease.

The private Wi-Fi/WPS adapter supports the explicitly verified ESP-IDF range
**6.0.0 through 6.0.1**. Other IDF patches are rejected at compile time until
the adapter and the full radio-compatibility matrix are revalidated.

## Commands

| Command | Admission and result |
| --- | --- |
| `wps verify <bssid> <8-digit-pin>` | Requires an explicit unicast BSSID, a valid WPS-checksummed PIN and an idle/admissible radio. Returns `0` after an asynchronous run is accepted; refusal or invalid input returns nonzero. |
| `wps pixie <bssid> [epoch]` | Capture, run the bounded offline Pixie search in tracked PSRAM, then verify the recovered candidate online. The optional epoch is unsigned decimal Unix seconds in `1577836800..4102444800` (2020-01-01 through 2100-01-01 UTC). |
| `wps status` | Safe read under either radio owner. Returns the current phase, run/generation, operation and cleanup results, and allocation counters; console result is zero. |
| `wps stop` | Stops only WPS. It remains admitted under another owner but is idempotent when no WPS run exists; it never cancels analyzer work. |
| `jwps plan <bssid> [ssid]` | Build and print the bounded candidate plan offline. The optional SSID may be quoted or supplied as multiple trailing CLI words; its joined byte length is at most 32. |
| `jwps campaign <bssid> <start-index> <count:1-3> [ssid]` | Run one to three planned candidates through the shared radio/restore path. The optional SSID follows the same joining rule. |
| `selftest db` / `selftest fragment` / `selftest pixie` | Serialized deterministic offline checks; they do not borrow the radio. |
| `selftest transport` | Serialized transport test through the shared WPS radio owner and exact restore path. |
| `secret status` | Safe read under either owner. Reports `empty`, `available` or `expired` without exposing secret bytes; console result is zero. |
| `secret reveal` | One-time plaintext reveal. An available value is consumed and wiped. Empty/expired states return a JSON result with console result zero rather than the generic console error. |
| `secret erase` | Wipes the volatile vault and returns zero without printing a dedicated acknowledgement. |

The production component reuses `private/workflow`, campaign, Pixie, session,
protocol, PIN and transport sources directly. It does not depend on a standalone
mini-OS entry point. `sta_mac` policy commands remain outside this surface.

## Asynchronous contract

An accepted request prints exactly this shape before returning to the prompt:

```text
{"schema_version":1,"record_type":"accepted","run_id":7,"operation":"wps_verify"}
```

That run later emits exactly one terminal record. The existing verify terminal
shape remains byte-compatible with ADV Tab5:

```text
{"schema_version":1,"record_type":"terminal","run_id":7,"operation_result":"success","cleanup_result":"restored","lease_state":"released","bulk_bytes":0,"bulk_peak_bytes":24576,"secret_bytes":0,"secret_peak_bytes":24,"allocation_failures":0}
```

Treat the three outcomes independently:

- `operation_result` describes the WPS operation, for example `success`,
  `cancelled`, `timeout`, `wifi_prepare_failed` or an internal/protocol result;
- `cleanup_result` says whether the borrowed radio was restored;
- `lease_state` says whether shared ownership was released or retained.

When persistence was attempted, JanOS emits one additive record immediately
before the unchanged terminal record:

```text
{"schema_version":1,"record_type":"wps_storage","run_id":7,"storage_result":"ok"}
```

`storage_result` is independent of protocol and cleanup results. Current values
are `not_required`, `ok`, `duplicate`, `full`, `invalid`, `cancelled`,
`io_error`, `mount_error` and `unmount_error`. Consumers that only understand
the existing terminal schema may ignore this additive record.

`operation_result:"success"` means authenticated M7 and credential extraction;
it does not by itself prove cleanup. The secret vault is made available only
when that operation succeeded **and** cleanup restored/released the lease. A
failed restoration can therefore pair an operation success with
`cleanup_result:"failed"` and `lease_state:"retained"`; it quarantines the
shared lease and blocks new radio mutations until reboot recovery. `wps status`
remains available.

Example with redacted laboratory values:

```text
> wps verify 02:00:00:00:00:01 <valid-8-digit-pin>
{"schema_version":1,"record_type":"accepted","run_id":7,"operation":"wps_verify"}
...
{"schema_version":1,"record_type":"terminal","run_id":7,"operation_result":"success","cleanup_result":"restored","lease_state":"released","bulk_bytes":0,"bulk_peak_bytes":24576,"secret_bytes":0,"secret_peak_bytes":24,"allocation_failures":0}
```

The interactive REPL normally echoes what the operator types, so the PIN can be
visible on the terminal while entering `wps verify`. JanOS wipes the mutable PIN
argument and drops retained linenoise history after dispatch; this does not erase
bytes already displayed or captured by an external serial logger.

## Pixie capture, recovery and verification

`wps pixie` is one asynchronous run with three separated phases:

1. capture one WPS exchange from the explicit owned BSSID, then completely
   clean up that radio session;
2. run the bounded offline search once, using the tracked 160000-byte PSRAM
   cache and cooperative yield/cancel checks;
3. if a full candidate was found, perform up to three fresh online verification
   sessions with a one-second cancellable delay after timeout, disconnect or an
   identity loop.

The offline search is not rerun between verification retries. One operation
keeps its randomized client identity across capture and retries; a later
operation generates a new identity. An optional epoch enables the bounded RTL
window only after exact unsigned parsing and range/overflow validation.

Progress uses additive `wps_stage` records such as `pixie_capture_start`,
`pixie_capture`, `pixie_done`, `pixie_verify_attempt`, `pixie_verify` and
`pixie_verify_retry`. These workflow records currently use their established
`schema:1`/`operation_id` envelope and do not replace the production
`schema_version:1` accepted/status/terminal contract. Capture success, an
offline match or a partial match is not credential recovery. Only a fresh
authenticated M7 publishes the vault/result. The terminal operation result is
`pixie_pin_and_m7_verified`; unlike known-PIN `wps verify`, it is not normalized
to the generic `success` value. A bounded campaign reports
`pin_and_m7_verified` after the same authenticated-M7 gate.

## JWPS plan and bounded campaign

`jwps plan` mounts the laboratory database, creates a deterministic candidate
order, removes duplicates and reports unsupported/truncated counts. It is an
offline serialized service operation and does not acquire the radio. The SSID
may be omitted, passed as one quoted argument, or reconstructed from trailing
arguments joined by single spaces; the resulting byte string is limited to 32
bytes and rejects control characters.

`jwps campaign` loads the same plan and attempts at most `count` candidates,
where `count` is `1..3` and the start index must exist. Only an explicit
cryptographic PIN rejection consumes a candidate and advances `resume_index`.
Success stops at the successful index; timeout, disconnect, identity refusal,
setup lock, cancellation and internal/cleanup failure stop without consuming
the current candidate. Exhausting the requested budget returns
`candidate_budget_exhausted`; setup lock, pause and fatal paths remain distinct.
A success result file is still gated on authenticated M7, never on plan output
or PIN-half evidence.

Every accepted campaign emits an additive progress record before storage and
terminal output:

```text
{"schema_version":1,"record_type":"wps_campaign","run_id":7,"candidate_count":10,"attempt_count":3,"resume_index":6}
```

`candidate_count` is the deduplicated plan size, `attempt_count` is the number
of online candidates actually started, and `resume_index` is the safe index for
the next bounded invocation. Older clients may ignore this record.

Both `jwps plan` and `jwps campaign` print every generated candidate as a
`SENSITIVE` line. This includes candidates outside the selected campaign
budget. These lines can reveal usable PIN candidates and must be redacted from
support logs. One-shot `secret reveal`, vault expiry and `secret erase` do not
erase candidate lines already captured by the UART terminal or logger.

The database must be present as `/sdcard/lab/wps_pin.bin`. Missing or unreadable
media is an early operation failure: it must not mutate or quarantine a radio
that was never borrowed.

## Component self-tests

`selftest db`, `selftest fragment` and `selftest pixie` exercise deterministic
component paths without a radio lease. `selftest transport` uses the WPS owner
and the same exact idle-STA restore/quarantine path as online operations. A
verified self-test terminates with `operation_result:"selftest_verified"`;
self-tests never publish a recovered credential.

## Status, stop and cancellation

`wps status` has this exact schema-v1 field set:

```text
{"schema_version":1,"record_type":"wps_status","phase":"idle","run_id":7,"generation":7,"operation_result":"success","cleanup_result":"restored","bulk_bytes":0,"bulk_peak_bytes":24576,"secret_bytes":0,"secret_peak_bytes":24,"allocation_failures":0}
```

Phases are `idle`, `preparing`, `running`, `cleanup` and `quarantined`.

`wps stop` cooperatively requests cancellation and waits up to five seconds for
cleanup. Its response is one of these shapes (a pending phase can also be
`preparing` or `running`):

```text
{"schema_version":1,"record_type":"wps_stop","result":"stopped","phase":"idle"}
{"schema_version":1,"record_type":"wps_stop","result":"stop_pending","phase":"cleanup"}
{"schema_version":1,"record_type":"wps_stop","result":"quarantined","phase":"quarantined"}
```

`stopped` and `stop_pending` return success. `quarantined` returns nonzero.
Cancellation produces one terminal record with `operation_result:"cancelled"`,
wipes the result vault and restores/releases the lease when cleanup succeeds.
An operation that already crossed its irreversible success-file commit gate
owns bounded completion: a late `wps stop` waits for safe teardown but reports
`stop_pending` rather than falsely claiming `stopped`.
The universal `stop` also joins WPS before legacy radio teardown.

Cancellation is polled during Pixie capture, offline search, verification
delay/retry, campaign execution and M1-M7 processing. It also participates in
the storage commit gate described below. Cleanup and terminal publication remain
single-owner operations, so each accepted run emits exactly one terminal.

## Exact idle-STA restore and quarantine

An online WPS operation first reserves the WPS owner, then lets the existing
host preparation hook establish the canonical initialized/running idle STA when
needed. Before the transport mutates the driver it snapshots the tracked
storage policy, mode, complete STA configuration, primary/secondary channel and
STA MAC. Stopped STA, AP and APSTA baselines are rejected before mutation.

Cleanup restores every saved field and verifies complete readback plus tracked
running/storage invariants. A transient restore error retains the internal
snapshot for retry. Only exact equality permits lease release; otherwise the
service remains quarantined. The configuration snapshot is allocated in wiped
internal RAM because it can contain credentials. It is never copied to PSRAM,
SD or NVS. This transport contract preserves the active boot MAC but does not
add a persistent `sta_mac` policy.

## Secret lifecycle and memory

- The request copy and other secret allocations use 8-bit internal RAM.
- Protocol/session scratch uses 8-bit PSRAM; there is no internal-RAM fallback
  for the bulk allocator. The 160000-byte Pixie search cache uses this tracked
  allocator and is scrubbed/freed on success, failure and cancellation.
- The retained vault expires after **300000 ms (five minutes)** using monotonic
  time, including after the radio lease has been released.
- Reveal is one-shot. A newly accepted operation replaces the previous
  unrevealed value; lease/admission/allocation/worker-start refusal preserves
  it because no operation was accepted. Cancellation, expiry, explicit erase
  and failure paths wipe the volatile copy using a non-optimizable wipe.
- `secret erase` is vault-only. It erases the value available at its
  linearization point and never cancels an active WPS operation; if an active
  run authenticates later, that run may publish a new five-minute secret.
- Status and terminal telemetry contain allocation sizes/high-water marks only,
  never secret contents.

Examples:

```text
> secret status
{"schema_version":1,"record_type":"secret_status","state":"available","run_id":7,"remaining_ms":298000}
> secret reveal
SENSITIVE operation_id=7 recovered_pin=<redacted-pin> network_key="<redacted-network-key>"
> secret reveal
{"schema_version":1,"record_type":"secret_reveal","result":"empty"}
```

An expired vault returns the same record with `result:"expired"`. `secret erase`
prints no acknowledgement; confirm it with `secret status`:

```text
> secret erase
> secret status
{"schema_version":1,"record_type":"secret_status","state":"empty","run_id":0,"remaining_ms":0}
```

## SD result storage

After authenticated M7, JanOS attempts to write one plaintext JSON result per
normalized BSSID under:

```text
/sdcard/lab/wps/results/wps_aa-bb-cc-dd-ee-ff.json
```

The file contains the recovered PIN and network key plus bounded WSC identity
metadata. It is deliberately sensitive data: protect the card, do not publish
the file, and remove it according to the laboratory retention policy. No partial
PIN proof, failed candidate or capture bundle is written as a success result.

Storage failure does not turn authenticated protocol success into failure. The
write occurs before final outer lease restoration, so a complete result file may
also exist when later cleanup is quarantined; operation, cleanup and durability
must be judged independently. Durability is reported by the separate
`wps_storage` record; it is deliberately not added to the production schema-v1
terminal record.

The success writer first flushes and `fsync`s a temporary file. It then asks the
service commit gate exactly once. A stop that won before this gate truncates and
`fsync`s the sensitive temporary file before unlink and leaves the existing
final result untouched. If opening, truncating, syncing, closing or unlinking
the temporary file fails, storage reports `io_error`. JanOS attempts to scrub
and unlink the file, but damaged or read-only media can prevent that cleanup;
inspect and remove any residual `.tmp` locally before reusing or sharing the
card. Once the gate wins, stop is too late and the writer performs a bounded
recoverable replacement (`final -> .bak`, `.tmp -> final`), restoring or
retaining the backup if a promotion fails. The next write repairs an
interrupted backup before promotion. Filesystem lookup distinguishes missing
paths from media I/O errors and fails closed on the latter.

After an unsuccessful session JanOS may also append one bounded, deduplicated
diagnostic observation to:

```text
/sdcard/lab/wps/unknown_devices.jsonl
```

The observation file is bounded: its pre-append size must remain below 131072
bytes. At or above that boundary the append is rejected as `full`.

This is not a partial success record. It may contain BSSID/OUI, SSID, bounded
manufacturer/model/device identity and the failure stage/reason so the local
vendor database can be improved. It must not contain PINs or PIN candidates,
network keys, nonces, DH/AuthKey material, E-Hashes, credential hashes,
encrypted settings or raw frames. Treat BSSID/SSID and device identity as
potentially sensitive metadata. Observation-storage failure is independent of
the WPS result and is likewise reported separately from the production
`terminal` record.

## Source and licensing boundary

Production builds consume only component-owned sources listed in
`components/janos_wps/CMakeLists.txt`; removed standalone test firmware is not a
build dependency. Keep the source-ownership and license tests green whenever
the private engines or their build graph change.

## Shared-radio refusal

If another owner holds the radio, JanOS refuses a conflicting radio mutation
before its handler:

```text
[WFACTL1] {"v":1,"type":"error","command":"console","code":"busy","reason":"radio_lease"}
Command returned non-zero error code: 0x1 (ERROR)
```

No `accepted` record is emitted for a refused request. Status reads remain
available. See [Shared radio ownership](janos-radio-lease.md) for the complete
matrix and [compatibility validation](janos-radio-compatibility-validation.md)
for the hardware runbook. The concise CLI catalogue is in the
[command manual](command-manual.md#wps-jwps-selftest-and-secret).
