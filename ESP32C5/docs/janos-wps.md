# JanOS known-PIN WPS

JanOS exposes a deliberately small production WPS surface for authorized,
explicitly selected laboratory access points. The current implementation verifies
one known eight-digit WPS PIN and, after authenticated M7, retains the recovered
PIN and network key for a bounded one-time reveal.

The adapter is pinned to **ESP-IDF 6.0.2** because it uses private Wi-Fi/WPS APIs.
Do not build this component against another IDF release without revalidating the
adapter and the full radio-compatibility matrix.

## Commands

| Command | Admission and result |
| --- | --- |
| `wps verify <bssid> <8-digit-pin>` | Requires an explicit unicast BSSID, a valid WPS-checksummed PIN and an idle/admissible radio. Returns `0` after an asynchronous run is accepted; refusal or invalid input returns nonzero. |
| `wps status` | Safe read under either radio owner. Returns the current phase, run/generation, operation and cleanup results, and allocation counters; console result is zero. |
| `wps stop` | Stops only WPS. It is admitted while WPS owns the radio, but is refused with the shared busy contract while the analyzer owns it. |
| `secret status` | Safe read under either owner. Reports `empty`, `available` or `expired` without exposing secret bytes; console result is zero. |
| `secret reveal` | One-time plaintext reveal. An available value is consumed and wiped. Empty/expired states return a JSON result with console result zero rather than the generic console error. |
| `secret erase` | Wipes the volatile vault and returns zero without printing a dedicated acknowledgement. |

The production JanOS CLI does **not** expose PixieDust, JWPS lookup/campaign,
per-request RTC epoch, or `sta_mac` policy commands. Those remain standalone
laboratory/probe capabilities.

## Asynchronous contract

An accepted request prints exactly this shape before returning to the prompt:

```text
{"schema_version":1,"record_type":"accepted","run_id":7,"operation":"wps_verify"}
```

That run later emits exactly one terminal record:

```text
{"schema_version":1,"record_type":"terminal","run_id":7,"operation_result":"success","cleanup_result":"restored","lease_state":"released","bulk_bytes":0,"bulk_peak_bytes":24576,"secret_bytes":0,"secret_peak_bytes":24,"allocation_failures":0}
```

Treat the three outcomes independently:

- `operation_result` describes the WPS operation, for example `success`,
  `cancelled`, `timeout`, `wifi_prepare_failed` or an internal/protocol result;
- `cleanup_result` says whether the borrowed radio was restored;
- `lease_state` says whether shared ownership was released or retained.

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
The universal `stop` also joins WPS before legacy radio teardown.

## Secret lifecycle and memory

- The request copy and other secret allocations use 8-bit internal RAM.
- Protocol/session scratch uses 8-bit PSRAM; there is no internal-RAM fallback
  for the bulk allocator.
- The retained vault expires after **300000 ms (five minutes)** using monotonic
  time, including after the radio lease has been released.
- Reveal is one-shot. Replacement, cancellation, expiry, explicit erase and
  failure paths wipe the volatile copy using a non-optimizable wipe.
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
must be judged independently. The current JanOS `terminal` schema does not
expose `storage_result`; inspect the SD card separately if durable export
matters. The standalone lab suite has richer storage diagnostics, but those
fields are not part of the production JanOS schema-v1 terminal record.

After an unsuccessful session JanOS may also append one bounded, deduplicated
diagnostic observation to:

```text
/sdcard/lab/wps/unknown_devices.jsonl
```

This is not a partial success record. It may contain BSSID/OUI, SSID, bounded
manufacturer/model/device identity and the failure stage/reason so the local
vendor database can be improved. It must not contain PINs or PIN candidates,
network keys, nonces, DH/AuthKey material, E-Hashes, credential hashes,
encrypted settings or raw frames. Treat BSSID/SSID and device identity as
potentially sensitive metadata. Observation-storage failure is independent of
the WPS result and, like the success-file write, is not exposed by the current
production `terminal` record.

## Shared-radio refusal

If another owner holds the radio, JanOS refuses the command before its handler:

```text
[WFACTL1] {"v":1,"type":"error","command":"console","code":"busy","reason":"radio_lease"}
Command returned non-zero error code: 0x1 (ERROR)
```

No `accepted` record is emitted for a refused request. Status reads remain
available. See [Shared radio ownership](janos-radio-lease.md) for the complete
matrix and [compatibility validation](janos-radio-compatibility-validation.md)
for the hardware runbook.
