# JanOS radio compatibility validation

This runbook validates the integrated analyzer/WPS lease without confusing
source checks, host execution, firmware compilation and device evidence.
Use only explicitly owned laboratory access points. Replace every angle-bracket
placeholder locally; do not paste PINs or network keys into repository logs.

## Evidence status

| Layer | Current evidence | Status |
| --- | --- | --- |
| Source/portable policy | Exact WFACTL1 busy fixture, dispatcher ordering, owner/subcommand matrix, legacy analyzer isolation, OTA guards | complete in focused tests |
| Host C/Python | Task-5 compatibility selection: 124/124 passed; lease race test includes 10,000 acquisitions and the lease suite passed 20 repeated runs | complete before this document |
| Full repository host suite | 2026-10-16: 275 tests, 0 failures, 0 skips | PASS |
| ESP-IDF firmware | 2026-10-16: ESP-IDF 6.0.2 Docker build, 40% app partition free | PASS |
| Device hardening matrix | Contention both directions, stops, handoff, MAC/resource checks | pending user execution |

Earlier analyzer and known-PIN device sessions are useful historical evidence,
but they do not replace the complete matrix below for the final hardening build.

## Host and build gates

From the repository root:

```powershell
wsl.exe bash -lc 'cd /mnt/c/Users/mati/Documents/GitHub/projectZero/ESP32C5 && python3 -m unittest discover -s tests -p "test_*.py"'
git diff --check
docker run --rm -v "${PWD}:/project" -w /project `
  -e IDF_PY_FLAGS=--preview espressif/idf:v6.0.2 `
  bash -lc "idf.py -B build-janos-wps build"
Get-Item build-janos-wps/projectZero.bin | Select-Object Length,FullName
Get-FileHash build-janos-wps/projectZero.bin -Algorithm SHA256
```

Record the exact test count/skips, image path, image size, partition headroom and
SHA-256. The user performs flashing:

```powershell
idf.py -B build-janos-wps -p COMx flash monitor
```

Do not call a device row PASS based only on host tests or a successful link.

Final host/build evidence for the current source tree (2026-10-16):

- full discovery: 275 tests, 0 failures, 0 skips;
- repeated lease suite: 20/20 passes, including 10,000 acquire/transition/ABA
  races per run;
- `build-janos-wps/projectZero.bin`: 2,472,016 bytes;
- application size: `0x25b850`, smallest app partition `0x3f0000`, 40% free;
- BIN SHA-256:
  `C2E7D177124604A0709BD64B86F6F589FD080229374B627CD263CE7AC9E2B808`;
- matching `projectZero.elf`: 22,236,056 bytes, SHA-256
  `12B21DE9FE5E99B7BE692B1782A5EB7238A5FE1FF8BBD7AA52B5A9E8CD0BF8D1`.

The configure step reports non-fatal ESP-IDF component-ownership warnings for
reviewed shared sources compiled by `janos_wps`; the build and partition checks
still complete successfully. Those warnings are not device-acceptance evidence.

## Baseline

After boot, save the full boot banner and run:

```text
wps status
secret status
wifi_analyzer status
wifi_analyzer caps
show_scan_results
```

Expected: WPS/analyzer idle, no current WPS bulk/secret allocation, no allocation
failures, and status/caps do not start a scan or allocate analyzer bulk storage.
Preserve this legacy `show_scan_results` output for the isolation comparison.

## Known-PIN success on two owned APs

Run separately for both devices:

```text
wps verify <owned-ap-1-bssid> <owned-ap-1-valid-pin>
wps status
secret status
secret reveal
secret reveal

wps verify <owned-ap-2-bssid> <owned-ap-2-valid-pin>
wps status
secret status
secret erase
secret status
```

Acceptance:

- each accepted run emits one `accepted` and exactly one `terminal`;
- terminal operation is successful, cleanup is `restored`, lease is `released`;
- current `bulk_bytes` and `secret_bytes` return to zero, peaks are bounded and
  `allocation_failures` remains zero;
- first reveal displays the expected local values, the second returns
  `secret_reveal/result:"empty"` without a generic console error;
- erase emits no invented acknowledgement and subsequent status is empty;
- `/sdcard/lab/wps/results/` contains only complete authenticated-M7 result
  files; redact secrets before retaining any diagnostic copy.

## Cancellation, failure and quarantine

Start a run and cancel promptly:

```text
wps verify <owned-ap-bssid> <owned-ap-valid-pin>
wps stop
wps status
secret status
```

Expected: `wps stop` is `stopped` or bounded `stop_pending`; the run eventually
has one cancelled terminal, cleanup restores/releases, and the secret is empty.
Repeat with universal `stop`; it must join WPS/analyzer before legacy teardown.

Safely exercise target-not-found/timeout if the lab can do so without changing
scope. Failure must not create a success secret, leak allocations or leave a
false released state. A deliberately induced restoration failure, if available,
must retain owner/generation in `quarantined`, block mutations and allow status
and reboot. Do not induce destructive failure merely to fill this row.

## Contention in both directions

### WPS owns the radio

```text
wps verify <owned-ap-bssid> <owned-ap-valid-pin>
wifi_analyzer status
wifi_analyzer caps
show_scan_results
wifi_analyzer scan --band 2.4 --profile passive --limit 1
wifi_analyzer stop
wps status
wps stop
```

The three reads remain available. Both analyzer mutations are refused before
their handlers with the exact old line and nonzero console result:

```text
[WFACTL1] {"v":1,"type":"error","command":"console","code":"busy","reason":"radio_lease"}
Command returned non-zero error code: 0x1 (ERROR)
```

No analyzer `begin` may follow a refused scan. `wps stop` remains owner-local.

### Analyzer owns the radio

Start a sufficiently long analyzer scan, then issue:

```text
wifi_analyzer scan --band 2.4 --profile passive --limit 64
wps status
secret status
show_scan_results
wps verify <owned-ap-bssid> <owned-ap-valid-pin>
wps stop
wifi_analyzer status
wifi_analyzer stop
```

Status/legacy reads remain available. WPS verify and WPS stop receive the same
busy/nonzero contract and emit no WPS `accepted`. Analyzer stop remains local.

## Post-release handoff and legacy compatibility

After each owner reaches idle:

```text
wifi_analyzer scan --band 2.4 --profile passive --limit 1
wifi_analyzer status
wps verify <owned-ap-bssid> <owned-ap-valid-pin>
show_scan_results
```

Use a short bounded retry if the next mutation races final worker handoff; no AP
reboot should be necessary for a transient busy response. Confirm the analyzer
produces one begin/end transaction, WPS succeeds afterward, and the saved legacy
snapshot/index mapping is unchanged. Also run the usual legacy scan/selection and
the existing Tab5/Flipper parsers; WFA/1 remains `v:1` and WPS remains
`schema_version:1`.

## OTA exclusion

While either owner is active, run the normal manual command appropriate to the
test environment:

```text
ota_check [rf] [latest|<tag>]
```

Acceptance: OTA is refused before its worker/in-progress flag is created. After
the radio returns idle, a new request must pass the same preconditions it did
before this integration. Do not perform an actual update merely to prove the
busy gate.

## MAC and resource acceptance

For each available starting identity (factory, a controlled fixed local-unicast
address, and one random-per-boot local-unicast address), record the active STA MAC
before and after WPS success and cancellation. The bytes must match exactly
within that boot. The production JanOS CLI currently has no `sta_mac` command;
prepare non-factory identities only with an approved test build/procedure.

For every terminal row record:

- WPS `bulk_bytes=0`, `secret_bytes=0`, bounded peaks and zero allocation failures;
- lease released after successful cleanup, retained after quarantine;
- analyzer idle and its PSRAM ownership consistent with `clear`/status;
- no watchdog trigger, panic, core dump, stale callback output or spontaneous
  AP reboot.

Store redacted logs with firmware SHA-256 and board/AP labels. Never commit a
real BSSID, PIN, network key or plaintext result file.
