# JanOS radio compatibility validation

This runbook validates the integrated legacy/analyzer/WPS radio coordinator,
the hardened D-UCB handshaker and the complete production WPS CLI. Use only
explicitly owned laboratory access points. Replace placeholders locally and do
not paste PINs, network keys or plaintext result files into repository logs.

## Evidence boundary

Keep four layers separate:

| Layer | What constitutes evidence | Current state |
| --- | --- | --- |
| source/contracts | exact command, wire, admission, ownership and provenance checks | verified by focused fixtures and final compatibility replay |
| host execution | ordinary plus ASan/UBSan fixtures and full discovery | PASS: 327/327 final host tests; focused ASan/UBSan suites pass |
| firmware build | supported ESP-IDF 6.0.0/6.0.1 root images, size, partition headroom and SHA-256 | PASS: exact 6.0.0 and local 6.0.1 builds, details below |
| device | target logs for restore, contention, D-UCB, WPS/Pixie/JWPS, storage and ADV Tab5 replay | pending operator execution |

Final host/build evidence (2026-10-18): full discovery passed 327/327.
The root JanOS project built with ESP-IDF v6.0.0 at commit
`662a3be354759d9487bf4b1a629fadb766cb1800`. The generated
`build-task6-idf600/projectZero.bin` is 2,355,200 bytes (`0x23f000`);
the smallest app partition is 4,128,768 bytes (`0x3f0000`), leaving
1,773,568 bytes (`0x1b1000`, 42.96%; IDF reports 43%). The final verification
rebuild has SHA-256
`E420B16C7AC6A417FD6E0E70E85A78FAE7F52CCA565E3AE7C171B297A8C4A492`.
ESP-IDF embeds build-time metadata in the application descriptor, so a separate
clean relink can retain the same size while changing the digest. Always record
the SHA-256 of the exact artifact flashed for target validation.
This is host/build evidence only; the device matrix remains pending.

Compatibility build evidence (2026-10-18): the same tree also built to
completion with local ESP-IDF v6.0.1 (`8c19b156084a0753687347cca1f5355782893533`).
`build/projectZero.bin` is 2,369,664 bytes (`0x242880`), with 43% of the
smallest app partition free, and SHA-256
`D186E0E09DE7F012AC72DF10F9FCDDF09020D4986D17334B09A4CF84DAC2DD72`.
The private WPS adapter compile guard accepts only 6.0.0 and 6.0.1.

Historical 2026-10-16 evidence used an older source tree and ESP-IDF 6.0.2:
275 host tests passed; `build-janos-wps/projectZero.bin` was 2,472,016 bytes
with reported 40% app-partition headroom and SHA-256
`C2E7D177124604A0709BD64B86F6F589FD080229374B627CD263CE7AC9E2B808`.
That dated result remains useful history but is **not** acceptance evidence for
the current hardening image.

## Host and build gates

From the repository root, run the complete Python discovery in the supported
host environment, then the focused sanitizer launchers for Tasks 1-5. Record
the commands, exact count, skips and failures rather than copying old numbers.
ThreadSanitizer currently compiles but cannot execute in the available WSL
runtime (`FATAL: ThreadSanitizer: unexpected memory mapping`); record this as an
environment limitation, not as a pass.

At minimum include these behavior groups:

- immediate WPS worker success/failure/cancel/quarantine/NULL/start rejection;
- legacy/WPS races in both orders, channel commands, analyzer pre-unlock/global
  stop, analyzer clear, OTA self-token and stale generations;
- FLASH and RAM idle-STA snapshot/restore, every fault/readback/retry path,
  cold host preparation and stopped/AP/APSTA rejection without mutation;
- D-UCB RX at all burst delays, FIFO reuse, stale generation, allocation/setup
  retry, immutable target snapshots, slow/failing SD and stop during TX/write;
- WPS parser/goldens, spaced SSID, deterministic plan, bounded campaign,
  Pixie retries/cancellation, vault TTL/reveal-once/erase, persistence commit
  gate and memory stress;
- legacy console fixtures, analyzer WFA/1, ADV Tab5 compatibility,
  source-ownership and license/provenance checks.

Also run a relative-link check across current Markdown, then:

```powershell
git diff --check
docker run --rm -v "${PWD}:/project" -w /project `
  -e IDF_PY_FLAGS=--preview espressif/idf:release-v6.0 `
  bash -lc "set -e; git -C /opt/esp/idf checkout --detach 662a3be354759d9487bf4b1a629fadb766cb1800; git -C /opt/esp/idf submodule update --init --recursive; idf.py -B build-task6-idf600 build"
Get-Item build-task6-idf600/projectZero.bin | Select-Object Length,FullName
Get-FileHash build-task6-idf600/projectZero.bin -Algorithm SHA256
```

The registry has no `espressif/idf:v6.0.0` manifest, so the command pins the
signed v6.0 source tag inside the disposable `release-v6.0` container. The
output directory name does not make this a standalone WPS image: this command
builds the root JanOS project. Record the linked app size, smallest app
partition, remaining headroom, BIN/ELF paths and SHA-256. Do not flash as part
of this gate. A successful link is not device evidence.

## Device baseline and exact restore

After boot, save the full banner and run:

```text
wps status
secret status
wifi_analyzer status
wifi_analyzer caps
show_scan_results
```

Expected: WPS/analyzer idle, no live WPS bulk/secret allocation, no allocation
failure, and status/caps do not start work or allocate analyzer bulk storage.
Save the active Wi-Fi storage policy, mode, complete STA config, primary and
secondary channel and STA MAC with an approved diagnostic build/procedure.

For WPS success, timeout and cancellation, compare every field after terminal
cleanup. Acceptance requires exact equality and `cleanup_result:"restored"`.
Separately exercise stopped STA, AP and APSTA baselines: they must be rejected
before mutation. A deliberately injected restore mismatch must retain the WPS
owner in quarantine; do not induce a destructive hardware failure merely to
fill that row.

## Known-PIN, Pixie and JWPS

On both owned validated APs:

```text
wps verify <owned-bssid> <valid-8-digit-pin>
wps status
secret status
secret reveal
secret reveal

wps pixie <owned-bssid>
secret status
secret reveal
secret erase
secret status
```

Each accepted radio run must emit one `accepted` and exactly one unchanged
schema-v1 `terminal`. Success requires authenticated M7, restored cleanup,
released lease, zero live bulk/secret bytes and bounded peaks. First reveal
returns the expected local value; second reveal returns
`secret_reveal/result:"empty"` without a generic console error. `secret erase`
has no acknowledgement and is confirmed with status.

Exercise offline planning with an empty SSID, a quoted spaced SSID and trailing
word reconstruction:

```text
jwps plan <owned-bssid>
jwps plan <owned-bssid> "Lab AP With Spaces"
jwps plan <owned-bssid> Lab AP With Spaces
```

The two spaced forms must produce the same deterministic deduplicated order.
Campaign counts `0` and `4` must reject before `accepted`. Run an authorized
count `1..3`, stop during candidate/retry, and verify `resume_index`: only an
explicit PIN rejection advances it; timeout, disconnect and setup lock retain
the candidate.

Also exercise early failures which occur before the transport borrows the
radio: malformed BSSID/PIN, Pixie epoch below/above the documented range and a
campaign with missing SD/database. These runs must not leave the WPS lease
quarantined. A subsequent analyzer scan or known-PIN run must start without a
board/AP reboot.

Run `selftest db`, `selftest fragment` and `selftest pixie` without disturbing
the current radio owner. Run `selftest transport` only when WPS can acquire the
radio, and require exact restore.

## Storage and vault matrix

An authenticated-M7 result may create only:

```text
/sdcard/lab/wps/results/wps_<normalized-bssid>.json
```

No capture-only, no-match, timeout, rejected/partial candidate or cancellation
may create a success file. A persistence attempt emits additive `wps_storage`
immediately before the unchanged terminal; protocol, cleanup and storage
results are independent. Test successful replacement, an existing-file
preserving cancellation before the commit gate, and missing/read-only/full SD.
With missing media, authenticated protocol success remains success while
`wps_storage` reports the storage failure and the vault remains usable.

Confirm the five-minute TTL, reveal-once behavior and second reveal `empty`.
Confirm explicit erase never cancels an active operation; a later successful
run may publish a new value. Inspect `unknown_devices.jsonl` only with redacted
metadata and verify it contains no PIN/candidate/key/session material.

## Contention and startup races

Run each pair in both orders with deterministic timing where the test build
allows it:

- BOOT-button portal or another legacy startup versus `wps verify`;
- analyzer scan announcement/preparation versus WPS;
- `test_radio_channel(s)` versus WPS;
- manual OTA versus analyzer/WPS;
- global stop during announced analyzer startup.

Exactly one mutation owns the generation. A loser receives the established
busy/nonzero contract and does not start a worker. Status/read commands remain
available. Analyzer and WPS owner-specific stops are admitted but affect only
their own subsystem. After cleanup, the opposite owner must start without AP
reboot.

The frozen dispatcher refusal remains:

```text
[WFACTL1] {"v":1,"type":"error","command":"console","code":"busy","reason":"radio_lease"}
Command returned non-zero error code: 0x1 (ERROR)
```

## D-UCB and legacy handshaker

In an isolated authorized RF environment validate:

1. active-client reconnect/EAPOL reception while all deauth burst delays run;
2. up to three eligible targets during one D-UCB dwell;
3. two clients on one AP and two APs with interleaved EAPOL;
4. FIFO churn during delayed SD writes and stale-generation rejection;
5. SD removal/full media/delayed `fsync`, then successful retry;
6. stop during TX, observation, write and publication, followed by second stop;
7. bounded diagnostic-PCAP allocation/limit rotation recovery;
8. a multi-hour scan-all soak with final `[HS-DUCB]`, `[HS-PCAP]`, `[HS-TX]`,
   heap and PSRAM telemetry.

A success is valid only when the target-bound HCCAPX and target-only PCAP both
commit. Confirm `.pcap.part` is not treated as complete. Preserve the existing
`HANDSHAKE IS COMPLETE AND VALID` and
`Complete 4-way handshake saved for SSID:` lines for ADV Tab5/CardputerADV/
FlipperLight replay.

## Compatibility replay and acceptance record

Replay old `[WFA1]`, `[WFACTL1]`, WPS `accepted`, `wps_status`, `terminal`,
`wps_stop`, `secret_status` and empty `secret_reveal` fixtures through ADV
Tab5. Existing records/fields must parse unchanged; unknown additive
`wps_stage`, `wps_campaign`, `wps_storage`, `[HS-DUCB]` and `[HS-STOP]`
output may be ignored.

## Remaining target acceptance checklist

Run these rows on the exact final supported ESP-IDF image. Record the firmware
SHA-256, cold/warm boot state, owned AP label and redacted UART for every row.

| Area | Target exercise | Pass evidence |
| --- | --- | --- |
| Baseline | Cold boot, warm reboot, SD inserted/absent | WPS/analyzer idle, zero live WPS allocations, expected PSRAM and no retained lease |
| Known PIN | Correct PIN, wrong PIN, absent AP and AP setup lock | One accepted/terminal pair; only authenticated M7 exposes a secret; exact restore/release |
| Pixie | Vulnerable AP, nonmatching AP, epoch bounds, stop in capture/search/retry | Ordered stage records; no vault/result for partial/no-match/cancel; exact terminal result |
| Campaign | Counts 1 and 3; reject, timeout, disconnect, lock and cancellation | Bounded attempts and restart position; only explicit PIN rejection advances the index |
| Restore | Idle STA with RAM/FLASH storage; stopped STA/AP/APSTA refusal | Complete before/after config equality or deliberate retained quarantine on mismatch |
| Contention | WPS/analyzer/legacy/button/OTA in both start orders | Exactly one owner; loser uses established busy contract; opposite owner starts after cleanup |
| Storage | Replace success; missing/full/read-only SD; injected write/sync/close/rename faults | Existing final preserved before commit; storage result independent; residual `.tmp/.bak` inventory inspected locally |
| Vault | Reveal twice, TTL expiry, explicit erase during an active run | One-shot/expiry semantics and zero live secret bytes after consumption |
| D-UCB | Interleaved AP/clients, slow SD, stop phases and multi-hour soak | Target-bound HCCAPX/PCAP, no completed `.part`, bounded memory and final HS telemetry |
| Country RU | `wifi_country set RU`, reboot/status, valid and rejected channel probes, reset | Configured/active `RU`, manual policy and IDF readback; no claim that RU bypasses C5 DFS/SoftAP limits |
| Client replay | Historical ADV Tab5/CardputerADV/FlipperLight fixtures | Existing records parse unchanged and additive records are ignored safely |

For the RU row, ESP-IDF 6.0.0 defines channels 1-13, 36-64 and 132-165 for
that profile; 100-128 are not part of the RU table. Country selection never
overrides the ESP32-C5 hardware/driver restriction on independently operating a
SoftAP on DFS channels.

For every device row record firmware BIN SHA-256, board/AP labels and redacted
UART. Record live/peak memory, allocation failures, owner/generation, cleanup,
storage outcome and post-run analyzer state. Do not mark the final image PASS
until host, build and the applicable target rows all have fresh evidence.

Related contracts: [WPS workflows](janos-wps.md),
[shared radio ownership](janos-radio-lease.md),
[command manual](command-manual.md), and
[Wi-Fi country/handshake compatibility](wifi-country-ph-dfs-fix.md).
