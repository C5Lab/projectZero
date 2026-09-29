# OTA: test coverage and RF integration constraints

Date: 2026-09-29. Scope: tests and analysis only. No firmware, binaries,
Flipper application, partition tables or deployment configuration changed.

Verified result: **33 tests: 24 passing, 9 expected failures** under Debian WSL.
Strict mode exposes the same nine gaps as assertion failures. Two mutations of
only the temporary generated source (reversed version gate and bypassed project
validation) were also caught by assertions. No production source was modified
for those checks. A read-only review checked the harness and coverage limits.

## Run the executable tests

From `ESP32C5`, with Python 3 and a host C compiler:

```sh
python3 -m unittest discover -s tests -p 'test_ota_flow.py' -v
```

On the current Windows workstation, Debian WSL has the required compiler:

```powershell
wsl -d Debian -- python3 -m unittest discover -s tests -p test_ota_flow.py -v
```

To expose known defects as ordinary failures (expected exit status 1):

```powershell
wsl -d Debian -- env OTA_STRICT_KNOWN_DEFECTS=1 python3 -m unittest discover -s tests -p test_ota_flow.py -v
```

For native execution, `CC` can specify a compiler executable path. Compiler
flags/wrappers in `CC` are not supported. A missing compiler is an error, not a
silently skipped suite. Temporary generated C and executables are removed.

## What actually executes

`tests/test_ota_flow.py` extracts function definitions directly from the current
`main/main.c`, including their signatures and bodies. `tests/ota_host.c` compiles
them unchanged against a host adapter. OTA decisions are not reimplemented in
Python. The harness intercepts task scheduling, network state, release metadata
lookup, ESP-IDF HTTPS OTA operations, NVS, display/LED operations and restart.

The production code still decides which metadata lookup to call, which URL to
use, whether to start an update, how to validate the descriptor, when to abort,
finish and restart, and how to save/load channels. The fake OTA handle rejects
use after close. Allocation balance and task scheduling are observed.

Each scenario runs in a separate process, except `retry`, which deliberately
performs a failed transfer followed by a successful request in the same process.
Compilation, process execution and decoding happen outside expected-failure
test methods, so infrastructure problems cannot count as known defects.

This is a host behavioral test of JanOS control flow, not a test of actual
ESP-IDF flashing or the published RF binary. Tests use synthetic release metadata
and image descriptors; they never access GitHub, Wi-Fi, serial ports or devices.

## Known defects retained intentionally

Default `unittest.expectedFailure` annotations make these gaps visible while
allowing the rest of the suite to act as a regression gate. An unexpected success
fails the suite, prompting removal of the annotation after a real fix. Strict
mode disables those annotations. A successful default run does **not** mean OTA
is free of defects.

| ID | Expected invariant | Current failure | Tests |
|---|---|---|---:|
| OTA-01 | Accepted `DEV` selects development, including after reboot | Validation is case-insensitive, routing is case-sensitive | 2 |
| OTA-02 | Failed NVS save preserves the active channel | RAM changes before open/set/commit succeeds | 3 |
| OTA-03 | New release must not install an older application image | Release tag is compared; descriptor version is only logged | 1 |
| OTA-04 | Malformed version is rejected | `1.7.xyz` parses as `1.7.0` | 1 |
| OTA-05 | Stable version follows its release candidate | `1.7.6-rc1` and `1.7.6` compare equal | 1 |
| OTA-06 | Overlong tag is rejected | Request silently uses the first 63 bytes | 1 |

OTA-05 is a proposed versioning contract if prerelease versions are used, not
evidence that a current stable release is broken. OTA-03 uses a newer release
with an older descriptor, not a claim about the contents of published releases.

No finding in this host run demonstrates an immediate destructive fault on the
current classic setup that requires overriding the user's tests-only scope.
Variant validation and late-boot health confirmation remain important release
gates before RF rollout. These have not been fixed.

The suite also covers main/dev/latest/explicit-tag selection, no-op version
checks, connection preconditions, NVS persistence/defaults, malformed command
arguments, serial duplicate requests, allocation/task creation failure, a lost
connection before the worker starts, metadata errors, begin/descriptor/transfer/
completion/finish errors, stalled transfer, cleanup/retry and the pending-image
confirmation helper. Explicit tags and development images currently allow
reinstallation/downgrade; tests preserve that existing policy.

## Tests still requiring integration or hardware

These are reproducible test procedures, **not executed automated coverage**.

| ID | Setup and action | Required observation |
|---|---|---|
| H01 | Connect with `wifi_connect ... ota`; DHCP assigns IP 6–10 seconds after association | Record whether the request is resumed once; current source suggests it is lost after the 5-second wait |
| H02 | Start in each OTA slot and install a different valid image | Only inactive app slot changes; boot selects complete image; NVS/data unchanged |
| H03 | Interrupt power during transfer, finalization and first boot | Boot selects a complete image; no unbootable state |
| H04 | New test image fails before, then after the current `ota_mark_valid_if_pending()` call, before `BOARD READY` | Compare rollback behavior; present code confirms health before all initialization completes |
| H05 | Drop network at multiple transfer offsets; reconnect and retry repeatedly | Old app remains bootable; no task/heap/handle accumulation |
| H06 | Concurrent commands during OTA: second check, channel change, `wifi_connect`, `ota_boot`, radio mode change | No concurrent writers or unexpected target change; define and verify busy policy |
| H07 | HTTP fixtures: 403/404/429/500, bad TLS, malformed/truncated/oversized JSON, missing asset, long URL, redirects | Appropriate error; no boot activation; later retry works |
| H08 | Feed incompatible chip, corrupt image, oversized image and truncated body through actual ESP-IDF | Rejection without booting invalid image |
| H09 | Flipper: change channel with arrows but not OK; then start OTA | UI must distinguish uncommitted selection from actual firmware channel |
| H10 | Flipper: save channel successfully/fail NVS; feed status lines bytewise and fragmented | UI reports result and actual channel; current parser does not handle `OTA channel set to:` |
| H11 | Physical RF: run `board_name`, `version`, `ota_info`; capture startup `[BOARD]` | Establish real identity format and partition layout; `<unset>` is not proof of classic hardware |
| H12 | RF update and subsequent update, including unavailable RF source | Source remains RF; no fallback to classic; `secrets` and identification unchanged |

Host metadata lookup is mocked: H07 is not covered just because the suite handles
the error returned from that boundary. The pending-image helper test does not
validate its position in `app_main`. Duplicate requests are exercised serially
while one task is pending, not as a proof of cross-task atomicity. Real NVS
durability after a failed commit and power interruption also requires hardware.

## RF: what can be done with only published binaries

The user confirmed that RF firmware sources are unavailable. The sole required
distribution source is:

- [RF latest directory](https://github.com/elpadrino26/janosrf-web-flasher/tree/main/latest)
- [RF flasher](https://github.com/elpadrino26/janosrf-web-flasher/blob/main/index.html)

At inspection, this repository exposes three binaries and no release manifest
or GitHub Releases. The downloaded app descriptor is `projectZero`, version
`1.7.5`, so these fields alone cannot distinguish classic from RF. String
inspection of the RF app shows `board_name`, an eFuse BLK5 label description,
`[BOARD] name=...`, and the classic `C5Lab/projectZero` OTA endpoint templates.
Strings suggest retained classic OTA configuration but do not prove the active
runtime route. This needs confirmation on a physical RF device.

### Feasible next implementation: external RF updater

1. Read identity while the application still runs, before entering ROM download
   mode. Verify actual RF `board_name` values on a device. A user/device label may
   not be a trustworthy model identifier. Do not classify missing response or
   `<unset>` as classic automatically; an explicit variant selection can be the
   initial fallback when identity is ambiguous.
2. Add a separate RF download/flash profile using the exact supplied repository.
   Keep classic and RF profile selection independent from main/dev channel names.
3. Resolve the repository commit first and download all three files from that
   same commit's `latest/` directory. This prevents mixing assets if `main`
   changes during download. Read/validate image and partition headers before
   writing. Locally computed hashes identify downloads but are not publisher
   authentication without a trusted digest/signature.
4. Use RF USB offsets: bootloader `0x2000`, partition table `0x10000`, app
   `0x20000`; DIO, 80 MHz, 8 MB. Never use the classic table offset `0x8000`.
   Preserve NVS, `secrets` and eFuse; no full-chip erase or new provisioning.
5. Before automating reflash of a device already updated by OTA, inspect its boot
   selection: the supplied RF flasher writes only `ota_0` and preserves otadata.
   If otadata selects `ota_1`, it may restart the older slot. Define and test a
   boot-selection procedure; do not copy that behavior blindly or erase RF data.
6. After reset verify responsive firmware and intended image/version. This is a
   USB update workflow, not wireless OTA, and it does not enable RF functionality
   on classic hardware.

### Wireless OTA constraint

Flipper currently sends OTA commands; ESP32 firmware owns download URL selection.
Changing the classic source tree or Flipper menu cannot rewrite routing inside a
downloaded RF binary. A locally modified updater would itself be replaced by the
RF application after installation.

True persistent RF Wi-Fi OTA therefore needs either an existing, verified RF
command/configuration for a custom OTA URL, or a new RF binary from its producer
that implements the RF source. No such custom-URL interface was established in
this analysis. Do not promise that changing our repository constants solves it,
do not patch opaque RF binaries, and do not fall back to classic images on error.

If the producer adds support, ordinary RF-to-RF OTA downloads only
`latest/projectZero.bin` into the inactive app slot and preserves the RF layout.
Both app slots are `0x3F0000` bytes, at `0x20000` and `0x410000`. RF also has
NVS at `0x11000`, otadata at `0x17000`, PHY at `0x19000`, and `secrets` at
`0x1A000` (size `0x4000`). Bootloader/table migration is not part of this OTA path.
