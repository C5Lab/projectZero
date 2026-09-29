# OTA: test coverage and RF integration constraints

Date: 2026-09-29. Scope: JanOS OTA hardening and explicit, one-shot RF release
selection on `development`. Automatic hardware identification and Tab5 remain
separate work. No partition migration is implemented.

Latest verification: **76 tests pass, no expected failures** — 49 flow, 7 startup,
11 metadata and 9 HTTP tests. Both review findings (GitHub redirects and accepting
a matching truncated bootloader prefix) were reproduced by failing tests and
fixed. Final ESP32-C5 application build succeeds with ESP-IDF v6.0.2; image size
`0x248fb0` fits the `0x3f0000` app slot (42% free). Hardware OTA was not executed.

First hardening checkpoint: **47 tests passed, no expected failures**, under Debian
WSL (40 flow tests and 7 startup tests). The original baseline had 33 tests,
including 9 expected failures. Those nine assertions are now ordinary regression
tests. New tests were first run against the unfixed behavior and failed.

The application also builds with local ESP-IDF **v6.0.2**, target **esp32c5**
(`idf.py app`). The image fits its OTA slot. No device was flashed and no release
or tracked distribution binary was updated. RF hardware and rollback acceptance
are still pending.

## Run the executable tests

From `ESP32C5`, with Python 3 and a host C compiler:

```sh
python3 -B -m unittest discover -s tests -p 'test_ota*.py' -v
```

On the current Windows workstation, Debian WSL has the required compiler:

```powershell
wsl -d Debian -- python3 -B -m unittest discover -s tests -p 'test_ota*.py' -v
```

The former `OTA_STRICT_KNOWN_DEFECTS` switch is no longer needed; all assertions
run normally.

For native execution, `CC` can specify a compiler executable path. Compiler
flags/wrappers in `CC` are not supported. A missing compiler is an error, not a
silently skipped suite. Temporary generated C and executables are removed.
The metadata suite also requires the project's managed cJSON dependency at
`managed_components/espressif__cjson/cJSON` (populated by ESP-IDF configuration/build).

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
Compilation and scenario execution failures are reported as infrastructure errors.

`tests/test_ota_boot.py` and `tests/ota_boot_host.c` execute selected production
startup statements plus the real confirmation helper and `ota_boot` command.
They check confirmation ordering relative to UART, command registration, REPL
and GPIO, failure before readiness, failed image confirmation, legacy missing
OTA state, and slot-change rejection before readiness. SD initialization is a
failing hardware substitute and occurs after confirmation. This is a scoped
startup integration test, not execution of the whole `app_main` or peripherals.

`tests/test_ota_metadata.py` compiles the actual release/list functions with the
project's real cJSON parser; only HTTP and Wi-Fi are substituted. It checks both
repository URLs, app selection among assets, malformed/missing metadata,
overlong outputs, exact tags, drafts, foreign RF download URLs, and HTTP failure
without fallback. `tests/test_ota_http.py` exercises the actual HTTP downloader
against transport substitutes, including redirects and incomplete bodies.

RF flow tests execute partition checks against simulated partition records and
compile the guard for both table offsets (`0x8000`, `0x10000`). They verify
same-version explicit RF install, latest gating, classic dev isolation, failure
cleanup, unchanged default source, and read-only support-image comparisons.
The installed bootloader verifier is an ESP-IDF boundary substitute: these tests
prove the code requires its success and full image length; they do not validate
physical flash contents or re-test IDF's image checksum implementation.

This is a host behavioral test of JanOS control flow, not a test of actual
ESP-IDF flashing or the published RF binary. Tests use synthetic release metadata
and image descriptors; they never access GitHub, Wi-Fi, serial ports or devices.

## Fixed defects and version policy

These previously failing invariants now pass. This does not establish that the
entire OTA system is defect-free or that published RF firmware contains the fixes.

| ID | Expected invariant | Implemented correction | Original tests |
|---|---|---|---:|
| OTA-01 | Accepted `DEV` selects development, including after reboot | Canonical lowercase at save and load | 2 |
| OTA-02 | Failed NVS save preserves the active channel | RAM changes only after successful commit | 3 |
| OTA-03 | Release version must match application image | Descriptor checked before perform/finish; mismatch aborts | 1 |
| OTA-04 | Malformed version is rejected | Complete three-component SemVer parser with overflow checks | 1 |
| OTA-05 | Stable version follows its release candidate | Numeric/lexical prerelease precedence | 1 |
| OTA-06 | Overlong tag is rejected | Reject before allocating/scheduling a task | 1 |

Version policy follows [SemVer 2.0](https://semver.org/): three nonnegative
components (bounded by `INT_MAX`), optional prerelease/build identifiers, no
whitespace or partial numeric parsing. One leading `v` or `V` is also accepted.
Build metadata does not change ordering. Release-to-image equality is stricter:
after removing that prefix the entire version must match, including build
metadata. Explicit tags still permit reinstall/downgrade if the image matches;
classic `dev` bypasses release-version checks. Automatic release comparison uses
the running app descriptor, not the separately maintained C macro.

Additional tests cover a mismatched newer image, explicit-tag mismatch, legacy
uppercase NVS, channel snapshot at request acceptance, malformed descriptor
strings, and rejection of OTA until core startup/confirmation completes.

Pending images are now confirmed after successful core initialization, before
optional SD setup. Mark/state errors leave updates and slot changes blocked;
diagnostic commands remain available. Missing metadata (`ESP_ERR_NOT_FOUND`) or
an undefined legacy state can become ready without claiming a pending-image
confirmation. No boot deadline or automatic reset was added: a hang still needs
a reset before the bootloader can attempt rollback. Actual fallback availability
must be established on the test device. See [ESP-IDF rollback documentation](https://docs.espressif.com/projects/esp-idf/en/v6.0.2/esp32c5/api-reference/system/ota.html).

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
| H04 | New test image fails during required startup, then separately after confirmation | Before confirmation a reset should roll back when a valid fallback exists; optional SD failure must not prevent confirmation |
| H05 | Drop network at multiple transfer offsets; reconnect and retry repeatedly | Old app remains bootable; no task/heap/handle accumulation |
| H06 | Concurrent commands during OTA: second check, channel change, `wifi_connect`, `ota_boot`, radio mode change | No concurrent writers or unexpected target change; define and verify busy policy |
| H07 | HTTP fixtures: 403/404/429/500, bad TLS, malformed/truncated/oversized JSON, missing asset, long URL, redirects | Appropriate error; no boot activation; later retry works |
| H08 | Feed incompatible chip, corrupt image, oversized image and truncated body through actual ESP-IDF | Rejection without booting invalid image |
| H09 | Flipper: change channel with arrows but not OK; then start OTA | UI must distinguish uncommitted selection from actual firmware channel |
| H10 | Flipper: save channel successfully/fail NVS; feed status lines bytewise and fragmented | UI reports result and actual channel; current parser does not handle `OTA channel set to:` |
| H11 | Physical RF: run `board_name`, `version`, `ota_info`; capture startup `[BOARD]` | Establish real identity format and partition layout; `<unset>` is not proof of classic hardware |
| H12 | RF update and subsequent update, including unavailable RF source | Source remains RF; no fallback to classic; `secrets` and identification unchanged |

The flow suite mocks metadata lookup; the separate metadata and HTTP suites
execute those production layers with synthetic inputs. H07 still requires real
TLS/server integration. The startup slice checks specific startup
boundaries, not every statement in `app_main`. Duplicate requests are exercised serially
while one task is pending, not as a proof of cross-task atomicity. Real NVS
durability after a failed commit and power interruption also requires hardware.

## RF: what can be done with only published binaries

### Implemented manual commands

This is a manual operation for a **known physical RF board**. Selecting `rf`
does not prove board identity and does not enable RF hardware on a classic board.

```text
ota_info
wifi_connect "YOUR_SSID" "YOUR_PASSWORD"
ota_list rf
ota_check rf 1.7.5
```

Wait for an IP before listing/installing. The first three commands do not install
an image. The final command is an explicit installation request; it permits
reinstallation/downgrade, but still requires the downloaded descriptor to match
the requested release. `ota_check rf` and `ota_check rf latest` instead require
a newer release. `ota_check rf dev` is rejected. Existing commands without `rf`
keep their classic behavior and configured main/dev channel.

RF selects `elpadrino26/janosrf-web-flasher` for that operation only; no source
is saved in NVS. Errors never retry against the classic repository. RF metadata
must point to that exact repository, resolved release tag, and `projectZero.bin`.
The per-request source and channel cannot change after a task is queued.

Before scheduling RF OTA, the firmware requires a table at `0x10000` and the
RF NVS/otadata/PHY/secrets/app layout, flags and internal flash ownership.
Before writing an app, it also downloads the selected release's
`partition-table.bin` and `bootloader.bin` and compares them to installed bytes.
The table must be exactly 3072 bytes. IDF must first verify the installed
bootloader and report its full image length; the download must have that exact
length. Matching truncated prefixes are rejected. Support images are read only;
only the inactive application slot is written. A differing but potentially
compatible bootloader is conservatively rejected too.

**The standard local build uses `0x8000`, so RF installation is deliberately
blocked on that build.** `ota_info` reports this; `ota_list rf` still works.
This change supplies no RF-layout bridge build and cannot convert a classic
layout over OTA. Restoring the RF layout needs the producer's USB workflow,
with the device's provisioning/data preserved. Do not bypass the check by
merely changing a constant in the existing binary.

After installing published RF firmware, it replaces this local updater. These
commands and hardening fixes do not magically persist in RF 1.7.5; ongoing
RF OTA still requires producer support or a verified existing RF configuration.

### Agreed delivery split: JanOS and Tab5

The user explicitly requires two implementation stages. Tab5 also has an OTA
workflow and must be included. Its confirmed local checkout is
`C:/Users/mati/Documents/GitHub/M5MonsterC5-Tab5`. Inspection of its
`main/main.c` Monster OTA block confirms it sends commands and monitors logs;
the C5 owns Wi-Fi, release selection, download and flash. Tab5 already tracks
RF version and Sub-GHz capability, which do not alone establish a trusted OTA
variant. The discussion plan is [ota-rf-implementation-plan.md](ota-rf-implementation-plan.md).

Before either stage, define the shared device-identification contract: explicit
classic/RF/unknown variant, running firmware version and supported update
capabilities. These are proposed semantics, not an already implemented protocol.
Do not infer model from `projectZero`, version `1.7.5`, absence of a command,
timeout or an unset/user-defined board label. Determine compatibility behavior
for older firmware from actual responses. Unknown identity must not silently
select classic firmware. Re-query identity after reconnect/device replacement
and after update so a previous board's profile is not reused.

1. **JanOS firmware stage:** implement and test the shared OTA corrections,
   reliable identity reporting and variant-specific release profiles. Define
   version, downgrade and unsupported-channel behavior. Preserve the RF build
   dependency described below: changes must exist in the RF firmware to persist
   across RF updates.
2. **Tab5 stage:** consume the shared identity, display the detected model and
   actual firmware version, and bind the update to the correct connection.
   Continue delegating download/flash to the board; use its supported OTA
   commands and report the actual selected source/status, including verification
   after the board restarts.
   Prevent an unknown or mismatched device from receiving an automatic update.

Tab5 tests must cover classic/RF/unknown/legacy responses, fragmented UART
messages and timeouts, device replacement without restarting Tab5, reconnect,
the correct release source, no RF-to-classic fallback, unsupported channels,
transfer errors and post-update re-identification. Final integration acceptance
is two successive RF updates through Tab5 with the RF source retained, plus a
classic regression update. No Tab5 production changes are authorized by this
planning note; this records the required scope for later implementation.

The user confirmed that RF firmware sources are unavailable. Distribution stays
in the supplied RF repository, which now also publishes GitHub Releases:

- [RF release 1.7.5](https://github.com/elpadrino26/janosrf-web-flasher/releases/tag/1.7.5)
- [RF latest directory](https://github.com/elpadrino26/janosrf-web-flasher/tree/main/latest)
- [RF flasher](https://github.com/elpadrino26/janosrf-web-flasher/blob/main/index.html)

Initially only `latest/` binaries were available. On 2026-09-29, release `1.7.5`
was verified through both the tag endpoint and `/releases/latest`: not a draft,
not a prerelease, with assets `bootloader.bin`, `partition-table.bin` and
`projectZero.bin`. The downloaded release app is 2,685,040 bytes, has descriptor
project `projectZero` and version `1.7.5`, and SHA-256
`9b64690fa751cce0d4feb5ac9d27f50a3be8e0ea6b5a4e83362e6964fd809df7`, matching
GitHub's asset digest and the previously inspected `latest/` app.

GitHub Releases now supplies the version and download URL required by the
existing metadata parser; a separate release-info manifest is not required for
version discovery. Select owner `elpadrino26`, repository `janosrf-web-flasher`
and asset `projectZero.bin` for the manual RF release profile. Automatic hardware
variant selection and an image-embedded variant identifier still need implementation. These descriptor fields alone
cannot distinguish classic from RF. String
inspection of the RF app shows `board_name`, an eFuse BLK5 label description,
`[BOARD] name=...`, and the classic `C5Lab/projectZero` OTA endpoint templates.
Strings suggest retained classic OTA configuration but do not prove the active
runtime route. This needs confirmation on a physical RF device.

### Alternative USB updater (outside the accepted two-stage OTA scope)

1. Read identity while the application still runs, before entering ROM download
   mode. Verify actual RF `board_name` values on a device. A user/device label may
   not be a trustworthy model identifier. Do not classify missing response or
   `<unset>` as classic automatically; an explicit variant selection can be the
   initial fallback when identity is ambiguous.
2. Add a separate RF download/flash profile using the exact supplied repository.
   Keep classic and RF profile selection independent from main/dev channel names.
3. Resolve a release once, then download all three assets from that same release
   and verify their recorded sizes and SHA-256 digests. If explicitly using
   `latest/`, resolve one repository commit and use it for all three files.
   Read/validate image and partition headers before writing. A digest obtained
   from GitHub checks the asset against that metadata; it is not an independent
   publisher signature.
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

Flipper and Tab5 send OTA commands; ESP32 firmware owns download URL selection.
Changing the classic source tree or controller menu cannot rewrite routing inside a
downloaded RF binary. A locally modified updater would itself be replaced by the
RF application after installation.

True persistent RF Wi-Fi OTA therefore needs either an existing, verified RF
command/configuration for a custom OTA URL, or a new RF binary from its producer
that implements the RF source. No such custom-URL interface was established in
this analysis. Do not promise that changing our repository constants solves it,
do not patch opaque RF binaries, and do not fall back to classic images on error.

If the producer adds support, ordinary RF-to-RF OTA downloads only the selected
release's `projectZero.bin` into the inactive app slot and preserves the RF layout.
Both app slots are `0x3F0000` bytes, at `0x20000` and `0x410000`. RF also has
NVS at `0x11000`, otadata at `0x17000`, PHY at `0x19000`, and `secrets` at
`0x1A000` (size `0x4000`). Bootloader/table migration is not part of this OTA path.
