# JanOS Wi-Fi analyzer smoke test for a later device session

This is a runbook, not a record of tests already performed. The current user
instruction is **no C compilation, firmware build, flash, or serial/hardware
test**. A later agent must keep that constraint unless the user changes it.
The focused Python contract and source-integration suites passed 53 tests on
2026-09-28; that does not
validate the ESP-IDF worker or legacy Flipper devices.

## Preparation after authorization

1. Build JanOS with the selected ESP-IDF installation, then flash the intended
   ESP32-C5. Record the IDF version, commit, build result, board, UART port and
   baud rate. For example, from this project in an initialized IDF shell:

   ```powershell
   idf.py build
   idf.py -p COMx flash monitor
   ```

2. Record complete raw serial output to a file. Keep original line endings and
   log lines so framing and legacy parser behavior can be checked. Identify a
   known 2.4 GHz AP and, if available, a known 5 GHz AP with known width.
3. Run the host reference without a compiler before comparing captured WFA/1
   traffic. It ignores non-WFA lines but reports incomplete or malformed WFA/1
   transactions:

   ```powershell
   python -B -m unittest tests.test_wifi_analyzer_contract tests.test_wifi_analyzer_integration -v
   python -B tools/wifi_analyzer_contract.py path\to\serial-capture.ndjson
   ```

   A capture containing only control/legacy lines has no terminal and returns
   nonzero by design. Use a capture that includes at least one analyzer scan.

## Commands and expected observations

Run commands one at a time. After each terminal `end`, wait at least 100 ms and
confirm `status=idle` before a new scan. `end` is written before the worker
releases ownership, so an immediate retry may briefly return `busy`.
Use the device's actual allowed channels. Explicit channels excluded by the
public country bounds/mask return `unsupported_channel` without `begin`.
For AUTO/zero-mask 5 GHz policy, IDF may silently filter candidates; a successful
empty snapshot is not evidence that every requested channel was visited.

| Command or action | Check |
| --- | --- |
| `wifi_analyzer caps` | `[WFACTL1]` advertises WFA/1, default 64, max 128, 1024-byte lines, `sdk_unverified` width and `requested_driver_filtered` channel scope. No scan starts. |
| `wifi_analyzer status` | `idle`, boot ID, null active scan, and `psram_bytes=0` before the first scan. |
| `wifi_analyzer scan` | One `begin`, 0..64 AP records, one `end`; matching boot/scan, contiguous `seq`, valid counts. No unsolicited second scan. |
| `wifi_analyzer scan --band 2.4 --channels 1,6,11 --profile quick --limit 1` | If all three channels are allowed, the explicit scope appears in `begin`. Otherwise expect `unsupported_channel` without `begin`. If more than one AP is found, `returned=1`, `truncated=true`, and `found` may exceed 255. |
| `wifi_analyzer scan --band 5 --profile passive --limit 128` | A 5 GHz candidate plan only, at most 128 AP records. Publicly known exclusions give a control error; other regulatory filtering remains in the driver. A scan-start failure after `begin` gives a non-success `end`. |
| `wifi_analyzer scan --limit 129` and a duplicate/invalid `--channels` list | `invalid_argument` control error and no `begin`; existing legacy results remain intact. |
| `wifi_analyzer stop` during a scan, then `wifi_analyzer status` | A non-success terminal if transport is usable, followed by idle only after worker cleanup. A quiescence fault must keep radio ownership reserved. |
| Universal `stop` during a scan | It joins analyzer shutdown before legacy radio teardown. No use-after-free, mixed analyzer/legacy scan event, or false success terminal. |
| `wifi_analyzer clear` while idle | `cleared` acknowledgement and released analyzer PSRAM; legacy scan results remain. While active it returns busy. |
| `show_scan_results` during and after analyzer work | The previous legacy snapshot and index mapping are unchanged. |

Also test a successful empty scan, scan-driver failure, retrieval failure, TX
failure, timeout, stop near publication, and a late scan completion when those
conditions can be induced safely. Confirm that a failed or partial transaction
leaves the last successful host snapshot visible with stale/error state. Check
that `found` comes from the 16-bit AP total, not the 8-bit event number.

## Compatibility and measurements

- Capture `scan_networks`, `show_scan_results`, `channel_view`, selection and
  universal `stop` before and after analyzer use. Feed the captures through
  the real parsers in both `../FLIPPER/Lab_C5.c` and
  `../FlipperLight/src/uart_comm.c`, or use those devices directly. Confirm
  legacy CSV fields, one-based printed indices, pacing and completion markers
  for nonempty scans, plus exact channel-view markers. Include quoted SSIDs,
  empty scans and failed scans; preserve the existing empty-scan behavior as
  a regression baseline until changed in its own task.
- Exercise `scan_networks` -> select a legacy index -> analyzer scan -> stop
  -> `show_scan_results` -> legacy action. Analyzer `seq` must never become a
  legacy selection index. While analyzer owns the radio, conflicting commands
  should receive a `[WFACTL1]` busy reply before changing state.
- Start an asynchronous legacy scan and attempt analyzer admission before its
  completion callback drains. Expect `busy` / `legacy_scan_draining`, even if
  legacy timeout or stop clears visible scan flags. If legacy stop force-deletes
  a wardrive task, expect `busy` / `legacy_radio_uncertain` until reboot. A
  failed or timed-out `wifi_connect` has the same reboot requirement; an active
  connection attempt blocks with reason `wifi_connect`.
- Repeat scans and stop/clear cycles while recording internal RAM, PSRAM total
  and largest free block, worker stack high-water mark, scan duration and UART
  transmit duration. Check first-time Wi-Fi initialization leaves the existing
  country policy unchanged and that saved band/channel settings are restored.
- Compare reported 20/40/80/160/80+80 geometry against known AP settings.
  Keep `sdk_unverified` until supported cases are checked on target; null
  geometry is a truthful result. Do not treat primary-channel AP counts as
  measured interference or airtime usage.
