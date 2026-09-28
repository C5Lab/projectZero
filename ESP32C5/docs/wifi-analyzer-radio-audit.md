# Wi-Fi analyzer radio integration audit

Final source-review record, 2026-09-28. Scope: JanOS only, default 64 APs,
maximum 128, lazy PSRAM storage. No compiler, firmware, serial or hardware test
was used for this review. Locate code by symbol; line numbers change as the
monolithic main file evolves.

## Reviewed boundaries

- `janos_console_cmd_dispatch` serializes analyzer command admission. Ordinary
  handlers reserve an in-flight slot and release the mutex while running, so
  a concurrent legacy `stop` is not held behind a long connection/file command.
  The analyzer cannot overtake those handlers before they publish task state.
- `analyzer_host_busy_reason` checks legacy radio tasks, connection attempts,
  transfers, application state and pending legacy scan callbacks. The sole
  legacy asynchronous start increments a separate completion counter; the
  complete callback or failed start decrements it. Clearing legacy public flags
  on timeout does not admit an analyzer scan early.
- Normal blocking wardrive scans retain their task ownership until completion.
  Forced wardrive deletion and an unsuccessful legacy `wifi_connect` latch
  `legacy_radio_uncertain`, requiring reboot before analyzer admission.
  A missing legacy asynchronous completion similarly keeps admission blocked.
  These are conservative availability limits, not automatic recovery claims.
- `wifi_analyzer_on_scan_done` runs before every legacy scan side effect. It
  records only completion metadata under a short critical section. The worker
  alone retrieves/clears driver records, restores radio settings and writes UART.
- Universal `cmd_stop` joins analyzer cleanup before legacy teardown. A missing
  scan completion keeps the worker and buffers quarantined; a late completion
  may release them. Restore/cleanup failure requires reboot.
- The analyzer-owned initializer returns setup errors and rolls back its Wi-Fi
  driver initialization. It avoids both the legacy `ESP_ERROR_CHECK` initializer
  and the SDK convenience netif helper that asserts on allocation failure.
  Successfully created shared infrastructure stays available for retry. Failed
  cleanup latches uncertain radio ownership. The legacy initializer is unchanged.

## SDK and protocol review

The installed ESP-IDF 6.0.2 headers and implementation were read directly.

- The scan event count and scan ID are 8-bit; the worker obtains the full total
  with `esp_wifi_scan_get_ap_num(uint16_t *)`. It retrieves at most the requested
  capacity and checks returned count, channel scope, RSSI and duplicate BSSIDs.
- The bulk retrieval API releases the entire driver list. Error/zero-result
  paths clear any owned list. No list or PSRAM buffer is reused before cleanup.
- AP bandwidth, secondary, VHT centers, PHY flags, auth modes, band-mode APIs,
  channel bitmaps, netif cleanup and recursive static mutex APIs match the local
  SDK declarations. This is not a compiler or linker check.
- The C formatter rejects sequence 128 and invalid primary/band combinations.
  Incomplete or inconsistent width geometry becomes null, including unsupported
  secondary/center combinations. The adapter enforces begin-plan/count rules
  that the standalone formatter cannot know.
- `sdk_unverified` deliberately identifies SDK-derived width metadata awaiting
  target validation. `requested_driver_filtered` identifies candidate channel
  scope, not measured dwell. AUTO/zero-mask 5 GHz regulatory filtering remains
  inside IDF; an explicit requested channel may be silently skipped.
- PSRAM allocations are transactional and bounded, with reserve and transient
  growth checks. No internal-memory fallback exists for the result arrays.
- UART writes lock each entire record, account for baud-dependent publication
  time and prevent idle baud fallback during analyzer ownership. A blocking
  transport write cannot be forcibly preempted; host deadlines remain required.

## Verification and remaining evidence

Independent review found and resolved the preparation-hook ownership collision,
late legacy callback admission, whole-handler mutex delay, connection/forced-stop
uncertainty, and aborting initialization error path. The final targeted review
reported no further actionable defect in the reviewed source.

The focused Python tests exercise wire parsing and static integration guards;
Tree-sitter checks C grammar without compiling. The portable C harness has been
written but not built or run. Neither source review nor these checks proves
FreeRTOS scheduling, radio event timing, SDK metadata fidelity, UART interleaving
with other writers, or Flipper device compatibility. Follow the
[device smoke-test runbook](wifi-analyzer-smoke-test.md) after the user builds.
