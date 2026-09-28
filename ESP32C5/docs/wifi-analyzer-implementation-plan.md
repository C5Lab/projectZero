# JanOS Wi-Fi Analyzer Implementation Plan

**Goal:** Implement the documented opt-in analyzer in JanOS while preserving Flipper's legacy protocol.
**Spec:** [Design](wifi-analyzer-design.md), [protocol](wifi-analyzer-protocol.md).
**Architecture:** A portable allocation-free core handles scan arguments and JSON-line output. An ESP-IDF adapter owns lazy PSRAM buffers and asynchronous scans. The existing console dispatcher serializes command admission; an early scan-event hook isolates results from legacy state.
**Tech stack:** C, ESP-IDF 6.0.2, FreeRTOS, PSRAM; Python-only verification in this session.

## Binding updates and constraints

- User approved implementation in the existing development checkout; preserve prior design work and all unrelated files.
- Default 64 AP, maximum 128, buffer capacities match the selected limit. Preserve old MAX_AP_CNT and CSV output/pacing.
- JanOS is implemented in this checkout; the user's clarified scope also includes
  the sibling Tab5 application, implemented in parallel under its own
  `docs/wifi-analyzer-plan.md`. Do not modify Flipper. Retain the Tab5 prompt as
  a protocol/handoff reference, not as a substitute for the host implementation.
- No firmware or host C compilation, flashing, or hardware I/O. Run Python tests and source parsing; document the limits. Provide portable C tests for the user's later build workflow where feasible.
- English code comments and documentation. No commits or pushes are needed for this local handoff.

## Tasks and interfaces

- [x] Portable core: implemented the API in `main/wifi_analyzer_core.h/.c`, portable C harness, strict bounded serializers and 64/128 limits. Python reference and synthetic fixtures updated. C harness execution remains deferred under the no-compilation instruction.
- [x] ESP-IDF adapter: lazy transactional PSRAM arrays, asynchronous scan lifecycle, driver record validation, cooperative cancellation, quarantine, radio restoration, control/status replies and bounded line publication.
- [x] Integration: narrow console admission mutex and in-flight legacy handlers, first-branch event interception, legacy callback drain tracking, uncertain-radio exclusion, fallible analyzer-only initialization, early universal stop, UART baud activity protection and CMake sources. Legacy presentation bodies remain byte-for-byte equivalent after newline normalization.
- [x] Verification and handoff: independent source reviews, focused Python suites, C grammar parsing without compilation, English protocol/design/smoke documentation and final Tab5 prompt. Firmware compilation, portable C test execution and hardware validation are explicitly deferred to the user's next session.

## Progress and design rulings

- Baseline: existing Python reference contract had 38 passing tests; only design/docs/reference artifacts were changed before implementation.
- Ruling: perform implementation in place on `development`, because the user will compile this exact checkout on return and the design files are already here.
- Ruling: automatic refresh stays host-driven (one-shot scan plus stop/status/caps/clear); avoids abandoned continuous UART streams.
- Ruling: report the requested driver-filtered channel scope honestly when the public country API does not enumerate 5 GHz legal channels. Never change country settings to expand the scan.
- Ruling: do not claim compiler-free Python tests execute the ESP-IDF radio lifecycle. Keep that verification limitation explicit.
- JanOS verification scope: 54 Python tests (39 protocol + 15 static integration guards), fixture 1 snapshot / 2 terminals / 0 errors, and 21 C files/function-body fragments parsed without syntax diagnostics. No Flipper application file was edited. Tab5 implementation and its separate verification are documented in the sibling checkout.
- Host integration follow-up: status reports `active_scan=null` if preparation quarantines the radio before the first scan ID is allocated, preserving the WFA/1 identity range.
