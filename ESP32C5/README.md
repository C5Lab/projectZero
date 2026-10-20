# Project Zero

## Overview
Project Zero is an ESP32-C5 firmware that bundles Wi-Fi assessment tooling, console-driven attacks, and peripherals such as the onboard NeoPixel, SD card storage, and GPS interface.

The firmware boots into an `esp_console` REPL, so most capabilities are exposed as CLI commands (`start_blackout`, `start_sniffer_dog`, `start_portal`, and more). Refer to the serial console banner for the full list after flashing.

Documentation:

- [Command Manual](docs/command-manual.md) — complete CLI catalog, including a
  [quick reference for the new WPS/radio commands](docs/command-manual.md#new-cli-commands-in-the-wpsradio-update).
- [Passive sniffer extension](docs/sniffer-extended-uart.md) — opt-in UART metadata, binary SSIDs, RSN/WPA/PMF, WPS, fixtures and manual tests; legacy result lines remain compatible.
- [JanOS Capture Gateway](docs/janos-capture-gateway.md) — instrumented APSTA/NAPT gateway for authorized traffic analysis.
- [Wi-Fi Analyzer](docs/wifi-analyzer-design.md) — opt-in PSRAM-backed AP survey, 64 records by default and up to 128, with isolated legacy Flipper results. See the [WFA/1 protocol](docs/wifi-analyzer-protocol.md), [smoke-test commands](docs/wifi-analyzer-smoke-test.md), and [device evidence](docs/wifi-analyzer-device-validation.md).
- [JanOS WPS laboratory workflows](docs/janos-wps.md) — known-PIN,
  PixieDust, bounded JWPS campaign and self-test commands, asynchronous
  schema-v1 results, volatile one-shot secrets and authenticated-M7 SD export.
- [RF database tooling](tools/rfdb/README.md) — reproducible generation of the
  vendor/OUI and laboratory JWPS databases, including provenance and source
  release bundles.
- [Shared radio ownership](docs/janos-radio-lease.md) — atomic
  `LEGACY`/`ANALYZER`/`WPS` admission, stable busy contract, cancellation,
  quarantine, OTA exclusion and exact idle-STA restoration. The
  [validation runbook](docs/janos-radio-compatibility-validation.md) separates
  host, build and device evidence.
- [Wi-Fi country `PA` and handshake compatibility](docs/wifi-country-ph-dfs-fix.md)
  — persistent country policy, driver read-back and the single APSTA/AP raw-TX
  handshake path.

## Generated RF database artifacts

The RF database generators write their local outputs to `out/`:

- `out/vendors.bin` is the compact vendor/OUI database copied to
  `/sdcard/lab/vendors.bin`;
- `out/wps_pin.bin` is the compact JWPS laboratory candidate database copied to
  `/sdcard/lab/wps_pin.bin`;
- the matching `*.report.json` files record source revisions, hashes, format
  versions, and generation statistics;
- `rfdb-source-*.tar` archives contain the corresponding verified inputs,
  generators, license texts, notices, and manifest required for source-complete
  distribution.

These are generated artifacts rather than firmware source files. When a
`vendors.bin` or `wps_pin.bin` is distributed, the matching source archive must
be distributed through the same release channel. See
[RF database tooling](tools/rfdb/README.md) for build commands and
[third-party notices](THIRD_PARTY_NOTICES.md) for licenses and provenance.
Production JanOS consumes these databases through its component-owned offline
JWPS planner and bounded online campaign. The removed standalone WPS mini-OS
is not a production dependency.

## Build Note: exFAT
This repo auto-patches your local ESP-IDF `ffconf.h` during CMake configure to force:
- `FF_FS_EXFAT = 1`

Path patched on each machine:
- `$IDF_PATH/components/fatfs/src/ffconf.h`

Disable this behavior if needed:
- `-DPROJECTZERO_PATCH_IDF_EXFAT=OFF`

## Build Note: `PA` Wi-Fi regulatory table
During CMake configure, this repo updates the `country PA` stanza in the
selected ESP-IDF 6.0.0 or 6.0.1 checkout at
`$IDF_PATH/components/esp_wifi/regulatory/esp_wifi_regulatory.txt`. It changes
`5470 - 5725` to `5470 - 5730` MHz and `5725 - 5850` to `5725 - 5895` MHz,
then runs `reg2fw.py` to update the `esp_wifi_regulatory.c` file compiled by IDF.
The patch uses IDF's selected Python interpreter, leaves an already patched
table untouched, and stops configuration if the IDF version or `PA` stanza
differs from the supported layout. These files are in the shared IDF checkout,
so the change also affects other projects using that checkout.

Disable this behavior with `-DPROJECTZERO_PATCH_IDF_PA_REGULATORY=OFF`.
Changing the table does not establish that a channel is accepted by the Wi-Fi
driver or usable by a particular device mode; those require device testing.

## OTA Update Flow
The firmware uses a dual-slot OTA layout (`ota_0`/`ota_1`) with `otadata` and the IDF bootloader rollback feature enabled. OTA updates overwrite the inactive slot and reboot into it.

Important notes:
- The bootloader and partition table must be flashed once via UART after enabling OTA/rollback. OTA only updates the app image.
- Rollback happens if the new image crashes before it is marked valid.
- Auto-OTA on IP is disabled; use the CLI commands below.
- On ESP32-C5 N8R8 (8 MB flash), each OTA slot is `0x3F0000` bytes (~3.94 MiB). Two full `4 MiB` slots do not fit because boot metadata and data partitions occupy the space before `0x20000`.
- A UART/web flash that writes only `ota_0` leaves `ota_1` empty until the first OTA update. The bundled `binaries-esp32c5/flash_board.py` now seeds `ota_1` by default by also writing the app at `0x410000`.

### OTA Commands
- `wifi_connect <SSID> <Password> [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]`: Connect to Wi-Fi as STA. Add `ota` to trigger OTA right after DHCP, or pass static IP settings (optionally with DNS).
- `wifi_disconnect`: Disconnect from the current Wi-Fi AP (STA).
- `ota_check [rf] [latest|<tag>]`: Check and apply OTA. Default respects
  `ota_channel`; `rf` selects the RF-support release path. `latest` forces the
  selected source's latest release and `<tag>` forces a specific release. An
  active analyzer/WPS radio lease refuses OTA before worker creation.
- `ota_list`: List recent GitHub releases (up to 5) with dates.
- `ota_channel [main|dev]`: Get/set OTA channel (saved in NVS).
  - `main`: GitHub release/latest.
  - `dev`: Pulls the app image from the `development` branch using a raw GitHub URL.
- `ota_info`: Show OTA partitions, states, and embedded app version.
- `ota_boot <ota_0|ota_1>`: Force boot to a specific OTA slot (useful for recovery/testing).

### OTA Source
- Main channel uses GitHub Releases and expects an asset named `projectZero.bin`.
- Dev channel pulls directly from:
  - `https://raw.githubusercontent.com/C5Lab/projectZero/development/ESP32C5/binaries-esp32c5/projectZero.bin`

### Rollback Validation
On boot, the firmware marks the running slot valid early (after NVS init). If you want stricter safety, move validation later in the boot sequence.

## GPS Modules
- Default profile targets ATGM336H at 9600 bps.
- M5Stack GPS v1.1 (115200 bps) is supported via `gps_set m5`; switch back with `gps_set atgm`. No reboot required.
- Use `start_gps_raw [baud]` to stream NMEA sentences to the console for quick verification.

## Boot Button Usage
The Boot button is wired to GPIO28 and is configured for two different actions while the device is running the firmware:

- Quick press: prints `Boot Pressed` to the console and runs the `start_sniffer_dog` command.
- Press and hold (≈1 second or longer): prints `Boot Long Pressed` and launches the `start_blackout` command.

Both shortcuts work only during normal operation (not in download mode). Use them to trigger the respective attacks without typing into the console.
