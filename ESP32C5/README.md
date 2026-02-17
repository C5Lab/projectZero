# Project Zero

## Overview
Project Zero is an ESP32-C5 firmware that bundles Wi-Fi assessment tooling, console-driven attacks, and peripherals such as the onboard NeoPixel, SD card storage, and GPS interface.

The firmware boots into an `esp_console` REPL, so most capabilities are exposed as CLI commands (`start_blackout`, `start_sniffer_dog`, `start_portal`, and more). Refer to the serial console banner for the full list after flashing.

## Build Note: exFAT
This repo auto-patches your local ESP-IDF `ffconf.h` during CMake configure to force:
- `FF_FS_EXFAT = 1`

Path patched on each machine:
- `$IDF_PATH/components/fatfs/src/ffconf.h`

Disable this behavior if needed:
- `-DPROJECTZERO_PATCH_IDF_EXFAT=OFF`

## OTA Update Flow
The firmware uses a dual-slot OTA layout (`ota_0`/`ota_1`) with `otadata` and the IDF bootloader rollback feature enabled. OTA updates overwrite the inactive slot and reboot into it.

Important notes:
- The bootloader and partition table must be flashed once via UART after enabling OTA/rollback. OTA only updates the app image.
- Rollback happens if the new image crashes before it is marked valid.
- Auto-OTA on IP is disabled; use the CLI commands below.

### OTA Commands
- `wifi_connect <SSID> <Password> [ota] [<IP> <Netmask> <GW> [DNS1] [DNS2]]`: Connect to Wi-Fi as STA. Add `ota` to trigger OTA right after DHCP, or pass static IP settings (optionally with DNS).
- `wifi_disconnect`: Disconnect from the current Wi-Fi AP (STA).
- `ota_check [latest|<tag>]`: Check and apply OTA. Default respects `ota_channel`. `latest` forces GitHub releases/latest. `<tag>` forces a specific release.
- `ota_list`: List recent GitHub releases (up to 5) with dates.
- `ota_channel [main|dev]`: Get/set OTA channel (saved in NVS).
  - `main`: GitHub release/latest.
  - `dev`: Pulls the app image from the `development` branch using a raw GitHub URL.
- `ota_info`: Show OTA partitions, states, and embedded app metadata (version/date).
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
