# Project Zero

## Overview
Project Zero is an ESP32-C5 firmware that bundles Wi-Fi assessment tooling, console-driven attacks, and peripherals such as the onboard NeoPixel, SD card storage, and GPS interface.

The firmware boots into an `esp_console` REPL, so most capabilities are exposed as CLI commands (`start_blackout`, `start_sniffer_dog`, `start_portal`, and more). Refer to the serial console banner for the full list after flashing.

## Boot Button Usage
The Boot button is wired to GPIO28 and is configured for two different actions while the device is running the firmware:

- Quick press: prints `Boot Pressed` to the console and runs the `start_sniffer_dog` command.
- Press and hold (≈1 second or longer): prints `Boot Long Pressed` and launches the `start_blackout` command.

Both shortcuts work only during normal operation (not in download mode). Use them to trigger the respective attacks without typing into the console.
