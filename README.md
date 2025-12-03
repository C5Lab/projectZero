# projectZero

projectZero is a LAB C5 board add-on firmware that layers blackout, Sniffer Dog, wardriving, and captive portal tools on top of ESP32-C5 dual-band (2.4/5 GHz) radios—and is the first to ship working WPA handshake capture on ESP32-C5 using ESP-IDF.
- **ESP32-C5-WROOM-1** (USB CLI) scans, runs the embedded evil-twin portal, captures credentials, and verifies WPA2/WPA3 passwords—everything lives on the same board now.  
- **Flipper Zero companion app** mirrors the CLI features and keeps the handheld navigation lightweight.
- **LAB C5 board** is available on Tindie: https://www.tindie.com/products/lab/lab-esp32c5-flipper-zero-marauder/

## Overview

The firmware focuses on a small set of repeatable operations: discover targets, decide which networks matter, disrupt or impersonate them, and log the evidence. Use the CLI for fine control or the Flipper UI when you need a glanceable dashboard. The entire `ESP32C5/main/main.c` file is JanOS, a ground-up ESP-IDF stack written by the LAB team specifically for this hardware.

<img src="Gfx/fap_over.gif" alt="GUI overview" width="30%">

- Scan once, re-use the dataset everywhere: CLI commands and the Flipper Targets list consume the same buffers from `ESP32C5/main/main.c`.
- Attacks keep their own FreeRTOS tasks and respect the global `stop` flag, so you can stack scans, sniffing and portals without rebooting.
- Credential harvesting writes to `/sdcard/lab/portals.txt`, and validated passwords automatically end a deauth run.

## Core Capabilities

### Target Discovery & Reconnaissance
- `scan_networks` / `show_scan_results` - multi-band scans (with PH regulatory settings) populate an in-memory table for later selection.
- `select_networks <idx...>` - marks one or more rows as the active working set; the first entry also names the evil twin.
- `start_sniffer` / `show_sniffer_results` - dual-band sniffer logs AP/client pairs, RSSI and last-seen timestamps; use `sniffer_debug <0|1>` to toggle verbose logging.
- `show_probes` / `list_probes` - reviews all captured probe requests so you can pivot into Karma or custom portals.
- `packet_monitor <channel>` - lightweight packet-per-second telemetry for a single channel, useful before launching SAE floods.
- `start_wardrive` - waits for a GPS fix, then writes Wigle-style logs to `/sdcard/lab/wardrives/wXXXX.log` with auth mode, RSSI, and coordinates.

### Credential Capture & Portal Control
- `start_evil_twin` - spins up the ESP-NOW link to the secondary ESP32 so that deauth + portal orchestration happens automatically; once a password is validated, ESP32-C5 stops the attack.
- `start_portal <ssid>` - launches the captive portal locally on the C5, adds DNS redirection, and stores submissions inside `/sdcard/lab/portals.txt`.
- `list_sd` / `select_html <index>` - browse `/sdcard/lab/htmls/` for custom captive-portal templates (limited to 800 KB each) and push them into RAM.
- `start_karma <probe_index>` - re-broadcasts one of the sniffed probe SSIDs so the portal can masquerade as whatever nearby phones expect.
- `start_handshake` - exclusive LAB feature that spins up a dedicated WPA handshake capture task (shown as **Handshaker** inside the Flipper UI). More details: https://github.com/C5Lab/projectZero/wiki/Handshaker

### Disruption & Containment
- `start_deauth` - multi-network broadcast and targeted deauth (including DFS/high 5 GHz channels) with LED status feedback.
- `sae_overflow` - floods a single WPA3 access point with randomized SAE commit frames until it stops accepting new stations.
- `start_blackout` - scheduled global deauth: periodic scan + sorted channel list + broadcast attack every cycle.
- `start_sniffer_dog` - watches for data and management packets in real time and sends targeted deauths only for the active pairs (honors the whitelist).
- Deep dive into both flows: https://github.com/C5Lab/projectZero/wiki/Blackout_SnifferDog
- `white.txt` - place MAC addresses (one per line) on `/sdcard/lab/white.txt` to exempt them from Blackout and Sniffer Dog logic.

### System Utilities & Feedback
- `vendor set <on|off>` / `vendor read` - toggles OUI lookup backed by `/lab/oui_wifi.bin` on the SD card.
- `led set <on|off>` / `led level <1-100>` - controls the WS2812 status LED (purple for portal, other colors for attacks).
- `stop` - flips the global stop flag so every running task can wind down gracefully.
- `reboot` - clean restart without USB re-plug.
- `list_sd` / `select_html` - also double as simple SD-card diagnostics.

## Flipper App Navigation

The Flipper application lives in `FLIPPER/Lab_C5.c` and mirrors the CLI primitives. Use it when you need to keep the board in a backpack but still see what is happening.

1. Launch the app and connect the ESP32-C5 when the splash screen prompts you.
2. Run **Scanner** from the main menu, then user Right navigation to jump in to **Targets** to see the same list that `show_scan_results` prints. Multi-select is handled by tapping OK on each row and confirming the dialog that pops up after every selection.
3. Use the attack selector to start Deauth, Evil Twin, SAE Overflow, Blackout, Sniffer Dog, Handshaker, Wardrive, Karma, or Sniffer views—each mirrors the CLI command of the same name.
4. Live attack telemetry reuses the same counters and whitelist state as the firmware, so you can monitor progress from the Flipper screen while the board stays tethered elsewhere.
5. Portal acknowledgements show up in the UI as soon as `portals.txt` is updated. Full walkthrough notes and screenshots now live on the wiki.

## Vendor Lookup Data

Enrich CLI/Flipper listings with manufacturer names by feeding a compact OUI database to the SD card.

1. Fetch the latest `oui.txt` from [IEEE](https://standards-oui.ieee.org/oui/oui.txt) and place it in the repo root.
2. Build the binary table:
   ```bash
   python ESP32C5/tools/build_oui_binary.py --input oui.txt --output ESP32C5/binaries-esp32c5/oui_wifi.bin
   ```
3. Copy `ESP32C5/binaries-esp32c5/oui_wifi.bin` to `/lab/oui_wifi.bin` on the SD card.
4. Toggle lookups with the CLI (`vendor set on|off`) or from the Flipper path **Setup -> Scanner Filters -> Vendor**.

## SD Card & File Layout

- `/lab/white.txt` - whitelist BSSIDs (colon or dash separated) respected by Blackout and Sniffer Dog.
- `/lab/wardrives/wXXXX.log` - Wigle-compatible wardrive logs incremented automatically.
- `/lab/htmls/*.html` - captive portal templates discovered by `list_sd`.
- `/lab/portals.txt` - persistent CSV-like log of every POST field the captive portal receives.
- `/lab/oui_wifi.bin` - vendor lookup table streamed on demand.

## Flashing the ESP32-C5 Firmware

1. Open a terminal in the repo and switch to the binaries folder: `cd ESP32C5/binaries-esp32c5`.
2. Run the flasher: `python flash_board.py`. The script waits for a USB-UART bridge before streaming the binary.
3. On the Flipper Zero, open **GPIO → GPIO → USB-UART Bridge** so it presents a serial adapter to the host PC.
- While holding the lower **BOOT** button on the LAB C5 board, plug the board into the Flipper; release BOOT right after it clicks in.
4. Connect the Flipper to your PC over USB; the flashing script will detect the bridge automatically (no qFlipper needed).
5. Once the transfer begins the rest is automatic; the board reboots into the freshly flashed JanOS build.

### Flashing Troubleshooting

- Make sure the qFlipper application is closed; it will keep the UART bridge busy and the script will hang.
- If you launched `flash_board.py` while the Flipper was already connected and nothing happened, unplug the USB cable, stop the script, then rerun the script before reconnecting (with BOOT held as described above).

With these anchors in place the README now focuses purely on the software's primary functions-scanning, deciding, attacking, and logging-while pointing both CLI and Flipper users to the exact commands and assets that power each flow.

## About Us

We're regular tinkerers who got bored and decided to design the full stack ourselves—from the LAB C5 hardware layout, through the JanOS firmware, to the graphics that ship with the Flipper app. Got questions or ideas? Drop by the Discord: https://discord.gg/57wmJzzR8C

## Community and Docs

- Full technical documentation, wiring notes, and troubleshooting live on the wiki: https://github.com/C5Lab/projectZero/wiki
- Join the LAB Discord server to discuss ESP32-C5 builds and projectZero workflows: https://discord.gg/57wmJzzR8C

## Last Changes
- 2025-12-03 JanOS 0.7.6 / FAP 0.28 - Setup / Scan timing: add configurable min/max durations for scanning.
- 2025-11-30 JanOS 0.7.5 / FAP 0.27 - Added Sniffer start with selected targets; Back stops and returns to Sniffers on Show Sniffer Results.
- 2025-11-29 FAP 0.26 - Setup → SD Manager with folder picker, file listing, delete + scrolling for long names.
- 2025-11-29 JanOS 0.7.1 - Added `list_dir [path]` and `file_delete <path>` for SD browsing/cleanup alongside `list_sd`.
- 2025-11-29 FAP 0.25 - Fixed missing propagation of `config.txt` (config load/create popups now appear and settings persist).
- 2025-11-28 JanOS 0.7.0 - Added WPA handshake capture via `start_handshake`.
- 2025-11-28 FAP 0.24 - Attack / Handshaker.
