# Flipper Companion App

The Flipper Zero companion app (`Lab_C5.fap`) mirrors the ESP32-C5 CLI workflows (scan, Targets, attacks, wardrive, Sniffer Dog, portal control) so you can steer the board from the handheld UI.

## Install the `.fap` (Windows + qFlipper)

1. Build or grab the packaged binary from `FLIPPER/dist/Lab_C5.fap`.
2. Launch **qFlipper**, connect your Flipper Zero, and wait until it shows as `Connected`.
3. Open **File manager** in qFlipper, then navigate to your SD card (`SD Card` tab) and browse to `/apps`.
4. Drag-drop or copy `Lab_C5.fap` from your PC (the repo `FLIPPER/dist` folder) into `/apps` on the SD card.
5. Safely eject the device or close qFlipper—the app now appears under **Applications → External** on the Flipper.

A short walkthrough video is also available: https://youtu.be/Jf8JnbvrvnI

Need help? Ping the team on Discord: https://discord.gg/57wmJzzR8C
