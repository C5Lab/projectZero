# Flipper Companion App

Flipper Zero controls the ESP32-C5 Monster running JanOS through 3.3 V GPIO UART. The app keeps its menu, UART and power control in the host; larger features are embedded FAL plugins loaded when opened.

## Current Unleashed artifact

| File | Purpose | Device evidence |
| --- | --- | --- |
| [lab_c5_v0.41_unleashed_clean_candidate.fap](dist/lab_c5_v0.41_unleashed_clean_candidate.fap) | Current source, 12 embedded FAL plugins; 269,300 B; SHA-256 `A5E6D2E10E810F7C9E295D3BECB806EEFF4FF56AE5BBD1A7818FCD2D6B9B4E15` | User reported 8 separate reboot → first-start cycles with no OOM or Monster 5 V dropout; Connect → Nmap → GPS → Package Monitor worked. |

The clean candidate was built against Unleashed SDK `unlshd-083`. Its host ELF has `SHF_ALLOC` 69,330 B, a preload section-size lower bound of 80,070 B and a largest-section-plus-1024-B estimate of 34,216 B. These are build metrics, not measured free RAM on the Flipper. The candidate retains its tested filename because the FAP basename determines its extracted plugin asset path. The older Momentum and Momentum Dev binaries in `dist/` are separate historical builds; they have not received this current-source device test.

## Build and verify (Windows PowerShell)

From the repository root:

~~~powershell
Set-Location .\FLIPPER
py -3 -B -m unittest discover -s .\tests -p "test_*.py"
py -3 -B .\tests\run_adoption_c_tests.py
py -3 .\build_fap.py --no-upload --variant unleashed --artifact-suffix local_rebuild
py -3 .\tests\check_fap_code_sections.py .\dist\lab_c5_v0.41_unleashed_local_rebuild.fap
Get-FileHash .\dist\lab_c5_v0.41_unleashed_local_rebuild.fap -Algorithm SHA256
~~~

The build script checks the 12 embedded FAL entry points and ABI before publishing the FAP. `local_rebuild` creates a separate file and leaves the tested candidate and rollback binaries intact. A fresh build may have different bytes and needs its own hash and device check. Match the SDK variant to the firmware on the Flipper.

Pre-commit verification on 2026-10-30: 41/41 Python tests, 27/27 C host tests with ASan/UBSan, the candidate executable-section check and all 12 embedded FAL checks passed. This verification did not flash the device or measure its free RAM.

## Deploy over USB

Close qFlipper and other serial clients, connect the Flipper to the PC, then run:

~~~powershell
py -3 .\dist\deploy_fap.py
~~~

Select exactly `lab_c5_v0.41_unleashed_clean_candidate.fap`, the Flipper COM port and `/ext/apps`. Answer `n` to removing old FAPs and `n` to automatic launch; pressing Enter on either `[Y/n]` prompt means yes. Unplug USB, reboot the Flipper and launch the app manually for a first-start RAM check. Two more separate reboot/start cycles would complete the planned 10-cycle sample. Watch Monster 5 V during transitions within the app; closing the entire app may reboot the Monster as part of its existing behavior.

## Current behavior and limits

- Scanner displays up to 64 results and limits GUI selection to six networks because the current JanOS `select_networks` summary uses a 500 B buffer.
- Scanner → Connect uses JanOS saved Wi-Fi credentials. If no key exists, JanOS tries an open connection and the Connect screen reports that fallback.
- GPS, Web/Portal/Evil Twin/Karma, Recon, Rogue AP, ARP, Nmap, MITM PCAP, Wardrive and other adopted features are loaded through on-demand FAL modules.
- WPA-sec and Wardrive external upload screens remain blocked until JanOS TLS endpoint verification is resolved and tested.

Walkthrough: https://youtu.be/Jf8JnbvrvnI

Support: https://discord.gg/57wmJzzR8C
