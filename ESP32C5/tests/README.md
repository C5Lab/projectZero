# ESP32C5 tests

## Quick start (flash suite)

1) Put base firmware binaries into `ESP32C5/tools/SW/`:
   - `bootloader.bin`
   - `partition-table.bin`
   - `projectZero.bin`
2) Plug the ESP32C5 DUT (CP2102N) into USB.
3) Run with Docker Compose:

```bash
docker compose -f ESP32C5/tests/docker-compose.yml run --rm tests
```

## Alternate runs

Run without pytest-sugar:
```bash
docker compose -f ESP32C5/tests/docker-compose.yml run --rm \
  -e ESP32C5_DUT_PORT=/dev/ttyUSB0 \
  -e PYTEST_ADDOPTS="-p no:sugar" \
  tests
```

Generate HTML report:
```bash
docker compose -f ESP32C5/tests/docker-compose.yml run --rm \
  -e ESP32C5_DUT_PORT=/dev/ttyUSB0 \
  -e PYTEST_ADDOPTS="--html=/workspace/ESP32C5/tests/results/report.html --self-contained-html" \
  tests
```

## Hardware

Primary test device (master):
- ESP32C5 Dev Kit with SD card attached
- Connected to Linux host via USB (CP2102N)

## Flow (current: flash)

```mermaid
flowchart TD
    A[Connect ESP32C5 Dev Kit via USB] --> B[Detect device by VID/PID/Serial]
    B --> C{Device found?}
    C -- no --> D[Fail: precondition not met]
    C -- yes --> E[Erase flash]
    E --> F[Write base firmware]
    F --> G[Reset device]
    G --> H[Flash suite done]
```

## Test flow (current suites)

```mermaid
flowchart TD
    A[Preflight: device + files] --> B[Flash base firmware]
    B --> C[Flash target firmware]
    C --> D[Validate OTA info]
    D --> E[WiFi scan tests]
```

## Test suites

### Flash (mandatory)

1) `flash_base`  
   - Full erase + flash base firmware from `ESP32C5/tests/SW`
2) `flash_target`  
   - Full erase + flash target firmware from `ESP32C5/binaries-esp32c5`
3) `flash_validate`  
   - Wait for `BOARD READY`, send `ota_info`, validate OTA info output

#### Flash flows

`flash_base`
```mermaid
flowchart TD
    A[Preflight OK] --> B[Erase base flash]
    B --> C[Write base firmware]
    C --> D[Flash base done]
```

`flash_target`
```mermaid
flowchart TD
    A[Preflight OK] --> B[Erase target flash]
    B --> C[Write target firmware]
    C --> D[Flash target done]
```

`flash_validate`
```mermaid
flowchart TD
    A[Wait for BOARD READY] --> B[Send ota_info]
    B --> C[Read output until prompt]
    C --> D[Validate OTA fields]
```

### Scan (mandatory)

1) `scan_networks_basic`  
   - Run `scan_networks`, verify summary and status
2) `scan_networks_repeatability`  
   - Run `scan_networks` twice, both must pass basic checks
3) `show_scan_results_after_scan`  
   - Run `show_scan_results`, verify CSV-like output
4) `scan_channel_time_defaults`  
   - Run `channel_time read min/max`, verify values >= 1
5) `scan_networks_timeout_guard`  
   - Ensure scan completes within timeout
6) `scan_networks_output_fields`  
   - Validate CSV rows have 8 fields

#### Scan flows

`scan_networks_basic`
```mermaid
flowchart TD
    A[Wait for BOARD READY] --> B[Send scan_networks]
    B --> C[Wait for Scan results printed.]
    C --> D[Parse summary]
    D --> E[Validate counts + status]
```

`scan_networks_repeatability`
```mermaid
flowchart TD
    A[Wait for BOARD READY] --> B["Send scan_networks 1"]
    B --> C["Send scan_networks 2"]
    C --> D[Validate both summaries]
```

`show_scan_results_after_scan`
```mermaid
flowchart TD
    A[Send show_scan_results] --> B[Read until prompt]
    B --> C[Validate CSV output]
```

`scan_channel_time_defaults`
```mermaid
flowchart TD
    A[Send channel_time read min] --> B[Read value]
    B --> C[Send channel_time read max]
    C --> D[Read value]
    D --> E[Validate values >= 1]
```

`scan_networks_timeout_guard`
```mermaid
flowchart TD
    A[Start scan] --> B[Measure elapsed]
    B --> C[Validate within timeout]
```

`scan_networks_output_fields`
```mermaid
flowchart TD
    A[Parse CSV lines] --> B[Check 8 fields per row]
```

### System (mandatory)

1) `vendor_read`  
   - Run `vendor read`, verify vendor status output
2) `led_set_and_read`  
   - Toggle LED on/off and verify `led read` output
3) `list_sd`  
   - Run `list_sd`, verify SD is mounted and output is valid

#### System flows

`vendor_read`
```mermaid
flowchart TD
    A[Wait for BOARD READY] --> B[Send vendor read]
    B --> C[Read until prompt]
    C --> D[Validate Vendor scan output]
```

`led_set_and_read`
```mermaid
flowchart TD
    A[Send led set on] --> B[Read LED status]
    B --> C[Send led set off]
    C --> D[Read LED status]
```

`list_sd`
```mermaid
flowchart TD
    A[Send list_sd] --> B[Read until prompt]
    B --> C[Validate SD output]
```

### BLE (mandatory)

1) `scan_bt`  
   - Run `scan_bt`, verify BLE scan summary output

#### BLE flow

`scan_bt`
```mermaid
flowchart TD
    A[Wait for BOARD READY] --> B[Send scan_bt]
    B --> C[Wait for Summary line]
    C --> D[Validate BLE summary]
```

## Device configuration

Default detection uses `ESP32C5/tests/config/devices.json` and looks for a
single DUT device by VID/PID/serial. You can override with:

- `ESP32C5_DUT_PORT=/dev/ttyUSB0`
- `ESP32C5_DEVICES_CONFIG=/path/to/devices.json`

## Flash manifest

If base binaries or offsets differ, provide a manifest JSON and optional base
directory:

```json
{
  "files": [
    {"path": "bootloader.bin", "offset": "0x2000"},
    {"path": "partition-table.bin", "offset": "0x8000"},
    {"path": "projectZero.bin", "offset": "0x20000"}
  ]
}
```

Use it with:

```bash
ESP32C5_FLASH_MANIFEST=/workspace/ESP32C5/tests/flash_manifest.json \
ESP32C5_BASE_SW_DIR=/workspace/ESP32C5/tools/SW \
pytest -m flash
```
