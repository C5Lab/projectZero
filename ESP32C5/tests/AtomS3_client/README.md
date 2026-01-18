# AtomS3 client (JanOSmini, ESP-IDF)

Console uses USB-Serial-JTAG by default (prompt: `JanOSmini> `).

Local helper scripts for building/flashing the AtomS3 client live in this folder.

## Build (Docker)

```bash
python ESP32C5/tests/AtomS3_client/build_bin_docker.py
```

Artifacts are copied to `ESP32C5/tests/AtomS3_client/docker_bin_output`.

## Flash

```bash
python ESP32C5/tests/AtomS3_client/flash_board.py --port COMx
```

The flasher uses `flasher_args.json` if present, otherwise it will look for
`flash_args` in the build output directory.
