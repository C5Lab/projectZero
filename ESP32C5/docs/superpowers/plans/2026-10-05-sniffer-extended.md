# JanOS passive sniffer extension

Approved design: passive collection in the existing sniffer; independent legacy SSID;
bounded frame parser; coherent snapshots; opt-in `extended` suffix, version 1.
Implementation stays in ESP32C5. No Tab5 edits, active discovery, or flashing.

- [x] Add host C fixtures exercising hidden SSID discovery, address validation,
  RSN/WPA, PMF, WPS, malformed/truncated frames and binary SSIDs. Observe failures.
- [x] Implement allocation-free parser and bounded UART suffix formatter.
- [x] Integrate collection, synchronization, reset and snapshots. Execute the actual
  old and new command bodies against identical fixtures and compare legacy output.
- [x] Document every field, units, limits and unknown/absent semantics; generate
  fixture output and manual commands.
- [x] Run host tests, existing adequate tests and ESP-IDF build; review the diff.

Regression follow-up: restore legacy AP/client collection and hopping decisions;
compare frozen original and production callbacks after every replayed frame.
Keep extension RSSI/age/profile metadata independent of legacy records.
