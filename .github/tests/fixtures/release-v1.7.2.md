Release v1.7.2 published.

Release page: https://github.com/C5Lab/projectZero/releases/tag/v1.7.2
Web flasher: https://C5Lab.github.io/projectZero/
JanOS (1.7.2): https://github.com/C5Lab/projectZero/releases/download/v1.7.2/projectZero-1.7.2.zip
FAPs (0.41): https://github.com/C5Lab/projectZero/releases/download/v1.7.2/projectZero-faps-0.41.zip
Full package: https://github.com/C5Lab/projectZero/releases/download/v1.7.2/projectZero-1.7.2-with-fap-0.41.zip

1.7.2

Summary
JanOS 1.7.2 release with a new capture gateway, Rogue GITM mode, resumable UART file transfers, and major wardriving performance improvements.
Key changes
- Added capture_gateway:
  - creates a dedicated APSTA/NAPT gateway for authorized traffic analysis,
  - automatically records downstream traffic to PCAP,
  - provides DNS proxying and connected-client monitoring,
  - uses adaptive rate limiting to protect the recorder queue,
  - exposes detailed machine-readable status and capture statistics.
- Added start_rogue_gitm:
  - creates a mirrored WPA2 access point using the Capture Gateway,
  - supports optional same-channel deauthentication,
  - rejects targets on other channels and the upstream STA BSSID,
  - restricts captured traffic to the mirrored 10.42.0.0/24 network.
- Added resumable SD-card file transfers over UART:
  - introduced send_file <path> [offset],
  - uses framed binary blocks with CRC32 validation,
  - supports acknowledgements, retries, cancellation, and timeout recovery,
  - prevents baud-rate fallback from interrupting active transfers.
- Added UART baud-rate management with confirmation, status reporting, and automatic recovery to 115200.
- Improved file management:
  - added file sizes to list_dir with the -s option,
  - added HTTP Range support for resumable Admin Portal downloads,
  - extended file_delete to process multiple paths with machine-readable results.
- Improved wardrive listing and cleanup:
  - added persistent scan-result caching based on filename, size, and modification time,
  - eliminated redundant file reads and temporary sanitized copies,
  - added progress heartbeats for long-running scans,
  - guaranteed BEGIN, SUMMARY, and END output framing, including error paths,
  - improved file counts and unreadable-file reporting.
- Improved wardrive upload handling by skipping files already marked as uploaded before sanitization.
- Updated wardrive_fix to store repaired logs in a dedicated fixed/ directory and exclude them from automatic upload scans.
- Added sd_benchmark for measuring sustained SD-card write speed, latency, and conservative gateway throughput.
- Updated the build environment, dependencies, Docker tooling, and CI workflows to ESP-IDF 6.0.2.
- Updated command documentation and added comprehensive Capture Gateway architecture and testing documentation.
- Removed the obsolete Google Drive uploader implementation plan.
Artifacts
- Updated projectZero.bin and bootloader.bin.
- Updated the firmware version to JanOS 1.7.2.
