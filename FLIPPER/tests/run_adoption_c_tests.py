"""Compile and run all FLIPPER host C tests under WSL.

Run from PowerShell: py -3 ./tests/run_adoption_c_tests.py
These exercise module state machines with fake Flipper APIs and JanOS
transcripts. They do not run firmware or prove physical-device behavior.
"""

from pathlib import Path
import os
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
RECON_SOURCES = [
    "modules/recon/recon_module.c",
    "modules/recon/recon_scan.c",
    "modules/recon/recon_sniffer_probe.c",
    "modules/recon/recon_sniffer_clients.c",
]
WEB_SOURCES = [
    "modules/web/web_module.c",
    "modules/web/web_protocol.c",
    "modules/web/web_lists.c",
    "modules/web/web_qr.c",
    "modules/web/web_status.c",
    "modules/web/web_overlay.c",
    "modules/web/web_karma.c",
    "qrcodegen.c",
]
CASES = [
    ("arp", ["tests/test_arp_module.c", "modules/arp/arp_module.c"]),
    ("command_io", ["tests/test_command_io.c"]),
    ("gps_coord", ["tests/test_gps_coord.c", "gps_coord.c"]),
    ("gps_module", ["tests/test_gps_module.c", "modules/gps/gps_module.c", "gps_coord.c"]),
    ("help_qr_bitmap", ["tests/test_help_qr_bitmap.c", "qrcodegen.c"]),
    ("recon_scan", ["tests/test_recon_scan.c", "modules/recon/recon_scan.c"]),
    ("recon_module", ["tests/test_recon_module.c", *RECON_SOURCES]),
    ("recon_clients", ["tests/test_recon_sniffer_clients.c", *RECON_SOURCES]),
    ("recon_probe", ["tests/test_recon_sniffer_probe.c", "modules/recon/recon_sniffer_probe.c"]),
    ("recon_targets", ["tests/test_recon_targets.c", "modules/recon/recon_targets.c"]),
    ("rogue", ["tests/test_rogue_module.c", "modules/rogue/rogue_module.c"]),
    ("wardrive", ["tests/test_wardrive_module.c", "modules/wardrive/wardrive_module.c"]),
    ("beacon", ["tests/test_beacon_module.c", "modules/beacon/beacon_module.c"]),
    ("mitm_pcap", ["tests/test_mitm_pcap_module.c", "modules/mitm_pcap/mitm_pcap_module.c"]),
    ("wardrive_upload", ["tests/test_wardrive_upload_module.c", "modules/wardrive_upload/wardrive_upload_module.c"]),
    ("nmap", ["tests/test_nmap_module.c", "modules/nmap/nmap_module.c"]),
    ("wpasec", ["tests/test_wpasec_module.c", "modules/wpasec/wpasec_module.c"]),
    ("connect", ["tests/test_connect_module.c", "modules/connect/connect_module.c"]),
    ("web_karma", ["tests/test_web_karma.c", "modules/web/web_karma.c"]),
    ("web_lists", ["tests/test_web_lists.c", "modules/web/web_lists.c"]),
    ("web_module", ["tests/test_web_module.c", *WEB_SOURCES]),
    ("web_overlay", ["tests/test_web_overlay.c", "modules/web/web_overlay.c", "modules/web/web_status.c"]),
    ("web_protocol", ["tests/test_web_protocol.c", "modules/web/web_protocol.c"]),
    ("web_qr", ["tests/test_web_qr.c", "modules/web/web_qr.c", "qrcodegen.c"]),
    ("web_status", ["tests/test_web_status.c", "modules/web/web_status.c"]),
    ("attack_rx_guard", ["tests/test_attack_rx_guard.c", "attack_rx_guard.c"]),
    ("module_loader", ["tests/test_module_loader.c", "module_loader.c"]),
]
EXTRA_FLAGS = {
    "gps_coord": ["-DLAB_C5_HOST_TEST"],
    "recon_probe": ["-DC5_RECON_TEST_WRAP_CALLOC", "-Wl,--wrap=calloc"],
    "module_loader": ["-D_XOPEN_SOURCE=700", "-pthread"],
}


def main() -> int:
    listed = [Path(sources[0]).name for _, sources in CASES]
    available = {path.name for path in (ROOT / "tests").glob("test_*.c")}
    if len(listed) != len(set(listed)) or set(listed) != available:
        print(
            f"C test runner mismatch: missing={sorted(available - set(listed))}, "
            f"unknown={sorted(set(listed) - available)}, duplicates={len(listed) - len(set(listed))}",
            file=sys.stderr,
        )
        return 2
    for name, sources in CASES:
        executable = f"/tmp/c5_adoption_{name}_{os.getpid()}"
        command = [
            "wsl.exe", "--", "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
            "-fsanitize=address,undefined", "-Itests/stubs",
            *EXTRA_FLAGS.get(name, []), *sources, "-o", executable,
        ]
        try:
            built = subprocess.run(command, cwd=ROOT, check=False)
            if built.returncode:
                print(f"FAIL compile: {name}", file=sys.stderr)
                return built.returncode
            ran = subprocess.run(["wsl.exe", "--", executable], cwd=ROOT, check=False)
            if ran.returncode:
                print(f"FAIL run: {name}", file=sys.stderr)
                return ran.returncode
            print(f"PASS: {name}")
        finally:
            subprocess.run(["wsl.exe", "--", "rm", "-f", executable], cwd=ROOT, check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
