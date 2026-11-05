"""Host integration contract for Router Audit CLI and source wiring."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")

class RouterAuditIntegrationTest(unittest.TestCase):
    def test_cli_and_records_use_real_command_code(self):
        with tempfile.TemporaryDirectory(prefix="janos-router-integration-") as directory:
            executable = Path(directory) / "router_audit_integration_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                     "-DROUTER_AUDIT_TESTING"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/router_audit_integration_test.c",
                       ROOT / "main/router_audit.c",
                       ROOT / "main/router_audit_wire.c",
                       ROOT / "main/router_fingerprint.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"), "host C compiler required")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            stack_object = Path(directory) / "router_audit.o"
            if compiler:
                stack_command = [compiler, *flags, "-Wframe-larger-than=2048",
                                 "-I", str(ROOT / "main"), "-c",
                                 str(ROOT / "main/router_audit.c"),
                                 "-o", str(stack_object)]
            else:
                stack_command = ["wsl.exe", "cc", *flags,
                                 "-Wframe-larger-than=2048", "-I",
                                 wsl_path(ROOT / "main"), "-c",
                                 wsl_path(ROOT / "main/router_audit.c"),
                                 "-o", wsl_path(stack_object)]
            stack_built = subprocess.run(stack_command, cwd=ROOT,
                                         capture_output=True, text=True)
            self.assertEqual(stack_built.returncode, 0,
                             stack_built.stdout + stack_built.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(),
                "PASS: Router Audit CLI, bounded operations, evidence records")

    def test_main_registration_admission_and_storage_contract(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        command = (ROOT / "main/router_audit.c").read_text(encoding="utf-8")
        header = (ROOT / "main/router_audit.h").read_text(encoding="utf-8")
        core = (ROOT / "main/router_audit_core.c").read_text(encoding="utf-8")
        admission = (ROOT / "main/janos_console_admission.c").read_text(encoding="utf-8")
        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn('#include "router_audit.h"', main)
        match = re.search(r"const\s+esp_console_cmd_t\s+router_audit_cmd\s*=\s*\{(.*?)\n\s*\};",
                          main, flags=re.S)
        self.assertIsNotNone(match)
        body = match.group(1)
        self.assertIn('.command = "router_audit"', body)
        self.assertIn('Gateway inventory/CVE audit: scan passive | scan standard --owned | status | db status|verify|install [--allow-time-unknown]', body)
        self.assertRegex(body, r"\.func\s*=\s*&?router_audit_command")
        self.assertEqual(len(re.findall(r"esp_console_cmd_register\s*\(\s*&router_audit_cmd\s*\)", main)), 1)
        self.assertEqual(cmake.count('"router_audit.c"'), 1)
        self.assertEqual(cmake.count('"router_audit_wire.c"'), 1)
        self.assertIn("router_audit_init(&router_audit_hooks)", main)
        self.assertIn('"/sdcard/lab/router-audit"', main)
        self.assertIn("sd_sync_checked", main)
        self.assertIn("router_audit", admission)
        self.assertIn("is_router_audit_status", admission)
        self.assertIn("_Static_assert(sizeof(router_audit_command_state_t)", command)
        self.assertIn("ROUTER_AUDIT_COMMAND_STATE_MAX", command)
        self.assertIn("command_workspace", header)
        self.assertIn("command_workspace_size", header)
        self.assertNotIn("static atomic_bool output_failed", command)
        self.assertNotIn("router_evidence_set_t result;", core)
        adapter = main.split("static bool router_audit_platform_snapshot", 1)[1].split(
            "static portMUX_TYPE wps_guard_state_lock", 1)[0]
        self.assertIn("esp_wifi_sta_get_ap_info", adapter)
        self.assertIn("esp_netif_get_ip_info", adapter)
        self.assertIn("etharp_find_addr", adapter)
        self.assertNotIn("etharp_request", adapter)
        self.assertIn("socket(AF_INET", adapter)
        self.assertIn("O_NONBLOCK", adapter)
        self.assertIn("select(", adapter)
        self.assertIn("SO_ERROR", adapter)
        self.assertIn("ROUTER_CVE_STAGE_PATH", adapter)
        self.assertIn("MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT", adapter)
        self.assertIn("router_cve_verify_owned", adapter)
        self.assertIn("router_cve_install_recover_owned", adapter)
        self.assertIn("router_cve_install_catalog_owned", adapter)
        self.assertIn("router_cve_db_open_owned_snapshot_with_release", adapter)
        self.assertNotIn("router_cve_db_open_owned_snapshot(\n", adapter)
        self.assertNotIn("router_cve_install_recover(", adapter)
        self.assertNotIn("router_cve_install_catalog(", adapter)
        status_adapter = adapter.split(
            "static router_cve_verify_result_t router_audit_platform_db_status", 1
        )[1].split(
            "static router_cve_verify_result_t router_audit_platform_db_verify", 1
        )[0]
        self.assertIn("router_cve_install_recover_owned", status_adapter)
        self.assertIn("recovered.created_epoch", status_adapter)
        self.assertIn("recovered.expires_epoch", status_adapter)
        self.assertIn("recovered.installed_time_unknown", status_adapter)
        self.assertNotIn("stat(", status_adapter)
        self.assertIn("router_cve_mbedtls_p256_verify", adapter)
        self.assertIn("router_cve_storage_advance_commit", adapter)
        self.assertEqual(adapter.count("uart_write_bytes"), 1)
        self.assertNotIn("test private", adapter.lower())
        self.assertNotIn("BEGIN PRIVATE KEY", adapter)

    def test_documentation_and_release_governance_contract(self):
        manual = (ROOT / "docs/command-manual.md").read_text(encoding="utf-8")
        catalog = (ROOT / "docs/router-cve-catalog.md").read_text(encoding="utf-8")
        builder = (ROOT / "tools/cvedb/README.md").read_text(encoding="utf-8")
        runtime = (ROOT / "docs/wifi-security-runtime.md").read_text(encoding="utf-8")
        combined = "\n".join((manual, catalog, builder, runtime))
        normalized = re.sub(r"\s+", " ", combined)

        help_text = ("Gateway inventory/CVE audit: scan passive | scan standard "
                     "--owned | status | db status|verify|install "
                     "[--allow-time-unknown]")
        self.assertIn(help_text, manual)
        for command in (
                "router_audit scan passive",
                "router_audit scan standard --owned",
                "router_audit status",
                "router_audit db status",
                "router_audit db verify",
                "router_audit db install",
                "router_audit db install --allow-time-unknown"):
            self.assertIn(f"`{command}`", manual)

        for exact_record in (
                "EVIDENCE SOURCE STATUS FIELD VALUE TRUNCATED",
                "IDENTITY VENDOR MODEL FIRMWARE CONFIDENCE CONFLICT TRUNCATED",
                "CVE ID MATCH SEVERITY EOL KEV KEV_DATE FIXED URL CATALOG_SERIAL CATALOG_AGE_S STALE TIME_UNKNOWN SOURCE",
                "STATUS BUSY DB_AVAILABLE SERIAL STALE TIME_UNKNOWN DB_OUTCOME OUTCOME",
                "END MODE REQUESTS ERRORS EVIDENCE CONFIDENCE CANDIDATES EXACT OUTCOME"):
            self.assertIn(exact_record, catalog)

        for required in (
                "passive mode performs zero network I/O",
                "one unicast SSDP M-SEARCH",
                "literal gateway",
                "MODEL_CANDIDATE",
                "EXACT_FIRMWARE",
                "never claims that a router is vulnerable or exploitable",
                "UNKNOWN_KEY",
                "production trust anchor",
                "reviewed source lock v2",
                "source_lock_sha256",
                "official vendor, CNA, or CISA",
                "retrieval UTC",
                "immutable revision or dated snapshot",
                "lower-case 40- or 64-hex revision",
                "snapshot-YYYYMMDDTHHMMSSZ-<64-hex-digest>",
                "license file",
                "firmware performs no download",
                "external production key",
                "pair-atomic",
                "PUBLISHED_UNCERTAIN",
                "--allow-time-unknown",
                "4 MiB",
                "PSRAM",
                "Mbed TLS development package was unavailable",
                "no firmware build",
                "no real router",
                "no real SD/NVS",
                "no physical power-cut"):
            self.assertIn(required, normalized)

        workflow = [
            "fetch and pin official sources outside JanOS firmware",
            "review aliases and exact firmware rules",
            "build the deterministic JCVE/1 catalog offline",
            "parse the catalog independently",
            "sign with the external production key",
            "verify catalog hash, provenance hash, key ID and JCSG/1",
            "upload through the existing FS tooling",
            "run `router_audit db verify`",
            "run `router_audit db install`",
        ]
        normalized_catalog = re.sub(r"\s+", " ", catalog)
        positions = [normalized_catalog.index(step) for step in workflow]
        self.assertEqual(positions, sorted(positions))

        for acceptance in (
                "separate build approval",
                "separate owned-router approval",
                "passive zero-TX",
                "request caps",
                "same-gateway enforcement",
                "zero configuration changes",
                "must not attempt CVE exploitation or authentication bypass"):
            self.assertIn(acceptance, normalized_catalog)

        self.assertIn("CVE-2099", combined)
        self.assertIn("synthetic test fixture", normalized)
        self.assertNotRegex(combined, r"(?i)production catalog.*CVE-2099")

if __name__ == "__main__":
    unittest.main()
