"""Audit the public Wi-Fi Shield CLI and operator documentation contract."""

from pathlib import Path
import os
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MAIN = ROOT / "main" / "main.c"
SHIELD_HEADER = ROOT / "main" / "wifi_shield.h"
SHIELD_SOURCE = ROOT / "main" / "wifi_shield.c"
COMMAND_MANUAL = ROOT / "docs" / "command-manual.md"
LEASE_MANUAL = ROOT / "docs" / "janos-radio-lease.md"
RUNTIME_MANUAL = ROOT / "docs" / "wifi-security-runtime.md"
OPERATOR_GUIDE = ROOT / "docs" / "wifi-shield.md"
VALIDATION_GUIDE = ROOT / "docs" / "wifi-shield-validation.md"

EXACT_HELP = (
    "Wi-Fi Shield: start [--only indexes...] "
    "[--protect-all | --defence decoy-4way "
    "[--pmkid-decoy [--multi-vector]]] | status | report | log status | stop"
)

PUBLIC_FORMS = (
    "wifi_shield start",
    "wifi_shield start --only <scan-index> [scan-index ...]",
    "wifi_shield start --only <scan-index> [scan-index ...] --defence decoy-4way",
    "wifi_shield start --only <scan-index> [scan-index ...] --defence decoy-4way --pmkid-decoy",
    "wifi_shield start --only <scan-index> [scan-index ...] --defence decoy-4way --pmkid-decoy --multi-vector",
    "wifi_shield start --only <scan-index> [scan-index ...] --protect-all",
    "wifi_shield status",
    "wifi_shield report",
    "wifi_shield log status",
    "wifi_shield stop",
)

V2_OPERATOR_CONTRACT = (
    "correlation window is 30 seconds",
    "idle deadline is 60 seconds",
    "REASON=isolated_activity",
    "REASON=isolated_alert",
    "REASON=cross_vector",
    "SESSION_PEAK",
    "COMPLETED",
    "Loss lowers confidence but never erases an observed event",
    "[SHIELD/2] RECOMMENDATION",
    "ACTION=<token> EVIDENCE=<token> CONFIDENCE=<observed|limited>",
    "replacement set",
    "revision/index/count",
    "/sdcard/lab/shield/shield-b<boot_id>-s<session_id>.jsonl.part",
    "8 MiB",
    "no in-session retry",
    "fail-open",
    "AP-relative and spoofable",
    "never UTC",
    "ap_tsf_quality` and `ap_tsf_uncertainty_us",
    "trusted GPS",
    "epoch_ms`, `time_source=gps` and `time_uncertainty_ms",
    "station identities",
    "dedicated writer",
    "journal queue depth is 32",
    "usable while Shield owns the radio lease",
    "CSA activity alone does not establish channel instability",
    "tsf_epoch_change_observed",
    "list_dir lab/shield -s",
)


def section(text, heading):
    position = text.find(heading)
    if position < 0:
        return ""
    start = position + len(heading)
    next_heading = re.search(r"(?m)^###? ", text[start:])
    return text[start:start + next_heading.start()] if next_heading else text[start:]


def normalized(text):
    return " ".join(text.split())


class WifiShieldDocumentationTest(unittest.TestCase):
    def test_shield_guides_separate_operation_from_validation_evidence(self):
        """Catch loss of the operator guide, evidence ledger or proof limits."""
        operator = OPERATOR_GUIDE.read_text(encoding="utf-8")
        validation = VALIDATION_GUIDE.read_text(encoding="utf-8")
        manual = COMMAND_MANUAL.read_text(encoding="utf-8")
        runtime = RUNTIME_MANUAL.read_text(encoding="utf-8")

        operator_contract = (
            "# JanOS Wi-Fi Shield",
            "## Operator workflow",
            "## Trust and Evil Twin indicators",
            "## Beacon sequence continuity",
            "## CSA interpretation",
            "## Evidence boundaries",
            "does not prove an evil twin",
            "not AP-side packet loss",
            "cannot authenticate a CSA transmitter",
            "wifi_shield start --only <scan-index> --protect-all",
            "wifi_shield report",
            "wifi_shield log status",
            "[SHIELD/2] EVENT SOURCE=deauth TYPE=csa_announcement",
            "a lone CSA announcement never authorizes Defence TX",
            "Shield Trust currently compares only an observed selected BSSID with its matching baseline",
            "same-SSID candidates on other BSSIDs are Stage 1 work",
        )
        validation_contract = (
            "# JanOS Wi-Fi Shield Validation",
            "## Evidence levels",
            "## Methodology",
            "## Controlled session evidence",
            "## Recommended next tests",
            "verified",
            "observed",
            "inconclusive",
            "not run",
            "LAB-AP-A",
            "independent monitor",
            "firmware SHA-256",
            "UART",
            "PCAP",
            "JSONL",
            "4095 -> 0",
            "spoofed CSA",
            "negative control",
            "CSA Stage 0",
            "one legitimate AP-controlled CSA",
            "one authorized spoofed CSA",
            "one Deauth control",
            "zero CSA-triggered Defence telemetry",
        )
        for phrase in operator_contract:
            with self.subTest(guide="operator", phrase=phrase):
                self.assertIn(normalized(phrase), normalized(operator))
        for phrase in validation_contract:
            with self.subTest(guide="validation", phrase=phrase):
                self.assertIn(normalized(phrase), normalized(validation))

        for source in (manual, runtime):
            self.assertIn("wifi-shield.md", source)
            self.assertIn("wifi-shield-validation.md", source)

        stage_zero_contract = (
            "[SHIELD/2] EVENT SOURCE=deauth TYPE=csa_announcement",
            "a lone CSA announcement never authorizes Defence TX",
        )
        for phrase in stage_zero_contract:
            with self.subTest(guide="stage-zero", phrase=phrase):
                self.assertIn(normalized(phrase), normalized(manual))

        self.assertNotIn("a new BSSID relative to the baseline", operator)

        for sensitive in ("CZARNA", "TP-Link_0E90", "68:ff:7b:cd:fc:40",
                          "b0:be:76:70:0e:90"):
            self.assertNotIn(sensitive, operator)
            self.assertNotIn(sensitive, validation)

    def test_v2_operator_contract_runs_real_cli_and_lifecycle_harnesses(self):
        """The operator prose is accepted only with executable CLI evidence."""
        environment = os.environ.copy()
        environment.pop("JANOS_TEST_SANITIZERS", None)
        for wrapper in ("test_wifi_shield_cli.py",
                        "test_wifi_shield_integration.py"):
            result = subprocess.run(
                [sys.executable, "-B", str(ROOT / "tests" / wrapper), "-q"],
                cwd=ROOT, env=environment, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
            self.assertIn("OK", result.stderr)

        manual = COMMAND_MANUAL.read_text(encoding="utf-8")
        shield = section(manual, "### `wifi_shield`")
        for phrase in V2_OPERATOR_CONTRACT:
            with self.subTest(phrase=phrase):
                self.assertIn(normalized(phrase), normalized(shield))

    def test_dispatch_registration_and_help_are_one_exact_public_command(self):
        header = SHIELD_HEADER.read_text(encoding="utf-8")
        source = SHIELD_SOURCE.read_text(encoding="utf-8")
        main = MAIN.read_text(encoding="utf-8")

        help_match = re.search(
            r'#define WIFI_SHIELD_HELP_TEXT\s*\\\s*\n\s*"([^"]+)"', header)
        self.assertIsNotNone(help_match, "Shield help constant is missing")
        self.assertEqual(help_match.group(1), EXACT_HELP)

        command = source.split("int wifi_shield_command(int argc, char **argv)", 1)[1]
        command = command.split("\n}\n", 1)[0]
        self.assertIn("wifi_shield_parse_cli(argc, argv, &cli)", command)
        self.assertIn("cli.kind == WIFI_SHIELD_COMMAND_START", command)
        self.assertIn("cli.kind == WIFI_SHIELD_COMMAND_STOP", command)
        self.assertIn("wifi_shield_format_status", command)

        registration = re.search(
            r"const\s+esp_console_cmd_t\s+wifi_shield_cmd\s*=\s*\{(.*?)\n\s*\};",
            main, flags=re.S)
        self.assertIsNotNone(registration, "wifi_shield registration is missing")
        body = registration.group(1)
        self.assertIn('.command = "wifi_shield"', body)
        self.assertIn(".help = WIFI_SHIELD_HELP_TEXT", body)
        self.assertIn(".func = &wifi_shield_command", body)
        self.assertEqual(main.count("esp_console_cmd_register(&wifi_shield_cmd)"), 1)
        for internal in (
                "wifi_shield_start_wps_profile",
                "wifi_shield_start_sae_profile",
                "wifi_shield_start_trust_profile",
                "wifi_shield_start_deauth_profile"):
            self.assertNotRegex(main, rf'\.command\s*=\s*"{internal}"')

    def test_command_manual_freezes_forms_and_safety_evidence_boundaries(self):
        manual = COMMAND_MANUAL.read_text(encoding="utf-8")
        shield = section(manual, "### `wifi_shield`")
        forms = re.search(
            r"The accepted command forms are exactly:\s*```text\n(.*?)\n```",
            shield, flags=re.S)
        self.assertIsNotNone(forms, "exact Shield CLI forms are not documented")
        self.assertEqual(tuple(forms.group(1).splitlines()), PUBLIC_FORMS)
        self.assertIn(EXACT_HELP, shield)

        required = (
            "Passive Shield makes exactly zero TX calls",
            "immutable selected BSSID and snapshotted channel",
            "WPA2-PSK/CCMP",
            "explicit and experimental",
            "`--protect-all` is an explicit preset",
            "ACTIVE=deauth,pmkid",
            "PASSIVE=wps,sae,trust",
            "COVERAGE=continuous",
            "COVERAGE=sampled",
            "silence is not proof of absence",
            "WPS activity does not prove Pixie Dust, exploitation or a vulnerable router",
            "WPS, SAE and Trust never trigger an active response",
            "does not prove prevention, client retention or that a real handshake was not captured",
            "MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT",
            "no fallback to internal SRAM",
            "SHIELD/QUARANTINED",
            "wifi_shield stop",
            "global stop",
            "Host tests do not prove firmware compilation, device behavior, physical PSRAM/SD behavior or RF behavior",
            "not public CLI",
        )
        for phrase in required:
            with self.subTest(phrase=phrase):
                self.assertIn(normalized(phrase), normalized(shield))
        self.assertNotRegex(shield, r"(?m)^\s*wifi_shield_start_[a-z_]+")

    def test_manual_preserves_trust_and_detector_v2_compatibility_claims(self):
        manual = COMMAND_MANUAL.read_text(encoding="utf-8")
        trust = section(manual, "### `wifi_trust`")
        detector = section(manual, "## Sniffing & monitoring")
        for phrase in (
                "Bare capture and monitor remain current-channel only",
                "`--only` uses sampled residence",
                "`SCOPE=current_channel` remains byte-for-byte unchanged"):
            self.assertIn(normalized(phrase), normalized(trust))
        for phrase in (
                "Deauth-only compatibility profile of the shared Wi-Fi Shield runtime",
                "legacy `deauth_detector` remains on its direct established path",
                "does not change legacy V2 record bytes, ordering, Forensics, Trace, Defence, LED or OLED behavior"):
            self.assertIn(normalized(phrase), normalized(detector))
        self.assertNotRegex(
            normalized(detector),
            r"Defence examples are .{0,1500}JANOS_RADIO_OWNER_DEFENCE")

    def test_radio_owner_manual_maps_combined_and_compatibility_profiles(self):
        manual = LEASE_MANUAL.read_text(encoding="utf-8")
        for phrase in (
                "JANOS_RADIO_OWNER_SHIELD",
                "combined `wifi_shield`",
                "JANOS_RADIO_OWNER_SECURITY_MONITOR",
                "`wps_guard`, `sae_guard`, `wifi_trust` and `deauth_detector_v2` compatibility profiles",
                "JANOS_RADIO_OWNER_DEFENCE",
                "legacy standalone active Detector Defence"):
            self.assertIn(normalized(phrase), normalized(manual))
        self.assertIn("SHIELD/QUARANTINED", manual)
        self.assertNotRegex(
            normalized(manual),
            r"deauth_detector_v2 --only .{0,300}DEFENCE/PREPARING")

    def test_runtime_manual_covers_shared_profiles_psram_and_uncertainty(self):
        manual = RUNTIME_MANUAL.read_text(encoding="utf-8")
        for phrase in (
                "WIFI_SECURITY_MODULE_SHIELD",
                "WIFI_SECURITY_MODULE_DEAUTH_V2",
                "one shared callback and worker",
                "MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT",
                "no silent fallback to internal SRAM",
                "SHIELD/QUARANTINED",
                "single-channel coverage is continuous",
                "multi-channel coverage is sampled",
                "silence is not proof of absence",
                "WPS, SAE and Trust observations never authorize active response",
                "Host success is not firmware, device, physical PSRAM/SD or RF proof"):
            self.assertIn(normalized(phrase), normalized(manual))

    @unittest.skipUnless(os.name == "nt", "Windows WSL fallback test")
    def test_console_startup_gate_does_not_skip_without_native_compiler(self):
        environment = os.environ.copy()
        environment["CC"] = "__janos_missing_native_compiler__"
        result = subprocess.run(
            [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests",
             "-p", "test_janos_console_startup.py", "-v"],
            cwd=ROOT, env=environment, capture_output=True, text=True)
        transcript = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, transcript)
        self.assertNotIn("skipped", transcript.lower(), transcript)
        self.assertIn("test_wifi_shield_registration_uses_exact_help_and_handler", transcript)


if __name__ == "__main__":
    unittest.main()
