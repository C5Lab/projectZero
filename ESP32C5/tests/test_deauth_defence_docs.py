"""Source and documentation contract for active Deauth Detector V2 Defence."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DeauthDefenceDocumentationTests(unittest.TestCase):
    def test_builtin_help_exposes_only_the_explicit_selected_active_forms(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        registration = source.split(
            'const esp_console_cmd_t deauth_detector_v2_cmd = {', 1
        )[1].split('};', 1)[0]
        self.assertIn("trace", registration)
        self.assertIn("defence", registration)
        self.assertIn("pmkid-decoy", registration)
        self.assertIn("selected", registration.lower())
        v2_line = next(
            line for line in source.splitlines()
            if '{ "deauth_detector_v2",' in line
        )
        self.assertIn("defence", v2_line)
        self.assertIn("pmkid-decoy", v2_line)

    def test_manual_records_safety_limits_and_validation_boundary(self):
        manual = (ROOT / "docs/command-manual.md").read_text(encoding="utf-8")
        required = (
            "deauth_detector_v2 --only 1 3 trace",
            "deauth_detector_v2 --only 1 3 trace defence",
            "deauth_detector_v2 --only 1 3 trace defence pmkid-decoy",
            "Defence requires --only protected scan indices.",
            "WIFI_SECURITY_MODULE_DEAUTH_V2",
            "JANOS_RADIO_OWNER_SECURITY_MONITOR",
            "1000 ms",
            "response_satisfied",
            "20 seconds of inactivity",
            "startup scan channel",
            "10 second",
            "5000 ms",
            "WPA2-PSK/CCMP",
            "PMKID",
            "experimental",
            "suppressed=<n>",
            "observations=<n>",
            "outcome=<responded|observed|idle>",
            "response=<decoy_4way|decoy_pmkid>",
            "750 ms SSID-resolution window",
            "exactly one active scan",
            "20–60 ms active dwell",
            "without replacing the main scan cache",
            "disabled in Defence mode",
            "probe requests",
            "host tests",
            "RF validation",
        )
        for text in required:
            with self.subTest(text=text):
                self.assertIn(text, manual)

    def test_radio_lease_manual_names_defence_owner_and_cleanup(self):
        lease = (ROOT / "docs/janos-radio-lease.md").read_text(encoding="utf-8")
        for text in (
            "DEFENCE",
            "deauth_detector_v2",
            "selected BSSID",
            "raw TX",
            "CLEANUP",
            "QUARANTINED",
            "later global `stop`",
            "bare `reboot`",
        ):
            with self.subTest(text=text):
                self.assertIn(text, lease)

    def test_stop_closes_generation_before_tx_stop_and_releases_after_restore(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        block = source.split("// Stop deauth_detector if active", 1)[1].split(
            "// Stop GPS raw task", 1
        )[0]
        close = block.index("deauth_detector_close_events();")
        request = block.index(
            "deauth_defence_runtime_request_stop(&detector_defence_runtime);"
        )
        disable = block.index("esp_wifi_set_promiscuous(false);")
        restore = block.index(
            "esp_wifi_set_channel(detector_defence_restore_channel"
        )
        release = block.index("deauth_detector_stop_defence_session(")
        self.assertLess(close, request)
        self.assertLess(request, disable)
        self.assertLess(disable, restore)
        self.assertLess(restore, release)


if __name__ == "__main__":
    unittest.main()
