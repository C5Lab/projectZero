"""Real extracted ESP callback plus portable two-lane runtime; no RF or firmware."""
from pathlib import Path
import unittest
from test_sniffer_extended import function
import test_wifi_security_runtime as runtime_tests

ROOT = Path(__file__).resolve().parents[1]


def detector_enum(source):
    start = source.index("typedef enum {\n    DETECTOR_EVENT_DEAUTH")
    end = source.index("} detector_event_kind_t;", start)
    return source[start:end + len("} detector_event_kind_t;")]


class WifiShieldRuntimeIntegrationTest(unittest.TestCase):
    def test_callback_routing_fairness_generation_stop_and_worker(self):
        self.run_harness()

    def test_short_sae_auth_reaches_full_frame_worker(self):
        self.run_harness(("short-sae",))

    def test_ht_control_sae_uses_auth_body_offset(self):
        self.run_harness(("ht-sae",))

    def test_callback_uses_monotonic_clock_for_response_latency(self):
        self.run_harness(("clock-domain",))

    def test_beacon_time_and_health_are_worker_only(self):
        source = (ROOT / "main/wifi_shield.c").read_text(encoding="utf-8")
        worker = source.split("static bool observe_beacon_locked(", 1)[1]
        worker = worker.split("\nstatic void defence_emit_association_complete", 1)[0]
        self.assertIn("wifi_shield_time_exact", worker)
        self.assertIn("wifi_shield_ap_health_observe_beacon", worker)
        callback_source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        callback = function(callback_source, "wifi_security_promiscuous_callback")
        self.assertNotIn("wifi_shield_time_exact", callback)
        self.assertNotIn("wifi_shield_ap_health_observe_beacon", callback)
        self.assertNotIn("journal_", callback)

    def run_harness(self, arguments=()):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        names = ("security_shield_kind", "security_shield_data_candidate",
                 "security_shield_submit",
                 "wifi_security_promiscuous_callback", "security_worker_stop")
        for name in names:
            self.assertTrue(name + "(" in source, "missing Shield callback routing: " + name)
        functions = "\n".join(function(source, name) for name in names)
        for forbidden in ("malloc(", "calloc(", "realloc(", "printf(", "ESP_LOG",
                          "MY_LOG", "esp_wifi_set_channel(", "esp_wifi_80211_tx(",
                          "uart_", "fwrite(", "mbedtls_", "wifi_security_decode(",
                          "csa_format_line(", "snprintf(", "heap_caps_"):
            self.assertNotIn(forbidden, functions)
        harness = (ROOT / "tests/wifi_shield_runtime_integration_test.c").read_text(encoding="utf-8")
        harness = harness.replace("/* DETECTOR ENUM */", detector_enum(source))
        harness = harness.replace("/* EXTRACTED CALLBACK */", functions)
        runner = runtime_tests.WifiSecurityRuntimeTest()
        output = runner.compile_adapter(harness, link_runtime=True, arguments=arguments)
        self.assertEqual(output.strip(), "PASS: Shield two bounded RX lanes")


if __name__ == "__main__":
    unittest.main()
