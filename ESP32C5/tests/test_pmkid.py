"""Exercise byte parsing and the actual bounded recorder/publication path."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")), "C compiler required")
class PMKIDTest(unittest.TestCase):
    def run_c(self, name):
        with tempfile.TemporaryDirectory(prefix="janos-pmkid-") as temp:
            temp = Path(temp)
            (temp / "freertos").mkdir()
            for header in ("freertos/FreeRTOS.h", "freertos/queue.h",
                           "freertos/semphr.h", "freertos/task.h",
                           "esp_heap_caps.h", "esp_log.h", "esp_timer.h"):
                (temp / header).write_text('#include "pmkid_host_runtime.h"\n')
            executable = temp / name
            command = [os.environ.get("CC", "gcc"), "-std=c11", "-Wall", "-Wextra",
                       "-Werror", "-D_POSIX_C_SOURCE=200809L",
                       "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                       "-I", str(temp), "-I", str(ROOT / "main"),
                       "-I", str(ROOT / "tests"),
                       "-I", str(ROOT / "components/pcap_serializer/include"),
                       str(ROOT / "tests" / f"{name}.c"),
                       str(ROOT / "main/pmkid_parser.c"), "-o", str(executable)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(executable)], cwd=temp, capture_output=True,
                                    text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            if name == "pmkid_capture_test":
                for expected in ("result=failed reason=no_pmkid_received",
                                 "result=success reason=pmkid_saved",
                                 "result=success reason=already_saved",
                                 "result=failed reason=write_failed",
                                 "result=failed reason=stopped",
                                 "result=not_attempted reason=detector_unavailable",
                                 "method=sta_auth_assoc"):
                    self.assertIn(expected, result.stdout)

    def test_parser(self):
        self.run_c("pmkid_parser_test")

    def test_recorder(self):
        self.run_c("pmkid_capture_test")

    def test_both_capture_paths_and_lifecycle_are_wired(self):
        main = (ROOT / "main/main.c").read_text()
        selected = (ROOT / "main/attack_handshake.c").read_text()
        from test_attack_handshake_helpers import _function
        rx = _function(main, "hs_sniffer_process_packet")
        self.assertLess(rx.index("pmkid_capture_observe"), rx.index("ap->has_existing_file"))
        self.assertLess(rx.index("pmkid_capture_observe"), rx.index("hs_ducb_capture_identity_matches("))
        cleanup = _function(main, "handshake_cleanup")
        self.assertLess(cleanup.index("handshake_quiesce_sniffer_callbacks"),
                        cleanup.index("pmkid_capture_stop"))
        self.assertLess(cleanup.index("attack_handshake_stop"), cleanup.index("pmkid_capture_stop"))
        self.assertIn("pmkid_capture_start(is_bssid_whitelisted)",
                      _function(main, "handshake_attack_task"))
        self.assertIn("[HS-PMKID] started mode=", _function(main, "handshake_attack_task"))
        for name in ("check_handshake_file_exists", "check_handshake_file_exists_by_bssid"):
            self.assertIn("!pmkid_is_capture_filename", _function(main, name))
        self.assertIn("pmkid_capture_observe", _function(selected, "mgmt_frame_handler"))
        self.assertIn("pmkid_capture_observe", _function(selected, "pmkid_data_frame_handler"))
        self.assertIn("&pmkid_data_frame_handler", _function(selected, "attack_handshake_start"))
        self.assertIn("&pmkid_data_frame_handler", _function(selected, "attack_handshake_stop"))
        attempt = _function(main, "attack_network_with_burst")
        self.assertIn("ATTACK_HANDSHAKE_METHOD_PASSIVE", attempt)
        self.assertLess(attempt.index("hs_run_active_pmkid_probes"),
                        attempt.index("attack_handshake_enable_broadcast_deauth"))
        active = _function(main, "hs_run_active_pmkid_probes")
        self.assertIn("HS_PMKID_ACTIVE_ATTEMPTS", active)
        self.assertLess(active.index("pmkid_capture_attempt_begin"),
                        active.index("analyzer_tracked_wifi_connect"))
        self.assertLess(active.index("analyzer_tracked_wifi_connect"),
                        active.index("pmkid_capture_attempt_end"))
        tracked_connect = _function(main, "analyzer_tracked_wifi_connect")
        self.assertIn("analyzer_sta_connect_pending = true", tracked_connect)
        self.assertIn("esp_wifi_connect", tracked_connect)
        self.assertIn("active_phase=%s", active)
        worker = _function(main, "handshake_attack_task_sniffer")
        self.assertIn("phase=before_clients", worker)
        self.assertLess(worker.index("hs_run_active_pmkid_probes"),
                        worker.index("hs_send_targeted_deauth"))
        self.assertIn("ap->pmkid_active_attempts < HS_PMKID_ACTIVE_ATTEMPTS", worker)


if __name__ == "__main__":
    unittest.main()
