"""Deterministic production stack budget for the shared Shield worker."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKER_STACK_BYTES = 5120
REQUIRED_MARGIN_BYTES = 1024
# `main.c` is ESP-IDF-specific and cannot be compiled by this portable host
# harness. Reserve conservative bounded frames for the production worker entry
# and the longest indirect profile hook/callee chain in addition to measured
# portable `.su` frames. The source assertions below keep these reservations
# attached to the exact production calls they cover. A current firmware map is
# still the device-side release gate.
SECURITY_WORKER_FRAME_BUDGET = 256
PROFILE_PLATFORM_HOOK_BUDGET = 1024
DEAUTH_V2_WORKER_HOOK_BUDGET = 1024


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


class WifiShieldStackBudgetTest(unittest.TestCase):
    def _compile_usage(self, source, output):
        compiler = next((shutil.which(name) for name in ("cc", "gcc", "clang")
                         if shutil.which(name)), None)
        flags = ["-std=c11", "-D_POSIX_C_SOURCE=200809L", "-O2", "-fno-inline",
                 "-fno-inline-functions", "-fno-inline-functions-called-once",
                 "-fstack-usage", "-I", str(ROOT / "main")]
        if compiler:
            command = [compiler, *flags, "-c", str(source), "-o", str(output)]
        else:
            self.assertIsNotNone(shutil.which("wsl.exe"),
                                 "host C compiler required")
            flags[-1] = wsl_path(ROOT / "main")
            command = ["wsl.exe", "cc", *flags, "-c", wsl_path(source),
                       "-o", wsl_path(output)]
        built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        self.assertEqual(built.stdout + built.stderr, "")

    @staticmethod
    def _read_usage(path):
        usage = {}
        for line in path.read_text(encoding="utf-8").splitlines():
            match = re.search(r":([^:\t]+)\t(\d+)\t([^\t]+)$", line)
            if match:
                name = re.sub(r"\.(?:constprop|isra|part)(?:\.\d+)?$", "",
                              match.group(1))
                current = usage.get(name)
                size = int(match.group(2))
                if current is None or size > current[0]:
                    usage[name] = (size, match.group(3))
        return usage

    def test_production_consumer_keeps_explicit_worker_margin(self):
        main_source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        self.assertIn("#define SECURITY_WORKER_STACK_BYTES 5120U", main_source)
        self.assertIn(
            "SECURITY_WORKER_STACK_BYTES / sizeof(StackType_t)",
            main_source,
        )
        security_worker = main_source.split(
            "static void security_worker", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("wifi_security_runtime_drain_bounded", security_worker)
        self.assertIn("wifi_shield_worker_poll", security_worker)
        self.assertIn("ulTaskNotifyTake", security_worker)
        deauth_worker = main_source.rsplit(
            "static void deauth_detector_v2_worker_poll", 1)[1].split(
                "\n}", 1)[0]
        for required_call in ("deauth_detector_process_events",
                              "detector_trace_hop_delay_locked",
                              "deauth_detector_channel_hop",
                              "oled_display_update_full"):
            self.assertIn(required_call, deauth_worker)
        process_events = main_source.rsplit(
            "static void deauth_detector_process_events", 1)[1].split(
                "\n}", 1)[0]
        self.assertIn(
            "for (size_t i = 0; i < DETECTOR_EVENT_CAPACITY; ++i)",
            process_events)
        v2_command = main_source.split(
            "static int cmd_deauth_detector_impl", 1)[1].split(
                "static int cmd_deauth_detector(", 1)[0]
        self.assertIn("if (details)", v2_command)
        self.assertIn("goto detector_receiver_running", v2_command)
        self.assertEqual(v2_command.count('"deauth_det"'), 1,
                         "V2 must reuse the shared worker, not add a task")
        profile_retune = main_source.split(
            "static bool wifi_shield_profile_retune", 1)[1].split(
                "\n}\n", 1)[0]
        for required_call in ("wifi_security_runtime_get_status",
                              "status.stopping", "status.module == module",
                              "status.generation == generation",
                              "security_channel_tune"):
            self.assertIn(required_call, profile_retune)
        channel_tune = main_source.split(
            "static bool security_channel_tune", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("esp_wifi_set_channel", channel_tune)
        for hook, required_call in (
                ("wifi_shield_monotonic_us", "esp_timer_get_time"),
                ("wifi_shield_radio_enter", "xSemaphoreTake"),
                ("wifi_shield_state_enter", "xSemaphoreTake"),
                ("wifi_shield_runtime_status",
                 "wifi_security_runtime_get_status")):
            body = main_source.split(hook, 1)[1].split("\n}\n", 1)[0]
            self.assertIn(required_call, body, hook)
        sources = [
            ROOT / "main/wifi_shield.c",
            ROOT / "main/wifi_shield_wire.c",
            ROOT / "main/wifi_shield_campaign.c",
            ROOT / "main/wifi_shield_time.c",
            ROOT / "main/wifi_trust_core.c",
            ROOT / "main/sniffer_extended.c",
            ROOT / "main/wps_guard_core.c",
            ROOT / "main/sae_guard_parser.c",
            ROOT / "main/sae_guard_core.c",
            ROOT / "main/csa_detector_core.c",
            ROOT / "main/deauth_defence_runtime.c",
            ROOT / "main/deauth_defence_core.c",
            ROOT / "main/wpa_decoy.c",
            ROOT / "main/wpa_crypto_primitives.c",
            ROOT / "main/crack_worker_sw_sha1.c",
        ]
        with tempfile.TemporaryDirectory(prefix="janos-shield-stack-") as directory:
            directory = Path(directory)
            measured = {}
            qualifiers = {}
            by_source = {}
            for source in sources:
                output = directory / f"{source.stem}.o"
                self._compile_usage(source, output)
                current = self._read_usage(output.with_suffix(".su"))
                by_source[source.name] = {
                    name: size for name, (size, _qualifier) in current.items()
                }
                measured.update({
                    name: size for name, (size, _qualifier) in current.items()
                })
                qualifiers.update({
                    name: qualifier
                    for name, (_size, qualifier) in current.items()
                })

        required = (
            "shield_feature_consume",
            "shield_feature_consume_modules",
            "shield_qualify_event_locked",
            "wifi_shield_campaign_observe",
            "wifi_shield_time_resolve",
            "journal_submit",
            "publish_event",
            "wifi_shield_format_event",
            "publish_line",
            "presentation_record_event",
            "wifi_trust_table_observe_with_workspace",
            "wifi_trust_builder_snapshot",
            "wifi_trust_diff",
            "wifi_trust_builder_conflict_events",
            "wifi_trust_malformed_events",
            "sx_parse",
            "wps_guard_decode_fragment",
            "wps_guard_observe",
            "sae_guard_parse",
            "sae_guard_observe",
            "csa_parse",
            "wifi_shield_consume_compact",
            "defence_process_observation",
            "defence_tune_adapter",
            "wifi_shield_channel_lock_running",
            "wifi_shield_worker_poll",
            "profile_worker_poll",
            "defence_telemetry_adapter",
            "publish_line_internal",
            "deauth_defence_runtime_process",
            "emit_trigger",
            "emit_tx",
            "emit_suppression",
            "finish_error",
            "wpa_decoy_build_pair",
            "wpa_decoy_build_pmkid_m1",
            "build_eapol_key",
            "janos_wpa_ptk_sha1",
            "janos_wpa_eapol_mic_v2",
            "janos_wpa_pmkid",
            "crack_worker_sw_hmac_sha1",
            "cw_seed",
            "cw_seed_hmac",
            "cw_sw_sha1_update",
            "cw_sw_sha1_finish",
            "cw_sw_sha1_process",
        )
        missing = [name for name in required if name not in measured]
        if missing and os.environ.get("JANOS_REPORT_STACK"):
            print("stack symbols:", sorted(measured))
        self.assertEqual(missing, [])
        self.assertEqual(
            [name for name in required
             if qualifiers[name] not in ("static", "dynamic,bounded")],
            [], "reachable worker frames must have deterministic bounds")

        shield_frame = measured["shield_feature_consume"]
        self.assertLessEqual(shield_frame, 1024,
                             "Shield frame leaves too little transitive margin")

        passive_required = (
            "wifi_trust_table_observe_with_workspace",
            "wifi_trust_builder_snapshot",
            "wifi_trust_diff",
            "wifi_trust_builder_conflict_events",
            "wifi_trust_malformed_events",
            "sx_parse",
            "wps_guard_decode_fragment",
            "wps_guard_observe",
            "sae_guard_parse",
            "sae_guard_observe",
            "csa_parse",
        )
        direct_callees = [measured[name] for name in passive_required]
        # Account conservatively for one direct callee plus its largest helper
        # in the same Trust translation unit. Legacy wrappers intentionally use
        # caller stack and are not reachable from Shield.
        trust_legacy_wrappers = {
            "wifi_trust_builder_observe", "wifi_trust_table_observe"
        }
        trust_internal = [
            size for name, size in by_source["wifi_trust_core.c"].items()
            if name not in trust_legacy_wrappers and name not in required
        ]
        event_publish_path = measured["publish_event"] + max(
            measured["wifi_shield_format_event"],
            measured["publish_line"] + measured["publish_line_internal"],
            measured["presentation_record_event"],
        )
        qualify_path = measured["shield_qualify_event_locked"] + max(
            measured["wifi_shield_campaign_observe"],
            measured["wifi_shield_time_resolve"],
            measured["journal_submit"],
        )
        passive_peak = SECURITY_WORKER_FRAME_BUDGET + shield_frame + \
            measured["shield_feature_consume_modules"] + \
            max(max(direct_callees) + max(trust_internal),
                event_publish_path, qualify_path)

        sha_update = measured["cw_sw_sha1_update"] + \
            measured["cw_sw_sha1_process"]
        sha_finish = measured["cw_sw_sha1_finish"] + sha_update
        hmac_tail = measured["crack_worker_sw_hmac_sha1"] + max(
            measured["cw_seed"] + sha_update,
            measured["cw_seed_hmac"] + max(sha_update, sha_finish))
        pair_path = measured["wpa_decoy_build_pair"] + \
            measured["build_eapol_key"] + max(
            measured["janos_wpa_ptk_sha1"],
            measured["janos_wpa_eapol_mic_v2"]) + hmac_tail
        pmkid_path = measured["wpa_decoy_build_pmkid_m1"] + \
            max(measured["janos_wpa_pmkid"] + hmac_tail,
                measured["build_eapol_key"])
        tune_path = measured["defence_tune_adapter"] + \
            measured["wifi_shield_channel_lock_running"]
        publisher_path = measured["defence_telemetry_adapter"] + \
            measured["publish_line_internal"]
        telemetry_path = max(
            measured["emit_trigger"] + publisher_path,
            measured["emit_tx"] + publisher_path,
            measured["emit_suppression"] + publisher_path,
            measured["finish_error"] + measured["emit_tx"] + publisher_path)
        active_caller = max(measured["wifi_shield_consume_compact"],
                            measured["shield_feature_consume"])
        active_peak = SECURITY_WORKER_FRAME_BUDGET + active_caller + \
            measured["defence_process_observation"] + \
            measured["deauth_defence_runtime_process"] + \
            max(pair_path, pmkid_path, tune_path, telemetry_path)
        profile_peak = SECURITY_WORKER_FRAME_BUDGET + \
            measured["wifi_shield_worker_poll"] + \
            measured["profile_worker_poll"] + max(
                PROFILE_PLATFORM_HOOK_BUDGET,
                DEAUTH_V2_WORKER_HOOK_BUDGET)
        v2_active_peak = SECURITY_WORKER_FRAME_BUDGET + \
            measured["wifi_shield_worker_poll"] + \
            measured["profile_worker_poll"] + \
            DEAUTH_V2_WORKER_HOOK_BUDGET + \
            measured["deauth_defence_runtime_process"] + \
            max(pair_path, pmkid_path, tune_path, telemetry_path)
        transitive_peak = max(passive_peak, active_peak, profile_peak,
                              v2_active_peak)
        margin = WORKER_STACK_BYTES - transitive_peak
        if os.environ.get("JANOS_REPORT_STACK"):
            print(f"shield stack: passive={passive_peak} active={active_peak} "
                  f"profile={profile_peak} v2_active={v2_active_peak} "
                  f"peak={transitive_peak} margin={margin} "
                  f"worker_budget={SECURITY_WORKER_FRAME_BUDGET} "
                  f"profile_hook_budget={PROFILE_PLATFORM_HOOK_BUDGET} "
                  f"deauth_v2_hook_budget={DEAUTH_V2_WORKER_HOOK_BUDGET} "
                  f"caller={active_caller} bridge={measured['defence_process_observation']} "
                  f"runtime={measured['deauth_defence_runtime_process']} "
                  f"event_publish={event_publish_path} qualify={qualify_path}")
        self.assertGreaterEqual(
            margin, REQUIRED_MARGIN_BYTES,
            f"worker stack peak={transitive_peak} margin={margin}; "
            f"passive={passive_peak} active={active_peak} "
            f"profile={profile_peak} v2_active={v2_active_peak} "
            f"shield={shield_frame} "
            f"worker_budget={SECURITY_WORKER_FRAME_BUDGET} "
            f"profile_hook_budget={PROFILE_PLATFORM_HOOK_BUDGET} "
            f"deauth_v2_hook_budget={DEAUTH_V2_WORKER_HOOK_BUDGET} "
            f"direct_max={max(direct_callees)} "
            f"trust_helper_max={max(trust_internal)} pair={pair_path} "
            f"pmkid={pmkid_path} tune={tune_path} telemetry={telemetry_path} "
            f"qualify={qualify_path}")
        shield_source = (ROOT / "main/wifi_shield.c").read_text(encoding="utf-8")
        state = shield_source.split("struct wifi_shield_state", 1)[1].split("};", 1)[0]
        consume_modules = shield_source.split(
            "static bool shield_feature_consume_modules", 1)[1].split("\n}\n", 1)[0]
        publish_event = shield_source.split(
            "static bool publish_event", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("wifi_shield_journal_record_t journal_scratch[2]", state)
        self.assertNotIn("wifi_shield_journal_record_t health_record", consume_modules)
        self.assertNotIn("wifi_shield_journal_record_t event_record", publish_event)


if __name__ == "__main__":
    unittest.main()
