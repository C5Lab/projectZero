"""Compile and run the portable Wi-Fi Shield lifecycle contract."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


class WifiShieldIntegrationTest(unittest.TestCase):
    def test_rsn_only_strong_cipher_suites_are_not_accepted_for_wpa(self):
        source = (ROOT / "main/wifi_shield.c").read_text(encoding="utf-8")
        cipher = source.split("static bool shield_cipher_suite(", 1)[1]
        cipher = cipher.split("\n}\n", 1)[0]
        strong = cipher.split("case 8U:", 1)[1].split("default:", 1)[0]
        self.assertIn("return rsn;", strong)

    def test_start_gates_prior_idle_publishers_before_session_reset(self):
        source = (ROOT / "main/wifi_shield.c").read_text(encoding="utf-8")
        block = source.split("static int start_command(", 1)[1]
        block = block.split("size_t wifi_shield_state_size(", 1)[0]
        self.assertIn("shield.output_inflight", block)
        self.assertLess(block.index("shield.output_inflight"),
                        block.index("&shield.output_failed, false"))

    def _compiler(self):
        requested = os.environ.get("CC", "")
        compiler = shutil.which(requested) if requested else None
        return compiler or next((shutil.which(name) for name in
                                 ("cc", "gcc", "clang")
                                 if shutil.which(name)), None)

    def _command(self, compiler, sources, output, compile_only=False):
        flags = ["-std=c11", "-D_POSIX_C_SOURCE=200809L",
                 "-Wall", "-Wextra", "-Werror", "-pedantic",
                 "-pthread"]
        if os.environ.get("JANOS_TEST_SANITIZERS"):
            flags += ["-fsanitize=address,undefined",
                      "-fno-sanitize-recover=all",
                      "-fno-omit-frame-pointer",
                      "-DJANOS_TEST_FREE_AFTER_RELEASE=1"]
        if not compile_only:
            flags += ["-Wl,--wrap=malloc", "-Wl,--wrap=calloc",
                      "-Wl,--wrap=realloc", "-Wl,--wrap=free"]
        if compiler:
            command = [compiler, *flags, "-I", str(ROOT / "main")]
            command += list(map(str, sources))
            command += (["-c", "-o", str(output)] if compile_only
                        else ["-o", str(output)])
            return command, None if compile_only else [str(output)]
        self.assertIsNotNone(shutil.which("wsl.exe"),
                             "host C compiler required (native or WSL)")
        command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main")]
        command += list(map(wsl_path, sources))
        command += (["-c", "-o", wsl_path(output)] if compile_only
                    else ["-o", wsl_path(output)])
        return command, None if compile_only else ["wsl.exe", wsl_path(output)]

    def test_public_header_is_self_contained(self):
        self.assertTrue((ROOT / "main/wifi_shield.h").is_file(),
                        "missing portable Shield public header")
        with tempfile.TemporaryDirectory(prefix="janos-shield-header-") as directory:
            source = Path(directory) / "public_header.c"
            source.write_text(
                '#include "wifi_shield.h"\n'
                'static wifi_trust_profile_t profile;\n'
                'int main(void) { return (int)(sizeof(profile) == 0U || '
                'wifi_shield_retained_size() == 0U); }\n',
                encoding="utf-8")
            output = Path(directory) / "public_header.o"
            command, _ = self._command(self._compiler(), [source], output, True)
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            self.assertEqual(built.stdout + built.stderr, "")

    def test_bridge_keeps_accepted_default_builders(self):
        source = (ROOT / "main/wifi_shield.c").read_text(encoding="utf-8")
        prepare = source.split("static bool defence_prepare", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn(".build_pair = NULL", prepare)
        self.assertIn(".build_pmkid = NULL", prepare)

    def test_v2_stop_restores_radio_before_terminal_journal_and_retains_writer(self):
        source = (ROOT / "main/wifi_shield.c").read_text(encoding="utf-8")
        stop = source.split("bool wifi_shield_stop(", 1)[1].split(
            "\nint wifi_shield_command(", 1)[0]
        self.assertIn("SHIELD_PHASE_STORAGE_PENDING", stop)
        self.assertIn("shield_submit_terminal_bounded", stop)
        self.assertIn("shield_finish_journal", stop)
        cleanup = stop.index("finish_radio_cleanup")
        terminal = stop.index("shield_submit_terminal_bounded", cleanup)
        self.assertLess(cleanup, terminal)
        finish = stop.index("shield_finish_journal", terminal)
        self.assertLess(terminal, finish)
        self.assertLess(finish,
                        stop.index("wipe_and_release_state", finish))

    def test_v2_read_only_commands_have_dedicated_handlers(self):
        source = (ROOT / "main/wifi_shield.c").read_text(encoding="utf-8")
        command = source.split("int wifi_shield_command(", 1)[1].split(
            "\nstatic bool publish_event(", 1)[0]
        self.assertIn("WIFI_SHIELD_COMMAND_REPORT", command)
        self.assertIn("WIFI_SHIELD_COMMAND_LOG_STATUS", command)
        self.assertIn("publish_v2_report", command)
        self.assertIn("publish_v2_log_status", command)

    def test_lifecycle_failures_cleanup_generation_and_no_heap(self):
        self.assertTrue((ROOT / "main/wifi_shield.c").is_file(),
                        "missing portable Shield lifecycle implementation")
        with tempfile.TemporaryDirectory(prefix="janos-shield-life-") as directory:
            executable = Path(directory) / "wifi_shield_integration_test"
            sources = [ROOT / "tests/wifi_shield_integration_test.c",
                       ROOT / "main/wifi_shield.c",
                       ROOT / "main/wifi_shield_cli.c",
                       ROOT / "main/wifi_shield_channel.c",
                       ROOT / "main/wifi_shield_core.c",
                       ROOT / "main/wifi_shield_wire.c",
                       ROOT / "main/wifi_shield_time.c",
                       ROOT / "main/wifi_shield_campaign.c",
                       ROOT / "main/wifi_shield_ap_health.c",
                       ROOT / "main/wifi_shield_journal.c",
                       ROOT / "main/wifi_shield_wps.c",
                       ROOT / "main/wifi_security_frame.c",
                       ROOT / "main/wps_guard.c",
                       ROOT / "main/wps_guard_core.c",
                       ROOT / "main/wps_guard_wire.c",
                       ROOT / "main/sae_guard.c",
                       ROOT / "main/sae_guard_wire.c",
                       ROOT / "main/sae_guard_parser.c",
                       ROOT / "main/sae_guard_core.c",
                       ROOT / "main/wifi_trust_core.c",
                       ROOT / "main/sniffer_extended.c",
                       ROOT / "main/pmkid_probe_detector.c",
                       ROOT / "main/csa_detector_core.c"]
            sources += [ROOT / "main/deauth_defence_runtime.c",
                        ROOT / "main/deauth_defence_core.c",
                        ROOT / "main/wpa_decoy.c",
                        ROOT / "main/wpa_crypto_primitives.c",
                        ROOT / "main/crack_worker_sw_sha1.c"]
            command, run = self._command(self._compiler(), sources, executable)
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            self.assertEqual(built.stdout + built.stderr, "")
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                result.stdout,
                "wifi shield lifecycle: PASS (91 scenarios; heap=0; tx=0; poison=clean)\n")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
