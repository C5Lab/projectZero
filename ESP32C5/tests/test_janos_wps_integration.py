from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
COMPONENT = ROOT / "components" / "janos_wps"
WPS_PRIVATE = COMPONENT / "private"
TRANSPORT = WPS_PRIVATE / "transport"
WORKFLOW = WPS_PRIVATE / "workflow"


def compile_and_run(name, sources, include_dirs=(), extra_flags=()):
    with tempfile.TemporaryDirectory() as directory:
        executable = Path(directory) / name
        requested = os.environ.get("CC", "")
        compiler = shutil.which(requested) if requested else None
        if compiler is None:
            compiler = next((shutil.which(item) for item in ("cc", "gcc", "clang")
                             if shutil.which(item)), None)
        if compiler is not None:
            command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                       "-pedantic", *extra_flags]
            for include_dir in include_dirs:
                command.extend(("-I", str(include_dir)))
            command.extend(str(source) for source in sources)
            command.extend(("-o", str(executable)))
            run_command = [str(executable)]
        elif shutil.which("wsl.exe"):
            def wsl_path(path):
                resolved = Path(path).resolve()
                return (f"/mnt/{resolved.drive.rstrip(':').lower()}/"
                        f"{resolved.relative_to(resolved.anchor).as_posix()}")
            command = ["wsl.exe", "cc", "-std=c11", "-Wall", "-Wextra",
                       "-Werror", "-pedantic", *extra_flags]
            for include_dir in include_dirs:
                command.extend(("-I", wsl_path(include_dir)))
            command.extend(wsl_path(source) for source in sources)
            command.extend(("-o", wsl_path(executable)))
            run_command = ["wsl.exe", wsl_path(executable)]
        else:
            raise AssertionError("host C compiler required")
        built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        if built.returncode != 0:
            raise AssertionError(built.stdout + built.stderr)
        result = subprocess.run(run_command, cwd=ROOT,
                                capture_output=True, text=True)
        if result.returncode != 0:
            raise AssertionError(result.stdout + result.stderr)
        return result.stdout.strip()


class JanosWpsBuildGraphTest(unittest.TestCase):
    def test_component_reuses_verified_sources_without_standalone_entrypoint(self):
        cmake_path = COMPONENT / "CMakeLists.txt"
        self.assertTrue(cmake_path.is_file(), "missing janos_wps component")
        cmake = cmake_path.read_text(encoding="utf-8")

        expected_sources = (
            "lab_secret.c",
            "lab_result_store.c",
            "lab_wps_session.c",
            "lab_wps_session_esp.c",
            "lab_wps_rx_gate.c",
            "session_policy.c",
            "session_frames.c",
            "pin_crypto.c",
            "pin_protocol.c",
            "protocol.c",
            "m3_protocol.c",
            "wsc_fragment.c",
            "wps_transport_core.c",
        )
        for source in expected_sources:
            self.assertIn(source, cmake)
        self.assertNotIn("lab_main.c", cmake)
        self.assertNotRegex(cmake, r"(?:probe|stress|campaign)_main\.c")

        main_cmake = (ROOT / "main" / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertRegex(main_cmake, r"\bjanos_wps\b")

    def test_build_contract_is_pinned_and_known_pin_only(self):
        header_path = COMPONENT / "include" / "janos_wps_build.h"
        self.assertTrue(header_path.is_file(), "missing WPS build contract")
        header = header_path.read_text(encoding="utf-8")
        self.assertIn("JANOS_WPS_IDF_MAJOR 6", header)
        self.assertIn("JANOS_WPS_IDF_MINOR 0", header)
        self.assertIn("JANOS_WPS_IDF_PATCH 1", header)

        transport = (COMPONENT / "janos_wps_transport.c").read_text(
            encoding="utf-8")
        self.assertIn('#include "janos_wps_build.h"', transport)
        self.assertIn("ESP_IDF_VERSION_MAJOR != JANOS_WPS_IDF_MAJOR", transport)
        self.assertIn("ESP_IDF_VERSION_MINOR != JANOS_WPS_IDF_MINOR", transport)
        self.assertIn("ESP_IDF_VERSION_PATCH != JANOS_WPS_IDF_PATCH", transport)

        cmake = (COMPONENT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertNotIn("JANOS_WPS_EXPECTED_IDF_", cmake)

        stub = (ROOT / "tests" / "host_stubs" / "wps_transport" /
                "esp_idf_version.h").read_text(encoding="utf-8")
        self.assertIn("ESP_IDF_VERSION_PATCH 1", stub)
        self.assertRegex(header, r"JANOS_WPS_FEATURE_KNOWN_PIN\s+\(1u\s*<<\s*0\)")
        self.assertRegex(header, r"JANOS_WPS_FEATURE_FRAGMENTATION\s+\(1u\s*<<\s*1\)")
        self.assertRegex(header, r"JANOS_WPS_FEATURE_SECRET_VAULT\s+\(1u\s*<<\s*2\)")
        self.assertRegex(header, r"JANOS_WPS_FEATURE_RESULT_STORE\s+\(1u\s*<<\s*3\)")
        self.assertIn("JANOS_WPS_FEATURES", header)
        self.assertNotRegex(header, r"JANOS_WPS_FEATURES[^\n]*(PIXIE|JWPS|CAMPAIGN)")


class JanosWpsMemoryTest(unittest.TestCase):
    def test_memory_classes_fail_closed_and_wipe_secrets(self):
        output = compile_and_run(
            "janos_wps_memory_test",
            [COMPONENT / "test" / "janos_wps_memory_test.c",
             COMPONENT / "janos_wps_memory.c"],
            [COMPONENT / "include"],
        )
        self.assertEqual(output, "PASS: JanOS WPS memory policy")


class JanosRadioLeaseTest(unittest.TestCase):
    def test_owner_generation_cancel_and_quarantine_contract(self):
        output = compile_and_run(
            "janos_radio_lease_test",
            [COMPONENT / "test" / "janos_radio_lease_test.c",
             COMPONENT / "janos_radio_lease.c"],
            [COMPONENT / "include"],
        )
        self.assertEqual(output, "PASS: JanOS shared radio lease")

    def test_concurrent_analyzer_and_wps_acquire_have_one_winner(self):
        output = compile_and_run(
            "janos_radio_lease_concurrency_test",
            [COMPONENT / "test" / "janos_radio_lease_concurrency_test.c",
             COMPONENT / "janos_radio_lease.c"],
            [COMPONENT / "include"],
            ["-pthread"],
        )
        self.assertEqual(output,
                         "PASS: JanOS shared radio lease concurrency")

    def test_analyzer_and_ota_use_the_shared_lease(self):
        analyzer = (ROOT / "main" / "wifi_analyzer.c").read_text(encoding="utf-8")
        main = (ROOT / "main" / "main.c").read_text(encoding="utf-8")
        self.assertLess(analyzer.index("s_hooks.lease_acquire"),
                        analyzer.index("s_state = WFA_PREPARING"))
        self.assertIn("s_hooks.lease_mark_running", analyzer)
        self.assertIn("s_hooks.lease_cancel", analyzer)
        self.assertIn("s_hooks.lease_release", analyzer)
        self.assertIn("janos_radio_lease_snapshot(&janos_radio_lease)", main)
        ota = main[main.index("static bool ota_start_check_source"):]
        self.assertLess(ota.index("janos_radio_lease_snapshot"),
                        ota.index("ota_check_in_progress = true"))


class JanosWpsServiceTest(unittest.TestCase):
    def test_async_known_pin_service_and_secret_lifecycle(self):
        output = compile_and_run(
            "janos_wps_service_test",
            [COMPONENT / "test" / "janos_wps_service_test.c",
             COMPONENT / "janos_wps_service.c",
             COMPONENT / "janos_wps_memory.c",
             COMPONENT / "janos_radio_lease.c",
             WORKFLOW / "lab_secret.c"],
            [COMPONENT / "include"],
        )
        self.assertEqual(output, "PASS: JanOS asynchronous known-PIN service")

    def test_main_routes_wps_through_shared_runtime_and_radio_lease(self):
        main = (ROOT / "main" / "main.c").read_text(encoding="utf-8")
        self.assertIn('#include "janos_wps_runtime.h"', main)
        self.assertIn('strcmp(cmd_context->command, "wps") == 0', main)
        self.assertIn('strcmp(cmd_context->command, "secret") == 0', main)
        self.assertIn('.command = "wps"', main)
        self.assertIn('.func = &janos_wps_command', main)
        self.assertIn('.command = "secret"', main)
        self.assertIn('.func = &janos_wps_secret_command', main)
        self.assertRegex(main,
                         r"janos_wps_runtime_init\(\s*&janos_radio_lease")
        self.assertNotIn("assert(janos_wps_runtime_init", main)
        self.assertIn("janos_wps_runtime_stop(5000)", main)
        runtime = (COMPONENT / "janos_wps_runtime.c").read_text(encoding="utf-8")
        self.assertRegex(runtime,
                         r"janos_wps_secure_wipe\(argv\[3\],\s*strlen\(argv\[3\]\)\)")
        self.assertIn("linenoiseHistoryFree();", main)
        self.assertIn("bulk_peak_bytes", runtime)
        self.assertIn("secret_peak_bytes", runtime)

        handler_marker = main.index("// --- Wi-Fi event handler ---")
        wifi_handler = main[handler_marker:
                            main.index("static void ip_event_handler(void *event_handler_arg,",
                                       handler_marker)]
        self.assertIn("JANOS_RADIO_OWNER_WPS", wifi_handler)

    def test_transport_borrows_driver_and_restores_mac_without_deinit(self):
        transport = (COMPONENT / "janos_wps_transport.c").read_text(encoding="utf-8")
        self.assertIn("esp_wifi_stop", transport)
        self.assertIn("esp_wifi_set_mac", transport)
        self.assertIn("esp_wifi_get_mac", transport)
        self.assertNotIn("esp_wifi_deinit", transport)
        self.assertNotIn("sta_mac_policy_store", transport)
        self.assertNotRegex(transport, r"\bnvs_[a-zA-Z0-9_]*\s*\(")

        runtime = (COMPONENT / "janos_wps_runtime.c").read_text(encoding="utf-8")
        execute = runtime[runtime.index("static bool service_execute"):]
        self.assertLess(execute.index("esp_wifi_get_mac(WIFI_IF_STA, current_mac)"),
                        execute.index("lab_workflows_execute"))
        self.assertIn("memcmp(current_mac, state->effective_boot_mac", execute)

        core = (TRANSPORT / "wps_transport_core.c").read_text(encoding="utf-8")
        cancel = core[core.index("bool wps_transport_cancel"):]
        self.assertLess(cancel.index("transport->original_mac"),
                        cancel.index("ops->deinit"))

        service = (COMPONENT / "janos_wps_service.c").read_text(encoding="utf-8")
        worker = service[service.index("void janos_wps_service_run_pending"):]
        self.assertLess(worker.index("execute_verify"),
                        worker.index("janos_radio_lease_finish_cleanup"))


if __name__ == "__main__":
    unittest.main()
