"""Behavior and integration tests for permanent feature storage in PSRAM."""

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


class PsramStorageTest(unittest.TestCase):
    def test_transactional_allocator_rolls_back_without_internal_fallback(self):
        with tempfile.TemporaryDirectory(prefix="janos-psram-storage-") as directory:
            executable = Path(directory) / "psram_storage_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            sources = [ROOT / "tests/psram_storage_test.c",
                       ROOT / "main/janos_psram_storage.c"]
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"),
                                     "host C compiler required")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout.strip(),
                             "PASS: transactional PSRAM storage")

    def test_large_feature_storage_is_not_static_internal_bss(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        router = (ROOT / "main/router_audit.c").read_text(encoding="utf-8")
        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")

        self.assertIn('"janos_psram_storage.c"', cmake)
        self.assertIn("MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT", main)
        self.assertIn("janos_psram_allocate_all", main)
        self.assertIn("heap_caps_aligned_calloc", main)
        self.assertIn(".alignment = portBYTE_ALIGNMENT", main)
        for name in (
            "wps_guard_output_queue_buffer", "sae_guard_output_queue_buffer",
            "wifi_trust_output_queue_buffer", "wifi_trust_control_queue_buffer",
            "wps_guard_output_task_stack", "sae_guard_output_task_stack",
            "wifi_trust_output_task_stack", "wifi_trust_control_task_stack",
            "wifi_shield_state_storage", "wifi_shield_event_ring",
            "wifi_shield_output_queue_buffer", "wifi_shield_output_task_stack",
            "wifi_shield_retained_storage",
        ):
            self.assertRegex(main, rf"static\s+[A-Za-z0-9_]+\s+\*{name}\s*;")
            self.assertNotRegex(main, rf"static\s+[A-Za-z0-9_]+\s+{name}\s*\[")

        self.assertRegex(main, r"wifi_security_runtime_t\s+\*runtime\s*;")
        self.assertRegex(main, r"StackType_t\s+\*worker_stack\s*;")
        self.assertNotRegex(router,
                            r"static\s+router_audit_command_state_t\s+command_state\s*;")
        self.assertRegex(router,
                         r"static\s+router_audit_command_state_t\s+\*command_state\s*;")
        permanent = main.split("static bool init_feature_psram_storage", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn(".destination = &wifi_shield_retained_storage", permanent)
        self.assertIn(".size = wifi_shield_retained_size()", permanent)
        initialize = main.split(
            "ESP_ERROR_CHECK(wifi_shield_init(", 1)[1].split("?", 1)[0]
        self.assertIn("wifi_shield_retained_storage", initialize)
        self.assertIn("wifi_shield_retained_size()", initialize)

    def test_shield_bundle_is_per_start_transactional_spiram(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")
        bundle = (ROOT / "main/wifi_shield_storage_bundle.c").read_text(
            encoding="utf-8")
        self.assertRegex(main, r"#define WIFI_SHIELD_OUTPUT_QUEUE_DEPTH\s+8U")
        self.assertRegex(main, r"#define WIFI_SHIELD_OUTPUT_STACK_BYTES\s+4096U")
        self.assertIn("static bool wifi_shield_storage_acquire", main)
        self.assertIn("static void wifi_shield_storage_release", main)
        self.assertIn('"wifi_shield_storage_bundle.c"', cmake)
        self.assertIn('"wifi_shield_output_platform.c"', cmake)
        layout = main.split("static wifi_shield_storage_layout_t wifi_shield_storage_layout", 1)[1].split(
            "\n}\n", 1)[0]
        for required in ("wifi_shield_state_size()",
                         "WIFI_SHIELD_COMPACT_EVENT_CAPACITY",
                         "WIFI_SHIELD_OUTPUT_QUEUE_DEPTH",
                         "WIFI_SHIELD_OUTPUT_STACK_BYTES",
                         "sizeof(*wifi_shield_journal_platform)",
                         "portBYTE_ALIGNMENT", "MALLOC_CAP_SPIRAM",
                         "MALLOC_CAP_8BIT"):
            self.assertIn(required, layout)
        acquire = main.split("static bool wifi_shield_storage_acquire", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("wifi_shield_storage_bundle_acquire", acquire)
        self.assertNotIn("MALLOC_CAP_INTERNAL", acquire)
        self.assertIn("janos_psram_allocate_all", bundle)
        self.assertIn("janos_psram_release_all", bundle)
        self.assertRegex(
            main,
            r"static\s+wifi_shield_journal_platform_t\s+"
            r"\*wifi_shield_journal_platform\s*;")
        self.assertNotRegex(
            main,
            r"static\s+wifi_shield_journal_platform_t\s+"
            r"wifi_shield_journal_platform\s*;")

        release = main.split("static void wifi_shield_storage_release", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("if (!wifi_security_runtime_detach_compact", release)
        self.assertIn("abort()", release)
        self.assertIn("wifi_shield_storage_bundle_release", release)
        self.assertLess(release.index("wifi_security_runtime_detach_compact"),
                        release.index("wifi_shield_storage_bundle_release"))
    def test_shield_platform_scan_and_publisher_fail_closed(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        scan = main.split("static bool wifi_shield_scan_all", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("analyzer_host_prepare_wifi()", scan)
        self.assertLess(scan.index("analyzer_host_prepare_wifi()"),
                        scan.index("esp_wifi_scan_start"))

        target = main.split("static void wifi_shield_copy_target", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("record->authmode == WIFI_AUTH_WPA2_PSK", target)
        self.assertIn("record->pairwise_cipher == WIFI_CIPHER_TYPE_CCMP", target)

        start = main.split("static wifi_security_session_result_t wifi_shield_start_radio", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("WIFI_SECURITY_SESSION_JOIN_TIMEOUT", start)
        self.assertIn("wifi_shield_output_task_handle", start)
        self.assertIn("wifi_security_runtime_detach_compact", start)
        self.assertIn("wifi_security_platform_abort_shield_scan", start)

        finish = main.split("static bool wifi_shield_finish_radio_cleanup", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("wifi_security_runtime_platform_finish_cleanup", finish)
        self.assertIn("wifi_security_runtime_detach_compact", finish)

        hooks = main.split("static const wifi_shield_runtime_hooks_t wifi_shield_runtime_hooks", 1)[1].split(
            "\n};", 1)[0]
        for required in (".storage_acquire", ".storage_release", ".scan_all",
                         ".scan_snapshot", ".trust_snapshot", ".reserve_scan",
                         ".abort_prepare", ".start_radio", ".tune",
                         ".retune", ".radio_enter", ".radio_leave",
                         ".state_enter", ".state_leave",
                         ".runtime_status",
                         ".quiesce_radio", ".finish_radio_cleanup", ".monotonic_us",
                         ".defence_random", ".defence_tx"):
            self.assertIn(required, hooks)

        shield = (ROOT / "main/wifi_shield.c").read_text(encoding="utf-8")
        state = shield.split("struct wifi_shield_state {", 1)[1].split("\n};", 1)[0]
        self.assertIn("deauth_defence_runtime_t defence;", state)
        self.assertIn("defence_targets[DEAUTH_DEFENCE_RUNTIME_TARGETS]", state)
        self.assertIn("char defence_armed_line[160];", state)
        self.assertIn("char defence_telemetry_line[WIFI_SHIELD_LINE_MAX];", state)
        self.assertNotIn("malloc", shield)
        self.assertNotIn("calloc", shield)

        output_hooks = main.split(
            "static const wifi_shield_output_hooks_t wifi_shield_output_hooks", 1
        )[1].split("\n};", 1)[0]
        for required in (".enter", ".leave", ".write", ".write_terminal",
                         ".complete", ".idle", ".drain", ".take_failures"):
            self.assertIn(required, output_hooks)

        publisher = main.split("static void wifi_shield_output_publisher", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("uart_write_bytes", publisher)
        self.assertIn("wifi_shield_output_platform_published", publisher)
        drain = main.split("static bool wifi_shield_output_drain", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("wifi_shield_output_platform_close", drain)
        self.assertIn("remaining_ms", drain)

    def test_wps_profile_snapshot_is_whole_record_psram_without_fallback(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        snapshot = main.split("static bool wps_guard_scan_snapshot", 1)[1].split(
            "\n}\n", 1)[0]
        release = main.split("static void wps_guard_scan_release", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("wifi_shield_target_t (**targets)", snapshot)
        self.assertIn("heap_caps_calloc", snapshot)
        self.assertIn("MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT", snapshot)
        self.assertIn("wifi_shield_copy_target", snapshot)
        self.assertNotRegex(snapshot, r"(?<!heap_caps_)calloc\s*\(")
        self.assertNotRegex(snapshot, r"\bmalloc\s*\(")
        self.assertIn("wifi_shield_target_t *targets", release)
        self.assertIn("sizeof(*targets)", release)
        self.assertIn("heap_caps_free", release)
        self.assertNotRegex(release, r"(?<!heap_caps_)free\s*\(targets\)")

    def test_sae_profile_snapshot_is_whole_record_psram_without_fallback(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        snapshot = main.split("static bool sae_guard_scan_snapshot", 1)[1].split(
            "\n}\n", 1)[0]
        release = main.split("static void sae_guard_scan_release", 1)[1].split(
            "\n}\n", 1)[0]
        start = main.split("static wifi_security_session_result_t sae_guard_runtime_start", 1)[1].split(
            "\n}\n", 1)[0]
        stop = main.split("static bool sae_guard_runtime_stop", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("wifi_shield_target_t (**targets)", snapshot)
        self.assertIn("heap_caps_calloc", snapshot)
        self.assertIn("MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT", snapshot)
        self.assertIn("wifi_shield_copy_target", snapshot)
        self.assertNotRegex(snapshot, r"(?<!heap_caps_)calloc\s*\(")
        self.assertNotRegex(snapshot, r"\bmalloc\s*\(")
        self.assertIn("wifi_shield_target_t *targets", release)
        self.assertIn("sizeof(*targets)", release)
        self.assertIn("heap_caps_free", release)
        self.assertNotRegex(release, r"(?<!heap_caps_)free\s*\(targets\)")
        self.assertIn("wifi_shield_start_sae_profile", start)
        self.assertIn("wifi_shield_stop_sae_profile", stop)
        self.assertNotIn("wifi_security_runtime_platform_start", start)
        self.assertNotIn("wifi_security_runtime_stop", stop)

    def test_trust_profile_targets_share_whole_psram_arena_without_fallback(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        trust = (ROOT / "main/wifi_trust.c").read_text(encoding="utf-8")
        arena = trust.split("typedef struct {", 1)[1].split(
            "} wifi_trust_arena_t;", 1)[0]
        snapshot = main.split(
            "static bool wifi_trust_scan_snapshot", 1)[1].split(
                "\n}\n", 1)[0]
        acquire = main.split(
            "static bool wifi_trust_arena_acquire", 1)[1].split(
                "\n}\n", 1)[0]
        release = main.split(
            "static void wifi_trust_arena_release", 1)[1].split(
                "\n}\n", 1)[0]
        start = main.split(
            "static wifi_security_session_result_t wifi_trust_runtime_start",
            1)[1].split("\n}\n", 1)[0]
        stop = main.split(
            "static bool wifi_trust_runtime_stop", 1)[1].split(
                "\n}\n", 1)[0]

        self.assertIn(
            "wifi_shield_target_t targets[WIFI_TRUST_MAX_PROFILES]", arena)
        self.assertIn("wifi_shield_target_t *entries", snapshot)
        self.assertIn("wifi_shield_copy_target", snapshot)
        self.assertNotIn("heap_caps_", snapshot)
        self.assertIn("heap_caps_calloc", acquire)
        self.assertIn("MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT", acquire)
        self.assertNotIn("MALLOC_CAP_DEFAULT", acquire)
        self.assertNotIn("MALLOC_CAP_INTERNAL", acquire)
        self.assertIn("volatile uint8_t *bytes", release)
        self.assertIn("i < size", release)
        self.assertIn("heap_caps_free(arena)", release)
        self.assertIn("wifi_shield_start_trust_profile", start)
        self.assertIn("wifi_shield_stop_trust_profile", stop)

    def test_shield_worker_hopping_mutex_and_readonly_trust_are_production_wired(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        worker = main.split("static void security_worker", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("wifi_security_runtime_drain_bounded", worker)
        self.assertIn("wifi_shield_worker_poll()", worker)
        self.assertIn("pdMS_TO_TICKS(50U)", worker)
        self.assertIn("wifi_security_runtime_drain(runtime)", worker)

        compact = main.split("static bool wifi_shield_compact_consume", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("wifi_shield_consume_compact(context, event)", compact)

        self.assertIn("static StaticSemaphore_t wifi_shield_state_mutex_storage;", main)
        self.assertIn("static SemaphoreHandle_t wifi_shield_state_mutex;", main)
        self.assertIn("static StaticSemaphore_t wifi_shield_radio_mutex_storage;", main)
        self.assertIn("static SemaphoreHandle_t wifi_shield_radio_mutex;", main)
        create = main.find(
            "xSemaphoreCreateMutexStatic(&wifi_shield_state_mutex_storage)")
        initialize = main.find("wifi_shield_init(&wifi_shield_runtime_hooks")
        self.assertGreaterEqual(create, 0)
        self.assertGreater(initialize, create)
        radio_create = main.find(
            "xSemaphoreCreateMutexStatic(&wifi_shield_radio_mutex_storage)")
        self.assertGreaterEqual(radio_create, 0)
        self.assertGreater(initialize, radio_create)

        retune = main.split("static bool wifi_shield_retune_channel", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("security_channel_tune", retune)
        status = main.split("static void wifi_shield_runtime_status", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("wifi_security_runtime_get_status", status)

        trust = main.split("static bool wifi_shield_trust_snapshot", 1)[1].split(
            "\n}\n", 1)[0]
        self.assertIn("wifi_trust_store_load_readonly", trust)
        self.assertIn("wifi_trust_readonly_storage_ops", trust)
        readonly_enter = main.split(
            "static bool wifi_trust_store_enter_readonly", 1)[1].split(
                "\n}\n", 1)[0]
        self.assertIn("init_sd_card()", readonly_enter)
        self.assertNotIn("sd_mkdir_recursive", readonly_enter)

    def test_shield_presentation_task_is_static_psram_only_and_failure_isolated(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        shield = (ROOT / "main/wifi_shield.c").read_text(encoding="utf-8")

        self.assertRegex(
            main, r"#define WIFI_SHIELD_PRESENTATION_STACK_BYTES\s+4096U")
        self.assertRegex(
            main, r"static\s+StackType_t\s+\*wifi_shield_presentation_task_stack\s*;")
        self.assertIn("static StaticTask_t wifi_shield_presentation_task_storage;",
                      main)
        self.assertIn("static atomic_bool wifi_shield_presentation_monitor", main)

        start = main.split(
            "static bool wifi_shield_presentation_start", 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn("feature_psram_aligned_calloc", start)
        self.assertIn("portBYTE_ALIGNMENT", start)
        self.assertIn("MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT", start)
        self.assertIn("xTaskCreateStatic", start)
        self.assertIn("wifi_shield_presentation_task_stack", start)
        self.assertNotIn("xTaskCreate(", start)
        self.assertNotIn("MALLOC_CAP_INTERNAL", start)

        permanent = main.split(
            "static bool init_feature_psram_storage", 1
        )[1].split("\n}\n", 1)[0]
        self.assertNotIn("wifi_shield_presentation_task_stack", permanent)

        task = main.split(
            "static void wifi_shield_presentation_task", 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn("wifi_shield_presentation_get", task)
        self.assertIn("wifi_shield_presentation_format_oled", task)
        self.assertIn("oled_display_update_full", task)
        self.assertIn("led_status_notify_event", task)
        self.assertIn("pdMS_TO_TICKS(25", task)
        self.assertNotIn("wifi_shield_output_write", task)
        self.assertNotIn("security_channel_tune", task)

        publisher = main.split(
            "static void wifi_shield_output_publisher", 1
        )[1].split("\n}\n", 1)[0]
        self.assertNotIn("oled_display", publisher)
        self.assertNotIn("wifi_shield_presentation", publisher)
        consumer = shield.split(
            "static bool shield_feature_consume", 1
        )[1].split("\n}\n", 1)[0]
        self.assertNotIn("oled_display", consumer)
        self.assertNotIn("led_status", consumer)

        app = main.split("void app_main(void) {", 1)[1]
        self.assertIn("if (!wifi_shield_presentation_start())", app)
        self.assertNotRegex(
            app, r"ESP_ERROR_CHECK\s*\(\s*wifi_shield_presentation_start")
        renderer = main.split(
            "static void led_status_render_task", 1
        )[1].split("\n}\n", 1)[0]
        self.assertIn("wifi_shield_presentation_monitor", renderer)

    def test_shield_sram_map_gate_skips_stale_map_explicitly(self):
        maps = list(ROOT.glob("build*/projectZero.map"))
        ownership_sources = [
            ROOT / "main/main.c",
            ROOT / "main/wifi_shield.c",
            ROOT / "main/wifi_shield.h",
            ROOT / "main/wifi_shield_storage_bundle.c",
            ROOT / "main/wifi_shield_storage_bundle.h",
            ROOT / "main/wifi_shield_journal.c",
            ROOT / "main/wifi_shield_journal.h",
            ROOT / "main/wifi_shield_journal_platform.c",
            ROOT / "main/wifi_shield_journal_platform.h",
            ROOT / "main/CMakeLists.txt",
            ROOT / "sdkconfig",
        ]
        newest_source_mtime = max(path.stat().st_mtime
                                  for path in ownership_sources)
        current = [path for path in maps
                   if path.stat().st_mtime >= newest_source_mtime]
        if not current:
            self.skipTest("no current map: available projectZero.map predates Wi-Fi Shield sources")
        current_map = max(current, key=lambda path: path.stat().st_mtime)
        text = current_map.read_text(encoding="utf-8", errors="replace")

        def section_size(name):
            match = re.search(
                rf"(?m)^{re.escape(name)}\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)",
                text,
            )
            self.assertIsNotNone(match, f"missing {name} in {current_map}")
            return int(match.group(1), 16)

        hp_sram = sum(section_size(name) for name in (
            ".iram0.text", ".dram0.data", ".dram0.bss"))
        self.assertLessEqual(
            hp_sram,
            242719 + 2048,
            f"HP SRAM {hp_sram} exceeds the reviewed Shield ceiling 244767",
        )

    def test_wifi_init_no_mem_is_propagated_without_abort(self):
        main = (ROOT / "main/main.c").read_text(encoding="utf-8")
        body = main.split("static esp_err_t wifi_init_ap_sta(void) {", 1)[1].split(
            "\n}\n\nstatic esp_err_t wifi_country_save", 1)[0]
        prepare = main.split("static esp_err_t wifi_prepare_sta_driver(void) {", 1)[1].split(
            "\n}\n\nstatic esp_err_t wifi_init_ap_sta", 1)[0]
        self.assertNotIn("ESP_ERROR_CHECK", prepare)
        self.assertNotIn("esp_netif_create_default_wifi_sta", prepare)
        self.assertIn("esp_netif_new", prepare)
        self.assertIn("wifi_init_with_configured_country", prepare)
        self.assertIn("wifi_prepare_sta_driver()", body)

        boot = main.split("void app_main(void) {", 1)[1]
        self.assertRegex(boot, r"if \(!init_psram_buffers\(\)\)\s*\{")
        self.assertRegex(boot, r"if \(!init_feature_psram_storage\(\)\)\s*\{\s*"
                               r"deinit_psram_buffers\(\);")

        connect = main.split(
            "static int cmd_wifi_connect(int argc, char **argv) {", 1)[1]
        reset = connect.split("// Reset only a driver", 1)[1].split(
            "// Destroy AP netif", 1)[0]
        self.assertIn("if (wifi_initialized)", reset)
        self.assertNotRegex(reset, r"(?m)^\s*esp_wifi_(?:disconnect|stop|deinit)\(\);")


if __name__ == "__main__":
    unittest.main()
