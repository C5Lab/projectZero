"""Run the portable journal platform against an in-memory filesystem."""
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return f"/mnt/{path.drive.rstrip(':').lower()}/{path.relative_to(path.anchor).as_posix()}"


class WifiShieldJournalPlatformTests(unittest.TestCase):
    def test_journal_queue_covers_observed_attack_and_health_burst(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        health = (ROOT / "main/wifi_shield_ap_health.h").read_text(
            encoding="utf-8")
        depth_match = re.search(
            r"^#define WIFI_SHIELD_JOURNAL_QUEUE_DEPTH\s+(\d+)U$",
            source, re.M)
        recommendations_match = re.search(
            r"^#define WIFI_SHIELD_AP_RECOMMENDATION_MAX\s+(\d+)U$",
            health, re.M)
        self.assertIsNotNone(depth_match)
        self.assertIsNotNone(recommendations_match)
        depth = int(depth_match.group(1))
        maximum_recommendations = int(recommendations_match.group(1))
        self.assertGreaterEqual(
            depth, 32,
            "journal queue must absorb the measured 21-record in-flight burst")
        self.assertGreaterEqual(
            depth, maximum_recommendations + 2,
            "journal queue must hold event + AP health + a full recommendation set")

    def test_esp_adapter_ownership_and_psram_wiring(self):
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("static wifi_shield_journal_record_t *wifi_shield_journal_queue_buffer;", source)
        self.assertIn("static StackType_t *wifi_shield_journal_task_stack;", source)
        def body(name):
            return source.split(name + "(", 1)[1].split("\n}\n", 1)[0]
        for field in (".journal_queue", ".journal_stack", ".journal_records",
                      ".journal_record_size", ".journal_stack_bytes"):
            self.assertIn(field, source)
        self.assertIn("WIFI_SHIELD_STORAGE_QUEUE_JOURNAL", body("wifi_shield_storage_create_queue"))
        self.assertIn("xQueueSend(wifi_shield_journal_queue, record, 0U)", body("wifi_shield_journal_queue_send"))
        self.assertIn("xQueueReceive(wifi_shield_journal_queue, record, 0U)", body("wifi_shield_journal_queue_receive"))
        self.assertIn("xTaskCreateStatic", body("wifi_shield_journal_task_start"))
        self.assertIn("wifi_shield_journal_task_stack", body("wifi_shield_journal_task_start"))
        self.assertIn("vTaskDelete", body("wifi_shield_journal_task_join"))
        release = body("wifi_shield_storage_release")
        self.assertLess(release.index("wifi_shield_journal_platform_finish"),
                        release.index("wifi_shield_storage_bundle_release"))
        self.assertIn("g_gps_clock_synced", body("wifi_shield_journal_gps_time"))
        self.assertIn("time(NULL)", body("wifi_shield_journal_gps_time"))
        self.assertIn("*uncertainty_ms = 1000U", body("wifi_shield_journal_gps_time"))
        drain = body("wifi_shield_journal_drain_adapter")
        self.assertIn("wifi_shield_journal_platform_drain", drain)
        self.assertIn("esp_timer_get_time", drain)
        self.assertIn("vTaskDelay", drain)
        self.assertIn(".journal_drain = wifi_shield_journal_drain_adapter", source)
        self.assertIn("O_EXCL", body("wifi_shield_journal_open"))
        self.assertIn("fdopen", body("wifi_shield_journal_open"))
        self.assertIn("init_sd_card()", body("wifi_shield_journal_mount"))
        self.assertIn("sd_mkdir_recursive", body("wifi_shield_journal_mkdir"))
        self.assertIn("sd_sync_checked", body("wifi_shield_journal_sync"))
        self.assertIn("f_rename", body("wifi_shield_journal_rename"))
        self.assertIn("stat(to", body("wifi_shield_journal_rename"))
        self.assertIn("errno != ENOENT", body("wifi_shield_journal_rename"))
        self.assertIn("rename(from, to)", body("wifi_shield_journal_rename"))
        adapter = source.split("/* Shield journal ESP-IDF adapters", 1)[1].split(
            "/* End Shield journal ESP-IDF adapters */", 1)[0]
        for forbidden in ("malloc(", "calloc(", "MALLOC_CAP_INTERNAL", "WIFI_SECURITY_SESSION_",
                          "quarantine", "xTaskCreate("):
            self.assertNotIn(forbidden, adapter)
        for name in ("wifi_shield_journal.c", "wifi_shield_journal_store.c",
                     "wifi_shield_journal_platform.c", "wifi_shield_summary.c"):
            self.assertIn('"' + name + '"', cmake)

    def test_rx_callback_local_reachability_stays_clean(self):
        sources = [(ROOT / "main" / name).read_text(encoding="utf-8") for name in
                   ("main.c", "wifi_security_runtime.c", "wifi_security_frame.c",
                    "csa_detector_core.c")]
        def extract(source, name):
            match = re.search(r"^(?:static\s+)?(?:inline\s+)?\w+[ \t*]+\b" +
                              re.escape(name) + r"\s*\([^;{}]*\)\s*\{", source, re.M)
            if not match:
                return None
            end, depth = match.end(), 1
            while depth:
                depth += (source[end] == "{") - (source[end] == "}")
                end += 1
            return source[match.start():end]
        seen, pending = set(), ["wifi_security_promiscuous_callback"]
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            body = next((b for source in sources if (b := extract(source, name))), None)
            if body is None:
                continue
            seen.add(name)
            body = re.sub(r"/\*.*?\*/|//[^\n]*", "", body, flags=re.S)
            self.assertNotRegex(body, r"\b(?:fopen|fwrite|fflush|fsync|snprintf|malloc|"
                                      r"wifi_shield_journal\w*|xQueueSend|xSemaphoreTake)\s*\(")
            pending.extend(re.findall(r"\b([A-Za-z_]\w*)\s*\(", body))
        self.assertTrue({"wifi_security_promiscuous_callback", "security_shield_submit",
                         "wifi_security_runtime_submit_compact"} <= seen)

    def test_writer_queue_lifecycle(self):
        for name in ("wifi_shield_journal_platform.h", "wifi_shield_journal_platform.c"):
            self.assertTrue((ROOT / "main" / name).is_file(), f"missing journal platform: {name}")
        with tempfile.TemporaryDirectory(prefix="janos-shield-store-") as directory:
            executable = Path(directory) / "store-test"
            compiler = shutil.which(os.environ.get("CC", "cc"))
            compiler = compiler or shutil.which("gcc") or shutil.which("clang")
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                     "-Wl,--wrap=malloc", "-Wl,--wrap=calloc",
                     "-Wl,--wrap=realloc", "-Wl,--wrap=free"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                          "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/wifi_shield_journal_platform_test.c",
                       ROOT / "main/wifi_shield_journal_platform.c",
                       ROOT / "main/wifi_shield_journal_store.c",
                       ROOT / "main/wifi_shield_journal.c",
                       ROOT / "main/wifi_shield_summary.c",
                       ROOT / "main/wifi_shield_campaign.c",
                       ROOT / "main/wifi_shield_ap_health.c"]
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
            self.assertEqual(built.stdout + built.stderr, "")
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "wifi shield journal platform: PASS\n")
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
