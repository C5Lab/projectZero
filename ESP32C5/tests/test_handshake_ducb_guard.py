import re
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAIN = (ROOT / "main" / "main.c").read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;]*?\)\s*\{", source, re.S)
    if not match:
        raise AssertionError(f"function not found: {name}")
    depth = 1
    pos = match.end()
    while depth and pos < len(source):
        depth += (source[pos] == "{") - (source[pos] == "}")
        pos += 1
    return source[match.start():pos]


class DUCBCriticalSectionTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                         "host C tests require GCC; run the suite in Linux/WSL")
    def test_guard_module(self):
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "handshake_ducb_guard_test"
            subprocess.run([
                os.environ.get("CC", "gcc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                "-pthread",
                "-I", str(ROOT / "main"),
                str(ROOT / "tests" / "handshake_ducb_guard_test.c"),
                str(ROOT / "main" / "handshake_ducb_guard.c"),
                "-o", str(executable),
            ], check=True)
            subprocess.run([str(executable)], check=True)

    @unittest.skipUnless(shutil.which(os.environ.get("CC", "gcc")),
                         "host C tests require GCC; run the suite in Linux/WSL")
    def test_deauth_failure_logs_compile_with_literal_formats(self):
        """Compile the real TX helper against an ESP-style literal macro."""
        function = function_body(MAIN, "hs_deauth_burst_tx")
        function_start = MAIN.index(function)
        context_start = MAIN.rfind("typedef struct {", 0, function_start)
        context = MAIN[context_start:function_start]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef int esp_err_t;
#define ESP_OK 0
#define WIFI_IF_AP 0
#define TAG "test"
static char emitted[128];
static void fake_log(const char *tag, const char *format, ...) {
    (void)tag;
    va_list args;
    va_start(args, format);
    vsnprintf(emitted, sizeof(emitted), format, args);
    va_end(args);
}
#define ESP_LOGW(tag, format, ...) fake_log(tag, "W " format, __VA_ARGS__)
static esp_err_t esp_wifi_80211_tx(int interface, const void *frame,
                                  size_t size, bool sequence) {
    (void)interface; (void)frame; (void)size; (void)sequence;
    return -1;
}
static const char *esp_err_to_name(esp_err_t error) {
    (void)error;
    return "ERR";
}
'''
        harness += context + function
        harness += r'''
int main(void) {
    uint8_t station[6] = {0};
    uint8_t ap[6] = {0};
    uint8_t frame[24] = {0};
    hs_deauth_burst_context_t context = {station, ap, frame, sizeof(frame)};
    assert(!hs_deauth_burst_tx(&context, 0U, true));
    assert(strcmp(emitted, "W [HS-DEAUTH] Failed to send deauth #1: ERR") == 0);
    assert(!hs_deauth_burst_tx(&context, 5U, false));
    assert(strcmp(emitted, "W [HS-DEAUTH] Failed to send reverse deauth #1: ERR") == 0);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "deauth_log_compile.c"
            executable = Path(directory) / "deauth_log_compile"
            source.write_text(harness, encoding="utf-8")
            subprocess.run([
                os.environ.get("CC", "gcc"), "-std=c11", "-Wall", "-Wextra",
                "-Werror", str(source), "-o", str(executable),
            ], check=True)
            subprocess.run([str(executable)], check=True)

    def test_worker_does_not_hold_state_lock_across_tx_delay_or_sd(self):
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        self.assertIn("hs_ducb_target_snapshot_init", worker)
        self.assertIn("hs_revalidate_target_locked", worker)
        self.assertIn("hs_target_is_eligible_locked", worker)
        self.assertIn("hs_capture_snapshot_create", worker)
        self.assertIn("hs_save_handshake_snapshot_to_sd", worker)

        lock_regions = list(re.finditer(
            r"hs_sniffer_lock\(hs_sniffer_mutex,\s*portMAX_DELAY\)", worker))
        self.assertGreater(len(lock_regions), 0)
        for match in lock_regions:
            give = worker.find("hs_sniffer_unlock(hs_sniffer_mutex)",
                               match.start())
            self.assertNotEqual(give, -1)
            critical = worker[match.start():give]
            self.assertNotIn("hs_send_targeted_deauth", critical)
            self.assertNotIn("vTaskDelay", critical)
            self.assertNotIn("check_handshake_file_exists", critical)
            self.assertNotIn("hs_save_handshake_snapshot_to_sd", critical)

    def test_rotation_is_retried_before_target_selection(self):
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        selection = worker.index("for (int i = 0; i < hs_client_count")
        rotation = worker.index("hs_pcap_rotate_if_pending()")
        quiesce = worker.rfind("handshake_quiesce_sniffer_callbacks", 0,
                               rotation)
        self.assertGreater(quiesce, 0)
        self.assertLess(rotation, selection)

    def test_worker_preserves_three_targets_per_dwell(self):
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        self.assertIn("HS_DUCB_TARGETS_PER_DWELL", worker)
        self.assertIn("hs_ducb_target_budget()", worker)
        target_loop = worker.index(
            "for (unsigned target_i = 0; target_i < target_count; ++target_i)")
        init = worker.index("hccapx_serializer_init", target_loop)
        snapshot = worker.index("hs_capture_snapshot_create", init)
        self.assertLess(init, snapshot)
        self.assertNotIn("hccapx_serializer_init", worker[:target_loop].split(
            "for (int i = 0; i < hs_client_count", 1)[1])

    def test_stop_wait_is_bounded_and_defers_owned_snapshot(self):
        stop = function_body(MAIN, "cmd_stop")
        self.assertIn("hs_ducb_stop_decide", stop)
        self.assertIn("action != HS_DUCB_STOP_WAIT", stop)
        self.assertIn("stop_pending", stop)
        self.assertIn("HS_STOP_WAIT_MS", stop)
        self.assertNotIn("vTaskDelete(handshake_attack_task_handle)", stop)
        self.assertNotRegex(stop, r"while\s*\([^)]*hs_snapshot_io_inflight")
        self.assertIn("xSemaphoreTake(hs_publish_gate, pdMS_TO_TICKS(50))", stop)
        self.assertIn("reason=publish_gate", stop)

    def test_max_lock_duration_is_reported(self):
        cleanup = function_body(MAIN, "handshake_cleanup")
        self.assertIn("max_lock_us", cleanup)
        self.assertIn("lock_acquisitions", cleanup)
        self.assertIn("hs_sniffer_lock_max_us", MAIN)
        self.assertIn("hs_sniffer_lock_acquisitions", MAIN)

    def test_save_uses_only_owned_snapshot(self):
        save = function_body(MAIN, "hs_save_handshake_snapshot_to_sd")
        self.assertNotIn("pcap_serializer_get_buffer", save)
        self.assertNotIn("hccapx_serializer_get", save)
        self.assertIn("snapshot->pcap", save)
        self.assertIn("snapshot->hccapx", save)
        self.assertIn("snapshot->pcap_size, written", save)
        self.assertIn("snapshot->hccapx_size, hccapx_written", save)
        self.assertIn("fflush", save)
        self.assertIn("fsync", save)
        self.assertIn("fclose", save)
        self.assertIn("hs_ducb_writer_succeeded", save)

    def test_failed_writer_retains_snapshot_and_stop_releases_it(self):
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        stop = function_body(MAIN, "cmd_stop")
        failed = worker.split("if (saved) {", 1)[1].split("// Periodic stats", 1)[0]
        self.assertIn("hs_capture_snapshot_release", failed)
        self.assertIn("else", failed)
        self.assertIn("save failed", failed)
        tail = worker.rsplit(
            "for (unsigned i = 0; i < HS_DUCB_TARGETS_PER_DWELL; ++i)", 1)[1]
        self.assertIn("hs_capture_snapshot_release", tail)
        self.assertIn("hs_snapshot_io_inflight", stop)
        self.assertIn("hs_snapshot_owned_inflight", stop)
        self.assertNotIn("vTaskDelete(handshake_attack_task_handle)", stop)

    def test_generation_gates_save_and_publish(self):
        save = function_body(MAIN, "hs_save_handshake_snapshot_to_sd")
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        self.assertIn("hs_ducb_capture_is_publishable", save)
        self.assertIn("snapshot->session_generation != atomic_load_explicit", save)
        self.assertIn("&hs_session_generation", save)
        self.assertIn("xSemaphoreTake(hs_publish_gate", save)
        publish = worker.split("hs_publish_saved_handshake", 1)[0]
        self.assertLess(publish.index("published = true"),
                        publish.index("hs_revalidate_target_locked",
                                      publish.index("published = true")))
        self.assertIn("hs_ducb_capture_is_publishable", save)

    def test_temporary_pcap_is_not_treated_as_completed(self):
        by_ssid = function_body(MAIN, "check_handshake_file_exists")
        by_bssid = function_body(MAIN, "check_handshake_file_exists_by_bssid")
        self.assertIn("hs_ducb_has_suffix", by_ssid)
        self.assertIn("hs_ducb_has_suffix", by_bssid)
        self.assertNotIn('strstr(entry->d_name, ".pcap")', by_ssid)
        self.assertNotIn('strstr(entry->d_name, ".pcap")', by_bssid)

    def test_attempt_capture_not_global_pcap_is_published(self):
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        snapshot_call = worker.index("hs_capture_snapshot_create")
        context = worker[max(0, snapshot_call - 600):snapshot_call + 400]
        self.assertIn("hs_attempt_pcap", context)
        self.assertNotIn("pcap_serializer_get_buffer", context)

    def test_global_diagnostic_pcap_failure_does_not_drop_target_eapol(self):
        process = function_body(MAIN, "hs_sniffer_process_packet")
        global_append = process.index(
            "pcap_serializer_append_frame_checked", process.index("EAPOL"))
        attempt_append = process.index(
            "hs_attempt_pcap_append_if_matching", global_append)
        between = process[global_append:attempt_append]
        self.assertIn("hs_pcap_record_append_result", between)
        self.assertNotIn("return;", between)

    def test_commit_marker_and_per_target_listen_contract(self):
        save = function_body(MAIN, "hs_save_handshake_snapshot_to_sd")
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        hccapx_commit = save.index("rename(hccapx_part, hccapx_filename)")
        pcap_commit = save.index("rename(pcap_part, pcap_filename)")
        self.assertLess(hccapx_commit, pcap_commit)
        self.assertIn("for (int i = 0; i < 20", worker)

    def test_action_and_cooldown_revalidate_current_eligibility(self):
        eligible = function_body(MAIN, "hs_target_is_eligible_locked")
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        for marker in ("ap->complete", "ap->has_existing_file",
                       "ap->authmode == WIFI_AUTH_OPEN",
                       "ap->channel != target->channel",
                       "client->last_deauth_us"):
            self.assertIn(marker, eligible)
        self.assertGreaterEqual(worker.count("hs_target_is_eligible_locked"), 2)

    def test_callback_reports_contention_without_blocking(self):
        callback = function_body(MAIN, "hs_sniffer_promiscuous_cb")
        self.assertIn("hs_sniffer_lock(sniffer_mutex, 0)", callback)
        self.assertIn("hs_rx_mutex_contention_drops", callback)
        self.assertNotIn("portMAX_DELAY", callback)

    def test_eight_burst_delays_are_outside_mutex(self):
        send = function_body(MAIN, "hs_send_targeted_deauth")
        self.assertIn("hs_ducb_run_burst", send)
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        tx = worker.index("hs_send_targeted_deauth")
        previous_take = worker.rfind("hs_sniffer_lock(hs_sniffer_mutex", 0, tx)
        previous_give = worker.rfind("hs_sniffer_unlock(hs_sniffer_mutex)", 0, tx)
        self.assertGreater(previous_give, previous_take)

    def test_large_snapshot_copy_runs_with_rx_quiesced(self):
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        snapshot = worker.index("hs_capture_snapshot_create")
        quiesce = worker.rfind("handshake_quiesce_sniffer_callbacks", 0,
                               snapshot)
        rearm = worker.index("handshake_prepare_sniffer_channel", snapshot)
        self.assertGreater(quiesce, 0)
        self.assertGreater(rearm, snapshot)

    def test_every_pre_tx_setup_failure_releases_reservation(self):
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        tx = worker.index("hs_send_targeted_deauth")
        setup = worker[worker.index(
            "for (unsigned target_i = 0; target_i < target_count; ++target_i)"):tx]
        self.assertIn("hs_release_target_reservation", setup)
        self.assertIn('"attempt_pcap_alloc"', setup)
        self.assertIn('"channel_rearm"', setup)
        self.assertIn('[HS-DUCB] setup_failed reason=%s', setup)
        self.assertIn("reservation_released=", setup)

    def test_target_loop_has_common_pending_reservation_cleanup(self):
        worker = function_body(MAIN, "handshake_attack_task_sniffer")
        loop = worker.index(
            "for (unsigned target_i = 0; target_i < target_count; ++target_i)")
        cleanup = worker.index("hs_ducb_release_pending_targets", loop)
        next_phase = worker.index(
            "if (!handshake_attack_active || operation_stop_requested) break;",
            cleanup)
        self.assertLess(cleanup, next_phase)


if __name__ == "__main__":
    unittest.main()
