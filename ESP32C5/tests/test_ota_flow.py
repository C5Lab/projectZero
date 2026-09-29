"""Execute current JanOS OTA C functions on a host, without touching firmware.

Run: python -m unittest discover -s tests -p test_ota_flow.py -v
Set OTA_STRICT_KNOWN_DEFECTS=1 to report documented defects as failures.
Requires a host C compiler (CC, cc, gcc or clang). No network/device access.
"""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
NONCODE = re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*', re.S)


def extract_function(source, name):
    """Keep the production signature/body verbatim; ignore braces in literals."""
    masked = NONCODE.sub(lambda m: re.sub(r"[^\n]", " ", m.group()), source)
    pattern = r"^static\s+[^;{}]*\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{"
    match = re.search(pattern, masked, re.M)
    if match is None:
        raise RuntimeError(f"production function missing: {name}")
    depth = 1
    for pos in range(match.end(), len(masked)):
        depth += (masked[pos] == "{") - (masked[pos] == "}")
        if depth == 0:
            return source[match.start():pos + 1]
    raise RuntimeError(f"unclosed production function: {name}")


def production_slice(source):
    definitions = re.findall(r"^#define (?:OTA_\w+|JANOS_VERSION)\b[^\n]*", source, re.M)
    args = re.search(r"typedef struct \{\s*char tag\[64\];.*?\} ota_check_args_t;", source, re.S)
    if args is None:
        raise RuntimeError("OTA task argument declaration missing; update host adapter")
    functions = (
        "ota_parse_version", "ota_is_newer_version", "ota_build_branch_url",
        "ota_is_expected_project", "ota_perform_https_update",
        "ota_has_ip", "ota_is_connected", "ota_start_check", "ota_check_task",
        "ota_load_channel_from_nvs", "ota_save_channel_to_nvs",
        "cmd_ota_channel", "cmd_ota_check", "ota_mark_valid_if_pending",
    )
    return "\n".join([*definitions, args.group(),
                        *(extract_function(source, name) for name in functions)])


def known_defect(test):
    return test if os.environ.get("OTA_STRICT_KNOWN_DEFECTS") == "1" else unittest.expectedFailure(test)


class OtaFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            raise RuntimeError("Host C compiler required. On Windows run this suite in WSL, or set CC.")
        cls.temp = tempfile.TemporaryDirectory(prefix="janos-ota-tests-")
        cls.addClassCleanup(cls.temp.cleanup)
        temporary = Path(cls.temp.name)
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        (temporary / "ota_production.inc").write_text(production_slice(source), encoding="utf-8")
        executable = temporary / ("ota_host.exe" if os.name == "nt" else "ota_host")
        build = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                "-I", str(temporary), str(ROOT / "tests/ota_host.c"),
                                "-o", str(executable)], capture_output=True, text=True)
        if build.returncode:
            raise RuntimeError(f"OTA host compilation failed:\n{build.stdout}\n{build.stderr}")
        # Infrastructure failures happen outside expectedFailure test methods.
        cls.results = {}
        scenarios = (
            "newer", "equal", "older", "dev", "dev_latest", "dev_latest_equal",
            "tag_older", "bad_version", "uppercase", "uppercase_reload",
            "nvs_open_fail", "nvs_set_fail", "nvs_commit_fail", "nvs_invalid",
            "nvs_missing", "nvs_roundtrip", "invalid_channel", "invalid_args",
            "offline", "no_ip", "no_netif", "ip_error", "wifi_mode_fail",
            "busy", "alloc_fail", "task_fail", "disconnect_before_task",
            "metadata_fail", "begin_fail", "descriptor_fail", "wrong_project",
            "perform_fail", "incomplete", "finish_fail", "stall",
            "version_mismatch", "retry", "malformed_version", "prerelease",
            "numeric_versions", "null_version", "pending", "valid", "state_fail",
            "url_too_small", "url", "long_tag",
        )
        for scenario in scenarios:
            run = subprocess.run([str(executable), scenario], capture_output=True, text=True, timeout=5)
            if run.returncode:
                raise RuntimeError(f"OTA scenario {scenario} failed ({run.returncode}):\n{run.stdout}\n{run.stderr}")
            rows = [line.split("=", 1) for line in run.stdout.splitlines()]
            cls.results[scenario] = dict(rows)
            for key in ("started", "begin", "perform", "finish", "abort", "restart", "busy", "allocs", "mark"):
                int(cls.results[scenario][key])

    def result(self, scenario):
        return self.results[scenario]

    def assert_idle(self, scenario):
        r = self.result(scenario)
        self.assertEqual((r["busy"], r["allocs"]), ("0", "0"))

    def test_newer_release_updates_and_restarts(self):
        r = self.result("newer")
        self.assertEqual((r["route"], r["finish"], r["restart"], r["abort"]), ("latest", "1", "1", "0"))
        self.assertEqual(r["events"], "begin,desc,perform,perform,perform,complete,finish,restart,")
        self.assert_idle("newer")

    def test_equal_or_older_release_does_not_write(self):
        for scenario in ("equal", "older", "bad_version"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.result(scenario)["begin"], "0")
                self.assertEqual(self.result(scenario)["restart"], "0")
                self.assert_idle(scenario)

    def test_dev_installs_without_version_gate(self):
        self.assertEqual(self.result("dev")["restart"], "1")
        self.assertIn("/development/ESP32C5/binaries-esp32c5/projectZero.bin", self.result("dev")["url"])

    def test_latest_overrides_dev_but_does_not_force_reinstall(self):
        self.assertEqual(self.result("dev_latest")["route"], "latest")
        self.assertEqual(self.result("dev_latest")["restart"], "1")
        self.assertEqual(self.result("dev_latest_equal")["begin"], "0")

    def test_explicit_tag_can_downgrade(self):
        r = self.result("tag_older")
        self.assertEqual((r["route"], r["tag"], r["restart"]), ("tag", "1.0.0", "1"))

    @known_defect
    def test_accepted_uppercase_channel_routes_to_dev(self):
        self.assertIn("/development/", self.result("uppercase")["url"])

    @known_defect
    def test_uppercase_channel_routes_to_dev_after_nvs_reload(self):
        self.assertIn("/development/", self.result("uppercase_reload")["url"])

    @known_defect
    def test_nvs_open_failure_preserves_active_channel(self):
        self.assertEqual(self.result("nvs_open_fail")["channel"], "main")

    @known_defect
    def test_nvs_set_failure_preserves_active_channel(self):
        self.assertEqual(self.result("nvs_set_fail")["channel"], "main")

    @known_defect
    def test_nvs_commit_failure_preserves_active_channel(self):
        self.assertEqual(self.result("nvs_commit_fail")["channel"], "main")

    def test_nvs_failure_is_reported(self):
        for scenario in ("nvs_open_fail", "nvs_set_fail", "nvs_commit_fail"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.result(scenario)["command"], "1")

    def test_channel_persists_and_invalid_or_missing_nvs_defaults_to_main(self):
        self.assertEqual(self.result("nvs_roundtrip")["channel"], "dev")
        self.assertEqual(self.result("nvs_invalid")["channel"], "main")
        self.assertEqual(self.result("nvs_missing")["channel"], "main")

    def test_invalid_channel_does_not_change_state(self):
        r = self.result("invalid_channel")
        self.assertEqual((r["command"], r["channel"]), ("1", "main"))

    def test_invalid_check_arguments_do_not_start_task(self):
        self.assertEqual(self.result("invalid_args")["started"], "0")
        self.assertEqual(self.result("invalid_args")["command"], "1")

    def test_connection_preconditions_prevent_update(self):
        for scenario in ("offline", "no_ip", "no_netif", "ip_error", "wifi_mode_fail"):
            with self.subTest(scenario=scenario):
                r = self.result(scenario)
                self.assertEqual((r["command"], r["started"], r["begin"]), ("1", "0", "0"))
                self.assert_idle(scenario)

    def test_second_request_does_not_create_another_task(self):
        r = self.result("busy")
        self.assertEqual((r["started"], r["command"], r["restart"]), ("1", "1", "1"))

    def test_allocation_or_task_failure_releases_busy(self):
        for scenario in ("alloc_fail", "task_fail"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.result(scenario)["command"], "1")
                self.assert_idle(scenario)

    def test_disconnect_before_worker_starts_does_not_fetch(self):
        r = self.result("disconnect_before_task")
        self.assertEqual((r["route"], r["begin"]), ("none", "0"))
        self.assert_idle("disconnect_before_task")

    def test_metadata_failure_does_not_begin_ota(self):
        self.assertEqual(self.result("metadata_fail")["begin"], "0")
        self.assert_idle("metadata_fail")

    def test_begin_failure_does_not_use_uncreated_handle(self):
        r = self.result("begin_fail")
        self.assertEqual((r["abort"], r["perform"], r["finish"], r["restart"]), ("0", "0", "0", "0"))
        self.assert_idle("begin_fail")

    def test_descriptor_failure_or_wrong_project_aborts_before_perform(self):
        for scenario in ("descriptor_fail", "wrong_project"):
            with self.subTest(scenario=scenario):
                r = self.result(scenario)
                self.assertEqual((r["abort"], r["perform"], r["finish"], r["restart"]), ("1", "0", "0", "0"))
                self.assert_idle(scenario)

    def test_failed_or_incomplete_transfer_never_finishes(self):
        for scenario in ("perform_fail", "incomplete", "stall"):
            with self.subTest(scenario=scenario):
                r = self.result(scenario)
                self.assertEqual((r["abort"], r["finish"], r["restart"]), ("1", "0", "0"))
                self.assert_idle(scenario)

    def test_finish_failure_does_not_restart_or_double_free_handle(self):
        r = self.result("finish_fail")
        self.assertEqual((r["finish"], r["abort"], r["restart"]), ("1", "0", "0"))
        self.assert_idle("finish_fail")

    @known_defect
    def test_new_release_with_old_binary_is_not_activated(self):
        self.assertEqual(self.result("version_mismatch")["restart"], "0")

    def test_failed_download_allows_retry_in_same_process(self):
        r = self.result("retry")
        self.assertEqual((r["started"], r["abort"], r["restart"]), ("2", "1", "1"))
        self.assert_idle("retry")

    def test_numeric_versions_compare_numerically(self):
        self.assertEqual(self.result("numeric_versions")["value"], "1")

    def test_null_and_unparseable_versions_are_rejected(self):
        self.assertEqual(self.result("null_version")["value"], "0")

    @known_defect
    def test_malformed_version_is_rejected(self):
        self.assertEqual(self.result("malformed_version")["value"], "0")

    @known_defect
    def test_stable_release_is_newer_than_its_release_candidate(self):
        self.assertEqual(self.result("prerelease")["value"], "1")

    def test_only_pending_image_is_marked_valid(self):
        self.assertEqual(self.result("pending")["mark"], "1")
        self.assertEqual(self.result("valid")["mark"], "0")
        self.assertEqual(self.result("state_fail")["mark"], "0")

    def test_branch_url_builder_reports_insufficient_buffer(self):
        self.assertEqual(self.result("url_too_small")["value"], "-3")

    def test_branch_url_points_to_current_classic_source(self):
        self.assertEqual(self.result("url")["url"], "https://raw.githubusercontent.com/C5Lab/projectZero/development/ESP32C5/binaries-esp32c5/projectZero.bin")

    @known_defect
    def test_overlong_tag_is_rejected_instead_of_requesting_truncated_tag(self):
        self.assertEqual(self.result("long_tag")["started"], "0")


if __name__ == "__main__":
    unittest.main()
