"""Host tests for production ota_http_get and ESP-IDF HTTP boundary handling.

Run in WSL: python3 -B -m unittest discover -s tests -p test_ota_http.py -v
"""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_ota_flow import extract_function


ROOT = Path(__file__).resolve().parents[1]


class OtaHttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if compiler is None:
            raise RuntimeError("host C compiler required")
        cls.temp = tempfile.TemporaryDirectory(prefix="janos-http-")
        cls.addClassCleanup(cls.temp.cleanup)
        temporary = Path(cls.temp.name)
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        (temporary / "ota_http_production.inc").write_text(
            "#define OTA_HTTP_MAX_BODY (256 * 1024)\n" + extract_function(source, "ota_http_get"),
            encoding="utf-8",
        )
        cls.executable = temporary / "ota_http_host"
        build = subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(temporary),
             str(ROOT / "tests/ota_http_host.c"), "-o", str(cls.executable)],
            capture_output=True, text=True,
        )
        if build.returncode:
            raise RuntimeError(f"HTTP host compilation failed:\n{build.stdout}\n{build.stderr}")

    def result(self, case):
        run = subprocess.run([str(self.executable), case], capture_output=True, text=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stderr)
        return dict(line.split("=", 1) for line in run.stdout.splitlines())

    def assert_failed_cleanly(self, case, opens, closes, cleanup=1):
        result = self.result(case)
        self.assertNotEqual(result["status"], "0", result)
        self.assertEqual(result["opens"], str(opens), result)
        self.assertEqual(result["closes"], str(closes), result)
        self.assertEqual(result["cleanup"], str(cleanup), result)
        self.assertEqual(result["body"], "null", result)
        self.assertEqual(result["length"], "0", result)

    def test_get_follows_https_release_asset_redirect(self):
        result = self.result("redirect")
        self.assertEqual((result["status"], result["body"], result["length"]),
                         ("0", "payload", "7"))
        self.assertEqual((result["opens"], result["closes"], result["cleanup"]),
                         ("2", "2", "1"))
        self.assertEqual(result["redirects"], "1")

    def test_five_redirects_are_allowed_and_six_are_rejected(self):
        result = self.result("five_redirects")
        self.assertEqual(result["status"], "0", result)
        self.assertEqual((result["opens"], result["closes"], result["redirects"]),
                         ("6", "6", "5"))
        self.assert_failed_cleanly("redirect_loop", opens=6, closes=6)

    def test_redirect_to_plain_http_is_rejected_before_next_request(self):
        result = self.result("downgrade")
        self.assertNotEqual(result["status"], "0", result)
        self.assertEqual((result["opens"], result["closes"], result["cleanup"]),
                         ("1", "1", "1"))
        self.assertEqual(result["body"], "null")

    def test_redirect_error_and_open_failure_clean_up(self):
        self.assert_failed_cleanly("missing_location", opens=1, closes=1)
        self.assert_failed_cleanly("redirect_error", opens=1, closes=1)
        self.assert_failed_cleanly("open_after_redirect", opens=2, closes=1)

    def test_timeout_and_read_error_clean_up(self):
        self.assert_failed_cleanly("open_timeout", opens=1, closes=0)
        self.assert_failed_cleanly("headers_timeout", opens=1, closes=1)
        self.assert_failed_cleanly("read_error", opens=1, closes=1)

    def test_truncated_content_length_and_incomplete_data_are_rejected(self):
        for case in ("short_body", "incomplete_chunked"):
            with self.subTest(case=case):
                self.assert_failed_cleanly(case, opens=1, closes=1)

    def test_complete_chunked_body_is_accepted_without_content_length(self):
        result = self.result("complete_chunked")
        self.assertEqual((result["status"], result["length"], result["body"]),
                         ("0", "7", "payload"))

    def test_successful_binary_body_is_not_treated_as_c_string_during_read(self):
        result = self.result("binary")
        self.assertEqual((result["status"], result["length"], result["bytes_hex"]),
                         ("0", "4", "41004243"))

    def test_invalid_args_have_no_network_activity(self):
        result = self.result("invalid_args")
        self.assertNotEqual(result["status"], "0")
        self.assertEqual((result["opens"], result["cleanup"]), ("0", "0"))


if __name__ == "__main__":
    unittest.main()
