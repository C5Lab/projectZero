"""Exercise production OTA release metadata handling with real cJSON on a host.

Run in WSL: python3 -B -m unittest discover -s tests -p test_ota_metadata.py -v
"""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

from test_ota_flow import extract_function


ROOT = Path(__file__).resolve().parents[1]
CJSON = ROOT / "managed_components/espressif__cjson/cJSON"


def production_slice(source):
    definitions = re.findall(r"^#define (?:OTA_\w+|JANOS_VERSION)\b[^\n]*", source, re.M)
    names = ("ota_version_identifiers", "ota_parse_version", "ota_build_release_api_url",
             "ota_fetch_release", "cmd_ota_list")
    return "\n".join([*definitions, *(extract_function(source, name) for name in names)])


class OtaMetadataTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = os.environ.get("CC") or shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if compiler is None:
            raise RuntimeError("host C compiler required")
        cls.temp = tempfile.TemporaryDirectory(prefix="janos-metadata-")
        cls.addClassCleanup(cls.temp.cleanup)
        temporary = Path(cls.temp.name)
        source = (ROOT / "main/main.c").read_text(encoding="utf-8")
        (temporary / "ota_metadata_production.inc").write_text(production_slice(source), encoding="utf-8")
        cls.executable = temporary / "ota_metadata_host"
        build = subprocess.run(
            [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(temporary),
             "-I", str(CJSON), str(ROOT / "tests/ota_metadata_host.c"),
             str(CJSON / "cJSON.c"), "-lm", "-o", str(cls.executable)],
            capture_output=True, text=True,
        )
        if build.returncode:
            raise RuntimeError(f"metadata host compilation failed:\n{build.stdout}\n{build.stderr}")

    def run_case(self, mode, rf, tag="_", fixture="good_rf", url_len=512, tag_len=128):
        run = subprocess.run(
            [str(self.executable), mode, "1" if rf else "0", tag, fixture,
             str(url_len), str(tag_len)], capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        return dict(line.split("=", 1) for line in run.stdout.splitlines())

    def assert_failed(self, result, calls=None):
        self.assertNotEqual(result["status"], "0", result)
        if calls is not None:
            self.assertEqual(result["calls"], str(calls), result)

    def test_release_api_urls_select_repository_for_latest_tag_and_list(self):
        cases = (
            (False, "_", False, "https://api.github.com/repos/C5Lab/projectZero/releases/latest"),
            (False, "v1.2.3", False, "https://api.github.com/repos/C5Lab/projectZero/releases/tags/v1.2.3"),
            (False, "_", True, "https://api.github.com/repos/C5Lab/projectZero/releases?per_page=5"),
            (True, "_", False, "https://api.github.com/repos/elpadrino26/janosrf-web-flasher/releases/latest"),
            (True, "v1.2.3", False, "https://api.github.com/repos/elpadrino26/janosrf-web-flasher/releases/tags/v1.2.3"),
            (True, "_", True, "https://api.github.com/repos/elpadrino26/janosrf-web-flasher/releases?per_page=5"),
        )
        for rf, tag, listing, expected in cases:
            with self.subTest(rf=rf, tag=tag, listing=listing):
                result = self.run_case("url_list" if listing else "url", rf, tag)
                self.assertEqual(result["status"], "0")
                self.assertEqual(result["url"], expected)

    def test_release_url_builder_rejects_short_buffer_and_invalid_tag(self):
        self.assert_failed(self.run_case("url", True, "_", url_len=8), calls=0)
        self.assert_failed(self.run_case("url", True, "../bad"), calls=0)

    def test_fetch_selects_named_app_asset_when_bootloader_is_first(self):
        for rf, fixture, expected in (
            (True, "good_rf", "https://github.com/elpadrino26/janosrf-web-flasher/releases/download/v1.2.3/projectZero.bin"),
            (False, "good_classic", "https://github.com/C5Lab/projectZero/releases/download/v1.2.3/projectZero.bin"),
        ):
            with self.subTest(rf=rf):
                result = self.run_case("fetch", rf, fixture=fixture)
                self.assertEqual(result["status"], "0", result)
                self.assertEqual(result["url"], expected)
                self.assertEqual(result["tag"], "v1.2.3")
                self.assertEqual(result["calls"], "1")

    def test_fetch_tag_uses_selected_repository(self):
        result = self.run_case("fetch", True, "v1.2.3")
        self.assertEqual(result["status"], "0", result)
        self.assertEqual(result["request"], "https://api.github.com/repos/elpadrino26/janosrf-web-flasher/releases/tags/v1.2.3")

    def test_fetch_latest_uses_selected_repository(self):
        for rf, fixture, expected in (
            (True, "good_rf", "https://api.github.com/repos/elpadrino26/janosrf-web-flasher/releases/latest"),
            (False, "good_classic", "https://api.github.com/repos/C5Lab/projectZero/releases/latest"),
        ):
            with self.subTest(rf=rf):
                result = self.run_case("fetch", rf, fixture=fixture)
                self.assertEqual(result["status"], "0", result)
                self.assertEqual(result["request"], expected)

    def test_rejects_bad_metadata_without_fallback(self):
        for fixture in ("malformed", "missing_tag", "missing_asset", "wrong_asset",
                        "missing_download", "draft", "classic_download", "http_download",
                        "other_repo_download"):
            with self.subTest(fixture=fixture):
                self.assert_failed(self.run_case("fetch", True, fixture=fixture), calls=1)

    def test_rejects_tag_mismatch_and_truncation(self):
        for tag, url_len, tag_len in (("v1.2.4", 512, 128),
                                      ("_", 20, 128), ("_", 512, 4)):
            with self.subTest(tag=tag, url_len=url_len, tag_len=tag_len):
                self.assert_failed(self.run_case("fetch", True, tag, url_len=url_len,
                                                 tag_len=tag_len), calls=1)

    def test_invalid_tag_is_rejected_before_http(self):
        for tag in ("bad/tag", "../bad", "bad?x=1", "", "v1.2.3%2Fbad"):
            with self.subTest(tag=tag):
                self.assert_failed(self.run_case("fetch", True, tag or "EMPTY"), calls=0)

    def test_http_error_has_no_fallback(self):
        self.assert_failed(self.run_case("fetch", True, fixture="http_fail"), calls=1)

    def test_list_routes_through_selected_release_api(self):
        for rf, expected in (
            (True, "https://api.github.com/repos/elpadrino26/janosrf-web-flasher/releases?per_page=5"),
            (False, "https://api.github.com/repos/C5Lab/projectZero/releases?per_page=5"),
        ):
            with self.subTest(rf=rf):
                result = self.run_case("list", rf, fixture="listing")
                self.assertEqual(result["status"], "0", result)
                self.assertEqual(result["request"], expected)
                self.assertEqual(result["calls"], "1")

    def test_list_rejects_unknown_source_before_http(self):
        self.assert_failed(self.run_case("list_invalid", True, fixture="listing"), calls=0)


if __name__ == "__main__":
    unittest.main()
