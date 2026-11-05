"""Exercise real metadata-only WSC streaming, plus storage hygiene guards."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return f"/mnt/{path.drive.rstrip(':').lower()}/{path.relative_to(path.anchor).as_posix()}"


class WifiShieldWpsTests(unittest.TestCase):
    def test_streaming_classification_flows_and_hygiene(self):
        with tempfile.TemporaryDirectory(prefix="janos-shield-wps-") as directory:
            executable = Path(directory) / "shield-wps-test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                          "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/wifi_shield_wps_test.c",
                       ROOT / "main/wifi_shield_wps.c",
                       ROOT / "main/wps_guard_core.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(executable)]
                run = [str(executable)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"),
                                     "host C compiler required (native or WSL)")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(executable)]
                run = ["wsl.exe", wsl_path(executable)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            self.assertEqual(built.stdout + built.stderr, "", "compiler output must be pristine")
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "wifi shield wps: PASS\n")
            self.assertEqual(result.stderr, "", "runtime/sanitizer output must be pristine")

    def test_cursor_storage_has_no_secret_or_payload_retention(self):
        path = ROOT / "main/wifi_shield_wps.h"
        self.assertTrue(path.exists(), "missing metadata-only Shield WPS module")
        header = path.read_text(encoding="utf-8")
        structs = re.findall(r"typedef\s+struct\s*\{(.*?)\}\s*\w+;", header, re.S)
        self.assertTrue(structs, "expected caller-owned cursor/table storage")
        for body in structs:
            body = re.sub(r"/\*.*?\*/|//[^\n]*", "", body, flags=re.S)
            self.assertNotIn("*", body, "cursor/table may not retain any pointer")
            self.assertNotRegex(body.lower(), r"\b\w*(?:nonce|credential|pin|key)\w*\b")
            self.assertNotRegex(body, r"\b\w*payload\w*\s*\[")
            arrays = re.findall(r"\b(\w+)\s*\[([^]]+)\]", body)
            for name, size in arrays:
                self.assertIn((name, size), (("bssid", "6"), ("station", "6"),
                              ("tlv_header", "4"), ("flows", "WIFI_SHIELD_WPS_FLOW_CAPACITY")))


if __name__ == "__main__":
    unittest.main()
