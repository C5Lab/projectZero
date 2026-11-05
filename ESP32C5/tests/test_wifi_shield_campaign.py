"""Compile and run the real portable campaign policy, optionally sanitized."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return f"/mnt/{path.drive.rstrip(':').lower()}/{path.relative_to(path.anchor).as_posix()}"


class WifiShieldCampaignTests(unittest.TestCase):
    def test_campaign_policy(self):
        self.assertTrue((ROOT / "main/wifi_shield_campaign.h").is_file(),
                        "missing portable campaign header")
        self.assertTrue((ROOT / "main/wifi_shield_campaign.c").is_file(),
                        "missing portable campaign implementation")
        with tempfile.TemporaryDirectory(prefix="janos-shield-campaign-") as directory:
            executable = Path(directory) / "campaign-test"
            requested = os.environ.get("CC", "")
            compiler = shutil.which(requested) if requested else None
            compiler = compiler or next((shutil.which(name) for name in
                                        ("cc", "gcc", "clang") if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-sanitize-recover=all",
                          "-fno-omit-frame-pointer"]
            flags += ["-Wl,--wrap=malloc", "-Wl,--wrap=calloc",
                      "-Wl,--wrap=realloc", "-Wl,--wrap=free"]
            sources = [ROOT / "tests/wifi_shield_campaign_test.c",
                       ROOT / "main/wifi_shield_campaign.c",
                       ROOT / "main/wifi_shield_channel.c"]
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
            for case in ("history", "before-first", "overflow", "watermark", "all"):
                with self.subTest(case=case):
                    result = subprocess.run(run + ([] if case == "all" else [case]),
                                            cwd=ROOT, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    expected = ("wifi shield campaign: PASS (17 scenarios; heap=0)\n"
                                if case == "all" else "wifi shield campaign regression: PASS\n")
                    self.assertEqual(result.stdout, expected)
                    self.assertEqual(result.stderr, "", "runtime/sanitizer output must be pristine")


if __name__ == "__main__":
    unittest.main()
