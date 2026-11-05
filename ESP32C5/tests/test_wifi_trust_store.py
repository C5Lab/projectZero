"""Compile and run the bounded Wi-Fi Trust JSONL store contract."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest
import zlib


ROOT = Path(__file__).resolve().parents[1]

ONE_PROFILE_AP = (
    b'{"v":1,"type":"ap","bssid":"021122334455","ssid_status":"valid",'
    b'"ssid_hex":"4100FF55","source":"probe_response","privacy":1,'
    b'"rsn_status":"valid","rsn_group":"000FAC04","rsn_pairwise":'
    b'["000FAC04","000FAC08"],"rsn_akm":["000FAC08","000FAC02"],'
    b'"rsn_capabilities_present":true,"rsn_pmf_capable":true,'
    b'"rsn_pmf_required":true,"rsn_management":"000FAC06",'
    b'"wpa_status":"absent","wpa_group":null,"wpa_pairwise":null,'
    b'"wpa_akm":null,"wpa_capabilities_present":false,'
    b'"wpa_pmf_capable":null,"wpa_pmf_required":null,'
    b'"wpa_management":null,"rsnxe_status":"valid","rsnxe_hex":"2155",'
    b'"wps_status":"valid","wps_present":true,"wps_state":2,'
    b'"wps_config_methods":128,"wps_setup_locked":false,'
    b'"wps_selected_registrar":true,"wps_manufacturer_hex":"4C4142",'
    b'"wps_manufacturer_truncated":false,"wps_model_name_hex":"0055",'
    b'"wps_model_name_truncated":false,"wps_model_number_hex":null,'
    b'"wps_model_number_truncated":null,"wps_device_name_hex":null,'
    b'"wps_device_name_truncated":null,"country_status":"valid",'
    b'"country_hex":"504C20","channel":6,"observed_us":123456874}'
)
ONE_PROFILE_CRC = 0xD8216EF8


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


class WifiTrustStoreTest(unittest.TestCase):
    def test_zero_profile_fixture_is_exact_canonical_jsonl(self):
        expected = (
            b'{"v":1,"type":"header","count":0,"boot":'
            b'"0001020304050607","created_unix":null,'
            b'"created_us":987654321}\n'
            b'{"v":1,"type":"end","count":0,"crc32":"00000000"}\n'
        )
        fixture = ROOT / "tests/fixtures/wifi_trust_baseline_v1.jsonl"
        self.assertEqual(fixture.read_bytes(), expected)

    def test_one_profile_fixture_has_independent_crc_kat(self):
        self.assertEqual(zlib.crc32(ONE_PROFILE_AP + b"\n"), ONE_PROFILE_CRC)
        expected = (
            b'{"v":1,"type":"header","count":1,"boot":'
            b'"0001020304050607","created_unix":1793650000,'
            b'"created_us":987654321}\n' + ONE_PROFILE_AP + b"\n" +
            b'{"v":1,"type":"end","count":1,"crc32":"D8216EF8"}\n'
        )
        fixture = ROOT / "tests/fixtures/wifi_trust_baseline_v1_one_profile.jsonl"
        self.assertEqual(fixture.read_bytes(), expected)

    def test_store_has_no_allocator_dependency(self):
        source = (ROOT / "main/wifi_trust_store.c").read_text(encoding="utf-8")
        for allocator in ("malloc(", "calloc(", "realloc(", "free("):
            self.assertNotIn(allocator, source)

    def test_canonical_jsonl_io_recovery_and_fault_matrix(self):
        with tempfile.TemporaryDirectory(prefix="janos-wifi-trust-store-") as directory:
            executable = Path(directory) / "wifi_trust_store_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
            if os.environ.get("JANOS_TEST_SANITIZERS"):
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/wifi_trust_store_test.c",
                       ROOT / "main/wifi_trust_store.c",
                       ROOT / "main/wifi_trust_core.c"]
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
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("PASS: Wi-Fi Trust canonical JSONL store", result.stdout)


if __name__ == "__main__":
    unittest.main()
