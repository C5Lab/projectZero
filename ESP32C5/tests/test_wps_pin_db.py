import binascii
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from tools.rfdb.wps_format import HEADER_SIZE, WpsDataset, build_wps_blob


ROOT = Path(__file__).resolve().parents[1]


def _wsl_path(path: Path) -> str:
    resolved = path.resolve()
    return f"/mnt/{resolved.drive.rstrip(':').lower()}/{resolved.relative_to(resolved.anchor).as_posix()}"


class WpsPinDbCTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.fixture = cls.directory / "wps_pin.bin"
        dataset = WpsDataset(
            oui_pins={"00AABB": ["12345670", "12345678", "00000000"]},
            oui_algorithms={"00AABB": ["zhao", "asus"]},
            model_pins={"DIR-TEST": ["12345670", "11111111"]},
            vendor_pins={"tp-link": ["61116597", "22222222"],
                         "d-link": ["20172527"]},
            ssid_pins={
                1: ["11866428", "33333333"], 2: ["20329761"], 3: ["71537573"],
                4: ["21464065"], 5: ["38163289"], 6: ["66202240"],
            },
            common_pins=["12345670", "00000000", "00000001", "99999999"],
        )
        cls.fixture.write_bytes(build_wps_blob(dataset, 0x12345678,
                                               validate_checksums=False))
        cls.fixture_v1 = cls.directory / "wps_pin_v1.bin"
        dataset_v1 = WpsDataset(
            oui_pins={"00AABB": ["12345670", "00000000"]},
            oui_algorithms=dataset.oui_algorithms,
            model_pins={"DIR-TEST": ["12345670"]},
            vendor_pins={"tp-link": ["61116597"], "d-link": ["20172527"]},
            ssid_pins={
                1: ["11866428"], 2: ["20329761"], 3: ["71537573"],
                4: ["21464065"], 5: ["38163289"], 6: ["66202240"],
            },
            common_pins=["12345670", "00000000"],
        )
        cls.fixture_v1.write_bytes(build_wps_blob(dataset_v1, 0x12345678,
                                                  version=1))
        cls.executable = cls.directory / "wps_pin_db_test"
        requested = os.environ.get("CC")
        compiler = shutil.which(requested) if requested else None
        if compiler is None:
            compiler = next((shutil.which(c) for c in ("cc", "gcc", "clang") if shutil.which(c)), None)
        sources = [ROOT / "tests" / "wps_pin_db_test.c", ROOT / "main" / "wps_pin_db.c",
                   ROOT / "main" / "wps_pin_algorithms.c"]
        if compiler:
            command = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                       "-I", str(ROOT / "main"), *(str(p) for p in sources), "-o", str(cls.executable)]
            cls.prefix = []
        elif shutil.which("wsl.exe"):
            command = ["wsl.exe", "cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                       "-I", _wsl_path(ROOT / "main"), *(_wsl_path(p) for p in sources),
                       "-o", _wsl_path(cls.executable)]
            cls.prefix = ["wsl.exe"]
        else:
            raise unittest.SkipTest("no host C compiler available")
        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)

    def run_case(self, case, path, expected=None):
        executable = _wsl_path(self.executable) if self.prefix else str(self.executable)
        target = _wsl_path(path) if self.prefix else str(path)
        command = [*self.prefix, executable, case, target]
        if expected is not None:
            command.append(str(expected))
        subprocess.run(command, cwd=ROOT, check=True,
                       capture_output=True, text=True, timeout=10)

    def test_ranking_cache_fallback_and_ssid_rules(self):
        self.run_case("rank-v2", self.fixture)
        self.run_case("rank-v1", self.fixture_v1)

    def test_missing_crc_and_offset_errors_are_distinct(self):
        self.run_case("open", self.directory / "missing.bin", 2)
        crc = self.directory / "crc.bin"
        payload = bytearray(self.fixture.read_bytes()); payload[-1] ^= 1; crc.write_bytes(payload)
        self.run_case("open", crc, 4)
        malformed = self.directory / "malformed.bin"
        payload = bytearray(self.fixture.read_bytes())
        struct.pack_into("<I", payload, 32, len(payload) + 1)
        struct.pack_into("<I", payload, 12, binascii.crc32(payload[HEADER_SIZE:]) & 0xFFFFFFFF)
        malformed.write_bytes(payload)
        self.run_case("open", malformed, 3)

        legacy_pin = self.directory / "legacy-pin-overflow.bin"
        payload = bytearray(self.fixture_v1.read_bytes())
        pool_offset = struct.unpack_from("<I", payload, 40)[0]
        payload[pool_offset:pool_offset + 3] = (10_000_000).to_bytes(3, "little")
        struct.pack_into("<I", payload, 12,
                         binascii.crc32(payload[HEADER_SIZE:]) & 0xFFFFFFFF)
        legacy_pin.write_bytes(payload)
        self.run_case("open", legacy_pin, 3)

        current_pin = self.directory / "current-pin-overflow.bin"
        payload = bytearray(self.fixture.read_bytes())
        pool_offset = struct.unpack_from("<I", payload, 40)[0]
        payload[pool_offset:pool_offset + 4] = (100_000_000).to_bytes(4, "little")
        struct.pack_into("<I", payload, 12,
                         binascii.crc32(payload[HEADER_SIZE:]) & 0xFFFFFFFF)
        current_pin.write_bytes(payload)
        self.run_case("open", current_pin, 3)

        current_common = self.directory / "current-common-overflow.bin"
        payload = bytearray(self.fixture.read_bytes())
        common_offset = struct.unpack_from("<I", payload, 80)[0]
        payload[common_offset:common_offset + 4] = (0xffffffff).to_bytes(4, "little")
        struct.pack_into("<I", payload, 12,
                         binascii.crc32(payload[HEADER_SIZE:]) & 0xFFFFFFFF)
        current_common.write_bytes(payload)
        self.run_case("open", current_common, 3)

    def test_c_reader_rejects_malformed_strings_and_unsorted_rules(self):
        malformed_tail = self.directory / "malformed-string-tail.bin"
        payload = bytearray(self.fixture.read_bytes())
        string_count = struct.unpack_from("<I", payload, 92)[0]
        payload.append(0)
        struct.pack_into("<I", payload, 8, len(payload))
        struct.pack_into("<I", payload, 92, string_count + 1)
        struct.pack_into("<I", payload, 12,
                         binascii.crc32(payload[HEADER_SIZE:]) & 0xFFFFFFFF)
        malformed_tail.write_bytes(payload)
        self.run_case("open", malformed_tail, 3)

        invalid_utf8 = self.directory / "invalid-string-utf8.bin"
        payload = bytearray(self.fixture.read_bytes())
        strings_offset = struct.unpack_from("<I", payload, 88)[0]
        payload[strings_offset + 1] = 0xFF
        struct.pack_into("<I", payload, 12,
                         binascii.crc32(payload[HEADER_SIZE:]) & 0xFFFFFFFF)
        invalid_utf8.write_bytes(payload)
        self.run_case("open", invalid_utf8, 3)

        unsorted_vendor = self.directory / "unsorted-vendor.bin"
        payload = bytearray(self.fixture.read_bytes())
        vendor_offset = struct.unpack_from("<I", payload, 64)[0]
        vendor_count = struct.unpack_from("<I", payload, 68)[0]
        self.assertGreaterEqual(vendor_count, 2)
        first = bytes(payload[vendor_offset:vendor_offset + 7])
        second = bytes(payload[vendor_offset + 7:vendor_offset + 14])
        payload[vendor_offset:vendor_offset + 7] = second
        payload[vendor_offset + 7:vendor_offset + 14] = first
        struct.pack_into("<I", payload, 12,
                         binascii.crc32(payload[HEADER_SIZE:]) & 0xFFFFFFFF)
        unsorted_vendor.write_bytes(payload)
        self.run_case("open", unsorted_vendor, 3)


if __name__ == "__main__":
    unittest.main()
