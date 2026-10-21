import binascii
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "vendors_v3.bin"


def _wsl_path(path: Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive.rstrip(":").lower()
    if not drive:
        raise ValueError(f"WSL conversion requires an absolute drive path: {path}")
    tail = resolved.relative_to(resolved.anchor).as_posix()
    return f"/mnt/{drive}/{tail}"


class VendorDbCTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.executable = cls.directory / "vendor_db_test"

        requested = os.environ.get("CC")
        compiler = shutil.which(requested) if requested else None
        if compiler is None:
            for candidate in ("cc", "gcc", "clang"):
                compiler = shutil.which(candidate)
                if compiler:
                    break

        sources = [ROOT / "tests" / "vendor_db_test.c", ROOT / "main" / "vendor_db.c"]
        if compiler:
            command = [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(ROOT / "main"),
                *(str(path) for path in sources),
                "-o",
                str(cls.executable),
            ]
            cls.run_prefix = []
        elif shutil.which("wsl.exe"):
            command = [
                "wsl.exe",
                "cc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                _wsl_path(ROOT / "main"),
                *(_wsl_path(path) for path in sources),
                "-o",
                _wsl_path(cls.executable),
            ]
            cls.run_prefix = ["wsl.exe"]
        else:
            raise unittest.SkipTest("no host C compiler available")

        subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)

    def run_case(self, case, path=FIXTURE, expected=None):
        executable = (
            _wsl_path(self.executable) if self.run_prefix else str(self.executable)
        )
        target = _wsl_path(path) if self.run_prefix else str(path)
        command = [*self.run_prefix, executable, case, target]
        if expected is not None:
            command.append(str(expected))
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=10)

    def corrupt_fixture(self, name, mutate):
        path = self.directory / name
        payload = bytearray(FIXTURE.read_bytes())
        mutate(payload)
        path.write_bytes(payload)
        return path

    def test_longest_prefix_cached_lookup(self):
        self.run_case("cached")

    def test_allocation_failure_uses_direct_file_fallback(self):
        self.run_case("fallback")

    def test_close_and_reopen(self):
        self.run_case("reopen")

    def test_handle_allocation_failure(self):
        self.run_case("no_memory")

    def test_missing_file_reports_io_error(self):
        self.run_case("open_result", self.directory / "missing.bin", 3)

    def test_malformed_header_reports_format_error(self):
        path = self.corrupt_fixture("bad-magic.bin", lambda blob: blob.__setitem__(0, 0))
        self.run_case("open_result", path, 4)

    def test_crc_mismatch_is_distinct(self):
        path = self.corrupt_fixture("bad-crc.bin", lambda blob: blob.__setitem__(-1, blob[-1] ^ 1))
        self.run_case("open_result", path, 5)

    def test_short_read_reports_format_error(self):
        path = self.corrupt_fixture("short.bin", lambda blob: blob.__delitem__(slice(-1, None)))
        self.run_case("open_result", path, 4)

    def test_offset_overflow_reports_format_error(self):
        path = self.corrupt_fixture(
            "overflow.bin", lambda blob: struct.pack_into("<I", blob, 0x1C, 0xFFFFFFF0)
        )
        self.run_case("open_result", path, 4)

    def test_overlapping_sections_report_format_error(self):
        def overlap(blob):
            index24_offset = struct.unpack_from("<I", blob, 0x1C)[0]
            struct.pack_into("<I", blob, 0x24, index24_offset)

        path = self.corrupt_fixture("overlap.bin", overlap)
        self.run_case("open_result", path, 4)


if __name__ == "__main__":
    unittest.main()
