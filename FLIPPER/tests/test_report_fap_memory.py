"""Checks for section-based FAP RAM accounting and comparison gates."""

import contextlib
import io
import struct
import tempfile
import unittest
from pathlib import Path

import report_fap_memory


def make_fap(path: Path, text: int, rodata: int, bss: int, fast_rel: int) -> None:
    """Write a minimal ELF32 section table with independently chosen sizes."""
    specifications = [
        (".text", 1, 0x6, text),
        (".rodata", 1, 0x2, rodata),
        (".bss", 8, 0x2, bss),
        (".fast.rel.text", 1, 0, fast_rel),
        (".fapassets", 1, 0, 200),
    ]
    names = bytearray(b"\0")
    name_offsets = {}
    for name, *_ in specifications:
        name_offsets[name] = len(names)
        names += name.encode("ascii") + b"\0"
    name_offsets[".shstrtab"] = len(names)
    names += b".shstrtab\0"

    blob = bytearray(52)
    blob[:6] = b"\x7fELF\x01\x01"
    headers = [(0, 0, 0, 0, 0)]
    for name, section_type, flags, size in specifications:
        offset = len(blob)
        if section_type != 8:  # NOBITS contributes to RAM but not file bytes.
            blob += b"\0" * size
        headers.append((name_offsets[name], section_type, flags, offset, size))
    names_offset = len(blob)
    blob += names
    headers.append((name_offsets[".shstrtab"], 3, 0, names_offset, len(names)))
    section_offset = len(blob)
    for name_offset, section_type, flags, offset, size in headers:
        blob += struct.pack("<IIIIIIIIII", name_offset, section_type, flags, 0, offset, size, 0, 0, 1, 0)
    struct.pack_into("<I", blob, 32, section_offset)
    struct.pack_into("<HHH", blob, 46, 40, len(headers), len(headers) - 1)
    path.write_bytes(blob)


class FapMemoryReportTests(unittest.TestCase):
    def test_reports_resident_temporary_preload_and_largest_block(self) -> None:
        # Catches counting embedded assets as RAM or omitting NOBITS .bss.
        with tempfile.TemporaryDirectory() as temp:
            candidate = Path(temp) / "candidate.fap"
            make_fap(candidate, text=100, rodata=30, bss=20, fast_rel=40)
            metrics = report_fap_memory.measure(candidate)
            self.assertEqual(metrics.resident_bytes, 150)
            self.assertEqual(metrics.temporary_bytes, 40)
            self.assertEqual(metrics.preload_lower_bound_bytes, 190)
            self.assertEqual(metrics.largest_alloc_name, ".text")
            self.assertEqual(metrics.largest_alloc_bytes, 100)
            self.assertEqual(metrics.largest_block_with_margin_bytes, 1124)

    def test_minimum_resident_reduction_is_enforced(self) -> None:
        # Catches accepting a new FAP that has not actually freed the requested RAM.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            baseline = root / "failed-trial.fap"
            candidate = root / "candidate.fap"
            make_fap(baseline, text=150, rodata=30, bss=20, fast_rel=40)
            make_fap(candidate, text=100, rodata=30, bss=20, fast_rel=40)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                enough = report_fap_memory.main(
                    [str(candidate), "--baseline", str(baseline), "--min-reduction-bytes", "50"]
                )
                too_little = report_fap_memory.main(
                    [str(candidate), "--baseline", str(baseline), "--min-reduction-bytes", "51"]
                )
            self.assertEqual(enough, 0)
            self.assertEqual(too_little, 1)

    def test_rejects_truncated_elf(self) -> None:
        # Catches a bogus binary being reported as a measured FAP.
        with tempfile.TemporaryDirectory() as temp:
            candidate = Path(temp) / "broken.fap"
            candidate.write_bytes(b"\x7fELF\x01\x01")
            with self.assertRaises(ValueError):
                report_fap_memory.measure(candidate)

    def test_comparison_without_threshold_reports_regression_without_failing(self) -> None:
        # Catches treating the default zero as a requested minimum reduction.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            baseline = root / "baseline.fap"
            candidate = root / "larger.fap"
            make_fap(baseline, text=100, rodata=30, bss=20, fast_rel=40)
            make_fap(candidate, text=110, rodata=30, bss=20, fast_rel=40)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = report_fap_memory.main([str(candidate), "--baseline", str(baseline)])
            self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
