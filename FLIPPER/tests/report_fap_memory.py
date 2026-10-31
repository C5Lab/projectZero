"""Report ELF section size bounds for a Flipper FAP.

Usage:
  py -3 tests/report_fap_memory.py dist/lab_c5.fap
  py -3 tests/report_fap_memory.py dist/new.fap --baseline dist/old.fap --min-reduction-bytes 8192

The reduction gate applies to resident SHF_ALLOC section sizes. These section
sums exclude allocator overhead, stack, firmware services and fragmentation;
passing the gate does not guarantee that the FAP starts on a device.
"""

from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

from check_fap_code_sections import SHF_ALLOC, read_sections, section_name


LOADER_SECTION_MARGIN_BYTES = 1024  # Unleashed unlshd-083 section check.


@dataclass(frozen=True)
class FapMemoryMetrics:
    resident_bytes: int
    temporary_bytes: int
    preload_lower_bound_bytes: int
    largest_alloc_name: str
    largest_alloc_bytes: int
    largest_block_with_margin_bytes: int


def measure(path: Path) -> FapMemoryMetrics:
    try:
        _, sections, names = read_sections(path)
        resident: list[tuple[str, int]] = []
        temporary = 0
        for section in sections:
            name = section_name(section, names)
            flags, size = section[2], section[5]
            if flags & SHF_ALLOC:
                resident.append((name, size))
            elif name.startswith(".fast.rel"):
                temporary += size
        if not resident:
            raise ValueError("FAP has no SHF_ALLOC sections")
    except (struct.error, UnicodeError, IndexError) as exc:
        raise ValueError(f"invalid ELF section data: {exc}") from exc

    resident_bytes = sum(size for _, size in resident)
    largest_name, largest_size = max(resident, key=lambda item: item[1])
    return FapMemoryMetrics(
        resident_bytes=resident_bytes,
        temporary_bytes=temporary,
        preload_lower_bound_bytes=resident_bytes + temporary,
        largest_alloc_name=largest_name,
        largest_alloc_bytes=largest_size,
        largest_block_with_margin_bytes=largest_size + LOADER_SECTION_MARGIN_BYTES,
    )


def print_metrics(path: Path, metrics: FapMemoryMetrics) -> None:
    print(f"FAP: {path}")
    print(f"  SHF_ALLOC resident: {metrics.resident_bytes} B")
    print(f"  temporary .fast.rel*: {metrics.temporary_bytes} B")
    print(f"  preload section-size lower bound: {metrics.preload_lower_bound_bytes} B")
    print(
        f"  largest SHF_ALLOC: {metrics.largest_alloc_name} "
        f"{metrics.largest_alloc_bytes} B; +1024: {metrics.largest_block_with_margin_bytes} B"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fap", type=Path)
    parser.add_argument("--baseline", type=Path, help="FAP to compare against")
    parser.add_argument(
        "--min-reduction-bytes",
        type=int,
        default=None,
        help="minimum reduction in SHF_ALLOC bytes versus --baseline",
    )
    args = parser.parse_args(argv)
    if args.min_reduction_bytes is not None and (
        args.min_reduction_bytes < 0 or not args.baseline
    ):
        parser.error("--min-reduction-bytes requires --baseline and a nonnegative value")

    try:
        current = measure(args.fap)
        baseline = measure(args.baseline) if args.baseline else None
    except (OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print_metrics(args.fap, current)
    if baseline is not None:
        print_metrics(args.baseline, baseline)
        resident_reduction = baseline.resident_bytes - current.resident_bytes
        preload_reduction = baseline.preload_lower_bound_bytes - current.preload_lower_bound_bytes
        block_reduction = (
            baseline.largest_block_with_margin_bytes - current.largest_block_with_margin_bytes
        )
        print(f"Resident reduction: {resident_reduction} B")
        print(f"Preload lower-bound reduction: {preload_reduction} B")
        print(f"Largest-block threshold reduction: {block_reduction} B")
        if args.min_reduction_bytes is not None and resident_reduction < args.min_reduction_bytes:
            print(
                f"FAIL: resident reduction {resident_reduction} B is below "
                f"required {args.min_reduction_bytes} B",
                file=sys.stderr,
            )
            return 1
    print("Section-size estimates only; device startup requires separate testing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
