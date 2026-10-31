"""Check the Unleashed low-RAM FAP layout and loader entry-point invariant.

Usage: py -3 tests/check_fap_code_sections.py path/to/lab_c5.fap

The 65 KiB section cap is a regression guard, not a measured device RAM budget.
"""

import struct
import sys
from pathlib import Path


MAX_CODE_SECTION = 65 * 1024
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4


def read_sections(path: Path) -> tuple[bytes, list[tuple[int, ...]], bytes]:
    blob = path.read_bytes()
    if blob[:6] != b"\x7fELF\x01\x01":
        raise ValueError("expected a little-endian ELF32 FAP")

    section_offset = struct.unpack_from("<I", blob, 32)[0]
    section_stride, section_count, names_index = struct.unpack_from("<HHH", blob, 46)
    if section_stride < 40 or section_count == 0 or names_index >= section_count:
        raise ValueError("invalid ELF section table")
    if section_offset + section_stride * section_count > len(blob):
        raise ValueError("truncated ELF section table")

    sections = [
        struct.unpack_from("<IIIIIIIIII", blob, section_offset + i * section_stride)
        for i in range(section_count)
    ]
    names = sections[names_index]
    string_table = blob[names[4] : names[4] + names[5]]
    if len(string_table) != names[5]:
        raise ValueError("truncated ELF section names")
    return blob, sections, string_table


def section_name(section: tuple[int, ...], names: bytes) -> str:
    end = names.find(b"\0", section[0])
    if end < 0:
        raise ValueError("invalid ELF section name")
    return names[section[0] : end].decode("ascii")


def code_sections(sections: list[tuple[int, ...]], names: bytes) -> list[tuple[str, int]]:

    result = []
    for section in sections:
        _, _, flags, _, _, size, *_ = section
        if (flags & (SHF_ALLOC | SHF_EXECINSTR)) != (SHF_ALLOC | SHF_EXECINSTR):
            continue
        result.append((section_name(section, names), size))
    if not result:
        raise ValueError("FAP has no executable section")
    return result


def check_entry(blob: bytes, sections: list[tuple[int, ...]], names: bytes) -> None:
    text_index = next(
        (i for i, section in enumerate(sections) if section_name(section, names) == ".text"),
        None,
    )
    symtab = next(
        (section for section in sections if section_name(section, names) == ".symtab"),
        None,
    )
    if text_index is None or symtab is None or symtab[6] >= len(sections):
        raise ValueError("FAP is missing .text or .symtab")

    strtab = sections[symtab[6]]
    symbols = blob[strtab[4] : strtab[4] + strtab[5]]
    if len(symbols) != strtab[5]:
        raise ValueError("truncated symbol names")
    stride = symtab[9]
    if stride < 16 or symtab[5] % stride:
        raise ValueError("invalid symbol table")

    entry = struct.unpack_from("<I", blob, 24)[0]
    for offset in range(symtab[4], symtab[4] + symtab[5], stride):
        if offset + 16 > len(blob):
            raise ValueError("truncated symbol table")
        name_offset, value, _, _, _, section_index = struct.unpack_from(
            "<IIIBBH", blob, offset
        )
        name_end = symbols.find(b"\0", name_offset)
        if name_end < 0:
            raise ValueError("invalid symbol name")
        if symbols[name_offset:name_end] == b"Lab_C5_app":
            if section_index != text_index or value != entry:
                raise ValueError(
                    "Lab_C5_app must be in .text at e_entry: "
                    f"section={section_index}, value=0x{value:x}, e_entry=0x{entry:x}"
                )
            print(f"entry: Lab_C5_app in .text at 0x{entry:x}")
            return
    raise ValueError("Lab_C5_app symbol not found")


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        blob, headers, names = read_sections(Path(sys.argv[1]))
        check_entry(blob, headers, names)
        executable = code_sections(headers, names)
    except (OSError, ValueError, struct.error) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    for name, size in executable:
        print(f"{name}: {size} B")
    largest_name, largest_size = max(executable, key=lambda section: section[1])
    if largest_size > MAX_CODE_SECTION:
        print(
            f"FAIL: {largest_name} needs {largest_size} B, limit {MAX_CODE_SECTION} B",
            file=sys.stderr,
        )
        return 1
    print(f"PASS: largest executable section {largest_name} is {largest_size} B")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
