"""Check embedded GPS/Web FALs, plus optional Recon/Rogue/ARP trial modules.

Usage: py -3 tests/check_embedded_plugin.py dist/lab_c5_v0.41_unleashed.fap
       py -3 tests/check_embedded_plugin.py dist/lab_c5.fap dist/lab_c5_gps.fal dist/lab_c5_web.fal
       py -3 tests/check_embedded_plugin.py dist/lab_c5_recon_trial.fap --require-recon
       py -3 tests/check_embedded_plugin.py dist/lab_c5_light_trial.fap --require-recon --require-rogue --require-arp
"""

import argparse
import re
import struct
import sys
from pathlib import Path

from check_fap_code_sections import read_sections, section_name


SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4
ASSETS_MAGIC = 0x4F4C5A44
GPS_PLUGIN_ASSET = "plugins/lab_c5_gps.fal"
WEB_PLUGIN_ASSET = "plugins/lab_c5_web.fal"
RECON_PLUGIN_ASSET = "plugins/lab_c5_recon.fal"
ROGUE_PLUGIN_ASSET = "plugins/lab_c5_rogue.fal"
ARP_PLUGIN_ASSET = "plugins/lab_c5_arp.fal"
EXPECTED_APP_ID = b"lab_c5\0"
EXPECTED_API_VERSION = 3
EXPECTED_MODULE_VTABLE_SIZE = 40  # C5ModuleV3: two u32 fields and eight pointers on F7.


class EmbeddedElf:
    def __init__(self, blob):
        self.blob = blob

    def read_bytes(self):
        return self.blob


def find_section(sections, names, wanted):
    for index, section in enumerate(sections):
        if section_name(section, names) == wanted:
            return index, section
    raise ValueError(f"missing {wanted} section")


def section_bytes(blob, section):
    offset, size = section[4], section[5]
    if offset + size > len(blob):
        raise ValueError("section extends beyond ELF file")
    return blob[offset : offset + size]


def defined_symbols(blob, sections, names):
    _, symtab = find_section(sections, names, ".symtab")
    if symtab[6] >= len(sections) or symtab[9] < 16 or symtab[5] % symtab[9]:
        raise ValueError("invalid ELF symbol table")
    strings = section_bytes(blob, sections[symtab[6]])
    symbols = {}
    for offset in range(symtab[4], symtab[4] + symtab[5], symtab[9]):
        if offset + 16 > len(blob):
            raise ValueError("truncated ELF symbol table")
        name_offset, value, _, _, _, section_index = struct.unpack_from("<IIIBBH", blob, offset)
        if name_offset >= len(strings):
            raise ValueError("invalid ELF symbol name")
        name_end = strings.find(b"\0", name_offset)
        if name_end < 0:
            raise ValueError("unterminated ELF symbol name")
        if section_index != 0:
            symbols[strings[name_offset:name_end].decode("ascii")] = (value, section_index)
    return symbols


def check_entry(blob, sections, names, symbols, entry_name):
    text_index, text_section = find_section(sections, names, ".text")
    if text_section[2] & (SHF_ALLOC | SHF_EXECINSTR) != SHF_ALLOC | SHF_EXECINSTR:
        raise ValueError(".text is not allocated executable code")
    entry = struct.unpack_from("<I", blob, 24)[0]
    if symbols.get(entry_name) != (entry, text_index):
        raise ValueError(f"{entry_name} is not the ELF entry in .text")


def check_descriptor_abi(blob, sections, names, symbols, entry_name):
    """Follow the SDK's Thumb LDR/BX entry stub to its descriptor and vtable."""
    _, text_section = find_section(sections, names, ".text")
    _, rodata_section = find_section(sections, names, ".rodata")
    text_data = section_bytes(blob, text_section)
    rodata = section_bytes(blob, rodata_section)
    entry_value = symbols[entry_name][0]
    entry_offset = entry_value & ~1
    if entry_offset < 0 or entry_offset + 8 > len(text_data):
        raise ValueError(f"{entry_name} has an invalid entry stub")
    load_instruction, return_instruction = struct.unpack_from("<HH", text_data, entry_offset)
    if load_instruction & 0xFF00 != 0x4800 or return_instruction != 0x4770:
        raise ValueError(f"{entry_name} has an unsupported entry stub; inspect ABI manually")
    literal_offset = ((entry_offset + 4) & ~3) + (load_instruction & 0xFF) * 4
    if literal_offset + 4 > len(text_data):
        raise ValueError(f"{entry_name} descriptor literal is outside .text")
    descriptor_address = struct.unpack_from("<I", text_data, literal_offset)[0]
    descriptor_offset = descriptor_address
    if descriptor_offset < 0 or descriptor_offset + 12 > len(rodata):
        raise ValueError(f"{entry_name} descriptor is outside .rodata")
    appid_address, abi_version, vtable_address = struct.unpack_from(
        "<III", rodata, descriptor_offset
    )
    appid_offset = appid_address
    vtable_offset = vtable_address
    if appid_offset < 0 or rodata[appid_offset : appid_offset + len(EXPECTED_APP_ID)] != EXPECTED_APP_ID:
        raise ValueError(f"{entry_name} descriptor has wrong appid")
    if abi_version != EXPECTED_API_VERSION:
        raise ValueError(
            f"{entry_name} descriptor ABI version {abi_version}, expected {EXPECTED_API_VERSION}"
        )
    if vtable_offset < 0 or vtable_offset + 8 > len(rodata):
        raise ValueError(f"{entry_name} module vtable is outside .rodata")
    module_version, module_size = struct.unpack_from("<II", rodata, vtable_offset)
    if module_version != EXPECTED_API_VERSION or module_size != EXPECTED_MODULE_VTABLE_SIZE:
        raise ValueError(
            f"{entry_name} module ABI version/size {module_version}/{module_size}, "
            f"expected {EXPECTED_API_VERSION}/{EXPECTED_MODULE_VTABLE_SIZE}"
        )


def read_u32(data, offset):
    if offset + 4 > len(data):
        raise ValueError("truncated embedded assets")
    return struct.unpack_from("<I", data, offset)[0], offset + 4


def read_bytes(data, offset, length):
    if length > len(data) - offset:
        raise ValueError("truncated embedded asset payload")
    return data[offset : offset + length], offset + length


def read_path(data, offset):
    length, offset = read_u32(data, offset)
    path, offset = read_bytes(data, offset, length)
    if not path.endswith(b"\0"):
        raise ValueError("unterminated embedded asset path")
    return path[:-1].decode("utf-8").replace("\\", "/"), offset


def embedded_files(data):
    if len(data) < 16:
        raise ValueError("truncated .fapassets header")
    magic, version, dirs_count, files_count = struct.unpack_from("<IIII", data)
    if magic != ASSETS_MAGIC or version != 1:
        raise ValueError("invalid .fapassets header")
    offset = 16
    signature_size, offset = read_u32(data, offset)
    _, offset = read_bytes(data, offset, signature_size)
    for _ in range(dirs_count):
        _, offset = read_path(data, offset)
    result = {}
    for _ in range(files_count):
        path, offset = read_path(data, offset)
        size, offset = read_u32(data, offset)
        payload, offset = read_bytes(data, offset, size)
        if path in result:
            raise ValueError(f"duplicate embedded asset {path}")
        result[path] = payload
    if offset != len(data):
        raise ValueError("trailing bytes in .fapassets")
    return result


def check(
    host_path,
    plugin_path=None,
    host_entry="Lab_C5_app",
    plugin_entry="lab_c5_gps_plugin_ep",
    plugin_only_symbol="gps_coord_format",
    web_plugin_path=None,
    web_entry="lab_c5_web_plugin_ep",
    require_recon=False,
    recon_plugin_path=None,
    recon_entry="lab_c5_recon_plugin_ep",
    require_rogue=False,
    rogue_plugin_path=None,
    rogue_entry="lab_c5_rogue_plugin_ep",
    require_arp=False,
    arp_plugin_path=None,
    arp_entry="lab_c5_arp_plugin_ep",
    required_plugins=(),
):
    host_blob, host_sections, host_names = read_sections(host_path)
    host_symbols = defined_symbols(host_blob, host_sections, host_names)
    check_entry(host_blob, host_sections, host_names, host_symbols, host_entry)
    for name in required_plugins:
        if not re.fullmatch(r"lab_c5_[a-z0-9_]+", name):
            raise ValueError(f"invalid plugin name {name!r}")
    if (plugin_entry in host_symbols or web_entry in host_symbols or
            plugin_only_symbol in host_symbols or
            (require_recon and recon_entry in host_symbols) or
            (require_rogue and rogue_entry in host_symbols) or
            (require_arp and arp_entry in host_symbols) or
            any(f"{name}_plugin_ep" in host_symbols for name in required_plugins)):
        raise ValueError("plugin code was linked into host FAP")
    if recon_plugin_path and not require_recon:
        raise ValueError("--recon-plugin requires --require-recon")
    if rogue_plugin_path and not require_rogue:
        raise ValueError("--rogue-plugin requires --require-rogue")
    if arp_plugin_path and not require_arp:
        raise ValueError("--arp-plugin requires --require-arp")

    _, assets_section = find_section(host_sections, host_names, ".fapassets")
    if assets_section[2] & SHF_ALLOC:
        raise ValueError(".fapassets would be mapped into RAM")
    files = embedded_files(section_bytes(host_blob, assets_section))
    plugins = [
        (GPS_PLUGIN_ASSET, plugin_entry, plugin_only_symbol, plugin_path),
        (WEB_PLUGIN_ASSET, web_entry, None, web_plugin_path),
    ]
    if require_recon:
        plugins.append((RECON_PLUGIN_ASSET, recon_entry, None, recon_plugin_path))
    if require_rogue:
        plugins.append((ROGUE_PLUGIN_ASSET, rogue_entry, None, rogue_plugin_path))
    if require_arp:
        plugins.append((ARP_PLUGIN_ASSET, arp_entry, None, arp_plugin_path))
    for name in required_plugins:
        plugins.append((f"plugins/{name}.fal", f"{name}_plugin_ep", None, None))
    for asset_path, entry_name, required_symbol, loose_path in plugins:
        plugin_blob = files.get(asset_path)
        if plugin_blob is None:
            raise ValueError(f"embedded {asset_path} is missing")
        if loose_path and loose_path.read_bytes() != plugin_blob:
            raise ValueError(f"embedded {asset_path} differs from FAL")
        plugin_blob, plugin_sections, plugin_names = read_sections(EmbeddedElf(plugin_blob))
        plugin_symbols = defined_symbols(plugin_blob, plugin_sections, plugin_names)
        check_entry(plugin_blob, plugin_sections, plugin_names, plugin_symbols, entry_name)
        check_descriptor_abi(plugin_blob, plugin_sections, plugin_names, plugin_symbols, entry_name)
        if required_symbol and required_symbol not in plugin_symbols:
            raise ValueError(f"plugin is missing {required_symbol}")
        comparison = ", byte-for-byte match" if loose_path else ""
        print(f"PASS: {asset_path} embedded{comparison}, entry and ABI valid")
    print("PASS: plugin entrypoints absent from host")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", type=Path)
    parser.add_argument("plugin", type=Path, nargs="?", help="optional loose GPS FAL comparison")
    parser.add_argument("web_plugin", type=Path, nargs="?", help="optional loose Web FAL comparison")
    parser.add_argument("--host-entry", default="Lab_C5_app")
    parser.add_argument("--plugin-entry", default="lab_c5_gps_plugin_ep")
    parser.add_argument("--plugin-only-symbol", default="gps_coord_format")
    parser.add_argument("--web-entry", default="lab_c5_web_plugin_ep")
    parser.add_argument("--require-recon", action="store_true", help="require and validate embedded Recon FAL")
    parser.add_argument("--recon-plugin", type=Path, help="optional loose Recon FAL comparison")
    parser.add_argument("--recon-entry", default="lab_c5_recon_plugin_ep")
    parser.add_argument("--require-rogue", action="store_true", help="require embedded Rogue AP FAL")
    parser.add_argument("--rogue-plugin", type=Path, help="optional loose Rogue AP FAL comparison")
    parser.add_argument("--rogue-entry", default="lab_c5_rogue_plugin_ep")
    parser.add_argument("--require-arp", action="store_true", help="require embedded ARP FAL")
    parser.add_argument("--arp-plugin", type=Path, help="optional loose ARP FAL comparison")
    parser.add_argument("--arp-entry", default="lab_c5_arp_plugin_ep")
    parser.add_argument(
        "--require-plugin", action="append", default=[], metavar="APPID",
        help="require another embedded lab_c5_* FAL and validate its derived entry point",
    )
    args = parser.parse_args(argv)
    try:
        check(
            args.host,
            args.plugin,
            args.host_entry,
            args.plugin_entry,
            args.plugin_only_symbol,
            args.web_plugin,
            args.web_entry,
            require_recon=args.require_recon,
            recon_plugin_path=args.recon_plugin,
            recon_entry=args.recon_entry,
            require_rogue=args.require_rogue,
            rogue_plugin_path=args.rogue_plugin,
            rogue_entry=args.rogue_entry,
            require_arp=args.require_arp,
            arp_plugin_path=args.arp_plugin,
            arp_entry=args.arp_entry,
            required_plugins=tuple(args.require_plugin),
        )
    except (OSError, ValueError, struct.error, UnicodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
