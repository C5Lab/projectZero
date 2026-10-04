#!/usr/bin/env python3
"""Convert IEEE oui.txt into the JanOS Wi-Fi vendor binary table.

Two output formats:

  v2 (default) -- compact, string-interned, forward-compatible:
      [16B header][index: N * (OUI[3] + nameOff u24 LE)]
      [name table: (len u8 + utf8 bytes) blobs, deduplicated]
    Header: magic "JVND", version=2, oui_len=3, entry_size=6, reserved,
            record_count u32 LE, names_offset u32 LE.
    Many OUIs share one vendor name, so interning shrinks the file massively
    and lets the firmware cache the whole index in PSRAM.

  v1 (--format v1) -- legacy headerless fixed 64B records (3B OUI + 1B len +
    60B name, zero padded). Kept for older firmware.

JanOS firmware with v2 support reads BOTH formats (it detects v1 by the
absence of the magic header), so a v1 file keeps working everywhere.
"""
import argparse
import pathlib
import struct


KNOWN_VENDOR_KEYWORDS = [
    "TP-LINK", "TPLINK", "D-LINK", "LINKSYS", "NETGEAR",
    "ASUSTEK", "ASUS", "TENDA", "TOTOLINK", "EDIMAX", "DRAYTEK",
    "NETIS", "ZYXEL", "ENGENIUS", "UBIQUITI", "MIKROTIK",
    "ARRIS", "ARCADYAN", "GEMTEK", "SERCOMM",
    "TECHNICOLOR", "SAGEMCOM", "HITRON", "ACTIONTEC",
    "HUMAX", "CALIX", "BELKIN",
    "CISCO SYSTEMS", "MERAKI", "ARUBA", "RUCKUS",
    "EXTREME NETWORKS", "FORTINET", "JUNIPER",
    "H3C", "CAMBIUM", "MIST SYSTEMS",
    "QUALCOMM", "ATHEROS", "BROADCOM", "MARVELL",
    "MEDIATEK", "REALTEK", "INTEL", "QUANTENNA",
    "ESPRESSIF", "NORDIC SEMICONDUCTOR", "RAK WIRELESS",
    "QUECTEL", "SIERRA WIRELESS", "TELIT", "FIBOCOM",
    "SIMCOM",
    "APPLE", "SAMSUNG", "XIAOMI", "HUAWEI", "OPPO", "VIVO",
    "ONEPLUS", "LENOVO", "MOTOROLA", "GOOGLE", "SONY", "LG",
    "NOKIA", "HMD GLOBAL", "HTC", "HONOR", "REALME", "MEIZU",
    "ZTE", "TCL", "ALCATEL", "AMAZON", "MICROSOFT",
    "ACER", "DELL", "HP",
    "FOXCONN", "HON HAI", "FIH", "LITEON", "LITE-ON", "LITEON TECHNOLOGY",
    "WISTRON", "COMPAL", "QUANTA", "PEGATRON", "INVENTEC",
    "USI", "UNIMICRON", "DELTA ELECTRONICS", "MURATA", "KYOCERA",
    "TAIYO YUDEN", "GOERTEK", "AAC TECHNOLOGIES",
    "WINGTECH", "LONGCHEER", "HUAQIN",
    "SHENZHEN", "GUANGDONG", "JABIL", "FLEXTRONICS", "CELESTICA", "SANMINA",
    "UNISOC", "SPREADTRUM",
    "TEXAS INSTRUMENTS", "COMMSCOPE", "FIBERHOME",
    "HEWLETT PACKARD ENTERPRISE", "HEWLETT PACKARD",
    "SILICON LABORATORIES", "VANTIVA", "EERO",
    "HIKVISION", "AZUREWAVE", "CHINA MOBILE",
    "EM MICROELECTRONIC", "NINTENDO", "TECNO",
    "ASKEY", "WNC", "ALPSALPINE", "CISCO SPVTG",
    "ARISTA", "PALO ALTO NETWORKS", "INFINIX",
    "TUYA", "2WIRE", "BUFFALO", "AVM",
    "RUIJIE", "UNIVERSAL ELECTRONICS", "ALTOBEAM",
    "CIENA", "LCFC", "ERICSSON", "DAHUA",
    "AI-LINK", "RENESAS", "FUGUI",
]

# Legacy v1 record: 3 bytes OUI + 1 byte name length + 60 bytes name (padded)
RECORD_NAME_BYTES = 60
RECORD_STRUCT = struct.Struct("!3sB{}s".format(RECORD_NAME_BYTES))

# v2 format constants (must match main.c)
V2_MAGIC = b"JVND"
V2_VERSION = 2
V2_HEADER_SIZE = 16
V2_INDEX_ENTRY_SIZE = 6   # OUI[3] + name offset u24 LE
# Name length is a u8, and the firmware buffer holds up to 60 chars.
V2_NAME_MAX = 60


def normalize_vendor_name(name: str) -> str:
    return name.strip().replace("\t", " ")


def should_keep_vendor(name: str) -> bool:
    upper_name = name.upper()
    normalized = []
    for ch in upper_name:
        normalized.append(ch if ch.isalnum() else " ")
    normalized_str = " " + " ".join("".join(normalized).split()) + " "
    for keyword in KNOWN_VENDOR_KEYWORDS:
        if f" {keyword} " in normalized_str:
            return True
    return False


def parse_oui_file(path: pathlib.Path):
    results = {}
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        current_oui = None
        for raw_line in handle:
            line = raw_line.strip()
            if "(hex)" in line:
                prefix, _, tail = line.partition("(hex)")
                oui_text = "".join(ch for ch in prefix if ch.isalnum())
                if len(oui_text) != 6:
                    current_oui = None
                    continue
                current_oui = bytes.fromhex(oui_text)
                vendor_name = normalize_vendor_name(tail)
                if vendor_name:
                    results.setdefault(current_oui, vendor_name)
            elif "(base 16)" in line:
                # alternate header, ignore - handled via (hex) section
                current_oui = None
                continue
            elif current_oui and line:
                # Continuation lines; append address info if present
                existing = results.get(current_oui, "")
                if existing:
                    existing = f"{existing} {line}"
                else:
                    existing = line
                results[current_oui] = normalize_vendor_name(existing)
            else:
                current_oui = None
    return results


def select_entries(oui_map, keep_all: bool):
    entries = [
        (oui, name)
        for (oui, name) in oui_map.items()
        if keep_all or should_keep_vendor(name)
    ]
    entries.sort(key=lambda item: item[0])
    return entries


def build_v1(entries) -> bytes:
    out = bytearray()
    for oui, name in entries:
        truncated = name.encode("utf-8")[:RECORD_NAME_BYTES]
        length = len(truncated)
        encoded = truncated.ljust(RECORD_NAME_BYTES, b"\x00")
        out += RECORD_STRUCT.pack(oui, length, encoded)
    return bytes(out)


def build_v2(entries) -> bytes:
    # Intern names: one copy of each distinct vendor string, shared by every OUI.
    name_table = bytearray()
    name_to_off = {}

    def intern(name: str) -> int:
        encoded = name.encode("utf-8")[:V2_NAME_MAX]
        key = bytes(encoded)
        off = name_to_off.get(key)
        if off is None:
            off = len(name_table)
            if off >= (1 << 24):
                raise ValueError("name table exceeds 16 MB (u24 offset)")
            name_table.append(len(encoded))
            name_table.extend(encoded)
            name_to_off[key] = off
        return off

    index = bytearray()
    for oui, name in entries:
        off = intern(name)
        index.extend(oui)                          # 3 bytes
        index.extend(off.to_bytes(3, "little"))    # name offset u24 LE

    record_count = len(entries)
    names_offset = V2_HEADER_SIZE + len(index)

    header = bytearray(V2_HEADER_SIZE)
    header[0:4] = V2_MAGIC
    header[4] = V2_VERSION
    header[5] = 3                       # oui_len
    header[6] = V2_INDEX_ENTRY_SIZE     # index entry size
    header[7] = 0                       # reserved
    header[8:12] = record_count.to_bytes(4, "little")
    header[12:16] = names_offset.to_bytes(4, "little")

    return bytes(header) + bytes(index) + bytes(name_table)


def main():
    parser = argparse.ArgumentParser(
        description="Convert oui.txt to the JanOS Wi-Fi vendor binary table."
    )
    parser.add_argument("--input", type=pathlib.Path, default=pathlib.Path("oui.txt"))
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("oui_wifi.bin"))
    parser.add_argument("--format", choices=["v1", "v2"], default="v2",
                        help="output format (default v2; firmware reads both)")
    parser.add_argument("--all", action="store_true",
                        help="keep every OUI instead of only the Wi-Fi vendor whitelist "
                             "(recommended with v2; fewer 'missing' lookups)")
    args = parser.parse_args()

    oui_map = parse_oui_file(args.input)
    entries = select_entries(oui_map, keep_all=args.all)

    if args.format == "v1":
        blob = build_v1(entries)
    else:
        blob = build_v2(entries)

    with args.output.open("wb") as out_file:
        out_file.write(blob)

    scope = "all OUIs" if args.all else "Wi-Fi vendor whitelist"
    print(f"Parsed {len(oui_map)} OUI entries, kept {len(entries)} ({scope}).")
    print(f"Wrote {args.format} format: {len(blob)} bytes -> {args.output}")
    if args.format == "v2":
        unique_names = len({name.encode('utf-8')[:V2_NAME_MAX] for _, name in entries})
        print(f"  index: {len(entries)} x {V2_INDEX_ENTRY_SIZE}B, "
              f"unique vendor names: {unique_names}")
    if entries:
        sample = ", ".join(name for _, name in entries[:10])
        print(f"Sample vendors: {sample}")


if __name__ == "__main__":
    main()
