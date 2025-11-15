#!/usr/bin/env python3
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
]

# Fixed record size: 3 bytes OUI + 1 byte name length + 60 bytes name (padded)
RECORD_NAME_BYTES = 60
RECORD_STRUCT = struct.Struct("!3sB{}s".format(RECORD_NAME_BYTES))


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
                # alternate header, ignore – handled via (hex) section
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


def build_records(oui_map):
    filtered = [
        (oui, name)
        for (oui, name) in oui_map.items()
        if should_keep_vendor(name)
    ]
    filtered.sort(key=lambda item: item[0])
    records = []
    for oui, name in filtered:
        truncated = name.encode("utf-8")[:RECORD_NAME_BYTES]
        length = len(truncated)
        encoded = truncated.ljust(RECORD_NAME_BYTES, b"\x00")
        records.append(RECORD_STRUCT.pack(oui, length, encoded))
    return records, filtered


def main():
    parser = argparse.ArgumentParser(description="Convert oui.txt to compact Wi-Fi vendor binary table.")
    parser.add_argument("--input", type=pathlib.Path, default=pathlib.Path("oui.txt"))
    parser.add_argument("--output", type=pathlib.Path, default=pathlib.Path("oui_wifi.bin"))
    args = parser.parse_args()

    oui_map = parse_oui_file(args.input)
    records, filtered = build_records(oui_map)

    with args.output.open("wb") as out_file:
        for record in records:
            out_file.write(record)

    print(f"Parsed {len(oui_map)} OUI entries, kept {len(filtered)} Wi-Fi vendor entries.")
    if filtered:
        sample = ", ".join(name for _, name in filtered[:10])
        print(f"Sample vendors: {sample}")


if __name__ == "__main__":
    main()
