"""Binary checks for optional embedded FAL sets in a host FAP."""

import struct
import tempfile
import unittest
from pathlib import Path

from check_embedded_plugin import check, main


ASSETS_MAGIC = 0x4F4C5A44


def make_assets(files: dict[str, bytes]) -> bytes:
    data = bytearray(struct.pack("<IIIII", ASSETS_MAGIC, 1, 0, len(files), 0))
    for name, payload in files.items():
        encoded = name.encode("utf-8") + b"\0"
        data += struct.pack("<I", len(encoded)) + encoded
        data += struct.pack("<I", len(payload)) + payload
    return bytes(data)


def make_elf(
    path: Path,
    entry_name: str,
    *,
    abi_version: int = 3,
    module_version: int = 3,
    assets: bytes | None = None,
    extra_symbols: tuple[str, ...] = (),
) -> bytes:
    """Create the ELF32 sections and Thumb entry trampoline used by the SDK."""
    rodata = bytearray(72)
    rodata[:7] = b"lab_c5\0"
    struct.pack_into("<III", rodata, 16, 0, abi_version, 32)
    struct.pack_into("<II", rodata, 32, module_version, 40)
    text = b"\x00\x48\x70\x47" + struct.pack("<I", 16)

    names = [entry_name, *extra_symbols]
    strtab = bytearray(b"\0")
    name_offsets = {}
    for name in names:
        name_offsets[name] = len(strtab)
        strtab += name.encode("ascii") + b"\0"
    symtab = bytearray(16)
    for name in names:
        symtab += struct.pack("<IIIBBH", name_offsets[name], 1, 0, 0, 0, 1)

    entries = [
        (".text", 1, 0x6, text),
        (".rodata", 1, 0x2, bytes(rodata)),
    ]
    if assets is not None:
        entries.append((".fapassets", 1, 0, assets))
    entries.extend([(".symtab", 2, 0, bytes(symtab)), (".strtab", 3, 0, bytes(strtab))])
    names_blob = bytearray(b"\0")
    section_name_offsets = {}
    for name, *_ in entries:
        section_name_offsets[name] = len(names_blob)
        names_blob += name.encode("ascii") + b"\0"
    section_name_offsets[".shstrtab"] = len(names_blob)
    names_blob += b".shstrtab\0"
    entries.append((".shstrtab", 3, 0, bytes(names_blob)))

    blob = bytearray(52)
    blob[:6] = b"\x7fELF\x01\x01"
    struct.pack_into("<I", blob, 24, 1)
    headers = [(0, 0, 0, 0, 0, 0)]
    symtab_index = next(i for i, entry in enumerate(entries, start=1) if entry[0] == ".symtab")
    strtab_index = next(i for i, entry in enumerate(entries, start=1) if entry[0] == ".strtab")
    for name, section_type, flags, payload in entries:
        offset = len(blob)
        blob += payload
        link = strtab_index if name == ".symtab" else 0
        headers.append((section_name_offsets[name], section_type, flags, offset, len(payload), link))
    section_offset = len(blob)
    for name_offset, section_type, flags, offset, size, link in headers:
        # FAP relocation pointers are section-relative even when sh_addr is nonzero.
        address = 0x200 if name_offset == section_name_offsets[".rodata"] else 0
        blob += struct.pack("<IIIIIIIIII", name_offset, section_type, flags, address, offset, size, link, 0, 1, 16 if link else 0)
    struct.pack_into("<I", blob, 32, section_offset)
    struct.pack_into("<HHH", blob, 46, 40, len(headers), len(headers) - 1)
    path.write_bytes(blob)
    return bytes(blob)


class EmbeddedPluginTests(unittest.TestCase):
    def make_bundle(
        self,
        root: Path,
        *,
        include_web: bool = True,
        web_abi: int = 3,
        web_module_version: int = 3,
        include_recon: bool = False,
        recon_abi: int = 3,
        recon_module_version: int = 3,
        recon_entry: str = "lab_c5_recon_plugin_ep",
        include_rogue: bool = False,
        include_arp: bool = False,
        extra_plugins: tuple[str, ...] = (),
        host_extra_symbols: tuple[str, ...] = (),
    ) -> Path:
        gps = make_elf(root / "gps.fal", "lab_c5_gps_plugin_ep", extra_symbols=("gps_coord_format",))
        web = make_elf(
            root / "web.fal",
            "lab_c5_web_plugin_ep",
            abi_version=web_abi,
            module_version=web_module_version,
        )
        files = {"plugins/lab_c5_gps.fal": gps}
        if include_web:
            files["plugins/lab_c5_web.fal"] = web
        if include_recon:
            files["plugins/lab_c5_recon.fal"] = make_elf(
                root / "recon.fal",
                recon_entry,
                abi_version=recon_abi,
                module_version=recon_module_version,
            )
        if include_rogue:
            files["plugins/lab_c5_rogue.fal"] = make_elf(
                root / "rogue.fal", "lab_c5_rogue_plugin_ep"
            )
        if include_arp:
            files["plugins/lab_c5_arp.fal"] = make_elf(
                root / "arp.fal", "lab_c5_arp_plugin_ep"
            )
        for name in extra_plugins:
            files[f"plugins/{name}.fal"] = make_elf(
                root / f"{name}.fal", f"{name}_plugin_ep"
            )
        host = root / "host.fap"
        make_elf(host, "Lab_C5_app", assets=make_assets(files), extra_symbols=host_extra_symbols)
        return host

    def test_accepts_both_valid_embedded_modules(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            check(self.make_bundle(Path(temp)))

    def test_rejects_missing_web_module(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "plugins/lab_c5_web.fal"):
                check(self.make_bundle(Path(temp), include_web=False))

    def test_rejects_wrong_web_descriptor_abi(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "ABI version"):
                check(self.make_bundle(Path(temp), web_abi=2))

    def test_rejects_wrong_web_vtable_abi(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "module ABI"):
                check(self.make_bundle(Path(temp), web_module_version=2))

    def test_rejects_plugin_entrypoint_linked_into_host(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "linked into host"):
                check(self.make_bundle(Path(temp), host_extra_symbols=("lab_c5_web_plugin_ep",)))

    def test_trial_requires_recon_but_default_accepts_two_modules(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            host = self.make_bundle(Path(temp))
            check(host)
            with self.assertRaisesRegex(ValueError, "plugins/lab_c5_recon.fal"):
                check(host, require_recon=True)

    def test_trial_accepts_valid_recon_and_optional_loose_fal(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            host = self.make_bundle(root, include_recon=True)
            check(host, require_recon=True, recon_plugin_path=root / "recon.fal")
            self.assertEqual(main([str(host), "--require-recon"]), 0)

    def test_trial_rejects_wrong_recon_entry_and_descriptor_abi(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "lab_c5_recon_plugin_ep"):
                check(self.make_bundle(root, include_recon=True, recon_entry="other_ep"), require_recon=True)
            with self.assertRaisesRegex(ValueError, "ABI version"):
                check(self.make_bundle(root, include_recon=True, recon_abi=2), require_recon=True)
            with self.assertRaisesRegex(ValueError, "module ABI"):
                check(self.make_bundle(root, include_recon=True, recon_module_version=2), require_recon=True)

    def test_trial_rejects_recon_entry_linked_into_host(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            host = self.make_bundle(
                Path(temp), include_recon=True,
                host_extra_symbols=("lab_c5_recon_plugin_ep",),
            )
            with self.assertRaisesRegex(ValueError, "linked into host"):
                check(host, require_recon=True)

    def test_trial_rejects_loose_recon_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            host = self.make_bundle(root, include_recon=True)
            (root / "recon.fal").write_bytes(b"other")
            with self.assertRaisesRegex(ValueError, "differs from FAL"):
                check(host, require_recon=True, recon_plugin_path=root / "recon.fal")

    def test_light_trial_requires_both_new_modules(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            recon_only = self.make_bundle(root, include_recon=True)
            with self.assertRaisesRegex(ValueError, "plugins/lab_c5_rogue.fal"):
                check(recon_only, require_recon=True, require_rogue=True, require_arp=True)
            with_rogue = self.make_bundle(root, include_recon=True, include_rogue=True)
            with self.assertRaisesRegex(ValueError, "plugins/lab_c5_arp.fal"):
                check(with_rogue, require_recon=True, require_rogue=True, require_arp=True)
            complete = self.make_bundle(root, include_recon=True, include_rogue=True, include_arp=True)
            check(complete, require_recon=True, require_rogue=True, require_arp=True)
            self.assertEqual(
                main([str(complete), "--require-recon", "--require-rogue", "--require-arp"]),
                0,
            )

    def test_light_trial_rejects_new_entry_linked_into_host(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            host = self.make_bundle(
                root, include_recon=True, include_rogue=True, include_arp=True,
                host_extra_symbols=("lab_c5_arp_plugin_ep",),
            )
            with self.assertRaisesRegex(ValueError, "linked into host"):
                check(host, require_recon=True, require_rogue=True, require_arp=True)

    def test_extra_fal_must_be_embedded_with_its_entry_and_abi(self) -> None:
        name = "lab_c5_wardrive"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            old_host = self.make_bundle(root)
            with self.assertRaisesRegex(ValueError, "plugins/lab_c5_wardrive.fal"):
                check(old_host, required_plugins=(name,))
            complete = self.make_bundle(root, extra_plugins=(name,))
            check(complete, required_plugins=(name,))
            self.assertEqual(main([str(complete), "--require-plugin", name]), 0)

    def test_extra_fal_entry_must_not_be_linked_into_host(self) -> None:
        name = "lab_c5_beacon"
        with tempfile.TemporaryDirectory() as temp:
            host = self.make_bundle(
                Path(temp), extra_plugins=(name,),
                host_extra_symbols=(f"{name}_plugin_ep",),
            )
            with self.assertRaisesRegex(ValueError, "linked into host"):
                check(host, required_plugins=(name,))


if __name__ == "__main__":
    unittest.main()
