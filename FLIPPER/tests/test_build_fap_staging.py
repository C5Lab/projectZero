"""Regression checks for preserving published FAPs during a failed build."""

import argparse
import importlib.util
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "build_fap.py"
SPEC = importlib.util.spec_from_file_location("lab_c5_build_fap", SCRIPT)
assert SPEC and SPEC.loader
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


def minimal_elf32() -> bytes:
    """A hand-built ELF32 header with one bounded section table entry."""
    blob = bytearray(52 + 40)
    blob[:6] = b"\x7fELF\x01\x01"
    struct.pack_into("<I", blob, 24, 0x1000)  # e_entry
    struct.pack_into("<I", blob, 32, 52)  # e_shoff
    struct.pack_into("<HHH", blob, 46, 40, 1, 0)  # e_shentsize, e_shnum, e_shstrndx
    return bytes(blob)


class StagedBuildTests(unittest.TestCase):
    def test_builder_requires_all_modular_plugins(self) -> None:
        with patch.object(
            builder.subprocess,
            "run",
            return_value=SimpleNamespace(returncode=0, stdout="ok", stderr=""),
        ) as run:
            builder.validate_embedded_plugin(Path("trial.fap"))
        argv = run.call_args.args[0]
        self.assertIn("--require-recon", argv)
        self.assertIn("--require-rogue", argv)
        self.assertIn("--require-arp", argv)
        self.assertEqual(
            [argv[i + 1] for i, value in enumerate(argv[:-1]) if value == "--require-plugin"],
            [
                "lab_c5_wardrive", "lab_c5_beacon", "lab_c5_mitm_pcap",
                "lab_c5_wardrive_upload", "lab_c5_nmap", "lab_c5_wpasec",
                "lab_c5_connect",
            ],
        )

    def test_trial_name_is_stable_and_rejects_paths(self) -> None:
        self.assertEqual(
            builder.artifact_target(Path("dist"), "0.41", "unleashed", "modular_web_trial"),
            Path("dist/lab_c5_v0.41_unleashed_modular_web_trial.fap"),
        )
        for bad in ("../other", "../other.fap", "a/b", "a\\b", "", ".hidden"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                builder.artifact_target(Path("dist"), "0.41", "unleashed", bad)

    def test_selected_variant_only_publishes_named_trial(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "project"
            dist = root / "dist"
            dist.mkdir(parents=True)
            source = root / "Lab_C5.c"
            source.write_text('#define LAB_C5_VERSION_TEXT "0.41"\n', encoding="utf-8")
            regular = dist / "lab_c5_v0.41_unleashed.fap"
            regular.write_bytes(b"current build")
            picked: list[str] = []

            def fake_pick(_sdk_dir: Path, patterns: tuple[str, ...], _exclude: tuple[str, ...]):
                picked.append(patterns[0])
                return root / "sdk" / "unleashed.zip"

            def fake_build(project_dir: Path) -> None:
                artifact = project_dir / "dist" / "lab_c5.fap"
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(minimal_elf32())

            with (
                patch.object(builder, "ROOT", root),
                patch.object(builder, "DIST_DIR", dist),
                patch.object(builder, "SOURCE_FILE", source),
                patch.object(
                    builder,
                    "parse_args",
                    return_value=argparse.Namespace(
                        sdk_dir=root / "sdk", no_upload=True,
                        variant="unleashed", artifact_suffix="modular_web_trial",
                    ),
                ),
                patch.object(builder, "ensure_dependencies"),
                patch.object(builder, "pick_sdk", side_effect=fake_pick),
                patch.object(builder, "update_sdk"),
                patch.object(builder, "build_app", side_effect=fake_build),
                patch.object(builder, "validate_embedded_plugin"),
            ):
                builder.main()

            self.assertEqual(picked, ["unlsh"])
            self.assertEqual(regular.read_bytes(), b"current build")
            self.assertEqual(
                (dist / "lab_c5_v0.41_unleashed_modular_web_trial.fap").read_bytes(),
                minimal_elf32(),
            )

    def test_failed_build_keeps_existing_and_trial_faps(self) -> None:
        # Catches cleanup_dist_faps() running before a replacement is available.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "project"
            dist = root / "dist"
            dist.mkdir(parents=True)
            source = root / "Lab_C5.c"
            source.write_text('#define LAB_C5_VERSION_TEXT "0.41"\n', encoding="utf-8")
            old = dist / "lab_c5_v0.41_unleashed.fap"
            trial = dist / "lab_c5_v0.41_unleashed_lowram_trial.fap"
            old.write_bytes(b"old known-good artifact")
            trial.write_bytes(b"unpublished trial")
            with (
                patch.object(builder, "ROOT", root),
                patch.object(builder, "DIST_DIR", dist),
                patch.object(builder, "SOURCE_FILE", source),
                patch.object(
                    builder,
                    "parse_args",
                    return_value=argparse.Namespace(sdk_dir=root / "sdk", no_upload=True),
                ),
                patch.object(builder, "ensure_dependencies"),
                patch.object(builder, "pick_sdk", return_value=root / "sdk" / "unleashed.zip"),
                patch.object(builder, "update_sdk"),
                patch.object(builder, "build_app", side_effect=RuntimeError("compile failed")),
            ):
                with self.assertRaisesRegex(RuntimeError, "compile failed"):
                    builder.main()
            self.assertTrue(old.exists(), "failed build removed the existing FAP")
            self.assertEqual(old.read_bytes(), b"old known-good artifact")
            self.assertEqual(trial.read_bytes(), b"unpublished trial")

    def test_invalid_new_fap_does_not_replace_existing_target(self) -> None:
        # Catches publication before basic ELF validation.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = root / "candidate.fap"
            target = root / "lab_c5_v0.41_unleashed.fap"
            candidate.write_bytes(b"not an ELF")
            target.write_bytes(b"old artifact")
            with self.assertRaises(ValueError):
                builder.publish_artifact(candidate, target)
            self.assertEqual(target.read_bytes(), b"old artifact")

    def test_valid_new_fap_replaces_only_named_target(self) -> None:
        # Catches accidental cleanup of neighboring versioned/trial builds.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            candidate = root / "candidate.fap"
            target = root / "lab_c5_v0.41_unleashed.fap"
            neighbor = root / "lab_c5_v0.41_unleashed_lowram_trial.fap"
            candidate.write_bytes(minimal_elf32())
            target.write_bytes(b"old artifact")
            neighbor.write_bytes(b"trial")
            builder.publish_artifact(candidate, target)
            self.assertEqual(target.read_bytes(), minimal_elf32())
            self.assertEqual(neighbor.read_bytes(), b"trial")

    def test_each_firmware_variant_uses_an_isolated_build_directory(self) -> None:
        # Catches stale object files leaking from one SDK variant into another.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "project"
            dist = root / "dist"
            dist.mkdir(parents=True)
            source = root / "Lab_C5.c"
            source.write_text('#define LAB_C5_VERSION_TEXT "0.41"\n', encoding="utf-8")
            stage_dirs: list[Path] = []

            def fake_build(project_dir: Path) -> None:
                stage_dirs.append(project_dir)
                artifact = project_dir / "dist" / "lab_c5.fap"
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(minimal_elf32() + bytes([len(stage_dirs)]))

            with (
                patch.object(builder, "ROOT", root),
                patch.object(builder, "DIST_DIR", dist),
                patch.object(builder, "SOURCE_FILE", source),
                patch.object(
                    builder,
                    "parse_args",
                    return_value=argparse.Namespace(sdk_dir=root / "sdk", no_upload=True),
                ),
                patch.object(builder, "ensure_dependencies"),
                patch.object(builder, "pick_sdk", side_effect=[root / "dev.zip", root / "mntm.zip", None]),
                patch.object(builder, "update_sdk"),
                patch.object(builder, "build_app", side_effect=fake_build),
                patch.object(builder, "validate_embedded_plugin"),
            ):
                builder.main()

            self.assertEqual(len(stage_dirs), 2)
            self.assertNotEqual(stage_dirs[0], stage_dirs[1])
            self.assertEqual(
                (dist / "lab_c5_v0.41_momentum_dev.fap").read_bytes(), minimal_elf32() + b"\x01"
            )
            self.assertEqual(
                (dist / "lab_c5_v0.41_momentum.fap").read_bytes(), minimal_elf32() + b"\x02"
            )

    def test_web_plugin_check_failure_preserves_existing_target(self) -> None:
        # Catches publishing a host FAP when its embedded Web plugin is absent or corrupt.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "project"
            dist = root / "dist"
            dist.mkdir(parents=True)
            source = root / "Lab_C5.c"
            source.write_text('#define LAB_C5_VERSION_TEXT "0.41"\n', encoding="utf-8")
            target = dist / "lab_c5_v0.41_momentum_dev.fap"
            target.write_bytes(b"known-good host")

            def fake_build(project_dir: Path) -> None:
                artifact = project_dir / "dist" / "lab_c5.fap"
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(minimal_elf32())

            with (
                patch.object(builder, "ROOT", root),
                patch.object(builder, "DIST_DIR", dist),
                patch.object(builder, "SOURCE_FILE", source),
                patch.object(
                    builder,
                    "parse_args",
                    return_value=argparse.Namespace(sdk_dir=root / "sdk", no_upload=True),
                ),
                patch.object(builder, "ensure_dependencies"),
                patch.object(builder, "pick_sdk", return_value=root / "dev.zip"),
                patch.object(builder, "update_sdk"),
                patch.object(builder, "build_app", side_effect=fake_build),
                patch.object(
                    builder,
                    "validate_embedded_plugin",
                    side_effect=ValueError("embedded plugins/lab_c5_web.fal is missing"),
                ),
            ):
                with self.assertRaisesRegex(ValueError, "plugins/lab_c5_web.fal"):
                    builder.main()
            self.assertEqual(target.read_bytes(), b"known-good host")

    def test_embedded_plugin_validator_rejects_host_without_plugin(self) -> None:
        # Catches a checker invocation that silently accepts a host-only FAP.
        with tempfile.TemporaryDirectory() as temp:
            candidate = Path(temp) / "host_only.fap"
            candidate.write_bytes(minimal_elf32())
            with self.assertRaises(ValueError):
                builder.validate_embedded_plugin(candidate)

    def test_optional_upload_uses_exact_published_versioned_fap(self) -> None:
        # Catches `ufbt launch` rebuilding an unversioned staging artifact.
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "project"
            dist = root / "dist"
            dist.mkdir(parents=True)
            source = root / "Lab_C5.c"
            source.write_text('#define LAB_C5_VERSION_TEXT "0.41"\n', encoding="utf-8")
            built_paths: list[Path] = []
            uploaded_paths: list[Path] = []

            def fake_build(project_dir: Path) -> None:
                built_paths.append(project_dir)
                artifact = project_dir / "dist" / "lab_c5.fap"
                artifact.parent.mkdir(parents=True, exist_ok=True)
                artifact.write_bytes(minimal_elf32())

            def fake_upload(path: Path) -> None:
                uploaded_paths.append(path)
                self.assertEqual(path.read_bytes(), minimal_elf32())

            with (
                patch.object(builder, "ROOT", root),
                patch.object(builder, "DIST_DIR", dist),
                patch.object(builder, "SOURCE_FILE", source),
                patch.object(
                    builder,
                    "parse_args",
                    return_value=argparse.Namespace(sdk_dir=root / "sdk", no_upload=False),
                ),
                patch.object(builder, "ensure_dependencies"),
                patch.object(builder, "pick_sdk", side_effect=[None, None, root / "unleashed.zip"]),
                patch.object(builder, "update_sdk"),
                patch.object(builder, "build_app", side_effect=fake_build),
                patch.object(builder, "validate_embedded_plugin"),
                patch.object(builder, "prompt_upload_choice", side_effect=lambda built: built[0]),
                patch.object(builder, "upload_app", side_effect=fake_upload),
                patch.dict("os.environ", {"CI": ""}),
            ):
                builder.main()

            self.assertEqual(len(built_paths), 1)
            self.assertEqual(uploaded_paths, [dist / "lab_c5_v0.41_unleashed.fap"])

    def test_upload_helper_uses_deployer_options_with_selected_fap(self) -> None:
        # Catches bypassing the existing COM/path/purge/start prompts.
        with tempfile.TemporaryDirectory() as temp:
            fap = Path(temp) / "lab_c5_v0.41_unleashed.fap"
            fap.write_bytes(minimal_elf32())
            uploads: list[tuple[Path, str, str, bool, bool]] = []
            answers = iter([True, False])
            deployer = SimpleNamespace(
                pick_port=lambda: "COM7",
                prompt_flipper_path=lambda default: "/ext/apps/GPIO",
                prompt_yes_no=lambda question, default: next(answers),
                upload_via_serial=lambda *args: uploads.append(args),
            )
            with patch.object(builder, "load_deployer", return_value=deployer):
                builder.upload_app(fap)
            self.assertEqual(uploads, [(fap, "COM7", "/ext/apps/GPIO", True, False)])


if __name__ == "__main__":
    unittest.main()
