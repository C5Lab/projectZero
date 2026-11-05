import tempfile
import unittest
from pathlib import Path
from unittest import mock
import subprocess
import shutil
import base64
import hashlib
import json
import os
import sys

from tools.cvedb.sign_catalog import (P256_ORDER, canonical_low_s_der,
                                      enforce_key_location, sign_catalog)


ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


def integer(value):
    raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\0" + raw
    return b"\x02" + bytes([len(raw)]) + raw


def signature(r, s):
    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


class SignCatalogTests(unittest.TestCase):
    def test_high_s_is_canonicalized_without_private_material(self):
        result = canonical_low_s_der(signature(1, P256_ORDER - 1))
        self.assertEqual(result, signature(1, 1))
        for bad in (b"", signature(0, 1), signature(1, P256_ORDER),
                    signature(1, 1) + b"\0", b"\x30\x07\x02\x02\0\1\x02\1\1"):
            with self.assertRaises(ValueError):
                canonical_low_s_der(bad)

    def test_repository_private_key_policy_is_fail_closed(self):
        with self.assertRaises(ValueError):
            enforce_key_location(ROOT / "secret.pem", ROOT, False)
        with self.assertRaises(ValueError):
            enforce_key_location(ROOT / "main/secret.pem", ROOT, True)
        enforce_key_location(ROOT / "tests/fixtures/test-only.pem", ROOT, True)
        with tempfile.TemporaryDirectory() as directory:
            enforce_key_location(Path(directory) / "external.pem", ROOT, False)

    def test_signer_builds_exact_detached_container_without_key_output(self):
        catalog = ROOT / "tests/fixtures/router_cve_v1.bin"
        key_id = catalog.read_bytes()[112:128].hex()
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            key = directory / "external-private.pem"
            output = directory / "catalog.sig"
            key.write_text("not-real-private-material", encoding="ascii")

            def fake_run(command, **kwargs):
                del kwargs
                raw = Path(command[command.index("-out") + 1])
                raw.write_bytes(signature(1, P256_ORDER - 1))
                return mock.Mock(returncode=0)

            with mock.patch("tools.cvedb.sign_catalog.subprocess.run", side_effect=fake_run):
                digest, returned_id = sign_catalog(catalog, key, output, key_id)
            blob = output.read_bytes()
            self.assertEqual(blob[:4], b"JCSG")
            self.assertEqual(int.from_bytes(blob[4:6], "little"), 1)
            self.assertEqual(int.from_bytes(blob[6:8], "little"), 80)
            self.assertEqual(int.from_bytes(blob[12:16], "little"), len(blob))
            self.assertEqual(blob[16:32].hex(), key_id)
            self.assertEqual(blob[80:], signature(1, 1))
            self.assertEqual(returned_id, key_id)
            self.assertEqual(len(digest), 64)
            self.assertNotIn(key.read_bytes(), blob)

            output.write_bytes(b"existing")
            with mock.patch("tools.cvedb.sign_catalog.subprocess.run",
                            side_effect=subprocess.CalledProcessError(1, "openssl")):
                with self.assertRaises(subprocess.CalledProcessError):
                    sign_catalog(catalog, key, output, key_id)
            self.assertEqual(output.read_bytes(), b"existing")

    def test_real_openssl_p256_sign_and_independent_verify(self):
        catalog = ROOT / "tests/fixtures/router_cve_v1.bin"
        key_id = catalog.read_bytes()[112:128].hex()
        wsl = shutil.which("wsl.exe") if os.name == "nt" else None
        openssl = shutil.which("openssl") if os.name != "nt" else None
        if wsl is None and openssl is None:
            self.skipTest("OpenSSL is not available")
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            key = directory / "ephemeral-test-key.pem"
            public = directory / "ephemeral-test-public.pem"
            output = directory / "catalog.sig"
            der = directory / "catalog.der"
            # Deterministic nonsecret test scalar derived at runtime. No PEM
            # or private-key fixture is stored in the repository.
            scalar_value = (int.from_bytes(hashlib.sha256(
                b"JanOS JCSG/1 nonsecret P-256 test vector").digest(), "big") %
                (P256_ORDER - 1)) + 1
            scalar = scalar_value.to_bytes(32, "big")
            sec1 = (bytes.fromhex("30310201010420") + scalar +
                    bytes.fromhex("a00a06082a8648ce3d030107"))
            encoded = base64.b64encode(sec1).decode("ascii")
            key.write_text("-----BEGIN EC PRIVATE KEY-----\n" + encoded +
                           "\n-----END EC PRIVATE KEY-----\n", encoding="ascii")
            if wsl:
                commands = [
                    [wsl, "--cd", wsl_path(ROOT), "python3", "-m", "tools.cvedb.sign_catalog",
                     "--catalog", wsl_path(catalog), "--private-key", wsl_path(key),
                     "--output", wsl_path(output), "--key-id", key_id,
                     "--openssl", "openssl"],
                    [wsl, "openssl", "pkey", "-in", wsl_path(key), "-pubout",
                     "-out", wsl_path(public)],
                ]
                domain_command = [wsl, "openssl", "pkey", "-pubin", "-in",
                                  wsl_path(public), "-text", "-noout"]
                verify_command = [wsl, "openssl", "dgst", "-sha256", "-verify",
                                  wsl_path(public), "-signature", wsl_path(der),
                                  wsl_path(catalog)]
            else:
                commands = [
                    [sys.executable, "-m", "tools.cvedb.sign_catalog",
                     "--catalog", str(catalog), "--private-key", str(key),
                     "--output", str(output), "--key-id", key_id,
                     "--openssl", openssl],
                    [openssl, "pkey", "-in", str(key), "-pubout", "-out", str(public)],
                ]
                domain_command = [openssl, "pkey", "-pubin", "-in", str(public),
                                  "-text", "-noout"]
                verify_command = [openssl, "dgst", "-sha256", "-verify", str(public),
                                  "-signature", str(der), str(catalog)]
            outputs = []
            for command in commands:
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
                if result.returncode != 0 and ("E_ACCESSDENIED" in result.stderr or
                                                "CreateInstance" in result.stderr):
                    self.skipTest("sandbox denied WSL instance creation")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                outputs.append(result.stdout + result.stderr)
            blob = output.read_bytes()
            der.write_bytes(blob[80:])
            self.assertEqual(canonical_low_s_der(blob[80:]), blob[80:])
            domain = subprocess.run(
                domain_command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(domain.returncode, 0, domain.stdout + domain.stderr)
            self.assertIn("prime256v1", domain.stdout)
            verified = subprocess.run(
                verify_command,
                cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(verified.returncode, 0, verified.stdout + verified.stderr)
            self.assertIn("Verified OK", verified.stdout)
            self.assertTrue(all("PRIVATE KEY" not in output_text for output_text in outputs))

    def test_esp_idf_mbedtls4_adapter_behavior(self):
        wsl = shutil.which("wsl.exe")
        if wsl is None:
            self.skipTest("WSL is not available")
        cmake_lookup = subprocess.run(
            [wsl, "sh", "-lc", "command -v cmake"], cwd=ROOT,
            capture_output=True, text=True)
        if cmake_lookup.returncode != 0 or not cmake_lookup.stdout.strip():
            self.skipTest("WSL CMake is unavailable")
        cmake = cmake_lookup.stdout.strip()
        project_description = ROOT / "build/project_description.json"
        idf_path = os.environ.get("IDF_PATH")
        if not idf_path and project_description.is_file():
            idf_path = json.loads(project_description.read_text(
                encoding="utf-8"))["idf_path"]
        if not idf_path:
            self.skipTest("configured ESP-IDF path is unavailable")
        idf_path = Path(idf_path)
        mbedtls_source = idf_path / "components/mbedtls/mbedtls"
        config_include = ROOT / "build/config"
        if not mbedtls_source.is_dir() or not (config_include / "sdkconfig.h").is_file():
            self.skipTest("configured ESP-IDF Mbed TLS 4 source is unavailable")

        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            message = directory / "message.bin"
            message.write_bytes(b"JanOS Mbed TLS 4 adapter behavior test\n")
            digest = directory / "digest.bin"
            signature_path = directory / "signature.der"
            tampered = directory / "signature-tampered.der"
            public_keys = {}
            key_specs = {
                "p256": ["EC", "ec_paramgen_curve:prime256v1"],
                "secp256k1": ["EC", "ec_paramgen_curve:secp256k1"],
                "p384": ["EC", "ec_paramgen_curve:secp384r1"],
                "rsa": ["RSA", "rsa_keygen_bits:2048"],
            }
            for name, (algorithm, option) in key_specs.items():
                private = directory / f"{name}-private.pem"
                public = directory / f"{name}-public.der"
                generated = subprocess.run([
                    wsl, "openssl", "genpkey", "-algorithm", algorithm,
                    "-pkeyopt", option, "-out", wsl_path(private),
                ], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(generated.returncode, 0,
                                 generated.stdout + generated.stderr)
                exported = subprocess.run([
                    wsl, "openssl", "pkey", "-in", wsl_path(private),
                    "-pubout", "-outform", "DER", "-out", wsl_path(public),
                ], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(exported.returncode, 0,
                                 exported.stdout + exported.stderr)
                public_keys[name] = public

            commands = [
                [wsl, "openssl", "dgst", "-sha256", "-binary", "-out",
                 wsl_path(digest), wsl_path(message)],
                [wsl, "openssl", "dgst", "-sha256", "-sign",
                 wsl_path(directory / "p256-private.pem"), "-out",
                 wsl_path(signature_path), wsl_path(message)],
            ]
            for command in commands:
                completed = subprocess.run(command, cwd=ROOT,
                                           capture_output=True, text=True)
                self.assertEqual(completed.returncode, 0,
                                 completed.stdout + completed.stderr)
            tampered_bytes = bytearray(signature_path.read_bytes())
            tampered_bytes[-1] ^= 1
            tampered.write_bytes(tampered_bytes)

            build_dir = f"/tmp/janos-mbedtls4-adapter-{os.getpid()}"
            subprocess.run([wsl, "rm", "-rf", build_dir], cwd=ROOT,
                           capture_output=True, text=True)
            try:
                configure = subprocess.run([
                    wsl, cmake, "-S", wsl_path(ROOT / "tests/mbedtls4_adapter"),
                    "-B", build_dir, "-DCMAKE_BUILD_TYPE=Release",
                    "-DCMAKE_POLICY_VERSION_MINIMUM=3.5",
                    f"-DIDF_PATH={wsl_path(idf_path)}",
                    f"-DJANOS_ROOT={wsl_path(ROOT)}",
                    f"-DJANOS_CONFIG_INCLUDE={wsl_path(config_include)}",
                ], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(configure.returncode, 0,
                                 configure.stdout + configure.stderr)
                built = subprocess.run([
                    wsl, cmake, "--build", build_dir, "--parallel", "4",
                    "--target", "router_cve_mbedtls4_test",
                ], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
                run = subprocess.run([
                    wsl, f"{build_dir}/router_cve_mbedtls4_test",
                    wsl_path(public_keys["p256"]), wsl_path(digest),
                    wsl_path(signature_path), wsl_path(tampered),
                    wsl_path(public_keys["rsa"]),
                    wsl_path(public_keys["secp256k1"]),
                    wsl_path(public_keys["p384"]),
                ], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            finally:
                subprocess.run([wsl, "rm", "-rf", build_dir], cwd=ROOT,
                               capture_output=True, text=True)


if __name__ == "__main__":
    unittest.main()
