import os
import shutil
import hashlib
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def wsl_path(path):
    path = Path(path).resolve()
    return (f"/mnt/{path.drive.rstrip(':').lower()}/"
            f"{path.relative_to(path.anchor).as_posix()}")


class RouterCveVerifyTests(unittest.TestCase):
    def test_c_verifier_and_install_state_machine(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            catalog = (ROOT / "tests/fixtures/router_cve_v1.bin").read_bytes()
            catalog8 = bytearray(catalog)
            struct.pack_into("<Q", catalog8, 40, 8)
            catalog8_path = directory / "catalog8.bin"
            catalog8_path.write_bytes(catalog8)

            def make_signature(blob, path, key_id=None):
                der = bytes.fromhex("3006020101020101")
                key_id = blob[112:128] if key_id is None else key_id
                header = bytearray(80)
                header[0:4] = b"JCSG"
                struct.pack_into("<HHII", header, 4, 1, 80, 0, 80 + len(der))
                header[16:32] = key_id
                header[32:64] = hashlib.sha256(blob).digest()
                struct.pack_into("<H", header, 64, len(der))
                path.write_bytes(header + der)

            signature7 = directory / "catalog7.sig"
            signature8 = directory / "catalog8.sig"
            make_signature(catalog, signature7)
            make_signature(catalog8, signature8)
            max_catalog = directory / "catalog-max.bin"
            max_catalog_blob = bytes(4 * 1024 * 1024)
            max_catalog.write_bytes(max_catalog_blob)
            max_signature = directory / "catalog-max.sig"
            make_signature(max_catalog_blob, max_signature, catalog[112:128])
            exe = Path(directory) / "router_cve_verify_test"
            compiler = shutil.which(os.environ.get("CC", "")) or next(
                (shutil.which(name) for name in ("cc", "gcc", "clang")
                 if shutil.which(name)), None)
            flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic",
                     "-Dmalloc=router_cve_test_malloc",
                     "-Dcalloc=router_cve_test_calloc",
                     "-Dfree=router_cve_test_free"]
            if os.environ.get("JANOS_TEST_SANITIZERS") == "1":
                flags += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
            sources = [ROOT / "tests/router_cve_verify_test.c",
                       ROOT / "main/router_cve_verify.c",
                       ROOT / "main/router_cve_db.c",
                       ROOT / "main/router_fingerprint.c"]
            if compiler:
                command = [compiler, *flags, "-I", str(ROOT / "main"),
                           *map(str, sources), "-o", str(exe)]
                run = [str(exe), str(ROOT / "tests/fixtures/router_cve_v1.bin"),
                       str(signature7), str(catalog8_path), str(signature8),
                       str(max_catalog), str(max_signature)]
            else:
                self.assertIsNotNone(shutil.which("wsl.exe"), "native compiler or WSL required")
                command = ["wsl.exe", "cc", *flags, "-I", wsl_path(ROOT / "main"),
                           *map(wsl_path, sources), "-o", wsl_path(exe)]
                run = ["wsl.exe", wsl_path(exe),
                       wsl_path(ROOT / "tests/fixtures/router_cve_v1.bin"),
                       wsl_path(signature7), wsl_path(catalog8_path), wsl_path(signature8),
                       wsl_path(max_catalog), wsl_path(max_signature)]
            built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_source_registered_once(self):
        cmake = (ROOT / "main/CMakeLists.txt").read_text(encoding="utf-8")
        self.assertEqual(cmake.count('"router_cve_verify.c"'), 1)
        source = (ROOT / "main/router_cve_verify.c").read_text(encoding="utf-8")
        self.assertIn("router_cve_db_open_owned_snapshot", source)
        self.assertNotIn("borrow_allocate", source)
        self.assertIn("MBEDTLS_ECP_DP_SECP256R1", source)
        self.assertIn("mbedtls_pk_verify", source)


if __name__ == "__main__":
    unittest.main()
