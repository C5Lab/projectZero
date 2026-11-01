"""Keep the WPA-sec verification exception isolated from other cloud endpoints.

This is a source/configuration gate; it does not replace a live bad-certificate
connection test on the Monster firmware.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "main" / "main.c").read_text(encoding="utf-8")
DEFAULTS = (ROOT / "sdkconfig.defaults").read_text(encoding="utf-8")
CONFIG = (ROOT / "sdkconfig").read_text(encoding="utf-8")


class CloudUploadTlsPolicy(unittest.TestCase):
    def test_only_wpasec_omits_certificate_bundle(self) -> None:
        # WPA-sec, WiGLE, WDGWars upload, polling, and history each use a
        # separate ESP-TLS connection. Check all five, not only the first.
        configs = re.findall(r"esp_tls_cfg_t\s+tls_cfg\s*=\s*\{([^}]*)\}", SOURCE, re.DOTALL)
        self.assertEqual(len(configs), 5)
        wpasec = SOURCE.split("static int wpasec_upload_file(", 1)[1].split("esp_tls_cfg_t tls_cfg", 1)[1]
        self.assertRegex(wpasec.split("}", 1)[0], r"\.crt_bundle_attach\s*=\s*NULL")
        self.assertRegex(configs[0], r"\.crt_bundle_attach\s*=\s*NULL")
        for config in configs[1:]:
            with self.subTest(config=config[:80]):
                self.assertRegex(config, r"\.crt_bundle_attach\s*=\s*esp_crt_bundle_attach")
                self.assertNotRegex(config, r"\.skip_common_name\s*=\s*true")

    def test_project_configs_enable_wpasec_fallback_and_ca_bundle(self) -> None:
        for path, contents in (("sdkconfig.defaults", DEFAULTS), ("sdkconfig", CONFIG)):
            with self.subTest(path=path):
                self.assertTrue(re.search(r"(?m)^CONFIG_ESP_TLS_INSECURE=y$", contents), path)
                self.assertTrue(re.search(r"(?m)^CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY=y$", contents), path)
                self.assertTrue(re.search(r"(?m)^CONFIG_MBEDTLS_CERTIFICATE_BUNDLE=y$", contents), path)


if __name__ == "__main__":
    unittest.main()
