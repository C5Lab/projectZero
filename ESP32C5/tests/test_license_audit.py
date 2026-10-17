from pathlib import Path
import unittest

from tools.license_audit import classify


class LicenseAuditTest(unittest.TestCase):
    def test_existing_spdx_is_third_party(self):
        text = (
            "/* SPDX-FileCopyrightText: 2024 Example\n"
            " * SPDX-License-Identifier: MIT */"
        )
        self.assertEqual(classify(Path("component.c"), text), "third_party")

    def test_existing_copyright_is_third_party(self):
        text = "/* Copyright (c) 2024 Example */"
        self.assertEqual(classify(Path("component.c"), text), "third_party")

    def test_generated_binary_is_generated(self):
        self.assertEqual(
            classify(Path("binaries-esp32c5/projectZero.bin"), ""),
            "generated",
        )

    def test_build_tree_is_generated(self):
        self.assertEqual(
            classify(Path("component/build/generated.c"), ""),
            "generated",
        )

    def test_unmarked_source_requires_manual_review(self):
        self.assertEqual(
            classify(Path("main/main.c"), "#include <stdio.h>"),
            "manual_review",
        )

    def test_unmarked_document_is_apache_candidate(self):
        self.assertEqual(
            classify(Path("docs/design.md"), "# Original design"),
            "apache_candidate",
        )


if __name__ == "__main__":
    unittest.main()
