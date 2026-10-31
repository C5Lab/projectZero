"""Run the host's target and Wardrive mode policy as native C."""

from pathlib import Path
import os
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "Lab_C5.c").read_text(encoding="utf-8")


def extract(pattern: str) -> str:
    match = re.search(pattern, SOURCE, re.MULTILINE | re.DOTALL)
    if match is None:
        raise AssertionError(f"Missing production code: {pattern}")
    opening = SOURCE.find("{", match.start(), match.end())
    depth = 1
    end = opening + 1
    while depth:
        depth += (SOURCE[end] == "{") - (SOURCE[end] == "}")
        end += 1
    if SOURCE[end] == ";":
        end += 1
    return SOURCE[match.start():end]


class AttackLaunchPolicy(unittest.TestCase):
    def test_target_gate_and_wardrive_modes(self) -> None:
        match = re.search(r"^typedef enum \{[^}]*C5AttackModuleRogue[^}]*\} C5AttackModule;", SOURCE, re.MULTILINE)
        assert match is not None
        enum = match.group()
        functions = "\n".join(
            extract(rf"^static [^;{{\n]+ {name}\([^;{{]*\)\s*\{{")
            for name in (
                "simple_app_attack_requires_target",
                "simple_app_attack_may_stop_prior",
                "simple_app_wardrive_module_for_index",
            )
        )
        program = f"""
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
{enum}
{functions}
int main(void) {{
    assert(simple_app_attack_requires_target(C5AttackModuleRogue));
    assert(simple_app_attack_requires_target(C5AttackModuleArp));
    assert(simple_app_attack_requires_target(C5AttackModuleMitmPcap));
    assert(simple_app_attack_requires_target(C5AttackModuleConnect));
    assert(!simple_app_attack_may_stop_prior(C5AttackModuleConnect));
    assert(simple_app_attack_may_stop_prior(C5AttackModuleRogue));
    assert(simple_app_attack_may_stop_prior(C5AttackModuleWardriveLegacy));
    assert(!simple_app_attack_requires_target(C5AttackModuleArpSaved));
    assert(!simple_app_attack_requires_target(C5AttackModuleBeacon));
    assert(!simple_app_attack_requires_target(C5AttackModuleWardriveLegacy));
    assert(!simple_app_attack_requires_target(C5AttackModuleWardrivePromisc));
    assert(!simple_app_attack_requires_target(C5AttackModuleWardriveTrace));
    assert(!simple_app_attack_requires_target(C5AttackModuleWardriveUploadWigle));
    assert(!simple_app_attack_requires_target(C5AttackModuleWardriveUploadWdgwars));
    assert(!simple_app_attack_requires_target(C5AttackModuleNmap));
    assert(!simple_app_attack_requires_target(C5AttackModuleWpasec));
    assert(simple_app_wardrive_module_for_index(0) == C5AttackModuleWardriveLegacy);
    assert(simple_app_wardrive_module_for_index(1) == C5AttackModuleWardrivePromisc);
    assert(simple_app_wardrive_module_for_index(2) == C5AttackModuleWardriveTrace);
    assert(simple_app_wardrive_module_for_index(3) == C5AttackModuleWardriveUploadWigle);
    assert(simple_app_wardrive_module_for_index(4) == C5AttackModuleWardriveUploadWdgwars);
    assert(simple_app_wardrive_module_for_index(99) == C5AttackModuleWardriveLegacy);
    return 0;
}}
"""
        executable = f"/tmp/lab_c5_attack_launch_policy_{os.getpid()}"
        built = subprocess.run(
            ["wsl.exe", "--", "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-x", "c", "-", "-o", executable],
            input=program, text=True, capture_output=True, check=False,
        )
        self.assertEqual(built.returncode, 0, built.stderr)
        try:
            ran = subprocess.run(["wsl.exe", "--", executable], text=True, capture_output=True, check=False)
            self.assertEqual(ran.returncode, 0, ran.stderr)
        finally:
            subprocess.run(["wsl.exe", "--", "rm", "-f", executable], check=False)


if __name__ == "__main__":
    unittest.main()
