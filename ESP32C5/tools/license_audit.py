#!/usr/bin/env python3
"""Create a read-only license/provenance inventory for one project directory."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import re
import subprocess


GENERATED_SUFFIXES = {".bin", ".elf", ".map", ".pyc"}
SOURCE_SUFFIXES = {".c", ".h", ".cc", ".hh", ".cpp", ".hpp", ".py", ".cmake"}
THIRD_PARTY_MARKERS = (
    "SPDX-License-Identifier:",
    "Copyright (c)",
    "Copyright (C)",
)
SPDX_PATTERN = re.compile(r"SPDX-License-Identifier:\s*([^\s*]+)")
COPYRIGHT_PATTERN = re.compile(r"Copyright\s*(?:\([cC]\))?[^\r\n]*", re.IGNORECASE)


@dataclass(frozen=True)
class AuditRow:
    path: str
    classification: str
    spdx: str
    copyright: str
    reason: str


def classify(path: Path, text: str) -> str:
    """Classify a file without asserting ownership of unmarked source code."""
    lowered_parts = {part.lower() for part in path.parts}
    if path.suffix.lower() in GENERATED_SUFFIXES or "build" in lowered_parts:
        return "generated"
    if any(marker in text[:4096] for marker in THIRD_PARTY_MARKERS):
        return "third_party"
    if path.suffix.lower() in SOURCE_SUFFIXES or path.name == "CMakeLists.txt":
        return "manual_review"
    return "apache_candidate"


def _tracked_paths(root: Path) -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z", "--", "."],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    names = [name for name in result.stdout.split(b"\0") if name]
    paths = [Path(name.decode("utf-8")) for name in names]
    if len(paths) != len(set(paths)):
        raise ValueError("git returned duplicate tracked paths")
    return sorted(paths, key=lambda path: path.as_posix())


def _read_prefix(path: Path, limit: int = 4096) -> str:
    if path.suffix.lower() in GENERATED_SUFFIXES:
        return ""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return ""


def _first_match(pattern: re.Pattern[str], text: str) -> str:
    match = pattern.search(text)
    return match.group(1 if pattern is SPDX_PATTERN else 0).strip() if match else ""


def _reason(path: Path, classification: str, text: str) -> str:
    if classification == "generated":
        return "generated/build artifact"
    if classification == "third_party":
        if "SPDX-License-Identifier:" in text:
            return "existing SPDX notice"
        return "existing copyright notice"
    if classification == "manual_review":
        return "unmarked source; ownership review required"
    return "unmarked non-source file"


def audit(root: Path) -> list[AuditRow]:
    root = root.resolve(strict=True)
    rows: list[AuditRow] = []
    for relative in _tracked_paths(root):
        absolute = (root / relative).resolve(strict=False)
        try:
            absolute.relative_to(root)
        except ValueError as exc:
            raise ValueError(f"tracked path escapes audit root: {relative}") from exc

        text = _read_prefix(absolute)
        classification = classify(relative, text)
        rows.append(
            AuditRow(
                path=relative.as_posix(),
                classification=classification,
                spdx=_first_match(SPDX_PATTERN, text),
                copyright=_first_match(COPYRIGHT_PATTERN, text),
                reason=_reason(relative, classification, text),
            )
        )
    return rows


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\r", " ").replace("\n", " ") or "—"


def render_report(root: Path, rows: list[AuditRow]) -> str:
    counts: dict[str, int] = {}
    for row in rows:
        counts[row.classification] = counts.get(row.classification, 0) + 1

    lines = [
        "# ESP32C5 License Audit",
        "",
        "This is a read-only inventory of tracked files beneath the ESP32C5 project root.",
        "A classification is not a declaration of ownership or a license change.",
        "",
        "## Summary",
        "",
    ]
    for name in ("apache_candidate", "manual_review", "third_party", "generated"):
        lines.append(f"- `{name}`: {counts.get(name, 0)}")

    lines.extend(
        [
            "",
            "## Files",
            "",
            "| path | classification | detected SPDX | existing copyright | reason |",
            "|---|---|---|---|---|",
        ]
    )
    for row in rows:
        lines.append(
            "| " + " | ".join(
                _cell(value)
                for value in (
                    row.path,
                    row.classification,
                    row.spdx,
                    row.copyright,
                    row.reason,
                )
            ) + " |"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve(strict=True)
    output = args.output if args.output.is_absolute() else root / args.output
    output = output.resolve(strict=False)
    try:
        output.relative_to(root)
    except ValueError as exc:
        raise SystemExit("output must remain inside the audit root") from exc

    rows = audit(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_report(root, rows), encoding="utf-8", newline="\n")
    print(f"Wrote {len(rows)} entries to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
