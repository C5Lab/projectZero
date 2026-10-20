"""Patch the ESP-IDF 6.0.x PA profile and regenerate its compiled C table."""

from pathlib import Path
import os
import re
import subprocess
import sys


OLD_PA = (
    b"country PA: DFS-FCC\n"
    b"\t(2400 - 2483.5 @ 40), (36)\n"
    b"\t(5150 - 5250 @ 80), (36), AUTO-BW\n"
    b"\t(5250 - 5350 @ 80), (30), AUTO-BW\n"
    b"\t(5470 - 5725 @ 160), (30)\n"
    b"\t(5725 - 5850 @ 80), (36)\n"
    b"\t(57000 - 64000 @ 2160), (43)"
)
NEW_PA = (
    b"country PA: DFS-FCC\n"
    b"\t(2400 - 2483.5 @ 40), (36)\n"
    b"\t(5150 - 5250 @ 80), (36), AUTO-BW\n"
    b"\t(5250 - 5350 @ 80), (30), AUTO-BW\n"
    b"\t(5470 - 5730 @ 160), (30)\n"
    b"\t(5725 - 5895 @ 80), (36)\n"
    b"\t(57000 - 64000 @ 2160), (43)"
)
PA_MARKER = b"/* ESP_WIFI_REGULATORY_TYPE_PA */"
NEXT_MARKER = b"/* ESP_WIFI_REGULATORY_TYPE_PH */"
PA_ROWS = (
    b"5,  /* Number of rules */",
    b"{ 1, 13, 2, 36, 0, 0 }",
    b"{ 36, 48, 3, 36, 0, 0 }",
    b"{ 52, 64, 3, 30, 0, 0 }",
    b"{ 100, 144, 4, 30, 0, 0 }",
    b"{ 149, 177, 3, 36, 0, 0 }",
)
OLD_C_RULES = (
    b"{ 100, 140, 4, 30, 0, 0 },  /* chan:100~140, max_bw:160M, max_power:30(dBm), dfs:0, reserved.*/",
    b"{ 149, 165, 3, 36, 0, 0 },  /* chan:149~165, max_bw:80M, max_power:36(dBm), dfs:0, reserved.*/",
)
NEW_C_RULES = (
    b"{ 100, 144, 4, 30, 0, 0 },  /* chan:100~144, max_bw:160M, max_power:30(dBm), dfs:0, reserved.*/",
    b"{ 149, 177, 3, 36, 0, 0 },  /* chan:149~177, max_bw:80M, max_power:36(dBm), dfs:0, reserved.*/",
)


class PatchError(Exception):
    pass


def idf_version(idf_path: Path) -> tuple[int, int, int]:
    path = idf_path / "tools" / "cmake" / "version.cmake"
    try:
        source = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PatchError(f"cannot read {path}: {exc}") from exc
    values = []
    for name in ("MAJOR", "MINOR", "PATCH"):
        match = re.search(rf"(?m)^set\(IDF_VERSION_{name}\s+([0-9]+)\)", source)
        if not match:
            raise PatchError(f"missing IDF_VERSION_{name} in {path}")
        values.append(int(match.group(1)))
    return tuple(values)


def pa_stanza(source: bytes) -> tuple[int, int, bytes, bytes]:
    if source.count(b"country PA:") != 1:
        raise PatchError("expected exactly one country PA block")
    newline = b"\r\n" if b"\r\n" in source else b"\n"
    start = source.index(b"country PA:")
    end = source.find(newline + newline, start)
    if end == -1:
        raise PatchError("country PA block has no blank-line terminator")
    old = OLD_PA.replace(b"\n", newline)
    new = NEW_PA.replace(b"\n", newline)
    return start, end, old, new


def generated_pa_is_current(source: bytes) -> bool:
    start = source.find(PA_MARKER)
    end = source.find(NEXT_MARKER, start + len(PA_MARKER)) if start != -1 else -1
    if start == -1 or end == -1:
        return False
    pa_section = source[start:end]
    return all(pa_section.count(row) == 1 for row in PA_ROWS)


def expected_generated_c(source: bytes) -> bytes:
    """Allow only the two PA rule changes in an existing generated table."""
    start = source.find(PA_MARKER)
    end = source.find(NEXT_MARKER, start + len(PA_MARKER)) if start != -1 else -1
    if start == -1 or end == -1:
        raise PatchError("unexpected existing PA table in esp_wifi_regulatory.c")
    expected = source[start:end]
    for old, new in zip(OLD_C_RULES, NEW_C_RULES):
        if expected.count(old) == 1 and expected.count(new) == 0:
            expected = expected.replace(old, new, 1)
        elif expected.count(old) == 0 and expected.count(new) == 1:
            pass
        else:
            raise PatchError("unexpected existing PA rule in esp_wifi_regulatory.c")
    return source[:start] + expected + source[end:]


def apply_patch(idf_path: Path) -> str:
    version = idf_version(idf_path)
    if version not in ((6, 0, 0), (6, 0, 1)):
        raise PatchError(
            f"only ESP-IDF 6.0.0 and 6.0.1 are supported; found {'.'.join(map(str, version))}"
        )

    directory = idf_path / "components" / "esp_wifi" / "regulatory"
    text_path = directory / "esp_wifi_regulatory.txt"
    c_path = directory / "esp_wifi_regulatory.c"
    generator = directory / "reg2fw.py"
    parser = directory / "reg_parse.py"
    for path in (text_path, generator, parser):
        if not path.is_file():
            raise PatchError(f"missing {path}")

    original_text = text_path.read_bytes()
    start, end, old, new = pa_stanza(original_text)
    block = original_text[start:end]
    if block == old:
        updated_text = original_text[:start] + new + original_text[end:]
    elif block == new:
        updated_text = original_text
    else:
        raise PatchError(f"unexpected country PA block in {text_path}")

    had_c = c_path.is_file()
    original_c = c_path.read_bytes() if had_c else b""
    if updated_text == original_text and generated_pa_is_current(original_c):
        return f"PA regulatory patch: already applied in {directory}"

    try:
        if updated_text != original_text:
            text_path.write_bytes(updated_text)
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [sys.executable, str(generator)], cwd=directory, env=environment,
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise PatchError(f"reg2fw.py failed ({result.returncode}): {result.stderr.strip()}")
        if not c_path.is_file():
            raise PatchError(f"reg2fw.py did not produce {c_path}")
        generated_c = c_path.read_bytes().replace(b"\r\n", b"\n")
        if b"\r\n" in original_c:
            generated_c = generated_c.replace(b"\n", b"\r\n")
        if not generated_pa_is_current(generated_c):
            raise PatchError(f"reg2fw.py produced an unexpected PA table in {c_path}")
        if had_c and generated_c != expected_generated_c(original_c):
            raise PatchError("reg2fw.py would overwrite unrelated regulatory C changes")
        if c_path.read_bytes() != generated_c:
            c_path.write_bytes(generated_c)
    except (OSError, PatchError) as exc:
        try:
            if updated_text != original_text:
                text_path.write_bytes(original_text)
            if had_c:
                c_path.write_bytes(original_c)
            elif c_path.exists():
                c_path.unlink()
        except OSError as rollback_error:
            raise PatchError(f"{exc}; rollback failed: {rollback_error}") from exc
        raise PatchError(str(exc)) from exc

    return f"PA regulatory patch: {result.stdout.strip() or 'reg2fw.py completed'}"


def main() -> int:
    if len(sys.argv) != 2:
        print("PA regulatory patch: expected IDF_PATH argument", file=sys.stderr)
        return 1
    try:
        print(apply_patch(Path(sys.argv[1])))
    except (OSError, PatchError) as exc:
        print(f"PA regulatory patch: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
