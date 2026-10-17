"""Compile component fixtures with a native host compiler or the existing WSL CC."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[2]


def wsl_path(path):
    resolved = Path(path).resolve()
    return f"/mnt/{resolved.drive.rstrip(':').lower()}/{resolved.relative_to(resolved.anchor).as_posix()}"


def compile_and_run(case, name, sources, include_dirs, *, expected=None,
                    extra_flags=(), libraries=(), run_args=()):
    for source in sources:
        case.assertTrue(source.is_file(), f"missing source: {source}")
    compiler = next((shutil.which(candidate) for candidate in
                     (os.environ.get("CC", ""), "cc", "gcc", "clang")
                     if candidate and shutil.which(candidate)), None)
    with tempfile.TemporaryDirectory() as directory:
        executable = Path(directory) / name
        flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", *extra_flags]
        if compiler:
            command = [compiler, *flags,
                       *(item for path in include_dirs for item in ("-I", str(path))),
                       *map(str, sources), *libraries, "-o", str(executable)]
            run = [str(executable), *map(str, run_args)]
        elif shutil.which("wsl.exe"):
            command = ["wsl.exe", "cc", *flags,
                       *(item for path in include_dirs for item in ("-I", wsl_path(path))),
                       *map(wsl_path, sources), *libraries, "-o", wsl_path(executable)]
            run = ["wsl.exe", wsl_path(executable), *map(str, run_args)]
        else:
            case.fail("Host C compiler required (native or WSL)")
        built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True,
                               timeout=60)
        case.assertEqual(built.returncode, 0, built.stdout + built.stderr)
        result = subprocess.run(run, cwd=ROOT, capture_output=True, text=True,
                                timeout=60)
        case.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        if expected is not None:
            case.assertEqual(result.stdout.strip(), expected)
        return result.stdout
