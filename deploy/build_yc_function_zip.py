from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build" / "function_pkg"
ZIP_PATH = ROOT / "build" / "murdb_yc_function.zip"

INCLUDE_DIRS = [
    ROOT / "yc_function",
    ROOT / "murdb_core",
]

INCLUDE_FILES = [
    ROOT / "requirements.txt",
]


def clean() -> None:
    if BUILD_DIR.exists():
        shutil.rmtree(BUILD_DIR)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    ZIP_PATH.parent.mkdir(parents=True, exist_ok=True)


def copy_sources() -> None:
    for src in INCLUDE_DIRS:
        if src.exists():
            shutil.copytree(
                src,
                BUILD_DIR / src.name,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".pytest_cache"),
            )

    for src in INCLUDE_FILES:
        if src.exists():
            shutil.copy2(src, BUILD_DIR / src.name)


def install_deps() -> None:
    req = ROOT / "requirements.txt"
    if req.exists() and req.read_text(encoding="utf-8").strip():
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "-r",
                str(req),
                "-t",
                str(BUILD_DIR),
                "--upgrade",
            ]
        )


def make_zip() -> None:
    if ZIP_PATH.exists():
        ZIP_PATH.unlink()

    with zipfile.ZipFile(ZIP_PATH, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in BUILD_DIR.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(BUILD_DIR))


def main() -> None:
    clean()
    copy_sources()
    install_deps()
    make_zip()
    print(ZIP_PATH)


if __name__ == "__main__":
    main()