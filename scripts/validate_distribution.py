from __future__ import annotations

import argparse
import sys
import tarfile
import zipfile
from pathlib import Path

REQUIRED_PACKAGE_PATHS = {
    "ttg_device_xray/__init__.py",
    "ttg_device_xray/cli.py",
    "ttg_device_xray/profiles/__init__.py",
    "ttg_device_xray/profiles/transsion/__init__.py",
    "ttg_device_xray/profiles/transsion/km7.json",
}


def _wheel_members(path: Path) -> set[str]:
    with zipfile.ZipFile(path) as archive:
        return set(archive.namelist())


def _sdist_members(path: Path) -> set[str]:
    with tarfile.open(path, mode="r:gz") as archive:
        members = {item.name for item in archive.getmembers() if item.isfile()}
    roots = {item.split("/", 1)[0] for item in members if "/" in item}
    if len(roots) != 1:
        return members
    root = next(iter(roots))
    prefix = f"{root}/src/"
    return {item.removeprefix(prefix) for item in members if item.startswith(prefix)}


def validate(dist: Path) -> list[str]:
    errors: list[str] = []
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))

    if len(wheels) != 1:
        errors.append(f"expected exactly one wheel in {dist}, found {len(wheels)}")
    if len(sdists) != 1:
        errors.append(f"expected exactly one source archive in {dist}, found {len(sdists)}")

    if wheels:
        missing = sorted(REQUIRED_PACKAGE_PATHS - _wheel_members(wheels[0]))
        if missing:
            errors.append(f"wheel is missing required package paths: {missing}")

    if sdists:
        missing = sorted(REQUIRED_PACKAGE_PATHS - _sdist_members(sdists[0]))
        if missing:
            errors.append(f"source archive is missing required package paths: {missing}")

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate built TTG Device X-Ray archives")
    parser.add_argument("dist", nargs="?", type=Path, default=Path("dist"))
    args = parser.parse_args(argv)

    errors = validate(args.dist.resolve())
    if errors:
        print("Distribution validation failed:", file=sys.stderr)
        for item in errors:
            print(f"- {item}", file=sys.stderr)
        return 1

    print("Distribution contains the CLI package and reviewed profile registry.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
