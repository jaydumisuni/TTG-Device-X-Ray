from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
PACKAGE_VERSION_RE = re.compile(r'^__version__\s*=\s*"([^"]+)"\s*$', re.MULTILINE)
TAG_RE = re.compile(r"^v(?P<version>\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$")


def _extract(path: Path, pattern: re.Pattern[str], label: str) -> str:
    text = path.read_text(encoding="utf-8")
    match = pattern.search(text)
    if match is None:
        raise ValueError(f"could not find {label} in {path.relative_to(ROOT)}")
    return match.group(1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a TTG Device X-Ray release tag")
    parser.add_argument("tag", nargs="?", default=os.environ.get("GITHUB_REF_NAME", ""))
    args = parser.parse_args(argv)

    match = TAG_RE.fullmatch(args.tag.strip())
    if match is None:
        print(f"Release tag must match vMAJOR.MINOR.PATCH; received {args.tag!r}", file=sys.stderr)
        return 1

    tag_version = match.group("version")
    pyproject_version = _extract(ROOT / "pyproject.toml", VERSION_RE, "project version")
    package_version = _extract(
        ROOT / "src" / "ttg_device_xray" / "__init__.py",
        PACKAGE_VERSION_RE,
        "package __version__",
    )

    versions = {
        "tag": tag_version,
        "pyproject": pyproject_version,
        "package": package_version,
    }
    if len(set(versions.values())) != 1:
        print(f"Release version mismatch: {versions}", file=sys.stderr)
        return 1

    print(f"Release version verified: {tag_version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
