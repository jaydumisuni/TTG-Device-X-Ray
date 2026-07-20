from __future__ import annotations

import ast
import re
import sys
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src" / "ttg_device_xray"

COMMAND_CALL_NAMES = {"run", "adb", "fastboot", "shell", "su"}
FORBIDDEN_COMMAND_PATTERNS = {
    "device partition flash": re.compile(r"\bflash(?:ing)?\b", re.IGNORECASE),
    "device erase": re.compile(r"\berase\b", re.IGNORECASE),
    "device format": re.compile(r"\bformat\b", re.IGNORECASE),
    "device wipe": re.compile(r"\bwipe\b", re.IGNORECASE),
    "raw block write": re.compile(r"(^|\s)dd(\s|$).*\bof=", re.IGNORECASE),
    "filesystem creation": re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b", re.IGNORECASE),
    "partition editor": re.compile(r"\b(?:sgdisk|parted|fdisk)\b", re.IGNORECASE),
    "package uninstall": re.compile(r"\bpm\s+uninstall\b", re.IGNORECASE),
    "device-admin removal": re.compile(r"\bdpm\s+remove-active-admin\b", re.IGNORECASE),
    "settings mutation": re.compile(r"\bsettings\s+put\b", re.IGNORECASE),
    "property mutation": re.compile(r"\bsetprop\b", re.IGNORECASE),
    "bootloader unlock": re.compile(
        r"\b(?:flashing\s+unlock|oem\s+unlock|unlock_critical)\b", re.IGNORECASE
    ),
    "logical-partition mutation": re.compile(
        r"\b(?:create|delete|resize)-logical-partition\b", re.IGNORECASE
    ),
}


def _call_name(node: ast.Call) -> str:
    function = node.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return ""


def _string_constants(nodes: Iterable[ast.AST]) -> list[str]:
    values: list[str] = []
    for node in nodes:
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                values.append(child.value)
    return values


def _source_position(path: Path, node: ast.AST) -> str:
    return f"{path.relative_to(ROOT)}:{getattr(node, 'lineno', 0)}"


def check_file(path: Path) -> list[str]:
    errors: list[str] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        return [f"{path.relative_to(ROOT)}: could not parse source: {exc}"]

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        if _call_name(node) == "run":
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant):
                    if keyword.value.value is True:
                        errors.append(
                            f"{_source_position(path, node)}: subprocess shell=True is forbidden"
                        )

        if _call_name(node) not in COMMAND_CALL_NAMES:
            continue

        text = " ".join(_string_constants([*node.args, *(item.value for item in node.keywords)]))
        if not text:
            continue
        for description, pattern in FORBIDDEN_COMMAND_PATTERNS.items():
            if pattern.search(text):
                errors.append(
                    f"{_source_position(path, node)}: {description} command literal detected: "
                    f"{text[:180]!r}"
                )

    return errors


def main() -> int:
    errors: list[str] = []
    paths = sorted(SOURCE_ROOT.rglob("*.py"))
    if not paths:
        print("No Python source files found.", file=sys.stderr)
        return 1

    for path in paths:
        errors.extend(check_file(path))

    if errors:
        print("Read-only boundary check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    print(f"Read-only boundary verified across {len(paths)} Python source file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
