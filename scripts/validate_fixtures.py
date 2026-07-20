from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE_ROOT = ROOT / "tests" / "fixtures"

FALSE_ONLY_CAPABILITIES = {
    "programmer_uploaded",
    "fdl_sent",
    "fdl_uploaded",
    "pit_written",
    "odin_command_sent",
    "write_allowed",
    "partition_written",
    "flash_performed",
    "format_performed",
    "erase_performed",
}
INTEGER_PARTITION_FIELDS = {
    "size_bytes",
    "start_sector",
    "sector_count",
    "logical_block_size",
}


def _fail(errors: list[str], path: Path, message: str) -> None:
    errors.append(f"{path.relative_to(ROOT)}: {message}")


def _validate_observation(
    path: Path,
    index: int,
    observation: dict[str, Any],
    errors: list[str],
) -> None:
    prefix = f"observation[{index}]"
    if not isinstance(observation.get("connected", True), bool):
        _fail(errors, path, f"{prefix}.connected must be a boolean")

    mode = observation.get("mode")
    if not isinstance(mode, str) or not mode.strip():
        _fail(errors, path, f"{prefix}.mode must be a non-empty string")

    identifiers = observation.get("identifiers", {})
    if not isinstance(identifiers, dict):
        _fail(errors, path, f"{prefix}.identifiers must be an object")
    else:
        for key, value in identifiers.items():
            if not isinstance(key, str):
                _fail(errors, path, f"{prefix}.identifiers keys must be strings")
            if not isinstance(value, (str, int, float, bool)):
                _fail(errors, path, f"{prefix}.identifiers.{key} must be a scalar value")

    capabilities = observation.get("capabilities", {})
    if not isinstance(capabilities, dict):
        _fail(errors, path, f"{prefix}.capabilities must be an object")
        capabilities = {}
    if capabilities.get("read_only") is not True:
        _fail(errors, path, f"{prefix}.capabilities.read_only must be true")
    for field in FALSE_ONLY_CAPABILITIES:
        if capabilities.get(field) is True:
            _fail(errors, path, f"{prefix}.capabilities.{field} must never be true")

    partitions = observation.get("partitions", [])
    if not isinstance(partitions, list):
        _fail(errors, path, f"{prefix}.partitions must be a list")
        return

    names: set[str] = set()
    for partition_index, partition in enumerate(partitions):
        item_prefix = f"{prefix}.partitions[{partition_index}]"
        if not isinstance(partition, dict):
            _fail(errors, path, f"{item_prefix} must be an object")
            continue
        name = partition.get("name")
        if not isinstance(name, str) or not name.strip():
            _fail(errors, path, f"{item_prefix}.name must be a non-empty string")
            continue
        if name in names:
            _fail(errors, path, f"{prefix} contains duplicate partition name {name!r}")
        names.add(name)
        for field in INTEGER_PARTITION_FIELDS:
            if field not in partition:
                continue
            value = partition[field]
            try:
                parsed = int(str(value), 0)
            except ValueError:
                _fail(errors, path, f"{item_prefix}.{field} must be an integer")
                continue
            if parsed < 0:
                _fail(errors, path, f"{item_prefix}.{field} must not be negative")


def validate_fixture_roots(roots: list[Path]) -> list[str]:
    errors: list[str] = []
    fixture_count = 0
    observation_count = 0

    for root in roots:
        if not root.exists():
            errors.append(f"{root}: fixture root does not exist")
            continue
        for path in sorted(root.rglob("*.json")):
            fixture_count += 1
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                _fail(errors, path, f"could not parse JSON: {exc}")
                continue

            items = payload if isinstance(payload, list) else [payload]
            if not items or not all(isinstance(item, dict) for item in items):
                _fail(errors, path, "fixture must contain an object or a list of objects")
                continue
            for index, item in enumerate(items):
                observation_count += 1
                _validate_observation(path, index, item, errors)

    if fixture_count == 0:
        errors.append("no JSON fixtures were found")
    if not errors:
        print(
            f"Validated {fixture_count} fixture file(s) and "
            f"{observation_count} observation(s)."
        )
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate read-only X-Ray evidence fixtures")
    parser.add_argument("roots", nargs="*", type=Path, default=[DEFAULT_FIXTURE_ROOT])
    args = parser.parse_args(argv)

    roots = [path.resolve() for path in args.roots]
    errors = validate_fixture_roots(roots)
    if errors:
        print("Fixture validation failed:", file=sys.stderr)
        for item in errors:
            print(f"- {item}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
