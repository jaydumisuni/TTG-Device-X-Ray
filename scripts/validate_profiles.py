from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE_ROOT = ROOT / "src" / "ttg_device_xray" / "profiles"

PROFILE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]+$")
CONTRACT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]+$")
ALLOWED_STAGES = {
    "OBSERVED",
    "CANDIDATE",
    "REPEATED_MATCH",
    "LAB_VERIFIED",
    "SHOP_VERIFIED",
    "CERTIFIED",
    "DEPRECATED",
}
ALLOWED_TRANSPORTS = {
    "adb",
    "fastboot",
    "mtk_meta",
    "qualcomm_edl",
    "spd_download",
    "samsung_download",
    "apple_normal",
    "apple_recovery",
    "apple_dfu",
}
MATCH_LIST_FIELDS = {
    "platforms",
    "brands",
    "internal_models",
    "product_types",
    "chipsets",
    "board_patterns",
    "build_patterns",
    "storage_types",
    "required_partitions",
}


def _error(errors: list[str], path: Path, message: str) -> None:
    errors.append(f"{path.relative_to(ROOT)}: {message}")


def _require_dict(value: Any, errors: list[str], path: Path, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _error(errors, path, f"{field} must be an object")
        return {}
    return value


def _validate_profile(
    path: Path,
    profile: dict[str, Any],
    errors: list[str],
) -> tuple[str, list[str]]:
    profile_id = str(profile.get("profile_id", "")).strip()
    if not PROFILE_ID_RE.fullmatch(profile_id):
        _error(errors, path, "profile_id must be a lowercase namespaced identifier")

    schema_version = profile.get("schema_version")
    if not isinstance(schema_version, int) or schema_version < 1:
        _error(errors, path, "schema_version must be an integer >= 1")

    stage = str(profile.get("stage", "")).strip().upper()
    if stage not in ALLOWED_STAGES:
        _error(errors, path, f"stage must be one of {sorted(ALLOWED_STAGES)}")

    aliases_value = profile.get("aliases", [])
    aliases: list[str] = []
    if not isinstance(aliases_value, list):
        _error(errors, path, "aliases must be a list")
    else:
        for alias in aliases_value:
            alias_text = str(alias).strip()
            if not PROFILE_ID_RE.fullmatch(alias_text):
                _error(errors, path, f"invalid alias: {alias!r}")
            else:
                aliases.append(alias_text)

    match = _require_dict(profile.get("match"), errors, path, "match")
    discriminator_count = 0
    for field in MATCH_LIST_FIELDS:
        if field not in match:
            continue
        value = match[field]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            _error(errors, path, f"match.{field} must be a list of strings")
            continue
        if value:
            discriminator_count += 1
        if field.endswith("_patterns"):
            for pattern in value:
                try:
                    re.compile(pattern)
                except re.error as exc:
                    _error(errors, path, f"invalid regex in match.{field}: {pattern!r}: {exc}")
    if discriminator_count < 2:
        _error(errors, path, "match must contain at least two independent evidence fields")

    transports = profile.get("transport_priority", [])
    if not isinstance(transports, list) or not all(isinstance(item, str) for item in transports):
        _error(errors, path, "transport_priority must be a list of strings")
    else:
        unknown = sorted(set(transports) - ALLOWED_TRANSPORTS)
        if unknown:
            _error(errors, path, f"unknown transport values: {unknown}")
        if len(transports) != len(set(transports)):
            _error(errors, path, "transport_priority contains duplicates")

    contracts = _require_dict(
        profile.get("adapter_contracts", {}), errors, path, "adapter_contracts"
    )
    for name, contract in contracts.items():
        if not isinstance(name, str) or not isinstance(contract, str):
            _error(errors, path, "adapter_contracts keys and values must be strings")
            continue
        if not CONTRACT_RE.fullmatch(contract):
            _error(errors, path, f"invalid adapter contract identifier: {contract!r}")

    safety = _require_dict(profile.get("safety"), errors, path, "safety")
    required_safety = {
        "read_only": True,
        "write_allowed": False,
        "profile_cannot_authorize_repairs": True,
    }
    for field, expected in required_safety.items():
        if safety.get(field) is not expected:
            _error(errors, path, f"safety.{field} must be {expected!r}")

    return profile_id, aliases


def validate_profile_roots(roots: list[Path]) -> list[str]:
    errors: list[str] = []
    claimed_ids: dict[str, Path] = {}
    profile_count = 0

    for root in roots:
        if not root.exists():
            errors.append(f"{root}: profile root does not exist")
            continue
        for path in sorted(root.rglob("*.json")):
            profile_count += 1
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                _error(errors, path, f"could not parse JSON: {exc}")
                continue
            if not isinstance(payload, dict):
                _error(errors, path, "profile root must be a JSON object")
                continue

            profile_id, aliases = _validate_profile(path, payload, errors)
            for claimed in [profile_id, *aliases]:
                if not claimed:
                    continue
                previous = claimed_ids.get(claimed)
                if previous is not None:
                    _error(
                        errors,
                        path,
                        f"profile identifier {claimed!r} is already claimed by "
                        f"{previous.relative_to(ROOT)}",
                    )
                else:
                    claimed_ids[claimed] = path

    if profile_count == 0:
        errors.append("no JSON profiles were found")
    if not errors:
        print(f"Validated {profile_count} profile file(s) and {len(claimed_ids)} identifier(s).")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate TTG Device X-Ray profile registries")
    parser.add_argument("roots", nargs="*", type=Path, default=[DEFAULT_PROFILE_ROOT])
    args = parser.parse_args(argv)

    roots = [path.resolve() for path in args.roots]
    errors = validate_profile_roots(roots)
    if errors:
        print("Profile validation failed:", file=sys.stderr)
        for item in errors:
            print(f"- {item}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
