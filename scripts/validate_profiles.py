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
GIT_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
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
ALLOWED_APPLE_ROUTE_CLASSIFICATIONS = {
    "documented_known_good_reference",
    "working_package_reference",
    "hardware_verified_reference",
    "research_reference",
}
ALLOWED_APPLE_GENERATIONS = {"a5_a5x", "a6_a7", "a8_a11", "a12_a13"}
ALLOWED_APPLE_PWN_PROVIDERS = {
    "arduino_max3421e",
    "ipwndfu",
    "gaster",
    "usbliter8_rp2350",
}


def _error(errors: list[str], path: Path, message: str) -> None:
    errors.append(f"{path.relative_to(ROOT)}: {message}")


def _require_dict(value: Any, errors: list[str], path: Path, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _error(errors, path, f"{field} must be an object")
        return {}
    return value


def _validate_apple_route_reference(
    path: Path,
    profile: dict[str, Any],
    errors: list[str],
) -> None:
    capabilities = profile.get("capabilities", {})
    if not isinstance(capabilities, dict):
        return
    value = capabilities.get("apple_route_reference")
    if value is None:
        return
    route = _require_dict(value, errors, path, "capabilities.apple_route_reference")

    if route.get("schema_version") != "ttg.apple-route-reference.v1":
        _error(errors, path, "Apple route reference schema must be ttg.apple-route-reference.v1")

    classification = str(route.get("classification", "")).strip()
    if classification not in ALLOWED_APPLE_ROUTE_CLASSIFICATIONS:
        _error(errors, path, "Apple route reference classification is unsupported")

    generation = str(route.get("generation", "")).strip()
    if generation not in ALLOWED_APPLE_GENERATIONS:
        _error(errors, path, "Apple route reference generation is unsupported")

    provider = str(route.get("pwn_provider", "")).strip()
    if provider not in ALLOWED_APPLE_PWN_PROVIDERS:
        _error(errors, path, "Apple route reference pwn provider is unsupported")

    source = _require_dict(route.get("pwn_source"), errors, path, "pwn_source")
    repository = str(source.get("repository", "")).strip()
    commit = str(source.get("commit", "")).strip()
    licence = str(source.get("licence", "")).strip()
    if not repository.startswith("https://github.com/"):
        _error(errors, path, "pwn_source.repository must be an HTTPS GitHub URL")
    if not GIT_COMMIT_RE.fullmatch(commit):
        _error(errors, path, "pwn_source.commit must be a full 40-character commit")
    if not licence:
        _error(errors, path, "pwn_source.licence is required")

    catalogs = route.get("reference_catalogs")
    if not isinstance(catalogs, list) or not catalogs:
        _error(errors, path, "reference_catalogs must contain at least one source")
    else:
        for index, catalog in enumerate(catalogs):
            if not isinstance(catalog, dict):
                _error(errors, path, f"reference_catalogs[{index}] must be an object")
                continue
            url = str(catalog.get("url", "")).strip()
            role = str(catalog.get("role", "")).strip()
            if not url.startswith("https://"):
                _error(errors, path, f"reference_catalogs[{index}].url must use HTTPS")
            if not role:
                _error(errors, path, f"reference_catalogs[{index}].role is required")
            if catalog.get("artifacts_bundled") is not False:
                _error(errors, path, "public X-Ray profiles cannot bundle reference artifacts")

    asset_policy = _require_dict(route.get("asset_policy"), errors, path, "asset_policy")
    required_asset_policy = {
        "local_only": True,
        "sha256_required": True,
        "device_exact": True,
        "redistribution_allowed": False,
    }
    for field, expected in required_asset_policy.items():
        if asset_policy.get(field) is not expected:
            _error(errors, path, f"asset_policy.{field} must be {expected!r}")

    transitions = route.get("expected_transitions")
    if not isinstance(transitions, list) or not all(
        isinstance(item, str) and item.strip() for item in transitions
    ):
        _error(errors, path, "expected_transitions must be a non-empty list of strings")
    else:
        required = {"apple_dfu", "pwned_dfu"}
        if not required.issubset(set(transitions)):
            _error(errors, path, "expected_transitions must include apple_dfu and pwned_dfu")

    if route.get("xray_scope") != "READ_ONLY_ROUTE_CERTIFICATION":
        _error(errors, path, "xray_scope must remain READ_ONLY_ROUTE_CERTIFICATION")

    if classification == "documented_known_good_reference":
        if generation == "a8_a11" and provider != "gaster":
            _error(errors, path, "documented A8-A11 route references must use Gaster")

    contracts = profile.get("adapter_contracts", {})
    if not isinstance(contracts, dict) or contracts.get("apple_route_reference") != (
        "tgcheckm8.apple-route-reference.v1"
    ):
        _error(errors, path, "Apple route reference profile must declare the TGCHECKM8 contract")


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

    _validate_apple_route_reference(path, profile, errors)
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
