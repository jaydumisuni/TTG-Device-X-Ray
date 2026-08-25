from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


class RegionalCompareError(ValueError):
    """Raised when a regional firmware manifest cannot be recovered safely."""


def _canonical_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _extract_manifest(payload: Any) -> dict[str, Any] | None:
    if isinstance(payload, dict):
        if payload.get("kind") == "firmware_regional_evidence":
            return payload
        direct = payload.get("firmware_regional_manifest")
        if isinstance(direct, dict):
            return direct
        capabilities = payload.get("capabilities")
        if isinstance(capabilities, dict):
            nested = capabilities.get("firmware_regional_manifest")
            if isinstance(nested, dict):
                return nested
        observations = payload.get("observations")
        if isinstance(observations, list):
            for observation in observations:
                manifest = _extract_manifest(observation)
                if manifest is not None:
                    return manifest
    elif isinstance(payload, list):
        for item in payload:
            manifest = _extract_manifest(item)
            if manifest is not None:
                return manifest
    return None


def load_firmware_regional_manifest(source: Path) -> dict[str, Any]:
    """Load one firmware-regional manifest from a bundle directory or JSON file."""

    path = source.expanduser()
    if path.is_dir():
        path = path / "transport_evidence.json"
    if not path.is_file():
        raise RegionalCompareError(f"regional comparison source not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegionalCompareError(f"could not read regional comparison source: {path}") from exc
    manifest = _extract_manifest(payload)
    if manifest is None:
        raise RegionalCompareError(f"firmware regional manifest not found in: {path}")
    if manifest.get("kind") != "firmware_regional_evidence":
        raise RegionalCompareError(f"unsupported regional manifest kind in: {path}")
    return manifest


def _mapping_diff(
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any]:
    left_keys = set(left)
    right_keys = set(right)
    common = left_keys & right_keys
    changed = {
        key: {"left": left[key], "right": right[key]}
        for key in sorted(common)
        if left[key] != right[key]
    }
    return {
        "added": {key: right[key] for key in sorted(right_keys - left_keys)},
        "removed": {key: left[key] for key in sorted(left_keys - right_keys)},
        "changed": changed,
        "unchanged_count": sum(left[key] == right[key] for key in common),
    }


def _record_index(records: Any, key_fields: tuple[str, ...]) -> dict[str, dict[str, Any]]:
    if not isinstance(records, list):
        return {}
    index: dict[str, dict[str, Any]] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        parts = [str(record.get(field, "")).strip() for field in key_fields]
        if not all(parts):
            continue
        index["|".join(parts)] = record
    return index


def _record_diff(
    left_records: Any,
    right_records: Any,
    *,
    key_fields: tuple[str, ...],
) -> dict[str, Any]:
    left = _record_index(left_records, key_fields)
    right = _record_index(right_records, key_fields)
    diff = _mapping_diff(left, right)
    return {
        "key_fields": list(key_fields),
        "added": list(diff["added"].values()),
        "removed": list(diff["removed"].values()),
        "changed": [
            {"key": key, **value}
            for key, value in diff["changed"].items()
        ],
        "unchanged_count": diff["unchanged_count"],
    }


def _summary(diff: dict[str, Any]) -> dict[str, int]:
    return {
        "added": len(diff.get("added", [])),
        "removed": len(diff.get("removed", [])),
        "changed": len(diff.get("changed", [])),
        "unchanged": int(diff.get("unchanged_count", 0)),
    }


def _xiaomi_selector_parts(
    manifest: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Split Xiaomi selector metadata from its package policy for useful diffs."""

    raw_selector = manifest.get("xiaomi_customization_selector")
    selector = dict(raw_selector) if isinstance(raw_selector, dict) else {}
    raw_policy = selector.get("preload_policy")
    policy = dict(raw_policy) if isinstance(raw_policy, dict) else {}
    raw_packages = policy.pop("packages", [])
    packages = [dict(item) for item in raw_packages if isinstance(item, dict)] if isinstance(raw_packages, list) else []
    selector["preload_policy"] = policy
    return selector, packages


def compare_regional_manifests(
    left: dict[str, Any],
    right: dict[str, Any],
) -> dict[str, Any]:
    """Compare two canonical firmware-regional manifests without device writes."""

    properties = _mapping_diff(
        dict(left.get("regional_properties") or {}),
        dict(right.get("regional_properties") or {}),
    )
    packages = _record_diff(
        left.get("regional_packages"),
        right.get("regional_packages"),
        key_fields=("package",),
    )
    overlays = _record_diff(
        left.get("regional_overlays"),
        right.get("regional_overlays"),
        key_fields=("target", "package"),
    )
    files = _record_diff(
        left.get("customization_files"),
        right.get("customization_files"),
        key_fields=("path",),
    )
    google = _mapping_diff(
        dict(left.get("google_stack") or {}),
        dict(right.get("google_stack") or {}),
    )

    left_selector, left_preloads = _xiaomi_selector_parts(left)
    right_selector, right_preloads = _xiaomi_selector_parts(right)
    xiaomi_selector = _mapping_diff(left_selector, right_selector)
    xiaomi_preloads = _record_diff(
        left_preloads,
        right_preloads,
        key_fields=("package",),
    )
    xiaomi_mi_ext = _mapping_diff(
        dict(left.get("xiaomi_mi_ext") or {}),
        dict(right.get("xiaomi_mi_ext") or {}),
    )

    left_region = dict(left.get("region_inference") or {})
    right_region = dict(right.get("region_inference") or {})
    left_collection = dict(left.get("customization_file_collection") or {})
    right_collection = dict(right.get("customization_file_collection") or {})

    return {
        "schema": "ttg.xray.android-regional-compare.v1",
        "kind": "firmware_regional_comparison",
        "read_only": True,
        "left": {
            "region_inference": left_region,
            "manifest_sha256": _canonical_sha256(left),
            "customization_file_collection": left_collection,
        },
        "right": {
            "region_inference": right_region,
            "manifest_sha256": _canonical_sha256(right),
            "customization_file_collection": right_collection,
        },
        "region_changed": left_region != right_region,
        "summary": {
            "properties": _summary(properties),
            "regional_packages": _summary(packages),
            "regional_overlays": _summary(overlays),
            "customization_files": _summary(files),
            "google_stack": _summary(google),
            "xiaomi_customization_selector": _summary(xiaomi_selector),
            "xiaomi_preload_packages": _summary(xiaomi_preloads),
            "xiaomi_mi_ext": _summary(xiaomi_mi_ext),
        },
        "properties": properties,
        "regional_packages": packages,
        "regional_overlays": overlays,
        "customization_files": files,
        "google_stack": google,
        "xiaomi_customization_selector": xiaomi_selector,
        "xiaomi_preload_packages": xiaomi_preloads,
        "xiaomi_mi_ext": xiaomi_mi_ext,
    }


def compare_regional_sources(left: Path, right: Path) -> dict[str, Any]:
    return compare_regional_manifests(
        load_firmware_regional_manifest(left),
        load_firmware_regional_manifest(right),
    )
