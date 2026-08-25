from __future__ import annotations

import json
import re
from typing import Any


XIAOMI_CUST_SELECTOR_SCRIPT = r'''emit_file() {
  tag="$1"
  path="$2"
  printf 'TTG_XIAOMI_CUST_BEGIN|%s|%s\n' "$tag" "$path"
  if [ -f "$path" ]; then
    cat "$path" 2>/dev/null
    printf '\nTTG_XIAOMI_CUST_END|%s\n' "$tag"
  else
    printf 'TTG_XIAOMI_CUST_MISSING\n'
    printf 'TTG_XIAOMI_CUST_END|%s\n' "$tag"
  fi
}
emit_file cust_variant /cust/cust_variant
emit_file business_prop /cust/etc/business.prop
emit_file request_config /cust/etc/cust_apps_request_config
emit_file apps_config /cust/etc/cust_apps_config'''

_BEGIN_RE = re.compile(r"^TTG_XIAOMI_CUST_BEGIN\|([^|]+)\|(.*)$")
_END_RE = re.compile(r"^TTG_XIAOMI_CUST_END\|([^|]+)$")
_REQUEST_PAIR_RE = re.compile(r"([A-Za-z][A-Za-z0-9_]*)\s*=\s*([^\s]*)")


def parse_xiaomi_cust_selector(text: str) -> dict[str, Any]:
    """Parse Xiaomi /cust selector files into deterministic regional evidence.

    The parser intentionally omits repository/download URLs from the canonical
    selector record. Those URLs are delivery metadata and can change while the
    regional firmware policy itself remains equivalent.
    """

    sections = _sections(text)
    present = {name for name, value in sections.items() if value.strip() and value.strip() != "TTG_XIAOMI_CUST_MISSING"}
    if not present:
        return {
            "status": "NOT_PRESENT",
            "cust_variant": "",
            "business_version": "",
            "request": {},
            "preload_policy": {},
        }

    cust_variant = sections.get("cust_variant", "").strip()
    business_version = _business_version(sections.get("business_prop", ""))
    request = _request_config(sections.get("request_config", ""))
    preload_policy = _apps_config(sections.get("apps_config", ""))

    return {
        "status": "COLLECTED",
        "cust_variant": cust_variant,
        "business_version": business_version,
        "request": request,
        "preload_policy": preload_policy,
    }


def selector_consistency(selector: dict[str, Any], regional_properties: dict[str, Any]) -> dict[str, Any]:
    """Compare file-backed Xiaomi selector state with live regional properties."""

    file_variant = str(selector.get("cust_variant", "")).strip()
    request = selector.get("request") if isinstance(selector.get("request"), dict) else {}
    property_variant = str(regional_properties.get("ro.miui.cust_variant", "")).strip()
    property_region = str(regional_properties.get("ro.miui.region", "")).strip()
    request_sku = str(request.get("currentSku", "")).strip()
    request_region = str(request.get("romRegion", "")).strip()

    checks = {
        "cust_variant_matches_property": _same_when_present(file_variant, property_variant),
        "cust_variant_matches_request_sku": _same_when_present(file_variant, request_sku),
        "region_matches_request": _same_when_present(property_region.lower(), request_region.lower()),
    }
    available = [value for value in checks.values() if value is not None]
    return {
        "checks": checks,
        "consistent": all(available) if available else None,
    }


def compact_xiaomi_cust_selector(selector: dict[str, Any]) -> str:
    preload = selector.get("preload_policy") if isinstance(selector.get("preload_policy"), dict) else {}
    packages = preload.get("packages") if isinstance(preload.get("packages"), list) else []
    return (
        f"xiaomi_cust_status={selector.get('status', 'ERROR')} "
        f"cust_variant={selector.get('cust_variant', '')} "
        f"business_version={selector.get('business_version', '')} "
        f"preload_packages={len(packages)}"
    )


def _sections(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    current = ""
    body: list[str] = []

    def flush() -> None:
        nonlocal current, body
        if current:
            result[current] = "\n".join(body).strip()
        current = ""
        body = []

    for raw_line in text.splitlines():
        begin = _BEGIN_RE.match(raw_line)
        if begin:
            flush()
            current = begin.group(1).strip()
            continue
        end = _END_RE.match(raw_line)
        if end and current == end.group(1).strip():
            flush()
            continue
        if current:
            body.append(raw_line)
    flush()
    return result


def _business_version(text: str) -> str:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if line.startswith("ro.miui.business.version="):
            return line.split("=", 1)[1].strip()
    return ""


def _request_config(text: str) -> dict[str, str]:
    pairs = dict(_REQUEST_PAIR_RE.findall(" ".join(text.splitlines())))
    keep = (
        "device",
        "romRegion",
        "romVersionType",
        "profile",
        "custprop",
        "testConfigId",
        "currentSku",
        "custVersion",
    )
    return {key: pairs.get(key, "") for key in keep if key in pairs}


def _apps_config(text: str) -> dict[str, Any]:
    raw = text.strip()
    if not raw or raw == "TTG_XIAOMI_CUST_MISSING":
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {"parse_status": "ERROR"}
    if not isinstance(payload, dict):
        return {"parse_status": "ERROR"}

    packages: list[dict[str, Any]] = []
    variants: set[str] = set()
    subareas: set[str] = set()
    data = payload.get("data")
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            enabled_variants: set[str] = set()
            item_subareas: set[str] = set()
            configs = item.get("custConfig")
            if isinstance(configs, list):
                for config in configs:
                    if not isinstance(config, dict) or config.get("enable") is not True:
                        continue
                    variant = str(config.get("custVariants", "")).strip()
                    subarea = str(config.get("subarea", "")).strip()
                    if variant:
                        enabled_variants.add(variant)
                        variants.add(variant)
                    if subarea:
                        item_subareas.add(subarea)
                        subareas.add(subarea)
            packages.append(
                {
                    "package": str(item.get("packageName", "")).strip(),
                    "package_id": str(item.get("packageId", "")).strip(),
                    "ota_skip": bool(item.get("otaSkip")),
                    "launcher_icon_location": item.get("launcherIconLocation"),
                    "enabled_cust_variants": sorted(enabled_variants),
                    "subareas": sorted(item_subareas),
                }
            )

    packages = sorted(
        (item for item in packages if item.get("package")),
        key=lambda item: str(item["package"]),
    )
    declared_count = payload.get("appNum")
    return {
        "parse_status": "COLLECTED",
        "status_code": payload.get("status"),
        "target_product": str(payload.get("targetProduct", "")).strip(),
        "rom_region": str(payload.get("romRegion", "")).strip(),
        "rom_version_type": str(payload.get("romVersionType", "")).strip(),
        "is_test": payload.get("isTest"),
        "declared_app_count": declared_count if isinstance(declared_count, int) else None,
        "observed_app_count": len(packages),
        "enabled_cust_variants": sorted(variants),
        "subareas": sorted(subareas),
        "packages": packages,
    }


def _same_when_present(left: str, right: str) -> bool | None:
    if not left or not right:
        return None
    return left == right
