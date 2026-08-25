from __future__ import annotations

from typing import Any

from .android_regional_manifest import AndroidRegionalManifestProbe
from .xiaomi_cust_selector import (
    XIAOMI_CUST_SELECTOR_SCRIPT,
    compact_xiaomi_cust_selector,
    parse_xiaomi_cust_selector,
    selector_consistency,
)


class XiaomiRegionalManifestProbe(AndroidRegionalManifestProbe):
    """Add Xiaomi-specific regional provenance without expanding write authority.

    HyperOS can overlay the AVB-verified ``mi_ext`` logical partition over
    ``/product``, ``/system`` and ``/system_ext``. Treating only the merged mount
    paths as evidence loses the signed source partition. This probe preserves that
    provenance and structures Xiaomi's ``/cust`` selector/preload policy.
    """

    name = "android_regional_manifest"
    MANIFEST_SCHEMA = "ttg.xray.android-regional-manifest.v3"

    FILE_MANIFEST_SCRIPT = r'''for root in /cust /mi_ext /product/etc/sysconfig /product/etc/permissions /system_ext/etc/sysconfig /system_ext/etc/permissions /vendor/etc /odm/etc; do
[ -d "$root" ] || continue
case "$root" in
  /cust) depth=5 ;;
  /mi_ext) depth=8 ;;
  /vendor/etc|/odm/etc) depth=2 ;;
  *) depth=3 ;;
esac
find "$root" -maxdepth "$depth" -type f 2>/dev/null
done | while IFS= read -r file; do
size=$(wc -c < "$file" 2>/dev/null)
hash=""
if command -v sha256sum >/dev/null 2>&1; then
  hash=$(sha256sum "$file" 2>/dev/null)
  hash=${hash%% *}
elif command -v toybox >/dev/null 2>&1; then
  hash=$(toybox sha256sum "$file" 2>/dev/null)
  hash=${hash%% *}
fi
printf '%s|%s|%s\n' "$file" "$size" "$hash"
done'''

    MI_EXT_IDENTITY_SCRIPT = r'''if [ -d /mi_ext ]; then
printf 'present=true\n'
else
printf 'present=false\n'
fi
for k in partition.mi_ext.verified partition.mi_ext.verified.hash_alg partition.mi_ext.verified.root_digest partition.mi_ext.verified.check_at_most_once; do
printf '%s=%s\n' "$k" "$(getprop "$k")"
done
awk '$2 == "/mi_ext" {printf "mount_source=%s\nfilesystem=%s\nmount_options=%s\n", $1, $3, $4; exit}' /proc/mounts 2>/dev/null
if [ -f /mi_ext/etc/build.prop ]; then
for k in ro.miui.build.region ro.com.google.clientidbase ro.com.google.clientidbase.ms; do
v=$(grep -a -m1 "^${k}=" /mi_ext/etc/build.prop 2>/dev/null)
v=${v#*=}
printf 'buildprop.%s=%s\n' "$k" "$v"
done
fi'''

    def probe(self):
        observations = super().probe()
        for observation in observations:
            if not observation.connected:
                continue

            properties = observation.capabilities.get("regional_properties", {})
            if not isinstance(properties, dict) or not self._is_miui(properties):
                continue
            serial = observation.identifiers.get("serial", "").strip()
            if not serial:
                continue

            selector_evidence = self._adb(
                serial,
                "shell",
                XIAOMI_CUST_SELECTOR_SCRIPT,
                timeout=30,
            )
            selector = (
                parse_xiaomi_cust_selector(selector_evidence.stdout)
                if selector_evidence.return_code == 0 and not selector_evidence.timed_out
                else {
                    "status": "ERROR",
                    "cust_variant": "",
                    "business_version": "",
                    "request": {},
                    "preload_policy": {},
                }
            )
            consistency = selector_consistency(selector, properties)
            selector_record = {
                **selector,
                "consistency": consistency,
            }
            selector_evidence.stdout = compact_xiaomi_cust_selector(selector)
            observation.commands.append(selector_evidence)
            if selector["status"] == "ERROR":
                observation.warnings.append(
                    "Xiaomi /cust selector evidence was unavailable because the read-only ADB command failed"
                )

            mi_ext_evidence = self._adb(
                serial,
                "shell",
                self.MI_EXT_IDENTITY_SCRIPT,
                timeout=30,
            )
            mi_ext = (
                self._parse_key_value_evidence(mi_ext_evidence.stdout)
                if mi_ext_evidence.return_code == 0 and not mi_ext_evidence.timed_out
                else {"status": "ERROR"}
            )
            if "status" not in mi_ext:
                mi_ext["status"] = "COLLECTED"
            mi_ext_evidence.stdout = self._compact_mi_ext_evidence(mi_ext)
            observation.commands.append(mi_ext_evidence)
            if mi_ext.get("status") == "ERROR":
                observation.warnings.append(
                    "Xiaomi mi_ext provenance was unavailable because the read-only ADB command failed"
                )

            observation.capabilities["xiaomi_customization_selector"] = selector_record
            observation.capabilities["xiaomi_mi_ext"] = mi_ext

            firmware_manifest = observation.capabilities.get(
                "firmware_regional_manifest", {}
            )
            if isinstance(firmware_manifest, dict):
                firmware_manifest["xiaomi_customization_selector"] = selector_record
                firmware_manifest["xiaomi_mi_ext"] = mi_ext
                observation.capabilities["firmware_regional_manifest_sha256"] = (
                    self._canonical_sha256(firmware_manifest)
                )
        return observations

    @staticmethod
    def _is_miui(properties: dict[str, Any]) -> bool:
        return any(
            key in properties
            for key in (
                "ro.miui.region",
                "ro.miui.build.region",
                "ro.miui.cust_variant",
                "ro.vendor.miui.region",
            )
        )

    @staticmethod
    def _partition_for_path(path: str) -> str:
        normalized = path.strip()
        if normalized == "/mi_ext" or normalized.startswith("/mi_ext/"):
            return "mi_ext"
        return AndroidRegionalManifestProbe._partition_for_path(path)

    @staticmethod
    def _is_region_relevant_path(path: str) -> bool:
        lowered = path.lower().strip()
        if lowered == "/mi_ext" or lowered.startswith("/mi_ext/"):
            return True
        return AndroidRegionalManifestProbe._is_region_relevant_path(path)

    @staticmethod
    def _parse_key_value_evidence(text: str) -> dict[str, Any]:
        record: dict[str, Any] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()
            if not key:
                continue
            if key == "present":
                record[key] = value.lower() == "true"
            else:
                record[key] = value
        return record

    @staticmethod
    def _compact_mi_ext_evidence(record: dict[str, Any]) -> str:
        return (
            f"mi_ext_status={record.get('status', 'ERROR')} "
            f"present={record.get('present')} "
            f"verified={record.get('partition.mi_ext.verified', '')} "
            f"hash_alg={record.get('partition.mi_ext.verified.hash_alg', '')} "
            f"root_digest={record.get('partition.mi_ext.verified.root_digest', '')}"
        )
