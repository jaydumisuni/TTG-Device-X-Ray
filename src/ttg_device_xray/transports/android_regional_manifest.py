from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .android_regional import AndroidRegionalProbe


class AndroidRegionalManifestProbe(AndroidRegionalProbe):
    """Deepen regional evidence without expanding X-Ray write authority.

    The base regional probe identifies region properties, package provenance,
    overlays and customization filenames. This layer adds bounded recursive
    config-file fingerprints, current-user package state (including suspension),
    Google integration classification, and canonical firmware/user manifests for
    later device-to-firmware or region-to-region comparison.
    """

    name = "android_regional_manifest"
    MANIFEST_SCHEMA = "ttg.xray.android-regional-manifest.v2"

    CORE_GOOGLE_PACKAGES = (
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.android.vending",
    )

    FILE_MANIFEST_SCRIPT = r'''for root in \
/cust \
/system/etc/sysconfig \
/system/etc/permissions \
/product/etc/sysconfig \
/product/etc/permissions \
/system_ext/etc/sysconfig \
/system_ext/etc/permissions \
/vendor/etc \
/odm/etc; do
[ -d "$root" ] || continue
case "$root" in
  /cust) depth=5 ;;
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

    def probe(self):
        observations = super().probe()
        for observation in observations:
            if not observation.connected:
                continue
            serial = observation.identifiers.get("serial", "").strip()
            if not serial:
                observation.warnings.append(
                    "regional manifest skipped because ADB serial was unavailable"
                )
                continue

            user_id = str(observation.capabilities.get("current_user", "")).strip()
            package_state_evidence = self._adb(
                serial,
                "shell",
                "dumpsys",
                "package",
                "packages",
                timeout=90,
            )
            package_states = self._parse_user_package_states(
                package_state_evidence.stdout,
                user_id,
            )
            # The raw package dump can be several MiB. Keep command provenance but
            # retain only the deterministic parsed state in the evidence bundle.
            package_state_evidence.stdout = self._compact_package_state_evidence(
                package_states
            )
            observation.commands.append(package_state_evidence)

            regional_packages = observation.capabilities.get("regional_packages", [])
            if isinstance(regional_packages, list):
                self._attach_user_states(regional_packages, package_states)

            google_stack = observation.capabilities.get("google_stack", {})
            if isinstance(google_stack, dict):
                self._attach_google_user_states(google_stack, package_states)
            else:
                google_stack = {}

            file_evidence = self._adb(
                serial,
                "shell",
                "sh",
                "-c",
                self.FILE_MANIFEST_SCRIPT,
                timeout=90,
            )
            file_manifest = self._parse_file_manifest(file_evidence.stdout)
            file_evidence.stdout = self._compact_file_manifest_evidence(file_manifest)
            observation.commands.append(file_evidence)

            google_integration = self._classify_google_integration(google_stack)
            firmware_manifest = self._firmware_manifest(observation, file_manifest)
            user_manifest = self._user_manifest(
                observation,
                package_states,
                google_integration,
            )

            observation.capabilities.update(
                {
                    "regional_manifest_schema": self.MANIFEST_SCHEMA,
                    "customization_file_manifest": file_manifest,
                    "customization_file_count": len(file_manifest),
                    "google_integration": google_integration,
                    "firmware_regional_manifest": firmware_manifest,
                    "firmware_regional_manifest_sha256": self._canonical_sha256(
                        firmware_manifest
                    ),
                    "user_regional_state": user_manifest,
                    "user_regional_state_sha256": self._canonical_sha256(user_manifest),
                }
            )
        return observations

    @staticmethod
    def _parse_user_package_states(
        text: str,
        user_id: str,
    ) -> dict[str, dict[str, Any]]:
        if not user_id.isdigit():
            return {}

        package_pattern = re.compile(r"^\s*Package \[([^\]]+)\]")
        user_pattern = re.compile(r"^\s*User (\d+):\s*(.*)$")
        flag_pattern = re.compile(r"([A-Za-z][A-Za-z0-9_]*)=([^\s]+)")
        current_package = ""
        states: dict[str, dict[str, Any]] = {}

        for raw_line in text.splitlines():
            package_match = package_pattern.match(raw_line)
            if package_match:
                current_package = package_match.group(1).strip()
                continue
            if not current_package:
                continue
            user_match = user_pattern.match(raw_line)
            if not user_match or user_match.group(1) != user_id:
                continue
            flags = dict(flag_pattern.findall(user_match.group(2)))
            states[current_package] = {
                "installed": AndroidRegionalManifestProbe._bool_flag(flags.get("installed")),
                "hidden": AndroidRegionalManifestProbe._bool_flag(flags.get("hidden")),
                "suspended": AndroidRegionalManifestProbe._bool_flag(flags.get("suspended")),
                "stopped": AndroidRegionalManifestProbe._bool_flag(flags.get("stopped")),
                "enabled": flags.get("enabled", ""),
            }
        return states

    @staticmethod
    def _bool_flag(value: str | None) -> bool | None:
        if value is None:
            return None
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        return None

    @staticmethod
    def _compact_package_state_evidence(states: dict[str, dict[str, Any]]) -> str:
        suspended = sum(1 for item in states.values() if item.get("suspended") is True)
        hidden = sum(1 for item in states.values() if item.get("hidden") is True)
        return f"parsed_user_package_states={len(states)} suspended={suspended} hidden={hidden}"

    @staticmethod
    def _attach_user_states(
        records: list[dict[str, Any]],
        package_states: dict[str, dict[str, Any]],
    ) -> None:
        for record in records:
            package = str(record.get("package", ""))
            state = package_states.get(package, {})
            record["user_state"] = dict(state)
            record["suspended_for_current_user"] = state.get("suspended")
            record["hidden_for_current_user"] = state.get("hidden")

    @staticmethod
    def _attach_google_user_states(
        google_stack: dict[str, dict[str, Any]],
        package_states: dict[str, dict[str, Any]],
    ) -> None:
        for package, record in google_stack.items():
            state = package_states.get(package, {})
            record["user_state"] = dict(state)
            record["suspended_for_current_user"] = state.get("suspended")
            record["hidden_for_current_user"] = state.get("hidden")

    @classmethod
    def _parse_file_manifest(cls, text: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for raw_line in text.splitlines():
            fields = raw_line.strip().split("|", 2)
            if len(fields) != 3:
                continue
            path, raw_size, sha256 = fields
            if not cls._is_region_relevant_path(path):
                continue
            size = int(raw_size) if raw_size.isdigit() else 0
            normalized_hash = sha256.lower().strip()
            if normalized_hash and not re.fullmatch(r"[0-9a-f]{64}", normalized_hash):
                normalized_hash = ""
            records.append(
                {
                    "path": path,
                    "partition": cls._partition_for_path(path),
                    "size_bytes": size,
                    "sha256": normalized_hash,
                }
            )
        unique = {item["path"]: item for item in records}
        return [unique[path] for path in sorted(unique)][:1000]

    @staticmethod
    def _is_region_relevant_path(path: str) -> bool:
        lowered = path.lower()
        if lowered.startswith("/cust/"):
            return True
        tokens = set(filter(None, re.split(r"[/_.\-]+", lowered)))
        if "cn" in tokens or "china" in tokens:
            return True
        return any(
            marker in lowered
            for marker in (
                "google",
                "gms",
                "miui",
                "xiaomi",
                "overlay",
                "preload",
                "region",
                "sysconfig",
                "cust",
            )
        )

    @staticmethod
    def _compact_file_manifest_evidence(records: list[dict[str, Any]]) -> str:
        hashed = sum(1 for item in records if item.get("sha256"))
        return f"regional_config_files={len(records)} sha256_available={hashed}"

    @classmethod
    def _classify_google_integration(
        cls,
        google_stack: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        installed = [
            package
            for package in cls.CORE_GOOGLE_PACKAGES
            if bool(google_stack.get(package, {}).get("installed_for_current_user"))
        ]
        known_system = [
            package
            for package in cls.CORE_GOOGLE_PACKAGES
            if bool(google_stack.get(package, {}).get("known_system_package"))
        ]
        known = [
            package
            for package in cls.CORE_GOOGLE_PACKAGES
            if bool(google_stack.get(package, {}).get("known_to_package_manager"))
        ]

        if not known and not installed:
            presence = "ABSENT"
        elif len(installed) == len(cls.CORE_GOOGLE_PACKAGES):
            presence = "PRESENT"
        else:
            presence = "PARTIAL"

        if presence == "ABSENT":
            integration = "NONE"
        elif len(known_system) == len(cls.CORE_GOOGLE_PACKAGES):
            integration = "SYSTEM"
        elif any(
            google_stack.get(package, {}).get("partition") == "data"
            for package in cls.CORE_GOOGLE_PACKAGES
        ):
            integration = "USER_DATA_OR_MIXED"
        else:
            integration = "MIXED_OR_UNKNOWN"

        return {
            "core_packages": list(cls.CORE_GOOGLE_PACKAGES),
            "presence": presence,
            "integration": integration,
            "installed_core_packages": installed,
            "known_core_packages": known,
            "system_core_packages": known_system,
        }

    @classmethod
    def _firmware_manifest(
        cls,
        observation,
        file_manifest: list[dict[str, Any]],
    ) -> dict[str, Any]:
        capabilities = observation.capabilities
        regional_packages = capabilities.get("regional_packages", [])
        firmware_packages = []
        if isinstance(regional_packages, list):
            for item in regional_packages:
                if not isinstance(item, dict):
                    continue
                firmware_packages.append(
                    {
                        "package": str(item.get("package", "")),
                        "path": str(item.get("path", "")),
                        "partition": str(item.get("partition", "")),
                        "known_system_package": bool(item.get("known_system_package")),
                    }
                )

        google_stack = capabilities.get("google_stack", {})
        google_firmware = {}
        if isinstance(google_stack, dict):
            for package in sorted(google_stack):
                item = google_stack[package]
                if not isinstance(item, dict):
                    continue
                google_firmware[package] = {
                    "path": str(item.get("path", "")),
                    "partition": str(item.get("partition", "")),
                    "known_to_package_manager": bool(item.get("known_to_package_manager")),
                    "known_system_package": bool(item.get("known_system_package")),
                }

        return {
            "schema": cls.MANIFEST_SCHEMA,
            "kind": "firmware_regional_evidence",
            "region_inference": capabilities.get("region_inference", {}),
            "regional_properties": capabilities.get("regional_properties", {}),
            "regional_packages": sorted(
                firmware_packages,
                key=lambda item: item["package"],
            ),
            "google_stack": google_firmware,
            "regional_overlays": capabilities.get("regional_overlays", []),
            "customization_files": file_manifest,
        }

    @classmethod
    def _user_manifest(
        cls,
        observation,
        package_states: dict[str, dict[str, Any]],
        google_integration: dict[str, Any],
    ) -> dict[str, Any]:
        capabilities = observation.capabilities
        interest = {
            str(item.get("package", ""))
            for item in capabilities.get("regional_packages", [])
            if isinstance(item, dict) and item.get("package")
        }
        interest.update(cls.GOOGLE_STACK_PACKAGES)
        states = {
            package: package_states[package]
            for package in sorted(interest)
            if package in package_states
        }
        return {
            "schema": cls.MANIFEST_SCHEMA,
            "kind": "current_user_regional_state",
            "user_id": str(capabilities.get("current_user", "")),
            "package_states": states,
            "google_integration": google_integration,
        }

    @staticmethod
    def _canonical_sha256(payload: dict[str, Any]) -> str:
        encoded = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()
