from __future__ import annotations

import json
import plistlib
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class IpswAnalysisError(RuntimeError):
    pass


@dataclass(slots=True)
class IpswAnalyzer:
    path: Path

    def analyze(self) -> dict[str, Any]:
        if not self.path.exists() or not self.path.is_file():
            raise IpswAnalysisError(f"IPSW file not found: {self.path}")
        if not zipfile.is_zipfile(self.path):
            raise IpswAnalysisError(f"Not a valid IPSW/ZIP archive: {self.path}")

        with zipfile.ZipFile(self.path) as archive:
            names = set(archive.namelist())
            manifest_name = self._find_name(names, "BuildManifest.plist")
            restore_name = self._find_name(names, "Restore.plist")
            if not manifest_name:
                raise IpswAnalysisError("BuildManifest.plist is missing from the IPSW")
            manifest = plistlib.loads(archive.read(manifest_name))
            restore = plistlib.loads(archive.read(restore_name)) if restore_name else {}

        identities = [self._identity_summary(item) for item in manifest.get("BuildIdentities", [])]
        product_types = sorted(
            {
                token
                for token in [
                    *manifest.get("SupportedProductTypes", []),
                    *restore.get("SupportedProductTypes", []),
                    *(item.get("product_type", "") for item in identities),
                ]
                if token
            }
        )
        board_configs = sorted({item["board_config"] for item in identities if item["board_config"]})
        chips = sorted({item["chip_id"] for item in identities if item["chip_id"]})
        boards = sorted({item["board_id"] for item in identities if item["board_id"]})

        return {
            "artifact": "apple_ipsw",
            "path": str(self.path.resolve()),
            "size_bytes": self.path.stat().st_size,
            "product_version": manifest.get("ProductVersion", restore.get("ProductVersion", "")),
            "product_build_version": manifest.get(
                "ProductBuildVersion", restore.get("ProductBuildVersion", "")
            ),
            "supported_product_types": product_types,
            "board_configs": board_configs,
            "chip_ids": chips,
            "board_ids": boards,
            "build_identity_count": len(identities),
            "build_identities": identities,
            "restore_variant": restore.get("RestoreVariant", ""),
            "system_restore_image": restore.get("SystemRestoreImageFileSystems", {}),
            "compatibility_keys": [
                {
                    "product_type": item["product_type"],
                    "board_config": item["board_config"],
                    "chip_id": item["chip_id"],
                    "board_id": item["board_id"],
                    "restore_behavior": item["restore_behavior"],
                    "variant": item["variant"],
                }
                for item in identities
            ],
        }

    @staticmethod
    def _find_name(names: set[str], suffix: str) -> str | None:
        exact = next((name for name in names if name == suffix), None)
        if exact:
            return exact
        return next((name for name in names if name.endswith(f"/{suffix}")), None)

    @staticmethod
    def _hexish(value: Any) -> str:
        if isinstance(value, bytes):
            return "0x" + value.hex().upper()
        if isinstance(value, int):
            return hex(value)
        return str(value or "")

    @classmethod
    def _identity_summary(cls, identity: dict[str, Any]) -> dict[str, Any]:
        info = identity.get("Info", {})
        manifest = identity.get("Manifest", {})
        components = {
            name: value.get("Info", {}).get("Path", "")
            for name, value in manifest.items()
            if isinstance(value, dict) and value.get("Info", {}).get("Path")
        }
        return {
            "product_type": info.get("ProductType", ""),
            "board_config": info.get("DeviceClass", ""),
            "variant": info.get("Variant", identity.get("Variant", "")),
            "restore_behavior": info.get("RestoreBehavior", ""),
            "chip_id": cls._hexish(identity.get("ApChipID")),
            "board_id": cls._hexish(identity.get("ApBoardID")),
            "security_domain": cls._hexish(identity.get("ApSecurityDomain")),
            "unique_build_id": cls._hexish(identity.get("UniqueBuildID")),
            "component_paths": components,
        }


def write_ipsw_report(path: Path, output: Path | None = None) -> dict[str, Any]:
    report = IpswAnalyzer(path).analyze()
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
