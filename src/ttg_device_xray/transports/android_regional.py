from __future__ import annotations

import re
from typing import Any

from ..command import Runner
from ..models import TransportKind, TransportObservation


class AndroidRegionalProbe:
    """Read-only Android regional/customization evidence probe.

    This probe deliberately stays separate from the mature ADB identity/storage
    probe. Both observations correlate through the same ADB serial, while this
    layer focuses on regional properties, package provenance, overlays and
    customization manifests that explain differences between regional firmware
    builds.
    """

    name = "android_regional"

    PROPERTY_KEYS = (
        "ro.build.display.id",
        "ro.build.version.incremental",
        "ro.product.mod_device",
        "ro.product.locale",
        "ro.product.locale.language",
        "ro.product.locale.region",
        "persist.sys.locale",
        "ro.miui.region",
        "ro.miui.build.region",
        "ro.miui.cust_variant",
        "ro.miui.ui.version.name",
        "ro.miui.ui.version.code",
        "ro.vendor.miui.region",
        "ro.com.google.gmsversion",
        "ro.com.google.clientidbase",
        "ro.boot.hwc",
        "ro.boot.hwcountry",
        "ro.boot.country",
        "ro.system.build.fingerprint",
        "ro.system_ext.build.fingerprint",
        "ro.product.build.fingerprint",
        "ro.vendor.build.fingerprint",
    )

    GOOGLE_STACK_PACKAGES = (
        "com.google.android.gms",
        "com.google.android.gsf",
        "com.google.android.gsf.login",
        "com.android.vending",
        "com.google.android.configupdater",
        "com.google.android.partnersetup",
        "com.google.android.onetimeinitializer",
        "com.google.android.setupwizard",
        "com.google.android.syncadapters.contacts",
        "com.google.android.syncadapters.calendar",
        "com.google.android.backuptransport",
        "com.google.android.feedback",
    )

    REGIONAL_PACKAGE_PREFIXES = (
        "com.google.",
        "com.miui.",
        "com.xiaomi.",
        "com.mipay.",
        "com.duokan.",
        "com.baidu.",
        "com.tencent.",
        "com.taobao.",
        "com.sina.",
        "com.ss.android.",
        "com.smile.gifmaker",
        "cn.",
    )

    REGIONAL_PACKAGE_EXACT = {
        "com.android.vending",
        "com.mi.health",
        "com.xiaomi.market",
        "com.xiaomi.mipicks",
        "com.xiaomi.shop",
    }

    CUSTOMIZATION_DIRS = (
        "/cust",
        "/product/etc/sysconfig",
        "/product/etc/permissions",
        "/system_ext/etc/sysconfig",
        "/system_ext/etc/permissions",
        "/vendor/etc",
        "/odm/etc",
    )

    CUSTOMIZATION_NAME_HINTS = (
        "china",
        "cn",
        "cust",
        "feature",
        "gms",
        "google",
        "miui",
        "overlay",
        "preload",
        "region",
        "sysconfig",
    )

    def __init__(self, runner: Runner) -> None:
        self.runner = runner

    def _adb(self, serial: str, *args: str, timeout: int = 20):
        return self.runner.run(["adb", "-s", serial, *args], timeout=timeout)

    def probe(self) -> list[TransportObservation]:
        if not self.runner.exists("adb"):
            return [
                TransportObservation(
                    transport=TransportKind.ADB,
                    available=False,
                    connected=False,
                    mode="regional-unavailable",
                    capabilities={
                        "evidence_scope": "regional_customization",
                        "read_only": True,
                    },
                    warnings=["adb executable was not found for regional evidence"],
                )
            ]

        listing = self.runner.run(["adb", "devices", "-l"])
        observations: list[TransportObservation] = []
        rows = [line.strip() for line in listing.stdout.splitlines() if line.strip()]

        for row in rows:
            if row.startswith("List of devices") or row.startswith("*"):
                continue
            parts = row.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            observation = TransportObservation(
                transport=TransportKind.ADB,
                available=True,
                connected=state == "device",
                mode=f"regional-{state}",
                identifiers={"serial": serial},
                capabilities={
                    "evidence_scope": "regional_customization",
                    "read_only": True,
                },
                commands=[listing],
            )
            if state != "device":
                observation.warnings.append(f"ADB device state is {state}")
                observations.append(observation)
                continue

            properties: dict[str, str] = {}
            for prop_name in self.PROPERTY_KEYS:
                evidence = self._adb(serial, "shell", "getprop", prop_name)
                observation.commands.append(evidence)
                value = evidence.stdout.strip()
                if evidence.return_code == 0 and value:
                    properties[prop_name] = value

            current_user = self._adb(serial, "shell", "am", "get-current-user")
            observation.commands.append(current_user)
            user_id = current_user.stdout.strip() if current_user.return_code == 0 else ""

            known_evidence = self._adb(
                serial, "shell", "pm", "list", "packages", "-u", "-f", timeout=45
            )
            installed_evidence = self._adb(
                serial, "shell", "pm", "list", "packages", timeout=30
            )
            system_evidence = self._adb(
                serial, "shell", "pm", "list", "packages", "-u", "-s", timeout=30
            )
            disabled_evidence = self._adb(
                serial, "shell", "pm", "list", "packages", "-d", timeout=30
            )
            observation.commands.extend(
                [known_evidence, installed_evidence, system_evidence, disabled_evidence]
            )

            known_packages = self._parse_package_paths(known_evidence.stdout)
            installed = self._parse_package_names(installed_evidence.stdout)
            system = self._parse_package_names(system_evidence.stdout)
            disabled = self._parse_package_names(disabled_evidence.stdout)

            regional_packages = self._regional_package_records(
                known_packages,
                installed=installed,
                system=system,
                disabled=disabled,
            )
            google_stack = self._google_stack(
                known_packages,
                installed=installed,
                system=system,
                disabled=disabled,
            )

            overlay_evidence = self._adb(
                serial, "shell", "cmd", "overlay", "list", timeout=30
            )
            observation.commands.append(overlay_evidence)
            overlays = self._regional_overlays(self._parse_overlays(overlay_evidence.stdout))

            customization_files: list[dict[str, Any]] = []
            for root in self.CUSTOMIZATION_DIRS:
                evidence = self._adb(serial, "shell", "ls", "-1", root, timeout=20)
                observation.commands.append(evidence)
                if evidence.return_code != 0:
                    continue
                names = self._regional_file_names(evidence.stdout)
                if names:
                    customization_files.append({"root": root, "entries": names})

            inference = self._infer_region(properties)
            observation.identifiers.update(
                {
                    "region": inference["region"],
                    "region_source": inference["source"],
                }
            )
            observation.capabilities.update(
                {
                    "regional_properties": properties,
                    "region_inference": inference,
                    "current_user": user_id,
                    "package_counts": {
                        "known": len(known_packages),
                        "installed_for_current_user": len(installed),
                        "system_known": len(system),
                        "disabled_for_current_user": len(disabled),
                    },
                    "regional_packages": regional_packages,
                    "google_stack": google_stack,
                    "google_stack_present_count": sum(
                        1 for item in google_stack.values() if item["installed_for_current_user"]
                    ),
                    "regional_overlays": overlays,
                    "customization_files": customization_files,
                }
            )
            observations.append(observation)

        if not observations:
            observations.append(
                TransportObservation(
                    transport=TransportKind.ADB,
                    available=True,
                    connected=False,
                    mode="regional-no-device",
                    capabilities={
                        "evidence_scope": "regional_customization",
                        "read_only": True,
                    },
                    commands=[listing],
                )
            )
        return observations

    @staticmethod
    def _parse_package_paths(text: str) -> dict[str, str]:
        packages: dict[str, str] = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line.startswith("package:"):
                continue
            payload = line.removeprefix("package:")
            if "=" in payload:
                path, package = payload.rsplit("=", 1)
            else:
                path, package = "", payload
            package = package.strip()
            if package:
                packages[package] = path.strip()
        return packages

    @staticmethod
    def _parse_package_names(text: str) -> set[str]:
        names: set[str] = set()
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line.startswith("package:"):
                continue
            payload = line.removeprefix("package:")
            package = payload.rsplit("=", 1)[-1].strip()
            if package:
                names.add(package)
        return names

    @classmethod
    def _is_regional_package(cls, package: str) -> bool:
        return package in cls.REGIONAL_PACKAGE_EXACT or package.startswith(
            cls.REGIONAL_PACKAGE_PREFIXES
        )

    @staticmethod
    def _partition_for_path(path: str) -> str:
        normalized = path.strip()
        for prefix, name in (
            ("/system_ext/", "system_ext"),
            ("/system/", "system"),
            ("/product/", "product"),
            ("/vendor/", "vendor"),
            ("/odm/", "odm"),
            ("/cust/", "cust"),
            ("/apex/", "apex"),
            ("/data/", "data"),
        ):
            if normalized.startswith(prefix):
                return name
        return "unknown"

    @classmethod
    def _package_record(
        cls,
        package: str,
        path: str,
        *,
        installed: set[str],
        system: set[str],
        disabled: set[str],
    ) -> dict[str, Any]:
        return {
            "package": package,
            "path": path,
            "partition": cls._partition_for_path(path),
            "installed_for_current_user": package in installed,
            "known_system_package": package in system,
            "disabled_for_current_user": package in disabled,
        }

    @classmethod
    def _regional_package_records(
        cls,
        packages: dict[str, str],
        *,
        installed: set[str],
        system: set[str],
        disabled: set[str],
    ) -> list[dict[str, Any]]:
        return [
            cls._package_record(
                package,
                packages[package],
                installed=installed,
                system=system,
                disabled=disabled,
            )
            for package in sorted(packages)
            if cls._is_regional_package(package)
        ]

    @classmethod
    def _google_stack(
        cls,
        packages: dict[str, str],
        *,
        installed: set[str],
        system: set[str],
        disabled: set[str],
    ) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        for package in cls.GOOGLE_STACK_PACKAGES:
            path = packages.get(package, "")
            record = cls._package_record(
                package,
                path,
                installed=installed,
                system=system,
                disabled=disabled,
            )
            record["known_to_package_manager"] = package in packages
            result[package] = record
        return result

    @staticmethod
    def _parse_overlays(text: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        target = ""
        state_pattern = re.compile(r"^\[([^\]]*)\]\s+(.+)$")
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            match = state_pattern.match(line)
            if match:
                marker = match.group(1).strip().lower()
                package = match.group(2).strip()
                enabled: bool | None
                if marker in {"x", "1", "enabled"}:
                    enabled = True
                elif marker in {"", "0", "disabled"}:
                    enabled = False
                else:
                    enabled = None
                records.append(
                    {"target": target, "package": package, "enabled": enabled}
                )
                continue
            if line.startswith("---"):
                package = line.removeprefix("---").strip()
                if package:
                    records.append(
                        {"target": target, "package": package, "enabled": None}
                    )
                continue
            target = line
        return records

    @classmethod
    def _regional_overlays(cls, overlays: list[dict[str, Any]]) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        for item in overlays:
            haystack = f"{item.get('target', '')} {item.get('package', '')}".lower()
            if any(
                token in haystack
                for token in ("china", "cn", "google", "gms", "miui", "region", "xiaomi")
            ):
                records.append(item)
        return records

    @classmethod
    def _regional_file_names(cls, text: str) -> list[str]:
        names = []
        for raw_line in text.splitlines():
            name = raw_line.strip()
            if not name or name in {".", ".."}:
                continue
            lowered = name.lower()
            if any(hint in lowered for hint in cls.CUSTOMIZATION_NAME_HINTS):
                names.append(name)
        return sorted(set(names))[:250]

    @staticmethod
    def _infer_region(properties: dict[str, str]) -> dict[str, str]:
        priority = (
            "ro.miui.region",
            "ro.miui.build.region",
            "ro.vendor.miui.region",
            "ro.miui.cust_variant",
            "ro.product.mod_device",
            "ro.build.display.id",
            "ro.build.version.incremental",
            "ro.boot.hwcountry",
            "ro.boot.hwc",
            "ro.product.locale.region",
            "ro.product.locale",
        )
        suffixes = (
            ("CNXM", "CN"),
            ("MIXM", "GLOBAL"),
            ("EUXM", "EEA"),
            ("INXM", "INDIA"),
            ("IDXM", "INDONESIA"),
            ("TRXM", "TURKEY"),
            ("TWXM", "TAIWAN"),
            ("RUXM", "RUSSIA"),
        )
        direct = {
            "cn": "CN",
            "china": "CN",
            "global": "GLOBAL",
            "eea": "EEA",
            "eu": "EEA",
            "india": "INDIA",
            "in": "INDIA",
            "indonesia": "INDONESIA",
            "id": "INDONESIA",
            "turkey": "TURKEY",
            "tr": "TURKEY",
            "taiwan": "TAIWAN",
            "tw": "TAIWAN",
            "russia": "RUSSIA",
            "ru": "RUSSIA",
        }

        for key in priority:
            value = properties.get(key, "").strip()
            if not value:
                continue
            upper = value.upper()
            for suffix, region in suffixes:
                if suffix in upper:
                    return {"region": region, "source": key, "value": value}
            normalized = re.sub(r"[^a-z]+", "", value.lower())
            if normalized in direct:
                return {"region": direct[normalized], "source": key, "value": value}
            if "global" in normalized:
                return {"region": "GLOBAL", "source": key, "value": value}
            if normalized.startswith("cn") or "china" in normalized:
                return {"region": "CN", "source": key, "value": value}

        return {"region": "UNKNOWN", "source": "", "value": ""}
