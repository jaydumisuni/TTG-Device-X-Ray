from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

from ..command import Runner
from ..models import CommandEvidence, TransportKind, TransportObservation


class ReadOnlyUsbServiceProbe:
    """Reusable read-only probe for emergency/download USB transports.

    Subclasses provide a transport kind, environment prefix and a conservative
    Windows PnP/lsusb match expression. A separately reviewed helper may enrich
    the observation with protocol-specific identity, storage and GPT evidence.
    The base class never uploads a programmer, flashes, formats or writes.
    """

    name = "service_mode"
    transport = TransportKind.FASTBOOT
    env_prefix = "TTG_SERVICE"
    default_mode = "service"
    device_regex = r"$^"
    linux_usb_regex = r"$^"
    helper_timeout = 90

    def __init__(self, runner: Runner) -> None:
        self.runner = runner

    def probe(self) -> list[TransportObservation]:
        fixture = os.environ.get(f"{self.env_prefix}_EVIDENCE_FILE", "").strip()
        if fixture:
            return self._probe_fixture(Path(fixture))

        endpoints, commands, detector_available = self._detect_endpoints()
        if not detector_available:
            return [
                TransportObservation(
                    transport=self.transport,
                    available=False,
                    connected=False,
                    mode="unavailable",
                    warnings=[
                        "No supported local USB inventory command was found for this probe"
                    ],
                )
            ]
        if not endpoints:
            return [
                TransportObservation(
                    transport=self.transport,
                    available=True,
                    connected=False,
                    mode="no-device",
                    commands=commands,
                )
            ]

        observations: list[TransportObservation] = []
        for endpoint in endpoints:
            helper, helper_evidence, helper_warning = self._run_helper(endpoint)
            identifiers = {
                "usb_vid": str(endpoint.get("usb_vid", "")),
                "usb_pid": str(endpoint.get("usb_pid", "")),
                "usb_name": str(endpoint.get("name", "")),
                "pnp_device_id": str(endpoint.get("pnp_device_id", "")),
                "port": str(endpoint.get("port", "")),
                "usb_path": str(endpoint.get("usb_path", "")),
                **self._string_dict(helper.get("identifiers", {})),
            }
            mode = str(helper.get("mode") or self._mode_for_endpoint(endpoint)).lower()
            endpoint_present = self._endpoint_present(endpoint)
            endpoint_capabilities = self._endpoint_capabilities(endpoint, mode)
            transport_confirmed = self._endpoint_confirms_transport(
                endpoint, mode, endpoint_capabilities
            )
            capabilities = {
                **self._dict(helper.get("capabilities", {})),
                **endpoint_capabilities,
                "read_only": True,
                "helper_configured": helper_evidence is not None,
                "pnp_present": endpoint_present,
                "pnp_status": str(endpoint.get("status", "")),
                "transport_confirmed": transport_confirmed,
            }
            warnings = self._warnings(helper.get("warnings", []))
            if helper_warning:
                warnings.insert(0, helper_warning)
            if endpoint_present and not transport_confirmed:
                warnings.append(
                    f"{self.name} vendor USB evidence is present, but service mode was not confirmed"
                )
            observation_commands = list(commands)
            if helper_evidence is not None:
                observation_commands.append(helper_evidence)

            if "connected" in helper:
                connected = bool(helper.get("connected"))
            else:
                connected = endpoint_present and transport_confirmed

            observations.append(
                TransportObservation(
                    transport=self.transport,
                    available=True,
                    connected=connected,
                    mode=mode,
                    identifiers=identifiers,
                    capabilities=capabilities,
                    partitions=self._normalize_partitions(helper.get("partitions", [])),
                    commands=observation_commands,
                    warnings=warnings,
                )
            )
        return observations

    def _detect_endpoints(self) -> tuple[list[dict[str, str]], list[CommandEvidence], bool]:
        commands: list[CommandEvidence] = []
        shell = "powershell" if self.runner.exists("powershell") else "pwsh"
        if self.runner.exists(shell):
            pattern = os.environ.get(
                f"{self.env_prefix}_USB_REGEX", self.device_regex
            ).replace("'", "''")
            evidence = self.runner.run(
                [
                    shell,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    (
                        f"$pattern = '{pattern}'; "
                        "if (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) { "
                        "$items = Get-PnpDevice -PresentOnly | Where-Object { "
                        "(\"$($_.InstanceId) $($_.FriendlyName)\") -match $pattern } | "
                        "Select-Object @{N='Name';E={$_.FriendlyName}},"
                        "@{N='PNPDeviceID';E={$_.InstanceId}},Status,"
                        "@{N='Present';E={$true}}; "
                        "} else { "
                        "$items = Get-CimInstance Win32_PnPEntity | Where-Object { "
                        "($_.Present -eq $true -or $_.ConfigManagerErrorCode -ne 45) -and "
                        "(\"$($_.PNPDeviceID) $($_.Name)\") -match $pattern } | "
                        "Select-Object Name,PNPDeviceID,Status,Present,ConfigManagerErrorCode; "
                        "}; if ($items) { $items | ConvertTo-Json -Compress }"
                    ),
                ],
                timeout=30,
            )
            commands.append(evidence)
            return self._parse_windows_pnp(evidence.stdout), commands, True

        if self.runner.exists("lsusb"):
            evidence = self.runner.run(["lsusb"])
            commands.append(evidence)
            pattern = re.compile(
                os.environ.get(f"{self.env_prefix}_LSUSB_REGEX", self.linux_usb_regex),
                flags=re.IGNORECASE,
            )
            endpoints: list[dict[str, str]] = []
            for line in evidence.stdout.splitlines():
                if not pattern.search(line):
                    continue
                match = re.search(r"ID\s+([0-9A-Fa-f]{4}):([0-9A-Fa-f]{4})", line)
                endpoints.append(
                    {
                        "usb_vid": match.group(1).upper() if match else "",
                        "usb_pid": match.group(2).upper() if match else "",
                        "name": line.strip(),
                        "usb_path": line.strip(),
                        "present": "true",
                        "status": "present",
                    }
                )
            return endpoints, commands, True

        return [], commands, False

    def _run_helper(
        self, endpoint: dict[str, str]
    ) -> tuple[dict[str, Any], CommandEvidence | None, str]:
        raw = os.environ.get(f"{self.env_prefix}_HELPER", "").strip()
        if not raw:
            return (
                {},
                None,
                (
                    f"{self.name} USB evidence was detected, but "
                    f"{self.env_prefix}_HELPER is not configured"
                ),
            )
        try:
            command = [
                token.strip('"')
                for token in shlex.split(raw, posix=os.name != "nt")
            ]
        except ValueError as exc:
            return {}, None, f"Invalid helper command: {exc}"

        command.extend(
            [
                "--probe-json",
                "--read-only",
                "--transport",
                self.transport.value,
                "--usb-vid",
                endpoint.get("usb_vid", ""),
                "--usb-pid",
                endpoint.get("usb_pid", ""),
            ]
        )
        for flag, key in (
            ("--pnp-device-id", "pnp_device_id"),
            ("--port", "port"),
            ("--usb-path", "usb_path"),
        ):
            value = endpoint.get(key, "")
            if value:
                command.extend([flag, value])

        evidence = self.runner.run(command, timeout=self.helper_timeout)
        if evidence.return_code != 0:
            return {}, evidence, f"Helper failed with exit code {evidence.return_code}"
        payload = self._extract_json_value(evidence.stdout)
        if not isinstance(payload, dict):
            return {}, evidence, "Helper returned no valid JSON object"
        return payload, evidence, ""

    def _probe_fixture(self, path: Path) -> list[TransportObservation]:
        if not path.exists():
            return [
                TransportObservation(
                    transport=self.transport,
                    available=True,
                    connected=False,
                    mode="fixture-missing",
                    warnings=[f"Evidence fixture was not found: {path}"],
                )
            ]
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [
                TransportObservation(
                    transport=self.transport,
                    available=True,
                    connected=False,
                    mode="fixture-invalid",
                    warnings=[f"Could not parse evidence fixture: {exc}"],
                )
            ]
        items = payload if isinstance(payload, list) else [payload]
        observations: list[TransportObservation] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            capabilities = self._dict(item.get("capabilities", {}))
            capabilities["read_only"] = True
            observations.append(
                TransportObservation(
                    transport=self.transport,
                    available=True,
                    connected=bool(item.get("connected", True)),
                    mode=str(item.get("mode", self.default_mode)).lower(),
                    identifiers=self._string_dict(item.get("identifiers", {})),
                    capabilities=capabilities,
                    partitions=self._normalize_partitions(item.get("partitions", [])),
                    warnings=self._warnings(item.get("warnings", [])),
                )
            )
        return observations or [
            TransportObservation(
                transport=self.transport,
                available=True,
                connected=False,
                mode="fixture-empty",
                warnings=["Evidence fixture contained no observations"],
            )
        ]

    def _mode_for_endpoint(self, endpoint: dict[str, str]) -> str:
        return self.default_mode

    def _endpoint_capabilities(
        self, endpoint: dict[str, str], mode: str
    ) -> dict[str, Any]:
        return {"usb_transport_detected": True, "mode_candidate": mode}

    def _endpoint_confirms_transport(
        self,
        endpoint: dict[str, str],
        mode: str,
        capabilities: dict[str, Any],
    ) -> bool:
        return True

    @staticmethod
    def _endpoint_present(endpoint: dict[str, str]) -> bool:
        value = str(endpoint.get("present", "true")).strip().lower()
        return value not in {"0", "false", "no", "off", "none"}

    @classmethod
    def _parse_windows_pnp(cls, text: str) -> list[dict[str, str]]:
        payload = cls._extract_json_value(text)
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list):
            return []
        result: list[dict[str, str]] = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            pnp_id = str(item.get("PNPDeviceID") or item.get("InstanceId") or "")
            name = str(item.get("Name") or item.get("FriendlyName") or "")
            present_value = item.get("Present", True)
            present = (
                present_value
                if isinstance(present_value, bool)
                else str(present_value).strip().lower()
                not in {"0", "false", "no", "off", "none"}
            )
            try:
                error_code = int(item.get("ConfigManagerErrorCode", 0) or 0)
            except (TypeError, ValueError):
                error_code = 0
            if not present or error_code == 45:
                continue
            result.append(
                {
                    "pnp_device_id": pnp_id,
                    "name": name,
                    "status": str(item.get("Status", "")),
                    "present": "true",
                    "config_error_code": str(error_code),
                    "usb_vid": cls._extract_token(pnp_id, "VID"),
                    "usb_pid": cls._extract_token(pnp_id, "PID"),
                    "port": cls._extract_com_port(name),
                }
            )
        return result

    @staticmethod
    def _extract_json_value(text: str) -> Any | None:
        stripped = text.strip()
        if not stripped:
            return None
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
        for line in reversed([line.strip() for line in text.splitlines() if line.strip()]):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
        return None

    @staticmethod
    def _extract_token(pnp_id: str, name: str) -> str:
        match = re.search(rf"{name}_([0-9A-Fa-f]{{4}})", pnp_id)
        return match.group(1).upper() if match else ""

    @staticmethod
    def _extract_com_port(name: str) -> str:
        match = re.search(r"\((COM\d+)\)", name, flags=re.IGNORECASE)
        return match.group(1).upper() if match else ""

    @staticmethod
    def _dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}

    @staticmethod
    def _string_dict(value: Any) -> dict[str, str]:
        if not isinstance(value, dict):
            return {}
        return {str(key): str(item) for key, item in value.items() if item is not None}

    @staticmethod
    def _warnings(value: Any) -> list[str]:
        if isinstance(value, str):
            return [value] if value else []
        if isinstance(value, list):
            return [str(item) for item in value if item]
        return []

    @staticmethod
    def _risk(name: str) -> str:
        base = name.removesuffix("_a").removesuffix("_b").lower()
        if base in {
            "xbl",
            "xbl_config",
            "abl",
            "sbl1",
            "tz",
            "rpm",
            "hyp",
            "uefisecapp",
            "pgpt",
            "sgpt",
            "gpt",
            "proinfo",
            "nvram",
            "nvdata",
            "persist",
            "modem",
            "efs",
            "super",
            "boot",
            "vendor_boot",
            "vbmeta",
        }:
            return "critical"
        if base in {"frp", "metadata", "userdata", "misc", "recovery"}:
            return "sensitive"
        return "normal"

    @staticmethod
    def _coerce_int(value: Any) -> int:
        text = str(value).strip()
        if not text:
            return 0
        try:
            return int(text, 0)
        except ValueError:
            return 0

    @classmethod
    def _normalize_partitions(cls, value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list):
            return []
        result: list[dict[str, Any]] = []
        for raw in value:
            if not isinstance(raw, dict):
                continue
            name = str(raw.get("name", "")).strip()
            if not name:
                continue
            item = dict(raw)
            item["name"] = name
            item.setdefault("path", f"{cls.name}:{name}")
            item.setdefault("source", f"{cls.name}-helper")
            item.setdefault("risk", cls._risk(name))
            item.setdefault(
                "slot",
                "a" if name.endswith("_a") else "b" if name.endswith("_b") else "",
            )
            for key in (
                "size_bytes",
                "start_sector",
                "sector_count",
                "logical_block_size",
            ):
                if key in item:
                    item[key] = cls._coerce_int(item[key])
            result.append(item)
        return sorted(result, key=lambda item: str(item.get("name", "")))
