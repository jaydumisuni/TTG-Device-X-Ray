from __future__ import annotations

import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

from ..command import Runner
from ..models import TransportKind, TransportObservation


class MtkMetaProbe:
    """Read-only MTK Preloader/META transport probe.

    Windows PnP identifies MediaTek Preloader PID 2000 and Kernel META PID
    2007. The already-proven D2e/TSM DLL chain plugs in through an optional
    helper command that returns structured read-only evidence.
    """

    name = "mtk_meta"
    VID = "0E8D"
    PRELOADER_PID = "2000"
    META_PID = "2007"

    def __init__(self, runner: Runner) -> None:
        self.runner = runner

    def probe(self) -> list[TransportObservation]:
        fixture = os.environ.get("TTG_MTK_META_EVIDENCE_FILE", "").strip()
        if fixture:
            return self._probe_fixture(Path(fixture))

        shell = "powershell" if self.runner.exists("powershell") else "pwsh"
        if not self.runner.exists(shell):
            return [
                TransportObservation(
                    transport=TransportKind.MTK_META,
                    available=False,
                    connected=False,
                    mode="unavailable",
                    warnings=[
                        "PowerShell was not found; MTK VID/PID detection is unavailable"
                    ],
                )
            ]

        pnp = self.runner.run(
            [
                shell,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                (
                    "$items = Get-CimInstance Win32_PnPEntity | "
                    "Where-Object { $_.PNPDeviceID -match 'VID_0E8D&PID_(2000|2007)' } | "
                    "Select-Object Name,PNPDeviceID,Status; "
                    "if ($items) { $items | ConvertTo-Json -Compress }"
                ),
            ],
            timeout=30,
        )
        devices = self._parse_pnp_json(pnp.stdout)
        if not devices:
            return [
                TransportObservation(
                    transport=TransportKind.MTK_META,
                    available=True,
                    connected=False,
                    mode="no-device",
                    commands=[pnp],
                )
            ]

        observations: list[TransportObservation] = []
        for device in devices:
            pnp_id = str(device.get("PNPDeviceID", ""))
            name = str(device.get("Name", ""))
            pid = self._extract_token(pnp_id, "PID")
            vid = self._extract_token(pnp_id, "VID") or self.VID
            port = self._extract_com_port(name)
            mode = self._mode_for_pid(pid)
            helper_result, helper_command, helper_warning = self._run_helper(
                port=port,
                pid=pid,
                pnp_device_id=pnp_id,
            )
            identifiers = {
                "usb_vid": vid,
                "usb_pid": pid,
                "pnp_device_id": pnp_id,
                "usb_name": name,
                "port": port,
                "serial": self._extract_usb_serial(pnp_id),
                **self._string_dict(helper_result.get("identifiers", {})),
            }
            helper_capabilities = self._dict(helper_result.get("capabilities", {}))
            capabilities = {
                **helper_capabilities,
                "read_only": True,
                "preloader_detected": pid == self.PRELOADER_PID,
                "kernel_meta_detected": pid == self.META_PID,
                "helper_configured": helper_command is not None,
            }
            warnings = self._warnings(helper_result.get("warnings", []))
            if helper_warning:
                warnings.insert(0, helper_warning)
            commands = [pnp]
            if helper_command is not None:
                commands.append(helper_command)
            observations.append(
                TransportObservation(
                    transport=TransportKind.MTK_META,
                    available=True,
                    connected=bool(helper_result.get("connected", True)),
                    mode=str(helper_result.get("mode", mode)).lower(),
                    identifiers=identifiers,
                    capabilities=capabilities,
                    partitions=self._normalize_partitions(
                        helper_result.get("partitions", [])
                    ),
                    commands=commands,
                    warnings=warnings,
                )
            )
        return observations

    def _probe_fixture(self, path: Path) -> list[TransportObservation]:
        if not path.exists():
            return [
                TransportObservation(
                    transport=TransportKind.MTK_META,
                    available=True,
                    connected=False,
                    mode="fixture-missing",
                    warnings=[f"MTK META evidence file was not found: {path}"],
                )
            ]
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [
                TransportObservation(
                    transport=TransportKind.MTK_META,
                    available=True,
                    connected=False,
                    mode="fixture-invalid",
                    warnings=[f"Could not parse MTK META evidence: {exc}"],
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
                    transport=TransportKind.MTK_META,
                    available=True,
                    connected=bool(item.get("connected", True)),
                    mode=str(item.get("mode", "meta")).lower(),
                    identifiers=self._string_dict(item.get("identifiers", {})),
                    capabilities=capabilities,
                    partitions=self._normalize_partitions(item.get("partitions", [])),
                    warnings=self._warnings(item.get("warnings", [])),
                )
            )
        return observations or [
            TransportObservation(
                transport=TransportKind.MTK_META,
                available=True,
                connected=False,
                mode="fixture-empty",
                warnings=["MTK META evidence file contained no observations"],
            )
        ]

    def _run_helper(
        self, *, port: str, pid: str, pnp_device_id: str
    ) -> tuple[dict[str, Any], Any | None, str]:
        raw = os.environ.get("TTG_MTK_META_HELPER", "").strip()
        if not raw:
            return (
                {},
                None,
                (
                    "MTK USB transport detected, but TTG_MTK_META_HELPER is not configured; "
                    "only VID/PID/COM evidence was collected"
                ),
            )
        try:
            command = [
                token.strip('"')
                for token in shlex.split(raw, posix=os.name != "nt")
            ]
        except ValueError as exc:
            return {}, None, f"Invalid TTG_MTK_META_HELPER command: {exc}"
        command.extend(
            [
                "--probe-json",
                "--read-only",
                "--pid",
                pid,
                "--pnp-device-id",
                pnp_device_id,
            ]
        )
        if port:
            command.extend(["--port", port])
        evidence = self.runner.run(command, timeout=90)
        if evidence.return_code != 0:
            return (
                {},
                evidence,
                f"MTK META helper failed with exit code {evidence.return_code}",
            )
        payload = self._extract_json_object(evidence.stdout)
        if payload is None:
            return {}, evidence, "MTK META helper returned no valid JSON object"
        return payload, evidence, ""

    @staticmethod
    def _parse_pnp_json(text: str) -> list[dict[str, Any]]:
        payload = MtkMetaProbe._extract_json_value(text)
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []

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
        start_candidates = [index for index in (text.find("{"), text.find("[")) if index >= 0]
        if not start_candidates:
            return None
        start = min(start_candidates)
        end = max(text.rfind("}"), text.rfind("]"))
        if end <= start:
            return None
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _extract_json_object(text: str) -> dict[str, Any] | None:
        payload = MtkMetaProbe._extract_json_value(text)
        return payload if isinstance(payload, dict) else None

    @staticmethod
    def _extract_token(pnp_id: str, name: str) -> str:
        match = re.search(rf"{name}_([0-9A-Fa-f]{{4}})", pnp_id)
        return match.group(1).upper() if match else ""

    @staticmethod
    def _extract_com_port(name: str) -> str:
        match = re.search(r"\((COM\d+)\)", name, flags=re.IGNORECASE)
        return match.group(1).upper() if match else ""

    @staticmethod
    def _extract_usb_serial(pnp_id: str) -> str:
        tail = pnp_id.rsplit("\\", 1)[-1]
        return "" if "&" in tail else tail

    @classmethod
    def _mode_for_pid(cls, pid: str) -> str:
        if pid == cls.PRELOADER_PID:
            return "preloader"
        if pid == cls.META_PID:
            return "meta"
        return "mtk-usb"

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
            "preloader",
            "pgpt",
            "sgpt",
            "gpt",
            "proinfo",
            "nvram",
            "nvdata",
            "protect1",
            "protect2",
            "md1img",
            "persist",
            "super",
            "boot",
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
            try:
                return int(text, 10)
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
            item.setdefault("path", f"mtk-meta:{name}")
            item.setdefault("source", "mtk-meta-helper")
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
