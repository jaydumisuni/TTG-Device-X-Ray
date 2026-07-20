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

    The probe has two layers:

    1. Deterministic Windows PnP detection for MediaTek VID 0E8D, including
       Preloader PID 2000 and Kernel META PID 2007.
    2. An optional external D2e/TSM helper that performs the already-proven
       DLL session chain and returns read-only JSON evidence.

    The helper is configured with TTG_MTK_META_HELPER or an evidence fixture
    can be supplied with TTG_MTK_META_EVIDENCE_FILE.
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

        command = [
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
        ]
        pnp = self.runner.run(command, timeout=30)
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
            base_ids = {
                "usb_vid": vid,
                "usb_pid": pid,
                "pnp_device_id": pnp_id,
                "usb_name": name,
                "port": port,
                "serial": self._extract_usb_serial(pnp_id),
            }
            helper_result, helper_command, helper_warning = self._run_helper(
                port=port,
                pid=pid,
                pnp_device_id=pnp_id,
            )
            identifiers = {**base_ids, **self._string_dict(helper_result.get("identifiers", {}))}
            capabilities = {
                "read_only": True,
                "preloader_detected": pid == self.PRELOADER_PID,
                "kernel_meta_detected": pid == self.META_PID,
                "helper_configured": helper_command is not None,
                **self._dict(helper_result.get("capabilities", {})),
            }
            partitions = self._normalize_partitions(helper_result.get("partitions", []))
            warnings = []
            if helper_warning:
                warnings.append(helper_warning)
            warnings.extend(str(item) for item in helper_result.get("warnings", []) if item)

            observation_mode = str(helper_result.get("mode", mode)).lower()
            connected = bool(helper_result.get("connected", True))
            commands = [pnp]
            if helper_command is not None:
                commands.append(helper_command)
            observations.append(
                TransportObservation(
                    transport=TransportKind.MTK_META,
                    available=True,
                    connected=connected,
                    mode=observation_mode,
                    identifiers=identifiers,
                    capabilities=capabilities,
                    partitions=partitions,
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
            observations.append(
                TransportObservation(
                    transport=TransportKind.MTK_META,
                    available=True,
                    connected=bool(item.get("connected", True)),
                    mode=str(item.get("mode", "meta")).lower(),
                    identifiers=self._string_dict(item.get("identifiers", {})),
                    capabilities={"read_only": True, **self._dict(item.get("capabilities", {}))},
                    partitions=self._normalize_partitions(item.get("partitions", [])),
                    warnings=[str(value) for value in item.get("warnings", [])],
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
            command = [token.strip('"') for token in shlex.split(raw, posix=os.name != "nt")]
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
        if not text.strip():
            return []
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return []
        if isinstance(payload, dict):
            return [payload]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []

    @staticmethod
    def _extract_json_object(text: str) -> dict[str, Any] | None:
        for line in reversed([line.strip() for line in text.splitlines() if line.strip()]):
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                return payload
        start = text.find("{")
        end = text.rfind("}")
        if start >= 0 and end > start:
            try:
                payload = json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                return None
            return payload if isinstance(payload, dict) else None
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
    def _extract_usb_serial(pnp_id: str) -> str:
        tail = pnp_id.rsplit("\\", 1)[-1]
        return "" if "&" in tail and tail.startswith("5&") else tail

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
                "slot", "a" if name.endswith("_a") else "b" if name.endswith("_b") else ""
            )
            for key in (
                "size_bytes",
                "start_sector",
                "sector_count",
                "logical_block_size",
            ):
                if key in item:
                    try:
                        item[key] = int(str(item[key]), 0)
                    except ValueError:
                        item[key] = 0
            result.append(item)
        return sorted(result, key=lambda item: str(item.get("name", "")))
