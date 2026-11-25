"""Vendor-neutral, read-only USB inventory for X-Ray.

This probe enumerates OS-observed USB endpoints independent of brands,
VID/PID allowlists and model profiles. A detected USB endpoint is NOT proof
of diagnostic protocol, firmware, storage, FDL/EDL/download mode or writing.
Unselected host peripherals remain inventory observations, not candidates.

An operator may select any present VID:PID explicitly for identity research.
The selector only affects presence candidacy and does not open a device.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any

from ..command import Runner
from ..models import CommandEvidence, TransportKind, TransportObservation


_HEX_SELECTOR = re.compile(r"(?i)^[0-9a-f]{4}:[0-9a-f]{4}$")
_TOKEN_SELECTOR = re.compile(r"(?i)^[0-9a-f]{16}$")
_USB_ID = re.compile(r"(?i)\bVID_([0-9a-f]{4})[&+]PID_([0-9a-f]{4})\b")
_LSUSB = re.compile(
    r"(?i)^Bus\s+(\d+)\s+Device\s+(\d+):\s+ID\s+"
    r"([0-9a-f]{4}):([0-9a-f]{4})\s*(.*)$"
)
_PORT = re.compile(r"(?i)\((COM\d+)\)")
# Interfaces whose OS-assigned class makes them relevant to device servicing
# discovery. This is not a protocol capability or manufacturer assumption.
_AUTO_CLASSES = frozenset({
    "ports", "modem", "wpd", "androidusbdevice", "usbdevice", "mobiledevices",
})
# Generic host peripherals are kept in the inventory but not added to the
# servicing candidate set solely because they are attached.
MAX_INVENTORY = 256


def _plain(value: Any, limit: int = 160) -> str:
    return str(value or "").strip()[:limit]


def _os_interface_class(value: str) -> str:
    kind = value.strip().lower()
    if kind == "ports":
        return "serial"
    if kind == "modem":
        return "modem"
    if kind in {"wpd", "mobiledevices"}:
        return "portable"
    if kind in {"diskdrive", "scsiadapter"}:
        return "mass_storage"
    if kind in {"hidclass", "keyboard", "mouse"}:
        return "hid"
    if kind in {"net", "network"}:
        return "network"
    if kind in {"camera", "image"}:
        return "camera"
    if kind == "bluetooth":
        return "bluetooth"
    return "unclassified"


class UniversalUsbProbe:
    """Inventory all physically present USB VID:PID endpoints using OS tools."""

    name = "universal_usb"
    transport = TransportKind.USB_INVENTORY

    def __init__(
        self, runner: Runner, *, target_usb: tuple[str, ...] = (),
        target_device: tuple[str, ...] = (),
    ) -> None:
        self.runner = runner
        normalized = tuple(token.upper() for token in target_usb)
        if any(_HEX_SELECTOR.fullmatch(token) is None for token in normalized):
            raise ValueError("USB selector must be an exact hexadecimal VID:PID")
        tokens = tuple(token.lower() for token in target_device)
        if any(_TOKEN_SELECTOR.fullmatch(token) is None for token in tokens):
            raise ValueError("Device selector must be a 16-digit inventory ID")
        self.target_usb = frozenset(normalized)
        self.target_device = frozenset(tokens)
        self.inventory_truncated = False

    def _windows(self) -> tuple[list[dict[str, Any]], CommandEvidence]:
        shell = "powershell" if self.runner.exists("powershell") else "pwsh"
        command = [
            shell, "-NoProfile", "-NonInteractive", "-Command",
            (
                "if (Get-Command Get-PnpDevice -ErrorAction SilentlyContinue) { "
                "$items = Get-PnpDevice -PresentOnly | Where-Object { "
                "$_.InstanceId -match '^(USB|FTDIBUS)\\\\VID_[0-9A-Fa-f]{4}'"
                " } | Select-Object "
                "@{N='InstanceId';E={$_.InstanceId}},"
                "@{N='Name';E={$_.FriendlyName}},"
                "@{N='Class';E={$_.Class}},"
                "@{N='Status';E={$_.Status}},"
                "@{N='Present';E={$true}}; "
                "} else { "
                "$items = Get-CimInstance Win32_PnPEntity | Where-Object { "
                "$_.Present -eq $true -and "
                "$_.PNPDeviceID -match '^(USB|FTDIBUS)\\\\VID_[0-9A-Fa-f]{4}'"
                " } | Select-Object "
                "@{N='InstanceId';E={$_.PNPDeviceID}},"
                "@{N='Name';E={$_.Name}},"
                "@{N='Class';E={$_.PNPClass}},"
                "@{N='Status';E={$_.Status}},"
                "@{N='Present';E={$_.Present}}; "
                "}; "
                "if ($items) { $items | ConvertTo-Json -Compress -Depth 3 }"
            ),
        ]
        evidence = self.runner.run(command, timeout=40)
        if evidence.return_code != 0 or evidence.timed_out:
            return [], evidence
        if len(evidence.stdout) > 1024 * 1024:
            return [], CommandEvidence(
                command=command, return_code=1,
                stderr="Universal USB inventory exceeds one MiB output budget",
                duration_ms=evidence.duration_ms,
            )
        try:
            items = json.loads(evidence.stdout) if evidence.stdout.strip() else []
        except json.JSONDecodeError:
            return [], CommandEvidence(
                command=command, return_code=1,
                stderr="Universal PnP inventory returned malformed JSON",
                duration_ms=evidence.duration_ms,
            )
        if isinstance(items, dict):
            items = [items]
        if not isinstance(items, list):
            return [], evidence
        self.inventory_truncated = len(items) > MAX_INVENTORY
        devices: list[dict[str, Any]] = []
        for item in items[:MAX_INVENTORY]:
            if not isinstance(item, dict):
                continue
            instance = _plain(item.get("InstanceId") or item.get("PNPDeviceID"), 512)
            found = _USB_ID.search(instance)
            if found is None or item.get("Present") is False:
                continue
            status = _plain(item.get("Status"))
            cls = _plain(item.get("Class"))
            devices.append({
                "usb_vid": found.group(1).upper(),
                "usb_pid": found.group(2).upper(),
                "pnp_device_id": instance,
                "name": _plain(item.get("Name")),
                "usb_class": cls,
                "status": status,
                "port": (
                    _PORT.search(_plain(item.get("Name"))).group(1).upper()
                    if _PORT.search(_plain(item.get("Name"))) else ""
                ),
                "present": True,
            })
        return devices, evidence

    def _linux(self) -> tuple[list[dict[str, Any]], CommandEvidence]:
        evidence = self.runner.run(["lsusb"], timeout=25)
        if evidence.return_code != 0 or evidence.timed_out:
            return [], evidence
        lines = evidence.stdout.splitlines()
        self.inventory_truncated = len(lines) > MAX_INVENTORY
        devices = []
        for line in lines[:MAX_INVENTORY]:
            match = _LSUSB.match(line.strip())
            if match is None:
                continue
            bus, dev, vid, pid, name = match.groups()
            devices.append({
                "usb_vid": vid.upper(),
                "usb_pid": pid.upper(),
                "pnp_device_id": "",
                "usb_path": f"bus-{bus}-device-{dev}",
                "name": _plain(name),
                "usb_class": "unknown",
                "status": "present",
                "port": "",
                "present": True,
            })
        return devices, evidence

    def probe(self) -> list[TransportObservation]:
        self.inventory_truncated = False
        if self.runner.exists("powershell") or self.runner.exists("pwsh"):
            records, evidence = self._windows()
        elif self.runner.exists("lsusb"):
            records, evidence = self._linux()
        else:
            return [
                TransportObservation(
                    transport=self.transport, available=False, connected=False,
                    mode="inventory-unavailable",
                    warnings=["No supported OS USB inventory tool found"],
                )
            ]
        if evidence.return_code != 0 or evidence.timed_out:
            return [
                TransportObservation(
                    transport=self.transport, available=False, connected=False,
                    mode="inventory-failed", commands=[evidence],
                    warnings=["Read-only OS USB inventory failed"],
                )
            ]
        if not records:
            return [
                TransportObservation(
                    transport=self.transport, available=True, connected=False,
                    mode="no-usb-device", commands=[evidence],
                )
            ]

        observations: list[TransportObservation] = []
        for row in records:
            cls = _plain(row.get("usb_class")).lower()
            selector = row["usb_vid"] + ":" + row["usb_pid"]
            source_identity = (
                str(row.get("pnp_device_id") or row.get("usb_path") or "")
            )
            if not source_identity:
                continue
            inventory_id = sha256(
                ("ttg-xray-usb-inventory-v1:" + source_identity.lower())
                .encode("utf-8")
            ).hexdigest()[:16]
            explicitly_selected = (
                selector in self.target_usb
                or inventory_id in self.target_device
            )
            auto_candidate = cls in _AUTO_CLASSES
            selected = explicitly_selected or auto_candidate
            interface = _os_interface_class(cls)
            capabilities: dict[str, Any] = {
                "read_only": True,
                "usb_present": bool(row["present"]),
                "transport_confirmed": False,
                "protocol_verified": False,
                "device_identity_verified": False,
                "download_mode_confirmed_by_usb": False,
                "serial_port_opened": False,
                "programmer_uploaded": False,
                "write_allowed": False,
                "os_interface_class": interface,
                "os_pnp_class": _plain(row.get("usb_class")),
                "inventory_id": inventory_id,
                "candidate_selected": selected,
                "selected_explicitly": explicitly_selected,
                "inventory_only": not selected,
                "inventory_truncated": self.inventory_truncated,
                "pnp_status": _plain(row.get("status")),
            }
            warnings = [
                "USB presence alone does not verify a servicing protocol"
            ]
            if not selected:
                warnings.append(
                    "Inventory only; use --target-usb VID:PID to investigate this endpoint"
                )
            if self.inventory_truncated:
                warnings.append(
                    "USB inventory exceeded bounded 256-entry scan budget"
                )
            observations.append(TransportObservation(
                transport=self.transport,
                available=True,
                connected=selected and bool(row["present"]),
                mode="usb-selected" if selected else "usb-inventory",
                identifiers={
                    "usb_vid": row["usb_vid"],
                    "usb_pid": row["usb_pid"],
                    "inventory_id": inventory_id,
                    "usb_name": _plain(row.get("name")),
                    "pnp_device_id": _plain(row.get("pnp_device_id"), 512),
                    "usb_path": _plain(row.get("usb_path"), 160),
                    "port": _plain(row.get("port"), 30),
                },
                capabilities=capabilities,
                commands=[evidence],
                warnings=warnings,
            ))
        return observations
