"""Detect the observed SPRD U2S diagnostic port, never claim SPD download.

No serial port is opened, and no firmware/loader/AT/DIAG command is sent.
"""
from __future__ import annotations
from typing import Any
from ..models import TransportKind
from .service_mode import ReadOnlyUsbServiceProbe


class SpdDiagnosticProbe(ReadOnlyUsbServiceProbe):
    name = "spd_diagnostic"
    transport = TransportKind.SPD_DIAGNOSTIC
    env_prefix = "TTG_SPD_DIAGNOSTIC"
    default_mode = "diagnostic"
    device_regex = r"(?i)(USB\\VID_1782&PID_4D00\b.*\bSPRD\s+U2S\s+Diag\b)"
    linux_usb_regex = r"(?i)\bID\s+1782:4D00\b"

    def _run_helper(self, endpoint):
        """Do not execute or trust unqualified DIAG helper commands.

        This transport proves only read-only Windows PnP/lsusb presence.
        """
        return {}, None, ""

    @staticmethod
    def _verified_diag_endpoint(endpoint: dict[str, str]) -> bool:
        return (
            endpoint.get("usb_vid", "").upper() == "1782"
            and endpoint.get("usb_pid", "").upper() == "4D00"
            and (
                "sprd u2s diag" in endpoint.get("name", "").lower()
                or (
                    "id 1782:4d00" in endpoint.get("usb_path", "").lower()
                    and endpoint.get("present", "true").lower() == "true"
                )
            )
        )

    def _mode_for_endpoint(self, endpoint: dict[str, str]) -> str:
        return "diagnostic" if self._verified_diag_endpoint(endpoint) else "unqualified-usb"

    def _endpoint_capabilities(
        self, endpoint: dict[str, str], mode: str
    ) -> dict[str, Any]:
        return {
            "usb_transport_detected": True,
            "diagnostic_port_confirmed_by_usb": mode == "diagnostic",
            "download_mode_confirmed_by_usb": False,
            "fdl_sent": False,
            "serial_port_opened": False,
            "read_only": True,
        }

    def _endpoint_confirms_transport(
        self, endpoint: dict[str, str], mode: str, capabilities: dict[str, Any]
    ) -> bool:
        return (
            mode == "diagnostic"
            and self._verified_diag_endpoint(endpoint)
            and capabilities.get("diagnostic_port_confirmed_by_usb") is True
            and capabilities.get("download_mode_confirmed_by_usb") is False
        )
