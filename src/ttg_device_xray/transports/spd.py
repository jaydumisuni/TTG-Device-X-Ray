from __future__ import annotations

from typing import Any

from ..models import TransportKind
from .service_mode import ReadOnlyUsbServiceProbe


class SpdDownloadProbe(ReadOnlyUsbServiceProbe):
    """Detect Spreadtrum/Unisoc download transport without sending loaders."""

    name = "spd_download"
    transport = TransportKind.SPD_DOWNLOAD
    env_prefix = "TTG_SPD"
    default_mode = "download"
    device_regex = (
        r"(?i)(SCI USB2Serial|SPRD.*(?:Download|Diagnostic)|USB Download Gadget|"
        r"Spreadtrum.*(?:Download|Diagnostic)|Unisoc.*(?:Download|Diagnostic))"
    )
    linux_usb_regex = (
        r"(?i)(sci usb2serial|sprd.*(?:download|diagnostic)|usb download gadget|"
        r"spreadtrum.*(?:download|diagnostic)|unisoc.*(?:download|diagnostic))"
    )

    def _mode_for_endpoint(self, endpoint: dict[str, str]) -> str:
        text = " ".join(
            [
                endpoint.get("pnp_device_id", ""),
                endpoint.get("name", ""),
                endpoint.get("usb_path", ""),
            ]
        ).lower()
        if any(
            token in text
            for token in (
                "download",
                "sci usb2serial",
                "usb download gadget",
                "diagnostic",
            )
        ):
            return "download"
        return "spd-usb-candidate"

    def _endpoint_capabilities(
        self, endpoint: dict[str, str], mode: str
    ) -> dict[str, Any]:
        return {
            "usb_transport_detected": True,
            "download_mode_confirmed_by_usb": mode == "download",
            "fdl_sent": False,
            "read_only": True,
        }

    def _endpoint_confirms_transport(
        self,
        endpoint: dict[str, str],
        mode: str,
        capabilities: dict[str, Any],
    ) -> bool:
        return bool(capabilities.get("download_mode_confirmed_by_usb"))
