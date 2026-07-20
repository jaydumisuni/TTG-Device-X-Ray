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
        r"(?i)(VID_1782&PID_[0-9A-F]{4}|Spreadtrum|Unisoc|SCI USB2Serial|"
        r"SPRD.*Download|USB Download Gadget)"
    )
    linux_usb_regex = r"(?i)(1782:[0-9a-f]{4}|spreadtrum|unisoc|sprd)"

    def _mode_for_endpoint(self, endpoint: dict[str, str]) -> str:
        text = " ".join(
            [
                endpoint.get("pnp_device_id", ""),
                endpoint.get("name", ""),
                endpoint.get("usb_path", ""),
            ]
        ).lower()
        if any(token in text for token in ("download", "sci usb2serial", "spreadtrum", "unisoc")):
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
