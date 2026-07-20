from __future__ import annotations

from typing import Any

from ..models import TransportKind
from .service_mode import ReadOnlyUsbServiceProbe


class SamsungDownloadProbe(ReadOnlyUsbServiceProbe):
    """Detect Samsung Odin/Download Mode without issuing PIT or flash commands."""

    name = "samsung_download"
    transport = TransportKind.SAMSUNG_DOWNLOAD
    env_prefix = "TTG_SAMSUNG_DOWNLOAD"
    default_mode = "download"
    device_regex = (
        r"(?i)(VID_04E8&PID_685D|Samsung.*(?:Download|Odin|Gadget Serial))"
    )
    linux_usb_regex = r"(?i)(04e8:685d|samsung.*(?:download|odin|gadget serial))"

    def _mode_for_endpoint(self, endpoint: dict[str, str]) -> str:
        text = " ".join(
            [
                endpoint.get("pnp_device_id", ""),
                endpoint.get("name", ""),
                endpoint.get("usb_path", ""),
            ]
        ).lower()
        exact_download_pid = endpoint.get("usb_vid", "").upper() == "04E8" and endpoint.get(
            "usb_pid", ""
        ).upper() == "685D"
        if exact_download_pid or any(
            token in text for token in ("download", "odin", "gadget serial")
        ):
            return "download"
        return "samsung-usb-candidate"

    def _endpoint_capabilities(
        self, endpoint: dict[str, str], mode: str
    ) -> dict[str, Any]:
        return {
            "usb_transport_detected": True,
            "download_mode_confirmed_by_usb": mode == "download",
            "pit_read": False,
            "odin_command_sent": False,
            "read_only": True,
        }

    def _endpoint_confirms_transport(
        self,
        endpoint: dict[str, str],
        mode: str,
        capabilities: dict[str, Any],
    ) -> bool:
        return bool(capabilities.get("download_mode_confirmed_by_usb"))
