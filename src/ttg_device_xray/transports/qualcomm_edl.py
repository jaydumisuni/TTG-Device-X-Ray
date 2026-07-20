from __future__ import annotations

from typing import Any

from ..models import TransportKind
from .service_mode import ReadOnlyUsbServiceProbe


class QualcommEdlProbe(ReadOnlyUsbServiceProbe):
    """Detect Qualcomm emergency download transport without loading a programmer."""

    name = "qualcomm_edl"
    transport = TransportKind.QUALCOMM_EDL
    env_prefix = "TTG_QUALCOMM_EDL"
    default_mode = "edl"
    device_regex = (
        r"(?i)(VID_05C6&PID_9008|QDLoader\s*9008|QUSB_BULK|Qualcomm.*9008)"
    )
    linux_usb_regex = r"(?i)(05c6:9008|qualcomm.*9008|qusb_bulk)"

    def _mode_for_endpoint(self, endpoint: dict[str, str]) -> str:
        text = " ".join(
            [
                endpoint.get("usb_vid", ""),
                endpoint.get("usb_pid", ""),
                endpoint.get("name", ""),
            ]
        ).lower()
        if endpoint.get("usb_vid", "").upper() == "05C6" and endpoint.get(
            "usb_pid", ""
        ).upper() == "9008":
            return "edl"
        if "9008" in text or "qusb_bulk" in text:
            return "edl-candidate"
        return "qualcomm-emergency-candidate"

    def _endpoint_capabilities(
        self, endpoint: dict[str, str], mode: str
    ) -> dict[str, Any]:
        return {
            "usb_transport_detected": True,
            "edl_confirmed_by_usb": mode == "edl",
            "sahara_query_requires_helper": True,
            "programmer_uploaded": False,
            "read_only": True,
        }
