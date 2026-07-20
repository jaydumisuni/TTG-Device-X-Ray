import json

from ttg_device_xray.cli import _diagnostic_observation
from ttg_device_xray.models import CommandEvidence, TransportKind, TransportObservation
from ttg_device_xray.transports.qualcomm_edl import QualcommEdlProbe
from ttg_device_xray.transports.samsung_download import SamsungDownloadProbe
from ttg_device_xray.transports.service_mode import ReadOnlyUsbServiceProbe
from ttg_device_xray.transports.spd import SpdDownloadProbe


class FakeRunner:
    def __init__(self, payload: object) -> None:
        self.payload = payload

    def exists(self, command: str) -> bool:
        return command == "powershell"

    def run(self, command: list[str], timeout: int = 20) -> CommandEvidence:
        return CommandEvidence(
            command=command,
            return_code=0,
            stdout=json.dumps(self.payload),
            duration_ms=1,
        )


def test_windows_pnp_parser_drops_non_present_and_code_45_devices() -> None:
    payload = [
        {
            "Name": "Qualcomm HS-USB QDLoader 9008",
            "PNPDeviceID": r"USB\VID_05C6&PID_9008\LIVE",
            "Status": "OK",
            "Present": True,
            "ConfigManagerErrorCode": 0,
        },
        {
            "Name": "Old Qualcomm HS-USB QDLoader 9008",
            "PNPDeviceID": r"USB\VID_05C6&PID_9008\GHOST",
            "Status": "Unknown",
            "Present": False,
            "ConfigManagerErrorCode": 45,
        },
    ]

    parsed = ReadOnlyUsbServiceProbe._parse_windows_pnp(json.dumps(payload))

    assert len(parsed) == 1
    assert parsed[0]["usb_vid"] == "05C6"
    assert parsed[0]["usb_pid"] == "9008"
    assert parsed[0]["present"] == "true"


def test_normal_unisoc_vendor_interface_is_not_a_connected_download_candidate() -> None:
    probe = SpdDownloadProbe(
        FakeRunner(
            {
                "Name": "Unisoc Android Composite ADB Interface",
                "PNPDeviceID": r"USB\VID_1782&PID_4EE7\NORMAL",
                "Status": "OK",
                "Present": True,
            }
        )
    )

    observations = probe.probe()

    assert len(observations) == 1
    assert observations[0].mode == "spd-usb-candidate"
    assert observations[0].connected is False
    assert observations[0].capabilities["transport_confirmed"] is False


def test_normal_samsung_modem_interface_is_not_download_mode() -> None:
    probe = SamsungDownloadProbe(
        FakeRunner(
            {
                "Name": "Samsung Mobile USB Modem",
                "PNPDeviceID": r"USB\VID_04E8&PID_6860\NORMAL",
                "Status": "OK",
                "Present": True,
            }
        )
    )

    observations = probe.probe()

    assert len(observations) == 1
    assert observations[0].mode == "samsung-usb-candidate"
    assert observations[0].connected is False
    assert observations[0].capabilities["transport_confirmed"] is False


def test_present_qualcomm_9008_is_a_connected_read_only_candidate() -> None:
    probe = QualcommEdlProbe(
        FakeRunner(
            {
                "Name": "Qualcomm HS-USB QDLoader 9008",
                "PNPDeviceID": r"USB\VID_05C6&PID_9008\LIVE",
                "Status": "OK",
                "Present": True,
            }
        )
    )

    observations = probe.probe()

    assert len(observations) == 1
    assert observations[0].mode == "edl"
    assert observations[0].connected is True
    assert observations[0].capabilities["pnp_present"] is True
    assert observations[0].capabilities["transport_confirmed"] is True
    assert observations[0].capabilities["programmer_uploaded"] is False


def test_diagnostic_observation_excludes_device_identifiers_and_paths() -> None:
    observation = TransportObservation(
        transport=TransportKind.ADB,
        available=True,
        connected=True,
        mode="device",
        identifiers={
            "serial": "SECRET-SERIAL",
            "pnp_device_id": r"USB\VID_1234&PID_5678\SECRET",
            "usb_name": "Customer Phone",
            "usb_vid": "1234",
            "usb_pid": "5678",
        },
        capabilities={
            "pnp_present": True,
            "pnp_status": "OK",
            "transport_confirmed": True,
        },
        warnings=["example"],
    )

    diagnostic = _diagnostic_observation(observation)

    assert diagnostic["transport"] == "adb"
    assert diagnostic["usb_vid"] == "1234"
    assert diagnostic["usb_pid"] == "5678"
    assert diagnostic["warning_count"] == 1
    assert "serial" not in diagnostic
    assert "pnp_device_id" not in diagnostic
    assert "usb_name" not in diagnostic
