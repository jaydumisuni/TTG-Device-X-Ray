from ttg_device_xray.models import TransportKind, TransportObservation
from ttg_device_xray.pipeline import XRayPipeline


class StaticProbe:
    def __init__(self, observations):
        self.observations = observations

    def probe(self):
        return self.observations


def test_multiple_android_devices_are_separate_candidates_and_block_selection():
    first = TransportObservation(
        transport=TransportKind.ADB,
        available=True,
        connected=True,
        mode="device",
        identifiers={
            "serial": "PHONE-A",
            "brand": "TECNO",
            "device": "KM7",
            "soc": "mt6765",
        },
    )
    second = TransportObservation(
        transport=TransportKind.ADB,
        available=True,
        connected=True,
        mode="device",
        identifiers={
            "serial": "PHONE-B",
            "brand": "Infinix",
            "device": "X6816",
            "soc": "mt6765",
        },
    )

    bundle = XRayPipeline([StaticProbe([first, second])]).scan()

    assert len(bundle.candidates) == 2
    assert bundle.selected_candidate_id is None
    assert bundle.certification.verdict.value == "UNSAFE"
    assert "MULTIPLE_DEVICE_CANDIDATES" in [item.code for item in bundle.challenges]
    assert bundle.identity.platform == "unknown"


def test_apple_modes_link_by_hardware_without_collapsing_identifier_types():
    normal = TransportObservation(
        transport=TransportKind.APPLE_NORMAL,
        available=True,
        connected=True,
        mode="normal",
        identifiers={
            "udid": "UDID-ONE",
            "SerialNumber": "APPLE-SERIAL",
            "ProductType": "iPhone10,6",
            "HardwareModel": "d221ap",
            "ChipID": "0x8015",
            "BoardId": "0x0E",
        },
    )
    recovery = TransportObservation(
        transport=TransportKind.APPLE_RECOVERY,
        available=True,
        connected=True,
        mode="recovery",
        identifiers={
            "ECID": "123456789",
            "PRODUCT": "iPhone10,6",
            "MODEL": "d221ap",
            "CPID": "0x8015",
            "BDID": "0x0e",
        },
    )

    bundle = XRayPipeline([StaticProbe([normal, recovery])]).scan()

    assert len(bundle.candidates) == 1
    assert bundle.identity.udid == "UDID-ONE"
    assert bundle.identity.apple_serial == "APPLE-SERIAL"
    assert bundle.identity.ecid == "123456789"
    assert bundle.identity.serial == ""
    assert any(
        item["method"] == "apple_hardware_correlation"
        for item in bundle.candidates[0].link_evidence
    )
