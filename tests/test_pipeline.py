from ttg_device_xray.models import TransportKind, TransportObservation
from ttg_device_xray.pipeline import XRayPipeline


class StaticProbe:
    def __init__(self, observations):
        self.observations = observations

    def probe(self):
        return self.observations


def test_certifies_coherent_android_evidence():
    adb = TransportObservation(
        transport=TransportKind.ADB,
        available=True,
        connected=True,
        mode="device",
        identifiers={
            "serial": "ABC123",
            "brand": "TECNO",
            "manufacturer": "TECNO MOBILE LIMITED",
            "model": "SPARK",
            "device": "KM7",
            "board": "k65v1_64_bsp",
            "soc": "mt6765",
            "android": "11",
            "build": "KM7-H6128",
        },
        partitions=[{"name": "proinfo", "path": "/dev/block/by-name/proinfo"}],
    )
    fastboot = TransportObservation(
        transport=TransportKind.FASTBOOT,
        available=True,
        connected=True,
        mode="fastboot",
        identifiers={"serial": "ABC123", "product": "KM7"},
    )
    bundle = XRayPipeline([StaticProbe([adb, fastboot])]).scan()
    assert bundle.certification.verdict.value == "CERTIFIED"
    assert bundle.identity.internal_model == "KM7"
    assert bundle.certification.write_allowed is False


def test_blocks_when_no_device_is_connected():
    observation = TransportObservation(
        transport=TransportKind.ADB,
        available=True,
        connected=False,
        mode="no-device",
    )
    bundle = XRayPipeline([StaticProbe([observation])]).scan()
    assert bundle.certification.verdict.value == "UNSAFE"
    assert bundle.certification.blockers


def test_identifies_apple_recovery_evidence():
    observation = TransportObservation(
        transport=TransportKind.APPLE_RECOVERY,
        available=True,
        connected=True,
        mode="recovery",
        identifiers={
            "MODEL": "d221ap",
            "CPID": "0x8015",
            "BDID": "0x0E",
            "ECID": "123456789",
        },
    )
    bundle = XRayPipeline([StaticProbe([observation])]).scan()
    assert bundle.identity.platform == "apple"
    assert bundle.identity.internal_model == "d221ap"
    assert bundle.certification.verdict.value in {"INVESTIGATE", "CERTIFIED"}
