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
            "product": "KM7-H6128",
            "board": "k65v1_64_bsp",
            "soc": "mt6765",
            "android": "11",
            "build": "KM7-H6128",
            "fingerprint": "TECNO/KM7/11:user/release-keys",
            "storage_type": "eMMC",
            "storage_capacity_bytes": "64000000000",
        },
        capabilities={
            "storage": {
                "type": "eMMC",
                "model": "HYNIX",
                "capacity_bytes": 64000000000,
                "logical_block_size": 512,
            },
            "ab_slots": False,
        },
        partitions=[
            {
                "name": "proinfo",
                "path": "/dev/block/by-name/proinfo",
                "size_bytes": 3145728,
                "risk": "critical",
            },
            {
                "name": "super",
                "path": "/dev/block/by-name/super",
                "size_bytes": 4000000000,
                "risk": "critical",
            },
        ],
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
    assert bundle.storage.storage_type == "eMMC"
    assert bundle.storage.has_super is True
    assert bundle.firmware.completeness >= 0.8
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
            "PRODUCT": "iPhone10,6",
            "MODEL": "d221ap",
            "CPID": "0x8015",
            "BDID": "0x0E",
            "ECID": "123456789",
        },
    )
    bundle = XRayPipeline([StaticProbe([observation])]).scan()
    assert bundle.identity.platform == "apple"
    assert bundle.identity.product_type == "iPhone10,6"
    assert bundle.identity.internal_model == "d221ap"
    assert bundle.certification.verdict.value in {"INVESTIGATE", "CERTIFIED"}


def test_flags_unlocked_bootloader_without_allowing_write():
    observation = TransportObservation(
        transport=TransportKind.ADB,
        available=True,
        connected=True,
        mode="device",
        identifiers={
            "serial": "A",
            "brand": "Example",
            "device": "board1",
            "soc": "sm7250",
            "android": "13",
            "fingerprint": "example/board1/13:userdebug/test-keys",
            "storage_type": "UFS",
        },
        capabilities={"bootloader_locked": False},
        partitions=[{"name": "boot_a", "size_bytes": 1, "risk": "critical"}],
    )
    bundle = XRayPipeline([StaticProbe([observation])]).scan()
    assert "BOOTLOADER_UNLOCKED" in [item.code for item in bundle.challenges]
    assert bundle.certification.write_allowed is False
