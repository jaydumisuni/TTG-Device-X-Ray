from ttg_device_xray.models import (
    DeviceIdentity,
    StorageSummary,
    TransportKind,
    TransportObservation,
)
from ttg_device_xray.profile_loader import ProfileLoader


def _adb_observation(*partition_names: str) -> TransportObservation:
    return TransportObservation(
        transport=TransportKind.ADB,
        available=True,
        connected=True,
        mode="device",
        partitions=[{"name": name} for name in partition_names],
    )


def test_unrelated_profile_is_not_exposed_as_no_match_source() -> None:
    match = ProfileLoader()._match(
        requested="android:oneplus:waffle:pineapple",
        identity=DeviceIdentity(
            platform="android",
            brand="OnePlus",
            manufacturer="OnePlus",
            internal_model="waffle",
            board="waffle",
            chipset="pineapple",
        ),
        storage=StorageSummary(),
        observations=[_adb_observation("boot_a", "boot_b", "super")],
    )

    assert match.status == "NO_MATCH"
    assert match.profile_id is None
    assert match.source == ""
    assert match.stage == "UNAVAILABLE"
    assert match.confidence == 0.0
    assert match.adapter_contracts == {}
    assert match.write_allowed is False


def test_redmi_sky_profile_remains_candidate_until_approved() -> None:
    match = ProfileLoader()._match(
        requested="android:redmi:sky:parrot",
        identity=DeviceIdentity(
            platform="android",
            brand="Redmi",
            manufacturer="Xiaomi",
            marketing_model="23076RA4BC",
            internal_model="sky",
            board="sky",
            chipset="parrot",
            firmware_version="15",
            build="AQ3A.240912.001",
        ),
        storage=StorageSummary(),
        observations=[
            _adb_observation(
                "boot_a",
                "boot_b",
                "persist",
                "super",
                "vbmeta_a",
                "vbmeta_b",
            )
        ],
    )

    assert match.status == "CANDIDATE_PROFILE"
    assert match.profile_id == "android:redmi:sky:parrot"
    assert match.stage == "CANDIDATE"
    assert match.confidence >= 0.8
    assert match.source.endswith("profiles/xiaomi/redmi_sky_parrot.json")
    assert "profile_registry_candidate" in match.reasons
    assert match.adapter_contracts == {}
    assert match.write_allowed is False
