from ttg_device_xray.models import (
    DeviceIdentity,
    StorageSummary,
    TransportKind,
    TransportObservation,
)
from ttg_device_xray.profile_loader import ProfileLoader


def _dfu_observation() -> TransportObservation:
    return TransportObservation(
        transport=TransportKind.APPLE_DFU,
        available=True,
        connected=True,
        mode="dfu",
        identifiers={
            "PRODUCT": "iPhone10,6",
            "MODEL": "d221ap",
            "CPID": "0x8015",
            "BDID": "0x0e",
        },
        capabilities={"queryable": True},
    )


def test_a11_gaster_reference_is_read_only_candidate() -> None:
    match = ProfileLoader()._match(
        requested="apple:a8-a11:gaster-reference",
        identity=DeviceIdentity(
            platform="apple",
            brand="Apple",
            manufacturer="Apple",
            product_type="iPhone10,6",
            internal_model="d221ap",
            board="d221ap",
            chipset="0x8015",
            active_mode="dfu",
        ),
        storage=StorageSummary(),
        observations=[_dfu_observation()],
    )

    assert match.status == "CANDIDATE_PROFILE"
    assert match.profile_id == "apple:a8-a11:gaster-reference"
    assert match.stage == "CANDIDATE"
    assert match.confidence >= 0.8
    assert match.source.endswith("profiles/apple/a8_a11_gaster_reference.json")
    assert match.adapter_contracts == {}
    assert match.write_allowed is False

    route = match.capabilities["apple_route_reference"]
    assert route["classification"] == "documented_known_good_reference"
    assert route["generation"] == "a8_a11"
    assert route["pwn_provider"] == "gaster"
    assert route["pwn_source"]["commit"] == "7fffffff38a1bed1cdc1c5bae0df70f14395129b"
    assert route["asset_policy"] == {
        "local_only": True,
        "sha256_required": True,
        "device_exact": True,
        "redistribution_allowed": False,
    }
    assert route["xray_scope"] == "READ_ONLY_ROUTE_CERTIFICATION"


def test_unrelated_a12_board_does_not_match_gaster_reference() -> None:
    match = ProfileLoader()._match(
        requested="",
        identity=DeviceIdentity(
            platform="apple",
            brand="Apple",
            manufacturer="Apple",
            product_type="iPhone11,6",
            internal_model="d331pap",
            board="d331pap",
            chipset="0x8020",
            active_mode="dfu",
        ),
        storage=StorageSummary(),
        observations=[_dfu_observation()],
    )

    assert match.status == "NO_MATCH"
    assert match.profile_id is None
    assert match.write_allowed is False
