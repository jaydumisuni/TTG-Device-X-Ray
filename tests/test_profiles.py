from ttg_device_xray.enhanced_pipeline import EnhancedXRayPipeline
from ttg_device_xray.models import TransportKind, TransportObservation
from ttg_device_xray.profile_loader import ProfileLoader


class StaticProbe:
    def __init__(self, observations):
        self.observations = observations

    def probe(self):
        return self.observations


def test_packaged_km7_profile_matches_certified_evidence():
    observation = TransportObservation(
        transport=TransportKind.ADB,
        available=True,
        connected=True,
        mode="device",
        identifiers={
            "serial": "KM7-TEST",
            "brand": "TECNO",
            "manufacturer": "TECNO MOBILE LIMITED",
            "model": "TECNO SPARK",
            "device": "KM7",
            "board": "k65v1_64_bsp",
            "soc": "mt6765",
            "android": "11",
            "build": "KM7-H6128",
            "fingerprint": "TECNO/KM7/11/test",
            "storage_type": "eMMC",
        },
        capabilities={
            "storage": {
                "type": "eMMC",
                "model": "TEST",
                "capacity_bytes": 64_000_000_000,
                "logical_block_size": 512,
            }
        },
        partitions=[
            {"name": "proinfo", "size_bytes": 3_145_728, "risk": "critical"},
            {"name": "nvram", "size_bytes": 5_242_880, "risk": "critical"},
            {"name": "nvdata", "size_bytes": 33_554_432, "risk": "critical"},
        ],
    )
    bundle = EnhancedXRayPipeline([StaticProbe([observation])]).scan()
    loader = ProfileLoader()
    loader.apply_bundle_matches(bundle)

    assert bundle.certification.proposed_profile_id == "android:tecno:km7:mt6765"
    assert bundle.profile_match.status == "MATCHED"
    assert bundle.profile_match.profile_id == "android:tecno:km7:mt6765"
    assert bundle.profile_match.confidence == 1.0
    assert bundle.certification.dimensions.profile_match_confidence == 1.0
    assert bundle.profile_match.write_allowed is False
    assert bundle.profile_match.adapter_contracts["flash"] == "transsion.flash-plan.v1"


def test_profile_loader_fails_closed_when_no_profile_matches():
    observation = TransportObservation(
        transport=TransportKind.ADB,
        available=True,
        connected=True,
        mode="device",
        identifiers={
            "serial": "UNKNOWN",
            "brand": "UNKNOWN",
            "device": "NOPE",
            "soc": "mystery",
        },
    )
    bundle = EnhancedXRayPipeline([StaticProbe([observation])]).scan()
    loader = ProfileLoader()
    loader.apply_bundle_matches(bundle)

    assert bundle.profile_match.status in {"NO_MATCH", "NO_PROFILE"}
    assert bundle.profile_match.profile_id is None
    assert bundle.profile_match.write_allowed is False
