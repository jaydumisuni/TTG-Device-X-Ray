import json

from ttg_device_xray.enhanced_pipeline import EnhancedXRayPipeline
from ttg_device_xray.models import TransportKind, TransportObservation
from ttg_device_xray.transports.mtk_meta import MtkMetaProbe


class NoopRunner:
    def exists(self, executable):
        return False

    def run(self, command, timeout=20):
        raise AssertionError("runner should not be called for fixture test")


class StaticProbe:
    def __init__(self, observations):
        self.observations = observations

    def probe(self):
        return self.observations


def test_mtk_helpers_parse_usb_and_partitions():
    assert MtkMetaProbe._extract_token(r"USB\VID_0E8D&PID_2007\ABC", "PID") == "2007"
    assert MtkMetaProbe._extract_com_port("MediaTek USB Port (COM17)") == "COM17"
    parts = MtkMetaProbe._normalize_partitions(
        [
            {
                "name": "proinfo",
                "start_sector": "0x100",
                "sector_count": "768",
                "logical_block_size": "4096",
                "size_bytes": "3145728",
            }
        ]
    )
    assert parts[0]["start_sector"] == 0x100
    assert parts[0]["risk"] == "critical"


def test_fixture_replay_and_meta_correlation(tmp_path, monkeypatch):
    evidence = {
        "connected": True,
        "mode": "meta",
        "identifiers": {
            "brand": "TECNO",
            "model_code": "CM6",
            "chipset": "MT6789",
            "android_version": "13",
            "build_id": "CM6-H8123",
            "security_patch": "2024-01-05",
            "serial": "META-CM6",
            "storage_type": "UFS",
            "storage_capacity_bytes": "128000000000",
        },
        "capabilities": {
            "target_info_read": True,
            "partition_map_read": True,
            "storage": {
                "type": "UFS",
                "model": "TEST-UFS",
                "capacity_bytes": 128000000000,
                "logical_block_size": 4096,
            },
        },
        "partitions": [
            {
                "name": "proinfo",
                "start_sector": 123,
                "sector_count": 768,
                "logical_block_size": 4096,
                "size_bytes": 3145728,
            }
        ],
    }
    path = tmp_path / "meta.json"
    path.write_text(json.dumps(evidence), encoding="utf-8")
    monkeypatch.setenv("TTG_MTK_META_EVIDENCE_FILE", str(path))

    observations = MtkMetaProbe(NoopRunner()).probe()
    assert observations[0].transport == TransportKind.MTK_META
    assert observations[0].partitions[0]["name"] == "proinfo"

    bundle = EnhancedXRayPipeline([StaticProbe(observations)]).scan()
    assert bundle.identity.platform == "android"
    assert bundle.identity.internal_model == "CM6"
    assert bundle.identity.chipset == "MT6789"
    assert bundle.storage.storage_type == "UFS"
    assert bundle.certification.write_allowed is False
