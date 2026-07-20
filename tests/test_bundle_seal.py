import hashlib
import json

from ttg_device_xray.bundle_seal import seal_bundle
from ttg_device_xray.models import TransportKind, TransportObservation
from ttg_device_xray.pipeline import XRayPipeline, write_bundle


class StaticProbe:
    def __init__(self, observations):
        self.observations = observations

    def probe(self):
        return self.observations


def test_bundle_manifest_hashes_every_completed_evidence_file(tmp_path, monkeypatch):
    observation = TransportObservation(
        transport=TransportKind.ADB,
        available=True,
        connected=True,
        mode="device",
        identifiers={
            "serial": "SEAL-TEST",
            "brand": "TECNO",
            "device": "KM7",
            "soc": "mt6765",
            "android": "11",
            "fingerprint": "TECNO/KM7/11/test",
        },
        capabilities={
            "storage": {
                "type": "eMMC",
                "model": "TEST",
                "capacity_bytes": 64_000_000_000,
                "logical_block_size": 512,
            }
        },
        partitions=[{"name": "proinfo", "size_bytes": 3_145_728, "risk": "critical"}],
    )
    bundle = XRayPipeline([StaticProbe([observation])]).scan()
    target = write_bundle(bundle, tmp_path)
    (target / "profile_match.json").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("TTG_XRAY_SIGNING_KEY", "test-key")
    monkeypatch.setenv("TTG_XRAY_SIGNING_KEY_ID", "test-signer")

    result = seal_bundle(target, bundle)
    manifest = json.loads((target / "bundle_manifest.json").read_text(encoding="utf-8"))
    signature = json.loads((target / "bundle_manifest.sig").read_text(encoding="utf-8"))

    assert result["status"] == "SIGNED"
    assert signature["status"] == "SIGNED"
    assert manifest["device_candidate_id"] == bundle.selected_candidate_id
    assert manifest["signer_key_id"] == "test-signer"

    for item in manifest["files"]:
        path = target / item["path"]
        assert path.exists()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"]
