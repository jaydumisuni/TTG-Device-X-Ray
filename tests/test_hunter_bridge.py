import urllib.error

from ttg_device_xray.enhanced_pipeline import EnhancedXRayPipeline
from ttg_device_xray.hunter_bridge import HunterBridge
from ttg_device_xray.models import TransportKind, TransportObservation
from ttg_device_xray.profile_loader import ProfileLoader


class StaticProbe:
    def __init__(self, observations):
        self.observations = observations

    def probe(self):
        return self.observations


def _bundle():
    observation = TransportObservation(
        transport=TransportKind.ADB,
        available=True,
        connected=True,
        mode="device",
        identifiers={
            "serial": "SERIAL-RAW",
            "brand": "TECNO",
            "device": "KM7",
            "soc": "mt6765",
            "android": "11",
            "fingerprint": "TECNO/KM7/test",
        },
    )
    bundle = EnhancedXRayPipeline([StaticProbe([observation])]).scan()
    bundle.identity.imei = "351234567890123"
    bundle.profile_match = ProfileLoader().match_bundle(bundle)
    return bundle


def test_hunter_payload_hashes_sensitive_identifiers(monkeypatch):
    monkeypatch.delenv("TTG_HUNTER_INCLUDE_SENSITIVE", raising=False)
    payload = HunterBridge()._payload(_bundle())
    assert "serial" not in payload["identity"]
    assert "imei" not in payload["identity"]
    assert payload["identity"]["serial_sha256"]
    assert payload["identity"]["imei_suffix"] == "0123"
    assert payload["write_allowed"] is False


def test_hunter_failure_spools_bundle(tmp_path, monkeypatch):
    bundle = _bundle()
    bundle_dir = tmp_path / bundle.scan_id
    bundle_dir.mkdir()
    (bundle_dir / "audit.jsonl").write_text("", encoding="utf-8")

    def fail(*args, **kwargs):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr("urllib.request.urlopen", fail)
    monkeypatch.setenv("TTG_HUNTER_XRAY_URL", "http://127.0.0.1:9/ingest")
    delivery = HunterBridge().deliver(bundle, bundle_dir)
    assert delivery.attempted is True
    assert delivery.delivered is False
    assert delivery.spool_file
    assert (bundle_dir / "hunter_delivery.json").exists()
