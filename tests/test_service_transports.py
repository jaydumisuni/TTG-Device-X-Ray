import json

from ttg_device_xray.enhanced_pipeline import EnhancedXRayPipeline
from ttg_device_xray.models import TransportKind
from ttg_device_xray.transports.qualcomm_edl import QualcommEdlProbe
from ttg_device_xray.transports.samsung_download import SamsungDownloadProbe
from ttg_device_xray.transports.service_mode import ReadOnlyUsbServiceProbe
from ttg_device_xray.transports.spd import SpdDownloadProbe


class NoopRunner:
    def exists(self, executable):
        return False

    def run(self, command, timeout=20):
        raise AssertionError("runner should not be called for fixture replay")


class StaticProbe:
    def __init__(self, observations):
        self.observations = observations

    def probe(self):
        return self.observations


def test_windows_pnp_parser_extracts_usb_and_com():
    payload = json.dumps(
        {
            "Name": "Qualcomm HS-USB QDLoader 9008 (COM19)",
            "PNPDeviceID": r"USB\VID_05C6&PID_9008\ABC",
            "Status": "OK",
        }
    )
    endpoint = ReadOnlyUsbServiceProbe._parse_windows_pnp(payload)[0]
    assert endpoint["usb_vid"] == "05C6"
    assert endpoint["usb_pid"] == "9008"
    assert endpoint["port"] == "COM19"


def test_qualcomm_fixture_is_read_only_and_correlates(tmp_path, monkeypatch):
    fixture = tmp_path / "edl.json"
    fixture.write_text(
        json.dumps(
            {
                "connected": True,
                "mode": "edl",
                "identifiers": {
                    "brand": "TECNO",
                    "model_code": "CK8n",
                    "chipset": "SM6225",
                    "serial": "EDL-1",
                    "storage_type": "UFS",
                },
                "capabilities": {
                    "sahara_query": True,
                    "storage": {
                        "type": "UFS",
                        "model": "TEST-UFS",
                        "capacity_bytes": 128000000000,
                        "logical_block_size": 4096,
                    },
                },
                "partitions": [{"name": "xbl", "size_bytes": "0x100000"}],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("TTG_QUALCOMM_EDL_EVIDENCE_FILE", str(fixture))
    observation = QualcommEdlProbe(NoopRunner()).probe()[0]
    assert observation.transport == TransportKind.QUALCOMM_EDL
    assert observation.capabilities["read_only"] is True
    assert observation.partitions[0]["risk"] == "critical"

    bundle = EnhancedXRayPipeline([StaticProbe([observation])]).scan()
    assert bundle.identity.platform == "android"
    assert bundle.identity.internal_model == "CK8n"
    assert bundle.identity.chipset == "SM6225"
    assert bundle.storage.storage_type == "UFS"
    assert bundle.certification.write_allowed is False


def test_spd_and_samsung_mode_classification():
    spd = SpdDownloadProbe(NoopRunner())
    samsung = SamsungDownloadProbe(NoopRunner())
    assert (
        spd._mode_for_endpoint({"name": "Spreadtrum SCI USB2Serial (COM7)"})
        == "download"
    )
    assert (
        samsung._mode_for_endpoint({"name": "Samsung Mobile USB Download Mode"})
        == "download"
    )
    assert (
        samsung._mode_for_endpoint({"name": "Samsung Mobile USB Composite Device"})
        == "samsung-usb-candidate"
    )
