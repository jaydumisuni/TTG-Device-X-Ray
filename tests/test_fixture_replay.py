from __future__ import annotations

from pathlib import Path

import pytest

from ttg_device_xray.models import TransportKind
from ttg_device_xray.transports.mtk_meta import MtkMetaProbe
from ttg_device_xray.transports.qualcomm_edl import QualcommEdlProbe
from ttg_device_xray.transports.samsung_download import SamsungDownloadProbe
from ttg_device_xray.transports.spd import SpdDownloadProbe

FIXTURE_ROOT = Path(__file__).parent / "fixtures"


class NullRunner:
    def exists(self, executable: str) -> bool:
        return False

    def run(self, command: list[str], timeout: int = 20):
        raise AssertionError(f"fixture replay must not execute a command: {command}")


@pytest.mark.parametrize(
    ("environment", "probe_type", "fixture_name", "transport", "mode"),
    [
        (
            "TTG_MTK_META_EVIDENCE_FILE",
            MtkMetaProbe,
            "mtk_meta_km7.json",
            TransportKind.MTK_META,
            "meta",
        ),
        (
            "TTG_QUALCOMM_EDL_EVIDENCE_FILE",
            QualcommEdlProbe,
            "qualcomm_edl_sm7250.json",
            TransportKind.QUALCOMM_EDL,
            "edl",
        ),
        (
            "TTG_SPD_EVIDENCE_FILE",
            SpdDownloadProbe,
            "spd_ums9230.json",
            TransportKind.SPD_DOWNLOAD,
            "download",
        ),
        (
            "TTG_SAMSUNG_DOWNLOAD_EVIDENCE_FILE",
            SamsungDownloadProbe,
            "samsung_download_exynos.json",
            TransportKind.SAMSUNG_DOWNLOAD,
            "download",
        ),
    ],
)
def test_service_mode_fixture_replay_is_read_only(
    monkeypatch,
    environment,
    probe_type,
    fixture_name,
    transport,
    mode,
):
    fixture = FIXTURE_ROOT / fixture_name
    monkeypatch.setenv(environment, str(fixture))

    observations = probe_type(NullRunner()).probe()

    assert len(observations) == 1
    observation = observations[0]
    assert observation.transport == transport
    assert observation.connected is True
    assert observation.mode == mode
    assert observation.capabilities["read_only"] is True
    assert observation.partitions
    assert all(partition["risk"] in {"normal", "sensitive", "critical"} for partition in observation.partitions)
    assert all(int(partition.get("size_bytes", 0)) > 0 for partition in observation.partitions)


def test_mtk_fixture_contains_profile_grade_evidence(monkeypatch):
    monkeypatch.setenv(
        "TTG_MTK_META_EVIDENCE_FILE",
        str(FIXTURE_ROOT / "mtk_meta_km7.json"),
    )

    observation = MtkMetaProbe(NullRunner()).probe()[0]

    assert observation.identifiers["device"] == "KM7"
    assert observation.identifiers["chipset"] == "mt6765"
    assert {item["name"] for item in observation.partitions} >= {
        "proinfo",
        "nvram",
        "nvdata",
    }
