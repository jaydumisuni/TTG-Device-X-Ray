import struct

from ttg_device_xray.analyzers.deep_diagnostics import (
    classify_errors,
    diagnose,
    inspect_partition,
    parse_health,
)
from ttg_device_xray.models import CommandEvidence, TransportKind, TransportObservation
from ttg_device_xray.transports.fastboot import FastbootProbe


def test_unknown_health_is_not_healthy():
    assert parse_health("") == {"health_descriptors": [], "physical_start_sectors_512": {}}
    data = parse_health("mmcblk0|life_time|0x00 0x00\nmmcblk0p1|start_sector_512|2048")
    assert data["health_descriptors"][0]["status"] == "UNKNOWN"
    assert data["physical_start_sectors_512"]["mmcblk0p1"] == 2048


def test_storage_and_filesystem_evidence_distinct():
    data = parse_health("mmcblk0|pre_eol_info|0x03")
    obs = TransportObservation(TransportKind.ADB, True, True, "recovery",
                               capabilities={"deep_storage": data, "deep_errors":
                                             classify_errors("EXT4-fs error on mmcblk0p4")})
    result = diagnose([obs])
    assert result["causes"]["storage_failure"] == "SUSPECTED"
    assert result["causes"]["filesystem_damage"] == "SUSPECTED"
    assert result["causes"]["partition_corruption"] == "UNKNOWN"


def test_boot_image_and_failed_readback(tmp_path):
    path = tmp_path / "boot.img"
    path.write_bytes(b"")
    assert inspect_partition(path, "boot")["status"] == "UNKNOWN"
    raw = bytearray(8192)
    raw[:8] = b"ANDROID!"
    struct.pack_into("<I", raw, 8, 4096)
    struct.pack_into("<I", raw, 36, 4096)
    path.write_bytes(raw)
    assert inspect_partition(path, "boot", path)["reference_match"] is True
    assert inspect_partition(path, "boot")["status"] == "HEADER_VALID"
    path.write_bytes(raw[:4096])
    assert inspect_partition(path, "boot")["status"] == "STRUCTURAL_ERROR"


def test_ext_superblock_bounds(tmp_path):
    path = tmp_path / "system.img"
    raw = bytearray(4096)
    raw[1080:1082] = b"\x53\xef"
    struct.pack_into("<I", raw, 1028, 100)
    path.write_bytes(raw)
    assert inspect_partition(path, "filesystem")["status"] == "STRUCTURAL_ERROR"


def test_huawei_oem_identity_and_transport_route():
    class FakeRunner:
        def exists(self, executable):
            return True

        def run(self, command, timeout=20):
            responses = {
                "devices": "example fastboot",
                "all": "(bootloader) product: MSM8953",
                "max-fetch-size": "max-fetch-size:",
                "get-product-model": "(bootloader) HUAWEI CAZ-AL10",
                "get-build-number": "(bootloader) CAZ-AL10C00B387",
                "get-bootinfo": "(bootloader) Lock state is unlock",
            }
            return CommandEvidence(command, 0, stdout=responses[command[-1]])

    obs = FastbootProbe(FakeRunner(), deep=True).probe()[0]
    assert obs.identifiers["model"] == "CAZ-AL10"
    assert obs.identifiers["build"] == "CAZ-AL10C00B387"
    assert obs.capabilities["bootloader_locked"] is False
    report = diagnose([obs])
    assert report["causes"]["storage_failure"] == "UNKNOWN"
    assert any(r["interface"] == "qualcomm_edl" for r in report["alternative_interfaces"])
    assert report["alternative_interfaces"][0]["partition_readback"] == "NOT_ADVERTISED"
    assert report["mode_switch_performed"] is False


def test_exact_build_reference_does_not_infer_corruption():
    from ttg_device_xray.analyzers.deep_diagnostics import compare_reference

    report = {"partition_integrity": [
        {"name": "boot", "size_bytes": 8192, "sha256": "a" * 64}
    ]}
    ref = {"model": "CAZ-AL10", "build": "B387", "partitions": {
        "boot": {"size_bytes": 8192, "sha256": "b" * 64}
    }}
    assert compare_reference(report, "CAZ-AL10", "B175", ref)["status"] == (
        "REFERENCE_NOT_APPLICABLE"
    )
    result = compare_reference(report, "CAZ-AL10", "B387", ref)
    assert result["comparisons"][0]["status"] == "BYTE_MISMATCH"


def test_structural_evidence_correlates_without_storage_assumption():
    obs = TransportObservation(
        TransportKind.ADB, True, True, "recovery",
        capabilities={"partition_integrity": [
            {"kind": "boot", "status": "STRUCTURAL_ERROR"}
        ]},
    )
    causes = diagnose([obs])["causes"]
    assert causes["partition_corruption"] == "SUSPECTED"
    assert causes["boot_chain_failure"] == "SUSPECTED"
    assert causes["storage_failure"] == "UNKNOWN"
