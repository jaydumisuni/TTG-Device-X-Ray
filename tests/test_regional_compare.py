import json

from ttg_device_xray.regional_compare import (
    compare_regional_manifests,
    load_firmware_regional_manifest,
)


def _manifest(region: str) -> dict:
    return {
        "schema": "ttg.xray.android-regional-manifest.v2",
        "kind": "firmware_regional_evidence",
        "region_inference": {
            "region": region,
            "source": "ro.miui.region",
            "value": region,
        },
        "regional_properties": {"ro.miui.region": region, "common": "same"},
        "regional_packages": [],
        "google_stack": {},
        "regional_overlays": [],
        "customization_file_collection": {
            "status": "COLLECTED",
            "return_code": 0,
            "timed_out": False,
            "file_count": 0,
        },
        "customization_files": [],
    }


def test_compare_regional_manifests_reports_added_removed_and_changed() -> None:
    left = _manifest("CN")
    right = _manifest("GLOBAL")
    left["regional_packages"] = [
        {"package": "com.baidu.searchbox", "partition": "cust", "path": "/cust/baidu.apk"}
    ]
    right["regional_packages"] = [
        {"package": "com.google.android.gms", "partition": "product", "path": "/product/gms.apk"}
    ]
    left["regional_overlays"] = [
        {"target": "android", "package": "com.miui.region.overlay", "enabled": True}
    ]
    right["regional_overlays"] = [
        {"target": "android", "package": "com.miui.region.overlay", "enabled": False}
    ]
    left["customization_files"] = [
        {"path": "/cust/cust_variant", "partition": "cust", "size_bytes": 2, "sha256": "a" * 64},
        {"path": "/cust/baidu.apk", "partition": "cust", "size_bytes": 10, "sha256": "b" * 64},
    ]
    right["customization_files"] = [
        {"path": "/cust/cust_variant", "partition": "cust", "size_bytes": 6, "sha256": "c" * 64},
        {"path": "/product/etc/permissions/google.xml", "partition": "product", "size_bytes": 12, "sha256": "d" * 64},
    ]

    report = compare_regional_manifests(left, right)

    assert report["region_changed"] is True
    assert report["summary"]["properties"]["changed"] == 1
    assert report["summary"]["regional_packages"]["added"] == 1
    assert report["summary"]["regional_packages"]["removed"] == 1
    assert report["summary"]["regional_overlays"]["changed"] == 1
    assert report["summary"]["customization_files"] == {
        "added": 1,
        "removed": 1,
        "changed": 1,
        "unchanged": 0,
    }


def test_load_manifest_from_xray_bundle_directory(tmp_path) -> None:
    manifest = _manifest("CN")
    payload = [
        {
            "transport": "adb",
            "mode": "device",
            "capabilities": {
                "evidence_scope": "regional_customization",
                "firmware_regional_manifest": manifest,
            },
        }
    ]
    (tmp_path / "transport_evidence.json").write_text(
        json.dumps(payload),
        encoding="utf-8",
    )

    loaded = load_firmware_regional_manifest(tmp_path)

    assert loaded == manifest


def test_manifest_comparison_is_order_independent_for_mapping_keys() -> None:
    left = _manifest("CN")
    right = _manifest("CN")
    left["regional_properties"] = {"b": "2", "a": "1"}
    right["regional_properties"] = {"a": "1", "b": "2"}

    report = compare_regional_manifests(left, right)

    assert report["region_changed"] is False
    assert report["summary"]["properties"] == {
        "added": 0,
        "removed": 0,
        "changed": 0,
        "unchanged": 2,
    }
    assert report["left"]["manifest_sha256"] == report["right"]["manifest_sha256"]
