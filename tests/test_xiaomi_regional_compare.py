from ttg_device_xray.regional_compare import compare_regional_manifests


def _base_manifest(region: str) -> dict:
    return {
        "schema": "ttg.xray.android-regional-manifest.v3",
        "kind": "firmware_regional_evidence",
        "region_inference": {
            "region": region,
            "source": "ro.miui.region",
            "value": region,
        },
        "regional_properties": {"ro.miui.region": region},
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


def test_compare_reports_xiaomi_selector_preload_and_mi_ext_deltas() -> None:
    left = _base_manifest("CN")
    right = _base_manifest("GLOBAL")

    left["xiaomi_customization_selector"] = {
        "status": "COLLECTED",
        "cust_variant": "cn_chinatelecom",
        "business_version": "sky.cn_chinatelecom.1.1.0038",
        "request": {
            "device": "sky",
            "romRegion": "cn",
            "currentSku": "cn_chinatelecom",
        },
        "consistency": {"consistent": True},
        "preload_policy": {
            "parse_status": "COLLECTED",
            "target_product": "sky",
            "rom_region": "cn",
            "packages": [
                {
                    "package": "com.baidu.searchbox",
                    "package_id": "com.baidu.searchbox_9",
                    "enabled_cust_variants": ["cn", "cn_chinatelecom"],
                },
                {
                    "package": "com.eg.android.AlipayGphone",
                    "package_id": "com.eg.android.AlipayGphone_23",
                    "enabled_cust_variants": ["cn_chinatelecom"],
                },
            ],
        },
    }
    right["xiaomi_customization_selector"] = {
        "status": "COLLECTED",
        "cust_variant": "global",
        "business_version": "sky.global.1.0",
        "request": {
            "device": "sky",
            "romRegion": "global",
            "currentSku": "global",
        },
        "consistency": {"consistent": True},
        "preload_policy": {
            "parse_status": "COLLECTED",
            "target_product": "sky",
            "rom_region": "global",
            "packages": [
                {
                    "package": "com.google.android.apps.messaging",
                    "package_id": "messaging",
                    "enabled_cust_variants": ["global"],
                }
            ],
        },
    }

    left["xiaomi_mi_ext"] = {
        "status": "COLLECTED",
        "present": True,
        "partition.mi_ext.verified": "2",
        "partition.mi_ext.verified.hash_alg": "sha256",
        "partition.mi_ext.verified.root_digest": "a" * 64,
        "buildprop.ro.miui.build.region": "cn",
    }
    right["xiaomi_mi_ext"] = {
        "status": "COLLECTED",
        "present": True,
        "partition.mi_ext.verified": "2",
        "partition.mi_ext.verified.hash_alg": "sha256",
        "partition.mi_ext.verified.root_digest": "b" * 64,
        "buildprop.ro.miui.build.region": "global",
    }

    report = compare_regional_manifests(left, right)

    assert report["summary"]["xiaomi_customization_selector"]["changed"] >= 3
    assert report["summary"]["xiaomi_preload_packages"] == {
        "added": 1,
        "removed": 2,
        "changed": 0,
        "unchanged": 0,
    }
    assert report["summary"]["xiaomi_mi_ext"]["changed"] == 2
    assert [item["package"] for item in report["xiaomi_preload_packages"]["removed"]] == [
        "com.baidu.searchbox",
        "com.eg.android.AlipayGphone",
    ]
    assert [item["package"] for item in report["xiaomi_preload_packages"]["added"]] == [
        "com.google.android.apps.messaging"
    ]
    assert (
        report["xiaomi_mi_ext"]["changed"][
            "partition.mi_ext.verified.root_digest"
        ]["left"]
        == "a" * 64
    )


def test_compare_remains_backward_compatible_when_xiaomi_fields_are_absent() -> None:
    left = _base_manifest("CN")
    right = _base_manifest("CN")

    report = compare_regional_manifests(left, right)

    assert report["summary"]["xiaomi_customization_selector"] == {
        "added": 0,
        "removed": 0,
        "changed": 0,
        "unchanged": 0,
    }
    assert report["summary"]["xiaomi_preload_packages"] == {
        "added": 0,
        "removed": 0,
        "changed": 0,
        "unchanged": 0,
    }
    assert report["summary"]["xiaomi_mi_ext"] == {
        "added": 0,
        "removed": 0,
        "changed": 0,
        "unchanged": 0,
    }
