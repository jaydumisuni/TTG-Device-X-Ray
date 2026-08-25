from ttg_device_xray.transports.xiaomi_regional_manifest import XiaomiRegionalManifestProbe


SHA = "a" * 64


def test_mi_ext_is_first_class_manifest_partition() -> None:
    records = XiaomiRegionalManifestProbe._parse_file_manifest(
        f"/mi_ext/etc/build.prop|123|{SHA}\n"
        f"/mi_ext/product/overlay/GmsMiCSPTelephonyOverlay.apk|456|{SHA}\n"
    )

    assert records == [
        {
            "path": "/mi_ext/etc/build.prop",
            "partition": "mi_ext",
            "size_bytes": 123,
            "sha256": SHA,
        },
        {
            "path": "/mi_ext/product/overlay/GmsMiCSPTelephonyOverlay.apk",
            "partition": "mi_ext",
            "size_bytes": 456,
            "sha256": SHA,
        },
    ]


def test_xiaomi_manifest_script_collects_mi_ext_directly() -> None:
    assert "for root in /cust /mi_ext " in XiaomiRegionalManifestProbe.FILE_MANIFEST_SCRIPT
    assert "/mi_ext) depth=8" in XiaomiRegionalManifestProbe.FILE_MANIFEST_SCRIPT


def test_mi_ext_identity_parser_preserves_avb_provenance() -> None:
    record = XiaomiRegionalManifestProbe._parse_key_value_evidence(
        """present=true
partition.mi_ext.verified=2
partition.mi_ext.verified.hash_alg=sha256
partition.mi_ext.verified.root_digest=4f80a533
mount_source=/dev/block/dm-12
filesystem=erofs
buildprop.ro.miui.build.region=cn
buildprop.ro.com.google.clientidbase=android-xiaomi
"""
    )

    assert record["present"] is True
    assert record["partition.mi_ext.verified"] == "2"
    assert record["partition.mi_ext.verified.hash_alg"] == "sha256"
    assert record["partition.mi_ext.verified.root_digest"] == "4f80a533"
    assert record["mount_source"] == "/dev/block/dm-12"
    assert record["filesystem"] == "erofs"
    assert record["buildprop.ro.miui.build.region"] == "cn"


def test_probe_only_enriches_miui_family_observations() -> None:
    assert XiaomiRegionalManifestProbe._is_miui({"ro.miui.region": "CN"}) is True
    assert (
        XiaomiRegionalManifestProbe._is_miui(
            {"ro.vendor.miui.region": "CN", "ro.product.locale": "zh-CN"}
        )
        is True
    )
    assert XiaomiRegionalManifestProbe._is_miui({"ro.product.locale": "en-US"}) is False


def test_non_mi_ext_paths_keep_generic_partition_classification() -> None:
    assert XiaomiRegionalManifestProbe._partition_for_path("/cust/etc/business.prop") == "cust"
    assert XiaomiRegionalManifestProbe._partition_for_path("/product/etc/sysconfig/a.xml") == "product"
