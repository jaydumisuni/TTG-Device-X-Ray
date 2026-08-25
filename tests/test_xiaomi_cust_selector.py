from ttg_device_xray.transports.xiaomi_cust_selector import (
    compact_xiaomi_cust_selector,
    parse_xiaomi_cust_selector,
    selector_consistency,
)


REAL_SKY_STYLE_EVIDENCE = """TTG_XIAOMI_CUST_BEGIN|cust_variant|/cust/cust_variant
cn_chinatelecom
TTG_XIAOMI_CUST_END|cust_variant
TTG_XIAOMI_CUST_BEGIN|business_prop|/cust/etc/business.prop
ro.miui.business.version=sky.cn_chinatelecom.1.1.0038
TTG_XIAOMI_CUST_END|business_prop
TTG_XIAOMI_CUST_BEGIN|request_config|/cust/etc/cust_apps_request_config
repository_url =http://pm.preload.xiaomi.srv/admin/api/v2/preload device =sky romRegion =cn romVersionType =stable profile =1 custprop =None testConfigId= currentSku=cn_chinatelecom custVersion=sky.cn_chinatelecom.1.1.0038
TTG_XIAOMI_CUST_END|request_config
TTG_XIAOMI_CUST_BEGIN|apps_config|/cust/etc/cust_apps_config
{"status":0,"appNum":2,"targetProduct":"sky","romRegion":"cn","isTest":false,"romVersionType":"stable","data":[{"packageId":"com.baidu.searchbox_9","packageName":"com.baidu.searchbox","otaSkip":true,"apkPath":"https://example.invalid/volatile.apk","launcherIconLocation":7,"custConfig":[{"targetProduct":"sky","custVariants":"cn","enable":true,"subarea":"cust"},{"targetProduct":"sky","custVariants":"cn_chinatelecom","enable":true,"subarea":"cust"}]},{"packageId":"com.eg.android.AlipayGphone_23","packageName":"com.eg.android.AlipayGphone","otaSkip":true,"launcherIconLocation":7,"custConfig":[{"targetProduct":"sky","custVariants":"cn_chinatelecom","enable":true,"subarea":"cust"},{"targetProduct":"sky","custVariants":"cn_chinaunicom","enable":false,"subarea":"cust"}]}]}
TTG_XIAOMI_CUST_END|apps_config
"""


def test_parse_xiaomi_selector_recovers_sky_cn_policy_without_urls() -> None:
    selector = parse_xiaomi_cust_selector(REAL_SKY_STYLE_EVIDENCE)

    assert selector["status"] == "COLLECTED"
    assert selector["cust_variant"] == "cn_chinatelecom"
    assert selector["business_version"] == "sky.cn_chinatelecom.1.1.0038"
    assert selector["request"] == {
        "device": "sky",
        "romRegion": "cn",
        "romVersionType": "stable",
        "profile": "1",
        "custprop": "None",
        "testConfigId": "",
        "currentSku": "cn_chinatelecom",
        "custVersion": "sky.cn_chinatelecom.1.1.0038",
    }

    policy = selector["preload_policy"]
    assert policy["target_product"] == "sky"
    assert policy["rom_region"] == "cn"
    assert policy["declared_app_count"] == 2
    assert policy["observed_app_count"] == 2
    assert policy["enabled_cust_variants"] == ["cn", "cn_chinatelecom"]
    assert [item["package"] for item in policy["packages"]] == [
        "com.baidu.searchbox",
        "com.eg.android.AlipayGphone",
    ]
    assert "apkPath" not in str(policy)
    assert "example.invalid" not in str(policy)


def test_selector_consistency_matches_live_sky_properties() -> None:
    selector = parse_xiaomi_cust_selector(REAL_SKY_STYLE_EVIDENCE)
    consistency = selector_consistency(
        selector,
        {
            "ro.miui.region": "CN",
            "ro.miui.cust_variant": "cn_chinatelecom",
        },
    )

    assert consistency["consistent"] is True
    assert consistency["checks"] == {
        "cust_variant_matches_property": True,
        "cust_variant_matches_request_sku": True,
        "region_matches_request": True,
    }


def test_selector_parser_fails_closed_when_xiaomi_cust_files_are_absent() -> None:
    selector = parse_xiaomi_cust_selector(
        """TTG_XIAOMI_CUST_BEGIN|cust_variant|/cust/cust_variant
TTG_XIAOMI_CUST_MISSING
TTG_XIAOMI_CUST_END|cust_variant
"""
    )

    assert selector["status"] == "NOT_PRESENT"
    assert selector["preload_policy"] == {}


def test_selector_compaction_keeps_only_diagnostic_summary() -> None:
    selector = parse_xiaomi_cust_selector(REAL_SKY_STYLE_EVIDENCE)
    compact = compact_xiaomi_cust_selector(selector)

    assert "xiaomi_cust_status=COLLECTED" in compact
    assert "cust_variant=cn_chinatelecom" in compact
    assert "business_version=sky.cn_chinatelecom.1.1.0038" in compact
    assert "preload_packages=2" in compact
