from ttg_device_xray.transports.android_regional import AndroidRegionalProbe


def test_region_inference_prefers_xiaomi_build_channel() -> None:
    inferred = AndroidRegionalProbe._infer_region(
        {
            "ro.build.display.id": "OS2.0.204.0.VMWCNXM",
            "ro.product.locale": "en-US",
        }
    )

    assert inferred == {
        "region": "CN",
        "source": "ro.build.display.id",
        "value": "OS2.0.204.0.VMWCNXM",
    }


def test_region_inference_recognizes_global_suffix() -> None:
    inferred = AndroidRegionalProbe._infer_region(
        {"ro.build.version.incremental": "OS2.0.10.0.VMWMIXM"}
    )

    assert inferred["region"] == "GLOBAL"
    assert inferred["source"] == "ro.build.version.incremental"


def test_package_manifest_preserves_user_uninstalled_system_packages() -> None:
    packages = AndroidRegionalProbe._parse_package_paths(
        "\n".join(
            [
                "package:/product/app/MiuiMarket/MiuiMarket.apk=com.xiaomi.market",
                "package:/product/priv-app/GmsCore/GmsCore.apk=com.google.android.gms",
                "package:/data/app/example/base.apk=com.example.user",
            ]
        )
    )
    installed = {"com.google.android.gms", "com.example.user"}
    system = {"com.xiaomi.market", "com.google.android.gms"}
    disabled = {"com.xiaomi.market"}

    records = AndroidRegionalProbe._regional_package_records(
        packages,
        installed=installed,
        system=system,
        disabled=disabled,
    )
    by_package = {item["package"]: item for item in records}

    assert by_package["com.xiaomi.market"]["partition"] == "product"
    assert by_package["com.xiaomi.market"]["installed_for_current_user"] is False
    assert by_package["com.xiaomi.market"]["known_system_package"] is True
    assert by_package["com.xiaomi.market"]["disabled_for_current_user"] is True
    assert by_package["com.google.android.gms"]["installed_for_current_user"] is True
    assert "com.example.user" not in by_package


def test_google_stack_distinguishes_absent_known_and_installed() -> None:
    packages = {
        "com.google.android.gms": "/product/priv-app/GmsCore/GmsCore.apk",
        "com.android.vending": "/product/priv-app/Phonesky/Phonesky.apk",
    }
    stack = AndroidRegionalProbe._google_stack(
        packages,
        installed={"com.android.vending"},
        system={"com.google.android.gms", "com.android.vending"},
        disabled={"com.google.android.gms"},
    )

    assert stack["com.google.android.gms"]["known_to_package_manager"] is True
    assert stack["com.google.android.gms"]["installed_for_current_user"] is False
    assert stack["com.google.android.gms"]["disabled_for_current_user"] is True
    assert stack["com.android.vending"]["installed_for_current_user"] is True
    assert stack["com.google.android.gsf"]["known_to_package_manager"] is False


def test_overlay_parser_keeps_target_and_state() -> None:
    overlays = AndroidRegionalProbe._parse_overlays(
        "\n".join(
            [
                "com.android.settings",
                "[x] com.miui.settings.overlay.cn",
                "[ ] com.google.android.settings.overlay",
                "com.android.systemui",
                "--- com.xiaomi.systemui.overlay.dynamic",
            ]
        )
    )

    assert overlays == [
        {
            "target": "com.android.settings",
            "package": "com.miui.settings.overlay.cn",
            "enabled": True,
        },
        {
            "target": "com.android.settings",
            "package": "com.google.android.settings.overlay",
            "enabled": False,
        },
        {
            "target": "com.android.systemui",
            "package": "com.xiaomi.systemui.overlay.dynamic",
            "enabled": None,
        },
    ]


def test_customization_inventory_filters_for_regional_signals() -> None:
    names = AndroidRegionalProbe._regional_file_names(
        "\n".join(
            [
                "google.xml",
                "miui_cn_features.xml",
                "platform.xml",
                "regional_preload_config.json",
                "unrelated-permissions.xml",
            ]
        )
    )

    assert names == [
        "google.xml",
        "miui_cn_features.xml",
        "regional_preload_config.json",
    ]
