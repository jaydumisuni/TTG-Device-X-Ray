from ttg_device_xray.transports.android_regional_manifest import (
    AndroidRegionalManifestProbe,
)


def test_package_state_parser_keeps_current_user_suspension() -> None:
    states = AndroidRegionalManifestProbe._parse_user_package_states(
        "\n".join(
            [
                "Package [com.xiaomi.market] (abc123):",
                "  User 0: installed=false hidden=false suspended=true stopped=true enabled=0",
                "Package [com.google.android.gms] (def456):",
                "  User 0: installed=true hidden=false suspended=false stopped=false enabled=0",
                "  User 10: installed=false hidden=false suspended=false stopped=true enabled=0",
            ]
        ),
        "0",
    )

    assert states["com.xiaomi.market"]["installed"] is False
    assert states["com.xiaomi.market"]["suspended"] is True
    assert states["com.google.android.gms"]["installed"] is True
    assert states["com.google.android.gms"]["suspended"] is False


def test_package_state_parser_fails_closed_without_numeric_user() -> None:
    assert AndroidRegionalManifestProbe._parse_user_package_states("anything", "") == {}


def test_file_manifest_keeps_cust_and_hashes_relevant_configs() -> None:
    digest = "a" * 64
    records = AndroidRegionalManifestProbe._parse_file_manifest(
        "\n".join(
            [
                f"/cust/cn/app/preload.json|123|{digest}",
                f"/system/etc/sysconfig/google.xml|234|{digest}",
                f"/system/etc/permissions/com.google.android.maps.xml|345|{digest}",
                f"/product/etc/sysconfig/whitelist.xml|456|{digest}",
                f"/product/etc/permissions/google-hiddenapi-package-whitelist.xml|789|{digest}",
                f"/vendor/etc/audio_policy_configuration.xml|111|{digest}",
            ]
        )
    )

    by_path = {item["path"]: item for item in records}
    assert by_path["/cust/cn/app/preload.json"]["partition"] == "cust"
    assert by_path["/cust/cn/app/preload.json"]["sha256"] == digest
    assert by_path["/system/etc/sysconfig/google.xml"]["partition"] == "system"
    assert by_path["/system/etc/permissions/com.google.android.maps.xml"]["partition"] == "system"
    assert "/product/etc/sysconfig/whitelist.xml" in by_path
    assert "/product/etc/permissions/google-hiddenapi-package-whitelist.xml" in by_path
    assert "/vendor/etc/audio_policy_configuration.xml" not in by_path


def test_file_manifest_script_scans_common_system_google_config_roots() -> None:
    script = AndroidRegionalManifestProbe.FILE_MANIFEST_SCRIPT

    assert "/system/etc/sysconfig" in script
    assert "/system/etc/permissions" in script


def test_google_integration_classifies_absent_partial_and_system() -> None:
    absent = {
        package: {
            "known_to_package_manager": False,
            "installed_for_current_user": False,
            "known_system_package": False,
            "partition": "unknown",
        }
        for package in AndroidRegionalManifestProbe.CORE_GOOGLE_PACKAGES
    }
    assert AndroidRegionalManifestProbe._classify_google_integration(absent)["presence"] == "ABSENT"

    partial = {package: dict(record) for package, record in absent.items()}
    partial["com.google.android.gms"].update(
        {
            "known_to_package_manager": True,
            "installed_for_current_user": True,
            "partition": "data",
        }
    )
    partial_result = AndroidRegionalManifestProbe._classify_google_integration(partial)
    assert partial_result["presence"] == "PARTIAL"
    assert partial_result["integration"] == "USER_DATA_OR_MIXED"

    system = {package: dict(record) for package, record in absent.items()}
    for record in system.values():
        record.update(
            {
                "known_to_package_manager": True,
                "installed_for_current_user": True,
                "known_system_package": True,
                "partition": "product",
            }
        )
    system_result = AndroidRegionalManifestProbe._classify_google_integration(system)
    assert system_result["presence"] == "PRESENT"
    assert system_result["integration"] == "SYSTEM"


def test_manifest_digest_is_order_independent_for_mapping_keys() -> None:
    left = {"schema": "v1", "properties": {"b": "2", "a": "1"}}
    right = {"properties": {"a": "1", "b": "2"}, "schema": "v1"}

    assert AndroidRegionalManifestProbe._canonical_sha256(left) == (
        AndroidRegionalManifestProbe._canonical_sha256(right)
    )


def test_region_path_filter_avoids_unrelated_vendor_configs() -> None:
    assert AndroidRegionalManifestProbe._is_region_relevant_path(
        "/system/etc/permissions/com.google.android.maps.xml"
    )
    assert AndroidRegionalManifestProbe._is_region_relevant_path(
        "/product/etc/permissions/com.google.android.maps.xml"
    )
    assert AndroidRegionalManifestProbe._is_region_relevant_path(
        "/cust/cn/overlay/config.xml"
    )
    assert not AndroidRegionalManifestProbe._is_region_relevant_path(
        "/vendor/etc/audio_policy_configuration.xml"
    )
