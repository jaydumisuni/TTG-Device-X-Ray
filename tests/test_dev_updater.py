from __future__ import annotations

import pytest

from ttg_device_xray.dev_updater import (
    _validate_manifest,
    compare_versions,
    package_version_to_channel,
)


def test_package_version_maps_to_dev_channel_version() -> None:
    assert package_version_to_channel("0.4.3.dev1") == "0.4.3-dev.1"
    assert package_version_to_channel("0.4.3") == "0.4.3"


def test_dev_versions_compare_in_release_order() -> None:
    assert compare_versions("0.4.3-dev.1", "0.4.3-dev.2") < 0
    assert compare_versions("0.4.3-dev.2", "0.4.3-dev.2") == 0
    assert compare_versions("0.4.3", "0.4.3-dev.9") > 0
    assert compare_versions("0.4.4-dev.1", "0.4.3") > 0


def test_manifest_is_locked_to_private_dev_channel() -> None:
    payload = {
        "schema_version": 1,
        "tool_id": "ttg-device-xray",
        "channel": "dev",
        "version": "0.4.3-dev.2",
        "repository": "jaydumisuni/tools-test-repo",
        "release_tag": "ttg-device-xray/v0.4.3-dev.2",
        "asset_name": "TTG-Device-XRay-v0.4.3-dev.2-Windows.exe",
        "sha256": "a" * 64,
        "size_bytes": 50_000_000,
    }

    manifest = _validate_manifest(payload, "jaydumisuni/tools-test-repo")

    assert manifest.version == "0.4.3-dev.2"
    assert manifest.repository == "jaydumisuni/tools-test-repo"


def test_manifest_rejects_public_or_wrong_repository() -> None:
    payload = {
        "schema_version": 1,
        "tool_id": "ttg-device-xray",
        "channel": "dev",
        "version": "0.4.3-dev.2",
        "repository": "jaydumisuni/TTG-Device-X-Ray",
        "release_tag": "v0.4.3",
        "asset_name": "TTG-Device-XRay.exe",
        "sha256": "b" * 64,
        "size_bytes": 50_000_000,
    }

    with pytest.raises(ValueError, match="repository mismatch"):
        _validate_manifest(payload, "jaydumisuni/tools-test-repo")


def test_manifest_rejects_path_traversal_asset() -> None:
    payload = {
        "schema_version": 1,
        "tool_id": "ttg-device-xray",
        "channel": "dev",
        "version": "0.4.3-dev.2",
        "repository": "jaydumisuni/tools-test-repo",
        "release_tag": "ttg-device-xray/v0.4.3-dev.2",
        "asset_name": "../TTG-Device-XRay.exe",
        "sha256": "c" * 64,
        "size_bytes": 50_000_000,
    }

    with pytest.raises(ValueError, match="Unsafe update asset"):
        _validate_manifest(payload, "jaydumisuni/tools-test-repo")
