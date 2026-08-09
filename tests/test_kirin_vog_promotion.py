from __future__ import annotations

import copy

import pytest

from ttg_device_xray.models import DeviceIdentity, StorageSummary
from ttg_device_xray.profile_loader import ProfileLoader
from ttg_device_xray.promoted_kirin import (
    PromotedKirinError,
    explain_vog_replay,
    load_promoted_vog_pack,
    validate_promoted_vog_pack,
)


def frozen_vog_evidence() -> dict[str, bool]:
    return {
        "version_artifact_valid": True,
        "version_write_accepted": True,
        "main_version_after_version_write": False,
        "writable_verlist_partition_observed": False,
        "oeminfo_version_identity_present": False,
        "service_mode_required_for_unresolved_repair": True,
        "stock_fastboot_restored_before_release": True,
        "release_conditions_verified": False,
        "core_boot_recovered": True,
        "branding_mismatch_remaining": True,
    }


def test_promoted_vog_profile_is_native_read_only_match() -> None:
    match = ProfileLoader()._match(
        requested="android:huawei:vog-l29:kirin980:c185",
        identity=DeviceIdentity(
            platform="android",
            brand="Huawei",
            manufacturer="Huawei",
            product_type="VOG-L29",
            internal_model="VOG-L29",
            board="VOG",
            chipset="Kirin 980",
            active_mode="fastboot",
        ),
        storage=StorageSummary(),
        observations=[],
    )

    assert match.status == "MATCHED"
    assert match.profile_id == "android:huawei:vog-l29:kirin980:c185"
    assert match.stage == "REPEATED_MATCH"
    assert match.confidence >= 0.9
    assert match.source.endswith("profiles/huawei/vog_l29_c185_kirin.json")
    assert match.adapter_contracts == {}
    assert match.capabilities["repair_profile_ready"] is False
    assert match.capabilities["kirin_capability_reference"]["includes_execution"] is False
    assert match.write_allowed is False


def test_promoted_capability_independently_explains_frozen_vog_case() -> None:
    explanation = explain_vog_replay(frozen_vog_evidence())

    assert explanation["independently_explains_frozen_vog_case"] is True
    assert explanation["missing_rule_explanations"] == []
    assert explanation["evidence_level"] == "replay_supported"
    assert explanation["physical_hardware_certification"] == "NOT_CLAIMED"
    assert explanation["execution_authority"] == "none"
    assert explanation["write_allowed"] is False
    assert {item["code"] for item in explanation["findings"]} == {
        "VOG_MAIN_VERSION_OEMINFO_CAUSAL_EXPLANATION",
        "VOG_SERVICE_MODE_PREMATURE_RELEASE_HAZARD",
        "VOG_STOCK_FASTBOOT_FINALIZATION_ONLY",
        "VOG_BRANDING_NORMALIZATION_SEPARATE_STAGE",
    }


def test_promoted_capability_does_not_force_oeminfo_explanation_when_evidence_disagrees() -> None:
    evidence = frozen_vog_evidence()
    evidence["oeminfo_version_identity_present"] = True

    explanation = explain_vog_replay(evidence)

    assert explanation["independently_explains_frozen_vog_case"] is False
    assert "vog.main_version_state.oeminfo" in explanation["missing_rule_explanations"]
    assert "VOG_MAIN_VERSION_OEMINFO_CAUSAL_EXPLANATION" not in {
        item["code"] for item in explanation["findings"]
    }


def test_promoted_pack_rejects_execution_authority() -> None:
    pack = copy.deepcopy(load_promoted_vog_pack())
    pack["includes_execution"] = True

    with pytest.raises(PromotedKirinError, match="may not include execution"):
        validate_promoted_vog_pack(pack)


def test_promoted_pack_rejects_forbidden_authority_keys() -> None:
    pack = copy.deepcopy(load_promoted_vog_pack())
    pack["partition_write"] = {"allowed": False}

    with pytest.raises(PromotedKirinError, match="forbidden execution authority key"):
        validate_promoted_vog_pack(pack)
