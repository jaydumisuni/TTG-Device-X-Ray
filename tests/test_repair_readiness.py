from ttg_device_xray.repair_readiness import (
    build_repair_readiness,
    scan_completion_message,
)


def test_candidate_profile_keeps_adapters_locked() -> None:
    readiness = build_repair_readiness(
        {
            "status": "CANDIDATE_PROFILE",
            "profile_id": "android:redmi:sky:parrot",
            "adapter_contracts": {"flash": "must-not-escape"},
        }
    )

    assert readiness["certification_scope"] == "DEVICE_IDENTITY_EVIDENCE"
    assert readiness["profile_ready"] is False
    assert readiness["review_required"] is True
    assert readiness["adapters_available"] is False
    assert readiness["adapter_contracts"] == {}
    assert readiness["write_allowed"] is False
    assert "adapters remain locked" in readiness["message"]


def test_approved_match_exposes_reviewed_adapter_contracts() -> None:
    readiness = build_repair_readiness(
        {
            "status": "MATCHED",
            "profile_id": "android:tecno:km7:mt6765",
            "adapter_contracts": {"flash": "transsion.flash-plan.v1"},
        }
    )

    assert readiness["profile_ready"] is True
    assert readiness["adapters_available"] is True
    assert readiness["adapter_contracts"] == {"flash": "transsion.flash-plan.v1"}
    assert readiness["write_allowed"] is False


def test_completion_message_names_identity_scope_and_profile_lock() -> None:
    message = scan_completion_message(
        {
            "scan_id": "xray-test",
            "verdict": "CERTIFIED",
            "profile_match": {
                "status": "CANDIDATE_PROFILE",
                "profile_id": "android:redmi:sky:parrot",
            },
        }
    )

    assert message.startswith("Identity evidence CERTIFIED — xray-test")
    assert "owner review required" in message
    assert "adapters remain locked" in message
