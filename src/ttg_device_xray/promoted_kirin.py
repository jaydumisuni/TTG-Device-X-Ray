from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import resources
from typing import Any

PACK_RESOURCE = "capability_packs/kirin/vog_replay_v1.json"
PACK_SCHEMA = "ttg-device-xray.promoted-kirin-capability.v1"
PACK_ID = "kirin-vog-l29-c185-replay"
SOURCE_REPOSITORY = "jaydumisuni/TECHGUYTOOL-Huawei"
SOURCE_COMMIT = "93a8bd705bd9e8d8bade40f0e15181644211812e"
SOURCE_MANIFEST_SHA256 = "3859e0e71495a4847c8698714494b5ce94264d12d6d8eaa663d4d56c45b8fc9f"
REQUIRED_RULE_IDS = frozenset(
    {
        "vog.main_version_state.oeminfo",
        "vog.service_mode.preserve_until_verified",
        "vog.stock_fastboot.finalization_only",
        "vog.branding.separate_stage",
    }
)
REQUIRED_EVIDENCE_FIELDS = (
    "version_artifact_valid",
    "version_write_accepted",
    "main_version_after_version_write",
    "writable_verlist_partition_observed",
    "oeminfo_version_identity_present",
    "service_mode_required_for_unresolved_repair",
    "stock_fastboot_restored_before_release",
    "release_conditions_verified",
    "core_boot_recovered",
    "branding_mismatch_remaining",
)
FORBIDDEN_AUTHORITY_KEYS = frozenset(
    {
        "executor",
        "execution_lease",
        "loader_transfer",
        "partition_write",
        "firmware_write",
        "reboot_authority",
        "unlock_authority",
        "relock_authority",
        "repair_recipe",
        "write_target",
        "write_offset",
    }
)


class PromotedKirinError(ValueError):
    pass


def load_promoted_vog_pack() -> dict[str, Any]:
    root = resources.files("ttg_device_xray")
    path = root.joinpath(*PACK_RESOURCE.split("/"))
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise PromotedKirinError("promoted Kirin pack must be a JSON object")
    validate_promoted_vog_pack(payload)
    return payload


def validate_promoted_vog_pack(payload: Mapping[str, Any]) -> None:
    if payload.get("schema") != PACK_SCHEMA:
        raise PromotedKirinError("promoted Kirin pack schema mismatch")
    if payload.get("pack_id") != PACK_ID:
        raise PromotedKirinError("promoted Kirin pack id mismatch")
    if payload.get("includes_execution") is not False:
        raise PromotedKirinError("promoted Kirin pack may not include execution")
    if payload.get("write_allowed") is not False:
        raise PromotedKirinError("promoted Kirin pack may not grant write authority")

    source = payload.get("source")
    if not isinstance(source, Mapping):
        raise PromotedKirinError("promoted Kirin source provenance is missing")
    expected_source = {
        "repository": SOURCE_REPOSITORY,
        "commit": SOURCE_COMMIT,
        "manifest_path": "packs/kirin/manifest.json",
        "manifest_sha256": SOURCE_MANIFEST_SHA256,
        "source_maturity": "replay_supported",
    }
    for key, expected in expected_source.items():
        if source.get(key) != expected:
            raise PromotedKirinError(f"promoted Kirin source {key} mismatch")

    rules = payload.get("rules")
    if not isinstance(rules, list) or not rules:
        raise PromotedKirinError("promoted Kirin rules are missing")
    rule_ids: list[str] = []
    for item in rules:
        if not isinstance(item, Mapping):
            raise PromotedKirinError("promoted Kirin rule must be an object")
        rule_id = item.get("id")
        if not isinstance(rule_id, str) or not rule_id:
            raise PromotedKirinError("promoted Kirin rule id is invalid")
        if item.get("evidence_level") != "replay_supported":
            raise PromotedKirinError(f"promoted Kirin rule {rule_id} overstates maturity")
        statement = item.get("statement")
        if not isinstance(statement, str) or not statement.strip():
            raise PromotedKirinError(f"promoted Kirin rule {rule_id} has no statement")
        rule_ids.append(rule_id)
    if len(rule_ids) != len(set(rule_ids)):
        raise PromotedKirinError("promoted Kirin rule ids must be unique")
    if not REQUIRED_RULE_IDS.issubset(set(rule_ids)):
        raise PromotedKirinError("promoted Kirin VOG explanation rules are incomplete")

    limitations = payload.get("limitations")
    if not isinstance(limitations, list) or not limitations:
        raise PromotedKirinError("promoted Kirin limitations are required")

    _reject_authority_keys(payload)


def explain_vog_replay(evidence: Mapping[str, Any]) -> dict[str, Any]:
    pack = load_promoted_vog_pack()
    normalized: dict[str, bool] = {}
    for field in REQUIRED_EVIDENCE_FIELDS:
        value = evidence.get(field)
        if not isinstance(value, bool):
            raise PromotedKirinError(f"VOG replay evidence field {field} must be boolean")
        normalized[field] = value

    findings: list[dict[str, str]] = []

    main_version_explained = (
        normalized["version_artifact_valid"]
        and normalized["version_write_accepted"]
        and not normalized["main_version_after_version_write"]
        and not normalized["writable_verlist_partition_observed"]
        and not normalized["oeminfo_version_identity_present"]
    )
    if main_version_explained:
        findings.append(
            {
                "code": "VOG_MAIN_VERSION_OEMINFO_CAUSAL_EXPLANATION",
                "rule_id": "vog.main_version_state.oeminfo",
            }
        )

    premature_release_hazard = (
        normalized["service_mode_required_for_unresolved_repair"]
        and normalized["stock_fastboot_restored_before_release"]
        and not normalized["release_conditions_verified"]
    )
    if premature_release_hazard:
        findings.extend(
            [
                {
                    "code": "VOG_SERVICE_MODE_PREMATURE_RELEASE_HAZARD",
                    "rule_id": "vog.service_mode.preserve_until_verified",
                },
                {
                    "code": "VOG_STOCK_FASTBOOT_FINALIZATION_ONLY",
                    "rule_id": "vog.stock_fastboot.finalization_only",
                },
            ]
        )

    branding_separate = (
        normalized["core_boot_recovered"] and normalized["branding_mismatch_remaining"]
    )
    if branding_separate:
        findings.append(
            {
                "code": "VOG_BRANDING_NORMALIZATION_SEPARATE_STAGE",
                "rule_id": "vog.branding.separate_stage",
            }
        )

    used_rule_ids = {item["rule_id"] for item in findings}
    missing = sorted(REQUIRED_RULE_IDS - used_rule_ids)
    return {
        "schema": "ttg-device-xray.vog-promoted-explanation.v1",
        "pack_id": pack["pack_id"],
        "pack_version": pack["pack_version"],
        "source_commit": pack["source"]["commit"],
        "source_manifest_sha256": pack["source"]["manifest_sha256"],
        "evidence_level": "replay_supported",
        "findings": findings,
        "required_rule_ids": sorted(REQUIRED_RULE_IDS),
        "missing_rule_explanations": missing,
        "independently_explains_frozen_vog_case": not missing,
        "physical_hardware_certification": "NOT_CLAIMED",
        "execution_authority": "none",
        "write_allowed": False,
    }


def _reject_authority_keys(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            key_text = str(key)
            if key_text in FORBIDDEN_AUTHORITY_KEYS:
                joined = ".".join((*path, key_text))
                raise PromotedKirinError(f"forbidden execution authority key in promoted pack: {joined}")
            _reject_authority_keys(child, (*path, key_text))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_authority_keys(child, (*path, str(index)))
