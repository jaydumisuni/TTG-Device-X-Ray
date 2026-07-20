from __future__ import annotations

from collections.abc import Mapping
from typing import Any


READY_STATUS = "MATCHED"
CANDIDATE_STATUSES = {"CANDIDATE", "CANDIDATE_PROFILE"}


def build_repair_readiness(profile_match: Mapping[str, Any] | None) -> dict[str, Any]:
    """Describe adapter readiness independently from identity certification.

    X-Ray can certify the observed device identity while still refusing to route
    a repair adapter. This payload makes that distinction explicit for the CLI,
    Qt UI, Hunter and downstream tools.
    """

    match = profile_match if isinstance(profile_match, Mapping) else {}
    status = str(match.get("status", "NO_PROFILE") or "NO_PROFILE").upper()
    profile_id = str(match.get("profile_id", "") or "")
    adapters = match.get("adapter_contracts", {})
    adapter_contracts = dict(adapters) if isinstance(adapters, Mapping) else {}

    profile_ready = status == READY_STATUS and bool(profile_id)
    adapters_available = profile_ready and bool(adapter_contracts)
    review_required = status in CANDIDATE_STATUSES

    if profile_ready:
        message = (
            "Approved repair profile matched. Adapter routing is available, "
            "but X-Ray itself remains read-only."
            if adapters_available
            else "Repair profile matched, but no adapter contracts are currently available."
        )
    elif review_required:
        message = (
            "Device identity is certified and a candidate profile was found, "
            "but owner review is required and repair adapters remain locked."
        )
    elif status == "NO_MATCH":
        message = (
            "Device identity may be certified, but no compatible repair profile is available. "
            "Repair adapters remain locked."
        )
    elif status == "NO_SELECTION":
        message = "Select exactly one device candidate before repair-profile routing."
    else:
        message = "No approved repair profile is available. Repair adapters remain locked."

    return {
        "certification_scope": "DEVICE_IDENTITY_EVIDENCE",
        "profile_status": status,
        "profile_id": profile_id or None,
        "profile_ready": profile_ready,
        "review_required": review_required,
        "adapters_available": adapters_available,
        "adapter_contracts": adapter_contracts if adapters_available else {},
        "write_allowed": False,
        "message": message,
    }


def scan_completion_message(summary: Mapping[str, Any] | None) -> str:
    data = summary if isinstance(summary, Mapping) else {}
    verdict = str(data.get("verdict", "COMPLETED") or "COMPLETED").upper()
    scan_id = str(data.get("scan_id", "") or "")
    readiness_value = data.get("repair_readiness")
    readiness = (
        dict(readiness_value)
        if isinstance(readiness_value, Mapping)
        else build_repair_readiness(
            data.get("profile_match") if isinstance(data.get("profile_match"), Mapping) else {}
        )
    )
    profile_status = str(readiness.get("profile_status", "NO_PROFILE"))

    prefix = f"Identity evidence {verdict}"
    if scan_id:
        prefix += f" — {scan_id}"

    if profile_status == READY_STATUS:
        suffix = "Approved repair profile matched."
    elif profile_status in CANDIDATE_STATUSES:
        suffix = "Candidate repair profile found; owner review required and adapters remain locked."
    elif profile_status == "NO_MATCH":
        suffix = "No compatible repair profile; adapters remain locked."
    elif profile_status == "NO_SELECTION":
        suffix = "No single device selected for profile routing."
    else:
        suffix = "No approved repair profile; adapters remain locked."
    return f"{prefix}. {suffix}"
