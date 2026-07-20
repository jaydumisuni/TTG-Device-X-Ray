from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from .models import (
    Certification,
    CertificationVerdict,
    ChallengeFinding,
    DeviceIdentity,
    ScanBundle,
    TransportKind,
    TransportObservation,
)


class XRayPipeline:
    """PROBE -> MAP -> CORRELATE -> CHALLENGE -> CERTIFY -> PLAN."""

    def __init__(self, probes: Iterable[object]) -> None:
        self.probes = list(probes)

    def scan(self, mission: str = "identify-and-plan") -> ScanBundle:
        observations: list[TransportObservation] = []
        for probe in self.probes:
            observations.extend(probe.probe())

        identity = self._correlate(observations)
        challenges = self._challenge(observations, identity)
        certification = self._certify(observations, identity, challenges)
        plan = self._plan(observations, identity, certification)
        return ScanBundle(
            scan_id=f"xray-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}",
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            mission={"name": mission, "read_only": True},
            observations=observations,
            identity=identity,
            challenges=challenges,
            certification=certification,
            plan=plan,
        )

    @staticmethod
    def _correlate(observations: list[TransportObservation]) -> DeviceIdentity:
        identity = DeviceIdentity()
        for observation in observations:
            if not observation.connected:
                continue
            ids = observation.identifiers
            identity.evidence_sources.append(observation.transport.value)
            identity.active_mode = observation.mode

            if observation.transport == TransportKind.ADB:
                identity.platform = "android"
                identity.brand = ids.get("brand", identity.brand)
                identity.manufacturer = ids.get("manufacturer", identity.manufacturer)
                identity.marketing_model = ids.get("model", identity.marketing_model)
                identity.internal_model = ids.get("device", identity.internal_model)
                identity.board = ids.get("board", identity.board)
                identity.chipset = ids.get("soc", ids.get("hardware", identity.chipset))
                identity.serial = ids.get("serial", identity.serial)
                identity.firmware_version = ids.get("android", identity.firmware_version)
                identity.build = ids.get("build", ids.get("fingerprint", identity.build))
                identity.security_patch = ids.get("security_patch", identity.security_patch)
                identity.storage_type = ids.get("storage_type", identity.storage_type)

            elif observation.transport == TransportKind.FASTBOOT:
                if identity.platform == "unknown":
                    identity.platform = "android"
                identity.internal_model = ids.get("product", identity.internal_model)
                identity.serial = ids.get("serial", ids.get("serialno", identity.serial))
                identity.build = ids.get("version-bootloader", identity.build)

            elif observation.transport == TransportKind.APPLE_NORMAL:
                identity.platform = "apple"
                identity.brand = "Apple"
                identity.manufacturer = "Apple"
                identity.product_type = ids.get("ProductType", identity.product_type)
                identity.internal_model = ids.get("HardwareModel", identity.internal_model)
                identity.marketing_model = ids.get("DeviceName", identity.marketing_model)
                identity.serial = ids.get("SerialNumber", ids.get("udid", identity.serial))
                identity.firmware_version = ids.get("ProductVersion", identity.firmware_version)
                identity.build = ids.get("BuildVersion", identity.build)

            elif observation.transport in {
                TransportKind.APPLE_RECOVERY,
                TransportKind.APPLE_DFU,
            }:
                identity.platform = "apple"
                identity.brand = "Apple"
                identity.manufacturer = "Apple"
                identity.internal_model = ids.get("MODEL", identity.internal_model)
                identity.board = ids.get("BDID", identity.board)
                identity.chipset = ids.get("CPID", identity.chipset)
                identity.ecid = ids.get("ECID", identity.ecid)
                identity.serial = ids.get("ECID", identity.serial)

        identity.evidence_sources = sorted(set(identity.evidence_sources))
        return identity

    @staticmethod
    def _challenge(
        observations: list[TransportObservation], identity: DeviceIdentity
    ) -> list[ChallengeFinding]:
        findings: list[ChallengeFinding] = []
        connected = [item for item in observations if item.connected]
        platforms = set()
        serials = set()
        for item in connected:
            platforms.add("apple" if item.transport.value.startswith("apple") else "android")
            value = item.identifiers.get("serial") or item.identifiers.get("serialno")
            if value:
                serials.add(value)

        if len(platforms) > 1:
            findings.append(
                ChallengeFinding(
                    severity="critical",
                    code="MULTIPLE_PLATFORM_FAMILIES",
                    message="Apple and Android transports are active in the same scan.",
                    evidence={"platforms": sorted(platforms)},
                )
            )
        if len(serials) > 1:
            findings.append(
                ChallengeFinding(
                    severity="warning",
                    code="MULTIPLE_DEVICE_SERIALS",
                    message="More than one device identity appears in the evidence.",
                    evidence={"serials": sorted(serials)},
                )
            )
        if identity.platform == "android" and identity.chipset:
            soc = identity.chipset.lower()
            brand = identity.brand.lower()
            expected = ("exynos", "universal", "qcom", "sm", "msm")
            if "samsung" in brand and not any(token in soc for token in expected):
                findings.append(
                    ChallengeFinding(
                        severity="warning",
                        code="SAMSUNG_SOC_UNUSUAL",
                        message="Samsung branding and detected SoC require manual correlation.",
                        evidence={"brand": identity.brand, "chipset": identity.chipset},
                    )
                )
        if identity.platform == "apple" and identity.product_type:
            pattern = r"^(iPhone|iPad|iPod|AppleTV|Watch)\d+,\d+$"
            if not re.match(pattern, identity.product_type):
                findings.append(
                    ChallengeFinding(
                        severity="warning",
                        code="APPLE_PRODUCT_TYPE_FORMAT",
                        message="Apple ProductType has an unexpected format.",
                        evidence={"product_type": identity.product_type},
                    )
                )
        if not connected:
            findings.append(
                ChallengeFinding(
                    severity="critical",
                    code="NO_CONNECTED_DEVICE",
                    message="No supported transport reported a connected device.",
                )
            )
        return findings

    @staticmethod
    def _certify(
        observations: list[TransportObservation],
        identity: DeviceIdentity,
        challenges: list[ChallengeFinding],
    ) -> Certification:
        connected = [item for item in observations if item.connected]
        score = 0.0
        reasons: list[str] = []
        blockers = [item.message for item in challenges if item.severity == "critical"]

        if connected:
            score += 0.25
            reasons.append("At least one supported transport is connected.")
        if identity.platform != "unknown":
            score += 0.15
            reasons.append(f"Platform identified as {identity.platform}.")
        if identity.internal_model or identity.product_type:
            score += 0.20
            reasons.append("Internal model or Apple ProductType was observed.")
        if identity.chipset or identity.board:
            score += 0.15
            reasons.append("Chipset or board evidence was observed.")
        if identity.serial or identity.ecid:
            score += 0.10
            reasons.append("A stable device identifier was observed.")
        if identity.build or identity.firmware_version:
            score += 0.10
            reasons.append("Firmware or build evidence was observed.")
        if len(identity.evidence_sources) >= 2:
            score += 0.05
            reasons.append("Multiple transport evidence sources agree.")

        score -= 0.15 * sum(1 for item in challenges if item.severity == "warning")
        score = max(0.0, min(1.0, round(score, 3)))

        if blockers:
            verdict = CertificationVerdict.UNSAFE
        elif score >= 0.80:
            verdict = CertificationVerdict.CERTIFIED
        elif score >= 0.45:
            verdict = CertificationVerdict.INVESTIGATE
        else:
            verdict = CertificationVerdict.UNSAFE

        profile = XRayPipeline._profile_id(identity) if verdict != CertificationVerdict.UNSAFE else None
        return Certification(
            verdict=verdict,
            confidence=score,
            reasons=reasons,
            blockers=blockers,
            profile_id=profile,
            write_allowed=False,
        )

    @staticmethod
    def _profile_id(identity: DeviceIdentity) -> str | None:
        if identity.platform == "apple":
            token = identity.product_type or identity.internal_model
            return f"apple:{token.lower()}" if token else None
        if identity.platform == "android":
            brand = (identity.brand or "generic").lower().replace(" ", "-")
            model = (
                identity.internal_model or identity.marketing_model or "unknown"
            ).lower().replace(" ", "-")
            return f"android:{brand}:{model}"
        return None

    @staticmethod
    def _plan(
        observations: list[TransportObservation],
        identity: DeviceIdentity,
        certification: Certification,
    ) -> dict[str, object]:
        connected_modes = [item.mode for item in observations if item.connected]
        partition_count = sum(len(item.partitions) for item in observations)
        if certification.verdict == CertificationVerdict.CERTIFIED:
            action = "MATCH_PROFILE_AND_PREPARE_REVIEWED_ADAPTER"
        elif certification.verdict == CertificationVerdict.INVESTIGATE:
            action = "HUNTER_OR_CODE_AGENT_REVIEW"
        else:
            action = "STOP_NO_WRITE_WORKFLOW"

        return {
            "recommended_action": action,
            "read_only_complete": True,
            "write_allowed": False,
            "active_modes": connected_modes,
            "partition_entries_observed": partition_count,
            "next_consumers": [
                "Hunter",
                "TechGuy Tool",
                "firmware matcher",
                "flash planner",
                "unbrick planner",
            ],
            "identity_summary": {
                "platform": identity.platform,
                "brand": identity.brand,
                "model": identity.product_type
                or identity.internal_model
                or identity.marketing_model,
                "chipset": identity.chipset,
            },
        }


def write_bundle(bundle: ScanBundle, output_root: Path) -> Path:
    target = output_root / bundle.scan_id
    target.mkdir(parents=True, exist_ok=False)

    observations = [item.to_dict() for item in bundle.observations]
    partitions = [
        {"transport": item.transport.value, **partition}
        for item in bundle.observations
        for partition in item.partitions
    ]
    files = {
        "mission.json": bundle.mission,
        "transport_evidence.json": observations,
        "device_identity.json": bundle.identity.to_dict(),
        "partition_map.json": {"partitions": partitions},
        "challenger_findings.json": {
            "findings": [item.to_dict() for item in bundle.challenges]
        },
        "certification.json": bundle.certification.to_dict(),
        "recommended_plan.json": bundle.plan,
    }
    for name, payload in files.items():
        (target / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    audit_path = target / "audit.jsonl"
    with audit_path.open("w", encoding="utf-8") as stream:
        stream.write(json.dumps({"event": "SCAN_CREATED", "scan_id": bundle.scan_id}) + "\n")
        for observation in observations:
            stream.write(
                json.dumps(
                    {
                        "event": "TRANSPORT_OBSERVED",
                        "transport": observation["transport"],
                        "connected": observation["connected"],
                        "mode": observation["mode"],
                    }
                )
                + "\n"
            )
        stream.write(
            json.dumps(
                {
                    "event": "CERTIFICATION",
                    "verdict": bundle.certification.verdict.value,
                    "confidence": bundle.certification.confidence,
                }
            )
            + "\n"
        )
    return target
