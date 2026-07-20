from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .candidate_grouping import GroupedCandidate, ObservationGrouper
from .models import (
    Certification,
    CertificationDimensions,
    CertificationVerdict,
    ChallengeFinding,
    DeviceCandidate,
    DeviceIdentity,
    FirmwareFingerprint,
    ScanBundle,
    StorageSummary,
    TransportKind,
    TransportObservation,
)


APPLE_TRANSPORTS = {
    TransportKind.APPLE_NORMAL,
    TransportKind.APPLE_RECOVERY,
    TransportKind.APPLE_DFU,
}


class XRayPipeline:
    """PROBE -> NORMALIZE -> GROUP -> CORRELATE -> MAP -> CHALLENGE -> CERTIFY -> PLAN."""

    def __init__(self, probes: Iterable[object]) -> None:
        self.probes = list(probes)

    def scan(self, mission: str = "identify-and-plan") -> ScanBundle:
        observations: list[TransportObservation] = []
        for probe in self.probes:
            observations.extend(probe.probe())

        grouped = ObservationGrouper.group(observations)
        candidates = [self._build_candidate(item) for item in grouped]
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        scan_id = f"xray-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:8]}"

        if len(candidates) == 1:
            selected = candidates[0]
            identity = selected.identity
            firmware = selected.firmware
            storage = selected.storage
            challenges = selected.challenges
            certification = selected.certification
            plan = self._plan(
                selected.observations,
                identity,
                firmware,
                storage,
                certification,
                challenges,
            )
            selected_candidate_id = selected.candidate_id
        else:
            identity = DeviceIdentity()
            firmware = self._fingerprint_firmware([], identity)
            storage = self._summarize_storage([], identity)
            if candidates:
                challenges = [
                    ChallengeFinding(
                        severity="critical",
                        code="MULTIPLE_DEVICE_CANDIDATES",
                        message=(
                            "More than one physical device candidate is connected. "
                            "Select one candidate and rescan before adapter consumption."
                        ),
                        evidence={
                            "candidate_ids": [item.candidate_id for item in candidates],
                            "candidate_count": len(candidates),
                        },
                    )
                ]
            else:
                challenges = [
                    ChallengeFinding(
                        severity="critical",
                        code="NO_CONNECTED_DEVICE",
                        message="No supported transport reported a connected device.",
                    )
                ]
            certification = self._certify([], identity, firmware, storage, challenges)
            plan = self._plan([], identity, firmware, storage, certification, challenges)
            plan["candidate_count"] = len(candidates)
            plan["candidate_ids"] = [item.candidate_id for item in candidates]
            plan["recommended_action"] = (
                "SELECT_SINGLE_DEVICE_CANDIDATE" if candidates else "STOP_NO_WRITE_WORKFLOW"
            )
            selected_candidate_id = None

        return ScanBundle(
            scan_id=scan_id,
            created_at=created_at,
            mission={
                "name": mission,
                "read_only": True,
                "pipeline": (
                    "PROBE->NORMALIZE->GROUP->CORRELATE->FINGERPRINT->MAP->"
                    "CHALLENGE->CERTIFY->PROFILE->PLAN->SEAL"
                ),
            },
            observations=observations,
            candidates=candidates,
            selected_candidate_id=selected_candidate_id,
            identity=identity,
            firmware=firmware,
            storage=storage,
            challenges=challenges,
            certification=certification,
            plan=plan,
        )

    def _build_candidate(self, grouped: GroupedCandidate) -> DeviceCandidate:
        identity = self._correlate(grouped.observations)
        firmware = self._fingerprint_firmware(grouped.observations, identity)
        storage = self._summarize_storage(grouped.observations, identity)
        challenges = self._challenge(grouped.observations, identity, firmware, storage)
        certification = self._certify(
            grouped.observations,
            identity,
            firmware,
            storage,
            challenges,
            link_confidence=grouped.link_confidence,
        )
        return DeviceCandidate(
            candidate_id=grouped.candidate_id,
            observation_indexes=grouped.observation_indexes,
            observations=grouped.observations,
            link_confidence=grouped.link_confidence,
            link_evidence=grouped.link_evidence,
            identity=identity,
            firmware=firmware,
            storage=storage,
            challenges=challenges,
            certification=certification,
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
                identity.product_name = ids.get("product", identity.product_name)
                identity.board = ids.get("board", identity.board)
                identity.chipset = ids.get("soc", ids.get("hardware", identity.chipset))
                identity.serial = ids.get("serial", identity.serial)
                identity.firmware_version = ids.get("android", identity.firmware_version)
                identity.build = ids.get("build", identity.build)
                identity.build_fingerprint = ids.get("fingerprint", identity.build_fingerprint)
                identity.security_patch = ids.get("security_patch", identity.security_patch)
                identity.baseband = ids.get("baseband", identity.baseband)
                identity.bootloader = ids.get("bootloader", identity.bootloader)
                identity.kernel = ids.get("kernel", identity.kernel)
                identity.storage_type = ids.get("storage_type", identity.storage_type)
                identity.storage_model = ids.get("storage_model", identity.storage_model)
                capacity = ids.get("storage_capacity_bytes", "")
                if str(capacity).isdigit():
                    identity.storage_capacity_bytes = int(capacity)
                identity.slot_suffix = ids.get("slot_suffix", identity.slot_suffix)
                identity.dynamic_partitions = identity.dynamic_partitions or bool(
                    observation.capabilities.get("dynamic_partitions_detected")
                )
                identity.verified_boot_state = ids.get(
                    "verified_boot_state", identity.verified_boot_state
                )
                locked = observation.capabilities.get("bootloader_locked")
                if isinstance(locked, bool):
                    identity.bootloader_locked = locked

            elif observation.transport == TransportKind.FASTBOOT:
                if identity.platform == "unknown":
                    identity.platform = "android"
                identity.internal_model = ids.get("product", identity.internal_model)
                identity.serial = ids.get("serial", ids.get("serialno", identity.serial))
                identity.bootloader = ids.get("version-bootloader", identity.bootloader)
                identity.baseband = ids.get("version-baseband", identity.baseband)
                current_slot = ids.get("current-slot", "")
                if current_slot:
                    identity.slot_suffix = current_slot
                locked = observation.capabilities.get("bootloader_locked")
                if isinstance(locked, bool):
                    identity.bootloader_locked = locked
                identity.dynamic_partitions = identity.dynamic_partitions or bool(
                    observation.capabilities.get("dynamic_partitions_detected")
                )

            elif observation.transport == TransportKind.APPLE_NORMAL:
                identity.platform = "apple"
                identity.brand = "Apple"
                identity.manufacturer = "Apple"
                identity.product_type = ids.get("ProductType", identity.product_type)
                identity.product_name = ids.get("ProductName", identity.product_name)
                identity.internal_model = ids.get("HardwareModel", identity.internal_model)
                identity.marketing_model = ids.get("DeviceName", identity.marketing_model)
                identity.udid = ids.get("udid", ids.get("UniqueDeviceID", identity.udid))
                identity.apple_serial = ids.get("SerialNumber", identity.apple_serial)
                identity.imei = ids.get(
                    "InternationalMobileEquipmentIdentity", identity.imei
                )
                identity.firmware_version = ids.get(
                    "ProductVersion", identity.firmware_version
                )
                identity.build = ids.get("BuildVersion", identity.build)
                identity.baseband = ids.get("BasebandVersion", identity.baseband)
                identity.chipset = ids.get("ChipID", identity.chipset)
                identity.board = ids.get("BoardId", identity.board)

            elif observation.transport in {TransportKind.APPLE_RECOVERY, TransportKind.APPLE_DFU}:
                identity.platform = "apple"
                identity.brand = "Apple"
                identity.manufacturer = "Apple"
                identity.product_type = ids.get("PRODUCT", identity.product_type)
                identity.internal_model = ids.get("MODEL", identity.internal_model)
                identity.board = ids.get("BDID", identity.board)
                identity.chipset = ids.get("CPID", identity.chipset)
                identity.ecid = ids.get("ECID", identity.ecid)
                identity.bootloader = ids.get("IBFL", ids.get("IBOOT", identity.bootloader))

        identity.evidence_sources = sorted(set(identity.evidence_sources))
        return identity

    @staticmethod
    def _fingerprint_firmware(
        observations: list[TransportObservation], identity: DeviceIdentity
    ) -> FirmwareFingerprint:
        if identity.platform == "apple":
            canonical: dict[str, Any] = {
                "platform": "apple",
                "product_type": identity.product_type,
                "hardware_model": identity.internal_model,
                "board_id": identity.board,
                "chip_id": identity.chipset,
                "product_version": identity.firmware_version,
                "build_version": identity.build,
                "baseband": identity.baseband,
                "bootloader": identity.bootloader,
            }
            important = ["product_type", "hardware_model", "chip_id", "build_version"]
        else:
            adb_ids: dict[str, str] = {}
            for item in observations:
                if item.connected and item.transport == TransportKind.ADB:
                    adb_ids.update(item.identifiers)
            canonical = {
                "platform": identity.platform,
                "brand": identity.brand,
                "manufacturer": identity.manufacturer,
                "model": identity.marketing_model,
                "device": identity.internal_model,
                "product": identity.product_name,
                "board": identity.board,
                "soc": identity.chipset,
                "android": identity.firmware_version,
                "build": identity.build,
                "fingerprint": identity.build_fingerprint,
                "security_patch": identity.security_patch,
                "baseband": identity.baseband,
                "bootloader": identity.bootloader,
                "first_api_level": adb_ids.get("first_api_level", ""),
                "vndk": adb_ids.get("vndk", ""),
                "verified_boot_state": identity.verified_boot_state,
            }
            important = ["brand", "device", "soc", "android", "fingerprint"]

        normalized = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        completeness = round(
            sum(1 for key in important if canonical.get(key)) / max(1, len(important)), 3
        )
        return FirmwareFingerprint(
            platform=identity.platform,
            canonical=canonical,
            fingerprint_sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
            completeness=completeness,
            evidence_sources=identity.evidence_sources.copy(),
        )

    @staticmethod
    def _summarize_storage(
        observations: list[TransportObservation], identity: DeviceIdentity
    ) -> StorageSummary:
        partitions = [
            partition
            for item in observations
            if item.connected
            for partition in item.partitions
        ]
        storage: dict[str, Any] = {}
        dynamic = identity.dynamic_partitions
        ab_slots = bool(identity.slot_suffix)
        for item in observations:
            if not item.connected:
                continue
            candidate = item.capabilities.get("storage")
            if isinstance(candidate, dict) and int(candidate.get("capacity_bytes", 0) or 0) > int(
                storage.get("capacity_bytes", 0) or 0
            ):
                storage = candidate
            dynamic = dynamic or bool(item.capabilities.get("dynamic_partitions_detected"))
            ab_slots = ab_slots or bool(item.capabilities.get("ab_slots"))

        critical = sorted(
            {
                str(item.get("name", ""))
                for item in partitions
                if item.get("risk") == "critical"
            }
        )
        return StorageSummary(
            storage_type=str(storage.get("type", identity.storage_type)),
            model=str(storage.get("model", identity.storage_model)),
            capacity_bytes=int(storage.get("capacity_bytes", identity.storage_capacity_bytes) or 0),
            logical_block_size=int(storage.get("logical_block_size", 0) or 0),
            partition_count=len(partitions),
            total_partition_bytes=sum(int(item.get("size_bytes", 0) or 0) for item in partitions),
            has_super=any(
                str(item.get("name", "")).removesuffix("_a").removesuffix("_b") == "super"
                for item in partitions
            ),
            dynamic_partitions=dynamic,
            ab_slots=ab_slots,
            active_slot=identity.slot_suffix.removeprefix("_"),
            critical_partitions=critical,
        )

    @staticmethod
    def _challenge(
        observations: list[TransportObservation],
        identity: DeviceIdentity,
        firmware: FirmwareFingerprint,
        storage: StorageSummary,
    ) -> list[ChallengeFinding]:
        findings: list[ChallengeFinding] = []
        connected = [item for item in observations if item.connected]
        platforms = {
            "apple" if item.transport in APPLE_TRANSPORTS else "android" for item in connected
        }
        if len(platforms) > 1:
            findings.append(
                ChallengeFinding(
                    severity="critical",
                    code="MULTIPLE_PLATFORM_FAMILIES",
                    message="Apple and Android observations were grouped into one candidate.",
                    evidence={"platforms": sorted(platforms)},
                )
            )

        android_serials = {
            item.identifiers.get("serial") or item.identifiers.get("serialno")
            for item in connected
            if item.transport not in APPLE_TRANSPORTS
        } - {None, ""}
        if len(android_serials) > 1:
            findings.append(
                ChallengeFinding(
                    severity="critical",
                    code="MULTIPLE_DEVICE_SERIALS",
                    message="More than one Android serial exists inside one candidate.",
                    evidence={"serials": sorted(android_serials)},
                )
            )

        apple_identifier_sets = {
            "udids": {
                item.identifiers.get("udid") or item.identifiers.get("UniqueDeviceID")
                for item in connected
                if item.transport in APPLE_TRANSPORTS
            }
            - {None, ""},
            "serial_numbers": {
                item.identifiers.get("SerialNumber")
                for item in connected
                if item.transport in APPLE_TRANSPORTS
            }
            - {None, ""},
            "ecids": {
                item.identifiers.get("ECID")
                for item in connected
                if item.transport in APPLE_TRANSPORTS
            }
            - {None, ""},
        }
        for identifier_type, values in apple_identifier_sets.items():
            if len(values) > 1:
                findings.append(
                    ChallengeFinding(
                        severity="critical",
                        code=f"MULTIPLE_APPLE_{identifier_type.upper()}",
                        message=f"More than one Apple {identifier_type} value exists in one candidate.",
                        evidence={identifier_type: sorted(values)},
                    )
                )

        if identity.platform == "android" and identity.chipset:
            soc = identity.chipset.lower()
            brand = identity.brand.lower()
            expected = (
                "exynos",
                "universal",
                "qcom",
                "sm",
                "msm",
                "mt",
                "dimensity",
                "ums",
                "sprd",
                "sc",
            )
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

        if identity.platform == "android":
            partition_names = [
                str(partition.get("name", ""))
                for item in connected
                for partition in item.partitions
            ]
            duplicate_names = sorted(
                {name for name in partition_names if partition_names.count(name) > 1}
            )
            conflicts: list[dict[str, Any]] = []
            for name in duplicate_names:
                sizes = {
                    int(partition.get("size_bytes", 0) or 0)
                    for item in connected
                    for partition in item.partitions
                    if partition.get("name") == name and int(partition.get("size_bytes", 0) or 0)
                }
                if len(sizes) > 1:
                    conflicts.append({"name": name, "sizes": sorted(sizes)})
            if conflicts:
                findings.append(
                    ChallengeFinding(
                        severity="warning",
                        code="PARTITION_SIZE_CONFLICT",
                        message="Transport sources disagree on one or more partition sizes.",
                        evidence={"conflicts": conflicts},
                    )
                )
            if storage.dynamic_partitions and storage.partition_count and not storage.has_super:
                findings.append(
                    ChallengeFinding(
                        severity="warning",
                        code="DYNAMIC_WITHOUT_SUPER",
                        message="Dynamic partitions were reported but no super partition was mapped.",
                    )
                )
            if identity.bootloader_locked is False:
                findings.append(
                    ChallengeFinding(
                        severity="warning",
                        code="BOOTLOADER_UNLOCKED",
                        message="The bootloader is unlocked; firmware state may differ from factory state.",
                    )
                )
            if identity.verified_boot_state and identity.verified_boot_state.lower() not in {
                "green",
                "locked",
            }:
                findings.append(
                    ChallengeFinding(
                        severity="warning",
                        code="VERIFIED_BOOT_NON_GREEN",
                        message="Verified Boot is not in the normal green state.",
                        evidence={"state": identity.verified_boot_state},
                    )
                )
            if not storage.storage_type and any(
                item.transport == TransportKind.ADB and item.connected for item in connected
            ):
                findings.append(
                    ChallengeFinding(
                        severity="warning",
                        code="STORAGE_TYPE_UNKNOWN",
                        message="Storage technology could not be identified as eMMC, UFS or NVMe.",
                    )
                )

        if firmware.completeness < 0.5 and connected:
            findings.append(
                ChallengeFinding(
                    severity="warning",
                    code="FIRMWARE_FINGERPRINT_INCOMPLETE",
                    message="Firmware evidence is incomplete for exact package matching.",
                    evidence={"completeness": firmware.completeness},
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
        firmware: FirmwareFingerprint,
        storage: StorageSummary,
        challenges: list[ChallengeFinding],
        link_confidence: float = 1.0,
    ) -> Certification:
        connected = [item for item in observations if item.connected]
        stable_identifier = bool(
            identity.serial
            or identity.udid
            or identity.apple_serial
            or identity.ecid
        )
        identity_signals = [
            identity.platform != "unknown",
            bool(identity.internal_model or identity.product_type),
            bool(identity.chipset or identity.board),
            stable_identifier,
        ]
        identity_confidence = round(sum(identity_signals) / len(identity_signals), 3)
        transport_confidence = round(link_confidence if connected else 0.0, 3)
        firmware_confidence = round(firmware.completeness, 3)

        storage_signals = [
            bool(storage.storage_type),
            storage.capacity_bytes > 0,
            bool(storage.model),
        ]
        storage_confidence = round(sum(storage_signals) / len(storage_signals), 3)

        partition_entries = [
            partition
            for item in connected
            for partition in item.partitions
        ]
        if partition_entries:
            sized = sum(1 for item in partition_entries if int(item.get("size_bytes", 0) or 0) > 0)
            partition_confidence = round(0.5 + (0.5 * sized / len(partition_entries)), 3)
        else:
            partition_confidence = 0.0

        dimensions = CertificationDimensions(
            identity_confidence=identity_confidence,
            transport_confidence=transport_confidence,
            firmware_confidence=firmware_confidence,
            storage_confidence=storage_confidence,
            partition_map_confidence=partition_confidence,
            profile_match_confidence=0.0,
            freshness_confidence=1.0 if connected else 0.0,
        )
        score = (
            0.30 * identity_confidence
            + 0.20 * transport_confidence
            + 0.20 * firmware_confidence
            + 0.10 * storage_confidence
            + 0.10 * partition_confidence
            + 0.10 * dimensions.freshness_confidence
        )
        score -= 0.05 * sum(1 for item in challenges if item.severity == "warning")
        score = max(0.0, min(1.0, round(score, 3)))

        blockers = [item.message for item in challenges if item.severity == "critical"]
        reasons = [
            f"identity_confidence={identity_confidence}",
            f"transport_confidence={transport_confidence}",
            f"firmware_confidence={firmware_confidence}",
            f"storage_confidence={storage_confidence}",
            f"partition_map_confidence={partition_confidence}",
            f"freshness_confidence={dimensions.freshness_confidence}",
        ]
        if blockers:
            verdict = CertificationVerdict.UNSAFE
        elif score >= 0.80:
            verdict = CertificationVerdict.CERTIFIED
        elif score >= 0.45:
            verdict = CertificationVerdict.INVESTIGATE
        else:
            verdict = CertificationVerdict.UNSAFE

        proposal = (
            XRayPipeline._proposed_profile_id(identity)
            if verdict != CertificationVerdict.UNSAFE
            else None
        )
        return Certification(
            verdict=verdict,
            confidence=score,
            reasons=reasons,
            blockers=blockers,
            proposed_profile_id=proposal,
            dimensions=dimensions,
            write_allowed=False,
        )

    @staticmethod
    def _proposed_profile_id(identity: DeviceIdentity) -> str | None:
        if identity.platform == "apple":
            token = identity.product_type or identity.internal_model
            return f"apple:{token.lower()}" if token else None
        if identity.platform == "android":
            brand = (identity.brand or "generic").lower().replace(" ", "-")
            model = (
                identity.internal_model or identity.marketing_model or "unknown"
            ).lower().replace(" ", "-")
            chipset = (identity.chipset or "unknown").lower().replace(" ", "-")
            return f"android:{brand}:{model}:{chipset}"
        return None

    @staticmethod
    def _plan(
        observations: list[TransportObservation],
        identity: DeviceIdentity,
        firmware: FirmwareFingerprint,
        storage: StorageSummary,
        certification: Certification,
        challenges: list[ChallengeFinding],
    ) -> dict[str, object]:
        connected_modes = [item.mode for item in observations if item.connected]
        if certification.verdict == CertificationVerdict.CERTIFIED:
            action = "RESOLVE_APPROVED_PROFILE_AND_PREPARE_REVIEWED_ADAPTER"
        elif certification.verdict == CertificationVerdict.INVESTIGATE:
            action = "HUNTER_OR_CODE_AGENT_REVIEW"
        else:
            action = "STOP_NO_WRITE_WORKFLOW"

        return {
            "recommended_action": action,
            "read_only_complete": True,
            "write_allowed": False,
            "active_modes": connected_modes,
            "partition_entries_observed": storage.partition_count,
            "firmware_fingerprint": firmware.fingerprint_sha256,
            "firmware_completeness": firmware.completeness,
            "proposed_profile_id": certification.proposed_profile_id,
            "certification_dimensions": certification.dimensions.to_dict(),
            "flash_safety_signals": {
                "exact_firmware_fingerprint_ready": firmware.completeness >= 0.8,
                "partition_layout_mapped": storage.partition_count > 0,
                "storage_capacity_known": storage.capacity_bytes > 0,
                "ab_slots": storage.ab_slots,
                "dynamic_partitions": storage.dynamic_partitions,
                "bootloader_locked": identity.bootloader_locked,
                "verified_boot_state": identity.verified_boot_state,
                "critical_partition_backups_required": storage.critical_partitions,
            },
            "challenge_codes": [item.code for item in challenges],
            "next_consumers": [
                "Hunter",
                "Ptah Detector Observations",
                "TechGuy Tool",
                "firmware matcher",
                "flash planner",
                "unbrick planner",
                "Apple IPSW matcher",
            ],
            "identity_summary": {
                "platform": identity.platform,
                "brand": identity.brand,
                "model": identity.product_type
                or identity.internal_model
                or identity.marketing_model,
                "chipset": identity.chipset,
                "storage": storage.storage_type,
                "capacity_bytes": storage.capacity_bytes,
            },
        }


def write_bundle(bundle: ScanBundle, output_root: Path) -> Path:
    target = output_root / bundle.scan_id
    target.mkdir(parents=True, exist_ok=False)

    observations = [item.to_dict() for item in bundle.observations]
    selected = next(
        (item for item in bundle.candidates if item.candidate_id == bundle.selected_candidate_id),
        None,
    )
    selected_observations = selected.observations if selected else []
    partitions = [
        {"transport": item.transport.value, **partition}
        for item in selected_observations
        for partition in item.partitions
    ]
    files = {
        "mission.json": bundle.mission,
        "transport_evidence.json": observations,
        "device_candidates.json": {
            "selected_candidate_id": bundle.selected_candidate_id,
            "candidate_count": len(bundle.candidates),
            "candidates": [item.to_dict() for item in bundle.candidates],
        },
        "device_identity.json": bundle.identity.to_dict(),
        "storage_summary.json": bundle.storage.to_dict(),
        "partition_map.json": {
            "candidate_id": bundle.selected_candidate_id,
            "summary": bundle.storage.to_dict(),
            "partitions": partitions,
        },
        "firmware_fingerprint.json": bundle.firmware.to_dict(),
        "challenger_findings.json": {
            "findings": [item.to_dict() for item in bundle.challenges]
        },
        "certification.json": bundle.certification.to_dict(),
        "recommended_plan.json": bundle.plan,
    }
    for name, payload in files.items():
        (target / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    candidates_root = target / "candidates"
    for candidate in bundle.candidates:
        candidate_dir = candidates_root / candidate.candidate_id
        candidate_dir.mkdir(parents=True, exist_ok=False)
        candidate_partitions = [
            {"transport": item.transport.value, **partition}
            for item in candidate.observations
            for partition in item.partitions
        ]
        candidate_files = {
            "candidate.json": candidate.to_dict(),
            "device_identity.json": candidate.identity.to_dict(),
            "firmware_fingerprint.json": candidate.firmware.to_dict(),
            "storage_summary.json": candidate.storage.to_dict(),
            "partition_map.json": {
                "candidate_id": candidate.candidate_id,
                "summary": candidate.storage.to_dict(),
                "partitions": candidate_partitions,
            },
            "challenger_findings.json": {
                "findings": [item.to_dict() for item in candidate.challenges]
            },
            "certification.json": candidate.certification.to_dict(),
        }
        for name, payload in candidate_files.items():
            (candidate_dir / name).write_text(json.dumps(payload, indent=2), encoding="utf-8")

    audit_path = target / "audit.jsonl"
    with audit_path.open("w", encoding="utf-8") as stream:
        stream.write(
            json.dumps(
                {
                    "event": "SCAN_CREATED",
                    "scan_id": bundle.scan_id,
                    "schema_version": bundle.schema_version,
                }
            )
            + "\n"
        )
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
        for candidate in bundle.candidates:
            stream.write(
                json.dumps(
                    {
                        "event": "DEVICE_CANDIDATE",
                        "candidate_id": candidate.candidate_id,
                        "observation_indexes": candidate.observation_indexes,
                        "link_confidence": candidate.link_confidence,
                        "verdict": candidate.certification.verdict.value,
                    }
                )
                + "\n"
            )
        stream.write(
            json.dumps(
                {
                    "event": "FIRMWARE_FINGERPRINT",
                    "sha256": bundle.firmware.fingerprint_sha256,
                    "completeness": bundle.firmware.completeness,
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
                    "dimensions": bundle.certification.dimensions.to_dict(),
                    "selected_candidate_id": bundle.selected_candidate_id,
                }
            )
            + "\n"
        )
    return target
