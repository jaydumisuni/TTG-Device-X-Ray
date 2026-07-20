from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class TransportKind(str, Enum):
    ADB = "adb"
    FASTBOOT = "fastboot"
    APPLE_NORMAL = "apple_normal"
    APPLE_RECOVERY = "apple_recovery"
    APPLE_DFU = "apple_dfu"


class CertificationVerdict(str, Enum):
    CERTIFIED = "CERTIFIED"
    INVESTIGATE = "INVESTIGATE"
    UNSAFE = "UNSAFE"


@dataclass(slots=True)
class CommandEvidence:
    command: list[str]
    return_code: int
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class TransportObservation:
    transport: TransportKind
    available: bool
    connected: bool
    mode: str
    identifiers: dict[str, str] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)
    partitions: list[dict[str, Any]] = field(default_factory=list)
    commands: list[CommandEvidence] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["transport"] = self.transport.value
        return payload


@dataclass(slots=True)
class DeviceIdentity:
    platform: str = "unknown"
    brand: str = ""
    manufacturer: str = ""
    marketing_model: str = ""
    internal_model: str = ""
    product_name: str = ""
    product_type: str = ""
    board: str = ""
    chipset: str = ""
    serial: str = ""
    ecid: str = ""
    imei: str = ""
    firmware_version: str = ""
    build: str = ""
    build_fingerprint: str = ""
    security_patch: str = ""
    baseband: str = ""
    bootloader: str = ""
    kernel: str = ""
    storage_type: str = ""
    storage_model: str = ""
    storage_capacity_bytes: int = 0
    slot_suffix: str = ""
    dynamic_partitions: bool = False
    verified_boot_state: str = ""
    bootloader_locked: bool | None = None
    active_mode: str = "unknown"
    evidence_sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class FirmwareFingerprint:
    platform: str
    canonical: dict[str, Any]
    fingerprint_sha256: str
    completeness: float
    evidence_sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class StorageSummary:
    storage_type: str = ""
    model: str = ""
    capacity_bytes: int = 0
    logical_block_size: int = 0
    partition_count: int = 0
    total_partition_bytes: int = 0
    has_super: bool = False
    dynamic_partitions: bool = False
    ab_slots: bool = False
    active_slot: str = ""
    critical_partitions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ChallengeFinding:
    severity: str
    code: str
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class Certification:
    verdict: CertificationVerdict
    confidence: float
    reasons: list[str]
    blockers: list[str]
    profile_id: str | None = None
    write_allowed: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["verdict"] = self.verdict.value
        return payload


@dataclass(slots=True)
class ScanBundle:
    scan_id: str
    created_at: str
    mission: dict[str, Any]
    observations: list[TransportObservation]
    identity: DeviceIdentity
    firmware: FirmwareFingerprint
    storage: StorageSummary
    challenges: list[ChallengeFinding]
    certification: Certification
    plan: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "created_at": self.created_at,
            "mission": self.mission,
            "observations": [item.to_dict() for item in self.observations],
            "identity": self.identity.to_dict(),
            "firmware": self.firmware.to_dict(),
            "storage": self.storage.to_dict(),
            "challenges": [item.to_dict() for item in self.challenges],
            "certification": self.certification.to_dict(),
            "plan": self.plan,
        }
