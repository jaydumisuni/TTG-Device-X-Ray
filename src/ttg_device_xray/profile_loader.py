from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any, Iterable

from .models import (
    DeviceCandidate,
    DeviceIdentity,
    ProfileMatch,
    ScanBundle,
    StorageSummary,
    TransportObservation,
)


@dataclass(slots=True)
class LoadedProfile:
    data: dict[str, Any]
    source: str


class ProfileLoader:
    """Resolve proposed profile IDs against a versioned approved registry.

    Generated profile IDs are only proposals. A profile becomes a match only
    after evidence-weighted comparison against a packaged or explicitly supplied
    registry entry. Profiles never grant write permission.
    """

    def __init__(self, extra_roots: Iterable[Path] | None = None) -> None:
        self.extra_roots = [Path(item) for item in (extra_roots or [])]
        configured = os.environ.get("TTG_XRAY_PROFILE_DIR", "").strip()
        if configured:
            self.extra_roots.extend(
                Path(item) for item in configured.split(os.pathsep) if item.strip()
            )

    def load(self) -> list[LoadedProfile]:
        profiles: list[LoadedProfile] = []
        profiles.extend(self._load_packaged())
        for root in self.extra_roots:
            profiles.extend(self._load_path(root))

        deduplicated: dict[str, LoadedProfile] = {}
        for profile in profiles:
            profile_id = str(profile.data.get("profile_id", "")).strip()
            if profile_id:
                deduplicated[profile_id] = profile
        return list(deduplicated.values())

    def match_bundle(self, bundle: ScanBundle) -> ProfileMatch:
        return self._match(
            requested=bundle.certification.proposed_profile_id or "",
            identity=bundle.identity,
            storage=bundle.storage,
            observations=next(
                (
                    item.observations
                    for item in bundle.candidates
                    if item.candidate_id == bundle.selected_candidate_id
                ),
                [],
            ),
        )

    def match_candidate(self, candidate: DeviceCandidate) -> ProfileMatch:
        if candidate.certification.verdict.value == "UNSAFE":
            return ProfileMatch(
                status="BLOCKED_UNSAFE",
                requested_profile_id=candidate.certification.proposed_profile_id or "",
                reasons=["Profile routing is blocked because candidate certification is UNSAFE."],
                write_allowed=False,
            )
        return self._match(
            requested=candidate.certification.proposed_profile_id or "",
            identity=candidate.identity,
            storage=candidate.storage,
            observations=candidate.observations,
        )

    def apply_bundle_matches(self, bundle: ScanBundle) -> ProfileMatch:
        for candidate in bundle.candidates:
            candidate.profile_match = self.match_candidate(candidate)
            candidate.certification.dimensions.profile_match_confidence = (
                candidate.profile_match.confidence
            )

        selected = next(
            (
                item
                for item in bundle.candidates
                if item.candidate_id == bundle.selected_candidate_id
            ),
            None,
        )
        if selected is not None:
            bundle.profile_match = selected.profile_match
            bundle.certification.dimensions.profile_match_confidence = (
                selected.profile_match.confidence
            )
        else:
            bundle.profile_match = ProfileMatch(
                status="NO_SELECTION" if bundle.candidates else "NO_PROFILE",
                requested_profile_id=bundle.certification.proposed_profile_id or "",
                reasons=[
                    "Select exactly one device candidate before resolving a repair profile."
                    if bundle.candidates
                    else "No connected device candidate was available."
                ],
                write_allowed=False,
            )
        return bundle.profile_match

    def _match(
        self,
        requested: str,
        identity: DeviceIdentity,
        storage: StorageSummary,
        observations: list[TransportObservation],
    ) -> ProfileMatch:
        candidates = [
            self._score(profile, requested, identity, storage, observations)
            for profile in self.load()
        ]
        candidates = [item for item in candidates if item.profile_id]
        if not candidates:
            return ProfileMatch(
                status="NO_PROFILE",
                requested_profile_id=requested,
                reasons=["No device profiles were available."],
                write_allowed=False,
            )

        best = max(candidates, key=lambda item: item.confidence)
        if best.confidence >= 0.80:
            best.status = "MATCHED"
        elif best.confidence >= 0.55:
            best.status = "CANDIDATE"
        else:
            best.status = "NO_MATCH"
            best.profile_id = None
            best.capabilities = {}
            best.adapter_contracts = {}
            best.transport_priority = []
        best.write_allowed = False
        return best

    def write_match(self, bundle: ScanBundle, bundle_dir: Path) -> Path:
        path = bundle_dir / "profile_match.json"
        payload = {
            "selected_candidate_id": bundle.selected_candidate_id,
            "selected": bundle.profile_match.to_dict(),
            "candidates": [
                {
                    "candidate_id": item.candidate_id,
                    "proposed_profile_id": item.certification.proposed_profile_id,
                    "match": item.profile_match.to_dict(),
                }
                for item in bundle.candidates
            ],
            "write_allowed": False,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        for candidate in bundle.candidates:
            candidate_path = bundle_dir / "candidates" / candidate.candidate_id
            if candidate_path.exists():
                (candidate_path / "profile_match.json").write_text(
                    json.dumps(candidate.profile_match.to_dict(), indent=2),
                    encoding="utf-8",
                )
                (candidate_path / "certification.json").write_text(
                    json.dumps(candidate.certification.to_dict(), indent=2),
                    encoding="utf-8",
                )

        audit = bundle_dir / "audit.jsonl"
        with audit.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "event": "PROFILE_MATCH",
                        "selected_candidate_id": bundle.selected_candidate_id,
                        "status": bundle.profile_match.status,
                        "requested_profile_id": bundle.profile_match.requested_profile_id,
                        "profile_id": bundle.profile_match.profile_id,
                        "confidence": bundle.profile_match.confidence,
                        "stage": bundle.profile_match.stage,
                        "write_allowed": False,
                    }
                )
                + "\n"
            )
        return path

    def _score(
        self,
        loaded: LoadedProfile,
        requested: str,
        identity: DeviceIdentity,
        storage: StorageSummary,
        observations: list[TransportObservation],
    ) -> ProfileMatch:
        profile = loaded.data
        profile_id = str(profile.get("profile_id", "")).strip()
        aliases = {self._norm(item) for item in profile.get("aliases", []) if item}
        ids = {self._norm(profile_id), *aliases}
        match = profile.get("match", {}) if isinstance(profile.get("match"), dict) else {}

        weighted: list[tuple[str, float, bool, str]] = []
        if requested:
            exact = self._norm(requested) in ids
            weighted.append(("proposed_profile_id", 0.35, exact, requested))

        self._add_set_rule(
            weighted, "platform", 0.08, identity.platform, match.get("platforms", [])
        )
        self._add_set_rule(
            weighted,
            "brand",
            0.10,
            identity.brand,
            match.get("brands", profile.get("brands", [])),
        )
        self._add_set_rule(
            weighted,
            "internal_model",
            0.18,
            identity.internal_model,
            match.get("internal_models", []),
        )
        self._add_set_rule(
            weighted, "chipset", 0.10, identity.chipset, match.get("chipsets", [])
        )
        self._add_regex_rule(
            weighted, "board", 0.05, identity.board, match.get("board_patterns", [])
        )
        self._add_regex_rule(
            weighted,
            "build",
            0.05,
            identity.build or identity.build_fingerprint,
            match.get("build_patterns", []),
        )
        self._add_set_rule(
            weighted,
            "storage_type",
            0.04,
            storage.storage_type,
            match.get("storage_types", []),
        )

        required_partitions = {
            self._norm(item) for item in match.get("required_partitions", []) if item
        }
        if required_partitions:
            observed = {
                self._norm(partition.get("name", ""))
                for observation in observations
                for partition in observation.partitions
            }
            weighted.append(
                (
                    "required_partitions",
                    0.10,
                    required_partitions.issubset(observed),
                    ",".join(sorted(required_partitions - observed)),
                )
            )

        available_transports = {
            observation.transport.value for observation in observations if observation.connected
        }
        priority = [str(item) for item in profile.get("transport_priority", [])]
        if priority:
            weighted.append(
                (
                    "transport",
                    0.05,
                    any(item in available_transports for item in priority),
                    ",".join(sorted(available_transports)),
                )
            )

        total_weight = sum(weight for _, weight, _, _ in weighted) or 1.0
        matched_weight = sum(weight for _, weight, passed, _ in weighted if passed)
        confidence = round(min(1.0, matched_weight / total_weight), 3)
        reasons = [name for name, _, passed, _ in weighted if passed]
        mismatches = [
            f"{name}: {detail or 'evidence did not match'}"
            for name, _, passed, detail in weighted
            if not passed
        ]

        safety = profile.get("safety", {}) if isinstance(profile.get("safety"), dict) else {}
        if safety.get("write_allowed") is True:
            mismatches.append("profile requested write permission; X-Ray rejected it")
            confidence = 0.0

        return ProfileMatch(
            status="CANDIDATE",
            requested_profile_id=requested,
            profile_id=profile_id,
            stage=str(profile.get("stage", "CANDIDATE")),
            confidence=confidence,
            source=loaded.source,
            reasons=reasons,
            mismatches=mismatches,
            capabilities=self._dict(profile.get("capabilities", {})),
            adapter_contracts=self._dict(profile.get("adapter_contracts", {})),
            transport_priority=priority,
            write_allowed=False,
        )

    @classmethod
    def _add_set_rule(
        cls,
        weighted: list[tuple[str, float, bool, str]],
        name: str,
        weight: float,
        observed: str,
        expected: Any,
    ) -> None:
        values = (
            {cls._norm(item) for item in expected if item}
            if isinstance(expected, list)
            else set()
        )
        if not values:
            return
        normalized = cls._norm(observed)
        weighted.append((name, weight, normalized in values, observed))

    @staticmethod
    def _add_regex_rule(
        weighted: list[tuple[str, float, bool, str]],
        name: str,
        weight: float,
        observed: str,
        patterns: Any,
    ) -> None:
        if not isinstance(patterns, list) or not patterns:
            return
        passed = False
        for pattern in patterns:
            try:
                if re.search(str(pattern), observed or ""):
                    passed = True
                    break
            except re.error:
                continue
        weighted.append((name, weight, passed, observed))

    def _load_packaged(self) -> list[LoadedProfile]:
        root = resources.files("ttg_device_xray").joinpath("profiles")
        return self._walk_resource(root, "package:ttg_device_xray/profiles")

    def _walk_resource(self, root: Any, prefix: str) -> list[LoadedProfile]:
        try:
            entries = list(root.iterdir())
        except (FileNotFoundError, TypeError):
            return []
        result: list[LoadedProfile] = []
        for entry in entries:
            if entry.is_dir():
                result.extend(self._walk_resource(entry, f"{prefix}/{entry.name}"))
            elif entry.name.endswith(".json"):
                try:
                    data = json.loads(entry.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if isinstance(data, dict):
                    result.append(LoadedProfile(data=data, source=f"{prefix}/{entry.name}"))
        return result

    def _load_path(self, root: Path) -> list[LoadedProfile]:
        if not root.exists():
            return []
        paths = [root] if root.is_file() else sorted(root.rglob("*.json"))
        result: list[LoadedProfile] = []
        for path in paths:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict):
                result.append(LoadedProfile(data=data, source=str(path.resolve())))
        return result

    @staticmethod
    def _norm(value: Any) -> str:
        return re.sub(r"[^a-z0-9]+", "-", str(value).strip().lower()).strip("-")

    @staticmethod
    def _dict(value: Any) -> dict[str, Any]:
        return value if isinstance(value, dict) else {}
