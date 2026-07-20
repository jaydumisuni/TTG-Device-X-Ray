from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from .models import TransportKind, TransportObservation


APPLE_TRANSPORTS = {
    TransportKind.APPLE_NORMAL,
    TransportKind.APPLE_RECOVERY,
    TransportKind.APPLE_DFU,
}


@dataclass(slots=True)
class GroupedCandidate:
    candidate_id: str
    observation_indexes: list[int]
    observations: list[TransportObservation]
    link_confidence: float
    link_evidence: list[dict[str, Any]] = field(default_factory=list)


class ObservationGrouper:
    """Group transport observations by physical device before correlation.

    Strong identifiers are never compared across identifier types. In particular,
    Apple ECID, UDID and serial number remain separate identifiers. Apple
    normal/recovery observations may be linked only through corroborating hardware
    evidence and the link confidence is recorded explicitly.
    """

    @classmethod
    def group(cls, observations: list[TransportObservation]) -> list[GroupedCandidate]:
        connected = [(index, item) for index, item in enumerate(observations) if item.connected]
        if not connected:
            return []

        parent = list(range(len(connected)))
        evidence: dict[int, list[dict[str, Any]]] = {index: [] for index in range(len(connected))}
        confidence: dict[int, float] = {index: 1.0 for index in range(len(connected))}

        def find(value: int) -> int:
            while parent[value] != value:
                parent[value] = parent[parent[value]]
                value = parent[value]
            return value

        def union(left: int, right: int, reason: dict[str, Any], score: float) -> None:
            root_left = find(left)
            root_right = find(right)
            if root_left == root_right:
                evidence[root_left].append(reason)
                confidence[root_left] = min(confidence[root_left], score)
                return
            parent[root_right] = root_left
            evidence[root_left].extend(evidence.pop(root_right, []))
            evidence[root_left].append(reason)
            confidence[root_left] = min(confidence[root_left], confidence.pop(root_right, 1.0), score)

        strong_keys = [cls._strong_keys(item) for _, item in connected]
        for left in range(len(connected)):
            for right in range(left + 1, len(connected)):
                shared = strong_keys[left] & strong_keys[right]
                if shared:
                    union(
                        left,
                        right,
                        {
                            "method": "shared_strong_identifier",
                            "keys": sorted(shared),
                            "confidence": 1.0,
                        },
                        1.0,
                    )

        # Apple normal/recovery modes usually expose different identifier types.
        # Correlate only when at least two independent hardware attributes agree.
        for left in range(len(connected)):
            for right in range(left + 1, len(connected)):
                if find(left) == find(right):
                    continue
                left_obs = connected[left][1]
                right_obs = connected[right][1]
                if left_obs.transport not in APPLE_TRANSPORTS or right_obs.transport not in APPLE_TRANSPORTS:
                    continue
                matches = cls._apple_hardware_matches(left_obs, right_obs)
                if len(matches) >= 2:
                    score = round(min(0.95, 0.65 + (0.10 * len(matches))), 3)
                    union(
                        left,
                        right,
                        {
                            "method": "apple_hardware_correlation",
                            "matched_fields": matches,
                            "confidence": score,
                            "note": "ECID, UDID and serial remain distinct identifiers",
                        },
                        score,
                    )

        groups: dict[int, list[int]] = {}
        for item_index in range(len(connected)):
            groups.setdefault(find(item_index), []).append(item_index)

        candidates: list[GroupedCandidate] = []
        for root, members in groups.items():
            observation_indexes = [connected[item][0] for item in members]
            grouped_observations = [connected[item][1] for item in members]
            fingerprint_tokens = sorted(
                {
                    token
                    for member in members
                    for token in strong_keys[member]
                }
                or {
                    cls._observation_fingerprint(observation)
                    for observation in grouped_observations
                }
            )
            digest = hashlib.sha256("|".join(fingerprint_tokens).encode("utf-8")).hexdigest()[:12]
            candidates.append(
                GroupedCandidate(
                    candidate_id=f"candidate-{digest}",
                    observation_indexes=sorted(observation_indexes),
                    observations=grouped_observations,
                    link_confidence=round(confidence.get(find(root), 1.0), 3),
                    link_evidence=evidence.get(find(root), []),
                )
            )

        return sorted(candidates, key=lambda item: item.observation_indexes[0])

    @classmethod
    def _strong_keys(cls, observation: TransportObservation) -> set[str]:
        ids = observation.identifiers
        keys: set[str] = set()

        if observation.transport in APPLE_TRANSPORTS:
            values = {
                "apple_udid": ids.get("udid") or ids.get("UniqueDeviceID"),
                "apple_serial": ids.get("SerialNumber"),
                "apple_ecid": ids.get("ECID"),
            }
        else:
            values = {
                "android_serial": ids.get("serial")
                or ids.get("serialno")
                or ids.get("adb_serial"),
                "usb_pnp": ids.get("pnp_device_id"),
                "usb_path": ids.get("usb_path"),
            }

        for kind, value in values.items():
            normalized = cls._normalize(value)
            if normalized:
                keys.add(f"{kind}:{normalized}")
        return keys

    @classmethod
    def _apple_hardware_matches(
        cls, left: TransportObservation, right: TransportObservation
    ) -> list[str]:
        left_tokens = cls._apple_hardware_tokens(left)
        right_tokens = cls._apple_hardware_tokens(right)
        return sorted(
            key
            for key in left_tokens.keys() & right_tokens.keys()
            if left_tokens[key] and left_tokens[key] == right_tokens[key]
        )

    @classmethod
    def _apple_hardware_tokens(cls, observation: TransportObservation) -> dict[str, str]:
        ids = observation.identifiers
        return {
            "product_type": cls._normalize(ids.get("ProductType") or ids.get("PRODUCT")),
            "hardware_model": cls._normalize(ids.get("HardwareModel") or ids.get("MODEL")),
            "chip_id": cls._normalize_numeric(ids.get("ChipID") or ids.get("CPID")),
            "board_id": cls._normalize_numeric(ids.get("BoardId") or ids.get("BDID")),
        }

    @classmethod
    def _observation_fingerprint(cls, observation: TransportObservation) -> str:
        ids = observation.identifiers
        parts = [
            observation.transport.value,
            observation.mode,
            ids.get("brand", ""),
            ids.get("model", ""),
            ids.get("device", ""),
            ids.get("product", ""),
            ids.get("ProductType", ids.get("PRODUCT", "")),
            ids.get("HardwareModel", ids.get("MODEL", "")),
            ids.get("usb_vid", ""),
            ids.get("usb_pid", ""),
            ids.get("port", ""),
        ]
        return ":".join(cls._normalize(item) for item in parts if item)

    @staticmethod
    def _normalize(value: Any) -> str:
        return re.sub(r"[^a-z0-9]+", "", str(value or "").strip().lower())

    @classmethod
    def _normalize_numeric(cls, value: Any) -> str:
        raw = str(value or "").strip().lower()
        if not raw:
            return ""
        try:
            return str(int(raw, 0))
        except ValueError:
            return cls._normalize(raw)
