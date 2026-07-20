from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .models import ScanBundle


@dataclass(slots=True)
class HunterDelivery:
    attempted: bool
    delivered: bool
    endpoint: str
    status_code: int = 0
    response: str = ""
    error: str = ""
    payload_file: str = ""
    spool_file: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HunterBridge:
    """Post every X-Ray bundle to Hunter and spool failures without blocking scans."""

    DEFAULT_PATH = "/api/device-xray/ingest"

    def __init__(self) -> None:
        self.include_sensitive = os.environ.get(
            "TTG_HUNTER_INCLUDE_SENSITIVE", "0"
        ).strip().lower() in {"1", "true", "yes"}
        self.timeout = self._timeout()

    def deliver(self, bundle: ScanBundle, bundle_dir: Path) -> HunterDelivery:
        payload = self._payload(bundle)
        payload_path = bundle_dir / "hunter_payload.json"
        payload_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        endpoint = self._endpoint()
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "TTG-Device-X-Ray/0.4",
            "X-TTG-Source": "ttg-device-xray",
            "X-TTG-Scan-ID": bundle.scan_id,
        }
        token = os.environ.get("TTG_HUNTER_TOKEN", "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"

        request = urllib.request.Request(
            endpoint,
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        delivery = HunterDelivery(
            attempted=True,
            delivered=False,
            endpoint=endpoint,
            payload_file=str(payload_path),
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read(8192).decode("utf-8", errors="replace")
                delivery.status_code = int(response.status)
                delivery.response = body
                delivery.delivered = 200 <= response.status < 300
        except urllib.error.HTTPError as exc:
            delivery.status_code = int(exc.code)
            delivery.error = f"HTTP {exc.code}: {exc.reason}"
            try:
                delivery.response = exc.read(8192).decode("utf-8", errors="replace")
            except OSError:
                pass
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            delivery.error = str(exc)

        if not delivery.delivered:
            spool_dir = self._spool_dir(bundle_dir)
            spool_dir.mkdir(parents=True, exist_ok=True)
            spool_path = spool_dir / f"{bundle.scan_id}.json"
            spool_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            delivery.spool_file = str(spool_path)

        report_path = bundle_dir / "hunter_delivery.json"
        report_path.write_text(
            json.dumps(delivery.to_dict(), indent=2), encoding="utf-8"
        )
        with (bundle_dir / "audit.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "event": "HUNTER_DELIVERY",
                        "attempted": delivery.attempted,
                        "delivered": delivery.delivered,
                        "endpoint": delivery.endpoint,
                        "status_code": delivery.status_code,
                        "error": delivery.error,
                        "spool_file": delivery.spool_file,
                    }
                )
                + "\n"
            )
        return delivery

    def _payload(self, bundle: ScanBundle) -> dict[str, Any]:
        identity = self._privacy_identity(bundle.identity.to_dict())
        candidate_summaries = []
        for candidate in bundle.candidates:
            candidate_summaries.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "observation_indexes": candidate.observation_indexes,
                    "link_confidence": candidate.link_confidence,
                    "link_evidence": candidate.link_evidence,
                    "identity": self._privacy_identity(candidate.identity.to_dict()),
                    "firmware": candidate.firmware.to_dict(),
                    "storage": candidate.storage.to_dict(),
                    "certification": candidate.certification.to_dict(),
                    "profile_match": candidate.profile_match.to_dict(),
                    "challenge_codes": [item.code for item in candidate.challenges],
                    "transports": [
                        {
                            "transport": item.transport.value,
                            "mode": item.mode,
                            "partition_count": len(item.partitions),
                        }
                        for item in candidate.observations
                    ],
                }
            )

        return {
            "event": "DEVICE_XRAY_SCAN_COMPLETED",
            "source": "ttg-device-xray",
            "schema_version": 2,
            "scan_id": bundle.scan_id,
            "created_at": bundle.created_at,
            "mission": bundle.mission,
            "candidate_count": len(bundle.candidates),
            "selected_candidate_id": bundle.selected_candidate_id,
            "candidates": candidate_summaries,
            "certification": bundle.certification.to_dict(),
            "profile_match": bundle.profile_match.to_dict(),
            "identity": identity,
            "firmware": bundle.firmware.to_dict(),
            "storage": bundle.storage.to_dict(),
            "plan": bundle.plan,
            "challenges": [item.to_dict() for item in bundle.challenges],
            "transports": [
                {
                    "transport": item.transport.value,
                    "available": item.available,
                    "connected": item.connected,
                    "mode": item.mode,
                    "capabilities": item.capabilities,
                    "warnings": item.warnings,
                    "partition_count": len(item.partitions),
                }
                for item in bundle.observations
            ],
            "privacy": {
                "raw_sensitive_identifiers_included": self.include_sensitive,
                "hash_algorithm": "sha256",
                "identifier_types_kept_separate": [
                    "android_serial",
                    "apple_udid",
                    "apple_serial",
                    "apple_ecid",
                    "imei",
                ],
            },
            "write_allowed": False,
        }

    def _privacy_identity(self, identity: dict[str, Any]) -> dict[str, Any]:
        result = dict(identity)
        sensitive = {
            "serial": result.pop("serial", ""),
            "udid": result.pop("udid", ""),
            "apple_serial": result.pop("apple_serial", ""),
            "ecid": result.pop("ecid", ""),
            "imei": result.pop("imei", ""),
        }
        if self.include_sensitive:
            result.update(sensitive)
        else:
            for key, value in sensitive.items():
                if value:
                    result[f"{key}_sha256"] = hashlib.sha256(
                        str(value).encode("utf-8")
                    ).hexdigest()
                    if key == "imei":
                        result["imei_suffix"] = str(value)[-4:]
        return result

    @classmethod
    def _endpoint(cls) -> str:
        exact = os.environ.get("TTG_HUNTER_XRAY_URL", "").strip()
        if exact:
            return exact
        base = (
            os.environ.get("TTG_HUNTER_URL", "").strip()
            or os.environ.get("HUNTER_URL", "").strip()
            or "http://127.0.0.1:5000"
        )
        return f"{base.rstrip('/')}{cls.DEFAULT_PATH}"

    @staticmethod
    def _spool_dir(bundle_dir: Path) -> Path:
        configured = os.environ.get("TTG_HUNTER_SPOOL_DIR", "").strip()
        return Path(configured) if configured else bundle_dir.parent / "_hunter_spool"

    @staticmethod
    def _timeout() -> float:
        raw = os.environ.get("TTG_HUNTER_TIMEOUT_SECONDS", "3").strip()
        try:
            return max(0.5, min(30.0, float(raw)))
        except ValueError:
            return 3.0
