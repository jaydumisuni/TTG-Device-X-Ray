from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

from .models import ScanBundle


MANIFEST_NAME = "bundle_manifest.json"
SIGNATURE_NAME = "bundle_manifest.sig"
BUNDLE_SCHEMA_VERSION = "2.0"


def seal_bundle(bundle_dir: Path, bundle: ScanBundle) -> dict[str, Any]:
    """Create a digest manifest and optional HMAC signature for a completed bundle.

    The signing key is read from TTG_XRAY_SIGNING_KEY. When no key is configured,
    the digest manifest is still emitted but the signature report is explicitly
    UNSIGNED. Repair adapters can require status=SIGNED before accepting a bundle.
    """

    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(seconds=_ttl_seconds())
    signer_key_id = os.environ.get("TTG_XRAY_SIGNING_KEY_ID", "ttg-xray-local").strip()

    files: list[dict[str, Any]] = []
    for path in sorted(bundle_dir.rglob("*")):
        if not path.is_file() or path.name in {MANIFEST_NAME, SIGNATURE_NAME}:
            continue
        relative = path.relative_to(bundle_dir).as_posix()
        files.append(
            {
                "path": relative,
                "size_bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )

    manifest: dict[str, Any] = {
        "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
        "scan_schema_version": bundle.schema_version,
        "scanner": {
            "name": "ttg-device-xray",
            "version": _scanner_version(),
        },
        "scan_id": bundle.scan_id,
        "device_candidate_id": bundle.selected_candidate_id,
        "candidate_count": len(bundle.candidates),
        "created_at": created_at.isoformat(timespec="seconds"),
        "expires_at": expires_at.isoformat(timespec="seconds"),
        "signer_key_id": signer_key_id,
        "hash_algorithm": "sha256",
        "signature_algorithm": "hmac-sha256",
        "write_allowed": False,
        "files": files,
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    manifest_sha256 = hashlib.sha256(canonical).hexdigest()
    manifest["manifest_sha256"] = manifest_sha256

    manifest_path = bundle_dir / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    signing_key = os.environ.get("TTG_XRAY_SIGNING_KEY", "").encode("utf-8")
    if signing_key:
        signed_bytes = json.dumps(
            manifest, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        signature = hmac.new(signing_key, signed_bytes, hashlib.sha256).hexdigest()
        signature_report = {
            "status": "SIGNED",
            "algorithm": "hmac-sha256",
            "signer_key_id": signer_key_id,
            "manifest_sha256": manifest_sha256,
            "signature_hex": signature,
        }
    else:
        signature_report = {
            "status": "UNSIGNED",
            "algorithm": "hmac-sha256",
            "signer_key_id": signer_key_id,
            "manifest_sha256": manifest_sha256,
            "signature_hex": "",
            "reason": "TTG_XRAY_SIGNING_KEY is not configured",
        }

    (bundle_dir / SIGNATURE_NAME).write_text(
        json.dumps(signature_report, indent=2), encoding="utf-8"
    )
    with (bundle_dir / "audit.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(
            json.dumps(
                {
                    "event": "BUNDLE_SEALED",
                    "status": signature_report["status"],
                    "manifest_sha256": manifest_sha256,
                    "signer_key_id": signer_key_id,
                    "file_count": len(files),
                }
            )
            + "\n"
        )

    return {
        "manifest": str(manifest_path),
        "signature": str(bundle_dir / SIGNATURE_NAME),
        "status": signature_report["status"],
        "manifest_sha256": manifest_sha256,
        "signer_key_id": signer_key_id,
        "file_count": len(files),
    }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _scanner_version() -> str:
    try:
        return version("ttg-device-xray")
    except PackageNotFoundError:
        return "0.4.0-dev"


def _ttl_seconds() -> int:
    raw = os.environ.get("TTG_XRAY_BUNDLE_TTL_SECONDS", "86400").strip()
    try:
        return max(300, min(30 * 86400, int(raw)))
    except ValueError:
        return 86400
