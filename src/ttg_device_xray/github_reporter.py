from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_REPORT_REPO = os.environ.get(
    "TTG_XRAY_REPORT_REPO", "jaydumisuni/TTG-Device-X-Ray"
).strip()
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SECRET_RE = re.compile(
    r"(?i)(?:github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9_]+|bearer\s+[A-Za-z0-9._-]+)"
)
_IDENTIFIER_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(serial|imei|ecid|udid|apple_serial|token|authorization)\b"
    r"\s*[\"']?\s*[:=]\s*[\"']?[^,\s}\]\"']+"
)
_WINDOWS_PATH_RE = re.compile(r"(?i)\b[A-Z]:\\[^\r\n\"']+")
_POSIX_HOME_RE = re.compile(r"(?i)(?:/home/|/Users/)[^/\s]+(?:/[^\s\"']*)?")
_IMEI_LIKE_RE = re.compile(r"\b\d{14,17}\b")


@dataclass(slots=True)
class ReportResult:
    attempted: bool
    delivered: bool
    created: bool
    url: str
    local_markdown: Path
    local_json: Path
    fingerprint: str
    message: str


def parse_summary(output: str) -> dict[str, Any]:
    if not output:
        return {}
    try:
        value = json.loads(output)
        return value if isinstance(value, dict) else {}
    except json.JSONDecodeError:
        start = output.find("{")
        if start < 0:
            return {}
        decoder = json.JSONDecoder()
        try:
            value, _ = decoder.raw_decode(output[start:])
        except json.JSONDecodeError:
            return {}
        return value if isinstance(value, dict) else {}


def should_report(exit_code: int, summary: dict[str, Any]) -> bool:
    return exit_code != 0 or str(summary.get("verdict", "")).upper() == "UNSAFE"


def sanitize_console(text: str, limit: int = 4000) -> str:
    if not text:
        return ""
    tail = "\n".join(text.splitlines()[-80:])
    tail = _SECRET_RE.sub("<redacted-secret>", tail)
    tail = _IDENTIFIER_ASSIGNMENT_RE.sub(lambda match: f"{match.group(1)}=<redacted>", tail)
    tail = _WINDOWS_PATH_RE.sub("<local-path>", tail)
    tail = _POSIX_HOME_RE.sub("<local-path>", tail)
    tail = _IMEI_LIKE_RE.sub("<redacted-identifier>", tail)
    return tail[-limit:]


def _mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_observation(value: Any) -> dict[str, Any]:
    item = _mapping(value)
    return {
        "transport": str(item.get("transport", "")),
        "mode": str(item.get("mode", "")),
        "available": bool(item.get("available", False)),
        "connected": bool(item.get("connected", False)),
        "usb_vid": str(item.get("usb_vid", ""))[:4],
        "usb_pid": str(item.get("usb_pid", ""))[:4],
        "pnp_present": item.get("pnp_present"),
        "pnp_status": str(item.get("pnp_status", ""))[:40],
        "transport_confirmed": item.get("transport_confirmed"),
        "helper_configured": bool(item.get("helper_configured", False)),
        "partition_count": int(item.get("partition_count", 0) or 0),
        "warning_count": int(item.get("warning_count", 0) or 0),
    }


def _safe_candidate_summaries(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, Any]] = []
    for raw in value[:12]:
        item = _mapping(raw)
        identity = _mapping(item.get("identity"))
        observations = item.get("observations", [])
        result.append(
            {
                "candidate_index": int(item.get("candidate_index", 0) or 0),
                "link_confidence": float(item.get("link_confidence", 0.0) or 0.0),
                "identity": {
                    "platform": str(identity.get("platform", "unknown")),
                    "brand": str(identity.get("brand", "")),
                    "manufacturer": str(identity.get("manufacturer", "")),
                    "marketing_model": str(identity.get("marketing_model", "")),
                    "internal_model": str(identity.get("internal_model", "")),
                    "board": str(identity.get("board", "")),
                    "chipset": str(identity.get("chipset", "")),
                    "active_mode": str(identity.get("active_mode", "unknown")),
                },
                "observations": [
                    _safe_observation(observation)
                    for observation in observations[:12]
                    if isinstance(observation, dict)
                ]
                if isinstance(observations, list)
                else [],
            }
        )
    return result


def safe_summary(summary: dict[str, Any], exit_code: int) -> dict[str, Any]:
    profile = _mapping(summary.get("profile_match"))
    hunter = _mapping(summary.get("hunter_delivery"))
    seal = _mapping(summary.get("bundle_seal"))
    dimensions = _mapping(summary.get("certification_dimensions"))
    identity = _mapping(summary.get("identity"))
    storage = _mapping(summary.get("storage"))

    return {
        "scan_id": str(summary.get("scan_id", "")),
        "exit_code": int(exit_code),
        "candidate_count": int(summary.get("candidate_count", 0) or 0),
        "candidate_summaries": _safe_candidate_summaries(
            summary.get("candidate_summaries")
        ),
        "selected_candidate_present": bool(summary.get("selected_candidate_id")),
        "verdict": str(summary.get("verdict", "UNKNOWN")),
        "confidence": float(summary.get("confidence", 0.0) or 0.0),
        "certification_dimensions": dimensions,
        "identity": {
            "platform": str(identity.get("platform", "unknown")),
            "brand": str(identity.get("brand", "")),
            "manufacturer": str(identity.get("manufacturer", "")),
            "marketing_model": str(identity.get("marketing_model", "")),
            "internal_model": str(identity.get("internal_model", "")),
            "product_name": str(identity.get("product_name", "")),
            "board": str(identity.get("board", "")),
            "chipset": str(identity.get("chipset", "")),
            "firmware_version": str(identity.get("firmware_version", "")),
            "security_patch": str(identity.get("security_patch", "")),
            "active_mode": str(identity.get("active_mode", "unknown")),
        },
        "storage": {
            "storage_type": str(storage.get("storage_type", "")),
            "capacity_bytes": int(storage.get("capacity_bytes", 0) or 0),
            "partition_count": int(storage.get("partition_count", 0) or 0),
            "has_super": bool(storage.get("has_super", False)),
            "dynamic_partitions": bool(storage.get("dynamic_partitions", False)),
            "ab_slots": bool(storage.get("ab_slots", False)),
        },
        "profile_match": {
            "status": str(profile.get("status", "")),
            "stage": str(profile.get("stage", "")),
            "confidence": float(profile.get("confidence", 0.0) or 0.0),
            "reasons": [str(item) for item in profile.get("reasons", []) if item],
            "mismatches": [str(item) for item in profile.get("mismatches", []) if item],
            "transport_priority": [
                str(item) for item in profile.get("transport_priority", []) if item
            ],
            "write_allowed": False,
        },
        "hunter_delivery": {
            "attempted": bool(hunter.get("attempted", False)),
            "delivered": bool(hunter.get("delivered", False)),
            "status_code": int(hunter.get("status_code", 0) or 0),
            "error": sanitize_console(str(hunter.get("error", "")), limit=500),
        },
        "bundle_seal": {
            "status": str(seal.get("status", "")),
            "file_count": int(seal.get("file_count", 0) or 0),
        },
        "runtime": {
            "platform": sys.platform,
            "frozen_executable": bool(getattr(sys, "frozen", False)),
        },
    }


def diagnostic_category(safe: dict[str, Any]) -> str:
    if safe.get("verdict") == "UNSAFE" and int(safe.get("candidate_count", 0)) > 1:
        return "unsafe-multi-candidate"
    if safe.get("verdict") == "UNSAFE":
        return "unsafe-evidence"
    if int(safe.get("candidate_count", 0)) == 0:
        return "no-device-evidence"
    return "scan-failure"


def diagnostic_fingerprint(safe: dict[str, Any], console_tail: str) -> str:
    profile = _mapping(safe.get("profile_match"))
    basis = {
        "category": diagnostic_category(safe),
        "exit_code": safe.get("exit_code"),
        "candidate_count": safe.get("candidate_count"),
        "candidate_summaries": safe.get("candidate_summaries", []),
        "verdict": safe.get("verdict"),
        "profile_status": profile.get("status"),
        "reasons": profile.get("reasons", []),
        "mismatches": profile.get("mismatches", []),
        "console_tail": console_tail[-800:],
    }
    encoded = json.dumps(basis, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:12]


def build_markdown(
    safe: dict[str, Any],
    fingerprint: str,
    console_tail: str,
) -> str:
    category = diagnostic_category(safe)
    profile = _mapping(safe.get("profile_match"))
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return f"""<!-- ttg-xray-auto-diagnostic:{fingerprint} -->
## Automatic TTG Device X-Ray diagnostic

This report was created by the pre-release owner-mode reporter after a read-only scan failed or returned an unsafe verdict.

| Field | Value |
|---|---|
| Category | `{category}` |
| Fingerprint | `{fingerprint}` |
| Scan ID | `{safe.get('scan_id', '')}` |
| Exit code | `{safe.get('exit_code', '')}` |
| Verdict | `{safe.get('verdict', '')}` |
| Candidate count | `{safe.get('candidate_count', '')}` |
| Selected candidate present | `{safe.get('selected_candidate_present', False)}` |
| Profile status | `{profile.get('status', '')}` |
| Generated UTC | `{generated}` |

### Sanitized diagnostic payload

```json
{json.dumps(safe, indent=2, sort_keys=True)}
```

### Sanitized console tail

```text
{console_tail or '<no console output>'}
```

### Privacy boundary

The reporter deliberately excludes serial numbers, IMEI, ECID, UDID, Apple serial, tokens, authorization headers, raw customer evidence, absolute local paths, bundle signatures, and the full local scan bundle. The complete bundle remains on the technician workstation.
"""


def _find_gh() -> str | None:
    found = shutil.which("gh")
    if found:
        return found
    if os.name != "nt":
        return None
    candidates = [
        Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "GitHub CLI" / "gh.exe",
        Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "GitHub CLI" / "gh.exe",
    ]
    return next((str(path) for path in candidates if path.is_file()), None)


def _run(command: list[str], timeout: int = 45) -> subprocess.CompletedProcess[str]:
    kwargs: dict[str, Any] = {
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "errors": "replace",
        "shell": False,
    }
    if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    return subprocess.run(command, **kwargs)


def github_cli_status() -> tuple[bool, str]:
    gh = _find_gh()
    if not gh:
        return False, "GitHub CLI not found"
    try:
        result = _run([gh, "auth", "status", "--hostname", "github.com"], timeout=8)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"GitHub CLI check failed: {exc}"
    if result.returncode == 0:
        return True, "GitHub CLI authenticated"
    message = sanitize_console(result.stderr or result.stdout, limit=300).strip()
    return False, message or "GitHub CLI is not authenticated"


def _validate_repo(repo: str) -> str:
    normalized = repo.strip()
    if not _REPO_RE.fullmatch(normalized):
        raise ValueError(f"Invalid GitHub repository name: {repo!r}")
    return normalized


def submit_failure_report(
    *,
    summary: dict[str, Any],
    exit_code: int,
    console_output: str,
    output_directory: Path,
    repo: str = DEFAULT_REPORT_REPO,
) -> ReportResult:
    safe = safe_summary(summary, exit_code)
    console_tail = sanitize_console(console_output)
    fingerprint = diagnostic_fingerprint(safe, console_tail)
    category = diagnostic_category(safe)

    report_directory = output_directory / "_diagnostics"
    report_directory.mkdir(parents=True, exist_ok=True)
    stem = safe.get("scan_id") or datetime.now(timezone.utc).strftime("xray-%Y%m%d-%H%M%S")
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(stem)).strip("-") or "xray-report"
    markdown_path = report_directory / f"{stem}-{fingerprint}.md"
    json_path = report_directory / f"{stem}-{fingerprint}.json"
    markdown = build_markdown(safe, fingerprint, console_tail)
    markdown_path.write_text(markdown, encoding="utf-8")
    json_path.write_text(json.dumps(safe, indent=2, sort_keys=True), encoding="utf-8")

    try:
        repository = _validate_repo(repo)
    except ValueError as exc:
        return ReportResult(
            attempted=False,
            delivered=False,
            created=False,
            url="",
            local_markdown=markdown_path,
            local_json=json_path,
            fingerprint=fingerprint,
            message=f"Diagnostic saved locally; {exc}",
        )

    ready, status = github_cli_status()
    gh = _find_gh()
    if not ready or not gh:
        return ReportResult(
            attempted=False,
            delivered=False,
            created=False,
            url="",
            local_markdown=markdown_path,
            local_json=json_path,
            fingerprint=fingerprint,
            message=f"Diagnostic saved locally; GitHub sync unavailable: {status}",
        )

    marker = f"ttg-xray-auto-diagnostic:{fingerprint}"
    try:
        search = _run(
            [
                gh,
                "issue",
                "list",
                "--repo",
                repository,
                "--state",
                "open",
                "--search",
                f'"{marker}" in:body',
                "--json",
                "number,url",
                "--limit",
                "1",
            ]
        )
        if search.returncode != 0:
            raise RuntimeError(search.stderr or search.stdout or "GitHub issue search failed")
        existing = json.loads(search.stdout or "[]")
        if existing:
            number = str(existing[0]["number"])
            url = str(existing[0].get("url", ""))
            submitted = _run(
                [
                    gh,
                    "issue",
                    "comment",
                    number,
                    "--repo",
                    repository,
                    "--body-file",
                    str(markdown_path),
                ]
            )
            if submitted.returncode != 0:
                raise RuntimeError(submitted.stderr or submitted.stdout or "GitHub comment failed")
            return ReportResult(
                attempted=True,
                delivered=True,
                created=False,
                url=url,
                local_markdown=markdown_path,
                local_json=json_path,
                fingerprint=fingerprint,
                message=f"Diagnostics added to existing GitHub issue: {url}",
            )

        title = f"[AUTO-DIAGNOSTIC] {category} [{fingerprint}]"
        submitted = _run(
            [
                gh,
                "issue",
                "create",
                "--repo",
                repository,
                "--title",
                title,
                "--body-file",
                str(markdown_path),
            ]
        )
        if submitted.returncode != 0:
            raise RuntimeError(submitted.stderr or submitted.stdout or "GitHub issue creation failed")
        url = (submitted.stdout or "").strip().splitlines()[-1]
        return ReportResult(
            attempted=True,
            delivered=True,
            created=True,
            url=url,
            local_markdown=markdown_path,
            local_json=json_path,
            fingerprint=fingerprint,
            message=f"GitHub diagnostic issue created: {url}",
        )
    except (OSError, RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        return ReportResult(
            attempted=True,
            delivered=False,
            created=False,
            url="",
            local_markdown=markdown_path,
            local_json=json_path,
            fingerprint=fingerprint,
            message=f"Diagnostic saved locally; GitHub sync failed: {sanitize_console(str(exc), 500)}",
        )
