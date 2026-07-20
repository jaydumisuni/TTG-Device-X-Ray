from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import __version__

TOOL_ID = "ttg-device-xray"
DEFAULT_DEV_REPOSITORY = "jaydumisuni/tools-test-repo"
REGISTRY_PATH = f"registry/dev/{TOOL_ID}.json"
_VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+]([0-9A-Za-z.-]+))?$")
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")


@dataclass(slots=True)
class UpdateManifest:
    version: str
    repository: str
    release_tag: str
    asset_name: str
    sha256: str
    size_bytes: int


@dataclass(slots=True)
class UpdateCheck:
    available: bool
    current_version: str
    remote_version: str = ""
    manifest: UpdateManifest | None = None
    message: str = ""


def package_version_to_channel(version: str) -> str:
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)\.dev(\d+)", version.strip())
    if match:
        return f"{match.group(1)}.{match.group(2)}.{match.group(3)}-dev.{match.group(4)}"
    return version.strip().lstrip("v")


def _version_parts(version: str) -> tuple[int, int, int, tuple[tuple[int, str], ...] | None]:
    match = _VERSION_RE.fullmatch(version.strip())
    if not match:
        raise ValueError(f"Unsupported update version: {version}")
    prerelease = match.group(4)
    tokens: tuple[tuple[int, str], ...] | None = None
    if prerelease:
        parsed: list[tuple[int, str]] = []
        for token in prerelease.split("."):
            if token.isdigit():
                parsed.append((0, f"{int(token):020d}"))
            else:
                parsed.append((1, token.casefold()))
        tokens = tuple(parsed)
    return int(match.group(1)), int(match.group(2)), int(match.group(3)), tokens


def compare_versions(left: str, right: str) -> int:
    left_parts = _version_parts(left)
    right_parts = _version_parts(right)
    if left_parts[:3] < right_parts[:3]:
        return -1
    if left_parts[:3] > right_parts[:3]:
        return 1

    left_pre = left_parts[3]
    right_pre = right_parts[3]
    if left_pre is None and right_pre is None:
        return 0
    if left_pre is None:
        return 1
    if right_pre is None:
        return -1
    if left_pre < right_pre:
        return -1
    if left_pre > right_pre:
        return 1
    return 0


def _enabled() -> bool:
    value = os.environ.get("TTG_XRAY_AUTO_UPDATE", "1").strip().lower()
    return value not in {"0", "false", "no", "off", "disabled"}


def _repository() -> str:
    value = os.environ.get("TTG_XRAY_DEV_REPO", DEFAULT_DEV_REPOSITORY).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ValueError("Invalid development repository configuration")
    return value


def _state_directory() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    target = base / "THETECHGUY DIGITAL SOLUTIONS" / "Maintenance" / TOOL_ID
    for folder in (target, target / "logs", target / "downloads", target / "rollback"):
        folder.mkdir(parents=True, exist_ok=True)
    return target


def _log(message: str) -> None:
    try:
        path = _state_directory() / "logs" / "in-app-updater.log"
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with path.open("a", encoding="utf-8") as handle:
            handle.write(f"{stamp} {message}\n")
    except OSError:
        pass


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


def _find_powershell() -> str | None:
    found = shutil.which("powershell.exe") or shutil.which("powershell")
    if found:
        return found
    if os.name == "nt":
        candidate = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        if candidate.is_file():
            return str(candidate)
    return None


def _run(command: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
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


def _authenticated(gh: str) -> bool:
    try:
        result = _run([gh, "auth", "status", "--hostname", "github.com"], timeout=8)
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _validate_manifest(payload: dict[str, Any], repository: str) -> UpdateManifest:
    required = {
        "schema_version",
        "tool_id",
        "channel",
        "version",
        "repository",
        "release_tag",
        "asset_name",
        "sha256",
        "size_bytes",
    }
    missing = sorted(required - payload.keys())
    if missing:
        raise ValueError(f"Update manifest is missing: {', '.join(missing)}")
    if int(payload["schema_version"]) != 1:
        raise ValueError("Unsupported update manifest schema")
    if str(payload["tool_id"]) != TOOL_ID:
        raise ValueError("Update manifest tool ID mismatch")
    if str(payload["channel"]) != "dev":
        raise ValueError("Update manifest channel mismatch")
    if str(payload["repository"]) != repository:
        raise ValueError("Update manifest repository mismatch")

    version = str(payload["version"]).strip()
    _version_parts(version)
    release_tag = str(payload["release_tag"]).strip()
    asset_name = str(payload["asset_name"]).strip()
    sha256 = str(payload["sha256"]).strip().lower()
    size_bytes = int(payload["size_bytes"])
    if not release_tag or any(character in release_tag for character in "\r\n"):
        raise ValueError("Unsafe development release tag")
    if Path(asset_name).name != asset_name or not asset_name.lower().endswith(".exe"):
        raise ValueError("Unsafe update asset name")
    if not _SHA256_RE.fullmatch(sha256):
        raise ValueError("Invalid update SHA-256")
    if size_bytes < 10_000_000:
        raise ValueError("Update executable is unexpectedly small")

    return UpdateManifest(
        version=version,
        repository=repository,
        release_tag=release_tag,
        asset_name=asset_name,
        sha256=sha256,
        size_bytes=size_bytes,
    )


def check_for_update() -> UpdateCheck:
    current = package_version_to_channel(__version__)
    if not _enabled():
        return UpdateCheck(False, current, message="Development updates are disabled")
    if os.name != "nt" or not getattr(sys, "frozen", False):
        return UpdateCheck(False, current, message="Updater is active only in the packaged Windows EXE")

    gh = _find_gh()
    if not gh:
        return UpdateCheck(False, current, message="GitHub CLI is not installed")
    if not _authenticated(gh):
        return UpdateCheck(False, current, message="GitHub CLI is not authenticated")

    repository = _repository()
    result = _run(
        [
            gh,
            "api",
            "-H",
            "Accept: application/vnd.github.raw+json",
            f"repos/{repository}/contents/{REGISTRY_PATH}",
        ],
        timeout=15,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout or "Private update registry lookup failed")
    payload = json.loads(result.stdout)
    if not isinstance(payload, dict):
        raise ValueError("Private update registry returned an invalid payload")
    manifest = _validate_manifest(payload, repository)
    available = compare_versions(current, manifest.version) < 0
    return UpdateCheck(
        available=available,
        current_version=current,
        remote_version=manifest.version,
        manifest=manifest,
        message="Update available" if available else "Development channel is current",
    )


def _download(manifest: UpdateManifest) -> Path:
    gh = _find_gh()
    if not gh or not _authenticated(gh):
        raise RuntimeError("Authenticated GitHub CLI is required for development updates")

    folder = _state_directory() / "downloads" / manifest.version
    folder.mkdir(parents=True, exist_ok=True)
    destination = folder / manifest.asset_name
    destination.unlink(missing_ok=True)
    result = _run(
        [
            gh,
            "release",
            "download",
            manifest.release_tag,
            "--repo",
            manifest.repository,
            "--pattern",
            manifest.asset_name,
            "--dir",
            str(folder),
            "--clobber",
        ],
        timeout=180,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout or "Private update download failed")
    if not destination.is_file():
        raise RuntimeError("Downloaded update executable is missing")
    if destination.stat().st_size != manifest.size_bytes:
        raise RuntimeError("Downloaded update size mismatch")
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    if digest != manifest.sha256:
        raise RuntimeError("Downloaded update SHA-256 mismatch")
    return destination


def _schedule_replacement(replacement: Path, manifest: UpdateManifest) -> bool:
    powershell = _find_powershell()
    if not powershell:
        raise RuntimeError("Windows PowerShell is required to replace the running EXE")

    current = Path(sys.executable).resolve()
    state = _state_directory()
    rollback = state / "rollback" / f"{current.name}.previous"
    installed_version = state / "installed-version.txt"
    script_path = state / "apply-xray-update.ps1"
    log_path = state / "logs" / "replacement.log"
    script = r'''param(
    [int]$ParentPid,
    [string]$Current,
    [string]$Replacement,
    [string]$Rollback,
    [string]$InstalledVersion,
    [string]$Version,
    [string]$LogPath
)
$ErrorActionPreference = "Stop"
try {
    Wait-Process -Id $ParentPid -Timeout 60 -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 700
    if (Test-Path -LiteralPath $Current) {
        Copy-Item -LiteralPath $Current -Destination $Rollback -Force
    }
    $installed = $false
    for ($attempt = 1; $attempt -le 30; $attempt++) {
        try {
            Copy-Item -LiteralPath $Replacement -Destination $Current -Force
            $installed = $true
            break
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $installed) { throw "The replacement executable remained locked." }
    Set-Content -LiteralPath $InstalledVersion -Value $Version -Encoding ASCII
    Add-Content -LiteralPath $LogPath -Value "$(Get-Date -Format o) Installed $Version" -Encoding UTF8
    Start-Process -FilePath $Current -WorkingDirectory (Split-Path -Parent $Current) | Out-Null
} catch {
    Add-Content -LiteralPath $LogPath -Value "$(Get-Date -Format o) Update failed: $($_.Exception.Message)" -Encoding UTF8
    if ((Test-Path -LiteralPath $Rollback) -and -not (Test-Path -LiteralPath $Current)) {
        Copy-Item -LiteralPath $Rollback -Destination $Current -Force
    }
}
'''
    script_path.write_text(script, encoding="utf-8")

    command = [
        powershell,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        "-ParentPid",
        str(os.getpid()),
        "-Current",
        str(current),
        "-Replacement",
        str(replacement),
        "-Rollback",
        str(rollback),
        "-InstalledVersion",
        str(installed_version),
        "-Version",
        manifest.version,
        "-LogPath",
        str(log_path),
    ]
    kwargs: dict[str, Any] = {
        "cwd": str(current.parent),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "close_fds": True,
    }
    if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW | subprocess.DETACHED_PROCESS
    subprocess.Popen(command, **kwargs)
    return True


def check_and_schedule_update() -> bool:
    try:
        check = check_for_update()
        _log(
            f"Current={check.current_version} Remote={check.remote_version or '-'} "
            f"Available={check.available} Message={check.message}"
        )
        if not check.available or check.manifest is None:
            return False
        replacement = _download(check.manifest)
        scheduled = _schedule_replacement(replacement, check.manifest)
        if scheduled:
            _log(f"Scheduled replacement with {check.manifest.version}")
        return scheduled
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        _log(f"Update deferred safely: {type(exc).__name__}: {exc}")
        return False


__all__ = [
    "UpdateCheck",
    "UpdateManifest",
    "check_and_schedule_update",
    "check_for_update",
    "compare_versions",
    "package_version_to_channel",
]
