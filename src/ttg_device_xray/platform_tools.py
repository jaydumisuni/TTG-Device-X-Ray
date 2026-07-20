from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path

from .command import Runner
from .models import CommandEvidence

_PLATFORM_TOOL_NAMES = {"adb", "fastboot"}


def _unique_paths(paths: list[Path]) -> list[Path]:
    result: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        if not str(path):
            continue
        try:
            resolved = path.expanduser().resolve()
        except OSError:
            continue
        key = str(resolved).casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append(resolved)
    return result


def _runtime_roots() -> list[Path]:
    roots: list[Path] = []
    bundle_root = str(getattr(sys, "_MEIPASS", "")).strip()
    if bundle_root:
        roots.append(Path(bundle_root))
    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent)
    roots.extend([Path.cwd(), Path(__file__).resolve().parent])
    return _unique_paths(roots)


def _environment_tool(name: str) -> str:
    names = (
        ("TTG_XRAY_ADB", "MIBU_ADB", "ADB")
        if name == "adb"
        else ("TTG_XRAY_FASTBOOT", "MIBU_FASTBOOT", "FASTBOOT")
    )
    for variable in names:
        configured = os.environ.get(variable, "").strip()
        if configured:
            return configured
    return ""


def platform_tool_candidates(name: str) -> list[Path]:
    normalized = Path(name).stem.lower()
    if normalized not in _PLATFORM_TOOL_NAMES:
        return []

    executable = f"{normalized}.exe" if os.name == "nt" else normalized
    candidates: list[Path] = []

    configured = _environment_tool(normalized)
    if configured:
        candidates.append(Path(configured))

    relative_locations = (
        Path("platform-tools"),
        Path("_internal/platform-tools"),
        Path("tools/platform-tools"),
        Path("tools/adb"),
        Path("."),
    )
    for root in _runtime_roots():
        candidates.extend(root / relative / executable for relative in relative_locations)

    for sdk in (
        os.environ.get("ANDROID_SDK_ROOT", ""),
        os.environ.get("ANDROID_HOME", ""),
        "D:/mibu-build-tools/android-sdk",
    ):
        if sdk:
            candidates.append(Path(sdk) / "platform-tools" / executable)

    # MIBU already ships a verified platform-tools folder. These are conservative
    # local fallbacks for owner/development machines; the X-Ray EXE bundles its own.
    candidates.extend(
        [
            Path("D:/mibu-build-tools/platform-tools") / executable,
            Path.home() / "Downloads" / "MIBU-PC-Helper" / "platform-tools" / executable,
        ]
    )
    return _unique_paths(candidates)


def resolve_platform_tool(name: str) -> str | None:
    normalized = Path(name).stem.lower()
    for candidate in platform_tool_candidates(normalized):
        if candidate.is_file():
            return str(candidate)
    return shutil.which(normalized)


def _combined_output(evidence: CommandEvidence) -> CommandEvidence:
    parts = [part.strip() for part in (evidence.stdout, evidence.stderr) if part.strip()]
    return CommandEvidence(
        command=evidence.command,
        return_code=evidence.return_code,
        stdout="\n".join(parts),
        stderr=evidence.stderr,
        duration_ms=evidence.duration_ms,
        timed_out=evidence.timed_out,
    )


@dataclass(slots=True)
class PlatformToolsRunner:
    """Resolve bundled platform-tools and preserve MIBU's proven ADB listing path."""

    runner: Runner
    adb_executable: str | None = None
    fastboot_executable: str | None = None

    def _resolve(self, name: str) -> str | None:
        if name == "adb":
            if not self.adb_executable:
                self.adb_executable = resolve_platform_tool("adb")
            return self.adb_executable
        if name == "fastboot":
            if not self.fastboot_executable:
                self.fastboot_executable = resolve_platform_tool("fastboot")
            return self.fastboot_executable
        return None

    def exists(self, executable: str) -> bool:
        name = Path(executable).stem.lower()
        if name in _PLATFORM_TOOL_NAMES:
            return self._resolve(name) is not None
        return self.runner.exists(executable)

    def run(self, command: list[str], timeout: int = 20) -> CommandEvidence:
        if not command:
            return self.runner.run(command, timeout=timeout)

        name = Path(command[0]).stem.lower()
        if name not in _PLATFORM_TOOL_NAMES:
            return self.runner.run(command, timeout=timeout)

        resolved = self._resolve(name)
        if not resolved:
            return CommandEvidence(
                command=command,
                return_code=127,
                stderr=f"{name} executable was not found",
            )

        arguments = command[1:]
        if name == "adb" and arguments == ["devices", "-l"]:
            # MIBU deliberately uses plain `adb devices`, which works across old and
            # current platform-tools. X-Ray does not need -l because it reads getprop.
            primary = self.runner.run([resolved, "devices"], timeout=timeout)
            combined = _combined_output(primary)
            if primary.return_code == 0:
                return combined

            # A broken/stale daemon is the only case where starting the server helps.
            self.runner.run([resolved, "start-server"], timeout=min(timeout, 15))
            retry = self.runner.run([resolved, "devices"], timeout=timeout)
            if retry.return_code == 0:
                return _combined_output(retry)

            detailed = self.runner.run([resolved, "devices", "-l"], timeout=timeout)
            return _combined_output(detailed)

        return self.runner.run([resolved, *arguments], timeout=timeout)
