from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Protocol

from .models import CommandEvidence


class Runner(Protocol):
    def exists(self, executable: str) -> bool: ...

    def run(self, command: list[str], timeout: int = 20) -> CommandEvidence: ...


@dataclass(slots=True)
class CommandRunner:
    """Small deterministic command wrapper used by every transport probe."""

    def exists(self, executable: str) -> bool:
        return shutil.which(executable) is not None

    def run(self, command: list[str], timeout: int = 20) -> CommandEvidence:
        started = time.perf_counter()
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                errors="replace",
            )
            return CommandEvidence(
                command=command,
                return_code=result.returncode,
                stdout=result.stdout.strip(),
                stderr=result.stderr.strip(),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
        except subprocess.TimeoutExpired as exc:
            return CommandEvidence(
                command=command,
                return_code=124,
                stdout=(exc.stdout or "").strip() if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "").strip() if isinstance(exc.stderr, str) else "",
                duration_ms=int((time.perf_counter() - started) * 1000),
                timed_out=True,
            )
        except OSError as exc:
            return CommandEvidence(
                command=command,
                return_code=127,
                stderr=str(exc),
                duration_ms=int((time.perf_counter() - started) * 1000),
            )
