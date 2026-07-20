from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".md", ".json", ".toml", ".yml", ".yaml", ".ps1", ".txt"}
SKIP_PARTS = {".git", ".venv", "dist", "build", "__pycache__"}

FORBIDDEN = {
    "internal_api_url": re.compile(r"https?://[^\s'\"`]*thetechguyds\.com/(?:api|internal|admin)", re.IGNORECASE),
    "runtime_token_variable": re.compile(r"TTG_[A-Z0-9_]*(?:TOKEN|ACCESS_KEY|AUTHORIZATION)", re.IGNORECASE),
    "authorization_header": re.compile(r"\bAuthorization\s*[:=]", re.IGNORECASE),
    "bearer_example": re.compile(r"\bBearer\s+[A-Za-z0-9_.-]+", re.IGNORECASE),
}


def main() -> int:
    findings: list[str] = []
    for path in sorted(ROOT.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        relative = path.relative_to(ROOT)
        if any(part in SKIP_PARTS for part in relative.parts):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for label, pattern in FORBIDDEN.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{relative}:{line}: {label}")

    if findings:
        print("Public privacy check failed:")
        for finding in findings:
            print(f"  - {finding}")
        return 1

    print("Public privacy check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
