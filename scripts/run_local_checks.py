from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> None:
    print(f"\n$ {' '.join(command)}", flush=True)
    environment = os.environ.copy()
    environment.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    subprocess.run(command, cwd=ROOT, env=environment, check=True, shell=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the TTG Device X-Ray quality gate")
    parser.add_argument("--skip-tests", action="store_true")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args(argv)

    python = sys.executable
    run([python, "scripts/validate_profiles.py"])
    run([python, "scripts/validate_fixtures.py"])
    run([python, "scripts/check_read_only.py"])
    run([python, "-m", "ruff", "check", "."])

    if not args.skip_tests:
        run([python, "-m", "pytest", "-q"])

    if not args.skip_build:
        with tempfile.TemporaryDirectory(prefix="ttg-xray-dist-") as temporary:
            dist = Path(temporary)
            run([python, "-m", "build", "--outdir", str(dist)])
            artifacts = sorted(str(path) for path in dist.iterdir() if path.is_file())
            if not artifacts:
                raise RuntimeError("package build produced no artifacts")
            run([python, "-m", "twine", "check", *artifacts])

    print("\nTTG Device X-Ray quality gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
