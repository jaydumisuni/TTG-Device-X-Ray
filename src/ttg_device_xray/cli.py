from __future__ import annotations

import argparse
import json
from pathlib import Path

from .command import CommandRunner
from .pipeline import XRayPipeline, write_bundle
from .transports.adb import AdbProbe
from .transports.apple import AppleProbe
from .transports.fastboot import FastbootProbe


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ttg-xray", description="TTG Device X-Ray")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a read-only device scan")
    scan.add_argument("--output", type=Path, default=Path("scans"))
    scan.add_argument("--mission", default="identify-and-plan")

    subparsers.add_parser("doctor", help="Check local transport tools")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = CommandRunner()

    if args.command == "doctor":
        tools = {
            name: runner.exists(name)
            for name in ("adb", "fastboot", "idevice_id", "ideviceinfo", "irecovery")
        }
        print(json.dumps({"tools": tools}, indent=2))
        return 0

    pipeline = XRayPipeline(
        probes=[
            AdbProbe(runner),
            FastbootProbe(runner),
            AppleProbe(runner),
        ]
    )
    bundle = pipeline.scan(mission=args.mission)
    target = write_bundle(bundle, args.output)
    print(
        json.dumps(
            {
                "scan_id": bundle.scan_id,
                "verdict": bundle.certification.verdict.value,
                "confidence": bundle.certification.confidence,
                "identity": bundle.identity.to_dict(),
                "output": str(target),
            },
            indent=2,
        )
    )
    return 0 if bundle.certification.verdict.value != "UNSAFE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
