from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from .analyzers.ipsw import IpswAnalysisError, write_ipsw_report
from .command import CommandRunner
from .enhanced_pipeline import EnhancedXRayPipeline
from .hunter_bridge import HunterBridge, HunterDelivery
from .models import ProfileMatch
from .pipeline import write_bundle
from .profile_loader import ProfileLoader
from .transports.adb import AdbProbe
from .transports.apple import AppleProbe
from .transports.fastboot import FastbootProbe
from .transports.mtk_meta import MtkMetaProbe
from .transports.qualcomm_edl import QualcommEdlProbe
from .transports.samsung_download import SamsungDownloadProbe
from .transports.spd import SpdDownloadProbe


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ttg-xray", description="TTG Device X-Ray")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a read-only device scan")
    scan.add_argument("--output", type=Path, default=Path("scans"))
    scan.add_argument("--mission", default="identify-and-plan")
    scan.add_argument(
        "--profile-dir",
        type=Path,
        action="append",
        default=[],
        help="Additional profile directory; may be supplied more than once",
    )
    scan.add_argument(
        "--no-hunter",
        action="store_true",
        help="Do not post this scan to Hunter",
    )
    scan.add_argument(
        "--hunter-required",
        action="store_true",
        help="Return a non-zero exit code when Hunter delivery fails",
    )

    ipsw = subparsers.add_parser(
        "inspect-ipsw", help="Inspect an Apple IPSW BuildManifest without restoring"
    )
    ipsw.add_argument("path", type=Path)
    ipsw.add_argument("--output", type=Path)

    subparsers.add_parser("doctor", help="Check local transport tools")
    return parser


def _helper_status(prefix: str) -> dict[str, bool]:
    return {
        "helper_configured": bool(os.environ.get(f"{prefix}_HELPER", "").strip()),
        "evidence_file_configured": bool(
            os.environ.get(f"{prefix}_EVIDENCE_FILE", "").strip()
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = CommandRunner()

    if args.command == "doctor":
        tools = {
            name: runner.exists(name)
            for name in (
                "adb",
                "fastboot",
                "idevice_id",
                "ideviceinfo",
                "irecovery",
                "powershell",
                "pwsh",
                "lsusb",
            )
        }
        print(
            json.dumps(
                {
                    "tools": tools,
                    "transports": {
                        "mtk_meta": {
                            **_helper_status("TTG_MTK_META"),
                            "supported_vid_pid": ["0E8D:2000", "0E8D:2007"],
                        },
                        "qualcomm_edl": {
                            **_helper_status("TTG_QUALCOMM_EDL"),
                            "primary_vid_pid": "05C6:9008",
                        },
                        "spd_download": {
                            **_helper_status("TTG_SPD"),
                            "vendor_hint": "1782",
                        },
                        "samsung_download": {
                            **_helper_status("TTG_SAMSUNG_DOWNLOAD"),
                            "vendor_hint": "04E8",
                        },
                    },
                    "profiles": {
                        "extra_directory_configured": bool(
                            os.environ.get("TTG_XRAY_PROFILE_DIR", "").strip()
                        )
                    },
                    "hunter": {
                        "endpoint": HunterBridge._endpoint(),
                        "token_configured": bool(
                            os.environ.get("TTG_HUNTER_TOKEN", "").strip()
                        ),
                    },
                },
                indent=2,
            )
        )
        return 0

    if args.command == "inspect-ipsw":
        try:
            report = write_ipsw_report(args.path, args.output)
        except IpswAnalysisError as exc:
            print(json.dumps({"error": str(exc)}, indent=2))
            return 2
        print(json.dumps(report, indent=2))
        return 0

    pipeline = EnhancedXRayPipeline(
        probes=[
            AdbProbe(runner),
            FastbootProbe(runner),
            MtkMetaProbe(runner),
            QualcommEdlProbe(runner),
            SpdDownloadProbe(runner),
            SamsungDownloadProbe(runner),
            AppleProbe(runner),
        ]
    )
    bundle = pipeline.scan(mission=args.mission)

    profile_loader = ProfileLoader(args.profile_dir)
    if bundle.certification.verdict.value == "UNSAFE":
        bundle.profile_match = ProfileMatch(
            status="BLOCKED_UNSAFE",
            requested_profile_id=bundle.certification.profile_id or "",
            reasons=["Profile routing is blocked because certification is UNSAFE."],
            write_allowed=False,
        )
    else:
        bundle.profile_match = profile_loader.match_bundle(bundle)
    bundle.plan["profile_match"] = bundle.profile_match.to_dict()
    if bundle.profile_match.status == "MATCHED":
        bundle.plan["recommended_profile"] = bundle.profile_match.profile_id
        bundle.plan["adapter_contracts"] = bundle.profile_match.adapter_contracts
        bundle.plan["transport_priority"] = bundle.profile_match.transport_priority

    target = write_bundle(bundle, args.output)
    profile_loader.write_match(bundle, target)

    if args.no_hunter:
        delivery = HunterDelivery(
            attempted=False,
            delivered=False,
            endpoint=HunterBridge._endpoint(),
            error="disabled by --no-hunter",
        )
        (target / "hunter_delivery.json").write_text(
            json.dumps(delivery.to_dict(), indent=2), encoding="utf-8"
        )
    else:
        delivery = HunterBridge().deliver(bundle, target)

    print(
        json.dumps(
            {
                "scan_id": bundle.scan_id,
                "verdict": bundle.certification.verdict.value,
                "confidence": bundle.certification.confidence,
                "identity": bundle.identity.to_dict(),
                "firmware_fingerprint": bundle.firmware.fingerprint_sha256,
                "storage": bundle.storage.to_dict(),
                "profile_match": bundle.profile_match.to_dict(),
                "hunter_delivery": delivery.to_dict(),
                "output": str(target),
            },
            indent=2,
        )
    )

    if args.hunter_required and not delivery.delivered:
        return 3
    return 0 if bundle.certification.verdict.value != "UNSAFE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
