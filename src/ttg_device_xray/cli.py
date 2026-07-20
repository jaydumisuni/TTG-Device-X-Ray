from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

from .analyzers.ipsw import IpswAnalysisError, write_ipsw_report
from .bundle_seal import seal_bundle
from .command import CommandRunner
from .enhanced_pipeline import EnhancedXRayPipeline
from .hunter_bridge import HunterBridge, HunterDelivery
from .models import ScanBundle, TransportObservation
from .pipeline import write_bundle
from .platform_tools import PlatformToolsRunner
from .profile_loader import ProfileLoader
from .repair_readiness import build_repair_readiness
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


def _diagnostic_observation(observation: TransportObservation) -> dict[str, Any]:
    identifiers = observation.identifiers
    capabilities = observation.capabilities
    return {
        "transport": observation.transport.value,
        "mode": observation.mode,
        "available": observation.available,
        "connected": observation.connected,
        "usb_vid": str(identifiers.get("usb_vid", "")),
        "usb_pid": str(identifiers.get("usb_pid", "")),
        "pnp_present": capabilities.get("pnp_present"),
        "pnp_status": str(capabilities.get("pnp_status", "")),
        "transport_confirmed": capabilities.get("transport_confirmed"),
        "helper_configured": bool(capabilities.get("helper_configured", False)),
        "partition_count": len(observation.partitions),
        "warning_count": len(observation.warnings),
    }


def _diagnostic_candidates(bundle: ScanBundle) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for index, candidate in enumerate(bundle.candidates, start=1):
        identity = candidate.identity
        summaries.append(
            {
                "candidate_index": index,
                "link_confidence": candidate.link_confidence,
                "identity": {
                    "platform": identity.platform,
                    "brand": identity.brand,
                    "manufacturer": identity.manufacturer,
                    "marketing_model": identity.marketing_model,
                    "internal_model": identity.internal_model,
                    "board": identity.board,
                    "chipset": identity.chipset,
                    "active_mode": identity.active_mode,
                },
                "observations": [
                    _diagnostic_observation(observation)
                    for observation in candidate.observations
                ],
            }
        )
    return summaries


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = CommandRunner()
    platform_tools = PlatformToolsRunner(runner)

    if args.command == "doctor":
        tools = {
            name: (
                platform_tools.exists(name)
                if name in {"adb", "fastboot"}
                else runner.exists(name)
            )
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
                    "bundle_seal": {
                        "signing_key_configured": bool(
                            os.environ.get("TTG_XRAY_SIGNING_KEY", "").strip()
                        ),
                        "signer_key_id": os.environ.get(
                            "TTG_XRAY_SIGNING_KEY_ID", "ttg-xray-local"
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
            AdbProbe(platform_tools),
            FastbootProbe(platform_tools),
            MtkMetaProbe(runner),
            QualcommEdlProbe(runner),
            SpdDownloadProbe(runner),
            SamsungDownloadProbe(runner),
            AppleProbe(runner),
        ]
    )
    bundle = pipeline.scan(mission=args.mission)

    profile_loader = ProfileLoader(args.profile_dir)
    profile_loader.apply_bundle_matches(bundle)
    profile_payload = bundle.profile_match.to_dict()
    repair_readiness = build_repair_readiness(profile_payload)
    bundle.plan["profile_match"] = profile_payload
    bundle.plan["repair_readiness"] = repair_readiness
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

    seal = seal_bundle(target, bundle)
    print(
        json.dumps(
            {
                "scan_id": bundle.scan_id,
                "candidate_count": len(bundle.candidates),
                "candidate_summaries": _diagnostic_candidates(bundle),
                "selected_candidate_id": bundle.selected_candidate_id,
                "verdict": bundle.certification.verdict.value,
                "certification_scope": "DEVICE_IDENTITY_EVIDENCE",
                "confidence": bundle.certification.confidence,
                "certification_dimensions": bundle.certification.dimensions.to_dict(),
                "identity": bundle.identity.to_dict(),
                "firmware_fingerprint": bundle.firmware.fingerprint_sha256,
                "storage": bundle.storage.to_dict(),
                "profile_match": profile_payload,
                "repair_readiness": repair_readiness,
                "hunter_delivery": delivery.to_dict(),
                "bundle_seal": seal,
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
