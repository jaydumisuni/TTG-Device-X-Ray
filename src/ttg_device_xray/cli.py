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
from .models import ScanBundle, TransportObservation
from .pipeline import write_bundle
from .platform_tools import PlatformToolsRunner
from .profile_loader import ProfileLoader
from .regional_compare import RegionalCompareError, compare_regional_sources
from .repair_readiness import build_repair_readiness
from .transports.adb import AdbProbe
from .transports.apple import AppleProbe
from .transports.fastboot import FastbootProbe
from .transports.mtk_meta import MtkMetaProbe
from .transports.qualcomm_edl import QualcommEdlProbe
from .transports.samsung_download import SamsungDownloadProbe
from .transports.spd import SpdDownloadProbe
from .transports.spd_diagnostic import SpdDiagnosticProbe
from .transports.universal_usb import UniversalUsbProbe
from .transports.xiaomi_regional_manifest import XiaomiRegionalManifestProbe


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ttg-xray", description="TTG Device X-Ray")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a read-only device scan")
    scan.add_argument("--output", type=Path, default=Path("scans"))
    scan.add_argument("--mission", default="identify-and-plan")
    scan.add_argument(
        "--target-usb", action="append", default=[], metavar="VID:PID",
        help="Select any physically enumerated USB VID:PID as an investigation candidate "
             "without asserting a servicing protocol; may be repeated",
    )
    scan.add_argument(
        "--target-device", action="append", default=[], metavar="INVENTORY_ID",
        help="Select one enumerated endpoint by the 16-hex ID from discover",
    )
    scan.add_argument(
        "--profile-dir",
        type=Path,
        action="append",
        default=[],
        help="Additional profile directory; may be supplied more than once",
    )

    compare = subparsers.add_parser(
        "compare-regional",
        help="Compare two read-only Android firmware-regional manifests",
    )
    compare.add_argument(
        "left",
        type=Path,
        help="Left X-Ray bundle directory, transport_evidence.json, or manifest JSON",
    )
    compare.add_argument(
        "right",
        type=Path,
        help="Right X-Ray bundle directory, transport_evidence.json, or manifest JSON",
    )
    compare.add_argument("--output", type=Path, help="Optional JSON report path")

    ipsw = subparsers.add_parser(
        "inspect-ipsw", help="Inspect an Apple IPSW BuildManifest without restoring"
    )
    ipsw.add_argument("path", type=Path)
    ipsw.add_argument("--output", type=Path)

    discover = subparsers.add_parser(
        "discover", help="Enumerate USB interfaces without model/VID allowlists"
    )
    discover.add_argument(
        "--target-usb", action="append", default=[], metavar="VID:PID",
        help="Mark an OS-present USB endpoint for read-only investigation",
    )
    discover.add_argument(
        "--target-device", action="append", default=[], metavar="INVENTORY_ID",
        help="Mark one enumerated USB interface by its inventory ID",
    )
    discover.add_argument(
        "--output", type=Path,
        help="Optional unsigned JSON inventory report (not a signed X-Ray scan)",
    )

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
        "evidence_scope": str(capabilities.get("evidence_scope", "")),
        "region": str(identifiers.get("region", "")),
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


def _run_regional_compare(args: argparse.Namespace) -> int:
    try:
        report = compare_regional_sources(args.left, args.right)
    except RegionalCompareError as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 2

    body = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(body, encoding="utf-8")
    print(body, end="")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    runner = CommandRunner()
    platform_tools = PlatformToolsRunner(runner)

    if args.command == "discover":
        try:
            inventory = UniversalUsbProbe(
                runner, target_usb=tuple(args.target_usb),
                target_device=tuple(args.target_device),
            ).probe()
        except ValueError as exc:
            print(json.dumps({"error": str(exc), "source": "universal_usb"}))
            return 2
        devices = [
            {
                "vid_pid": str(item.identifiers.get("usb_vid", "")) + ":"
                + str(item.identifiers.get("usb_pid", "")),
                "inventory_id": item.identifiers.get("inventory_id", ""),
                "os_interface": item.capabilities.get("os_interface_class", ""),
                "pnp_class": item.capabilities.get("os_pnp_class", ""),
                "selected": item.connected,
                "explicitly_selected": bool(
                    item.capabilities.get("selected_explicitly", False)
                ),
                "protocol_verified": False,
                "write_allowed": False,
            }
            for item in inventory
            if item.capabilities.get("usb_present") is True
        ]
        payload = {
            "schema": "ttg.xray.universal-usb-discovery.v1",
            "evidence_scope": "OS_PRESENT_USB_ONLY",
            "signed": False,
            "host_read_only": True,
            "protocol_verified": False,
            "write_allowed": False,
            "inventory_available": any(item.available for item in inventory),
            "inventory_count": len(devices),
            "inventory_truncated": any(
                item.capabilities.get("inventory_truncated") is True
                for item in inventory
            ),
            "candidate_count": sum(1 for item in devices if item["selected"]),
            "devices": devices,
            "next_step": (
                "Run signed scan --target-device INVENTORY_ID for one endpoint; "
                "USB presence is not a servicing capability"
            ),
        }
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                json.dumps(payload, sort_keys=True, indent=2) + "\n",
                encoding="utf-8",
            )
        print(json.dumps(payload, indent=2))
        return 0 if payload["inventory_available"] else 2

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
                        "spd_diagnostic": {
                            **_helper_status("TTG_SPD_DIAGNOSTIC"),
                            "observed_vid_pid": "1782:4D00",
                            "purpose": "diagnostic-presence-only; no download claim",
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

    if args.command == "compare-regional":
        return _run_regional_compare(args)

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
            XiaomiRegionalManifestProbe(platform_tools),
            FastbootProbe(platform_tools),
            MtkMetaProbe(runner),
            QualcommEdlProbe(runner),
            SpdDownloadProbe(runner),
            SpdDiagnosticProbe(runner),
            UniversalUsbProbe(
                runner, target_usb=tuple(args.target_usb),
                target_device=tuple(args.target_device),
            ),
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
    seal = seal_bundle(target, bundle)
    print(
        json.dumps(
            {
                "scan_id": bundle.scan_id,
                "candidate_count": len(bundle.candidates),
                "usb_inventory_count": sum(
                    1 for item in bundle.observations
                    if item.transport.value == "usb_inventory"
                    and item.capabilities.get("usb_present") is True
                ),
                "usb_inventory": [
                    {
                        "vid_pid": str(item.identifiers.get("usb_vid", ""))
                        + ":" + str(item.identifiers.get("usb_pid", "")),
                        "inventory_id": item.identifiers.get("inventory_id", ""),
                        "os_interface_class": item.capabilities.get("os_interface_class"),
                        "os_pnp_class": item.capabilities.get("os_pnp_class"),
                        "selected_as_candidate": item.connected,
                        "mode": item.mode,
                        "protocol_verified": False,
                    }
                    for item in bundle.observations
                    if item.transport.value == "usb_inventory"
                    and item.capabilities.get("usb_present") is True
                ],
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
                "bundle_seal": seal,
                "output": str(target),
            },
            indent=2,
        )
    )
    return 0 if bundle.certification.verdict.value != "UNSAFE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
