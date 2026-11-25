"""Evidence-limited Android diagnostics; no device mutation or mode switching."""
from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path
from typing import Any

from ..models import ScanBundle, TransportObservation

# Linux kernel exposes these only on some drivers/devices. Missing != healthy.
HEALTH_SCRIPT = r'''for p in /sys/class/block/mmcblk[0-9] /sys/class/block/sd[a-z]; do
[ -e "$p" ] || continue
b=${p##*/}
for f in life_time pre_eol_info; do
v=$(cat "$p/device/$f" 2>/dev/null) || continue
printf '%s|%s|%s\n' "$b" "$f" "$v"
done
done
for p in /sys/bus/platform/devices/*/health_descriptor /sys/bus/platform/devices/*/*/health_descriptor; do
[ -d "$p" ] || continue
for f in eol_info life_time_estimation_a life_time_estimation_b; do
v=$(cat "$p/$f" 2>/dev/null) || continue
printf '%s|%s|%s\n' "$p" "$f" "$v"
done
done
for p in /sys/class/block/*/start; do
[ -f "$p" ] || continue
b=${p%/start}; b=${b##*/}
v=$(cat "$p" 2>/dev/null) || continue
printf '%s|start_sector_512|%s\n' "$b" "$v"
done'''
ERROR_SCRIPT = r'''logs=$(dmesg 2>/dev/null) || exit 1
printf '%s\n' "$logs" | grep -Ei 'I/O error|Buffer I/O|mmc.*(timeout|error)|ufs.*(fatal|error)|EXT4-fs error|F2FS-fs.*(corrupt|error)|dm-verity.*(corrupt|fail)' | tail -n 80'''


def parse_health(text: str) -> dict[str, Any]:
    health: list[dict[str, Any]] = []
    starts: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split("|", 2)
        if len(parts) != 3:
            continue
        source, field, raw = parts
        if field == "start_sector_512":
            if raw.isdecimal():
                starts[source] = int(raw)
            continue
        if field not in {"life_time", "pre_eol_info", "eol_info",
                         "life_time_estimation_a", "life_time_estimation_b"}:
            continue
        try:
            values = [int(x, 16) if x.lower().startswith("0x") else int(x)
                      for x in raw.split()]
        except ValueError:
            continue
        if not values or any(v < 0 or v > 255 for v in values):
            continue
        is_eol = field in {"pre_eol_info", "eol_info"}
        known = [v for v in values if 1 <= v <= (3 if is_eol else 11)]
        worst = max(known, default=0)
        health.append({
            "source": source, "field": field, "values": values,
            "status": (
                "URGENT" if (worst == 3 if is_eol else worst == 11) else
                "WARNING" if (worst == 2 if is_eol else worst >= 9) else
                "REPORTED" if len(known) == len(values) else "UNKNOWN"
            ),
        })
    return {"health_descriptors": health, "physical_start_sectors_512": starts}


def classify_errors(text: str) -> list[dict[str, str]]:
    patterns = {
        "STORAGE_IO": r"(?:Buffer )?I/O error.*(?:mmcblk|\bsd[a-z]|\bdm-\d)|"
        r"(?:mmc\d|ufshcd).*?(?:timeout|fatal|error)",
        "FILESYSTEM": r"EXT4-fs error|F2FS-fs.*(?:corrupt|error)",
        "VERIFIED_BOOT": r"dm-verity.*(?:corrupt|fail)",
    }
    return [{"kind": kind, "line": line[:512]}
            for line in text.splitlines()[:80]
            for kind, pattern in patterns.items() if re.search(pattern, line, re.I)]


def inspect_partition(path: Path, kind: str, reference: Path | None = None) -> dict[str, Any]:
    """Inspect a local raw image; no device paths or filesystem repair."""
    if not path.is_file() or (reference is not None and not reference.is_file()):
        raise ValueError("Only regular local image files are accepted")
    size = path.stat().st_size
    with path.open("rb") as stream:
        head = stream.read(4096)
        stream.seek(0)
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    status, detail = inspect_header(head, size, kind)
    result: dict[str, Any] = {
        "kind": kind, "size_bytes": size, "sha256": digest.hexdigest(),
        "status": status, "detail": detail, "reference_match": None,
        "scope": "LOCAL_ARTIFACT_ONLY", "write_allowed": False,
    }
    if reference is not None:
        other = hashlib.sha256()
        with reference.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                other.update(chunk)
        result["reference_sha256"] = other.hexdigest()
        result["reference_match"] = size > 0 and digest.digest() == other.digest()
        result["reference_scope"] = "BYTE_COMPARISON_ONLY; exact model/build not inferred"
    return result


def inspect_header(head: bytes, size: int, kind: str) -> tuple[str, str]:
    status = "UNKNOWN"
    detail = "No supported structure recognized"
    if size == 0:
        detail = "Empty artifact is not evidence of a corrupt partition"
    elif head[:4] == b"\x3a\xff\x26\xed":
        detail = "Android sparse container; decode to raw before structure comparison"
    elif kind == "boot":
        if head[:8] != b"ANDROID!":
            detail = "Expected Android boot magic absent; format or corruption unresolved"
        elif len(head) < 48:
            status, detail = "STRUCTURAL_ERROR", "Truncated boot header"
        else:
            version = struct.unpack_from("<I", head, 40)[0]
            kernel = struct.unpack_from("<I", head, 8)[0]
            if version in (3, 4):
                ramdisk = struct.unpack_from("<I", head, 12)[0]
                page = 4096
                header_size = struct.unpack_from("<I", head, 20)[0]
                valid = (1580 if version == 3 else 1584) <= header_size <= page
            elif version in (0, 1, 2):
                ramdisk = struct.unpack_from("<I", head, 16)[0]
                page = struct.unpack_from("<I", head, 36)[0]
                valid = page in (2048, 4096, 8192, 16384)
            else:
                page, ramdisk, valid = 0, 0, False
            if valid:
                minimum = page + ((kernel + page - 1) // page) * page + ramdisk
                status = "HEADER_VALID" if kernel and size >= minimum else "STRUCTURAL_ERROR"
                detail = "Boot header and minimum payload bounds; not signature validation"
            else:
                detail = "Unsupported or invalid header layout"
    elif kind == "filesystem":
        if len(head) >= 2048 and head[1080:1082] == b"\x53\xef":
            blocks = struct.unpack_from("<I", head, 1028)[0]
            shift = struct.unpack_from("<I", head, 1048)[0]
            if shift <= 6 and blocks > 0:
                minimum = blocks * (1024 << shift)
                status = "HEADER_VALID" if minimum <= size else "STRUCTURAL_ERROR"
                detail = "ext superblock lower-bound check; not a full filesystem check"
            else:
                status, detail = "STRUCTURAL_ERROR", "Invalid ext superblock geometry"
        elif head[1024:1028] == b"\x10\x20\xf5\xf2":
            status, detail = "MAGIC_ONLY", "F2FS superblock magic; full check not performed"
    return status, detail


def _dict_rows(value: Any) -> list[dict[str, Any]]:
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def diagnose(observations: list[TransportObservation]) -> dict[str, Any]:
    active = [o for o in observations if o.connected]
    modes = sorted({o.transport.value for o in active})
    health = []
    for o in active:
        storage = o.capabilities.get("deep_storage", {})
        if not isinstance(storage, dict):
            continue
        for row in _dict_rows(storage.get("health_descriptors")):
            if isinstance(row, dict) and row.get("status") in {
                "REPORTED", "WARNING", "URGENT", "UNKNOWN"
            }:
                health.append({"transport": o.transport.value, **row})
    errors = [{"transport": o.transport.value, **e}
              for o in active for e in _dict_rows(o.capabilities.get("deep_errors"))]
    known = {e["kind"] for e in errors if isinstance(e.get("kind"), str)}
    integrity = [{"transport": o.transport.value, **p}
                 for o in active for p in _dict_rows(o.capabilities.get("partition_integrity"))]
    builds = sorted({o.identifiers.get("build", "").strip() for o in active
                     if o.identifiers.get("build", "").strip()})
    structural = [p for p in integrity if p.get("status") == "STRUCTURAL_ERROR"]
    boot_structural = any(p.get("kind") == "boot" for p in structural)
    read_errors = [p for p in integrity if p.get("read_error") == "IO_ERROR"]
    routes = []
    for o in active:
        if o.transport.value == "fastboot":
            fetch = o.identifiers.get("max-fetch-size", "")
            routes.append({"interface": "fastboot", "status": "ACTIVE",
                           "partition_readback": "ADVERTISED" if fetch else "NOT_ADVERTISED"})
    if active and "adb" not in modes and any(o.transport.value == "fastboot" for o in active):
        routes.append({"interface": "adb-recovery", "status": "NOT_OBSERVED",
                       "next": "Operator may enter recovery; verify identity again"})
    if "fastboot" not in modes and any(o.transport.value == "adb" for o in active):
        routes.append({"interface": "fastboot", "status": "NOT_OBSERVED",
                       "next": "Consider bootloader only if current ADB evidence is insufficient"})
    if "qualcomm_edl" not in modes and any(
        re.match(r"^(MSM|SDM|SM)\d", o.identifiers.get("product", ""), re.I)
        or any(re.match(r"^(MSM|SDM|SM)\d", o.identifiers.get(k, ""), re.I)
               for k in ("chipset", "soc", "board"))
        or "qualcomm" in o.identifiers.get("chipset", "").lower()
        for o in active
    ):
        routes.append({"interface": "qualcomm_edl", "status": "NOT_OBSERVED",
                       "next": "Requires model-matched reviewed read-only helper"})
    for o in active:
        if o.transport.value != "fastboot":
            routes.append({"interface": o.transport.value, "status": "ACTIVE",
                           "partition_entries": len(o.partitions),
                           "protocol_confirmed": o.capabilities.get("transport_confirmed"),
                           "helper_configured": o.capabilities.get("helper_configured")})
    # No negative inference from unavailable evidence or empty logs.
    causes = {
        "storage_failure": "SUSPECTED" if "STORAGE_IO" in known or read_errors or any(
            h["status"] in {"URGENT", "WARNING"} for h in health) else "UNKNOWN",
        "filesystem_damage": "SUSPECTED" if "FILESYSTEM" in known else "UNKNOWN",
        "boot_chain_failure": (
            "SUSPECTED" if "VERIFIED_BOOT" in known or boot_structural else "UNKNOWN"
        ),
        "firmware_mismatch": "POSSIBLE_BUILD_CONFLICT" if len(builds) > 1 else "UNKNOWN",
        "partition_corruption": "SUSPECTED" if structural else "UNKNOWN",
    }
    return {"active_interfaces": modes, "alternative_interfaces": routes,
            "health_descriptors": health, "error_evidence": errors, "causes": causes,
            "partition_integrity": integrity, "observed_build_labels": builds,
            "physical_partition_map": [
                {"transport": o.transport.value, **p}
                for o in active for p in o.partitions
                if "start_sector_512" in p or "start_sector" in p
            ],
            "coverage": {
                "storage_health": "OBSERVED" if health else "UNAVAILABLE",
                "kernel_errors": "OBSERVED" if errors else "NO_POSITIVE_EVIDENCE",
                "partition_headers": "OBSERVED" if any(
                    p.get("status") != "UNKNOWN" for p in integrity
                ) else "UNAVAILABLE",
            },
            "build_conflict_note": "Different labels require same-format firmware verification",
            "write_allowed": False, "mode_switch_performed": False}


def load_reference(path: Path) -> dict[str, Any]:
    """Operator-supplied metadata; never represented as vendor-signed evidence."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Reference must be an object")
    if not all(isinstance(payload.get(k), str) and payload[k].strip()
               for k in ("model", "build")):
        raise ValueError("Reference requires model and build")
    parts = payload.get("partitions")
    if not isinstance(parts, dict) or not parts:
        raise ValueError("Reference requires partition hashes and sizes")
    for name, row in parts.items():
        if (not isinstance(name, str) or not isinstance(row, dict)
                or not isinstance(row.get("sha256"), str)
                or not re.fullmatch(r"[a-fA-F0-9]{64}", row["sha256"])
                or type(row.get("size_bytes")) is not int or row["size_bytes"] <= 0):
            raise ValueError("Invalid reference partition entry")
    return payload


def compare_reference(report: dict[str, Any], model: str, build: str,
                      reference: dict[str, Any]) -> dict[str, Any]:
    if not model or not build:
        return {"status": "IDENTITY_INCOMPLETE", "comparisons": []}
    if model.casefold() != reference["model"].casefold() or build != reference["build"]:
        return {"status": "REFERENCE_NOT_APPLICABLE", "comparisons": []}
    rows = []
    for p in report["partition_integrity"]:
        expected = reference["partitions"].get(p.get("name"))
        if expected is None:
            continue
        if p.get("size_bytes") != expected["size_bytes"] or not p.get("sha256"):
            status = "NOT_COMPARABLE"
        else:
            status = ("MATCH" if p["sha256"].lower() == expected["sha256"].lower()
                      else "BYTE_MISMATCH")
        rows.append({"name": p["name"], "status": status,
                     "observed_sha256": p.get("sha256"),
                     "expected_sha256": expected["sha256"]})
    return {"status": "COMPARED" if rows else "NO_READBACK", "comparisons": rows,
            "trust": "OPERATOR_SUPPLIED_REFERENCE; not authenticated firmware"}


def bundle_diagnostics(bundle: ScanBundle,
                       reference: dict[str, Any] | None = None) -> dict[str, Any]:
    reports = {}
    for c in bundle.candidates:
        report = diagnose(c.observations)
        if reference is not None:
            comparison = compare_reference(
                report, c.identity.internal_model, c.identity.build, reference
            )
            report["firmware_reference"] = comparison
            if any(row["status"] == "BYTE_MISMATCH" for row in comparison["comparisons"]):
                report["reference_finding"] = "PARTITION_DIFFERS_FROM_REFERENCE"
        reports[c.candidate_id] = report
    return {"schema": "ttg.xray.deep-diagnostics.v1",
            "selected_candidate_id": bundle.selected_candidate_id,
            "candidates": reports, "write_allowed": False}
