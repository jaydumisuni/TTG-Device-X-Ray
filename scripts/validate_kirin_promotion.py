from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from ttg_device_xray.promoted_kirin import (  # noqa: E402
    PACK_ID,
    PACK_RESOURCE,
    SOURCE_COMMIT,
    SOURCE_MANIFEST_SHA256,
    SOURCE_REPOSITORY,
    load_promoted_vog_pack,
)

PROFILE = ROOT / "src" / "ttg_device_xray" / "profiles" / "huawei" / "vog_l29_c185_kirin.json"


def main() -> int:
    pack = load_promoted_vog_pack()
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    if not isinstance(profile, dict):
        raise SystemExit("promoted VOG profile must be a JSON object")

    safety = profile.get("safety")
    if not isinstance(safety, dict):
        raise SystemExit("promoted VOG profile safety block is missing")
    expected_safety = {
        "read_only": True,
        "write_allowed": False,
        "profile_cannot_authorize_repairs": True,
    }
    for key, expected in expected_safety.items():
        if safety.get(key) is not expected:
            raise SystemExit(f"promoted VOG profile safety.{key} must be {expected!r}")
    if profile.get("adapter_contracts") != {}:
        raise SystemExit("promoted VOG profile may not expose adapter contracts")

    capabilities = profile.get("capabilities")
    if not isinstance(capabilities, dict):
        raise SystemExit("promoted VOG profile capabilities are missing")
    reference = capabilities.get("kirin_capability_reference")
    if not isinstance(reference, dict):
        raise SystemExit("promoted Kirin capability reference is missing")

    expected_reference = {
        "schema": "ttg.kirin-capability-reference.v1",
        "pack_id": PACK_ID,
        "pack_version": pack["pack_version"],
        "packaged_path": PACK_RESOURCE,
        "source_repository": SOURCE_REPOSITORY,
        "source_commit": SOURCE_COMMIT,
        "source_manifest_path": "packs/kirin/manifest.json",
        "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "maturity": "replay_supported",
        "includes_execution": False,
        "xray_scope": "READ_ONLY_DIAGNOSTIC_PROMOTION",
    }
    for key, expected in expected_reference.items():
        if reference.get(key) != expected:
            raise SystemExit(f"promoted Kirin reference {key} mismatch")

    if capabilities.get("repair_profile_ready") is not False:
        raise SystemExit("promoted VOG diagnostic profile may not claim repair readiness")

    print(
        "Validated promoted Kirin VOG capability: "
        f"pack={PACK_ID} source={SOURCE_COMMIT} execution=false write=false"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
