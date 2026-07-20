# TTG Device X-Ray

TTG Device X-Ray is the read-first device intelligence layer for THETECHGUY DIGITAL SOLUTIONS.
It identifies connected Android and Apple devices, records transport evidence, maps accessible
storage information, challenges conflicting identity signals, and produces an auditable repair,
flash, or unbrick recommendation.

## Core rule

> X-Ray may observe, identify, correlate, challenge, certify, and recommend. It does not perform
> destructive writes. Reviewed repair adapters consume its certified evidence package.

## Active transports

- Android Debug Bridge (ADB)
- Fastboot / Fastbootd
- MTK Preloader and Kernel META detection (`0E8D:2000` / `0E8D:2007`)
- Optional D2e/TSM MTK META read-only helper bridge
- Apple normal mode through `libimobiledevice`
- Apple Recovery / DFU through `irecovery`

Planned next transports are Qualcomm DIAG/EDL, Unisoc download mode, Samsung Download Mode,
and Apple service/ramdisk transports.

## Pipeline

```text
PROBE -> MAP -> CORRELATE -> CHALLENGE -> CERTIFY -> PLAN
```

Certification verdicts:

- `CERTIFIED`: identity evidence is coherent and sufficiently strong.
- `INVESTIGATE`: useful evidence exists, but a technician or Code Agent must resolve ambiguity.
- `UNSAFE`: identity is unknown or contradictory; no write workflow should be offered.

## Current intelligence

Android scans can collect:

- brand, model, internal device, board, SoC, build, fingerprint and security patch
- baseband, bootloader, kernel and Verified Boot state
- eMMC/UFS/NVMe model and capacity where exposed
- partition paths, block devices, sector counts, logical block sizes and sizes
- A/B slot and dynamic-partition evidence
- partition risk classification and cross-transport size conflicts

Apple scans can collect normal, Recovery and DFU identity. IPSW archives can be inspected offline
to extract BuildManifest compatibility keys, ProductTypes, board configurations, chip IDs,
board IDs, restore behavior and component paths.

## Install for development

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Run

```powershell
ttg-xray doctor
ttg-xray scan --output scans
ttg-xray inspect-ipsw .\firmware\device.ipsw --output .\reports\device-ipsw.json
```

### MTK META helper

The USB probe works without vendor DLLs. To plug in the proven D2e/TSM read-only session chain:

```powershell
$env:TTG_MTK_META_HELPER='D:\aimob\hunter\venv\Scripts\python.exe D:\projects\TTG-META\ttg_mtk_meta_probe_helper.py'
ttg-xray scan --output scans
```

See `docs/mtk-meta-helper-contract.md` for the JSON contract. Captured evidence can also be
replayed with `TTG_MTK_META_EVIDENCE_FILE` for fixtures and profile development.

## Evidence bundle

A scan creates:

```text
scans/<scan-id>/
├─ mission.json
├─ transport_evidence.json
├─ device_identity.json
├─ storage_summary.json
├─ partition_map.json
├─ firmware_fingerprint.json
├─ challenger_findings.json
├─ certification.json
├─ recommended_plan.json
└─ audit.jsonl
```

## Tool requirements

X-Ray uses tools already present on the workstation when available:

- `adb`
- `fastboot`
- Windows PowerShell or PowerShell Core for MTK PnP detection
- `idevice_id` and `ideviceinfo`
- `irecovery`

Missing tools do not crash the full scan. Their probes report `unavailable`, and the remaining
transports continue.

## Safety boundary

No partition write, FRP clear, MDM removal, activation bypass, or firmware flashing operation
belongs in this repository. Those actions must live in separately reviewed deterministic adapters
that require a certified X-Ray report and their own authorization controls.
