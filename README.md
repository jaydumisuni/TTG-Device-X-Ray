# TTG Device X-Ray

TTG Device X-Ray is the read-first device intelligence layer for THETECHGUY DIGITAL SOLUTIONS.
It identifies Android and Apple devices, records transport evidence, maps accessible storage,
challenges conflicting identity signals, matches reviewed device profiles, and produces an auditable
repair, flash, or unbrick recommendation.

## Core rule

> X-Ray may observe, identify, correlate, challenge, certify, match profiles, and recommend. It does
> not perform destructive writes. Reviewed repair adapters consume its certified evidence package.

## Active transports

- Android Debug Bridge (ADB)
- Fastboot / Fastbootd
- MTK Preloader and Kernel META (`0E8D:2000` / `0E8D:2007`)
- Qualcomm Emergency Download / EDL candidate detection
- Spreadtrum / Unisoc download-mode candidate detection
- Samsung Odin / Download Mode candidate detection
- Apple normal mode through `libimobiledevice`
- Apple Recovery / DFU through `irecovery`

Every emergency/download probe supports an optional read-only JSON helper and offline evidence
fixture. No probe uploads a programmer, sends an FDL, reads PIT automatically, flashes, formats, or
writes a partition.

## Pipeline

```text
PROBE -> MAP -> CORRELATE -> CHALLENGE -> CERTIFY -> PROFILE -> PLAN -> HUNTER
```

Certification verdicts:

- `CERTIFIED`: identity evidence is coherent and sufficiently strong.
- `INVESTIGATE`: useful evidence exists, but a technician or Code Agent must resolve ambiguity.
- `UNSAFE`: identity is unknown or contradictory; no write workflow should be offered.

Profile verdicts:

- `MATCHED`: profile evidence is strong enough for planning and adapter routing.
- `CANDIDATE`: a likely profile exists but needs more evidence.
- `NO_MATCH` / `NO_PROFILE`: no profile should be trusted for routing.

A profile never authorizes writing. `write_allowed` remains `false` throughout X-Ray.

## Current intelligence

Android scans can collect:

- brand, model, internal device, board, SoC, build, fingerprint and security patch
- baseband, bootloader, kernel and Verified Boot state
- eMMC/UFS/NVMe model and capacity where exposed
- partition paths, block devices, sector counts, logical block sizes and sizes
- A/B slot and dynamic-partition evidence
- partition risk classification and cross-transport size conflicts
- service-mode identity, storage and GPT evidence supplied by read-only helpers

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

Extra profile directories may be supplied without changing the engine:

```powershell
ttg-xray scan --profile-dir D:\TTG\profiles --output scans
```

## Read-only service helpers

```powershell
$env:TTG_MTK_META_HELPER='python D:\TTG\helpers\mtk_meta_probe.py'
$env:TTG_QUALCOMM_EDL_HELPER='python D:\TTG\helpers\qualcomm_edl_probe.py'
$env:TTG_SPD_HELPER='python D:\TTG\helpers\spd_probe.py'
$env:TTG_SAMSUNG_DOWNLOAD_HELPER='python D:\TTG\helpers\samsung_download_probe.py'
```

Each helper receives `--probe-json`, `--read-only`, transport and USB endpoint arguments, then
returns identity, capabilities and optional partition evidence as JSON. Captured evidence can be
replayed with the matching `*_EVIDENCE_FILE` environment variable.

See `docs/mtk-meta-helper-contract.md` and `docs/service-mode-helper-contract.md`.

## Automatic Hunter bridge

Every scan is posted to Hunter after the evidence bundle and profile match are written. Configure an
exact endpoint or a Hunter base URL:

```powershell
$env:TTG_HUNTER_XRAY_URL='https://hunter.thetechguyds.com/api/device-xray/ingest'
# or
$env:TTG_HUNTER_URL='https://hunter.thetechguyds.com'
$env:TTG_HUNTER_TOKEN='...'
ttg-xray scan --output scans
```

Delivery failures do not lose the scan. The payload is placed in `scans/_hunter_spool/` and the
bundle receives `hunter_delivery.json`. Raw IMEI, ECID and serial values are hashed by default; set
`TTG_HUNTER_INCLUDE_SENSITIVE=1` only for an approved internal deployment.

Use `--no-hunter` for an intentionally offline scan or `--hunter-required` when delivery must
succeed.

## Evidence bundle

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
├─ profile_match.json
├─ recommended_plan.json
├─ hunter_payload.json
├─ hunter_delivery.json
└─ audit.jsonl
```

## Packaged profile fixture

The first packaged profile is `src/ttg_device_xray/profiles/transsion/km7.json`. It matches
`android:tecno:km7:mt6765` and aliases, checks independent device evidence, records transport
priority, and exposes adapter contract names for the repair, flash and unbrick planners. Its stage is
`CANDIDATE`, and it cannot authorize a write.

## Tool requirements

X-Ray uses tools already present on the workstation when available:

- `adb`
- `fastboot`
- Windows PowerShell / PowerShell Core or `lsusb` for service-mode USB inventory
- `idevice_id` and `ideviceinfo`
- `irecovery`

Missing tools do not crash the full scan. Their probes report `unavailable`, and the remaining
transports continue.

## Safety boundary

No partition write, FRP clear, MDM removal, activation bypass, programmer upload, FDL upload, PIT
write, or firmware flashing operation belongs in this repository. Those actions must live in
separately reviewed deterministic adapters that require a certified X-Ray report and their own
authorization controls.
