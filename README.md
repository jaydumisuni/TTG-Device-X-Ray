# TTG Device X-Ray

[![CI](https://github.com/jaydumisuni/TTG-Device-X-Ray/actions/workflows/ci.yml/badge.svg)](https://github.com/jaydumisuni/TTG-Device-X-Ray/actions/workflows/ci.yml)

TTG Device X-Ray is the read-first device intelligence layer for THETECHGUY DIGITAL SOLUTIONS.
It identifies Android and Apple devices, records transport evidence, maps accessible storage,
challenges conflicting identity signals, resolves reviewed device profiles, and produces an auditable
repair, flash, or unbrick recommendation.

## Core rule

> X-Ray may observe, identify, correlate, challenge, certify, match profiles, and recommend. It does
> not perform destructive writes. Reviewed repair adapters consume its sealed evidence package.

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
fixture. No probe uploads a programmer, sends an FDL, writes PIT, flashes, formats, resets, or writes
a device partition.

## Pipeline

```text
PROBE
-> NORMALIZE
-> GROUP PHYSICAL DEVICES
-> CORRELATE IDENTITY
-> BUILD FIRMWARE FINGERPRINT
-> BUILD STORAGE SUMMARY
-> CHALLENGE
-> CERTIFY BY DIMENSION
-> RESOLVE REVIEWED PROFILE
-> PLAN
-> HUNTER
-> SEAL EVIDENCE BUNDLE
```

When multiple physical-device candidates are connected, the workstation-level result is `UNSAFE`.
Each candidate still receives separate evidence, but no repair profile is selected until a
single-device scan is produced.

Certification verdicts:

- `CERTIFIED`: identity evidence is coherent and sufficiently strong.
- `INVESTIGATE`: useful evidence exists, but a technician or Code Agent must resolve ambiguity.
- `UNSAFE`: identity is unknown, contradictory, or mixed across devices.

Certification records independent confidence dimensions for identity, transport, firmware, storage,
partition mapping, profile matching, and freshness. A profile never authorizes writing;
`write_allowed` remains `false` throughout X-Ray.

## Install for development

```powershell
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

Linux or macOS:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

## Local quality gate

Run the same deterministic checks used by CI:

```powershell
python scripts/run_local_checks.py
```

The gate validates the profile registry, validates offline service-mode fixtures, scans command
literals for forbidden device-write operations, runs Ruff, executes the test suite, builds the wheel
and source distribution, and verifies package metadata with Twine.

Individual validators are also available:

```powershell
python scripts/validate_profiles.py
python scripts/validate_fixtures.py
python scripts/check_read_only.py
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

Each helper receives `--probe-json`, `--read-only`, transport, and USB endpoint arguments, then
returns identity, capabilities, and optional partition evidence as JSON. Captured evidence can be
replayed with the matching `*_EVIDENCE_FILE` environment variable.

Canonical synthetic fixtures live in `tests/fixtures/` for MTK META, Qualcomm EDL, Unisoc/SPD, and
Samsung Download Mode. They contain no customer identifiers and require no connected hardware.

See `docs/mtk-meta-helper-contract.md`, `docs/service-mode-helper-contract.md`, and
`docs/candidate-bundle-v2.md`.

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

Delivery failures do not lose the scan. The payload is placed in `scans/_hunter_spool/`, and the
bundle receives `hunter_delivery.json`. Raw IMEI, ECID, UDID, and serial values are hashed by default.
Use `TTG_HUNTER_INCLUDE_SENSITIVE=1` only for an approved internal deployment.

Use `--no-hunter` for an intentionally offline scan or `--hunter-required` when delivery must
succeed.

## Evidence bundle

```text
scans/<scan-id>/
├─ mission.json
├─ transport_evidence.json
├─ candidates.json
├─ candidates/<candidate-id>/
│  ├─ device_identity.json
│  ├─ firmware_fingerprint.json
│  ├─ storage_summary.json
│  ├─ partition_map.json
│  ├─ challenger_findings.json
│  ├─ certification.json
│  └─ profile_match.json
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
├─ audit.jsonl
├─ bundle_manifest.json
└─ bundle_manifest.sig
```

The manifest records SHA-256 for every completed evidence file, schema and scanner versions, the
selected candidate ID, creation and expiry times, signer key ID, and the fixed read-only boundary.
Set `TTG_XRAY_SIGNING_KEY` and `TTG_XRAY_SIGNING_KEY_ID` on an approved workstation to emit a signed
HMAC manifest. Without a key, the bundle is explicitly marked `UNSIGNED`.

## CI and releases

Pull requests and pushes to `main` run:

- deterministic profile, fixture, and read-only boundary validation
- Ruff checks
- package build and Twine metadata validation
- Linux tests on Python 3.10 through 3.14
- Windows smoke tests and `ttg-xray doctor`
- one aggregate `CI Gate` result for branch protection

A release is created only from a version tag such as `v0.4.0`. The release workflow reruns the full
quality gate, verifies that the tag, `pyproject.toml`, and package `__version__` agree, builds wheel and
source archives, generates SHA-256 checksums, creates provenance attestations, and publishes the
GitHub Release.

## Safety boundary

No partition write, FRP clear, MDM removal, activation bypass, programmer upload, FDL upload, PIT
write, or firmware flashing operation belongs in this repository. Those actions must live in
separately reviewed deterministic adapters that require a certified X-Ray report and their own
authorization controls.

## License

TTG Device X-Ray is open source under the MIT License. See `LICENSE`.
