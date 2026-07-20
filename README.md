# TTG Device X-Ray

TTG Device X-Ray is the read-first device intelligence layer for THETECHGUY DIGITAL SOLUTIONS.
It identifies connected Android and Apple devices, records transport evidence, maps accessible
storage information, challenges conflicting identity signals, and produces an auditable repair,
flash, or unbrick recommendation.

## Core rule

> X-Ray may observe, identify, correlate, challenge, certify, and recommend. It does not perform
> destructive writes. Reviewed repair adapters consume its certified evidence package.

## Initial transports

- Android Debug Bridge (ADB)
- Fastboot / Fastbootd
- Apple normal mode through `libimobiledevice`
- Apple Recovery / DFU through `irecovery`

Later transports can be added without changing the core pipeline: MTK META/BROM, Qualcomm
DIAG/EDL, Unisoc download mode, Samsung Download Mode, and Apple service/ramdisk transports.

## Pipeline

```text
PROBE -> MAP -> CORRELATE -> CHALLENGE -> CERTIFY -> PLAN
```

Certification verdicts:

- `CERTIFIED`: identity evidence is coherent and sufficiently strong.
- `INVESTIGATE`: useful evidence exists, but a technician or Code Agent must resolve ambiguity.
- `UNSAFE`: identity is unknown or contradictory; no write workflow should be offered.

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
```

A scan creates a reusable evidence bundle:

```text
scans/<scan-id>/
├─ mission.json
├─ transport_evidence.json
├─ device_identity.json
├─ partition_map.json
├─ challenger_findings.json
├─ certification.json
├─ recommended_plan.json
└─ audit.jsonl
```

## Tool requirements

X-Ray uses tools already present on the workstation when available:

- `adb`
- `fastboot`
- `idevice_id` and `ideviceinfo`
- `irecovery`

Missing tools do not crash the full scan. Their probes report `unavailable`, and the remaining
transports continue.

## Safety boundary

No partition write, FRP clear, MDM removal, activation bypass, or firmware flashing operation
belongs in this repository. Those actions must live in separately reviewed deterministic adapters
that require a certified X-Ray report and their own authorization controls.
