# Device candidates and sealed evidence bundles

TTG Device X-Ray v0.4 separates workstation observations into physical-device candidates before identity correlation.

## Pipeline

```text
PROBE
-> NORMALIZE
-> GROUP DEVICES
-> CORRELATE IDENTITY
-> BUILD FIRMWARE FINGERPRINT
-> BUILD STORAGE SUMMARY
-> CHALLENGE
-> CERTIFY
-> RESOLVE APPROVED PROFILE
-> PLAN
-> HUNTER
-> SEAL BUNDLE
```

## Candidate boundary

Observations with the same strong identifier may be grouped. Android serials, Apple UDIDs, Apple serial numbers and Apple ECIDs remain distinct identifier types.

Apple ProductType, HardwareModel, CPID and BDID agreement creates a cross-mode link proposal with recorded confidence. Hardware attributes alone do not merge candidates because two different phones of the same model can match them. Automatic normal/recovery grouping also requires a shared scan/session correlation token or a same-type strong identifier. ECID is never rewritten as a serial number.

When more than one candidate is present, the workstation-level result is `UNSAFE` with `MULTIPLE_DEVICE_CANDIDATES`. Each candidate still receives its own identity, firmware, storage, challenge and certification records, but no repair profile is selected until a single-device scan exists.

## Certification dimensions

Every candidate records independent confidence dimensions:

- identity confidence
- transport confidence
- firmware confidence
- storage confidence
- partition-map confidence
- profile-match confidence
- freshness confidence

The overall confidence remains available for display, but a downstream repair adapter can enforce its own minimum dimension requirements.

## Profile proposals and matches

A generated identifier such as `android:tecno:km7:mt6765` is stored as `proposed_profile_id`. It is not proof that an approved profile exists.

`ProfileLoader` resolves the proposal against packaged and configured profile registries and returns `MATCHED`, `CANDIDATE`, `NO_MATCH`, `NO_PROFILE`, `NO_SELECTION` or `BLOCKED_UNSAFE`. All results retain `write_allowed: false`.

## Bundle sealing

After profile routing and Hunter delivery, X-Ray writes:

- `bundle_manifest.json`
- `bundle_manifest.sig`

The manifest includes SHA-256 for every completed evidence file, the scan and bundle schema versions, scanner version, selected candidate ID, creation and expiry times, signer key ID and the fixed read-only boundary.

Set these on the shop workstation to produce a signed bundle:

```powershell
$env:TTG_XRAY_SIGNING_KEY='use-a-secret-from-the-shop-key-store'
$env:TTG_XRAY_SIGNING_KEY_ID='ttg-shop-xray-v1'
```

Without a key, the digest manifest is still produced but the signature status is explicitly `UNSIGNED`. Repair adapters may require `SIGNED`.

## Ptah placement

X-Ray is a Device Detector and Domain Pack evidence producer:

```text
TTG Device X-Ray
-> Ptah Detector Observations
-> Device/Profile/Partition evidence
-> sealed Evidence Bundle
-> reviewed recovery/flash/unbrick adapter
```

X-Ray does not become Ptah Core and does not execute destructive repair operations.
