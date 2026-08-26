# Android regional/customization evidence

TTG Device X-Ray records a second read-only ADB observation for regional firmware analysis. The
observation correlates to the normal ADB identity/storage observation through the same device serial,
but it has a deliberately narrower evidence scope: explain how a regional Android build is
customized without changing the device.

## Why this exists

Two firmware packages for the same hardware family may share the kernel, vendor stack, modem and
most system components while differing in product/cust overlays, preload policy, regional properties
and service packages. Treating those differences as a full-device identity problem makes regional
comparison harder than necessary.

The regional observation records evidence that can later be compared against an offline firmware
manifest or another known-good regional device. A ROM download is not required to build the live
phone side of the comparison.

## Evidence collected

The probe is read-only and records:

- allow-listed build, locale, Xiaomi/MIUI region and Google integration properties;
- the current Android user ID;
- package-manager knowledge including packages removed only for the current user (`pm -u`);
- system/user, disabled, hidden and suspended state for region-relevant packages;
- explicit presence/absence state for the core Google stack;
- whether the core Google stack is system-integrated, partial, absent or data/mixed;
- runtime overlay state from `cmd overlay list`;
- bounded recursive fingerprints for region-relevant configuration files under `/cust`, product,
  system-ext, vendor and ODM configuration roots;
- Xiaomi `mi_ext` file provenance when that logical partition is present;
- canonical firmware-regional and current-user manifests with SHA-256 digests.

The package manifest intentionally distinguishes:

```text
known_to_package_manager
installed_for_current_user
known_system_package
disabled_for_current_user
suspended_for_current_user
hidden_for_current_user
partition
```

That distinction is important after a technician has removed or suspended a preloaded system package
for user 0: the package may disappear from the launcher while still existing in the signed firmware.

## Configuration fingerprints

X-Ray does not need to copy regional configuration contents to compare builds. The v3 probe records
bounded file metadata instead:

```text
path
partition
size_bytes
sha256
```

All files under `/cust` are treated as regional evidence. On Xiaomi/HyperOS devices, files under
`/mi_ext` are also first-class regional evidence because HyperOS may overlay that verified logical
partition over paths in `/product`, `/system` and `/system_ext`. Outside those roots, the probe
retains only paths associated with Google/GMS, MIUI/Xiaomi, overlays, preload, region, sysconfig or
other customization markers. This gives a deterministic comparison surface without collecting
unrelated system files.

## Google integration classification

The core comparison set is:

```text
com.google.android.gms
com.google.android.gsf
com.android.vending
```

The probe reports `ABSENT`, `PARTIAL` or `PRESENT`, then separately reports whether those packages are
known system components or appear to be data/mixed installations. This is evidence only; it does not
claim Play Protect certification or authorize package installation.

## Xiaomi region inference

For Xiaomi/Redmi devices, X-Ray reports a bounded `region_inference` using explicit properties first
and Xiaomi build suffixes second. Recognized suffixes include:

```text
CNXM -> CN
MIXM -> GLOBAL
EUXM -> EEA
INXM -> INDIA
IDXM -> INDONESIA
TRXM -> TURKEY
TWXM -> TAIWAN
RUXM -> RUSSIA
```

This is evidence classification, not write authority. A suffix match never authorizes conversion,
firmware installation, property mutation or bootloader changes.

### Xiaomi `/cust` selector evidence

When MIUI/HyperOS regional properties are present, X-Ray additionally inspects the bounded Xiaomi
selector files:

```text
/cust/cust_variant
/cust/etc/business.prop
/cust/etc/cust_apps_request_config
/cust/etc/cust_apps_config
```

The resulting `xiaomi_customization_selector` records the file-backed SKU/cust variant, business
version, request metadata and canonical preload policy. Volatile APK/repository URLs are deliberately
excluded from the canonical policy so download-service changes do not create false firmware deltas.

X-Ray also reports consistency checks between the file-backed selector and live properties such as
`ro.miui.region` and `ro.miui.cust_variant`. A mismatch is evidence for review, not authorization to
rewrite either source.

### Xiaomi `mi_ext` provenance

HyperOS can provide a separate AVB-verified EROFS logical partition named `mi_ext` and overlay its
content over ordinary product/system paths. X-Ray records that signed source separately rather than
attributing all merged files to `/product` or `/system`.

`xiaomi_mi_ext` can include:

```text
present
partition.mi_ext.verified
partition.mi_ext.verified.hash_alg
partition.mi_ext.verified.root_digest
mount_source
filesystem
mount_options
buildprop.ro.miui.build.region
buildprop.ro.com.google.clientidbase
buildprop.ro.com.google.clientidbase.ms
```

The AVB root digest is evidence of partition identity. X-Ray does not read raw partition blocks and
does not use the digest to authorize flashing.

## Output location

Regional evidence remains inside the normal transport observations in `transport_evidence.json` and
the selected candidate evidence. Look for an ADB observation with:

```json
{
  "mode": "device",
  "capabilities": {
    "evidence_scope": "regional_customization",
    "read_only": true,
    "regional_manifest_schema": "ttg.xray.android-regional-manifest.v3"
  }
}
```

Useful fields include:

- `capabilities.regional_properties`
- `capabilities.region_inference`
- `capabilities.regional_packages`
- `capabilities.google_stack`
- `capabilities.google_integration`
- `capabilities.regional_overlays`
- `capabilities.customization_file_manifest`
- `capabilities.xiaomi_customization_selector`
- `capabilities.xiaomi_mi_ext`
- `capabilities.firmware_regional_manifest`
- `capabilities.firmware_regional_manifest_sha256`
- `capabilities.user_regional_state`
- `capabilities.user_regional_state_sha256`

The two state digests are deliberately separate. Firmware-region evidence can remain stable while
current user state changes after a debloat, suspension or reinstall.

## Regional comparison

`ttg-xray compare-regional LEFT RIGHT` compares two canonical manifests offline. In addition to the
generic properties, packages, overlays, customization-file hashes and Google-stack sections, v3
Xiaomi manifests expose first-class comparison sections for:

```text
xiaomi_customization_selector
xiaomi_preload_packages
xiaomi_mi_ext
```

Older v2 manifests remain valid comparison inputs; missing Xiaomi sections compare as empty evidence
rather than being synthesized into false differences.

## Safety boundary

The regional probe does not:

- write properties;
- change locale/region settings;
- enable, disable, suspend, install or uninstall packages;
- mutate overlays;
- read or write raw partitions;
- unlock or relock the bootloader;
- install firmware.

Any later repair or conversion operation must be implemented in a separately reviewed deterministic
adapter and consume X-Ray evidence rather than extending X-Ray's authority.
