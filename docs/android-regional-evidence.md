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
manifest or another known-good regional device.

## Evidence collected

The probe is read-only and records:

- allow-listed build, locale, Xiaomi/MIUI region and Google integration properties;
- the current Android user ID;
- package-manager knowledge including packages removed only for the current user (`pm -u`);
- system/user and disabled state for region-relevant packages;
- explicit presence/absence state for the core Google stack;
- runtime overlay state from `cmd overlay list`;
- region-relevant filenames from fixed customization roots such as `/cust`, product/system-ext
  `sysconfig` and `permissions`, vendor and ODM configuration directories.

The package manifest intentionally distinguishes:

```text
known_to_package_manager
installed_for_current_user
known_system_package
disabled_for_current_user
partition
```

That distinction is important after a technician has removed a preloaded system package only for
user 0: the package may disappear from the launcher while still existing in the signed firmware.

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
flashing, property mutation or bootloader changes.

## Output location

Regional evidence remains inside the normal transport observations in `transport_evidence.json` and
the selected candidate evidence. Look for an ADB observation with:

```json
{
  "mode": "regional-device",
  "capabilities": {
    "evidence_scope": "regional_customization",
    "read_only": true
  }
}
```

Useful fields include:

- `capabilities.regional_properties`
- `capabilities.region_inference`
- `capabilities.regional_packages`
- `capabilities.google_stack`
- `capabilities.regional_overlays`
- `capabilities.customization_files`

## Safety boundary

The regional probe does not:

- write properties;
- change locale/region settings;
- enable, disable, suspend, install or uninstall packages;
- mutate overlays;
- read or write raw partitions;
- unlock or relock the bootloader;
- flash firmware.

Any later repair or conversion operation must be implemented in a separately reviewed deterministic
adapter and consume X-Ray evidence rather than extending X-Ray's authority.
