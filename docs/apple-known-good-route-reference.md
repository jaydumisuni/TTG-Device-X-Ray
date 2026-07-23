# Apple Known-Good Route References

## Purpose

TTG Device X-Ray may certify that an observed Apple device matches a documented service-route family. It remains read-only and does not pwn, boot, restore, jailbreak, mount, or write the device.

The reference exists so downstream reviewed adapters do not begin from guessed timing, baud, boot arguments, or asset selection when a working route is already documented.

## A8-A11 baseline

The first candidate reference records:

- Gaster as the documented checkm8 pwn provider;
- the pinned upstream source commit;
- known working ramdisk and Diags catalogues as reference sources;
- the expected DFU, pwned-DFU, patched-iBoot/recovery, and ramdisk/Purple transitions;
- local-only, device-exact, SHA-256-pinned asset requirements.

The profile intentionally remains `CANDIDATE`. A broad family reference is not a device-exact repair profile and exposes no adapter contract until exact product, board, firmware, assets, and evidence are reviewed.

## X-Ray evidence boundary

X-Ray may report:

```text
observed Apple identity
→ matched documented route family
→ expected transport transitions
→ required local asset classes
→ reference provenance
→ missing device-exact evidence
```

X-Ray may not:

- download or redistribute Apple images;
- execute Gaster or another exploit;
- select an unpinned local binary;
- authorize a ramdisk, Purple, jailbreak, restore, or SysCfg operation;
- convert a candidate reference into write permission.

`write_allowed` remains `false` in the profile, certification, plan, and sealed evidence bundle.

## Promotion path

A reference becomes a reviewed device route only after a separate manifest records:

1. exact product type and board configuration;
2. exact firmware build or tested range;
3. exact Gaster build hash and source commit;
4. every local boot or ramdisk asset SHA-256;
5. fixed ordered boot stages and expected transitions;
6. a redacted working transcript from an authorised device;
7. failure and recovery evidence;
8. independent review in the consuming adapter repository.

TGCHECKM8 remains the operational authority. X-Ray supplies sealed read-only identity and route evidence only.
