# X-Ray to COG: Host-owned evidence authority

Status: opt-in implementation, KRATOS host keys enrolled, NOT independently admitted to production.

## Source of authority

TTG Device X-Ray creates a native v2 HMAC-SHA256 bundle. The X-Ray host-owned module cog_host_attestation.py verifies the native HMAC, file inventory, signing identity, expiry, owner-controlled revocations, file byte limits and symlink/path constraints. Its Ed25519 private attestor separately signs a bounded read-only COG observation.

COG must receive ONLY the signed Ed25519 observation. The public key and product-to-signer mapping must come from the independently configured host authority, not from a field sent by the claim. The HMAC secret and Ed25519 private key remain under the host owner's restricted filesystem directory, outside Cookpit and GitHub.

New enrollment is fail-closed, cannot overwrite an existing key directory, and always reports HOST_ENROLLED_NOT_ADMITTED. Revocation is explicit and irreversible through the API, with a hash-chained append-only local journal. A compromised host user can still erase this local journal; separate owner/operator custody and independent reviewer acceptance are required for a production authorization claim.

## Host operator commands

Run from a host where the optional cryptography package is installed:

    ROOT="$HOME/.local/state/ttg-device-xray/cog-host-trust"
    python3 -m ttg_device_xray.cog_host_attestation enroll --root "$ROOT" --product ttg-device-xray --host KRATOS
    python3 -m ttg_device_xray.cog_host_attestation inspect --root "$ROOT"
    python3 -m ttg_device_xray.cog_host_attestation scan --root "$ROOT" --output "/registered/project/evidence"
    python3 -m ttg_device_xray.cog_host_attestation attest --root "$ROOT" --bundle "/path/to/native/bundle"
    python3 -m ttg_device_xray.cog_host_attestation revoke --root "$ROOT" --key-id "exact-key-id" --reason "owner justification"

The scan command runs only the native read-only X-Ray CLI with a fixed allowlisted argv. It passes the HMAC secret only in the child process environment; no secret is printed or included in COG. A zero-candidate scan is not a device certification.

## Actual evidence

The KRATOS native scan xray-20261123-005108-05749dac had zero connected candidates, correctly UNSAFE. Its HMAC and host Ed25519 claim were verified, and COG processed the host's signed observation without receiving the HMAC key; result OBSERVED_CONFORMING for the count-zero observation, no execution authorization, SHADOW_UNQUALIFIED.

The private Cookpit proof is G1_XRAY_HOST_SIGNED_REAL_COG_BRIDGE_20261123.json. The X-Ray source is on a separate review branch; its complete tests passed 94/94 when first constructed.

## Open release gates

Independent G0/G1 owner and signing-key admission, a genuine connected-device readback, protected off-host revocation custody, real product execution permissions and G6 owner activation are still pending. This source does not register production effects, upgrade active COG, or merge a protected branch.


## Windows qualification limitation

The native X-Ray scanner remains cross-platform. Host private-key enrollment and
attestation explicitly refuse Windows until a Windows ACL/DPAPI or equivalent
OS owner-custody implementation receives separate security review. No Unix 0700/
0600 mode claim is made on Windows. Windows smoke tests skip only these
Linux-private-key custody checks; tests for the scanner remain enabled.


## Real SPRD diagnostic USB readback

The read-only X-Ray transports now include a separate `spd_diagnostic`
presence observation for the Windows PnP `SPRD U2S Diag` interface at USB
VID 1782, PID 4D00. This is distinct from SPD download: observing a diagnostic
USB endpoint does not prove a valid download session, FDL loader access,
storage/partition access, product firmware identity or permission to write.
No diagnostic port is opened and no service command is issued. Other UNISOC
USB devices remain unqualified unless independently matched.

ATHENA PnP reported the COM52 interface physically present and healthy.
An earlier X-Ray scan missed the exact diagnostic label and returned zero
candidates. Positive, negative and ghost-device tests now cover this
classification; a source-bound physical rescan is required before admission.


## Universal USB evidence beyond model-specific detectors

X-Ray now has a vendor-neutral universal USB inventory probe. This records
all physically present USB VID:PID interfaces visible to the Windows PnP
inventory or Linux lsusb. Unknown device brands/models no longer vanish just
because there is no service-mode matcher. Read-only discover exposes sanitized
VID:PID and a non-raw inventory ID.

The operator may select an unknown device by inventory ID, including when
multiple endpoints share the same VID:PID, or select by VID:PID. Selection
confirms only OS USB presence. Device model, firmware, storage, download mode,
partition access, signed product-key custody and servicing capabilities require
separate evidence; no new write authority is provided. Host peripherals remain
discoverable but not automatic service candidates. G0–G6 admission remains
unchanged.
