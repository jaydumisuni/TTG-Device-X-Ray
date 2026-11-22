"""Native X-Ray host-owned trust enrollment, revocation and COG evidence."""
from __future__ import annotations

import base64
import json
import os
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="Unix owner/0700/0600 custody test is not a valid Windows ACL proof",
)

from ttg_device_xray.bundle_seal import seal_bundle
from ttg_device_xray.cog_host_attestation import (
    provision_host_trust,public_trust_identity,revoke_host_key,host_attest_bundle,
)
from ttg_device_xray.pipeline import XRayPipeline,write_bundle


def _setup(tmp_path, monkeypatch):
    root=tmp_path/"private-owner-trust"
    public=provision_host_trust(root,product_id="ttg-device-xray",host_id="KRATOS")
    assert public["stage"]=="HOST_ENROLLED_NOT_ADMITTED"
    assert not public["g0_g1_independent_admission"]
    key=(root/"xray_hmac.key").read_bytes().decode()
    monkeypatch.setenv("TTG_XRAY_SIGNING_KEY",key)
    monkeypatch.setenv("TTG_XRAY_SIGNING_KEY_ID",public["xray_hmac_key_id"])
    bundle=XRayPipeline([]).scan()
    scan=write_bundle(bundle,tmp_path/"scans")
    seal_bundle(scan,bundle)
    return root,public,scan


def test_host_private_keys_and_ed25519_claim_are_separate(tmp_path,monkeypatch):
    root,identity,bundle=_setup(tmp_path,monkeypatch)
    assert stat.S_IMODE(root.stat().st_mode)==0o700
    for name in ("xray_hmac.key","cog_ed25519.pem","registry.json"):
        assert stat.S_IMODE((root/name).stat().st_mode)==0o600
    receipt=host_attest_bundle(root,bundle)
    assert receipt["native_hmac_verified"]
    assert receipt["not_production_admitted"]
    assert receipt["no_device_certification"]
    signed=receipt["signed_observation"]
    assert signed["payload"]["observation"]["value"]==0
    assert signed["key_id"]==identity["cog_attestor_key_id"]
    unsigned={k:v for k,v in signed.items() if k!="signature_hex"}
    public=base64.b64decode(identity["cog_attestor_ed25519_public_b64"])
    Ed25519PublicKey.from_public_bytes(public).verify(
        bytes.fromhex(signed["signature_hex"]),
        json.dumps(unsigned,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode())
    assert "secret" not in json.dumps(receipt).lower()
    assert "private" not in json.dumps(receipt).lower()


def test_revocation_of_native_hmac_signer_is_irreversible(tmp_path,monkeypatch):
    root,identity,bundle=_setup(tmp_path,monkeypatch)
    assert host_attest_bundle(root,bundle)["native_hmac_verified"]
    receipt=revoke_host_key(root,key_id=identity["xray_hmac_key_id"],
                            reason="owner retirement verified")
    assert receipt["revoked"]
    assert identity["xray_hmac_key_id"] in public_trust_identity(root)["revoked_signing_key_ids"]
    with pytest.raises(ValueError,match="revoked"):
        host_attest_bundle(root,bundle)
    with pytest.raises(ValueError,match="already revoked"):
        revoke_host_key(root,key_id=identity["xray_hmac_key_id"],reason="attempted undo")


def test_revocation_of_host_ed25519_signer_fails_closed(tmp_path,monkeypatch):
    root,identity,bundle=_setup(tmp_path,monkeypatch)
    revoke_host_key(root,key_id=identity["cog_attestor_key_id"],
                    reason="retire compromised attestor")
    with pytest.raises(ValueError,match="revoked"):
        host_attest_bundle(root,bundle)


def test_forged_native_manifest_and_missing_proof_fail(tmp_path,monkeypatch):
    root,identity,bundle=_setup(tmp_path,monkeypatch)
    path=bundle/"bundle_manifest.json"
    item=json.loads(path.read_text())
    item["candidate_count"]=11
    path.write_text(json.dumps(item))
    with pytest.raises(ValueError,match="manifest tampered"):
        host_attest_bundle(root,bundle)
    path.unlink()
    with pytest.raises(ValueError,match="manifest/signature"):
        host_attest_bundle(root,bundle)


def test_host_trust_cannot_be_reenrolled_or_forged_by_writable_state(tmp_path,monkeypatch):
    root,identity,bundle=_setup(tmp_path,monkeypatch)
    with pytest.raises(ValueError,match="already initialized"):
        provision_host_trust(root,product_id="ttg-device-xray",host_id="KRATOS")
    os.chmod(root/"xray_hmac.key",0o644)
    with pytest.raises(ValueError,match="permissions too broad"):
        host_attest_bundle(root,bundle)


def test_revocation_journal_detects_corruption(tmp_path,monkeypatch):
    root,identity,bundle=_setup(tmp_path,monkeypatch)
    revoke_host_key(root,key_id=identity["xray_hmac_key_id"],
                    reason="owner custody rotation")
    journal=root/"revocations.jsonl"
    text=journal.read_text()
    journal.write_text(text.replace("owner custody rotation","all good"))
    with pytest.raises(ValueError,match="chain invalid"):
        public_trust_identity(root)
    with pytest.raises(ValueError,match="chain invalid"):
        host_attest_bundle(root,bundle)


def test_revocation_journal_symlink_rejected(tmp_path,monkeypatch):
    root,identity,bundle=_setup(tmp_path,monkeypatch)
    external=tmp_path/"outside-jsonl"
    external.write_text("")
    (root/"revocations.jsonl").symlink_to(external)
    with pytest.raises(ValueError,match="private trust file unavailable"):
        public_trust_identity(root)
    with pytest.raises(ValueError,match="private trust file unavailable"):
        revoke_host_key(root,key_id=identity["xray_hmac_key_id"],
                        reason="custody breached")
    assert external.read_text()==""
