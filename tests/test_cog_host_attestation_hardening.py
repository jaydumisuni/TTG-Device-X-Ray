"""Security regression tests for host-side X-Ray authority (not production admission)."""
from __future__ import annotations

import concurrent.futures
import hashlib
import hmac
import json
import os
import stat
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ttg_device_xray import cog_host_attestation as host
from ttg_device_xray.command import CommandRunner
from test_cog_host_attestation import _setup

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="Private host trust requires Linux/POSIX owner custody"
)


def test_existing_unauthorized_root_never_chmodded_before_enrollment(tmp_path):
    target = tmp_path / "existing-owner-root"
    target.mkdir(mode=0o750)
    (target / "sentinel").write_text("retain")
    prior = stat.S_IMODE(target.stat().st_mode)
    with pytest.raises(ValueError, match="permissions expose|already initialized"):
        host.provision_host_trust(target, product_id="ttg-device-xray", host_id="KRATOS")
    assert stat.S_IMODE(target.stat().st_mode) == prior
    assert (target / "sentinel").read_text() == "retain"


def test_enrollment_failure_does_not_publish_partial_keys(tmp_path, monkeypatch):
    target = tmp_path / "new-owner-root"
    original = host._new_secret

    def fail_after_first(path, data):
        if path.name == "cog_ed25519.pem":
            raise OSError("synthetic storage failure")
        return original(path, data)

    with monkeypatch.context() as patch:
        patch.setattr(host, "_new_secret", fail_after_first)
        with pytest.raises(OSError, match="synthetic storage"):
            host.provision_host_trust(target, product_id="ttg-device-xray", host_id="KRATOS")
    assert not target.exists()
    result = host.provision_host_trust(target, product_id="ttg-device-xray", host_id="KRATOS")
    assert result["stage"] == "HOST_ENROLLED_NOT_ADMITTED"


def test_two_simultaneous_revocations_form_valid_chain(tmp_path, monkeypatch):
    root, identity, bundle = _setup(tmp_path, monkeypatch)
    keys = [identity["xray_hmac_key_id"], identity["cog_attestor_key_id"]]
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(host.revoke_host_key, root, key_id=key,
                            reason="owner initiated signer retirement") for key in keys]
        results = [job.result(timeout=8) for job in jobs]
    assert len(results) == 2 and all(row["revoked"] for row in results)
    assert set(host.public_trust_identity(root)["revoked_signing_key_ids"]) == set(keys)
    journal = host._revocations(root)
    assert len(journal) == 2
    assert journal[1]["previous_sha256"] == journal[0]["entry_sha256"]


def test_failed_atomic_revocation_keeps_previous_chain(tmp_path, monkeypatch):
    root, identity, bundle = _setup(tmp_path, monkeypatch)
    host.revoke_host_key(root, key_id=identity["xray_hmac_key_id"],
                         reason="owner retired first signer")
    previous = (root / "revocations.jsonl").read_bytes()
    with monkeypatch.context() as patch:
        def fail_replace(src, dst):
            raise OSError("synthetic replacement failure")
        patch.setattr(host.os, "replace", fail_replace)
        with pytest.raises(OSError, match="synthetic replacement"):
            host.revoke_host_key(root, key_id=identity["cog_attestor_key_id"],
                                 reason="owner retired second signer")
    assert (root / "revocations.jsonl").read_bytes() == previous
    assert host.public_trust_identity(root)["revoked_signing_key_ids"] == [
        identity["xray_hmac_key_id"]
    ]
    host.revoke_host_key(root, key_id=identity["cog_attestor_key_id"],
                         reason="owner second signer retry after disk recovery")
    assert len(host._revocations(root)) == 2


def test_unbounded_revocation_reason_refused_before_mutation(tmp_path, monkeypatch):
    root, identity, bundle = _setup(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="byte limit"):
        host.revoke_host_key(root, key_id=identity["xray_hmac_key_id"], reason="r" * 140000)
    assert host._revocations(root) == []


def test_registered_private_public_mismatch_refused_without_assert(tmp_path, monkeypatch):
    root, identity, bundle = _setup(tmp_path, monkeypatch)
    unrelated = Ed25519PrivateKey.generate()
    material = unrelated.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    (root / "cog_ed25519.pem").write_bytes(material)
    with pytest.raises(ValueError, match="private/public key mismatch"):
        host.host_attest_bundle(root, bundle)


def test_exact_native_v2_unicode_manifest_verifies(tmp_path, monkeypatch):
    root, identity, bundle = _setup(tmp_path, monkeypatch)
    filename = "r\u00e9sum\u00e9.json"
    content = b'{"verified":true}'
    (bundle / filename).write_bytes(content)
    manifest_path = bundle / "bundle_manifest.json"
    report_path = bundle / "bundle_manifest.sig"
    manifest = json.loads(manifest_path.read_text())
    manifest["files"].append({
        "path": filename,
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    })
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    def native(obj):
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    manifest["manifest_sha256"] = hashlib.sha256(native(unsigned)).hexdigest()
    report = json.loads(report_path.read_text())
    report["manifest_sha256"] = manifest["manifest_sha256"]
    report["signature_hex"] = hmac.new(
        (root / "xray_hmac.key").read_bytes(), native(manifest), "sha256"
    ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2))
    report_path.write_text(json.dumps(report, indent=2))
    assert host.host_attest_bundle(root, bundle)["native_hmac_verified"]


def test_external_subprocess_must_not_inherit_native_signing_keys(monkeypatch):
    monkeypatch.setenv("TTG_XRAY_SIGNING_KEY", "not-a-real-key-example")
    monkeypatch.setenv("TTG_XRAY_SIGNING_KEY_ID", "test-key-id")
    script = ("import os;print(os.getenv('TTG_XRAY_SIGNING_KEY','UNSET'));"
              "print(os.getenv('TTG_XRAY_SIGNING_KEY_ID','UNSET'))")
    result = CommandRunner().run([sys.executable, "-c", script])
    assert result.return_code == 0
    assert result.stdout.splitlines() == ["UNSET", "UNSET"]
