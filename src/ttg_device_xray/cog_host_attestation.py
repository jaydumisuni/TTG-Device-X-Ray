"""Host-only X-Ray HMAC custody and Ed25519 COG evidence attestation.

Unlike COG's effect-free verifier, this module is a host-side operator
boundary. It keeps HMAC and private Ed25519 keys OUTSIDE COG, Git, and public
attestation packets. Provisioning is pending owner/independent admission.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import uuid

MANIFEST="bundle_manifest.json"
SIGNATURE="bundle_manifest.sig"
SCHEMA="ttg.xray.host-cog-trust.v1"
COG_SCHEMA="ttg.cog.provenance-gate.v1"
MAX_BUNDLE=16*1024*1024
MAX_FILE=4*1024*1024


def _canon(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,separators=(",",":"),
                      ensure_ascii=False,allow_nan=False).encode()


def _time(s: object) -> datetime:
    if not isinstance(s,str):
        raise ValueError("missing timezone-aware timestamp")
    try:
        d=datetime.fromisoformat(s.replace("Z","+00:00"))
    except ValueError as exc:
        raise ValueError("invalid timestamp") from exc
    if d.tzinfo is None or d.utcoffset() is None:
        raise ValueError("unsigned clock")
    return d.astimezone(timezone.utc)


def _secure_root(root: Path, create: bool=False) -> Path:
    if os.name == "nt":
        raise ValueError(
            "Windows host private-key custody requires a separately qualified "
            "Windows ACL implementation; Unix mode bits are not authority"
        )
    r=Path(root)
    if r.is_symlink():
        raise ValueError("symlinked trust root")
    if create:
        r.mkdir(parents=True,exist_ok=True,mode=0o700)
        os.chmod(r,0o700)
    if not r.is_dir():
        raise ValueError("trust root unavailable")
    mode=r.stat()
    if hasattr(os,"geteuid") and mode.st_uid!=os.geteuid():
        raise ValueError("trust root has wrong OS owner")
    if stat.S_IMODE(mode.st_mode)&0o077:
        raise ValueError("trust root permissions expose private authority")
    return r


def _read_secret(path: Path, maxbytes: int=4096) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("private trust file unavailable")
    mode=path.stat()
    if hasattr(os,"geteuid") and mode.st_uid!=os.geteuid():
        raise ValueError("private trust file owner mismatch")
    if stat.S_IMODE(mode.st_mode)&0o077:
        raise ValueError("private trust file permissions too broad")
    if mode.st_size>maxbytes:
        raise ValueError("private trust file too large")
    return path.read_bytes()


def _new_secret(path: Path, data: bytes) -> None:
    fd=os.open(path,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    try:
        with os.fdopen(fd,"wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def _registry(root: Path) -> dict:
    r=_secure_root(root)
    value=json.loads(_read_secret(r/"registry.json"))
    if value.get("schema")!=SCHEMA or value.get("stage")!="HOST_ENROLLED_NOT_ADMITTED":
        raise ValueError("host trust registry has not been admitted")
    if not isinstance(value.get("product_id"),str):
        raise ValueError("product binding missing")
    return value


def provision_host_trust(root: Path, *, product_id: str, host_id: str) -> dict:
    """Operator bootstrap: generate private credentials once, never overwrite."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not re.fullmatch(r"[A-Za-z0-9_-]{2,48}",host_id):
        raise ValueError("invalid host identity")
    if not isinstance(product_id,str) or not re.fullmatch(r"[a-z0-9_.-]{3,90}",product_id):
        raise ValueError("invalid registered product ID")
    root=_secure_root(root,create=True)
    if any(root.iterdir()):
        raise ValueError("host trust already initialized; refuse key replacement")
    stamp=datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    uid=uuid.uuid4().hex[:20]
    hmac_keyid="ttg-xray-"+host_id+"-hmac-"+uid
    attestor_id="ttg-xray-"+host_id+"-ed25519-"+uid
    hmac_secret=secrets.token_hex(32).encode("ascii")
    signer=Ed25519PrivateKey.generate()
    private=signer.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    pub=signer.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    data={
        "schema":SCHEMA,"stage":"HOST_ENROLLED_NOT_ADMITTED",
        "created_at":stamp,"product_id":product_id,"host_id":host_id,
        "xray_hmac_key_id":hmac_keyid,"cog_attestor_key_id":attestor_id,
        "cog_attestor_ed25519_public_b64":base64.b64encode(pub).decode(),
        "operator_review_required":True,"independent_gate_accepted":False,
        "revocation_journal":"revocations.jsonl",
    }
    # Secure key files are never returned to caller nor committed to Git.
    _new_secret(root/"xray_hmac.key",hmac_secret)
    _new_secret(root/"cog_ed25519.pem",private)
    _new_secret(root/"registry.json",json.dumps(data,sort_keys=True,indent=2).encode())
    return public_trust_identity(root)


def _revocations(root: Path) -> list[dict]:
    r=_secure_root(root)
    path=r/"revocations.jsonl"
    if not path.exists():
        return []
    raw=_read_secret(path,maxbytes=131072)
    prev="0"*64
    rows=[]
    for line in raw.splitlines():
        if not line:
            raise ValueError("blank revocation journal entry")
        row=json.loads(line)
        expected=row.get("entry_sha256")
        body=dict(row)
        body.pop("entry_sha256",None)
        if body.get("previous_sha256")!=prev or sha256(_canon(body)).hexdigest()!=expected:
            raise ValueError("revocation chain invalid")
        if not isinstance(row.get("key_id"),str) or not row["key_id"]:
            raise ValueError("revocation key missing")
        rows.append(row)
        prev=expected
    return rows


def revoke_host_key(root: Path, *, key_id: str, reason: str) -> dict:
    """Explicit host-owner action: append-only revocation, no un-revoke API."""
    r=_secure_root(root)
    state=_registry(r)
    allowed=(state["xray_hmac_key_id"],state["cog_attestor_key_id"])
    if key_id not in allowed:
        raise ValueError("unknown host signing key")
    if not isinstance(reason,str) or len(reason.strip())<6:
        raise ValueError("revocation requires reason")
    rows=_revocations(r)
    if any(row["key_id"]==key_id for row in rows):
        raise ValueError("signer already revoked")
    prior=rows[-1]["entry_sha256"] if rows else "0"*64
    body={"schema":"ttg.xray.host-revocation.v1","key_id":key_id,
          "reason":reason,"observed_at":datetime.now(timezone.utc).isoformat(),
          "previous_sha256":prior}
    body["entry_sha256"]=sha256(_canon(body)).hexdigest()
    path=r/"revocations.jsonl"
    # Append is owned by this host. Physical deletion/rollback still requires
    # independent OS/backup custody to defeat a compromised host principal.
    if path.is_symlink():
        raise ValueError("revocation journal symlink forbidden")
    fd=os.open(path,os.O_CREAT|os.O_APPEND|os.O_WRONLY|getattr(os,"O_NOFOLLOW",0),0o600)
    with os.fdopen(fd,"ab") as f:
        f.write(_canon(body)+b"\n")
        f.flush()
        os.fsync(f.fileno())
    return {"key_id":key_id,"revoked":True,"revocation_entry_sha256":body["entry_sha256"]}


def public_trust_identity(root: Path) -> dict:
    state=_registry(root)
    revoked={x["key_id"] for x in _revocations(root)}
    return {"schema":"ttg.xray.cog-public-identity.v1",
      "product_id":state["product_id"],"host_id":state["host_id"],
      "xray_hmac_key_id":state["xray_hmac_key_id"],
      "cog_attestor_key_id":state["cog_attestor_key_id"],
      "cog_attestor_ed25519_public_b64":state["cog_attestor_ed25519_public_b64"],
      "revoked_signing_key_ids":sorted(revoked),
      "owner_approval_required":True,
      "g0_g1_independent_admission":False,
      "stage":state["stage"]}


def _manifest(root: Path, key: bytes, state: dict, clock: datetime) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("unsafe X-Ray bundle root")
    for file in (MANIFEST,SIGNATURE):
        p=root/file
        if p.is_symlink() or not p.is_file() or p.stat().st_size>262144:
            raise ValueError("unsafe X-Ray manifest/signature")
    manifest=json.loads((root/MANIFEST).read_bytes())
    report=json.loads((root/SIGNATURE).read_bytes())
    if not isinstance(manifest,dict) or not isinstance(report,dict):
        raise ValueError("X-Ray manifest shape")
    if (manifest.get("bundle_schema_version")!="2.0"
      or manifest.get("hash_algorithm")!="sha256"
      or manifest.get("signature_algorithm")!="hmac-sha256"
      or manifest.get("write_allowed") is not False
      or manifest.get("signer_key_id")!=state["xray_hmac_key_id"]
      or not isinstance(manifest.get("scanner"),dict)
      or manifest["scanner"].get("name")!="ttg-device-xray"):
        raise ValueError("native X-Ray contract or host owner mismatch")
    if _time(manifest.get("created_at"))>clock or _time(manifest.get("expires_at"))<clock:
        raise ValueError("X-Ray currentness expired")
    scan=manifest.get("scan_id")
    if not isinstance(scan,str) or not scan:
        raise ValueError("X-Ray generation unavailable")
    expectedsha=manifest.get("manifest_sha256")
    unsigned=dict(manifest)
    unsigned.pop("manifest_sha256",None)
    if not isinstance(expectedsha,str) or not hmac.compare_digest(
        sha256(_canon(unsigned)).hexdigest(),expectedsha):
        raise ValueError("X-Ray manifest tampered")
    if (report.get("status")!="SIGNED"
        or report.get("algorithm")!="hmac-sha256"
        or report.get("signer_key_id")!=state["xray_hmac_key_id"]
        or report.get("manifest_sha256")!=expectedsha):
        raise ValueError("X-Ray signature report missing or unqualified")
    sig=report.get("signature_hex")
    if not isinstance(sig,str) or len(sig)!=64:
        raise ValueError("X-Ray signature invalid")
    try:
        sigbytes=bytes.fromhex(sig)
    except ValueError as exc:
        raise ValueError("X-Ray signature hex invalid") from exc
    if not hmac.compare_digest(
       hmac.new(key,_canon(manifest),"sha256").digest(),sigbytes):
        raise ValueError("X-Ray HMAC could not be verified")
    files=manifest.get("files")
    if not isinstance(files,list) or not 1<=len(files)<=128:
        raise ValueError("X-Ray inventory invalid")
    expected={MANIFEST,SIGNATURE}
    total=0
    for item in files:
        if not isinstance(item,dict) or set(item)!={"path","size_bytes","sha256"}:
            raise ValueError("X-Ray inventory entry invalid")
        name=item["path"]
        if (not isinstance(name,str) or not name or name.startswith("/")
            or "\\" in name or "//" in name or
            any(x in ("..",".") for x in name.split("/"))):
            raise ValueError("X-Ray path traversal")
        if name in expected:
            raise ValueError("duplicate X-Ray path")
        expected.add(name)
        p=root.joinpath(*PurePosixPath(name).parts)
        current=root
        for part in PurePosixPath(name).parts:
            current=current/part
            if current.is_symlink():
                raise ValueError("linked X-Ray input")
        if not p.is_file():
            raise ValueError("missing X-Ray file")
        size=item["size_bytes"]
        if type(size) is not int or size<0 or size>MAX_FILE or p.stat().st_size!=size:
            raise ValueError("X-Ray file size mismatch")
        total+=size
        if total>MAX_BUNDLE:
            raise ValueError("X-Ray bundle budget exceeded")
        if sha256(p.read_bytes()).hexdigest()!=item["sha256"]:
            raise ValueError("X-Ray file hash mismatch")
    seen=set()
    for index,p in enumerate(root.rglob("*")):
        if index>512:
            raise ValueError("X-Ray directory count exceeded")
        if p.is_symlink():
            raise ValueError("X-Ray symlink outside inventory")
        if p.is_file():
            seen.add(p.relative_to(root).as_posix())
    if seen!=expected:
        raise ValueError("X-Ray inventory missing/unlisted files")
    if type(manifest.get("candidate_count")) is not int or manifest["candidate_count"]<0:
        raise ValueError("invalid candidate count")
    return manifest


def host_attest_bundle(root: Path, bundle_dir: Path, *, host_time: datetime|None=None) -> dict:
    """Verify native HMAC in host-private process and emit Ed25519 claim.

    COG receives ONLY this signed claim and a separately configured public key.
    """
    from cryptography.hazmat.primitives import serialization

    r=_secure_root(root)
    state=_registry(r)
    revoked={x["key_id"] for x in _revocations(r)}
    if state["xray_hmac_key_id"] in revoked or state["cog_attestor_key_id"] in revoked:
        raise ValueError("host signer revoked")
    now=host_time or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("host clock must be timezone aware")
    now=now.astimezone(timezone.utc)
    key=_read_secret(r/"xray_hmac.key")
    signer=serialization.load_pem_private_key(_read_secret(r/"cog_ed25519.pem"),password=None)
    pub=signer.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    assert base64.b64encode(pub).decode()==state["cog_attestor_ed25519_public_b64"]
    manifest=_manifest(Path(bundle_dir),key,state,now)
    obs={
      "obligation_id":"xray.device_candidate_count",
      "source_ref":"xray:"+manifest["scan_id"]+":sha256:"+manifest["manifest_sha256"],
      "snapshot_generation":manifest["scan_id"],
      "observed_at":now.isoformat(),
      "kind":"direct_readback",
      "value":manifest["candidate_count"],
    }
    envelope={
      "schema":COG_SCHEMA,"claim_kind":"observation",
      "key_id":state["cog_attestor_key_id"],
      "payload":{
         "product_id":state["product_id"],"snapshot_generation":manifest["scan_id"],
         "issued_at":(now-timedelta(seconds=2)).isoformat(),
         "expires_at":min(now+timedelta(seconds=60),
                          _time(manifest["expires_at"])).isoformat(),
         "observation":obs,
      },
    }
    envelope["signature_hex"]=signer.sign(_canon(envelope)).hex()
    return {
      "schema":"ttg.xray.cog-host-attested-observation.v1",
      "product_id":state["product_id"],
      "scan_id":manifest["scan_id"],
      "native_hmac_verified":True,
      "signed_observation":envelope,
      "revocation_checked":True,
      "trust_stage":state["stage"],
      "not_production_admitted":True,
      "no_device_certification":manifest["candidate_count"]==0,
    }

def main(argv: list[str] | None = None) -> int:
    """Exact owner-operated host trust commands; no arbitrary execution."""
    import argparse
    import subprocess
    import sys

    parser=argparse.ArgumentParser(description="Host-owned X-Ray-to-COG trust (never COG self-enrollment)")
    sub=parser.add_subparsers(dest="action",required=True)
    for action in ("enroll","inspect","revoke","attest","scan"):
        cmd=sub.add_parser(action)
        cmd.add_argument("--root",required=True,help="private 0700 host custody root")
        if action=="enroll":
            cmd.add_argument("--product",required=True)
            cmd.add_argument("--host",required=True)
        if action=="revoke":
            cmd.add_argument("--key-id",required=True)
            cmd.add_argument("--reason",required=True)
        if action=="attest":
            cmd.add_argument("--bundle",required=True)
        if action=="scan":
            cmd.add_argument("--output",required=True)
    args=parser.parse_args(argv)
    trustroot=Path(args.root)
    if args.action=="enroll":
        result=provision_host_trust(trustroot,product_id=args.product,host_id=args.host)
    elif args.action=="inspect":
        result=public_trust_identity(trustroot)
    elif args.action=="revoke":
        result=revoke_host_key(trustroot,key_id=args.key_id,reason=args.reason)
    elif args.action=="attest":
        result=host_attest_bundle(trustroot,Path(args.bundle))
    else:
        root=_secure_root(trustroot)
        state=_registry(root)
        revoked={r["key_id"] for r in _revocations(root)}
        if state["xray_hmac_key_id"] in revoked:
            raise ValueError("host scanner signer revoked")
        target=Path(args.output).resolve()
        target.mkdir(parents=True,exist_ok=True)
        key=_read_secret(root/"xray_hmac.key").decode("ascii")
        env=dict(os.environ)
        env["TTG_XRAY_SIGNING_KEY"]=key
        env["TTG_XRAY_SIGNING_KEY_ID"]=state["xray_hmac_key_id"]
        completed=subprocess.run(
            [sys.executable,"-m","ttg_device_xray.cli","scan","--output",str(target)],
            capture_output=True,text=True,timeout=90,env=env,check=False,
        )
        if completed.returncode not in (0,2):
            raise ValueError("native X-Ray scan failed: exit "+str(completed.returncode))
        scanner=json.loads(completed.stdout)
        bundle=Path(scanner["output"]).resolve()
        if not bundle.is_relative_to(target):
            raise ValueError("native scanner produced bundle outside output root")
        result=host_attest_bundle(root,bundle)
        if result["scan_id"] != scanner.get("scan_id"):
            raise ValueError("native scanner did not bind scan identity")
        result["scanner_verdict"]=scanner.get("verdict")
        result["scanner_exit_code"]=completed.returncode
        result["no_device_certification"]=scanner.get("candidate_count",0)==0
    print(json.dumps(result,sort_keys=True,indent=2))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
