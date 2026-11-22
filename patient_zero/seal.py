"""Seal an assessment: Merkle root over every evidence file, signed with Ed25519.

What a seal gives you:
  * Any later change to the assessment or to an evidence file is detectable.
  * You can hand a customer ONE evidence file plus a short proof that it was
    part of the sealed assessment, without showing them the rest (`prove`).
  * Each seal names the root of the seal before it, so reassessments chain.

What it does not give you: identity. A key you generated yourself proves the
same key signed each seal, not who holds it. Publish the public key somewhere
you control, or have your assessor sign.
"""
from __future__ import annotations

import base64
import json
import os
import re
from datetime import datetime, timezone
from hashlib import blake2b
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .custody import MerkleTree, generate_keypair, sign, verify, verify_inclusion_proof

SCHEMA = "patient-zero-seal-v1"
COSIGN_SCHEMA = "patient-zero-cosign-v1"
BUNDLE_SCHEMA = "patient-zero-bundle-v1"
IDENTITY_SCHEMA = "patient-zero-identity-v1"
IDENTITY_PATH = "/.well-known/patient-zero.json"
ROLES = ("independent-assessor", "customer", "counsel", "internal-reviewer")
_DOMAIN = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _digest(path: str) -> Tuple[str, int]:
    h = blake2b(digest_size=32)
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def _leaf(item: Dict[str, Any]) -> bytes:
    return _canonical({"path": item["path"], "blake2b_256": item["blake2b_256"], "bytes": item["bytes"]})


def _domain(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    value = value.strip().lower()
    if not _DOMAIN.match(value):
        raise ValueError(f"not a domain name: {value} (expected something like example.com, with no https:// and no path)")
    return value


def summarize(assessment: Dict[str, Any]) -> Dict[str, Any]:
    """What the assessment claims, in counts, so a verifier can show it without parsing the files.

    It goes inside the signed head. Integers and strings only: the head has to
    serialize the same way in every language.
    """
    counts = {"confirmed": 0, "tested_clean_only": 0, "failed": 0, "not_assessed": 0, "not_applicable": 0}
    names = {"pass": "confirmed", "partial": "tested_clean_only", "fail": "failed", "not_assessed": "not_assessed",
             "not_applicable": "not_applicable"}
    probed = independent = self_only = 0
    for entry in (assessment.get("controls") or {}).values():
        status = entry.get("status", "not_assessed")
        counts[names.get(status, "not_assessed")] += 1
        observations = entry.get("observations") or []
        if any(o.get("kind") == "probe" for o in observations):
            probed += 1
        if status == "pass":
            by = {o.get("by") for o in observations if o.get("kind") == "attestation" and o.get("outcome") == "pass"}
            if "independent" in by:
                independent += 1
            else:
                self_only += 1
    return {"controls": sum(counts.values()), **counts, "with_probe_evidence": probed,
            "confirmed_by_independent": independent, "confirmed_by_self_only": self_only,
            "build": str(assessment["build"]) if assessment.get("build") is not None else None}


def keygen(path: str) -> str:
    """Write a new private seed (mode 0600) and return the public key."""
    private, public = generate_keypair()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(private + "\n")
    return public


def _read_key(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def collect(assessment_path: str, base_dir: str) -> List[str]:
    """The assessment file plus every evidence file it cites that exists under base_dir."""
    with open(assessment_path, "r", encoding="utf-8") as fh:
        assessment = yaml.safe_load(fh)
    base = os.path.realpath(base_dir)
    paths = {os.path.relpath(os.path.realpath(assessment_path), base)}
    missing = []
    for entry in assessment.get("controls", {}).values():
        for ref in entry.get("evidence", []) or []:
            full = os.path.realpath(ref if os.path.isabs(ref) else os.path.join(base, ref))
            if not (full == base or full.startswith(base + os.sep)):
                raise ValueError(f"evidence outside the sealed directory: {ref}")
            if os.path.isfile(full):
                paths.add(os.path.relpath(full, base))
            else:
                missing.append(ref)
    if missing:
        raise FileNotFoundError("cited evidence not found: " + ", ".join(sorted(set(missing))[:5]))
    return sorted(p.replace(os.sep, "/") for p in paths)


def seal(assessment_path: str, key_path: str, out_path: str = "seal.json", base_dir: Optional[str] = None,
         signer_name: str = "", domain: Optional[str] = None) -> Dict[str, Any]:
    base = base_dir or os.path.dirname(os.path.abspath(assessment_path))
    with open(assessment_path, "r", encoding="utf-8") as fh:
        assessment = yaml.safe_load(fh)
    items = []
    for rel in collect(assessment_path, base):
        digest, size = _digest(os.path.join(base, rel))
        items.append({"path": rel, "blake2b_256": digest, "bytes": size})
    tree = MerkleTree([_leaf(i) for i in items])
    previous = None
    if os.path.exists(out_path):
        with open(out_path, "r", encoding="utf-8") as fh:
            previous = json.load(fh)["head"]["merkle_root"]
    private = _read_key(key_path)
    _, public = generate_keypair(bytes.fromhex(private))
    head = {
        "schema": SCHEMA,
        "product": assessment.get("product"),
        "level": assessment.get("level"),
        "profile_version": assessment.get("profile_version"),
        "sealed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "item_count": len(items),
        "merkle_root": tree.root_hex,
        "previous_root": previous,
        "signer": {"name": signer_name, "public_key": public},
        "summary": summarize(assessment),
    }
    if _domain(domain):
        head["signer"]["domain"] = _domain(domain)
    document = {"head": head, "signature": sign(_canonical(head), private), "items": items}
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return document


def _check_head(document: Dict[str, Any], expect_public_key: Optional[str]) -> List[str]:
    errors = []
    head = document.get("head", {})
    if head.get("schema") != SCHEMA:
        return ["unsupported seal schema"]
    public = head.get("signer", {}).get("public_key", "")
    if not verify(_canonical(head), document.get("signature", ""), public):
        errors.append("signature does not verify")
    if expect_public_key and public != expect_public_key.strip().lower():
        errors.append("signed by a different key than expected")
    for number, entry in enumerate(document.get("cosignatures") or [], 1):
        body = entry.get("body", {})
        who = body.get("signer", {}).get("name") or f"number {number}"
        if body.get("schema") != COSIGN_SCHEMA:
            errors.append(f"co-signature by {who}: unsupported schema")
        elif body.get("merkle_root") != head.get("merkle_root") or body.get("seal_signature") != document.get("signature"):
            errors.append(f"co-signature by {who} was made over a different seal")
        elif not verify(_canonical(body), entry.get("signature", ""), body.get("signer", {}).get("public_key", "")):
            errors.append(f"co-signature by {who} does not verify")
    return errors


def cosign(seal_path: str, key_path: str, name: str, role: str, statement: str = "", domain: Optional[str] = None) -> Dict[str, Any]:
    """Add a second party's signature to an existing seal, without changing what was sealed.

    The co-signer signs the seal's root and the first signature, with their
    role and a statement in their own words. They should verify the seal and
    read the evidence first: a co-signature says a named party looked.
    """
    if role not in ROLES:
        raise ValueError(f"role must be one of {ROLES}")
    with open(seal_path, "r", encoding="utf-8") as fh:
        document = json.load(fh)
    problems = _check_head(document, None)
    if problems:
        raise ValueError("refusing to co-sign a seal that does not verify: " + "; ".join(problems))
    private = _read_key(key_path)
    _, public = generate_keypair(bytes.fromhex(private))
    if public == document["head"]["signer"]["public_key"]:
        raise ValueError("this key already signed the seal; a co-signature has to come from a different key")
    signer: Dict[str, Any] = {"name": name, "public_key": public}
    if _domain(domain):
        signer["domain"] = _domain(domain)
    body = {
        "schema": COSIGN_SCHEMA,
        "merkle_root": document["head"]["merkle_root"],
        "seal_signature": document["signature"],
        "signer": signer,
        "role": role,
        "statement": statement,
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    document.setdefault("cosignatures", []).append({"body": body, "signature": sign(_canonical(body), private)})
    with open(seal_path, "w", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return body


def describe(document: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    """Who signed, how long ago, and what the signed summary claims. For display after verifying."""
    head = document.get("head", {})
    now = now or datetime.now(timezone.utc)
    try:
        age_days: Optional[int] = max((now - datetime.fromisoformat(head["sealed_at"])).days, 0)
    except (KeyError, ValueError, TypeError):
        age_days = None
    return {
        "product": head.get("product"), "level": head.get("level"), "profile_version": head.get("profile_version"),
        "sealed_at": head.get("sealed_at"), "age_days": age_days, "signer": head.get("signer", {}),
        "summary": head.get("summary"), "files": head.get("item_count"),
        "cosigners": [{"name": c["body"]["signer"].get("name"), "role": c["body"].get("role"), "domain": c["body"]["signer"].get("domain"),
                       "public_key": c["body"]["signer"].get("public_key"), "statement": c["body"].get("statement"),
                       "signed_at": c["body"].get("signed_at")} for c in document.get("cosignatures") or []],
    }


def age_phrase(days: Optional[int]) -> str:
    if days is None:
        return "at an unknown time"
    if days < 1:
        return "today"
    if days < 60:
        return f"{days} day(s) ago"
    return f"about {round(days / 30.44)} months ago"


def identity_document(domain: str, public_keys: List[str], retired: Optional[List[str]] = None) -> Dict[str, Any]:
    """The file a signer publishes at https://<domain>/.well-known/patient-zero.json to tie a key to a name people know."""
    return {"schema": IDENTITY_SCHEMA, "domain": _domain(domain),
            "keys": [{"public_key": k.strip().lower(), "status": "active"} for k in public_keys] +
                    [{"public_key": k.strip().lower(), "status": "retired"} for k in retired or []]}


def check_identity(identity: Any, domain: str, public_key: str) -> List[str]:
    """Does this published identity file say the key belongs to the domain? Empty list means yes."""
    if not isinstance(identity, dict) or identity.get("schema") != IDENTITY_SCHEMA:
        return [f"{domain} does not publish a patient-zero identity file"]
    if identity.get("domain") != domain:
        return [f"the identity file is for {identity.get('domain')}, not {domain}"]
    for key in identity.get("keys") or []:
        if isinstance(key, dict) and key.get("public_key") == public_key:
            return [] if key.get("status") == "active" else [f"{domain} lists this key as {key.get('status')}"]
    return [f"{domain} does not list this key"]


def fetch_identity(domain: str, timeout: float = 10.0) -> Any:
    """The one place patient-zero opens a connection the user did not put in a target file. Only on `--check-domain`."""
    import urllib.request

    url = f"https://{_domain(domain)}{IDENTITY_PATH}"
    request = urllib.request.Request(url, headers={"User-Agent": "patient-zero-verify", "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - https only, built above
        return json.loads(response.read(65536).decode("utf-8"))


def check_domains(document: Dict[str, Any], fetch=fetch_identity) -> List[str]:
    """Check every signer that names a domain against the file that domain publishes."""
    errors = []
    signers = [document.get("head", {}).get("signer", {})] + [c["body"]["signer"] for c in document.get("cosignatures") or []]
    for signer in signers:
        domain = signer.get("domain")
        if not domain:
            errors.append(f"{signer.get('name') or signer.get('public_key', '')[:16]} names no domain: the key proves continuity, not who holds it")
            continue
        try:
            identity = fetch(domain)
        except Exception as exc:  # network, TLS, JSON: all mean the claim could not be confirmed
            errors.append(f"could not read https://{domain}{IDENTITY_PATH}: {exc}")
            continue
        errors += check_identity(identity, domain, signer.get("public_key", ""))
    return errors


def bundle(seal_path: str, out_path: str, base_dir: Optional[str] = None) -> Dict[str, Any]:
    """One file holding the seal and every sealed file, so a buyer can verify it in a browser with nothing installed."""
    problems = verify_seal(seal_path, base_dir)
    if problems:
        raise ValueError("refusing to bundle a seal that does not verify: " + "; ".join(problems))
    with open(seal_path, "r", encoding="utf-8") as fh:
        document = json.load(fh)
    base = base_dir or os.path.dirname(os.path.abspath(seal_path))
    files = {}
    for item in document["items"]:
        with open(os.path.join(base, item["path"]), "rb") as fh:
            files[item["path"]] = base64.b64encode(fh.read()).decode("ascii")
    packed = {"schema": BUNDLE_SCHEMA, "seal": document, "files": files}
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(packed, fh, sort_keys=True)
        fh.write("\n")
    return packed


def verify_bundle(bundle_path: str, expect_public_key: Optional[str] = None) -> Tuple[List[str], Dict[str, Any]]:
    """Verify a one-file bundle. Returns (problems, the seal document)."""
    with open(bundle_path, "r", encoding="utf-8") as fh:
        packed = json.load(fh)
    if not isinstance(packed, dict) or packed.get("schema") != BUNDLE_SCHEMA:
        return ["not a patient-zero bundle"], {}
    document, files = packed.get("seal", {}), packed.get("files", {})
    errors = _check_head(document, expect_public_key)
    items, head = document.get("items", []), document.get("head", {})
    if len(items) != head.get("item_count"):
        errors.append("item count does not match the signed head")
    if MerkleTree([_leaf(i) for i in items]).root_hex != head.get("merkle_root"):
        errors.append("item list does not match the signed Merkle root")
    for item in items:
        if item["path"] not in files:
            errors.append(f"missing: {item['path']}")
            continue
        try:
            data = base64.b64decode(files[item["path"]], validate=True)
        except ValueError:
            errors.append(f"unreadable: {item['path']}")
            continue
        if blake2b(data, digest_size=32).hexdigest() != item["blake2b_256"] or len(data) != item["bytes"]:
            errors.append(f"changed since sealing: {item['path']}")
    return errors, document


def verify_seal(seal_path: str, base_dir: Optional[str] = None, expect_public_key: Optional[str] = None) -> List[str]:
    """Return a list of problems. Empty means the seal and every file check out."""
    with open(seal_path, "r", encoding="utf-8") as fh:
        document = json.load(fh)
    errors = _check_head(document, expect_public_key)
    base = base_dir or os.path.dirname(os.path.abspath(seal_path))
    items = document.get("items", [])
    head = document.get("head", {})
    if len(items) != head.get("item_count"):
        errors.append("item count does not match the signed head")
    if MerkleTree([_leaf(i) for i in items]).root_hex != head.get("merkle_root"):
        errors.append("item list does not match the signed Merkle root")
    for item in items:
        full = os.path.join(base, item["path"])
        if not os.path.isfile(full):
            errors.append(f"missing: {item['path']}")
            continue
        digest, size = _digest(full)
        if digest != item["blake2b_256"] or size != item["bytes"]:
            errors.append(f"changed since sealing: {item['path']}")
    return errors


def prove(seal_path: str, item_path: str) -> Dict[str, Any]:
    """A standalone proof that one file belongs to the seal, revealing no other item."""
    with open(seal_path, "r", encoding="utf-8") as fh:
        document = json.load(fh)
    items = document["items"]
    wanted = item_path.replace(os.sep, "/")
    for index, item in enumerate(items):
        if item["path"] == wanted:
            tree = MerkleTree([_leaf(i) for i in items])
            return {"head": document["head"], "signature": document["signature"], "item": item,
                    "proof": tree.inclusion_proof(index)}
    raise KeyError(f"{item_path} is not in the seal")


def verify_proof(proof: Dict[str, Any], file_path: str, expect_public_key: Optional[str] = None) -> List[str]:
    errors = _check_head(proof, expect_public_key)
    item = proof.get("item", {})
    digest, size = _digest(file_path)
    if digest != item.get("blake2b_256") or size != item.get("bytes"):
        errors.append("file does not match the proven item")
    path = [tuple(step) for step in proof.get("proof", [])]
    if not verify_inclusion_proof(_leaf(item), proof.get("head", {}).get("merkle_root", ""), path):
        errors.append("inclusion proof does not lead to the signed root")
    return errors
