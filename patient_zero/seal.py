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

import json
import os
from datetime import datetime, timezone
from hashlib import blake2b
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .custody import MerkleTree, generate_keypair, sign, verify, verify_inclusion_proof

SCHEMA = "patient-zero-seal-v1"


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
         signer_name: str = "") -> Dict[str, Any]:
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
    }
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
    return errors


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
