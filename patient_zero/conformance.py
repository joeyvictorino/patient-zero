"""Conformance: the spec's test vectors, run against an implementation.

The profile is a standard; this package is one implementation of it. An
implementation in any language conforms when it reproduces every vector in
patient_zero/data/vectors/. The vectors are plain JSON and carry their own
inputs, so a port needs nothing from this package to run them.

`run` checks this implementation. `tools/make_vectors.py` regenerates the
files; a vector may only change together with the spec version.
"""
from __future__ import annotations

import base64
import copy
import glob
import json
import os
from datetime import date
from hashlib import blake2b
from importlib import resources
from typing import Any, Callable, Dict, List, Optional

from . import assess, bayes
from . import profile as profile_mod
from . import seal as seal_mod
from .custody import MerkleTree, generate_keypair, sign, verify, verify_inclusion_proof
from .probes.common import ProbeResult


def _canonical(case: Dict[str, Any]) -> Optional[str]:
    got = seal_mod._canonical(case["value"]).hex()
    return None if got == case["canonical_hex"] else f"canonical JSON gave {got}"


def _merkle(case: Dict[str, Any]) -> Optional[str]:
    leaves = [bytes.fromhex(x) for x in case["leaves_hex"]]
    tree = MerkleTree(leaves)
    if tree.root_hex != case["root"]:
        return f"root {tree.root_hex}"
    for index, expected in enumerate(case["proofs"]):
        proof = [list(step) for step in tree.inclusion_proof(index)]
        if proof != expected:
            return f"proof for leaf {index} differs"
        if not verify_inclusion_proof(leaves[index], case["root"], [tuple(s) for s in expected]):
            return f"proof for leaf {index} does not verify"
    return None


def _ed25519(case: Dict[str, Any]) -> Optional[str]:
    message = bytes.fromhex(case["message_hex"])
    if case.get("seed"):
        if generate_keypair(bytes.fromhex(case["seed"]))[1] != case["public_key"]:
            return "public key differs"
        if sign(message, case["seed"]) != case["signature"]:
            return "signature differs"
    if verify(message, case["signature"], case["public_key"]) != case["valid"]:
        return f"verify did not return {case['valid']}"
    return None


def check_bundle(packed: Dict[str, Any]) -> List[str]:
    """The verification every implementation must perform on a bundle, as error classes."""
    document, files = packed["seal"], packed["files"]
    errors = set()
    for message in seal_mod._check_head(document, None):
        errors.add("cosignature" if "co-signature" in message else "signature")
    items, head = document.get("items", []), document.get("head", {})
    if len(items) != head.get("item_count") or MerkleTree([seal_mod._leaf(i) for i in items]).root_hex != head.get("merkle_root"):
        errors.add("root")
    for item in items:
        data = base64.b64decode(files.get(item["path"], ""))
        if item["path"] not in files or blake2b(data, digest_size=32).hexdigest() != item["blake2b_256"] or len(data) != item["bytes"]:
            errors.add("file")
    return sorted(errors)


def _seal(case: Dict[str, Any]) -> Optional[str]:
    got = check_bundle(case["bundle"])
    return None if got == case["errors"] else f"errors {got}, expected {case['errors']}"


def _belief(case: Dict[str, Any]) -> Optional[str]:
    got = bayes.posterior(case["model"], case["entry"], case["control"], date.fromisoformat(case["today"]), build=case.get("build"))
    return None if abs(got - case["p_holds"]) < 1e-9 else f"P(holds) {got!r}, expected {case['p_holds']!r}"


def _status(case: Dict[str, Any]) -> Optional[str]:
    data = {"level": "L1", "controls": {"C-1": copy.deepcopy(case["before"])}}
    result = ProbeResult(case["probe"], ["C-1"], "vector")
    result.checks_for = {"C-1": case["checks"]} if case["checks"] else {}
    result.checks = case["checks"]
    if case["finding"]:
        result.add("C-1", "high", "vector finding")
    assess.apply_probe(data, result, "evidence/vector.json")
    got = data["controls"]["C-1"]["status"]
    return None if got == case["after"] else f"status {got}, expected {case['after']}"


def _profile(case: Dict[str, Any]) -> Optional[str]:
    prof = profile_mod.load()
    if prof.version != case["version"]:
        return None  # vectors for another profile version do not apply
    got = {level: sorted(c.id for c in prof.for_level(level)) for level in profile_mod.LEVELS}
    return None if got == case["controls_by_level"] else "controls required per level differ"


KINDS: Dict[str, Callable[[Dict[str, Any]], Optional[str]]] = {
    "canonical-json": _canonical, "merkle": _merkle, "ed25519": _ed25519, "seal": _seal, "belief": _belief,
    "probe-status": _status, "profile": _profile,
}


def load(directory: Optional[str] = None) -> List[Dict[str, Any]]:
    if directory:
        texts = [open(p, "r", encoding="utf-8").read() for p in sorted(glob.glob(os.path.join(directory, "*.json")))]
    else:
        folder = resources.files("patient_zero").joinpath("data/vectors")
        texts = [p.read_text("utf-8") for p in sorted(folder.iterdir(), key=lambda p: p.name) if p.name.endswith(".json")]
    return [json.loads(t) for t in texts]


def run(directory: Optional[str] = None) -> List[str]:
    """Run every vector. Returns one line per failure; empty means this implementation conforms."""
    failures: List[str] = []
    files = load(directory)
    if not files:
        return ["no vector files found"]
    seen = set()
    for doc in files:
        check = KINDS.get(doc.get("kind"))
        if check is None:
            failures.append(f"unknown vector kind: {doc.get('kind')}")
            continue
        seen.add(doc["kind"])
        for case in doc["cases"]:
            try:
                problem = check(case)
            except Exception as exc:  # a crash on a vector is a failure of that vector
                problem = f"{type(exc).__name__}: {exc}"
            if problem:
                failures.append(f"{doc['kind']} / {case['name']}: {problem}")
    for missing in sorted(set(KINDS) - seen):
        failures.append(f"no vectors of kind {missing}")
    return failures
