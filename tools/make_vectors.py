"""Regenerate the conformance vectors in patient_zero/data/vectors/.

Run from the repository root: python tools/make_vectors.py
Everything is derived from fixed inputs (fixed keys, fixed dates), so the
output is byte-for-byte repeatable. Change a vector only with the spec version.
"""
import base64
import copy
import json
import os
from datetime import date
from hashlib import blake2b

from patient_zero import bayes, profile, seal
from patient_zero.custody import MerkleTree, generate_keypair, sign

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "patient_zero", "data", "vectors")
SPEC = "0.1"


def write(kind, description, cases):
    with open(os.path.join(OUT, f"{kind}.json"), "w", encoding="utf-8") as fh:
        json.dump({"spec": SPEC, "kind": kind, "description": description, "cases": cases}, fh, indent=1, sort_keys=True)
        fh.write("\n")


def canonical():
    values = {
        "empty object": {},
        "keys sorted": {"b": 1, "a": 2, "C": 3},
        "nested": {"z": [1, "two", None, True, False], "a": {"y": "x", "b": []}},
        "non-ascii escaped": {"name": "Clínica Niño", "emoji": "\U0001f600"},
        "control characters and quotes": {"t": "line\nbreak\t\"quoted\" \\ slash /"},
        "seal leaf": {"path": "evidence/a.json", "blake2b_256": "00" * 32, "bytes": 17},
    }
    write("canonical-json", "UTF-8 bytes of the canonical form: keys sorted by code point, no spaces, non-ASCII as \\uXXXX "
          "(UTF-16 code units), integers only.", [{"name": k, "value": v, "canonical_hex": seal._canonical(v).hex()} for k, v in values.items()])


def merkle():
    cases = []
    for n in (0, 1, 2, 3, 4, 5, 8):
        leaves = [f"leaf-{i}".encode() for i in range(n)]
        tree = MerkleTree(leaves)
        cases.append({"name": f"{n} leaves", "leaves_hex": [x.hex() for x in leaves], "root": tree.root_hex,
                      "proofs": [[list(s) for s in tree.inclusion_proof(i)] for i in range(n)]})
    write("merkle", "RFC 6962 topology with BLAKE2b-256. Leaf = H(0x00 || data), node = H(0x01 || left || right), an odd node is "
          "promoted unchanged, the empty tree's root is H(0x00). Proof steps are [side of the sibling, sibling hash].", cases)


RFC8032 = [  # RFC 8032 section 7.1, tests 1 to 3
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", ""),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72"),
    ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82"),
]


def ed25519():
    cases = []
    for number, (seed, message) in enumerate(RFC8032, 1):
        _, public = generate_keypair(bytes.fromhex(seed))
        cases.append({"name": f"RFC 8032 test {number}", "seed": seed, "public_key": public, "message_hex": message,
                      "signature": sign(bytes.fromhex(message), seed), "valid": True})
    seed, public = RFC8032[0][0], generate_keypair(bytes.fromhex(RFC8032[0][0]))[1]
    good = sign(b"patient-zero", seed)
    cases += [
        {"name": "altered message", "public_key": public, "message_hex": b"patient-zer0".hex(), "signature": good, "valid": False},
        {"name": "altered signature", "public_key": public, "message_hex": b"patient-zero".hex(),
         "signature": good[:-2] + ("00" if good[-2:] != "00" else "01"), "valid": False},
        {"name": "wrong key", "public_key": generate_keypair(bytes.fromhex(RFC8032[1][0]))[1], "message_hex": b"patient-zero".hex(),
         "signature": good, "valid": False},
        {"name": "scalar not reduced (s >= L)", "public_key": public, "message_hex": b"patient-zero".hex(),
         "signature": good[:64] + "ff" * 32, "valid": False},
    ]
    write("ed25519", "RFC 8032 Ed25519. Keys and signatures are lowercase hex. Verification must reject s >= L and points outside "
          "the prime-order subgroup.", cases)


def seals():
    vendor, assessor = RFC8032[0][0], RFC8032[1][0]
    files = {"assessment.yaml": b"product: Vector Clinic\nlevel: L1\n", "evidence/isolation.json": b'{"probe": "isolation"}\n',
             "evidence/política.txt": "MFA en todas las cuentas\n".encode()}
    items = [{"path": p, "blake2b_256": blake2b(data, digest_size=32).hexdigest(), "bytes": len(data)} for p, data in sorted(files.items())]
    head = {
        "schema": seal.SCHEMA, "product": "Vector Clinic", "level": "L1", "profile_version": "0.1",
        "sealed_at": "2026-11-22T00:00:00+00:00", "item_count": len(items),
        "merkle_root": MerkleTree([seal._leaf(i) for i in items]).root_hex, "previous_root": None,
        "signer": {"name": "Vector Clinic, Inc.", "public_key": generate_keypair(bytes.fromhex(vendor))[1], "domain": "vendor.example"},
        "summary": {"controls": 43, "confirmed": 2, "tested_clean_only": 5, "failed": 1, "not_assessed": 35, "not_applicable": 0,
                    "with_probe_evidence": 6, "confirmed_by_independent": 1, "confirmed_by_self_only": 1, "build": "2026.11.0"},
    }
    document = {"head": head, "signature": sign(seal._canonical(head), vendor), "items": items}
    body = {"schema": seal.COSIGN_SCHEMA, "merkle_root": head["merkle_root"], "seal_signature": document["signature"],
            "signer": {"name": "Example Assessors LLC", "public_key": generate_keypair(bytes.fromhex(assessor))[1], "domain": "assessor.example"},
            "role": "independent-assessor", "statement": "Reviewed the isolation evidence for build 2026.11.0.",
            "signed_at": "2026-11-22T01:00:00+00:00"}
    document["cosignatures"] = [{"body": body, "signature": sign(seal._canonical(body), assessor)}]
    good = {"schema": seal.BUNDLE_SCHEMA, "seal": document, "files": {p: base64.b64encode(d).decode() for p, d in files.items()}}

    def variant(name, errors, change):
        packed = copy.deepcopy(good)
        change(packed)
        return {"name": name, "bundle": packed, "errors": errors}

    def edit_file(p):
        p["files"]["evidence/isolation.json"] = base64.b64encode(b'{"probe": "isolation", "clean": true}\n').decode()

    def drop_item(p):
        p["seal"]["items"].pop()

    def swap_cosign(p):
        p["seal"]["cosignatures"][0]["body"]["role"] = "customer"

    cases = [
        {"name": "valid seal with a co-signature", "bundle": good, "errors": []},
        variant("one evidence file edited after sealing", ["file"], edit_file),
        variant("one evidence file withheld", ["file"], lambda p: p["files"].pop("evidence/isolation.json")),
        variant("an item dropped from the list", ["root"], drop_item),
        variant("the level in the head raised", ["signature"], lambda p: p["seal"]["head"].__setitem__("level", "L2")),
        variant("the summary in the head improved", ["signature"], lambda p: p["seal"]["head"]["summary"].__setitem__("failed", 0)),
        variant("the co-signer's role changed", ["cosignature"], swap_cosign),
        variant("a co-signature moved from another seal", ["cosignature"],
                lambda p: p["seal"]["cosignatures"][0]["body"].__setitem__("merkle_root", "11" * 32)),
    ]
    samples = os.path.join(os.path.dirname(OUT), "..", "..", "docs", "verify", "samples.js")
    with open(os.path.normpath(samples), "w", encoding="utf-8") as fh:
        fh.write("/* Generated by tools/make_vectors.py from the seal test vectors. Made-up product, made-up signers. */\n")
        fh.write("window.PZ_SAMPLES = " + json.dumps({"good": cases[0]["bundle"], "edited": cases[1]["bundle"]}, sort_keys=True) + ";\n")
    write("seal", "A bundle is a seal plus its files in base64. `errors` is the sorted set of error classes a verifier must report: "
          "signature (head signature invalid), cosignature (a co-signature invalid or made over another seal), root (item list does "
          "not match the signed root or count), file (a listed file is missing or does not match its digest and size).", cases)


def belief():
    model = bayes.load_model()
    today = "2026-11-22"

    def case(name, control, observations, build=None):
        entry = {"status": "not_assessed", "observations": observations}
        p = bayes.posterior(model, entry, control, date.fromisoformat(today), build=build)
        out = {"name": name, "model": model, "control": control, "entry": entry, "today": today, "p_holds": p}
        if build:
            out["build"] = build
        return out

    probe = lambda outcome, checks, day, build=None: {"kind": "probe", "probe": "isolation", "outcome": outcome, "checks": checks,  # noqa: E731
                                                       "date": day, "build": build}
    att = lambda by, outcome, day: {"kind": "attestation", "by": by, "outcome": outcome, "date": day, "ref": "a"}  # noqa: E731
    write("belief", "P(control holds) from the prior and the latest observation per source. Each observation adds "
          "weight * ln(P(obs | holds) / P(obs | broken)) to the log-odds; weight = 0.5 ^ (age_days / half_life_days), times "
          "other_build_weight when the observation is about another build. A newer observation from the same source replaces the "
          "older one. Probabilities are clamped to [1e-6, 1 - 1e-6]. Match to 1e-9.", [
              case("no evidence is the prior", "GATE-3", []),
              case("a finding today", "GATE-3", [probe("finding", 2, today)]),
              case("a clean run of 3 checks today", "GATE-3", [probe("clean", 3, today)]),
              case("a clean run with no checks moves nothing", "GATE-3", [probe("clean", 0, today)]),
              case("a clean run on a control the probe cannot see", "BASE-1", [probe("clean", 10, today)]),
              case("a clean run 180 days old counts half", "GATE-3", [probe("clean", 3, "2026-05-26")]),
              case("a rerun replaces the earlier result", "GATE-3", [probe("finding", 2, "2026-11-01"), probe("clean", 3, today)]),
              case("self attestation", "BASE-1", [att("self", "pass", today)]),
              case("independent attestation", "BASE-1", [att("independent", "pass", today)]),
              case("self and independent attestations add", "BASE-1", [att("self", "pass", today), att("independent", "pass", today)]),
              case("an assessor's fail", "BASE-1", [att("independent", "fail", today)]),
              case("evidence from another build counts a quarter", "GATE-3", [probe("clean", 3, today, "2026.10.0")], build="2026.11.0"),
          ])


def status():
    blank = {"status": "not_assessed", "source": None, "note": "", "evidence": [], "observations": []}

    def entry(status_, source):
        return {**blank, "status": status_, "source": source, "evidence": ["e.png"]}

    cases = [
        ("a clean run lifts not_assessed to partial, never to pass", blank, 3, False, "partial"),
        ("a finding fails the control", blank, 3, True, "fail"),
        ("a finding overrides a person's pass", entry("pass", "assessor"), 3, True, "fail"),
        ("a clean run does not undo a person's pass", entry("pass", "assessor"), 3, False, "pass"),
        ("a clean run does not undo a person's fail", entry("fail", "assessor"), 3, False, "fail"),
        ("a clean rerun lifts the same probe's own fail to partial", entry("fail", "probe:isolation"), 3, False, "partial"),
        ("a run with no checks is void and changes nothing", blank, 0, False, "not_assessed"),
        ("a void run does not lift a fail", entry("fail", "probe:isolation"), 0, False, "fail"),
    ]
    write("probe-status", "How one probe run changes one control's status. A probe can fail a control; it cannot pass one.",
          [{"name": n, "probe": "isolation", "before": b, "checks": c, "finding": f, "after": a} for n, b, c, f, a in cases])


def profile_vector():
    prof = profile.load()
    write("profile", "Which controls each level requires, for one profile version. Levels are cumulative.",
          [{"name": f"profile {prof.version}", "version": prof.version,
            "controls_by_level": {level: sorted(c.id for c in prof.for_level(level)) for level in profile.LEVELS}}])


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for make in (canonical, merkle, ed25519, seals, belief, status, profile_vector):
        make()
    print(f"wrote vectors to {OUT}")
