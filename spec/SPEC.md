# patient-zero specification

Version 0.1, draft. This document is the standard. The Python package in this repository is one implementation of it; `docs/verify/verify.js` is a second, partial one. An implementation in any language conforms when it reproduces the test vectors in [`patient_zero/data/vectors/`](../patient_zero/data/vectors/).

The words "must", "must not" and "may" are requirements on an implementation.

## 1. Scope

The specification defines five things:

1. the **profile**: a catalogue of controls, grouped in families, required by level
2. the **assessment**: one status per control, with observations, and the rules by which a test changes a status
3. the **belief model**: how observations become P(control holds)
4. the **seal**: a signed, tamper-evident record of an assessment and its evidence, with co-signatures, single-file proofs, bundles and signer identity
5. **conformance**: what an implementation has to reproduce

It does not define the probes. A probe is any test that produces observations; implementations may add their own.

## 2. Profile

A profile is a document with `version`, `levels`, `families` and `controls`. The reference copy is [`patient_zero/data/controls.yaml`](../patient_zero/data/controls.yaml).

- A **control** has `id`, `family`, `min_level`, `keyword` (`shall` or `should`) and `statement`. Ids are unique. The statement contains the keyword.
- **Levels** are `L0`, `L1`, `L2`, and are cumulative: a level requires every control whose `min_level` is at or below it.
- A workspace **conforms** to a level when every required `shall` control has status `pass`, or `not_applicable` with a written reason.

Vector kind `profile` fixes the controls each level requires for one profile version.

## 3. Assessment

Each required control has a `status`: `not_assessed`, `pass`, `partial`, `fail` or `not_applicable`.

An **observation** is one of:

- a probe observation: `{kind: "probe", probe, outcome: "clean" | "finding", checks, date, build}` where `checks` counts only checks that could have found a problem with this control
- an attestation: `{kind: "attestation", by: "self" | "independent", outcome: "pass" | "fail", date, build, ref}`

A probe run changes a control's status by these rules, and no others (vector kind `probe-status`):

1. A finding sets the status to `fail`, even over a person's `pass`.
2. A clean run with at least one check lifts `not_assessed` to `partial`. It lifts `fail` to `partial` only if that same probe set the `fail`.
3. A clean run must not set `pass`. Only a person records `pass`, with at least one piece of evidence.
4. A run with no check able to test the control is **void** for that control. It must not change the status, add an observation or settle a prediction.

## 4. Belief model

For each control, an implementation computes P(holds) from a prior and the **latest** observation per source (a source is one probe, or one kind of attester). A newer observation from the same source replaces the older one.

Each observation adds `weight * ln(P(obs | holds) / P(obs | broken))` to the log-odds of the prior, where:

- for a probe finding: `P(obs | holds) = false_positive`, `P(obs | broken) = finding_if_broken`
- for a clean probe run: `P(obs | holds) = 1 - false_positive`, `P(obs | broken) = 1 - power`, with `power = coverage[probe][control] * (1 - (1 - detection[probe]) ^ checks)`
- for an attestation: the `if_holds` and `if_broken` values for its kind
- `weight = 0.5 ^ (age_days / half_life_days)`, multiplied by `other_build_weight` when the observation names a build other than the one under assessment

Every probability is clamped to `[1e-6, 1 - 1e-6]`. The parameter values are not part of this specification: they live in a model file ([`belief.yaml`](../patient_zero/data/belief.yaml)) and are stated guesses. The arithmetic is specified; vector kind `belief` carries its own model and must be matched to `1e-9`.

## 5. Seal

### 5.1 Canonical JSON

Signed data is serialized as JSON with object keys sorted by Unicode code point, no insignificant whitespace, and every character above U+007F written as `\uXXXX` escapes of its UTF-16 code units in lowercase hex, then encoded as UTF-8. Signed data must contain only objects, arrays, strings, integers, booleans and null. Floating point numbers must not appear in signed data. Vector kind `canonical-json`.

### 5.2 Hashing and the Merkle tree

All hashes are BLAKE2b with a 32-byte digest and no key.

- An **item** is `{path, blake2b_256, bytes}` for one file: its path relative to the sealed directory with `/` separators, the hex digest of its content, and its size.
- A **leaf** is the canonical JSON of the item. `leaf_hash = H(0x00 || leaf)`, `node_hash = H(0x01 || left || right)`.
- Items are ordered by path. The tree has RFC 6962 topology except that an odd node at any level is promoted unchanged, and the root of an empty tree is `H(0x00)`.
- An **inclusion proof** is a list of `[side, sibling_hex]` steps from leaf to root, where `side` is `L` or `R`, the side the sibling is on.

Vector kind `merkle`.

### 5.3 Signatures

Signatures are Ed25519 (RFC 8032) over canonical JSON. Keys and signatures are lowercase hex. A verifier must reject a signature whose scalar is not less than the group order, and keys or nonce points outside the prime-order subgroup. Vector kind `ed25519`.

### 5.4 The seal document

```
{
  "head": {
    "schema": "patient-zero-seal-v1",
    "product", "level", "profile_version",
    "sealed_at":      ISO 8601 with offset,
    "item_count":     integer,
    "merkle_root":    hex,
    "previous_root":  hex or null,          the root of the seal this one replaces
    "signer":         {"name", "public_key", "domain"?},
    "summary":        {...}                 optional, see 5.5
  },
  "signature":    Ed25519 over canonical(head) by signer.public_key,
  "items":        [item, ...],
  "cosignatures": [{"body", "signature"}, ...]   optional, see 5.6
}
```

A verifier must report, as separate error classes:

- `signature`: the head's schema is unknown, or the signature over the head does not verify
- `root`: `item_count` differs from the number of items, or the Merkle root of the items differs from `merkle_root`
- `file`: a listed file is missing, or its size or digest differs
- `cosignature`: see 5.6

A verifier must not treat unknown fields in the head as an error: they are covered by the signature. A verifier that displays a seal must display the age of `sealed_at`.

### 5.5 The signed summary

`summary` lets a verifier show what the assessment claims without parsing the sealed files. Its fields are integers, and `build` a string or null: `controls`, `confirmed` (status `pass`), `tested_clean_only` (`partial`), `failed`, `not_assessed`, `not_applicable`, `with_probe_evidence`, `confirmed_by_independent`, `confirmed_by_self_only`.

A display of a seal must not describe it as compliant, certified or passed. It states the counts.

### 5.6 Co-signatures

A second party signs an existing seal without changing it. The body is:

```
{"schema": "patient-zero-cosign-v1", "merkle_root", "seal_signature",
 "signer": {"name", "public_key", "domain"?},
 "role": "independent-assessor" | "customer" | "counsel" | "internal-reviewer",
 "statement", "signed_at"}
```

and the signature is Ed25519 over the canonical body. A verifier must report `cosignature` when the body's `merkle_root` or `seal_signature` differ from the seal's, or the signature does not verify. An implementation must refuse to create a co-signature with the key that signed the head.

### 5.7 Single-file proof

`{head, signature, item, proof}` lets a holder of one file show it belongs to a seal without revealing the other items. A verifier checks the head signature, the file against the item, and the inclusion proof from the item's leaf to `head.merkle_root`.

### 5.8 Bundle

`{"schema": "patient-zero-bundle-v1", "seal": <seal document>, "files": {path: base64 content}}`. One file a recipient can verify with nothing else. Vector kind `seal` is expressed as bundles, each with the sorted set of error classes a verifier must report.

### 5.9 Signer identity

A key alone shows that the same party signed successive seals. To tie a key to a name people know, a signer publishes at `https://<domain>/.well-known/patient-zero.json`:

```
{"schema": "patient-zero-identity-v1", "domain": "<domain>",
 "keys": [{"public_key": hex, "status": "active" | "retired"}]}
```

and names that `domain` in `signer`. A verifier that checks identity fetches the file over HTTPS and confirms that `domain` matches and the key is listed as `active`. This rests on control of the domain and on web PKI, no more. A verifier must not fetch it unless the user asks: verification is otherwise offline.

## 6. Conformance

An implementation states which classes it implements:

| Class | Must reproduce vector kinds |
| --- | --- |
| Verifier | `canonical-json`, `merkle`, `ed25519`, `seal` |
| Sealer | Verifier, and produce seals a conforming verifier accepts |
| Assessor | `profile`, `probe-status`, `belief` |

`pz conformance` runs every kind against the Python implementation. `node tools/run_vectors.js` runs the Verifier class against the JavaScript one. A port runs the JSON files directly; each case carries its inputs and expected result.

## 7. Versioning

- The **profile** has its own version. Adding, removing or changing the level of a control changes it. An assessment and a seal record the profile version they were made against.
- **Schemas** (`patient-zero-seal-v1` and the others) change name when a verifier of the old version would accept something it should reject, or reject something valid. Adding an optional field to a signed head does not change the schema.
- **Vectors** change only together with this document's version. A change to a vector is a change to the standard and goes through the process in [`GOVERNANCE.md`](../GOVERNANCE.md).

## 8. What this specification is not

It is not a HIPAA certification scheme, and conformance of software to this document says nothing about whether a product protects patient data. It defines how claims about a product are recorded, weighed and made tamper-evident, so that a reader can see exactly what was tested, by whom, on which build.
