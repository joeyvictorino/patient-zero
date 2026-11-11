# patient-zero

Every AI app that touches PHI is patient zero. We run the outbreak investigation.

An open safeguard profile for AI applications that handle protected health information, as code: 43 controls in machine-readable form, small reference safeguards you can adopt, and probes that produce dated evidence. The goal is to cut the cost of getting useful AI tools into healthcare safely.

**Status: draft 0.1.** This is not a NIST publication and not a HIPAA certification. HHS does not issue or recognize one. The HIPAA, SP 800-53 and CSF mappings are first-pass and unverified. Nothing here is legal advice.

## Install

```
pip install -e ".[dev]"
pytest -q
```

## The profile

`patient_zero/data/controls.yaml` holds eight families: GATE, TRUST, AGENT, MEMORY, LOG, MAP, BASE, TEST. Levels are cumulative.

| Level | Name | Meaning | Controls |
| --- | --- | --- | --- |
| L0 | Unprivileged | No PHI; the product keeps it out | 5 |
| L1 | Helper | Stores and processes PHI on BAA-covered models | 35 |
| L2 | Agentic | Agents act on PHI; external assistants connect | 43 |

```
pz controls --level L1
pz controls --family AGENT --json
```

## Reference safeguards

| Module | What it does | Controls |
| --- | --- | --- |
| `patient_zero.gate` | PHI off by default, on only with an executed BAA, closed on any failure | GATE-1, GATE-2, GATE-4 |
| `patient_zero.auditlog` | Append-only, hash-chained log with separate user and agent identity | LOG-1, LOG-2, AGENT-1 |
| `patient_zero.egress` | Subprocessor register and egress allowlist | TRUST-1, TRUST-2, TRUST-3 |
| `patient_zero.phi` | Heuristic likely-PHI tripwire for non-PHI workspaces | GATE-5 |

`examples/adopt.py` wires all four together.

## Assess a product

```
pz init --product "My App" --level L1
cp examples/target.example.yaml target.yaml      # then edit it

pz probe isolation --config target.yaml -a assessment.yaml
pz probe agent     --config target.yaml -a assessment.yaml
pz probe egress    --config target.yaml -a assessment.yaml
pz probe tls       --config target.yaml -a assessment.yaml
pz probe log --file audit.jsonl --expected-head <anchored hash> -a assessment.yaml

pz set BASE-1 pass --evidence evidence/mfa-policy.png --note "enforced at the IdP"
pz report assessment.yaml -o report.md
pz report assessment.yaml --strict               # exit 1 unless conformant, for CI
```

| Probe | Tests | Controls |
| --- | --- | --- |
| `isolation` | Tenant A's routes requested as tenant B and with no token | GATE-3, TEST-1 |
| `agent` | Cross-tenant canary leakage; instruction planted in a record | MEM-1, AGENT-4 |
| `egress` | Observed outbound hosts against the register | TRUST-1, TRUST-2 |
| `tls` | Transport encryption | BASE-2 |
| `log` | Hash chain integrity | LOG-2 |

Rules the tooling enforces:

- Probes run only when the target file sets `authorized: true`, `synthetic_data_only: true` and an `authorization_ref`. Test systems you own or have written permission to test, with synthetic data, never real PHI.
- A probe can fail a control. It cannot pass one. A clean run sets `partial`; a person records `pass` with evidence.
- Every probe run writes a dated, hashed JSON file under `evidence/`.

## Design

The model is least privilege as practiced by a good system tool: do useful work with no special rights, and earn elevated access through an explicit, verified, revocable step. Here the privilege is access to PHI.

## License

MIT
