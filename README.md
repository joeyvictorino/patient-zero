# patient-zero

Every AI app that touches PHI is patient zero. We run the outbreak investigation.

An open safeguard profile for AI apps that handle protected health information, shipped as code: 43 testable controls, drop-in reference safeguards, black-box probes, and a Bayesian readiness score that refuses to pretend a green tick is certainty.

```
pip install git+https://github.com/joeyvictorino/patient-zero
pz demo
```

`pz demo` starts a deliberately broken AI app on localhost, investigates it, patches it, and investigates again. It needs no network, no account and no API key.

```
== vulnerable build ==
  isolation   3 checks  2 finding(s)
      [CRITICAL] GATE-3: GET /api/workspaces/ws_a/clients returned tenant A's data to another tenant
      [CRITICAL] GATE-3: GET /api/workspaces/ws_a/clients returned tenant A's data to an anonymous caller
  agent       6 checks  5 finding(s)
      [CRITICAL] MEM-1: Agent returned tenant A's canary to tenant B (x4)
      [HIGH] AGENT-4: Agent followed an instruction planted in a record
  egress      3 checks  1 finding(s)
      [HIGH] TRUST-2: PHI enclave reached collect.adtracker.example
  log         3 checks  1 finding(s)
      [CRITICAL] LOG-2: Audit log failed verification

== patched build ==
  isolation   3 checks  clean
  agent       6 checks  clean
  egress      2 checks  clean
  log         6 checks  clean

  belief after the same probes come back clean:
  GATE-3   ###########.........  54.0%  partial
  TRUST-2  ############........  57.6%  partial
  AGENT-4  ##########..........  51.0%  partial
  MEM-1    ############........  57.9%  partial
  LOG-2    ##############......  68.1%  partial
```

Look at the last block. Every probe came back clean and belief barely moved. Three requests that found nothing are not proof of tenant isolation, and the score says so.

## Why this exists

Getting an AI product into a clinic costs months and a consultant before anyone has tested anything. Small teams with useful tools give up, and healthcare keeps its fax machines. Most of that cost is working out what to check and how to show you checked it. That part can be open source.

## The idea: compliance is inference, not a checklist

A checklist with 35 green ticks reads as 100% done. If each tick is really 90% likely to be true, the chance that nothing is broken is 0.9^35, about 2.5%.

patient-zero keeps one number per control, P(control holds | evidence), and updates it with Bayes' rule:

- A probe **finding** is strong evidence the control is broken.
- A **clean** probe run is weak evidence it holds, scaled by how many checks ran and how much of the control that probe can see at all.
- A person's **attestation** counts for more when they are independent of the team that built the control.
- Evidence **decays**. Its weight halves every 180 days, so last year's pentest stops carrying this year's release.
- Rerunning a probe **replaces** its old result, so the same test is never counted twice.

Because belief is a number, the tool can also tell you what to do next. `pz next` ranks every test you could run by expected bits of uncertainty removed per unit of effort:

```
$ pz next
most uncertainty removed per unit of effort:
  TRUST-2  run the egress probe                   0.43 bits  cost 1
  LOG-2    run the log probe                      0.34 bits  cost 1
  TRUST-1  run the egress probe                   0.25 bits  cost 1
  GATE-3   run the isolation probe                0.24 bits  cost 1
```

**The numbers are assumptions, not measurements.** Every likelihood sits in one short file, [`patient_zero/data/belief.yaml`](patient_zero/data/belief.yaml). Nobody has calibration data for "how often does a self-attested access control turn out to be broken", so the file states its guesses and you can replace them with `--model`. The headline product also treats controls as independent, which they are not. If you have real calibration data, that is the most valuable contribution this project could get.

## The profile

[`patient_zero/data/controls.yaml`](patient_zero/data/controls.yaml) holds eight families. Levels are cumulative and declared per workspace.

| Family | Principle |
| --- | --- |
| GATE | PHI is off by default; turning it on is an explicit, recorded act |
| TRUST | No party touches PHI without a verified identity and a signed BAA |
| AGENT | Agents act with their own identity, narrower rights, and confirmation on disclosure |
| MEMORY | Tenant scope is the boundary for learned memory, embeddings and caches |
| LOG | Every PHI event lands in a log that shows tampering |
| MAP | The operator can enumerate every PHI store, flow and egress |
| BASE | The ordinary Security Rule safeguards come first |
| TEST | Controls are proven by repeatable tests, not policy text |

| Level | Name | Meaning | Controls |
| --- | --- | --- | --- |
| L0 | Unprivileged | No PHI; the product keeps it out | 5 |
| L1 | Helper | Stores and processes PHI on BAA-covered models | 35 |
| L2 | Agentic | Agents act on PHI; external assistants connect | 43 |

The design is least privilege as a good system tool practices it: do useful work with no special rights, and earn elevated access through an explicit, verified, revocable step. Here the privilege is access to PHI.

## Reference safeguards

Small, dependency-light modules you can adopt or port. [`examples/adopt.py`](examples/adopt.py) wires all four together.

| Module | What it does | Controls |
| --- | --- | --- |
| `patient_zero.gate` | PHI off by default, on only with an executed BAA, closed on any failure | GATE-1, GATE-2, GATE-4 |
| `patient_zero.auditlog` | Append-only, hash-chained log with separate user and agent identity | LOG-1, LOG-2, AGENT-1 |
| `patient_zero.egress` | Subprocessor register and egress allowlist | TRUST-1, TRUST-2, TRUST-3 |
| `patient_zero.phi` | Heuristic likely-PHI tripwire for non-PHI workspaces | GATE-5 |

## Assess your own product

```
pz init --product "My App" --level L1
cp examples/target.example.yaml target.yaml      # then edit it

pz probe isolation --config target.yaml -a assessment.yaml
pz probe agent     --config target.yaml -a assessment.yaml
pz probe egress    --config target.yaml -a assessment.yaml
pz probe tls       --config target.yaml -a assessment.yaml
pz probe log --file audit.jsonl --expected-head <anchored hash> -a assessment.yaml

pz set BASE-1 pass --evidence evidence/mfa-policy.png --independent
pz belief                                        # P(holds) per control
pz next                                          # what to test next
pz report --html -o report.html                  # hand this to a customer
pz report --strict                               # exit 1 unless conformant, for CI
```

| Probe | Tests | Controls |
| --- | --- | --- |
| `isolation` | Tenant A's routes requested as tenant B and with no token | GATE-3, TEST-1 |
| `agent` | Cross-tenant canary leakage; an instruction planted in a record | MEM-1, AGENT-4 |
| `egress` | Observed outbound hosts against the register | TRUST-1, TRUST-2 |
| `tls` | Transport encryption | BASE-2 |
| `log` | Hash chain integrity | LOG-2 |

![HTML report](docs/report.png)

Rules the tooling enforces:

- Probes refuse to run unless the target file sets `authorized: true`, `synthetic_data_only: true` and an `authorization_ref`. Test systems you own or have written permission to test, with synthetic data, never real PHI.
- A probe can fail a control. It cannot pass one. A clean run sets `partial`; a person records `pass` with evidence.
- Every probe run writes a dated, hashed JSON file under `evidence/`.

Want to try the probes by hand first? `pz demo --serve` runs the broken app on port 8099, and `pz demo --serve --patched` runs the fixed one.

## What this is not

- **Not a HIPAA certification.** HHS does not issue or recognize one. This produces evidence for a customer or an external assessor.
- **Not a NIST publication**, and not legal advice. Every HIPAA paragraph cited was checked to exist in eCFR on 2026-11-10; whether it is the right home for a control is the author's judgment. The SP 800-53 and CSF identifiers are unchecked.
- **Not a pentest.** Five probes touch eight of 43 controls. The other 35 need a person, and so does the final call on those eight.
- **Not battle-tested.** Draft 0.1, one author, proven only against its own demo app. The agent probe sends one planted instruction; a clean result says little, and the score reflects that.
- **Not tamper-proof logging.** The hash chain shows edits. It cannot show a cut tail unless you anchor the head hash somewhere the app cannot write.

## Help wanted

- Calibration data or better arguments for the numbers in `belief.yaml`
- Review of the control wording and mappings by people who do HIPAA assessments
- More probes: agent permission escalation, memory deletion, confirmation gates
- Ports of the reference safeguards to TypeScript and Go

## Develop

```
pip install -e ".[dev]"
pytest -q
```

## License

MIT
