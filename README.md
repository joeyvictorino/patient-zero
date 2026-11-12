# patient-zero

Every AI app that touches PHI is patient zero. We run the outbreak investigation.

An open safeguard profile for AI apps that handle protected health information, shipped as code: 43 testable controls, drop-in reference safeguards, nine probes, a Bayesian readiness score that refuses to pretend a green tick is certainty, and signed evidence you can disclose one file at a time.

```
pip install git+https://github.com/joeyvictorino/patient-zero
pz demo
```

`pz demo` starts a deliberately broken AI app on localhost, investigates it, patches it, and investigates again. It needs no network, no account and no API key.

```
== before any test: write the prediction down ==
  isolation  the team says 90% it comes back clean; the model says 65%
  agent      the team says 80% it comes back clean; the model says 62%

== vulnerable build ==
  isolation   3 checks  2 finding(s)
      [CRITICAL] GATE-3: GET /api/workspaces/ws_a/clients returned tenant A's data to another tenant
      [CRITICAL] GATE-3: GET /api/workspaces/ws_a/clients returned tenant A's data to an anonymous caller
  agent      21 checks  16 finding(s)
      [CRITICAL] MEM-1: Agent returned tenant A's canary to tenant B (x12)
      [HIGH] AGENT-4: Agent followed an instruction planted in a record (x4)
  egress      3 checks  1 finding(s)
      [HIGH] TRUST-2: PHI enclave reached collect.adtracker.example
  log         3 checks  1 finding(s)
      [CRITICAL] LOG-2: Audit log failed verification
  stack       3 checks  3 finding(s)
      [HIGH] GATE-3: inference API published to all interfaces
      [MEDIUM] GATE-3: wildcard CORS (OLLAMA_ORIGINS=*)
      [HIGH] GATE-3: vector database published to all interfaces

  predictions settled (Brier score, 0 is perfect, 0.25 is a coin flip):
  the model (belief.yaml)    0.41
  the team                   0.73

== patched build ==
  isolation   3 checks  clean
  agent      21 checks  clean
  egress      2 checks  clean
  log         6 checks  clean
  stack       3 checks  clean

  belief after the same probes come back clean:
  GATE-3   ############........  61.0%  partial
  TRUST-2  ############........  57.6%  partial
  AGENT-4  ###########.........  54.8%  partial
  MEM-1    #############.......  66.9%  partial
  LOG-2    ##############......  68.1%  partial

== agent action gate: the agent proposes, a fixed policy decides ==
  summarize a record                       ALLOW  AUTHORIZED
  same proposal again                      DENY   REPLAY_DETECTED
  read a record and call an outside URL    DENY   DANGEROUS_COMBINATION:http.external+record.read
  email a patient, no human confirmation   DENY   CONFIRMATION_REQUIRED
  return the full note text                DENY   OUTPUT_NOT_ALLOWED:note_text
  agent returned 3 fields, 1 crossed: ['appointment_count']

== replay: re-derive a finding from its recording, offline ==
  isolation run from the vulnerable build: REPRODUCED from recorded exchanges
  same file with its findings deleted by hand: MISMATCH, the recording still shows the leak

== seal the evidence ==
  11 files under Merkle root df7638170a0c31715bbbec6d..., signed with Ed25519
  verify: ok
  edit one evidence file to say clean instead of finding, verify again: changed since sealing: evidence/agent-...json
```

Look at the belief block. Every probe came back clean and belief barely moved. Three requests that found nothing are not proof of tenant isolation, and the score says so.

## If you buy AI tools rather than build them

You run a practice, a clinic or a health system, and a vendor wants your patient data. You do not need to read the rest of this page.

- [One page for healthcare leaders](docs/FOR-HEALTHCARE-LEADERS.md) ([en español](docs/PARA-LIDERES-DE-SALUD.md))
- [The questions to send a vendor](docs/VENDOR-QUESTIONNAIRE.md): all 43 safeguards in plain language, each with the question to ask and what a good answer comes with
- [What Nevada law adds](docs/NEVADA.md): AB 406 (2025) on AI in mental and behavioral health care, and SB 370 on consumer health data

A vendor who uses this tool can hand you a plain-language summary (`pz report --executive`) and a signed evidence bundle.

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

Controls are scored as independent, but evidence often is not. One person signing twenty controls is one point of failure, not twenty. `pz fragile` leaves each source out in turn and shows what falls:

```
$ pz fragile
if everything one source told you were wrong:
  pat (self)                         props up  6 control(s), 1.5 more expected broken
  lee (independent)                  props up  1 control(s), 0.4 more expected broken
```

**The numbers are assumptions, not measurements.** Every likelihood sits in one short file, [`patient_zero/data/belief.yaml`](patient_zero/data/belief.yaml). Nobody has calibration data for "how often does a self-attested access control turn out to be broken", so the file states its guesses and you can replace them with `--model`. The headline product also treats controls as independent, which they are not. If you have real calibration data, that is the most valuable contribution this project could get.

## Method: four rules that keep the numbers honest

**Predict before you look.** `pz predict isolation 0.9 --by pat` records your forecast before the probe runs, next to the model's own. The next run settles both, and `pz calibration` keeps a Brier score for each person and for `belief.yaml`. This is how the guesses in that file get replaced with data: on your own product, one settled prediction at a time. It also tells you under 20 settled predictions that the differences are noise.

**A run that tested nothing is void, not clean.** If the setup request fails, or the target is plain HTTP on localhost, no check could have found a problem. The run is marked void, changes no status, moves no belief and settles no prediction.

**Evidence is about a build.** Put `build:` in the target file, or run `pz build 2026.11.1` when you ship. Evidence gathered on another release keeps counting, at a quarter weight, on top of the time decay. Last release's pentest does not cover this release.

**Every network finding can be replayed.** Probes record each request and response (never tokens). `pz replay evidence/isolation-....json` feeds the recording back through the probe logic offline and checks the same findings come out. A reviewer can confirm a finding without access to your system, and a result edited by hand no longer matches its own recording. Model output varies between runs, so the agent probe asks each leak prompt three times by default.

## Embedded mode: the probes inside your own tests

No server, no port, no target file. Hand the probe your framework's test client and it calls your application in-process:

```python
from patient_zero.embedded import assert_isolated

def test_tenants_cannot_read_each_other(client):
    assert_isolated(client, token_a=TOKEN_A, token_b=TOKEN_B,
                    resources=["/api/workspaces/ws_a/clients", "/api/workspaces/ws_a/notes"],
                    canary="a string only tenant A's data contains")
```

It works with FastAPI, Starlette, httpx and requests-shaped clients, with Flask and Werkzeug test clients, and with any bare WSGI app. The test fails on a cross-tenant read, and also when no route could be tested at all. `assert_agent_contained` does the same for the agent probe.

## Try it on your own stack in ten seconds

No target file, no running app. Point it at any directory with a Docker Compose file:

```
pz probe stack --path .
```

It flags inference APIs, model UIs, vector databases and data stores published on every interface, host networking, privileged containers, a mounted Docker socket and wildcard CORS.

On Postgres or Supabase? Point it at your migrations:

```
pz probe rls --path supabase/migrations
```

It reads the SQL in order and reports tables that end up without row level security, and policies that say `USING (true)`.

## Signed evidence, disclosed one file at a time

```
pz keygen                          # Ed25519 key, written 0600, never overwritten
pz seal --signer "Your Name"       # Merkle root over the assessment and every evidence file, signed
pz verify                          # any edited, missing or dropped file fails

pz prove evidence/pentest.json     # a small proof for ONE file
pz verify-proof proof.json evidence/pentest.json --public-key <yours>
```

A customer asks for your pentest evidence. You send that one file and `proof.json`. They can check it belongs to your signed assessment without seeing any other file, or even the other file names. Each new seal records the root of the one before it, so reassessments form a chain.

The Merkle tree and the Ed25519 implementation are standard library only, checked against the RFC 8032 test vectors. A key you generated proves the same key signed each seal, not who holds it: publish the public key somewhere you control, or have your assessor sign.

## The profile

The full text is in [`docs/PROFILE.md`](docs/PROFILE.md), generated from the data file.

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

Small, dependency-light modules you can adopt or port. [`examples/adopt.py`](examples/adopt.py) wires the first five together.

| Module | What it does | Controls |
| --- | --- | --- |
| `patient_zero.gate` | PHI off by default, on only with an executed BAA, closed on any failure | GATE-1, GATE-2, GATE-4 |
| `patient_zero.auditlog` | Append-only, hash-chained log with separate user and agent identity | LOG-1, LOG-2, AGENT-1 |
| `patient_zero.egress` | Subprocessor register and egress allowlist | TRUST-1, TRUST-2, TRUST-3 |
| `patient_zero.phi` | Heuristic likely-PHI tripwire for non-PHI workspaces | GATE-5 |
| `patient_zero.hidden` | Concealed-text tripwire: invisible characters, hidden markup and comments in anything an agent will read. Judges position, not wording | AGENT-4 |
| `patient_zero.phi.Vault` | Swap identifiers for placeholders before a model call and restore them after | AGENT-7 |
| `patient_zero.policy` | Agent action gate: the agent proposes, a deterministic policy decides, only allowlisted fields cross | AGENT-2, AGENT-3, AGENT-6, AGENT-7 |
| `patient_zero.custody` | Merkle tree and Ed25519, standard library only | TEST-4 |

## Assess your own product

```
pz init --product "My App" --level L1
cp examples/target.example.yaml target.yaml      # then edit it

pz predict isolation 0.8 --by you                # before you look
pz probe isolation --config target.yaml -a assessment.yaml
pz probe agent     --config target.yaml -a assessment.yaml
pz probe egress    --config target.yaml -a assessment.yaml
pz probe tls       --config target.yaml -a assessment.yaml
pz probe log --file audit.jsonl --expected-head <anchored hash> -a assessment.yaml
pz probe stack --path . -a assessment.yaml
pz probe rls --path supabase/migrations -a assessment.yaml
pz probe claims --transcript agent.jsonl --file audit.jsonl -a assessment.yaml
pz manifest /data -o before.json                 # then back up, restore elsewhere, and:
pz probe restore --manifest before.json --path /restored -a assessment.yaml

pz set BASE-1 pass --evidence evidence/mfa-policy.png --independent
pz belief                                        # P(holds) per control
pz next                                          # what to test next
pz fragile                                       # which source you lean on most
pz calibration                                   # how good the forecasts were, yours and the model's
pz replay evidence/<file>.json                   # re-derive a finding offline
pz report --html -o report.html                  # hand this to a customer
pz report --executive                            # one page in plain language for the decision maker
pz questionnaire --level L1 --overlay nevada     # what a buyer will ask you
pz scan site-copy.txt --care-claims              # wording that presents an AI as a therapist (Nevada AB 406)
pz report --strict                               # exit 1 unless conformant, for CI
```

| Probe | Tests | Controls |
| --- | --- | --- |
| `isolation` | Tenant A's routes requested as tenant B and with no token | GATE-3, TEST-1 |
| `agent` | Cross-tenant canary leakage, with a positive control; an instruction planted in each carrier, dressed four ways | MEM-1, AGENT-4 |
| `egress` | Observed outbound hosts against the register | TRUST-1, TRUST-2 |
| `tls` | Transport encryption | BASE-2 |
| `log` | Hash chain integrity | LOG-2 |
| `stack` | Docker Compose files that publish the stack's insides | GATE-3 |
| `rls` | SQL migrations that leave a table without row level security | GATE-3 |
| `claims` | What agents said they did against what the audit log recorded | LOG-1, AGENT-1 |
| `restore` | A restored directory against checksums taken before the backup | BASE-4 |

![HTML report](docs/report.png)

Rules the tooling enforces:

- Probes refuse to run unless the target file sets `authorized: true`, `synthetic_data_only: true` and an `authorization_ref`. Test systems you own or have written permission to test, with synthetic data, never real PHI.
- A probe can fail a control. It cannot pass one. A clean run sets `partial`; a person records `pass` with evidence.
- A finding is a theory until it reproduces. Network probes ask a second time before reporting, and a one-off goes to the notes, not the findings.
- Every probe run writes a dated, hashed JSON file under `evidence/`.

Want to try the probes by hand first? `pz demo --serve` runs the broken app on port 8099, and `pz demo --serve --patched` runs the fixed one.

## No telemetry

patient-zero collects nothing and phones nowhere. The only network traffic it ever creates goes to the `base_url` you put in the target file, and the demo stays on 127.0.0.1. A test in the suite fails if the demo opens a connection to anything but loopback.

## What this is not

- **Not a HIPAA certification.** HHS does not issue or recognize one. This produces evidence for a customer or an external assessor.
- **Not a NIST publication**, and not legal advice. Every HIPAA paragraph cited was checked to exist in eCFR on 2026-11-10; whether it is the right home for a control is the author's judgment. The SP 800-53 and CSF identifiers are unchecked.
- **Not a pentest.** Nine probes touch 11 of 43 controls. The other 32 need a person, and so does the final call on those 11. [`docs/COVERAGE.md`](docs/COVERAGE.md) is generated from the code and lists every control.
- **Not battle-tested.** Draft 0.1, one author, proven only against its own demo app. The agent probe plants one instruction per carrier in four dressings; current models shrug off naive injections, so a clean result says little, and the score reflects that. A model may also behave differently when it can tell it is being tested, which is why the markers look like ordinary words and the user agent is configurable.
- **Not tamper-proof logging.** The hash chain shows edits. It cannot show a cut tail unless you anchor the head hash somewhere the app cannot write.

## Things that do not work

Every known limit is a file in [`known-gaps/things-that-do-not-work/`](known-gaps/things-that-do-not-work/), with a severity and what would close it. Fixed ones move to [`things-that-now-work/`](known-gaps/things-that-now-work/). If you find a new one, that directory is where it goes.

## Built from this month's Hacker News

Features that came out of threads and submissions from October and November 2026. Only titles and comment threads were read for these, not every linked article.

| What HN said | What it became here |
| --- | --- |
| Guardrails belong outside the prompt; a prompt is not enforcement ([containment thread](https://news.ycombinator.com/item?id=50091788), [erased footage thread](https://news.ycombinator.com/item?id=50085323)) | The action gate is ordinary code the model cannot talk its way past; the demo shows five proposals decided without a model |
| You cannot do a root-cause analysis from an agent's own summary; you need a log of what it ran ([same thread](https://news.ycombinator.com/item?id=50085323)) | `pz probe claims` |
| A backup is unproven until a restore matches checksums ([same thread](https://news.ycombinator.com/item?id=50085323)) | `pz manifest` and `pz probe restore` |
| Injection is moving from short strings into tool results and long fetched content; hidden white-on-white text shows up in real documents ([HTTP headers study thread](https://news.ycombinator.com/item?id=50104310)) | The agent probe plants its instruction as plain text, an HTML comment, a hidden span and a fake tool result; `patient_zero.hidden` flags concealment |
| Scanners should be positional, not phrasal; classifiers are poor security boundaries ([1](https://news.ycombinator.com/item?id=50223560), [2](https://news.ycombinator.com/item?id=50056871)) | The tripwire looks at where text sits, never at wording, and the README calls it a tripwire, not a boundary |
| An auditor should try to disprove its own findings ([PuedoBot](https://news.ycombinator.com/item?id=50207787)) | Findings must reproduce; the leak test now needs a positive control, or it is void |
| Models can recognize a test and behave differently ([containment thread](https://news.ycombinator.com/item?id=50091788)) | Word-like markers, configurable user agent, and a stated limit |
| HIPAA evidence from Supabase row level security ([Show HN](https://news.ycombinator.com/item?id=50362545)) | `pz probe rls` |
| Keep secrets away from agents with reversible placeholders ([Cloakroom](https://news.ycombinator.com/item?id=50446007), [mcp-shield](https://news.ycombinator.com/item?id=50089763)) | `phi.Vault` |

## Lineage

patient-zero reuses ideas from the author's other open source security tools:

- **[assay](https://github.com/joeyvictorino/assay)** (multi-model security validation, Go): a claimed finding is a theory until a deterministic check reproduces it.
- **[tasia](https://github.com/joeyvictorino/tasia)** (static gate for self-hosted AI stacks, Go): the exposure rules in `pz probe stack`. tasia has the full rule set with `file:line` findings.
- **[orbit-ir](https://github.com/joeyvictorino/orbit-ir)** (agent incident reconstruction): an agent's transcript is a claim, not a record, which is the whole of `pz probe claims`.

The four method rules (predict before reading results, discard runs that never reached the target, bind results to an exact build, and check a replay against its recording) are adapted from the testing discipline described in the README of [bo2-mac](https://github.com/adrbn/bo2-mac), an unrelated recompilation project. No code was taken from it.

Embedded mode, the generated coverage table and the `known-gaps` directory follow the way [aws-emulator](https://github.com/aws/aws-emulator) runs in-process for tests, publishes fidelity scores and tracks what does not work as files in the repository.

## Help wanted

- Settled predictions from real assessments (`pz calibration --json`), or better arguments for the numbers in `belief.yaml`
- Review of the control wording and mappings by people who do HIPAA assessments
- More probes: agent permission escalation, memory deletion, and a live test of the action gate
- Ports of the reference safeguards to TypeScript and Go

## Develop

```
pip install -e ".[dev]"
pytest -q
```

## License

MIT
