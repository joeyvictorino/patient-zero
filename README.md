# patient-zero

Every AI app that touches PHI is patient zero. We run the outbreak investigation.

Open source checks for AI apps that handle protected health information (PHI). It tells you what to fix, shows a buyer exactly what was tested, and never calls anything "compliant".

```
pip install git+https://github.com/joeyvictorino/patient-zero

pz check .                       # read your project and list what to fix first
pz check examples/vibe-clinic    # or see it on a sample app with the usual mistakes
pz demo                          # watch it investigate a deliberately broken clinic app, patch it, and investigate again
```

Nothing here needs a network, an account or an API key. With [uv](https://docs.astral.sh/uv/) there is nothing to install: `uvx --from git+https://github.com/joeyvictorino/patient-zero pz check .`

![pz check on a sample app](docs/check.gif)

Underneath the check is an open safeguard profile shipped as code: 51 testable controls, drop-in reference safeguards, nine probes, a Bayesian readiness score that refuses to pretend a green tick is certainty, and signed evidence a buyer can verify in a browser. Questions people ask, including "isn't this just regexes?" and "why did you write your own Ed25519?", are answered in the [FAQ](docs/FAQ.md).

Three ways in, depending on who you are:

| You are | Start with |
| --- | --- |
| Building a health app yourself, often with an AI coding tool | [`pz check .`](#check-your-own-project-in-ten-seconds): no setup, plain-language fixes |
| A vendor who has to show a clinic what you tested | [Seal it, bundle it, badge it](#show-a-customer-what-you-tested) |
| A clinic or health system deciding on a vendor | [Verify what they sent you](#if-you-buy-ai-tools-rather-than-build-them), in a browser |
| A coalition, association or sandbox that convenes them | [Pilots, sandbox criteria, cohort view, briefs](#for-coalitions-sandboxes-and-classrooms) |

**How well does it work?** Honestly: it is new. On its first run against 13 real open source packages, most of what `pz check` reported was a false alarm; those are fixed and [written up](docs/FIELD-NOTES.md), and what it misses is still unmeasured. The integrations run in CI. No lawyer or clinician has reviewed the safeguards, and it has not yet been used on a real product in a real clinic. [Every known limit is a file in the repository.](known-gaps/things-that-do-not-work/)

**It is not** a HIPAA certification (none exists), a pentest or a code review. A clean result is weak evidence, and the tool says so every time.

<details>
<summary>Contents</summary>

- [If you buy AI tools rather than build them](#if-you-buy-ai-tools-rather-than-build-them)
- [Why this exists](#why-this-exists)
- [The idea: compliance is inference, not a checklist](#the-idea-compliance-is-inference-not-a-checklist)
- [The demo](#the-demo)
- [Method: four rules that keep the numbers honest](#method-four-rules-that-keep-the-numbers-honest)
- [Embedded mode: the probes inside your own tests](#embedded-mode-the-probes-inside-your-own-tests)
- [Check your own project in ten seconds](#check-your-own-project-in-ten-seconds)
- [Show a customer what you tested](#show-a-customer-what-you-tested)
- [For coalitions, sandboxes and classrooms](#for-coalitions-sandboxes-and-classrooms)
- [Signed evidence, disclosed one file at a time](#signed-evidence-disclosed-one-file-at-a-time)
- [A standard, not just a tool](#a-standard-not-just-a-tool)
- [The profile](#the-profile), [reference safeguards](#reference-safeguards), [assess your own product](#assess-your-own-product)
- [No telemetry](#no-telemetry), [what this is not](#what-this-is-not), [things that do not work](#things-that-do-not-work)
- [Questions people ask](docs/FAQ.md)

</details>

## If you buy AI tools rather than build them

You run a practice, a clinic or a health system, and a vendor wants your patient data. You do not need to read the rest of this page.

- [One page for healthcare leaders](docs/FOR-HEALTHCARE-LEADERS.md) ([en español](docs/PARA-LIDERES-DE-SALUD.md))
- [The questions to send a vendor](docs/VENDOR-QUESTIONNAIRE.md): all 51 safeguards in plain language, each with the question to ask and what a good answer comes with
- [What Nevada law adds](docs/NEVADA.md): AB 406 (2025) on AI in mental and behavioral health care, SB 370 on consumer health data, and consent before recording a call

A vendor who uses this tool can hand you a plain-language summary (`pz report --executive`) and one signed file of evidence. To check that file, open [`docs/verify/index.html`](docs/verify/index.html) in a browser and drop it in. Nothing is installed and nothing is uploaded. The page tells you whether the evidence is unchanged since it was signed, how old it is, who signed it, and how many safeguards a person has confirmed, in plain numbers. It never says "compliant", because no tool can.

![The verify page](docs/verify.png)

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

## The demo

`pz demo` starts a deliberately broken clinic app on your own machine, investigates it, patches it, and investigates again. The short version, in plain language (`pz demo --brief`):

![pz demo --brief](docs/demo.gif)

Look at the belief block. Every probe came back clean and belief barely moved. Three requests that found nothing are not proof of tenant isolation, and the score says so.

<details>
<summary>The full run of <code>pz demo</code></summary>

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

</details>

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

## Check your own project in ten seconds

```
pz check .
```

No target file, no running app, no account, no network. It reads the project folder and lists what to fix first:

```
NOT READY for real patient data. 8 thing(s) to fix, starting with these 3:

1. [CRITICAL] The AI model is called straight from the browser  (BASE-2)
     src/lib/ai.ts:2
     Why it matters: To call the model from the browser, the page must carry your model key, and patient
     text goes from the patient's device to the model company with nothing of yours in between.
     Fix: Move the model call to a server route. The browser talks to your server; your server talks to the model.

2. [HIGH] Patient data can reach OpenAI, and nothing on file says an agreement covers it  (TRUST-1)
     ...
What this could not check:
  - whether a signed-in user can open another patient's or another clinic's records
  ...
A clean check is not a pass, and this is not a HIPAA certification. None exists.
```

It looks for keys written into code or exposed to the browser, a committed `.env`, AI model and transcription companies with no agreement in your `register.yaml`, session recorders and analytics, patient data in log lines, certificate checks switched off, wildcard CORS, audio recording, tables without row level security, and an exposed Docker stack. It never prints a secret it finds. `--json` and `--sarif` are for tools; a line marked `pz:ignore <reason>` is skipped and reported as skipped.

It is a list of text patterns. It misses things and it flags things that are fine ([here is what it got wrong on 13 real packages](docs/FIELD-NOTES.md)), and it cannot see the flaw that matters most, which is who can read whose records. [Its limits are written down.](known-gaps/things-that-do-not-work/20261122-pz-check-is-a-list-of-patterns.md)

**Let your coding agent run it.** `pz mcp` is a read-only Model Context Protocol server; there is a Claude Code skill, a snippet for any agent's instructions file, a GitHub Action and a pre-commit hook. See [`integrations/`](integrations/README.md).

The two static probes behind it also run on their own. Point one at any directory with a Docker Compose file:

```
pz probe stack --path .
```

It flags inference APIs, model UIs, vector databases and data stores published on every interface, host networking, privileged containers, a mounted Docker socket and wildcard CORS.

On Postgres or Supabase? Point it at your migrations:

```
pz probe rls --path supabase/migrations
```

It reads the SQL in order and reports tables that end up without row level security, and policies that say `USING (true)`.

## Show a customer what you tested

```
pz seal --signer "Acme Health" --domain acme.example      # sign the assessment and every evidence file
pz identity --domain acme.example --key pz.key            # publish the output at acme.example/.well-known/patient-zero.json
pz cosign --key assessor.key --name "Example Assessors" --role independent-assessor --statement "Reviewed ..."
pz bundle                                                 # one file to send
pz badge --report-url https://acme.example/trust/         # a badge that links to it
```

The customer drops the bundle on the [verify page](docs/verify/index.html), or runs `pz verify patient-zero-bundle.json`:

```
VERIFIED: signature valid, Merkle root matches, every file unchanged
  Acme Scribe  level L1  profile 0.1
  sealed today by Acme Health, claiming acme.example
  2 of 43 safeguards confirmed by a person (1 by someone independent), 0 tested clean only, 0 failing, 41 not assessed; build 2026.11.1
  co-signed by Example Assessors LLC as independent-assessor: "Reviewed MFA evidence for build 2026.11.1."
  This shows the files are what was signed. It does not show the claims in them are true.
```

The counts are inside the signature, so they cannot be improved after signing. The badge reads `patient-zero | L1 · 2/43 confirmed · sealed 2026-11-22`. It is never green and never says "compliant", "certified" or "passed": it states what the seal states and links to the evidence. [`TRADEMARK.md`](TRADEMARK.md) has the rules for using the name.

## For coalitions, sandboxes and classrooms

Some things only a convening body can do: run a sandbox, brief legislators, train students, see across many vendors. [`docs/COALITIONS.md`](docs/COALITIONS.md) is the guide.

```
pz pilot init pilot --product "Product" --base-url https://staging.example.com   # permission form, test data, target file, run sheet
pz synth --patients 50 -o patients.json       # made-up records that cannot be mistaken for real ones, with a test marker per clinic
pz pilot run pilot                            # every configured probe, then pilot-report.md in plain language
pz sandbox pilot --path ./product             # which sandbox entry and exit criteria the pilot meets
pz vendors bundles/ --anonymize               # across many sealed reports: what fails most, what nobody has confirmed
pz brief legislator --overlay nevada          # ten questions with checkable answers, and what state rules say today
pz brief judge                                # an eight-question scorecard for health AI pitches
pz overlay nevada --review                    # a form for a lawyer in that state to mark up
```

- **A first pilot in about an hour.** `pz pilot init` writes the rules of engagement for the system's owner to sign, synthetic patients, a target file that starts unauthorized, and a run sheet. [`docs/pilot/HOSTING.md`](docs/pilot/HOSTING.md) and the `Dockerfile` are for whoever provides the machine.
- **Sandbox entry and exit that can be checked.** Eleven criteria in [`sandbox.yaml`](patient_zero/data/sandbox.yaml), each reported as met, not met or not checked, with the reason. The operator decides who is admitted.
- **One view across many vendors.** `pz vendors` verifies every bundle in a folder. A clinic sees which of its vendors' reports are current, co-signed and failing nothing. A coalition, with `--anonymize`, sees which safeguards fail most often across its members without ranking them.
- **Briefs for people who do not build software.** [Ten questions for legislators](docs/LEGISLATOR-BRIEF.md) and [a pitch scorecard](docs/PITCH-SCORECARD.md), generated from the profile. Neither takes a position on a bill, a vendor or a product.
- **A ten-minute talk.** [`docs/talk/slides.html`](docs/talk/slides.html) works offline, and [`docs/talk/TALK.md`](docs/talk/TALK.md) has the track, three live demos with fallbacks, and the questions a room asks.
- **A 45-minute lab** for students and new developers: [`docs/workshop/LAB.md`](docs/workshop/LAB.md), with instructor notes and versions for buyers and policy audiences.

## Signed evidence, disclosed one file at a time

```
pz keygen                          # Ed25519 key, written 0600, never overwritten
pz seal --signer "Your Name"       # Merkle root over the assessment and every evidence file, signed
pz verify                          # any edited, missing or dropped file fails

pz prove evidence/pentest.json     # a small proof for ONE file
pz verify-proof proof.json evidence/pentest.json --public-key <yours>
```

A customer asks for your pentest evidence. You send that one file and `proof.json`. They can check it belongs to your signed assessment without seeing any other file, or even the other file names. Each new seal records the root of the one before it, so reassessments form a chain.

The Merkle tree and the Ed25519 implementation are standard library only, checked against the RFC 8032 test vectors. Signing uses the audited `cryptography` package instead whenever it is installed (`pip install "patient-zero[sign]"`); both give the same bytes. A key you generated proves the same key signed each seal, not who holds it. `--domain` and `pz identity` tie it to a website you control, and `pz cosign` lets an assessor, a customer or counsel add their own signature. That is as strong as control of the domain, and [no stronger](known-gaps/things-that-do-not-work/20261111-self-generated-keys-prove-continuity-not-identity.md).

## A standard, not just a tool

For patient-zero to be something a whole field can rely on, it cannot belong to one codebase.

- [`spec/SPEC.md`](spec/SPEC.md) is the standard: the profile, the rules for statuses, the belief arithmetic and the seal format, separate from this implementation.
- [`patient_zero/data/vectors/`](patient_zero/data/vectors/) holds test vectors as plain JSON. An implementation in any language conforms when it reproduces them. `pz conformance` runs them here. The browser verifier is a second implementation and passes the same ones (`node tools/run_vectors.js`).
- [`GOVERNANCE.md`](GOVERNANCE.md) says how the standard changes and who decides. [`MAINTAINERS.md`](MAINTAINERS.md) lists the reviewer seats, all of them open: a health privacy lawyer, a clinician, a Nevada lawyer, an assessor, a statistician.
- [`calibration-data/`](calibration-data/README.md) is where settled predictions are pooled, without names, so the guesses in `belief.yaml` can become measurements.
- [`ROADMAP.md`](ROADMAP.md) says what is built, what is not, and what needs people and not code.

## The profile

The full text is in [`docs/PROFILE.md`](docs/PROFILE.md), generated from the data file.

[`patient_zero/data/controls.yaml`](patient_zero/data/controls.yaml) holds nine families. Levels are cumulative and declared per workspace.

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
| CONSENT | People know when AI is involved, can decline it where they have that right, and are not treated worse by it |

| Level | Name | Meaning | Controls |
| --- | --- | --- | --- |
| L0 | Unprivileged | No PHI; the product keeps it out | 5 |
| L1 | Helper | Stores and processes PHI on BAA-covered models | 43 |
| L2 | Agentic | Agents act on PHI; external assistants connect | 51 |

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
pz calibration --export pooled.json              # your settled predictions without names, to contribute
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

- Probes refuse to run unless the target file sets `authorized: true`, `synthetic_data_only: true`, an `authorization_ref`, and `authorized_hosts` that include the `base_url` host. Test systems you own or have written permission to test, with synthetic data, never real PHI. Copy the hosts from the rules of engagement, and say there if you set `user_agent` so the test looks like ordinary traffic.
- `pz calibration` scores each named forecaster. The scores grade guesses about a system, not anyone's work; do not use them to rate staff, and use a role or alias with `--by` if that is a risk.
- A probe can fail a control. It cannot pass one. A clean run sets `partial`; a person records `pass` with evidence.
- A finding is a theory until it reproduces. Network probes ask a second time before reporting, and a one-off goes to the notes, not the findings.
- Every probe run writes a dated, hashed JSON file under `evidence/`.
- Nothing the tooling prints, signs or draws says "compliant", "certified" or "passed". A seal carries counts, a badge shows them, and tests fail if those words appear.

Want to try the probes by hand first? `pz demo --serve` runs the broken app on port 8099, and `pz demo --serve --patched` runs the fixed one.

## No telemetry

patient-zero collects nothing and phones nowhere. It opens a network connection in two cases only, both of which you ask for: probes talk to the `base_url` you put in the target file, and `pz verify --check-domain` fetches a signer's published key from the domain named in the seal. Everything else, including `pz check`, `pz verify`, `pz mcp` and the verify page, works offline. The demo stays on 127.0.0.1, and tests in the suite fail if the demo reaches anything but loopback or if `pz verify` fetches anything without the flag.

## What this is not

- **Not a HIPAA certification.** HHS does not issue or recognize one. This produces evidence for a customer or an external assessor.
- **Not a NIST publication**, and not legal advice. Every HIPAA paragraph cited was checked to exist in eCFR on 2026-11-10; whether it is the right home for a control is the author's judgment. The SP 800-53 and CSF identifiers are unchecked.
- **Not a code review.** `pz check` matches text patterns. It finds common mistakes quickly and misses anything it has no pattern for.
- **Not a pentest.** Nine probes touch 11 of 51 controls. The other 40 need a person, and so does the final call on those 11. [`docs/COVERAGE.md`](docs/COVERAGE.md) is generated from the code and lists every control.
- **Not battle-tested.** Draft 0.1, one author, proven only against its own demo app. The agent probe plants one instruction per carrier in four dressings; current models shrug off naive injections, so a clean result says little, and the score reflects that. A model may also behave differently when it can tell it is being tested, which is why the markers look like ordinary words and the user agent is configurable.
- **Not a consent or ethics review.** The CONSENT family asks whether patients are told about AI, can decline it, are recorded only with agreement, and are not treated worse by it. Its citations were checked against eCFR and the Nevada statutes on 2026-11-21, including the HIPAA Privacy Rule changes published 2026-11-19, but no lawyer has reviewed them, and none of its controls has a probe. An IRB, an ethics committee or counsel still makes those calls.
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

- One vendor and one clinic willing to run it together and publish what they learn
- People to fill the reviewer seats in [`MAINTAINERS.md`](MAINTAINERS.md)
- Rules for `pz check` from people who review these apps, and a corpus of sample apps to measure it against
- Runs of the integrations in their real hosts (Claude Code, Cursor, GitHub Actions, pre-commit), with what broke
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
