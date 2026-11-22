# Questions people ask

Short answers, with the weak points stated. Every known limit also has a file in [`known-gaps/things-that-do-not-work/`](../known-gaps/things-that-do-not-work/).

## Isn't `pz check` just a list of regexes?

Yes. It reads files line by line against the patterns in [`check_rules.yaml`](../patient_zero/data/check_rules.yaml). It does not parse code or follow data, so it misses anything written in a way no pattern expects, and it flags some things that are fine. Its hit and miss rates have not been measured on real projects.

It exists because the people it is for will not write a target file or stand up a test tenant, and the mistakes it looks for are the ones that make everything else moot: a model key shipped to the browser, patient data sent to a company with no agreement, a table with no row level security. After every run it prints what it could not check, and it says a clean result is not a pass.

## Why not Semgrep, gitleaks or TruffleHog?

Use them. They are better at what they do: gitleaks and TruffleHog know far more secret formats and scan git history, and Semgrep understands code structure. `pz check` overlaps with them on secrets and does less.

What it adds is the health-specific part and the framing: which model and transcription companies receive patient data and whether your register says an agreement covers them, trackers on pages patients use, patient fields in log lines, recording without consent, and findings written for someone who is not a security engineer, each tied to a control in the profile. It can emit SARIF, so it sits beside those tools in the same code scanning tab.

## Does a clean run mean my app is HIPAA compliant?

No. Nothing this project prints, signs or draws says "compliant", "certified" or "passed", and tests fail if those words appear in the badge or the rules. HHS does not issue or recognize a HIPAA certification. A clean check means a short list of common mistakes was not found. A clean probe moves a control to `partial`, never `pass`; a person records a pass, with evidence.

## The belief numbers are made up. Why should anyone trust the score?

They are made up, and [`belief.yaml`](../patient_zero/data/belief.yaml) says so on its first line. Nobody has published how often a self-attested access control turns out to be broken.

The claim is narrower than "the score is right". It is that a checklist already implies numbers, namely that every tick is certain, and those are worse. Writing the guesses down makes them arguable and replaceable (`--model`). `pz predict` and `pz calibration` score the model's forecasts against what probes then find, on your own product, and [`calibration-data/`](../calibration-data/README.md) is where settled predictions can be pooled. Until there is data, read the score as "which controls rest on thin evidence", not as a probability to quote.

The model also treats controls as independent, which they are not. `pz fragile` shows how much rests on a single source.

## Why did you write your own Ed25519 and Merkle tree?

So that verifying a seal needs nothing but Python's standard library, and so a buyer's machine installs as little as possible. The implementation is checked against the RFC 8032 test vectors, rejects non-canonical and small-order inputs, and is cross-checked by a second implementation in JavaScript that passes the same vectors.

Verification handles only public data, so timing does not matter there. Signing is different: pure Python big integers are not constant-time. When the `cryptography` package is installed (`pip install "patient-zero[sign]"`), signing goes through OpenSSL instead, and a test holds both paths to identical output. Without it, `pz keygen` tells you the fallback is in use. Neither implementation has had an outside audit.

## Why BLAKE2b and a custom seal format, and not Sigstore or in-toto?

The honest answer is that a self-contained format was faster to build and has no service to depend on. It gives tamper evidence, single-file disclosure and co-signatures, offline. It does not give what a transparency log gives: a public record that a seal existed at a time, and key history. Identity rests on a file at a domain and is [no stronger than that](../known-gaps/things-that-do-not-work/20261111-self-generated-keys-prove-continuity-not-identity.md). Signing with an existing identity and a public log are on the [roadmap](../ROADMAP.md). If you know that area well, this is a good place to push.

## What stops a vendor from sealing a report full of false claims?

Nothing. A seal shows the files are what was signed, by that key, unchanged. It does not show they are true, and the verify page says so. What the design does is make the claims specific and countable: how many safeguards a person confirmed, how many of those by someone independent, how many only "tested clean by software", how many failing, on which build, how long ago. Those counts are inside the signature. A vendor who lies has signed a specific false statement, which is a different position from a logo on a website.

## Can I use it to scan someone else's product?

`pz check` reads a folder on your disk, so point it at code you have a right to read. The network probes refuse to run unless the target file states that you are authorized, cites the authorization, lists the hosts it covers and says the data is synthetic. Those are your statements; the tool cannot verify them. Test what you own or have written permission to test.

## Does it send my code or findings anywhere?

No. `pz check`, `pz verify`, `pz mcp` and the verify page work offline. Two commands open a connection, both because you asked: probes talk to the `base_url` in your target file, and `pz verify --check-domain` fetches a signer's published key. Tests fail if the demo reaches anything but loopback or if `pz verify` fetches without the flag.

## My app is not covered by HIPAA. Is this useful?

Partly. HIPAA covers health plans, most providers and the companies that handle patient data for them. A wellness or consumer health app is often outside it, but may fall under the FTC's Health Breach Notification Rule and state laws such as Washington's My Health My Data Act or Nevada's SB 370. The mistakes `pz check` looks for are worth fixing either way. The profile's citations are to HIPAA, and whether a given law applies to you is a question for a lawyer.

## Was this written with AI?

Yes, heavily, with an AI coding assistant, and reviewed by one person. That is a reason to distrust it in the usual ways: read the code, run the tests, check the citations. The legal citations were checked against eCFR and the Nevada statutes on the dates the files state, and no lawyer has reviewed them. The repository records what has not been verified instead of asking you to assume.

## Who is behind it, and who decides what the standard says?

One maintainer, Joey Victorino, a security practitioner. [`GOVERNANCE.md`](../GOVERNANCE.md) describes how the standard changes, and [`MAINTAINERS.md`](../MAINTAINERS.md) lists reviewer seats for a health privacy lawyer, a clinician, an assessor and others. All of them are open. Until they are filled, changes to the standard are reviewed by the person who wrote them, which is the project's largest weakness.

## How is this different from Vanta, Drata or a HITRUST assessment?

Those are commercial compliance platforms and a certification framework, with auditors, breadth and standing this project does not have. patient-zero is narrower and free: controls specific to AI features (agents, memory, model providers, prompt injection), tests that produce evidence, and a way to show a buyer exactly what was and was not tested. It could feed evidence into one of those programs. It does not replace them, and it does not replace a penetration test.
