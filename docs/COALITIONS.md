# For coalitions, associations and sandboxes

patient-zero was written for one vendor and one buyer. A body that convenes many of them (a provider association, a regional AI coalition, a state sandbox) can use the same pieces to do things no single member can.

## What a convening body can do with it

**Give members a common question list.** [`VENDOR-QUESTIONNAIRE.md`](VENDOR-QUESTIONNAIRE.md) is the same for every vendor. A clinic with no technical staff can send it, and a vendor answers it once for all of them.

**Run a sandbox whose entry and exit mean something.** `pz sandbox <pilot folder>` checks a pilot against written criteria: permission in writing, synthetic data only, every data recipient named, nothing critical in the code, and to leave, a clean cross-customer test on the current build, signed agreements, sealed evidence and an independent co-signature. The criteria are a short data file, [`sandbox.yaml`](../patient_zero/data/sandbox.yaml); change them to yours. The tool reports which are met. Your operator decides who is admitted.

**Start pilots without weeks of paperwork.** `pz pilot init` writes the permission form, the test data, the target file and a one-hour run sheet. [`pilot/HOSTING.md`](pilot/HOSTING.md) is for whoever provides the machine.

**See the whole cohort without ranking anyone.** Put members' sealed bundles in a folder:

```
pz vendors bundles/ --anonymize
```

It verifies each one and reports, across all of them, which safeguards fail most often and which nobody has confirmed. That is where shared training, a shared service or a rule would help most, and it is a number you can show a funder or a legislator. Without `--anonymize`, the same command is a clinic's own view of its vendors: which reports are current, verified, co-signed and failing nothing.

**Brief people who do not build software.** [`LEGISLATOR-BRIEF.md`](LEGISLATOR-BRIEF.md) is ten questions with checkable answers and, where a state overlay exists, what that state's rules say today. [`PITCH-SCORECARD.md`](PITCH-SCORECARD.md) is eight questions for judging a health AI pitch. Both are generated from the profile and take no position on any bill, vendor or product.

**Present it.** [`talk/slides.html`](talk/slides.html) is a twelve-slide deck that works offline, and [`talk/TALK.md`](talk/TALK.md) is a ten-minute track with three live demos and the questions a room asks.

**Teach.** [`workshop/LAB.md`](workshop/LAB.md) is a 45-minute lab for students and new developers, with instructor notes and variations for buyers and for policy audiences.

**Get the law checked locally.** `pz overlay nevada --review` produces [a form](NEVADA-REVIEW.md) a lawyer in the state can mark up in half an hour. A coalition is the natural place to find that lawyer, and to write the overlay for the next state.

## Staying neutral

A convening body has to be trusted by members who compete. Four properties of the tool help:

- **It names no preferred vendor.** Every AI model company is treated the same: it is acceptable when the register shows a signed agreement, a bar on training and a retention period, and not before.
- **It runs offline and collects nothing.** No member's code, findings or evidence goes to the project or to another member.
- **It gives counts, not verdicts.** Nothing it prints, signs or draws says compliant, certified or passed, so the body is never vouching for a product.
- **It is open.** MIT licensed, with [governance](../GOVERNANCE.md) that says how the standard changes. A coalition can hold a reviewer seat ([`MAINTAINERS.md`](../MAINTAINERS.md)) without owning the project, and the project's own rules say the name should move to a neutral home once vendors rely on it.

## Measuring whether it helped

Decide the numbers before the first pilot, and report them whatever they turn out to be:

- pilots started, and pilots that reached the exit criteria
- across the cohort, how many safeguards a person has confirmed, at the start and after six months
- findings fixed, and the median days from finding to fix
- settled forecasts contributed to [`calibration-data/`](../calibration-data/README.md)

## What it will not do for you

It is not a certification scheme, and a sandbox that treats it as one will be embarrassed by the first breach. It has one maintainer, no outside audit, and has not yet been run on a real product; [every known limit is written down](../known-gaps/things-that-do-not-work/). The honest pitch to members is that it makes claims specific and checkable, and that is all.
