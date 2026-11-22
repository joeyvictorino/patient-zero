---
name: patient-zero
description: Check an app that handles patient or health data before it touches real data. Use when the user is building or changing a healthcare, clinic, therapy, medical-records or patient-facing app, mentions HIPAA or PHI, or adds an AI model call, a database table, analytics, logging, audio recording or auth to such an app.
---

# patient-zero

patient-zero is an open source checker for AI apps that handle patient data. Use it while you build, not after.

## When to run it

Run `pz check .` in the project folder:

- before you tell the user a health app is ready for anything
- after adding or changing: a call to an AI model, a database table or policy, analytics or error reporting, logging, audio recording or transcription, login or sessions, a Docker Compose file
- whenever the user mentions HIPAA, PHI, patients, a clinic or a BAA

If `pz` is not installed: `pip install git+https://github.com/joeyvictorino/patient-zero`.

For machine-readable output use `pz check . --json`. If the patient-zero MCP server is connected, the same check is the `pz_check` tool.

## What to do with the result

1. Fix findings worst first. Each one comes with why it matters and a fix. Make the fix in the code; do not just describe it.
2. Some fixes are not code. A finding that says a model company has no agreement on file needs the user to sign a Business Associate Agreement (BAA) with that company and record it in `register.yaml`. Tell the user plainly; do not create a register entry that claims an agreement exists.
3. If a line is a false positive, say why to the user, then add a `pz:ignore <reason>` comment on that line. Never suppress a finding to make the check pass.
4. Run the check again until nothing at `high` or `critical` remains.
5. Read "What this could not check" out to the user. Those are the things that matter most and no scan can see them.

## Rules that are not negotiable

- Never tell the user the app is "HIPAA compliant", "certified" or "passes patient-zero". A clean check is not a pass. No HIPAA certification exists. Say what was checked and what was not.
- Never put real patient data in prompts, tests, fixtures, logs or examples. Use made-up data. `pz scan <file>` flags likely patient data in text.
- Never run the network probes (`pz probe isolation`, `pz probe agent`) against a system unless the user confirms they own it or hold written permission, and it holds synthetic data only. The target file requires `authorized`, `authorization_ref`, `authorized_hosts` and `synthetic_data_only`; the user fills those in, not you.
- Never record a control as `pass` (`pz set ... pass`) or sign a seal (`pz seal`, `pz cosign`) on the user's behalf. Those are a person's judgment and signature.

## Going further than the check

- `pz controls --level L1` lists the safeguards; `pz questionnaire --level L1` is what a clinic will ask.
- `pz init --product "Name" --level L1` starts an assessment; `pz next` says which test removes the most uncertainty.
- `examples/adopt.py` in the patient-zero repository shows drop-in safeguards: a PHI gate that is off by default, a tamper-evident audit log, an egress allowlist, an identifier vault for model calls, and an agent action gate.
- When the user wants to show a customer: `pz seal`, `pz bundle`, `pz badge`. The customer verifies the bundle in a browser with no install.
