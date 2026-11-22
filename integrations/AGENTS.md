<!-- Paste this section into your project's AGENTS.md, CLAUDE.md, .cursorrules or equivalent. -->

## Patient data rules for this project

This project handles patient data. patient-zero (`pz`) is installed to check it.

- After changing anything that touches a model call, the database schema, analytics, logging, audio recording, login or deployment files, run `pz check .` and fix what it reports, worst first.
- Do not suppress a finding to make the check pass. A false positive gets a `pz:ignore <reason>` comment and a note to the maintainer.
- Use made-up data in prompts, tests, fixtures and logs. Never real patient data.
- A model or tracking company needs a signed Business Associate Agreement before it receives patient data. That is a contract a person signs; do not add a `register.yaml` entry that claims one exists.
- Never describe this project as "HIPAA compliant" or "certified". A clean check is not a pass.
- Do not run `pz probe isolation` or `pz probe agent` against any system without a person confirming written permission and synthetic data.
- Do not run `pz set ... pass`, `pz seal` or `pz cosign`. Those record a person's judgment.
