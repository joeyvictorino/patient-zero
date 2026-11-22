# Changelog

Changes to the standard (profile, spec, vectors) are marked **standard**.

## Unreleased

### Added
- `pz pilot init` and `pz pilot run`: a pilot folder with rules of engagement to sign, synthetic patients, a target file that starts unauthorized and a run sheet; then every configured probe and a plain-language report.
- `pz synth`: seeded, obviously fake patient records with a test marker per clinic.
- `pz sandbox`: eleven entry and exit criteria for a healthcare AI sandbox, checked against a pilot folder. Criteria are data in `patient_zero/data/sandbox.yaml`.
- `pz vendors`: verify every sealed bundle in a folder; a clinic's view of its vendors, or with `--anonymize` a cohort view that ranks nobody.
- `pz brief legislator` and `pz brief judge`, and `pz overlay <state> --review`: generated one-page briefs and a review form for a lawyer.
- `docs/COALITIONS.md`, `docs/pilot/HOSTING.md`, `docs/workshop/`, a `Dockerfile`.
- `pz check`: zero-setup scan of a project folder with plain-language fixes, `--json`, `--sarif`, `pz:ignore` suppression and a `patient_zero.checks` plugin point. Rules are data in `patient_zero/data/check_rules.yaml`.
- `pz mcp`: a read-only Model Context Protocol server. A Claude Code skill, an agent instructions snippet, a GitHub Action and a pre-commit hook under `integrations/` and the repository root.
- `pz bundle` and `docs/verify/`: a one-file evidence bundle and a browser page that verifies it offline.
- `pz badge`: a badge that states what a seal says and links to the evidence. `TRADEMARK.md` sets the rules.
- `pz seal --domain`, `pz identity`, `pz verify --check-domain`: tie a signing key to a domain. `--check-domain` is the only command that opens a connection the user did not put in a target file.
- `pz cosign`: a second party signs an existing seal.
- **standard** A signed `summary` and optional `signer.domain` in the seal head; co-signature, bundle and identity schemas. Seals made before this still verify.
- **standard** `spec/SPEC.md` and conformance vectors in `patient_zero/data/vectors/`; `pz conformance`; `tools/run_vectors.js` for the JavaScript verifier.
- `pz calibration --export` and `--pool`, and `calibration-data/`.
- `GOVERNANCE.md`, `MAINTAINERS.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `TRADEMARK.md`, `ROADMAP.md`.
- **standard** CONSENT family (eight controls) and Nevada item NV-6. Profile is 51 controls.
- `examples/vibe-clinic`, a sample app that is wrong on purpose, and `docs/check.gif`.
- Signing uses the `cryptography` package when installed (`patient-zero[sign]`); the pure Python signer is the fallback.
- `pz check` skips files that contain none of a rule's `hints`, which makes it about seven times faster, and hands the stack and row level security probes the same file list it uses, so excluded and test files stay out of them.
- "Try a sample" on the verify page, a landing page at `docs/index.html`, `docs/FAQ.md`, a PyPI release workflow, and a CI step that builds the package and runs a clean install.
- Target files must list `authorized_hosts`. Existing target files need the new field.

## 0.1.0

First draft: 43 controls, reference safeguards, nine probes, belief model, signed seals.
