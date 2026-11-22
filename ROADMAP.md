# Roadmap

The aim: patient-zero becomes the default, shared way to check an AI product before it touches patient data, the way people reach for Linux without asking who owns it. That takes four things a single repository cannot have on day one: adoption, trust, other implementations, and people.

## Where it stands (2026-11)

Built and tested here:

- **A zero-setup check** (`pz check .`) for people building their own apps, with plain-language fixes, JSON and SARIF output, and a plugin point.
- **Hooks for where code gets written**: an MCP server, a Claude Code skill, an instructions snippet for other agents, a GitHub Action, a pre-commit hook.
- **A report a buyer can check without installing anything**: one-file bundles and a browser verifier.
- **A badge that cannot say "compliant"**, and rules for the name.
- **Identity for signers**: a key published at a domain, and co-signatures by a second party.
- **A specification separate from the code**, with test vectors, and two implementations of the verifier that pass them.
- **Written governance**, with open reviewer seats.
- **A way to pool calibration data** without names.

Not done, and not possible from inside the repository:

- Nobody outside the author has used it. Every limit is in `known-gaps/things-that-do-not-work/`.

## Next: things that need people, not code

1. **One vendor and one clinic run it together** and publish what they learn. This is the single most valuable next step.
2. **Fill the reviewer seats** in `MAINTAINERS.md`, starting with a health privacy lawyer for CONSENT and a Nevada lawyer for the overlay.
3. **Host the verifier.** Turn on GitHub Pages for `docs/` so buyers have a link, not a file.
4. **Publish a release** to PyPI, tag it, and pin the Action and pre-commit examples to the tag.
5. **A second maintainer** from a different organization.

## Next: things that need code

| What | Why | Size |
| --- | --- | --- |
| Connect the MCP server in real agent hosts, evaluate the skill, run SARIF upload once | CI covers the Action, pre-commit and the MCP client library, not these | small |
| A corpus of sample apps with known flaws, and measured hit and miss rates for `pz check` | Its accuracy is unknown | medium |
| Probes for the 40 controls that have none, CONSENT first | Most of the profile rests on a person's word | large, one at a time |
| A deeper agent probe: multi-turn, tool-result and long-document injection | The current one is shallow | medium |
| A TypeScript package for the reference safeguards and the check | Most AI-built health apps are TypeScript | large |
| Overlays for more states (California, Texas, Illinois, Utah first) | State AI and health privacy law is where the rules are moving | medium each, needs a local reviewer |
| A public, append-only log of seals | Domain identity is weak on its own | large |
| `pz check --fix` for the mechanical fixes | Faster path from finding to fixed | medium |
| Signing with an existing identity (Sigstore, SSH keys, hardware keys) | Pure-Python signing is not constant-time | medium |

## Later

- A directory of independent assessors who co-sign, with a stated basis for listing each.
- A neutral home for the standard and the name, once vendors rely on the badge.
- Buyer-side tooling: a clinic keeps the seals of all its vendors and is told when one goes stale.
- Crosswalks other frameworks can cite (HITRUST, SOC 2, NIST AI RMF), written by people who assess against them.

## What will not change

A clean test is never a pass. A run that tested nothing is void. The tool never calls anything compliant. Every limit is written down in the repository.
