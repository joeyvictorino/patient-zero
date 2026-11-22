# Show HN: draft post and launch checklist

A draft for the maintainer to edit and post. Nothing here has been posted. Rewrite it in your own voice before you use it; Hacker News readers can tell.

## Before you post

In order. The first two are blocking: without them the install command in the post does not give people what the post describes.

- [ ] **Merge this branch to `main`.** `pip install git+https://github.com/joeyvictorino/patient-zero` installs the default branch.
- [ ] **Check CI is green on `main`.** The workflow has new steps (conformance, the Node vector run, a package build and clean install, `pz check`) that have not yet run on GitHub.
- [ ] **Turn on GitHub Pages**: repository Settings, Pages, deploy from branch `main`, folder `/docs`. That serves the landing page and the verifier at `https://joeyvictorino.github.io/patient-zero/`. Open `/verify/` and click "Try a sample".
- [ ] **Try the install on a machine that has never seen the project**: the three commands at the top of the README, then `pz check` on a real project of yours.
- [ ] Optional: publish to PyPI so the command is `pip install patient-zero`. The name was unclaimed on 2026-11-22. `.github/workflows/release.yml` publishes on a `v*` tag once you add the repository as a trusted publisher on pypi.org. If you do, update the install lines in the README, `docs/index.html` and below.
- [ ] Optional: connect `pz mcp` in the agent host you use (Claude Code, Cursor) once. CI already runs the GitHub Action, the pre-commit hook and the MCP server against the official client library, but no person has yet used the server from inside an agent.
- [ ] Read [`docs/FAQ.md`](../FAQ.md). Those are the objections to expect. If you disagree with an answer, change it before posting, not in the thread.

## Title

Hacker News titles are capped at 80 characters, and "Show HN" is for something people can run. Plain beats clever. Options:

1. `Show HN: Patient-zero – open-source checks for AI apps that touch patient data`
2. `Show HN: Patient-zero – find the HIPAA mistakes in an AI-built health app`
3. `Show HN: A HIPAA checker for AI apps that refuses to say "compliant"`

The first is the safest. The third is the most likely to be read, and it is accurate.

**URL:** the GitHub repository. Put the Pages link in the comment.

## First comment

Post this as a comment on your own submission, right away.

> Hi HN. I work in security, and I keep meeting small teams, and lately individuals with an AI coding tool, who have built something useful for a clinic and cannot get it through the door. The clinic asks "is it HIPAA compliant?", nobody can answer honestly, and either the tool dies or it goes in on a handshake.
>
> patient-zero is my attempt at the part of that problem that can be open source. Three pieces:
>
> - `pz check .` reads a project and lists what to fix first, in plain language: a model key shipped to the browser, a model company with no BAA on file, session recorders on patient pages, patient fields in logs, tables with no row level security. No setup, no network. It runs as an MCP server and a Claude Code skill so the agent writing the app can run it.
> - A profile of 51 controls for AI features that handle PHI, with probes for cross-tenant access and prompt injection, and a score that treats a clean test as weak evidence instead of a green tick.
> - Signed evidence a buyer can verify in a browser with nothing installed: [Pages link]/verify/ has a sample you can click.
>
> The thing I care most about: it never says "compliant". No HIPAA certification exists, a clean scan is not a pass, and the badge it generates only states counts (how many safeguards a person confirmed, how many are failing) and has to link to the evidence.
>
> What is weak, so you do not have to find it:
>
> - `pz check` is a list of regexes. Its false positive and miss rates are unmeasured.
> - The numbers behind the score are stated guesses. There is a mechanism to replace them with data and no data yet.
> - I wrote the Ed25519 and Merkle code so verification needs only the standard library. Signing uses `cryptography` when installed. No outside audit.
> - No lawyer or clinician has reviewed the controls. One maintainer. It has only been run against its own demo and sample apps.
> - A lot of it was written with an AI assistant.
>
> All of that, and more, is in `known-gaps/things-that-do-not-work/`.
>
> I would most like to hear from people who do HIPAA assessments (are the controls the right ones?), anyone who reviews AI-built apps (what do you actually find?), and anyone who thinks the seal format should have been Sigstore.

Replace `[Pages link]` once Pages is on. Cut anything that is not true for you: the first paragraph is written from the README's description of you and should be your own account.

## While the thread is live

- Be there for the first few hours and answer plainly. "You're right, that's a gap, it's in known-gaps" is a good answer and is usually true.
- Do not ask anyone to upvote or comment. It is against the site's rules and it gets posts flagged.
- When someone finds a real bug or a wrong citation, thank them, open an issue, and link it in the thread.
- Expect "this is security theater" and "regex scanner". The FAQ has the honest version of both answers: it is a regex scanner, and here is what it is for.
- If someone runs it on a real project and posts the output, that is the most valuable thing that can happen. Ask what it missed.

## After

- Add what the thread taught you to `known-gaps/` and the FAQ.
- Anyone who offers to review a control family goes in `MAINTAINERS.md`.
