"""`pz pilot`: everything one real pilot needs, in one folder.

A first pilot usually stalls on paperwork and test data, not on testing: who
said this was allowed, against which hosts, with what records. `init` writes
those pieces so the hour with the product's owner is spent testing:

  rules-of-engagement.md   the permission, for the system's owner to sign
  target.yaml              where the probes point; `authorized` starts false
  synthetic-patients.*     made-up records with a canary per tenant
  register.yaml            who may receive patient data
  assessment.yaml          the assessment the probes will write into
  PILOT.md                 the run sheet: what to do, in order, in about an hour

`run` executes every probe the target file configures, folds the results into
the assessment and writes pilot-report.md. It refuses until a person has set
`authorized: true`, which the run sheet says to do only after signing.
"""
from __future__ import annotations

import os
from datetime import date
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import yaml

from . import assess, bayes, buyer, check, synth
from . import profile as profile_mod
from .probes import ProbeRefused, load_target, write_evidence
from .probes import agent as agent_probe
from .probes import isolation as isolation_probe
from .probes import offline as offline_probe
from .probes import tls as tls_probe

RULES = """# Rules of engagement: {product} pilot

This is the written permission the probes ask for. Nothing is tested until the system's owner has signed it.

## Who and what

- **System under test:** {product}
- **Owner giving permission:** ______________________ (name, role, organization)
- **Tester:** ______________________
- **Hosts in scope:** {hosts}
- **Hosts out of scope:** everything else, including production
- **Window:** from ____________ to ____________

## Conditions

1. **Synthetic data only.** The test tenants hold the records in `synthetic-patients.json` and nothing else.
   No real patient's data is in scope, on either side.
2. **Tests that will run:** requests for one test tenant's records made as the other test tenant and with no login;
   questions to the AI assistant meant to make it reveal the other tenant's test marker; an instruction planted in a
   test note to see whether the assistant obeys it; a check of the encryption on the connection.
3. **Tests that will not run:** anything that deletes data, floods the service, guesses passwords, or touches a host not listed above.
4. **Test traffic is not disguised** unless noted here: ______________________
5. **Stop conditions:** testing stops at once if real patient data is seen, if the service degrades, or if the owner asks.
6. **Findings** go to the owner first, in writing, within two working days. The tester does not publish or share them without the owner's agreement.
7. **Evidence** is kept in this folder. The owner receives a copy.

## Signatures

Owner: ______________________  Date: ____________

Tester: ______________________  Date: ____________
"""

RUN_SHEET = """# Pilot run sheet: {product}

About an hour with the product's owner. Work down the list.

## Before the hour

- [ ] Owner and tester sign `rules-of-engagement.md`.
- [ ] Owner creates two test tenants (clinics) and one login for each. No real data in either.
- [ ] Load `synthetic-patients.json` (or `.csv`): tenant `a` records into the first, tenant `b` into the second.
      Each tenant's test marker is in one note.
- [ ] Put the two logins' tokens in the environment: `export PZ_TOKEN_A=...` and `export PZ_TOKEN_B=...`
- [ ] In `target.yaml`: fill in the real paths under `isolation.resources` and, if the product has an AI assistant,
      the `agent` section. Then set `authorized: true` and write the signing date in `authorization_ref`.

## During the hour

- [ ] Each person writes down a forecast before anything runs: `pz predict isolation 0.8 --by owner` and `pz predict isolation 0.6 --by tester`
- [ ] `pz pilot run .`{check_step}
- [ ] Read `pilot-report.md` together. For each failing item: is it real, and who fixes it by when?
- [ ] `pz calibration` shows whose forecast was closer.

## After

- [ ] Owner fixes, tester reruns `pz pilot run .`
- [ ] A person records what they have confirmed: `pz set BASE-1 pass --evidence evidence/mfa-policy.png`
- [ ] `pz keygen`, `pz seal --signer "..."`, `pz bundle`: one file the owner can show a customer.
- [ ] `pz calibration --export pooled.json`: forecasts without names, to contribute if the owner agrees.

A clean run is not a pass. It moves controls to "tested clean", and a person confirms them.
"""


def init(folder: str, product: str, level: str = "L1", base_url: str = "https://staging.example.com", patients: int = 20,
         seed: Optional[int] = None) -> List[str]:
    """Write the pilot folder. Returns the files written. Never overwrites."""
    os.makedirs(folder, exist_ok=True)
    host = urlparse(base_url).hostname
    if not host:
        raise ValueError("base_url must look like https://staging.example.com")
    seed = seed if seed is not None else date.today().toordinal() % 10000
    data = synth.generate(patients, seed, tenants=2)
    canary_a = data["tenants"][0]["canary"]
    target: Dict[str, Any] = {
        "authorized": False,
        "authorization_ref": "rules-of-engagement.md, signed YYYY-MM-DD by <owner>",
        "synthetic_data_only": True,
        "authorized_hosts": [host],
        "base_url": base_url,
        "tenants": {"a": {"token": "env:PZ_TOKEN_A"}, "b": {"token": "env:PZ_TOKEN_B"}},
        "isolation": {"canary": canary_a, "resources": [{"method": "GET", "path": "/REPLACE/with/a/path/that/returns/tenant-a/records"}]},
    }
    register = {"endpoints": [{"host": "REPLACE.with.your.model.provider", "purpose": "LLM inference", "baa": False,
                               "training_on_phi": "unknown", "retention": None}]}
    prof = profile_mod.load()
    files = {
        "rules-of-engagement.md": RULES.format(product=product, hosts=host),
        "target.yaml": "# Set authorized: true only after rules-of-engagement.md is signed.\n" + yaml.safe_dump(target, sort_keys=False),
        "register.yaml": "# Every company that can receive patient data. Set baa: true only when an agreement is signed.\n"
                         + yaml.safe_dump(register, sort_keys=False),
        "synthetic-patients.json": synth.to_json(data),
        "synthetic-patients.csv": synth.to_csv(data),
        "PILOT.md": RUN_SHEET.format(product=product, check_step=""),
        ".gitignore": "*.key\nevidence/\n",
    }
    written = []
    for name, text in files.items():
        path = os.path.join(folder, name)
        if os.path.exists(path):
            raise FileExistsError(f"{path} already exists; pilot init never overwrites")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        written.append(name)
    assess.save(assess.new(product, level, prof), os.path.join(folder, "assessment.yaml"))
    return written + ["assessment.yaml"]


def run(folder: str, project: Optional[str] = None) -> Dict[str, Any]:
    """Run every probe the target configures. Returns what ran, what was skipped and why, and the report path."""
    target_path = os.path.join(folder, "target.yaml")
    assessment_path = os.path.join(folder, "assessment.yaml")
    target = load_target(target_path)            # refuses unless authorized, synthetic, scoped
    prof = profile_mod.load()
    data = assess.load(assessment_path)
    ran: List[Dict[str, Any]] = []
    skipped: List[str] = []
    plan = [("isolation", isolation_probe.run, "isolation" in target),
            ("agent", agent_probe.run, "agent" in target),
            ("tls", tls_probe.run, True),
            ("egress", offline_probe.run_egress, "egress" in target)]
    for name, runner, configured in plan:
        if not configured:
            skipped.append(f"{name}: no `{name}` section in target.yaml")
            continue
        try:
            result = runner(target)
        except (ProbeRefused, KeyError, OSError, ValueError) as exc:
            skipped.append(f"{name}: {exc}")
            continue
        path = write_evidence(result, os.path.join(folder, "evidence"))
        rel = os.path.relpath(path, folder)
        assess.apply_probe(data, result, rel)
        ran.append({"probe": name, "checks": result.checks, "findings": result.grouped(), "void": result.void, "evidence": rel})
    assess.save(data, assessment_path)

    checked = check.run(project) if project else None
    lines = [f"# Pilot report: {data.get('product')}", "", f"Run on {date.today().isoformat()} against {target['base_url']}, "
             f"under: {target['authorization_ref']}. Synthetic data only.", "", "## What ran", ""]
    for r in ran:
        state = "VOID: nothing in this run could have found a problem" if r["void"] else (
            f"{len(r['findings'])} kind(s) of finding" if r["findings"] else "clean")
        lines.append(f"- **{r['probe']}**: {r['checks']} checks, {state}. Evidence: `{r['evidence']}`")
        lines += [f"  - {f}" for f in r["findings"]]
    if not ran:
        lines.append("- Nothing ran.")
    if skipped:
        lines += ["", "## What did not run", ""] + [f"- {s}" for s in skipped]
    if checked is not None:
        groups = check.grouped(checked)
        lines += ["", f"## Code check of `{project}`", "", f"{checked.files} files read, {len(groups)} kind(s) of mistake found."]
        lines += [f"- [{g['issue'].severity.upper()}] {g['issue'].title} ({len(g['places'])} place(s))" for g in groups]
    lines += ["", "## Where that leaves the assessment", "", buyer.executive_summary(data, prof).strip(), "", "## What to test next", ""]
    lines += [f"- {a['control']}: {a['action']}" for a in bayes.next_actions(data, prof, bayes.load_model(), top=5)]
    lines += ["", "A clean run is not a pass, and this report is not a certification. It records what was tested, on what, with whose permission."]
    report = os.path.join(folder, "pilot-report.md")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return {"ran": ran, "skipped": skipped, "report": report, "failed": any(r["findings"] for r in ran)}
