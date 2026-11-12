"""`pz demo`: a full investigation of the bundled Leaky Clinic app, start to finish, offline."""
from __future__ import annotations

import os
import tempfile
import textwrap
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import yaml

from .. import assess, bayes, buyer, profile as profile_mod, replay as replay_mod, seal as seal_mod
from ..policy import ActionGate, Policy, Proposal
from ..auditlog import AuditLog
from ..probes import agent, isolation, offline, stack, write_evidence
from .leaky_clinic import make_server, target_for

REGISTER = {"endpoints": [
    {"host": "api.model-vendor.example", "purpose": "LLM inference", "baa": True,
     "training_on_phi": "prohibited", "retention": "0 days"},
]}


MESSY_STACK = {"services": {
    "ollama": {"image": "ollama/ollama:latest", "ports": ["11434:11434"], "environment": ["OLLAMA_ORIGINS=*"]},
    "qdrant": {"image": "qdrant/qdrant", "ports": ["6333:6333"]},
    "app": {"image": "leaky-clinic:dev", "ports": ["8080:8080"]},
}}
HARDENED_STACK = {"services": {
    "ollama": {"image": "ollama/ollama:0.12.3"},
    "qdrant": {"image": "qdrant/qdrant:v1.15.0"},
    "app": {"image": "leaky-clinic:1.0.1", "ports": ["127.0.0.1:8080:8080"]},
}}


def _audit_log(path: str, tamper: bool) -> str:
    log = AuditLog(path)
    for i in range(6):
        log.append(user="dr.a", agent="assistant-1", workspace="ws_a", action="record.read", obj=f"client:{i}")
    head = log.head()
    if tamper:  # someone quietly rewrites who read record 3
        lines = open(path, encoding="utf-8").read().splitlines()
        lines[3] = lines[3].replace('"user":"dr.a"', '"user":"nobody"')
        open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    return head


def _investigate(label: str, vulnerable: bool, data: Dict[str, Any], workdir: str, out) -> List[str]:
    server = make_server(vulnerable)
    touched: List[str] = []
    try:
        target = target_for(server)
        target["_dir"] = workdir
        with open(os.path.join(workdir, "register.yaml"), "w", encoding="utf-8") as fh:
            yaml.safe_dump(REGISTER, fh)
        hosts = ["api.model-vendor.example"] + (["collect.adtracker.example"] if vulnerable else [])
        with open(os.path.join(workdir, "observed.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(hosts) + "\n")
        target["egress"] = {"register": "register.yaml", "observed": "observed.txt"}
        log_path = os.path.join(workdir, f"audit-{label}.jsonl")
        head = _audit_log(log_path, tamper=vulnerable)

        stack_dir = os.path.join(workdir, f"stack-{label}")
        os.makedirs(stack_dir, exist_ok=True)
        with open(os.path.join(stack_dir, "docker-compose.yml"), "w", encoding="utf-8") as fh:
            yaml.safe_dump(MESSY_STACK if vulnerable else HARDENED_STACK, fh)

        out(f"\n== {label} build ==")
        runs = [isolation.run(target), agent.run(target), offline.run_egress(target),
                offline.run_log(log_path, head, target_name="Leaky Clinic audit log"), stack.run(stack_dir)]
        for result in runs:
            path = os.path.relpath(write_evidence(result, os.path.join(workdir, "evidence")), workdir)
            touched += assess.apply_probe(data, result, path)
            verdict = "clean" if result.clean else f"{len(result.findings)} finding(s)"
            out(f"  {result.probe:<10} {result.checks:>2} checks  {verdict}")
            for line in result.grouped():
                out(f"      {line}")
    finally:
        server.shutdown()
        server.server_close()
    return sorted(set(touched))


def _gate_demo(out) -> None:
    policy = Policy(
        version="2026.1",
        allowed_capabilities=frozenset({"record.read", "email.send", "http.external"}),
        allowed_outputs=frozenset({"appointment_count", "next_visit"}),
        write_capabilities=frozenset({"email.send"}),
        confirm_actions=frozenset({"email.send"}),
        dangerous_combinations=(frozenset({"record.read", "http.external"}),),
    )
    gate = ActionGate(policy, workspace="ws_a", user_capabilities=lambda user: {"record.read", "email.send"},
                      agent_write_grants=lambda agent: {"email.send"})
    soon = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()

    def propose(action, capabilities, nonce, outputs=("appointment_count",)):
        return Proposal(agent="assistant-1", user="dr.a", workspace="ws_a", action=action,
                        capabilities=frozenset(capabilities), outputs=frozenset(outputs), nonce=nonce,
                        expires_at=soon, policy_version="2026.1", recipient="patient@example.com", content="Reminder")

    summary = propose("record.summarize", {"record.read"}, "n1")
    cases = [
        ("summarize a record", summary),
        ("same proposal again", summary),
        ("read a record and call an outside URL", propose("record.forward", {"record.read", "http.external"}, "n2")),
        ("email a patient, no human confirmation", propose("email.send", {"email.send"}, "n3")),
        ("return the full note text", propose("record.summarize", {"record.read"}, "n4", outputs=("note_text",))),
    ]
    for label, proposal in cases:
        decision = gate.evaluate(proposal)
        out(f"  {label:<40} {'ALLOW' if decision.allowed else 'DENY '}  {decision.reason}")
    released = gate.release(summary, {"appointment_count": 3, "note_text": "synthetic note", "ssn": "000-00-0000"})
    out(f"  agent returned 3 fields, {len(released)} crossed: {sorted(released)}")


def _belief_lines(data, prof, model, touched) -> List[str]:
    rows = bayes.beliefs(data, prof, model)
    lines = [f"  {r['id']:<8} {bayes.bar(r['p'])} {r['p'] * 100:5.1f}%  {r['status']}" for r in rows if r["id"] in touched]
    summary = bayes.readiness(rows)
    lines.append(f"  across all {summary['controls']} controls at this level: {summary['expected_open']:.1f} expected still broken")
    return lines


def run(out=print) -> int:
    prof = profile_mod.load()
    model = bayes.load_model()
    data = assess.new("Leaky Clinic", "L2", prof)
    out("patient-zero demo: investigating Leaky Clinic, a deliberately broken AI app.")
    out("Everything runs on 127.0.0.1 with synthetic data. Nothing leaves this machine.")
    with tempfile.TemporaryDirectory(prefix="pz-demo-") as workdir:
        out("\n== before any test: write the prediction down ==")
        for probe, guess in (("isolation", 0.9), ("agent", 0.8)):
            model_p = bayes.predicted_clean(data, prof, model, probe)
            assess.predict(data, probe, guess, "the team", model_p)
            out(f"  {probe:<10} the team says {guess * 100:.0f}% it comes back clean; the model says {model_p * 100:.0f}%")

        touched = _investigate("vulnerable", True, data, workdir, out)
        out("\n  predictions settled (Brier score, 0 is perfect, 0.25 is a coin flip):")
        for row in bayes.calibration(data):
            out(f"  {row['forecaster']:<26} {row['brier']:.2f}")
        out("\n  belief that each tested control holds:")
        for line in _belief_lines(data, prof, model, touched):
            out(line)

        out("\n  the same result, for the person who has to decide:")
        report = buyer.executive_summary(data, prof).splitlines()
        out("  " + next(line for line in report if line.startswith("**Bottom line")).replace("**", ""))
        for line in [x for x in report if x.startswith("- **")][:2]:
            out("  " + line.replace("**", "").split(" What the test found")[0])

        touched = _investigate("patched", False, data, workdir, out)
        out("\n  belief after the same probes come back clean:")
        for line in _belief_lines(data, prof, model, touched):
            out(line)

        out("\n  Clean probes move belief up but never to a pass. A person still has to sign each control.")

        out("\n== agent action gate: the agent proposes, a fixed policy decides ==")
        _gate_demo(out)

        out("\n== replay: re-derive a finding from its recording, offline ==")
        first = sorted(f for f in os.listdir(os.path.join(workdir, "evidence")) if f.startswith("isolation"))[0]
        recorded = os.path.join(workdir, "evidence", first)
        reproduced, _ = replay_mod.replay(recorded)
        out("  isolation run from the vulnerable build: " + ("REPRODUCED from recorded exchanges" if reproduced else "MISMATCH"))
        doctored = os.path.join(workdir, "doctored.json")
        with open(recorded, encoding="utf-8") as src, open(doctored, "w", encoding="utf-8") as dst:
            dst.write(src.read().replace('"findings": [', '"findings_hidden": [', 1).replace('"clean": false', '"clean": true', 1)
                      .replace('"result": {', '"result": {"findings": [],', 1))
        reproduced, why = replay_mod.replay(doctored)
        out("  same file with its findings deleted by hand: " + ("NOT DETECTED" if reproduced else "MISMATCH, the recording still shows the leak"))

        out("\n== seal the evidence ==")
        a_path, key, sealed = (os.path.join(workdir, n) for n in ("assessment.yaml", "demo.key", "seal.json"))
        assess.save(data, a_path)
        seal_mod.keygen(key)
        head = seal_mod.seal(a_path, key, sealed, signer_name="demo")["head"]
        out(f"  {head['item_count']} files under Merkle root {head['merkle_root'][:24]}..., signed with Ed25519")
        out("  verify: " + ("ok" if not seal_mod.verify_seal(sealed) else "FAILED"))
        victim = os.path.join(workdir, [i for i in seal_mod.collect(a_path, workdir) if i.startswith("evidence")][0])
        with open(victim, "r+", encoding="utf-8") as fh:
            text = fh.read()
            fh.seek(0)
            fh.write(text.replace('"clean": false', '"clean": true', 1))
        problems = seal_mod.verify_seal(sealed)
        out("  edit one evidence file to say clean instead of finding, verify again: "
            + (problems[0] if problems else "NOT DETECTED"))
    out("\n== what to test next (most uncertainty removed per unit of effort) ==")
    for a in bayes.next_actions(data, prof, model, top=5):
        out(f"  {a['control']:<8} {a['action']:<38} {a['bits']:.2f} bits")
    out("\nNext: pz init --product <yours> --level L1, then point the probes at your own staging environment.")
    return 0


def run_brief(out=print) -> int:
    """The same investigation in plain language, short enough to read on a phone."""
    prof = profile_mod.load()
    plain = buyer.load_plain()
    data = assess.new("Leaky Clinic", "L2", prof)
    total = len(data["controls"])
    quiet = lambda line: None

    def statuses(status):
        return [cid for cid, entry in data["controls"].items() if entry["status"] == status]

    out('Testing "Leaky Clinic", a deliberately broken AI app for a medical office.')
    out("Synthetic data only. Everything runs on this machine.")
    with tempfile.TemporaryDirectory(prefix="pz-demo-") as workdir:
        _investigate("vulnerable", True, data, workdir, quiet)
        failed = statuses("fail")
        out("\nBEFORE THE FIX")
        out(f"  NOT READY. {len(failed)} of {total} safeguards failed a test:")
        for cid in failed:
            out(textwrap.fill(plain[cid]["plain"], width=78, initial_indent="  x  ", subsequent_indent="     "))

        _investigate("patched", False, data, workdir, quiet)
        out("\nAFTER THE FIX")
        out(f"  All {len(failed)} now test clean, and {len(statuses('fail'))} safeguards are failing.")
        out(f"  Still not approved: {len(statuses('pass'))} of {total} are confirmed. A clean test is not a pass.")
        out("  A named person has to check the evidence and sign each one.")

        a_path, key, sealed = (os.path.join(workdir, n) for n in ("assessment.yaml", "demo.key", "seal.json"))
        assess.save(data, a_path)
        seal_mod.keygen(key)
        head = seal_mod.seal(a_path, key, sealed, signer_name="demo")["head"]
        intact = not seal_mod.verify_seal(sealed)
        victim = os.path.join(workdir, [i for i in seal_mod.collect(a_path, workdir) if i.startswith("evidence")][0])
        with open(victim, "a", encoding="utf-8") as fh:
            fh.write(" ")
        caught = bool(seal_mod.verify_seal(sealed))
        out("\nTHE EVIDENCE")
        out(f"  {head['item_count']} files sealed and signed. Seal checks out: {'yes' if intact else 'NO'}.")
        out(f"  One file altered afterward. Caught: {'yes' if caught else 'NO'}.")
    return 0
