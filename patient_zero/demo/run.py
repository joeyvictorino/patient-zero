"""`pz demo`: a full investigation of the bundled Leaky Clinic app, start to finish, offline."""
from __future__ import annotations

import os
import tempfile
from typing import Any, Dict, List

import yaml

from .. import assess, bayes, profile as profile_mod
from ..auditlog import AuditLog
from ..probes import agent, isolation, offline, write_evidence
from .leaky_clinic import make_server, target_for

REGISTER = {"endpoints": [
    {"host": "api.model-vendor.example", "purpose": "LLM inference", "baa": True,
     "training_on_phi": "prohibited", "retention": "0 days"},
]}


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

        out(f"\n== {label} build ==")
        runs = [isolation.run(target), agent.run(target), offline.run_egress(target),
                offline.run_log(log_path, head, target_name="Leaky Clinic audit log")]
        for result in runs:
            path = write_evidence(result, os.path.join(workdir, "evidence"))
            touched += assess.apply_probe(data, result, path)
            verdict = "clean" if result.clean else f"{len(result.findings)} finding(s)"
            out(f"  {result.probe:<10} {result.checks:>2} checks  {verdict}")
            for line in result.grouped():
                out(f"      {line}")
    finally:
        server.shutdown()
        server.server_close()
    return sorted(set(touched))


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
        touched = _investigate("vulnerable", True, data, workdir, out)
        out("\n  belief that each tested control holds:")
        for line in _belief_lines(data, prof, model, touched):
            out(line)

        touched = _investigate("patched", False, data, workdir, out)
        out("\n  belief after the same probes come back clean:")
        for line in _belief_lines(data, prof, model, touched):
            out(line)

    out("\n  Clean probes move belief up but never to a pass. A person still has to sign each control.")
    out("\n== what to test next (most uncertainty removed per unit of effort) ==")
    for a in bayes.next_actions(data, prof, model, top=5):
        out(f"  {a['control']:<8} {a['action']:<38} {a['bits']:.2f} bits")
    out("\nNext: pz init --product <yours> --level L1, then point the probes at your own staging environment.")
    return 0
