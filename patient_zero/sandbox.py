"""`pz sandbox`: is this pilot ready to enter a sandbox, and ready to leave it?

A sandbox lets a product be tried safely before it meets real patients. That
only works if entry and exit mean something that can be checked. The criteria
are data (patient_zero/data/sandbox.yaml); this module checks each one against
a pilot folder and says met, not met, or not checked, with the reason.

It does not admit or graduate anyone. The sandbox's operator does.
"""
from __future__ import annotations

import json
import os
from importlib import resources
from typing import Any, Dict, List, Optional, Tuple

import yaml

from . import assess, check, seal
from .egress import load_register

MET, NOT_MET, NOT_CHECKED = "met", "not met", "not checked"


def criteria() -> Dict[str, List[Dict[str, str]]]:
    return yaml.safe_load(resources.files("patient_zero").joinpath("data/sandbox.yaml").read_text("utf-8"))


def _load(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    return doc if isinstance(doc, dict) else None


def evaluate(folder: str, project: Optional[str] = None) -> Dict[str, Any]:
    target = _load(os.path.join(folder, "target.yaml"))
    assessment = None
    if os.path.isfile(os.path.join(folder, "assessment.yaml")):
        assessment = assess.load(os.path.join(folder, "assessment.yaml"))
    register_path = os.path.join(folder, "register.yaml")
    endpoints = load_register(register_path) if os.path.isfile(register_path) else None
    checked = check.run(project) if project else None
    seal_path = os.path.join(folder, "seal.json")

    def permission() -> Tuple[str, str]:
        if not target:
            return NOT_MET, "no target.yaml in the pilot folder"
        missing = [k for k in ("authorization_ref", "authorized_hosts") if not target.get(k)]
        if target.get("authorized") is not True:
            missing.insert(0, "authorized: true")
        return (NOT_MET, "target.yaml is missing " + ", ".join(missing)) if missing else (MET, str(target["authorization_ref"]))

    def synthetic() -> Tuple[str, str]:
        ok = bool(target) and target.get("synthetic_data_only") is True
        return (MET, "declared in target.yaml") if ok else (NOT_MET, "target.yaml does not set synthetic_data_only: true")

    def started() -> Tuple[str, str]:
        return (MET, f"level {assessment['level']}") if assessment else (NOT_MET, "no assessment.yaml in the pilot folder")

    def registered() -> Tuple[str, str]:
        if endpoints is None:
            return NOT_MET, "no register.yaml in the pilot folder"
        if not endpoints or any("replace" in e.host for e in endpoints):
            return NOT_MET, "register.yaml still has a placeholder or is empty"
        return MET, f"{len(endpoints)} company(ies) named"

    def code(limit: str) -> Tuple[str, str]:
        if checked is None:
            return NOT_CHECKED, "no project folder given (--path)"
        if checked.void:
            return NOT_CHECKED, "the project folder had no files to read"
        bad = [i for i in checked.issues if check.SEVERITIES.index(i.severity) <= check.SEVERITIES.index(limit)]
        return (NOT_MET, f"{len(bad)} finding(s), first: {bad[0].title}") if bad else (MET, f"{checked.files} files read")

    def isolation() -> Tuple[str, str]:
        if not assessment:
            return NOT_MET, "no assessment"
        entry = assessment["controls"].get("GATE-3")
        if entry is None:
            return NOT_CHECKED, "GATE-3 is not required at this level"
        runs = [o for o in entry.get("observations") or [] if o.get("kind") == "probe" and o.get("probe") == "isolation"]
        if not runs:
            return NOT_MET, "the isolation probe has not run"
        latest = runs[-1]
        if assessment.get("build") and latest.get("build") and str(latest["build"]) != str(assessment["build"]):
            return NOT_MET, f"last run was on build {latest['build']}, not the current {assessment['build']}"
        if latest.get("outcome") != "clean" or not latest.get("checks"):
            return NOT_MET, "the last run found a leak" if latest.get("outcome") != "clean" else "the last run tested nothing"
        return MET, f"{latest['checks']} checks on {latest.get('date')}"

    def nothing_failing() -> Tuple[str, str]:
        if not assessment:
            return NOT_MET, "no assessment"
        failing = sorted(cid for cid, e in assessment["controls"].items() if e.get("status") == "fail")
        return (NOT_MET, "failing: " + ", ".join(failing)) if failing else (MET, "none failing")

    def agreements() -> Tuple[str, str]:
        if not endpoints:
            return NOT_MET, "no register"
        weak = [f"{e.host} ({', '.join(e.problems())})" for e in endpoints if not e.approved()]
        return (NOT_MET, "; ".join(weak)) if weak else (MET, f"{len(endpoints)} agreement(s) on record")

    def sealed() -> Tuple[str, str]:
        if not os.path.isfile(seal_path):
            return NOT_MET, "no seal.json in the pilot folder"
        problems = seal.verify_seal(seal_path)
        return (NOT_MET, problems[0]) if problems else (MET, "seal verifies")

    def independent() -> Tuple[str, str]:
        if not os.path.isfile(seal_path) or seal.verify_seal(seal_path):
            return NOT_MET, "no verified seal"
        with open(seal_path, "r", encoding="utf-8") as fh:
            names = [c["body"]["signer"].get("name") for c in json.load(fh).get("cosignatures") or []
                     if c["body"].get("role") == "independent-assessor"]
        return (MET, "co-signed by " + ", ".join(n or "an unnamed assessor" for n in names)) if names else (NOT_MET, "no independent co-signature")

    checks = {"permission": permission, "synthetic": synthetic, "assessment": started, "register": registered,
              "no-critical-code": lambda: code("critical"), "isolation-tested": isolation, "nothing-failing": nothing_failing,
              "agreements": agreements, "no-serious-code": lambda: code("high"), "sealed": sealed, "independent": independent}
    out: Dict[str, Any] = {"folder": os.path.abspath(folder)}
    for stage, items in criteria().items():
        rows = []
        for item in items:
            status, reason = checks[item["id"]]()
            rows.append({"id": item["id"], "text": item["text"], "status": status, "reason": reason})
        out[stage] = rows
        out[f"{stage}_met"] = all(r["status"] == MET for r in rows)
    return out


def render(result: Dict[str, Any]) -> str:
    mark = {MET: "[x]", NOT_MET: "[ ]", NOT_CHECKED: "[?]"}
    lines = [f"Sandbox criteria for {result['folder']}", ""]
    for stage, title in (("entry", "TO ENTER"), ("exit", "TO LEAVE")):
        rows = result[stage]
        lines.append(f"{title}: {sum(r['status'] == MET for r in rows)} of {len(rows)} met")
        for r in rows:
            lines.append(f"  {mark[r['status']]} {r['text']}")
            lines.append(f"        {r['status']}: {r['reason']}")
        lines.append("")
    lines.append("This reports which criteria are met. The sandbox's operator decides who enters and who leaves, "
                 "and meeting every one is not a certification.")
    return "\n".join(lines) + "\n"
