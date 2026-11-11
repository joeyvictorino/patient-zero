"""Assessment file: one status per control, with evidence.

Statuses: not_assessed, pass, partial, fail, not_applicable.
A workspace conforms to its level when every required `shall` control is
`pass`, or `not_applicable` with a written reason.
"""
from __future__ import annotations

from datetime import date
from typing import Any, Dict, List, Optional

import yaml

from .probes.common import ProbeResult
from .profile import Profile

STATUSES = ("not_assessed", "pass", "partial", "fail", "not_applicable")


def new(product: str, level: str, profile: Profile) -> Dict[str, Any]:
    return {
        "product": product,
        "level": level,
        "profile_version": profile.version,
        "created": date.today().isoformat(),
        "controls": {
            c.id: {"status": "not_assessed", "source": None, "note": "", "evidence": []}
            for c in profile.for_level(level)
        },
    }


def load(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or "controls" not in data or "level" not in data:
        raise ValueError(f"{path} is not an assessment file")
    return data


def save(assessment: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(assessment, fh, sort_keys=False, width=100)


def set_status(
    assessment: Dict[str, Any],
    control_id: str,
    status: str,
    note: str = "",
    evidence: Optional[List[str]] = None,
    assessor: str = "assessor",
) -> None:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {STATUSES}")
    if control_id not in assessment["controls"]:
        raise KeyError(f"{control_id} is not required at level {assessment['level']}")
    if status == "not_applicable" and not note.strip():
        raise ValueError("not_applicable needs a note that says why")
    if status == "pass" and not (evidence or assessment["controls"][control_id]["evidence"]):
        raise ValueError("pass needs at least one piece of evidence")
    entry = assessment["controls"][control_id]
    entry["status"] = status
    entry["source"] = assessor
    entry["note"] = note
    entry["updated"] = date.today().isoformat()
    for item in evidence or []:
        if item not in entry["evidence"]:
            entry["evidence"].append(item)


def apply_probe(assessment: Dict[str, Any], result: ProbeResult, evidence_path: str) -> List[str]:
    """Fold a probe run into the assessment. Returns the control ids it touched.

    A finding sets the control to fail, even over an assessor's pass.
    A clean run never sets pass: it lifts not_assessed (or this probe's own
    earlier fail) to partial and leaves the judgment to the assessor.
    """
    source = f"probe:{result.probe}"
    failed = {f.control for f in result.findings}
    touched = []
    for control_id in sorted(set(result.controls) | failed):
        entry = assessment["controls"].get(control_id)
        if entry is None:
            continue  # control not required at this level
        touched.append(control_id)
        if evidence_path not in entry["evidence"]:
            entry["evidence"].append(evidence_path)
        if control_id in failed:
            titles = [f.title for f in result.findings if f.control == control_id]
            entry.update(status="fail", source=source, note="; ".join(titles), updated=date.today().isoformat())
        elif entry["status"] == "not_assessed" or (entry["status"] == "fail" and entry.get("source") == source):
            entry.update(
                status="partial",
                source=source,
                note=f"{result.probe} probe clean ({result.checks} checks); assessor to confirm coverage",
                updated=date.today().isoformat(),
            )
    return touched


def summarize(assessment: Dict[str, Any], profile: Profile) -> Dict[str, Any]:
    counts = {s: 0 for s in STATUSES}
    blocking = []
    for control in profile.for_level(assessment["level"]):
        entry = assessment["controls"].get(control.id, {"status": "not_assessed"})
        status = entry.get("status", "not_assessed")
        counts[status] = counts.get(status, 0) + 1
        if control.keyword == "shall" and status not in ("pass", "not_applicable"):
            blocking.append(control.id)
    return {
        "product": assessment.get("product"),
        "level": assessment["level"],
        "counts": counts,
        "required": sum(counts.values()),
        "blocking": blocking,
        "conformant": not blocking,
    }
