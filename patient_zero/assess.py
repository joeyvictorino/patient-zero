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
            c.id: {"status": "not_assessed", "source": None, "note": "", "evidence": [], "observations": []}
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
    independent: bool = False,
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
    if status in ("pass", "fail"):
        # The ledger behind `pz belief`: who judged, how, and when.
        entry.setdefault("observations", []).append({
            "kind": "attestation",
            "build": assessment.get("build"),
            "by": "independent" if independent else "self",
            "outcome": status,
            "date": date.today().isoformat(),
            "ref": assessor,
        })


def apply_probe(assessment: Dict[str, Any], result: ProbeResult, evidence_path: str) -> List[str]:
    """Fold a probe run into the assessment. Returns the control ids it touched.

    A finding sets the control to fail, even over an assessor's pass.
    A clean run never sets pass: it lifts not_assessed (or this probe's own
    earlier fail) to partial and leaves the judgment to the assessor.
    A run that made no check able to test a control leaves that control alone.
    """
    source = f"probe:{result.probe}"
    failed = {f.control for f in result.findings}
    touched = []
    if result.build:
        assessment["build"] = result.build
    _resolve_predictions(assessment, result)
    for control_id in sorted(set(result.controls) | failed):
        entry = assessment["controls"].get(control_id)
        if entry is None:
            continue  # control not required at this level
        if control_id not in failed and not result.checks_for.get(control_id):
            continue  # the run never tested this control: void, which is not the same as clean
        touched.append(control_id)
        if evidence_path not in entry["evidence"]:
            entry["evidence"].append(evidence_path)
        entry.setdefault("observations", []).append({
            "build": result.build,
            "kind": "probe",
            "probe": result.probe,
            "outcome": "finding" if control_id in failed else "clean",
            "checks": int(result.checks_for.get(control_id, 0)),
            "date": date.today().isoformat(),
            "ref": evidence_path,
        })
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


def predict(assessment: Dict[str, Any], probe: str, p_clean: float, by: str, model_p: Optional[float] = None) -> Dict[str, Any]:
    """Write down, before the run, how likely you think the probe is to come back clean.

    The next run of that probe that actually tests something settles it. One open
    prediction per person per probe: you cannot revise after seeing the result,
    because by then it is already settled.
    """
    if not 0 <= p_clean <= 1:
        raise ValueError("probability must be between 0 and 1")
    if not by.strip():
        raise ValueError("a prediction needs a name")
    predictions = assessment.setdefault("predictions", [])
    if any(q["probe"] == probe and q["by"] == by and q["outcome"] is None for q in predictions):
        raise ValueError(f"{by} already has an open prediction for the {probe} probe")
    entry = {"probe": probe, "by": by, "p_clean": float(p_clean), "model_p_clean": model_p,
             "made": date.today().isoformat(), "outcome": None, "settled": None}
    predictions.append(entry)
    return entry


def _resolve_predictions(assessment: Dict[str, Any], result: ProbeResult) -> None:
    if result.void:
        return  # a run that tested nothing settles nothing
    for q in assessment.get("predictions") or []:
        if q["probe"] == result.probe and q["outcome"] is None:
            q["outcome"] = "clean" if result.clean else "finding"
            q["settled"] = date.today().isoformat()


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
