"""Readiness as inference instead of a checklist.

A checklist says a control is done or not done. Evidence does not work that
way. A clean probe run that made three requests is weak evidence; a finding
is strong evidence; a self-attested pass is somewhere between; all of it goes
stale. This module keeps one number per control, P(control holds | evidence),
and updates it with Bayes' rule in odds form:

    posterior odds = prior odds * product of likelihood ratios

Each observation contributes P(observation | holds) / P(observation | broken),
raised to a weight between 0 and 1 that halves every `half_life_days`.

The headline number, P(every required control holds), is the product of the
per-control posteriors. That treats controls as independent, which they are
not, so read it as a rough upper-bound style sanity check on a wall of green
ticks: 35 controls at 90% each is about a 2.5% chance that nothing is broken.

Every number in data/belief.yaml is a stated assumption, not a measurement.
"""
from __future__ import annotations

import math
from datetime import date
from importlib import resources
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .profile import Profile

_EPS = 1e-6


def load_model(path: Optional[str] = None) -> Dict[str, Any]:
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    return yaml.safe_load(resources.files("patient_zero").joinpath("data/belief.yaml").read_text("utf-8"))


def _clamp(p: float) -> float:
    return min(1 - _EPS, max(_EPS, p))


def entropy(p: float) -> float:
    """Uncertainty about one control, in bits. 1.0 at p=0.5, 0 when certain."""
    p = _clamp(p)
    return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))


def power(model: Dict[str, Any], probe: str, control_id: str, checks: int) -> float:
    """Chance a probe run would have caught this control being broken."""
    coverage = model.get("coverage", {}).get(probe, {}).get(control_id, 0.0)
    detection = model.get("detection", {})
    d = detection.get(probe, detection.get("default", 0.15))
    return coverage * (1 - (1 - d) ** max(0, checks))


def likelihoods(model: Dict[str, Any], obs: Dict[str, Any], control_id: str) -> Tuple[float, float]:
    """(P(observation | control holds), P(observation | control broken))."""
    if obs["kind"] == "probe":
        fp = model["false_positive"]
        if obs["outcome"] == "finding":
            return fp, model["finding_if_broken"]
        return 1 - fp, 1 - power(model, obs["probe"], control_id, int(obs.get("checks", 0)))
    if obs["kind"] == "attestation":
        if obs["outcome"] == "fail":
            cfg = model["assessor_fail"]
        else:
            cfg = model["attestation"][obs.get("by", "self")]
        return cfg["if_holds"], cfg["if_broken"]
    raise ValueError(f"unknown observation kind: {obs['kind']}")


def _weight(model: Dict[str, Any], obs: Dict[str, Any], today: date) -> float:
    try:
        age = (today - date.fromisoformat(str(obs["date"]))).days
    except (KeyError, ValueError):
        return 1.0
    return 0.5 ** (max(0, age) / float(model["half_life_days"]))


def _key(obs: Dict[str, Any]) -> str:
    return f"probe:{obs['probe']}" if obs["kind"] == "probe" else f"attestation:{obs.get('by', 'self')}"


def current_observations(entry: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """Latest observation per source. Rerunning a probe replaces its old result
    instead of stacking, so the same test cannot be counted twice."""
    latest: Dict[str, Dict[str, Any]] = {}
    for obs in entry.get("observations") or []:
        latest[_key(obs)] = obs
    if not latest and entry.get("status") in ("pass", "fail"):
        # Assessment files written before the ledger existed.
        latest["attestation:self"] = {"kind": "attestation", "by": "self", "outcome": entry["status"],
                                      "date": entry.get("updated", "")}
    return latest


def _log_odds(p: float) -> float:
    p = _clamp(p)
    return math.log(p / (1 - p))


def _from_log_odds(x: float) -> float:
    return _clamp(1 / (1 + math.exp(-x)))


def source_of(obs: Dict[str, Any]) -> str:
    """Who or what stands behind an observation: a probe, or a named person."""
    if obs["kind"] == "probe":
        return f"the {obs['probe']} probe"
    return f"{obs.get('ref') or 'unnamed assessor'} ({obs.get('by', 'self')})"


def posterior(model: Dict[str, Any], entry: Dict[str, Any], control_id: str, today: Optional[date] = None,
              skip: Optional[str] = None, without_source: Optional[str] = None) -> float:
    today = today or date.today()
    total = _log_odds(model["prior"])
    for key, obs in current_observations(entry).items():
        if key == skip or (without_source is not None and source_of(obs) == without_source):
            continue
        if_holds, if_broken = likelihoods(model, obs, control_id)
        total += _weight(model, obs, today) * math.log(_clamp(if_holds) / _clamp(if_broken))
    return _from_log_odds(total)


def beliefs(assessment: Dict[str, Any], profile: Profile, model: Dict[str, Any],
            today: Optional[date] = None) -> List[Dict[str, Any]]:
    rows = []
    for control in profile.for_level(assessment["level"]):
        entry = assessment["controls"].get(control.id, {})
        if entry.get("status") == "not_applicable":
            continue
        rows.append({
            "id": control.id,
            "family": control.family,
            "status": entry.get("status", "not_assessed"),
            "p": posterior(model, entry, control.id, today),
            "sources": sorted(current_observations(entry)),
        })
    return rows


def readiness(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    log_all = sum(math.log(_clamp(r["p"])) for r in rows)
    return {
        "controls": len(rows),
        "p_all_hold": math.exp(log_all),
        "expected_open": sum(1 - r["p"] for r in rows),
        "uncertainty_bits": sum(entropy(r["p"]) for r in rows),
        "weakest": [r["id"] for r in sorted(rows, key=lambda r: r["p"])[:5]],
    }


def _expected_entropy_after(model, entry, control_id, key, outcomes, today) -> float:
    """Expected uncertainty after a test, averaging over how it could come out."""
    base = posterior(model, entry, control_id, today, skip=key)  # the new result replaces the old one
    total = 0.0
    for if_holds, if_broken in outcomes:
        p_outcome = base * if_holds + (1 - base) * if_broken
        if p_outcome <= 0:
            continue
        total += p_outcome * entropy(base * if_holds / p_outcome)
    return total


def next_actions(assessment: Dict[str, Any], profile: Profile, model: Dict[str, Any],
                 today: Optional[date] = None, top: int = 10) -> List[Dict[str, Any]]:
    """Rank the evidence worth gathering next by expected bits of uncertainty removed per unit cost."""
    today = today or date.today()
    fp = model["false_positive"]
    typical = model.get("typical_checks", 10)
    costs = model["costs"]
    actions = []
    for control in profile.for_level(assessment["level"]):
        entry = assessment["controls"].get(control.id, {})
        if entry.get("status") == "not_applicable":
            continue
        now = entropy(posterior(model, entry, control.id, today))
        candidates = []
        seen = current_observations(entry)
        for probe, covered in model.get("coverage", {}).items():
            if control.id in covered:
                n = int(typical.get(probe, typical.get("default", 10)) if isinstance(typical, dict) else typical)
                previous = seen.get(f"probe:{probe}")
                label = f"run the {probe} probe"
                if previous is not None and previous["outcome"] == "clean":
                    if int(previous.get("checks", 0)) >= n:
                        continue  # already run at full size; a repeat tells you little
                    label = f"widen the {probe} probe to {n}+ checks"
                elif previous is not None:
                    label = f"fix, then rerun the {probe} probe"
                pw = power(model, probe, control.id, n)
                # two outcomes: clean, finding
                candidates.append((label, f"probe:{probe}", costs["probe"],
                                   [(1 - fp, 1 - pw), (fp, pw)]))
        for by in ("self", "independent"):
            cfg = model["attestation"][by]
            label = "review evidence and attest" if by == "self" else "have an independent tester attest"
            candidates.append((label, f"attestation:{by}", costs[by],
                               [(cfg["if_holds"], cfg["if_broken"]), (1 - cfg["if_holds"], 1 - cfg["if_broken"])]))
        for label, key, cost, outcomes in candidates:
            gain = now - _expected_entropy_after(model, entry, control.id, key, outcomes, today)
            if gain > 1e-4:
                actions.append({"control": control.id, "action": label, "bits": gain, "cost": cost,
                                "bits_per_cost": gain / cost})
    actions.sort(key=lambda a: a["bits_per_cost"], reverse=True)
    return actions[:top]


def fragility(assessment: Dict[str, Any], profile: Profile, model: Dict[str, Any],
              today: Optional[date] = None) -> List[Dict[str, Any]]:
    """Leave one source out. If everything a single source told you were wrong,
    how much of the picture goes with it?

    Controls are scored as independent, but evidence often is not: one person
    signing twenty controls is one point of failure, not twenty. This ranks
    sources by how much expected-broken rises when their evidence is discarded.
    """
    today = today or date.today()
    controls = [c for c in profile.for_level(assessment["level"])
                if assessment["controls"].get(c.id, {}).get("status") != "not_applicable"]
    sources: Dict[str, List[str]] = {}
    for c in controls:
        for obs in current_observations(assessment["controls"].get(c.id, {})).values():
            if obs.get("outcome") in ("clean", "pass"):  # only evidence that props belief up
                sources.setdefault(source_of(obs), []).append(c.id)
    rows = []
    for source, supported in sources.items():
        lost = 0.0
        for cid in supported:
            entry = assessment["controls"][cid]
            lost += posterior(model, entry, cid, today) - posterior(model, entry, cid, today, without_source=source)
        rows.append({"source": source, "controls": sorted(set(supported)), "belief_lost": lost})
    rows.sort(key=lambda r: r["belief_lost"], reverse=True)
    return rows


def bar(p: float, width: int = 20) -> str:
    filled = int(round(p * width))
    return "#" * filled + "." * (width - filled)


def render_text(assessment: Dict[str, Any], profile: Profile, model: Dict[str, Any],
                today: Optional[date] = None) -> str:
    rows = beliefs(assessment, profile, model, today)
    summary = readiness(rows)
    ticked = sum(1 for r in rows if r["status"] == "pass")
    lines = [f"{assessment.get('product')}  level {assessment['level']}  {len(rows)} controls", ""]
    for r in rows:
        lines.append(f"  {r['id']:<8} {bar(r['p'])} {r['p'] * 100:5.1f}%  {r['status']}")
    lines += [
        "",
        f"  checklist view:  {ticked} of {len(rows)} controls marked pass",
        f"  P(every control holds):  {format_probability(summary['p_all_hold'])}",
        f"  expected controls still broken:  {summary['expected_open']:.1f}",
        f"  remaining uncertainty:  {summary['uncertainty_bits']:.1f} bits",
        f"  weakest:  {', '.join(summary['weakest'])}",
        "",
        "  Assumes independent controls and the stated likelihoods in belief.yaml. Not a measurement.",
    ]
    return "\n".join(lines) + "\n"


def format_probability(p: float) -> str:
    if p >= 0.001:
        return f"{p * 100:.1f}%"
    if p < 1e-9:
        return "under 1 in a billion"
    return f"1 in {round(1 / p):,}"
