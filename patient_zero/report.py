"""Render an assessment as a Markdown report."""
from __future__ import annotations

from datetime import date
from typing import Any, Dict

from .assess import summarize
from .profile import Profile

_LABEL = {
    "pass": "Pass",
    "partial": "Partial",
    "fail": "FAIL",
    "not_assessed": "Not assessed",
    "not_applicable": "N/A",
}


def _cell(text: Any) -> str:
    return str(text or "").replace("|", "\\|").replace("\n", " ")


def render(assessment: Dict[str, Any], profile: Profile) -> str:
    summary = summarize(assessment, profile)
    level = summary["level"]
    lines = [
        f"# PHI safeguard assessment: {summary['product']}",
        "",
        f"Level {level} ({profile.levels[level]['name']}), profile version {profile.version}, generated {date.today().isoformat()}.",
        "",
    ]
    if summary["conformant"]:
        lines.append(f"**Result: conforms to {level}.** All {summary['required']} required controls pass or are not applicable.")
    else:
        lines.append(
            f"**Result: does not yet conform to {level}.** "
            f"{len(summary['blocking'])} of {summary['required']} required controls are open."
        )
    counts = summary["counts"]
    lines += [
        "",
        f"Pass {counts['pass']}, partial {counts['partial']}, fail {counts['fail']}, "
        f"not assessed {counts['not_assessed']}, not applicable {counts['not_applicable']}.",
        "",
    ]

    required = profile.for_level(level)
    for family, meta in profile.families.items():
        rows = [c for c in required if c.family == family]
        if not rows:
            continue
        lines += [
            f"## {family}: {meta['name']}",
            "",
            f"HIPAA {', '.join(meta['hipaa'])}. SP 800-53 {', '.join(meta['sp800_53'])}. CSF {', '.join(meta['csf'])}.",
            "",
            "| Control | Status | Requirement | Note | Evidence |",
            "| --- | --- | --- | --- | --- |",
        ]
        for c in rows:
            entry = assessment["controls"].get(c.id, {})
            evidence = ", ".join(entry.get("evidence", []))
            lines.append(
                f"| {c.id} | {_LABEL.get(entry.get('status', 'not_assessed'))} | {_cell(c.statement)} "
                f"| {_cell(entry.get('note'))} | {_cell(evidence)} |"
            )
        lines.append("")

    lines += [
        "## Limits of this report",
        "",
        "This report is evidence for a customer or an external assessor. It is not a HIPAA certification; HHS does not issue or recognize one.",
        "Automated probes can fail a control but cannot pass one. Every pass was recorded by a person with evidence attached.",
    ]
    if not profile.mappings_verified:
        checked = (f"HIPAA citations were checked to exist in eCFR on {profile.hipaa_citations_checked}; "
                   if profile.hipaa_citations_checked else "")
        lines.append(f"Mappings are first-pass. {checked}SP 800-53 and CSF identifiers are unchecked, "
                     "and the fit of every mapping is the author's judgment, not a legal opinion.")
    lines.append("")
    return "\n".join(lines)
