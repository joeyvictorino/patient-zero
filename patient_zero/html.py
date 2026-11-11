"""Self-contained HTML report: status and belief per control."""
from __future__ import annotations

from datetime import date
from html import escape
from typing import Any, Dict

from . import bayes
from .assess import summarize
from .profile import Profile

_CSS = """
:root{color-scheme:light dark;--bg:#fbfaf7;--fg:#1c1b19;--muted:#6b6862;--line:#dedbd3;--track:#e9e6de;
--pass:#2f7d4f;--partial:#b7791f;--fail:#b3261e;--none:#8a877f}
@media(prefers-color-scheme:dark){:root{--bg:#161614;--fg:#eceae4;--muted:#a09d95;--line:#33312d;--track:#2a2926;
--pass:#6cc08b;--partial:#e0b060;--fail:#f0766d;--none:#7d7a73}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:860px;margin:0 auto;padding:32px 20px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:15px;margin:32px 0 8px;letter-spacing:.04em;text-transform:uppercase}
.sub,.fine{color:var(--muted)}.fine{font-size:13px;margin-top:32px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:24px 0}
.stat{border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.stat b{display:block;font-size:22px;font-variant-numeric:tabular-nums}.stat span{color:var(--muted);font-size:13px}
.row{display:grid;grid-template-columns:76px 150px 1fr;gap:12px;align-items:start;padding:8px 0;border-top:1px solid var(--line)}
.id{font:600 13px ui-monospace,Menlo,monospace;padding-top:2px}
.track{height:8px;background:var(--track);border-radius:4px;overflow:hidden;margin-top:6px}
.fill{height:100%}.pct{font-size:12px;color:var(--muted);font-variant-numeric:tabular-nums}
.tag{font-size:12px;font-weight:600}.note{color:var(--muted);font-size:13px}
.pass{color:var(--pass)}.partial{color:var(--partial)}.fail{color:var(--fail)}.not_assessed,.not_applicable{color:var(--none)}
.fill.pass{background:var(--pass)}.fill.partial{background:var(--partial)}.fill.fail{background:var(--fail)}
.fill.not_assessed,.fill.not_applicable{background:var(--none)}
@media(max-width:560px){.row{grid-template-columns:70px 1fr}.row>div:last-child{grid-column:1/-1}}
"""

_LABEL = {"pass": "Pass", "partial": "Partial", "fail": "Fail", "not_assessed": "Not assessed", "not_applicable": "N/A"}


def render(assessment: Dict[str, Any], profile: Profile, model: Dict[str, Any]) -> str:
    summary = summarize(assessment, profile)
    rows = {r["id"]: r for r in bayes.beliefs(assessment, profile, model)}
    ready = bayes.readiness(list(rows.values()))
    level = summary["level"]
    product = escape(str(summary["product"]))
    verdict = f"Conforms to {level}" if summary["conformant"] else f"Does not yet conform to {level}"
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>PHI safeguard assessment: {product}</title><style>{_CSS}</style></head><body><main>",
        f"<h1>{product}</h1>",
        f"<div class='sub'>PHI safeguard assessment, level {level} ({escape(profile.levels[level]['name'])}), "
        f"profile {escape(profile.version)}, {date.today().isoformat()}</div>",
        "<div class='stats'>",
        f"<div class='stat'><b>{verdict}</b><span>{len(summary['blocking'])} of {summary['required']} required controls open</span></div>",
        f"<div class='stat'><b>{summary['counts']['pass']} / {summary['required']}</b><span>marked pass (checklist view)</span></div>",
        f"<div class='stat'><b>{ready['expected_open']:.1f}</b><span>controls expected still broken</span></div>",
        (f"<div class='stat'><b>{bayes.format_probability(ready['p_all_hold'])}</b><span>P(every control holds)</span></div>"
         if ready["p_all_hold"] >= 0.001 else
         f"<div class='stat'><b>{ready['uncertainty_bits']:.1f} bits</b><span>of uncertainty left to remove</span></div>"),
        "</div>",
    ]
    required = profile.for_level(level)
    for family, meta in profile.families.items():
        controls = [c for c in required if c.family == family]
        if not controls:
            continue
        parts.append(f"<h2>{family}: {escape(meta['name'])}</h2>")
        for c in controls:
            entry = assessment["controls"].get(c.id, {})
            status = entry.get("status", "not_assessed")
            belief = rows.get(c.id)
            if belief:
                meter = (f"<div class='track'><div class='fill {status}' style='width:{belief['p'] * 100:.1f}%'></div></div>"
                         f"<div class='pct'>{belief['p'] * 100:.0f}% belief it holds</div>")
            else:
                meter = "<div class='pct'>not applicable</div>"
            note = f"<div class='note'>{escape(str(entry.get('note') or ''))}</div>" if entry.get("note") else ""
            parts.append(
                f"<div class='row'><div class='id'>{c.id}</div>"
                f"<div><span class='tag {status}'>{_LABEL[status]}</span>{meter}</div>"
                f"<div>{escape(c.statement)}{note}</div></div>"
            )
    parts.append(
        "<p class='fine'>This report is evidence for a customer or an external assessor. It is not a HIPAA certification; "
        "HHS does not issue or recognize one. Belief figures come from stated assumptions in belief.yaml, treat controls "
        "as independent, and are not measurements. Automated probes can fail a control but cannot pass one.</p>"
    )
    parts.append("</main></body></html>")
    return "\n".join(parts)
