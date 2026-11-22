"""A badge that states what a seal says, and nothing more.

It never says "compliant", "certified" or "passed", and it is never green. It
gives the level, how many safeguards a person has confirmed out of how many,
how many are failing, and the date, and it is meant to link to the sealed
evidence so a reader can check. A badge with no link to something verifiable
is a sticker; TRADEMARK.md says how the name may be used.
"""
from __future__ import annotations

from html import escape
from typing import Any, Dict

LABEL = "patient-zero"
NEUTRAL, WARNING = "#4b5b6b", "#9a3b2f"
STATEMENT = "This is not a certification and does not mean HIPAA compliant. It says what was tested and who signed it."


def message(document: Dict[str, Any]) -> str:
    head = document.get("head", {})
    summary = head.get("summary") or {}
    day = str(head.get("sealed_at", ""))[:10]
    parts = [str(head.get("level") or "?")]
    if summary:
        parts.append(f"{summary['confirmed']}/{summary['controls']} confirmed")
        if summary.get("failed"):
            parts.append(f"{summary['failed']} failing")
    parts.append(f"sealed {day}")
    return " · ".join(parts)


def svg(document: Dict[str, Any]) -> str:
    text = message(document)
    failing = bool((document.get("head", {}).get("summary") or {}).get("failed"))
    left, right = int(len(LABEL) * 6.7) + 12, int(len(text) * 6.4) + 14
    width = left + right
    title = escape(f"{LABEL}: {text}. {STATEMENT}")
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="20" role="img" aria-label="{title}">'
        f"<title>{title}</title>"
        f'<clipPath id="r"><rect width="{width}" height="20" rx="3"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{left}" height="20" fill="#2f3640"/>'
        f'<rect x="{left}" width="{right}" height="20" fill="{WARNING if failing else NEUTRAL}"/></g>'
        f'<g fill="#fff" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11" text-anchor="middle">'
        f'<text x="{left / 2:.0f}" y="14">{LABEL}</text>'
        f'<text x="{left + right / 2:.0f}" y="14">{escape(text)}</text></g></svg>\n'
    )


def markdown(document: Dict[str, Any], report_url: str, image: str = "patient-zero-badge.svg") -> str:
    head = document.get("head", {})
    return (
        f"[![{LABEL}: {message(document)}]({image})]({report_url})\n\n"
        f"We ran patient-zero on {str(head.get('sealed_at', ''))[:10]}. {STATEMENT} "
        f"The sealed evidence is at {report_url}; anyone can verify it has not been changed.\n"
    )
