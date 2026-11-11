"""Heuristic likely-PHI detector for non-PHI workspaces (GATE-5).

This is a tripwire, not de-identification. It catches obvious identifiers
and health context so a non-PHI workspace can warn or quarantine. It will
miss PHI and it will flag things that are not PHI. Do not use it to claim
data is de-identified under 45 CFR 164.514.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

_PATTERNS = [
    ("ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("mrn", re.compile(r"\b(?:MRN|medical record(?: number| no\.?)?|patient id)\s*[:#]?\s*[A-Z0-9-]{5,}\b", re.I)),
    ("dob", re.compile(r"\b(?:DOB|date of birth|born)\s*[:\-]?\s*\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b", re.I)),
    ("member_id", re.compile(r"\b(?:member|subscriber|policy)\s*(?:id|number|no\.?)\s*[:#]?\s*[A-Z0-9-]{6,}\b", re.I)),
    ("icd10", re.compile(r"\b(?:ICD-?10|dx|diagnosis code)\s*[:#]?\s*[A-TV-Z]\d{2}(?:\.\d{1,4})?\b", re.I)),
    ("phone", re.compile(r"(?<!\d)(?:\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)")),
    ("email", re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")),
]

_HEALTH_TERMS = re.compile(
    r"\b(patient|diagnos(?:is|ed)|prescri(?:bed|ption)|medication|treatment plan|lab results?|"
    r"discharge|referral|symptoms?|appointment with dr\.?|insurance claim|prior authorization)\b",
    re.I,
)

# Identifiers that are only PHI when they sit next to health context.
_CONTEXT_ONLY = {"phone", "email"}


@dataclass(frozen=True)
class Finding:
    kind: str
    start: int
    end: int


def scan(text: str) -> List[Finding]:
    health_context = bool(_HEALTH_TERMS.search(text))
    findings: List[Finding] = []
    for kind, pattern in _PATTERNS:
        if kind in _CONTEXT_ONLY and not health_context:
            continue
        for m in pattern.finditer(text):
            findings.append(Finding(kind, m.start(), m.end()))
    findings.sort(key=lambda f: (f.start, -f.end))
    return findings


def likely_phi(text: str) -> bool:
    return bool(scan(text))


def redact(text: str) -> str:
    out, cursor = [], 0
    for f in scan(text):
        if f.start < cursor:
            continue
        out.append(text[cursor:f.start])
        out.append(f"[{f.kind.upper()}]")
        cursor = f.end
    out.append(text[cursor:])
    return "".join(out)
