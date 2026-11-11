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


def scan(text: str, strict: bool = False) -> List[Finding]:
    """`strict` flags phone numbers and email addresses even with no health context around them."""
    health_context = strict or bool(_HEALTH_TERMS.search(text))
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


class Vault:
    """Swap identifiers for placeholders before text goes to a model, and swap them back after.

        vault = Vault()
        safe = vault.mask("Call Ana at 702-555-0100 about MRN: A1234567")
        reply = call_model(safe)          # the model never sees the number or the MRN
        final = vault.unmask(reply)

    The same value always gets the same placeholder, so the model can still tell
    two people apart. Detection is the heuristic in this module: it reduces what
    you send, it does not make text de-identified under 45 CFR 164.514, and names
    and free-text details pass through. Keep the vault in memory for one request.
    """

    def __init__(self) -> None:
        self._by_value: dict = {}
        self._by_token: dict = {}

    def mask(self, text: str) -> str:
        out, cursor = [], 0
        for f in scan(text, strict=True):
            if f.start < cursor:
                continue
            value = text[f.start:f.end]
            token = self._by_value.get(value)
            if token is None:
                token = f"[[PZ:{f.kind.upper()}:{len(self._by_value) + 1}]]"
                self._by_value[value] = token
                self._by_token[token] = value
            out.append(text[cursor:f.start])
            out.append(token)
            cursor = f.end
        out.append(text[cursor:])
        return "".join(out)

    def unmask(self, text: str) -> str:
        for token, value in self._by_token.items():
            text = text.replace(token, value)
        return text

    def __len__(self) -> int:
        return len(self._by_value)
