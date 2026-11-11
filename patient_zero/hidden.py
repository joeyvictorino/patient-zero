"""Concealed-text tripwire for anything an agent is about to read (AGENT-4).

It looks at where text sits and how it is encoded, not at what it says:
characters a person cannot see, markup that hides content from a person but
not from a model, and comments. It does not try to recognize "malicious"
wording, because wording can always be rephrased and concealment cannot be
explained away so easily.

This is a tripwire, not a security boundary. A document with nothing hidden
can still carry an instruction in plain sight. The boundary is the action
gate (patient_zero.policy), which holds whatever the model was told.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

ZERO_WIDTH = "​‌‍⁠﻿"
BIDI = "‪‫‬‭‮⁦⁧⁨⁩"
_TAG_LOW, _TAG_HIGH = 0xE0000, 0xE007F

_ZERO_WIDTH_IN_WORD = re.compile(f"(?<=[A-Za-z0-9])[{ZERO_WIDTH}]+(?=[A-Za-z0-9])|[{ZERO_WIDTH}]{{3,}}")
_BIDI = re.compile(f"[{BIDI}]+")
_TAGS = re.compile("[\U000E0000-\U000E007F]+")
_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_HIDDEN_STYLE = re.compile(
    r"""<[a-zA-Z][^>]*\bstyle\s*=\s*["'][^"']*(?:
        display\s*:\s*none | visibility\s*:\s*hidden | opacity\s*:\s*0(?:\.0+)?\s*(?:;|["']) |
        font-size\s*:\s*0(?:px|pt|em|rem|%)?\s*(?:;|["']) |
        (?<![-\w])color\s*:\s*(?:\#fff(?:fff)?\b|white\b|rgba?\(\s*255\s*,\s*255\s*,\s*255)
    )[^>]*>""",
    re.I | re.X,
)
_HIDDEN_ATTR = re.compile(r"<[a-zA-Z][^>]*\s(?:hidden|aria-hidden\s*=\s*[\"']true[\"'])(?=[\s>/])[^>]*>", re.I)


@dataclass(frozen=True)
class Concealed:
    kind: str      # zero_width | bidi_override | unicode_tags | html_comment | hidden_style | hidden_attribute
    start: int
    end: int
    revealed: str  # what was hidden, where it can be recovered


def _decode_tags(text: str) -> str:
    return "".join(chr(ord(ch) - _TAG_LOW) for ch in text if _TAG_LOW + 0x20 <= ord(ch) < _TAG_HIGH)


def scan(text: str) -> List[Concealed]:
    found: List[Concealed] = []
    for m in _TAGS.finditer(text):
        found.append(Concealed("unicode_tags", m.start(), m.end(), _decode_tags(m.group())))
    for m in _ZERO_WIDTH_IN_WORD.finditer(text):
        found.append(Concealed("zero_width", m.start(), m.end(), ""))
    for m in _BIDI.finditer(text):
        found.append(Concealed("bidi_override", m.start(), m.end(), ""))
    for m in _COMMENT.finditer(text):
        if m.group(1).strip():
            found.append(Concealed("html_comment", m.start(), m.end(), m.group(1).strip()))
    for m in _HIDDEN_STYLE.finditer(text):
        found.append(Concealed("hidden_style", m.start(), m.end(), ""))
    for m in _HIDDEN_ATTR.finditer(text):
        found.append(Concealed("hidden_attribute", m.start(), m.end(), ""))
    found.sort(key=lambda c: (c.start, c.end))
    return found


def has_concealed(text: str) -> bool:
    return bool(scan(text))


def strip(text: str) -> str:
    """Remove invisible characters and comments. Hidden elements are flagged by scan, not removed:
    cutting markup safely needs a real HTML parser, so render to plain text before a model reads it."""
    text = _TAGS.sub("", text)
    text = _BIDI.sub("", text)
    text = re.sub(f"[{ZERO_WIDTH}]", "", text)
    return _COMMENT.sub("", text)
