"""Care-claims tripwire for Nevada AB 406 (2025), section 7(1).

The law bars representing that an AI system can provide professional mental
or behavioral health care, that talking to it is a way to obtain such care,
or that it is a therapist, counselor, psychiatrist, doctor or similar
provider. This scans product copy, marketing text or AI replies for wording
that reads that way.

It is a phrase scan, so it is easy to evade and it will misjudge some
sentences. A hit is a reason for a person to read the sentence. No hit is not
a legal clearance. Sentences that plainly deny the claim are reported as
disclaimers, not findings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

_AI = r"(?:AI|A\.I\.|artificial intelligence|chatbot|bot|virtual assistant|digital assistant|assistant|companion|avatar)"
_TITLE = r"(?:clinical therapist|psychotherapist|therapist|counsell?or|psychiatrist|psychologist|doctor|clinician|social worker)"
_CARE = (r"(?:therapy|psychotherapy|counsell?ing|mental health (?:care|treatment|support from a professional)|"
         r"behavioral health (?:care|treatment)|treatment for (?:depression|anxiety|ptsd|addiction|trauma))")
_CONDITION = r"(?:depression|anxiety|ptsd|bipolar|mental illness|addiction|substance use|trauma|eating disorders?)"

_PATTERNS = [
    ("ai_called_a_provider", re.compile(rf"\b(?:AI|virtual|digital|automated|robot|chatbot|bot)[- ]?(?:powered\s+)?{_TITLE}\b", re.I)),
    ("ai_called_a_provider", re.compile(rf"\b{_AI}\b[^.!?]{{0,40}}\b(?:is|as|acts as|works as|becomes|be)\s+(?:your|a|an|the)\s+(?:\w+\s+)?{_TITLE}\b", re.I)),
    ("ai_called_a_provider", re.compile(rf"\byour\s+(?:own\s+|personal\s+|24/7\s+)?(?:AI|virtual|digital)\s+{_TITLE}\b", re.I)),
    ("ai_provides_care", re.compile(rf"\b{_AI}\b[^.!?]{{0,60}}\b(?:provides?|delivers?|offers?|gives?|conducts?|does)\b[^.!?]{{0,30}}\b{_CARE}\b", re.I)),
    ("ai_provides_care", re.compile(rf"\b{_CARE}\b[^.!?]{{0,40}}\b(?:from|by|with|through|powered by)\s+(?:our\s+|an?\s+|the\s+|your\s+)?{_AI}\b", re.I)),
    ("ai_provides_care", re.compile(rf"\b{_AI}\b[^.!?]{{0,40}}\b(?:diagnos\w+|treats?|cures?)\b[^.!?]{{0,40}}\b{_CONDITION}\b", re.I)),
    ("talk_to_ai_for_care", re.compile(rf"\b(?:talk|chat|speak|open up)\s+(?:to|with)\s+(?:our\s+|an?\s+|the\s+|your\s+)?{_AI}\b[^.!?]{{0,60}}\b{_CARE}\b", re.I)),
]
_DENIAL = re.compile(r"\b(?:not|never|cannot|can't|isn't|doesn't|won't|no substitute|not a substitute|does not replace|instead of)\b", re.I)
_SENTENCE = re.compile(r"[^.!?\n]+[.!?]?")


@dataclass(frozen=True)
class Claim:
    kind: str          # ai_called_a_provider | ai_provides_care | talk_to_ai_for_care | disclaimer
    sentence: str


def scan_claims(text: str) -> List[Claim]:
    found: List[Claim] = []
    for m in _SENTENCE.finditer(text):
        sentence = m.group().strip()
        if len(sentence) < 8:
            continue
        for kind, pattern in _PATTERNS:
            if pattern.search(sentence):
                found.append(Claim("disclaimer" if _DENIAL.search(sentence) else kind, sentence))
                break
    return found


def findings(text: str) -> List[Claim]:
    return [c for c in scan_claims(text) if c.kind != "disclaimer"]
