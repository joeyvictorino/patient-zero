"""Claims against records (LOG-1, AGENT-1).

An agent-authored transcript is a claim, not a record of what executed. This
probe lines up what agents said they did against the audit log and reports the
gaps. The principle and the method come from orbit-ir, an agent incident
reconstruction lab by the same author: https://github.com/joeyvictorino/orbit-ir

Transcript: JSON Lines, one claimed action per line:
    {"agent": "assistant-1", "workspace": "ws_a", "action": "record.read", "object": "client:3"}
Audit log: the hash-chained format written by patient_zero.auditlog.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Dict, List, Tuple

from .common import ProbeRefused, ProbeResult

CONTROLS = ["LOG-1", "AGENT-1"]
Key = Tuple[str, str, str]


def _jsonl(path: str) -> List[Tuple[int, Dict]]:
    rows = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                rows.append((lineno, json.loads(line)))
            except json.JSONDecodeError:
                raise ProbeRefused(f"{path} line {lineno} is not valid JSON") from None
    return rows


def run(transcript_path: str, log_path: str) -> ProbeResult:
    claims = _jsonl(transcript_path)
    records = _jsonl(log_path)
    result = ProbeResult("claims", CONTROLS, log_path)
    if not claims:
        result.inconclusive.append("transcript is empty")
        return result

    named: Counter = Counter()      # (workspace, action, object, agent) the log attributes to an agent
    unnamed: Counter = Counter()    # same action with no agent recorded
    for _, rec in records:
        key: Key = (str(rec.get("workspace")), str(rec.get("action")), str(rec.get("object")))
        if rec.get("agent"):
            named[key + (str(rec["agent"]),)] += 1
        else:
            unnamed[key] += 1

    for lineno, claim in claims:
        key = (str(claim.get("workspace")), str(claim.get("action")), str(claim.get("object")))
        agent = str(claim.get("agent"))
        label = f"{agent} {key[1]} {key[2]} (transcript line {lineno})"
        result.tick("LOG-1", "AGENT-1")
        if named[key + (agent,)] > 0:
            named[key + (agent,)] -= 1
        elif unnamed[key] > 0:
            unnamed[key] -= 1
            result.add("AGENT-1", "medium", "Logged action does not name the agent that performed it", label)
        else:
            result.add("LOG-1", "high", "Agent claims an action the audit log has no record of", label)

    silent = sum(named.values())
    if silent:
        result.inconclusive.append(f"{silent} logged agent action(s) appear in no transcript; agents did more than they reported")
    return result
